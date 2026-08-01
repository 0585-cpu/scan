# 대시보드 UI 개편 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 스캔 대시보드를 아이콘 레일 + 2단(명령/결과) 레이아웃으로 바꾸고, 프리셋으로 입력을 줄이고, 전역 진행 띠와 실시간 결과로 진행 상황을 항상 보이게 한다.

**Architecture:** `netroach/static/dashboard.html` 한 파일만 바꾼다. 백엔드 API·저장소·리포트는 건드리지 않는다. 기존 `state` 객체, `$()`/`escapeHtml()`/`api()` 헬퍼, `refreshScans()`/`refreshScanProgress()`/`renderScanResults()` 파이프라인을 그대로 재사용하고, 그 위에 프리셋·진행 띠·실시간 호스트 목록을 얹는다.

**Tech Stack:** 순수 HTML/CSS/JS (프레임워크 없음), `localStorage`, 기존 FastAPI 엔드포인트 `/v1/scans`, `/v1/scans/{id}/progress`, `/v1/scans/{id}/results`. 테스트는 Python `unittest` (`tests/test_dashboard.py`)로 자산의 구조를 검증하고, 동작은 브라우저에서 확인한다.

## Global Constraints

- 단일 자립 HTML 파일. 빌드 단계 없음. **파일을 분할하지 않는다** — `netroach/dashboard.py`가 이 파일 하나를 그대로 서빙하고 `tests/test_dashboard.py::test_dashboard_file_is_served`가 파일 내용과 응답의 동일성을 검사한다.
- CDN·외부 폰트·외부 스크립트·외부 이미지 금지. `src`/`href`에 `http://`·`https://` 없음.
- `target="_blank"`, `window.open(` 금지. 회귀 테스트가 강제한다.
- 라이트 테마 유지. 다크 테마 추가 금지.
- UI 문구는 한국어. 기술 용어는 영문 유지: `open`, `filtered`, `closed`, CIDR, BPF, TCP.
- 백엔드 API 변경 금지. 새 엔드포인트·새 응답 필드를 만들지 않는다.
- 새 런타임 의존성 금지.
- 정보 밀도는 현재 수준 유지.
- 강조색은 `#0f766e`(청록). 기존 `#1b6ec2`는 남기지 않는다.
- 모서리 반경은 4px로 통일.
- 폴링 간격 상수: 활성 700ms, 숨김 5000ms, 실행 중인 스캔 없으면 정지.
- 사용자 프리셋 최대 12개, `localStorage` 키 `netroach.scanPresets.v1`.
- **권한 확인 체크(`confirm_authorized`)는 어떤 경로로도 저장·복원되지 않는다.**

---

### Task 1: 디자인 토큰과 셸 레이아웃

기존 `:root` 토큰을 새 시각 언어로 교체하고, 텍스트 사이드바를 아이콘 레일로 바꾼다. 스캔 화면의 2단 구조는 Task 6에서 채우고 여기서는 뼈대만 만든다.

**Files:**
- Modify: `netroach/static/dashboard.html:11-45` (`:root` 토큰)
- Modify: `netroach/static/dashboard.html:668-690` (`<aside class="sidebar">` / `<nav class="nav">`)
- Test: `tests/test_dashboard.py`

**Interfaces:**
- Consumes: 없음 (첫 작업)
- Produces: CSS 변수 `--accent: #0f766e`, `--accent-dark: #0b5f58`, `--accent-soft: #e6f2f0`, `--bg: #f7f8f7`, `--surface: #ffffff`, `--radius: 4px`, `--radius-sm: 4px`, `--state-open`, `--state-filtered`, `--state-closed`, `--state-error`. 레일 마크업의 각 버튼은 `data-view-target`(기존 이름 그대로)과 `data-rail-icon` 속성을 가진다.

- [ ] **Step 1: 실패하는 테스트를 쓴다**

`tests/test_dashboard.py`에 추가:

```python
class DashboardVisualLanguageTests(unittest.TestCase):
    def test_accent_is_the_new_teal_and_the_old_blue_is_gone(self):
        html = dashboard_html()

        self.assertIn("--accent: #0f766e;", html)
        self.assertIn("--bg: #f7f8f7;", html)
        self.assertNotIn("#1b6ec2", html)
        self.assertNotIn("#14589e", html)

    def test_state_colours_are_declared_once_as_tokens(self):
        html = dashboard_html()

        for token in ("--state-open:", "--state-filtered:", "--state-closed:", "--state-error:"):
            self.assertIn(token, html)

    def test_corners_are_uniform(self):
        html = dashboard_html()

        self.assertIn("--radius: 4px;", html)
        self.assertIn("--radius-sm: 4px;", html)

    def test_navigation_is_an_icon_rail(self):
        html = dashboard_html()

        self.assertIn('class="rail"', html)
        self.assertNotIn('class="sidebar"', html)
        # Labels stay in the markup for screen readers and hover.
        self.assertIn('data-rail-icon', html)
        self.assertIn('data-view-target="scans"', html)
```

- [ ] **Step 2: 테스트를 돌려 실패를 확인한다**

Run: `python -m unittest tests.test_dashboard -v`
Expected: FAIL — `--accent: #0f766e;` not found.

- [ ] **Step 3: 토큰을 교체한다**

`netroach/static/dashboard.html`의 `:root` 블록에서 아래 값들을 교체/추가한다. 기존 변수 이름은 유지해 나머지 CSS가 그대로 동작하게 한다.

```css
    :root {
      --bg: #f7f8f7;
      --surface: #ffffff;
      --accent: #0f766e;
      --accent-dark: #0b5f58;
      --accent-soft: #e6f2f0;
      --state-open: #0f766e;
      --state-filtered: #6b7280;
      --state-closed: #9ca3af;
      --state-error: #b91c1c;
      --radius: 4px;
      --radius-sm: 4px;
    }
```

`#1b6ec2`·`#14589e`·`#e9f1fb`가 하드코딩된 자리가 남아 있으면 모두 대응 변수로 바꾼다. 확인:

```bash
grep -n '1b6ec2\|14589e\|e9f1fb' netroach/static/dashboard.html
```

출력이 비어야 한다.

- [ ] **Step 4: 사이드바를 아이콘 레일로 바꾼다**

`<aside class="sidebar">` 전체를 아래로 교체한다. 라벨 텍스트는 그대로 두되 시각적으로는 호버 시에만 펼친다 — `showView()`가 `[data-view-target]`의 `textContent`로 화면 제목을 만들기 때문에 텍스트를 지우면 제목이 깨진다.

```html
      <aside class="rail">
        <div class="rail-brand" title="netroach">N</div>
        <nav class="nav" aria-label="대시보드 섹션">
          <button type="button" data-view-target="overview" data-rail-icon="◈" class="active"><span class="rail-label">개요</span></button>
          <button type="button" data-view-target="scans" data-rail-icon="◉"><span class="rail-label">포트 스캔</span></button>
          <button type="button" data-view-target="pcap" data-rail-icon="⬡"><span class="rail-label">PCAP 분석</span></button>
          <button type="button" data-view-target="capture" data-rail-icon="⬢"><span class="rail-label">라이브 캡처</span></button>
          <button type="button" data-view-target="packets" data-rail-icon="◇"><span class="rail-label">패킷 전송</span></button>
          <button type="button" data-view-target="oast" data-rail-icon="◎"><span class="rail-label">OAST 콜백</span></button>
          <button type="button" data-view-target="plugins" data-rail-icon="▣"><span class="rail-label">플러그인</span></button>
          <button type="button" data-view-target="diagnostics" data-rail-icon="⚙"><span class="rail-label">진단</span></button>
        </nav>
      </aside>
```

기존 `.sidebar` CSS 규칙을 아래로 대체한다:

```css
    .rail {
      width: 56px;
      flex: 0 0 56px;
      background: var(--surface);
      border-right: 1px solid var(--line);
      display: flex;
      flex-direction: column;
      align-items: stretch;
      padding: 8px 0;
      transition: width 120ms ease, flex-basis 120ms ease;
      overflow: hidden;
    }
    .rail:hover, .rail:focus-within { width: 184px; flex-basis: 184px; }
    .rail-brand {
      height: 40px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 700;
      color: var(--accent);
      letter-spacing: 0.04em;
    }
    .rail .nav { display: flex; flex-direction: column; gap: 2px; }
    .rail .nav button {
      display: flex;
      align-items: center;
      gap: 12px;
      height: 36px;
      padding: 0 18px;
      border: 0;
      border-radius: 0;
      background: transparent;
      color: var(--muted);
      white-space: nowrap;
      text-align: left;
    }
    .rail .nav button::before {
      content: attr(data-rail-icon);
      width: 20px;
      flex: 0 0 20px;
      text-align: center;
      font-size: 14px;
    }
    .rail .nav button:hover { background: var(--accent-soft); color: var(--accent); }
    .rail .nav button.active { background: var(--accent-soft); color: var(--accent); box-shadow: inset 3px 0 0 var(--accent); }
    .rail-label { opacity: 0; transition: opacity 120ms ease; }
    .rail:hover .rail-label, .rail:focus-within .rail-label { opacity: 1; }
    @media (prefers-reduced-motion: reduce) {
      .rail, .rail-label { transition: none; }
    }
```

- [ ] **Step 5: 테스트를 돌려 통과를 확인한다**

Run: `python -m unittest tests.test_dashboard -v`
Expected: PASS (모든 테스트)

- [ ] **Step 6: 브라우저에서 확인한다**

`.claude/launch.json`에 항목이 없으면 만든다:

```json
{
  "version": "0.0.1",
  "configurations": [
    {"name": "netroach", "runtimeExecutable": "netroach", "runtimeArgs": ["serve"], "port": 8000}
  ]
}
```

서버를 띄우고 대시보드를 연다. 확인 항목: 레일이 56px로 좁게 보이고, 마우스를 올리면 라벨이 나오고, 선택된 항목만 청록으로 강조되고, 화면 전환이 여전히 동작한다.

- [ ] **Step 7: 커밋**

```bash
git add netroach/static/dashboard.html tests/test_dashboard.py .claude/launch.json
git commit -m "feat(ui): teal design tokens and an icon rail"
```

---

### Task 2: 전역 진행 띠

실행 중인 스캔이 있을 때만 나타나 모든 화면에서 보이는 상단 띠. 데이터는 이미 `state.scans`에 들어와 있으므로 새 요청을 만들지 않는다.

**Files:**
- Modify: `netroach/static/dashboard.html` — `<body>` 최상단에 마크업 추가, CSS 추가, JS에 `renderProgressStrip()` 추가, `refreshScans()` 말미에서 호출
- Test: `tests/test_dashboard.py`

**Interfaces:**
- Consumes: Task 1의 토큰 (`--accent`, `--state-error`), 기존 `state.scans`, `state.scanId`, `api()`, `selectScan()`, `showView()`
- Produces: `function renderProgressStrip()` — 인자 없음, 반환 없음. `state.runningProgress` (`{scanId, percent, completed, planned, open, error, elapsedMs}` 또는 `null`)를 읽어 `#progressStrip`을 갱신한다. `async function refreshRunningProgress()` — 실행 중 스캔 하나의 progress를 받아 `state.runningProgress`를 채운다.

- [ ] **Step 1: 실패하는 테스트를 쓴다**

```python
class DashboardProgressStripTests(unittest.TestCase):
    def test_strip_markup_and_renderer_exist(self):
        html = dashboard_html()

        self.assertIn('id="progressStrip"', html)
        self.assertIn("function renderProgressStrip(", html)
        self.assertIn("async function refreshRunningProgress(", html)

    def test_strip_shows_the_counts_an_operator_watches(self):
        html = dashboard_html()

        self.assertIn('id="stripTarget"', html)
        self.assertIn('id="stripPercent"', html)
        self.assertIn('id="stripCounts"', html)
        self.assertIn('id="stripOpen"', html)
        self.assertIn('id="stripElapsed"', html)
        self.assertIn('id="stripStop"', html)
        self.assertIn('id="stripOpenScan"', html)

    def test_strip_reuses_the_scan_list_instead_of_a_new_endpoint(self):
        html = dashboard_html()

        # The backend contract is unchanged: no new routes were invented.
        for route in ("/v1/scans/running", "/v1/progress", "/v1/scans/active"):
            self.assertNotIn(route, html)
```

- [ ] **Step 2: 테스트를 돌려 실패를 확인한다**

Run: `python -m unittest tests.test_dashboard -v`
Expected: FAIL — `id="progressStrip"` not found.

- [ ] **Step 3: 마크업을 추가한다**

`<body>` 바로 다음, `<aside class="rail">`를 감싸는 셸 컨테이너보다 위에 넣는다:

```html
  <div class="progress-strip" id="progressStrip" hidden>
    <span class="strip-dot" id="stripDot">◉</span>
    <span class="strip-target mono" id="stripTarget"></span>
    <span class="strip-bar"><i id="stripBar"></i></span>
    <span class="strip-percent" id="stripPercent">0%</span>
    <span class="strip-counts mono" id="stripCounts"></span>
    <span class="strip-open mono" id="stripOpen"></span>
    <span class="strip-error mono" id="stripError" hidden></span>
    <span class="strip-more" id="stripMore" hidden></span>
    <span class="strip-elapsed mono" id="stripElapsed">00:00</span>
    <button type="button" id="stripStop">중지</button>
    <button type="button" id="stripOpenScan">열기</button>
  </div>
```

CSS:

```css
    .progress-strip {
      position: sticky;
      top: 0;
      z-index: 40;
      height: 36px;
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 0 12px;
      background: var(--accent-soft);
      border-bottom: 1px solid var(--line);
      font-size: 12px;
      cursor: pointer;
    }
    .progress-strip[hidden] { display: none; }
    .progress-strip.done { background: #e7f5ec; }
    .progress-strip.failed { background: #fdeaea; }
    .strip-bar { flex: 0 0 140px; height: 6px; background: #ffffff; border-radius: 4px; overflow: hidden; }
    .strip-bar i { display: block; height: 100%; width: 0; background: var(--accent); transition: width 200ms ease; }
    .strip-target { flex: 0 1 auto; max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .strip-error { color: var(--state-error); }
    .strip-elapsed { margin-left: auto; }
    .progress-strip button { height: 24px; padding: 0 10px; font-size: 12px; }
    @media (prefers-reduced-motion: reduce) { .strip-bar i { transition: none; } }
```

- [ ] **Step 4: 렌더러와 갱신 함수를 추가한다**

`state` 객체에 필드를 더한다:

```js
      runningProgress: null,
      stripClosedFor: null,
```

`refreshScanProgress()` 정의 뒤에 추가:

```js
    const RUNNING_STATUSES = new Set(['queued', 'running']);

    function runningScanJobs() {
      return state.scans.filter((job) => RUNNING_STATUSES.has(job.status));
    }

    // The strip reads the job list the dashboard already polls, then asks for
    // the progress of the one job it displays. No new endpoint, one extra
    // request only while something is actually running.
    async function refreshRunningProgress() {
      const jobs = runningScanJobs();
      if (!jobs.length) {
        const finished = state.runningProgress && state.scans.find((job) => job.id === state.runningProgress.scanId);
        state.runningProgress = finished && state.stripClosedFor !== finished.id
          ? {...state.runningProgress, status: finished.status, percent: 100}
          : null;
        renderProgressStrip();
        return;
      }
      const job = jobs[0];
      try {
        const progress = await api(`/v1/scans/${encodeURIComponent(job.id)}/progress`);
        const states = progress.states || {};
        state.runningProgress = {
          scanId: job.id,
          status: progress.status,
          label: `${job.targets} · ${job.ports}`,
          percent: progress.percent || 0,
          completed: progress.completed_results || 0,
          planned: progress.planned_total || 0,
          open: states.open || 0,
          error: states.error || 0,
          startedAt: progress.started_at || progress.created_at,
          extra: jobs.length - 1
        };
      } catch (err) {
        state.runningProgress = null;
      }
      renderProgressStrip();
    }

    function elapsedLabel(startedAt) {
      if (!startedAt) return '00:00';
      const source = text(startedAt);
      const started = new Date(source.includes('T') ? source : `${source.replace(' ', 'T')}Z`);
      if (Number.isNaN(started.getTime())) return '00:00';
      const seconds = Math.max(0, Math.floor((Date.now() - started.getTime()) / 1000));
      return `${String(Math.floor(seconds / 60)).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`;
    }

    function renderProgressStrip() {
      const strip = $('progressStrip');
      const progress = state.runningProgress;
      if (!progress) {
        strip.hidden = true;
        return;
      }
      const done = !RUNNING_STATUSES.has(progress.status);
      strip.hidden = false;
      strip.classList.toggle('done', done && progress.status === 'completed');
      strip.classList.toggle('failed', done && progress.status !== 'completed');
      $('stripTarget').textContent = progress.label;
      $('stripBar').style.width = `${progress.percent}%`;
      $('stripPercent').textContent = `${progress.percent}%`;
      $('stripCounts').textContent = `${progress.completed.toLocaleString()}/${progress.planned.toLocaleString()}`;
      $('stripOpen').textContent = `open ${progress.open}`;
      $('stripError').hidden = !progress.error;
      $('stripError').textContent = `err ${progress.error}`;
      $('stripMore').hidden = !progress.extra;
      $('stripMore').textContent = `+${progress.extra}`;
      $('stripElapsed').textContent = done ? '완료' : elapsedLabel(progress.startedAt);
      $('stripStop').hidden = done;
      // A completed scan clears itself; a failed one stays until dismissed so a
      // failure is never missed by someone who looked away.
      if (done && progress.status === 'completed') {
        const scanId = progress.scanId;
        setTimeout(() => {
          if (state.runningProgress && state.runningProgress.scanId === scanId) {
            state.stripClosedFor = scanId;
            state.runningProgress = null;
            renderProgressStrip();
          }
        }, 3000);
      }
    }
```

`refreshScans()`의 `try` 블록 끝(`if (render) { ... }` 다음)에 추가:

```js
        await refreshRunningProgress();
```

바인딩을 초기화 구간(`bindScanLinkActions();` 근처)에 추가:

```js
    $('progressStrip').addEventListener('click', (event) => {
      if (event.target.id === 'stripStop') return;
      const progress = state.runningProgress;
      if (!progress) return;
      if (!RUNNING_STATUSES.has(progress.status) && progress.status !== 'completed') {
        state.stripClosedFor = progress.scanId;
        state.runningProgress = null;
        renderProgressStrip();
        return;
      }
      showView('scans');
      selectScan(progress.scanId);
    });
    $('stripStop').addEventListener('click', async (event) => {
      event.stopPropagation();
      const progress = state.runningProgress;
      if (!progress) return;
      await api(`/v1/scans/${encodeURIComponent(progress.scanId)}/cancel`, {method: 'POST'}).catch(() => {});
      await refreshScans();
    });
```

취소 엔드포인트 이름은 코드에서 확인한다:

```bash
grep -n 'cancel' netroach/api.py netroach/static/dashboard.html | head
```

기존에 쓰던 경로와 다르면 그 경로로 맞춘다. 새 엔드포인트를 만들지 않는다.

- [ ] **Step 5: 테스트를 돌려 통과를 확인한다**

Run: `python -m unittest tests.test_dashboard -v`
Expected: PASS

- [ ] **Step 6: 브라우저에서 확인한다**

`127.0.0.1/32`에 대해 상위 100포트 스캔을 시작한다. 확인 항목: 띠가 나타나고, 다른 화면(진단 등)으로 이동해도 계속 보이고, `open` 수가 늘고, 완료 후 3초 뒤 사라진다. 띠를 클릭하면 스캔 화면의 해당 작업이 선택된다.

- [ ] **Step 7: 커밋**

```bash
git add netroach/static/dashboard.html tests/test_dashboard.py
git commit -m "feat(ui): global progress strip visible from every view"
```

---

### Task 3: 상황에 맞춘 폴링

지금은 무조건 5초마다 돈다. 실행 중일 때는 빠르게, 숨겨져 있으면 느리게, 할 일이 없으면 멈춘다.

**Files:**
- Modify: `netroach/static/dashboard.html:2690-2704` (파일 끝 폴링 블록)
- Test: `tests/test_dashboard.py`

**Interfaces:**
- Consumes: Task 2의 `runningScanJobs()`, `state.runningProgress`
- Produces: 상수 `POLL_ACTIVE_MS = 700`, `POLL_HIDDEN_MS = 5000`; `function schedulePoll()` — 다음 폴링을 예약하고, 실행 중인 스캔이 없으면 예약하지 않는다.

- [ ] **Step 1: 실패하는 테스트를 쓴다**

```python
class DashboardPollingTests(unittest.TestCase):
    def test_poll_cadence_matches_the_three_documented_states(self):
        html = dashboard_html()

        self.assertIn("const POLL_ACTIVE_MS = 700;", html)
        self.assertIn("const POLL_HIDDEN_MS = 5000;", html)
        self.assertIn("function schedulePoll(", html)
        self.assertIn("document.hidden", html)

    def test_the_old_fixed_interval_is_gone(self):
        html = dashboard_html()

        # A weak machine must not keep polling with nothing running.
        self.assertNotIn("setInterval(", html)
```

- [ ] **Step 2: 테스트를 돌려 실패를 확인한다**

Run: `python -m unittest tests.test_dashboard -v`
Expected: FAIL — `const POLL_ACTIVE_MS = 700;` not found.

- [ ] **Step 3: 폴링 블록을 교체한다**

파일 끝의 `function pollOnce() { ... } setInterval(...) ... visibilitychange ...` 전체를 아래로 바꾼다:

```js
    // Poll fast while a scan is actually moving, slowly while the window is
    // hidden, and not at all when there is nothing to watch: an idle
    // dashboard should cost a weak machine nothing.
    const POLL_ACTIVE_MS = 700;
    const POLL_HIDDEN_MS = 5000;
    let pollTimer = null;

    function pollOnce() {
      refreshHealth().catch(() => {});
      refreshScans().catch(() => {}).finally(schedulePoll);
    }

    function schedulePoll() {
      if (pollTimer) {
        clearTimeout(pollTimer);
        pollTimer = null;
      }
      if (!runningScanJobs().length && !state.runningProgress) return;
      pollTimer = setTimeout(pollOnce, document.hidden ? POLL_HIDDEN_MS : POLL_ACTIVE_MS);
    }

    pollOnce();
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) pollOnce();
    });
```

폴링이 멈춘 상태에서도 스캔을 새로 시작하면 다시 돌아야 한다. 스캔 제출 핸들러(`$('scanForm').addEventListener('submit', ...)`)에서 `refreshScans()` 호출 뒤에 `schedulePoll();`을 추가한다.

- [ ] **Step 4: 테스트를 돌려 통과를 확인한다**

Run: `python -m unittest tests.test_dashboard -v`
Expected: PASS

- [ ] **Step 5: 브라우저에서 확인한다**

개발자 도구 네트워크 탭을 열고 스캔이 없는 상태로 30초 둔다. `/v1/scans` 요청이 더 이상 발생하지 않아야 한다. 스캔을 시작하면 약 700ms 간격으로 재개되고, 탭을 다른 데로 옮기면 간격이 벌어지고, 스캔이 끝나면 다시 멈춘다.

- [ ] **Step 6: 커밋**

```bash
git add netroach/static/dashboard.html tests/test_dashboard.py
git commit -m "perf(ui): poll only while a scan is running, faster when watched"
```

---

### Task 4: 프리셋

기존 포트 프리셋 버튼(`data-port-preset`)과 가져온 포트 프로필(`netroach.customPortProfiles.v1`)을 대체하는 통합 프리셋. 프리셋은 폼을 **채우기만** 하고 스캔을 시작하지 않는다.

**Files:**
- Modify: `netroach/static/dashboard.html:761-777` (`.preset-row` 포트 프리셋 마크업)
- Modify: `netroach/static/dashboard.html:1281-1283` 부근 (저장 상수)
- Modify: `netroach/static/dashboard.html` JS — 프리셋 저장/적용/렌더 함수 추가
- Test: `tests/test_dashboard.py`

**Interfaces:**
- Consumes: Task 1의 토큰, 기존 `$()`, `escapeHtml()`, `setStatus()`, `updateScanScopeMode()`, `updateScanActionState()`
- Produces:
  - 상수 `SCAN_PRESET_STORAGE_KEY = 'netroach.scanPresets.v1'`, `SCAN_PRESET_MAX_COUNT = 12`, `PRESET_FIELDS`(배열), `BUILTIN_SCAN_PRESETS`(배열)
  - `function presetFromForm(includeTargets)` → `{name, targets, values}` — `values`는 `PRESET_FIELDS`에 있는 키만 담는다
  - `function applyScanPreset(preset)` → 반환 없음. 폼을 채우고 대상 칸에 포커스+전체선택한다. **권한 확인 체크는 항상 해제한다.**
  - `function loadScanPresets()` / `function saveScanPresets(list)` — `localStorage` 입출력
  - `function renderScanPresets()` — 칩 줄을 다시 그린다

- [ ] **Step 1: 실패하는 테스트를 쓴다**

```python
class DashboardPresetTests(unittest.TestCase):
    def test_preset_storage_is_versioned_and_bounded(self):
        html = dashboard_html()

        self.assertIn("const SCAN_PRESET_STORAGE_KEY = 'netroach.scanPresets.v1';", html)
        self.assertIn("const SCAN_PRESET_MAX_COUNT = 12;", html)

    def test_three_builtin_presets_ship_with_the_dashboard(self):
        html = dashboard_html()

        self.assertIn("const BUILTIN_SCAN_PRESETS = [", html)
        for name in ("빠른 점검", "웹 포트", "전체 정밀"):
            self.assertIn(name, html)

    def test_authorization_is_never_part_of_a_preset(self):
        """A restored checkbox would silently defeat the authorization gate.

        The field list a preset serialises must not contain it, and applying a
        preset must actively clear it.
        """
        html = dashboard_html()

        fields = html.split("const PRESET_FIELDS = [", 1)[1].split("];", 1)[0]
        self.assertNotIn("confirm_authorized", fields)
        self.assertNotIn("authorized", fields)
        self.assertIn("function applyScanPreset(", html)
        self.assertIn("scanAuthorized').checked = false", html)

    def test_a_preset_fills_the_form_rather_than_starting_a_scan(self):
        html = dashboard_html()

        body = html.split("function applyScanPreset(", 1)[1].split("\n    }", 1)[0]
        self.assertNotIn("submit(", body)
        self.assertNotIn("startScan(", body)
        self.assertIn("select()", body)

    def test_preset_chips_and_management_controls_exist(self):
        html = dashboard_html()

        self.assertIn('id="scanPresetChips"', html)
        self.assertIn('id="scanPresetSave"', html)
        self.assertIn('id="scanPresetIncludeTargets"', html)
        self.assertIn("function renderScanPresets(", html)
```

- [ ] **Step 2: 테스트를 돌려 실패를 확인한다**

Run: `python -m unittest tests.test_dashboard -v`
Expected: FAIL — `SCAN_PRESET_STORAGE_KEY` not found.

- [ ] **Step 3: 권한 확인 체크박스의 id를 확인한다**

```bash
grep -n 'authorization-box' -A 6 netroach/static/dashboard.html
```

체크박스에 id가 없으면 `id="scanAuthorized"`를 부여한다. 위 테스트가 이 id를 참조한다.

- [ ] **Step 4: 프리셋 칩 마크업을 추가한다**

`<form id="scanForm">` 바로 안쪽, `.form-grid` 앞에 넣는다:

```html
                  <div class="preset-chips" id="scanPresetChips" aria-label="스캔 프리셋"></div>
                  <div class="preset-save-row">
                    <button type="button" id="scanPresetSave">+ 저장</button>
                    <label class="check-row"><input id="scanPresetIncludeTargets" type="checkbox">대상도 함께 저장</label>
                    <span class="helper" id="scanPresetStatus"></span>
                  </div>
```

기존 `<div class="preset-row" aria-label="포트 프리셋">` 블록과 `<div class="preset-row custom-profile-list" id="scanCustomProfiles">`를 삭제한다. 이들을 참조하던 JS(`data-port-preset` 핸들러, `renderCustomPortProfiles()`, `loadCustomPortProfiles()`, `CUSTOM_PORT_PROFILE_*` 상수, `state.customPortProfiles`, `state.activeCustomPortProfile`)도 함께 제거한다. TXT 가져오기(`scanPortProfileFile`)는 남긴다 — 프리셋과 목적이 다르다.

제거 후 남은 참조가 없는지 확인:

```bash
grep -n 'customPortProfile\|CUSTOM_PORT_PROFILE\|data-port-preset\|activeCustomPortProfile' netroach/static/dashboard.html
```

출력은 비어야 한다.

CSS:

```css
    .preset-chips { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 10px; }
    .preset-chip {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      height: 26px;
      padding: 0 10px;
      font-size: 12px;
      border: 1px solid var(--line);
      border-radius: var(--radius-sm);
      background: var(--surface);
      color: var(--muted);
    }
    .preset-chip.active { border-color: var(--accent); color: var(--accent); background: var(--accent-soft); }
    .preset-chip .chip-dirty { color: var(--accent); font-weight: 700; }
    .preset-chip .chip-key { opacity: 0.5; font-size: 10px; }
    .preset-chip-actions { display: none; gap: 4px; }
    .preset-chip:hover .preset-chip-actions { display: inline-flex; }
    .preset-save-row { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; flex-wrap: wrap; }
```

- [ ] **Step 5: 프리셋 로직을 추가한다**

`CUSTOM_PORT_PROFILE_*` 상수를 지운 자리에 넣는다:

```js
    const SCAN_PRESET_STORAGE_KEY = 'netroach.scanPresets.v1';
    const SCAN_PRESET_MAX_COUNT = 12;
    // The authorization checkbox is deliberately absent: a restored tick would
    // defeat the gate that makes every scan a deliberate act.
    const PRESET_FIELDS = ['ports', 'protocol', 'concurrency', 'timeout_ms', 'retries', 'engine', 'service_probe', 'capture_screenshots'];

    const BUILTIN_SCAN_PRESETS = [
      {id: 'builtin-quick', name: '빠른 점검', builtin: true, values: {ports: '1-1024', protocol: 'tcp', service_probe: true}},
      {id: 'builtin-web', name: '웹 포트', builtin: true, values: {ports: '80,443,8000-8090,8443', protocol: 'tcp', service_probe: true}},
      {id: 'builtin-full', name: '전체 정밀', builtin: true, values: {ports: '1-65535', protocol: 'tcp', service_probe: true, timeout_ms: 3000, concurrency: 128}}
    ];

    function loadScanPresets() {
      try {
        const raw = JSON.parse(window.localStorage.getItem(SCAN_PRESET_STORAGE_KEY) || '[]');
        if (!Array.isArray(raw)) return [];
        return raw.filter((item) => item && typeof item.name === 'string').slice(0, SCAN_PRESET_MAX_COUNT);
      } catch (err) {
        return [];
      }
    }

    function saveScanPresets(list) {
      try {
        window.localStorage.setItem(SCAN_PRESET_STORAGE_KEY, JSON.stringify(list.slice(0, SCAN_PRESET_MAX_COUNT)));
      } catch (err) {
        setStatus('scanPresetStatus', '프리셋을 저장하지 못했습니다', true);
      }
    }

    function formFieldValue(name) {
      const node = $('scanForm').elements[name];
      if (!node) return undefined;
      return node.type === 'checkbox' ? node.checked : node.value;
    }

    function presetFromForm(includeTargets) {
      const values = {};
      PRESET_FIELDS.forEach((name) => {
        const value = formFieldValue(name);
        if (value !== undefined && value !== '') values[name] = value;
      });
      return {name: '', targets: includeTargets ? $('scanTargets').value : '', values};
    }

    function applyScanPreset(preset) {
      PRESET_FIELDS.forEach((name) => {
        const node = $('scanForm').elements[name];
        if (!node) return;
        const value = preset.values[name];
        if (value === undefined) return;
        if (node.type === 'checkbox') node.checked = Boolean(value);
        else node.value = value;
      });
      if (preset.targets) $('scanTargets').value = preset.targets;
      // Authorization is never restored - it must be given for each scan.
      $('scanAuthorized').checked = false;
      state.activePresetId = preset.id;
      state.presetDirty = false;
      updateScanScopeMode();
      updateScanActionState();
      renderScanPresets();
      $('scanTargets').focus();
      $('scanTargets').select();
    }

    function allScanPresets() {
      return [...BUILTIN_SCAN_PRESETS, ...state.scanPresets];
    }

    function renderScanPresets() {
      const presets = allScanPresets();
      $('scanPresetChips').innerHTML = presets.map((preset, index) => {
        const active = preset.id === state.activePresetId;
        const dirty = active && state.presetDirty ? '<span class="chip-dirty">*</span>' : '';
        const key = index < 9 ? `<span class="chip-key">${index + 1}</span>` : '';
        const actions = preset.builtin ? '' :
          `<span class="preset-chip-actions"><button type="button" data-preset-rename="${escapeHtml(preset.id)}" title="이름 변경">✎</button><button type="button" data-preset-delete="${escapeHtml(preset.id)}" title="삭제">✕</button></span>`;
        return `<button type="button" class="preset-chip ${active ? 'active' : ''}" data-preset-apply="${escapeHtml(preset.id)}">${key}${escapeHtml(preset.name)}${dirty}${actions}</button>`;
      }).join('');

      document.querySelectorAll('[data-preset-apply]').forEach((node) => {
        node.addEventListener('click', (event) => {
          if (event.target.closest('.preset-chip-actions')) return;
          const preset = allScanPresets().find((item) => item.id === node.dataset.presetApply);
          if (preset) applyScanPreset(preset);
        });
      });
      document.querySelectorAll('[data-preset-delete]').forEach((node) => {
        node.addEventListener('click', (event) => {
          event.stopPropagation();
          state.scanPresets = state.scanPresets.filter((item) => item.id !== node.dataset.presetDelete);
          saveScanPresets(state.scanPresets);
          renderScanPresets();
        });
      });
      document.querySelectorAll('[data-preset-rename]').forEach((node) => {
        node.addEventListener('click', (event) => {
          event.stopPropagation();
          const preset = state.scanPresets.find((item) => item.id === node.dataset.presetRename);
          if (!preset) return;
          const name = window.prompt('프리셋 이름', preset.name);
          if (!name || !name.trim()) return;
          preset.name = name.trim().slice(0, 24);
          saveScanPresets(state.scanPresets);
          renderScanPresets();
        });
      });

      const full = state.scanPresets.length >= SCAN_PRESET_MAX_COUNT;
      const dirtyActive = state.presetDirty && state.activePresetId && !state.activePresetId.startsWith('builtin-');
      $('scanPresetSave').textContent = dirtyActive ? '덮어쓰기' : '+ 저장';
      $('scanPresetSave').disabled = full && !dirtyActive;
      setStatus('scanPresetStatus', full && !dirtyActive ? `프리셋은 ${SCAN_PRESET_MAX_COUNT}개까지 저장할 수 있습니다` : '');
    }
```

`state`에 필드를 더한다:

```js
      scanPresets: [],
      activePresetId: null,
      presetDirty: false,
```

저장 버튼과 더티 추적 바인딩:

```js
    $('scanPresetSave').addEventListener('click', () => {
      const includeTargets = $('scanPresetIncludeTargets').checked;
      const draft = presetFromForm(includeTargets);
      const active = state.scanPresets.find((item) => item.id === state.activePresetId);
      if (state.presetDirty && active) {
        active.values = draft.values;
        active.targets = draft.targets;
      } else {
        if (state.scanPresets.length >= SCAN_PRESET_MAX_COUNT) return;
        const name = window.prompt('프리셋 이름');
        if (!name || !name.trim()) return;
        const preset = {...draft, id: `user-${Date.now()}`, name: name.trim().slice(0, 24)};
        state.scanPresets.push(preset);
        state.activePresetId = preset.id;
      }
      state.presetDirty = false;
      saveScanPresets(state.scanPresets);
      renderScanPresets();
    });

    $('scanForm').addEventListener('input', () => {
      if (!state.activePresetId || state.presetDirty) return;
      state.presetDirty = true;
      renderScanPresets();
    });
```

초기화 구간에서 `state.customPortProfiles = loadCustomPortProfiles(); renderCustomPortProfiles();`를 아래로 교체:

```js
    state.scanPresets = loadScanPresets();
    renderScanPresets();
```

`scanReset` 핸들러에서 지운 함수 참조(`state.activeCustomPortProfile`, `renderCustomPortProfiles()`)를 제거하고 `state.activePresetId = null; state.presetDirty = false; renderScanPresets();`로 바꾼다.

- [ ] **Step 6: 테스트를 돌려 통과를 확인한다**

Run: `python -m unittest tests.test_dashboard -v`
Expected: PASS

- [ ] **Step 7: 브라우저에서 확인한다**

1. `웹 포트` 칩을 누른다 → 포트 칸이 채워지고, 대상 칸에 커서가 잡히고 전체 선택되고, **스캔은 시작되지 않고**, 권한 확인 체크는 꺼져 있다.
2. 타임아웃을 바꾼다 → 칩에 `*`가 붙고 저장 버튼이 `덮어쓰기`로 바뀐다.
3. `+ 저장`으로 새 프리셋을 만든다 → 새로고침 후에도 남아 있다.
4. 프리셋을 적용한 뒤 권한 확인을 켜고 저장한다 → 새로고침하고 그 프리셋을 다시 적용하면 권한 확인이 **꺼져 있다.**
5. 13개째 저장을 시도하면 버튼이 비활성이고 안내가 뜬다.

콘솔에서 저장 내용을 직접 확인:

```js
JSON.parse(localStorage.getItem('netroach.scanPresets.v1'))
```

어떤 항목에도 권한 관련 키가 없어야 한다.

- [ ] **Step 8: 커밋**

```bash
git add netroach/static/dashboard.html tests/test_dashboard.py
git commit -m "feat(ui): scan presets that fill the form and never store authorization"
```

---

### Task 5: 입력 즉시 검증과 예상치

대상 칸에서 포커스가 빠질 때 파싱해 요약을 보여주고, 틀렸으면 시작 버튼을 잠근다.

**Files:**
- Modify: `netroach/static/dashboard.html` — 시작 버튼 위 요약 영역 추가, `updateScanActionState()` 확장
- Test: `tests/test_dashboard.py`

**Interfaces:**
- Consumes: 기존 `asList()`, `parsePortExpression()`, `updateScanActionState()`, Task 4의 `state.activePresetId`
- Produces: `function estimateScanScale()` → `{hosts, ports, probes, seconds}` 또는 `{error}` — 폼의 현재 값만 읽는 순수 함수. `function renderScanEstimate()` — `#scanEstimate`를 갱신하고 시작 버튼의 잠금 여부를 정한다. `function expandTargetCount(expression)` → 정수 (CIDR 확장 개수, `/8`보다 큰 범위는 상한을 두고 셈).

- [ ] **Step 1: 실패하는 테스트를 쓴다**

```python
class DashboardEstimateTests(unittest.TestCase):
    def test_estimate_helpers_exist(self):
        html = dashboard_html()

        self.assertIn("function estimateScanScale(", html)
        self.assertIn("function renderScanEstimate(", html)
        self.assertIn("function expandTargetCount(", html)
        self.assertIn('id="scanEstimate"', html)

    def test_estimate_runs_on_blur_not_only_on_submit(self):
        html = dashboard_html()

        self.assertRegex(html, r"scanTargets'\)\.addEventListener\('blur'")

    def test_a_bad_target_disables_the_start_button(self):
        html = dashboard_html()

        body = html.split("function renderScanEstimate(", 1)[1].split("\n    }", 1)[0]
        self.assertIn("disabled", body)
```

- [ ] **Step 2: 테스트를 돌려 실패를 확인한다**

Run: `python -m unittest tests.test_dashboard -v`
Expected: FAIL — `function estimateScanScale(` not found.

- [ ] **Step 3: 요약 영역을 추가한다**

시작 버튼을 감싼 요소 바로 앞에 넣는다 (`grep -n 'scanSubmit\|type="submit"' netroach/static/dashboard.html`로 위치를 찾는다):

```html
                  <p class="scan-estimate" id="scanEstimate"></p>
```

```css
    .scan-estimate { font-size: 12px; color: var(--muted); margin: 4px 0 8px; min-height: 16px; }
    .scan-estimate.bad { color: var(--state-error); }
```

- [ ] **Step 4: 추정 로직을 추가한다**

```js
    // A /8 has 16 million addresses; counting them exactly would freeze the
    // page and the scanner refuses ranges that size anyway.
    const TARGET_COUNT_CEILING = 65536;
    // Measured against the default concurrency on the machine this was built
    // for. It is a rough guide, not a promise.
    const PROBES_PER_SECOND = 640;

    function expandTargetCount(expression) {
      const item = text(expression).trim();
      if (!item) return 0;
      const slash = item.indexOf('/');
      if (slash < 0) return 1;
      const prefix = Number(item.slice(slash + 1));
      if (!Number.isFinite(prefix)) throw new Error(`잘못된 CIDR: ${item}`);
      const width = item.includes(':') ? 128 : 32;
      if (prefix < 0 || prefix > width) throw new Error(`잘못된 CIDR: ${item}`);
      const bits = width - prefix;
      return bits >= 32 ? TARGET_COUNT_CEILING : Math.min(TARGET_COUNT_CEILING, 2 ** bits);
    }

    function estimateScanScale() {
      const targets = asList($('scanTargets').value);
      if (!targets.length) return {error: '대상을 입력하세요'};
      let hosts = 0;
      try {
        targets.forEach((item) => { hosts += expandTargetCount(item); });
      } catch (err) {
        return {error: err.message};
      }
      let ports = 0;
      try {
        ports = parsePortExpression($('scanPorts').value).ports.length;
      } catch (err) {
        return {error: `포트: ${err.message}`};
      }
      const probes = hosts * ports;
      return {hosts, ports, probes, seconds: Math.max(1, Math.round(probes / PROBES_PER_SECOND))};
    }

    function renderScanEstimate() {
      const node = $('scanEstimate');
      const estimate = estimateScanScale();
      const submit = $('scanForm').querySelector('button[type="submit"]');
      if (estimate.error) {
        node.textContent = estimate.error;
        node.classList.add('bad');
        if (submit) submit.disabled = true;
        return;
      }
      node.classList.remove('bad');
      node.textContent = `호스트 ${estimate.hosts.toLocaleString()}개 · 포트 ${estimate.ports.toLocaleString()}개 = ${estimate.probes.toLocaleString()} 프로브 · 예상 ${estimate.seconds}초`;
      if (submit) submit.disabled = !$('scanAuthorized').checked;
    }

    $('scanTargets').addEventListener('blur', renderScanEstimate);
    $('scanPorts').addEventListener('change', renderScanEstimate);
    $('scanAuthorized').addEventListener('change', renderScanEstimate);
```

`parsePortExpression()`의 반환 형태를 확인하고 `.ports` 키 이름을 맞춘다:

```bash
sed -n '/function parsePortExpression/,/^    }/p' netroach/static/dashboard.html | tail -12
```

`applyScanPreset()` 끝, `updateScanActionState()` 호출 뒤에 `renderScanEstimate();`를 추가한다. 초기화 구간의 `updateScanActionState();` 다음에도 추가한다.

기존 `updateScanActionState()`가 시작 버튼의 `disabled`를 따로 만지고 있으면, 두 함수가 서로 덮어쓰지 않도록 `updateScanActionState()`에서 버튼 잠금 부분을 제거하고 `renderScanEstimate()`가 단독으로 결정하게 한다.

- [ ] **Step 5: 테스트를 돌려 통과를 확인한다**

Run: `python -m unittest tests.test_dashboard -v`
Expected: PASS

- [ ] **Step 6: 브라우저에서 순수 함수를 실제로 검증한다**

콘솔에서:

```js
expandTargetCount('192.168.0.0/24') === 256 &&
expandTargetCount('10.0.0.1') === 1 &&
(() => { try { expandTargetCount('10.0.0.0/99'); return false; } catch (e) { return true; } })()
```

`true`가 나와야 한다. 이어서 대상에 `192.168.0.0/24`, 포트에 `1-100`을 넣고 포커스를 뺐을 때 `호스트 256개 · 포트 100개 = 25,600 프로브`가 뜨는지, 대상에 `999.1.1.1/99`를 넣으면 시작 버튼이 잠기는지 확인한다.

- [ ] **Step 7: 커밋**

```bash
git add netroach/static/dashboard.html tests/test_dashboard.py
git commit -m "feat(ui): validate targets on blur and show the scan scale before starting"
```

---

### Task 6: 2단 레이아웃과 실시간 결과

스캔 화면을 명령 패널(380px) + 결과로 나누고, 결과를 호스트 단위 실시간 목록으로 만든다.

**Files:**
- Modify: `netroach/static/dashboard.html:737-...` (`<section class="view" id="view-scans">`의 `.layout-two.scan-layout`)
- Modify: `netroach/static/dashboard.html:2078-...` (`renderScanResults()`)
- Test: `tests/test_dashboard.py`

**Interfaces:**
- Consumes: Task 2의 `state.runningProgress`, 기존 `state.scanResultPayload`(`{results, total, hosts}`), `refreshScanResults()`, `pill()`, `stateClass()`
- Produces:
  - `function groupResultsByHost(results)` → `[{host, open: [port...], total, error, done}]` — 순수 함수, `open`이 있는 호스트가 앞에 오도록 정렬
  - `function renderHostRows()` — `#scanHostRows`를 변경된 줄만 교체하는 방식으로 갱신
  - `state.resultTab` (`'hosts' | 'ports' | 'log'`), `state.autoScroll` (불리언)

- [ ] **Step 1: 실패하는 테스트를 쓴다**

```python
class DashboardResultPaneTests(unittest.TestCase):
    def test_scan_screen_is_a_command_pane_and_a_result_pane(self):
        html = dashboard_html()

        self.assertIn('class="scan-shell"', html)
        self.assertIn('class="command-pane"', html)
        self.assertIn('class="result-pane"', html)

    def test_host_rows_are_grouped_and_open_hosts_come_first(self):
        html = dashboard_html()

        self.assertIn("function groupResultsByHost(", html)
        self.assertIn("function renderHostRows(", html)
        self.assertIn('id="scanHostRows"', html)
        body = html.split("function groupResultsByHost(", 1)[1].split("\n    }", 1)[0]
        self.assertIn("sort(", body)

    def test_result_tabs_exist(self):
        html = dashboard_html()

        for tab in ("data-result-tab=\"hosts\"", "data-result-tab=\"ports\"", "data-result-tab=\"log\""):
            self.assertIn(tab, html)

    def test_scrolling_up_pins_the_list(self):
        html = dashboard_html()

        self.assertIn('id="scanNewResults"', html)
        self.assertIn("state.autoScroll", html)

    def test_offscreen_rows_are_not_rendered_for_large_scans(self):
        html = dashboard_html()

        self.assertIn("HOST_ROW_RENDER_LIMIT", html)
```

- [ ] **Step 2: 테스트를 돌려 실패를 확인한다**

Run: `python -m unittest tests.test_dashboard -v`
Expected: FAIL — `class="scan-shell"` not found.

- [ ] **Step 3: 레이아웃 마크업을 바꾼다**

`<div class="layout-two scan-layout">`를 `<div class="scan-shell">`로 바꾸고, 안의 첫 `<section class="band">`(새 스캔 폼)에 `command-pane` 클래스를, 결과 쪽 컨테이너에 `result-pane` 클래스를 준다. 결과 영역 상단에 탭과 호스트 목록을 넣는다:

```html
            <section class="band result-pane">
              <div class="result-tabs">
                <button type="button" data-result-tab="hosts" class="active">호스트</button>
                <button type="button" data-result-tab="ports">열린 포트</button>
                <button type="button" data-result-tab="log">로그</button>
                <span class="result-progress" id="scanMetrics"></span>
              </div>
              <button type="button" class="new-results" id="scanNewResults" hidden>새 결과 ↓</button>
              <div class="host-rows" id="scanHostRows"></div>
              ...기존 결과 테이블/필터는 '열린 포트' 탭 아래로 옮긴다...
            </section>
```

```css
    .scan-shell { display: flex; gap: 12px; align-items: flex-start; }
    .command-pane { flex: 0 0 380px; max-width: 380px; }
    .result-pane { flex: 1 1 auto; min-width: 0; }
    .result-tabs { display: flex; align-items: center; gap: 4px; padding: 8px 12px; border-bottom: 1px solid var(--line); }
    .result-tabs button { height: 28px; border: 0; background: transparent; color: var(--muted); }
    .result-tabs button.active { color: var(--accent); box-shadow: inset 0 -2px 0 var(--accent); }
    .result-progress { margin-left: auto; font-size: 12px; color: var(--muted); }
    .host-rows { max-height: 62vh; overflow-y: auto; }
    .host-row {
      display: flex;
      align-items: center;
      gap: 12px;
      height: 30px;
      padding: 0 12px;
      font-size: 12px;
      border-bottom: 1px solid var(--line);
    }
    .host-row .host-name { flex: 0 0 180px; font-family: ui-monospace, monospace; }
    .host-row .host-open { flex: 1 1 auto; font-family: ui-monospace, monospace; color: var(--state-open); }
    .host-row .host-state { flex: 0 0 90px; text-align: right; color: var(--muted); }
    .host-row.fresh { animation: rowFresh 600ms ease; }
    @keyframes rowFresh { from { background: var(--accent-soft); } to { background: transparent; } }
    .new-results { position: sticky; top: 0; z-index: 2; width: 100%; height: 26px; font-size: 12px; }
    @media (prefers-reduced-motion: reduce) { .host-row.fresh { animation: none; } }
    @media (max-width: 1100px) {
      .scan-shell { flex-direction: column; }
      .command-pane { flex: 1 1 auto; max-width: none; width: 100%; }
    }
```

- [ ] **Step 4: 그룹핑과 렌더러를 추가한다**

```js
    // Rendering every row of a /16 would stall a weak machine; the operator
    // only ever reads the top of the list, and open hosts are sorted there.
    const HOST_ROW_RENDER_LIMIT = 200;

    function groupResultsByHost(results) {
      const byHost = new Map();
      (results || []).forEach((row) => {
        const entry = byHost.get(row.host) || {host: row.host, open: [], total: 0, error: 0};
        entry.total += 1;
        if (row.state === 'open') entry.open.push(row.port);
        if (row.state === 'error') entry.error += 1;
        byHost.set(row.host, entry);
      });
      const rows = [...byHost.values()];
      rows.forEach((entry) => entry.open.sort((a, b) => a - b));
      // Open hosts first: in a 254-address sweep the three that matter should
      // never be below the fold.
      return rows.sort((a, b) => (b.open.length ? 1 : 0) - (a.open.length ? 1 : 0));
    }

    function renderHostRows() {
      const container = $('scanHostRows');
      const rows = groupResultsByHost(state.scanResultPayload.results).slice(0, HOST_ROW_RENDER_LIMIT);
      const seen = new Set();
      rows.forEach((entry) => {
        seen.add(entry.host);
        const id = `host-${entry.host.replace(/[^a-zA-Z0-9]/g, '-')}`;
        const openText = entry.open.length ? `open ${entry.open.join(',')}` : '';
        const stateText = entry.error ? '오류' : '완료';
        let node = document.getElementById(id);
        if (!node) {
          node = document.createElement('div');
          node.id = id;
          node.className = 'host-row';
          container.appendChild(node);
        }
        const html = `<span class="host-name">${escapeHtml(entry.host)}</span><span class="host-open">${escapeHtml(openText)}</span><span class="host-state">${escapeHtml(stateText)}</span>`;
        // Replace only what changed: a full redraw at 700ms would fight the
        // scroll position and burn CPU on a machine that has none to spare.
        if (node.innerHTML !== html) {
          const gainedOpen = entry.open.length && !node.dataset.open;
          node.innerHTML = html;
          node.dataset.open = entry.open.length ? '1' : '';
          if (gainedOpen) {
            node.classList.remove('fresh');
            void node.offsetWidth;
            node.classList.add('fresh');
          }
        }
      });
      [...container.children].forEach((node) => {
        if (!seen.has(node.querySelector('.host-name')?.textContent)) node.remove();
      });
      if (state.autoScroll) container.scrollTop = container.scrollHeight;
      $('scanNewResults').hidden = state.autoScroll;
    }

    $('scanHostRows').addEventListener('scroll', (event) => {
      const node = event.currentTarget;
      state.autoScroll = node.scrollHeight - node.scrollTop - node.clientHeight < 24;
      $('scanNewResults').hidden = state.autoScroll;
    });
    $('scanNewResults').addEventListener('click', () => {
      state.autoScroll = true;
      $('scanHostRows').scrollTop = $('scanHostRows').scrollHeight;
      $('scanNewResults').hidden = true;
    });

    document.querySelectorAll('[data-result-tab]').forEach((node) => {
      node.addEventListener('click', () => {
        state.resultTab = node.dataset.resultTab;
        document.querySelectorAll('[data-result-tab]').forEach((tab) => tab.classList.toggle('active', tab === node));
        renderScanResults();
      });
    });
```

`state`에 추가:

```js
      resultTab: 'hosts',
      autoScroll: true,
```

`renderScanResults()` 시작부에 탭 분기를 넣는다:

```js
      $('scanHostRows').hidden = state.resultTab !== 'hosts';
      if (state.resultTab === 'hosts') {
        renderHostRows();
        return;
      }
```

`hosts` 탭이 아닐 때는 기존 테이블 렌더링이 그대로 돌아간다.

- [ ] **Step 5: 테스트를 돌려 통과를 확인한다**

Run: `python -m unittest tests.test_dashboard -v`
Expected: PASS

- [ ] **Step 6: 브라우저에서 확인한다**

콘솔에서 그룹핑을 직접 검증한다:

```js
JSON.stringify(groupResultsByHost([
  {host: 'b', port: 1, state: 'closed'},
  {host: 'a', port: 80, state: 'open'},
  {host: 'a', port: 22, state: 'open'}
])) === '[{"host":"a","open":[22,80],"total":2,"error":0},{"host":"b","open":[],"total":1,"error":0}]'
```

`true`여야 한다. 이어서 `192.168.0.0/24` 스캔을 시작하고: 줄이 실시간으로 늘어나는지, 열린 포트가 있는 호스트가 위로 오는지, 새로 열린 포트가 잠깐 강조되는지, 목록을 위로 스크롤하면 자동 스크롤이 멈추고 `새 결과 ↓` 버튼이 뜨는지 확인한다. 창을 1000px로 좁혀 두 칸이 위아래로 쌓이는지도 본다.

- [ ] **Step 7: 커밋**

```bash
git add netroach/static/dashboard.html tests/test_dashboard.py
git commit -m "feat(ui): two-pane scan screen with live per-host results"
```

---

### Task 7: 단축키

**Files:**
- Modify: `netroach/static/dashboard.html` — 전역 `keydown` 핸들러, `?` 오버레이 마크업
- Test: `tests/test_dashboard.py`

**Interfaces:**
- Consumes: Task 4의 `allScanPresets()`/`applyScanPreset()`, 기존 `showView()`, `closeViewer()`
- Produces: `function isTypingTarget(node)` → 불리언 — `input`/`textarea`/`select`/`contenteditable`이면 참. `function handleShortcut(event)` — 전역 키 핸들러.

- [ ] **Step 1: 실패하는 테스트를 쓴다**

```python
class DashboardShortcutTests(unittest.TestCase):
    def test_shortcut_handler_and_help_overlay_exist(self):
        html = dashboard_html()

        self.assertIn("function handleShortcut(", html)
        self.assertIn("function isTypingTarget(", html)
        self.assertIn('id="shortcutHelp"', html)

    def test_every_documented_shortcut_is_handled(self):
        html = dashboard_html()
        body = html.split("function handleShortcut(", 1)[1].split("\n    }\n", 1)[0]

        for key in ("'t'", "'g'", "'?'", "'Escape'", "ctrlKey"):
            self.assertIn(key, body)

    def test_single_key_shortcuts_do_not_fire_while_typing(self):
        html = dashboard_html()
        body = html.split("function handleShortcut(", 1)[1].split("\n    }\n", 1)[0]

        self.assertIn("isTypingTarget(", body)
```

- [ ] **Step 2: 테스트를 돌려 실패를 확인한다**

Run: `python -m unittest tests.test_dashboard -v`
Expected: FAIL — `function handleShortcut(` not found.

- [ ] **Step 3: 도움말 오버레이를 추가한다**

`#viewer` 옆에 넣는다:

```html
  <div class="viewer" id="shortcutHelp" hidden role="dialog" aria-modal="true" aria-label="단축키">
    <div class="viewer-panel">
      <div class="viewer-head"><h3>단축키</h3><button type="button" id="shortcutHelpClose">닫기</button></div>
      <div class="viewer-body">
        <dl class="shortcut-list">
          <dt>1 ~ 9</dt><dd>프리셋 선택</dd>
          <dt>Ctrl + Enter</dt><dd>스캔 시작</dd>
          <dt>t</dt><dd>대상 칸으로 이동</dd>
          <dt>g 다음 s / p / r</dt><dd>화면 이동 (스캔 / 패킷 / 리포트)</dd>
          <dt>Esc</dt><dd>오버레이 닫기</dd>
          <dt>?</dt><dd>이 목록</dd>
        </dl>
      </div>
    </div>
  </div>
```

```css
    .shortcut-list { display: grid; grid-template-columns: 160px 1fr; gap: 6px 16px; padding: 14px; font-size: 13px; }
    .shortcut-list dt { font-family: ui-monospace, monospace; color: var(--accent); }
    .shortcut-list dd { margin: 0; color: var(--muted); }
```

- [ ] **Step 4: 핸들러를 추가한다**

기존 `document.addEventListener('keydown', ...)`(Escape로 뷰어를 닫는 것) 자리를 아래로 대체한다:

```js
    function isTypingTarget(node) {
      if (!node) return false;
      const tag = node.tagName;
      return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || node.isContentEditable;
    }

    let pendingGoto = false;

    // Single-key shortcuts must never steal a character from a field: the
    // target box is the one thing an operator types into constantly.
    function handleShortcut(event) {
      if (event.key === 'Escape') {
        pendingGoto = false;
        if (!$('shortcutHelp').hidden) { $('shortcutHelp').hidden = true; return; }
        if (!$('viewer').hidden) { closeViewer(); return; }
        const advanced = $('scanAdvanced');
        if (advanced && advanced.open) advanced.open = false;
        return;
      }
      if (event.ctrlKey && event.key === 'Enter') {
        event.preventDefault();
        if (!$('scanAuthorized').checked) {
          $('scanAuthorized').focus();
          $('scanAuthorized').closest('.authorization-box')?.classList.add('nudge');
          setTimeout(() => $('scanAuthorized').closest('.authorization-box')?.classList.remove('nudge'), 400);
          return;
        }
        $('scanForm').requestSubmit();
        return;
      }
      if (event.ctrlKey || event.altKey || event.metaKey || isTypingTarget(event.target)) return;

      if (pendingGoto) {
        pendingGoto = false;
        const destination = {s: 'scans', p: 'packets', r: 'overview'}[event.key];
        if (destination) { event.preventDefault(); showView(destination); }
        return;
      }
      if (event.key === 'g') { pendingGoto = true; return; }
      if (event.key === '?') { event.preventDefault(); $('shortcutHelp').hidden = false; return; }
      if (event.key === 't') {
        event.preventDefault();
        showView('scans');
        $('scanTargets').focus();
        $('scanTargets').select();
        return;
      }
      if (/^[1-9]$/.test(event.key)) {
        const preset = allScanPresets()[Number(event.key) - 1];
        if (preset) { event.preventDefault(); applyScanPreset(preset); }
      }
    }

    document.addEventListener('keydown', handleShortcut);
    $('shortcutHelpClose').addEventListener('click', () => { $('shortcutHelp').hidden = true; });
```

```css
    .authorization-box.nudge { animation: nudge 320ms ease; }
    @keyframes nudge { 0%,100% { transform: translateX(0); } 25% { transform: translateX(-4px); } 75% { transform: translateX(4px); } }
    @media (prefers-reduced-motion: reduce) { .authorization-box.nudge { animation: none; outline: 2px solid var(--state-error); } }
```

`r` 는 리포트 화면이 별도로 없으면 `overview`로 보낸다. 화면 id는 `grep -n 'data-view-target=' netroach/static/dashboard.html`로 확인해 실제 존재하는 값만 매핑한다.

- [ ] **Step 5: 테스트를 돌려 통과를 확인한다**

Run: `python -m unittest tests.test_dashboard -v`
Expected: PASS

- [ ] **Step 6: 브라우저에서 확인한다**

대상 칸에 커서를 두고 `1`, `t`, `g`, `?`를 친다 → 전부 그냥 글자로 입력되고 단축키가 발동하지 않아야 한다. 칸 밖을 클릭한 뒤 같은 키를 누르면 각각 동작해야 한다. 권한 확인을 끈 채 `Ctrl+Enter`를 누르면 스캔이 시작되지 않고 체크박스가 흔들린다.

- [ ] **Step 7: 커밋**

```bash
git add netroach/static/dashboard.html tests/test_dashboard.py
git commit -m "feat(ui): keyboard shortcuts that never steal a keystroke from a field"
```

---

### Task 8: 마감 — 시각 정리와 전체 점검

남은 시각 규칙(등폭 값, 선 대신 면, 4px 간격 배수)을 적용하고 전체 스위트를 돌린다.

**Files:**
- Modify: `netroach/static/dashboard.html` (CSS 전반)
- Test: `tests/test_dashboard.py`

**Interfaces:**
- Consumes: Task 1-7의 결과 전부
- Produces: 없음 (마감 작업)

- [ ] **Step 1: 실패하는 테스트를 쓴다**

```python
class DashboardSelfContainmentTests(unittest.TestCase):
    def test_nothing_is_loaded_from_outside(self):
        """A strict desktop shell and an offline operator both need this."""
        html = dashboard_html()

        self.assertNotRegex(html, r'(?:src|href)\s*=\s*"https?://')
        self.assertNotIn("@import", html)
        self.assertNotIn("fonts.googleapis", html)

    def test_values_are_monospaced_and_motion_is_optional(self):
        html = dashboard_html()

        self.assertIn("ui-monospace", html)
        self.assertIn("@media (prefers-reduced-motion: reduce)", html)
```

- [ ] **Step 2: 테스트를 돌려 실패를 확인한다**

Run: `python -m unittest tests.test_dashboard -v`
Expected: 두 테스트 중 최소 하나가 FAIL하거나, 이미 통과한다면 다음 단계로 넘어간다.

- [ ] **Step 3: 시각 규칙을 적용한다**

- `.mono` 클래스의 폰트를 `ui-monospace, SFMono-Regular, Menlo, Consolas, monospace`로 통일하고, 대상·포트·IP·스캔 id를 표시하는 자리에 `.mono`가 빠진 곳을 채운다.
- 카드/밴드의 `border: 1px solid var(--line)`을 배경 대비로 대체한다: `.band { background: var(--surface); border: 0; }`, 컨테이너 배경은 `var(--bg)`. 구분이 필요한 가로선만 남긴다.
- 라벨(`label`, `.field-label`, `.helper`)을 `font-size: 12px; color: var(--muted);`로, 값은 `font-size: 13px; color: var(--fg);`로 맞춘다.
- `padding`/`margin`/`gap` 중 4의 배수가 아닌 값을 가장 가까운 4의 배수로 올린다. 높이 값은 건드리지 않는다 (밀도 유지).

- [ ] **Step 4: 전체 스위트를 돌린다**

```bash
python -m unittest discover -s tests
python -m ruff check .
python -m mypy
```

셋 다 통과해야 한다. 대시보드는 Python 코드가 아니므로 ruff/mypy 결과는 Task 4에서 삭제한 함수들 때문에 바뀌지 않아야 한다 — 바뀐다면 지우면 안 될 것을 지운 것이다.

- [ ] **Step 5: 브라우저에서 전체를 확인한다**

여덟 개 화면을 모두 열어 레이아웃이 깨진 곳이 없는지 본다. 스캔 한 건을 처음부터 끝까지 돌린다: 프리셋 선택 → 대상 입력 → 예상치 확인 → 권한 확인 → `Ctrl+Enter` → 진행 띠 → 실시간 결과 → 리포트 미리보기 → 증적 이미지 보기 → export 미리보기. 마지막 세 가지는 기존 기능이며, 오버레이로 열려야 한다(새 창 금지).

- [ ] **Step 6: 커밋**

```bash
git add netroach/static/dashboard.html tests/test_dashboard.py
git commit -m "style(ui): monospaced values, surfaces instead of borders, 4px rhythm"
```

---

### Task 9: 데스크톱 설치본 재빌드

UI 변경분과 (아직 설치본에 없는) pktmon 백엔드를 포함해 설치본을 다시 만든다.

**Files:**
- 변경 없음 (빌드만)

**Interfaces:**
- Consumes: Task 1-8의 결과
- Produces: 없음

- [ ] **Step 1: 기존 산출물을 확인한다**

```bash
ls dist desktop/src-tauri/target/release/bundle 2>/dev/null
```

- [ ] **Step 2: 패키징 스모크를 먼저 돌린다**

```bash
python tools/package.py --output-dir dist-smoke
python tools/smoke_package.py dist-smoke
```

- [ ] **Step 3: 설치본을 빌드한다**

프로젝트의 빌드 스크립트를 쓴다. 정확한 명령은 `docs/`의 패키징 문서에서 확인한다:

```bash
grep -rn 'tauri build\|nsis\|installer' docs/ tools/ --include='*.md' --include='*.py' | head
```

- [ ] **Step 4: 설치본에서 UI를 확인한다**

설치본을 실행해 새 레이아웃이 나오는지, 리포트·증적·export 오버레이가 동작하는지 확인한다. 데스크톱 셸은 웹뷰라 새 창 이동이 죽으므로 이 확인은 브라우저 확인을 대체하지 않는다.

- [ ] **Step 5: 커밋 및 푸시**

```bash
git push origin HEAD
```

---

## 자체 점검 결과

**스펙 대응:** 셸 구조 → Task 1·6. 프리셋 → Task 4. 입력 검증 → Task 5. 진행 띠 → Task 2. 실시간 결과 → Task 6. 갱신 방식 → Task 3. 실패 처리 → Task 2(`err`)·Task 6(호스트 오류 줄). 단축키 → Task 7. 시각 언어 → Task 1·8. 테스트 → 각 Task의 Step 1 및 Task 8. 좁은 창 → Task 6의 미디어 쿼리. 프리셋 12개 한도 → Task 4.

**스펙에 없어 계획에서 정한 것:**
- `PROBES_PER_SECOND = 640` — 예상 소요 시간의 기준. 안내용 추정치이며 약속이 아님을 코드 주석에 남긴다.
- `TARGET_COUNT_CEILING = 65536` — `/8` 같은 범위를 정확히 세면 화면이 멈춘다.
- `HOST_ROW_RENDER_LIMIT = 200` — 스펙의 "호스트 200개 넘으면 화면 밖 줄 렌더 생략"을 상수로 고정.
- 기존 포트 프리셋 버튼과 `netroach.customPortProfiles.v1` 저장소는 새 프리셋이 대체하므로 제거한다. TXT 가져오기는 남긴다.
- Task 9(설치본 재빌드)는 스펙 범위 밖이지만 이번 변경이 사용자에게 닿으려면 필요하다.
