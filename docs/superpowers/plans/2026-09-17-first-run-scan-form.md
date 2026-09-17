# 처음 쓰는 사람을 위한 스캔 폼 — 구현 계획

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 스캔 폼의 첫 화면을 다섯 가지로 줄이고, 재수집을 작업 탭으로 옮기고, 웹 증적이 화면이 멈춘 뒤에 찍히게 하고, 느려지는 결과 조회를 잴 수 있게 한다.

**Architecture:** 대시보드는 `netroach/static/dashboard.html` 한 파일(HTML+CSS+JS)이고, 백엔드는 FastAPI(`netroach/api.py`), 증적 캡처는 `netroach/evidence.py`(Playwright)와 `netroach/console_capture.py`다. API는 바꾸지 않는다 — `screenshot_max: null`과 `missing_only`는 이미 있다. 대시보드 테스트는 HTML 문자열을 검사하는 `tests/test_dashboard.py`, 캡처 테스트는 가짜 Playwright 페이지를 쓰는 `tests/test_evidence.py`다.

**Tech Stack:** Python 3.14, FastAPI, Playwright(Chromium), Pillow, 바닐라 JS. 도구: `.venv/Scripts/python.exe -m pytest`, `.venv/Scripts/ruff.exe`, `.venv/Scripts/mypy.exe`. 브라우저 실측은 `PLAYWRIGHT_BROWSERS_PATH=desktop/src-tauri/target/release/resources/playwright`.

설계: `docs/superpowers/specs/2026-09-17-first-run-scan-form-design.md`

## Global Constraints

- API 변경 없음. `EvidenceRecaptureRequest`·`ScanCreateRequest`의 필드는 그대로.
- 대시보드 문구는 한국어, 기존 어조(짧은 서술문, 마침표) 유지.
- 대시보드 HTML을 검사하는 테스트는 문자열 일치라, 바꾸는 문자열이 있으면 그 테스트도 같은 태스크에서 고친다.
- 커밋 메시지 끝에 `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`.
- 작업 트리에 미커밋 변경(403/404 웹 캡처 수정: `netroach/evidence.py`, `tests/test_evidence.py`)이 있다. Task 0에서 먼저 커밋한다.
- 실제 스캔 대상은 `127.0.0.1`뿐. 다른 주소로 스캔·캡처하지 않는다.

---

## 파일 구조

| 파일 | 책임 | 바뀌는 것 |
|---|---|---|
| `netroach/evidence.py` | 웹 스크린샷 | 화면이 멈출 때까지 기다리는 루프 (Task 1) |
| `netroach/api.py` | HTTP API | `Server-Timing` 미들웨어 (Task 2) |
| `netroach/static/dashboard.html` | 대시보드 | 조회 시간 측정과 진단 표 (Task 3), 재수집 이동 (Task 4), 폼 재구성 (Task 5) |
| `tests/test_evidence.py` | 캡처 테스트 | Task 1 |
| `tests/test_api.py` | API 테스트 | Task 2 |
| `tests/test_dashboard.py` | HTML 검사 | Task 3, 4, 5 |

---

### Task 0: 미커밋된 403/404 수정을 먼저 커밋

**Files:**
- Modify (이미 수정됨): `netroach/evidence.py`, `tests/test_evidence.py`

- [ ] **Step 1: 상태 확인**

Run: `git status --short`
Expected: ` M netroach/evidence.py` 와 ` M tests/test_evidence.py` 두 줄만.

- [ ] **Step 2: 테스트**

Run: `.venv/Scripts/python.exe -m pytest tests/test_evidence.py -q`
Expected: 전부 통과 (`test_a_page_chromium_drew_about_the_failure_is_still_the_evidence` 포함).

- [ ] **Step 3: 커밋**

```bash
git add netroach/evidence.py tests/test_evidence.py
git commit -m "fix(evidence): photograph the page Chromium draws about a failed navigation

An error status with no body is a failed navigation to Chromium: it raises
ERR_HTTP_RESPONSE_CODE_FAILURE and Playwright raises with it, so a
management port answering 403 with nothing after it fell to the console
capture and was photographed as a netstat line. Found in a real
assessment's capture errors beside ERR_SSL_VERSION_OR_CIPHER_MISMATCH and
ERR_SSL_PROTOCOL_ERROR on the same hosts. For all three Chromium draws its
own page naming the problem - the address bar and \"HTTP ERROR 403\" - which
is what an operator opening the address sees, so it is the evidence. That
page is Chromium's, not the target's: nothing on it to still, and it is
still being swapped in when the call returns, so the screenshot waits a
moment and goes through the compositor. The address kept is the one asked
for; Chromium reports its error page as about:blank.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 1: 웹 캡처는 화면이 멈춘 뒤에

**Files:**
- Modify: `netroach/evidence.py` (goto 뒤 ~ store 앞, 현재 532-570행 부근)
- Test: `tests/test_evidence.py` (`ScreenshotRetryTests` 클래스, `FakePage`)

**Interfaces:**
- Produces: `WEB_SETTLE_POLL_S = 0.4`, `WEB_SETTLE_STILL_PIXELS = 400`, `_screenshot_when_settled(page, left_ms) -> bytes`

- [ ] **Step 1: 실패하는 테스트 — 두 프레임 뒤에 멈추는 페이지는 세 번째 사진이 저장된다**

`tests/test_evidence.py`의 `FakePage`에 프레임 시퀀스를 추가한다. 기존 `screenshot()`은 고정 바이트를 돌려주므로 `frames` 목록을 받아 순서대로 돌려주게 한다:

```python
class FakePage:
    def __init__(self, screenshot_failures: int, goto_failures: int = 0, frames: list[bytes] | None = None):
        self.screenshot_failures = screenshot_failures
        self.goto_failures = goto_failures
        self.frames = list(frames or [])
        ...

    def screenshot(self, **_kwargs):
        self.screenshot_calls += 1
        if self.screenshot_calls <= self.screenshot_failures:
            raise RuntimeError("Protocol error (Page.captureScreenshot): Unable to capture screenshot")
        if self.frames:
            index = min(self.screenshot_calls - self.screenshot_failures, len(self.frames)) - 1
            return self.frames[index]
        return b"\x89PNG\r\n\x1a\nimage"
```

`ScreenshotRetryTests`에 테스트를 추가한다. 픽셀 비교는 `_changed_pixels`를 패치해 바이트가 같으면 0, 다르면 9,999로 만든다:

```python
    def test_the_page_is_photographed_once_it_stops_changing(self):
        """domcontentloaded is when the HTML arrived, not when the page is drawn.

        A management page that draws itself with script, or loads its login
        form after the shell, is a spinner at that moment - and the spinner
        was the evidence. The console panes already wait for their window to
        stop changing; the browser pane now does the same, within the port's
        budget.
        """
        from netroach import evidence as evidence_module

        loading, half, done = b"\x89PNG-loading", b"\x89PNG-half", b"\x89PNG-done"
        page = FakePage(screenshot_failures=0, frames=[loading, half, done, done, done])
        with (
            patch.object(evidence_module, "_capture_browser_window", return_value=None),
            patch.object(evidence_module, "_changed_pixels", lambda a, b: 0 if a == b else 9_999),
            patch.object(evidence_module.time, "sleep", lambda _s: None),
        ):
            summary, stored = self._capture(page)

        self.assertEqual(summary.captured, 1)
        self.assertEqual(stored[0][1], done, "the first frame that matched the one before it")
        self.assertEqual(page.screenshot_calls, 4, "loading, half, done, done - then it stopped")

    def test_a_page_that_never_settles_is_photographed_when_the_budget_runs_out(self):
        from netroach import evidence as evidence_module

        frames = [f"\x89PNG-{index}".encode() for index in range(50)]
        page = FakePage(screenshot_failures=0, frames=frames)
        clock = SimpleNamespace(now=0.0)

        def sleep(seconds):
            clock.now += seconds

        with (
            patch.object(evidence_module, "_capture_browser_window", return_value=None),
            patch.object(evidence_module, "_changed_pixels", lambda a, b: 0 if a == b else 9_999),
            patch.object(evidence_module.time, "sleep", sleep),
            patch.object(evidence_module.time, "monotonic", lambda: clock.now),
        ):
            summary, stored = self._capture(page)

        self.assertEqual(summary.captured, 1, "out of time is still a picture, as before")
        self.assertEqual(stored[0][1], frames[page.screenshot_calls - 1], "the last one seen")
        # Default timeout 8000ms x budget factor 2 = 16s; polled every 0.4s.
        self.assertLessEqual(page.screenshot_calls, 16_000 / 400 + 2)
```

`SimpleNamespace`는 이미 import되어 있다(`from types import SimpleNamespace`).

- [ ] **Step 2: 실패 확인**

Run: `.venv/Scripts/python.exe -m pytest tests/test_evidence.py -q -k "stops_changing or never_settles"`
Expected: FAIL — 첫 테스트는 `stored[0][1] == loading` (첫 프레임을 바로 저장), 둘째는 `screenshot_calls == 1`.

- [ ] **Step 3: 구현**

`netroach/evidence.py`에 상수와 함수를 추가한다. `SCREENSHOT_RETRY_DELAY_S = 0.4` 바로 아래:

```python
# How often the page is photographed while waiting for it to stop changing,
# and how many pixels may still differ between two takes for it to count as
# stopped - the console panes' figure, a cursor's worth. domcontentloaded is
# when the HTML arrived, not when the page is drawn: a management page that
# draws itself with script, or loads its login form after the shell, is a
# spinner at that moment, and the spinner was the picture. Bounded by the
# port's budget like everything else here; out of time keeps the last take,
# which is what a single take gave before.
WEB_SETTLE_POLL_S = 0.4
WEB_SETTLE_STILL_PIXELS = 400
```

`_screenshot_with_one_retry` 아래에:

```python
def _screenshot_when_settled(page: Any, left_ms: Callable[[], float]) -> bytes:
    """Photograph the page once two takes in a row agree, or when time runs out."""
    previous = _screenshot_with_one_retry(page, left_ms)
    while left_ms() > 0:
        time.sleep(WEB_SETTLE_POLL_S)
        current = _screenshot_with_one_retry(page, left_ms)
        if _changed_pixels(current, previous) <= WEB_SETTLE_STILL_PIXELS:
            return current
        previous = current
    return previous
```

`_changed_pixels`를 `console_capture`에서 가져온다 — 파일 상단 import 블록(20-30행)의 목록에 `_changed_pixels,`를 추가한다(알파벳 순서상 `OFFSCREEN_POSITION` 앞이 아니라, 밑줄 이름은 ruff isort가 놓는 자리에 맞춘다: `.venv/Scripts/ruff.exe check --fix netroach/evidence.py`로 정렬).

캡처 루프(현재 `image = _capture_browser_window(page, opened_before)` 부분)를 바꾼다:

```python
                        # Wait for the page to stop changing before either
                        # picture is taken; the window capture is the goal and
                        # the page screenshot the fallback, and both must be
                        # of a page that has finished drawing.
                        settled = _screenshot_when_settled(page, left_ms)
                        image = _capture_browser_window(page, opened_before)
                        if image is None:
                            image = settled
```

- [ ] **Step 4: 통과 확인**

Run: `.venv/Scripts/python.exe -m pytest tests/test_evidence.py -q`
Expected: 전부 PASS. 기존 `test_navigation_failures_are_not_retried`·`test_the_screenshot_is_retried_once`류가 `screenshot_calls` 수를 세고 있으면 새 루프에 맞게 기대값을 고친다 — 성공 경로는 최소 2회(첫 장 + 같은 두 번째 장)가 된다.

- [ ] **Step 5: 실제 Chromium으로 확인 — 3초 뒤에 내용을 그리는 페이지**

스크래치 스크립트(프로젝트 밖):

```python
import os, threading, time
from http.server import BaseHTTPRequestHandler, HTTPServer
os.environ["PLAYWRIGHT_BROWSERS_PATH"] = r"C:\Users\xxcxxcc\Desktop\scan\desktop\src-tauri\target\release\resources\playwright"
from netroach.evidence import capture_web_screenshots

PAGE = b"""<html><body><div id=s>Loading...</div>
<script>setTimeout(()=>{document.getElementById('s').innerHTML='<h1>Admin Console</h1><form><input placeholder=user><input type=password></form>'},3000)</script>
</body></html>"""
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type","text/html")
        self.send_header("Content-Length", str(len(PAGE))); self.end_headers(); self.wfile.write(PAGE)
    def log_message(self, *a): pass
threading.Thread(target=HTTPServer(("127.0.0.1", 5701), H).serve_forever, daemon=True).start()
time.sleep(0.3)
stored = []
t = time.monotonic()
capture_web_screenshots([{"host":"127.0.0.1","port":5701,"protocol":"tcp","state":"open","service_name":"http"}],
                        store=lambda r, data, name, url, agent: stored.append(data))
print(f"{time.monotonic()-t:.1f}s")
open(r"C:\Users\xxcxxcc\AppData\Local\Temp\claude\C--Users-xxcxxcc-Desktop-scan\8c688005-8d34-4aa3-be71-754cfac7aa25\scratchpad\settled.png","wb").write(stored[0])
```

Run: `PYTHONIOENCODING=utf-8 .venv/Scripts/python.exe <스크립트>` 그리고 `settled.png`를 Read로 본다.
Expected: 걸린 시간 4~5초, 그림에 `Admin Console`과 폼이 있고 `Loading...`이 없다.

- [ ] **Step 6: 커밋**

```bash
.venv/Scripts/ruff.exe check netroach tests && .venv/Scripts/mypy.exe netroach
git add netroach/evidence.py tests/test_evidence.py
git commit -m "fix(evidence): photograph a web page once it has stopped changing

domcontentloaded is when the HTML arrived, not when the page is drawn. A
management page that draws itself with script, or loads its login form
after the shell, is a spinner at that moment, and the spinner was the
picture - reported from use. The console panes already wait for their
window to stop changing; the browser pane now does the same, two takes
0.4 seconds apart within a cursor's worth of each other, bounded by the
port's budget. Out of time keeps the last take, which is what one take
gave before. Measured against a page that draws its console three seconds
in: the picture has the console.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 2: 모든 응답에 처리 시간 헤더

**Files:**
- Modify: `netroach/api.py` (`create_app` 안, `app = FastAPI(...)` 직후, 296행 부근)
- Test: `tests/test_api.py`

**Interfaces:**
- Produces: 모든 응답의 `Server-Timing: app;dur=<밀리초, 소수 1자리>` 헤더

- [ ] **Step 1: 실패하는 테스트**

`tests/test_api.py`에 (아무 클래스나 API 클라이언트를 만드는 곳 옆에) 추가:

```python
    def test_every_response_says_how_long_the_server_took(self):
        """A result view that gets slower over a session has been reported
        four times and never reproduced. The number that settles which side
        it is on has to be there when it happens, not asked for afterwards."""
        with tempfile.TemporaryDirectory() as tmp:
            client, _repo, scan_id = self._client_with_open_results(tmp)
            for path in ("/v1/health", "/v1/scans", f"/v1/scans/{scan_id}/results"):
                with self.subTest(path=path):
                    response = client.get(path)
                    self.assertEqual(response.status_code, 200)
                    timing = response.headers.get("server-timing", "")
                    self.assertRegex(timing, r"^app;dur=\d+(\.\d)?$")
```

`_client_with_open_results`는 `tests/test_api.py` 1903행의 헬퍼(같은 클래스 안에 두거나, 그 클래스에 추가한다).

- [ ] **Step 2: 실패 확인**

Run: `.venv/Scripts/python.exe -m pytest tests/test_api.py -q -k how_long_the_server_took`
Expected: FAIL — `server-timing` 헤더 없음.

- [ ] **Step 3: 구현**

`netroach/api.py`, `app = FastAPI(...)` 바로 다음 줄에:

```python
    # A result view that gets slower over a session has been reported four
    # times and never reproduced on a fresh backend. The number that says
    # which side it is on - the server's own time, against what the browser
    # measures around it - has to be on every response when it happens.
    @app.middleware("http")
    async def say_how_long_it_took(request: Request, call_next):
        began = time.perf_counter()
        response = await call_next(request)
        response.headers["Server-Timing"] = f"app;dur={(time.perf_counter() - began) * 1000:.1f}"
        return response
```

`time`과 `Request`는 이미 import되어 있는지 확인한다(`grep -n "^import time\|from fastapi import" netroach/api.py`). 없으면 추가한다.

- [ ] **Step 4: 통과 확인**

Run: `.venv/Scripts/python.exe -m pytest tests/test_api.py -q -k how_long_the_server_took`
Expected: PASS (3 subtests).

- [ ] **Step 5: 커밋**

```bash
.venv/Scripts/ruff.exe check netroach tests && .venv/Scripts/mypy.exe netroach
git add netroach/api.py tests/test_api.py
git commit -m "feat(api): say on every response how long the server took

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 3: 대시보드가 결과 조회 시간을 재서 진단 탭에 보여준다

**Files:**
- Modify: `netroach/static/dashboard.html` — `state` 객체(2183행), `refreshScanResults`(3657행), 진단 뷰 마크업(2121행 `view-diagnostics`), `renderDiagnostics`(4321행), `selectScan`(3205행)
- Test: `tests/test_dashboard.py`

**Interfaces:**
- Produces: `state.perf: Array<{at, scan, server, transfer, render, rows}>` (최근 30건), `recordResultTiming(entry)`, `renderResultTimings()`, 마크업 `id="diagnosticsTimings"`

- [ ] **Step 1: 실패하는 테스트**

`tests/test_dashboard.py`에 (진단 관련 테스트 클래스가 있으면 거기, 없으면 `DashboardHostViewTests`에):

```python
    def test_the_result_view_keeps_its_own_timings_for_the_diagnostics_tab(self):
        """Reported four times, never reproduced: the result view gets slower
        the longer the app runs. The three numbers that settle which side it
        is on are kept where the operator can read them when it happens."""
        html = dashboard_html()

        self.assertIn('id="diagnosticsTimings"', html)
        self.assertIn("function recordResultTiming(", html)
        self.assertIn("function renderResultTimings(", html)
        body = html.split("async function refreshScanResults(", 1)[1].split(chr(10) + "    }", 1)[0]
        self.assertIn("performance.now()", body)
        self.assertIn("recordResultTiming(", body)
        # The server's own number comes off the response header, not a guess.
        self.assertIn("serverTiming", html)
        self.assertIn("state.perf", html)
        self.assertIn("RESULT_TIMINGS_KEPT = 30", html)
```

- [ ] **Step 2: 실패 확인**

Run: `.venv/Scripts/python.exe -m pytest tests/test_dashboard.py -q -k own_timings`
Expected: FAIL — `diagnosticsTimings` 없음.

- [ ] **Step 3: 구현 — state와 기록 함수**

`const state = {` 안에 `perf: [],` 를 추가한다.

`renderDiagnostics` 함수 바로 앞에:

```javascript
    // The result view getting slower over a session has been reported four
    // times and never reproduced on a fresh backend. These are the three
    // numbers that settle which side it is on, kept for when it happens:
    // the server's own time from its Server-Timing header, the transfer
    // around it, and the render after it.
    const RESULT_TIMINGS_KEPT = 30;

    function recordResultTiming(entry) {
      state.perf.unshift(entry);
      if (state.perf.length > RESULT_TIMINGS_KEPT) state.perf.length = RESULT_TIMINGS_KEPT;
      console.debug('[netroach] results', entry);
      if (state.view === 'diagnostics') renderResultTimings();
    }

    // Same-origin responses expose their Server-Timing header on the
    // resource entry; this reads the one for the request just made.
    function serverTimingFor(path) {
      const entries = performance.getEntriesByType('resource');
      for (let index = entries.length - 1; index >= 0; index -= 1) {
        const entry = entries[index];
        if (!entry.name.includes(path)) continue;
        const app = (entry.serverTiming || []).find((item) => item.name === 'app');
        return app ? Math.round(app.duration) : null;
      }
      return null;
    }

    function renderResultTimings() {
      const rows = state.perf.map((item) => `<tr>
        <td>${escapeHtml(item.at)}</td><td>${escapeHtml(item.scan)}</td>
        <td>${item.server === null ? '–' : item.server.toLocaleString()}</td>
        <td>${item.transfer.toLocaleString()}</td><td>${item.render.toLocaleString()}</td>
        <td>${item.rows.toLocaleString()}</td></tr>`).join('');
      $('diagnosticsTimings').innerHTML = rows
        ? `<table class="cd-jobs-table"><thead><tr><th>시각</th><th>스캔</th><th>서버 ms</th><th>전송 ms</th><th>렌더 ms</th><th>행</th></tr></thead><tbody>${rows}</tbody></table>`
        : '<p class="hint">스캔을 선택하면 결과 조회에 걸린 시간이 여기 쌓입니다.</p>';
    }
```

`renderDiagnostics` 끝에 `renderResultTimings();` 한 줄을 추가한다.

- [ ] **Step 4: 구현 — 측정 지점**

`refreshScanResults` 안, `const payload = await api(...)` 앞뒤를 감싼다:

```javascript
      try {
        const path = `/v1/scans/${encodeURIComponent(scanId)}/results?${params}`;
        const fetchedAt = performance.now();
        const payload = await api(path);
        const transfer = performance.now() - fetchedAt;
        // Selection, filters and pages can change while an older request is pending.
        if (requestId !== state.scanResultsRequest || scanId !== state.scanId) return;
```

그리고 같은 함수에서 결과를 `state.scanResultPayload`에 넣고 `renderScanResults()`(또는 호스트 뷰 렌더)를 호출하는 지점 — 함수 끝부분을 읽어 정확한 줄을 찾는다 — 그 렌더 호출을 감싼다:

```javascript
        const renderedAt = performance.now();
        renderScanResults();
        recordResultTiming({
          at: new Date().toTimeString().slice(0, 8),
          scan: shortId(scanId),
          server: serverTimingFor(path),
          transfer: Math.round(transfer),
          render: Math.round(performance.now() - renderedAt),
          rows: Array.isArray(payload.results) ? payload.results.length : 0,
        });
```

`shortId`는 이미 있다(`selectScan`에서 사용). `renderScanResults()`가 여러 곳에서 불리면 이 함수 안의 호출만 감싼다.

- [ ] **Step 5: 구현 — 진단 뷰 마크업**

`view-diagnostics` 섹션의 첫 `<section class="band">` 뒤에 추가:

```html
          <section class="band">
            <div class="band-head"><h3>결과 조회 시간</h3></div>
            <div class="band-body">
              <p class="hint">스캔을 누를 때마다 결과를 불러오는 데 걸린 시간입니다. 느려졌다고 느껴질 때 어느 숫자가 커졌는지 보십시오 — 서버면 DB 쪽, 전송이면 응답 크기, 렌더면 화면 쪽입니다.</p>
              <div id="diagnosticsTimings"></div>
            </div>
          </section>
```

- [ ] **Step 6: 통과 확인 + 문법 확인**

Run: `.venv/Scripts/python.exe -m pytest tests/test_dashboard.py -q`
Run: `node -e "const fs=require('fs');const h=fs.readFileSync('netroach/static/dashboard.html','utf8');new Function(h.match(/<script>([\s\S]*)<\/script>/)[1]);console.log('JS OK')"`
Expected: 둘 다 통과.

- [ ] **Step 7: 실제 브라우저로 확인**

`preview_start {name: "netroach"}`로 서버를 띄우고(`.python-test/dashboard-preview.db`에 스캔이 몇 개 있어야 한다 — 없으면 `127.0.0.1`에 포트 몇 개 스캔을 하나 돌린다), 스캔 두 개를 클릭한 뒤 `javascript_tool`로 `state.perf`를 읽는다.
Expected: 항목 2개, `server`가 숫자(null 아님), `transfer`·`render`가 0 이상.

- [ ] **Step 8: 커밋**

```bash
git add netroach/static/dashboard.html tests/test_dashboard.py
git commit -m "feat(dashboard): keep the result view's own timings for the diagnostics tab

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 4: 재수집을 작업 탭 도구줄로

**Files:**
- Modify: `netroach/static/dashboard.html` — 도구줄 마크업(1770-1783행 `result-toolbar`), 폼의 `form-actions-secondary` 블록(1713-1724행) 삭제, `recaptureEvidence`(3271), `cancelRecapture`(3307), `fillFormWithOpenTargets`(3401), `updateScanActionState`(3459), `watchRecaptureProgress`(3330), 리스너 연결(4604행 부근), CSS `.form-actions-secondary`(452행)
- Test: `tests/test_dashboard.py` 591-641, 836-852행의 테스트

**Interfaces:**
- Consumes: 백엔드 `POST /v1/scans/{id}/evidence/recapture` body `{screenshot_max: null, capture_console, screenshot_timeout_ms, missing_only}`; `job.params`(작업 목록 응답에 실려 옴)
- Produces: 마크업 `id="scanRecaptureEvidence"`(버튼), `id="scanRecaptureAll"`(링크), `id="scanStopRecapture"`, `id="scanRescanOpen"`, `id="scanRecaptureStatus"`(상태 줄); 함수 `recaptureEvidence(missingOnly)`, `unphotographedOpenCount()`, `renderRecaptureHint()`

- [ ] **Step 1: 테스트를 새 구조에 맞게 고친다 (먼저 실패하게)**

`tests/test_dashboard.py`:

`test_the_two_result_actions_sit_with_the_settings_they_read`를 **교체**:

```python
    def test_the_actions_on_a_finished_scan_sit_with_its_results(self):
        """Recapture and rescan act on the scan the toolbar describes, not on
        the form - and a recapture that read the form's evidence settings
        had to be understood before it could be pressed. Now it reads the
        scan's own."""
        html = dashboard_html()

        form = html.split('<form id="scanForm">', 1)[1].split("</form>", 1)[0]
        self.assertNotIn('id="scanRecaptureEvidence"', form)
        self.assertNotIn('id="scanRescanOpen"', form)
        self.assertNotIn("form-actions-secondary", html)

        toolbar = html.split('class="toolbar result-toolbar"', 1)[1].split("band-head", 1)[0]
        for control in ("scanRecaptureEvidence", "scanRecaptureAll", "scanStopRecapture",
                        "scanRescanOpen", "scanRecaptureStatus", "scanCancel", "scanDelete"):
            self.assertIn(f'id="{control}"', toolbar)
```

`test_evidence_can_be_recaptured_without_scanning_again`을 **교체**:

```python
    def test_a_recapture_fills_the_gaps_with_the_scans_own_settings(self):
        """The button fills the ports that have no picture and leaves the rest;
        photographing every open port again is the link beside it. Both send
        the settings the scan itself ran with, not whatever the form holds."""
        html = dashboard_html()

        body = html.split("async function recaptureEvidence(", 1)[1].split(chr(10) + "    }", 1)[0]
        self.assertIn("missing_only: missingOnly", body)
        self.assertIn("screenshot_max: null", body)
        self.assertIn("job.params", body)
        self.assertIn("capture_console", body)
        self.assertIn("screenshot_timeout_ms", body)
        self.assertNotIn("form.get(", body)
        self.assertIn("$('scanRecaptureEvidence').addEventListener('click', () => recaptureEvidence(true))", html)
        self.assertIn("$('scanRecaptureAll').addEventListener('click'", html)
        self.assertIn("function unphotographedOpenCount(", html)
        self.assertIn("function renderRecaptureHint(", html)
```

`test_the_stop_is_its_own_button_not_the_start_one_relabelled`에서 두 줄을 고친다:

```python
        self.assertIn("$('scanRecaptureEvidence').addEventListener('click', () => recaptureEvidence(true))", html)
        ...
        self.assertIn("$('scanRecaptureEvidence').disabled = recapturing || !job || active;", html)
```

`test_rescanning_open_ports_fills_the_form_rather_than_starting`에 한 줄 추가:

```python
        self.assertIn("scrollIntoView", body)
```

기존 `test_the_evidence_limit_is_reachable_from_the_form`에서 `scanRecaptureMissingOnly` 두 줄은 이 태스크에서 지운다(체크박스가 없어진다). `scanScreenshotAll`·`screenshotLimit` 줄은 Task 5에서 다룬다.

- [ ] **Step 2: 실패 확인**

Run: `.venv/Scripts/python.exe -m pytest tests/test_dashboard.py -q`
Expected: 위 네 테스트 FAIL.

- [ ] **Step 3: 마크업 — 도구줄**

`result-toolbar`의 `작업` 그룹을 바꾼다:

```html
                <div class="toolbar-group">
                  <span class="toolbar-label">작업</span>
                  <button type="button" id="scanRecaptureEvidence" disabled title="증적이 없는 열린 포트만 이 스캔의 설정으로 수집합니다. 있는 증적은 그대로 둡니다">증적 재수집</button>
                  <button type="button" id="scanStopRecapture" class="danger" hidden title="진행 중인 포트까지 마치고 멈춥니다">재수집 중지</button>
                  <button type="button" id="scanRescanOpen" disabled title="이 스캔이 찾은 열린 포트를 스캔 폼의 대상·포트 칸에 채웁니다">열린 포트 재스캔</button>
                  <button type="button" id="scanCancel" disabled>취소</button>
                  <button class="danger" type="button" id="scanDelete" disabled>삭제</button>
                </div>
              </div>
              <p class="recapture-hint" id="scanRecaptureStatus" role="status"></p>
```

(`</div>`는 기존 `result-toolbar` 닫는 태그다 — 상태 줄은 도구줄 **밖**, 바로 아래에 둔다.)

폼의 `<!-- Both read this form ... -->` 주석과 `<div class="form-actions-secondary">…</div>` 블록 전체를 삭제한다. CSS `.form-actions-secondary` 규칙(452행 부근)도 삭제하고, 그 자리에:

```css
    .recapture-hint { margin: 6px 0 0; font-size: 12px; color: var(--muted); }
    .recapture-hint a { color: var(--accent); cursor: pointer; text-decoration: underline; margin-left: 6px; }
    .recapture-hint.error { color: var(--danger); }
```

- [ ] **Step 4: JS — 빈 곳 세기와 안내 줄**

`recaptureEvidence` 앞에:

```javascript
    // Open results with no automatic evidence, counted from what the result
    // view already holds. Manual attachments do not count: the recapture
    // photographs beside them, as the backend's own rule does.
    const AUTOMATIC_EVIDENCE = new Set(['web_screenshot', 'protocol_snapshot', 'terminal_transcript']);

    function unphotographedOpenCount() {
      const rows = state.scanResultPayload?.results || [];
      return rows.filter((row) =>
        ['open', 'open|filtered'].includes(row.state)
        && !(row.evidence_files || []).some((file) => AUTOMATIC_EVIDENCE.has(file.type))
      ).length;
    }

    function renderRecaptureHint() {
      const node = $('scanRecaptureStatus');
      if (state.recapturingScanId) return;           // the watch owns the line while a run is on
      node.classList.remove('error');
      const job = selectedScanJob();
      if (!job) { node.textContent = ''; return; }
      const missing = unphotographedOpenCount();
      const total = Number(state.scanResultPayload?.total || 0);
      const lead = missing
        ? `증적 재수집: 증적 없는 ${missing.toLocaleString()}개 포트만, 이 스캔의 설정으로.`
        : (total ? '증적이 모두 있습니다.' : '');
      node.innerHTML = lead
        ? `${escapeHtml(lead)}<a id="scanRecaptureAll" role="button" tabindex="0">전부 다시 찍기</a>`
        : '';
      const all = $('scanRecaptureAll');
      if (all) all.addEventListener('click', () => recaptureEvidence(false));
    }
```

`unphotographedOpenCount`는 호스트 탭에서는 결과 페이로드가 열린 행 500개까지만 담으므로(`HOST_VIEW_RESULT_LIMIT`) 그 범위 안의 수다. 안내 줄은 "약"을 붙이지 않는다 — 대신 재수집 응답의 `pending`이 확정 수이고 시작 메시지가 그것을 쓴다.

- [ ] **Step 5: JS — recaptureEvidence를 스캔의 설정으로**

`recaptureEvidence`를 교체:

```javascript
    async function recaptureEvidence(missingOnly) {
      const button = $('scanRecaptureEvidence');
      if (!state.scanId || button.disabled) return;
      const scanId = state.scanId;
      const job = selectedScanJob();
      if (!job) return;
      button.disabled = true;
      setStatus('scanRecaptureStatus', '증적 수집을 시작하는 중...');
      try {
        // The scan's own settings, not the form's: what it ran with is what
        // its evidence should be taken with.
        const params = job.params || {};
        const payload = await api(`/v1/scans/${encodeURIComponent(scanId)}/evidence/recapture`, {
          method: 'POST',
          body: JSON.stringify({
            screenshot_max: null,
            missing_only: missingOnly,
            capture_console: Boolean(params.capture_console),
            screenshot_timeout_ms: Number(params.screenshot_timeout_ms) || 8000,
          })
        });
        if (!payload.pending) {
          setStatus('scanRecaptureStatus', missingOnly ? '증적이 없는 열린 포트가 없습니다.' : '열린 포트가 없습니다.');
          return;
        }
        const pending = Number(payload.pending).toLocaleString();
        setStatus('scanRecaptureStatus', missingOnly
          ? `증적 재수집 시작 · 증적 없는 포트 ${pending}개. 기존 증적은 그대로 둡니다.`
          : `증적 재수집 시작 · 열린 포트 ${pending}개 전부. 기존 증적은 교체됩니다.`);
        state.recapturingScanId = scanId;
        watchRecaptureProgress(scanId);
      } catch (error) {
        setStatus('scanRecaptureStatus', error.message, true);
      } finally {
        updateScanActionState();
      }
    }
```

`setStatus(id, text, isError)`는 기존 헬퍼다 — `error` 클래스를 토글하는지 확인하고(`grep -n "function setStatus"`), 그렇다면 `.recapture-hint.error` CSS와 맞는다.

- [ ] **Step 6: JS — 나머지 참조 바꾸기**

- `cancelRecapture`, `watchRecaptureProgress`, `resumeRecaptureWatch`, `fillFormWithOpenTargets` 안의 `'scanSecondaryStatus'`를 모두 `'scanRecaptureStatus'`로 바꾼다 (`grep -n scanSecondaryStatus` 결과가 0이 될 때까지).
- `watchRecaptureProgress`에서 실행이 끝나는 세 자리(`state.recapturingScanId = null;` 뒤)와 `resumeRecaptureWatch` 끝에 `renderRecaptureHint();`를 부른다 — 진행 문구가 끝난 뒤 안내 줄로 돌아오게. 완료 문구는 그대로 두되, 그 다음 `refreshScanResults()`가 끝난 뒤에 `renderRecaptureHint()`가 불리도록 `selectScan`/`refreshScanResults` 끝에서도 부른다.
- `refreshScanResults`가 페이로드를 넣고 렌더한 뒤(Task 3에서 `recordResultTiming`을 넣은 자리 다음) `renderRecaptureHint();`를 부른다.
- `updateScanActionState`의 `$('scanRecaptureEvidence').disabled = recapturing || !job || active;`와 `$('scanRescanOpen').disabled = !job || active;`는 그대로 둔다(요소가 도구줄로 옮겨졌을 뿐 id는 같다).
- `fillFormWithOpenTargets` 끝, 폼을 채운 뒤에:

```javascript
        $('scanForm').scrollIntoView({behavior: 'smooth', block: 'start'});
        setStatus('scanRecaptureStatus', '스캔 폼에 열린 포트를 채웠습니다. 권한 확인 후 시작하십시오.');
```

- 리스너 연결(4604행 부근):

```javascript
    $('scanRecaptureEvidence').addEventListener('click', () => recaptureEvidence(true));
```

(`scanRecaptureAll`은 `renderRecaptureHint`가 만들 때마다 연결한다 — innerHTML로 다시 그려지기 때문.)

- Task 5 이전이라 `scanRecaptureMissingOnly` 요소는 이 태스크에서 마크업과 함께 사라진다. `grep -n scanRecaptureMissingOnly netroach/static/dashboard.html`이 0이어야 한다.

- [ ] **Step 7: 통과 확인 + 문법**

Run: `.venv/Scripts/python.exe -m pytest tests/test_dashboard.py -q`
Run: `node -e "const fs=require('fs');const h=fs.readFileSync('netroach/static/dashboard.html','utf8');new Function(h.match(/<script>([\s\S]*)<\/script>/)[1]);console.log('JS OK')"`
Expected: 통과. `grep -c scanSecondaryStatus netroach/static/dashboard.html` → 0.

- [ ] **Step 8: 실제 브라우저로 확인**

`preview_start`로 띄우고, 작업 탭에서 완료된 스캔을 선택한다. `read_page` 또는 `javascript_tool`로:
- `$('scanRecaptureStatus').textContent`가 "증적 재수집: 증적 없는 N개 포트만…" 또는 "증적이 모두 있습니다."로 시작하고 끝에 "전부 다시 찍기"가 있다.
- 폼 안에 `form-actions-secondary`가 없다.
- 도구줄 `작업` 그룹 순서: 증적 재수집 · 재수집 중지(숨김) · 열린 포트 재스캔 · 취소 · 삭제.

`127.0.0.1`에 텔넷 배너 서버 두 개를 띄우고 `screenshot_max: 1`로 스캔 하나를 만든 뒤(Task 6의 스크립트와 같은 방식), 그 스캔을 선택 → 안내가 "증적 없는 1개 포트만" → 증적 재수집 클릭 → 진행 문구 → 완료 → 안내가 "증적이 모두 있습니다." → "전부 다시 찍기" 클릭 → "열린 포트 2개 전부. 기존 증적은 교체됩니다."

- [ ] **Step 9: 커밋**

```bash
git add netroach/static/dashboard.html tests/test_dashboard.py
git commit -m "feat(dashboard): recapture from the scan's own toolbar, with its own settings

Recapture and rescan act on the scan the result toolbar describes, and
sat in the form because recapture read the form's evidence settings - a
coupling the operator had to know about before pressing it. They move to
the toolbar beside cancel and delete, and recapture sends the settings the
scan itself ran with. The button fills the ports that have no picture;
photographing every open port again is a link in the line beneath it,
which says beforehand how many ports each would touch.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 5: 스캔 폼 — 첫 화면 다섯 가지, 고급은 만지는 순서대로

**Files:**
- Modify: `netroach/static/dashboard.html` — 폼 마크업 1570-1712행, `screenshotLimit`/`syncScreenshotAll`(2635-2646), `ADVANCED_FIELDS`(2629), 스캔 생성 payload(4390행 부근 `screenshot_max:`), 리스너 목록(4655행 부근), 초기화 핸들러(4665행 부근), 서비스 탐지 도움말(1633행)
- Test: `tests/test_dashboard.py` — `test_the_evidence_limit_is_reachable_from_the_form`(679행) 교체, 새 구조 테스트 추가

**Interfaces:**
- Consumes: 없음 (Task 4가 끝난 상태의 폼)
- Produces: 마크업 순서와 `id`는 유지(`scanTargets`, `scanPorts`, `scanProtocol`, `scanAuthorized`, `scanAdvanced`, 그 안의 기존 id 전부). 없어지는 id: `scanScreenshotMax`, `scanScreenshotAll`, `scanScreenshotMaxHelper`. 없어지는 함수: `screenshotLimit`, `syncScreenshotAll`. 고급 묶음 제목 클래스 `advanced-group-title`.

- [ ] **Step 1: 테스트 — 첫 화면과 고급 묶음**

`test_the_evidence_limit_is_reachable_from_the_form`을 **교체**:

```python
    def test_evidence_is_every_open_port_and_the_form_has_no_count_for_it(self):
        """The count and its "all of them" switch were two more things to
        understand on a form that already asked too much of a first run.
        In an assessment the evidence is every open port; the request says
        so and the form no longer asks."""
        html = dashboard_html()

        self.assertNotIn('name="screenshot_max"', html)
        self.assertNotIn('id="scanScreenshotAll"', html)
        self.assertNotIn("function screenshotLimit(", html)
        # Both requests the dashboard makes say every open port.
        create = html.split("capture_screenshots: tcpServiceProbe", 1)[1].split("};", 1)[0]
        self.assertIn("screenshot_max: null", create)
        recapture = html.split("async function recaptureEvidence(", 1)[1].split(chr(10) + "    }", 1)[0]
        self.assertIn("screenshot_max: null", recapture)
        # Where the cost of that is said: on the switch that turns evidence on.
        service_help = html.split('id="scanServiceProbeHelp"', 1)[1].split("</span>", 1)[0]
        self.assertIn("열린 포트마다", service_help)
        self.assertIn("1~5초", service_help)

    def test_the_first_screen_is_five_things_and_the_rest_is_advanced_in_the_order_it_is_used(self):
        """Target, ports and protocol, the authorisation tick, start. Every
        other control sits behind "고급 설정", speed first because speed is
        what an assessor actually adjusts; detection, scope and the rest
        after it, each under its own heading."""
        html = dashboard_html()

        form = html.split('<form id="scanForm">', 1)[1].split("</form>", 1)[0]
        before_advanced = form.split('id="scanAdvanced"', 1)[0]
        advanced = form.split('id="scanAdvanced"', 1)[1]

        for control in ("scanPresetChips", "scanTargets", "scanPorts", "scanProtocol", "scanAuthorized"):
            self.assertIn(f'id="{control}"', before_advanced, control)
        for control in ("scanServiceProbe", "scanHostDiscovery", "scanUdpServiceProbe", "scanConnectOnly",
                        "scanScopeFromTargets", "scanScope", "scanTimeout", "scanConcurrency", "scanRate",
                        "scanTopPorts", "scanExclude", "scanUdpRetries", "scanSynRetries",
                        "scanMaxAttempts", "scanConfirmLargeScan"):
            self.assertNotIn(f'id="{control}"', before_advanced, f"{control} belongs in advanced")
            self.assertIn(f'id="{control}"', advanced, control)

        titles = [t for t in ("속도", "탐지", "승인 범위", "그 밖")]
        positions = [advanced.index(f'class="advanced-group-title">{t}<') for t in titles]
        self.assertEqual(positions, sorted(positions), "speed, detection, scope, the rest - in that order")
        # Speed's three fields come before the first detection switch.
        self.assertLess(advanced.index('id="scanRate"'), advanced.index('id="scanServiceProbe"'))
        # The start button follows the advanced panel, not the other way round.
        self.assertLess(form.index('id="scanAdvanced"'), form.index('id="scanSubmit"'))
```

`ADVANCED_FIELDS`를 검사하는 기존 테스트가 있으면(`grep -n ADVANCED_FIELDS tests/test_dashboard.py`) `screenshot_max`·`screenshot_all`이 빠지고 `service_probe`, `host_discovery`, `udp_service_probe`, `tcp_connect_only`, `scope_from_targets`, `scope`가 들어간 목록으로 고친다.

- [ ] **Step 2: 실패 확인**

Run: `.venv/Scripts/python.exe -m pytest tests/test_dashboard.py -q -k "every_open_port or first_screen"`
Expected: FAIL.

- [ ] **Step 3: 마크업 — 폼을 다시 짠다**

`<form id="scanForm">`부터 `<details class="advanced-panel" id="scanAdvanced">` 앞까지를 다음으로 바꾼다. 기존 요소(`id`, `name`, `placeholder`, 도움말 텍스트, `(?)` 도움말 블록)는 **그대로 옮기고**, 감싸는 섹션만 바뀐다:

```html
                <form id="scanForm">
                  <!-- Five things on the first screen: presets, target, ports
                       and protocol, the authorisation tick, start. Everything
                       else is behind 고급 설정, in the order it is reached
                       for - speed first, because speed is what an assessor
                       adjusts; the defaults answer the rest. -->
                  <div class="form-section first">
                    <h4>프리셋</h4>
                    [기존 프리셋 칩 + 저장 줄 그대로]
                  </div>
                  <div class="form-section"><h4>대상</h4>
                  <div class="form-grid">
                    [기존 scanTargets 필드 그대로]
                    [기존 scanPorts 필드(프로필 select, TXT 가져오기 포함) 그대로]
                    [기존 scanProtocol 필드 그대로]
                  </div>
                  </div>
                  <div class="form-section">
                  <div class="form-grid">
                    <div class="field full authorization-box">
                      <label class="check-row"><input id="scanAuthorized" name="confirm_authorized" type="checkbox" required>스캔 권한을 확인했습니다</label>
                      <span class="helper">소유했거나 명시적으로 허가받은 시스템만 스캔하세요.</span>
                    </div>
                  </div>
                  </div>
```

`<details class="advanced-panel" id="scanAdvanced">`의 `advanced-body`를 다음으로 바꾼다:

```html
                    <div class="advanced-body">
                      <p class="advanced-group-title">속도</p>
                      <div class="form-grid">
                        [기존 scanTimeout 필드]
                        [기존 scanConcurrency 필드]
                        [기존 scanRate 필드]
                      </div>
                      <p class="advanced-group-title">탐지</p>
                      <div class="form-grid">
                        <div class="field full">
                          [기존 scanServiceProbe scan-help-option 블록]
                          [기존 scanConnectOnly scan-help-option 블록]
                        </div>
                        <div class="field full">
                          [기존 scanUdpServiceProbe scan-help-option 블록]
                        </div>
                        <div class="field full">
                          [기존 scanHostDiscovery scan-help-option 블록]
                        </div>
                      </div>
                      <p class="advanced-group-title">승인 범위</p>
                      <div class="form-grid">
                        [기존 scanScopeFromTargets 필드]
                        [기존 scanScope 필드(대상에서 다시 채우기 버튼 포함)]
                      </div>
                      <p class="advanced-group-title">그 밖</p>
                      <div class="form-grid">
                        [기존 scanTopPorts 필드]
                        [기존 scanExclude 필드]
                        [기존 scanUdpRetries 필드]
                        [기존 scanSynRetries 필드]
                        [기존 scanMaxAttempts 필드]
                        [기존 scanConfirmLargeScan 필드]
                      </div>
                    </div>
```

"[기존 … 그대로]"는 현재 파일의 해당 블록을 잘라 붙인다는 뜻이다 — 새로 쓰지 않는다. `scanScreenshotMax`/`scanScreenshotAll`/`scanScreenshotMaxHelper` 필드는 붙이지 않는다(삭제). 기존 `<h4>승인 범위</h4>`·`<h4>실행</h4>` 섹션은 통째로 사라진다(내용물은 위로 옮겨짐).

서비스 탐지 도움말(`id="scanServiceProbeHelp"`) 문장 끝에 추가: ` 열린 포트마다 증적을 찍습니다 — 포트당 1~5초가 걸립니다.`

CSS에 추가(`.advanced-body` 규칙 근처):

```css
    .advanced-group-title { margin: 14px 0 6px; font-size: 12px; font-weight: 600; color: var(--text-soft); letter-spacing: .02em; }
    .advanced-group-title:first-child { margin-top: 4px; }
```

- [ ] **Step 4: JS — 증적 개수 흔적 제거**

- `screenshotLimit`와 `syncScreenshotAll` 함수, 그 위 주석 블록을 삭제한다.
- 리스너 연결의 `$('scanScreenshotAll').addEventListener('change', syncScreenshotAll); syncScreenshotAll();` 두 줄 삭제.
- 초기화 핸들러의 `syncScreenshotAll();`와 그 주석 삭제.
- 리스너 목록 배열에서 `'scanScreenshotMax', 'scanScreenshotAll',` 삭제하고 `'scanServiceProbe', 'scanHostDiscovery', 'scanUdpServiceProbe', 'scanScopeFromTargets'`를 추가한다(고급 배지가 이것들도 세도록).
- `ADVANCED_FIELDS`를 다음으로 바꾼다:

```javascript
    const ADVANCED_FIELDS = ['timeout_ms', 'concurrency', 'rate_limit_per_sec', 'service_probe', 'host_discovery',
      'udp_service_probe', 'tcp_connect_only', 'scope_from_targets', 'scope', 'top_ports', 'exclude',
      'udp_retries', 'syn_retries', 'max_attempts', 'confirm_large_scan'];
```

- 스캔 생성 payload에서 `screenshot_max: screenshotLimit(form),`를 `screenshot_max: null,`로 바꾼다.
- `grep -nE "screenshotLimit|syncScreenshotAll|scanScreenshotMax|scanScreenshotAll|screenshot_all" netroach/static/dashboard.html` → 0줄.

- [ ] **Step 5: 통과 확인 + 문법**

Run: `.venv/Scripts/python.exe -m pytest tests/test_dashboard.py -q`
Run: `node -e "const fs=require('fs');const h=fs.readFileSync('netroach/static/dashboard.html','utf8');new Function(h.match(/<script>([\s\S]*)<\/script>/)[1]);console.log('JS OK')"`
Expected: 통과. 다른 대시보드 테스트가 옮겨진 마크업의 **문맥**(예: `html.split('id="scanServiceProbe"', 1)[1].split("</div>", 1)[0]`)을 검사하면 그대로 통과해야 한다 — 블록을 통째로 옮겼기 때문. 실패하면 블록을 새로 쓴 것이니 원본과 대조한다.

- [ ] **Step 6: 실제 브라우저로 확인**

`preview_start`로 띄우고 `javascript_tool`:

```javascript
({
  firstScreen: [...document.querySelectorAll('#scanForm > .form-section input, #scanForm > .form-section select, #scanForm > .form-section textarea')].map(e => e.id).filter(Boolean),
  advancedTitles: [...document.querySelectorAll('#scanAdvanced .advanced-group-title')].map(e => e.textContent),
  advancedOpen: document.getElementById('scanAdvanced').open,
  badge: document.getElementById('scanAdvancedBadge').hidden,
})
```

Expected: `firstScreen`에 `scanPresetIncludeTargets, scanTargets, scanPorts, scanProfile, scanPortProfileFile, scanProtocol, scanAuthorized`만; `advancedTitles` = `["속도","탐지","승인 범위","그 밖"]`; `advancedOpen` false; 배지 hidden true.

그 다음 고급을 열고 타임아웃을 바꾼 뒤 배지가 "고급 1"이 되는지, 프리셋 "전체 정밀"을 눌렀을 때 폼이 채워지는지 확인한다. 스캔 하나를 `127.0.0.1` 포트 하나로 돌려 정상 완료되는지 본다(권한 확인 체크 필요).

- [ ] **Step 7: 커밋**

```bash
git add netroach/static/dashboard.html tests/test_dashboard.py
git commit -m "feat(dashboard): five things on the first screen, the rest behind advanced in the order it is used

The form asked a first run to understand five switches and their help,
nine numbers and two more switches behind advanced, and a recapture that
read those numbers. In an assessment the values that change are the
target, the ports, the protocol and the speed. The first screen is now
presets, target, ports and protocol, the authorisation tick and start;
everything else sits behind 고급 설정 under four headings - speed first,
then detection, scope and the rest. The evidence count is gone: evidence
is every open port, the request says so, and the cost is stated on the
switch that turns evidence on.

Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>"
```

---

### Task 6: 전체 검증과 패키지 확인

**Files:** 없음(검증만). 실패하면 해당 태스크로 돌아간다.

- [ ] **Step 1: 전체 테스트·린트·타입**

Run:
```bash
.venv/Scripts/ruff.exe check netroach tests && .venv/Scripts/mypy.exe netroach && .venv/Scripts/python.exe -m pytest tests/ -q
```
Expected: 전부 통과.

- [ ] **Step 2: 설계의 "확인" 절차를 소스 서버로**

`127.0.0.1`에 텔넷 배너 서버 두 개(5801, 5802)와 3초 뒤 내용을 그리는 HTTP 서버(5803)를 띄운다(Task 1 Step 5와 Task 4 Step 8의 서버를 합친 스크립트). `preview_start`로 대시보드를 띄우고:

1. 폼에 대상 `127.0.0.1`, 포트 `5801,5802,5803`, 권한 확인 → 스캔 시작 → 완료.
2. 작업 탭에서 그 스캔 선택 → 결과에 세 포트 모두 증적(웹 1, 터미널 2). 5803의 웹 증적을 열어 `Loading...`이 아니라 내용이 있는지.
3. 안내 줄 "증적이 모두 있습니다. 전부 다시 찍기".
4. DB에서 5802의 증적 행을 지운 뒤(`DELETE FROM result_evidence_files WHERE port=5802`) 스캔을 다시 선택 → "증적 없는 1개 포트만" → 증적 재수집 → 완료 → 5802에 증적 1건, 5801은 그대로.
5. 진단 탭 → 결과 조회 시간 표에 항목이 있고 서버 ms가 숫자.

- [ ] **Step 3: 패키지 확인은 빌드 뒤**

빌드·자산 교체는 별도 요청으로 진행한다. 빌드 뒤 `resources/bin/netroach-backend.exe`를 직접 띄워(이 세션의 `pkg_missing_only.py` 방식) Step 2의 4번을 API로 재현하고, PyInstaller 아카이브의 `dashboard.html`에 `id="diagnosticsTimings"`와 `advanced-group-title`이 있고 `scanScreenshotAll`이 없는지 확인한다.

- [ ] **Step 4: 푸시**

```bash
git push origin main
```
