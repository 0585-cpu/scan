# 스캔 부하 분산과 증적 예산 — 인수인계

2026-09-12~13 작업분이다. 커밋 두 개로 나뉘어 있고 둘 다 **로컬에만 있다(푸시 안 함)**.

| 커밋 | 내용 |
| --- | --- |
| `c46ef28` | 스캔 부하가 작업 목록 앞쪽 호스트에 몰리던 문제, ARP 직렬 해석, RST 미계량 |
| `30cf9b1` | 증적 수집 예산을 호스트당으로 분배 |

버전은 `0.2.4` 그대로다. 릴리즈와 자산 교체는 하지 않았다.

## 1. 왜 이 작업을 했나

두 범주로 스캐너를 점검했다. **스캔 성능**과 **대상 PC에 대한 네트워크 영향**이다.
성능 쪽에서 가장 컸던 것은 ARP 직렬 해석이고, 대상 영향 쪽에서 가장 위험했던 것은
connect 경로가 호스트-major였다는 점이다.

## 2. 대상 PC 영향 — 고친 것

### 2.1 connect 경로가 첫 호스트에 전부 몰렸다

스캔을 제한하는 두 가지가 **모두 작업 목록 앞쪽에서** 취해진다. rate limiter의
슬롯과 `concurrency`만큼의 진행 중 프로브다. 그런데 목록이 호스트-major였다.

```rust
// 이전
targets.into_iter().flat_map(|target| ports.iter().copied().map(move |port| (target, port)))
```

그래서 1,000대 범위 스캔이 **설정된 rate 전량과 진행 중 소켓 2,000개를 첫 호스트
한 대에** 쏟고, 그 호스트의 포트를 다 훑은 뒤 다음으로 넘어갔다. 목록 맨 앞에
있었다는 이유만으로 범위 전체용 부하를 한 대가 받았다.

포트-major로 바꿨다. [`scan_job_at`](../crates/netroach-engine/src/main.rs)이 그
순서를 만들고, 테스트도 그 함수를 직접 호출한다(자기 산술을 재현하는 테스트가
아니다).

### 2.2 connect 경로에 호스트당 예산이 없었다

SYN 스윕에는 `sweep_rate`로 호스트당 10pps 예산이 있었는데 connect 경로에는
대응물이 없었다. 같은 모양의 규칙을 넣었다.

```rust
fn probe_rate(requested: u64, host_count: usize) -> u64 {
    let spread = (host_count as u64).saturating_mul(PROBE_PER_HOST_RATE_PER_SEC);
    requested.min(spread.max(PROBE_RATE_FLOOR_PER_SEC))
}
```

| 상수 | 값 | 근거 |
| --- | --- | --- |
| `PROBE_PER_HOST_RATE_PER_SEC` | 100 | connect는 전체 핸드셰이크라 스윕 프로브보다 무겁다. 스윕의 호스트당 10보다 위, 기존의 "총량을 한 대에" 보다 훨씬 아래 |
| `PROBE_RATE_FLOOR_PER_SEC` | 1,000 | 단일 호스트 스캔이 기어가지 않게. 한 호스트 전체 포트를 1분 내 커버하면서 기존보다 5배 완만 |

**이름이 `probe_rate`인 이유**: TCP connect와 UDP 두 소켓 경로를 모두 지배한다.
더 무거운 쪽(핸드셰이크)에 맞춰 정했다.

**측정 (단일 호스트, 포트 2,000개)**

```
요청   1000/s ->    835 probes/s
요청   5000/s ->    839 probes/s
요청  20000/s ->    840 probes/s     <- 상한이 실제로 걸림
요청    200/s ->    161 probes/s     <- 낮춘 요청은 그대로 존중
```

1,000·5,000·20,000이 같은 값을 주는 것이 상한이 바인딩한다는 증거다. 조작자가
일부러 낮춘 값은 그대로 적용된다.

### 2.3 SYN 후속 connect도 같은 문제

범위 전체를 스윕해도 열린 포트가 **한 대에 전부 몰려 있을 수 있다**. 후속은
포트당 전체 핸드셰이크라, 예산을 실제 방문 호스트 수로 계산한다.

```rust
let follow_up_hosts = follow_up_jobs.iter().map(|(host, _, _)| *host)
    .collect::<HashSet<IpAddr>>().len();
let follow_up_limiter = RateLimiter::new(probe_rate(effective_rate(rate), follow_up_hosts));
```

후속 작업 목록도 `sort_by_key(port)`로 포트-major로 만든다. 호스트별로 모아
생성하면 호스트-major가 되기 때문이다.

### 2.4 RST가 rate limiter 밖에 있었다

스윕이 SYN-ACK에 보내는 RST가 계량되지 않았다. 열린 포트가 많은 호스트는
**프로브당 두 프레임**을 받았고, 예산은 한 프레임 기준으로 쓰여 있었다.
`close_opened`가 이제 프로브와 같은 limiter와 같은 배치를 공유한다.

같은 변경이 성능 결함도 없앴다. 이전에는 RST 하나마다 `flush_queue`를 불러
**열린 포트당 드라이버 왕복 1회**를 냈다. `SEND_BATCH_MAX = 256`이 없애려던 바로
그 비용이다.

> 주의: 라운드 마지막 `close_opened` 뒤에 전체 인터페이스 flush를 추가했다.
> 배치만 하고 이걸 빼면 마지막 RST들이 전송되지 않아 대상이 슬롯을 타임아웃까지
> 쥐고 있는다.

### 2.5 전 포트 open 호스트 (SYN 프록시)

전 포트에 SYN-ACK를 주는 방화벽은 후속 connect로 구별할 수 없다(그쪽도 완료된다).
할 수 있는 건 **범위 전체 포트에 핸드셰이크를 한 주소에 쏟는 것**뿐이라, 후속을
건너뛰고 사유를 각 포트 행에 붙인다.

```rust
fn answers_everything(open: usize, probed: usize) -> bool {
    probed >= ANSWERS_EVERYTHING_MIN_PORTS      // 100
        && open as f64 >= probed as f64 * ANSWERS_EVERYTHING_RATIO   // 0.5
}
```

**설계 판단**: 요약(`port_summary`)으로 접지 않고 **개별 행을 유지**한다.
`COLLAPSIBLE_STATES`는 `("closed", "filtered")`뿐이고 **접힌 open을 결과
테이블에 렌더하는 경로가 없다**. 요약으로 접으면 65,535개 발견이 화면에서
사라진다. 처음에 요약으로 구현했다가 이 사실을 발견해 방향을 바꿨다.

## 3. 성능 — 고친 것

### 3.1 ARP 직렬 해석 (가장 컸던 것)

같은 세그먼트에서 아무도 응답하지 않는 주소는 Windows가 ARP를 재전송하다 포기할
때까지 **약 3.2초**를 쓴다. 이걸 타깃마다 순서대로 했다.

**측정 (직접 `ResolveIpNetEntry2` 호출)**

```
198.51.100.254 (게이트웨이)  0.003s
198.51.100.201 (빈 주소)     3.16s
198.51.100.202 (빈 주소)     3.17s
198.51.100.203 (빈 주소)     3.18s
```

/24에 죽은 주소가 224개면 **SYN 한 발 나가기 전에 12분**이고, 아직 프로브를 보내지
않았으므로 진행률 표시에도 아무것도 안 뜬다.

`map_in_parallel`로 한꺼번에 해석한다. **측정 (실제 엔진, ARP 캐시 삭제 후)**

| 대역 | 호스트 | 실측 | 직렬 환산 |
| --- | --- | --- | --- |
| /27 | 30 | **1.68초** | 약 96초 |
| /25 | 126 | **2.52초** | 약 403초 |

`ARP_RESOLVE_THREADS = 64`로 잡은 이유는 코어 수가 아니다. **ARP 요청은
브로드캐스트**라 세그먼트의 모든 호스트가 받는다. 이 값은 동시에 떠 있을 수 있는
브로드캐스트 개수다. 64면 /24를 약 13초에 끝내면서 그 브로드캐스트를 호스트가
부팅할 때 내는 양보다 훨씬 아래로 유지한다.

> **이 경로는 게이트웨이 너머 대역에서는 원래 느리지 않았다.** 라우팅 대상은
> next-hop이 게이트웨이 하나뿐이고 그 MAC은 한 번 캐시되면 0.003초다. 그래서
> 10 × /24 테스트에서는 이 문제가 드러나지 않았다. **자기 대역(온링크) 스캔에서만**
> 호스트마다 3.2초가 터진다.

### 3.2 재개 시 접힌 범위를 개별 포트로 전개했다

`get_result_keys`가 접힌 범위를 전부 개별 `(host, port)` 튜플로 펼쳤다.

**측정 (`tracemalloc`)**

```
17,018,000개 키 -> 3.00 GB
```

재개된 스캔이 **첫 프로브를 보내기 전에** 3GB를 할당한다. 스팬으로 유지하면:

```
스팬 메모리: 0.34 MB (2,540 호스트)
17M 프로브 스캔 재개 판정: 0.017초
```

`get_result_keys` → `get_completed_port_spans`로 교체했고, 반환형이
`dict[str, list[tuple[int,int]]]`다. `merge_spans` / `spans_cover`를 새로 뺐고
`merge_range_strings`가 `merge_spans`를 쓰게 해서 병합 로직 중복을 없앴다.

`_group_pending_scan_work`도 호스트를 먼저 보고 "전부 미완" / "전부 완료" 두 경우를
포트당 검사 없이 처리한다. 0.7초 → 0.002초.

## 4. 증적 예산 — 호스트당 10개 (`30cf9b1`)

### 4.1 문제

예산이 **총량만** 있었고 후보 목록은 `ORDER BY host, port LIMIT ?`였다. 열린 포트가
예산보다 많은 호스트가 목록을 다 먹고, **그 뒤 호스트는 후보에조차 못 들어갔다.**
증적이 0개인 호스트는 보고서에서 "지적할 것이 없는 호스트"로 읽힌다.

### 4.2 숫자와 근거

`EVIDENCE_PER_HOST = 10`.

포트가 오름차순으로 뽑히므로 각 호스트가 **낮은 포트에 예산을 쓴다.** Windows
호스트 전체 포트 스캔은 `135, 139, 445, 3389, 5985, 47001` 뒤에 49152 이상 RPC
임시 포트가 줄줄이 나온다. 낮은 10개가 앞 그룹을 담는다. **5개면 WinRM(5985)이
잘리고 그건 실제 지적 사항이다.**

**측정한 캡처 비용**

| 방식 | 포트당 | 근거 |
| --- | --- | --- |
| PowerShell 기록 (기본) | **0.29초** | 3회 중앙값 |
| 콘솔 캡처 (`capture_console`) | **1.07초** | 8회 중앙값 |
| 웹 스크린샷 | 미측정 | 개발 venv에 Chromium 없음. 상한은 `screenshot_timeout_ms` × `WEB_PORT_BUDGET_FACTOR`(2) = 기본 16초 |

호스트당 10 × 0.29초 ≈ 호스트당 3초. 500대면 24분이다.

### 4.3 ⚠️ 반드시 알아야 할 제약

**호스트당 규칙은 총량 안에서 나누는 것이고 총량을 늘리지 않는다.** 총량이
`호스트당 × 호스트 수`보다 작으면 뒤쪽 호스트는 여전히 0개다.

**측정 (3호스트 × 40 열린 포트)**

```
총량 20, 총량만      -> {10.0.0.1: 20}
총량 20, 호스트당 10 -> {10.0.0.1: 10, 10.0.0.2: 10}
총량 30, 호스트당 10 -> {10.0.0.1: 10, 10.0.0.2: 10, 10.0.0.3: 10}
총량 10, 총량만      -> {10.0.0.1: 10}
총량 10, 호스트당 4  -> {10.0.0.1: 4, 10.0.0.2: 4, 10.0.0.3: 2}
```

`screenshot_max` 기본값 20은 **2대만 커버한다.** 이 기본값은 의도적으로 그대로
두었다. 부족하면 대시보드가 직접 경고하기 때문이다
([dashboard.html](../netroach/static/dashboard.html) `evidenceCoverageWarning()`):

> 증적을 1,500개 포트 중 20개만 수집했습니다. 나머지 1,480개는 증적 수집 개수
> 한도 때문에 시도하지 않았습니다. 고급 설정에서 한도를 올린 뒤 다시 스캔하세요.

기본값을 올리려면 증적 단계 시간과의 교환이다. `screenshot_max` × 0.29초가
소요 시간이다.

### 4.4 집계 층에서 함께 고친 세 곳

호스트당 규칙을 넣으면 **조용히 무효화되거나 잘못 보고하는 지점이 세 개** 있었다.

**(1) 캡처 층의 이중 절단 — 가장 위험**

`capture_automatic_evidence` 안에서 `automatic_evidence_candidates(results,
maximum=maximum)`가 **전역 상한을 다시 적용**한다. 그 절단은 목록의 단순 앞부분
잘라내기라서, 호스트별로 나눈 예산을 **다시 첫 호스트에 집중시킨다.** 그러면
"고친 것처럼 보이면서 아무것도 안 고쳐진" 상태가 된다.

테스트로 잡지 않고 **구조적으로 제거**했다. 세 호출처(api 스캔 / api 재수집 / cli)
모두 DB가 고른 목록의 길이를 넘긴다.

```python
maximum=max(1, len(stored_results))
```

`max(1, ...)`인 이유: 빈 목록에서 `maximum=0`은 `automatic_evidence_candidates`가
`ValueError`를 던지고, api 스캔 경로에는 빈 목록 가드가 없어 스캔 작업이 실패한다.

기존 캡처 테스트 2개가 `maximum == 3` 같은 **옛 배선을 단정**하고 있었다. 유지되어야
할 불변식(`maximum >= len(results)`)을 단정하게 바꿨다.

**(2) 재수집의 `eligible` 휴리스틱**

```python
# 이전: "총량보다 적게 받았으면 그게 전부다"
eligible = len(candidates) if len(candidates) < screenshot_max else repo.count_open_results(scan_id)
```

호스트당 규칙에서는 **총량보다 적게 받고도 호스트당으로 잘린 상태**가 가능하므로
이 가정이 무너진다. `eligible == captured`로 보고되면 **부분 커버리지가 숨는다.**
항상 COUNT 하도록 바꿨다.

**(3) 증적 진행률 분모**

`planned_evidence = min(eligible_evidence, screenshot_max)` → `len(stored_results)`.
총량이 더 이상 목록 길이가 아니다.

**(4) CLI가 `eligible`을 아예 안 넘겼다**

기존 누락이라 `not_attempted`가 항상 0이었고, CLI 요약이 모든 스캔을 "완전 커버"로
보고했다. 호스트당 규칙이 들어가면 더 자주 틀리므로 같이 고쳤다. **캡처 전에**
세어야 한다. 캡처가 증적을 만들면 "아직 없는 것"의 수가 바뀐다.

### 4.5 실제 경로 검증

단위 테스트만으로 끝내지 않았다. 실제 리스너를 띄운 두 호스트(15개 / 3개 열린 포트):

```
selected: {'127.0.0.1': 10, '127.0.0.2': 3}
captured: 13 of 13  failed: 0
evidence stored per host: {'127.0.0.1': 10, '127.0.0.2': 3}
```

DB에 두 호스트 모두 증적 행이 남았다.

## 5. 조정할 만한 상수

| 파일 | 상수 | 값 |
| --- | --- | --- |
| `crates/netroach-engine/src/syn_runner.rs` | `ARP_RESOLVE_THREADS` | 64 |
| `crates/netroach-engine/src/main.rs` | `PROBE_PER_HOST_RATE_PER_SEC` | 100 |
| `crates/netroach-engine/src/main.rs` | `PROBE_RATE_FLOOR_PER_SEC` | 1,000 |
| `crates/netroach-engine/src/main.rs` | `ANSWERS_EVERYTHING_RATIO` | 0.5 |
| `crates/netroach-engine/src/main.rs` | `ANSWERS_EVERYTHING_MIN_PORTS` | 100 |
| `netroach/evidence.py` | `EVIDENCE_PER_HOST` | 10 |

## 6. 검증 명령과 기준선

SYN 빌드는 `LIB`에 Npcap SDK가 있어야 한다.

```powershell
$env:LIB = "C:\npcap-sdk\Lib\x64;$env:LIB"; cargo test -p netroach-engine --features syn-sweep
```

```powershell
cargo test -p netroach-engine
```

```powershell
.venv\Scripts\python.exe -m pytest -q --ignore=tests/test_manager_api.py
```

| 검사 | 기준선 |
| --- | --- |
| 엔진 (SYN 기능 포함) | 77 + 13 통과 |
| 엔진 (connect 전용) | 46 + 14 통과 |
| Python | 461 통과, 10 skip |
| `ruff`, `mypy` | 통과 |
| `cargo clippy -D warnings` | **기존부터 실패** — 게이트가 아니다 |

clippy는 이 작업 전 clean tree에서도 실패했다(`git stash`로 확인). connect 전용
빌드에서 lint 5개다.

```
1  accessing first element with `frame.get(0)`      (syn_sweep.rs:76)
1  large size difference between variants           (enum Command)
2  the following explicit lifetimes could be elided (effective_known_*_service)
1  this function has too many arguments (8/7)       (scan_one)
```

`--features syn-sweep`를 붙이면 `manual_clamp`(`syn_runner.rs`의 `sweep_rate`)와
examples의 같은 `get_first`가 더해진다. **이 작업으로 새로 생긴 것은 없다.**
작업 중 내가 만든 `doc_lazy_continuation` 6개는 고쳤다(문단 첫 줄을 `-`로 시작해
마크다운 목록으로 해석된 것이다).

### 실제 경로 확인 기록

```powershell
# 게이트웨이 512포트 SYN 스윕 + 서비스 탐지
.\target\debug\netroach-engine.exe scan --scan-id t --targets 198.51.100.254 `
  --ports 1-512 --syn-sweep --timeout-ms 1000 --service-probe
```

결과: `80/tcp open`, 서비스 `http` 신뢰도 0.98, 배너 확보, 511 closed,
**filtered 0** (rate floor가 유지되고 있다는 신뢰도 지표),
`answers_everything` 오탐 없음(`error: null`).

## 7. 남은 미결 항목

### 결정이 필요한 것

- **넓은 스윕의 기본 rate.** `sweep_rate`는 `min(requested, max(hosts×10, 500))`이고
  UI 기본값이 5,000이다. 2,540대여도 25,400이 아니라 5,000에 묶인다. 코드는
  문서화된 의도대로 동작하므로 결함이 아니지만, "호스트당 예산이 넓은 스윕을
  빠르게 한다"는 약속이 사용자가 숫자를 직접 올리지 않으면 작동하지 않는다.
  고치려면 **rate 입력란이 스윕에서 무슨 뜻인가**를 바꾸는 UI 결정이 필요하다.

### 정확성 — 작지만 실재

- **웹 증적의 최종 URL이 기록되지 않는다.** `host_route_filter`는 **호스트명만**
  비교하고 포트·스킴은 비교하지 않는다. 같은 호스트의 다른 포트로 리다이렉트되면
  따라가서 촬영하는데, 저장되는 `source_url`은 **요청한** URL이고 파일명도 스캔한
  포트 번호다. 그래서 "80/tcp 열림"에 8443 관리 페이지 스크린샷이 붙고 **그 불일치를
  알아낼 방법이 없다.** 실제 예: 이 망 게이트웨이 80/tcp가
  `302 Found; location=http://198.51.100.254:80:8899/`를 반환한다.
  고치는 법: `netroach/evidence.py`의 `store(...)` 호출에서 `url` → `page.url`.
  다른 **호스트**로의 리다이렉트는 차단되므로(실패로 기록) 그쪽은 안전하다.
- **텔넷 창 탐색의 불필요한 추측.** `_find_window_by_title`이 `exact`를 요청받고도
  못 찾으면 `matches[0]`을 돌려준다. `exact`를 요구했는데 없으면 `None`이 맞다.
  콘솔 창은 제목에 uuid를 붙이므로 안전하고, 텔넷 쪽도 실행 전 `standing` 스냅샷과
  `process.wait()`로 대부분 막혀 있어 실제 위험은 낮다.

### 미측정

- **Governor가 `error` 상태에 반응하지 않는다.** `record_sample`은 timeout만 본다.
  임시 포트(이 PC 16,384개, `TcpTimedWaitDelay` 미설정)가 고갈되면 `error`가
  쏟아지는데 속도를 줄이지 않는다. 다만 2.2와 2.5로 위험이 크게 줄었으므로
  **실제로 문제가 되는지 먼저 측정**해야 한다.
- **콘솔 캡처 병렬화.** 텔넷 창 제목이 포트별로 유일하지 않은 것이 선결 과제다.

### 드롭한 것

- **스킵된 호스트의 프로브 인덱스 순회.** 미측정 2~3% 개선인데, 안전하게 고치려면
  응답 큐(16,384) 오버플로 위험을 다뤄야 해서 얻는 것보다 복잡하다.

## 8. 이 작업에서 틀렸던 추정 (같은 실수 반복 방지)

- **`_group_pending_scan_work`를 "수 분"으로 추정했으나 실측 0.7초였다.** 코드
  주석도 측정값으로 고쳤다. 다만 같은 측정에서 메모리 3.00 GB가 나와 그쪽이 진짜
  문제였다. **추정을 근거로 주석을 쓰지 말 것.**
- **증적 요약을 `port_summary`로 접으려 했다.** `COLLAPSIBLE_STATES`가
  closed/filtered뿐이고 접힌 open을 렌더할 경로가 없다는 것을 뒤늦게 발견했다.
  그대로 갔으면 65,535개 발견이 결과 테이블에서 사라졌다.
- **`covered >= len(ordered_ports)` 단축이 비연속 포트 목록에서 틀렸다.** 포트가
  `80,443`이고 스팬이 `1-100`이면 covered가 21로 나와 완료로 판정한다. 스팬 하나가
  최저~최고를 덮는지 보는 방식으로 바꿨다.
- **테스트가 내 버그 두 개를 잡았다.** 빈 입력에서 `chunks(0)` 패닉,
  `bisect_right`에 `(port, port+1)`을 키로 써서 `(1,2000) > (1,2)`가 되는 오류.
  **새 로직에는 실행 가능한 검사를 남길 것.**

## 9. 함정

`_run_scan_job`은 job이 `queued`가 아니면 **조용히 early-return**한다. 스캔이 돌지
않는데 로그도 없으면 이걸 먼저 본다.

`dashboard_html()`은 `lru_cache`다. HTML을 수정해도 프리뷰 서버를 재시작하지 않으면
옛 페이지가 서빙된다.

`SendQueue::len()`은 패킷 수가 아니라 **바이트 수**를 돌려준다. 배치 크기와
비교하면 안 되고, 별도 카운터를 쓴다(`queued` 맵).

## 10. 함께 볼 문서

- `docs/current-development-status-ko.md`: 배포·검증 현황의 기준
- `docs/testing-and-measurement-ko.md`: 측정 방법론
- `docs/syn-sweep-handoff.md`: SYN 스윕 구조와 개인용 설치본
- `docs/release-checklist.md`: 릴리즈 게이트
