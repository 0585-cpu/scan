# 테스트와 측정 방법

2026-09-11 작업에서 실제로 쓴 방법을 남긴다. 어느 경로로 무엇을 재야 하는지,
그리고 그날 실제로 밟은 함정들이다. 함정 쪽이 더 쓸모 있을 것이다.

---

## 1. 어느 진입점으로 테스트할 것인가

Netroach에는 스캔을 실행하는 경로가 네 개 있고, **서로 다른 코드를 탄다.**
잘못 고르면 쓰지도 않는 경로를 측정하게 된다.

| 진입점 | 실행 방법 | 무엇을 재기에 맞나 |
| --- | --- | --- |
| 엔진 바이너리 | `netroach-engine.exe scan ...` | 송신 속도, 패킷 동작, 스캔 정확성. Python이 끼지 않아 노이즈가 없다 |
| `_run_scan_job()` | 파이썬에서 직접 호출 | **GUI가 실제로 쓰는 경로.** DB 적재, 진행률, 작업 상태 |
| netroach CLI | `python -m netroach scan` | CLI 자체의 동작. **적재 경로가 GUI와 다르다** |
| HTTP API + 브라우저 | preview 서버 | 대시보드 렌더링, 사용자가 보는 것 |

**CLI와 GUI의 적재 경로가 다르다.** CLI(`cli.py`)는 스캔을 다 끝내고
`add_port_results()`를 한 번 부르고, GUI는 `_run_scan_job()`에서 배치 단위로
스트리밍 적재한다. 배치 크기나 접기 동작을 측정한다면 반드시 후자를 써야 한다.

---

## 2. 임시 DB로 측정하기

SQLite는 파일 하나라 테스트 환경이 따로 필요 없다. 측정마다 빈 DB를 만들면
이전 데이터의 영향도 없다.

```python
import tempfile, ipaddress
from netroach import api as A
from netroach.models import EngineSettings
from netroach.storage import SQLiteRepository

tmp = tempfile.mkdtemp()
db = f"{tmp}/m.db"
repo = SQLiteRepository(db)          # 스키마는 자동 생성된다

hosts = [ipaddress.ip_address("192.168.1.1")]
ports = list(range(1, 1025))
scan_id = repo.create_scan_job(
    targets="192.168.1.1", ports="1-1024",
    scope=["192.168.1.0/24"], params={},
)

A._run_scan_job(
    db, scan_id, hosts, ports,
    EngineSettings(protocol="tcp", syn_sweep=True, syn_retries=0,
                   timeout_ms=1000, concurrency=256,
                   rate_limit_per_sec=5000, service_probe=False),
)

job = repo.get_job(scan_id)
progress = repo.get_scan_progress(scan_id)
print(job["status"], progress["states"])
```

**작업을 `queued` 상태로 두어야 한다.** `_run_scan_job`이 안에서
`mark_scan_started()`를 부르는데 그건 `status='queued'`일 때만 성공한다. 미리
started로 바꿔두면 함수가 **조용히 early-return** 하고 아무 일도 일어나지
않는다. 그날 이걸로 한참 헤맸다.

---

## 3. 단계별 시간 가르기

SYN 스윕은 **모든 재시도가 정착할 때까지 결과를 하나도 저장하지 않는다.** 그
성질을 경계선으로 쓰면 스윕과 저장을 나눌 수 있다.

```python
import threading, time

marks = {}; t0 = time.monotonic(); done = threading.Event()

def watch():
    probe = SQLiteRepository(db)      # 별도 연결. WAL이라 쓰기를 막지 않는다
    while not done.is_set():
        p = probe.get_scan_progress(scan_id)
        if p and p["completed_results"] > 0:
            marks["first"] = time.monotonic() - t0     # 첫 결과 = 스윕 끝
            return
        time.sleep(0.05)

threading.Thread(target=watch, daemon=True).start()
A._run_scan_job(...)
done.set()

total = time.monotonic() - t0
sweep = marks.get("first", total)
store = total - sweep
print(f"스윕 {sweep:.1f}s | 저장 {store:.1f}s | {len(hosts)*len(ports)/store:,.0f}/s")
```

**이 "저장 처리량"이 SQLite만의 속도가 아니라는 점을 기억할 것.** Rust의 NDJSON
직렬화, 파이프, Python 파싱, SQLite 쓰기, 접기까지 전부 포함한 파이프라인 전체
수치다.

---

## 4. 송신 속도 재기

엔진이 스윕 중에 내보내는 `sweep_progress` 이벤트를 그대로 읽으면 된다. DB가
끼지 않아 순수 송신 성능이 나온다.

```bash
netroach-engine.exe scan --scan-id r --targets 192.168.1.0/24 --ports 1-256 \
  --timeout-ms 500 --concurrency 16 --rate-limit-per-sec 5000 \
  --syn-sweep --syn-retries 0 2>/dev/null | python -c "
import sys, json, time
t0 = time.monotonic(); last = None
for line in sys.stdin:
    e = json.loads(line)
    if e.get('event') == 'sweep_progress' and e['sent'] > 0:
        last = (e['sent'], time.monotonic() - t0)
if last:
    print(f'{last[0]/last[1]:,.0f} pps')
"
```

설정값과 실제값을 반드시 같이 볼 것. 그날 **설정 5,000인데 실제 2,387**이었고,
그 격차가 배치 송신을 만들게 된 출발점이었다.

---

## 5. 실패를 재현할 때는 예외를 직접 받기

`_run_scan_job`은 예외를 잡아 `fail_scan()`으로 기록한다. 원인을 보려면 한 겹
아래인 `run_scan`을 직접 부르는 편이 빠르다.

```python
from netroach.engine import run_scan
try:
    run_scan(scan_id="direct", targets=hosts, ports=ports,
             target_expr="192.168.1.0/24", port_expr="1-256",
             settings=EngineSettings(protocol="tcp", syn_sweep=True, ...),
             on_event=lambda e: None, collect_results=False)
except Exception as exc:
    print(type(exc).__name__, exc)
```

기록된 사유를 읽을 때는 **`job["summary"]["error"]`**다. `job["error"]`는
존재하지 않는 키라 `None`이 나오고, 그걸 보고 "사유가 저장되지 않는다"고 잘못
결론 내린 적이 있다.

---

## 6. UI는 반드시 브라우저로 확인할 것

`dashboard_html()` 문자열에 `assertIn`을 거는 테스트는 **파일에 그 문자열이
있다**는 것만 증명한다. 화면이 맞게 그려지는지는 증명하지 않는다.

그날 요약 스트립에 진행률을 넣고 테스트도 통과했는데, 실제로 띄워 보니 **정작
제일 눈에 띄는 상단 고정 바는 그대로 0%**였다. 그건 다른 함수였고, 브라우저로
보지 않았으면 그대로 배포됐을 것이다.

```python
# preview 서버를 띄운 뒤, 페이지 안에서 실제 함수를 불러 결과를 읽는다
await refreshScans(false);
await refreshRunningProgress();
document.getElementById('progressStrip').innerText
```

**`dashboard.html`은 `lru_cache`로 캐시된다**(`netroach/dashboard.py`). 파일을
고쳐도 **서버를 재시작하기 전까지는 예전 내용이 서빙된다.** 브라우저에서 새
코드가 반영됐는지 먼저 확인할 것:

```javascript
progressSnapshot.toString().includes('sweep')   // false면 아직 캐시된 옛 페이지
```

---

## 7. 실제 DB를 오염시키지 말 것

`.claude/launch.json`의 preview 서버는 **기본 DB 경로**를 쓴다. 즉 데스크톱 앱이
쓰는 그 DB다. 브라우저로 테스트 스캔을 돌리면 실제 작업 목록에 남는다.

그날 테스트 스캔 12건이 실제 DB에 섞였고, 만든 ID를 기록해뒀다가 하나씩
지워야 했다. 브라우저 테스트가 필요하면 **끝나고 반드시 지울 것**이며, 지울
때는 자기가 만든 ID만 정확히 지정할 것. 삭제 전에 개수를 대조하는 가드를 두면
남의 작업을 지우는 사고를 막는다.

```javascript
const mine = ['8e8380e9', 'a4cafdfa'];      // 이 세션이 만든 것만
const rows = (await fetch('/v1/scans?limit=60').then(r=>r.json())).scans;
const targets = rows.filter(j => mine.includes(j.id.slice(0,8)));
if (targets.length !== mine.length) return 'REFUSING';   // 하나라도 안 맞으면 중단
```

---

## 8. 성능 가설은 실험으로 배제할 것

"이게 병목일 것"이라는 추정은 대개 틀린다. 그날 프로브마다 도는
`drain_answers`(뮤텍스 2회 + 채널 드레인)가 범인이라고 확신했고, 64번에 한 번만
돌도록 바꿔 재보니 **2,386 pps로 완전히 동일**했다. 배제하고 나서야 진짜 원인인
패킷당 드라이버 호출로 갔다.

실험은 되돌릴 수 있게 할 것:

```bash
cp src/syn_runner.rs /tmp/backup.rs
# ... 수정하고 측정 ...
cp /tmp/backup.rs src/syn_runner.rs        # 반드시 복구
git diff --stat                            # 복구됐는지 확인
```

---

## 9. 정확성은 속도와 함께 재야 한다

속도를 올리는 변경은 **결과가 그대로인지 같이 확인**해야 한다. 그러지 않으면
더 빠르게 틀린 답을 내는 도구가 된다.

그날 호스트당 약 96 pps에서 같은 대역이 **열린 포트 3개 중 2개만** 보고했다.
속도만 봤다면 "24,000 pps 달성"으로 끝났을 것이다.

| 전체 속도 | 호스트당 | open | closed |
| --- | --- | --- | --- |
| 5,000 pps | 19.8 | 3 | 255 |
| 24,423 pps | 96.5 | **2** | 92 |

그리고 이 손실은 **Npcap 드롭 카운터가 0**이었다. 대상이 응답을 만들지 못한
것이라 드라이버 입장에서는 잃은 것이 없다. 즉 **드롭 검사로 잡히지 않는 손실이
존재한다**는 뜻이고, `filtered` 비율이 그 유일한 신호다.

---

## 10. 문자열 치환으로 코드를 고칠 때

같은 문자열이 파일에 여러 번 나오면 첫 번째가 바뀐다. 그날
`repo.mark_scan_started(scan_id)`를 바꾸려다 **전혀 다른 테스트의 줄**을 지웠고,
그 테스트가 깨지고 나서야 알았다.

- 치환 전에 몇 번 나오는지 세어볼 것 (`grep -c`)
- 여러 번 나오면 줄 번호로 지정하거나, 앞뒤를 포함해 유일하게 만들 것
- 치환 후 `git diff`로 **의도한 곳만 바뀌었는지** 확인할 것

---

## 11. 백그라운드 빌드 로그는 직접 파일로 남길 것

백그라운드 작업의 출력 파일은 **앞부분이 유실될 수 있다.** 그날 빌드 로그의
시작 부분이 사라져 Npcap 서명 검증 줄이 보이지 않았고, 설치본에 Npcap이 안
들어간 줄 알고 다시 빌드했다.

```bash
python -u tools/build_desktop.py ... > build.log 2>&1
```

`-u`로 버퍼링을 끄고 직접 리다이렉트하면 전체가 남는다. 빌드가 끝나면 증적을
확인할 것:

```bash
grep -c "verified Npcap installer Authenticode signer" build.log   # 2가 정상
grep -E "removed private|restored standard" build.log              # 정리 확인
```

서명 검증이 **2회** 찍히는 것이 정상이다. 원본 1회, staging 복사본 1회로 빌드
도중 파일이 바뀌지 않았음을 보장하는 설계다.

---

## 12. 릴리스 자산은 다시 받아서 대조할 것

업로드가 끝났다고 파일이 온전하다는 보장은 없다.

```bash
gh release download v0.2.3 --dir /tmp/verify
sha256sum /tmp/verify/Netroach_0.2.3_x64-setup.exe
cat /tmp/verify/Netroach_0.2.3_x64-setup.exe.sha256
```

설치본 크기가 이전 릴리스와 다르다고 해서 구성요소가 빠진 것은 아니다. 0.2.2가
0.2.1보다 44MB 작았던 이유는 Microsoft가 배포하는 WebView2 오프라인 설치
프로그램이 246.6MB에서 202.9MB로 바뀌었기 때문이다. 무결성은 크기가 아니라
`.sha256`으로 판단한다.
