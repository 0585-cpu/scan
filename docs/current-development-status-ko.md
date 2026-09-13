# Netroach 현재 개발 현황

이 문서는 2026-09-13 기준 Netroach의 구현, 검증, 배포 상태를 한곳에 정리한 기준 문서다. 현재 릴리스 버전은 `0.2.5`이다.

## 1. 현재 배포 상태

| 항목 | 현재 값 |
| --- | --- |
| 저장소 | 비공개 GitHub 저장소 `0585-cpu/scan` |
| 브랜치/기준 태그 | `main` / `v0.2.5` |
| 최신 공개 릴리즈 | [Netroach 0.2.5](https://github.com/0585-cpu/scan/releases/tag/v0.2.5) |
| 릴리스 설치본 | `Netroach_0.2.5_x64-setup.exe` |
| 설치 파일 크기 | 382,457,038 bytes |
| 설치 파일 SHA-256 | `db9a2f3655fbed3e836310ffb8f42267756296552c408781d4ef689dd8d990d9` |
| 릴리스의 Npcap 정책 | 설치 파일에 포함하지 않음. 대상 PC 사용자가 공식 Npcap을 직접 설치 |
| 현재 개발 PC Npcap | 1.88, 서비스 실행 중, `AdminOnly=0` |
| 현재 개발 PC Netroach | 0.2.5 설치 및 실행 확인 |
| Netroach 설치본 서명 | 코드 서명 없음 |

`0.2.5`부터 기본 배포 경계는 **Npcap 사용자 직접 설치**다. Netroach 설치본은 Npcap
설치 파일을 포함하거나 자동 다운로드하지 않는다. SYN 엔진은 SDK로 빌드하지만 대상 PC에서
공식 Npcap 설치와 접근 권한이 확인될 때만 사용할 수 있고, 그렇지 않으면 TCP Connect를
사용한다. Npcap 포함 개인용 설치본은 별도의 재배포 권한과 명시적 요청이 있을 때만 만든다.

`0.2.5` 릴리스의 해시와 sidecar 일치, 생성된 NSIS 스크립트의 Npcap 설치 항목 부재,
패키지 리소스 엔진의 `syn_sweep=true`와 버전 `0.2.5`를 확인했다. 현재 PC의 0.1.0을
0.2.5로 교체한 뒤 실제 UI, health 응답, 이 PC의 Wi-Fi 주소에 대한 raw SYN도 확인했다.

### 0.2.5 릴리스 증적 (2026-09-13)

- `tools/build_desktop.py --syn-sweep --npcap-sdk-lib C:\npcap-sdk\Lib\x64 --bundles nsis`로 빌드했다.
- Npcap 설치 파일 인수 없이 빌드했고, staging 및 번들 위치에 Npcap 설치 파일이 없음을 확인했다.
- 생성된 NSIS 스크립트에 Npcap 참조가 없고, 패키지 리소스 엔진은 `0.2.5`, `syn_sweep=true`다.
- NSIS 완료 뒤 표준 Connect 엔진(`syn_sweep=false`) staging 복원을 확인했다.
- 설치 파일과 `.sha256` sidecar 일치 확인.
- 설치 파일 자체는 코드 서명되지 않았다(`NotSigned`).

## 2. 제품 목적과 안전 경계

Netroach는 허가받은 대상의 네트워크 점검, 서비스 식별, PCAP 분석 및 증적 수집을 위한 로컬 도구다.

- 활성 스캔과 패킷 송신에는 명시적인 허가 확인과 `scope`가 필요하다.
- SYN 스캔은 Windows IPv4 TCP 전용이다.
- exploit 검사, 은폐·우회, 출발지 위조 스캔, 임의 raw byte 주입은 구현하지 않는다.
- JSON 플러그인은 데이터만 확장하며 임의 코드를 실행하지 않는다.
- 비루프백 API 바인드는 토큰 인증을 요구한다.

## 3. 구현된 기능

### 스캔과 서비스 분석

- Rust 엔진 기반 TCP Connect, Windows IPv4 TCP SYN, UDP 응답 스캔
- 대상 호스트명/IP/CIDR, 제외 CIDR, 포트 목록·파일, 기본·사용자 포트 프로필
- TCP/TLS/HTTP와 주요 UDP 서비스 식별, 배너 및 TLS 인증서 정보 분석
- 작업량·동시성·속도 제한, 취소, 중단 작업 복구
- 결과 이벤트와 독립된 heartbeat로 장시간 SYN 작업의 잘못된 복구 방지
- SYN 전송 속도 최대 5,000 pps, 재시도 0~2회
- Npcap 장치와 Windows 경로·인터페이스를 정확히 연결하며, 모호하거나 지원되지 않는 경우 실패 처리

### 증적과 결과 관리

- SQLite 기반 작업 이력, 포트 결과, 메모·태그 및 이미지 증적 저장
- Playwright Chromium을 이용한 웹 화면 캡처
- 웹 이외 TCP 서비스의 실제 콘솔 창 캡처와 비인증 단계 터미널 이미지 fallback
- JSON, CSV, NDJSON, Excel 내보내기
- HTML·Markdown 보고서와 인페이지 미리보기·파일 저장
- PCAP/PCAPNG 스트리밍 분석, 제한된 라이브 캡처, Windows `pktmon` 지원
- 승인 기반 ICMP/TCP/UDP/DNS/HTTP 템플릿 패킷 송신
- HTTP OAST 콜백 기록과 JSON 데이터 플러그인

### 실행 환경과 데스크톱

- FastAPI REST API와 단일 HTML/CSS/JavaScript 대시보드
- Tauri 2 Windows 데스크톱 셸
- PyInstaller 백엔드, Rust 엔진, Playwright Chromium, WebView2 오프라인 설치 프로그램을 포함한 독립 실행형 NSIS 설치본
- 대상 PC에 Python, Node.js, Rust 또는 첫 실행 시 인터넷 연결이 없어도 실행 가능
- 앱 종료 시 자식 백엔드 프로세스 종료

## 4. TCP 스캔 동작 기준

대시보드의 TCP 기본값은 SYN 스캔이다. CLI/API의 `syn_sweep` 필드는 호환성을 위해 호출자가 명시적으로 선택한다.

| 대시보드 선택 | 포트 확인 | 서비스·배너 | 증적 수집 |
| --- | --- | --- | --- |
| 기본, 서비스 탐지 OFF | SYN만 수행 | 수행하지 않음 | 수행하지 않음 |
| 기본, 서비스 탐지 ON | SYN-open 포트만 Connect로 재확인 | 수행 | 웹 이미지 또는 콘솔 증적 자동 수집 |
| `TCP Connect 스캔만 사용` | 선택한 모든 포트를 Connect로 스캔 | 서비스 탐지 선택에 따름 | 서비스 탐지 선택에 따름 |

SYN-ACK은 `open`, RST는 `closed`, 최종 무응답은 `filtered`로 기록한다.

**열린 포트를 찾으면 스윕이 직접 RST를 보내 half-open을 닫는다.** 스캔 호스트의
방화벽이 예상 못 한 SYN-ACK를 조용히 버려서 커널 RST가 나가지 않기 때문이다.
게이트웨이 80포트를 SYN 하나로 건드리고 캡처한 결과, 수정 전에는 대상의 SYN-ACK
4개에 우리 RST 0개였고 대상이 half-open을 자체 타임아웃까지 유지했다. 수정 후에는
SYN-ACK 2개에 RST 1개로, 대상이 backlog 칸을 즉시 되찾는다. backlog가 한두 칸인
임베디드·OT 장비에서 그 칸이 30~60초 동안 막히는 것을 막기 위한 것이다. 서비스 탐지용 후속 Connect가 실패해도 이미 관찰한 SYN-open 상태를 닫힘으로 낮추지 않는다. 루프백 대상은 raw SYN 대신 Connect 경로를 사용한다.

## 5. Npcap과 SYN 설치 동작

기본 SYN 설치 후보는 `tools/build_desktop.py`에 `--syn-sweep`과 Npcap SDK 라이브러리
경로만 지정해 만든다. SDK는 엔진 링크에만 필요하며 설치 파일에는 들어가지 않는다.

대상 PC 사용 절차는 다음과 같다.

1. Netroach는 Npcap이 없어도 설치한다.
2. Npcap이 없거나 접근 권한이 없으면 SYN 기능을 비활성화하고 조치 안내를 표시한다.
3. 그 상태에서도 `TCP Connect 스캔만 사용`은 동작한다.
4. 사용자가 Npcap 공식 설치 파일을 직접 받아 설치한 뒤 Netroach를 재시작한다.
5. 개인 PC에서 비관리자 SYN이 필요하면 Npcap 설치 시 관리자 전용 제한을 선택하지 않아
   `AdminOnly=0`으로 둔다.
6. 재시작 후 기능 진단에서 SYN 사용 가능 상태를 확인한다.

`AdminOnly=0`은 일반 사용자 계정에서도 Npcap 캡처·송신 장치 접근을 허용한다. 개인 PC에서 비관리자 SYN 스캔을 사용하기 위해 선택한 설정이며, 여러 사용자가 공유하는 PC에서는 로컬 권한 범위를 고려해야 한다.

Npcap은 다른 프로그램도 사용할 수 있는 시스템 공유 드라이버이므로 Netroach 설치·제거
프로그램은 Npcap을 설치하거나 제거하지 않는다. 빌드가 끝나면 SYN 전용 엔진 staging을
표준 Connect 엔진으로 복원한다.

## 6. 대시보드와 동작 결함 수정

`0.2.0`~`0.2.5`에서 반영된 주요 UI·동작 수정은 다음과 같다.

- 검색 가능한 작업 목록을 선택 작업의 요약·내보내기·결과·증적보다 위로 이동
- 작업 목록을 독립 스크롤 영역으로 만들어 긴 이력에서도 결과 영역 위치 유지
- 오래된 작업/검색 응답이 현재 선택 결과를 덮는 비동기 순서 역전 방지
- 열린 포트 재스캔에 이전 포트 입력이 섞이던 문제 수정
- 저장된 포트 프로필 복원 누락 수정
- 다른 작업 선택 시 증적 재수집 상태가 잘못 이동하던 문제 수정
- 사용할 수 없는 취소·재수집·고급 상태 버튼이 표시되던 문제 수정
- 데스크톱 WebView에서 새 창이 열리지 않아 보고서·증적·내보내기가 동작하지 않던 문제를 인페이지 뷰어로 전환
- Linux/macOS의 Windows 전용 `ctypes` 타입 검사 오류 수정
- OS 고정 경로 및 실제 타이머 정밀도에 의존하던 CI 테스트를 플랫폼 독립·결정적 테스트로 변경
- ControlDeck 2001 테마 적용: Windows 2000 계열 파란 제목 표시줄, 회색 양각·음각
  컨트롤, 디지털 상태 표시, 표 격자, 키보드 포커스·고대비 지원
- 390px 모바일 폭에서 탐색 막대 압축, 상태 표시 줄바꿈, 결과 영역 수평 넘침 방지
- 사이드바에는 포트 스캔만 남기고 시작 화면도 포트 스캔으로 변경. 제거된 화면의 코드와
  API는 삭제하지 않고 탐색 메뉴에서만 숨김
- 사이드바가 56px에서 184px로 확장될 때 같은 그리드 열도 함께 확장해 본문을 덮지 않도록 수정
- 주요 스캔 버튼 글자를 최소 14px로 높이고 비활성 글자 대비를 개선하며, 긴 글자 줄바꿈과
  프리셋 버튼의 중첩 양각 스타일을 정리
- 서비스 탐지, TCP Connect 전용, UDP 서비스 탐지의 긴 설명을 `(?)` 도움말로 정리하고
  마우스 호버·키보드 포커스·터치 포커스에서 표시. 체크박스 상태와 Npcap별 안내는 유지
- 서비스 탐지 체크에 따른 기본 SYN 및 열린 포트 Connect 재확인 UI 회귀 테스트 복구
- 작업 ID·상태·대상과 호스트 요약을 15~16px, 굵기 600으로 조정해 과도한 굵기 없이 가독성 개선
- 웹 리다이렉트 증적에 촬영한 최종 URL 기록
- 콘솔 캡처가 정확한 제목을 찾지 못했을 때 비슷한 다른 창을 선택하지 않도록 수정

## 7. 구조와 주요 소스

```text
Tauri 데스크톱 창
  -> 127.0.0.1의 임의 포트에서 PyInstaller 백엔드 실행
    -> FastAPI API와 대시보드 제공
      -> Python: 승인·입력 검증, 작업 상태, SQLite, 증적
      -> Rust 엔진: TCP/UDP/SYN 스캔과 서비스 분석
      -> NDJSON 결과를 Python이 SQLite에 스트리밍 저장
```

| 경로 | 역할 |
| --- | --- |
| `netroach/api.py` | API, 스캔 실행, heartbeat, 복구, 증적 연계 |
| `netroach/engine.py` | Rust 엔진 실행과 NDJSON 변환 |
| `netroach/storage.py` | SQLite 스키마·저장소 |
| `netroach/evidence.py` | 웹·콘솔·터미널 증적 |
| `netroach/static/dashboard.html` | 대시보드 UI와 클라이언트 상태 관리 |
| `crates/netroach-engine/src/main.rs` | TCP/UDP 실행과 SYN 경로 연결 |
| `crates/netroach-engine/src/syn_sweep.rs` | SYN 패킷·쿠키·응답 검증 |
| `crates/netroach-engine/src/netlink.rs` | Windows 라우트와 Npcap 장치 연결 |
| `crates/netroach-engine/src/syn_runner.rs` | Npcap 송수신·재시도·상태 집계 |
| `desktop/src-tauri/installer-hooks.nsh` | 명시적으로 Npcap을 포함하는 사설 빌드의 설치 훅 |
| `tools/build_desktop.py` | 백엔드·엔진·브라우저 및 선택적 Npcap 설치 파일을 조합하는 설치본 빌드 |
| `tests/test_dashboard_browser.py` | 실제 Chromium과 격리 API/DB 기반 UI 회귀 검사 |
| `docs/testing-and-measurement-ko.md` | 어느 진입점으로 무엇을 측정하는지와 실제로 밟은 함정들 |

## 8. 확인된 검증 결과

### `0.2.5` 릴리스 검증 (2026-09-13)

- Python 테스트 482개 통과, 기존 Scapy DNS 경고 1개
- 실제 Chromium 대시보드 테스트 20개 통과
- Rust 기본 빌드 60개 통과(단위 46, 통합 14)
- Rust `syn-sweep` feature 90개 통과(단위 77, 통합 13)
- Ruff, mypy 29개 소스 파일, `cargo fmt --check` 통과
- 실제 Chromium에서 넓은 화면과 390×844 화면의 ControlDeck 테마·배치·넘침을 확인
- Npcap SDK만으로 SYN 설치 후보 빌드, SHA-256 sidecar 일치, 내장 엔진
  `syn_sweep=true`, Npcap 설치 파일 미포함 확인
- 현재 PC 설치 레지스트리·실행 파일·health의 앱/엔진 버전이 모두 `0.2.5`로 일치
- 현재 Npcap 1.88, `AdminOnly=0`, 서비스 실행 상태에서 비관리자 raw SYN으로 이 PC의
  `198.51.100.39:18082` 임시 HTTP 포트를 `open`으로 확인(1.35ms, 오류 0). 임시 서버는 종료함
- 재설치된 실제 패키지에서 사이드바 항목 1개, 기본 화면 `포트 스캔`, 확장 rail 184px와
  본문 시작 184px(겹침 0), 주요 버튼 14px 및 기존 작업 39건 보존 확인
- 재설치된 실제 패키지에서 도움말 `(?)` 3개, 서비스·Connect·UDP 설명의 포커스 표시,
  체크 상태 보존 및 health의 앱/엔진 `0.2.5`, `syn_sweep=true`, Npcap 감지를 확인

### SYN 스윕 속도와 정확성 측정 (2026-09-11)

허가된 자체 대역에서 측정했다. 숫자는 이 스캔 PC 기준이며 다른 장비에서는 달라진다.

| 항목 | 값 |
| --- | --- |
| 프레임 하나씩 송신 | 초당 2,387개 (설정 5,000에 미달) |
| 배치 송신 적용 | 초당 5,010개 |
| 송신 경로 천장 | 약 35,000개 (설정 20,000까지는 추종, 이후 평탄) |
| 결과 저장 | 초당 50,264건 (배치 250→5,000, closed 접기 수정 후) |

**호스트당 속도가 정확성을 가른다.** 같은 대역·같은 포트에서 속도만 바꾼 결과:

| 전체 속도 | 호스트당 | open | closed |
| --- | --- | --- | --- |
| 5,000 pps | 19.8 | **3** | 255 |
| 24,423 pps | 96.5 | **2** | 92 |

호스트당 96개에서 열린 포트 하나를 놓쳤고, 이때 **Npcap 드롭 카운터는 0**이었다.

손실은 그보다 훨씬 낮은 속도에서도 일어난다. 같은 게이트웨이 200포트를 재시도 1로
반복 측정한 결과다.

| 속도(단일 호스트) | open | filtered |
| --- | --- | --- |
| 5,000 pps | **없음** | 49~107 |
| 1,000 pps | 80 (3회 모두) | 8~24 |
| 500 pps | 80 | 0 |

**단일 호스트에 5,000 pps는 재시도를 해도 열린 포트를 놓친다.** 확률적이어서
잡히는 실행도 있으므로 한 번의 성공을 근거로 삼으면 안 된다.

포트 수가 늘면 부하가 길어져 1,000 pps도 부족하다. 같은 게이트웨이 512포트,
재시도 1로 반복한 결과다.

| 속도 | 80번 발견 | filtered |
| --- | --- | --- |
| 1,000 pps | 3회 중 2회 | 34~50 |
| **500 pps** | **5회 중 5회** | **0** |

`filtered`가 0이 되는 지점에서만 결과가 안정적이며, 놓친 실행은 filtered가
38이었다. 좁은 스윕의 바닥값을 500으로 정한 근거가 이 측정이다. 다만 이는 이
장비 한 대에 맞춘 값이므로 보장이 아니라 기본값이다. 더 세게 제한하는 대상은
여전히 미응답을 남기며, 그것이 레이트를 더 낮추라는 신호다.
대상이 그 속도로 응답을 만들지 못한 것이므로 드라이버는 잃은 것이 없다. 이
손실은 드롭 검사로 잡히지 않으며 `filtered` 비율이 유일한 신호다. 호스트당
상한을 10으로 정한 근거가 이 측정이다.

### `v0.2.2` 과거 로컬 검증

- Python 테스트 450개 통과, 10개 건너뜀
- Rust 기본 빌드 57개 통과 (단위 43, 통합 14)
- Rust `syn-sweep` feature 80개 통과 (단위 67, 통합 13)
- Ruff 통과, mypy의 Windows·Linux·macOS 대상 검사 통과, `cargo fmt --check` 통과
- 기본 빌드가 Npcap SDK 없이 컴파일되고 `--syn-sweep`을 거부함을 실행으로 확인
- 엔진 통합 테스트가 `capabilities`의 주장과 실제 `--syn-sweep` 수용 여부를 대조하므로,
  빌드가 거부할 기능을 광고할 수 없다
- 실제 스윕과 증적 수집에서 진행률이 단계별로 갱신되고, 단계가 끝나면 결과 기반
  진행률로 넘어감을 브라우저에서 확인

### `v0.2.1` 릴리즈 과정에서 확인한 것

- 로컬 Python 테스트 451개 통과, 실제 Chromium UI 테스트 10개 포함
- Rust 기본 빌드 테스트 56개 통과
- Rust `syn-sweep` feature 테스트 75개 통과
- Ruff 통과
- mypy의 Windows, Linux, macOS 대상 검사 통과
- [GitHub Actions 실행 34508890124](https://github.com/0585-cpu/scan/actions/runs/34508890124)의 7개 작업 통과
  - Python: Windows, Linux, macOS
  - Rust: Windows, Linux, macOS
  - Rust 1.88 최소 버전 빌드
- NSIS 내부 311개 파일 압축 무결성 확인
- 릴리즈 설치 파일과 `.sha256` sidecar 일치 확인
- GitHub에 업로드된 두 자산의 크기와 SHA-256이 로컬 파일과 일치함을 확인
- 설치본에서 추출한 Npcap 1.88의 Nmap Software LLC 서명과 원본 SHA-256 일치 확인
- frozen 백엔드의 앱/엔진 버전 `0.2.1`, health API, 대시보드 소스 일치 확인
- 실제 Chromium에서 작업 목록이 결과 위에 표시되고 포트 결과가 렌더링되며 page error가 없음을 확인
- 추출한 SYN 지원 엔진으로 허가된 루프백 HTTP 서버에 서비스 탐지 OFF/ON 동작 확인

### 실제 LAN 교차검증 (2026-09-11, 통과)

허가된 자체 게이트웨이 `198.51.100.254`, 포트 `1-1024`, 서비스 탐지 OFF.
비관리자 계정에서 `AdminOnly=0` Npcap으로 실행했다.

| 방식 | 설정 | open | closed | filtered | 시간 |
| --- | --- | --- | --- | --- | --- |
| SYN | 5,000pps, 재시도 1 | **80** | 697 | 326 | 6.8s |
| SYN | 5,000pps, 재시도 2 | **80** | 843 | 180 | 10.0s |
| SYN | 1,000pps, 재시도 2 | **80** | 1,004 | 19 | 10.4s |
| SYN | 200pps, 재시도 2 | **80** | 1,023 | 0 | 8.2s |
| Connect | 동시성 16 | **80** | 1,020 | 3 | 133.6s |

- **모든 설정에서 열린 포트 집합이 일치**했다(80/tcp). 미탐·오탐 없음. 포트 80이
  실제로 열려 있음은 별도 소켓 연결(16ms)로 확인했다.
- `filtered`는 코드 결함이 아니라 **대상의 RST 레이트 제한**이다. 송신 레이트를
  낮추면 326 → 180 → 19 → 0으로 단조 감소했다. 200pps에서 1,024개 포트를 전부
  확정 분류했고, 이는 Connect보다 정확하며 16배 빠르다.
- 같은 대상에서 **Connect는 동시성에 취약**했다: 512에서 803개가 filtered로
  빠지고 열린 포트 80까지 놓쳤으며, 64에서 겨우 찾고 16에서야 안정됐다. 이
  장비에 대해서는 SYN이 Connect보다 신뢰도가 높다.
- 대역 밖 주소(`8.8.8.8`) 라우트 해석이 게이트웨이 MAC으로, on-link 대상이
  자기 MAC으로 해석됨을 확인했다(패킷 송신 없이 IP Helper 호출만 사용).

운영 지침: **`filtered` 개수가 신뢰도 계기판이다.** 비율이 높으면 대상이 RST를
레이트 제한하는 것이므로 송신 레이트를 낮추거나 재시도를 올린다. 0에 수렴하면
그 결과는 신뢰할 수 있다. 소비자용 공유기와 OT 장비는 공격적으로 제한하며,
일반 서버·PC는 그렇지 않으므로 200pps는 이 장비 기준값이지 일반 권장값이 아니다.

## 9. UNVERIFIED 및 남은 위험

다음 항목은 아직 최종 인수 증적이 없으므로 `UNVERIFIED`다.

- Npcap이 없는 깨끗한 Windows VM에서 Netroach 설치, Connect fallback, 공식 Npcap 직접
  설치, `AdminOnly=0`, 재시작 후 SYN 활성화, 제거 전 과정
- **다른 대역 호스트에 대한 종단 SYN 스윕.** 라우트 해석은 확인했으나 게이트웨이
  너머 호스트에 실제로 SYN을 보내고 응답을 받는 경로는 아직 돌려보지 않았다.
  이 분기가 틀리면 해당 대역 전체가 조용히 `filtered`로 보고된다.
- **다중 호스트 SYN 스윕의 교차검증.** /24 대역 스윕이 완료되고 총계가 맞는 것은
  확인했으나, 열린 포트 집합을 Connect 결과와 대조한 교차검증은 단일 호스트로만
  했다. `tools/syn_crosscheck.py`로 같은 대역을 두 방식으로 돌려 비교하면 된다.
- **호스트 500대를 넘는 스윕.** 호스트당 예산이 실제로 열리는 구간이지만 그만한
  대역이 없어 측정하지 못했다. 이 구간에서 수신 큐(16,384)와 캡처 스레드가
  버티는지는 미확인이다.
- **온링크 /24 전체의 병렬 ARP.** /25 126대까지는 2.52초로 측정했으나(아래 문서
  참조) 254대 4배치 구간은 환산값이다.
- **`error` 상태에서의 Governor 동작.** 임시 포트 고갈이 실제로 발생하는지 자체가
  미측정이다.

0.2.4 이후 커밋 두 개(`c46ef28`, `30cf9b1`)의 변경 내용·측정치·남은 항목은
`docs/scan-load-and-evidence-handoff-ko.md`에 있다. 두 커밋과 문서 커밋 `1f28f56`은
`origin/main`에 반영되어 있다.

추가 제한은 다음과 같다.

- Netroach 설치 파일 자체가 코드 서명되지 않아 SmartScreen 또는 조직 보안 정책이 경고·차단할 수 있다.
- `AdminOnly=0`은 같은 PC의 다른 로컬 사용자에게도 Npcap 접근을 허용한다.
- 설치본 크기가 큰 이유는 Chromium과 WebView2 오프라인 구성요소를 함께 포함하기 때문이다.
- 루프백 SYN 테스트는 설계상 Connect 예외이므로 실제 raw SYN 성공을 증명하지 않는다. 루프백 대상을 SYN으로 요청해도 Connect로 처리되므로, 교차검증은 반드시 실제 LAN 주소로 해야 한다.

## 10. 다음 개발 우선순위

1. 깨끗한 Windows VM에서 Npcap 미설치 → Connect 사용 → 공식 Npcap 직접 설치 → SYN 활성화 기록
2. 소유하거나 명시적으로 허가받은 LAN에서 비관리자 raw SYN과 Connect 결과 비교
3. UI의 `raw 소켓 제한됨` 문구가 SYN 제한으로 오해되지 않도록 패킷 전송 권한과 SYN
   사용 가능 상태를 더 명확히 분리할지 검토
4. 외부 배포 시 Netroach 코드 서명과, Npcap을 포함해야 한다면 OEM 재배포 권한 마련

## 11. 함께 볼 문서

- `docs/user-guide.md`: 실제 사용법
- `docs/install.md`: 일반 설치·체크섬 확인
- `docs/desktop-packaging.md`: Windows 데스크톱 빌드
- `docs/syn-sweep-handoff.md`: SYN 구현 세부 인수인계
- `docs/scan-load-and-evidence-handoff-ko.md`: 스캔 부하 분산·증적 예산 인수인계 (0.2.4 이후)
- `docs/release-checklist.md`: 릴리즈 검증 체크리스트
- `docs/development-handoff-ko.md`: 다른 PC에서 개발을 이어가기 위한 환경·이전 가이드
- `docs/superpowers/specs/2026-09-10-syn-sweep-personal-installer-design.md`: SYN/Npcap 설계 기준
- `docs/superpowers/specs/2026-09-11-default-syn-service-evidence-design.md`: 기본 SYN·서비스 증적 동작 기준
