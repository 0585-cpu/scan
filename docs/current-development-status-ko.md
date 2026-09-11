# Netroach 현재 개발 현황

이 문서는 2026-09-11 기준 Netroach의 구현, 검증, 배포 상태를 한곳에 정리한 기준 문서다. 소스 기준은 `main`의 커밋 `4c9c35b03340d63202b2b59b5b7f6cbab1f64600`, 제품 버전은 `0.2.1`이다.

## 1. 현재 배포 상태

| 항목 | 현재 값 |
| --- | --- |
| 저장소 | 비공개 GitHub 저장소 `0585-cpu/scan` |
| 브랜치/태그 | `main` / `v0.2.1` |
| 릴리즈 | [Netroach 0.2.1 개인용 Npcap 포함 설치본](https://github.com/0585-cpu/scan/releases/tag/v0.2.1) |
| 설치 파일 | `Netroach_0.2.1_x64-setup.exe` |
| 설치 파일 크기 | 430,233,741 bytes |
| 설치 파일 SHA-256 | `ee55d1c08677fad6c92dd1edb6a8cd5fbe15550dd9684b5c2433e7d6510d658f` |
| 체크섬 파일 SHA-256 | `2862974a4780bc5e64e8743d0ebf8908f070332da5a94930b1a170b2c504524d` |
| 내장 Npcap | 1.88, Nmap Software LLC Authenticode 서명 확인 |
| Netroach 설치본 서명 | 코드 서명 없음 |

릴리즈는 개인 사용 목적의 비공개 설치본이다. Npcap Free Edition 설치 파일을 포함하므로 공개하거나 제3자에게 재배포하지 않는다. 다른 사용자나 고객에게 배포하려면 Npcap OEM 재배포 권한과 그에 맞는 설치 절차가 필요하다.

현재 개발 PC의 기존 Netroach 설치는 이 릴리즈로 교체하지 않았다. GitHub 릴리즈 게시와 로컬 설치 상태는 별개의 작업이다.

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

SYN-ACK은 `open`, RST는 `closed`, 최종 무응답은 `filtered`로 기록한다. 서비스 탐지용 후속 Connect가 실패해도 이미 관찰한 SYN-open 상태를 닫힘으로 낮추지 않는다. 루프백 대상은 raw SYN 대신 Connect 경로를 사용한다.

## 5. Npcap 포함 개인용 설치 동작

개인용 빌드는 `tools/build_desktop.py`에 `--syn-sweep`, Npcap SDK 라이브러리 경로, 직접 받은 공식 Npcap 설치 파일을 명시해 만든다.

설치 시 동작은 다음과 같다.

1. Npcap 드라이버가 1.88 이상이고 레지스트리의 `AdminOnly=0`이면 바로 진행한다.
2. 조건을 충족하지 않으면 설치본에 포함된 공식 Npcap UI를 UAC로 실행한다.
3. 사용자는 **Restrict Npcap driver's access to Administrators only**를 선택하지 않아야 한다.
4. Npcap 설치 후 버전과 `AdminOnly=0`을 다시 확인한다.
5. 설치 취소, 실행 실패, 낮은 버전 또는 `AdminOnly=1`이면 Netroach 설치도 중단한다.

`AdminOnly=0`은 일반 사용자 계정에서도 Npcap 캡처·송신 장치 접근을 허용한다. 개인 PC에서 비관리자 SYN 스캔을 사용하기 위해 선택한 설정이며, 여러 사용자가 공유하는 PC에서는 로컬 권한 범위를 고려해야 한다.

Npcap은 다른 프로그램도 사용할 수 있는 시스템 공유 드라이버이므로 Netroach 제거 프로그램은 Npcap을 제거하지 않는다. 빌드가 끝나면 임시 Npcap 설치 파일과 SYN 전용 엔진 staging을 제거하고 표준 Connect 엔진을 복원한다.

## 6. 대시보드와 동작 결함 수정

`0.2.0`~`0.2.1`에서 반영된 주요 UI·동작 수정은 다음과 같다.

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
| `desktop/src-tauri/installer-hooks.nsh` | Npcap 버전·`AdminOnly` 설치 전후 검사 |
| `tools/build_desktop.py` | 백엔드·엔진·브라우저·Npcap 포함 설치본 빌드 |
| `tests/test_dashboard_browser.py` | 실제 Chromium과 격리 API/DB 기반 UI 회귀 검사 |

## 8. 확인된 검증 결과

`v0.2.1` 릴리즈 과정에서 다음을 확인했다.

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

## 9. UNVERIFIED 및 남은 위험

다음 항목은 아직 최종 인수 증적이 없으므로 `UNVERIFIED`다.

- Npcap이 없는 깨끗한 Windows VM에서 포함 설치, UAC, `AdminOnly=0`, 취소·재실행·제거 전 과정
- 비관리자 계정에서 실제 LAN의 open/closed/filtered 대상에 대한 raw SYN 스캔
- 같은 실제 LAN 대상에서 SYN과 TCP Connect의 열린 포트 집합 교차검증
- 현재 PC의 기존 Netroach를 `v0.2.1` 설치본으로 교체한 뒤의 실행 검증

추가 제한은 다음과 같다.

- Netroach 설치 파일 자체가 코드 서명되지 않아 SmartScreen 또는 조직 보안 정책이 경고·차단할 수 있다.
- `AdminOnly=0`은 같은 PC의 다른 로컬 사용자에게도 Npcap 접근을 허용한다.
- 설치본 크기가 큰 이유는 Chromium과 WebView2 오프라인 구성요소를 함께 포함하기 때문이다.
- 루프백 SYN 테스트는 설계상 Connect 예외이므로 실제 raw SYN 성공을 증명하지 않는다.

## 10. 다음 개발 우선순위

1. 깨끗한 Windows VM에서 개인용 설치본 전체 설치·제거 시나리오 기록
2. 소유하거나 명시적으로 허가받은 LAN에서 비관리자 raw SYN과 Connect 결과 비교
3. 현재 PC 설치본 교체가 필요하면 별도 승인 후 설치·실행·증적 수집
4. 외부 배포가 필요해지는 경우 Npcap OEM 권한과 Netroach 코드 서명 체계 마련
5. 이후 변경은 `docs/release-checklist.md`의 패키지·실기기 게이트를 분리해 기록

## 11. 함께 볼 문서

- `docs/user-guide.md`: 실제 사용법
- `docs/install.md`: 일반 설치·체크섬 확인
- `docs/desktop-packaging.md`: Windows 데스크톱 빌드
- `docs/syn-sweep-handoff.md`: SYN 구현 세부 인수인계
- `docs/release-checklist.md`: 릴리즈 검증 체크리스트
- `docs/development-handoff-ko.md`: 다른 PC에서 개발을 이어가기 위한 환경·이전 가이드
- `docs/superpowers/specs/2026-09-10-syn-sweep-personal-installer-design.md`: SYN/Npcap 설계 기준
- `docs/superpowers/specs/2026-09-11-default-syn-service-evidence-design.md`: 기본 SYN·서비스 증적 동작 기준
