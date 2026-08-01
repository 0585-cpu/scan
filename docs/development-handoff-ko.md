# Netroach 개발 인수인계 및 다른 PC 이전 가이드

이 문서는 Netroach 소스 코드를 다른 PC로 옮겨 현재 상태에서 개발을 이어가기 위한 기준 문서다. 문서 기준 버전은 `0.1.0`이며 마지막 갱신일은 2026-08-01이다.

## 1. 가장 먼저 알아둘 내용

- 이 폴더는 Git 저장소다(`main` 브랜치). 아직 원격이 없으므로 다른 PC로 옮기려면 비공개 원격 저장소를 만들어 푸시한다.
- `target`, `dist`, `.venv`, `node_modules`, `__pycache__`는 빌드 산출물 또는 PC 종속 파일이므로 소스 저장소에 넣지 않는다.
- 스캔 이력과 증거 이미지는 소스 폴더가 아니라 Windows의 `%APPDATA%\Netroach\netroach.db`에 저장된다. 기존 데이터를 이어서 사용하려면 소스와 별도로 옮겨야 한다.
- 활성 스캔과 패킷 송신은 소유하거나 명시적으로 허가받은 대상에서만 사용한다. 프로그램도 `scope`와 명시적 승인 값을 요구한다.

## 2. 현재 개발 상태

현재 구현된 주요 기능은 다음과 같다.

- Rust 엔진 기반 고속 TCP connect 및 UDP 응답 스캔
- TCP, TLS, HTTP 및 주요 UDP 서비스 식별과 지문 분석
- 대상, 제외 CIDR, 포트 파일, 기본/사용자 포트 프로필 지원
- 스캔 범위 승인, 작업량 제한, 속도 제한 및 취소
- 중단된 API 스캔 작업 복구와 미완료 host/port만 재실행
- SQLite 기반 스캔 이력, 결과 메모·태그 및 증거 이미지 저장
- JSON, CSV, NDJSON, XLSX 내보내기와 HTML/Markdown 보고서
- PCAP/PCAPNG 스트리밍 분석과 제한된 라이브 캡처
- 승인 기반 ICMP, TCP, UDP, DNS, HTTP 템플릿 패킷 송신
- HTTP OAST 세션 및 콜백 기록
- JSON 데이터 플러그인을 이용한 포트 프로필과 서비스 지문 확장
- Playwright 웹 스크린샷 및 비인증 단계 터미널 증거 생성
- FastAPI REST API와 단일 파일 HTML/JavaScript 대시보드(`netroach/static/dashboard.html`)
- 루프백이 아닌 바인드에 대한 API 토큰 인증(`--api-token`, `NETROACH_API_TOKEN`)
- Tauri 2 기반 Windows 데스크톱 창
- PyInstaller Python 백엔드, Rust 엔진, Playwright Chromium 및 WebView2를 포함한 독립 실행형 NSIS 설치 프로그램

현재 버전 식별자는 아래 파일에 있다.

- Python 앱: `netroach/version.py`
- Rust 엔진: `crates/netroach-engine/Cargo.toml`
- Tauri 앱: `desktop/src-tauri/Cargo.toml`과 `desktop/src-tauri/tauri.conf.json`

릴리스할 때 네 곳의 버전이 일치하는지 확인해야 한다.

## 3. 구조와 실행 흐름

```text
Tauri 데스크톱 창
  -> 임의의 127.0.0.1 포트에서 PyInstaller 백엔드 실행
    -> FastAPI API 및 netroach/static/dashboard.html 화면 제공
      -> Python이 입력 검증, 승인 범위, 작업 상태, SQLite를 담당
      -> netroach-engine Rust 프로세스가 실제 TCP/UDP 스캔 수행
      -> Rust 엔진의 NDJSON 이벤트를 Python이 SQLite에 스트리밍 저장
      -> evidence.py가 Playwright/PowerShell 증거 이미지 생성
```

중요 디렉터리와 파일은 다음과 같다.

| 경로 | 역할 |
| --- | --- |
| `netroach/cli.py` | CLI 명령과 인자 정의 |
| `netroach/api.py` | FastAPI 엔드포인트와 백그라운드 스캔 작업 |
| `netroach/static/dashboard.html` | 별도 프런트엔드 프레임워크 없이 제공되는 대시보드 HTML/CSS/JavaScript 본문 |
| `netroach/dashboard.py` | 위 정적 파일을 읽어 제공하는 로더 |
| `netroach/auth.py` | 스캔 범위 승인과 API 토큰 결정 |
| `netroach/engine.py` | Rust 엔진 탐색, 실행, NDJSON 이벤트 변환 및 취소 |
| `netroach/storage.py` | SQLite 스키마와 저장소 계층 |
| `netroach/evidence.py` | Playwright 웹 캡처와 터미널 증거 이미지 |
| `netroach/config.py` | TOML 설정과 환경별 스캔 기본값 |
| `netroach/plugins.py` | 실행 코드가 아닌 JSON 데이터 플러그인 검증/병합 |
| `netroach/pcap.py` | PCAP/PCAPNG 분석 |
| `netroach/packet_sender.py` | 제한된 패킷 템플릿 검증과 송신 |
| `crates/netroach-engine/src/main.rs` | 실제 TCP/UDP 스캔 및 서비스 지문 처리 |
| `crates/netroach-engine/tests/engine_cli.rs` | Rust 엔진 CLI 통합 테스트 |
| `desktop/src-tauri/src/main.rs` | 백엔드 프로세스 시작, 헬스체크, 창 생성 및 프로세스 종료 |
| `netroach/frozen_backend.py` | PyInstaller 백엔드 진입점 |
| `tools/build_desktop.py` | 독립 실행형 Windows 설치 프로그램 전체 빌드 |
| `tools/package.py` | Python 기반 휴대용 ZIP/TAR 패키지 생성 |
| `tests/` | Python 단위·통합 테스트 |
| `docs/netroach.example.toml` | 설정 파일 예제 |
| `docs/desktop-packaging.md` | 데스크톱 빌드 세부 설명 |

## 4. 소스를 다른 PC로 옮기는 방법

### 권장: Git과 비공개 원격 저장소 사용

저장소는 이미 초기화돼 있으므로 원격만 연결하면 된다. 아래 주소는 본인 저장소로 바꾼다.

```powershell
git remote add origin https://github.com/<account>/<repository>.git
git push -u origin main
```

`git add` 후에는 반드시 `git status`를 확인한다. `target`, `dist`, `.venv`, `node_modules`, Playwright 브라우저 캐시와 스테이징된 백엔드/엔진 실행 파일이 포함되면 안 된다. `Cargo.lock`과 `desktop/package-lock.json`은 재현 가능한 빌드를 위해 포함한다.

다른 PC에서는 다음과 같이 받는다.

```powershell
git clone https://github.com/<account>/<repository>.git
cd <repository>
```

원격 저장소에 토큰이나 비밀번호를 직접 기록하지 않는다. 비공개 저장소라면 GitHub 로그인 또는 credential manager를 사용한다.

### 대안: 소스 폴더 직접 복사

Git을 아직 사용하지 않는다면 다음 항목을 제외하고 프로젝트 폴더를 압축해 옮긴다.

```text
target/
dist/
.venv/
desktop/node_modules/
**/__pycache__/
*.pyc
benchmark-results/
```

`target/desktop-playwright`는 약 수백 MB의 다운로드 캐시다. 인터넷이 없는 새 PC에서 설치 프로그램을 다시 빌드해야 하는 경우에만 별도 저장장치로 복사할 가치가 있다. 일반 개발 이전에는 새 PC에서 다시 내려받는 편이 안전하다.

## 5. 기존 사용자 데이터 옮기기

소스 코드만 옮기면 이전 스캔 이력은 따라오지 않는다. 앱을 완전히 종료한 다음 아래 파일을 별도로 백업한다.

```text
C:\Users\<기존사용자>\AppData\Roaming\Netroach\netroach.db
```

새 PC에서 Netroach를 한 번 실행해 `%APPDATA%\Netroach` 폴더를 만든 후 앱을 종료하고 DB를 복사할 수 있다. 더 안전한 방법은 기존 PC의 대시보드 또는 `/v1/db/export`로 백업하고 새 PC의 `/v1/db/import`로 가져오는 것이다.

설정과 플러그인을 소스 밖에서 관리했다면 다음 파일도 따로 복사한다.

- 사용자 `netroach.toml`
- 사용자 JSON 플러그인 파일
- 분석할 PCAP/PCAPNG 원본
- 별도로 저장한 보고서와 내보내기 파일

## 6. 새 Windows 개발 PC 준비

### 공통 도구

다음 프로그램을 설치한다.

- Git
- Python 3.10 이상; CI 기준은 Python 3.12
- Rustup과 stable Rust
- Node.js LTS와 npm
- Visual Studio Build Tools의 **Desktop development with C++** workload
- 선택 사항: VS Code와 Python/Rust Analyzer 확장
- 선택 사항: Npcap. 라이브 캡처와 raw packet 송신을 개발할 때 필요

엔진은 `crates/netroach-engine/Cargo.toml`에 `rust-version = "1.88"`을 명시한다. 엔진 소스 자체는 1.83이면 되지만(`io::ErrorKind::HostUnreachable` 안정화 버전), 잠긴 의존성 트리가 1.88을 요구한다. CI의 `rust-msrv` job이 이 하한을 실제로 검증한다.

Windows Tauri 빌드는 MSVC Rust 도구 체인을 권장한다.

```powershell
rustup toolchain install stable-x86_64-pc-windows-msvc
rustup default stable-x86_64-pc-windows-msvc
rustup target add x86_64-pc-windows-msvc
```

Visual Studio Build Tools를 설치하지 못한 PC에서는 GNU 도구 체인을 사용할 수 있다.

```powershell
rustup toolchain install stable-x86_64-pc-windows-gnu --profile minimal
```

현재 설치 프로그램은 GNU 빌드에서도 실행되도록 `WebView2Loader.dll`을 명시적으로 스테이징한다. 관련 코드는 `tools/build_desktop.py`와 `desktop/src-tauri/tauri.windows.conf.json`에 있으며 제거하면 설치 후 `0xC0000135` DLL 누락 오류가 다시 발생할 수 있다.

### Python 환경

프로젝트 루트에서 다음을 실행한다.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev,screenshots,desktop-build]"
python -m playwright install chromium
```

PowerShell 실행 정책 때문에 활성화가 막히면 현재 터미널에서만 허용한다.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
```

### Rust 엔진

```powershell
cargo build --release -p netroach-engine
.\target\release\netroach-engine.exe --version
```

GNU 도구 체인을 명시하려면 다음과 같이 실행한다.

```powershell
cargo +stable-x86_64-pc-windows-gnu build --release -p netroach-engine
```

### Tauri 의존성

```powershell
cd desktop
npm ci
cd ..
```

## 7. 개발 실행 방법

먼저 진단을 실행한다.

```powershell
.\.venv\Scripts\Activate.ps1
netroach diagnostics
netroach serve --check
```

대시보드/API 개발은 다음 명령으로 시작한다.

```powershell
netroach serve --host 127.0.0.1 --port 8765
```

브라우저에서 `http://127.0.0.1:8765/dashboard`를 연다. 브라우저를 자동으로 열려면 다음 명령을 사용할 수 있다.

```powershell
netroach desktop
```

Tauri 창만 개발하면서 별도 Python 서버를 사용하려면 터미널을 두 개 사용한다.

터미널 1:

```powershell
netroach desktop --host 127.0.0.1 --port 8765 --no-open
```

터미널 2:

```powershell
cd desktop
$env:NETROACH_DESKTOP_URL = "http://127.0.0.1:8765/dashboard"
npm run dev
```

설정 파일을 사용한 안전한 로컬 스캔 예시는 다음과 같다.

```powershell
netroach scan `
  --config .\docs\netroach.example.toml `
  --env local `
  --targets 127.0.0.1 `
  --ports 80,443 `
  --scope 127.0.0.0/8 `
  --confirm-authorized
```

## 8. 테스트와 검증

일반 변경 후 최소 검증은 다음과 같다.

```powershell
python -m unittest discover -s tests
cargo fmt --check
cargo test -p netroach-engine
cargo test --manifest-path desktop\src-tauri\Cargo.toml
```

패키징 관련 변경 후에는 추가로 실행한다.

```powershell
python tools\package.py --output-dir dist-smoke
python tools\smoke_package.py dist-smoke
python tools\build_desktop.py --prepare-only
```

현재 작업 상태에서 확인된 테스트 기준은 다음과 같다.

- Python 테스트 186개 통과
- Rust 엔진 테스트 35개 통과(단위 25, CLI 통합 10)
- Tauri 테스트 2개 통과
- 설치 프로그램의 임시 폴더 설치/제거 성공
- 설치된 데스크톱 앱의 `/v1/health` 응답과 Rust 엔진 연결 성공
- 설치본의 Playwright Chromium을 이용한 실제 PNG 웹 증거 생성 성공

Npcap이 없는 현재 검증 환경에서는 라이브 캡처와 실제 raw packet 송신을 끝까지 검증하지 않았다. 해당 기능을 수정하면 Npcap이 설치된 관리자 권한 테스트 PC에서 별도 검증한다.

## 9. Windows 설치 프로그램 빌드

처음부터 전체 빌드하려면 프로젝트 루트에서 실행한다.

```powershell
.\.venv\Scripts\Activate.ps1
python tools\build_desktop.py
```

이 명령은 다음 작업을 수행한다.

1. Rust 스캔 엔진 빌드
2. PyInstaller 단일 파일 백엔드 생성
3. 버전에 맞는 Playwright headless Chromium 다운로드와 실행 확인
4. 엔진, 백엔드, 브라우저 및 WebView2 loader 스테이징
5. npm 의존성 설치
6. Tauri NSIS 설치 프로그램 생성

기본 출력 경로는 다음과 같다.

```text
desktop\src-tauri\target\release\bundle\nsis\Netroach_0.1.0_x64-setup.exe
```

백엔드와 엔진을 다시 만들지 않고 설치 프로그램만 반복 빌드하려면 이전 산출물이 존재하는지 확인한 후 실행한다.

```powershell
python tools\build_desktop.py `
  --skip-engine-build `
  --skip-backend-build `
  --skip-playwright-download
```

GNU 도구 체인을 명시하는 예시는 다음과 같다.

```powershell
python tools\build_desktop.py `
  --cargo-toolchain stable-x86_64-pc-windows-gnu
```

브라우저 캐시는 `target\desktop-playwright`, PyInstaller 출력은 `target\desktop-backend`, 최종 Tauri 출력은 `desktop\src-tauri\target` 아래에 생성된다.

## 10. 최근 생성된 로컬 배포본

현재 PC에서 마지막으로 생성하고 검증한 파일은 다음과 같다. `dist`는 Git에서 제외되므로 다른 PC에서 필요하면 설치 파일과 체크섬을 별도로 복사한다.

```text
dist\Netroach_0.1.0_x64-setup.exe
크기: 372,000,106 bytes
SHA-256: 00f81e9fcbece4ff01d60ec5770223e94a9320351973e2104bc6c5bf1c6c6667
```

체크섬 확인 명령:

```powershell
$expected = (Get-Content .\Netroach_0.1.0_x64-setup.exe.sha256).Split(" ")[0]
$actual = (Get-FileHash .\Netroach_0.1.0_x64-setup.exe -Algorithm SHA256).Hash.ToLower()
if ($actual -ne $expected) { throw "checksum mismatch" }
```

## 11. 알려진 제한과 다음 작업

- 설치 프로그램은 현재 코드 서명이 없다. 기능 제한은 없지만 SmartScreen 또는 회사 보안 정책이 실행을 경고하거나 차단할 수 있다.
- 공개 배포 전에는 Windows 코드 서명 인증서, 타임스탬프와 서명된 설치본 검증이 필요하다.
- 마지막 검증은 현재 Windows PC의 임시 설치 경로에서 수행했다. Python, Rust, Node.js가 전혀 없는 깨끗한 오프라인 Windows VM 검증은 릴리스 전에 한 번 더 수행하는 것이 좋다.
- GitHub Release 업로드와 자동 데스크톱 설치 프로그램 빌드 CI는 아직 구성되지 않았다. 현재 CI는 Python, Rust 엔진과 휴대용 패키지를 검사한다.
- 오프라인 WebView2와 Playwright Chromium을 모두 포함하므로 설치 프로그램 크기가 크다.
- `desktop/src-tauri/resources/runtime/WebView2Loader.dll`과 Windows 전용 리소스 매핑은 GNU Tauri 설치본 실행에 필요하다.
- Playwright Python 버전을 변경하면 호환되는 Chromium도 다시 내려받아 설치 프로그램을 재빌드해야 한다.
- 데이터베이스 스키마나 백업 형식을 변경하면 기존 `netroach.db` import/upgrade 호환성을 반드시 테스트한다.
- 대시보드는 데스크톱 웹뷰 안에서도 그대로 실행된다. 이 웹뷰는 새 창 요청을 조용히 버리므로 `target="_blank"`나 `window.open()`으로 여는 동작은 설치본에서 아무 반응 없이 죽는다. 리포트·증적·내보내기는 모두 페이지 안 뷰어에서 처리하고, 파일 저장은 fetch 후 Blob 다운로드로 한다. `tests/test_dashboard.py`가 이 규칙을 강제한다.

## 12. 변경 유형별 확인 파일

| 변경하려는 부분 | 먼저 볼 파일 | 함께 확인할 테스트 |
| --- | --- | --- |
| 스캔 동작/성능 | `crates/netroach-engine/src/main.rs`, `netroach/engine.py` | `crates/netroach-engine/tests/engine_cli.rs`, `tests/test_engine.py` |
| API | `netroach/api.py`, `netroach/models.py` | `tests/test_api.py` |
| 대시보드 UI | `netroach/static/dashboard.html` | `tests/test_dashboard.py`, `tests/test_api.py`의 dashboard 테스트 |
| DB/이력 | `netroach/storage.py` | `tests/test_storage.py` |
| 증거/스크린샷 | `netroach/evidence.py` | `tests/test_evidence.py`, `tests/test_api.py` |
| 설정/프로필 | `netroach/config.py`, `netroach/scan_inputs.py` | `tests/test_config.py`, `tests/test_scan_inputs.py` |
| 플러그인 | `netroach/plugins.py` | `tests/test_plugins.py` |
| 보고서/내보내기 | `netroach/reports.py`, `netroach/exporters.py` | `tests/test_reports.py`, `tests/test_exporters.py` |
| Tauri 프로세스 관리 | `desktop/src-tauri/src/main.rs` | Tauri Cargo 테스트와 실제 설치 smoke test |
| 설치 프로그램 | `tools/build_desktop.py`, `tauri*.json` | `tests/test_build_desktop.py`, `tests/test_desktop.py` |

세부 사용법은 `docs/user-guide.md`, 일반 설치는 `docs/install.md`, Windows 패키징은 `docs/desktop-packaging.md`, 공개 배포 전 검증은 `docs/release-checklist.md`를 함께 참고한다.
