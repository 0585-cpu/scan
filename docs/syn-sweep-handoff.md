# SYN 스윕 — 구현 및 인수인계

## 현재 상태

Windows IPv4 TCP SYN 스윕은 `syn-sweep` Cargo feature 뒤에서 구현되어 있다.
일반 CLI/API는 기존 호환성을 위해 `syn_sweep`를 명시적으로 선택하지만,
SYN 전용 개인용 NSIS 빌드의 대시보드는 TCP에서 SYN을 기본으로 사용한다.
`TCP Connect 스캔만 사용`을 선택하면 기존 connect 경로만 사용한다. 개인용
NSIS 빌드는 Npcap SDK로 엔진을 링크하고 공식 Npcap 설치 파일을 설치본 안에
포함한다.

SYN 스윕은 다음 결과를 낸다.

- SYN-ACK: `open`; 서비스 탐지가 켜진 경우에만 기존 connect 경로로 서비스와
  이미지/콘솔 증적을 보강하고, 꺼져 있으면 연결 없이 SYN 결과를 기록한다.
- RST: `closed`.
- 모든 전송 및 재시도 뒤 무응답: `filtered`.
- Npcap 열기·캡처·송신 오류: 스캔 실패. 결과를 추측해서 만들지 않는다.

## 구현 구조

- `syn_sweep.rs`: SYN 프레임 작성, 쿠키 생성, SYN-ACK/RST 검증과 파싱.
- `netlink.rs`: Windows 라우트·MAC 해석 및 인터페이스 인덱스에서 정확한
  `\Device\NPF_{GUID}` Npcap 장치로의 fail-closed 매핑.
- `syn_runner.rs`: 어댑터별 송신 핸들·수신 스레드, BPF 필터, 재시도,
  5,000pps 상한, 결과 집계. 수신 큐 포화·스레드 panic·캡처 오류는 스캔을
  실패시키며 로컬 인터페이스 주소를 원격 raw 대상으로 오인하지 않는다.
- `main.rs`: `--syn-sweep`, `--syn-retries 0..2`, 결과 이벤트와 기존 서비스
  탐지 경로 연결. 루프백은 connect 스캔으로 처리한다.
- Python CLI/API/대시보드: 옵션을 `EngineSettings`와 Rust 엔진까지 전달한다.
  API heartbeat는 결과 이벤트와 독립된 스레드에서 유지되어, 결과를 마지막에
  일괄 출력하는 장시간 SYN 스윕도 중단된 작업으로 오인하지 않는다.

쿠키가 외부 패킷을 거르고 응답을 `(host, port)`에 연결한다. 재시도 때 이미
응답한 프로브를 제외하기 위해 프로브당 2비트 상태만 유지한다. 따라서
16,000,000 프로브는 약 4MiB, 절대 상한 100,000,000 프로브는 약 25MiB이다.
프로브별 소켓·작업·타이머·객체는 만들지 않는다. 순서는 포트 우선이라 같은
호스트에 패킷이 연속 집중되지 않는다.

## 개발 빌드와 테스트

이 PC의 SDK 라이브러리는 `C:\npcap-sdk\Lib\x64`에 있다.

```powershell
$env:LIB = "C:\npcap-sdk\Lib\x64;$env:LIB"
cargo test -p netroach-engine --features syn-sweep
cargo build -p netroach-engine --features syn-sweep
```

기본 빌드는 Npcap SDK 없이 가능해야 한다.

```powershell
cargo test -p netroach-engine
cargo build -p netroach-engine
```

실행 예:

```powershell
netroach scan --targets 192.168.1.0/24 --ports 1-1000 `
  --scope 192.168.1.0/24 --confirm-authorized `
  --syn-sweep --syn-retries 1
```

SYN 스캔은 TCP/IPv4 전용이다. 요청 속도가 5,000pps보다 크더라도 SYN 송신은
5,000pps로 제한된다. 여러 어댑터를 사용하는 대상은 각각 정확한 Npcap 장치와
라우트가 확인되어야 시작된다.

## 개인용 Npcap 포함 설치본

무료 Npcap 설치 파일은 저장소에 넣거나 자동 다운로드하지 않는다. 공식
사이트에서 직접 받은 설치 파일을 명시적으로 지정한다.

```powershell
.\.venv\Scripts\python.exe tools\build_desktop.py `
  --syn-sweep `
  --npcap-sdk-lib C:\npcap-sdk\Lib\x64 `
  --npcap-installer C:\path\to\npcap-installer.exe `
  --bundles nsis
```

빌드는 공급자가 Nmap Software LLC이고 상태가 Valid인 Authenticode 서명을 먼저
확인한 뒤 설치 파일을 무시되는 staging 경로에 복사하고 SHA-256을 출력한다.
설치 훅은 Npcap 1.88 이상과 `AdminOnly=0`을 먼저 검사한다. 조건을 만족하지
않으면 포함된 Npcap 설치 UI를 실행하며 사용자는
`Restrict Npcap driver's access to Administrators only`를 선택하지 않아야 한다.
설치가 끝난 뒤 조건을 다시 만족하지 않으면 Netroach 설치도 중단된다.

NSIS 빌드가 성공하거나 실패하면 private staging 설치 파일을 제거하고 기본
connect-scan 엔진을 다시 staging한다. 따라서 다음 일반 빌드가 개인용 Npcap
설치 파일이나 feature 엔진을 우연히 재사용하지 않는다.
성공한 Windows 설치본에는 현재 파일과 일치하는 `.sha256` sidecar를 다시 쓴다.

Netroach 제거 프로그램은 공유 시스템 드라이버인 Npcap을 제거하지 않는다.
무료 Npcap은 예외 용도를 제외하면 최대 5대에서만 사용할 수 있고 외부
재배포할 수 없다. 설치 파일이 포함된 결과물은 이 사용자의 개인용 설치본으로만
취급하며 게시·전달하지 않는다. 다른 사용자나 고객에게 배포하려면 Npcap OEM
재배포 권한과 그에 맞는 설치 방식을 사용해야 한다.

## 남은 수동 검증 게이트

- 관리자 전용이 아닌 Npcap을 사용한 비관리자 실제 LAN open/closed/filtered 검사.
- 동일 대상에 대한 SYN 결과와 connect 결과의 열린 포트 교차검증.
- Npcap이 없는 깨끗한 Windows VM에서 포함 설치, 취소, 잘못된 AdminOnly 설정,
  재실행 및 제거 동작 검증.
- 설치 훅을 실제로 실행하는 clean-VM 설치 및 제거 검증.

이 게이트를 직접 실행하기 전에는 실제 네트워크 및 최종 설치본 인수를
`UNVERIFIED`로 표시한다.

## 2026-09-10 개인용 빌드 증적

- Npcap 입력: 1.88, Authenticode `Valid`, 서명자 `Nmap Software LLC`.
- Npcap 입력 SHA-256:
  `a2f4ec1e5ea353ff67efd24b2ebf081ba44532410fae8d5e146af0310aa4f56b`.
- NSIS 설치본: `desktop/src-tauri/target/release/bundle/nsis/Netroach_0.1.0_x64-setup.exe`.
- 크기: 430,240,347 bytes.
- 설치본 SHA-256:
  `2f07f139bbfc346180b046183c92743ff506f74e24a7b93969eb4c879a3d812c`.
- `.sha256` sidecar 일치 확인 완료.
- 설치본 자체의 Authenticode 상태: `NotSigned`.
- NSIS 완료 뒤 private Npcap staging 제거 및 표준 connect 엔진 복원 확인 완료.

이 기록은 패키지 생성·무결성 증적이다. Npcap이 없는 깨끗한 Windows VM에서
실제 설치 UI, `AdminOnly=0`, 비관리자 SYN 스캔과 제거 동작은 아직
`UNVERIFIED`이다.
