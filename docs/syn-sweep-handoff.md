# SYN 스윕 — 개발 인수인계

이어서 개발할 때 이 문서 하나로 재개할 수 있도록 정리한 것. 패킷 층과 라우트
해석은 완성·검증됐고, 송신 루프부터가 남았다.

---

## 1. 왜 만드는가

현재 엔진은 connect 스캔(`TcpStream::connect`)이라 포트마다 소켓을 타임아웃
동안 붙잡는다. 그래서 응답 없는 포트가 대부분인 대역에서 처리량은
`동시성 ÷ 타임아웃`이 상한이다. 고객사 `/24 × 10,000포트` 스캔이 **약 2시간**,
그리고 8GB PC에서 동시 소켓 수천 개가 메모리를 바닥내 **PC 전체가 멈췄다**.

SYN 스윕은 포트당 패킷 하나만 보내고 **프로브별 상태를 전혀 안 든다**. 열린
포트만 기존 connect 경로로 넘겨 배너·서비스 식별·콘솔 증적을 그대로 얻는다.
목표: **1,600만 프로브를 5,000pps로 약 53분**, 메모리 문제 없음.

속도가 목적이 아니다. 레이트는 **5,000pps로 고정**한다 — 수만 pps는 노후
OT/임베디드 장비를 멈추게 할 수 있다. 이점은 "소켓·상태를 안 드는 것"이지
속도가 아니다.

---

## 2. 빌드 환경 (이 PC에 이미 설치됨)

SYN 작업은 Npcap이 필요하다 (XP SP2 이후 일반 소켓으로 raw 송신 불가).

**이미 설치된 상태:**
- Npcap 1.88 런타임 — 드라이버 `npcap` Running, `C:\Windows\System32\Npcap\wpcap.dll`
- Npcap SDK 1.16 — `C:\npcap-sdk\` (`Lib\x64\wpcap.lib`, `Include\pcap.h`)

**빌드/테스트 (SDK lib을 LIB에 올려야 함):**
```powershell
$env:LIB = "C:\npcap-sdk\Lib\x64;$env:LIB"
cargo build --manifest-path crates\netroach-engine\Cargo.toml --features syn-sweep
cargo test  --manifest-path crates\netroach-engine\Cargo.toml --features syn-sweep syn_sweep
```

`pcap`, `windows-sys`는 **`syn-sweep` 기능 뒤 optional**이다. 기능 없는 기본
빌드는 둘 다 링크하지 않고 SDK도 필요 없다 — `cargo build`(플래그 없이)로 확인.
**패키징 데스크톱 빌드에는 절대 `syn-sweep`를 켜지 말 것.**

**raw 캡처 실행은 관리자 권한 필요.** UAC + 출력 캡처를 함께 쓰려면 cmd 래퍼로:
```powershell
$exe = (Resolve-Path "target\debug\examples\loopback_roundtrip.exe")
"`"$exe`" > `"$env:TEMP\out.txt`" 2>&1" | Set-Content -Encoding ascii "$env:TEMP\run.cmd"
Start-Process cmd.exe -ArgumentList "/c","$env:TEMP\run.cmd" -Verb RunAs -Wait
Get-Content "$env:TEMP\out.txt"
```
(라우트 해석 `resolve_route`는 IP Helper 호출뿐이라 권한 불필요.)

Npcap 라이선스는 개인·사내 무료. 설치본은 Netroach에 **재배포하지 않고** 각
PC에 별도 설치한다.

---

## 3. 완성된 것과 검증 방법

### `crates/netroach-engine/src/syn_sweep.rs` — 패킷 층 (커밋 5bbafe7)

순수 바이트 함수, I/O 없음. 유닛 테스트 9개(`--features syn-sweep syn_sweep`).

```rust
pub enum LinkLayer { Ethernet { source_mac: [u8;6], next_hop_mac: [u8;6] }, Null }
pub enum SynReply { Open, Closed }
pub struct SynAnswer { pub host: Ipv4Addr, pub port: u16, pub reply: SynReply }

pub fn syn_cookie(secret: u64, host: Ipv4Addr, port: u16, source_port: u16) -> u32
pub fn build_syn_frame(link: LinkLayer, source_ip: Ipv4Addr, host: Ipv4Addr,
                       source_port: u16, port: u16, sequence: u32, ip_id: u16) -> Vec<u8>
pub fn parse_syn_reply(link: LinkLayer, frame: &[u8], secret: u64) -> Option<SynAnswer>
```

- **`syn_cookie`** = TCP 시퀀스 번호에 넣는 keyed hash. 응답의 ack가 `쿠키+1`일
  때만 우리 것으로 인정 → **상태를 전혀 안 드는 근거**이자 위조/외부 패킷
  차단. 송신 시 `sequence`에 이 값을 넣고, 수신 시 `parse_syn_reply`가 검증.
- **`LinkLayer`** — 유선은 Ethernet(14바이트 + MAC), 루프백은 Null(DLT_NULL,
  4바이트 family). 프레이밍이 틀리면 응답이 아예 안 온다.

**종단 검증:** `examples/loopback_roundtrip.rs`가 루프백 어댑터로 SYN을 주입.
열린 포트(리스닝)→SYN-ACK, 닫힌 포트→RST를 커널이 실제로 응답했고 파서가
분류. 즉 우리가 만든 프레임이 실제 전송되고 실제 스택이 받아들인다.
```powershell
cargo run --features syn-sweep --example loopback_roundtrip   # 관리자 권한
```

### `crates/netroach-engine/src/netlink.rs` — 라우트 해석 (커밋 588c885)

Windows IP Helper (`windows-sys`).

```rust
pub struct Route { pub source_ip: Ipv4Addr, pub link: LinkLayer, pub interface_index: u32 }
pub enum RouteError { NoRoute(Ipv4Addr), NoInterfaceMac(u32), NoNextHopMac(Ipv4Addr) }
pub fn resolve_route(dest: Ipv4Addr) -> Result<Route, RouteError>
```

`GetBestRoute2`(다음 홉·인터페이스·소스) → `GetIfEntry2`(소스 MAC) →
`GetIpNetEntry2`/`ResolveIpNetEntry2`(다음 홉 MAC, 캐시 미스 시 ARP). 같은
대역이면 대상 자신을, 다른 대역이면 게이트웨이를 ARP.

**실제 테이블 검증:** `8.8.8.8`(대역 밖)과 게이트웨이가 둘 다 게이트웨이 MAC으로,
on-link 이웃은 자기 MAC으로 해석됨 — 혼합 대역 스캔이 의존하는 분기.
```powershell
cargo run --features syn-sweep --example resolve_route -- 8.8.8.8 <게이트웨이> <로컬IP>
```
(자기 자신 IP는 loopback 라우팅이라 next-hop MAC이 `00:..:00`으로 나온다.
self-target은 스캔 대상이 아니므로 통합 시 감지해 제외하거나 connect로 처리.)

---

## 4. 남은 작업

### 3단계 — 송신 루프 + 수신 스레드 (다음, 가장 큰 조각)

**먼저 풀어야 할 유일한 미해결점: `interface_index` → pcap 디바이스 매핑.**
`resolve_route`가 주는 인터페이스 인덱스(예: 10)를 pcap의
`\Device\NPF_{GUID}` 이름과 연결해야 올바른 어댑터로 송신한다.
- `ConvertInterfaceIndexToLuid(index, &luid)` → `ConvertInterfaceLuidToGuid(&luid, &guid)`
  → GUID 문자열(`{XXXX...}`)을 pcap `Device::list()`의 `name`에서 매칭
  (`name.contains(&guid_string)`).
- 둘 다 `windows-sys` IpHelper에 있음. GUID 포맷은 `StringFromGUID2` 또는
  직접 `{:08X}-{:04X}-...` 조립.

**송신:** 대상 목록을 `(host, port)`로 펼치고(순서는 호스트를 가로질러
인터리빙하는 게 방화벽 호스트당 제한을 피함 — main.rs의 현재 순서는 호스트
우선이라 다름), 각각에 대해:
1. 라우트 캐시에서 `Route` 조회 (`resolve_route`는 대상 IP당 1회, HashMap 캐시).
2. `syn_cookie(secret, host, port, source_port)` → `build_syn_frame(route.link,
   route.source_ip, host, source_port, port, cookie, ip_id)`.
3. 해당 어댑터의 pcap 핸들로 `sendpacket(&frame)`.
4. **레이트 제한**: 5,000pps 상한. main.rs의 `RateLimiter`(spacing 방식)를
   재사용하거나 동일 패턴으로.
- `source_port`는 런당 고정(예: 40000+) 하나로 두면 BPF 필터가 단순해진다.
  포트별로 바꾸면 쿠키에 이미 들어가니 상관없지만 필터가 복잡.

**수신:** 별도 스레드에서 pcap 캡처, BPF `tcp and dst port <source_port>`,
프레임마다 `parse_syn_reply(route_link_of_that_adapter, frame, secret)`.
`SynAnswer`를 채널로 메인에 전달. 어댑터가 여럿이면(혼합 대역이 서로 다른
인터페이스로 나가면) 어댑터마다 수신 스레드.

**어댑터 datalink → LinkLayer:** 캡처 핸들의 `get_datalink()`으로 판정
(loopback=DLT_NULL=`Linktype(0)`, 유선=DLT_EN10MB=`Linktype(1)`). 유선이면
`resolve_route`가 준 MAC으로 Ethernet, 아니면 Null.

### 4단계 — 재전송

SYN이나 응답 유실 = **조용한 미탐**(connect는 OS가 재전송해줘서 이 문제 없음).
무응답 포트를 1~2회 재전송. 이게 진단에 쓸 수 있는 신뢰성의 핵심.
- 1차 스윕 후 응답 못 받은 `(host,port)`를 모아 2차, (필요시) 3차.

### 5단계 — 교차검증 + 통합

**쓰기 전 필수:** 같은 대역을 SYN·connect로 각각 돌려 **열린 포트 목록이
일치하는지** 확인. 불일치 = 재전송 횟수 상향. 이게 안 되면 진단에 못 쓴다.

통합: `ScanArgs`에 `--syn-sweep` 플래그 추가. 기본은 현재 connect 스캔 유지.
켜지면 SYN 스윕 먼저 → 열린 포트만 기존 `scan_tcp_one` 경로로. 결과는
`PortEvent`(main.rs:201)로 emit — SYN에서 무응답은 `filtered`, RST는 `closed`,
SYN-ACK는 `open`. 플래그로 두면 문제 시 끄면 되므로 되돌릴 것이 없다.

---

## 5. 확정된 설계 결정

- **5,000pps 상한** — 충분하고(15M/53분) 노후 장비에 안전. 이점은 무상태.
- **쿠키 기반 무상태 매칭** — 1,600만 프로브 상태를 들 곳이 없고, 위조 방지도 됨.
- **어댑터별 `LinkLayer`** — 대상 IP당 1회 해석·캐시.
- **feature-gated** — 기본 빌드·배포는 pcap/windows-sys를 안 링크.
- **IPv4 전용** (당분간).

---

## 6. 아직 배포 금지

미배포 커밋(라우트·패킷 층·뷰포트 `d53a4ee`·이 문서)은 `main`에 있으나
릴리스에 없다. SYN 스윕은 **미완성**(기반만, 동작하는 스윕 없음)이라 5단계
교차검증 통과 전까지 패키징 빌드에 넣으면 안 된다. 앞선 증적 수정들은 배포
가능하지만 SYN 스윕은 아니다.

**배포된 설치본은 `e2adaf2` 기준.** 예제 3개(`probe_pcap`, `loopback_roundtrip`,
`resolve_route`)로 각 계층을 언제든 재검증할 수 있다.
