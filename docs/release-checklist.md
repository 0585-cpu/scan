# Release Checklist

Use this checklist before publishing a Netroach artifact.

## Version

- Confirm `netroach/version.py` contains the intended dynamic package version.
- Regenerate `requirements.lock.txt` if the runtime dependencies changed, and record the versions the release was built and tested with.
- Confirm `crates/netroach-engine/Cargo.toml` uses the same release version.
- Confirm `docs/user-guide.md` matches the current CLI/API surface.
- Run `netroach --version`.
- Run `netroach-engine --version` when an engine build is present.
- Confirm `netroach serve --check` reports `app_version` and, for engine artifacts, `rust_engine_version`.

## Validation

```powershell
py -3 -m ruff check .
py -3 -m json.tool postman\netroach.postman_collection.json > $null
py -3 -c "from netroach.config import load_config; load_config('docs/netroach.example.toml')"
py -3 -m compileall netroach tests tools
py -3 -m unittest discover -s tests
cargo fmt --check
cargo test -p netroach-engine
cargo build --profile portable -p netroach-engine
```

On locked-down Windows systems, use the GNU toolchain and a temp Cargo target directory if workspace executables are blocked.

## Packaging

```powershell
py -3 tools\package.py --output-dir dist-smoke
py -3 tools\smoke_package.py dist-smoke

py -3 tools\package.py --cargo-target-dir target --engine-profile portable --require-engine --output-dir dist-smoke-engine
py -3 tools\smoke_package.py dist-smoke-engine --require-engine

py -3 tools\package.py --archive-format tar.gz --target-platform linux-x86_64 --output-dir dist-smoke-tar
py -3 tools\smoke_package.py dist-smoke-tar

py -3 -m pip install -e ".[desktop-build]"
py -3 tools\build_desktop.py --prepare-only
py -3 tools\build_desktop.py --skip-engine-build --skip-backend-build
```

The final desktop command requires Node.js/npm, the Rust MSVC toolchain, and Visual Studio Build Tools with the Desktop C++ workload. Confirm that the NSIS installer is present under `desktop\src-tauri\target\release\bundle\nsis`.

## Smoke

- Run `netroach --help` from the extracted artifact.
- Run `netroach --version` from the extracted artifact.
- Run `netroach serve --check` from the extracted artifact.
- Open or request `/dashboard` from `netroach serve`.
- Confirm a loopback `serve` needs no token, and that `--host 0.0.0.0` prints a token, rejects an unauthenticated `/v1/health`, and accepts `Authorization: Bearer <token>`.
- In the installed desktop app, confirm Report, evidence thumbnails, and the JSON/CSV/Excel exports all open in the in-page viewer and that Save writes the file.
- Confirm the artifact has a matching `.sha256` sidecar and smoke test verifies it.
- Run a local authorized TCP scan against a loopback test server.
- Run a config-based scan smoke with `--config docs/netroach.example.toml --env local`.
- Generate a stored scan report with `netroach report <scan_id> --format html`.
- Run a PCAP analyze smoke with a known fixture.
- Run a bounded live capture smoke when packet capture privileges are available, or confirm diagnostics clearly explain the missing driver/privilege.
- Validate `docs/netroach.plugin.example.json`, list it with `netroach plugins list`, and run a plugin port-profile scan smoke.
- Create an HTTP OAST session, call its `/oast/<token>` URL locally, and confirm the interaction is stored.
- Confirm packet sending diagnostics report `packet_driver`, `packet_driver_available`, `elevated`, `raw_socket_privileged`, and a useful Windows Npcap or macOS/Linux privilege note.
- Install the desktop bundle on a clean Windows VM without Python, Node.js, or Rust; verify startup, an authorized loopback scan, database persistence after restart, and backend termination after the window closes.
- On the clean offline VM, enable evidence capture against an authorized local HTTP service and confirm a `web_screenshot` PNG is stored without downloading Chromium.

## Boundaries

- Confirm the release does not include exploit checks, stealth/evasion features, authentication bypass, arbitrary Scapy expressions, or raw byte packet injection.
- Confirm active scan and packet sending still require explicit scope and `confirm_authorized=true`.
- Confirm live capture still requires `confirm_authorized=true` plus a bounded `duration_s` or `count`.
- Confirm plugins are JSON data only and do not execute arbitrary code.
- Confirm OAST only records inbound HTTP callbacks and does not generate exploit payloads.
