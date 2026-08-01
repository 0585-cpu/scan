# Desktop And Installer Packaging

Netroach supports two desktop distribution modes:

1. Portable CLI package with `netroach desktop`
2. A self-contained Tauri installer that starts its bundled backend automatically

## Desktop Launcher

The fastest app-like mode is:

```powershell
netroach desktop
```

This starts the local FastAPI backend on the fixed `127.0.0.1:8765` address and opens the Netroach dashboard. Pass `--port 0` to opt into a free ephemeral port.

Use a stable port when another wrapper or shortcut needs a fixed URL:

```powershell
netroach desktop --host 127.0.0.1 --port 8765
```

Use `--no-open` when another shell, webview, or service manager will open the dashboard:

```powershell
netroach desktop --host 127.0.0.1 --port 8765 --no-open
```

The command accepts the same local data options as `serve`:

```powershell
netroach desktop --db .\netroach.db --config .\netroach.toml --env lab --plugin .\plugin.json
```

## Portable Artifact

Build a portable archive:

```powershell
py -3 tools\package.py --output-dir dist
```

With a bundled Rust engine:

```powershell
cargo build --release -p netroach-engine
py -3 tools\package.py --output-dir dist --require-engine
```

Smoke test:

```powershell
py -3 tools\smoke_package.py dist
```

Users can extract the archive and run:

```powershell
.\bin\setup.cmd
.\bin\start-desktop.cmd
```

Use `.\bin\setup.cmd --screenshots` when browser-based automatic evidence is required. The one-time setup requires Python 3.10+ and internet access; subsequent starts use the isolated `.venv` automatically.

On macOS/Linux:

```sh
./bin/netroach desktop
```

## Self-Contained Windows Installer

The installer contains all three application layers:

- the Tauri desktop window;
- a one-file Python API/dashboard backend produced by PyInstaller;
- the `netroach-engine.exe` Rust scan engine;
- the Playwright Python driver and a version-matched headless Chromium build.

The destination PC does not need Python, Node.js, Rust, a separately installed browser, or internet access. The installer embeds the WebView2 offline installer, and Chromium is bundled for automatic web screenshot evidence. When the desktop app starts, it selects a free loopback port, starts the backend without a console window, waits for `/v1/health`, and opens the dashboard. Closing the app terminates the backend and its browser/engine process tree. User data remains in `%APPDATA%\Netroach`.

Npcap and administrator privileges are still optional destination-PC prerequisites for live capture and raw packet sending. TCP connect scans and file PCAP analysis work without them.

### Build Prerequisites

The build PC needs:

- Python 3.10+ and the project dependencies;
- PyInstaller (`desktop-build` optional dependency);
- Node.js LTS and npm;
- the Rust MSVC toolchain;
- Visual Studio Build Tools with the **Desktop development with C++** workload;
- the other Windows prerequisites listed by Tauri.

Install the Python build dependency:

```powershell
py -3 -m pip install -e ".[desktop-build]"
```

Build the NSIS installer:

```powershell
py -3 tools\build_desktop.py
```

The command builds the Rust engine and frozen backend, downloads only Playwright's headless Chromium shell, stages the executables and browser under `desktop/src-tauri/resources`, installs the Tauri npm dependencies, and runs the Tauri bundle build. Building from an empty cache requires internet access. The installer is written under:

```text
desktop/src-tauri/target/release/bundle/nsis
```

To prepare and inspect the two bundled executables without running npm/Tauri:

```powershell
py -3 tools\build_desktop.py --prepare-only
```

Browser downloads are cached under `target\desktop-playwright`. Reuse that cache for an offline rebuild with:

```powershell
py -3 tools\build_desktop.py `
  --skip-engine-build `
  --skip-backend-build `
  --skip-playwright-download
```

Existing binaries can be reused when iterating on the desktop shell:

```powershell
py -3 tools\build_desktop.py `
  --engine-path .\target\release\netroach-engine.exe `
  --backend-path .\target\desktop-backend\dist\netroach-backend.exe
```

Use `--bundles msi` when an MSI is required instead of the default Windows NSIS executable.

### Wrapper Development

The `desktop/` directory can still be run against a separately started development backend. Start the backend on a stable URL:


```powershell
netroach desktop --host 127.0.0.1 --port 8765 --no-open
```

Run the wrapper:

```powershell
cd desktop
npm install
$env:NETROACH_DESKTOP_URL = "http://127.0.0.1:8765/dashboard"
npm run dev
```

Build installers:

```powershell
cd desktop
npm run build
```

For development without a separately started server, stage the binaries with `--prepare-only` and omit `NETROACH_DESKTOP_URL`. `NETROACH_BACKEND_PATH` and `NETROACH_ENGINE_PATH` can override the staged resource paths for debugging.

Backend startup output is appended to the Tauri application log directory as `backend.log`. Playwright browser navigation remains restricted to the scanned host by the evidence capture code. Updating the Playwright Python dependency requires rebuilding the installer so the matching Chromium revision is downloaded and bundled.

The offline WebView2 payload and Playwright Chromium substantially increase installer size. WebView2 renders the Netroach window; Chromium is a separate browser process used only for automatic screenshots.
