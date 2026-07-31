# Scaprobe Desktop

This directory contains the Tauri window for the self-contained Scaprobe desktop application. A production bundle includes a PyInstaller-frozen API/dashboard backend, the Rust scan engine, Playwright with headless Chromium, and the WebView2 offline installer. The app starts the backend on a free loopback port, waits for its health endpoint, and stops its backend/browser/engine process tree when the desktop process exits.

## Build The Windows Installer

From the repository root:

```powershell
py -3 -m pip install -e ".[desktop-build]"
py -3 tools\build_desktop.py
```

The build PC also needs Node.js/npm, the Rust MSVC toolchain, and Visual Studio Build Tools with the Desktop C++ workload. The default Windows bundle is NSIS and is written under `src-tauri/target/release/bundle/nsis`.

To build only the backend, engine, and Playwright browser resources:

```powershell
py -3 tools\build_desktop.py --prepare-only
```

The Playwright download is cached in `target\desktop-playwright`. Add `--skip-playwright-download` to reuse it during an offline rebuild.

## Development Against A Running Backend

Start the existing Python launcher from the repository root:

```powershell
scaprobe desktop --host 127.0.0.1 --port 8765 --no-open
```

Then run the wrapper:

```powershell
cd desktop
npm install
$env:SCAPROBE_DESKTOP_URL = "http://127.0.0.1:8765/dashboard"
npm run dev
```

If `SCAPROBE_DESKTOP_URL` is not set, the wrapper uses the staged executables under `src-tauri/resources/bin`. `SCAPROBE_BACKEND_PATH` and `SCAPROBE_ENGINE_PATH` override those paths for debugging.

See `docs/desktop-packaging.md` for packaging details and destination-PC requirements.
