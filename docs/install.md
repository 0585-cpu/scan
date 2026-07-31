# Scaprobe Install Guide

## Choose An Artifact

Use the artifact that matches your OS and CPU label:

- Windows: `scaprobe-<version>-windows-amd64.zip`
- macOS: `scaprobe-<version>-darwin-arm64.tar.gz` or `scaprobe-<version>-darwin-x86_64.tar.gz`
- Linux: `scaprobe-<version>-linux-x86_64.tar.gz`

The artifact contains the Python application, launcher scripts, docs, Postman collection, helper tools, and optionally `bin/scaprobe-engine`.

For Windows users who should not install Python or download dependencies, use the self-contained `Scaprobe_<version>_x64-setup.exe` desktop installer instead. It includes the API/dashboard backend, Rust engine, Playwright headless Chromium, and the WebView2 offline installer and starts the runtime components automatically.

## Verify Checksum

Each packaged artifact is written with a `.sha256` sidecar by default.

Windows PowerShell:

```powershell
$artifact = "scaprobe-0.1.0-windows-amd64.zip"
$expected = (Get-Content "$artifact.sha256").Split(" ")[0]
$actual = (Get-FileHash $artifact -Algorithm SHA256).Hash.ToLower()
if ($actual -ne $expected) { throw "checksum mismatch" }
```

macOS/Linux:

```sh
sha256sum -c scaprobe-0.1.0-linux-x86_64.tar.gz.sha256
```

On macOS, use `shasum -a 256 <artifact>` if `sha256sum` is not installed.

## Run

Windows:

```powershell
Expand-Archive .\scaprobe-0.1.0-windows-amd64.zip -DestinationPath .\scaprobe
.\scaprobe\Start-Scaprobe.cmd
```

The Windows package requires Python 3.10 or newer on the destination PC. `Start-Scaprobe.cmd` opens an interactive menu with options to start Scaprobe, install screenshot support and start, install or update only, run diagnostics, or exit. The normal start option detects the first run, calls `bin\setup.cmd` to create an isolated `.venv`, installs the pinned project requirements, runs diagnostics, and then opens the local dashboard. Internet access is required during this one-time dependency installation. Future normal launches skip setup automatically.

To install or update Chromium support for automatic web evidence and then start Scaprobe, run:

```powershell
.\scaprobe\Start-Scaprobe.cmd --screenshots
```

For automation, the launcher also accepts `--start`, `--setup`, and `--diagnostics`. Running it without an argument shows the interactive menu.

The lower-level `bin\setup.cmd` and `bin\start-desktop.cmd` scripts remain available for administrators who prefer separate setup and launch steps.

macOS/Linux:

```sh
mkdir -p scaprobe
tar -xzf scaprobe-0.1.0-linux-x86_64.tar.gz -C scaprobe
./scaprobe/bin/scaprobe --help
./scaprobe/bin/scaprobe serve --check
```

Set `PYTHON=/path/to/python` before running the launcher if you need a specific Python interpreter.

Scans, annotations, and evidence are stored outside the extracted application folder under `%APPDATA%\Scaprobe` on Windows, so replacing the application ZIP does not delete prior data. Use the database export/backup commands before moving data to a different PC.

## Windows Packet Driver

Template-based raw packet sending and live capture generally need Npcap and an elevated terminal.

1. Install Npcap from the official Npcap installer.
2. Open PowerShell or Command Prompt as Administrator.
3. Run `scaprobe diagnostics`.
4. Confirm `packet_driver` is `Npcap`, `packet_driver_available` is `true`, and `raw_socket_privileged` is `true`.

TCP connect scanning and file-based PCAP analysis do not require Npcap. Live capture does.

## Build The Self-Contained Windows Installer

The destination PC does not require Python, Node.js, Rust, a separate browser, or internet access. The build PC requires those toolchains plus Visual Studio Build Tools with the Desktop C++ workload and internet access on the first browser/toolchain build.

```powershell
py -3 -m pip install -e ".[desktop-build]"
py -3 tools\build_desktop.py
```

The default NSIS installer is written below `desktop\src-tauri\target\release\bundle\nsis`. See `docs\desktop-packaging.md` for reusable-binary options and desktop development commands.

## macOS/Linux Packet Privileges

Raw packet sending and live capture may require root privileges.

macOS:

```sh
sudo ./bin/scaprobe diagnostics
```

Linux:

```sh
sudo ./bin/scaprobe diagnostics
```

For Python-based development installs on Linux, `CAP_NET_RAW` can be granted to a dedicated interpreter or wrapper only after reviewing your local security policy. Scaprobe diagnostics reports whether the current process has root or `CAP_NET_RAW`.

## Build Artifacts Locally

Windows default:

```powershell
py -3 tools\package.py --archive-format auto --output-dir dist
```

Linux/macOS default:

```sh
python3 tools/package.py --archive-format auto --output-dir dist
```

Force a format or platform label for CI:

```powershell
py -3 tools\package.py --archive-format zip --target-platform windows-amd64 --output-dir dist
py -3 tools\package.py --archive-format tar.gz --target-platform linux-x86_64 --output-dir dist
```
