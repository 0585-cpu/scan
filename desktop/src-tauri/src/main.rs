use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant},
};

use tauri::{path::BaseDirectory, Manager, RunEvent};

const BACKEND_HOST: &str = "127.0.0.1";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Default)]
struct BackendProcess(Mutex<Option<Child>>);

fn executable_name(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    }
}

fn runtime_binary_path(
    app: &tauri::App,
    environment_variable: &str,
    name: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(path) = std::env::var_os(environment_variable) {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "{environment_variable} does not point to a file: {}",
                path.display()
            ),
        )
        .into());
    }

    let relative = format!("resources/bin/{}", executable_name(name));
    let path = app.path().resolve(relative, BaseDirectory::Resource)?;
    if !path.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("bundled executable was not found: {}", path.display()),
        )
        .into());
    }
    Ok(path)
}

fn runtime_directory_path(
    app: &tauri::App,
    environment_variable: &str,
    name: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    if let Some(path) = std::env::var_os(environment_variable) {
        let path = PathBuf::from(path);
        if path.is_dir() {
            return Ok(path);
        }
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "{environment_variable} does not point to a directory: {}",
                path.display()
            ),
        )
        .into());
    }

    let relative = format!("resources/{name}");
    let path = app.path().resolve(relative, BaseDirectory::Resource)?;
    if !path.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "bundled resource directory was not found: {}",
                path.display()
            ),
        )
        .into());
    }
    Ok(path)
}

fn reserve_local_port() -> io::Result<u16> {
    let listener = TcpListener::bind((BACKEND_HOST, 0))?;
    Ok(listener.local_addr()?.port())
}

fn health_check(port: u16) -> io::Result<bool> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(250))?;
    stream.set_read_timeout(Some(Duration::from_millis(500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(500)))?;
    stream.write_all(b"GET /v1/health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")?;

    let mut response = [0_u8; 128];
    let length = stream.read(&mut response)?;
    let status_line = String::from_utf8_lossy(&response[..length]);
    Ok(status_line.starts_with("HTTP/1.1 200") || status_line.starts_with("HTTP/1.0 200"))
}

fn wait_for_backend(child: &mut Child, port: u16) -> io::Result<()> {
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(io::Error::other(format!(
                "Scaprobe backend exited during startup with status {status}"
            )));
        }
        if health_check(port).unwrap_or(false) {
            return Ok(());
        }
        if started.elapsed() >= STARTUP_TIMEOUT {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Scaprobe backend did not become ready within 20 seconds",
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn spawn_backend(app: &tauri::App, port: u16) -> Result<Child, Box<dyn std::error::Error>> {
    let backend = runtime_binary_path(app, "SCAPROBE_BACKEND_PATH", "scaprobe-backend")?;
    let engine = runtime_binary_path(app, "SCAPROBE_ENGINE_PATH", "scaprobe-engine")?;
    let playwright_browsers =
        runtime_directory_path(app, "SCAPROBE_PLAYWRIGHT_BROWSERS_PATH", "playwright")?;
    let log_directory = app.path().app_log_dir()?;
    fs::create_dir_all(&log_directory)?;
    let log_path = log_directory.join("backend.log");
    let stdout = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)?;
    let stderr = stdout.try_clone()?;

    let mut command = Command::new(backend);
    command
        .args([
            "--host",
            BACKEND_HOST,
            "--port",
            &port.to_string(),
            "--engine-path",
            engine.to_string_lossy().as_ref(),
            "--playwright-browsers-path",
            playwright_browsers.to_string_lossy().as_ref(),
        ])
        .env("PYTHONUTF8", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }

    Ok(command.spawn()?)
}

fn stop_backend(app: &tauri::AppHandle) {
    let state = app.state::<BackendProcess>();
    if let Ok(mut process) = state.0.lock() {
        if let Some(mut child) = process.take() {
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                const CREATE_NO_WINDOW: u32 = 0x0800_0000;
                let _ = Command::new("taskkill")
                    .args(["/PID", &child.id().to_string(), "/T", "/F"])
                    .creation_flags(CREATE_NO_WINDOW)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            let _ = child.kill();
            let _ = child.wait();
        }
    };
}

fn main() {
    let app = tauri::Builder::default()
        .manage(BackendProcess::default())
        .setup(|app| {
            let url =
                if let Ok(url) = std::env::var("SCAPROBE_DESKTOP_URL") {
                    url
                } else {
                    let port = reserve_local_port()?;
                    let mut child = spawn_backend(app, port)?;
                    if let Err(error) = wait_for_backend(&mut child, port) {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(error.into());
                    }
                    *app.state::<BackendProcess>().0.lock().map_err(|_| {
                        io::Error::other("could not lock the backend process state")
                    })? = Some(child);
                    format!("http://{BACKEND_HOST}:{port}/dashboard")
                };

            let parsed_url = url.parse().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid Scaprobe desktop URL: {error}"),
                )
            })?;
            tauri::WebviewWindowBuilder::new(app, "main", tauri::WebviewUrl::External(parsed_url))
                .title("Scaprobe")
                .inner_size(1280.0, 820.0)
                .min_inner_size(960.0, 640.0)
                .build()?;
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("error while building Scaprobe desktop");

    app.run(|app_handle, event| {
        if matches!(event, RunEvent::ExitRequested { .. } | RunEvent::Exit) {
            stop_backend(app_handle);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{executable_name, reserve_local_port};
    use std::net::TcpListener;

    #[test]
    fn reserved_port_can_be_bound_after_reservation() {
        let port = reserve_local_port().expect("reserve port");
        TcpListener::bind(("127.0.0.1", port)).expect("bind reserved port");
    }

    #[test]
    fn executable_name_matches_the_platform() {
        let name = executable_name("scaprobe-engine");
        assert_eq!(name.ends_with(".exe"), cfg!(windows));
    }
}
