//! `cplt mcp-stdio <id>`, the sandbox side.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::process::ExitCode;

use super::SOCKET_ENV;

/// `cplt mcp-stdio <id>`, inside the sandbox: copy stdio to the broker.
pub fn run_stdio(id: &str) -> ExitCode {
    let Some(socket) = std::env::var_os(SOCKET_ENV).filter(|s| !s.is_empty()) else {
        eprintln!("cplt mcp-stdio: {SOCKET_ENV} is not set; run inside a cplt session");
        return ExitCode::FAILURE;
    };
    let mut stream = match UnixStream::connect(&socket) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cplt mcp-stdio: cannot reach the broker: {e}");
            return ExitCode::FAILURE;
        }
    };
    if writeln!(stream, "{id}").is_err() {
        return ExitCode::FAILURE;
    }
    let Ok(mut up) = stream.try_clone() else {
        return ExitCode::FAILURE;
    };
    std::thread::spawn(move || {
        let _ = std::io::copy(&mut std::io::stdin().lock(), &mut up);
        let _ = up.shutdown(std::net::Shutdown::Write);
    });
    let _ = std::io::copy(&mut stream, &mut std::io::stdout().lock());
    ExitCode::SUCCESS
}
