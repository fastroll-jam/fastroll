use std::{error::Error, path::Path};
use tokio::net::{UnixListener, UnixStream};

const DEFAULT_SOCKET_PATH: &str = "/tmp/jam_target.sock";

#[cfg(unix)]
fn is_socket_file(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;
    metadata.file_type().is_socket()
}

#[cfg(not(unix))]
fn is_socket_file(_metadata: &std::fs::Metadata) -> bool {
    false
}

pub fn validate_socket_path(socket_path: &str) -> Result<(), Box<dyn Error>> {
    if socket_path.is_empty() {
        return Err("Socket path cannot be empty".into());
    }

    // Check input length
    if socket_path.len() > 200 {
        return Err("Socket path is too long".into());
    }

    let path = Path::new(socket_path);

    // Enforce absolute path
    if !path.is_absolute() {
        return Err("Socket path should be absolute (start with `/`)".into());
    }

    // Check whether parent directory exists and is writable
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            return Err(format!("Parent directory does not exist: {}", parent.display()).into());
        }

        let metadata = std::fs::metadata(path)?;
        if metadata.permissions().readonly() {
            return Err(format!("Parent directory is read-only: {}", parent.display()).into());
        }
    }

    // Check if a file already exists at the path
    if path.exists() {
        let metadata = std::fs::metadata(path)?;
        if !is_socket_file(&metadata) {
            return Err(format!("Regular file exists at the path: {}", path.display()).into());
        }
    }

    Ok(())
}

pub struct FuzzRunner;
impl FuzzRunner {
    pub async fn run_as_fuzz_target(socket_path: Option<String>) -> Result<(), Box<dyn Error>> {
        let socket_path = socket_path.unwrap_or(DEFAULT_SOCKET_PATH.to_string());

        // Validate socket path input
        validate_socket_path(&socket_path)?;

        // Cleanup existing socket files at the path
        let _ = std::fs::remove_file(&socket_path);

        let listener = UnixListener::bind(&socket_path)?;
        tracing::info!("JAM Fuzzer target server listening on {socket_path}");

        // A single connection is used for the fuzzing
        let (stream, _addr) = listener.accept().await?;
        tracing::info!("Accepted a connection from the fuzzer");

        Self::handle_fuzzer_session(stream).await?;
        tracing::info!("Fuzzer session ended");
        Ok(())
    }

    async fn handle_fuzzer_session(_stream: UnixStream) -> Result<(), Box<dyn Error>> {
        unimplemented!()
    }
}
