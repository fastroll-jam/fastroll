use std::{error::Error, path::Path};

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

        let metadata = std::fs::metadata(parent)?;
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
