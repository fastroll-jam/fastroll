use crate::{
    fuzz_target::FuzzTargetError,
    types::{FuzzMessageKind, FuzzProtocolMessage},
};
use fr_codec::prelude::*;
use std::path::Path;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};

/// UnixStream message sender & receiver utils
pub(crate) struct StreamUtils;
impl StreamUtils {
    pub(crate) async fn read_message(
        stream: &mut UnixStream,
    ) -> Result<FuzzMessageKind, FuzzTargetError> {
        let mut length_buf = [0u8; 4];
        stream.read_exact(&mut length_buf).await?;
        let message_len = u32::decode_fixed(&mut length_buf.as_slice(), 4)?;

        let mut message_buf = vec![0u8; message_len as usize];
        stream.read_exact(&mut message_buf).await?;
        let message_kind = FuzzMessageKind::decode(&mut message_buf.as_slice())?;
        Ok(message_kind)
    }

    pub(crate) async fn send_message(
        stream: &mut UnixStream,
        message_kind: FuzzMessageKind,
    ) -> Result<(), FuzzTargetError> {
        let message = FuzzProtocolMessage::from_kind(message_kind)?;
        stream.write_all(&message.encode()?).await?;
        stream.flush().await?;
        Ok(())
    }
}

#[cfg(unix)]
fn is_socket_file(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;
    metadata.file_type().is_socket()
}

#[cfg(not(unix))]
fn is_socket_file(_metadata: &std::fs::Metadata) -> bool {
    false
}

pub fn validate_socket_path(socket_path: &str) -> Result<(), FuzzTargetError> {
    if socket_path.is_empty() {
        return Err(FuzzTargetError::InvalidSocketPath(
            "Socket path cannot be empty".to_string(),
        ));
    }

    // Check input length
    if socket_path.len() > 200 {
        return Err(FuzzTargetError::InvalidSocketPath(
            "Socket path is too long".to_string(),
        ));
    }

    let path = Path::new(socket_path);

    // Enforce absolute path
    if !path.is_absolute() {
        return Err(FuzzTargetError::InvalidSocketPath(
            "Socket path should be absolute (start with `/`)".to_string(),
        ));
    }

    // Check whether parent directory exists and is writable
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            return Err(FuzzTargetError::InvalidSocketPath(format!(
                "Parent directory does not exist: {}",
                parent.display()
            )));
        }

        let metadata = std::fs::metadata(parent)?;
        if metadata.permissions().readonly() {
            return Err(FuzzTargetError::InvalidSocketPath(format!(
                "Parent directory is read-only: {}",
                parent.display()
            )));
        }
    }

    // Check if a file already exists at the path
    if path.exists() {
        let metadata = std::fs::metadata(path)?;
        if !is_socket_file(&metadata) {
            return Err(FuzzTargetError::InvalidSocketPath(format!(
                "Regular file exists at the path: {}",
                path.display()
            )));
        }
    }

    Ok(())
}
