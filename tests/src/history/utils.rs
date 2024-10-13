use thiserror::Error;

#[derive(Debug, Error)]
pub enum AsnTypeError {
    #[error("BlockHistory state conversion error: {0}")]
    ConversionError(String),
}
