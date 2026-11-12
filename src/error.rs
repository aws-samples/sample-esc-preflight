//! Error type and its mapping to CLI exit codes.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScanError {
    /// The template could not be read or parsed.
    #[error("invalid input: {0}")]
    Input(String),
    /// A public data source could not be fetched or parsed.
    #[error("data source failure: {0}")]
    DataSource(String),
    /// Live mode could not authenticate or lacks permissions.
    #[error("live-mode authentication failure: {0}")]
    Auth(String),
    /// The `--profile` named does not exist.
    #[error("{0}")]
    Profile(String),
}

impl ScanError {
    pub fn exit_code(&self) -> i32 {
        match self {
            ScanError::Input(_) => 1,
            ScanError::DataSource(_) => 3,
            ScanError::Auth(_) | ScanError::Profile(_) => 4,
        }
    }
}

pub type Result<T> = std::result::Result<T, ScanError>;
