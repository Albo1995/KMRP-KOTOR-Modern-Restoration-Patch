//! The crate-wide error type.

use std::path::PathBuf;

/// Everything that can go wrong while reading or writing a resource.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An operating-system I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// An I/O error on a named file.
    #[error("{path}: {source}")]
    File {
        /// The file that failed.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },

    /// The data ended before a structure was complete.
    #[error("{format}: truncated: need {needed} bytes at offset {offset}, but the data is {len} bytes long")]
    Truncated {
        /// Format being parsed.
        format: &'static str,
        /// Offset of the read.
        offset: usize,
        /// Bytes the read needed.
        needed: usize,
        /// Length of the data.
        len: usize,
    },

    /// The file signature or version is not the expected one.
    #[error("{format}: bad signature {found:?}, expected {expected}")]
    BadSignature {
        /// Format being parsed.
        format: &'static str,
        /// What the file starts with (lossy).
        found: String,
        /// What was expected.
        expected: &'static str,
    },

    /// The data is structurally invalid.
    #[error("{format}: {message}")]
    Invalid {
        /// Format being parsed or written.
        format: &'static str,
        /// What is wrong.
        message: String,
    },

    /// A string cannot be represented in the on-disk encoding or field.
    #[error("cannot encode {what}: {message}")]
    Encode {
        /// What was being encoded.
        what: &'static str,
        /// Why it failed.
        message: String,
    },

    /// A resource or path was not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// A feature of the format that this crate does not implement.
    #[error("{format}: unsupported: {message}")]
    Unsupported {
        /// Format being parsed.
        format: &'static str,
        /// What is unsupported.
        message: String,
    },
}

impl Error {
    pub(crate) fn invalid(format: &'static str, message: impl Into<String>) -> Self {
        Error::Invalid {
            format,
            message: message.into(),
        }
    }

    pub(crate) fn unsupported(format: &'static str, message: impl Into<String>) -> Self {
        Error::Unsupported {
            format,
            message: message.into(),
        }
    }

    /// Wrap an I/O error with the path it happened on.
    pub fn file(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::File {
            path: path.into(),
            source,
        }
    }
}

/// Crate result alias.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Read a whole file, attaching the path to any error.
pub fn read_file(path: impl AsRef<std::path::Path>) -> Result<Vec<u8>> {
    let path = path.as_ref();
    std::fs::read(path).map_err(|e| Error::file(path, e))
}
