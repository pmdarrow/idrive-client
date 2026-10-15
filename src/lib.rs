//! IDrive Backup client written in Rust, with a C interface for other languages.
//!
//! Disable default features to build the codec without sockets, HTTP or a runtime.
//! Use the Rust client directly or enable `ffi` for the C ABI and Swift adapter.

#[cfg(feature = "native")]
pub mod client;
pub mod crypto;
#[cfg(feature = "native")]
pub mod native;
#[cfg(feature = "native")]
pub use client::Client;
#[cfg(feature = "ffi")]
pub mod ffi;

use zeroize::Zeroizing;

/// Intentionally implements neither Debug nor Serialize.
pub struct Credentials {
    pub username: Zeroizing<String>,
    pub password: Zeroizing<String>,
    pub private_key: Option<Zeroizing<String>>,
}

impl Credentials {
    pub fn new(username: String, password: String, private_key: Option<String>) -> Self {
        Self {
            username: Zeroizing::new(username),
            password: Zeroizing::new(password),
            private_key: private_key.map(Zeroizing::new),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid protocol frame: {0}")]
    Frame(&'static str),
    #[error("server rejected authentication or the requested operation")]
    Rejected,
    #[error("server closed the connection")]
    Closed,
    #[error("operation timed out")]
    Timeout,
    #[error("unsupported account or protocol feature: {0}")]
    Unsupported(&'static str),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[cfg(feature = "native")]
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
