//! Contains the error type for this library.

#![allow(clippy::default_trait_access)]

use crate::schema::RoleType;
use snafu::{Backtrace, Snafu};
use std::fmt::{self, Debug, Display};
use std::path::PathBuf;

/// Alias for `Result<T, Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// The error type for this library.
#[derive(Debug, Snafu)]
#[snafu(visibility = "pub(super)")]
pub enum Error {
    /// A duplicate key ID was present in the root metadata.
    #[snafu(display("Duplicate key ID: {}", keyid))]
    DuplicateKeyId { keyid: String },

    /// Unable to open a file
    #[snafu(display("Failed to open {}: {}", path.display(), source))]
    FileOpen {
        path: PathBuf,
        source: std::io::Error,
        backtrace: Backtrace,
    },

    /// Unable to read the file
    #[snafu(display("Failed to read {}: {}", path.display(), source))]
    FileRead {
        path: PathBuf,
        source: std::io::Error,
        backtrace: Backtrace,
    },

    /// A downloaded target's checksum does not match the checksum listed in the repository
    /// metadata.
    #[snafu(display("Invalid key ID {}: calculated {}", keyid, calculated))]
    InvalidKeyId {
        keyid: String,
        calculated: String,
        backtrace: Backtrace,
    },

    /// Failed to decode a hexadecimal-encoded string.
    #[snafu(display("Invalid hex string: {}", source))]
    HexDecode {
        source: hex::FromHexError,
        backtrace: Backtrace,
    },

    /// The library failed to serialize an object to JSON.
    #[snafu(display("Failed to serialize {} to JSON: {}", what, source))]
    JsonSerialization {
        what: String,
        source: serde_json::Error,
        backtrace: Backtrace,
    },

    /// A required role is missing from the root metadata file.
    #[snafu(display("Role {} missing from root metadata", role))]
    MissingRole {
        role: RoleType,
        backtrace: Backtrace,
    },

    /// Unable to determine file name (path ends in '..' or is '/')
    #[snafu(display("Unable to determine file name from path: '{}'", path.display()))]
    NoFileName { path: PathBuf, backtrace: Backtrace },

    /// Failed to decode a PEM-encoded key.
    #[snafu(display("Invalid PEM string: {}", source))]
    PemDecode {
        source: Compat<pem::PemError>,
        backtrace: Backtrace,
    },

    /// Path isn't a valid UTF8 string
    #[snafu(display("Path {} is not valid UTF-8", path.display()))]
    PathUtf8 { path: PathBuf, backtrace: Backtrace },

    /// A signature threshold specified in root.json was not met when verifying a signature.
    #[snafu(display(
        "Signature threshold of {} not met for role {} ({} valid signatures)",
        threshold,
        role,
        valid,
    ))]
    SignatureThreshold {
        role: RoleType,
        threshold: u64,
        valid: u64,
        backtrace: Backtrace,
    },

    /// Failed to extract a bit string from a `SubjectPublicKeyInfo` document.
    #[snafu(display("Invalid SubjectPublicKeyInfo document"))]
    SpkiDecode { backtrace: Backtrace },

    /// Unable to create a TUF target from anything but a file
    #[snafu(display("TUF targets must be files, given: '{}'", path.display()))]
    TargetNotAFile { path: PathBuf, backtrace: Backtrace },
}

/// Wrapper for error types that don't impl [`std::error::Error`].
///
/// This should not have to exist, and yet...
pub struct Compat<T>(pub T);

impl<T: Debug> Debug for Compat<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl<T: Display> Display for Compat<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl<T: Debug + Display> std::error::Error for Compat<T> {}
