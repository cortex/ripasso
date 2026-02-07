use std::{io, path, str::Utf8Error, string};
use std::sync::PoisonError;
use hex::FromHexError;
use thiserror::Error;

/// An enum that contains the different types of errors that the library returns as part of Result's.
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum Error {
    Clipboard(#[from] arboard::Error),
    Io(#[from] io::Error),
    Git(#[from] git2::Error),
    Gpg(#[from] gpgme::Error),
    Utf8(#[from] string::FromUtf8Error),
    OptionUtf8(Option<string::FromUtf8Error>),
    Generic(String),
    PathError(#[from] path::StripPrefixError),
    PatternError(#[from] glob::PatternError),
    GlobError(#[from] glob::GlobError),
    Utf8Error(#[from] std::str::Utf8Error),
    RecipientNotInKeyRing(String),
    ConfigError(#[from] config::ConfigError),
    SerError(#[from] toml::ser::Error),
    ReqwestError(#[from] reqwest::Error),
    AnyhowError(#[from] anyhow::Error),
    NoneError,
    HexError(#[from] FromHexError),
    FmtError(#[from] std::fmt::Error),
    TotpUrlError(#[from] totp_rs::TotpUrlError),
    SystemTimeError(#[from] std::time::SystemTimeError),
}

impl From<&str> for Error {
    fn from(err: &str) -> Self {
        Self::Generic(err.to_owned())
    }
}

impl From<Option<Utf8Error>> for Error {
    fn from(err: Option<Utf8Error>) -> Self {
        match err {
            None => Self::from("gpgme error with None"),
            Some(e) => Self::Utf8Error(e),
        }
    }
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Self::Generic(err)
    }
}

impl<E> From<PoisonError<E>> for Error {
    fn from(err: PoisonError<E>) -> Self {
        Self::Generic(err.to_string())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Clipboard(err) => write!(f, "{err}"),
            Self::Io(err) => write!(f, "{err}"),
            Self::Git(err) => write!(f, "{err}"),
            Self::Gpg(err) => write!(f, "{err}"),
            Self::Utf8(err) => write!(f, "{err}"),
            Self::Generic(err) | Self::RecipientNotInKeyRing(err) => write!(f, "{err}"),
            Self::PathError(err) => write!(f, "{err}"),
            Self::PatternError(err) => write!(f, "{err}"),
            Self::GlobError(err) => write!(f, "{err}"),
            Self::Utf8Error(err) => write!(f, "{err}"),
            Self::ConfigError(err) => write!(f, "{err}"),
            Self::SerError(err) => write!(f, "{err}"),
            Self::ReqwestError(err) => write!(f, "{err}"),
            Self::AnyhowError(err) => write!(f, "{err}"),
            Self::HexError(err) => write!(f, "{err}"),
            Self::FmtError(err) => write!(f, "{err}"),
            Self::SystemTimeError(err) => write!(f, "{err}"),
            Self::NoneError => write!(f, "NoneError"),
            Self::TotpUrlError(_err) => write!(f, "TOTP url error"),
            Self::OptionUtf8(_err) => write!(f, "FromUtf8Error"),
        }
    }
}

/// Convenience type for Results
pub type Result<T> = std::result::Result<T, Error>;

/// Converts a `LocalResult` to a normal `Result`.
///
/// # Errors
/// If the supplied `LocalResult` have no timezone or more than one timezone.
pub fn to_result<T: chrono::TimeZone>(
    res: chrono::LocalResult<chrono::DateTime<T>>,
) -> Result<chrono::DateTime<T>> {
    match res {
        chrono::LocalResult::None => Err(Error::from("no timezone")),
        chrono::LocalResult::Single(t) => Ok(t),
        chrono::LocalResult::Ambiguous(_, _) => Err(Error::from("too many timezones")),
    }
}
