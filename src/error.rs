use std::{
    io, path, string,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use hex::FromHexError;

use crate::pass::PasswordStore;

/// A enum that contains the different types of errors that the library returns as part of Result's.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    Clipboard(arboard::Error),
    Io(io::Error),
    Git(git2::Error),
    Gpg(gpgme::Error),
    Utf8(string::FromUtf8Error),
    Generic(&'static str),
    GenericDyn(String),
    PathError(path::StripPrefixError),
    PatternError(glob::PatternError),
    GlobError(glob::GlobError),
    Utf8Error(std::str::Utf8Error),
    RecipientNotInKeyRing(String),
    ConfigError(config::ConfigError),
    SerError(toml::ser::Error),
    ReqwestError(reqwest::Error),
    AnyhowError(anyhow::Error),
    NoneError,
    HexError(FromHexError),
    FmtError(std::fmt::Error),
    TotpUrlError(totp_rs::TotpUrlError),
    SystemTimeError(std::time::SystemTimeError),
}

impl From<arboard::Error> for Error {
    fn from(err: arboard::Error) -> Self {
        Self::Clipboard(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<gpgme::Error> for Error {
    fn from(err: gpgme::Error) -> Self {
        Self::Gpg(err)
    }
}

impl From<git2::Error> for Error {
    fn from(err: git2::Error) -> Self {
        Self::Git(err)
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(err: string::FromUtf8Error) -> Self {
        Self::Utf8(err)
    }
}

impl From<path::StripPrefixError> for Error {
    fn from(err: path::StripPrefixError) -> Self {
        Self::PathError(err)
    }
}

impl From<glob::PatternError> for Error {
    fn from(err: glob::PatternError) -> Self {
        Self::PatternError(err)
    }
}

impl From<glob::GlobError> for Error {
    fn from(err: glob::GlobError) -> Self {
        Self::GlobError(err)
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(err: std::str::Utf8Error) -> Self {
        Self::Utf8Error(err)
    }
}

impl From<Option<std::str::Utf8Error>> for Error {
    fn from(err: Option<std::str::Utf8Error>) -> Self {
        match err {
            None => Self::Generic("gpgme error with None"),
            Some(e) => Self::Utf8Error(e),
        }
    }
}

impl From<std::boxed::Box<dyn std::error::Error>> for Error {
    fn from(err: std::boxed::Box<dyn std::error::Error>) -> Self {
        Self::GenericDyn(err.to_string())
    }
}

impl From<config::ConfigError> for Error {
    fn from(err: config::ConfigError) -> Self {
        Self::ConfigError(err)
    }
}

impl From<toml::ser::Error> for Error {
    fn from(err: toml::ser::Error) -> Self {
        Self::SerError(err)
    }
}

impl From<&str> for Error {
    fn from(err: &str) -> Self {
        Self::GenericDyn(err.to_owned())
    }
}

impl From<std::sync::PoisonError<std::sync::MutexGuard<'_, crate::pass::PasswordStore>>> for Error {
    fn from(
        _err: std::sync::PoisonError<std::sync::MutexGuard<'_, crate::pass::PasswordStore>>,
    ) -> Self {
        Self::Generic("thread error")
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        Self::ReqwestError(err)
    }
}

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        Self::AnyhowError(err)
    }
}

impl
    From<
        std::sync::PoisonError<
            std::sync::MutexGuard<'_, std::vec::Vec<crate::pass::PasswordStore>>,
        >,
    > for Error
{
    fn from(
        _err: std::sync::PoisonError<
            std::sync::MutexGuard<'_, std::vec::Vec<crate::pass::PasswordStore>>,
        >,
    ) -> Self {
        Self::Generic("thread error")
    }
}

impl From<FromHexError> for Error {
    fn from(err: FromHexError) -> Self {
        Self::HexError(err)
    }
}

impl From<std::fmt::Error> for Error {
    fn from(err: std::fmt::Error) -> Self {
        Self::FmtError(err)
    }
}

impl From<totp_rs::TotpUrlError> for Error {
    fn from(err: totp_rs::TotpUrlError) -> Self {
        Self::TotpUrlError(err)
    }
}

impl From<std::time::SystemTimeError> for Error {
    fn from(err: std::time::SystemTimeError) -> Self {
        Self::SystemTimeError(err)
    }
}

impl From<PoisonError<MutexGuard<'_, Vec<Arc<Mutex<PasswordStore>>>>>> for Error {
    fn from(_err: PoisonError<MutexGuard<'_, Vec<Arc<Mutex<PasswordStore>>>>>) -> Self {
        Self::Generic("Error obtaining lock")
    }
}

impl From<PoisonError<MutexGuard<'_, Arc<Mutex<PasswordStore>>>>> for Error {
    fn from(_err: PoisonError<MutexGuard<'_, Arc<Mutex<PasswordStore>>>>) -> Self {
        Self::Generic("Error obtaining lock")
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
            Self::Generic(err) => write!(f, "{err}"),
            Self::GenericDyn(err) => write!(f, "{err}"),
            Self::PathError(err) => write!(f, "{err}"),
            Self::PatternError(err) => write!(f, "{err}"),
            Self::GlobError(err) => write!(f, "{err}"),
            Self::Utf8Error(err) => write!(f, "{err}"),
            Self::RecipientNotInKeyRing(err) => write!(f, "{err}"),
            Self::ConfigError(err) => write!(f, "{err}"),
            Self::SerError(err) => write!(f, "{err}"),
            Self::ReqwestError(err) => write!(f, "{err}"),
            Self::AnyhowError(err) => write!(f, "{err}"),
            Self::NoneError => write!(f, "NoneError"),
            Self::HexError(err) => write!(f, "{err}"),
            Self::FmtError(err) => write!(f, "{err}"),
            Self::TotpUrlError(_err) => write!(f, "TOTP url error"),
            Self::SystemTimeError(err) => write!(f, "{err}"),
        }
    }
}

/// Convenience type for Results
pub type Result<T> = std::result::Result<T, Error>;

pub fn to_result<T: chrono::TimeZone>(
    res: chrono::LocalResult<chrono::DateTime<T>>,
) -> Result<chrono::DateTime<T>> {
    match res {
        chrono::LocalResult::None => Err(Error::Generic("no timezone")),
        chrono::LocalResult::Single(t) => Ok(t),
        chrono::LocalResult::Ambiguous(_, _) => Err(Error::Generic("too many timezones")),
    }
}
