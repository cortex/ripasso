use std::io;
use std::path;
use std::string;

/// A enum that contains the different types of errors that the library returns as part of Result's.
#[derive(Debug)]
pub enum Error {
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
    NoneError,
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::Io(err)
    }
}

impl From<gpgme::Error> for Error {
    fn from(err: gpgme::Error) -> Error {
        Error::Gpg(err)
    }
}

impl From<git2::Error> for Error {
    fn from(err: git2::Error) -> Error {
        Error::Git(err)
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(err: string::FromUtf8Error) -> Error {
        Error::Utf8(err)
    }
}

impl From<path::StripPrefixError> for Error {
    fn from(err: path::StripPrefixError) -> Error {
        Error::PathError(err)
    }
}

impl From<glob::PatternError> for Error {
    fn from(err: glob::PatternError) -> Error {
        Error::PatternError(err)
    }
}

impl From<glob::GlobError> for Error {
    fn from(err: glob::GlobError) -> Error {
        Error::GlobError(err)
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(err: std::str::Utf8Error) -> Error {
        Error::Utf8Error(err)
    }
}

impl From<Option<std::str::Utf8Error>> for Error {
    fn from(err: Option<std::str::Utf8Error>) -> Error {
        match err {
            None => Error::Generic("gpgme error with None"),
            Some(e) => Error::Utf8Error(e),
        }
    }
}

impl From<std::boxed::Box<dyn std::error::Error>> for Error {
    fn from(err: std::boxed::Box<dyn std::error::Error>) -> Error {
        Error::GenericDyn(err.to_string())
    }
}

impl From<config::ConfigError> for Error {
    fn from(err: config::ConfigError) -> Error {
        Error::ConfigError(err)
    }
}

impl From<toml::ser::Error> for Error {
    fn from(err: toml::ser::Error) -> Error {
        Error::SerError(err)
    }
}

impl From<&str> for Error {
    fn from(err: &str) -> Error {
        Error::GenericDyn(err.to_string())
    }
}

impl From<std::sync::PoisonError<std::sync::MutexGuard<'_, crate::pass::PasswordStore>>> for Error {
    fn from(
        _err: std::sync::PoisonError<std::sync::MutexGuard<'_, crate::pass::PasswordStore>>,
    ) -> Error {
        Error::Generic("thread error")
    }
}

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Error {
        Error::ReqwestError(err)
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
    ) -> Error {
        Error::Generic("thread error")
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &*self {
            Error::Io(err) => write!(f, "{}", err),
            Error::Git(err) => write!(f, "{}", err),
            Error::Gpg(err) => write!(f, "{}", err),
            Error::Utf8(err) => write!(f, "{}", err),
            Error::Generic(err) => write!(f, "{}", err),
            Error::GenericDyn(err) => write!(f, "{}", err),
            Error::PathError(err) => write!(f, "{}", err),
            Error::PatternError(err) => write!(f, "{}", err),
            Error::GlobError(err) => write!(f, "{}", err),
            Error::Utf8Error(err) => write!(f, "{}", err),
            Error::RecipientNotInKeyRing(err) => write!(f, "{}", err),
            Error::ConfigError(err) => write!(f, "{}", err),
            Error::SerError(err) => write!(f, "{}", err),
            Error::ReqwestError(err) => write!(f, "{}", err),
            Error::NoneError => write!(f, "NoneError"),
        }
    }
}

/// Convenience type for Results
pub type Result<T> = std::result::Result<T, Error>;
