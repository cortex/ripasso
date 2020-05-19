use std::io;
use std::path;
use std::string;

/// A enum that contains the different types of errors that the library returns as part of Result's.
#[derive(Debug)]
pub enum Error {
    IO(io::Error),
    Git(git2::Error),
    GPG(gpgme::Error),
    UTF8(string::FromUtf8Error),
    Notify(notify::Error),
    Generic(&'static str),
    GenericDyn(String),
    PathError(path::StripPrefixError),
    PatternError(glob::PatternError),
    GlobError(glob::GlobError),
    Utf8Error(std::str::Utf8Error),
    RecipientNotInKeyRing(String),
    ConfigError(config::ConfigError),
    NoneError,
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IO(err)
    }
}

impl From<gpgme::Error> for Error {
    fn from(err: gpgme::Error) -> Error {
        Error::GPG(err)
    }
}

impl From<git2::Error> for Error {
    fn from(err: git2::Error) -> Error {
        Error::Git(err)
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(err: string::FromUtf8Error) -> Error {
        Error::UTF8(err)
    }
}

impl From<notify::Error> for Error {
    fn from(err: notify::Error) -> Error {
        Error::Notify(err)
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

/// Convenience type for Results
pub type Result<T> = std::result::Result<T, Error>;
