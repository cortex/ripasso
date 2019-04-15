use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub struct PasswordStore {
    root: PathBuf,
}

pub struct PasswordEntry {}

impl PasswordStore {
    // Creates a new password store directory
    pub fn create(path: &Path) -> Result<PasswordStore> {
        // TODO: Verify that it doesn't exist already
        let attr = fs::metadata(path)?;
        if attr.is_dir() {
            return Err(Error::Generic("Directory already exists"));
        }
        PasswordStore::open(path)
    }

    // Opens an existing password store directory
    pub fn open(path: &Path) -> Result<PasswordStore> {
        // TODO: Verify that the store looks valid
        let attr = fs::metadata(path)?;
        if !attr.is_dir() {
            return Err(Error::Generic("Supplied path is not a directory"));
        }
        Ok(PasswordStore { root: path.into() })
    }

    pub fn add(self, path: &Path, secret: &str) -> Result<()> {
        Err(Error::NotImplemented())
    }

    pub fn get(key: String) -> Result<PasswordEntry> {
        Err(Error::NotImplemented())
    }
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    IO(io::Error),
    // Git(git2::Error),
    // GPG(gpgme::Error),
    // UTF8(string::FromUtf8Error),
    // Notify(notify::Error),
    Generic(&'static str),
    // PathError(path::StripPrefixError),
    NotImplemented(),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IO(err)
    }
}
