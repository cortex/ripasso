extern crate chrono;
extern crate git2;
extern crate glob;
extern crate gpgme;
extern crate notify;

/// This is the library part of ripasso, it implements the functions needed to manipulate a pass
/// directory.
pub mod pass;
/// This is the library that handles password generation, based on the long word list from EFF
/// https://www.eff.org/sv/deeplinks/2016/07/new-wordlists-random-passphrases
pub mod words;

pub(crate) mod error;
pub(crate) mod signature;
