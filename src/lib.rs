extern crate chrono;
extern crate env_logger;
extern crate git2;
extern crate glob;
extern crate gpgme;
extern crate notify;

#[macro_use]
extern crate log;

/// This is the library part of ripasso, it implements the functions needed to manipulate a pass
/// directory.
pub mod pass;
