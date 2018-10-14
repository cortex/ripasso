#![recursion_limit = "1024"]
pub mod gtkui;
pub mod pass;
pub mod qmlui;
pub mod tui;

#[macro_use]
extern crate log;
extern crate env_logger;

extern crate chrono;
extern crate git2;
extern crate glob;
extern crate gpgme;
extern crate notify;

#[cfg(feature = "use-gtk")]
extern crate gtk;

#[cfg(feature = "use-gtk")]
extern crate glib;

#[cfg(feature = "use-qml")]
extern crate qml;
