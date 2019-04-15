extern crate ripasso;
use ripasso::pass2;
use std::path::Path;

// Can open a password store
fn test_open() {
    let store = pass2::PasswordStore::open(Path::new("examples/empty-store"));
}

// Can list entries in an existing password store
fn test_list() {}

// Can create a new password store
fn test_init() {
    pass2::PasswordStore::create(Path::new("/tmp/new"));
}

// Can add an entry to a password store
fn test_add() {
    let store = pass2::PasswordStore::open(Path::new("~/.password-store"))?;
    store.add(Path::new("test"), "test");
    store.info("test");
}
