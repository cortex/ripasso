use super::*;

impl std::cmp::PartialEq for Error {
    fn eq(&self, other: &Error) -> bool {
        format!("{:?}", self) == format!("{:?}", *other)
    }
}

#[test]
fn get_password_dir_no_env() {
    let dir = tempfile::tempdir().unwrap();
    env::set_var("HOME", dir.path());
    env::remove_var("PASSWORD_STORE_DIR");

    let path = password_dir();

    assert_eq!(path.unwrap_err(), Error::Generic("failed to locate password directory"));
}

#[test]
fn do_not_generate_passwords_that_ends_in_space() {
    let pass = generate_password(3);

    assert!(!pass.ends_with(" "));
}

#[test]
fn generate_long_enough_passwords() {
    let pass = generate_password(3);

    assert!(pass.len() > 10);
}
