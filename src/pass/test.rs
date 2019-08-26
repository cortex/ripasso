use super::*;

impl std::cmp::PartialEq for Error {
    fn eq(&self, other: &Error) -> bool {
        format!("{:?}", self) == format!("{:?}", *other)
    }
}

#[test]
fn get_password_dir() {
    let dir = tempfile::tempdir().unwrap();
    env::set_var("PASSWORD_STORE_DIR", dir.path());

    let path = password_dir().unwrap();

    assert_eq!(path, dir.path());
}

#[test]
fn get_password_dir_no_env() {
    let dir = tempfile::tempdir().unwrap();
    env::set_var("HOME", dir.path());
    env::remove_var("PASSWORD_STORE_DIR");

    let path = password_dir();

    assert_eq!(path.unwrap_err(), Error::Generic("failed to locate password directory"));
}
