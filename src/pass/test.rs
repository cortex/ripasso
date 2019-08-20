use super::*;

#[test]
fn get_password_dir() {
    let dir = tempfile::tempdir().unwrap();
    env::set_var("PASSWORD_STORE_DIR", dir.path());

    let path = password_dir().unwrap();

    assert_eq!(path, dir.path());
}
