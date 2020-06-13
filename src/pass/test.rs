use super::*;

extern crate flate2;
extern crate tar;

use flate2::read::GzDecoder;
use std::fs::File;
use std::path::PathBuf;
use tar::Archive;

use std::env;

impl std::cmp::PartialEq for Error {
    fn eq(&self, other: &Error) -> bool {
        format!("{:?}", self) == format!("{:?}", *other)
    }
}

fn unpack_tar_gz(mut base_path: PathBuf, tar_gz_name: &str) -> Result<()> {
    let target = format!("{}", base_path.as_path().display());
    base_path.push(tar_gz_name);

    let path = format!("{}", base_path.as_path().display());

    let tar_gz = File::open(path)?;
    let tar = GzDecoder::new(tar_gz);
    let mut archive = Archive::new(tar);
    archive.unpack(target)?;

    Ok(())
}

fn cleanup(mut base_path: PathBuf, path_name: &str) -> Result<()> {
    base_path.push(path_name);

    std::fs::remove_dir_all(base_path)?;

    Ok(())
}

#[test]
fn get_password_dir_no_env() {
    let dir = tempfile::tempdir().unwrap();
    env::set_var("HOME", dir.path());
    env::remove_var("PASSWORD_STORE_DIR");

    let path = password_dir(&None);

    assert_eq!(
        path.unwrap_err(),
        Error::Generic("failed to locate password directory")
    );
}

#[test]
fn populate_password_list_small_repo() -> Result<()> {
    let mut base_path: PathBuf = std::env::current_exe().unwrap();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.push("testres");

    let mut password_dir: PathBuf = base_path.clone();
    password_dir.push("populate_password_list_small_repo");

    unpack_tar_gz(
        base_path.clone(),
        "populate_password_list_small_repo.tar.gz",
    )
    .unwrap();

    let store = PasswordStore::new(
        "default",
        &Some(String::from(password_dir.to_str().unwrap())),
        &None,
    )?;
    let results = store.all_passwords().unwrap();

    cleanup(base_path, "populate_password_list_small_repo").unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "test");
    assert_eq!(results[0].committed_by, Some("Alexander Kjäll".to_string()));
    assert_eq!(results[0].signature_status.is_none(), true);
    Ok(())
}

#[test]
fn populate_password_list_repo_with_deleted_files() -> Result<()> {
    let mut base_path: PathBuf = std::env::current_exe().unwrap();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.push("testres");

    let mut password_dir: PathBuf = base_path.clone();
    password_dir.push("populate_password_list_repo_with_deleted_files");

    unpack_tar_gz(
        base_path.clone(),
        "populate_password_list_repo_with_deleted_files.tar.gz",
    )?;

    let store = PasswordStore::new(
        "default",
        &Some(String::from(password_dir.to_str().unwrap())),
        &None,
    )?;
    let results = store.all_passwords().unwrap();

    cleanup(base_path, "populate_password_list_repo_with_deleted_files").unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "10");
    assert_eq!(results[0].committed_by, Some("Alexander Kjäll".to_string()));
    assert_eq!(results[0].signature_status.is_none(), true);
    Ok(())
}

#[test]
fn populate_password_list_directory_without_git() -> Result<()> {
    let mut base_path: PathBuf = std::env::current_exe().unwrap();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.push("testres");

    let mut password_dir: PathBuf = base_path.clone();
    password_dir.push("populate_password_list_directory_without_git");

    unpack_tar_gz(
        base_path.clone(),
        "populate_password_list_directory_without_git.tar.gz",
    )?;

    let store = PasswordStore::new(
        "default",
        &Some(String::from(password_dir.to_str().unwrap())),
        &None,
    )?;
    let results = store.all_passwords().unwrap();

    cleanup(base_path, "populate_password_list_directory_without_git").unwrap();

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].name, "first");
    assert_eq!(results[0].committed_by.is_none(), true);
    assert_eq!(results[0].updated.is_none(), true);
    assert_eq!(results[0].signature_status.is_none(), true);

    assert_eq!(results[1].name, "second");
    assert_eq!(results[1].committed_by.is_none(), true);
    assert_eq!(results[1].updated.is_none(), true);
    assert_eq!(results[1].signature_status.is_none(), true);

    assert_eq!(results[2].name, "third");
    assert_eq!(results[2].committed_by.is_none(), true);
    assert_eq!(results[2].updated.is_none(), true);
    assert_eq!(results[2].signature_status.is_none(), true);
    Ok(())
}

#[test]
fn password_store_with_files_in_initial_commit() -> Result<()> {
    let mut base_path: PathBuf = std::env::current_exe().unwrap();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.push("testres");

    let mut password_dir: PathBuf = base_path.clone();
    password_dir.push("password_store_with_files_in_initial_commit");

    unpack_tar_gz(
        base_path.clone(),
        "password_store_with_files_in_initial_commit.tar.gz",
    )?;

    let store = PasswordStore::new(
        "default",
        &Some(String::from(password_dir.to_str().unwrap())),
        &None,
    )?;
    let results = store.all_passwords().unwrap();

    cleanup(base_path, "password_store_with_files_in_initial_commit").unwrap();

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].name, "3");
    assert_eq!(results[0].committed_by.is_none(), false);
    assert_eq!(results[0].updated.is_none(), false);

    assert_eq!(results[1].name, "2");
    assert_eq!(results[1].committed_by.is_none(), false);
    assert_eq!(results[1].updated.is_none(), false);

    assert_eq!(results[2].name, "1");
    assert_eq!(results[2].committed_by.is_none(), false);
    assert_eq!(results[2].updated.is_none(), false);
    Ok(())
}

#[test]
fn password_store_with_relative_path() -> Result<()> {
    let mut base_path: PathBuf = std::env::current_exe().unwrap();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.push("testres");

    let mut password_dir: PathBuf = base_path.clone();
    password_dir.push("password_store_with_relative_path");

    unpack_tar_gz(
        base_path.clone(),
        "password_store_with_relative_path.tar.gz",
    )?;

    let store = PasswordStore::new(
        "default",
        &Some("./testres/password_store_with_relative_path".to_string()),
        &None,
    );
    if store.is_err() {
        eprintln!("{:?}", store.err().unwrap());
    } else {
        let results = store?.all_passwords()?;

        cleanup(base_path, "password_store_with_relative_path").unwrap();

        assert_eq!(results.len(), 3);
        assert_eq!(results[0].name, "3");
        assert_eq!(results[0].committed_by.is_none(), false);
        assert_eq!(results[0].updated.is_none(), false);

        assert_eq!(results[1].name, "2");
        assert_eq!(results[1].committed_by.is_none(), false);
        assert_eq!(results[1].updated.is_none(), false);

        assert_eq!(results[2].name, "1");
        assert_eq!(results[2].committed_by.is_none(), false);
        assert_eq!(results[2].updated.is_none(), false);
    }
    Ok(())
}

#[test]
fn password_store_with_shallow_checkout() -> Result<()> {
    let mut base_path: PathBuf = std::env::current_exe().unwrap();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.push("testres");

    let mut password_dir: PathBuf = base_path.clone();
    password_dir.push("password_store_with_shallow_checkout");

    unpack_tar_gz(
        base_path.clone(),
        "password_store_with_shallow_checkout.tar.gz",
    )?;

    let store = PasswordStore::new(
        &"default",
        &Some(String::from(password_dir.to_str().unwrap())),
        &None,
    )?;
    let results = store.all_passwords().unwrap();

    cleanup(base_path, "password_store_with_shallow_checkout").unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "1");
    assert_eq!(results[0].committed_by.is_none(), false);
    assert_eq!(results[0].updated.is_none(), false);

    Ok(())
}

#[test]
fn password_store_with_sparse_checkout() -> Result<()> {
    let mut base_path: PathBuf = std::env::current_exe().unwrap();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.push("testres");

    let mut password_dir: PathBuf = base_path.clone();
    password_dir.push("password_store_with_sparse_checkout");

    unpack_tar_gz(
        base_path.clone(),
        "password_store_with_sparse_checkout.tar.gz",
    )?;

    let store = PasswordStore::new(
        "default",
        &Some(String::from(password_dir.to_str().unwrap())),
        &None,
    )?;
    let results = store.all_passwords().unwrap();

    cleanup(base_path, "password_store_with_sparse_checkout").unwrap();

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].name, "3/1");
    assert_eq!(results[0].committed_by.is_none(), false);
    assert_eq!(results[0].updated.is_none(), false);

    assert_eq!(results[1].name, "2/1");
    assert_eq!(results[1].committed_by.is_none(), false);
    assert_eq!(results[1].updated.is_none(), false);

    assert_eq!(results[2].name, "1/1");
    assert_eq!(results[2].committed_by.is_none(), false);
    assert_eq!(results[2].updated.is_none(), false);
    Ok(())
}

#[test]
fn parse_signing_keys_empty() {
    let result = parse_signing_keys(&None).unwrap();

    assert_eq!(result.len(), 0);
}

#[test]
fn home_exists_missing_home_env() {
    assert_eq!(false, home_exists(&None));
}

#[test]
fn home_exists_home_dir_without_config_dir() {
    let dir = tempfile::tempdir().unwrap();
    let result = home_exists(&Some(dir.path().to_str().unwrap().to_owned()));

    assert_eq!(false, result);
}

#[test]
fn home_exists_home_dir_with_file_instead_of_dir() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();
    File::create(dir.path().join(".password-store"))?;
    let result = home_exists(&Some(dir.path().to_str().unwrap().to_owned()));

    assert_eq!(false, result);

    Ok(())
}

#[test]
fn home_exists_home_dir_with_config_dir() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".password-store"))?;
    let result = home_exists(&Some(dir.path().to_str().unwrap().to_owned()));

    assert_eq!(true, result);

    Ok(())
}

#[test]
fn env_var_exists_test_none() {
    assert_eq!(false, env_var_exists(&None));
}

#[test]
fn env_var_exists_test_without_dir() {
    let dir = tempfile::tempdir().unwrap();

    assert_eq!(
        false,
        env_var_exists(&Some(
            dir.path()
                .join(".password-store")
                .to_str()
                .unwrap()
                .to_owned()
        ))
    );
}

#[test]
fn env_var_exists_test_with_dir() {
    let dir = tempfile::tempdir().unwrap();

    assert_eq!(
        true,
        env_var_exists(&Some(dir.path().to_str().unwrap().to_owned()))
    );
}

#[test]
fn home_settings_missing() {
    assert_eq!(
        Error::Generic("no home directory set"),
        home_settings(&None).err().unwrap()
    );
}

#[test]
fn home_settings_dir_exists() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".password-store"))?;

    let settings = home_settings(&Some(dir.path().to_str().unwrap().to_owned())).unwrap();

    let stores = settings.get_table("stores")?;
    let work = stores["default"].clone().into_table()?;
    let path = work["path"].clone().into_str()?;

    assert_eq!(
        dir.path()
            .join(".password-store/")
            .to_str()
            .unwrap()
            .to_owned(),
        path
    );

    Ok(())
}

/// this works due to that it's the function `home_exists` that checks if it exists
#[test]
fn home_settings_dir_doesnt_exists() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();

    let settings = home_settings(&Some(dir.path().to_str().unwrap().to_owned())).unwrap();

    let stores = settings.get_table("stores")?;
    let work = stores["default"].clone().into_table()?;
    let path = work["path"].clone().into_str()?;

    assert_eq!(
        dir.path()
            .join(".password-store/")
            .to_str()
            .unwrap()
            .to_owned(),
        path
    );

    Ok(())
}

#[test]
fn var_settings_test() -> Result<()> {
    let settings = var_settings(
        Some("/home/user/.password-store".to_string()),
        Some("E6A7D758338EC2EF2A8A9F4EE7E3DB4B3217482F".to_string()),
    )?;

    let stores = settings.get_table("stores")?;
    let work = stores["default"].clone().into_table()?;
    let path = work["path"].clone().into_str()?;
    let valid_signing_keys = work["valid_signing_keys"].clone().into_str()?;

    assert_eq!("/home/user/.password-store", path);
    assert_eq!(
        "E6A7D758338EC2EF2A8A9F4EE7E3DB4B3217482F",
        valid_signing_keys
    );

    Ok(())
}

#[test]
fn file_settings_simple_file() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".config").join("ripasso"))?;
    let mut file = File::create(
        dir.path()
            .join(".config")
            .join("ripasso")
            .join("settings.toml"),
    )?;

    writeln!(
        &file,
        "[stores]\n    [stores.work]\n    path = \"/home/user/.password-store\"\n"
    )?;
    file.flush()?;

    let mut settings: config::Config = config::Config::default();
    settings
        .merge(file_settings(&Some(dir.path().to_str().unwrap().to_owned()), &None).unwrap())?;

    let stores = settings.get_table("stores")?;

    let work = stores["work"].clone().into_table()?;
    let path = work["path"].clone().into_str()?;
    assert_eq!("/home/user/.password-store", path);

    Ok(())
}

#[test]
fn file_settings_file_in_xdg_config_home() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();
    let dir2 = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir2.path().join(".random_config").join("ripasso"))?;
    let mut file = File::create(
        dir2.path()
            .join(".random_config")
            .join("ripasso")
            .join("settings.toml"),
    )?;

    writeln!(
        &file,
        "[stores]\n    [stores.work]\n    path = \"/home/user/.password-store\"\n"
    )?;
    file.flush()?;

    let mut settings: config::Config = config::Config::default();
    settings.merge(
        file_settings(
            &Some(dir.path().to_str().unwrap().to_owned()),
            &Some(
                dir2.path()
                    .join(".random_config")
                    .to_str()
                    .unwrap()
                    .to_owned(),
            ),
        )
        .unwrap(),
    )?;

    let stores = settings.get_table("stores")?;

    let work = stores["work"].clone().into_table()?;
    let path = work["path"].clone().into_str()?;
    assert_eq!("/home/user/.password-store", path);

    Ok(())
}

#[test]
fn read_config_empty_config_file() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".config").join("ripasso"))?;
    std::fs::create_dir_all(dir.path().join(".password-store"))?;
    File::create(
        dir.path()
            .join(".config")
            .join("ripasso")
            .join("settings.toml"),
    )?;

    let settings = read_config(
        None,
        None,
        Some(dir.path().to_str().unwrap().to_owned()),
        None,
    )?;

    let stores = settings.get_table("stores")?;
    let work = stores["default"].clone().into_table()?;
    let path = work["path"].clone().into_str()?;

    assert_eq!(
        dir.path()
            .join(".password-store/")
            .to_str()
            .unwrap()
            .to_owned(),
        path
    );

    Ok(())
}
