use super::*;

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
    env::remove_var("PASSWORD_STORE_DIR");

    let path = password_dir(&None, &Some(dir.into_path()));

    assert_eq!(
        path.unwrap_err(),
        Error::Generic("failed to locate password directory")
    );
}

#[test]
fn get_password_dir_raw_none_none() {
    let result = password_dir_raw(&None, &None);

    assert_eq!(PathBuf::new().join(".password-store"), result);
}

#[test]
fn get_password_dir_raw_some_none() {
    let result = password_dir_raw(&Some(PathBuf::from("/tmp/")), &None);

    assert_eq!(PathBuf::from("/tmp/"), result);
}

#[test]
fn get_password_dir_raw_none_some() {
    let result = password_dir_raw(&None, &Some(PathBuf::from("/tmp/")));

    assert_eq!(PathBuf::from("/tmp/.password-store"), result);
}

#[test]
fn get_password_dir_raw_some_some() {
    let result = password_dir_raw(&Some(PathBuf::from("/tmp/")), &Some(PathBuf::from("/tmp/")));

    assert_eq!(PathBuf::from("/tmp/"), result);
}

#[test]
fn populate_password_list_small_repo() -> Result<()> {
    let mut base_path: PathBuf = std::env::current_exe().unwrap();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.push("testres");

    let home: PathBuf = base_path.clone();
    let mut password_dir: PathBuf = base_path.clone();
    password_dir.push("populate_password_list_small_repo");

    unpack_tar_gz(
        base_path.clone(),
        "populate_password_list_small_repo.tar.gz",
    )
    .unwrap();

    let store = PasswordStore::new("default", &Some(password_dir), &None, &Some(home), &None)?;
    let results = store.all_passwords().unwrap();

    cleanup(base_path, "populate_password_list_small_repo").unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "test");
    assert_eq!(results[0].committed_by, Some("Alexander Kjäll".to_string()));
    assert_eq!(results[0].signature_status.is_none(), false);
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

    let home: PathBuf = base_path.clone();
    let mut password_dir: PathBuf = base_path.clone();
    password_dir.push("populate_password_list_repo_with_deleted_files");

    unpack_tar_gz(
        base_path.clone(),
        "populate_password_list_repo_with_deleted_files.tar.gz",
    )?;

    let store = PasswordStore::new("default", &Some(password_dir), &None, &Some(home), &None)?;
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

    let home: PathBuf = base_path.clone();
    let mut password_dir: PathBuf = base_path.clone();
    password_dir.push("populate_password_list_directory_without_git");

    unpack_tar_gz(
        base_path.clone(),
        "populate_password_list_directory_without_git.tar.gz",
    )?;

    let store = PasswordStore::new("default", &Some(password_dir), &None, &Some(home), &None)?;
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

    let home: PathBuf = base_path.clone();
    let mut password_dir: PathBuf = base_path.clone();
    password_dir.push("password_store_with_files_in_initial_commit");

    unpack_tar_gz(
        base_path.clone(),
        "password_store_with_files_in_initial_commit.tar.gz",
    )?;

    let store = PasswordStore::new("default", &Some(password_dir), &None, &Some(home), &None)?;
    let results = store.all_passwords().unwrap();

    cleanup(base_path, "password_store_with_files_in_initial_commit").unwrap();

    let expected = vec!["3", "A/1", "B/2"];

    assert_eq!(results.len(), expected.len());

    for (i, e) in expected.iter().enumerate() {
        assert_eq!(results[i].name, e.to_string());
        assert_eq!(results[i].committed_by.is_none(), false);
        assert_eq!(results[i].updated.is_none(), false);
    }
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

    let home: PathBuf = base_path.clone();
    let mut password_dir: PathBuf = base_path.clone();
    password_dir.push("password_store_with_relative_path");

    unpack_tar_gz(
        base_path.clone(),
        "password_store_with_relative_path.tar.gz",
    )?;

    let store = PasswordStore::new(
        "default",
        &Some(PathBuf::from("./testres/password_store_with_relative_path")),
        &None,
        &Some(home),
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

    let home: PathBuf = base_path.clone();
    let mut password_dir: PathBuf = base_path.clone();
    password_dir.push("password_store_with_shallow_checkout");

    unpack_tar_gz(
        base_path.clone(),
        "password_store_with_shallow_checkout.tar.gz",
    )?;

    let store = PasswordStore::new(&"default", &Some(password_dir), &None, &Some(home), &None)?;
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

    let home: PathBuf = base_path.clone();
    let mut password_dir: PathBuf = base_path.clone();
    password_dir.push("password_store_with_sparse_checkout");

    unpack_tar_gz(
        base_path.clone(),
        "password_store_with_sparse_checkout.tar.gz",
    )?;

    let store = PasswordStore::new("default", &Some(password_dir), &None, &Some(home), &None)?;
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

#[cfg(target_family = "unix")]
#[test]
fn password_store_with_symlink() -> Result<()> {
    let mut base_path: PathBuf = std::env::current_exe().unwrap();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.push("testres");

    let home: PathBuf = base_path.clone();
    let mut password_dir: PathBuf = base_path.clone();
    password_dir.push("password_store_with_symlink_link");

    unpack_tar_gz(base_path.clone(), "password_store_with_symlink.tar.gz")?;

    let mut target = base_path.clone();
    target.push("password_store_with_symlink");
    std::os::unix::fs::symlink(target, password_dir.clone())?;

    let store = PasswordStore::new("default", &Some(password_dir), &None, &Some(home), &None)?;
    let results = store.all_passwords().unwrap();

    cleanup(base_path.clone(), "password_store_with_symlink").unwrap();
    cleanup(base_path, "password_store_with_symlink_link").unwrap();

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
fn parse_signing_keys_empty() {
    let result = parse_signing_keys(&None).unwrap();

    assert_eq!(result.len(), 0);
}

#[test]
fn home_exists_missing_home_env() {
    assert_eq!(false, home_exists(&None, &config::Config::default()));
}

#[test]
fn home_exists_home_dir_without_config_dir() {
    let dir = tempfile::tempdir().unwrap();
    let result = home_exists(&Some(dir.into_path()), &config::Config::default());

    assert_eq!(false, result);
}

#[test]
fn home_exists_home_dir_with_file_instead_of_dir() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();
    File::create(dir.path().join(".password-store"))?;
    let result = home_exists(&Some(dir.into_path()), &config::Config::default());

    assert_eq!(false, result);

    Ok(())
}

#[test]
fn home_exists_home_dir_with_config_dir() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".password-store"))?;
    let result = home_exists(&Some(dir.into_path()), &config::Config::default());

    assert_eq!(true, result);

    Ok(())
}

#[test]
fn env_var_exists_test_none() {
    assert_eq!(false, env_var_exists(&None, &None));
}

#[test]
fn env_var_exists_test_without_dir() {
    let dir = tempfile::tempdir().unwrap();

    assert_eq!(
        true,
        env_var_exists(
            &Some(
                dir.path()
                    .join(".password-store")
                    .to_str()
                    .unwrap()
                    .to_owned()
            ),
            &None
        )
    );
}

#[test]
fn env_var_exists_test_with_dir() {
    let dir = tempfile::tempdir().unwrap();

    assert_eq!(
        true,
        env_var_exists(&Some(dir.path().to_str().unwrap().to_owned()), &None)
    );
}

#[test]
fn home_settings_missing() {
    assert_eq!(
        Error::GenericDyn("no home directory set".to_string()),
        home_settings(&None).err().unwrap()
    );
}

#[test]
fn home_settings_dir_exists() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(".password-store"))?;

    let settings = home_settings(&Some(PathBuf::from(dir.path()))).unwrap();

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

    let settings = home_settings(&Some(PathBuf::from(dir.path()))).unwrap();

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
        &Some("/home/user/.password-store".to_string()),
        &Some("E6A7D758338EC2EF2A8A9F4EE7E3DB4B3217482F".to_string()),
    )?;

    let stores = settings.get_table("stores")?;
    let work = stores["default"].clone().into_table()?;
    let path = work["path"].clone().into_str()?;
    let valid_signing_keys = work["valid_signing_keys"].clone().into_str()?;

    assert_eq!("/home/user/.password-store/", path);
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
    settings.merge(file_settings(
        &xdg_config_file_location(&Some(dir.into_path()), &None).unwrap(),
    )?)?;

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
        file_settings(&xdg_config_file_location(
            &Some(dir.into_path()),
            &Some(dir2.path().join(".random_config")),
        )?)
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

    let (settings, _) = read_config(&None, &None, &Some(PathBuf::from(dir.path())), &None)?;

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
fn read_config_empty_config_file_with_keys_env() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".password-store"))?;

    let (settings, _) = read_config(
        &None,
        &Some("E6A7D758338EC2EF2A8A9F4EE7E3DB4B3217482F".to_string()),
        &Some(PathBuf::from(dir.path())),
        &None,
    )?;

    let stores = settings.get_table("stores")?;
    let work = stores["default"].clone().into_table()?;
    let path = work["path"].clone().into_str()?;
    let valid_signing_keys = work["valid_signing_keys"].clone().into_str()?;

    assert_eq!(
        dir.path()
            .join(".password-store/")
            .to_str()
            .unwrap()
            .to_owned(),
        path
    );
    assert_eq!(
        "E6A7D758338EC2EF2A8A9F4EE7E3DB4B3217482F",
        valid_signing_keys
    );

    Ok(())
}

#[test]
fn read_config_env_vars() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("env_var").join(".password-store"))?;

    let (settings, _) = read_config(
        &Some(
            dir.path()
                .join("env_var")
                .join(".password-store")
                .to_str()
                .unwrap()
                .to_owned(),
        ),
        &Some("E6A7D758338EC2EF2A8A9F4EE7E3DB4B3217482F".to_string()),
        &Some(PathBuf::from(dir.path())),
        &None,
    )?;

    let stores = settings.get_table("stores")?;
    let work = stores["default"].clone().into_table()?;
    let path = work["path"].clone().into_str()?;
    let valid_signing_keys = work["valid_signing_keys"].clone().into_str()?;

    assert_eq!(
        dir.path()
            .join("env_var")
            .join(".password-store/")
            .to_str()
            .unwrap()
            .to_owned(),
        path
    );
    assert_eq!(
        "E6A7D758338EC2EF2A8A9F4EE7E3DB4B3217482F",
        valid_signing_keys
    );

    Ok(())
}

#[test]
fn read_config_home_and_env_vars() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".password-store"))?;
    std::fs::create_dir_all(dir.path().join("env_var").join(".password-store"))?;

    let (settings, _) = read_config(
        &Some(
            dir.path()
                .join("env_var")
                .join(".password-store")
                .to_str()
                .unwrap()
                .to_owned(),
        ),
        &Some("E6A7D758338EC2EF2A8A9F4EE7E3DB4B3217482F".to_string()),
        &Some(PathBuf::from(dir.path())),
        &None,
    )?;

    let stores = settings.get_table("stores")?;
    let work = stores["default"].clone().into_table()?;
    let path = work["path"].clone().into_str()?;
    let valid_signing_keys = work["valid_signing_keys"].clone().into_str()?;

    assert_eq!(
        dir.path()
            .join("env_var")
            .join(".password-store/")
            .to_str()
            .unwrap()
            .to_owned(),
        path
    );
    assert_eq!(
        "E6A7D758338EC2EF2A8A9F4EE7E3DB4B3217482F",
        valid_signing_keys
    );

    Ok(())
}

#[test]
fn read_config_default_path_in_config_file() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".password-store"))?;
    let mut gpg_file = File::create(dir.path().join(".password-store").join(".gpg-id"))?;
    writeln!(&gpg_file, "0xDF0C3D316B7312D5\n")?;
    gpg_file.flush()?;

    std::fs::create_dir_all(dir.path().join(".config").join("ripasso"))?;
    let mut file = File::create(
        dir.path()
            .join(".config")
            .join("ripasso")
            .join("settings.toml"),
    )?;

    writeln!(
        &file,
        "[stores]\n    [stores.work]\n    path = \"{}\"\n",
        dir.path().join(".password-store").to_str().unwrap()
    )?;
    file.flush()?;

    let (settings, _) = read_config(&None, &None, &Some(PathBuf::from(dir.path())), &None)?;

    let stores = settings.get_table("stores")?;

    let work = stores["work"].clone().into_table()?;
    let path = work["path"].clone().into_str()?;
    assert_eq!(dir.path().join(".password-store").to_str().unwrap(), path);

    assert_eq!(false, stores.contains_key("default"));
    Ok(())
}

#[test]
fn read_config_default_path_in_env_var() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".password-store"))?;
    let mut gpg_file = File::create(dir.path().join(".password-store").join(".gpg-id"))?;
    writeln!(&gpg_file, "0xDF0C3D316B7312D5\n")?;
    gpg_file.flush()?;

    std::fs::create_dir_all(dir.path().join(".config").join("ripasso"))?;
    let mut file = File::create(
        dir.path()
            .join(".config")
            .join("ripasso")
            .join("settings.toml"),
    )?;

    writeln!(
        &file,
        "[stores]\n    [stores.default]\n    path = \"{}\"\n    valid_signing_keys = \"7E068070D5EF794B00C8A9D91D108E6C07CBC406\"\n",
        dir.path().join(".password-store").to_str().unwrap()
    )?;
    file.flush()?;

    let (settings, _) = read_config(
        &Some("/tmp/t2".to_owned()),
        &None,
        &Some(dir.into_path()),
        &None,
    )?;

    let stores = settings.get_table("stores")?;

    let work = stores["default"].clone().into_table()?;
    let path = work["path"].clone().into_str()?;
    let keys = work["valid_signing_keys"].clone().into_str()?;
    assert_eq!("/tmp/t2/", path);
    assert_eq!("-1", keys);

    assert_eq!(false, stores.contains_key("work"));
    Ok(())
}

#[test]
fn append_extension_with_dot() {
    let result = append_extension(PathBuf::from("foo.txt"), ".gpg");
    assert_eq!(result, PathBuf::from("foo.txt.gpg"));
}

#[test]
fn rename_file() -> Result<()> {
    let mut base_path: PathBuf = std::env::current_exe().unwrap();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.push("testres");

    let home: PathBuf = base_path.clone();
    let mut password_dir: PathBuf = base_path.clone();
    password_dir.push("rename_file");

    unpack_tar_gz(base_path.clone(), "rename_file.tar.gz")?;

    let mut config_location = password_dir.clone();
    config_location.push(".git");
    config_location.push("config");
    let mut config = git2::Config::open(&config_location)?;
    config.set_str("user.name", "default")?;
    config.set_str("user.email", "default@example.com")?;

    let mut store = PasswordStore::new("default", &Some(password_dir), &None, &Some(home), &None)?;
    store.reload_password_list()?;
    store.rename_file("1/test", "2/test")?;
    let results = store.all_passwords()?;

    cleanup(base_path, "rename_file").unwrap();

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].name, "2/test");
    assert_eq!(results[0].committed_by.is_none(), false);
    assert_eq!(results[0].updated.is_none(), false);

    assert_eq!(results[1].name, "test");
    assert_eq!(results[1].committed_by.is_none(), false);
    assert_eq!(results[1].updated.is_none(), false);
    Ok(())
}

#[test]
fn rename_file_absolute_path() -> Result<()> {
    let mut base_path: PathBuf = std::env::current_exe().unwrap();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.push("testres");

    let home: PathBuf = base_path.clone();
    let mut password_dir: PathBuf = base_path.clone();
    password_dir.push("rename_file_absolute_path");

    unpack_tar_gz(base_path.clone(), "rename_file_absolute_path.tar.gz")?;

    let mut store = PasswordStore::new("default", &Some(password_dir), &None, &Some(home), &None)?;
    store.reload_password_list()?;
    let res = store.rename_file("1/test", "/2/test");

    cleanup(base_path, "rename_file_absolute_path").unwrap();

    assert_eq!(true, res.is_err());
    Ok(())
}

#[test]
fn decrypt_secret_empty_file() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".password-store"))?;
    let mut gpg_file = File::create(dir.path().join(".password-store").join(".gpg-id"))?;
    writeln!(&gpg_file, "0xDF0C3D316B7312D5\n")?;
    gpg_file.flush()?;

    let mut pass_file = File::create(dir.path().join(".password-store").join("file.gpg"))?;
    pass_file.flush()?;

    let pe = PasswordEntry::new(
        &dir.path().join(".password-store"),
        &PathBuf::from("file.gpg"),
        Ok(Local::now()),
        Ok("".to_string()),
        Ok(SignatureStatus::Good),
        RepositoryStatus::NoRepo,
    );

    let res = pe.secret();

    assert_eq!(true, res.is_err());
    assert_eq!(
        "Generic(\"empty password file\")",
        format!("{:?}", res.err().unwrap())
    );

    Ok(())
}

#[test]
fn decrypt_password_empty_file() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".password-store"))?;
    let mut gpg_file = File::create(dir.path().join(".password-store").join(".gpg-id"))?;
    writeln!(&gpg_file, "0xDF0C3D316B7312D5\n")?;
    gpg_file.flush()?;

    let mut pass_file = File::create(dir.path().join(".password-store").join("file.gpg"))?;
    pass_file.flush()?;

    let pe = PasswordEntry::new(
        &dir.path().join(".password-store"),
        &PathBuf::from("file.gpg"),
        Ok(Local::now()),
        Ok("".to_string()),
        Ok(SignatureStatus::Good),
        RepositoryStatus::NoRepo,
    );

    let res = pe.password();

    assert_eq!(true, res.is_err());
    assert_eq!(
        "Generic(\"empty password file\")",
        format!("{:?}", res.err().unwrap())
    );

    Ok(())
}

#[test]
fn delete_file() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".password-store"))?;
    let mut gpg_file = File::create(dir.path().join(".password-store").join(".gpg-id"))?;
    writeln!(&gpg_file, "0xDF0C3D316B7312D5\n")?;
    gpg_file.flush()?;

    let mut pass_file = File::create(dir.path().join(".password-store").join("file.gpg"))?;
    pass_file.flush()?;

    let store = PasswordStore::new(
        "test",
        &Some(dir.path().join(".password-store")),
        &None,
        &None,
        &None,
    )?;

    let pe = PasswordEntry::new(
        &dir.path().join(".password-store"),
        &PathBuf::from("file.gpg"),
        Ok(Local::now()),
        Ok("".to_string()),
        Ok(SignatureStatus::Good),
        RepositoryStatus::NoRepo,
    );

    let res = pe.delete_file(&store);
    assert_eq!(false, res.is_err());

    let stat = fs::metadata(dir.path().join(".password-store").join("file.gpg"));
    assert_eq!(true, stat.is_err());

    Ok(())
}

#[test]
fn get_history_no_repo() -> Result<()> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".password-store"))?;
    let mut gpg_file = File::create(dir.path().join(".password-store").join(".gpg-id"))?;
    writeln!(&gpg_file, "0xDF0C3D316B7312D5\n")?;
    gpg_file.flush()?;

    let mut pass_file = File::create(dir.path().join(".password-store").join("file.gpg"))?;
    pass_file.flush()?;

    let store = PasswordStore::new(
        "test",
        &Some(dir.path().join(".password-store")),
        &None,
        &None,
        &None,
    )?;

    let pe = PasswordEntry::new(
        &dir.path().join(".password-store"),
        &PathBuf::from("file.gpg"),
        Ok(Local::now()),
        Ok("".to_string()),
        Ok(SignatureStatus::Good),
        RepositoryStatus::NoRepo,
    );

    let history = pe.get_history(&Arc::new(Mutex::new(store)))?;

    assert_eq!(0, history.len());

    Ok(())
}

#[test]
fn get_history_with_repo() -> Result<()> {
    let mut base_path: PathBuf = std::env::current_exe().unwrap();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.push("testres");

    let home: PathBuf = base_path.clone();
    let mut password_dir: PathBuf = base_path.clone();
    password_dir.push("get_history_with_repo");

    unpack_tar_gz(base_path.clone(), "get_history_with_repo.tar.gz")?;

    let store = PasswordStore::new("default", &Some(password_dir), &None, &Some(home), &None)?;
    let results = store.all_passwords().unwrap();

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "test");
    assert_eq!(results[0].committed_by, Some("default".to_string()));
    assert_eq!(results[0].signature_status.is_none(), true);

    let pw = &results[0];
    let history = pw.get_history(&Arc::new(Mutex::new(store)))?;

    cleanup(base_path, "get_history_with_repo").unwrap();

    assert_eq!(history.len(), 3);
    assert_eq!(history[0].message, "commit 3\n");
    assert_eq!(history[0].signature_status, None);
    assert_eq!(history[1].message, "commit 2\n");
    assert_eq!(history[1].signature_status, None);
    assert_eq!(history[2].message, "commit 1\n");
    assert_eq!(history[2].signature_status, None);

    Ok(())
}
