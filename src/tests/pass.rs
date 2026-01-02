use config::ConfigBuilder;
use git2::Repository;
use hex::FromHex;
use sequoia_openpgp::{
    cert::CertBuilder,
    serialize::{
        Serialize,
        stream::{Armorer, Message, Signer},
    },
};
use std::{env, fs::File, path::PathBuf};
use tempfile::tempdir;

use super::*;
use crate::test_helpers::{
    MockCrypto, UnpackedDir, count_recipients, generate_sequoia_cert,
    generate_sequoia_cert_without_private_key,
};

impl PartialEq for Error {
    fn eq(&self, other: &Error) -> bool {
        format!("{:?}", self) == format!("{:?}", *other)
    }
}

pub fn setup_store(
    td: &tempfile::TempDir,
    user_home: &Path,
) -> Result<(PasswordStore, Vec<Arc<sequoia_openpgp::Cert>>)> {
    let users = vec![
        Arc::new(generate_sequoia_cert("alice@example.org")),
        Arc::new(generate_sequoia_cert("bob@example.org")),
        Arc::new(generate_sequoia_cert("carlos@example.org")),
        Arc::new(generate_sequoia_cert_without_private_key(
            "daniel@example.com",
        )),
    ];
    let mut key_ring = HashMap::new();
    for u in &users {
        key_ring.insert(u.fingerprint().as_bytes().try_into()?, u.clone());
    }

    let store = PasswordStore {
        name: "store_name".to_owned(),
        root: td.path().to_path_buf(),
        valid_gpg_signing_keys: vec![],
        passwords: [].to_vec(),
        style_file: None,
        crypto: Box::new(Sequoia::from_values(
            users[0].fingerprint().as_bytes().try_into()?,
            key_ring,
            user_home,
        )),
        user_home: None,
    };

    Ok((store, users))
}

#[test]
fn get_password_dir_no_env() {
    let dir = tempdir().unwrap();

    // ensure that the test run isn't polluted by outside env.
    // "safe" as it's just a unit test
    unsafe {
        env::remove_var("PASSWORD_STORE_DIR");
    }

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
    let dir = UnpackedDir::new("populate_password_list_small_repo")?;

    let store = PasswordStore::new(
        "default",
        &Some(dir.dir()),
        &None,
        &Some(dir.dir()),
        &None,
        &CryptoImpl::GpgMe,
        &None,
    )?;
    let results = store.all_passwords()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "test");
    assert_eq!(results[0].committed_by, Some("Alexander Kjäll".to_owned()));
    assert!(results[0].signature_status.is_none());
    Ok(())
}

#[test]
fn populate_password_list_repo_with_deleted_files() -> Result<()> {
    let dir = UnpackedDir::new("populate_password_list_repo_with_deleted_files")?;

    let store = PasswordStore::new(
        "default",
        &Some(dir.dir()),
        &None,
        &Some(dir.dir()),
        &None,
        &CryptoImpl::GpgMe,
        &None,
    )?;
    let results = store.all_passwords()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "10");
    assert_eq!(results[0].committed_by, Some("Alexander Kjäll".to_owned()));
    assert!(results[0].signature_status.is_none());
    Ok(())
}

#[test]
fn populate_password_list_directory_without_git() -> Result<()> {
    let dir = UnpackedDir::new("populate_password_list_directory_without_git")?;

    let store = PasswordStore::new(
        "default",
        &Some(dir.dir()),
        &None,
        &Some(dir.dir()),
        &None,
        &CryptoImpl::GpgMe,
        &None,
    )?;
    let results = store.all_passwords()?;

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].name, "first");
    assert!(results[0].committed_by.is_none());
    assert!(results[0].updated.is_none());
    assert!(results[0].signature_status.is_none());

    assert_eq!(results[1].name, "second");
    assert!(results[1].committed_by.is_none());
    assert!(results[1].updated.is_none());
    assert!(results[1].signature_status.is_none());

    assert_eq!(results[2].name, "third");
    assert!(results[2].committed_by.is_none());
    assert!(results[2].updated.is_none());
    assert!(results[2].signature_status.is_none());
    Ok(())
}

#[test]
fn password_store_with_files_in_initial_commit() -> Result<()> {
    let dir = UnpackedDir::new("password_store_with_files_in_initial_commit")?;

    let store = PasswordStore::new(
        "default",
        &Some(dir.dir()),
        &None,
        &Some(dir.dir()),
        &None,
        &CryptoImpl::GpgMe,
        &None,
    )?;
    let results = store.all_passwords()?;

    let expected = ["3", "A/1", "B/2"];

    assert_eq!(results.len(), expected.len());

    for (i, e) in expected.iter().enumerate() {
        assert_eq!(results[i].name, e.to_string());
        assert!(results[i].committed_by.is_some());
        assert!(results[i].updated.is_some());
    }
    Ok(())
}

#[test]
fn password_store_with_relative_path() -> Result<()> {
    let dir = UnpackedDir::new("password_store_with_relative_path")?;

    let store = PasswordStore::new(
        "default",
        &Some(dir.dir()),
        &None,
        &Some(dir.dir()),
        &None,
        &CryptoImpl::GpgMe,
        &None,
    )?;

    let results = store.all_passwords()?;

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].name, "3");
    assert!(results[0].committed_by.is_some());
    assert!(results[0].updated.is_some());

    assert_eq!(results[1].name, "2");
    assert!(results[1].committed_by.is_some());
    assert!(results[1].updated.is_some());

    assert_eq!(results[2].name, "1");
    assert!(results[2].committed_by.is_some());
    assert!(results[2].updated.is_some());

    Ok(())
}

#[test]
fn password_store_with_shallow_checkout() -> Result<()> {
    let dir = UnpackedDir::new("password_store_with_shallow_checkout")?;

    let store = PasswordStore::new(
        "default",
        &Some(dir.dir()),
        &None,
        &Some(dir.dir()),
        &None,
        &CryptoImpl::GpgMe,
        &None,
    )?;
    let results = store.all_passwords()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "1");
    assert!(results[0].committed_by.is_some());
    assert!(results[0].updated.is_some());

    Ok(())
}

#[test]
fn password_store_with_sparse_checkout() -> Result<()> {
    let dir = UnpackedDir::new("password_store_with_sparse_checkout")?;

    let store = PasswordStore::new(
        "default",
        &Some(dir.dir()),
        &None,
        &Some(dir.dir()),
        &None,
        &CryptoImpl::GpgMe,
        &None,
    )?;
    let results = store.all_passwords()?;

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].name, "3/1");
    assert!(results[0].committed_by.is_some());
    assert!(results[0].updated.is_some());

    assert_eq!(results[1].name, "2/1");
    assert!(results[1].committed_by.is_some());
    assert!(results[1].updated.is_some());

    assert_eq!(results[2].name, "1/1");
    assert!(results[2].committed_by.is_some());
    assert!(results[2].updated.is_some());
    Ok(())
}

#[cfg(target_family = "unix")]
#[test]
fn password_store_with_symlink() -> Result<()> {
    let dir = UnpackedDir::new("password_store_with_symlink")?;
    let link_dir = dir
        .path()
        .parent()
        .unwrap()
        .join("password_store_with_symlink_link");
    std::os::unix::fs::symlink(dir.path(), link_dir.clone())?;

    let store = PasswordStore::new(
        "default",
        &Some(link_dir.clone()),
        &None,
        &Some(link_dir.clone()),
        &None,
        &CryptoImpl::GpgMe,
        &None,
    )?;
    let results = store.all_passwords()?;

    fs::remove_file(link_dir)?;

    assert_eq!(results.len(), 3);
    assert_eq!(results[0].name, "3");
    assert!(results[0].committed_by.is_some());
    assert!(results[0].updated.is_some());

    assert_eq!(results[1].name, "2");
    assert!(results[1].committed_by.is_some());
    assert!(results[1].updated.is_some());

    assert_eq!(results[2].name, "1");
    assert!(results[2].committed_by.is_some());
    assert!(results[2].updated.is_some());
    Ok(())
}

#[test]
fn home_exists_missing_home_env() {
    assert!(!home_exists(&None, &Config::default()));
}

#[test]
fn home_exists_home_dir_without_config_dir() {
    let dir = tempdir().unwrap();
    let result = home_exists(&Some(dir.into_path()), &Config::default());

    assert!(!result);
}

#[test]
fn home_exists_home_dir_with_file_instead_of_dir() -> Result<()> {
    let dir = tempdir()?;
    File::create(dir.path().join(".password-store"))?;
    let result = home_exists(&Some(dir.into_path()), &Config::default());

    assert!(!result);

    Ok(())
}

#[test]
fn home_exists_home_dir_with_config_dir() -> Result<()> {
    let dir = tempdir()?;
    fs::create_dir(dir.path().join(".password-store"))?;
    let result = home_exists(&Some(dir.into_path()), &Config::default());

    assert!(result);

    Ok(())
}

#[test]
fn env_var_exists_test_none() {
    assert!(!env_var_exists(&None, &None));
}

#[test]
fn env_var_exists_test_without_dir() {
    let dir = tempdir().unwrap();

    assert!(env_var_exists(
        &Some(
            dir.path()
                .join(".password-store")
                .to_str()
                .unwrap()
                .to_owned()
        ),
        &None
    ));
}

#[test]
fn env_var_exists_test_with_dir() {
    let dir = tempdir().unwrap();

    assert!(env_var_exists(
        &Some(dir.path().to_str().unwrap().to_owned()),
        &None
    ));
}

#[test]
fn home_settings_missing() {
    assert_eq!(
        Error::GenericDyn("no home directory set".to_owned()),
        home_settings(&None).err().unwrap()
    );
}

#[test]
fn home_settings_dir_exists() -> Result<()> {
    let dir = tempdir()?;
    fs::create_dir(dir.path().join(".password-store"))?;

    let settings = home_settings(&Some(PathBuf::from(dir.path())))?;

    let stores = settings.get_table("stores")?;
    let work = stores["default"].clone().into_table()?;
    let path = work["path"].clone().into_string()?;

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
    let dir = tempdir()?;

    let settings = home_settings(&Some(PathBuf::from(dir.path())))?;

    let stores = settings.get_table("stores")?;
    let work = stores["default"].clone().into_table()?;
    let path = work["path"].clone().into_string()?;

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
        &Some("/home/user/.password-store".to_owned()),
        &Some("E6A7D758338EC2EF2A8A9F4EE7E3DB4B3217482F".to_owned()),
    )?;

    let stores = settings.get_table("stores")?;
    let work = stores["default"].clone().into_table()?;
    let path = work["path"].clone().into_string()?;
    let valid_signing_keys = work["valid_signing_keys"].clone().into_string()?;

    assert_eq!("/home/user/.password-store/", path);
    assert_eq!(
        "E6A7D758338EC2EF2A8A9F4EE7E3DB4B3217482F",
        valid_signing_keys
    );

    Ok(())
}

#[test]
fn file_settings_simple_file() -> Result<()> {
    let dir = tempdir()?;
    create_dir_all(dir.path().join(".config").join("ripasso"))?;
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

    let mut settings = ConfigBuilder::default();
    settings = config::ConfigBuilder::<config::builder::DefaultState>::add_source(
        settings,
        file_settings(&xdg_config_file_location(&Some(dir.into_path()), &None)?),
    );
    let settings = settings.build()?;

    let stores = settings.get_table("stores")?;

    let work = stores["work"].clone().into_table()?;
    let path = work["path"].clone().into_string()?;
    assert_eq!("/home/user/.password-store", path);

    Ok(())
}

#[test]
fn file_settings_file_in_xdg_config_home() -> Result<()> {
    let dir = tempdir()?;
    let dir2 = tempdir()?;
    create_dir_all(dir2.path().join(".random_config").join("ripasso"))?;
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

    let mut settings = ConfigBuilder::default();
    settings = config::ConfigBuilder::<config::builder::DefaultState>::add_source(
        settings,
        file_settings(&xdg_config_file_location(
            &Some(dir.into_path()),
            &Some(dir2.path().join(".random_config")),
        )?),
    );
    let settings = settings.build()?;

    let stores = settings.get_table("stores")?;

    let work = stores["work"].clone().into_table()?;
    let path = work["path"].clone().into_string()?;
    assert_eq!("/home/user/.password-store", path);

    Ok(())
}

#[test]
fn read_config_empty_config_file() -> Result<()> {
    let dir = tempdir()?;
    create_dir_all(dir.path().join(".config").join("ripasso"))?;
    create_dir_all(dir.path().join(".password-store"))?;
    File::create(
        dir.path()
            .join(".config")
            .join("ripasso")
            .join("settings.toml"),
    )?;

    let (settings, _) = read_config(&None, &None, &Some(PathBuf::from(dir.path())), &None)?;

    let stores = settings.get_table("stores")?;
    let work = stores["default"].clone().into_table()?;
    let path = work["path"].clone().into_string()?;

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
    let dir = tempdir()?;
    create_dir_all(dir.path().join(".password-store"))?;

    let (settings, _) = read_config(
        &None,
        &Some("E6A7D758338EC2EF2A8A9F4EE7E3DB4B3217482F".to_owned()),
        &Some(PathBuf::from(dir.path())),
        &None,
    )?;

    let stores = settings.get_table("stores")?;
    let work = stores["default"].clone().into_table()?;
    let path = work["path"].clone().into_string()?;
    let valid_signing_keys = work["valid_signing_keys"].clone().into_string()?;

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
    let dir = tempdir()?;
    create_dir_all(dir.path().join("env_var").join(".password-store"))?;

    let (settings, _) = read_config(
        &Some(
            dir.path()
                .join("env_var")
                .join(".password-store")
                .to_str()
                .unwrap()
                .to_owned(),
        ),
        &Some("E6A7D758338EC2EF2A8A9F4EE7E3DB4B3217482F".to_owned()),
        &Some(PathBuf::from(dir.path())),
        &None,
    )?;

    let stores = settings.get_table("stores")?;
    let work = stores["default"].clone().into_table()?;
    let path = work["path"].clone().into_string()?;
    let valid_signing_keys = work["valid_signing_keys"].clone().into_string()?;

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
    let dir = tempdir()?;
    create_dir_all(dir.path().join(".password-store"))?;
    create_dir_all(dir.path().join("env_var").join(".password-store"))?;

    let (settings, _) = read_config(
        &Some(
            dir.path()
                .join("env_var")
                .join(".password-store")
                .to_str()
                .unwrap()
                .to_owned(),
        ),
        &Some("E6A7D758338EC2EF2A8A9F4EE7E3DB4B3217482F".to_owned()),
        &Some(PathBuf::from(dir.path())),
        &None,
    )?;

    let stores = settings.get_table("stores")?;
    let work = stores["default"].clone().into_table()?;
    let path = work["path"].clone().into_string()?;
    let valid_signing_keys = work["valid_signing_keys"].clone().into_string()?;

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
    let dir = tempdir()?;
    create_dir_all(dir.path().join(".password-store"))?;
    let mut gpg_file = File::create(dir.path().join(".password-store").join(".gpg-id"))?;
    writeln!(&gpg_file, "0xDF0C3D316B7312D5\n")?;
    gpg_file.flush()?;

    create_dir_all(dir.path().join(".config").join("ripasso"))?;
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
    let path = work["path"].clone().into_string()?;
    assert_eq!(dir.path().join(".password-store").to_str().unwrap(), path);

    assert!(!stores.contains_key("default"));
    Ok(())
}

#[test]
fn read_config_default_path_in_env_var() -> Result<()> {
    let dir = tempdir()?;
    create_dir_all(dir.path().join(".password-store"))?;
    let mut gpg_file = File::create(dir.path().join(".password-store").join(".gpg-id"))?;
    writeln!(&gpg_file, "0xDF0C3D316B7312D5\n")?;
    gpg_file.flush()?;

    create_dir_all(dir.path().join(".config").join("ripasso"))?;
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
    let path = work["path"].clone().into_string()?;
    let keys = work["valid_signing_keys"].clone().into_string()?;
    assert_eq!("/tmp/t2/", path);
    assert_eq!("-1", keys);

    assert!(!stores.contains_key("work"));
    Ok(())
}

#[test]
fn read_config_default_path_in_env_var_with_pgp_setting() -> Result<()> {
    let dir = tempdir()?;
    create_dir_all(dir.path().join(".password-store"))?;
    let mut gpg_file = File::create(dir.path().join(".password-store").join(".gpg-id"))?;
    writeln!(&gpg_file, "0xDF0C3D316B7312D5\n")?;
    gpg_file.flush()?;

    create_dir_all(dir.path().join(".config").join("ripasso"))?;
    let mut file = File::create(
        dir.path()
            .join(".config")
            .join("ripasso")
            .join("settings.toml"),
    )?;

    writeln!(
        &file,
        "[stores.default]\npath = \"{}\"\nvalid_signing_keys = \"7E068070D5EF794B00C8A9D91D108E6C07CBC406\"\npgp_implementation = 'gpg'\nown_fingerprint = \"7E068070D5EF794B00C8A9D91D108E6C07CBC406\"",
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
    let path = work["path"].clone().into_string()?;
    let keys = work["valid_signing_keys"].clone().into_string()?;
    assert_eq!("/tmp/t2/", path);
    assert_eq!("-1", keys);
    assert_eq!("gpg", work["pgp_implementation"].clone().into_string()?);
    assert_eq!(
        "7E068070D5EF794B00C8A9D91D108E6C07CBC406",
        work["own_fingerprint"].clone().into_string()?
    );

    assert!(!stores.contains_key("work"));
    Ok(())
}

#[test]
fn save_config_one_store() {
    let config_file = tempfile::NamedTempFile::new().unwrap();
    let style_file = tempfile::NamedTempFile::new().unwrap();
    let passdir = tempdir().unwrap();
    let home = tempdir().unwrap();

    let s1 = PasswordStore::new(
        "s1 name",
        &Some(passdir.path().to_path_buf()),
        &None,
        &Some(home.path().to_path_buf()),
        &Some(style_file.path().to_path_buf()),
        &CryptoImpl::Sequoia,
        &Some(Fingerprint::V4([0; 20])),
    )
    .unwrap();

    save_config(
        Arc::new(Mutex::new(vec![Arc::new(Mutex::new(s1))])),
        config_file.path(),
    )
    .unwrap();

    let config = fs::read_to_string(config_file.path()).unwrap();

    assert!(config.contains("[stores.\"s1 name\"]\n"));
    assert!(config.contains(&format!("path = \"{}\"\n", passdir.path().display())));
    assert!(config.contains(&format!(
        "style_path = \"{}\"\n",
        style_file.path().display()
    )));
    assert!(config.contains("pgp_implementation = \"sequoia\"\n"));
    assert!(config.contains("own_fingerprint = \"0000000000000000000000000000000000000000\"\n"));
}

#[test]
fn save_config_one_store_with_pgp_impl() {
    let dir = tempdir().unwrap();

    let store = PasswordStore::new(
        "default",
        &Some(dir.path().to_path_buf()),
        &None,
        &Some(dir.path().to_path_buf()),
        &None,
        &CryptoImpl::GpgMe,
        &None,
    )
    .unwrap();

    save_config(
        Arc::new(Mutex::new(vec![Arc::new(Mutex::new(store))])),
        &dir.path().join("file.toml"),
    )
    .unwrap();

    let data = fs::read_to_string(dir.path().join("file.toml")).unwrap();

    assert!(data.contains("[stores.default]"));
    assert!(data.contains("pgp_implementation = \"gpg\""));
    assert!(data.contains(&format!("path = \"{}\"\n", &dir.path().display())));
}

#[test]
fn save_config_one_store_with_fingerprint() {
    let dir = tempdir().unwrap();

    let store = PasswordStore::new(
        "default",
        &Some(dir.path().to_path_buf()),
        &None,
        &Some(dir.path().to_path_buf()),
        &None,
        &CryptoImpl::Sequoia,
        &Some(Fingerprint::V4(
            <[u8; 20]>::from_hex("7E068070D5EF794B00C8A9D91D108E6C07CBC406").unwrap(),
        )),
    )
    .unwrap();

    save_config(
        Arc::new(Mutex::new(vec![Arc::new(Mutex::new(store))])),
        &dir.path().join("file.toml"),
    )
    .unwrap();

    let data = fs::read_to_string(dir.path().join("file.toml")).unwrap();

    assert!(data.contains("[stores.default]"));
    assert!(data.contains("pgp_implementation = \"sequoia\""));
    assert!(data.contains("own_fingerprint = \"7E068070D5EF794B00C8A9D91D108E6C07CBC406\""));
    assert!(data.contains(&format!("path = \"{}\"\n", &dir.path().display())));
}

#[test]
fn append_extension_with_dot() {
    let result = append_extension(PathBuf::from("foo.txt"), ".gpg");
    assert_eq!(result, PathBuf::from("foo.txt.gpg"));
}

#[test]
fn rename_file() -> Result<()> {
    let dir = UnpackedDir::new("rename_file")?;

    let mut config_location = dir.dir();
    config_location.push(".git");
    config_location.push("config");
    let mut config = git2::Config::open(&config_location)?;
    config.set_str("user.name", "default")?;
    config.set_str("user.email", "default@example.com")?;
    config.set_str("commit.gpgsign", "false")?;

    let mut store = PasswordStore {
        name: "default".to_owned(),
        root: dir.dir(),
        valid_gpg_signing_keys: vec![],
        passwords: vec![],
        style_file: None,
        crypto: Box::new(MockCrypto::new()),
        user_home: None,
    };

    store.reload_password_list()?;
    let index = store.rename_file("1/test", "2/test")?;

    assert_eq!(1, index);

    assert_eq!(store.passwords.len(), 2);
    assert_eq!(store.passwords[0].name, "test");
    assert!(store.passwords[0].committed_by.is_some());
    assert!(store.passwords[0].updated.is_some());

    assert_eq!(store.passwords[1].name, "2/test");
    assert!(store.passwords[1].committed_by.is_some());
    assert!(store.passwords[1].updated.is_some());
    Ok(())
}

#[test]
fn rename_file_absolute_path() -> Result<()> {
    let dir = UnpackedDir::new("rename_file_absolute_path")?;

    let mut store = PasswordStore::new(
        "default",
        &Some(dir.dir()),
        &None,
        &Some(dir.dir()),
        &None,
        &CryptoImpl::GpgMe,
        &None,
    )?;
    store.reload_password_list()?;
    let res = store.rename_file("1/test", "/2/test");

    assert!(res.is_err());
    Ok(())
}

#[test]
fn rename_file_git_index_clean() -> Result<()> {
    let dir = UnpackedDir::new("rename_file_git_index_clean")?;

    let mut config_location = dir.dir();
    config_location.push(".git");
    config_location.push("config");
    let mut config = git2::Config::open(&config_location)?;
    config.set_str("user.name", "default")?;
    config.set_str("user.email", "default@example.com")?;
    config.set_str("commit.gpgsign", "false")?;

    let mut store = PasswordStore {
        name: "default".to_owned(),
        root: dir.dir(),
        valid_gpg_signing_keys: vec![],
        passwords: vec![],
        style_file: None,
        crypto: Box::new(MockCrypto::new()),
        user_home: None,
    };
    store.reload_password_list()?;
    store.rename_file("1/test", "2/test")?;

    let repo = Repository::open(dir.path())?;

    assert!(repo.statuses(None)?.is_empty());

    Ok(())
}

#[test]
fn decrypt_secret_empty_file() -> Result<()> {
    let dir = tempdir()?;
    create_dir_all(dir.path().join(".password-store"))?;
    let mut gpg_file = File::create(dir.path().join(".password-store").join(".gpg-id"))?;
    writeln!(&gpg_file, "0xDF0C3D316B7312D5\n")?;
    gpg_file.flush()?;

    let mut pass_file = File::create(dir.path().join(".password-store").join("file.gpg"))?;
    pass_file.flush()?;

    let pe = PasswordEntry::new(
        &dir.path().join(".password-store"),
        &PathBuf::from("file.gpg"),
        Ok(Local::now()),
        Ok(String::new()),
        Ok(SignatureStatus::Good),
        RepositoryStatus::NoRepo,
    );

    let store = PasswordStore {
        name: "store_name".to_owned(),
        root: dir.path().join(".password-store"),
        valid_gpg_signing_keys: vec![],
        passwords: vec![],
        style_file: None,
        crypto: Box::new(GpgMe {}),
        user_home: None,
    };

    let res = pe.secret(&store);

    assert!(res.is_err());
    assert_eq!("empty password file", format!("{}", res.err().unwrap()));

    Ok(())
}

#[test]
fn decrypt_secret_missing_file() -> Result<()> {
    let dir = tempdir()?;
    create_dir_all(dir.path().join(".password-store"))?;
    let mut gpg_file = File::create(dir.path().join(".password-store").join(".gpg-id"))?;
    writeln!(&gpg_file, "0xDF0C3D316B7312D5\n")?;
    gpg_file.flush()?;

    let pe = PasswordEntry::new(
        &dir.path().join(".password-store"),
        &PathBuf::from("file.gpg"),
        Ok(Local::now()),
        Ok(String::new()),
        Ok(SignatureStatus::Good),
        RepositoryStatus::NoRepo,
    );

    let store = PasswordStore {
        name: "store_name".to_owned(),
        root: dir.path().join(".password-store"),
        valid_gpg_signing_keys: vec![],
        passwords: vec![],
        style_file: None,
        crypto: Box::new(GpgMe {}),
        user_home: None,
    };

    let res = pe.secret(&store);

    assert!(res.is_err());
    assert_eq!(
        "No such file or directory (os error 2)",
        format!("{}", res.err().unwrap())
    );

    Ok(())
}

#[test]
fn decrypt_secret() -> Result<()> {
    let dir = tempdir()?;
    create_dir_all(dir.path().join(".password-store"))?;
    let mut gpg_file = File::create(dir.path().join(".password-store").join(".gpg-id"))?;
    writeln!(&gpg_file, "0xDF0C3D316B7312D5\n")?;
    gpg_file.flush()?;

    let mut pass_file = File::create(dir.path().join(".password-store").join("file.gpg"))?;
    pass_file.write_all("dummy data".as_bytes())?;
    pass_file.flush()?;

    let pe = PasswordEntry::new(
        &dir.path().join(".password-store"),
        &PathBuf::from("file.gpg"),
        Ok(Local::now()),
        Ok(String::new()),
        Ok(SignatureStatus::Good),
        RepositoryStatus::NoRepo,
    );

    let crypto = MockCrypto::new().with_decrypt_string_return("decrypt_secret unit test");

    let store = PasswordStore {
        name: "store_name".to_owned(),
        root: dir.path().join(".password-store"),
        valid_gpg_signing_keys: vec![],
        passwords: vec![],
        style_file: None,
        crypto: Box::new(crypto),
        user_home: None,
    };

    let res = pe.secret(&store)?;

    assert_eq!("decrypt_secret unit test", res);

    Ok(())
}

#[test]
fn decrypt_password_empty_file() -> Result<()> {
    let dir = tempdir()?;
    create_dir_all(dir.path().join(".password-store"))?;
    let mut gpg_file = File::create(dir.path().join(".password-store").join(".gpg-id"))?;
    writeln!(&gpg_file, "0xDF0C3D316B7312D5\n")?;
    gpg_file.flush()?;

    let mut pass_file = File::create(dir.path().join(".password-store").join("file.gpg"))?;
    pass_file.flush()?;

    let pe = PasswordEntry::new(
        &dir.path().join(".password-store"),
        &PathBuf::from("file.gpg"),
        Ok(Local::now()),
        Ok(String::new()),
        Ok(SignatureStatus::Good),
        RepositoryStatus::NoRepo,
    );

    let store = PasswordStore {
        name: "store_name".to_owned(),
        root: dir.path().join(".password-store"),
        valid_gpg_signing_keys: vec![],
        passwords: vec![],
        style_file: None,
        crypto: Box::new(GpgMe {}),
        user_home: None,
    };

    let res = pe.password(&store);

    assert!(res.is_err());
    assert_eq!("empty password file", format!("{}", res.err().unwrap()));

    Ok(())
}

#[test]
fn decrypt_password_multiline() -> Result<()> {
    let dir = tempdir()?;
    create_dir_all(dir.path().join(".password-store"))?;
    let mut gpg_file = File::create(dir.path().join(".password-store").join(".gpg-id"))?;
    writeln!(&gpg_file, "0xDF0C3D316B7312D5\n")?;
    gpg_file.flush()?;

    let mut pass_file = File::create(dir.path().join(".password-store").join("file.gpg"))?;
    pass_file.write_all("dummy data".as_bytes())?;
    pass_file.flush()?;

    let pe = PasswordEntry::new(
        &dir.path().join(".password-store"),
        &PathBuf::from("file.gpg"),
        Ok(Local::now()),
        Ok(String::new()),
        Ok(SignatureStatus::Good),
        RepositoryStatus::NoRepo,
    );

    let crypto = MockCrypto::new().with_decrypt_string_return("row one\nrow two\nrow three");

    let store = PasswordStore {
        name: "store_name".to_owned(),
        root: dir.path().join(".password-store"),
        valid_gpg_signing_keys: vec![],
        passwords: vec![],
        style_file: None,
        crypto: Box::new(crypto),
        user_home: None,
    };

    let mut res = pe.password(&store)?;

    assert_eq!("row one", res);
    res.zeroize();

    Ok(())
}

fn mfa_setup(payload: String) -> Result<(tempfile::TempDir, PasswordEntry, PasswordStore)> {
    let dir = tempdir()?;
    create_dir_all(dir.path().join(".password-store"))?;
    let mut gpg_file = File::create(dir.path().join(".password-store").join(".gpg-id"))?;
    writeln!(&gpg_file, "0xDF0C3D316B7312D5\n")?;
    gpg_file.flush()?;

    let mut pass_file = File::create(dir.path().join(".password-store").join("file.gpg"))?;
    pass_file.write_all("dummy data".as_bytes())?;
    pass_file.flush()?;

    let pe = PasswordEntry::new(
        &dir.path().join(".password-store"),
        &PathBuf::from("file.gpg"),
        Ok(Local::now()),
        Ok(String::new()),
        Ok(SignatureStatus::Good),
        RepositoryStatus::NoRepo,
    );

    let crypto = MockCrypto::new().with_decrypt_string_return(&payload);

    let store = PasswordStore {
        name: "store_name".to_owned(),
        root: dir.path().join(".password-store"),
        valid_gpg_signing_keys: vec![],
        passwords: vec![],
        style_file: None,
        crypto: Box::new(crypto),
        user_home: None,
    };

    Ok((dir, pe, store))
}

#[test]
fn mfa_example1() -> Result<()> {
    let (_dir, pe, store) = mfa_setup("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXPAAAAAAAAAAAA&issuer=Example".to_owned())?;

    let res = pe.mfa(&store)?;

    assert_eq!(6, res.len());
    assert_eq!(6, res.chars().filter(|c| c.is_ascii_digit()).count());

    Ok(())
}

#[test]
fn mfa_example2() -> Result<()> {
    let (_dir, pe, store) = mfa_setup("some text\n otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXPAAAAAAAAAAAA&issuer=Example\nmore txt\n\n".to_owned())?;

    let res = pe.mfa(&store)?;

    assert_eq!(6, res.len());
    assert_eq!(6, res.chars().filter(|c| c.is_ascii_digit()).count());

    Ok(())
}

#[test]
fn mfa_example3() -> Result<()> {
    let (_dir, pe, store) = mfa_setup("lots and lots and lots and lots and lots and lots and lots and lots and lots and lots of text\n otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXPAAAAAAAAAAAA&issuer=Example\nmore txt\n\n".to_owned())?;

    let res = pe.mfa(&store)?;

    assert_eq!(6, res.len());
    assert_eq!(6, res.chars().filter(|c| c.is_ascii_digit()).count());

    Ok(())
}

#[test]
fn mfa_no_otpauth_url() -> Result<()> {
    let (_dir, pe, store) = mfa_setup("password".to_owned())?;

    let res = pe.mfa(&store);

    assert_eq!(Err(Error::Generic("No otpauth:// url in secret")), res);

    Ok(())
}

#[test]
fn update() -> Result<()> {
    let dir = tempdir()?;
    create_dir_all(dir.path().join(".password-store"))?;
    let mut gpg_file = File::create(dir.path().join(".password-store").join(".gpg-id"))?;
    writeln!(&gpg_file, "0xDF0C3D316B7312D5\n")?;
    gpg_file.flush()?;

    let mut pass_file = File::create(dir.path().join(".password-store").join("file.gpg"))?;
    pass_file.write_all("dummy data".as_bytes())?;
    pass_file.flush()?;

    let pe = PasswordEntry::new(
        &dir.path().join(".password-store"),
        &PathBuf::from("file.gpg"),
        Ok(Local::now()),
        Ok(String::new()),
        Ok(SignatureStatus::Good),
        RepositoryStatus::NoRepo,
    );

    let crypto = MockCrypto::new().with_encrypt_string_return(vec![1, 2, 3]);

    let store = PasswordStore {
        name: "store_name".to_owned(),
        root: dir.path().join(".password-store"),
        valid_gpg_signing_keys: vec![],
        passwords: vec![],
        style_file: None,
        crypto: Box::new(crypto),
        user_home: None,
    };

    let res = pe.update("new content".to_owned(), &store);

    assert!(res.is_ok());

    let mut pass_file = File::open(dir.path().join(".password-store").join("file.gpg"))?;
    let mut data = Vec::new();
    pass_file.read_to_end(&mut data)?;

    assert_eq!(vec![1, 2, 3], data);

    Ok(())
}

#[test]
fn delete_file() -> Result<()> {
    let dir = tempdir()?;
    create_dir_all(dir.path().join(".password-store"))?;
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
        &CryptoImpl::GpgMe,
        &None,
    )?;

    let pe = PasswordEntry::new(
        &dir.path().join(".password-store"),
        &PathBuf::from("file.gpg"),
        Ok(Local::now()),
        Ok(String::new()),
        Ok(SignatureStatus::Good),
        RepositoryStatus::NoRepo,
    );

    let res = pe.delete_file(&store);
    assert!(res.is_ok());

    let stat = fs::metadata(dir.path().join(".password-store").join("file.gpg"));
    assert!(stat.is_err());

    Ok(())
}

#[test]
fn get_history_no_repo() -> Result<()> {
    let dir = tempdir()?;
    create_dir_all(dir.path().join(".password-store"))?;
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
        &CryptoImpl::GpgMe,
        &None,
    )?;

    let pe = PasswordEntry::new(
        &dir.path().join(".password-store"),
        &PathBuf::from("file.gpg"),
        Ok(Local::now()),
        Ok(String::new()),
        Ok(SignatureStatus::Good),
        RepositoryStatus::NoRepo,
    );

    let history = pe.get_history(&store)?;

    assert_eq!(0, history.len());

    Ok(())
}

#[test]
fn get_history_with_repo() -> Result<()> {
    let dir = UnpackedDir::new("get_history_with_repo")?;

    let store = PasswordStore::new(
        "default",
        &Some(dir.dir()),
        &None,
        &Some(dir.dir()),
        &None,
        &CryptoImpl::GpgMe,
        &None,
    )?;
    let results = store.all_passwords()?;

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].name, "test");
    assert_eq!(results[0].committed_by, Some("default".to_owned()));
    assert!(results[0].signature_status.is_none());

    let pw = &results[0];
    let history = pw.get_history(&store)?;

    assert_eq!(history.len(), 3);
    assert_eq!(history[0].message, "commit 3\n");
    assert_eq!(history[0].signature_status, None);
    assert_eq!(history[1].message, "commit 2\n");
    assert_eq!(history[1].signature_status, None);
    assert_eq!(history[2].message, "commit 1\n");
    assert_eq!(history[2].signature_status, None);

    Ok(())
}

#[test]
fn test_format_error() {
    assert_eq!(
        format!("{}", Error::from(std::io::Error::from_raw_os_error(3))),
        "No such process (os error 3)"
    );

    assert_eq!(
        format!("{}", Error::from(gpgme::Error::from_errno(3))),
        "No such process (gpg error 32895)"
    );

    assert_eq!(
        format!("{}", Error::from(git2::Error::from_str("git error"))),
        "git error"
    );

    #[allow(invalid_from_utf8)]
    let utf8_error = String::from_utf8(vec![255]).err().unwrap();
    #[allow(invalid_from_utf8)]
    let str_utf8_error = str::from_utf8(&[255]).err().unwrap();

    assert_eq!(
        format!("{}", Error::from(utf8_error.clone())),
        "invalid utf-8 sequence of 1 bytes from index 0"
    );

    let path = Path::new("/test/haha/foo.txt");
    assert_eq!(
        format!("{}", Error::from(path.strip_prefix("test").err().unwrap())),
        "prefix not found"
    );

    assert_eq!(
        format!("{}", Error::from(glob::glob("****").err().unwrap())),
        "Pattern syntax error near position 2: wildcards are either regular `*` or recursive `**`"
    );

    assert_eq!(
        format!("{}", Error::from(utf8_error)),
        "invalid utf-8 sequence of 1 bytes from index 0"
    );
    assert_eq!(
        format!("{}", Error::from(Some(str_utf8_error))),
        "invalid utf-8 sequence of 1 bytes from index 0"
    );
    assert_eq!(
        format!("{}", Error::from(config::ConfigError::Frozen)),
        "configuration is frozen"
    );
    assert_eq!(
        format!(
            "{}",
            Error::from(toml::ser::to_string_pretty(&None::<String>).err().unwrap())
        ),
        "unsupported None value"
    );
    assert_eq!(
        format!("{}", Error::from("custom error message")),
        "custom error message"
    );
    assert_eq!(format!("{}", Error::NoneError), "NoneError");
}

#[test]
fn test_commit_unsigned() -> Result<()> {
    let td = tempdir()?;
    let repo = Repository::init(td.path())?;
    let mut config = repo.config()?;

    config.set_bool("commit.gpgsign", false)?;
    config.set_str("user.name", "default")?;
    config.set_str("user.email", "default@example.com")?;

    let mut index = repo.index()?;
    let path = td.path().join("password-to-add");
    let mut f = File::create(path)?;
    f.write_all("some data".as_bytes())?;
    index.add_path(Path::new("password-to-add"))?;
    index.write()?;

    let oid = index.write_tree()?;
    let tree = repo.find_tree(oid)?;

    let parents = vec![];

    let crypto = MockCrypto::new();
    let c_oid = commit(&repo, &repo.signature()?, "test", &tree, &parents, &crypto)?;

    assert!(!(*crypto.sign_called.borrow()));

    assert_eq!("test", repo.find_commit(c_oid)?.message().unwrap());

    Ok(())
}

#[test]
fn test_commit_signed() -> Result<()> {
    let td = tempdir()?;
    let repo = Repository::init(td.path())?;
    let mut config = repo.config()?;

    config.set_bool("commit.gpgsign", true)?;
    config.set_str("user.name", "default")?;
    config.set_str("user.email", "default@example.com")?;

    let mut index = repo.index()?;
    let path = td.path().join("password-to-add");
    let mut f = File::create(path)?;
    f.write_all("some data".as_bytes())?;
    index.add_path(Path::new("password-to-add"))?;
    index.write()?;

    let oid = index.write_tree()?;
    let tree = repo.find_tree(oid)?;

    let parents = vec![];

    let crypto = MockCrypto::new();
    let c_oid = commit(&repo, &repo.signature()?, "test", &tree, &parents, &crypto)?;

    assert!(*crypto.sign_called.borrow());

    assert_eq!("test", repo.find_commit(c_oid)?.message().unwrap());

    Ok(())
}

#[test]
fn test_move_and_commit_signed() -> Result<()> {
    let dir = UnpackedDir::new("test_move_and_commit_signed")?;

    let repo = Repository::init(dir.path())?;
    let mut config = repo.config()?;

    config.set_bool("commit.gpgsign", true)?;
    config.set_str("user.name", "default")?;
    config.set_str("user.email", "default@example.com")?;

    fs::rename(
        dir.path().join("first_pass.gpg"),
        dir.path().join("second_pass.gpg"),
    )?;

    let store = PasswordStore {
        name: "store_name".to_owned(),
        root: dir.dir(),
        valid_gpg_signing_keys: vec![],
        passwords: vec![],
        style_file: None,
        crypto: Box::new(MockCrypto::new()),
        user_home: None,
    };
    let c_oid = move_and_commit(
        &store,
        Path::new("first_pass.gpg"),
        Path::new("second_pass.gpg"),
        "unit test",
    )?;

    assert_eq!("unit test", repo.find_commit(c_oid)?.message().unwrap());

    Ok(())
}

#[test]
fn test_search() -> Result<()> {
    let p1 = PasswordEntry {
        name: "no/match/check".to_owned(),
        path: Default::default(),
        updated: None,
        committed_by: None,
        signature_status: None,
        is_in_git: RepositoryStatus::InRepo,
    };
    let p2 = PasswordEntry {
        name: "dir/test/middle".to_owned(),
        path: Default::default(),
        updated: None,
        committed_by: None,
        signature_status: None,
        is_in_git: RepositoryStatus::InRepo,
    };
    let p3 = PasswordEntry {
        name: " space test ".to_owned(),
        path: Default::default(),
        updated: None,
        committed_by: None,
        signature_status: None,
        is_in_git: RepositoryStatus::InRepo,
    };
    let store = PasswordStore {
        name: "store_name".to_owned(),
        root: env::temp_dir(),
        valid_gpg_signing_keys: vec![],
        passwords: vec![p1, p2, p3],
        style_file: None,
        crypto: Box::new(MockCrypto::new()),
        user_home: None,
    };
    let store = store;

    let result = search(&store, "test");

    assert_eq!(2, result.len());
    assert_eq!("dir/test/middle", result[0].name);
    assert_eq!(" space test ", result[1].name);

    Ok(())
}

#[test]
fn test_verify_git_signature() -> Result<()> {
    let dir = UnpackedDir::new("test_verify_git_signature")?;

    let repo = Repository::open(dir.path())?;
    let oid = repo.head()?.target().unwrap();

    let store = PasswordStore {
        name: "store_name".to_owned(),
        root: dir.dir(),
        valid_gpg_signing_keys: vec![Fingerprint::V4(<[u8; 20]>::from_hex(
            "7E068070D5EF794B00C8A9D91D108E6C07CBC406",
        )?)],
        passwords: [].to_vec(),
        style_file: None,
        crypto: Box::new(MockCrypto::new()),
        user_home: None,
    };

    let result = verify_git_signature(&repo, &oid, &store);

    assert_eq!(
        Error::Generic(
            "the commit wasn\'t signed by one of the keys specified in the environmental variable PASSWORD_STORE_SIGNING_KEY"
        ),
        result.err().unwrap()
    );

    Ok(())
}

#[test]
fn test_add_and_commit_internal() -> Result<()> {
    let dir = UnpackedDir::new("test_add_and_commit_internal")?;

    let repo = Repository::init(dir.path())?;
    let mut config = repo.config()?;

    config.set_bool("commit.gpgsign", true)?;
    config.set_str("user.name", "default")?;
    config.set_str("user.email", "default@example.com")?;

    let crypto = MockCrypto::new();

    let new_password = dir.path().join("new_password");
    File::create(new_password)?.write_all("swordfish".as_bytes())?;

    let c_oid = add_and_commit_internal(
        &repo,
        &[PathBuf::from("new_password")],
        "unit test",
        &crypto,
    )?;

    assert_eq!("unit test", repo.find_commit(c_oid)?.message().unwrap());

    Ok(())
}

#[test]
fn test_remove_and_commit() -> Result<()> {
    let dir = UnpackedDir::new("test_remove_and_commit")?;

    let store = PasswordStore {
        name: "store_name".to_owned(),
        root: dir.dir(),
        valid_gpg_signing_keys: vec![Fingerprint::V4(<[u8; 20]>::from_hex(
            "7E068070D5EF794B00C8A9D91D108E6C07CBC406",
        )?)],
        passwords: [].to_vec(),
        style_file: None,
        crypto: Box::new(MockCrypto::new()),
        user_home: None,
    };

    let repo = Repository::open(dir.path())?;
    let mut config = repo.config()?;

    config.set_bool("commit.gpgsign", true)?;
    config.set_str("user.name", "default")?;
    config.set_str("user.email", "default@example.com")?;

    let c_oid = remove_and_commit(&store, &[PathBuf::from("pass_to_be_deleted")], "unit test")?;

    assert_eq!("unit test", repo.find_commit(c_oid)?.message().unwrap());

    assert!(!dir.path().join("pass_to_be_deleted").is_file());

    Ok(())
}

#[test]
fn test_to_name() {
    assert_eq!("name", to_name(&PathBuf::from("name.gpg")));
    assert_eq!("dir/name", to_name(&PathBuf::from("dir/name.gpg")));
    assert_eq!(
        "dir/name without gpg on end",
        to_name(&PathBuf::from("dir/name without gpg on end"))
    );
}

#[test]
fn test_verify_gpg_id_files_missing_sig_file() -> Result<()> {
    let td = tempdir()?;

    let store = PasswordStore {
        name: "store_name".to_owned(),
        root: td.path().to_path_buf(),
        valid_gpg_signing_keys: vec![Fingerprint::V4(<[u8; 20]>::from_hex(
            "7E068070D5EF794B00C8A9D91D108E6C07CBC406",
        )?)],
        passwords: [].to_vec(),
        style_file: None,
        crypto: Box::new(MockCrypto::new()),
        user_home: None,
    };

    fs::write(
        td.path().join(".gpg-id"),
        "7E068070D5EF794B00C8A9D91D108E6C07CBC406",
    )?;

    let result = store.verify_gpg_id_files();

    assert!(result.is_err());

    assert_eq!(
        Error::Generic("problem reading .gpg-id.sig, and strict signature checking was asked for"),
        result.err().unwrap()
    );

    Ok(())
}

#[test]
fn test_verify_gpg_id_files() -> Result<()> {
    let td = tempdir()?;

    let store = PasswordStore {
        name: "store_name".to_owned(),
        root: td.path().to_path_buf(),
        valid_gpg_signing_keys: vec![Fingerprint::V4(<[u8; 20]>::from_hex(
            "7E068070D5EF794B00C8A9D91D108E6C07CBC406",
        )?)],
        passwords: [].to_vec(),
        style_file: None,
        crypto: Box::new(MockCrypto::new()),
        user_home: None,
    };

    fs::write(
        td.path().join(".gpg-id"),
        "7E068070D5EF794B00C8A9D91D108E6C07CBC406",
    )?;
    fs::write(
        td.path().join(".gpg-id.sig"),
        "here there should be gpg data",
    )?;

    let result = store.verify_gpg_id_files();

    assert!(result.is_err());

    assert_eq!(
        Error::Generic(
            "the .gpg-id file wasn't signed by one of the keys specified in the environmental variable PASSWORD_STORE_SIGNING_KEY"
        ),
        result.err().unwrap()
    );

    Ok(())
}

fn sign(to_sign: &str, tsk: &sequoia_openpgp::Cert) -> String {
    let p = sequoia_openpgp::policy::StandardPolicy::new();

    let keypair = tsk
        .keys()
        .unencrypted_secret()
        .with_policy(&p, None)
        .alive()
        .revoked(false)
        .for_signing()
        .next()
        .unwrap()
        .key()
        .clone()
        .into_keypair()
        .unwrap();

    let mut sink: Vec<u8> = vec![];

    // Start streaming an OpenPGP message.
    let message = Message::new(&mut sink);

    let message = Armorer::new(message)
        .kind(sequoia_openpgp::armor::Kind::Signature)
        .build()
        .unwrap();

    // We want to sign a literal data packet.
    let mut message = Signer::new(message, keypair)
        .unwrap()
        .detached()
        .build()
        .unwrap();

    // Sign the data.
    message.write_all(to_sign.as_bytes()).unwrap();

    // Finalize the OpenPGP message to make sure that all data is
    // written.
    message.finalize().unwrap();

    str::from_utf8(&sink).unwrap().to_owned()
}

#[test]
fn test_verify_gpg_id_files_untrusted_key_in_keyring() {
    let td = tempdir().unwrap();

    let (store_owner, _) = CertBuilder::new()
        .add_userid("store_owner@example.org")
        .add_signing_subkey()
        .generate()
        .unwrap();
    let sofp = store_owner.fingerprint().as_bytes().try_into().unwrap();
    let (unrelated_user, _) = CertBuilder::new()
        .add_userid("unrelated_user@example.org")
        .add_signing_subkey()
        .generate()
        .unwrap();

    let keys_dir = td
        .path()
        .join("local")
        .join("share")
        .join("ripasso")
        .join("keys");
    create_dir_all(&keys_dir).unwrap();
    let password_store_dir = td.path().join(".password_store");
    create_dir_all(&password_store_dir).unwrap();
    let mut file =
        File::create(keys_dir.join(hex::encode(store_owner.fingerprint().as_bytes()))).unwrap();
    store_owner.serialize(&mut file).unwrap();
    let mut file =
        File::create(keys_dir.join(hex::encode(unrelated_user.fingerprint().as_bytes()))).unwrap();
    unrelated_user.serialize(&mut file).unwrap();

    fs::write(password_store_dir.join(".gpg-id"), hex::encode_upper(sofp)).unwrap();
    fs::write(
        password_store_dir.join(".gpg-id.sig"),
        sign(&hex::encode_upper(sofp), &unrelated_user),
    )
    .unwrap();

    let store = PasswordStore {
        name: "store_name".to_owned(),
        root: password_store_dir.to_path_buf(),
        valid_gpg_signing_keys: vec![sofp],
        passwords: [].to_vec(),
        style_file: None,
        crypto: Box::new(Sequoia::new(&td.path().join("local"), sofp, td.path()).unwrap()),
        user_home: None,
    };

    let result = store.verify_gpg_id_files();

    assert!(result.is_err());

    assert_eq!(
        Error::GenericDyn("No valid signature".to_owned()),
        result.err().unwrap()
    );
}

#[test]
fn test_new_password_file() -> Result<()> {
    let td = tempdir()?;

    let mut store = PasswordStore {
        name: "store_name".to_owned(),
        root: td.path().to_path_buf(),
        valid_gpg_signing_keys: vec![],
        passwords: [].to_vec(),
        style_file: None,
        crypto: Box::new(MockCrypto::new()),
        user_home: None,
    };

    fs::write(
        td.path().join(".gpg-id"),
        "7E068070D5EF794B00C8A9D91D108E6C07CBC406",
    )?;

    assert_eq!(0, store.passwords.len());

    let result = store.new_password_file("test/file", "password")?;

    assert_eq!(1, store.passwords.len());
    assert_eq!("test/file", store.passwords[0].name);

    assert_eq!(RepositoryStatus::NoRepo, result.is_in_git);
    assert!(result.signature_status.is_none());
    assert!(result.committed_by.is_none());
    assert!(result.updated.is_none());
    assert_eq!("test/file", result.name);
    assert_eq!(td.path().join("test").join("file.gpg"), result.path);

    Ok(())
}

#[test]
fn test_new_password_file_in_git_repo() -> Result<()> {
    let td = tempdir()?;

    let mut store = PasswordStore {
        name: "store_name".to_owned(),
        root: td.path().to_path_buf(),
        valid_gpg_signing_keys: vec![],
        passwords: [].to_vec(),
        style_file: None,
        crypto: Box::new(MockCrypto::new().with_encrypt_string_return(vec![32, 32, 32, 32])),
        user_home: None,
    };

    fs::write(
        td.path().join(".gpg-id"),
        "7E068070D5EF794B00C8A9D91D108E6C07CBC406",
    )?;

    let repo = Repository::init(td.path())?;
    let mut config = repo.config()?;
    config.set_str("user.name", "default")?;
    config.set_str("user.email", "default@example.com")?;

    assert_eq!(0, store.passwords.len());

    let result = store.new_password_file("test/file", "password")?;

    assert_eq!(1, store.passwords.len());
    assert_eq!("test/file", store.passwords[0].name);

    assert_eq!(RepositoryStatus::InRepo, result.is_in_git);
    assert!(result.signature_status.is_none());
    assert!(result.committed_by.is_some());
    assert!(result.updated.is_some());
    assert_eq!("test/file", result.name);

    Ok(())
}

#[test]
fn test_new_password_file_encryption_failure() -> Result<()> {
    let td = tempdir()?;

    let mut store = PasswordStore {
        name: "store_name".to_owned(),
        root: td.path().to_path_buf(),
        valid_gpg_signing_keys: vec![],
        passwords: [].to_vec(),
        style_file: None,
        crypto: Box::new(MockCrypto::new().with_encrypt_error("unit test error")),
        user_home: None,
    };

    fs::write(
        td.path().join(".gpg-id"),
        "7E068070D5EF794B00C8A9D91D108E6C07CBC406",
    )?;

    let repo = Repository::init(td.path())?;
    let mut config = repo.config()?;
    config.set_str("user.name", "default")?;
    config.set_str("user.email", "default@example.com")?;

    assert_eq!(0, store.passwords.len());

    let err = store.new_password_file("test/file", "password");

    assert_eq!(0, store.passwords.len());

    assert!(err.is_err());

    assert!(!td.path().join("test").join("file.gpg").exists());

    Ok(())
}

#[test]
fn test_new_password_file_twice() -> Result<()> {
    let td = tempdir()?;

    let mut store = PasswordStore {
        name: "store_name".to_owned(),
        root: td.path().to_path_buf(),
        valid_gpg_signing_keys: vec![],
        passwords: [].to_vec(),
        style_file: None,
        crypto: Box::new(MockCrypto::new().with_encrypt_string_return(vec![32, 32, 32, 32])),
        user_home: None,
    };

    fs::write(
        td.path().join(".gpg-id"),
        "7E068070D5EF794B00C8A9D91D108E6C07CBC406",
    )?;

    let repo = Repository::init(td.path())?;
    let mut config = repo.config()?;
    config.set_str("user.name", "default")?;
    config.set_str("user.email", "default@example.com")?;

    assert_eq!(0, store.passwords.len());

    let result = store.new_password_file("test/file", "password")?;

    assert_eq!(1, store.passwords.len());
    assert_eq!("test/file", store.passwords[0].name);

    assert_eq!(RepositoryStatus::InRepo, result.is_in_git);
    assert!(result.signature_status.is_none());
    assert!(result.committed_by.is_some());
    assert!(result.updated.is_some());
    assert_eq!("test/file", result.name);

    let result = store.new_password_file("test/file", "password");

    assert_eq!(1, store.passwords.len());
    assert_eq!("test/file", store.passwords[0].name);

    assert!(result.is_err());
    assert!(td.path().join("test").join("file.gpg").exists());

    Ok(())
}

#[test]
fn test_new_password_file_outside_pass_dir() -> Result<()> {
    let td = tempdir()?;

    let mut store = PasswordStore {
        name: "store_name".to_owned(),
        root: td.path().to_path_buf(),
        valid_gpg_signing_keys: vec![],
        passwords: [].to_vec(),
        style_file: None,
        crypto: Box::new(MockCrypto::new()),
        user_home: None,
    };

    fs::write(
        td.path().join(".gpg-id"),
        "7E068070D5EF794B00C8A9D91D108E6C07CBC406",
    )?;

    assert_eq!(0, store.passwords.len());

    let result = store.new_password_file("../file", "password");

    assert_eq!(0, store.passwords.len());

    assert!(result.is_err());

    Ok(())
}

#[test]
fn test_new_password_file_different_sub_permissions() -> Result<()> {
    let td = tempdir()?;
    let user_home = tempdir()?;

    let (mut store, users) = setup_store(&td, user_home.path())?;

    fs::write(
        td.path().join(".gpg-id"),
        hex::encode(users[0].fingerprint().as_bytes())
            + "\n"
            + &hex::encode(users[1].fingerprint().as_bytes())
            + "\n",
    )?;

    fs::create_dir(td.path().join("dir"))?;
    fs::write(
        td.path().join("dir").join(".gpg-id"),
        hex::encode(users[1].fingerprint().as_bytes()),
    )?;

    assert_eq!(0, store.passwords.len());

    store.new_password_file("dir/file", "password")?;

    assert_eq!(1, store.passwords.len());

    let content = fs::read(td.path().join("dir").join("file.gpg"))?;
    assert_eq!(1, count_recipients(&content));

    Ok(())
}

#[test]
fn test_rename_file_different_sub_permissions() -> Result<()> {
    let td = tempdir()?;
    let user_home = tempdir()?;

    let (mut store, users) = setup_store(&td, user_home.path())?;

    fs::write(
        td.path().join(".gpg-id"),
        hex::encode(users[0].fingerprint().as_bytes())
            + "\n"
            + &hex::encode(users[1].fingerprint().as_bytes())
            + "\n",
    )?;

    fs::create_dir(td.path().join("dir"))?;
    fs::write(
        td.path().join("dir").join(".gpg-id"),
        hex::encode(users[0].fingerprint().as_bytes()),
    )?;

    assert_eq!(0, store.passwords.len());

    store.new_password_file("dir/file", "password")?;

    store.rename_file("dir/file", "file")?;

    assert_eq!(1, store.passwords.len());

    let content = fs::read(td.path().join("file.gpg"))?;
    assert_eq!(2, count_recipients(&content));

    Ok(())
}

#[test]
fn test_add_recipient_different_sub_permissions() -> Result<()> {
    let td = tempdir()?;
    let config_path = tempdir()?;
    let user_home = tempdir()?;

    let (mut store, users) = setup_store(&td, user_home.path())?;

    fs::write(
        td.path().join(".gpg-id"),
        hex::encode(users[0].fingerprint().as_bytes())
            + "\n"
            + &hex::encode(users[1].fingerprint().as_bytes())
            + "\n",
    )?;

    fs::create_dir(td.path().join("dir"))?;
    fs::write(
        td.path().join("dir").join(".gpg-id"),
        hex::encode(users[0].fingerprint().as_bytes()) + "\n",
    )?;

    assert_eq!(0, store.passwords.len());

    store.new_password_file("file", "password")?;
    store.new_password_file("dir/file", "password")?;

    store.add_recipient(
        &crate::test_helpers::recipient_from_cert(&users[2]),
        &PathBuf::from("./"),
        config_path.path(),
    )?;

    assert_eq!(2, store.passwords.len());

    let content = fs::read(td.path().join("file.gpg"))?;
    assert_eq!(3, count_recipients(&content));

    let content = fs::read(td.path().join("dir/file.gpg"))?;
    assert_eq!(1, count_recipients(&content));

    Ok(())
}

#[test]
fn test_add_recipient_to_sub_dir() -> Result<()> {
    let td = tempdir()?;
    let config_path = tempdir()?;
    let user_home = tempdir()?;

    let (mut store, users) = setup_store(&td, user_home.path())?;

    fs::write(
        td.path().join(".gpg-id"),
        hex::encode(users[0].fingerprint().as_bytes())
            + "\n"
            + &hex::encode(users[1].fingerprint().as_bytes())
            + "\n",
    )?;

    fs::create_dir(td.path().join("dir"))?;

    assert_eq!(0, store.passwords.len());

    store.new_password_file("file", "password")?;
    store.new_password_file("dir/file", "password")?;

    store.add_recipient(
        &crate::test_helpers::recipient_from_cert(&users[2]),
        &PathBuf::from("dir/"),
        config_path.path(),
    )?;

    assert_eq!(2, store.passwords.len());

    let content = fs::read(td.path().join("file.gpg"))?;
    assert_eq!(2, count_recipients(&content));

    let content = fs::read(td.path().join("dir/file.gpg"))?;
    assert_eq!(1, count_recipients(&content));

    Ok(())
}

#[test]
fn test_add_recipient_to_sub_dir_path_traversal() -> Result<()> {
    let td = tempdir()?;
    let config_path = tempdir()?;
    let user_home = tempdir()?;

    let (mut store, users) = setup_store(&td, user_home.path())?;

    let res = store.add_recipient(
        &crate::test_helpers::recipient_from_cert(&users[2]),
        &PathBuf::from("/tmp/"),
        config_path.path(),
    );

    assert!(res.is_err());
    assert_eq!(
        "Generic(\"path traversal not allowed\")",
        format!("{:?}", res.err().unwrap())
    );

    Ok(())
}

#[test]
fn test_add_recipient_to_sub_dir_unknown_path() -> Result<()> {
    let td = tempdir()?;
    let config_path = tempdir()?;
    let user_home = tempdir()?;

    let (mut store, users) = setup_store(&td, user_home.path())?;

    let res = store.add_recipient(
        &crate::test_helpers::recipient_from_cert(&users[2]),
        &PathBuf::from("path_that_doesnt_exist/"),
        config_path.path(),
    );

    assert!(res.is_err());
    assert_eq!(
        "Generic(\"path doesn't exist\")",
        format!("{:?}", res.err().unwrap())
    );

    Ok(())
}

#[test]
fn test_add_recipient_not_in_key_ring() -> Result<()> {
    let td = tempdir()?;
    let config_path = tempdir()?;
    let user_home = tempdir()?;

    let (mut store, users) = setup_store(&td, user_home.path())?;

    let external_user = generate_sequoia_cert_without_private_key("bob@example.com");
    let external_user_recipient = crate::test_helpers::recipient_from_cert(&external_user);

    fs::write(
        td.path().join(".gpg-id"),
        hex::encode(users[0].fingerprint().as_bytes()) + "\n",
    )?;

    assert_eq!(0, store.passwords.len());

    store.new_password_file("file", "password")?;
    let gpg_id_file_pre = fs::read_to_string(td.path().join(".gpg-id"))?;
    let res = store.add_recipient(
        &external_user_recipient,
        &PathBuf::from("./"),
        config_path.path(),
    );
    let gpg_id_file_post = fs::read_to_string(td.path().join(".gpg-id"))?;

    assert!(res.is_err());

    assert_eq!(gpg_id_file_pre, gpg_id_file_post);

    Ok(())
}

#[test]
fn test_remove_last_recipient_with_decryption_rights() -> Result<()> {
    let td = tempdir()?;
    let config_path = tempdir()?;
    let user_home = tempdir()?;

    let (mut store, users) = setup_store(&td, user_home.path())?;

    let user0_recipient = crate::test_helpers::recipient_from_cert(&users[0]);
    let user3_recipient = crate::test_helpers::recipient_from_cert(&users[3]);

    fs::write(
        td.path().join(".gpg-id"),
        hex::encode(users[0].fingerprint().as_bytes()) + "\n",
    )?;

    assert_eq!(0, store.passwords.len());

    store.new_password_file("file", "password")?;
    store.add_recipient(&user3_recipient, &PathBuf::from("./"), config_path.path())?;

    let gpg_id_file_pre = fs::read_to_string(td.path().join(".gpg-id"))?;
    let res = store.remove_recipient(&user0_recipient, &PathBuf::from("./"));
    let gpg_id_file_post = fs::read_to_string(td.path().join(".gpg-id"))?;

    assert!(res.is_ok());

    assert_ne!(gpg_id_file_pre, gpg_id_file_post);

    Ok(())
}

#[test]
fn test_remove_last_recipient_from_sub_folder() -> Result<()> {
    let td = tempdir()?;
    let user_home = tempdir()?;

    let (mut store, users) = setup_store(&td, user_home.path())?;

    let user0_recipient = crate::test_helpers::recipient_from_cert(&users[0]);

    fs::write(
        td.path().join(".gpg-id"),
        hex::encode(users[0].fingerprint().as_bytes()) + "\n",
    )?;

    fs::create_dir(td.path().join("dir"))?;

    fs::write(
        td.path().join("dir").join(".gpg-id"),
        hex::encode(users[0].fingerprint().as_bytes()) + "\n",
    )?;

    assert_eq!(0, store.passwords.len());

    store.new_password_file("file", "password")?;
    store.new_password_file("dir/file", "password")?;

    let gpg_id_file_pre = fs::read_to_string(td.path().join(".gpg-id"))?;
    let res = store.remove_recipient(&user0_recipient, &PathBuf::from("dir"));
    let gpg_id_file_post = fs::read_to_string(td.path().join(".gpg-id"))?;

    assert!(res.is_ok());
    assert!(!td.path().join("dir").join(".gpg-id").exists());

    assert_eq!(gpg_id_file_pre, gpg_id_file_post);

    Ok(())
}

#[test]
fn test_add_password_without_decryption_rights() -> Result<()> {
    let td = tempdir()?;
    let user_home = tempdir()?;

    let (mut store, users) = setup_store(&td, user_home.path())?;

    fs::write(
        td.path().join(".gpg-id"),
        hex::encode(users[3].fingerprint().as_bytes()) + "\n",
    )?;

    assert_eq!(0, store.passwords.len());

    store.new_password_file("file", "password")?;

    assert_eq!(1, store.passwords.len());

    Ok(())
}

#[test]
fn test_remove_recipient_root() -> Result<()> {
    let td = tempdir()?;
    let user_home = tempdir()?;

    let (mut store, users) = setup_store(&td, user_home.path())?;

    fs::write(
        td.path().join(".gpg-id"),
        hex::encode(users[0].fingerprint().as_bytes())
            + "\n"
            + &hex::encode(users[1].fingerprint().as_bytes())
            + "\n",
    )?;

    fs::create_dir(td.path().join("dir"))?;
    fs::write(
        td.path().join("dir").join(".gpg-id"),
        hex::encode(users[0].fingerprint().as_bytes()) + "\n",
    )?;

    assert_eq!(0, store.passwords.len());

    store.new_password_file("file", "password")?;
    store.new_password_file("dir/file", "password")?;

    store.remove_recipient(
        &crate::test_helpers::recipient_from_cert(&users[1]),
        &PathBuf::from("./"),
    )?;

    assert_eq!(2, store.passwords.len());

    let content = fs::read(td.path().join("file.gpg"))?;
    assert_eq!(1, count_recipients(&content));

    let content = fs::read(td.path().join("dir/file.gpg"))?;
    assert_eq!(1, count_recipients(&content));

    Ok(())
}

#[test]
fn test_recipients_file_for_dir() -> Result<()> {
    let td = tempdir()?;
    let user_home = tempdir()?;

    let (store, _) = setup_store(&td, user_home.path())?;

    File::create(td.path().join(".gpg-id"))?;

    assert_eq!(
        td.path().join(".gpg-id"),
        store.recipients_file_for_dir(&store.get_store_path())?
    );
    Ok(())
}

#[test]
fn test_recipient_files() -> Result<()> {
    let td = tempdir()?;
    let user_home = tempdir()?;

    let (store, users) = setup_store(&td, user_home.path())?;

    fs::write(
        td.path().join(".gpg-id"),
        hex::encode(users[0].fingerprint().as_bytes())
            + "\n"
            + &hex::encode(users[1].fingerprint().as_bytes())
            + "\n",
    )?;

    fs::create_dir(td.path().join("dir"))?;
    fs::write(
        td.path().join("dir").join(".gpg-id"),
        hex::encode(users[0].fingerprint().as_bytes()),
    )?;

    let result = store.recipients_files()?;
    assert_eq!(2, result.len());
    assert!(result.contains(&td.path().join(".gpg-id")));
    assert!(result.contains(&td.path().join("dir").join(".gpg-id")));
    Ok(())
}

#[test]
fn init_git_repo_success() -> Result<()> {
    let td = tempdir()?;

    assert!(!td.path().join(".git").exists());

    init_git_repo(td.path())?;

    assert!(td.path().join(".git").exists());

    Ok(())
}

#[test]
fn all_recipients_from_stores_plain() -> Result<()> {
    let td = tempdir()?;

    fs::write(
        td.path().join(".gpg-id"),
        "7E068070D5EF794B00C8A9D91D108E6C07CBC406",
    )?;

    let s1 = PasswordStore {
        name: "unit test store".to_owned(),
        root: td.path().to_path_buf(),
        valid_gpg_signing_keys: vec![],
        passwords: vec![],
        style_file: None,
        crypto: Box::new(MockCrypto::new()),
        user_home: None,
    };

    let result = all_recipients_from_stores(Arc::new(Mutex::new(vec![Arc::new(Mutex::new(s1))])))?;

    assert_eq!(1, result.len());
    assert_eq!("7E068070D5EF794B00C8A9D91D108E6C07CBC406", result[0].key_id);

    Ok(())
}
