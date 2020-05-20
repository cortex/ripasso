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
