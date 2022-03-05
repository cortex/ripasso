use super::*;
use chrono::Local;
use ripasso::pass::{PasswordEntry, RepositoryStatus};
use tempfile::tempdir;

#[test]
fn copy_name_none() {
    let mut siv = cursive::default();

    let entries = SelectView::<pass::PasswordEntry>::new();

    siv.add_layer(entries.with_name("results"));

    copy_name(&mut siv);
}

#[test]
fn do_delete_normal() {
    let mut siv = cursive::default();

    let td = tempdir().unwrap();
    std::fs::create_dir(&td.path().join(".password-store")).unwrap();
    std::fs::write(
        &td.path().join(".password-store").join("file.gpg"),
        "pgp-data",
    )
    .unwrap();

    let mut store =
        PasswordStore::new("", &Some(td.path().to_path_buf()), &None, &None, &None).unwrap();
    store.passwords.push(PasswordEntry::new(
        &td.path().join(".password-store"),
        &PathBuf::from("file.gpg"),
        Ok(Local::now()),
        Ok("".to_owned()),
        Ok(SignatureStatus::Good),
        RepositoryStatus::NoRepo,
    ));
    let store: PasswordStoreType = Arc::new(Mutex::new(store));

    let mut entries = SelectView::<pass::PasswordEntry>::new();
    entries.add_all(
        store
            .lock()
            .unwrap()
            .passwords
            .clone()
            .into_iter()
            .map(|p| (format!("{:?}", p), p)),
    );
    entries.set_selection(0);

    siv.add_layer(entries.with_name("results"));

    siv.call_on_name("results", |l: &mut SelectView<pass::PasswordEntry>| {
        assert_eq!(1, l.len());
    });
    do_delete(&mut siv, &store);

    siv.call_on_name("results", |l: &mut SelectView<pass::PasswordEntry>| {
        assert_eq!(0, l.len());
    });
}

#[test]
fn is_checkbox_checked_false() {
    let mut siv = cursive::default();
    siv.add_layer(Checkbox::new().with_name("unit_test"));

    assert_eq!(false, is_checkbox_checked(&mut siv, "unit_test"));
}

#[test]
fn is_checkbox_checked_true() {
    let mut siv = cursive::default();
    let mut c_b = Checkbox::new();
    c_b.set_checked(true);
    siv.add_layer(c_b.with_name("unit_test"));

    assert_eq!(true, is_checkbox_checked(&mut siv, "unit_test"));
}
