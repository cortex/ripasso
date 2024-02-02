use std::{fs::File, io::Write};

use chrono::Local;
use ripasso::pass::{PasswordEntry, RepositoryStatus};
use tempfile::tempdir;

use super::*;

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

    let mut store = PasswordStore::new(
        "",
        &Some(td.path().to_path_buf()),
        &None,
        &None,
        &None,
        &CryptoImpl::GpgMe,
        &None,
    )
    .unwrap();
    store.passwords.push(PasswordEntry::new(
        &td.path().join(".password-store"),
        &PathBuf::from("file.gpg"),
        Ok(Local::now()),
        Ok(String::new()),
        Ok(SignatureStatus::Good),
        RepositoryStatus::NoRepo,
    ));
    let store: PasswordStoreType = Arc::new(Mutex::new(Arc::new(Mutex::new(store))));

    let mut entries = SelectView::<pass::PasswordEntry>::new();
    entries.add_all(
        store
            .lock()
            .unwrap()
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
    do_delete(&mut siv, store);

    siv.call_on_name("results", |l: &mut SelectView<pass::PasswordEntry>| {
        assert_eq!(0, l.len());
    });
}

#[test]
fn get_selected_password_entry_none() {
    let mut siv = cursive::default();

    let result = get_selected_password_entry(&mut siv);

    assert!(result.is_none());
}

#[test]
fn get_selected_password_entry_some() {
    let mut siv = cursive::default();

    let mut sv = SelectView::<pass::PasswordEntry>::new();

    sv.add_item(
        "Item 1",
        pass::PasswordEntry::new(
            &PathBuf::from("/tmp/"),
            &PathBuf::from("file.gpg"),
            Ok(Local::now()),
            Ok(String::new()),
            Ok(SignatureStatus::Good),
            RepositoryStatus::NoRepo,
        ),
    );

    siv.add_layer(sv.with_name("results"));

    let result = get_selected_password_entry(&mut siv);

    assert!(result.is_some());
    assert_eq!(String::from("file"), result.unwrap().name);
}

#[test]
fn do_delete_one_entry() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join(".password-store")).unwrap();
    let mut pass_file = File::create(dir.path().join(".password-store").join("file.gpg")).unwrap();
    pass_file.flush().unwrap();

    let mut store = PasswordStore::new(
        "test",
        &Some(dir.path().join(".password-store")),
        &None,
        &None,
        &None,
        &CryptoImpl::GpgMe,
        &None,
    )
    .unwrap();
    store.passwords.push(PasswordEntry::new(
        &dir.path().join(".password-store"),
        &PathBuf::from("file.gpg"),
        Ok(Local::now()),
        Ok(String::new()),
        Ok(SignatureStatus::Good),
        RepositoryStatus::NoRepo,
    ));

    let mut siv = cursive::default();

    let mut sv = SelectView::<pass::PasswordEntry>::new();

    for (i, item) in store.all_passwords().unwrap().into_iter().enumerate() {
        sv.add_item(format!("Item {}", i), item);
    }

    assert_eq!(1, sv.len());

    siv.add_layer(sv.with_name("results"));
    siv.add_layer(SelectView::<pass::PasswordEntry>::new().with_name("just to be popped"));

    let store: PasswordStoreType = Arc::new(Mutex::new(Arc::new(Mutex::new(store))));
    do_delete(&mut siv, store);

    let cbr = siv.call_on_name("results", |l: &mut SelectView<pass::PasswordEntry>| {
        assert_eq!(0, l.len());
    });

    assert_eq!(Some(()), cbr);
}

#[test]
fn render_recipient_label_ultimate() {
    let r = Recipient {
        name: "Alexander Kjäll <alexander.kjall@gmail.com>".to_owned(),
        comment: ripasso::pass::Comment {
            pre_comment: None,
            post_comment: None,
        },
        key_id: "1D108E6C07CBC406".to_owned(),
        fingerprint: Some(
            <[u8; 20]>::from_hex("7E068070D5EF794B00C8A9D91D108E6C07CBC406").unwrap(),
        ),
        key_ring_status: ripasso::pass::KeyRingStatus::InKeyRing,
        trust_level: OwnerTrustLevel::Ultimate,
        not_usable: false,
    };

    let result = render_recipient_label(&r, 20, 20);

    assert_eq!(String::from("  \u{fe0f} 1D108E6C07CBC406     Alexander Kjäll <alexander.kjall@gmail.com> Ultimate  Usable  "), result);
}

#[test]
fn substr_wide_char() {
    assert_eq!(String::from("Können"), substr("Können", 0, 6));
}

#[test]
fn substr_overlong() {
    assert_eq!(String::from("Kö"), substr("Kö", 0, 6));
}

#[test]
fn create_label_basic() {

    // TODO: Fix this test so that time zones don't mess with it.

    let p = pass::PasswordEntry::new(
        &PathBuf::from("/tmp/"),
        &PathBuf::from("file.gpg"),
        Ok(chrono::DateTime::<Local>::from(
            chrono::DateTime::parse_from_str("2022-08-14 00:00:00+0000", "%Y-%m-%d %H:%M:%S%z")
                .unwrap(),
        )),
        Ok(String::new()),
        Ok(SignatureStatus::Good),
        RepositoryStatus::NoRepo,
    );

    let result = create_label(&p, 40);

    assert_eq!(String::from("file 🔒  2022-08-14"), result);
}

#[test]
fn get_sub_dirs_empty() {
    let dir = tempfile::tempdir().unwrap();

    let dirs = get_sub_dirs(&dir.path().to_path_buf()).unwrap();

    assert_eq!(1, dirs.len());
    assert_eq!(PathBuf::from("./"), dirs[0]);
}

#[test]
fn get_sub_dirs_one_dir() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("one_dir")).unwrap();

    let dirs = get_sub_dirs(&dir.path().to_path_buf()).unwrap();

    assert_eq!(1, dirs.len());
    assert_eq!(PathBuf::from("./"), dirs[0]);
}

#[test]
fn get_sub_dirs_one_dir_with_pgpid() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("one_dir")).unwrap();
    std::fs::File::create(dir.path().join("one_dir").join(".gpg-id")).unwrap();

    let dirs = get_sub_dirs(&dir.path().to_path_buf()).unwrap();

    assert_eq!(2, dirs.len());
    assert_eq!(PathBuf::from("./"), dirs[0]);
    assert_eq!(PathBuf::from("one_dir"), dirs[1]);
}
