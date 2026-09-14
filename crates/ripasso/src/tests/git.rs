use std::{
    borrow::Cow,
    path::{Path, PathBuf},
};

use crate::{
    error::Result,
    git::{should_sign, to_nfc},
    test_helpers::UnpackedDir,
};

#[test]
fn to_nfc_leaves_already_composed_paths_alone() {
    assert!(matches!(to_nfc(Path::new("dir/test")), Cow::Borrowed(_)));
    assert!(matches!(
        to_nfc(Path::new("dir/test_åÅæÆäÄøØöÖ.gpg")),
        Cow::Borrowed(_)
    ));
}

#[test]
fn to_nfc_composes_decomposed_paths() {
    let decomposed = Path::new("test_a\u{30a}A\u{30a}æÆa\u{308}A\u{308}øØo\u{308}O\u{308}.gpg");

    assert_eq!(
        PathBuf::from("test_åÅæÆäÄøØöÖ.gpg"),
        to_nfc(decomposed).into_owned()
    );
}

#[test]
fn to_nfc_composes_every_component() {
    let decomposed = Path::new("a\u{308}/o\u{308}/c\u{308}.gpg");

    // "c" has no precomposed form with a diaeresis, so that one stays as it is
    assert_eq!(
        PathBuf::from("ä/ö/c\u{308}.gpg"),
        to_nfc(decomposed).into_owned()
    );
}

#[test]
fn test_should_sign_true() -> Result<()> {
    let dir = UnpackedDir::new("test_should_sign_true")?;

    let repo = git2::Repository::open(dir.path())?;

    let result = should_sign(&repo);

    assert!(result);

    Ok(())
}

#[test]
fn test_should_sign_false() -> Result<()> {
    let dir = UnpackedDir::new("test_should_sign_false")?;

    let repo = git2::Repository::open(dir.path())?;

    let result = should_sign(&repo);

    assert!(!result);

    Ok(())
}
