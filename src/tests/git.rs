use crate::{
    error::Result,
    git::{hashed_hostname_matches, should_sign},
    test_helpers::UnpackedDir,
};

#[test]
fn hashed_hostname_matches_github_com() {
    let result = hashed_hostname_matches(
        "github.com",
        "QI6BGIOtEYviGBfiW2nsZ+JxeAY=|PnXH1BrfyPNBQ1fcKZmCeA7feLc=",
    );

    assert!(result);
}

#[test]
fn test_should_sign_true() -> Result<()> {
    let dir = UnpackedDir::new("test_should_sign_true")?;

    let repo = git2::Repository::open(dir.dir()).unwrap();

    let result = should_sign(&repo);

    assert!(result);

    Ok(())
}

#[test]
fn test_should_sign_false() -> Result<()> {
    let dir = UnpackedDir::new("test_should_sign_false")?;

    let repo = git2::Repository::open(dir.dir()).unwrap();

    let result = should_sign(&repo);

    assert!(!result);

    Ok(())
}
