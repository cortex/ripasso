use crate::words::generate_password;

#[test]
fn do_not_generate_passwords_that_ends_in_space() {
    let pass = generate_password(3);

    assert!(!pass.ends_with(' '));
}

#[test]
fn generate_long_enough_passwords() {
    let pass = generate_password(3);

    assert!(pass.len() > 10);
}
