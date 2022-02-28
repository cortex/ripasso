use super::*;

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
