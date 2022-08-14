use cursive::view::Nameable;
use cursive::views::{Checkbox, EditView, LinearLayout, RadioButton, RadioGroup};

use ripasso::crypto::CryptoImpl;

use std::rc::Rc;

use crate::helpers::{get_value_from_input, is_checkbox_checked, is_radio_button_selected};

#[test]
fn test_get_value_from_input() {
    let mut siv = cursive::default();

    let ev = EditView::new()
        .content("unit test content")
        .with_name("input");

    siv.add_layer(ev);

    assert_eq!(
        Some(Rc::new(String::from("unit test content"))),
        get_value_from_input(&mut siv, "input")
    );
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

#[test]
fn is_radio_button_selected_false() {
    let mut siv = cursive::default();

    let mut rg = RadioGroup::new();
    let button1 = rg.button(1, "b1").with_name("button1_name");
    let button2 = rg.button(2, "b2").with_name("button2_name");

    let mut ll = LinearLayout::horizontal();
    ll.add_child(button1);
    ll.add_child(button2);

    siv.add_layer(ll);

    assert_eq!(false, is_radio_button_selected(&mut siv, "button1_name"));
}

#[test]
fn is_radio_button_selected_true() {
    let mut siv = cursive::default();

    let mut rg = RadioGroup::new();
    let button1 = rg.button(CryptoImpl::GpgMe, "b1").with_name("button1_name");
    let button2 = rg
        .button(CryptoImpl::Sequoia, "b2")
        .with_name("button2_name");

    let mut ll = LinearLayout::horizontal();
    ll.add_child(button1);
    ll.add_child(button2);

    siv.add_layer(ll);

    siv.call_on_name("button2_name", |e: &mut RadioButton<CryptoImpl>| {
        e.select();
    });

    assert_eq!(true, is_radio_button_selected(&mut siv, "button2_name"));
}
