use std::sync::Arc;

use cursive::{
    view::Nameable,
    views::{Checkbox, EditView, LinearLayout, RadioButton, RadioGroup},
};
use hex::FromHex;
use ripasso::{
    crypto::{CryptoImpl, Fingerprint},
    pass::{Comment, KeyRingStatus, OwnerTrustLevel, Recipient},
};

use crate::helpers::{
    get_value_from_input, is_checkbox_checked, is_radio_button_selected, recipients_widths,
};

#[test]
fn test_get_value_from_input() {
    let mut siv = cursive::default();

    let ev = EditView::new()
        .content("unit test content")
        .with_name("input");

    siv.add_layer(ev);

    assert_eq!(
        Some(Arc::new(String::from("unit test content"))),
        get_value_from_input(&mut siv, "input")
    );
}

#[test]
fn is_checkbox_checked_false() {
    let mut siv = cursive::default();
    siv.add_layer(Checkbox::new().with_name("unit_test"));

    assert!(!is_checkbox_checked(&mut siv, "unit_test"));
}

#[test]
fn is_checkbox_checked_true() {
    let mut siv = cursive::default();
    let mut c_b = Checkbox::new();
    c_b.set_checked(true);
    siv.add_layer(c_b.with_name("unit_test"));

    assert!(is_checkbox_checked(&mut siv, "unit_test"));
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

    assert!(!is_radio_button_selected(&mut siv, "button1_name"));
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

    assert!(is_radio_button_selected(&mut siv, "button2_name"));
}

#[test]
fn recipients_widths_empty() {
    let (max_width_key, max_width_name) = recipients_widths(&[]);
    assert_eq!(0, max_width_key);
    assert_eq!(0, max_width_name);
}

pub fn recipient_alex() -> Recipient {
    Recipient {
        name: "Alexander Kjäll <alexander.kjall@gmail.com>".to_owned(),
        comment: Comment {
            pre_comment: None,
            post_comment: None,
        },
        key_id: "1D108E6C07CBC406".to_owned(),
        fingerprint: Some(Fingerprint::V4(
            <[u8; 20]>::from_hex("7E068070D5EF794B00C8A9D91D108E6C07CBC406").unwrap(),
        )),
        key_ring_status: KeyRingStatus::InKeyRing,
        trust_level: OwnerTrustLevel::Ultimate,
        not_usable: false,
    }
}

#[test]
fn recipients_widths_basic() {
    let (max_width_key, max_width_name) = recipients_widths(&[recipient_alex()]);
    assert_eq!(16, max_width_key);
    assert_eq!(44, max_width_name);
}
