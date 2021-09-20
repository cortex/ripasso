use crate::pass::{KeyRingStatus, OwnerTrustLevel, Recipient};
use crate::signature::parse_signing_keys;
use crate::test_helpers::{
    append_file_name, recipient_alex, recipient_alex_old, MockCrypto, MockKey,
};
use hex::FromHex;

#[test]
fn test_parse_signing_keys_two_keys() {
    let crypto = MockCrypto::new()
        .with_get_key_result(
            "7E068070D5EF794B00C8A9D91D108E6C07CBC406".to_owned(),
            MockKey::new(),
        )
        .with_get_key_result(
            "E6A7D758338EC2EF2A8A9F4EE7E3DB4B3217482F".to_owned(),
            MockKey::new(),
        );

    let file_content =
        "7E068070D5EF794B00C8A9D91D108E6C07CBC406,E6A7D758338EC2EF2A8A9F4EE7E3DB4B3217482F"
            .to_owned();

    let result = parse_signing_keys(&Some(file_content), &crypto).unwrap();

    assert_eq!(2, result.len());
    assert_eq!(
        true,
        result.contains(&"7E068070D5EF794B00C8A9D91D108E6C07CBC406".to_owned())
    );
    assert_eq!(
        true,
        result.contains(&"E6A7D758338EC2EF2A8A9F4EE7E3DB4B3217482F".to_owned())
    );
}

#[test]
fn test_parse_signing_keys_two_keys_with_0x() {
    let crypto = MockCrypto::new()
        .with_get_key_result(
            "0x7E068070D5EF794B00C8A9D91D108E6C07CBC406".to_owned(),
            MockKey::new(),
        )
        .with_get_key_result(
            "0xE6A7D758338EC2EF2A8A9F4EE7E3DB4B3217482F".to_owned(),
            MockKey::new(),
        );

    let file_content =
        "0x7E068070D5EF794B00C8A9D91D108E6C07CBC406,0xE6A7D758338EC2EF2A8A9F4EE7E3DB4B3217482F"
            .to_owned();

    let result = parse_signing_keys(&Some(file_content), &crypto).unwrap();

    assert_eq!(2, result.len());
    assert_eq!(
        true,
        result.contains(&"0x7E068070D5EF794B00C8A9D91D108E6C07CBC406".to_owned())
    );
    assert_eq!(
        true,
        result.contains(&"0xE6A7D758338EC2EF2A8A9F4EE7E3DB4B3217482F".to_owned())
    );
}

#[test]
fn parse_signing_keys_key_error() {
    let crypto = MockCrypto::new().with_get_key_error("unit test error".to_owned());

    let file_content =
        "0x7E068070D5EF794B00C8A9D91D108E6C07CBC406,0xE6A7D758338EC2EF2A8A9F4EE7E3DB4B3217482F"
            .to_owned();

    let result = parse_signing_keys(&Some(file_content), &crypto);

    assert_eq!(true, result.is_err());
}

#[test]
fn parse_signing_keys_empty() {
    let crypto = MockCrypto::new();

    let result = parse_signing_keys(&None, &crypto).unwrap();

    assert_eq!(result.len(), 0);
}

#[test]
fn parse_signing_keys_short() {
    let crypto = MockCrypto::new();

    let result = parse_signing_keys(&Some("0x1D108E6C07CBC406".to_string()), &crypto);

    assert_eq!(true, result.is_err());
}

#[test]
fn recipient_from_key_error() {
    let crypto = MockCrypto::new().with_get_key_error("unit test error".to_owned());

    let result = Recipient::from("0x1D108E6C07CBC406", &crypto);

    assert_eq!(false, result.is_err());
    let result = result.unwrap();
    assert_eq!("key id not in keyring", result.name);
}

#[test]
fn all_recipients() {
    let crypto = MockCrypto::new().with_get_key_result(
        "0x1D108E6C07CBC406".to_owned(),
        MockKey::from_args(
            <[u8; 20]>::from_hex("7E068070D5EF794B00C8A9D91D108E6C07CBC406").unwrap(),
            vec!["Alexander Kjäll <alexander.kjall@gmail.com>".to_owned()],
        ),
    );

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join(".gpg-id");

    std::fs::File::create(&file).unwrap();
    std::fs::write(&file, "0x1D108E6C07CBC406").unwrap();

    let result = Recipient::all_recipients(&file, &crypto).unwrap();

    assert_eq!(1, result.len());
    assert_eq!(
        "Alexander Kjäll <alexander.kjall@gmail.com>",
        result[0].name
    );
    assert_eq!("0x1D108E6C07CBC406", result[0].key_id);
    assert_eq!(true, KeyRingStatus::InKeyRing == result[0].key_ring_status);
}

#[test]
fn all_recipients_error() {
    let crypto = MockCrypto::new().with_get_key_error("unit test error".to_owned());

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join(".gpg-id");

    std::fs::File::create(&file).unwrap();
    std::fs::write(&file, "0x1D108E6C07CBC406").unwrap();

    let result = Recipient::all_recipients(&file, &crypto).unwrap();

    assert_eq!(1, result.len());
    assert_eq!("key id not in keyring", result[0].name);
    assert_eq!("0x1D108E6C07CBC406", result[0].key_id);
    assert_eq!(
        true,
        KeyRingStatus::NotInKeyRing == result[0].key_ring_status
    );
}

#[test]
fn all_recipients_no_file_error() {
    let crypto = MockCrypto::new();

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join(".gpg-id");

    let result = Recipient::all_recipients(&file, &crypto);

    assert_eq!(true, result.is_err());
}

#[test]
fn write_recipients_file_empty() {
    let recipients = vec![];

    let dir = tempfile::tempdir().unwrap();
    let recipients_file = dir.path().join(".gpg-id");
    let signature_file = dir.path().join(".gpg-id.sig");

    let valid_gpg_signing_keys = vec![];

    let crypto = MockCrypto::new();

    assert_eq!(false, recipients_file.exists());
    assert_eq!(false, signature_file.exists());

    let result = Recipient::write_recipients_file(
        &recipients,
        &recipients_file,
        &valid_gpg_signing_keys,
        &crypto,
    );

    assert_eq!(false, result.is_err());
    assert_eq!(true, recipients_file.exists());
    assert_eq!(false, recipients_file.join(".sig").exists());

    let contents = std::fs::read_to_string(recipients_file).unwrap();
    assert_eq!("", contents);
    assert_eq!(false, signature_file.exists());
}

#[test]
fn write_recipients_file_one() {
    let recipients = vec![recipient_alex()];

    let dir = tempfile::tempdir().unwrap();
    let recipients_file = dir.path().join(".gpg-id");
    let signature_file = dir.path().join(".gpg-id.sig");

    let valid_gpg_signing_keys = vec![];

    let crypto = MockCrypto::new();

    assert_eq!(false, recipients_file.exists());
    assert_eq!(false, signature_file.exists());

    let result = Recipient::write_recipients_file(
        &recipients,
        &recipients_file,
        &valid_gpg_signing_keys,
        &crypto,
    );

    assert_eq!(false, result.is_err());
    assert_eq!(true, recipients_file.exists());

    let recipient_sig_filename = append_file_name(&recipients_file);

    assert_eq!(false, recipient_sig_filename.exists());

    let contents = std::fs::read_to_string(recipients_file).unwrap();
    assert_eq!("0x7E068070D5EF794B00C8A9D91D108E6C07CBC406\n", contents);
    assert_eq!(false, signature_file.exists());
}

#[test]
fn write_recipients_file_one_and_signed() {
    let recipients = vec![recipient_alex()];

    let dir = tempfile::tempdir().unwrap();
    let recipients_file = dir.path().join(".gpg-id");
    let signature_file = dir.path().join(".gpg-id.sig");

    let valid_gpg_signing_keys = vec!["7E068070D5EF794B00C8A9D91D108E6C07CBC406".to_owned()];

    let crypto = MockCrypto::new().with_sign_string_return("unit test sign string".to_owned());

    assert_eq!(false, recipients_file.exists());
    assert_eq!(false, signature_file.exists());

    let result = Recipient::write_recipients_file(
        &recipients,
        &recipients_file,
        &valid_gpg_signing_keys,
        &crypto,
    );

    assert_eq!(false, result.is_err());
    assert_eq!(true, recipients_file.exists());

    let recipient_sig_filename = append_file_name(&recipients_file);

    assert_eq!(true, recipient_sig_filename.exists());

    let contents = std::fs::read_to_string(recipients_file).unwrap();
    assert_eq!("0x7E068070D5EF794B00C8A9D91D108E6C07CBC406\n", contents);

    assert_eq!(true, signature_file.exists());
    let contents = std::fs::read_to_string(&signature_file).unwrap();
    assert_eq!("unit test sign string", contents);
}

#[test]
fn remove_recipient_from_file_last() {
    let r = recipient_alex();
    let recipients = vec![r.clone()];

    let dir = tempfile::tempdir().unwrap();
    let recipients_file = dir.path().join(".gpg-id");
    let signature_file = dir.path().join(".gpg-id.sig");

    let valid_gpg_signing_keys = vec![];

    let crypto = MockCrypto::new();

    assert_eq!(false, recipients_file.exists());
    assert_eq!(false, signature_file.exists());

    let result = Recipient::write_recipients_file(
        &recipients,
        &recipients_file,
        &valid_gpg_signing_keys,
        &crypto,
    );
    assert_eq!(false, result.is_err());
    let contents = std::fs::read_to_string(&recipients_file).unwrap();
    assert_eq!("0x7E068070D5EF794B00C8A9D91D108E6C07CBC406\n", contents);

    let result = Recipient::remove_recipient_from_file(
        &r,
        &recipients_file,
        &valid_gpg_signing_keys,
        &crypto,
    );
    assert_eq!(false, result.is_err());

    let contents = std::fs::read_to_string(&recipients_file).unwrap();
    assert_eq!("0x7E068070D5EF794B00C8A9D91D108E6C07CBC406\n", contents);
    assert_eq!(false, signature_file.exists());
}

#[test]
fn remove_recipient_from_file_two() {
    let r = recipient_alex();
    let r2 = recipient_alex_old();
    let recipients = vec![r.clone(), r2.clone()];

    let dir = tempfile::tempdir().unwrap();
    let recipients_file = dir.path().join(".gpg-id");
    let signature_file = dir.path().join(".gpg-id.sig");

    let valid_gpg_signing_keys = vec![];

    let crypto = MockCrypto::new()
        .with_get_key_result(
            r.key_id.clone(),
            MockKey::from_args(r.fingerprint.unwrap(), vec![r.name.clone()]),
        )
        .with_get_key_result(
            r2.key_id.clone(),
            MockKey::from_args(r2.fingerprint.unwrap(), vec![r2.name.clone()]),
        );

    assert_eq!(false, recipients_file.exists());
    assert_eq!(false, signature_file.exists());

    let result = Recipient::write_recipients_file(
        &recipients,
        &recipients_file,
        &valid_gpg_signing_keys,
        &crypto,
    );
    assert_eq!(false, result.is_err());
    let contents = std::fs::read_to_string(&recipients_file).unwrap();
    assert_eq!(
        "0x7E068070D5EF794B00C8A9D91D108E6C07CBC406\n0xDB07DAC5B3882EAB659E1D2FDF0C3D316B7312D5\n",
        contents
    );

    let result = Recipient::remove_recipient_from_file(
        &r,
        &recipients_file,
        &valid_gpg_signing_keys,
        &crypto,
    );
    assert_eq!(false, result.is_err());

    let contents = std::fs::read_to_string(&recipients_file).unwrap();
    assert_eq!(86, contents.len());
    assert_eq!(
        true,
        contents.contains("0xDB07DAC5B3882EAB659E1D2FDF0C3D316B7312D5")
    );
    assert_eq!(
        true,
        contents.contains("0x7E068070D5EF794B00C8A9D91D108E6C07CBC406")
    );
    assert_eq!(false, signature_file.exists());
}

#[test]
fn remove_recipient_from_file_same_key_id_different_fingerprint() {
    let r = Recipient {
        name: "Alexander Kjäll <alexander.kjall@gmail.com>".to_owned(),
        key_id: "DF0C3D316B7312D5".to_owned(),
        fingerprint: Some(
            <[u8; 20]>::from_hex("DB07DAC5B3882EAB659E1D2FDF0C3D316B7312D5").unwrap(),
        ),
        key_ring_status: KeyRingStatus::InKeyRing,
        trust_level: OwnerTrustLevel::Ultimate,
        not_usable: false,
    };
    let r2 = Recipient {
        name: "Alexander Kjäll <alexander.kjall@gmail.com>".to_owned(),
        key_id: "DF0C3D316B7312D5".to_owned(),
        fingerprint: Some(
            <[u8; 20]>::from_hex("88283D2EF664DD5F6AEBB51CDF0C3D316B7312D5").unwrap(),
        ),
        key_ring_status: KeyRingStatus::InKeyRing,
        trust_level: OwnerTrustLevel::Ultimate,
        not_usable: false,
    };

    let recipients = vec![r.clone(), r2.clone()];

    let dir = tempfile::tempdir().unwrap();
    let recipients_file = dir.path().join(".gpg-id");
    let signature_file = dir.path().join(".gpg-id.sig");

    let valid_gpg_signing_keys = vec![];

    let crypto = MockCrypto::new()
        .with_get_key_result(
            "0xDB07DAC5B3882EAB659E1D2FDF0C3D316B7312D5".to_owned(),
            MockKey::from_args(
                <[u8; 20]>::from_hex("DB07DAC5B3882EAB659E1D2FDF0C3D316B7312D5").unwrap(),
                vec!["Alexander Kjäll <alexander.kjall@gmail.com>".to_owned()],
            ),
        )
        .with_get_key_result(
            "0x88283D2EF664DD5F6AEBB51CDF0C3D316B7312D5".to_owned(),
            MockKey::from_args(
                <[u8; 20]>::from_hex("88283D2EF664DD5F6AEBB51CDF0C3D316B7312D5").unwrap(),
                vec!["Alexander Kjäll <alexander.kjall@gmail.com>".to_owned()],
            ),
        );

    assert_eq!(false, recipients_file.exists());
    assert_eq!(false, signature_file.exists());

    let result = Recipient::write_recipients_file(
        &recipients,
        &recipients_file,
        &valid_gpg_signing_keys,
        &crypto,
    );
    assert_eq!(false, result.is_err());
    let contents = std::fs::read_to_string(&recipients_file).unwrap();
    assert_eq!(
        "0x88283D2EF664DD5F6AEBB51CDF0C3D316B7312D5\n0xDB07DAC5B3882EAB659E1D2FDF0C3D316B7312D5\n",
        contents
    );

    let result = Recipient::remove_recipient_from_file(
        &r,
        &recipients_file,
        &valid_gpg_signing_keys,
        &crypto,
    );
    assert_eq!(false, result.is_err());

    let contents = std::fs::read_to_string(&recipients_file).unwrap();
    assert_eq!(43, contents.len());
    assert_eq!(
        true,
        contents.contains("0x88283D2EF664DD5F6AEBB51CDF0C3D316B7312D5")
    );
    assert_eq!(false, signature_file.exists());
}

#[test]
fn add_recipient_from_file_one_plus_one() {
    let r = recipient_alex();
    let r2 = recipient_alex_old();
    let recipients = vec![r.clone()];

    let dir = tempfile::tempdir().unwrap();
    let recipients_file = dir.path().join(".gpg-id");
    let signature_file = dir.path().join(".gpg-id.sig");

    let valid_gpg_signing_keys = vec![];

    let crypto = MockCrypto::new()
        .with_get_key_result(
            r.key_id.clone(),
            MockKey::from_args(r.fingerprint.unwrap(), vec![r.name.clone()]),
        )
        .with_get_key_result(
            r2.key_id.clone(),
            MockKey::from_args(r2.fingerprint.unwrap(), vec![r2.name.clone()]),
        );

    assert_eq!(false, recipients_file.exists());
    assert_eq!(false, signature_file.exists());

    let result = Recipient::write_recipients_file(
        &recipients,
        &recipients_file,
        &valid_gpg_signing_keys,
        &crypto,
    );
    assert_eq!(false, result.is_err());

    let result =
        Recipient::add_recipient_to_file(&r2, &recipients_file, &valid_gpg_signing_keys, &crypto);
    assert_eq!(false, result.is_err());

    let contents = std::fs::read_to_string(&recipients_file).unwrap();
    assert_eq!(
        "0x7E068070D5EF794B00C8A9D91D108E6C07CBC406\n0xDB07DAC5B3882EAB659E1D2FDF0C3D316B7312D5\n",
        contents
    );

    let result = Recipient::remove_recipient_from_file(
        &r,
        &recipients_file,
        &valid_gpg_signing_keys,
        &crypto,
    );
    assert_eq!(false, result.is_err());

    let contents = std::fs::read_to_string(&recipients_file).unwrap();
    assert_eq!(86, contents.len());
    assert_eq!(
        true,
        contents.contains("0xDB07DAC5B3882EAB659E1D2FDF0C3D316B7312D5")
    );
    assert_eq!(
        true,
        contents.contains("0x7E068070D5EF794B00C8A9D91D108E6C07CBC406")
    );
    assert_eq!(false, signature_file.exists());
}

#[test]
fn recipient_both_none() {
    let r1 = Recipient {
        name: "Alexander Kjäll <alexander.kjall@gmail.com>".to_owned(),
        key_id: "DF0C3D316B7312D5".to_owned(),
        fingerprint: None,
        key_ring_status: KeyRingStatus::InKeyRing,
        trust_level: OwnerTrustLevel::Ultimate,
        not_usable: false,
    };
    let r2 = Recipient {
        name: "Alexander Kjäll <alexander.kjall@gmail.com>".to_owned(),
        key_id: "DF0C3D316B7312D5".to_owned(),
        fingerprint: None,
        key_ring_status: KeyRingStatus::InKeyRing,
        trust_level: OwnerTrustLevel::Ultimate,
        not_usable: false,
    };

    assert_eq!(false, r1 == r2);
    assert_eq!(false, r2 == r1);
    assert_eq!(true, r1 != r2);
    assert_eq!(true, r2 != r1);
}

#[test]
fn recipient_one_none() {
    let r1 = Recipient {
        name: "Alexander Kjäll <alexander.kjall@gmail.com>".to_owned(),
        key_id: "DF0C3D316B7312D5".to_owned(),
        fingerprint: Some(
            <[u8; 20]>::from_hex("DB07DAC5B3882EAB659E1D2FDF0C3D316B7312D5").unwrap(),
        ),
        key_ring_status: KeyRingStatus::InKeyRing,
        trust_level: OwnerTrustLevel::Ultimate,
        not_usable: false,
    };
    let r2 = Recipient {
        name: "Alexander Kjäll <alexander.kjall@gmail.com>".to_owned(),
        key_id: "DF0C3D316B7312D5".to_owned(),
        fingerprint: None,
        key_ring_status: KeyRingStatus::InKeyRing,
        trust_level: OwnerTrustLevel::Ultimate,
        not_usable: false,
    };

    assert_eq!(false, r1 == r2);
    assert_eq!(false, r2 == r1);
    assert_eq!(true, r1 != r2);
    assert_eq!(true, r2 != r1);
}

#[test]
fn recipient_same_fingerprint_different_key_id() {
    let r1 = Recipient {
        name: "Alexander Kjäll <alexander.kjall@gmail.com>".to_owned(),
        key_id: "DF0C3D316B7312D5".to_owned(),
        fingerprint: Some(
            <[u8; 20]>::from_hex("DB07DAC5B3882EAB659E1D2FDF0C3D316B7312D5").unwrap(),
        ),
        key_ring_status: KeyRingStatus::InKeyRing,
        trust_level: OwnerTrustLevel::Ultimate,
        not_usable: false,
    };
    let r2 = Recipient {
        name: "Alexander Kjäll <alexander.kjall@gmail.com>".to_owned(),
        key_id: "DB07DAC5B3882EAB659E1D2FDF0C3D316B7312D5".to_owned(),
        fingerprint: Some(
            <[u8; 20]>::from_hex("DB07DAC5B3882EAB659E1D2FDF0C3D316B7312D5").unwrap(),
        ),
        key_ring_status: KeyRingStatus::InKeyRing,
        trust_level: OwnerTrustLevel::Ultimate,
        not_usable: false,
    };

    assert_eq!(true, r1 == r2);
    assert_eq!(true, r2 == r1);
    assert_eq!(false, r1 != r2);
    assert_eq!(false, r2 != r1);
}
