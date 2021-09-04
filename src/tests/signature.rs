use crate::pass::Recipient;
use crate::signature::parse_signing_keys;
use crate::test_helpers::MockCrypto;

#[test]
fn test_parse_signing_keys_two_keys() {
    let crypto = MockCrypto::new();

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
    let crypto = MockCrypto::new();

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
    let crypto = MockCrypto::new();

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
    assert_eq!("7E068070D5EF794B00C8A9D91D108E6C07CBC406", result[0].key_id);
}
