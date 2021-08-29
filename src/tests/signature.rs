use crate::signature::parse_signing_keys;
use crate::test_helpers::MockCrypto;

#[test]
fn test_parse_signing_keys_two_keys() {
    let crypto = MockCrypto::new();

    let file_content = "7E068070D5EF794B00C8A9D91D108E6C07CBC406,E6A7D758338EC2EF2A8A9F4EE7E3DB4B3217482F".to_owned();

    let result = parse_signing_keys(&Some(file_content), &crypto).unwrap();

    assert_eq!(2, result.len());
    assert_eq!(true, result.contains(&"7E068070D5EF794B00C8A9D91D108E6C07CBC406".to_owned()));
    assert_eq!(true, result.contains(&"E6A7D758338EC2EF2A8A9F4EE7E3DB4B3217482F".to_owned()));
}

#[test]
fn test_parse_signing_keys_two_keys_with_0x() {
    let crypto = MockCrypto::new();

    let file_content = "0x7E068070D5EF794B00C8A9D91D108E6C07CBC406,0xE6A7D758338EC2EF2A8A9F4EE7E3DB4B3217482F".to_owned();

    let result = parse_signing_keys(&Some(file_content), &crypto).unwrap();

    assert_eq!(2, result.len());
    assert_eq!(true, result.contains(&"0x7E068070D5EF794B00C8A9D91D108E6C07CBC406".to_owned()));
    assert_eq!(true, result.contains(&"0xE6A7D758338EC2EF2A8A9F4EE7E3DB4B3217482F".to_owned()));
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

    assert_eq!(result.is_err(), true);
}
