use crate::crypto::slice_to_20_bytes;
use crate::crypto::{Crypto, CryptoImpl, Sequoia};
use crate::signature::Recipient;
use hex::FromHex;
use sequoia_openpgp::cert::CertBuilder;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::serialize::Serialize;
use sequoia_openpgp::Cert;
use std::collections::HashMap;
use std::sync::Arc;

#[test]
pub fn crypto_impl_from() {
    assert_eq!(CryptoImpl::GpgMe, CryptoImpl::try_from("gpg").unwrap());
    assert_eq!(
        CryptoImpl::Sequoia,
        CryptoImpl::try_from("sequoia").unwrap()
    );
}

#[test]
pub fn crypto_impl_from_error() {
    assert!(CryptoImpl::try_from("random").is_err());
}

#[test]
pub fn crypto_impl_display() {
    assert_eq!("gpg", format!("{}", CryptoImpl::GpgMe));
    assert_eq!("sequoia", format!("{}", CryptoImpl::Sequoia));
}

#[test]
pub fn slice_to_20_bytes_failure() {
    let input = [3; 16];

    let result = slice_to_20_bytes(&input);

    assert!(result.is_err());
}

#[test]
pub fn slice_to_20_bytes_success() {
    let input = [3; 20];

    let result = slice_to_20_bytes(&input).unwrap();

    assert_eq!(input, result);
}

#[test]
pub fn new_one_cert() {
    let dir = tempfile::tempdir().unwrap();

    let (cert, _) = CertBuilder::new()
        .add_userid("someone@example.org")
        .add_signing_subkey()
        .generate()
        .unwrap();

    let f = slice_to_20_bytes(cert.fingerprint().as_bytes()).unwrap();

    let p = dir.path().join("share").join("ripasso").join("keys");
    std::fs::create_dir_all(&p).unwrap();
    let file = p.join(hex::encode(f));
    let mut file = std::fs::File::create(file).expect("Unable to create file");

    cert.serialize(&mut file).unwrap();

    let sequoia = Sequoia::new(&dir.path(), f).unwrap();

    assert_eq!(1, sequoia.key_ring.len());
    assert_eq!(
        "someone@example.org",
        sequoia
            .key_ring
            .get(&f)
            .unwrap()
            .userids()
            .next()
            .unwrap()
            .userid()
            .email()
            .unwrap()
            .unwrap()
    );
}

fn cert() -> Arc<Cert> {
    Arc::new(
        Cert::from_bytes(
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=+GpQ
-----END PGP PUBLIC KEY BLOCK-----
",
        )
        .unwrap(),
    )
}

fn fingerprint() -> [u8; 20] {
    [
        0x7E, 0x06, 0x80, 0x70, 0xD5, 0xEF, 0x79, 0x4B, 0x00, 0xC8, 0xA9, 0xD9, 0x1D, 0x10, 0x8E,
        0x6C, 0x07, 0xCB, 0xC4, 0x06,
    ]
}

#[test]
pub fn verify_sign_sequoia_git_commit() {
    let mut c = Sequoia {
        user_key_id: fingerprint(),
        key_ring: HashMap::new(),
    };
    c.key_ring.insert(fingerprint(), cert());

    let data: Vec<u8> = vec![0x74, 0x65, 0x73, 0x74, 0x0a];
    let sig: Vec<u8> = vec![
        0x88, 0x75, 0x04, 0x00, 0x16, 0x0a, 0x00, 0x1d, 0x16, 0x21, 0x04, 0x7e, 0x06, 0x80, 0x70,
        0xd5, 0xef, 0x79, 0x4b, 0x00, 0xc8, 0xa9, 0xd9, 0x1d, 0x10, 0x8e, 0x6c, 0x07, 0xcb, 0xc4,
        0x06, 0x05, 0x02, 0x61, 0xac, 0xa5, 0x1f, 0x00, 0x0a, 0x09, 0x10, 0x1d, 0x10, 0x8e, 0x6c,
        0x07, 0xcb, 0xc4, 0x06, 0x0c, 0x03, 0x01, 0x00, 0xd3, 0xc7, 0x54, 0xd3, 0xed, 0xfc, 0x6b,
        0x42, 0x8a, 0xf5, 0x70, 0x8d, 0x83, 0xeb, 0xf3, 0x75, 0xea, 0x72, 0x07, 0x40, 0x71, 0x17,
        0xe6, 0xe2, 0xfb, 0xc9, 0xc5, 0x20, 0x24, 0xb5, 0x40, 0x65, 0x01, 0x00, 0x98, 0xb8, 0x6b,
        0xf1, 0xbb, 0x9b, 0xdd, 0xf6, 0x17, 0x09, 0x69, 0x73, 0xee, 0xce, 0xf2, 0x4c, 0xfe, 0xbb,
        0x99, 0xf3, 0xe1, 0x0c, 0x37, 0x53, 0xb9, 0xf6, 0x5e, 0x46, 0xdf, 0x57, 0x78, 0x06,
    ];

    let result = c.verify_sign(
        &data,
        &sig,
        &[<[u8; 20]>::from_hex("7E068070D5EF794B00C8A9D91D108E6C07CBC406").unwrap()],
    );

    assert!(result.is_ok());
}

#[test]
pub fn verify_sign_sequoia_git_commit_invalid_signing_key() {
    let mut c = Sequoia {
        user_key_id: fingerprint(),
        key_ring: HashMap::new(),
    };
    c.key_ring.insert(fingerprint(), cert());

    let data: Vec<u8> = vec![0x74, 0x65, 0x73, 0x74, 0x0a];
    let sig: Vec<u8> = vec![
        0x88, 0x75, 0x04, 0x00, 0x16, 0x0a, 0x00, 0x1d, 0x16, 0x21, 0x04, 0x7e, 0x06, 0x80, 0x70,
        0xd5, 0xef, 0x79, 0x4b, 0x00, 0xc8, 0xa9, 0xd9, 0x1d, 0x10, 0x8e, 0x6c, 0x07, 0xcb, 0xc4,
        0x06, 0x05, 0x02, 0x61, 0xac, 0xa5, 0x1f, 0x00, 0x0a, 0x09, 0x10, 0x1d, 0x10, 0x8e, 0x6c,
        0x07, 0xcb, 0xc4, 0x06, 0x0c, 0x03, 0x01, 0x00, 0xd3, 0xc7, 0x54, 0xd3, 0xed, 0xfc, 0x6b,
        0x42, 0x8a, 0xf5, 0x70, 0x8d, 0x83, 0xeb, 0xf3, 0x75, 0xea, 0x72, 0x07, 0x40, 0x71, 0x17,
        0xe6, 0xe2, 0xfb, 0xc9, 0xc5, 0x20, 0x24, 0xb5, 0x40, 0x65, 0x01, 0x00, 0x98, 0xb8, 0x6b,
        0xf1, 0xbb, 0x9b, 0xdd, 0xf6, 0x17, 0x09, 0x69, 0x73, 0xee, 0xce, 0xf2, 0x4c, 0xfe, 0xbb,
        0x99, 0xf3, 0xe1, 0x0c, 0x37, 0x53, 0xb9, 0xf6, 0x5e, 0x46, 0xdf, 0x57, 0x78, 0x06,
    ];

    let result = c.verify_sign(
        &data,
        &sig,
        &[<[u8; 20]>::from_hex("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap()],
    );

    assert!(result.is_err());
}

#[test]
pub fn sign_string_sequoia() {
    let (cert, _) = CertBuilder::new()
        .add_userid("someone@example.org")
        .add_signing_subkey()
        .generate()
        .unwrap();

    let f = slice_to_20_bytes(cert.fingerprint().as_bytes()).unwrap();

    let mut c = Sequoia {
        user_key_id: f,
        key_ring: HashMap::new(),
    };

    c.key_ring.insert(f, Arc::new(cert));

    let result = c.sign_string(
        "test",
        &[],
        &crate::crypto::FindSigningFingerprintStrategy::GPG,
    );

    assert!(result.is_ok());

    assert!(result.unwrap().contains("-----BEGIN PGP SIGNATURE-----"));
}

#[test]
pub fn sign_then_verify_sequoia_with_signing_keys() {
    let (cert, _) = CertBuilder::new()
        .add_userid("someone@example.org")
        .add_signing_subkey()
        .generate()
        .unwrap();

    let f = slice_to_20_bytes(cert.fingerprint().as_bytes()).unwrap();

    let mut c = Sequoia {
        user_key_id: f,
        key_ring: HashMap::new(),
    };

    c.key_ring.insert(f, Arc::new(cert));

    let sig = c
        .sign_string(
            "test",
            &[],
            &crate::crypto::FindSigningFingerprintStrategy::GPG,
        )
        .unwrap();

    let result = c.verify_sign("test".as_bytes(), sig.as_bytes(), &[f]);

    assert!(result.is_ok());
}

#[test]
pub fn sign_then_verify_sequoia_without_signing_keys() {
    let (cert, _) = CertBuilder::new()
        .add_userid("someone@example.org")
        .add_signing_subkey()
        .generate()
        .unwrap();

    let f = slice_to_20_bytes(cert.fingerprint().as_bytes()).unwrap();

    let mut c = Sequoia {
        user_key_id: f,
        key_ring: HashMap::new(),
    };

    c.key_ring.insert(f, Arc::new(cert));

    let sig = c
        .sign_string(
            "test",
            &[],
            &crate::crypto::FindSigningFingerprintStrategy::GPG,
        )
        .unwrap();

    let result = c.verify_sign("test".as_bytes(), sig.as_bytes(), &[]);

    assert!(result.is_ok());
}

#[test]
pub fn encrypt_then_decrypt_sequoia() {
    let (cert, _) = CertBuilder::new()
        .add_userid("someone@example.org")
        .add_transport_encryption_subkey()
        .generate()
        .unwrap();

    let f = slice_to_20_bytes(cert.fingerprint().as_bytes()).unwrap();

    let mut c = Sequoia {
        user_key_id: f,
        key_ring: HashMap::new(),
    };

    c.key_ring.insert(f, Arc::new(cert));

    let r = Recipient::from(&hex::encode(f), &[], None, &c).unwrap();

    let result = c.encrypt_string("test", &[r]).unwrap();

    let result = c.decrypt_string(&result).unwrap();

    assert_eq!("test", result);
}
