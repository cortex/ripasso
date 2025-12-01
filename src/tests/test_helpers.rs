use std::{
    cell::RefCell,
    collections::HashMap,
    fs::File,
    path::{Path, PathBuf},
};

use flate2::read::GzDecoder;
use hex::FromHex;
use sequoia_openpgp::crypto::SessionKey;
use sequoia_openpgp::packet::UserID;
use sequoia_openpgp::types::SymmetricAlgorithm;
use sequoia_openpgp::{
    Cert, KeyHandle, KeyID,
    cert::CertBuilder,
    parse::{
        Parse,
        stream::{DecryptionHelper, DecryptorBuilder, MessageStructure, VerificationHelper},
    },
    policy::StandardPolicy,
};
use tar::Archive;

use crate::{
    crypto::{Crypto, CryptoImpl, FindSigningFingerprintStrategy, Key, VerificationError},
    error::{Error, Result},
    pass::{KeyRingStatus, OwnerTrustLevel, SignatureStatus},
    signature::{Comment, Recipient},
};

pub struct UnpackedDir {
    dir: PathBuf,
}

impl Drop for UnpackedDir {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.dir).unwrap();
    }
}

impl UnpackedDir {
    pub fn new(name: &str) -> Result<UnpackedDir> {
        let base_path: PathBuf = get_testres_path();

        let packed_file = base_path.join(name.to_owned() + ".tar.gz");

        let tar_gz = File::open(packed_file)?;
        let tar = GzDecoder::new(tar_gz);
        let mut archive = Archive::new(tar);
        archive.unpack(base_path.clone())?;

        Ok(UnpackedDir {
            dir: base_path.join(name),
        })
    }

    pub fn path(&self) -> &Path {
        self.dir.as_path()
    }

    pub fn dir(&self) -> PathBuf {
        self.dir.clone()
    }
}

fn get_testres_path() -> PathBuf {
    let mut base_path: PathBuf = std::env::current_exe().unwrap();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.push("testres");

    base_path
}

#[derive(Clone)]
pub struct MockKey {
    fingerprint: [u8; 20],
    user_id_names: Vec<String>,
}

impl Key for MockKey {
    fn user_id_names(&self) -> Vec<String> {
        self.user_id_names.clone()
    }

    fn fingerprint(&self) -> Result<[u8; 20]> {
        Ok(self.fingerprint)
    }

    fn is_not_usable(&self) -> bool {
        false
    }
}

impl Default for MockKey {
    fn default() -> Self {
        Self::new()
    }
}

impl MockKey {
    pub fn new() -> MockKey {
        MockKey {
            fingerprint: <[u8; 20]>::from_hex("7E068070D5EF794B00C8A9D91D108E6C07CBC406").unwrap(),
            user_id_names: vec!["Alexander Kjäll <alexander.kjall@gmail.com>".to_owned()],
        }
    }

    pub fn from_args(fingerprint: [u8; 20], user_id_names: Vec<String>) -> MockKey {
        MockKey {
            user_id_names,
            fingerprint,
        }
    }
}

#[derive(Clone)]
pub struct MockCrypto {
    pub decrypt_called: RefCell<bool>,
    pub encrypt_called: RefCell<bool>,
    pub sign_called: RefCell<bool>,
    pub verify_called: RefCell<bool>,
    encrypt_string_return: Vec<u8>,
    decrypt_string_return: Option<String>,
    sign_string_return: Option<String>,
    encrypt_string_error: Option<String>,
    get_key_string_error: Option<String>,
    get_key_answers: HashMap<String, MockKey>,
}

impl Default for MockCrypto {
    fn default() -> Self {
        Self::new()
    }
}

impl MockCrypto {
    pub fn new() -> MockCrypto {
        MockCrypto {
            decrypt_called: RefCell::new(false),
            encrypt_called: RefCell::new(false),
            sign_called: RefCell::new(false),
            verify_called: RefCell::new(false),
            encrypt_string_return: vec![],
            decrypt_string_return: None,
            sign_string_return: None,
            encrypt_string_error: None,
            get_key_string_error: None,
            get_key_answers: HashMap::new(),
        }
    }

    pub fn with_encrypt_string_return(mut self, data: Vec<u8>) -> MockCrypto {
        self.encrypt_string_return = data;

        self
    }

    pub fn with_decrypt_string_return(mut self, data: String) -> MockCrypto {
        self.decrypt_string_return = Some(data);

        self
    }

    pub fn with_encrypt_error(mut self, err_str: String) -> MockCrypto {
        self.encrypt_string_error = Some(err_str);

        self
    }

    pub fn with_get_key_error(mut self, err_str: String) -> MockCrypto {
        self.get_key_string_error = Some(err_str);

        self
    }

    pub fn with_get_key_result(mut self, key_id: String, key: MockKey) -> MockCrypto {
        self.get_key_answers.insert(key_id, key);

        self
    }

    pub fn with_sign_string_return(mut self, sign_str: String) -> MockCrypto {
        self.sign_string_return = Some(sign_str);

        self
    }
}

impl Crypto for MockCrypto {
    fn decrypt_string(&self, _: &[u8]) -> Result<String> {
        self.decrypt_called.replace(true);

        match &self.decrypt_string_return {
            Some(s) => Ok(s.clone()),
            None => Ok(String::new()),
        }
    }

    fn encrypt_string(&self, _: &str, _: &[Recipient]) -> Result<Vec<u8>> {
        self.encrypt_called.replace(true);
        if self.encrypt_string_error.is_some() {
            Err(Error::GenericDyn(
                self.encrypt_string_error.clone().unwrap(),
            ))
        } else {
            Ok(self.encrypt_string_return.clone())
        }
    }

    fn sign_string(
        &self,
        _: &str,
        _: &[[u8; 20]],
        _: &FindSigningFingerprintStrategy,
    ) -> Result<String> {
        self.sign_called.replace(true);
        Ok(match self.sign_string_return.as_ref() {
            Some(s) => s.to_owned(),
            None => String::new(),
        })
    }

    fn verify_sign(
        &self,
        _: &[u8],
        _: &[u8],
        _: &[[u8; 20]],
    ) -> std::result::Result<SignatureStatus, VerificationError> {
        self.verify_called.replace(true);
        Err(VerificationError::SignatureFromWrongRecipient)
    }

    fn is_key_in_keyring(&self, _recipient: &Recipient) -> Result<bool> {
        Ok(true)
    }

    fn pull_keys(&mut self, _recipients: &[&Recipient], _config_path: &Path) -> Result<String> {
        Ok("dummy implementation".to_owned())
    }

    fn import_key(&mut self, _key: &str, _config_path: &Path) -> Result<String> {
        Ok("dummy implementation".to_owned())
    }

    fn get_key(&self, key_id: &str) -> Result<Box<dyn Key>> {
        if self.get_key_string_error.is_some() {
            Err(Error::GenericDyn(
                self.get_key_string_error.clone().unwrap(),
            ))
        } else if self.get_key_answers.contains_key(key_id) {
            Ok(Box::new(self.get_key_answers.get(key_id).unwrap().clone()))
        } else {
            Err(Error::Generic("no key configured"))
        }
    }

    fn get_all_trust_items(&self) -> Result<HashMap<[u8; 20], OwnerTrustLevel>> {
        Ok(HashMap::new())
    }

    fn implementation(&self) -> CryptoImpl {
        CryptoImpl::GpgMe
    }

    fn own_fingerprint(&self) -> Option<[u8; 20]> {
        None
    }
}

pub fn recipient_alex() -> Recipient {
    Recipient {
        name: "Alexander Kjäll <alexander.kjall@gmail.com>".to_owned(),
        comment: Comment {
            pre_comment: None,
            post_comment: None,
        },
        key_id: "1D108E6C07CBC406".to_owned(),
        fingerprint: Some(
            <[u8; 20]>::from_hex("7E068070D5EF794B00C8A9D91D108E6C07CBC406").unwrap(),
        ),
        key_ring_status: KeyRingStatus::InKeyRing,
        trust_level: OwnerTrustLevel::Ultimate,
        not_usable: false,
    }
}
pub fn recipient_alex_old() -> Recipient {
    Recipient {
        name: "Alexander Kjäll <alexander.kjall@gmail.com>".to_owned(),
        comment: Comment {
            pre_comment: None,
            post_comment: None,
        },
        key_id: "DF0C3D316B7312D5".to_owned(),
        fingerprint: Some(
            <[u8; 20]>::from_hex("DB07DAC5B3882EAB659E1D2FDF0C3D316B7312D5").unwrap(),
        ),
        key_ring_status: KeyRingStatus::InKeyRing,
        trust_level: OwnerTrustLevel::Ultimate,
        not_usable: false,
    }
}
pub fn recipient_from_cert(cert: &Cert) -> Recipient {
    Recipient {
        name: String::from_utf8(cert.userids().next().unwrap().userid().value().to_vec()).unwrap(),
        comment: Comment {
            pre_comment: None,
            post_comment: None,
        },
        key_id: cert.fingerprint().to_hex(),
        fingerprint: Some(<[u8; 20]>::from_hex(cert.fingerprint().to_hex()).unwrap()),
        key_ring_status: KeyRingStatus::InKeyRing,
        trust_level: OwnerTrustLevel::Ultimate,
        not_usable: false,
    }
}

pub fn append_file_name(file: &Path) -> PathBuf {
    let rf = file.to_path_buf();
    let mut sig = rf.into_os_string();
    sig.push(".sig");
    sig.into()
}

pub fn generate_sequoia_cert(email: &str) -> Cert {
    let (cert, _) = CertBuilder::general_purpose([UserID::from(email)])
        .generate()
        .unwrap();

    cert
}

pub fn generate_sequoia_cert_without_private_key(email: &str) -> Cert {
    let (cert, _) = CertBuilder::general_purpose([UserID::from(email)])
        .generate()
        .unwrap();

    cert.strip_secret_key_material()
}

struct KeyLister {
    pub ids: Vec<KeyID>,
}

impl VerificationHelper for &mut KeyLister {
    fn get_certs(&mut self, _: &[KeyHandle]) -> std::result::Result<Vec<Cert>, anyhow::Error> {
        Ok(vec![])
    }

    fn check(&mut self, _structure: MessageStructure) -> std::result::Result<(), anyhow::Error> {
        Ok(())
    }
}

impl DecryptionHelper for &mut KeyLister {
    fn decrypt(
        &mut self,
        pkesks: &[sequoia_openpgp::packet::PKESK],
        _: &[sequoia_openpgp::packet::SKESK],
        _: Option<SymmetricAlgorithm>,
        _: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> std::result::Result<Option<Cert>, anyhow::Error> {
        self.ids.extend(
            pkesks
                .iter()
                .map(|p| match p.recipient().clone().unwrap() {
                    KeyHandle::Fingerprint(fingerprint) => Ok(fingerprint.into()),
                    KeyHandle::KeyID(key_id) => Ok(key_id),
                })
                .collect::<std::result::Result<Vec<KeyID>, anyhow::Error>>()?,
        );
        Ok(None)
    }
}

pub fn count_recipients(data: &[u8]) -> usize {
    let p = StandardPolicy::new();
    let mut h = KeyLister { ids: vec![] };

    // result ignored since it's always an error, as we are not decrypting for real
    let _ = DecryptorBuilder::from_bytes(&data)
        .unwrap()
        .with_policy(&p, None, &mut h);

    h.ids.len()
}

#[test]
fn test_count_recipients() {
    let data = vec![
        0xc1, 0x6c, 0x06, 0x15, 0x04, 0x08, 0x6f, 0x6c, 0x69, 0x12, 0x24, 0xad, 0x6e, 0x3c, 0x0c,
        0x86, 0xfc, 0xa2, 0x26, 0xb7, 0x82, 0xd7, 0xfc, 0xd2, 0x44, 0x12, 0x01, 0x07, 0x40, 0x72,
        0xb0, 0x2f, 0x8b, 0x35, 0x5a, 0x34, 0xe1, 0x05, 0xbf, 0x6f, 0x35, 0x2d, 0xc8, 0x33, 0xed,
        0xaa, 0xdf, 0x76, 0xbf, 0xfb, 0x54, 0x8b, 0x73, 0x2c, 0xac, 0x7d, 0xd4, 0xd8, 0xc9, 0xdf,
        0x1b, 0x30, 0x0d, 0x09, 0x53, 0x11, 0x31, 0x03, 0x99, 0xfb, 0x77, 0xa0, 0xa1, 0x1a, 0x0d,
        0x9a, 0xb2, 0xf0, 0x22, 0xe6, 0xf1, 0x63, 0x90, 0x29, 0xb8, 0x37, 0xd4, 0x75, 0xd8, 0x03,
        0xc7, 0x22, 0xdb, 0xe3, 0x9d, 0x62, 0xea, 0x70, 0x69, 0xfa, 0x29, 0x4b, 0x00, 0x11, 0x49,
        0x0c, 0xbf, 0x96, 0x39, 0xa9, 0xd2, 0x54, 0x02, 0x09, 0x02, 0x06, 0x55, 0x14, 0xe8, 0x76,
        0xdd, 0x0f, 0x25, 0x13, 0x16, 0xe5, 0xfd, 0xb4, 0x57, 0x3b, 0xce, 0xa0, 0x3c, 0x81, 0x3d,
        0xc1, 0x82, 0x27, 0x46, 0x91, 0xf1, 0x9e, 0xc1, 0x09, 0x94, 0x9b, 0xbb, 0x55, 0xd4, 0xa4,
        0x26, 0x31, 0xb8, 0x17, 0xef, 0xd8, 0x48, 0xbd, 0x1b, 0x3a, 0xbd, 0x40, 0xec, 0xc6, 0x0b,
        0x33, 0xb0, 0x2f, 0x8c, 0x71, 0xb1, 0x90, 0xf6, 0xda, 0x35, 0xe5, 0x8b, 0xb5, 0x3e, 0x23,
        0xa3, 0x80, 0x35, 0x11, 0x83, 0x79, 0xf4, 0x79, 0x09, 0x71, 0xac, 0xee, 0xc5, 0x65, 0x0e,
        0xb8,
    ];

    assert_eq!(1, count_recipients(&data));
}
