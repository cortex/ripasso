use crate::crypto::{Crypto, FindSigningFingerprintStrategy, Key, VerificationError};
use crate::error::Error;
use crate::error::Result;
use crate::pass::{KeyRingStatus, OwnerTrustLevel, SignatureStatus};
use crate::signature::{Comment, Recipient};
use flate2::read::GzDecoder;
use hex::FromHex;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::path::Path;
use std::path::PathBuf;
use tar::Archive;

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

    pub fn dir(&self) -> &Path {
        self.dir.as_path()
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
        Ok(self.fingerprint.clone())
    }

    fn is_not_usable(&self) -> bool {
        false
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

    fn pull_keys(&self, _recipients: &[Recipient]) -> Result<String> {
        Ok("dummy implementation".to_owned())
    }

    fn import_key(&self, _key: &str) -> Result<String> {
        Ok("dummy implementation".to_owned())
    }

    fn get_key(&self, key_id: &str) -> Result<Box<dyn Key>> {
        if self.get_key_string_error.is_some() {
            Err(Error::GenericDyn(
                self.get_key_string_error.clone().unwrap(),
            ))
        } else {
            if self.get_key_answers.contains_key(key_id) {
                Ok(Box::new(self.get_key_answers.get(key_id).unwrap().clone()))
            } else {
                Err(Error::Generic("no key configured"))
            }
        }
    }

    fn get_all_trust_items(&self) -> Result<HashMap<[u8; 20], OwnerTrustLevel>> {
        Ok(HashMap::new())
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

pub fn append_file_name(file: &Path) -> PathBuf {
    let rf = file.to_path_buf();
    let mut sig = rf.into_os_string();
    sig.push(".sig");
    sig.into()
}
