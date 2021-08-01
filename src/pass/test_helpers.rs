use super::*;

use flate2::read::GzDecoder;
use std::cell::RefCell;
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

pub struct MockCrypto {
    pub decrypt_called: RefCell<bool>,
    pub encrypt_called: RefCell<bool>,
    pub sign_called: RefCell<bool>,
    pub verify_called: RefCell<bool>,
    encrypt_string_return: Vec<u8>,
}

impl MockCrypto {
    pub fn new() -> MockCrypto {
        MockCrypto {
            decrypt_called: RefCell::new(false),
            encrypt_called: RefCell::new(false),
            sign_called: RefCell::new(false),
            verify_called: RefCell::new(false),
            encrypt_string_return: vec![],
        }
    }

    pub fn with_encrypt_string_return(mut self, data: Vec<u8>) -> MockCrypto {
        self.encrypt_string_return = data;

        self
    }
}

impl Crypto for MockCrypto {
    fn decrypt_string(&self, _: &[u8]) -> Result<String> {
        self.decrypt_called.replace(true);
        Ok("".to_string())
    }

    fn encrypt_string(&self, _: &str, _: &[Recipient]) -> Result<Vec<u8>> {
        self.encrypt_called.replace(true);
        Ok(self.encrypt_string_return.clone())
    }

    fn sign_string(&self, _: &str) -> Result<String> {
        self.sign_called.replace(true);
        Ok("".to_string())
    }

    fn verify_sign(
        &self,
        _: &[u8],
        _: &[u8],
        _: &[String],
    ) -> std::result::Result<SignatureStatus, VerificationError> {
        self.verify_called.replace(true);
        Err(VerificationError::SignatureFromWrongRecipient)
    }

    fn pull_keys(&self, _recipients: &[Recipient]) -> Result<String> {
        Ok("dummy implementation".to_owned())
    }
}
