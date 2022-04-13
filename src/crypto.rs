use crate::crypto::VerificationError::InfrastructureError;
pub use crate::error::{Error, Result};
use crate::pass::OwnerTrustLevel;
use crate::signature::{KeyRingStatus, Recipient, SignatureStatus};
use hex::FromHex;
use sequoia_openpgp::crypto::SessionKey;
use sequoia_openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, DetachedVerifierBuilder, MessageLayer, MessageStructure,
    VerificationHelper,
};
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::Policy;
use sequoia_openpgp::serialize::stream::{Armorer, Encryptor, LiteralWriter, Message, Signer};
use sequoia_openpgp::serialize::Serialize;
use sequoia_openpgp::types::{RevocationStatus, SymmetricAlgorithm};
use sequoia_openpgp::Cert;
use sequoia_openpgp::KeyHandle;
use std::collections::HashMap;
use std::fmt::{Display, Formatter, Write as FmtWrite};
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

/// The different pgp implementations we support
#[derive(PartialEq, Debug)]
pub enum CryptoImpl {
    GpgMe,
    Sequoia,
}

impl std::convert::TryFrom<&str> for CryptoImpl {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "gpg" => Ok(CryptoImpl::GpgMe),
            "sequoia" => Ok(CryptoImpl::Sequoia),
            _ => Err(Error::Generic(
                "unknown pgp implementation value, valid values are 'gpg' and 'sequoia'",
            )),
        }
    }
}

impl Display for CryptoImpl {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        match self {
            CryptoImpl::GpgMe => write!(f, "gpg"),
            CryptoImpl::Sequoia => write!(f, "sequoia"),
        }?;
        Ok(())
    }
}

/// The different types of errors that can occur when doing a signature verification
#[derive(Debug)]
pub enum VerificationError {
    /// Error message from the pgp library.
    InfrastructureError(String),
    /// The data was signed, but not from one of the supplied recipients.
    SignatureFromWrongRecipient,
    /// The signature was invalid,
    BadSignature,
    /// No signature found.
    MissingSignatures,
    /// More than one signature, this shouldn't happen and can indicate that someone have tried
    /// to trick the process by appending an additional signature.
    TooManySignatures,
}

impl From<std::io::Error> for VerificationError {
    fn from(err: std::io::Error) -> VerificationError {
        InfrastructureError(format!("{:?}", err))
    }
}

impl From<crate::error::Error> for VerificationError {
    fn from(err: crate::error::Error) -> VerificationError {
        InfrastructureError(format!("{:?}", err))
    }
}

impl From<anyhow::Error> for VerificationError {
    fn from(err: anyhow::Error) -> VerificationError {
        InfrastructureError(format!("{:?}", err))
    }
}

/// The strategy for finding the gpg key to sign with can either be to look at the git
/// config, or ask gpg.
pub enum FindSigningFingerprintStrategy {
    GIT,
    GPG,
}

pub trait Key {
    fn user_id_names(&self) -> Vec<String>;

    fn fingerprint(&self) -> Result<[u8; 20]>;

    fn is_not_usable(&self) -> bool;
}

pub struct GpgMeKey {
    key: gpgme::Key,
}

impl Key for GpgMeKey {
    fn user_id_names(&self) -> Vec<String> {
        self.key
            .user_ids()
            .map(|user_id| user_id.name().unwrap_or("?").to_owned())
            .collect()
    }

    fn fingerprint(&self) -> Result<[u8; 20]> {
        let fp = self.key.fingerprint()?;

        Ok(<[u8; 20]>::from_hex(fp)?)
    }

    fn is_not_usable(&self) -> bool {
        self.key.is_bad()
            || self.key.is_revoked()
            || self.key.is_expired()
            || self.key.is_disabled()
            || self.key.is_invalid()
    }
}

pub trait Crypto {
    /// Reads a file and decrypts it
    fn decrypt_string(&self, ciphertext: &[u8]) -> Result<String>;
    /// Encrypts a string
    fn encrypt_string(&self, plaintext: &str, recipients: &[Recipient]) -> Result<Vec<u8>>;

    /// Returns a gpg signature for the supplied string. Suitable to add to a gpg commit.
    fn sign_string(
        &self,
        to_sign: &str,
        valid_gpg_signing_keys: &[[u8; 20]],
        strategy: &FindSigningFingerprintStrategy,
    ) -> Result<String>;

    /// Verifies is a signature is valid
    fn verify_sign(
        &self,
        data: &[u8],
        sig: &[u8],
        valid_signing_keys: &[[u8; 20]],
    ) -> std::result::Result<SignatureStatus, VerificationError>;

    /// Pull keys from the keyserver for those recipients.
    fn pull_keys(&mut self, recipients: &[Recipient], config_path: &Path) -> Result<String>;

    /// Import a key from text.
    fn import_key(&mut self, key: &str, config_path: &Path) -> Result<String>;

    /// Return a key corresponding to the given key id.
    fn get_key(&self, key_id: &str) -> Result<Box<dyn crate::crypto::Key>>;

    /// Returns a map from key fingerprints to OwnerTrustLevel's
    fn get_all_trust_items(&self) -> Result<HashMap<[u8; 20], crate::signature::OwnerTrustLevel>>;

    /// Returns the type of this CryptoImpl, useful for serializing the store config
    fn implementation(&self) -> CryptoImpl;

    /// Returns the fingerprint of the user using ripasso
    fn own_fingerprint(&self) -> Option<[u8; 20]>;
}

pub struct GpgMe {}

impl Crypto for GpgMe {
    fn decrypt_string(&self, ciphertext: &[u8]) -> Result<String> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
        let mut output = Vec::new();
        ctx.decrypt(ciphertext, &mut output)?;
        Ok(String::from_utf8(output)?)
    }

    fn encrypt_string(&self, plaintext: &str, recipients: &[Recipient]) -> Result<Vec<u8>> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
        ctx.set_armor(false);

        let mut keys = Vec::new();
        for recipient in recipients {
            if recipient.key_ring_status == KeyRingStatus::NotInKeyRing {
                return Err(Error::RecipientNotInKeyRing(recipient.key_id.clone()));
            }
            keys.push(ctx.get_key(recipient.key_id.clone())?);
        }

        let mut output = Vec::new();
        ctx.encrypt_with_flags(
            &keys,
            plaintext,
            &mut output,
            gpgme::EncryptFlags::NO_COMPRESS,
        )?;

        Ok(output)
    }

    fn sign_string(
        &self,
        to_sign: &str,
        valid_gpg_signing_keys: &[[u8; 20]],
        strategy: &FindSigningFingerprintStrategy,
    ) -> Result<String> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;

        let config = git2::Config::open_default()?;

        let signing_key = match strategy {
            FindSigningFingerprintStrategy::GIT => config.get_string("user.signingkey")?,
            FindSigningFingerprintStrategy::GPG => {
                let mut key_opt: Option<gpgme::Key> = None;

                for key_id in valid_gpg_signing_keys {
                    let key_res = ctx.get_key(hex::encode_upper(key_id));

                    if let Ok(r) = key_res {
                        key_opt = Some(r);
                    }
                }

                if let Some(key) = key_opt {
                    key.fingerprint()?.to_owned()
                } else {
                    return Err(Error::Generic("no valid signing key"));
                }
            }
        };

        ctx.set_armor(true);
        let key = ctx.get_secret_key(signing_key)?;

        ctx.add_signer(&key)?;
        let mut output = Vec::new();
        let signature = ctx.sign_detached(to_sign, &mut output);

        if let Err(e) = signature {
            return Err(Error::Gpg(e));
        }

        Ok(String::from_utf8(output)?)
    }

    fn verify_sign(
        &self,
        data: &[u8],
        sig: &[u8],
        valid_signing_keys: &[[u8; 20]],
    ) -> std::result::Result<SignatureStatus, VerificationError> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)
            .map_err(|e| VerificationError::InfrastructureError(format!("{:?}", e)))?;

        let result = ctx
            .verify_detached(sig, data)
            .map_err(|e| VerificationError::InfrastructureError(format!("{:?}", e)))?;

        let mut sig_sum = None;

        for (i, sig) in result.signatures().enumerate() {
            let fpr = sig
                .fingerprint()
                .map_err(|e| VerificationError::InfrastructureError(format!("{:?}", e)))?;

            let fpr = <[u8; 20]>::from_hex(fpr)
                .map_err(|e| VerificationError::InfrastructureError(format!("{:?}", e)))?;

            if !valid_signing_keys.contains(&fpr) {
                return Err(VerificationError::SignatureFromWrongRecipient);
            }
            if i == 0 {
                sig_sum = Some(sig.summary());
            } else {
                return Err(VerificationError::TooManySignatures);
            }
        }

        match sig_sum {
            None => Err(VerificationError::MissingSignatures),
            Some(sig_sum) => {
                let sig_status: SignatureStatus = sig_sum.into();
                match sig_status {
                    SignatureStatus::Bad => Err(VerificationError::BadSignature),
                    _ => Ok(sig_status),
                }
            }
        }
    }

    fn pull_keys(&mut self, recipients: &[Recipient], _config_path: &Path) -> Result<String> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;

        let mut result_str = String::new();
        for recipient in recipients {
            let response = download_keys(&recipient.key_id)?;

            let result = ctx.import(response)?;

            write!(
                result_str,
                "{}: import result: {:?}\n\n",
                recipient.key_id, result
            )?;
        }

        Ok(result_str)
    }

    fn import_key(&mut self, key: &str, _config_path: &Path) -> Result<String> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;

        let result = ctx.import(key)?;

        let result_str = format!("Import result: {:?}\n\n", result);

        Ok(result_str)
    }

    fn get_key(&self, key_id: &str) -> Result<Box<dyn crate::crypto::Key>> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;

        Ok(Box::new(GpgMeKey {
            key: ctx.get_key(key_id)?,
        }))
    }

    fn get_all_trust_items(&self) -> Result<HashMap<[u8; 20], crate::signature::OwnerTrustLevel>> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
        ctx.set_key_list_mode(gpgme::KeyListMode::SIGS)?;

        let keys = ctx.find_keys(vec![String::new()])?;

        let mut trusts = HashMap::new();
        for key_res in keys {
            let key = key_res?;
            trusts.insert(
                <[u8; 20]>::from_hex(key.fingerprint()?)?,
                crate::signature::OwnerTrustLevel::from(&key.owner_trust()),
            );
        }

        Ok(trusts)
    }

    fn implementation(&self) -> CryptoImpl {
        CryptoImpl::GpgMe
    }

    fn own_fingerprint(&self) -> Option<[u8; 20]> {
        None
    }
}

fn download_keys(recipient_key_id: &str) -> Result<String> {
    let url = match recipient_key_id.len() {
        16 => format!(
            "https://keys.openpgp.org/vks/v1/by-keyid/{}",
            recipient_key_id
        )
        .to_string(),
        18 if recipient_key_id.starts_with("0x") => format!(
            "https://keys.openpgp.org/vks/v1/by-keyid/{}",
            &recipient_key_id[2..]
        )
        .to_string(),
        40 => format!(
            "https://keys.openpgp.org/vks/v1/by-fingerprint/{}",
            recipient_key_id
        )
        .to_string(),
        42 if recipient_key_id.starts_with("0x") => format!(
            "https://keys.openpgp.org/vks/v1/by-fingerprint/{}",
            &recipient_key_id[2..]
        )
        .to_string(),
        _ => return Err(Error::Generic("key id is not 16 or 40 hex chars")),
    };

    Ok(reqwest::blocking::get(url)?.text()?)
}

struct Helper<'a> {
    policy: &'a dyn Policy,
    secret: Option<&'a sequoia_openpgp::Cert>,
    key_ring: &'a HashMap<[u8; 20], Arc<sequoia_openpgp::Cert>>,
    /// This is all the certificates that are allowed to sign something
    public_keys: Vec<Arc<sequoia_openpgp::Cert>>,
    ctx: Option<sequoia_ipc::gnupg::Context>,
    do_signature_verification: bool,
}

impl<'a> VerificationHelper for Helper<'a> {
    fn get_certs(
        &mut self,
        handles: &[sequoia_openpgp::KeyHandle],
    ) -> sequoia_openpgp::Result<Vec<sequoia_openpgp::Cert>> {
        let mut certs = vec![];

        for handle in handles {
            for cert in &self.public_keys {
                for c in cert.keys() {
                    if c.key_handle().aliases(handle) {
                        certs.push(cert.as_ref().clone());
                    }
                }
            }
        }
        // Return public keys for signature verification here.
        Ok(certs)
    }

    fn check(&mut self, structure: MessageStructure) -> sequoia_openpgp::Result<()> {
        if !self.do_signature_verification {
            return Ok(());
        }

        for layer in structure.into_iter() {
            match layer {
                MessageLayer::SignatureGroup { ref results } => {
                    if results.iter().any(|r| r.is_ok()) {
                        return Ok(());
                    }
                }
                _ => {}
            }
        }
        Err(anyhow::anyhow!("No valid signature"))
    }
}

fn find(
    key_ring: &HashMap<[u8; 20], Arc<sequoia_openpgp::Cert>>,
    recipient: &sequoia_openpgp::KeyID,
) -> Result<Arc<sequoia_openpgp::Cert>> {
    let bytes: &[u8; 8] = match recipient {
        sequoia_openpgp::KeyID::V4(bytes) => bytes,
        sequoia_openpgp::KeyID::Invalid(_) => return Err(Error::Generic("not an v4 keyid")),
        _ => return Err(Error::Generic("not an v4 keyid")),
    };

    for (key, value) in &*key_ring {
        if key[0..8] == *bytes {
            return Ok(value.clone());
        }
    }

    return Err(Error::Generic("key not found in keyring"));
}

impl<'a> DecryptionHelper for Helper<'a> {
    fn decrypt<D>(
        &mut self,
        pkesks: &[sequoia_openpgp::packet::PKESK],
        _skesks: &[sequoia_openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> sequoia_openpgp::Result<Option<sequoia_openpgp::Fingerprint>>
    where
        D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    {
        if self.secret.is_none() {
            // we don't know which key is the users own key, so lets try them all

            for pkesk in pkesks {
                if let Ok(cert) = find(self.key_ring, pkesk.recipient()) {
                    let key = cert.primary_key();
                    let mut pair =
                        sequoia_ipc::gnupg::KeyPair::new(self.ctx.as_ref().unwrap(), &*key)?;
                    if pkesk
                        .decrypt(&mut pair, sym_algo)
                        .map(|(algo, session_key)| decrypt(algo, &session_key))
                        .unwrap_or(false)
                    {
                        break;
                    }
                }
            }

            // XXX: In production code, return the Fingerprint of the
            // recipient's Cert here
            return Ok(None);
        }
        // The encryption key is the first and only subkey.
        let key = self
            .secret
            .unwrap()
            .keys()
            .unencrypted_secret()
            .with_policy(self.policy, None)
            .for_transport_encryption()
            .nth(0)
            .unwrap()
            .key()
            .clone();

        // The secret key is not encrypted.
        let mut pair = key.into_keypair().unwrap();

        pkesks[0]
            .decrypt(&mut pair, sym_algo)
            .map(|(algo, session_key)| decrypt(algo, &session_key));

        // XXX: In production code, return the Fingerprint of the
        // recipient's Cert here
        Ok(None)
    }
}

fn slice_to_20_bytes(b: &[u8]) -> Result<[u8; 20]> {
    if b.len() != 20 {
        return Err(Error::Generic("slice isn't 20 bytes"));
    }

    let mut f: [u8; 20] = [0; 20];
    f.copy_from_slice(&b[0..20]);

    Ok(f)
}

pub struct SequoiaKey {
    cert: sequoia_openpgp::Cert,
}

impl Key for SequoiaKey {
    fn user_id_names(&self) -> Vec<String> {
        self.cert.userids().map(|ui| ui.to_string()).collect()
    }

    fn fingerprint(&self) -> Result<[u8; 20]> {
        Ok(slice_to_20_bytes(self.cert.fingerprint().as_bytes())?)
    }

    fn is_not_usable(&self) -> bool {
        let p = sequoia_openpgp::policy::StandardPolicy::new();

        let policy = match self.cert.with_policy(&p, None) {
            Err(_) => return true,
            Ok(p) => p,
        };

        self.cert.revocation_status(&p, None) != RevocationStatus::NotAsFarAsWeKnow
            || policy.alive().is_err()
    }
}

pub struct Sequoia {
    user_key_id: [u8; 20],
    key_ring: HashMap<[u8; 20], Arc<sequoia_openpgp::Cert>>,
}

impl Sequoia {
    pub fn new(config_path: &Path, own_fingerprint: [u8; 20]) -> Result<Self> {
        let mut key_ring: HashMap<[u8; 20], Arc<sequoia_openpgp::Cert>> = HashMap::new();

        let dir = config_path.join("share").join("ripasso").join("keys");
        if dir.exists() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_file() {
                    let data = fs::read(path)?;
                    let cert = Cert::from_bytes(&data)?;

                    let fingerprint = slice_to_20_bytes(cert.fingerprint().as_bytes())?;
                    key_ring.insert(fingerprint, Arc::new(cert));
                }
            }
        }

        Ok(Sequoia {
            user_key_id: own_fingerprint,
            key_ring,
        })
    }

    fn convert_recipients(&self, input: &[Recipient]) -> Result<Vec<Arc<sequoia_openpgp::Cert>>> {
        let mut result = vec![];

        for recipient in input {
            match recipient.fingerprint {
                Some(fp) => match self.key_ring.get(&fp) {
                    Some(cert) => result.push(cert.clone()),
                    None => {
                        return Err(Error::GenericDyn(format!(
                            "Recipient with key id {} not found",
                            recipient.key_id
                        )))
                    }
                },
                None => {
                    let kh: sequoia_openpgp::KeyHandle = recipient.key_id.parse()?;

                    for cert in self.key_ring.values() {
                        if cert.key_handle().aliases(&kh) {
                            result.push(cert.clone())
                        }
                    }
                }
            };
        }

        Ok(result)
    }

    fn pull_and_write(&mut self, key_id: &str, keys_dir: &Path) -> Result<String> {
        let response = download_keys(&key_id)?;

        self.write_cert(&response, keys_dir)
    }

    fn write_cert(&mut self, cert_str: &str, keys_dir: &Path) -> Result<String> {
        let cert = Cert::from_bytes(cert_str.as_bytes())?;

        let fingerprint = slice_to_20_bytes(cert.fingerprint().as_bytes())?;

        let mut file = File::create(keys_dir.join(hex::encode(fingerprint)))?;

        cert.serialize(&mut file)?;

        self.key_ring.insert(fingerprint, Arc::new(cert));

        Ok("Downloaded ok".to_owned())
    }
}

impl Crypto for Sequoia {
    fn decrypt_string(&self, ciphertext: &[u8]) -> Result<String> {
        let p = sequoia_openpgp::policy::StandardPolicy::new();

        let mut sink: Vec<u8> = vec![];

        let decrypt_key = self
            .key_ring
            .get(&self.user_key_id)
            .ok_or(Error::Generic("no key for user found"))?;

        if decrypt_key.is_tsk() {
            // Make a helper that that feeds the recipient's secret key to the
            // decryptor.
            let helper = Helper {
                policy: &p,
                secret: Some(decrypt_key),
                key_ring: &self.key_ring,
                public_keys: vec![],
                ctx: None,
                do_signature_verification: false,
            };

            // Now, create a decryptor with a helper using the given Certs.
            let mut decryptor =
                DecryptorBuilder::from_bytes(ciphertext)?.with_policy(&p, None, helper)?;

            // Decrypt the data.
            std::io::copy(&mut decryptor, &mut sink)?;

            Ok(std::str::from_utf8(&sink)?.to_owned())
        } else {
            // Make a helper that that feeds the recipient's secret key to the
            // decryptor.
            let helper = Helper {
                policy: &p,
                secret: Some(decrypt_key),
                key_ring: &self.key_ring,
                public_keys: vec![],
                ctx: Some(sequoia_ipc::gnupg::Context::with_homedir("/home/capitol/")?),
                do_signature_verification: false,
            };

            // Now, create a decryptor with a helper using the given Certs.
            let mut decryptor =
                DecryptorBuilder::from_bytes(ciphertext)?.with_policy(&p, None, helper)?;

            // Decrypt the data.
            std::io::copy(&mut decryptor, &mut sink)?;

            Ok(std::str::from_utf8(&sink)?.to_owned())
        }
    }

    fn encrypt_string(&self, plaintext: &str, recipients: &[Recipient]) -> Result<Vec<u8>> {
        let p = sequoia_openpgp::policy::StandardPolicy::new();

        let mut recipient_keys = vec![];
        let cr = self.convert_recipients(recipients)?;
        for r in &cr {
            for k in r
                .keys()
                .with_policy(&p, None)
                .supported()
                .alive()
                .revoked(false)
                .for_transport_encryption()
            {
                recipient_keys.push(k);
            }
        }

        let mut sink: Vec<u8> = vec![];

        // Start streaming an OpenPGP message.
        let message = Message::new(&mut sink);

        // We want to encrypt a literal data packet.
        let message = Encryptor::for_recipients(message, recipient_keys).build()?;

        // Emit a literal data packet.
        let mut message = LiteralWriter::new(message).build()?;

        // Encrypt the data.
        message.write_all(plaintext.as_bytes())?;

        // Finalize the OpenPGP message to make sure that all data is
        // written.
        message.finalize()?;

        Ok(sink)
    }

    fn sign_string(
        &self,
        to_sign: &str,
        _valid_gpg_signing_keys: &[[u8; 20]],
        _strategy: &FindSigningFingerprintStrategy,
    ) -> Result<String> {
        let p = sequoia_openpgp::policy::StandardPolicy::new();

        let tsk = self
            .key_ring
            .get(&self.user_key_id)
            .ok_or(Error::Generic("no key for user found"))?;

        // Get the keypair to do the signing from the Cert.
        let keypair = tsk
            .keys()
            .unencrypted_secret()
            .with_policy(&p, None)
            .alive()
            .revoked(false)
            .for_signing()
            .nth(0)
            .unwrap()
            .key()
            .clone()
            .into_keypair()?;

        let mut sink: Vec<u8> = vec![];

        // Start streaming an OpenPGP message.
        let message = Message::new(&mut sink);

        let message = Armorer::new(message)
            .kind(sequoia_openpgp::armor::Kind::Signature)
            .build()?;

        // We want to sign a literal data packet.
        let mut message = Signer::new(message, keypair).detached().build()?;

        // Sign the data.
        message.write_all(to_sign.as_bytes())?;

        // Finalize the OpenPGP message to make sure that all data is
        // written.
        message.finalize()?;

        Ok(std::str::from_utf8(&sink)?.to_owned())
    }

    fn verify_sign(
        &self,
        data: &[u8],
        sig: &[u8],
        valid_signing_keys: &[[u8; 20]],
    ) -> std::result::Result<SignatureStatus, VerificationError> {
        let p = sequoia_openpgp::policy::StandardPolicy::new();

        let recipients: Vec<Recipient> = if valid_signing_keys.len() == 0 {
            self.key_ring
                .keys()
                .map(|k| Recipient::from(&hex::encode(k), &[], None, self))
                .collect::<Result<Vec<Recipient>>>()?
        } else {
            valid_signing_keys
                .iter()
                .map(|k| Recipient::from(&hex::encode_upper(k), &[], None, self))
                .collect::<Result<Vec<Recipient>>>()?
        };
        let senders = self.convert_recipients(&recipients)?;

        // Make a helper that that feeds the sender's public key to the
        // verifier.
        let helper = Helper {
            policy: &p,
            secret: None,
            key_ring: &self.key_ring,
            public_keys: senders,
            ctx: None,
            do_signature_verification: true,
        };

        // Now, create a verifier with a helper using the given Certs.
        let mut verifier =
            DetachedVerifierBuilder::from_bytes(sig)?.with_policy(&p, None, helper)?;

        // Verify the data.
        verifier.verify_bytes(data)?;

        Ok(SignatureStatus::Good)
    }

    fn pull_keys(&mut self, recipients: &[Recipient], config_path: &Path) -> Result<String> {
        let p = config_path.join("share").join("ripasso").join("keys");
        std::fs::create_dir_all(&p)?;

        let mut ret = "".to_owned();
        for recipient in recipients {
            let res = self.pull_and_write(&recipient.key_id, &p);

            ret.extend(format!("{}: ", &recipient.key_id).chars());
            match res {
                Ok(s) => ret.extend(s.chars()),
                Err(err) => ret.extend(format!("{:?}", err).chars()),
            }
            ret.extend("\n".chars());
        }

        Ok(ret)
    }

    fn import_key(&mut self, key: &str, config_path: &Path) -> Result<String> {
        let p = config_path.join("share").join("ripasso").join("keys");
        std::fs::create_dir_all(&p)?;

        self.write_cert(key, &p)
    }

    fn get_key(&self, key_id: &str) -> Result<Box<dyn Key>> {
        let kh: KeyHandle = key_id.parse()?;
        for c in self.key_ring.values() {
            if c.key_handle() == kh {
                return Ok(Box::new(SequoiaKey {
                    cert: c.as_ref().clone(),
                }));
            }
        }

        return Err(Error::GenericDyn(format!("no key found for {}", key_id)));
    }

    fn get_all_trust_items(&self) -> Result<HashMap<[u8; 20], OwnerTrustLevel>> {
        let mut res: HashMap<[u8; 20], OwnerTrustLevel> = HashMap::new();

        for k in self.key_ring.keys() {
            res.insert(k.clone(), OwnerTrustLevel::Ultimate);
        }

        Ok(res)
    }

    fn implementation(&self) -> CryptoImpl {
        CryptoImpl::Sequoia
    }

    fn own_fingerprint(&self) -> Option<[u8; 20]> {
        Some(self.user_key_id)
    }
}

#[cfg(test)]
#[path = "tests/crypto.rs"]
mod crypto_tests;
