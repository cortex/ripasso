pub use crate::error::{Error, Result};
use crate::signature::{KeyRingStatus, Recipient, SignatureStatus};

/// The different types of errors that can occur when doing a signature verification
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

pub trait Crypto {
    /// Reads a file and decrypts it
    fn decrypt_string(&self, content: &[u8]) -> Result<String>;
    /// encrypts a string
    fn encrypt_string(&self, content: &str, recipients: &[Recipient]) -> Result<Vec<u8>>;

    /// Returns a gpg signature for the supplied string. Suitable to add to a gpg commit.
    fn sign_string(&self, to_sign: &str) -> Result<String>;

    /// verifies is a signature is valid
    fn verify_sign(
        &self,
        data: &[u8],
        sig: &[u8],
        valid_signing_keys: &[String],
    ) -> std::result::Result<SignatureStatus, VerificationError>;

    /// pull keys from the keyserver for those recipients.
    fn pull_keys(&self, recipients: &[Recipient]) -> Result<String>;
}

pub struct GpgMe {}

impl Crypto for GpgMe {
    fn decrypt_string(&self, content: &[u8]) -> Result<String> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
        let mut output = Vec::new();
        ctx.decrypt(content, &mut output)?;
        Ok(String::from_utf8(output)?)
    }

    fn encrypt_string(&self, content: &str, recipients: &[Recipient]) -> Result<Vec<u8>> {
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
            content,
            &mut output,
            gpgme::EncryptFlags::NO_COMPRESS,
        )?;

        Ok(output)
    }

    fn sign_string(&self, to_sign: &str) -> Result<String> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;

        let config = git2::Config::open_default()?;

        let signing_key = config.get_string("user.signingkey")?;

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
        valid_signing_keys: &[String],
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

            if !valid_signing_keys.contains(&fpr.to_string()) {
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

    fn pull_keys(&self, recipients: &[Recipient]) -> Result<String> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;

        let mut result_str = "".to_owned();
        for recipient in recipients {
            let url = match recipient.key_id.len() {
                16 => format!(
                    "https://keys.openpgp.org/vks/v1/by-keyid/{}",
                    recipient.key_id
                )
                .to_string(),
                18 if recipient.key_id.starts_with("0x") => format!(
                    "https://keys.openpgp.org/vks/v1/by-keyid/{}",
                    recipient.key_id[2..].to_string()
                )
                .to_string(),
                40 => format!(
                    "https://keys.openpgp.org/vks/v1/by-fingerprint/{}",
                    recipient.key_id
                )
                .to_string(),
                42 if recipient.key_id.starts_with("0x") => format!(
                    "https://keys.openpgp.org/vks/v1/by-fingerprint/{}",
                    recipient.key_id[2..].to_string()
                )
                .to_string(),
                _ => return Err(Error::Generic("key id is not 16 or 40 hex chars")),
            };
            let response = reqwest::blocking::get(url)?.text()?;

            let result = ctx.import(response)?;

            result_str.push_str(&format!(
                "{}: import result: {:?}\n\n",
                recipient.key_id, result
            ));
        }

        Ok(result_str)
    }
}
