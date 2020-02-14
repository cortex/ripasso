pub use crate::error::{Error, Result};
use gpgme::Key;
use std::fs;
use std::io::prelude::*;
use std::path::PathBuf;

/// A git commit for a password might be signed by a gpg key, and this signature's verification
/// state is one of these values.
#[derive(Clone, Debug)]
pub enum SignatureStatus {
    /// Everything is fine with the signature, corresponds to the gpg status of VALID
    Good,
    /// There was a non-critical failure in the verification, corresponds to the gpg status of GREEN
    AlmostGood,
    /// Verification failed, corresponds to the gpg status of RED
    Bad,
}

impl From<gpgme::SignatureSummary> for SignatureStatus {
    fn from(s: gpgme::SignatureSummary) -> SignatureStatus {
        if s.contains(gpgme::SignatureSummary::VALID) {
            SignatureStatus::Good
        } else if s.contains(gpgme::SignatureSummary::GREEN) {
            SignatureStatus::AlmostGood
        } else {
            SignatureStatus::Bad
        }
    }
}

pub fn parse_signing_keys(
    password_store_signing_key: &Option<String>,
) -> Result<Vec<String>> {
    if password_store_signing_key.is_none() {
        return Ok(vec![]);
    }

    let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;

    let mut signing_keys = vec![];
    for key in password_store_signing_key.as_ref().unwrap().split(',') {
        let trimmed = key.trim().to_string();

        if trimmed.len() != 40
            || (trimmed.len() != 42 && trimmed.starts_with("0x"))
        {
            return Err(Error::Generic(
                "signing key isn't in full 40 character id format",
            ));
        }

        let key_res = ctx.get_key(&trimmed);
        if key_res.is_err() {
            return Err(Error::GenericDyn(format!(
                "signing key not found in keyring, error: {:?}",
                key_res.err()
            )));
        }

        signing_keys.push(trimmed);
    }
    Ok(signing_keys)
}
/// Returns a gpg signature for the supplied string. Suitable to add to a gpg commit.
pub fn gpg_sign_string(commit: &str) -> Result<String> {
    let config = git2::Config::open_default()?;

    let signing_key = config.get_string("user.signingkey")?;

    let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
    ctx.set_armor(true);
    let key = ctx.get_secret_key(signing_key)?;

    ctx.add_signer(&key)?;
    let mut output = Vec::new();
    let signature = ctx.sign_detached(commit, &mut output);

    if let Err(e) = signature {
        return Err(Error::GPG(e));
    }

    Ok(String::from_utf8(output)?)
}

/// the GPG trust level for a key
#[derive(Clone, PartialEq)]
pub enum OwnerTrustLevel {
    /// is only used for your own keys. You trust this key 'per se'. Any message signed with that key,
    /// will be trusted. This is also the reason why any key from a friend, that is signed by you, will
    /// also show as valid (green), even though you did not change the ownertrust of the signed key.
    /// The signed key will be valid due to the ultimate ownertrust of your own key.
    Ultimate,
    /// is used for keys, which you trust to sign other keys. That means, if Alice's key is signed by
    /// your Buddy Bob, whose key you set the ownertrust to Full, Alice's key will be trusted. You
    /// should only be using Full ownertrust after verifying and signing Bob's key.
    Full,
    /// will make a key show as valid, if it has been signed by at least three keys which you set to
    /// 'Marginal' trust-level. Example: If you set Alice's, Bob's and Peter's key to 'Marginal' and
    /// they all sign Ed's key, Ed's key will be valid. Due to the complexity of this status, we
    /// do not recommend using it.
    Marginal,
    /// Trust-level is identical to 'Unknown / Undefined' i.e. the key is not trusted. But in this case,
    /// you actively state, to never trust the key in question. That means, you know that the key
    /// owner is not accurately verifying other keys before signing them.
    Never,
    /// has the same meaning as 'Unknown' but differs, since it has actually been set by the user.
    /// That could mean, that this is a key you want to process at a later point in time.
    Undefined,
    /// is the default state. It means, no ownertrust has been set yet. The key is not trusted.
    Unknown,
}

impl From<&gpgme::Validity> for OwnerTrustLevel {
    fn from(level: &gpgme::Validity) -> OwnerTrustLevel {
        match level {
            gpgme::Validity::Unknown => OwnerTrustLevel::Unknown,
            gpgme::Validity::Undefined => OwnerTrustLevel::Undefined,
            gpgme::Validity::Never => OwnerTrustLevel::Never,
            gpgme::Validity::Marginal => OwnerTrustLevel::Marginal,
            gpgme::Validity::Full => OwnerTrustLevel::Full,
            gpgme::Validity::Ultimate => OwnerTrustLevel::Ultimate,
        }
    }
}

#[derive(Clone, PartialEq)]
pub enum KeyRingStatus {
    InKeyRing,
    NotInKeyRing,
}

/// Represents one person on the team.
///
/// All secrets are encrypted with the key_id of the recipients.
#[derive(Clone)]
pub struct Recipient {
    /// Human readable name of the person.
    pub name: String,
    /// Machine readable identity, in the form of a gpg key id.
    pub key_id: String,
    /// The status of the key in GPG's keyring
    pub key_ring_status: KeyRingStatus,
    /// The trust level the owner of the key ring has placed in this person
    pub trust_level: OwnerTrustLevel,
}

fn build_recipient(
    name: String,
    key_id: String,
    key_ring_status: KeyRingStatus,
    trust_level: OwnerTrustLevel,
) -> Recipient {
    Recipient {
        name,
        key_id,
        key_ring_status,
        trust_level,
    }
}

use std::collections::{HashMap, HashSet};

impl Recipient {
    /// Creates a Recipient from a gpg key id string
    pub fn new(key_id: String) -> Result<Recipient> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;

        let key_option = ctx.get_key(key_id.clone());
        if key_option.is_err() {
            return Ok(build_recipient(
                "key id not in keyring".to_string(),
                key_id,
                KeyRingStatus::NotInKeyRing,
                OwnerTrustLevel::Unknown,
            ));
        }

        let real_key = key_option?;

        let mut name = "?";
        for user_id in real_key.user_ids() {
            name = user_id.name().unwrap_or("?");
        }

        let trusts: HashMap<String, OwnerTrustLevel> =
            Recipient::get_all_trust_items()?;

        Ok(build_recipient(
            name.to_string(),
            key_id,
            KeyRingStatus::InKeyRing,
            (*trusts
                .get(real_key.fingerprint()?)
                .unwrap_or(&OwnerTrustLevel::Unknown))
            .clone(),
        ))
    }

    fn get_all_trust_items() -> Result<HashMap<String, OwnerTrustLevel>> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
        ctx.set_key_list_mode(gpgme::KeyListMode::SIGS)?;

        let keys = ctx.find_keys(vec!["".to_string()])?;

        let mut trusts = HashMap::new();
        for key_res in keys {
            let key = key_res?;
            trusts.insert(
                key.fingerprint()?.to_string(),
                OwnerTrustLevel::from(&key.owner_trust()),
            );
        }

        Ok(trusts)
    }
    /// Return a list of all the Recipients in the `$PASSWORD_STORE_DIR/.gpg-id` file.
    pub fn all_recipients(recipient_file: &PathBuf) -> Result<Vec<Recipient>> {
        let contents = fs::read_to_string(recipient_file)
            .expect("Something went wrong reading the file");

        let mut recipients: Vec<Recipient> = Vec::new();
        let mut unique_recipients_keys: HashSet<String> = HashSet::new();
        for key in contents.split('\n') {
            if key.len() > 1 {
                unique_recipients_keys.insert(key.to_string());
            }
        }

        let trusts: HashMap<String, OwnerTrustLevel> =
            Recipient::get_all_trust_items()?;

        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
        for key in unique_recipients_keys {
            let key_option = ctx.get_key(key.clone());
            if key_option.is_err() {
                recipients.push(build_recipient(
                    "key id not in keyring".to_string(),
                    key.clone(),
                    KeyRingStatus::NotInKeyRing,
                    OwnerTrustLevel::Unknown,
                ));
                continue;
            }

            let real_key = key_option?;

            let mut name = "?";
            for user_id in real_key.user_ids() {
                name = user_id.name().unwrap_or("?");
            }
            recipients.push(build_recipient(
                name.to_string(),
                real_key.id().unwrap_or("?").to_string(),
                KeyRingStatus::InKeyRing,
                (*trusts
                    .get(real_key.fingerprint()?)
                    .unwrap_or(&OwnerTrustLevel::Unknown))
                .clone(),
            ));
        }

        Ok(recipients)
    }

    fn write_recipients_file(
        recipients: &[Recipient],
        recipients_file: &PathBuf,
        valid_gpg_signing_keys: &[String],
    ) -> Result<()> {
        {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(recipients_file)?;

            let mut file_content = "".to_string();
            for recipient in recipients {
                if !recipient.key_id.starts_with("0x") {
                    file_content.push_str("0x");
                }
                file_content.push_str(recipient.key_id.as_str());
                file_content.push_str("\n");
            }
            file.write_all(file_content.as_bytes())?;

            if !valid_gpg_signing_keys.is_empty() {
                let mut ctx =
                    gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
                let mut key_opt: Option<Key> = None;

                for key_id in valid_gpg_signing_keys {
                    let key_res = ctx.get_key(key_id);

                    if let Ok(r) = key_res {
                        key_opt = Some(r);
                    }
                }

                if let Some(key) = key_opt {
                    ctx.add_signer(&key)?;

                    let mut output = Vec::new();
                    ctx.sign_detached(file_content, &mut output)?;

                    let recipient_sig_filename: PathBuf = {
                        let rf = recipients_file.clone();
                        let mut sig = rf.into_os_string();
                        sig.push(".sig");
                        sig.into()
                    };

                    let mut recipient_sig_file = std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(recipient_sig_filename)?;

                    recipient_sig_file.write_all(&output)?;
                }
            }
        }
        Ok(())
    }

    /// Delete one of the persons from the list of team members to encrypt the passwords for.
    pub fn remove_recipient_from_file(
        s: &Recipient,
        recipient_file: PathBuf,
        valid_gpg_signing_keys: &[String],
    ) -> Result<()> {
        let mut recipients: Vec<Recipient> =
            Recipient::all_recipients(&recipient_file)?;

        recipients.retain(|ref vs| vs.key_id != s.key_id);

        if recipients.is_empty() {
            return Err(Error::Generic("Can't delete the last encryption key"));
        }

        Recipient::write_recipients_file(
            &recipients,
            &recipient_file,
            valid_gpg_signing_keys,
        )
    }

    /// Add a new person to the list of team members to encrypt the passwords for.
    pub fn add_recipient_to_file(
        recipient: &Recipient,
        recipient_file: PathBuf,
        valid_gpg_signing_keys: &[String],
    ) -> Result<()> {
        let mut recipients: Vec<Recipient> =
            Recipient::all_recipients(&recipient_file)?;

        for r in &recipients {
            if r.key_id == recipient.key_id {
                return Err(Error::Generic(
                    "Team member is already in the list of key ids",
                ));
            }
        }
        recipients.push((*recipient).clone());

        Recipient::write_recipients_file(
            &recipients,
            &recipient_file,
            valid_gpg_signing_keys,
        )
    }
}
