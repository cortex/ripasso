use std::{
    cmp::PartialEq,
    collections::{HashMap, HashSet},
    fs,
    io::prelude::*,
    path::{Path, PathBuf},
};

use crate::crypto::{FindSigningFingerprintStrategy, Fingerprint};
use crate::error::{Error, Result};

/// A git commit for a password might be signed by a gpg key, and this signature's verification
/// state is one of these values.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureStatus {
    /// Everything is fine with the signature, corresponds to the gpg status of VALID
    Good,
    /// There was a non-critical failure in the verification, corresponds to the gpg status of GREEN
    AlmostGood,
    /// Verification failed, corresponds to the gpg status of RED
    Bad,
}

impl From<gpgme::SignatureSummary> for SignatureStatus {
    fn from(s: gpgme::SignatureSummary) -> Self {
        if s.contains(gpgme::SignatureSummary::VALID) {
            Self::Good
        } else if s.contains(gpgme::SignatureSummary::GREEN) {
            Self::AlmostGood
        } else {
            Self::Bad
        }
    }
}

/// Turns an optional string into a vec of parsed gpg fingerprints in the form of strings.
/// If any of the fingerprints isn't a full 40 chars or if they haven't been imported to
/// the gpg keyring yet, this function instead returns an error.
///
/// # Errors
/// Fails if the signing keys can't be parsed.
pub fn parse_signing_keys(
    password_store_signing_key: &Option<String>,
    crypto: &(dyn crate::crypto::Crypto + Send),
) -> Result<Vec<Fingerprint>> {
    if let Some(password_store_signing_key) = password_store_signing_key {
        let mut signing_keys = vec![];
        for key in password_store_signing_key.split(',') {
            let trimmed = key.trim().to_owned();
            let len = trimmed.len();
            let have_0x = trimmed.starts_with("0x");

            if !(len == 40 || len == 64 || len == 42 && have_0x || len == 66 && have_0x) {
                return Err(Error::Generic(
                    "signing key isn't in full 40/64 hex character fingerprint format",
                ));
            }

            let key_res = crypto.get_key(&trimmed);
            if let Some(err) = key_res.err() {
                return Err(Error::GenericDyn(format!(
                    "signing key not found in keyring, error: {err}",
                )));
            }

            signing_keys.push(trimmed.as_str().try_into()?);
        }
        Ok(signing_keys)
    } else {
        Ok(vec![])
    }
}

/// the GPG trust level for a key
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
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
    fn from(level: &gpgme::Validity) -> Self {
        match level {
            gpgme::Validity::Unknown => Self::Unknown,
            gpgme::Validity::Undefined => Self::Undefined,
            gpgme::Validity::Never => Self::Never,
            gpgme::Validity::Marginal => Self::Marginal,
            gpgme::Validity::Full => Self::Full,
            gpgme::Validity::Ultimate => Self::Ultimate,
        }
    }
}

/// A Recipient can either be in the GPG keyring, or not.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum KeyRingStatus {
    /// it's in the ring
    InKeyRing,
    /// it's not in the ring
    NotInKeyRing,
}

/// internal holder of a user id row and the comments that belong to it
struct IdComment {
    /// the id string
    pub id: String,
    /// an optional comment before the id string
    pub pre_comment: Vec<String>,
    /// an optional comment after the id string
    pub post_comment: Option<String>,
}

impl std::hash::Hash for IdComment {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl PartialEq for IdComment {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for IdComment {}

/// Describes a comment around a gpg id / fingerprint. See this commit for source:
/// <https://git.zx2c4.com/password-store/commit/?id=a271b43cbd76cc30406202c49041b552656538bd>
#[derive(Clone, Debug)]
pub struct Comment {
    /// The comment field from the .gpg-id file, above the user fingerprint
    /// not including the leading '#' characters.
    pub pre_comment: Option<String>,
    /// The comment field from the .gpg-id file, after the user fingerprint
    /// not including the leading '#' characters.
    pub post_comment: Option<String>,
}

/// Represents one person on the team.
///
/// All secrets are encrypted with the `key_id` of the recipients.
#[derive(Clone, Debug)]
pub struct Recipient {
    /// Human-readable name of the person.
    pub name: String,
    /// The comment field from the .gpg-id file, not including the leading '#' characters.
    pub comment: Comment,
    /// Machine-readable identity taken from the .gpg-id file, in the form of a gpg key id
    /// (16 hex chars) or a fingerprint (40 hex chars).
    pub key_id: String,
    /// The fingerprint of the pgp key, as 20 bytes or 32 bytes,
    /// if the fingerprint of the key is not known, this will be None.
    pub fingerprint: Option<Fingerprint>,
    /// The status of the key in GPG's keyring
    pub key_ring_status: KeyRingStatus,
    /// The trust level the owner of the key ring has placed in this person
    pub trust_level: OwnerTrustLevel,
    /// If the key isn't usable for any reason, i.e. if any of the gpg function
    /// `is_bad`, `is_revoked`, `is_expired`, `is_disabled` or `is_invalid` returns true
    pub not_usable: bool,
}

impl Recipient {
    /// Constructs a `Recipient` object.
    fn new(
        name: String,
        comment: Comment,
        key_id: String,
        fingerprint: Option<Fingerprint>,
        key_ring_status: KeyRingStatus,
        trust_level: OwnerTrustLevel,
        not_usable: bool,
    ) -> Self {
        Self {
            name,
            comment,
            key_id,
            fingerprint,
            key_ring_status,
            trust_level,
            not_usable,
        }
    }

    /// Creates a `Recipient` from a gpg key id string
    /// # Errors
    /// Returns an `Err` if the trust levels can't be retrieved or there is something wrong with the fingerprint.
    pub fn from(
        key_id: &str,
        pre_comment: &[String],
        post_comment: Option<String>,
        crypto: &(dyn crate::crypto::Crypto + Send),
    ) -> Result<Self> {
        let comment_opt = match pre_comment.len() {
            0 => None,
            _ => Some(pre_comment.join("\n")),
        };
        let comment = Comment {
            pre_comment: comment_opt,
            post_comment,
        };

        let key_result = crypto.get_key(key_id);
        if key_result.is_err() {
            return Ok(Recipient::new(
                "key id not in keyring".to_owned(),
                comment,
                key_id.to_owned(),
                None,
                KeyRingStatus::NotInKeyRing,
                OwnerTrustLevel::Unknown,
                true,
            ));
        }

        let real_key = key_result?;

        let mut names = real_key.user_id_names();

        let name = names.pop().unwrap_or("?".to_owned());

        let trusts: HashMap<Fingerprint, OwnerTrustLevel> = crypto.get_all_trust_items()?;

        let fingerprint = real_key.fingerprint()?;

        Ok(Self::new(
            name,
            comment,
            key_id.to_owned(),
            Some(fingerprint),
            KeyRingStatus::InKeyRing,
            (*trusts
                .get(&real_key.fingerprint()?)
                .unwrap_or(&OwnerTrustLevel::Unknown))
            .clone(),
            real_key.is_not_usable(),
        ))
    }

    /// Return a list of all the Recipients in the supplied file.
    /// # Errors
    /// Returns an `Err` if there is a problem reading the `.gpg_id` file
    pub fn all_recipients(
        recipients_file: &Path,
        crypto: &(dyn crate::crypto::Crypto + Send),
    ) -> Result<Vec<Self>> {
        let contents = fs::read_to_string(recipients_file)?;

        let mut recipients: Vec<Recipient> = Vec::new();
        let mut unique_recipients_keys: HashSet<IdComment> = HashSet::new();
        let mut comment_buf = vec![];
        for key in contents.split('\n') {
            if key.len() > 1 {
                if key.starts_with('#') {
                    comment_buf.push(key.chars().skip(1).collect());
                } else if key.contains('#') {
                    let mut splitter = key.splitn(2, '#');
                    if let Some(key) = splitter.next() {
                        let key = key.trim();
                        if let Some(comment) = splitter.next() {
                            unique_recipients_keys.insert(IdComment {
                                id: key.to_owned(),
                                pre_comment: comment_buf.clone(),
                                post_comment: Some(comment.to_owned()),
                            });
                            comment_buf.clear();
                        }
                    }
                } else {
                    unique_recipients_keys.insert(IdComment {
                        id: key.to_owned(),
                        pre_comment: comment_buf.clone(),
                        post_comment: None,
                    });
                    comment_buf.clear();
                }
            }
        }

        for key in unique_recipients_keys {
            let recipient =
                match Self::from(&key.id, &key.pre_comment, key.post_comment.clone(), crypto) {
                    Ok(r) => r,
                    Err(err) => {
                        let comment_opt = match key.pre_comment.len() {
                            0 => None,
                            _ => Some(key.pre_comment.join("\n")),
                        };

                        Self::new(
                            err.to_string(),
                            Comment {
                                pre_comment: comment_opt,
                                post_comment: key.post_comment,
                            },
                            key.id.clone(),
                            None,
                            KeyRingStatus::NotInKeyRing,
                            OwnerTrustLevel::Unknown,
                            true,
                        )
                    }
                };
            recipients.push(recipient);
        }

        Ok(recipients)
    }

    /// write the .gpg-id.sig file
    /// # Errors
    /// Returns an `Err` if the file writing fails
    pub fn write_recipients_file(
        recipients: &[Self],
        recipients_file: &Path,
        valid_gpg_signing_keys: &[Fingerprint],
        crypto: &(dyn crate::crypto::Crypto + Send),
    ) -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(recipients_file)?;

        let mut file_content = String::new();
        let mut sorted_recipients = recipients.to_owned();
        sorted_recipients.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        for recipient in sorted_recipients {
            let to_add = match recipient.fingerprint {
                Some(f) => hex::encode_upper(f),
                None => recipient.key_id,
            };

            if let Some(pre_comment) = recipient.comment.pre_comment.as_ref() {
                for line in pre_comment.split('\n') {
                    file_content.push('#');
                    file_content.push_str(line);
                    file_content.push('\n');
                }
            }

            if !to_add.starts_with("0x") {
                file_content.push_str("0x");
            }
            file_content.push_str(&to_add);

            if let Some(post_comment) = recipient.comment.post_comment.as_ref() {
                file_content.push_str(" #");
                file_content.push_str(post_comment);
            }
            file_content.push('\n');
        }
        file.write_all(file_content.as_bytes())?;

        if !valid_gpg_signing_keys.is_empty() {
            let output = crypto.sign_string(
                &file_content,
                valid_gpg_signing_keys,
                &FindSigningFingerprintStrategy::GPG,
            )?;

            let recipient_sig_filename: PathBuf = {
                let rf = recipients_file.to_path_buf();
                let mut sig = rf.into_os_string();
                sig.push(".sig");
                sig.into()
            };

            let mut recipient_sig_file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(recipient_sig_filename)?;

            recipient_sig_file.write_all(output.as_bytes())?;
        }

        Ok(())
    }

    /// Delete one of the persons from the list of team members to encrypt the passwords for.
    /// # Errors
    /// Return an `Err` if there is an error reading the `gpg_id` file
    pub fn remove_recipient_from_file(
        s: &Self,
        recipients_file: &Path,
        store_root_path: &Path,
        valid_gpg_signing_keys: &[Fingerprint],
        crypto: &(dyn crate::crypto::Crypto + Send),
    ) -> Result<()> {
        let mut recipients: Vec<Recipient> = Self::all_recipients(recipients_file, crypto)?;

        recipients.retain(|vs| {
            if vs.fingerprint.is_some() && s.fingerprint.is_some() {
                vs.fingerprint != s.fingerprint
            } else {
                vs.key_id != s.key_id
            }
        });

        if recipients.is_empty() {
            if recipients_file == store_root_path.join(".gpg_id") {
                Err(Error::Generic("Can't delete the last encryption key"))
            } else {
                Ok(fs::remove_file(recipients_file)?)
            }
        } else {
            Recipient::write_recipients_file(
                &recipients,
                recipients_file,
                valid_gpg_signing_keys,
                crypto,
            )
        }
    }

    /// Add a new person to the list of team members to encrypt the passwords for.
    /// # Errors
    /// Return an `Err` if there is an error reading the `gpg_id` file
    pub fn add_recipient_to_file(
        recipient: &Self,
        recipients_file: &Path,
        valid_gpg_signing_keys: &[Fingerprint],
        crypto: &(dyn crate::crypto::Crypto + Send),
    ) -> Result<()> {
        let mut recipients: Vec<Self> = Self::all_recipients(recipients_file, crypto)?;

        for r in &recipients {
            if r == recipient {
                return Err(Error::Generic(
                    "Team member is already in the list of key ids",
                ));
            }
        }
        recipients.push((*recipient).clone());

        Recipient::write_recipients_file(
            &recipients,
            recipients_file,
            valid_gpg_signing_keys,
            crypto,
        )
    }
}

impl PartialEq for Recipient {
    fn eq(&self, other: &Self) -> bool {
        if self.fingerprint.is_none() || other.fingerprint.is_none() {
            return false;
        }

        self.fingerprint.as_ref().unwrap() == other.fingerprint.as_ref().unwrap()
    }
}

#[cfg(test)]
#[path = "tests/signature.rs"]
mod signature_tests;
