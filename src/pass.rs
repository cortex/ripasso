/*  Ripasso - a simple password manager
    Copyright (C) 2019 Joakim Lundborg, Alexander Kjäll

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

use std::fs;
use std::fs::File;
use std::path;
use std::str;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::Duration;

use chrono::prelude::*;
use git2;
use glob;
use gpgme;
use notify;
use notify::Watcher;
use std::io::prelude::*;
use std::sync::{Arc, Mutex};
extern crate dirs;

use std;
use std::io;
use std::string;
use std::collections::HashSet;
use git2::{Oid, Repository};

/// Convenience type for Results
type Result<T> = std::result::Result<T, Error>;

/// The global state of all passwords are an instance of this type.
pub type PasswordList = Arc<Mutex<Vec<PasswordEntry>>>;

/// The type for how we handle git repositories
pub type GitRepo = Arc<Option<Mutex<git2::Repository>>>;

/// A enum that contains the different types of errors that the library returns as part of Result's.
#[derive(Debug)]
pub enum Error {
    IO(io::Error),
    Git(git2::Error),
    GPG(gpgme::Error),
    UTF8(string::FromUtf8Error),
    Notify(notify::Error),
    Generic(&'static str),
    GenericDyn(String),
    PathError(path::StripPrefixError),
    PatternError(glob::PatternError),
    GlobError(glob::GlobError),
    Utf8Error(std::str::Utf8Error),
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IO(err)
    }
}

impl From<gpgme::Error> for Error {
    fn from(err: gpgme::Error) -> Error {
        Error::GPG(err)
    }
}

impl From<git2::Error> for Error {
    fn from(err: git2::Error) -> Error {
        Error::Git(err)
    }
}

impl From<string::FromUtf8Error> for Error {
    fn from(err: string::FromUtf8Error) -> Error {
        Error::UTF8(err)
    }
}

impl From<notify::Error> for Error {
    fn from(err: notify::Error) -> Error {
        Error::Notify(err)
    }
}

impl From<path::StripPrefixError> for Error {
    fn from(err: path::StripPrefixError) -> Error {
        Error::PathError(err)
    }
}

impl From<glob::PatternError> for Error {
    fn from(err: glob::PatternError) -> Error {
        Error::PatternError(err)
    }
}

impl From<glob::GlobError> for Error {
    fn from(err: glob::GlobError) -> Error {
        Error::GlobError(err)
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(err: std::str::Utf8Error) -> Error {
        Error::Utf8Error(err)
    }
}

/// A git commit for a password might be signed by a gpg key, and this signature's verification
/// state is one of these values.
#[derive(Clone, Debug)]
pub enum SignatureStatus {
    /// Everything is fine with the signature, corresponds to the gpg status of GREEN
    GoodSignature,
    /// There was a non-critical failure in the verification, corresponds to the gpg status of VALID
    AlmostGoodSignature,
    /// Verification failed, corresponds to the gpg status of RED
    BadSignature
}

/// One password in the password store
#[derive(Clone, Debug)]
pub struct PasswordEntry {
    /// Name of the entry
    pub name: String,
    /// Metadata
    pub meta: String,
    /// Path, relative to the store
    path: path::PathBuf,
    /// Base path of password entry
    base: path::PathBuf,
    /// if we have a git repo, then commit time
    pub updated: Option<DateTime<Local>>,
    /// if we have a git repo, then the name of the committer
    pub committed_by: Option<String>,
    /// if we have a git repo, and the commit was signed
    pub signature_status: Option<SignatureStatus>,
    filename: String,
}

impl PasswordEntry {
    /// constructs a a `PasswordEntry` from the suplied parts
    pub fn new(base: &path::PathBuf, path: &path::PathBuf, update_time: Result<DateTime<Local>>, committed_by: Result<String>, signature_status: Result<SignatureStatus>) -> PasswordEntry {
        PasswordEntry {
            name: to_name(base, path),
            meta: "".to_string(),
            base: base.to_path_buf(),
            path: path.to_path_buf(),
            updated: match update_time {
                Ok(p) => Some(p),
                Err(_) => None,
            },
            committed_by: match committed_by {
                Ok(p) => Some(p),
                Err(_) => None,
            },
            signature_status: match signature_status {
                Ok(ss) => Some(ss),
                Err(_) => None,
            },
            filename: path.to_string_lossy().into_owned().clone(),
        }
    }

    /// creates a `PasswordEntry` by running git blame on the specified path
    pub fn load_from_git(base: &path::PathBuf, path: &path::PathBuf, repo_opt: GitRepo) -> Result<PasswordEntry> {
        let (update_time, committed_by, signature_status) = read_git_meta_data(base, path, repo_opt.clone());

        Ok(PasswordEntry {
            name: to_name(base, path),
            meta: "".to_string(),
            base: base.to_path_buf(),
            path: path.to_path_buf(),
            updated: match update_time {
                Ok(p) => Some(p),
                Err(_) => None,
            },
            committed_by: match committed_by {
                Ok(p) => Some(p),
                Err(_) => None,
            },
            signature_status: match signature_status {
                Ok(ss) => Some(ss),
                Err(_) => None,
            },
            filename: path.to_string_lossy().into_owned().clone(),
        })
    }

    /// Decrypts and returns the full content of the PasswordEntry
    pub fn secret(&self) -> Result<String> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
        let mut input = File::open(&self.filename)?;
        let mut output = Vec::new();
        ctx.decrypt(&mut input, &mut output)?;
        Ok(String::from_utf8(output)?)
    }

    /// Decrypts and returns the first line of the PasswordEntry
    pub fn password(&self) -> Result<String> {
        Ok(self.secret()?.split('\n').take(1).collect())
    }

    fn update_internal(&self, secret: String, password_store_dir: Arc<Option<String>>) -> Result<()> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;

        let mut keys = Vec::new();

        for recipient in Recipient::all_recipients(password_store_dir)? {
            keys.push(ctx.get_key(recipient.key_id)?);
        }

        let mut ciphertext = Vec::new();
        ctx.encrypt(&keys, secret, &mut ciphertext)?;

        let mut output = File::create(&self.filename)?;
        output.write_all(&ciphertext)?;
        Ok(())
    }

    /// Updates the password store entry with new content, and commits those to git if a repository
    /// is supplied.
    pub fn update(&self, secret: String, repo_opt: GitRepo, password_store_dir: Arc<Option<String>>) -> Result<()> {
        self.update_internal(secret, password_store_dir)?;

        if repo_opt.is_none() {
            return Ok(());
        }

        let message = format!("Edit password for {} using ripasso", &self.name);

        add_and_commit(repo_opt, &vec![format!("{}.gpg", &self.name)], &message)?;

        return Ok(());
    }

    /// Removes this entry from the filesystem and commit that to git if a repository is supplied.
    pub fn delete_file(&self, repo_opt: GitRepo) -> Result<()> {
        let res = Ok(std::fs::remove_file(&self.filename)?);

        if repo_opt.is_none() {
            return Ok(());
        }

        let message = format!("Removed password file for {} using ripasso", &self.name);

        remove_and_commit(repo_opt, &vec![format!("{}.gpg", &self.name)], &message)?;

        return res;
    }

    /// Returns a list of all password entries in the store.
    pub fn all_password_entries(repo_opt: GitRepo, password_store_dir: Arc<Option<String>>) -> Result<Vec<PasswordEntry>> {
        let dir = password_dir(password_store_dir)?;

        // Existing files iterator
        let password_path_glob = dir.join("**/*.gpg");
        let paths = glob::glob(&password_path_glob.to_string_lossy())?;

        let mut passwords = Vec::<PasswordEntry>::new();
        for path in paths {
            match PasswordEntry::load_from_git(&dir, &path?, repo_opt.clone()) {
                Ok(password) => passwords.push(password),
                Err(e) => return Err(e),
            }
        }

        return Ok(passwords);
    }

    /// Reencrypt all the entries in the store, for example when a new collaborator is added
    /// to the team.
    pub fn reencrypt_all_password_entries(repo_opt: GitRepo, password_store_dir: Arc<Option<String>>) -> Result<()> {
        let mut names: Vec<String> = Vec::new();
        for entry in PasswordEntry::all_password_entries(repo_opt.clone(), password_store_dir.clone())? {
            entry.update_internal(entry.secret()?, password_store_dir.clone())?;
            names.push(format!("{}.gpg", &entry.name));
        }
        names.push(".gpg-id".to_string());

        if repo_opt.is_none() {
            return Ok(());
        }

        let keys = Recipient::all_recipients(password_store_dir)?.into_iter().map(|s| format!("0x{}, ", s.key_id)).collect::<String>();
        let message = format!("Reencrypt password store with new GPG ids {}", keys);

        add_and_commit(repo_opt, &names, &message)?;

        return Ok(());
    }
}

fn find_last_commit(repo: &git2::Repository) -> Result<git2::Commit> {
    let obj = repo.head()?.resolve()?.peel(git2::ObjectType::Commit)?;
    obj.into_commit().map_err(|_| Error::Generic("Couldn't find commit"))
}

/// Returns if a git commit should be gpg signed or not.
fn should_sign() -> bool {
    let config = git2::Config::open_default();
    if config.is_err() {
        return false;
    }
    let config = config.unwrap();

    let do_sign = config.get_bool("commit.gpgsign");

    if do_sign.is_err() || !do_sign.unwrap() {
        return false;
    }

    return true;
}

/// Returns a gpg signature for the supplied string. Suitable to add to a gpg commit.
fn gpg_sign_string(commit: &String) -> Result<String> {
    let config = git2::Config::open_default()?;

    let signing_key = config.get_string("user.signingkey")?;

    let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
    ctx.set_armor(true);
    let key = ctx.get_secret_key(signing_key)?;

    ctx.add_signer(&key)?;
    let mut output = Vec::new();
    let signature = ctx.sign_detached(commit.clone(), &mut output);

    if signature.is_err() {
        return Err(Error::GPG(signature.unwrap_err()));
    }

    return Ok(String::from_utf8(output)?);
}

/// Apply the changes to the git repository.
fn commit(repo: &git2::Repository, signature: &git2::Signature, message: &String, tree: &git2::Tree, parents: &Vec<&git2::Commit>) -> Result<git2::Oid> {
    if should_sign() {
        let commit_buf = repo.commit_create_buffer(
            signature, // author
            signature, // committer
            message, // commit message
            tree, // tree
            parents)?; // parents

        let commit_as_str = str::from_utf8(&commit_buf)?.to_string();

        let sig = gpg_sign_string(&commit_as_str)?;

        let commit = repo.commit_signed(&commit_as_str, &sig, Some("gpgsig"))?;
        return Ok(commit);
    } else {
        let commit = repo.commit(Some("HEAD"), //  point HEAD to our new commit
                                                          signature, // author
                                                          signature, // committer
                                                          message, // commit message
                                                          tree, // tree
                                                          parents)?; // parents


        return Ok(commit);
    }
}

/// Add a file to the store, and commit it to the supplied git repository.
pub fn add_and_commit(repo_opt: GitRepo, paths: &Vec<String>, message: &str) -> Result<git2::Oid> {
    let repo_res = (*repo_opt).as_ref().unwrap().try_lock();
    if repo_res.is_err() {
        return Err(Error::GenericDyn(format!("{:?}", repo_res.err())))
    }
    let repo = repo_res.unwrap();

    let mut index = repo.index()?;
    for path in paths {
        index.add_path(path::Path::new(path))?;
    }
    let oid = index.write_tree()?;
    let signature = repo.signature()?;
    let parent_commit_res = find_last_commit(&repo);
    let mut parents = vec![];
    let parent_commit;
    if !parent_commit_res.is_err() {
        parent_commit = parent_commit_res?;
        parents.push(&parent_commit);
    }
    let tree = repo.find_tree(oid)?;

    let oid = commit(&repo, &signature, &message.to_string(), &tree, &parents)?;
    let obj = repo.find_object(oid, None)?;
    repo.reset(&obj, git2::ResetType::Hard, None)?;

    return Ok(oid);
}

/// Remove a file from the store, and commit the deletion to the supplied git repository.
fn remove_and_commit(repo_opt: GitRepo, paths: &Vec<String>, message: &str) -> Result<git2::Oid> {
    let repo_res = (*repo_opt).as_ref().unwrap().try_lock();
    if repo_res.is_err() {
        return Err(Error::GenericDyn(format!("{:?}", repo_res.err())))
    }
    let repo = repo_res.unwrap();

    let mut index = repo.index()?;
    for path in paths {
        index.remove_path(path::Path::new(path))?;
    }
    let oid = index.write_tree()?;
    let signature = repo.signature()?;
    let parent_commit_res = find_last_commit(&repo);
    let mut parents = vec![];
    let parent_commit;
    if !parent_commit_res.is_err() {
        parent_commit = parent_commit_res?;
        parents.push(&parent_commit);
    }
    let tree = repo.find_tree(oid)?;

    let oid = commit(&repo, &signature, &message.to_string(), &tree, &parents)?;
    let obj = repo.find_object(oid, None)?;
    repo.reset(&obj, git2::ResetType::Hard, None)?;

    return Ok(oid);
}

/// Push your changes to the remote git repository.
pub fn push(repo_opt: GitRepo) -> Result<()> {
    if repo_opt.is_none() {
        return Ok(());
    }

    let repo_res = (*repo_opt).as_ref().unwrap().try_lock();
    if repo_res.is_err() {
        return Err(Error::GenericDyn(format!("{:?}", repo_res.err())))
    }
    let repo = repo_res.unwrap();

    let mut ref_status = None;
    let mut origin = repo.find_remote("origin")?;
    let res = {
        let mut callbacks = git2::RemoteCallbacks::new();
        callbacks.credentials(|_url, username, allowed| {
            let sys_username = whoami::username();
            let user = match username {
                Some(name) => name,
                None => &sys_username
            };

            if allowed.contains(git2::CredentialType::USERNAME) {
                return git2::Cred::username(user);
            }

            git2::Cred::ssh_key_from_agent(user)
        });
        callbacks.push_update_reference(|refname, status| {
            assert_eq!(refname, "refs/heads/master");
            ref_status = status.map(|s| s.to_string());
            Ok(())
        });
        let mut opts = git2::PushOptions::new();
        opts.remote_callbacks(callbacks);
        origin.push(&["refs/heads/master"], Some(&mut opts))
    };
    return match res {
        Ok(()) if ref_status.is_none() => Ok(()),
        Ok(()) =>  Err(Error::GenericDyn(format!("failed to push a ref: {:?}", ref_status))),
        Err(e) => Err(Error::GenericDyn(format!("failure to push: {}", e))),
    }
}

/// Pull new changes from the remote git repository.
pub fn pull(repo_opt: GitRepo) -> Result<()> {
    if repo_opt.is_none() {
        return Ok(());
    }

    let repo_res = (*repo_opt).as_ref().unwrap().try_lock();
    if repo_res.is_err() {
        return Err(Error::GenericDyn(format!("{:?}", repo_res.err())))
    }
    let repo = repo_res.unwrap();

    let mut remote = repo.find_remote("origin")?;

    let mut cb = git2::RemoteCallbacks::new();
    cb.credentials(|_url, username, allowed| {
        let sys_username = whoami::username();
        let user = match username {
            Some(name) => name,
            None => &sys_username
        };

        if allowed.contains(git2::CredentialType::USERNAME) {
            return git2::Cred::username(user);
        }

        git2::Cred::ssh_key_from_agent(user)
    });

    let mut opts = git2::FetchOptions::new();
    opts.remote_callbacks(cb);
    remote.fetch(&["master"], Some(&mut opts), None)?;

    let remote_oid = repo.refname_to_id("refs/remotes/origin/master")?;
    let head_oid = repo.refname_to_id("HEAD")?;

    let (_, behind) = repo.graph_ahead_behind(head_oid, remote_oid)?;

    if behind == 0 {
        return Ok(());
    }

    let remote_annotated_commit = repo.find_annotated_commit(remote_oid)?;
    let remote_commit = repo.find_commit(remote_oid)?;
    repo.merge(&vec![&remote_annotated_commit], None, None)?;

    //commit it
    let mut index = repo.index()?;
    let oid = index.write_tree()?;
    let signature = repo.signature()?;
    let parent_commit = find_last_commit(&repo)?;
    let tree = repo.find_tree(oid)?;
    let message = "pull and merge by ripasso";
    let _commit = repo.commit(Some("HEAD"), //  point HEAD to our new commit
                             &signature, // author
                             &signature, // committer
                             message, // commit message
                             &tree, // tree
                             &[&parent_commit, &remote_commit])?; // parents

    //cleanup
    repo.cleanup_state()?;
    return Ok(());
}

/// Represents one person on the team.
///
/// All secrets are encrypted with the key_id of the recipients.
pub struct Recipient {
    /// Human readable name of the person.
    pub name: String,
    /// Machine readable identity, in the form of a gpg key id.
    pub key_id: String,
}

fn build_recipient(name: String, key_id: String) -> Recipient {
    Recipient {
        name,
        key_id,
    }
}

impl Recipient {
    /// Creates a Recipient from a gpg key id string
    pub fn new(key_id: String) -> Result<Recipient> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;

        let key_option = ctx.get_key(key_id.clone());
        if key_option.is_err() {
            return Err(Error::Generic("Can't find key in keyring, please import it first"));
        }

        let real_key = key_option?;

        let mut name = "?";
        for user_id in real_key.user_ids() {
            name = user_id.name().unwrap_or("?");
        }

        return Ok(build_recipient(name.to_string(), key_id));
    }

    /// Return a list of all the Recipients in the `$PASSWORD_STORE_DIR/.gpg-id` file.
    pub fn all_recipients(password_store_dir: Arc<Option<String>>) -> Result<Vec<Recipient>> {

        let mut recipient_file = password_dir(password_store_dir)?;
        recipient_file.push(".gpg-id");
        let contents = fs::read_to_string(recipient_file)
            .expect("Something went wrong reading the file");

        let mut recipients : Vec<Recipient> = Vec::new();
        let mut unique_recipients_keys : HashSet<String> = HashSet::new();
        for key in contents.split("\n") {
            if key.len() > 1 {
                unique_recipients_keys.insert(key.to_string());
            }
        }

        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;

        for key in unique_recipients_keys {
            let key_option = ctx.get_key(key.clone());
            if key_option.is_err() {
                continue;
            }

            let real_key = key_option?;

            let mut name = "?";
            for user_id in real_key.user_ids() {
                name = user_id.name().unwrap_or("?");
            }
            recipients.push(build_recipient(name.to_string(), real_key.id().unwrap_or("?").to_string()));
        }

        return Ok(recipients);
    }

    fn write_recipients_file(recipients: &Vec<Recipient>, repo_opt: GitRepo, password_store_dir: Arc<Option<String>>) -> Result<()> {
        let mut recipient_file = password_dir(password_store_dir.clone())?;
        recipient_file.push(".gpg-id");

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(recipient_file)?;

        for recipient in recipients {
            if !recipient.key_id.starts_with("0x") {
                file.write_all(b"0x")?;
            }
            file.write_all(recipient.key_id.as_bytes())?;
            file.write_all(b"\n")?;
        }

        PasswordEntry::reencrypt_all_password_entries(repo_opt, password_store_dir)?;

        return Ok(());
    }

    /// Delete one of the persons from the list of team members to encrypt the passwords for.
    pub fn remove_recipient_from_file(s: &Recipient, repo_opt: GitRepo, password_store_dir: Arc<Option<String>>) -> Result<()> {
        let mut recipients: Vec<Recipient> = Recipient::all_recipients(password_store_dir.clone())?;

        recipients.retain(|ref vs| vs.key_id != s.key_id);

        if recipients.len() < 1 {
            return Err(Error::Generic("Can't delete the last encryption key"));
        }

        return Recipient::write_recipients_file(&recipients, repo_opt, password_store_dir);
    }

    /// Add a new person to the list of team members to encrypt the passwords for.
    pub fn add_recipient_to_file(s: &Recipient, repo_opt: GitRepo, password_store_dir: Arc<Option<String>>) -> Result<()> {
        let mut recipients: Vec<Recipient> = Recipient::all_recipients(password_store_dir.clone())?;

        for recipient in &recipients {
            if recipient.key_id == s.key_id {
                return Err(Error::Generic("Team member is already in the list of key ids"));
            }
        }

        recipients.push(build_recipient(s.name.clone(), s.key_id.clone()));

        return Recipient::write_recipients_file(&recipients, repo_opt, password_store_dir);
    }
}

fn read_git_meta_data(base: &path::PathBuf, path: &path::PathBuf, repo_opt: GitRepo) -> (Result<DateTime<Local>>, Result<String>, Result<SignatureStatus>) {
    if repo_opt.is_none() {
        return (Err(Error::Generic("need repository to have meta information")),
                Err(Error::Generic("need repository to have meta information")),
                Err(Error::Generic("need repository to have meta information")));
    }

    let repo_res = (*repo_opt).as_ref().unwrap().try_lock();
    if repo_res.is_err() {
        let e = repo_res.err().unwrap();
        return (Err(Error::GenericDyn(format!("{:?}", e))),
                Err(Error::GenericDyn(format!("{:?}", e))),
                Err(Error::GenericDyn(format!("{:?}", e))));
    }
    let repo = repo_res.unwrap();

    let path_res = path.strip_prefix(base);
    if path_res.is_err() {
        let e = path_res.err().unwrap();
        return (Err(Error::GenericDyn(format!("{:?}", e))),
                Err(Error::GenericDyn(format!("{:?}", e))),
                Err(Error::GenericDyn(format!("{:?}", e))));
    }

    let blame_res = repo.blame_file(path_res.unwrap(), None);
    if blame_res.is_err() {
        let e = blame_res.err().unwrap();
        return (Err(Error::GenericDyn(format!("{:?}", e))),
                Err(Error::GenericDyn(format!("{:?}", e))),
                Err(Error::GenericDyn(format!("{:?}", e))));
    }
    let blame = blame_res.unwrap();
    let id_res = blame
        .get_line(1)
        .ok_or(Error::Generic("no git history found"));

    if id_res.is_err() {
        let e = id_res.err().unwrap();
        return (Err(Error::GenericDyn(format!("{:?}", e))),
                Err(Error::GenericDyn(format!("{:?}", e))),
                Err(Error::GenericDyn(format!("{:?}", e))));
    }
    let id = id_res.unwrap().orig_commit_id();

    let commit_res = repo.find_commit(id);
    if commit_res.is_err() {
        let e = commit_res.err().unwrap();
        return (Err(Error::GenericDyn(format!("{:?}", e))),
                Err(Error::GenericDyn(format!("{:?}", e))),
                Err(Error::GenericDyn(format!("{:?}", e))));
    }
    let commit = commit_res.unwrap();

    let time = commit.time();
    let time_return = Ok(Local.timestamp(time.seconds(), 0));

    let name_return: Result<String> = match commit.committer().name() {
        Some(s) => Ok(s.to_string()),
        None => Err(Error::Generic("missing committer name"))
    };

    let signature_return = verify_git_signature(&repo, &id);

    return (time_return, name_return, signature_return);
}

fn verify_git_signature(repo: &std::sync::MutexGuard<Repository>, id: &Oid) -> Result<SignatureStatus> {
    let (signature, signed_data) = repo.extract_signature(&id, Some("gpgsig"))?;

    let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;

    let signature_str = str::from_utf8(&signature)?.to_string();
    let signed_data_str = str::from_utf8(&signed_data)?.to_string();
    let result = ctx.verify_detached(signature_str, signed_data_str)?;

    let mut sig_sum = None;

    for (i, sig) in result.signatures().enumerate() {
        if i == 0 {
            sig_sum = Some(sig.summary());
        } else {
            return Err(Error::Generic("If a git contains more than one signature, something is fishy"));
        }
    }

    if sig_sum.is_none() {
        return Err(Error::Generic("Missing signature"));
    }

    let sig_sum = sig_sum.unwrap();

    if sig_sum.contains(gpgme::SignatureSummary::GREEN) {
        return Ok(SignatureStatus::GoodSignature);
    } else if sig_sum.contains(gpgme::SignatureSummary::VALID) {
        return Ok(SignatureStatus::AlmostGoodSignature);
    } else {
        return Ok(SignatureStatus::BadSignature);
    }

}

/// Creates a new password file in the store.
pub fn new_password_file(path_end: std::rc::Rc<String>, content: std::rc::Rc<String>, repo_opt: GitRepo, password_store_dir: Arc<Option<String>>) -> Result<()> {
    let mut path = password_dir(password_store_dir.clone())?;
    let c_path = std::fs::canonicalize(path.as_path())?;

    let path_deref = (*path_end).clone();
    let path_iter = &mut path_deref.split("/").peekable();

    while let Some(p) = path_iter.next() {
        if path_iter.peek().is_some() {
            path.push(p);
            let c_file = std::fs::canonicalize(path.as_path())?;
            if !c_file.starts_with(c_path.as_path()) {
                return Err(Error::Generic("trying to write outside of password store directory"));
            }
            if !path.exists() {
                std::fs::create_dir(&path)?;
            }
        } else {
            path.push(format!("{}.gpg", p));
        }
    }

    if path.exists() {
        return Err(Error::Generic("file already exist"));
    }

    let mut file = match File::create(path) {
        Err(why) => return Err(Error::from(why)),
        Ok(file) => file,
    };


    let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
    ctx.set_armor(false);

    let mut keys = Vec::new();

    for recipient in Recipient::all_recipients(password_store_dir)? {
        keys.push(ctx.get_key(recipient.key_id)?);
    }

    let mut output = Vec::new();
    ctx.encrypt(&keys, (*content).clone(), &mut output)?;

    match file.write_all(&output) {
        Err(why) => return Err(Error::from(why)),
        Ok(_) => (),
    }

    if repo_opt.is_none() {
        return Ok(());
    }

    let message = format!("Add password for {} using ripasso", path_end);

    add_and_commit(repo_opt, &vec![format!("{}.gpg", (*path_end).clone())], &message)?;

    return Ok(());
}

/// Initialize a git repository for the store.
pub fn init_git_repo(base: &path::PathBuf) -> Result<()> {
    git2::Repository::init(base)?;

    return Ok(());
}

/// When setting up a `watch` for the password store directory, events of these types will be sent.
#[derive(Debug)]
pub enum PasswordEvent {
    /// A new password file was created.
    NewPassword(PasswordEntry),
    /// A password file was removed.
    RemovedPassword(path::PathBuf),
    /// An error occured
    Error(Error),
}

/// Return a list of all passwords whose name contains `query`.
pub fn search(l: &PasswordList, query: &str) -> Result<Vec<PasswordEntry>> {
    let passwords = l.lock().unwrap();
    fn normalized(s: &str) -> String {
        s.to_lowercase()
    };
    fn matches(s: &str, q: &str) -> bool {
        normalized(s).as_str().contains(normalized(q).as_str())
    };
    let matching = passwords.iter().filter(|p| matches(&p.name, query));
    Ok(matching.cloned().collect())
}

/// Read the password store directory and populate the password list supplied.
pub fn populate_password_list(passwords: &PasswordList, repo_opt: GitRepo, password_store_dir: Arc<Option<String>>) -> Result<()> {
    let dir = password_dir(password_store_dir)?;

    let password_path_glob = dir.join("**/*.gpg");
    let existing_iter = glob::glob(&password_path_glob.to_string_lossy())?;

    let mut files_to_consider: Vec<String> = vec![];
    for existing_file in existing_iter {
        let pbuf = format!("{}", existing_file?.display());
        let filename = pbuf.trim_start_matches(format!("{}", dir.display()).as_str()).to_string();
        files_to_consider.push(filename.trim_start_matches("/").to_string());
    }

    let repo_res = (*repo_opt).as_ref().unwrap().try_lock();
    if repo_res.is_err() {
        return Err(Error::GenericDyn(format!("{:?}", repo_res.err())))
    }
    let repo = repo_res.unwrap();

    let mut walk = repo.revwalk()?;
    walk.push(repo.head()?.target().unwrap())?;
    let mut last_tree = repo.find_commit(repo.head()?.target().unwrap())?.tree()?;
    for rev in walk {
        let oid = rev?;

        let commit = repo.find_commit(oid)?;
        let tree = commit.tree()?;

        let diff = repo.diff_tree_to_tree(Some(&last_tree), Some(&tree), None)?;

        diff.foreach(&mut |delta: git2::DiffDelta, _f: f32| {
            let entry_name = format!("{}", delta.new_file().path().unwrap().display());
            &files_to_consider.retain(|filename| {
                if *filename == entry_name {
                    let time = commit.time();
                    let time_return = Ok(Local.timestamp(time.seconds(), 0));

                    let name_return: Result<String> = match commit.committer().name() {
                        Some(s) => Ok(s.to_string()),
                        None => Err(Error::Generic("missing committer name"))
                    };

                    let signature_return = verify_git_signature(&repo, &oid);

                    let mut pbuf = dir.clone();
                    pbuf.push(filename);

                    (passwords.lock().unwrap()).push(PasswordEntry::new(&dir, &pbuf, time_return, name_return, signature_return));
                    return false;
                }
                true
            });
            true
        }, None, None, None)?;

        last_tree = tree;
    }

    Ok(())
}

/// Subscribe to events, that happen when password files are added or removed
pub fn watch(repo_opt: GitRepo, password_store_dir: Arc<Option<String>>) -> Result<(Receiver<PasswordEvent>, PasswordList)> {
    let dir = password_dir(password_store_dir.clone())?;

    let (watcher_tx, watcher_rx) = channel();

    // Watcher iterator
    let (event_tx, event_rx): (
        Sender<PasswordEvent>,
        Receiver<PasswordEvent>,
    ) = channel();

    let passwords = Arc::new(Mutex::new(Vec::<PasswordEntry>::new()));
    let passwords_out = passwords.clone();

    populate_password_list(&passwords_out, repo_opt, password_store_dir)?;

    thread::spawn(move || {
        info!("Starting thread");


        // Automatically select the best implementation for your platform.
        let mut watcher: notify::RecommendedWatcher = Watcher::new(watcher_tx, Duration::from_secs(1)).unwrap();

        // Add a path to be watched. All files and directories at that path and
        // below will be monitored for changes.
        watcher.watch(&dir, notify::RecursiveMode::Recursive).unwrap();

        loop {
            match watcher_rx.recv() {
                Ok(event) => {
                    let pass_event = match event {
                        notify::DebouncedEvent::Create(p) => {
                            let ext = p.extension();
                            if ext == None || ext.unwrap() != "gpg" {
                                continue;
                            }
                            let password_store_dir = Arc::new(match std::env::var("PASSWORD_STORE_DIR") {
                                Ok(p) => Some(p),
                                Err(_) => None
                            });

                            let repo_res = git2::Repository::open(password_dir(password_store_dir.clone()).unwrap());
                            let mut repo_opt: GitRepo = Arc::new(None::<Mutex<git2::Repository>>);
                            if repo_res.is_ok() {
                                repo_opt = Arc::new(Some(Mutex::new(repo_res.unwrap())));
                            }
                            let p_e = PasswordEntry::load_from_git(&password_dir(password_store_dir).unwrap(), &p.clone(), repo_opt).unwrap();
                            if !(passwords.lock().unwrap()).iter().any(|p| p.path == p_e.path) {
                                (passwords.lock().unwrap()).push(p_e.clone());
                            }
                            PasswordEvent::NewPassword(p_e)
                        },
                        notify::DebouncedEvent::Remove(p) => {
                            let index = (passwords.lock().unwrap()).iter().position(|x| *x.path == p).unwrap();
                            (passwords.lock().unwrap()).remove(index);
                            PasswordEvent::RemovedPassword(p)
                        },
                        notify::DebouncedEvent::Error(e, _) => {
                            PasswordEvent::Error(Error::Notify(e))
                        },
                        _ => PasswordEvent::Error(Error::Generic("None")),
                    };

                    if let Err(_err) = event_tx.send(pass_event) {
                        //error!("Error sending event {}", err)
                    }
                },
                Err(e) => {
                    eprintln!("watch error: {:?}", e);
                    panic!("error")
                },
            }
        }
    });
    Ok((event_rx, passwords_out))
}

fn to_name(base: &path::PathBuf, path: &path::PathBuf) -> String {
    path.strip_prefix(base)
        .unwrap()
        .to_string_lossy()
        .into_owned()
        .trim_end_matches(".gpg")
        .to_string()
}

/// Determine password directory
pub fn password_dir(password_store_dir: Arc<Option<String>>) -> Result<path::PathBuf> {
    let pass_home = password_dir_raw(password_store_dir);
    if !pass_home.exists() {
        return Err(Error::Generic("failed to locate password directory"));
    }
    Ok(pass_home.to_path_buf())
}

/// Determine password directory
pub fn password_dir_raw(password_store_dir: Arc<Option<String>>) -> path::PathBuf {
    // If a directory is provided via env var, use it
    let pass_home = match password_store_dir.as_ref() {
        Some(p) => p.clone(),
        None => dirs::home_dir()
            .unwrap()
            .join(".password-store")
            .to_string_lossy()
            .into(),
    };
    return path::PathBuf::from(&pass_home);
}

#[cfg(test)]
mod test;
