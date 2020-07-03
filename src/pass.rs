/*  Ripasso - a simple password manager
    Copyright (C) 2019-2020 Joakim Lundborg, Alexander Kjäll

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
use notify::Watcher;
use std::io::prelude::*;
use std::sync::{Arc, Mutex};
extern crate config;

use git2::{Oid, Repository};

pub use crate::error::{Error, Result};
pub use crate::signature::{
    gpg_sign_string, parse_signing_keys, KeyRingStatus, OwnerTrustLevel, Recipient, SignatureStatus,
};
use std::collections::HashMap;

/// The global state of all passwords are an instance of this type.
pub type PasswordStoreType = Arc<Mutex<PasswordStore>>;

/// Represents a complete password store directory
pub struct PasswordStore {
    /// Name given to the store in a config file
    name: String,
    /// The path to the root directory of the password store
    root: path::PathBuf,
    /// A list of keys that are allowed to sign the .gpg-id file, obtained from the environmental
    /// variable `PASSWORD_STORE_SIGNING_KEY`
    valid_gpg_signing_keys: Vec<String>,
    /// a list of password files with meta data
    pub passwords: Vec<PasswordEntry>,
}

impl PasswordStore {
    /// Creates a `PasswordStore`
    pub fn new(
        store_name: &str,
        password_store_dir: &Option<String>,
        password_store_signing_key: &Option<String>,
        home: &Option<path::PathBuf>,
    ) -> Result<PasswordStore> {
        let pass_home = password_dir_raw(password_store_dir, home);
        if !pass_home.exists() {
            return Err(Error::Generic("failed to locate password directory"));
        }

        let signing_keys = parse_signing_keys(password_store_signing_key)?;

        if !signing_keys.is_empty() {
            PasswordStore::verify_gpg_id_file(&pass_home, &signing_keys)?;
        }

        Ok(PasswordStore {
            name: store_name.to_string(),
            root: pass_home,
            valid_gpg_signing_keys: signing_keys,
            passwords: [].to_vec(),
        })
    }

    /// Returns the name of the store, configured to the configuration file
    pub fn get_name(&self) -> &String {
        &self.name
    }

    /// Returns a vec with the keys in the .gog-id file
    pub fn get_valid_gpg_signing_keys(&self) -> &Vec<String> {
        &self.valid_gpg_signing_keys
    }

    /// returns the path to the directory where the store is located.
    pub fn get_store_path(&self) -> String {
        self.root.as_os_str().to_str().unwrap().to_string()
    }

    /// returns true if the store is located in $HOME/.password-store
    pub fn is_default(&self, home: Option<path::PathBuf>) -> bool {
        if self.name == "default" {
            return true;
        }

        if home.is_none() {
            return false;
        }
        let home = home.unwrap();

        let p = self.root.clone();
        let ph = home.join(".password-store");

        p == ph
    }

    /// validates the signature file of the .gpg-id file
    pub fn validate(&self) -> Result<bool> {
        let password_dir = path::Path::new(&self.root);
        if !password_dir.exists() {
            return Err(Error::GenericDyn(format!("path {:?} missing", &self.root)));
        }

        let mut gpg_id_file = password_dir.to_path_buf();
        gpg_id_file.push(".gpg-id");
        if !gpg_id_file.exists() {
            return Err(Error::GenericDyn(format!(
                "path {:?}/.gpg-id missing for store {}",
                &self.root, &self.name
            )));
        }

        if !self.valid_gpg_signing_keys.is_empty() {
            PasswordStore::verify_gpg_id_file(&self.root, &self.valid_gpg_signing_keys)?;
        }

        Ok(true)
    }

    /// resets the store object, so that it points to a different directory.
    pub fn reset(
        &mut self,
        password_store_dir: &str,
        valid_signing_keys: &[String],
        home: &Option<path::PathBuf>,
    ) -> Result<()> {
        let pass_home = password_dir_raw(&Some(password_store_dir.to_string()), home);
        if !pass_home.exists() {
            return Err(Error::Generic("failed to locate password directory"));
        }

        if !valid_signing_keys.is_empty() {
            PasswordStore::verify_gpg_id_file(&pass_home, &valid_signing_keys)?;
        }

        self.root = pass_home;
        self.valid_gpg_signing_keys = (*valid_signing_keys).to_vec();

        let all_passwords = self.all_passwords()?;

        self.passwords = all_passwords;

        Ok(())
    }

    fn repo(&self) -> Result<git2::Repository> {
        git2::Repository::open(self.root.to_path_buf()).map_err(Error::Git)
    }

    fn verify_gpg_id_file(
        pass_home: &path::PathBuf,
        signing_keys: &[String],
    ) -> Result<SignatureStatus> {
        let mut gpg_id_file = pass_home.clone();
        gpg_id_file.push(".gpg-id");
        let mut gpg_id_sig_file = pass_home.clone();
        gpg_id_sig_file.push(".gpg-id.sig");

        let gpg_id = fs::read(gpg_id_file)?;
        let gpg_id_sig = match fs::read(gpg_id_sig_file) {
            Ok(c) => c,
            Err(_) => {
                return Err(Error::Generic(
                    "problem reading .gpg-id.sig, and strict signature checking was asked for",
                ))
            }
        };

        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;

        let result = ctx.verify_detached(gpg_id_sig, gpg_id)?;

        let mut sig_sum = None;

        for (i, sig) in result.signatures().enumerate() {
            let fpr = sig.fingerprint().unwrap();

            if !signing_keys.contains(&fpr.to_string()) {
                return Err(Error::Generic("the .gpg-id file wasn't signed by one of the keys specified in the environmental variable PASSWORD_STORE_SIGNING_KEY"));
            }
            if i == 0 {
                sig_sum = Some(sig.summary());
            } else {
                return Err(Error::Generic("Signature for .gpg-id file contained more than one signature, something is fishy"));
            }
        }

        match sig_sum {
            None => Err(Error::Generic(
                "Missing signature for .gpg-id file, and PASSWORD_STORE_SIGNING_KEY specified",
            )),
            Some(sig_sum) => {
                let sig_status: SignatureStatus = sig_sum.into();
                match sig_status {
                    SignatureStatus::Bad => Err(Error::Generic("Bad signature for .gpg-id file")),
                    _ => Ok(sig_status),
                }
            }
        }
    }

    /// Creates a new password file in the store.
    pub fn new_password_file(&mut self, path_end: &str, content: &str) -> Result<PasswordEntry> {
        let mut path = self.root.clone();

        let c_path = std::fs::canonicalize(path.as_path())?;

        let path_iter = &mut path_end.split('/').peekable();

        while let Some(p) = path_iter.next() {
            if path_iter.peek().is_some() {
                path.push(p);
                let c_file_res = std::fs::canonicalize(path.as_path());
                if let Ok(c_file) = c_file_res {
                    if !c_file.starts_with(c_path.as_path()) {
                        return Err(Error::Generic(
                            "trying to write outside of password store directory",
                        ));
                    }
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

        let mut file = match File::create(path.clone()) {
            Err(why) => return Err(Error::from(why)),
            Ok(file) => file,
        };

        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
        ctx.set_armor(false);

        let mut keys = Vec::new();

        if !self.valid_gpg_signing_keys.is_empty() {
            PasswordStore::verify_gpg_id_file(&self.root, &self.valid_gpg_signing_keys)?;
        }

        let mut recipient_file = self.root.clone();
        recipient_file.push(".gpg-id");
        for recipient in Recipient::all_recipients(&recipient_file)? {
            if recipient.key_ring_status == KeyRingStatus::NotInKeyRing {
                return Err(Error::RecipientNotInKeyRing(recipient.key_id));
            }
            keys.push(ctx.get_key(recipient.key_id)?);
        }

        let mut output = Vec::new();
        ctx.encrypt(&keys, content, &mut output)?;

        if let Err(why) = file.write_all(&output) {
            return Err(Error::from(why));
        }
        let repo = self.repo();
        if repo.is_err() {
            return PasswordEntry::load_from_filesystem(&self.root, &path);
        }
        let repo = repo.unwrap();
        let message = format!("Add password for {} using ripasso", path_end);

        add_and_commit_internal(&repo, &[format!("{}.gpg", path_end)], &message)?;

        Ok(PasswordEntry::load_from_git(&self.root, &path, &repo))
    }

    /// loads the list of passwords from disk again
    pub fn reload_password_list(&mut self) -> Result<()> {
        let mut new_passwords = self.all_passwords()?;

        self.passwords.clear();

        self.passwords.append(&mut new_passwords);

        Ok(())
    }

    /// checks if there is a user name configured in git
    pub fn has_configured_username(&self) -> bool {
        if self.repo().is_err() {
            return true;
        }

        let config = git2::Config::open_default().unwrap();

        let user_name = config.get_string("user.name");

        if user_name.is_err() {
            return false;
        }
        true
    }

    /// Read the password store directory and return a list of all the password files.
    pub fn all_passwords(&self) -> Result<Vec<PasswordEntry>> {
        let mut passwords = vec![];

        let dir = std::fs::canonicalize(&self.root)?;

        let repo = self.repo();
        if repo.is_err() {
            let password_path_glob = dir.join("**/*.gpg");
            let existing_iter = glob::glob(&password_path_glob.to_string_lossy())?;

            for existing_file in existing_iter {
                let pbuf = existing_file?;
                passwords.push(PasswordEntry::load_from_filesystem(&dir, &pbuf)?);
            }

            return Ok(passwords);
        }
        let password_path_glob = dir.join("**/*.gpg");
        let existing_iter = glob::glob(&password_path_glob.to_string_lossy())?;

        let mut files_to_consider: Vec<String> = vec![];
        for existing_file in existing_iter {
            let pbuf = format!("{}", existing_file?.display());
            let filename = pbuf
                .trim_start_matches(format!("{}", dir.display()).as_str())
                .to_string();
            files_to_consider.push(filename.trim_start_matches('/').to_string());
        }

        if files_to_consider.is_empty() {
            return Ok(vec![]);
        }

        let repo = self.repo().unwrap();

        let mut walk = repo.revwalk()?;
        walk.push(repo.head()?.target().unwrap())?;
        let mut last_tree = repo.find_commit(repo.head()?.target().unwrap())?.tree()?;
        let mut last_commit = repo.head()?.peel_to_commit()?;
        for rev in walk {
            if rev.is_err() {
                continue;
            }
            let oid = rev?;

            let commit = repo.find_commit(oid)?;
            let tree = commit.tree()?;

            let diff = repo.diff_tree_to_tree(Some(&last_tree), Some(&tree), None)?;

            diff.foreach(
                &mut |delta: git2::DiffDelta, _f: f32| {
                    let entry_name = format!("{}", delta.new_file().path().unwrap().display());

                    files_to_consider.retain(|filename| {
                        push_password_if_match(
                            filename,
                            &entry_name,
                            &commit,
                            &repo,
                            &dir,
                            &mut passwords,
                            &oid,
                        )
                    });
                    true
                },
                None,
                None,
                None,
            )?;

            last_tree = tree;
            last_commit = commit;
        }

        last_tree
            .walk(git2::TreeWalkMode::PreOrder, |_, entry| {
                let entry_name = entry.name().unwrap().to_string();

                files_to_consider.retain(|filename| {
                    push_password_if_match(
                        filename,
                        &entry_name,
                        &last_commit,
                        &repo,
                        &dir,
                        &mut passwords,
                        &last_commit.id(),
                    )
                });
                git2::TreeWalkResult::Ok
            })
            .unwrap();

        for file in files_to_consider {
            let mut pbuf = dir.clone();
            pbuf.push(file);

            passwords.push(PasswordEntry::new(
                &dir,
                &pbuf,
                Err(Error::Generic("")),
                Err(Error::Generic("")),
                Err(Error::Generic("")),
                RepositoryStatus::NotInRepo,
            ));
        }

        Ok(passwords)
    }

    /// Return a list of all the Recipients in the `$PASSWORD_STORE_DIR/.gpg-id` file.
    pub fn all_recipients(&self) -> Result<Vec<Recipient>> {
        if !self.valid_gpg_signing_keys.is_empty() {
            PasswordStore::verify_gpg_id_file(&self.root, &self.valid_gpg_signing_keys)?;
        }

        let mut recipient_file = self.root.clone();
        recipient_file.push(".gpg-id");
        Recipient::all_recipients(&recipient_file)
    }

    fn recipient_file(&self) -> path::PathBuf {
        let mut rf = self.root.clone();
        rf.push(".gpg-id");
        rf
    }

    /// Removes a key from the .gpg-id file and re-encrypts all the passwords
    pub fn remove_recipient(&self, r: &Recipient) -> Result<()> {
        Recipient::remove_recipient_from_file(
            &r,
            self.recipient_file(),
            &self.valid_gpg_signing_keys,
        )?;
        self.reencrypt_all_password_entries()
    }

    /// Adds a key to the .gpg-id file and re-encrypts all the passwords
    pub fn add_recipient(&self, r: &Recipient) -> Result<()> {
        Recipient::add_recipient_to_file(&r, self.recipient_file(), &self.valid_gpg_signing_keys)?;
        self.reencrypt_all_password_entries()
    }

    /// Reencrypt all the entries in the store, for example when a new collaborator is added
    /// to the team.
    pub fn reencrypt_all_password_entries(&self) -> Result<()> {
        let mut names: Vec<String> = Vec::new();
        for entry in self.all_passwords()? {
            entry.update_internal(entry.secret()?, self)?;
            names.push(format!("{}.gpg", &entry.name));
        }
        names.push(".gpg-id".to_string());

        if self.repo().is_err() {
            return Ok(());
        }

        let mut recipient_file = self.root.clone();
        recipient_file.push(".gpg-id");
        let keys = Recipient::all_recipients(&recipient_file)?
            .into_iter()
            .map(|s| format!("0x{}, ", s.key_id))
            .collect::<String>();
        let message = format!("Reencrypt password store with new GPG ids {}", keys);

        self.add_and_commit(&names, &message)?;

        Ok(())
    }

    /// Add a file to the store, and commit it to the supplied git repository.
    pub fn add_and_commit(&self, paths: &[String], message: &str) -> Result<git2::Oid> {
        let repo = self.repo();
        if repo.is_err() {
            return Err(Error::Generic("must have a repository"));
        }
        let repo = repo.unwrap();

        let mut index = repo.index()?;
        for path in paths {
            index.add_path(path::Path::new(path))?;
        }
        let oid = index.write_tree()?;
        let signature = repo.signature()?;
        let parent_commit_res = find_last_commit(&repo);
        let mut parents = vec![];
        let parent_commit;
        if parent_commit_res.is_ok() {
            parent_commit = parent_commit_res?;
            parents.push(&parent_commit);
        }
        let tree = repo.find_tree(oid)?;

        let oid = commit(&repo, &signature, &message.to_string(), &tree, &parents)?;
        let obj = repo.find_object(oid, None)?;
        repo.reset(&obj, git2::ResetType::Hard, None)?;

        Ok(oid)
    }

    ///Renames a password file to a new name
    ///returns the index in the password vec of the renamed PasswordEntry
    pub fn rename_file(&mut self, old_name: &str, new_name: &str) -> Result<usize> {
        let mut old_path = self.root.clone();
        old_path.push(std::path::PathBuf::from(old_name));
        old_path.set_extension("gpg");
        let mut new_path = self.root.clone();
        new_path.push(std::path::PathBuf::from(new_name));
        new_path.set_extension("gpg");

        if !old_path.exists() {
            return Err(Error::Generic("source file is missing"));
        }

        if new_path.exists() {
            return Err(Error::Generic("can't target file already exists"));
        }

        let mut new_path_dir = new_path.clone();
        new_path_dir.pop();
        fs::create_dir_all(&new_path_dir)?;

        fs::rename(&old_path, &new_path)?;

        if self.repo().is_ok() {
            let old_file_name = format!("{}.gpg", old_name);
            let new_file_name = format!("{}.gpg", new_name);
            move_and_commit(self, &old_file_name, &new_file_name, "moved file")?;
        }

        let passwords = &mut self.passwords;
        let mut index = usize::MAX;
        for (i, entry) in passwords.iter().enumerate() {
            if entry.name == old_name {
                index = i;
            }
        }
        if index != usize::MAX {
            let old_entry = passwords.swap_remove(index);
            let new_entry = PasswordEntry::with_new_name(old_entry, &self.root, &new_path);
            passwords.push(new_entry);
        }

        Ok(passwords.len() - 1)
    }
}

fn push_password_if_match(
    filename: &str,
    entry_name: &str,
    commit: &git2::Commit,
    repo: &git2::Repository,
    dir: &path::PathBuf,
    passwords: &mut Vec<PasswordEntry>,
    oid: &git2::Oid,
) -> bool {
    if *filename == *entry_name {
        let time = commit.time();
        let time_return = Ok(Local.timestamp(time.seconds(), 0));

        let name_return = name_from_commit(commit);

        let signature_return = verify_git_signature(&repo, &oid);

        let mut pbuf: path::PathBuf = (*dir.clone()).to_owned();
        pbuf.push(filename);

        passwords.push(PasswordEntry::new(
            &dir,
            &pbuf,
            time_return,
            name_return,
            signature_return,
            RepositoryStatus::InRepo,
        ));
        return false;
    }
    true
}

/// Find the name of the committer, or an error message
fn name_from_commit(commit: &git2::Commit) -> Result<String> {
    match commit.committer().name() {
        Some(s) => Ok(s.to_string()),
        None => Err(Error::Generic("missing committer name")),
    }
}

/// Describes one log line in the history of a file
pub struct GitLogLine {
    pub message: String,
    pub commit_time: DateTime<Local>,
    pub signature_status: Option<SignatureStatus>,
}

impl GitLogLine {
    pub fn new(
        message: String,
        commit_time: DateTime<Local>,
        signature_status: Option<SignatureStatus>,
    ) -> GitLogLine {
        GitLogLine {
            message,
            commit_time,
            signature_status,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum RepositoryStatus {
    InRepo,
    NotInRepo,
    NoRepo,
}

/// One password in the password store
#[derive(Clone, Debug)]
pub struct PasswordEntry {
    /// Name of the entry
    pub name: String,
    /// Path, relative to the store
    path: path::PathBuf,
    /// if we have a git repo, then commit time
    pub updated: Option<DateTime<Local>>,
    /// if we have a git repo, then the name of the committer
    pub committed_by: Option<String>,
    /// if we have a git repo, and the commit was signed
    pub signature_status: Option<SignatureStatus>,
    filename: String,
    /// describes if the file is in a repository or not
    pub is_in_git: RepositoryStatus,
}

impl PasswordEntry {
    /// constructs a a `PasswordEntry` from the supplied parts
    pub fn new(
        base: &path::PathBuf,
        path: &path::PathBuf,
        update_time: Result<DateTime<Local>>,
        committed_by: Result<String>,
        signature_status: Result<SignatureStatus>,
        is_in_git: RepositoryStatus,
    ) -> PasswordEntry {
        PasswordEntry {
            name: to_name(base, path),
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
            filename: path.to_string_lossy().into_owned(),
            is_in_git,
        }
    }

    /// Consumes an PasswordEntry, and returns a new one with a new name
    pub fn with_new_name(
        old: PasswordEntry,
        base: &path::PathBuf,
        path: &path::PathBuf,
    ) -> PasswordEntry {
        PasswordEntry {
            name: to_name(base, path),
            path: path.to_path_buf(),
            updated: old.updated,
            committed_by: old.committed_by,
            signature_status: old.signature_status,
            filename: path.to_string_lossy().into_owned(),
            is_in_git: old.is_in_git,
        }
    }

    /// creates a `PasswordEntry` by running git blame on the specified path
    pub fn load_from_git(
        base: &path::PathBuf,
        path: &path::PathBuf,
        repo: &git2::Repository,
    ) -> PasswordEntry {
        let (update_time, committed_by, signature_status) = read_git_meta_data(base, path, repo);

        PasswordEntry::new(
            base,
            path,
            update_time,
            committed_by,
            signature_status,
            RepositoryStatus::InRepo,
        )
    }

    /// creates a `PasswordEntry` based on data in the filesystem
    pub fn load_from_filesystem(
        base: &path::PathBuf,
        path: &path::PathBuf,
    ) -> Result<PasswordEntry> {
        Ok(PasswordEntry {
            name: to_name(base, path),
            path: path.to_path_buf(),
            updated: None,
            committed_by: None,
            signature_status: None,
            filename: path.to_string_lossy().into_owned(),
            is_in_git: RepositoryStatus::NoRepo,
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

    fn update_internal(&self, secret: String, store: &PasswordStore) -> Result<()> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;

        let mut keys = Vec::new();
        let recipient_file = {
            let mut rf = store.root.clone();
            rf.push(".gpg-id");
            rf
        };

        for recipient in Recipient::all_recipients(&recipient_file)? {
            if recipient.key_ring_status == KeyRingStatus::NotInKeyRing {
                return Err(Error::RecipientNotInKeyRing(recipient.key_id));
            }
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
    pub fn update(&self, secret: String, store: &PasswordStore) -> Result<()> {
        self.update_internal(secret, &store)?;

        if store.repo().is_err() {
            return Ok(());
        }

        let message = format!("Edit password for {} using ripasso", &self.name);

        store.add_and_commit(&[format!("{}.gpg", &self.name)], &message)?;

        Ok(())
    }

    /// Removes this entry from the filesystem and commit that to git if a repository is supplied.
    pub fn delete_file(&self, store: &PasswordStore) -> Result<()> {
        std::fs::remove_file(&self.filename)?;

        if store.repo().is_err() {
            return Ok(());
        }
        let message = format!("Removed password file for {} using ripasso", &self.name);

        remove_and_commit(store, &[format!("{}.gpg", &self.name)], &message)?;
        Ok(())
    }

    /// Returns a list of log lines for the password, one line for each commit that have changed
    /// that password in some way
    pub fn get_history(&self, store: &PasswordStoreType) -> Result<Vec<GitLogLine>> {
        let repo = {
            let repo_res = (*store).lock().unwrap().repo();
            if repo_res.is_err() {
                return Ok(vec![]);
            }
            repo_res.unwrap()
        };

        let mut revwalk = repo.revwalk()?;

        revwalk.set_sorting(git2::Sort::REVERSE);
        revwalk.set_sorting(git2::Sort::TIME);

        revwalk.push_head()?;

        let mut p = self.path.to_str().unwrap().to_string();
        let root = (*store).lock().unwrap().root.clone();
        let prefix = root.to_str().unwrap().to_string();
        strip_prefix(&mut p, prefix.len());
        let ps = git2::Pathspec::new(vec![&p])?;

        let mut diffopts = git2::DiffOptions::new();
        diffopts.pathspec(&p);

        let walk_res: Vec<GitLogLine> = revwalk
            .filter_map(|id| {
                let oid = id.unwrap();
                let commit = repo.find_commit(oid).unwrap();

                match commit.parents().len() {
                    0 => {
                        let tree = commit.tree().unwrap();
                        let flags = git2::PathspecFlags::NO_MATCH_ERROR;
                        if ps.match_tree(&tree, flags).is_err() {
                            return None;
                        }
                    }
                    _ => {
                        let m = commit.parents().all(|parent| {
                            match_with_parent(&repo, &commit, &parent, &mut diffopts)
                                .unwrap_or(false)
                        });
                        if !m {
                            return None;
                        }
                    }
                }

                let time = commit.time();
                let dt = Local.timestamp(time.seconds(), 0);

                let signature_status = verify_git_signature(&repo, &oid);
                Some(GitLogLine::new(
                    commit.message().unwrap().to_string(),
                    dt,
                    signature_status.ok(),
                ))
            })
            .collect();

        Ok(walk_res)
    }
}

/// returns true if the diff between the two commit's contains the path that the `DiffOptions`
/// have been prepared with
fn match_with_parent(
    repo: &git2::Repository,
    commit: &git2::Commit,
    parent: &git2::Commit,
    opts: &mut git2::DiffOptions,
) -> Result<bool> {
    let a = parent.tree()?;
    let b = commit.tree()?;
    let diff = repo.diff_tree_to_tree(Some(&a), Some(&b), Some(opts))?;
    Ok(diff.deltas().len() > 0)
}

/// removes the pos first characters from a string
/// delete thing function when String.strip_prefix stabilizes
fn strip_prefix(s: &mut String, pos: usize) {
    match s.char_indices().nth(pos) {
        Some((pos, _)) => {
            s.drain(..pos);
        }
        None => {
            s.clear();
        }
    }
}

fn find_last_commit(repo: &git2::Repository) -> Result<git2::Commit> {
    let obj = repo.head()?.resolve()?.peel(git2::ObjectType::Commit)?;
    obj.into_commit()
        .map_err(|_| Error::Generic("Couldn't find commit"))
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

    true
}

/// Apply the changes to the git repository.
fn commit(
    repo: &git2::Repository,
    signature: &git2::Signature,
    message: &str,
    tree: &git2::Tree,
    parents: &[&git2::Commit],
) -> Result<git2::Oid> {
    if should_sign() {
        let commit_buf = repo.commit_create_buffer(
            signature, // author
            signature, // committer
            message,   // commit message
            tree,      // tree
            parents,
        )?; // parents

        let commit_as_str = str::from_utf8(&commit_buf)?.to_string();

        let sig = gpg_sign_string(&commit_as_str)?;

        let commit = repo.commit_signed(&commit_as_str, &sig, Some("gpgsig"))?;
        Ok(commit)
    } else {
        let commit = repo.commit(
            Some("HEAD"), //  point HEAD to our new commit
            signature,    // author
            signature,    // committer
            message,      // commit message
            tree,         // tree
            parents,
        )?; // parents

        Ok(commit)
    }
}

/// Add a file to the store, and commit it to the supplied git repository.
fn add_and_commit_internal(
    repo: &git2::Repository,
    paths: &[String],
    message: &str,
) -> Result<git2::Oid> {
    let mut index = repo.index()?;
    for path in paths {
        index.add_path(path::Path::new(path))?;
    }
    let oid = index.write_tree()?;
    let signature = repo.signature()?;
    let parent_commit_res = find_last_commit(&repo);
    let mut parents = vec![];
    let parent_commit;
    if parent_commit_res.is_ok() {
        parent_commit = parent_commit_res?;
        parents.push(&parent_commit);
    }
    let tree = repo.find_tree(oid)?;

    let oid = commit(&repo, &signature, &message.to_string(), &tree, &parents)?;
    let obj = repo.find_object(oid, None)?;
    repo.reset(&obj, git2::ResetType::Hard, None)?;

    Ok(oid)
}

/// Remove a file from the store, and commit the deletion to the supplied git repository.
fn remove_and_commit(store: &PasswordStore, paths: &[String], message: &str) -> Result<git2::Oid> {
    if store.repo().is_err() {
        return Err(Error::Generic("must have a repository"));
    }
    let repo = store.repo().unwrap();

    let mut index = repo.index()?;
    for path in paths {
        index.remove_path(path::Path::new(path))?;
    }
    let oid = index.write_tree()?;
    let signature = repo.signature()?;
    let parent_commit_res = find_last_commit(&repo);
    let mut parents = vec![];
    let parent_commit;
    if parent_commit_res.is_ok() {
        parent_commit = parent_commit_res?;
        parents.push(&parent_commit);
    }
    let tree = repo.find_tree(oid)?;

    let oid = commit(&repo, &signature, &message.to_string(), &tree, &parents)?;
    let obj = repo.find_object(oid, None)?;
    repo.reset(&obj, git2::ResetType::Hard, None)?;

    Ok(oid)
}

/// Remove a file from the store, and commit the deletion to the supplied git repository.
fn move_and_commit(
    store: &PasswordStore,
    old_name: &str,
    new_name: &str,
    message: &str,
) -> Result<git2::Oid> {
    if store.repo().is_err() {
        return Err(Error::Generic("must have a repository"));
    }
    let repo = store.repo().unwrap();

    let mut index = repo.index()?;
    index.remove_path(path::Path::new(old_name))?;
    index.add_path(path::Path::new(new_name))?;
    let oid = index.write_tree()?;
    let signature = repo.signature()?;
    let parent_commit_res = find_last_commit(&repo);
    let mut parents = vec![];
    let parent_commit;
    if parent_commit_res.is_ok() {
        parent_commit = parent_commit_res?;
        parents.push(&parent_commit);
    }
    let tree = repo.find_tree(oid)?;

    let oid = commit(&repo, &signature, &message.to_string(), &tree, &parents)?;
    let obj = repo.find_object(oid, None)?;
    repo.reset(&obj, git2::ResetType::Hard, None)?;

    Ok(oid)
}

/// find the origin of the git repo, with the following strategy:
/// find the branch that HEAD points to, and read the remote configured for that branch
/// returns the remote and the name of the local branch
fn find_origin(repo: &git2::Repository) -> Result<(git2::Remote, String)> {
    for branch in repo.branches(Some(git2::BranchType::Local))? {
        let b = branch?.0;
        if b.is_head() {
            let upstream_name_buf =
                repo.branch_upstream_remote(&format!("refs/heads/{}", &b.name()?.unwrap()))?;
            let upstream_name = upstream_name_buf.as_str().unwrap();
            let origin = repo.find_remote(&upstream_name)?;
            return Ok((origin, b.name()?.unwrap().to_string()));
        }
    }

    Err(Error::Generic("no remotes configured"))
}

/// function that can be used for callback handling of the ssh interaction in git2
fn cred(
    tried_sshkey: &mut bool,
    _url: &str,
    username: Option<&str>,
    allowed: git2::CredentialType,
) -> std::result::Result<git2::Cred, git2::Error> {
    let sys_username = whoami::username();
    let user = match username {
        Some(name) => name,
        None => &sys_username,
    };

    if allowed.contains(git2::CredentialType::USERNAME) {
        return git2::Cred::username(user);
    }

    if *tried_sshkey {
        return Err(git2::Error::from_str("no authentication available"));
    }
    *tried_sshkey = true;

    git2::Cred::ssh_key_from_agent(user)
}

/// Push your changes to the remote git repository.
pub fn push(store: &PasswordStore) -> Result<()> {
    if store.repo().is_err() {
        return Ok(());
    }
    let repo = store.repo().unwrap();

    let mut ref_status = None;
    let (mut origin, branch_name) = find_origin(&repo)?;
    let res = {
        let mut callbacks = git2::RemoteCallbacks::new();
        let mut tried_ssh_key = false;
        callbacks.credentials(|_url, username, allowed| {
            cred(&mut tried_ssh_key, _url, username, allowed)
        });
        callbacks.push_update_reference(|refname, status| {
            assert_eq!(refname, format!("refs/heads/{}", branch_name));
            ref_status = status.map(|s| s.to_string());
            Ok(())
        });
        let mut opts = git2::PushOptions::new();
        opts.remote_callbacks(callbacks);
        origin.push(&[format!("refs/heads/{}", branch_name)], Some(&mut opts))
    };
    match res {
        Ok(()) if ref_status.is_none() => Ok(()),
        Ok(()) => Err(Error::GenericDyn(format!(
            "failed to push a ref: {:?}",
            ref_status
        ))),
        Err(e) => Err(Error::GenericDyn(format!("failure to push: {}", e))),
    }
}

/// Pull new changes from the remote git repository.
pub fn pull(store: &PasswordStore) -> Result<()> {
    let repo = store.repo();
    if repo.is_err() {
        return Ok(());
    }
    let repo = repo.unwrap();

    let (mut origin, branch_name) = find_origin(&repo)?;

    let mut cb = git2::RemoteCallbacks::new();
    let mut tried_ssh_key = false;
    cb.credentials(|_url, username, allowed| cred(&mut tried_ssh_key, _url, username, allowed));

    let mut opts = git2::FetchOptions::new();
    opts.remote_callbacks(cb);
    origin.fetch(&[branch_name], Some(&mut opts), None)?;

    let remote_oid = repo.refname_to_id("FETCH_HEAD")?;
    let head_oid = repo.refname_to_id("HEAD")?;

    let (_, behind) = repo.graph_ahead_behind(head_oid, remote_oid)?;

    if behind == 0 {
        return Ok(());
    }

    let remote_annotated_commit = repo.find_annotated_commit(remote_oid)?;
    let remote_commit = repo.find_commit(remote_oid)?;
    repo.merge(&[&remote_annotated_commit], None, None)?;

    //commit it
    let mut index = repo.index()?;
    let oid = index.write_tree()?;
    let signature = repo.signature()?;
    let parent_commit = find_last_commit(&repo)?;
    let tree = repo.find_tree(oid)?;
    let message = "pull and merge by ripasso";
    let _commit = repo.commit(
        Some("HEAD"), //  point HEAD to our new commit
        &signature,   // author
        &signature,   // committer
        message,      // commit message
        &tree,        // tree
        &[&parent_commit, &remote_commit],
    )?; // parents

    //cleanup
    repo.cleanup_state()?;
    Ok(())
}

fn read_git_meta_data(
    base: &path::PathBuf,
    path: &path::PathBuf,
    repo: &git2::Repository,
) -> (
    Result<DateTime<Local>>,
    Result<String>,
    Result<SignatureStatus>,
) {
    let path_res = path.strip_prefix(base);
    if path_res.is_err() {
        let e = path_res.err().unwrap();
        return (
            Err(Error::GenericDyn(format!("{:?}", e))),
            Err(Error::GenericDyn(format!("{:?}", e))),
            Err(Error::GenericDyn(format!("{:?}", e))),
        );
    }

    let blame_res = repo.blame_file(path_res.unwrap(), None);
    if blame_res.is_err() {
        let e = blame_res.err().unwrap();
        return (
            Err(Error::GenericDyn(format!("{:?}", e))),
            Err(Error::GenericDyn(format!("{:?}", e))),
            Err(Error::GenericDyn(format!("{:?}", e))),
        );
    }
    let blame = blame_res.unwrap();
    let id_res = blame
        .get_line(1)
        .ok_or(Error::Generic("no git history found"));

    if id_res.is_err() {
        let e = id_res.err().unwrap();
        return (
            Err(Error::GenericDyn(format!("{:?}", e))),
            Err(Error::GenericDyn(format!("{:?}", e))),
            Err(Error::GenericDyn(format!("{:?}", e))),
        );
    }
    let id = id_res.unwrap().orig_commit_id();

    let commit_res = repo.find_commit(id);
    if commit_res.is_err() {
        let e = commit_res.err().unwrap();
        return (
            Err(Error::GenericDyn(format!("{:?}", e))),
            Err(Error::GenericDyn(format!("{:?}", e))),
            Err(Error::GenericDyn(format!("{:?}", e))),
        );
    }
    let commit = commit_res.unwrap();

    let time = commit.time();
    let time_return = Ok(Local.timestamp(time.seconds(), 0));

    let name_return = name_from_commit(&commit);

    let signature_return = verify_git_signature(repo, &id);

    (time_return, name_return, signature_return)
}

fn verify_git_signature(repo: &Repository, id: &Oid) -> Result<SignatureStatus> {
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
            return Err(Error::Generic(
                "If a git contains more than one signature, something is fishy",
            ));
        }
    }

    match sig_sum {
        None => Err(Error::Generic("Missing signature")),
        Some(s) => Ok(s.into()),
    }
}

/// Initialize a git repository for the store.
pub fn init_git_repo(base: &path::PathBuf) -> Result<()> {
    git2::Repository::init(base)?;

    Ok(())
}

/// When setting up a `watch` for the password store directory, events of these types will be sent.
#[derive(Debug)]
pub enum PasswordEvent {
    /// A new password file was created.
    NewPassword(PasswordEntry),
    /// A password file was removed.
    RemovedPassword(path::PathBuf),
    /// An error occurred
    Error(Error),
}

/// Return a list of all passwords whose name contains `query`.
pub fn search(store: &PasswordStoreType, query: &str) -> Result<Vec<PasswordEntry>> {
    let passwords = &(*store).lock().unwrap().passwords;
    fn normalized(s: &str) -> String {
        s.to_lowercase()
    };
    fn matches(s: &str, q: &str) -> bool {
        normalized(s).as_str().contains(normalized(q).as_str())
    };
    let matching = passwords.iter().filter(|p| matches(&p.name, query));
    Ok(matching.cloned().collect())
}

/// Subscribe to events, that happen when password files are added or removed
pub fn watch(store: PasswordStoreType) -> Result<Receiver<PasswordEvent>> {
    let dir = {
        let store_res = (*store).try_lock();
        if store_res.is_err() {
            return Err(Error::GenericDyn(format!("{:?}", store_res.err())));
        }
        let s = store_res.unwrap();

        s.root.clone()
    };

    let (watcher_tx, watcher_rx) = channel();

    // Watcher iterator
    let (event_tx, event_rx): (Sender<PasswordEvent>, Receiver<PasswordEvent>) = channel();

    thread::spawn(move || {
        // Automatically select the best implementation for your platform.
        let mut watcher: notify::RecommendedWatcher =
            Watcher::new(watcher_tx, Duration::from_secs(1)).unwrap();

        // Add a path to be watched. All files and directories at that path and
        // below will be monitored for changes.
        watcher
            .watch(&dir, notify::RecursiveMode::Recursive)
            .unwrap();

        loop {
            match watcher_rx.recv() {
                Ok(event) => {
                    let pass_event = match event {
                        notify::DebouncedEvent::Create(p) => {
                            let ext = p.extension();
                            if ext == None || ext.unwrap() != "gpg" {
                                continue;
                            }

                            let p_e = {
                                let s = (*store).lock().unwrap();
                                if s.repo().is_err() {
                                    PasswordEntry::load_from_filesystem(&s.root, &p.clone())
                                        .unwrap()
                                } else {
                                    PasswordEntry::load_from_git(
                                        &s.root,
                                        &p.clone(),
                                        &s.repo().unwrap(),
                                    )
                                }
                            };
                            PasswordEvent::NewPassword(p_e)
                        }
                        notify::DebouncedEvent::Remove(p) => PasswordEvent::RemovedPassword(p),
                        notify::DebouncedEvent::Error(e, _) => {
                            PasswordEvent::Error(Error::Notify(e))
                        }
                        _ => PasswordEvent::Error(Error::Generic("None")),
                    };

                    if let Err(_err) = event_tx.send(pass_event) {
                        //error!("Error sending event {}", err)
                    }
                }
                Err(e) => {
                    eprintln!("watch error: {:?}", e);
                    panic!("error")
                }
            }
        }
    });
    Ok(event_rx)
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
pub fn password_dir(
    password_store_dir: &Option<String>,
    home: &Option<path::PathBuf>,
) -> Result<path::PathBuf> {
    let pass_home = password_dir_raw(password_store_dir, home);
    if !pass_home.exists() {
        return Err(Error::Generic("failed to locate password directory"));
    }
    Ok(pass_home)
}

/// Determine password directory
pub fn password_dir_raw(
    password_store_dir: &Option<String>,
    home: &Option<path::PathBuf>,
) -> path::PathBuf {
    // If a directory is provided via env var, use it
    let pass_home = match password_store_dir.as_ref() {
        Some(p) => p.clone(),
        None => home
            .as_ref()
            .unwrap()
            .join(".password-store")
            .to_string_lossy()
            .into(),
    };
    path::PathBuf::from(&pass_home)
}

fn home_exists(home: &Option<path::PathBuf>, settings: &config::Config) -> bool {
    if home.is_none() {
        return false;
    }
    let home = home.as_ref().unwrap();
    let home_path = home.join(".password-store");

    let home_dir = home.join(".password-store");
    if home_dir.exists() {
        if !home_dir.is_dir() {
            return false;
        }

        let stores_res = settings.get("stores");
        if let Ok(stores) = stores_res {
            let stores: HashMap<String, config::Value> = stores;

            for store_name in stores.keys() {
                let store: HashMap<String, config::Value> = stores
                    .get(store_name)
                    .unwrap()
                    .clone()
                    .into_table()
                    .unwrap();

                let password_store_dir_opt = store.get("path");
                if let Some(p) = password_store_dir_opt {
                    let p_path = path::PathBuf::from(p.clone().into_str().unwrap());
                    let c1 = std::fs::canonicalize(home_path.clone());
                    let c2 = std::fs::canonicalize(p_path);
                    if c1.is_ok() && c2.is_ok() && c1.unwrap() == c2.unwrap() {
                        return false;
                    }
                }
            }
        }

        return true;
    }

    false
}

fn env_var_exists(store_dir: &Option<String>, signing_keys: &Option<String>) -> bool {
    store_dir.is_some() || signing_keys.is_some()
}

fn settings_file_exists(home: &Option<path::PathBuf>, xdg_config_home: &Option<String>) -> bool {
    if home.is_none() {
        return false;
    }
    let home = home.as_ref().unwrap();

    let xdg_config_file = match xdg_config_home.as_ref() {
        Some(p) => path::PathBuf::from(p).join("ripasso/settings.toml"),
        None => home.join(".config/ripasso/settings.toml"),
    };

    let xdg_config_file_dir = path::Path::new(&xdg_config_file);
    if xdg_config_file_dir.exists() {
        let config_file = fs::metadata(xdg_config_file_dir);
        if config_file.is_err() {
            return false;
        }
        let config_file = config_file.unwrap();

        if config_file.len() == 0 {
            return false;
        }
        return true;
    }

    false
}

fn home_settings(home: &Option<path::PathBuf>) -> Result<config::Config> {
    let mut default_store = std::collections::HashMap::new();

    if home.is_none() {
        return Err(Error::Generic("no home directory set"));
    }
    let home = home.as_ref().unwrap();

    default_store.insert(
        "path".to_string(),
        home.join(".password-store/").to_string_lossy().to_string(),
    );

    let mut stores_map = std::collections::HashMap::new();
    stores_map.insert("default".to_string(), default_store);

    let mut new_settings = config::Config::default();
    new_settings.set("stores", stores_map)?;

    Ok(new_settings)
}

fn var_settings(
    store_dir: &Option<String>,
    signing_keys: &Option<String>,
) -> Result<config::Config> {
    let mut default_store = std::collections::HashMap::new();

    if let Some(dir) = store_dir {
        if dir.ends_with('/') {
            default_store.insert("path".to_string(), dir.clone());
        } else {
            default_store.insert("path".to_string(), dir.clone() + "/");
        }
    }
    if let Some(keys) = signing_keys {
        default_store.insert("valid_signing_keys".to_string(), keys.clone());
    } else {
        default_store.insert("valid_signing_keys".to_string(), "-1".to_owned());
    }

    let mut stores_map = std::collections::HashMap::new();
    stores_map.insert("default".to_string(), default_store);

    let mut new_settings = config::Config::default();
    new_settings.set("stores", stores_map)?;

    Ok(new_settings)
}

fn xdg_config_file_location(
    home: &Option<path::PathBuf>,
    xdg_config_home: &Option<String>,
) -> Result<path::PathBuf> {
    match xdg_config_home.as_ref() {
        Some(p) => Ok(path::PathBuf::from(p).join("ripasso/settings.toml")),
        None => {
            if home.is_none() {
                Err(Error::Generic("no home directory"))
            } else {
                let home = home.as_ref().unwrap();

                Ok(home.join(".config/ripasso/settings.toml"))
            }
        }
    }
}

fn file_settings(xdg_config_file: &path::PathBuf) -> Result<config::File<config::FileSourceFile>> {
    Ok(config::File::from((*xdg_config_file).clone()))
}

/// reads ripasso's config file, in `$XDG_CONFIG_HOME/ripasso/settings.toml`
pub fn read_config(
    store_dir: &Option<String>,
    signing_keys: &Option<String>,
    home: &Option<path::PathBuf>,
    xdg_config_home: &Option<String>,
) -> Result<(config::Config, std::path::PathBuf)> {
    let mut settings = config::Config::default();
    let config_file_location = xdg_config_file_location(home, xdg_config_home)?;

    if settings_file_exists(&home, &xdg_config_home) {
        settings.merge(file_settings(&config_file_location)?)?;
    }

    if home_exists(&home, &settings) {
        settings.merge(home_settings(&home)?)?;
    }

    if env_var_exists(&store_dir, signing_keys) {
        settings.merge(var_settings(store_dir, signing_keys)?)?;
    }

    Ok((settings, config_file_location))
}

pub fn save_config(
    stores: Arc<Mutex<Vec<PasswordStore>>>,
    config_file_location: &std::path::PathBuf,
) -> Result<()> {
    let mut stores_map = std::collections::HashMap::new();
    let stores_borrowed = (*stores).lock().unwrap();
    for store in stores_borrowed.iter() {
        let mut store_map = std::collections::HashMap::new();
        store_map.insert("path", store.get_store_path());
        if !store.get_valid_gpg_signing_keys().is_empty() {
            store_map.insert(
                "valid_signing_keys",
                store.get_valid_gpg_signing_keys().join(","),
            );
        }
        stores_map.insert(store.get_name(), store_map);
    }

    let mut settings = std::collections::HashMap::new();
    settings.insert("stores", stores_map);

    let f = std::fs::File::create(config_file_location)?;
    let mut f = std::io::BufWriter::new(f);
    f.write_all(toml::ser::to_string_pretty(&settings)?.as_bytes())?;

    Ok(())
}

#[cfg(test)]
mod test;
