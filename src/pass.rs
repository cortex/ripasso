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
use notify::Watcher;
use std::io::prelude::*;
use std::sync::{Arc, Mutex};
extern crate dirs;

use git2::{Oid, Repository};

pub use crate::error::{Error, Result};
pub use crate::signature::{
    gpg_sign_string, parse_signing_keys, KeyRingStatus, OwnerTrustLevel,
    Recipient, SignatureStatus,
};

/// The global state of all passwords are an instance of this type.
pub type PasswordStoreType = Arc<Mutex<PasswordStore>>;

/// Represents a complete password store directory
pub struct PasswordStore {
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
        password_store_dir: &Option<String>,
        password_store_signing_key: &Option<String>,
    ) -> Result<PasswordStore> {
        let pass_home = password_dir_raw(password_store_dir);
        if !pass_home.exists() {
            return Err(Error::Generic("failed to locate password directory"));
        }

        //let all_passwords = create_password_list(&repo_opt, &pass_home)?;

        let signing_keys = parse_signing_keys(password_store_signing_key)?;

        if !signing_keys.is_empty() {
            PasswordStore::verify_gpg_id_file(&pass_home, &signing_keys)?;
        }

        Ok(PasswordStore {
            root: pass_home,
            valid_gpg_signing_keys: signing_keys,
            passwords: [].to_vec(),
        })
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
        let gpg_id_sig = fs::read(gpg_id_sig_file)?;

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

        if sig_sum.is_none() {
            return Err(Error::Generic("Missing signature for .gpg-id file, and PASSWORD_STORE_SIGNING_KEY specified"));
        }

        let sig_sum = sig_sum.unwrap();

        if sig_sum.contains(gpgme::SignatureSummary::GREEN) {
            Ok(SignatureStatus::GoodSignature)
        } else if sig_sum.contains(gpgme::SignatureSummary::VALID) {
            Ok(SignatureStatus::AlmostGoodSignature)
        } else {
            Err(Error::Generic("Bad signature for .gpg-id file"))
        }
    }

    /// Creates a new password file in the store.
    pub fn new_password_file(
        &mut self,
        path_end: &str,
        content: &str,
    ) -> Result<PasswordEntry> {
        let mut path = self.root.clone();

        let c_path = std::fs::canonicalize(path.as_path())?;

        let path_iter = &mut path_end.split('/').peekable();

        while let Some(p) = path_iter.next() {
            if path_iter.peek().is_some() {
                path.push(p);
                let c_file_res = std::fs::canonicalize(path.as_path());
                if c_file_res.is_ok() {
                    let c_file = c_file_res.unwrap();
                    if !c_file.starts_with(c_path.as_path()) {
                        return Err(Error::Generic("trying to write outside of password store directory"));
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
            PasswordStore::verify_gpg_id_file(
                &self.root,
                &self.valid_gpg_signing_keys,
            )?;
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

        add_and_commit_internal(
            &repo,
            &[format!("{}.gpg", path_end)],
            &message,
        )?;

        PasswordEntry::load_from_git(&self.root, &path, &repo)
    }

    pub fn reload_password_list(&mut self) -> Result<()> {
        let mut new_passwords = self.all_passwords()?;

        self.passwords.clear();

        self.passwords.append(&mut new_passwords);

        Ok(())
    }

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

        let dir = self.root.clone();

        let repo = self.repo();
        if repo.is_err() {
            let password_path_glob = dir.join("**/*.gpg");
            let existing_iter =
                glob::glob(&password_path_glob.to_string_lossy())?;

            for existing_file in existing_iter {
                let pbuf = existing_file?;
                passwords
                    .push(PasswordEntry::load_from_filesystem(&dir, &pbuf)?);
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
            files_to_consider
                .push(filename.trim_start_matches('/').to_string());
        }

        if files_to_consider.is_empty() {
            return Ok(vec![]);
        }

        let repo = self.repo().unwrap();

        let mut walk = repo.revwalk()?;
        walk.push(repo.head()?.target().unwrap())?;
        let mut last_tree =
            repo.find_commit(repo.head()?.target().unwrap())?.tree()?;
        for rev in walk {
            let oid = rev?;

            let commit = repo.find_commit(oid)?;
            let tree = commit.tree()?;

            let diff =
                repo.diff_tree_to_tree(Some(&last_tree), Some(&tree), None)?;

            diff.foreach(
                &mut |delta: git2::DiffDelta, _f: f32| {
                    let entry_name = format!(
                        "{}",
                        delta.new_file().path().unwrap().display()
                    );
                    files_to_consider.retain(|filename| {
                        if *filename == entry_name {
                            let time = commit.time();
                            let time_return =
                                Ok(Local.timestamp(time.seconds(), 0));

                            let name_return: Result<String> =
                                match commit.committer().name() {
                                    Some(s) => Ok(s.to_string()),
                                    None => Err(Error::Generic(
                                        "missing committer name",
                                    )),
                                };

                            let signature_return =
                                verify_git_signature(&repo, &oid);

                            let mut pbuf = dir.clone();
                            pbuf.push(filename);

                            passwords.push(PasswordEntry::new(
                                &dir,
                                &pbuf,
                                time_return,
                                name_return,
                                signature_return,
                            ));
                            return false;
                        }
                        true
                    });
                    true
                },
                None,
                None,
                None,
            )?;

            last_tree = tree;
        }

        Ok(passwords)
    }

    /// Return a list of all the Recipients in the `$PASSWORD_STORE_DIR/.gpg-id` file.
    pub fn all_recipients(&self) -> Result<Vec<Recipient>> {
        if !self.valid_gpg_signing_keys.is_empty() {
            PasswordStore::verify_gpg_id_file(
                &self.root,
                &self.valid_gpg_signing_keys,
            )?;
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

    pub fn remove_recipient(&self, r: &Recipient) -> Result<()> {
        Recipient::remove_recipient_from_file(
            &r,
            self.recipient_file(),
            &self.valid_gpg_signing_keys,
        )?;
        self.reencrypt_all_password_entries()
    }

    pub fn add_recipient(&self, r: &Recipient) -> Result<()> {
        Recipient::add_recipient_to_file(
            &r,
            self.recipient_file(),
            &self.valid_gpg_signing_keys,
        )?;
        self.reencrypt_all_password_entries()
    }

    /// Reencrypt all the entries in the store, for example when a new collaborator is added
    /// to the team.
    pub fn reencrypt_all_password_entries(&self) -> Result<()> {
        let mut names: Vec<String> = Vec::new();
        for entry in self.all_password_entries()? {
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
        let message =
            format!("Reencrypt password store with new GPG ids {}", keys);

        self.add_and_commit(&names, &message)?;

        Ok(())
    }

    /// Returns a list of all password entries in the store.
    pub fn all_password_entries(&self) -> Result<Vec<PasswordEntry>> {
        let dir = self.root.clone();

        // Existing files iterator
        let password_path_glob = dir.join("**/*.gpg");
        let paths = glob::glob(&password_path_glob.to_string_lossy())?;

        let mut passwords = Vec::<PasswordEntry>::new();
        for path in paths {
            if self.repo().is_err() {
                match PasswordEntry::load_from_git(
                    &dir,
                    &path?,
                    &self.repo().unwrap(),
                ) {
                    Ok(password) => passwords.push(password),
                    Err(e) => return Err(e),
                }
            } else {
                match PasswordEntry::load_from_filesystem(&dir, &path?) {
                    Ok(password) => passwords.push(password),
                    Err(e) => return Err(e),
                }
            }
        }

        Ok(passwords)
    }

    /// Add a file to the store, and commit it to the supplied git repository.
    pub fn add_and_commit(
        &self,
        paths: &[String],
        message: &str,
    ) -> Result<git2::Oid> {
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

        let oid =
            commit(&repo, &signature, &message.to_string(), &tree, &parents)?;
        let obj = repo.find_object(oid, None)?;
        repo.reset(&obj, git2::ResetType::Hard, None)?;

        Ok(oid)
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
}

impl PasswordEntry {
    /// constructs a a `PasswordEntry` from the supplied parts
    pub fn new(
        base: &path::PathBuf,
        path: &path::PathBuf,
        update_time: Result<DateTime<Local>>,
        committed_by: Result<String>,
        signature_status: Result<SignatureStatus>,
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
        }
    }

    /// creates a `PasswordEntry` by running git blame on the specified path
    pub fn load_from_git(
        base: &path::PathBuf,
        path: &path::PathBuf,
        repo: &git2::Repository,
    ) -> Result<PasswordEntry> {
        let (update_time, committed_by, signature_status) =
            read_git_meta_data(base, path, repo);

        Ok(PasswordEntry::new(
            base,
            path,
            update_time,
            committed_by,
            signature_status,
        ))
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

    fn update_internal(
        &self,
        secret: String,
        store: &PasswordStore,
    ) -> Result<()> {
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
        let message =
            format!("Removed password file for {} using ripasso", &self.name);

        remove_and_commit(store, &[format!("{}.gpg", &self.name)], &message)?;
        Ok(())
    }

    /// Returns a list of log lines for the password, one line for each commit that hade changed
    /// that password in some way
    pub fn get_history(
        &self,
        store: &PasswordStoreType,
    ) -> Result<Vec<GitLogLine>> {
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
                let commit = repo.find_commit(id.unwrap()).unwrap();

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
                            match_with_parent(
                                &repo,
                                &commit,
                                &parent,
                                &mut diffopts,
                            )
                            .unwrap_or(false)
                        });
                        if !m {
                            return None;
                        }
                    }
                }

                let time = commit.time();
                let dt = Local.timestamp(time.seconds(), 0);
                Some(GitLogLine::new(
                    commit.message().unwrap().to_string(),
                    dt,
                    None,
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

        let commit =
            repo.commit_signed(&commit_as_str, &sig, Some("gpgsig"))?;
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
fn remove_and_commit(
    store: &PasswordStore,
    paths: &[String],
    message: &str,
) -> Result<git2::Oid> {
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

/// find the origin of the git repo, with the following strategy:
/// first try the name `origin`, if that doesn't exist, list the available remotes and
/// choose the first one
fn find_origin(repo: &git2::Repository) -> Result<git2::Remote> {
    let mut origin_res = repo.find_remote("origin");
    if origin_res.is_err() {
        let remotes = repo.remotes()?;
        if remotes.is_empty() {
            return Err(Error::Generic("no remotes configured"));
        }
        origin_res = repo.find_remote(remotes.get(0).unwrap());
        if origin_res.is_err() {
            return Err(Error::Generic("error finding configured remote"));
        }
    }
    Ok(origin_res?)
}

/// Push your changes to the remote git repository.
pub fn push(store: &PasswordStore) -> Result<()> {
    if store.repo().is_err() {
        return Ok(());
    }
    let repo = store.repo().unwrap();

    let mut ref_status = None;
    let mut origin = find_origin(&repo)?;
    let res = {
        let mut callbacks = git2::RemoteCallbacks::new();
        let mut tried_sshkey = false;
        callbacks.credentials(|_url, username, allowed| {
            let sys_username = whoami::username();
            let user = match username {
                Some(name) => name,
                None => &sys_username,
            };

            if tried_sshkey {
                return Err(git2::Error::from_str(
                    "no authentication available",
                ));
            }
            tried_sshkey = true;
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

    let mut origin = find_origin(&repo)?;

    let mut cb = git2::RemoteCallbacks::new();
    let mut tried_sshkey = false;
    cb.credentials(|_url, username, allowed| {
        let sys_username = whoami::username();
        let user = match username {
            Some(name) => name,
            None => &sys_username,
        };

        if tried_sshkey {
            return Err(git2::Error::from_str("no authentication available"));
        }
        tried_sshkey = true;
        if allowed.contains(git2::CredentialType::USERNAME) {
            return git2::Cred::username(user);
        }

        git2::Cred::ssh_key_from_agent(user)
    });

    let mut opts = git2::FetchOptions::new();
    opts.remote_callbacks(cb);
    origin.fetch(&["master"], Some(&mut opts), None)?;

    let remote_oid = repo.refname_to_id("refs/remotes/origin/master")?;
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

    let name_return: Result<String> = match commit.committer().name() {
        Some(s) => Ok(s.to_string()),
        None => Err(Error::Generic("missing committer name")),
    };

    let signature_return = verify_git_signature(repo, &id);

    (time_return, name_return, signature_return)
}

fn verify_git_signature(
    repo: &Repository,
    id: &Oid,
) -> Result<SignatureStatus> {
    let (signature, signed_data) =
        repo.extract_signature(&id, Some("gpgsig"))?;

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

    if sig_sum.is_none() {
        return Err(Error::Generic("Missing signature"));
    }

    let sig_sum = sig_sum.unwrap();

    if sig_sum.contains(gpgme::SignatureSummary::VALID) {
        Ok(SignatureStatus::GoodSignature)
    } else if sig_sum.contains(gpgme::SignatureSummary::GREEN) {
        Ok(SignatureStatus::AlmostGoodSignature)
    } else {
        Ok(SignatureStatus::BadSignature)
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
    /// An error occured
    Error(Error),
}

/// Return a list of all passwords whose name contains `query`.
pub fn search(
    store: &PasswordStoreType,
    query: &str,
) -> Result<Vec<PasswordEntry>> {
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
    let (event_tx, event_rx): (Sender<PasswordEvent>, Receiver<PasswordEvent>) =
        channel();

    thread::spawn(move || {
        info!("Starting thread");

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
                                    PasswordEntry::load_from_filesystem(
                                        &s.root,
                                        &p.clone(),
                                    )
                                    .unwrap()
                                } else {
                                    PasswordEntry::load_from_git(
                                        &s.root,
                                        &p.clone(),
                                        &s.repo().unwrap(),
                                    )
                                    .unwrap()
                                }
                            };
                            PasswordEvent::NewPassword(p_e)
                        }
                        notify::DebouncedEvent::Remove(p) => {
                            PasswordEvent::RemovedPassword(p)
                        }
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
) -> Result<path::PathBuf> {
    let pass_home = password_dir_raw(password_store_dir);
    if !pass_home.exists() {
        return Err(Error::Generic("failed to locate password directory"));
    }
    Ok(pass_home)
}

/// Determine password directory
pub fn password_dir_raw(password_store_dir: &Option<String>) -> path::PathBuf {
    // If a directory is provided via env var, use it
    let pass_home = match password_store_dir.as_ref() {
        Some(p) => p.clone(),
        None => dirs::home_dir()
            .unwrap()
            .join(".password-store")
            .to_string_lossy()
            .into(),
    };
    path::PathBuf::from(&pass_home)
}

#[cfg(test)]
mod test;
