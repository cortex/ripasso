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

use std::env;
use std::fs;
use std::fs::File;
use std::path;
use std::str;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::Duration;

extern crate xkcd_password;
use self::xkcd_password::Dictionary::en_US as Dictionary;
use self::xkcd_password::generate_password as GeneratePassword;

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

type Result<T> = std::result::Result<T, Error>;

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

#[derive(Clone, Debug)]
pub struct PasswordEntry {
    pub name: String,    // Name of the entry
    pub meta: String,    // Metadata
    path: path::PathBuf, // Path, relative to the store
    base: path::PathBuf, // Base path of password entry
    pub updated: Option<DateTime<Local>>, // if we have a git repo, then commit time
    pub committed_by: Option<String>, // if we have a git repo, then the name of the committer
    filename: String,
}

impl PasswordEntry {
    pub fn secret(&self) -> Result<String> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
        let mut input = File::open(&self.filename)?;
        let mut output = Vec::new();
        ctx.decrypt(&mut input, &mut output)?;
        Ok(String::from_utf8(output)?)
    }

    pub fn password(&self) -> Result<String> {
        Ok(self.secret()?.split('\n').take(1).collect())
    }

    fn update_internal(&self, secret: String) -> Result<()> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;

        let mut keys = Vec::new();

        for recipient in Recipient::all_recipients() {
            keys.push(ctx.get_key(recipient.key_id).unwrap());
        }

        let mut ciphertext = Vec::new();
        ctx.encrypt(&keys, secret, &mut ciphertext)?;

        let mut output = File::create(&self.filename)?;
        output.write_all(&ciphertext)?;
        Ok(())
    }

    pub fn update(&self, secret: String, repo_opt: Arc<Option<git2::Repository>>) -> Result<()> {
        self.update_internal(secret)?;

        if repo_opt.is_none() {
            return Ok(());
        }

        let message = format!("Edit password for {} using ripasso", &self.name);

        add_and_commit(repo_opt, &vec![format!("{}.gpg", &self.name)], &message)?;

        return Ok(());
    }

    pub fn delete_file(&self, repo_opt: Arc<Option<git2::Repository>>) -> Result<()> {
        let res = Ok(std::fs::remove_file(&self.filename)?);

        if repo_opt.is_none() {
            return Ok(());
        }

        let message = format!("Removed password file for {} using ripasso", &self.name);

        remove_and_commit(repo_opt, &vec![format!("{}.gpg", &self.name)], &message)?;

        return res;
    }

    pub fn all_password_entries(repo_opt: Arc<Option<git2::Repository>>) -> Result<Vec<PasswordEntry>> {
        let dir = password_dir()?;

        // Existing files iterator
        let password_path_glob = dir.join("**/*.gpg");
        let paths = glob::glob(&password_path_glob.to_string_lossy()).unwrap();

        let mut passwords = Vec::<PasswordEntry>::new();
        for path in paths {
            match to_password(&dir, &path.unwrap(), repo_opt.clone()) {
                Ok(password) => passwords.push(password),
                Err(e) => return Err(e),
            }
        }

        return Ok(passwords);
    }

    pub fn reencrypt_all_password_entries(repo_opt: Arc<Option<git2::Repository>>) -> Result<()> {
        let mut names: Vec<String> = Vec::new();
        for entry in PasswordEntry::all_password_entries(repo_opt.clone()).unwrap() {
            entry.update_internal(entry.secret()?)?;
            names.push(format!("{}.gpg", &entry.name));
        }
        names.push(".gpg-id".to_string());

        if repo_opt.is_none() {
            return Ok(());
        }

        let keys = Recipient::all_recipients().into_iter().map(|s| format!("0x{}, ", s.key_id)).collect::<String>();
        let message = format!("Reencrypt password store with new GPG ids {}", keys);

        add_and_commit(repo_opt, &names, &message)?;

        return Ok(());
    }
}

fn find_last_commit(repo: &git2::Repository) -> Result<git2::Commit> {
    let obj = repo.head()?.resolve()?.peel(git2::ObjectType::Commit)?;
    obj.into_commit().map_err(|_| Error::Generic("Couldn't find commit"))
}

pub fn should_sign() -> bool {
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

pub fn add_and_commit(repo_opt: Arc<Option<git2::Repository>>, paths: &Vec<String>, message: &str) -> Result<git2::Oid> {
    let mut index = (*repo_opt).as_ref().unwrap().index()?;
    for path in paths {
        index.add_path(path::Path::new(path))?;
    }
    let oid = index.write_tree()?;
    let signature = (*repo_opt).as_ref().unwrap().signature()?;
    let parent_commit_res = find_last_commit((*repo_opt).as_ref().unwrap());
    let mut parents = vec![];
    let parent_commit;
    if !parent_commit_res.is_err() {
        parent_commit = parent_commit_res.unwrap();
        parents.push(&parent_commit);
    }
    let tree = (*repo_opt).as_ref().unwrap().find_tree(oid)?;

    if should_sign() {
        let commit_buf = (*repo_opt).as_ref().unwrap().commit_create_buffer(
            &signature, // author
            &signature, // committer
            message, // commit message
            &tree, // tree
            &parents)?; // parents

        let commit_as_str = str::from_utf8(&commit_buf).unwrap().to_string();

        let sig = gpg_sign_string(&commit_as_str)?;

        let commit = (*repo_opt).as_ref().unwrap().commit_signed(&commit_as_str, &sig, Some("gpgsig"));

        let oid = commit.unwrap();
        let obj = (*repo_opt).as_ref().unwrap().find_object(oid, None).unwrap();
        (*repo_opt).as_ref().unwrap().reset(&obj, git2::ResetType::Hard, None)?;

        return Ok(oid);
    } else {
        let commit = (*repo_opt).as_ref().unwrap().commit(Some("HEAD"), //  point HEAD to our new commit
                                                          &signature, // author
                                                          &signature, // committer
                                                          message, // commit message
                                                          &tree, // tree
                                                          &parents); // parents

        if commit.is_err() {
            return Err(Error::Git(commit.unwrap_err()));
        }

        let oid = commit.unwrap();
        let obj = (*repo_opt).as_ref().unwrap().find_object(oid, None).unwrap();
        let reset = (*repo_opt).as_ref().unwrap().reset(&obj, git2::ResetType::Hard, None);
        if reset.is_err() {
            return Err(Error::Git(reset.unwrap_err()));
        }

        return Ok(oid);
    }
}

fn remove_and_commit(repo_opt: Arc<Option<git2::Repository>>, paths: &Vec<String>, message: &str) -> Result<git2::Oid> {
    let mut index = (*repo_opt).as_ref().unwrap().index()?;
    for path in paths {
        index.remove_path(path::Path::new(path))?;
    }
    let oid = index.write_tree()?;
    let signature = (*repo_opt).as_ref().unwrap().signature()?;
    let parent_commit = find_last_commit((*repo_opt).as_ref().unwrap())?;
    let tree = (*repo_opt).as_ref().unwrap().find_tree(oid)?;
    let commit = (*repo_opt).as_ref().unwrap().commit(Some("HEAD"), //  point HEAD to our new commit
                &signature, // author
                &signature, // committer
                message, // commit message
                &tree, // tree
                &[&parent_commit]); // parents

    if commit.is_err() {
        return Err(Error::Git(commit.unwrap_err()));
    }

    let oid = commit.unwrap();
    let obj = (*repo_opt).as_ref().unwrap().find_object(oid, None).unwrap();
    let reset = (*repo_opt).as_ref().unwrap().reset(&obj, git2::ResetType::Hard, None);
    if reset.is_err() {
        return Err(Error::Git(reset.unwrap_err()));
    }

    return Ok(oid);
}

pub fn push(repo_opt: Arc<Option<git2::Repository>>) -> Result<()> {
    if repo_opt.is_none() {
        return Ok(());
    }

    let mut ref_status = None;
    let mut origin = (*repo_opt).as_ref().unwrap().find_remote("origin")?;
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

pub fn pull(repo_opt: Arc<Option<git2::Repository>>) -> Result<()> {
    if repo_opt.is_none() {
        return Ok(());
    }

    let mut remote = (*repo_opt).as_ref().unwrap().find_remote("origin")?;

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

    let remote_oid = (*repo_opt).as_ref().unwrap().refname_to_id("refs/remotes/origin/master")?;
    let head_oid = (*repo_opt).as_ref().unwrap().refname_to_id("HEAD")?;

    let (_, behind) = (*repo_opt).as_ref().unwrap().graph_ahead_behind(head_oid, remote_oid)?;

    if behind == 0 {
        return Ok(());
    }

    let remote_annotated_commit = (*repo_opt).as_ref().unwrap().find_annotated_commit(remote_oid)?;
    let remote_commit = (*repo_opt).as_ref().unwrap().find_commit(remote_oid)?;
    (*repo_opt).as_ref().unwrap().merge(&vec![&remote_annotated_commit], None, None)?;

    //commit it
    let mut index = (*repo_opt).as_ref().unwrap().index()?;
    let oid = index.write_tree()?;
    let signature = (*repo_opt).as_ref().unwrap().signature()?;
    let parent_commit = find_last_commit(&(*repo_opt).as_ref().unwrap())?;
    let tree = (*repo_opt).as_ref().unwrap().find_tree(oid)?;
    let message = "pull and merge by ripasso";
    let _commit = (*repo_opt).as_ref().unwrap().commit(Some("HEAD"), //  point HEAD to our new commit
                             &signature, // author
                             &signature, // committer
                             message, // commit message
                             &tree, // tree
                             &[&parent_commit, &remote_commit])?; // parents

    //cleanup
    (*repo_opt).as_ref().unwrap().cleanup_state()?;
    return Ok(());
}

pub struct Recipient {
    pub name: String,
    pub key_id: String,
}

fn build_recipient(name: String, key_id: String) -> Recipient {
    Recipient {
        name: name,
        key_id: key_id,
    }
}

impl Recipient {
    pub fn from_key_id(key_id: String) -> Result<Recipient> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp).unwrap();

        let key_option = ctx.get_key(key_id.clone());
        if key_option.is_err() {
            return Err(Error::Generic("Can't find key in keyring, please import it first"));
        }

        let real_key = key_option.unwrap();

        let mut name = "?";
        for user_id in real_key.user_ids() {
            name = user_id.name().unwrap_or("?");
        }

        return Ok(build_recipient(name.to_string(), key_id));
    }

    pub fn all_recipients() -> Vec<Recipient> {

        let mut recipient_file = password_dir().unwrap();
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

        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp).unwrap();

        for key in unique_recipients_keys {
            let key_option = ctx.get_key(key.clone());
            if key_option.is_err() {
                continue;
            }

            let real_key = key_option.unwrap();

            let mut name = "?";
            for user_id in real_key.user_ids() {
                name = user_id.name().unwrap_or("?");
            }
            recipients.push(build_recipient(name.to_string(), real_key.id().unwrap_or("?").to_string()));
        }

        return recipients;
    }

    fn write_recipients_file(recipients: &Vec<Recipient>, repo_opt: Arc<Option<git2::Repository>>) -> Result<()> {
        let mut recipient_file = password_dir().unwrap();
        recipient_file.push(".gpg-id");

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(recipient_file)
            .unwrap();

        for recipient in recipients {
            if !recipient.key_id.starts_with("0x") {
                file.write_all(b"0x")?;
            }
            file.write_all(recipient.key_id.as_bytes())?;
            file.write_all(b"\n")?;
        }

        PasswordEntry::reencrypt_all_password_entries(repo_opt)?;

        return Ok(());
    }

    pub fn remove_recipient_from_file(s: &Recipient, repo_opt: Arc<Option<git2::Repository>>) -> Result<()> {
        let mut recipients: Vec<Recipient> = Recipient::all_recipients();

        recipients.retain(|ref vs| vs.key_id != s.key_id);

        if recipients.len() < 1 {
            return Err(Error::Generic("Can't delete the last encryption key"));
        }

        return Recipient::write_recipients_file(&recipients, repo_opt);
    }

    pub fn add_recipient_to_file(s: &Recipient, repo_opt: Arc<Option<git2::Repository>>) -> Result<()> {
        let mut recipients: Vec<Recipient> = Recipient::all_recipients();

        for recipient in &recipients {
            if recipient.key_id == s.key_id {
                return Err(Error::Generic("Recipient is already in the list of key ids"));
            }
        }

        recipients.push(build_recipient(s.name.clone(), s.key_id.clone()));

        return Recipient::write_recipients_file(&recipients, repo_opt);
    }
}

fn updated(base: &path::PathBuf, path: &path::PathBuf, repo_opt: Arc<Option<git2::Repository>>) -> Result<DateTime<Local>> {
    if repo_opt.is_none() {
        return Err(Error::Generic("need repository to have DateTime information"));
    }

    let blame = (*repo_opt).as_ref().unwrap().blame_file(path.strip_prefix(base)?, None)?;
    let id = blame
        .get_line(1)
        .ok_or(Error::Generic("no git history found"))?
        .orig_commit_id();
    let time = (*repo_opt).as_ref().unwrap().find_commit(id)?.time();
    Ok(Local.timestamp(time.seconds(), 0))
}

fn committed_by(base: &path::PathBuf, path: &path::PathBuf, repo_opt: Arc<Option<git2::Repository>>) -> Result<String> {
    if repo_opt.is_none() {
        return Err(Error::Generic("need repository to have DateTime information"));
    }

    let blame = (*repo_opt).as_ref().unwrap().blame_file(path.strip_prefix(base)?, None)?;
    let id = blame
        .get_line(1)
        .ok_or(Error::Generic("no git history found"))?
        .orig_commit_id();

    match (*repo_opt).as_ref().unwrap().find_commit(id)?.committer().name() {
        Some(s) => Ok(s.to_string()),
        None => Err(Error::Generic("missing committer name"))
    }
}

pub fn new_password_file(path_end: std::rc::Rc<String>, content: std::rc::Rc<String>, repo_opt: Arc<Option<git2::Repository>>) -> Result<()> {
    let mut path = password_dir()?;

    let path_deref = (*path_end).clone();
    let path_iter = &mut path_deref.split("/").peekable();

    while let Some(p) = path_iter.next() {
        if path_iter.peek().is_some() {
            path.push(p);
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

    for recipient in Recipient::all_recipients() {
        keys.push(ctx.get_key(recipient.key_id).unwrap());
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

pub fn init_git_repo(base: &path::PathBuf) -> Result<()> {
    git2::Repository::init(base)?;

    return Ok(());
}

#[derive(Debug)]
pub enum PasswordEvent {
    NewPassword(PasswordEntry),
    RemovedPassword(path::PathBuf),
    Error(Error),
}

pub type PasswordList = Arc<Mutex<Vec<PasswordEntry>>>;

pub fn search(l: &PasswordList, query: &str) -> Vec<PasswordEntry> {
    let passwords = l.lock().unwrap();
    fn normalized(s: &str) -> String {
        s.to_lowercase()
    };
    fn matches(s: &str, q: &str) -> bool {
        normalized(s).as_str().contains(normalized(q).as_str())
    };
    let matching = passwords.iter().filter(|p| matches(&p.name, query));
    matching.cloned().collect()
}

pub fn populate_password_list(passwords: &PasswordList, repo_opt: Arc<Option<git2::Repository>>) -> Result<()> {
    let dir = password_dir()?;

    let password_path_glob = dir.join("**/*.gpg");
    let existing_iter = glob::glob(&password_path_glob.to_string_lossy()).unwrap();

    (passwords.lock().unwrap()).clear();
    for existing_file in existing_iter {
        let pbuf = existing_file.unwrap();
        (passwords.lock().unwrap()).push(to_password(&dir, &pbuf, repo_opt.clone())?);
    }

    Ok(())
}

pub fn watch(repo_opt: Arc<Option<git2::Repository>>) -> Result<(Receiver<PasswordEvent>, PasswordList)> {
    let dir = password_dir()?;

    let (watcher_tx, watcher_rx) = channel();

    // Watcher iterator
    let (event_tx, event_rx): (
        Sender<PasswordEvent>,
        Receiver<PasswordEvent>,
    ) = channel();

    let passwords = Arc::new(Mutex::new(Vec::<PasswordEntry>::new()));
    let passwords_out = passwords.clone();

    populate_password_list(&passwords_out, repo_opt)?;

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

                            let repo_opt = Arc::new(git2::Repository::open(password_dir().unwrap()).ok());
                            let p_e = to_password(&password_dir().unwrap(), &p.clone(), repo_opt).unwrap();
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

pub fn generate_password(length: usize) -> String {
    return GeneratePassword(length, Dictionary).trim().to_string();
}

fn to_name(base: &path::PathBuf, path: &path::PathBuf) -> String {
    path.strip_prefix(base)
        .unwrap()
        .to_string_lossy()
        .into_owned()
        .trim_end_matches(".gpg")
        .to_string()
}

pub fn to_password(base: &path::PathBuf, path: &path::PathBuf, repo_opt: Arc<Option<git2::Repository>>) -> Result<PasswordEntry> {
    Ok(PasswordEntry {
        name: to_name(base, path),
        meta: "".to_string(),
        base: base.to_path_buf(),
        path: path.to_path_buf(),
        updated: match updated(base, path, repo_opt.clone()) {
            Ok(p) => Some(p),
            Err(_) => None,
        },
        committed_by: match committed_by(base, path, repo_opt) {
            Ok(p) => Some(p),
            Err(_) => None,
        },
        filename: path.to_string_lossy().into_owned().clone(),
    })
}

/// Determine password directory
pub fn password_dir() -> Result<path::PathBuf> {
    let pass_home = password_dir_raw();
    if !pass_home.exists() {
        return Err(Error::Generic("failed to locate password directory"));
    }
    Ok(pass_home.to_path_buf())
}

pub fn password_dir_raw() -> path::PathBuf {
    // If a directory is provided via env var, use it
    let pass_home = match env::var("PASSWORD_STORE_DIR") {
        Ok(p) => p,
        Err(_) => dirs::home_dir()
            .unwrap()
            .join(".password-store")
            .to_string_lossy()
            .into(),
    };
    return path::PathBuf::from(&pass_home);
}

#[cfg(test)]
mod test;
