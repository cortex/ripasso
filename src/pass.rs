/*  Ripasso - a simple password manager
    Copyright (C) 2018 Joakim Lundborg

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

extern crate rand;
use pass::rand::{thread_rng, Rng};
use pass::rand::distributions::Alphanumeric;

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
    pub updated: Option<DateTime<Local>>,
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

        for signer in Signer::all_signers() {
            keys.push(ctx.get_key(signer.key_id).unwrap());
        }

        let mut ciphertext = Vec::new();
        ctx.encrypt(&keys, secret, &mut ciphertext)?;

        let mut output = File::create(&self.filename)?;
        output.write_all(&ciphertext)?;
        Ok(())
    }

    pub fn update(&self, secret: String) -> Result<()> {
        self.update_internal(secret)?;

        let repo_res = git2::Repository::open(password_dir().unwrap());

        if repo_res.is_err() {
            return Ok(());
        }

        let repo = repo_res.unwrap();

        let message = format!("Edit password for {} using ripasso", &self.name);

        add_and_commit(&repo, &vec![format!("{}.gpg", &self.name)], &message)?;

        return Ok(());
    }

    pub fn delete_file(&self) -> Result<()> {
        let res = Ok(std::fs::remove_file(&self.filename)?);

        let repo_res = git2::Repository::open(password_dir().unwrap());

        if repo_res.is_err() {
            return Ok(());
        }

        let repo = repo_res.unwrap();

        let message = format!("Removed password file for {} using ripasso", &self.name);

        remove_and_commit(&repo, &vec![format!("{}.gpg", &self.name)], &message)?;

        return res;
    }

    pub fn all_password_entries() -> Result<Vec<PasswordEntry>> {
        let dir = password_dir()?;

        // Existing files iterator
        let password_path_glob = dir.join("**/*.gpg");
        let paths = glob::glob(&password_path_glob.to_string_lossy()).unwrap();

        let mut passwords = Vec::<PasswordEntry>::new();
        for path in paths {
            match to_password(&dir, &path.unwrap()) {
                Ok(password) => passwords.push(password),
                Err(e) => return Err(e),
            }
        }

        return Ok(passwords);
    }

    pub fn reencrypt_all_password_entries() -> Result<()> {
        let mut names: Vec<String> = Vec::new();
        for entry in PasswordEntry::all_password_entries().unwrap() {
            entry.update_internal(entry.secret()?)?;
            names.push(format!("{}.gpg", &entry.name));
        }
        names.push(".gpg-id".to_string());

        let repo_res = git2::Repository::open(password_dir().unwrap());

        if repo_res.is_err() {
            return Ok(());
        }

        let repo = repo_res.unwrap();

        let keys = Signer::all_signers().into_iter().map(|s| format!("0x{}, ", s.key_id)).collect::<String>();
        let message = format!("Reencrypt password store with new GPG ids {}", keys);

        add_and_commit(&repo, &names, &message)?;

        return Ok(());
    }
}

fn find_last_commit(repo: &git2::Repository) -> Result<git2::Commit> {
    let obj = repo.head()?.resolve()?.peel(git2::ObjectType::Commit)?;
    obj.into_commit().map_err(|_| Error::Generic("Couldn't find commit"))
}

fn add_and_commit(repo: &git2::Repository, paths: &Vec<String>, message: &str) -> Result<git2::Oid> {
    let mut index = repo.index()?;
    for path in paths {
        index.add_path(path::Path::new(path))?;
    }
    let oid = index.write_tree()?;
    let signature = repo.signature()?;
    let parent_commit = find_last_commit(&repo)?;
    let tree = repo.find_tree(oid)?;
    let commit = repo.commit(Some("HEAD"), //  point HEAD to our new commit
                &signature, // author
                &signature, // committer
                message, // commit message
                &tree, // tree
                &[&parent_commit]); // parents

    if commit.is_err() {
        return Err(Error::Git(commit.unwrap_err()));
    }

    return Ok(commit.unwrap());
}

fn remove_and_commit(repo: &git2::Repository, paths: &Vec<String>, message: &str) -> Result<git2::Oid> {
    let mut index = repo.index()?;
    for path in paths {
        index.remove_path(path::Path::new(path))?;
    }
    let oid = index.write_tree()?;
    let signature = repo.signature()?;
    let parent_commit = find_last_commit(&repo)?;
    let tree = repo.find_tree(oid)?;
    let commit = repo.commit(Some("HEAD"), //  point HEAD to our new commit
                &signature, // author
                &signature, // committer
                message, // commit message
                &tree, // tree
                &[&parent_commit]); // parents

    if commit.is_err() {
        return Err(Error::Git(commit.unwrap_err()));
    }

    return Ok(commit.unwrap());
}

pub struct Signer {
    pub name: String,
    pub key_id: String,
}

fn build_signer(name: String, key_id: String) -> Signer {
    Signer {
        name: name,
        key_id: key_id,
    }
}

impl Signer {
    pub fn from_key_id(key_id: String) -> Result<Signer> {
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

        return Ok(build_signer(name.to_string(), key_id));
    }

    pub fn all_signers() -> Vec<Signer> {

        let mut signer_file = password_dir().unwrap();
        signer_file.push(".gpg-id");
        let contents = fs::read_to_string(signer_file)
            .expect("Something went wrong reading the file");

        let mut signers : Vec<Signer> = Vec::new();
        let mut unique_signers_keys : HashSet<String> = HashSet::new();
        for key in contents.split("\n") {
            if key.len() > 1 {
                unique_signers_keys.insert(key.to_string());
            }
        }

        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp).unwrap();

        for key in unique_signers_keys {
            let mut key_option = ctx.get_key(key.clone());
            if key_option.is_err() {
                continue;
            }

            let mut real_key = key_option.unwrap();

            let mut name = "?";
            for user_id in real_key.user_ids() {
                name = user_id.name().unwrap_or("?");
            }
            signers.push(build_signer(name.to_string(), real_key.id().unwrap_or("?").to_string()));
        }

        return signers;
    }

    fn write_signers_file(signers: &Vec<Signer>) -> Result<()> {
        let mut signer_file = password_dir().unwrap();
        signer_file.push(".gpg-id");

        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(signer_file)
            .unwrap();

        for signer in signers {
            if !signer.key_id.starts_with("0x") {
                file.write_all(b"0x")?;
            }
            file.write_all(signer.key_id.as_bytes())?;
            file.write_all(b"\n")?;
        }

        PasswordEntry::reencrypt_all_password_entries()?;

        return Ok(());
    }

    pub fn remove_signer_from_file(s: &Signer) -> Result<()> {
        let mut signers: Vec<Signer> = Signer::all_signers();

        signers.retain(|ref vs| vs.key_id != s.key_id);

        if signers.len() < 1 {
            return Err(Error::Generic("Can't delete the last signing key"));
        }

        return Signer::write_signers_file(&signers);
    }

    pub fn add_signer_to_file(s: &Signer) -> Result<()> {
        let mut signers: Vec<Signer> = Signer::all_signers();

        for signer in &signers {
            if signer.key_id == s.key_id {
                return Err(Error::Generic("Signer is already in the list of signing keys"));
            }
        }

        signers.push(build_signer(s.name.clone(), s.key_id.clone()));

        return Signer::write_signers_file(&signers);
    }
}

fn updated(base: &path::PathBuf, path: &path::PathBuf) -> Result<DateTime<Local>> {
    let repo = git2::Repository::open(base)?;
    let blame = repo.blame_file(path.strip_prefix(base)?, None)?;
    let id = blame
        .get_line(1)
        .ok_or(Error::Generic("no git history found"))?
        .orig_commit_id();
    let time = repo.find_commit(id)?.time();
    Ok(Local.timestamp(time.seconds(), 0))
}

pub fn new_password_file(path_end: std::rc::Rc<String>, content: std::rc::Rc<String>) -> Result<()> {
    let mut path = password_dir()?;

    path.push((*path_end).clone() + ".gpg");

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

    for signer in Signer::all_signers() {
        keys.push(ctx.get_key(signer.key_id).unwrap());
    }

    let mut output = Vec::new();
    ctx.encrypt(&keys, (*content).clone(), &mut output)?;

    match file.write_all(&output) {
        Err(why) => return Err(Error::from(why)),
        Ok(_) => (),
    }

    let repo_res = git2::Repository::open(password_dir().unwrap());

    if repo_res.is_err() {
        return Ok(());
    }

    let repo = repo_res.unwrap();

    let message = format!("Add password for {} using ripasso", path_end);

    add_and_commit(&repo, &vec![format!("{}.gpg", (*path_end).clone())], &message)?;

    return Ok(());
}

#[derive(Debug)]
pub enum PasswordEvent {
    NewPassword(PasswordEntry),
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

pub fn watch_iter() -> Result<impl Iterator<Item = PasswordEvent>> {
    let dir = password_dir()?;

    let (watcher_tx, watcher_rx) = channel();
    // Existing files iterator
    let password_path_glob = dir.join("**/*.gpg");
    let existing_iter =
        glob::glob(&password_path_glob.to_string_lossy()).unwrap();

    // Watcher iterator
    notify::RecommendedWatcher::new(watcher_tx, Duration::from_secs(2))?
        .watch(&dir, notify::RecursiveMode::Recursive)?;
    Ok(existing_iter
        .map(|event| -> Result<path::PathBuf> {
            match event {
                Ok(x) => Ok(x),
                Err(_) => Err(Error::Generic("test")),
            }
        }).chain(
            watcher_rx
                .into_iter()
                .map(|event| -> Result<path::PathBuf> {
                    match event {
                        notify::DebouncedEvent::Create(p) => Ok(p),
                        notify::DebouncedEvent::Error(_, _) => {
                            Err(Error::Generic("test"))
                        }
                        _ => Err(Error::Generic("None")),
                    }
                }),
        ).map(move |path| match path {
            Ok(p) => match to_password(&dir, &p) {
                Ok(password) => PasswordEvent::NewPassword(password),
                Err(e) => PasswordEvent::Error(e),
            },
            Err(e) => PasswordEvent::Error(e),
        }))
}

pub fn watch() -> Result<(Receiver<PasswordEvent>, PasswordList)> {
    let wi = watch_iter()?;

    let (event_tx, event_rx): (
        Sender<PasswordEvent>,
        Receiver<PasswordEvent>,
    ) = channel();

    let passwords = Arc::new(Mutex::new(Vec::new()));
    let passwords_out = passwords.clone();

    thread::spawn(move || {
        info!("Starting thread");
        for event in wi {
            match event {
                PasswordEvent::NewPassword(ref p) => {
                    (passwords.lock().unwrap()).push(p.clone());
                    info!("password: {}", p.name);
                }
                PasswordEvent::Error(ref err) => {
                    error!("Error: {:?}", err);
                }
            }
            if let Err(_err) = event_tx.send(event) { //error!("Error sending event {}", err)
            }
        }
    });
    Ok((event_rx, passwords_out))
}

pub fn generate_password(length: usize) -> String {
    return thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .collect();
}

fn to_name(base: &path::PathBuf, path: &path::PathBuf) -> String {
    path.strip_prefix(base)
        .unwrap()
        .to_string_lossy()
        .into_owned()
        .trim_end_matches(".gpg")
        .to_string()
}

fn to_password(
    base: &path::PathBuf,
    path: &path::PathBuf,
) -> Result<PasswordEntry> {
    Ok(PasswordEntry {
        name: to_name(base, path),
        meta: "".to_string(),
        base: base.to_path_buf(),
        path: path.to_path_buf(),
        updated: match updated(base, path) {
            Ok(p) => Some(p),
            Err(_) => None,
        }, // TODO: do we need lossy?
        filename: path.to_string_lossy().into_owned().clone(),
    })
}

/// Determine password directory
fn password_dir() -> Result<path::PathBuf> {
    // If a directory is provided via env var, use it
    let pass_home = match env::var("PASSWORD_STORE_DIR") {
        Ok(p) => p,
        Err(_) => dirs::home_dir()
            .unwrap()
            .join(".password-store")
            .to_string_lossy()
            .into(),
    };
    if !path::Path::new(&pass_home).exists() {
        return Err(Error::Generic("failed to locate password directory"));
    }
    Ok(path::Path::new(&pass_home).to_path_buf())
}
