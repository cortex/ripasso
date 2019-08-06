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

    pub fn update(&self, secret: String) -> Result<()> {
        let pwdir = password_dir()?;

        let mut gpg_id_file = File::open(pwdir.join(".gpg-id"))?;
        let mut gpgid = String::new();
        gpg_id_file.read_to_string(&mut gpgid)?;
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)?;
        let key = ctx.get_key(gpgid)?;

        let mut ciphertext = Vec::new();
        ctx.encrypt(Some(&key), secret, &mut ciphertext)?;

        let mut output = File::create(&self.filename)?;
        output.write_all(&ciphertext)?;
        Ok(())
    }
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
}

fn updated(
    base: &path::PathBuf,
    path: &path::PathBuf,
) -> Result<DateTime<Local>> {
    let repo = git2::Repository::open(base)?;
    let blame = repo.blame_file(path.strip_prefix(base)?, None)?;
    let id = blame
        .get_line(1)
        .ok_or(Error::Generic("no git history found"))?
        .orig_commit_id();
    let time = repo.find_commit(id)?.time();
    Ok(Local.timestamp(time.seconds(), 0))
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
