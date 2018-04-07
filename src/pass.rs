#![feature(conservative_impl_trait, universal_impl_trait)]
use errors::*;
use std::env;
use std::fs;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::str;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::Duration;

use chrono::DateTime;
use chrono::Local;
use glob;
use gpgme;
use notify;
use notify::Watcher;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub struct PasswordEntry {
    pub name: String, // Name of the entry
    pub meta: String, // Metadata
    pub path: String, // Path, relative to the store
    updated: DateTime<Local>,
    filename: String,
}

impl PasswordEntry {
    pub fn password(&self) -> Option<String> {
        let mut input = File::open(&self.filename).unwrap();

        // Decrypt password
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp).unwrap();
        let mut output = Vec::new();
        if let Err(e) = ctx.decrypt(&mut input, &mut output) {
            println!("decryption failed {:?}", e);
            return None;
        }
        let password = str::from_utf8(&output).unwrap();
        let firstline: String = password.split('\n').take(1).collect();
        Some(firstline)
    }
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
    let existing_iter = glob::glob(&password_path_glob.to_string_lossy())
        .chain_err(|| "failed to open password directory")?;

    // Watcher iterator
    notify::RecommendedWatcher::new(watcher_tx, Duration::from_secs(2))
        .chain_err(|| "failed to watch directory")?
        .watch(&dir, notify::RecursiveMode::Recursive)
        .chain_err(|| "failed to start watching")?;
    Ok(existing_iter
        .map(|event| -> Result<PathBuf> {
            match event {
                Ok(x) => Ok(x),
                Err(_) => Err(ErrorKind::GenericError("test".to_string()).into()),
            }
        })
        .chain(watcher_rx.into_iter().map(|event| -> Result<PathBuf> {
            match event {
                notify::DebouncedEvent::Create(p) => Ok(p),
                notify::DebouncedEvent::Error(_, _) => {
                    Err(ErrorKind::GenericError("test".to_string()).into())
                }
                _ => Err("None".into()),
            }
        }))
        .map(move |path| match path {
            Ok(p) => match to_password(&dir, &p) {
                Ok(password) => PasswordEvent::NewPassword(password),
                Err(e) => PasswordEvent::Error(e),
            },
            Err(e) => PasswordEvent::Error(e),
        }))
}

pub fn watch() -> Result<(Receiver<PasswordEvent>, PasswordList)> {
    let wi = watch_iter()?;

    let (event_tx, event_rx): (Sender<PasswordEvent>, Receiver<PasswordEvent>) = channel();

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
                   error!("Error: {}", err);
                }
            }
            match event_tx.send(event){
                _ => (),
                Err(err) => {error!("Error sending event {}", err)}
            }
        }
    });
    Ok((event_rx, passwords_out))
}

fn to_name(base: &PathBuf, path: &PathBuf) -> String {
    path.strip_prefix(base)
        .unwrap()
        .to_string_lossy()
        .into_owned()
        .trim_right_matches(".gpg")
        .to_string()
}

fn to_password(base: &PathBuf, path: &PathBuf) -> Result<PasswordEntry> {
    let metadata = fs::metadata(path).chain_err(|| "Failed to extract password metadata")?;
    let modified = metadata
        .modified()
        .chain_err(|| "Failed to extract updated time")?
        .into();
    Ok(PasswordEntry {
        name: to_name(base, path),
        meta: "".to_string(),
        path: path.to_string_lossy().to_string(), // TODO: do we need lossy?
        filename: path.to_string_lossy().into_owned().clone(),
        updated: modified,
    })
}

/// Determine password directory
fn password_dir() -> Result<PathBuf> {
    // If a directory is provided via env var, use it
    let pass_home = match env::var("PASSWORD_STORE_DIR") {
        Ok(p) => p,
        Err(_) => env::home_dir()
            .unwrap()
            .join(".password-store")
            .to_string_lossy()
            .into(),
    };
    if !Path::new(&pass_home).exists() {
        return Err(From::from("failed to locate password directory"));
    }
    Ok(Path::new(&pass_home).to_path_buf())
}
