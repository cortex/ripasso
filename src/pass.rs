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
use std::io::prelude::*;
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
    pub fn secret(&self) -> Result<String> {
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)
            .chain_err(|| "error obtaining gpgme context")?;
        let mut input =
            File::open(&self.filename).chain_err(|| "error opening file")?;
        let mut output = Vec::new();
        ctx.decrypt(&mut input, &mut output)
            .chain_err(|| "error decrypting")?;
        String::from_utf8(output).chain_err(|| "error decoding utf-8")
    }

    pub fn password(&self) -> Result<String> {
        Ok(self.secret()?.split('\n').take(1).collect())
    }

    pub fn update(&self, secret: String) -> Result<()> {
        let pwdir = password_dir()?;

        let mut gpg_id_file = File::open(pwdir.join(".gpg-id"))
            .chain_err(||"failed to open gpg-id file")?;

        let mut gpgid = String::new();
        gpg_id_file.read_to_string(&mut gpgid)
            .chain_err(||"failed to read gpg-id file")?;
            
        let mut ctx = gpgme::Context::from_protocol(gpgme::Protocol::OpenPgp)
            .chain_err(|| "error obtaining GPGME context")?;

        let key = ctx.find_key(gpgid)
            .chain_err(|| "keys not found")?;

        let mut ciphertext = Vec::new();
        ctx.encrypt(Some(&key), secret, &mut ciphertext)
            .chain_err(|| "encryption failed")?;

        let mut output =
            File::create(&self.filename).chain_err(|| "error opening file")?;
        output
            .write_all(&ciphertext)
            .chain_err(|| "error writing new password file")
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
        normalized(s)
            .as_str()
            .contains(normalized(q).as_str())
    };
    let matching = passwords
        .iter()
        .filter(|p| matches(&p.name, query));
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
                Err(_) => {
                    Err(ErrorKind::GenericError("test".to_string()).into())
                }
            }
        })
        .chain(
            watcher_rx
                .into_iter()
                .map(|event| -> Result<PathBuf> {
                    match event {
                        notify::DebouncedEvent::Create(p) => Ok(p),
                        notify::DebouncedEvent::Error(_, _) => Err(
                            ErrorKind::GenericError("test".to_string()).into(),
                        ),
                        _ => Err("None".into()),
                    }
                }),
        )
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
                    error!("Error: {}", err);
                }
            }
            match event_tx.send(event) {
                Err(err) => (), //error!("Error sending event {}", err),
                _ => (),
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
    let metadata =
        fs::metadata(path).chain_err(|| "Failed to extract password metadata")?;
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
        return Err(From::from(
            "failed to locate password directory",
        ));
    }
    Ok(Path::new(&pass_home).to_path_buf())
}
