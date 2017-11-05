extern crate glob;
extern crate gpgme;
extern crate notify;

use self::notify::{RecommendedWatcher, Watcher, RecursiveMode};
use self::notify::DebouncedEvent::Create;

use std::sync::mpsc::{Sender, Receiver, channel, SendError};
use std::time::Duration;
use std::error::Error;
use std::path::{PathBuf, Path};
use std::env;
use std::thread;
use std::fs::File;
use std::str;

use self::gpgme::{Context, Protocol};

use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct Password {
    pub name: String,
    pub meta: String,
    pub filename: String,
}

impl Password {
    pub fn password(&self) -> Option<String> {
        let mut input = File::open(&self.filename).unwrap();

        // Decrypt password
        let mut ctx = Context::from_protocol(Protocol::OpenPgp).unwrap();
        let mut output = Vec::new();
        match ctx.decrypt(&mut input, &mut output) {
            Err(_) => {
                println!("decryption failed");
                return None;
            }
            Ok(_) => (),
        }
        let password = str::from_utf8(&output).unwrap();
        let firstline: String = password.split("\n").take(1).collect();
        return Some(firstline);
    }
}

pub enum PasswordEvent {
    NewPassword,
}

pub type PasswordList = Arc<Mutex<Vec<Password>>>;

pub fn search(l: &PasswordList, query: String) -> Vec<Password> {
    let passwords = l.lock().unwrap();
    fn normalized(s: &String) -> String {
        s.to_lowercase()
    };
    fn matches(s: &String, q: &String) -> bool {
        normalized(&s).as_str().contains(normalized(&q).as_str())
    };
    let matching = passwords.iter().filter(|p| matches(&p.name, &query));
    matching.cloned().collect()
}

pub fn watch() -> Result<(Receiver<PasswordEvent>, PasswordList), Box<Error>> {

    let (password_tx, password_rx): (Sender<Password>, Receiver<Password>) = channel();
    let (event_tx, event_rx): (Sender<PasswordEvent>, Receiver<PasswordEvent>) = channel();

    let dir = password_dir()?;

    // Spawn watcher threads
    thread::spawn(move || {
        load_passwords(&dir, &password_tx);
        watch_passwords(&dir, password_tx);
    });

    let passwords = Arc::new(Mutex::new(Vec::new()));
    let passwords_out = passwords.clone();

    // Spawn password list update thread
    thread::spawn(move || loop {
        match password_rx.recv() {
            Ok(p) => {
                let mut passwords = passwords.lock().unwrap();
                passwords.push(p);
                event_tx.send(PasswordEvent::NewPassword);
            }
            Err(e) => {
                panic!("password receiver channel failed: {:?}", e);
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

fn to_password(base: &PathBuf, path: PathBuf) -> Password {
    Password {
        name: to_name(base, &path),
        filename: path.to_string_lossy().into_owned().clone(),
        meta: "".to_string(),
    }
}

/// Determine password directory
fn password_dir() -> Result<PathBuf, Box<Error>> {
    // If a directory is provided via env var, use it
    let pass_home = match env::var("PASSWORD_STORE_DIR") {
        Ok(p) => p,
        Err(_) => {
            env::home_dir()
                .unwrap()
                .join(".password-store")
                .to_string_lossy()
                .into()
        }
    };
    if !Path::new(&pass_home).exists() {
        return Err(From::from("failed to locate password directory"));
    }
    return Ok(Path::new(&pass_home).to_path_buf());
}

fn load_passwords(dir: &PathBuf, tx: &Sender<Password>) -> Result<(), SendError<Password>> {
    let password_path_glob = dir.join("**/*.gpg");

    // Find all passwords
    let ref passpath_str = password_path_glob.to_string_lossy();
    println!("path: {}", passpath_str);
    for entry in glob::glob(passpath_str).expect("Failed to read glob pattern") {
        match entry {
            Ok(path) => try!(tx.send(to_password(dir, path))),
            Err(e) => println!("{:?}", e),
        }
    }
    Ok(())
}

fn watch_passwords(dir: &PathBuf, password_tx: Sender<Password>) -> Result<(), Box<Error>> {
    let (tx, rx) = channel();
    let mut watcher: RecommendedWatcher = try!(Watcher::new(tx, Duration::from_secs(2)));
    try!(watcher.watch(dir, RecursiveMode::Recursive));

    loop {
        match rx.recv() {
            Ok(event) => {
                match event {
                    Create(path) => try!(password_tx.send(to_password(dir, path))),
                    _ => (),
                }
            }
            Err(e) => println!("watch error: {:?}", e),
        }
    }
}
