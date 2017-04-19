extern crate glob;
use self::glob::glob;

extern crate notify;
use self::notify::{RecommendedWatcher, Watcher, RecursiveMode};
use self::notify::DebouncedEvent::Create;
use std::sync::mpsc::{Sender, channel, SendError};
use std::time::Duration;
use std::error::Error;
use std::path::PathBuf;
use std::env;

#[derive(Clone)]
pub struct Password {
    pub name: String,
    pub meta: String,
    pub filename: String,
}

pub fn load_and_watch_passwords(tx: Sender<Password>) -> Result<(), Box<Error>> {
    try!(load_passwords(&tx));
    try!(watch_passwords(tx));
    Ok(())
}

fn to_name(path: &PathBuf) -> String {
    path.file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned()
        .trim_right_matches(".gpg")
        .to_string()
}

fn to_password(path: PathBuf) -> Password {
    Password {
        name: to_name(&path),
        filename: path.to_string_lossy().into_owned().clone(),
        meta: "".to_string(),
    }
}

fn load_passwords(tx: &Sender<Password>) -> Result<(), SendError<Password>> {
    let home = env::home_dir().unwrap();
    let passpath = home.join(".password-store/**/*.gpg");
    let passpath_str = passpath.to_str().unwrap();
    println!("path: {}", passpath_str);
    for entry in glob(passpath_str).expect("Failed to read glob pattern") {
        match entry {
            Ok(path) => try!(tx.send(to_password(path))),
            Err(e) => println!("{:?}", e),
        }
    }
    Ok(())
}

fn watch_passwords(password_tx: Sender<Password>) -> Result<(), Box<Error>> {
    let (tx, rx) = channel();
    let mut watcher: RecommendedWatcher = try!(Watcher::new(tx, Duration::from_secs(2)));

    try!(watcher.watch("/home/joakim/.password-store", RecursiveMode::Recursive));

    loop {
        match rx.recv() {
            Ok(event) => {
                match event {
                    Create(path) => try!(password_tx.send(to_password(path))),
                    _ => (),
                }
            }
            Err(e) => println!("watch error: {:?}", e),
        }
    }
}
