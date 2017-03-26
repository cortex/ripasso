extern crate glob;
use self::glob::glob;

extern crate notify;
use self::notify::{RecommendedWatcher, Watcher, RecursiveMode};
use self::notify::DebouncedEvent::Create;
use std::sync::mpsc::{Sender, channel, SendError};
use std::time::Duration;
use std::error::Error;
use std::path::PathBuf;

pub fn load_and_watch_passwords(tx: Sender<String>) -> Result<(), Box<Error>> {
    try!(load_passwords(&tx));
    try!(watch_passwords(tx));
    Ok(())
}

fn to_name(path: PathBuf) -> String {
    path.file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned()
        .trim_right_matches(".gpg")
        .to_string()
}

fn load_passwords(tx: &Sender<String>) -> Result<(), SendError<String>> {
    for entry in
        glob("/home/joakim/.password-store/**/*.gpg").expect("Failed to read glob pattern") {
        match entry {
            Ok(path) => {
                let name = to_name(path);
                try!(tx.send(name))
            }
            Err(e) => println!("{:?}", e),
        }
    }
    Ok(())
}

fn watch_passwords(password_tx: Sender<String>) -> Result<(), Box<Error>> {
    let (tx, rx) = channel();
    let mut watcher: RecommendedWatcher = try!(Watcher::new(tx, Duration::from_secs(2)));

    try!(watcher.watch("/home/joakim/.password-store", RecursiveMode::Recursive));

    loop {
        match rx.recv() {
            Ok(event) => {
                match event {
                    Create(path) => try!(password_tx.send(to_name(path))),
                    _ => (),
                }
            }
            Err(e) => println!("watch error: {:?}", e),
        }
    }
}
