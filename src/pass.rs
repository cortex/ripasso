extern crate glob;
use self::glob::glob;

extern crate notify;
use self::notify::{RecommendedWatcher, Watcher, RecursiveMode};
use self::notify::DebouncedEvent::Create;
use std::sync::mpsc::{Sender, channel, SendError};
use std::time::Duration;
use std::error::Error;
use std::path::{PathBuf, Path};
use std::env;
use std::thread;

#[derive(Clone)]
pub struct Password {
    pub name: String,
    pub meta: String,
    pub filename: String,
}

pub fn load_and_watch_passwords(tx: Sender<Password>) -> Result<(), Box<Error>> {
    let dir = password_dir()?;
    thread::spawn(move ||{
        load_passwords(&dir, &tx);
        watch_passwords(&dir, tx);
    }
    );
    Ok(())
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
    let pass_home = match env::var("PASSWORD_STORE_DIR"){
        Ok(p) => {p}
        Err(_) => {
            env::home_dir()
                .unwrap()
                .join(".password-store")
                .to_string_lossy()
                .into()
        }
    };
    if !Path::new(&pass_home).exists(){
        return Err(From::from("Not found"))
    }
    return Ok(Path::new(&pass_home).to_path_buf());
}

fn load_passwords(dir: &PathBuf, tx: &Sender<Password>) -> Result<(), SendError<Password>> {
    let password_path_glob = dir.join("**/*.gpg");

    // Find all passwords
    let ref passpath_str = password_path_glob.to_string_lossy();
    println!("path: {}", passpath_str);
    for entry in glob(passpath_str).expect("Failed to read glob pattern") {
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
                    Create(path) => try!(password_tx.send(to_password(dir, path ))),
                    _ => (),
                }
            }
            Err(e) => println!("watch error: {:?}", e),
        }
    }
}
