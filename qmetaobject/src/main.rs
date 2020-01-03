extern crate qmetaobject;
use qmetaobject::*;
use ripasso::pass;
use std::sync::{Arc, Mutex};

use ripasso::pass::GitRepo;

use std::process;

#[macro_use] extern crate cstr;

#[derive(QObject,Default)]
struct PasswordStore {
    base : qt_base_class!(trait QObject),
    name : qt_property!(QString; NOTIFY name_changed),
    name_changed : qt_signal!(),
    query : qt_method!(fn query(&self, verb : String) -> QString {
        return (verb + " " + &self.name.to_string()).into()
    })
}
fn main() {
    let password_store_dir = Arc::new(match std::env::var("PASSWORD_STORE_DIR") {
        Ok(p) => Some(p),
        Err(_) => None
    });
    let pdir_res = pass::password_dir(password_store_dir.clone());
    if pdir_res.is_err() {
        eprintln!("Error {:?}", pdir_res.err().unwrap());
        process::exit(1);
    }
    let repo_res = git2::Repository::open(pdir_res.unwrap());
    let mut repo_opt: GitRepo = Arc::new(None::<Mutex<git2::Repository>>);
    if repo_res.is_ok() {
        repo_opt = Arc::new(Some(Mutex::new(repo_res.unwrap())));
    }

    // Load and watch all the passwords in the background
    let (password_rx, passwords) = match pass::watch(repo_opt.clone(), password_store_dir.clone()) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error {:?}", e);
            process::exit(1);
        }
    };

    qml_register_type::<PasswordStore>(cstr!("PasswordStore"), 1, 0, cstr!("PasswordStore"));
    let mut engine = QmlEngine::new();

    engine.load_file(r#"res/main.qml"#.into());
    engine.exec();

}