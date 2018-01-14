#![cfg(feature = "use-qml")]
extern crate clipboard;
extern crate gpgme;
extern crate qml;

use self::qml::*;

use std::thread;
use std::sync::{Arc, Mutex};
use pass::PasswordEntry;
use pass;
use std::time::Duration;

use self::clipboard::{ClipboardContext, ClipboardProvider};

use std::panic;

// UI state
pub struct UI {
    all_passwords: Arc<Mutex<Vec<PasswordEntry>>>,
    current_passwords: Vec<PasswordEntry>,
    password: Box<QPasswordView>,
    passwords: QPasswordEntry,
}

impl UI {
    pub fn query(&mut self, query: String) -> Option<&QVariant> {
        println!("query");
        let passwords = self.all_passwords.lock().unwrap();
        fn normalized(s: &String) -> String {
            s.to_lowercase()
        };
        fn matches(s: &String, q: &String) -> bool {
            normalized(&s).as_str().contains(normalized(&q).as_str())
        };
        let matching = passwords.iter().filter(|p| matches(&p.name, &query));

        // Save currently matched passwords
        self.current_passwords = matching.cloned().collect();

        // Update QML data with currently matched passwords
        self.passwords.set_data(
            self.current_passwords
                .clone()
                .into_iter()
                .map(|p| (p.name.clone().into(), p.meta.clone().into()))
                .collect(),
        );
        None
    }

    fn get_password(&self, i: i32) -> PasswordEntry {
        return self.current_passwords[i as usize].clone();
    }

    pub fn copy_to_clipboard(&mut self, i: i32) -> Option<&QVariant> {
        // Open password file
        let password = self.get_password(i).password().unwrap();

        // Copy password to clipboard
        let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
        ctx.set_contents(password.to_owned()).unwrap();
        println!("password copied to clipboard");

        thread::spawn(move || {
            thread::sleep(Duration::new(5, 0));
            let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
            ctx.set_contents("".into()).unwrap();
            println!("clipoard cleared");
        });
        None
    }
    pub fn select(&mut self, i: i32) -> Option<&QVariant> {
        println!("select: {}", i);
        let pass = self.get_password(i);
        self.password.set_name(pass.name);
        self.password.set_meta(pass.meta);
        None
    }
    pub fn add_password(&mut self) -> Option<&QVariant> {
        None
    }
}

Q_OBJECT!(
pub UI as QUI{
    signals:
    slots:
        fn query(query:String);
        fn select(i:i32);
        fn add_password();
        fn copy_to_clipboard(i: i32);
    properties:
        status: String;
            read: get_status,
            write: set_status,
            notify: status_changed;
        countdown: f64;
            read: get_countdown,
            write: set_countdown,
            notify: countdown_changed;
});

// The currently shown password
pub struct PasswordView;
Q_OBJECT!(
pub PasswordView as QPasswordView{
     signals:
     slots:
     properties:
        cached: bool;
            read: get_cached,
            write: set_cached,
            notify: cached_changed;
        name: String;
            read: get_name,
            write: set_name,
            notify: name_changed;
        info: String;
            read: get_info,
            write: set_info,
            notify: info_changed;
        metadata: String;
            read: get_meta,
            write: set_meta,
            notify: meta_changed;
}
);

// PasswordEntry list
Q_LISTMODEL!(
    pub QPasswordEntry{
        name: String,
        meta: String
    }
);

pub fn main() {
    panic::set_hook(Box::new(|panic_info| {
        if let Some(location) = panic_info.location() {
            println!(
                "panic occurred in file '{}' at line {}",
                location.file(),
                location.line()
            );
        } else {
            println!("panic occurred but can't get location information...");
        }

        println!(
            "panic occurred: {:?}",
            panic_info.payload().downcast_ref::<&str>()
        );
    }));

    // Load and watch all the passwords in the background
    let (_, passwords) = pass::watch().expect("error");

    // Set up all the UI stuff
    let mut engine = QmlEngine::new();

    let ui = QUI::new(
        UI {
            all_passwords: passwords.clone(),
            current_passwords: Vec::<PasswordEntry>::new(),
            passwords: QPasswordEntry::new(),
            password: QPasswordView::new(
                PasswordView,
                true,
                "test".into(),
                "test".into(),
                "test".into(),
            ),
        },
        "started".into(),
        0.0,
    );
    let ref passwordsv = ui.passwords;
    let ref password = ui.password;
    engine.set_and_store_property("ui", ui.get_qobj());
    engine.set_and_store_property("passwords", passwordsv);
    engine.set_and_store_property("password", password.get_qobj());
    engine.load_file("res/main.qml");
    engine.exec();
}
