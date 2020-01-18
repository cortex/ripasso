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

extern crate clipboard;
extern crate qml;
extern crate ripasso;

use self::qml::*;

use pass::PasswordEntry;
use ripasso::pass;
use std::sync::{Arc, Mutex};
use std::thread;
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
        let passwords = self.all_passwords.clone();
        let matching = pass::search(&passwords, &String::from(query)).unwrap();


        // Save currently matched passwords
        self.current_passwords = matching.clone();

        // Update QML data with currently matched passwords
        self.passwords.set_data(
            self.current_passwords
                .clone()
                .into_iter()
                .map(|p| (p.name.clone(), p.meta.clone()))
                .collect(),
        );
        None
    }

    fn get_password(&self, i: i32) -> PasswordEntry {
        return self.current_passwords[i as usize].clone();
    }

    pub fn copy_to_clipboard(&mut self, i: i32) -> Option<&QVariant> {
        if self.current_passwords.is_empty() {// Exit fun if we have no passwords to copy
            return None;
        }
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
        if !self.current_passwords.is_empty() { // Select notihng if passwords list is empty
            let pass = self.get_password(i);
            self.password.set_name(pass.name);
            self.password.set_meta(pass.meta);
        }
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

fn main() {
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

    let password_store_dir = Arc::new(match std::env::var("PASSWORD_STORE_DIR") {
        Ok(p) => Some(p),
        Err(_) => None
    });

    let store = Arc::new(Mutex::new(pass::PasswordStore::new(password_store_dir.clone()).unwrap()));

    // Load and watch all the passwords in the background
    let (_, passwords) = pass::watch(store).expect("error");

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
    let passwordsv = &ui.passwords;
    let password = &ui.password;
    engine.set_and_store_property("ui", ui.get_qobj());
    engine.set_and_store_property("passwords", passwordsv);
    engine.set_and_store_property("password", password.get_qobj());
    engine.load_file("res/main.qml");
    engine.exec();
}
