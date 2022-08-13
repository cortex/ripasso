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
use qml::*;

use pass::PasswordEntry;
use ripasso::crypto::CryptoImpl;
use ripasso::pass;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use clipboard::{ClipboardContext, ClipboardProvider};

use std::panic;

/// The 'pointer' to the current PasswordStore is of this type.
type PasswordStoreType = Arc<Mutex<pass::PasswordStore>>;

// UI state
pub struct UI {
    store: PasswordStoreType,
    current_passwords: Vec<PasswordEntry>,
    password: Box<QPasswordView>,
    passwords: QPasswordEntry,
}

impl UI {
    pub fn query(&mut self, query: String) -> Option<&QVariant> {
        println!("query");
        let matching = pass::search(&self.store.lock().unwrap(), &query).unwrap();

        // Save currently matched passwords
        self.current_passwords = matching;

        // Update QML data with currently matched passwords
        self.passwords.set_data(
            self.current_passwords
                .clone()
                .into_iter()
                .map(|p| (p.name, String::new()))
                .collect(),
        );
        None
    }

    fn get_password(&self, i: i32) -> PasswordEntry {
        self.current_passwords[i as usize].clone()
    }

    pub fn copy_to_clipboard(&mut self, i: i32) -> Option<&QVariant> {
        if self.current_passwords.is_empty() {
            // Exit fun if we have no passwords to copy
            return None;
        }
        // Open password file
        let store = self.store.lock().unwrap();
        let password = self.get_password(i).password(&store).unwrap();

        // Copy password to clipboard
        let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
        ctx.set_contents(password).unwrap();
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
        if !self.current_passwords.is_empty() {
            // Select notihng if passwords list is empty
            let pass = self.get_password(i);
            self.password.set_name(pass.name);
            self.password.set_meta(String::new());
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

    let password_store_dir = match std::env::var("PASSWORD_STORE_DIR") {
        Ok(p) => Some(PathBuf::from(p)),
        Err(_) => None,
    };
    let password_store_signing_key = match std::env::var("PASSWORD_STORE_SIGNING_KEY") {
        Ok(p) => Some(p),
        Err(_) => None,
    };
    let home = match std::env::var("HOME") {
        Err(_) => None,
        Ok(home_path) => Some(PathBuf::from(home_path)),
    };

    let store = Arc::new(Mutex::new(
        pass::PasswordStore::new(
            "default",
            &password_store_dir,
            &password_store_signing_key,
            &home,
            &None,
            &CryptoImpl::GpgMe,
            &None,
        )
        .unwrap(),
    ));

    // Set up all the UI stuff
    let mut engine = QmlEngine::new();

    let ui = QUI::new(
        UI {
            store,
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
