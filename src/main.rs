#[macro_use]
extern crate qml;

use qml::*;
use std::thread;
use std::sync::mpsc;
use std::sync::mpsc::{Sender, Receiver};

mod pass;

// UI state
pub struct UI {
    password: Box<QPassword>,
    passwords: QPasswordEntry,
    password_updates: Receiver<String>,

}

impl UI {
    pub fn query(&mut self) -> Option<&QVariant> {
        println!("query");
        None
    }
    pub fn select(&mut self, i: i32) -> Option<&QVariant> {
        println!("select: {}", i);
        let item = self.passwords.view_data()[i as usize].clone();
        let name = item.0;
        let meta = item.1;
        self.password.set_name(name.into());
        self.password.set_meta(meta.into());
        None
    }
    pub fn add_password(&mut self) -> Option<&QVariant> {
        let entry = self.password_updates.try_recv();
        match entry {
            Err(_why) => return None, 
            Ok(entry) => {
                self.passwords.append_row(entry.clone(), entry.clone());
                return None;
            }
        }
    }
}

// The currently shown password
pub struct Password;
Q_OBJECT!(
pub Password as QPassword{
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

Q_OBJECT!(
pub UI as QUI{
    signals:
    slots:
        fn query();
        fn select(i:i32);
        fn add_password();
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

// Password list
Q_LISTMODEL!(
    pub QPasswordEntry{
        name: String,
        meta: String
    }
);

fn main() {

    // Channel for password updates
    let (password_tx, password_rx): (Sender<String>, Receiver<String>) = mpsc::channel();

    // Load and watch all the passwords in the background
    thread::spawn(move || if let Err(e) = pass::load_and_watch_passwords(password_tx) {
                      println!("error: {:?}", e)
                  });


    // Set up all the UI stuff
    let mut engine = QmlEngine::new();

    let ui = QUI::new(UI {
                          passwords: QPasswordEntry::new(),
                          password_updates: password_rx,
                          password: QPassword::new(Password, true, "test".into(), "test".into(), "test".into()),
                      },
                      "started".into(),
                      0.0);
    let ref passwords = ui.passwords;
    let ref password = ui.password;
    engine.set_and_store_property("ui", ui.get_qobj());
    engine.set_and_store_property("passwords", passwords);
    engine.set_and_store_property("password", password.get_qobj());

    engine.load_file("res/main.qml");
    engine.exec();
}
