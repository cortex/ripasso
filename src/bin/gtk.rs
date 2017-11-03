extern crate ripasso;
extern crate gtk;

use gtk::prelude::*;
use gtk::{Builder, ListBox, ListBoxRow, Window};

use std::thread;
use std::sync::mpsc;
use std::sync::mpsc::{Sender, Receiver};
use std::sync::{Arc, Mutex};

use ripasso::pass::{Password, load_and_watch_passwords};

//use std::time::Duration;
extern crate clipboard;

//use clipboard::{ClipboardProvider, ClipboardContext};
//use std::fs::File;

fn main() {

    // Channel for password updates
    let (password_tx, password_rx): (Sender<Password>, Receiver<Password>) = mpsc::channel();

    // Load and watch all the passwords in the background
    load_and_watch_passwords(password_tx).expect("failed to locate password directory");

    let passwords = Arc::new(Mutex::new(vec![]));
    let p1 = passwords.clone();
    thread::spawn(move || loop {
        match password_rx.recv() {
            Ok(p) => {
                println!("Recieved: {:?}", p.name);
                let mut passwords = p1.lock().unwrap();
                passwords.push(p);
            }
            Err(e) => {
                panic!("password reciever channel failed: {:?}", e);
            },
        }
    });
    print!("Hello world");

    if gtk::init().is_err() {
        println!("Failed to initialize GTK.");
        return;
    }

    let glade_src = include_str!("../../res/ripasso.ui");
    let builder = Builder::new_from_string(glade_src);

    let window: Window = builder.get_object("mainWindow").expect("Couldn't get window1");
    let list: ListBox = builder.get_object("passwordList").expect("Couldn't get list");
    window.connect_delete_event(|_, _| {
        gtk::main_quit();
        Inhibit(false)
    });

    window.show_all();

    gtk::main();
}
