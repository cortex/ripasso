/*  Ripasso - a simple password manager
    Copyright (C) 2018-2020 Joakim Lundborg, Alexander Kjäll

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

extern crate glib;
extern crate gtk;
extern crate ripasso;

use crate::gtk::prelude::BuilderExtManual;
use crate::gtk::prelude::GtkListStoreExtManual;
use gtk::*;

use self::glib::StaticType;

use clipboard::{ClipboardContext, ClipboardProvider};
use ripasso::pass;
use std::cell::RefCell;
use std::process;
use std::sync::{Arc, Mutex};
use std::{thread, time};

#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref SHOWN_PASSWORDS: Arc<Mutex<Vec<pass::PasswordEntry>>> = Arc::new(Mutex::new(vec![]));
}

fn main() {
    let password_store_dir = match std::env::var("PASSWORD_STORE_DIR") {
        Ok(p) => Some(p),
        Err(_) => None,
    };
    let password_store_signing_key = match std::env::var("PASSWORD_STORE_SIGNING_KEY") {
        Ok(p) => Some(p),
        Err(_) => None,
    };
    let home = match std::env::var("HOME") {
        Err(_) => None,
        Ok(home_path) => Some(std::path::PathBuf::from(home_path)),
    };

    let store = Arc::new(Mutex::new(
        pass::PasswordStore::new(
            &"default".to_string(),
            &password_store_dir,
            &password_store_signing_key,
            &home,
        )
        .unwrap(),
    ));
    let reload_res = (*store).lock().unwrap().reload_password_list();
    if let Err(e) = reload_res {
        eprintln!("Error: {:?}", e);
        process::exit(0x01);
    }

    // Load and watch all the passwords in the background
    let password_rx = match pass::watch(store.clone()) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error: {:?}", e);
            process::exit(0x01);
        }
    };

    if gtk::init().is_err() {
        panic!("failed to initialize GTK.");
    }

    let settings = gtk::Settings::get_default();
    settings
        .unwrap()
        .set_property_gtk_application_prefer_dark_theme(true);

    let glade_src = include_str!("../res/ripasso.ui.xml");
    let builder = Builder::new_from_string(glade_src);

    let window: Window = builder
        .get_object("mainWindow")
        .expect("Couldn't get window1");

    let password_list: TreeView = builder
        .get_object("passwordList")
        .expect("Couldn't get list");

    password_list.connect_row_activated(move |_, path, _column| {
        let passwords = (*SHOWN_PASSWORDS).lock().unwrap();

        let mut ctx = clipboard::ClipboardContext::new().unwrap();
        ctx.set_contents(
            passwords[path.get_indices()[0] as usize]
                .password()
                .unwrap(),
        )
        .unwrap();

        thread::spawn(|| {
            thread::sleep(time::Duration::from_secs(40));
            let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
            ctx.set_contents("".to_string()).unwrap();
        });
    });

    let password_search: gtk::SearchEntry = builder
        .get_object("passwordSearchBox")
        .expect("Couldn't get passwordSearchBox");

    let name_column = TreeViewColumn::new();
    let name_cell = CellRendererText::new();

    name_column.pack_start(&name_cell, true);
    name_column.add_attribute(&name_cell, "text", 0);

    password_list.set_headers_visible(false);
    password_list.append_column(&name_column);
    password_list.set_model(Some(&results(&store, "")));

    password_search.connect_search_changed(move |_| {
        receive();
    });

    window.connect_delete_event(|_, _| {
        gtk::main_quit();
        gtk::Inhibit(false)
    });

    GLOBAL.with(move |global| {
        *global.borrow_mut() = Some((password_search, password_list, store));
    });

    window.show_all();
    gtk::idle_add(move || {
        if password_rx.try_recv().is_ok() {
            receive();
        };
        glib::Continue(true)
    });

    gtk::main();
}

fn results(store: &pass::PasswordStoreType, query: &str) -> ListStore {
    let model = ListStore::new(&[String::static_type()]);
    let filtered = pass::search(store, query).unwrap();
    let mut passwords = (*SHOWN_PASSWORDS).lock().unwrap();
    for (i, p) in filtered.iter().enumerate() {
        model.insert_with_values(Some(i as u32), &[0], &[&p.name]);
    }
    passwords.clear();
    for p in filtered {
        passwords.push(p);
    }
    model
}

fn receive() -> glib::Continue {
    GLOBAL.with(|global| {
        if let Some((ref password_search, ref password_list, ref store)) = *global.borrow() {
            let query = password_search.get_text().unwrap();
            password_list.set_model(Some(&results(&store, &query)));
        }
    });
    glib::Continue(false)
}

thread_local!(
    static GLOBAL: RefCell<Option<(gtk::SearchEntry,
        TreeView,
        pass::PasswordStoreType,
    )>> = RefCell::new(None)
);
