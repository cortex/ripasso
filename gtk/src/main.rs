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

extern crate glib;
extern crate gtk;
extern crate ripasso;

use gtk::*;

use self::glib::StaticType;

use ripasso::pass;
use std::cell::RefCell;
use std::io::Write;
use std::process;

fn main() {
    // Load and watch all the passwords in the background
    let (password_rx, passwords) = match pass::watch() {
        Ok(t) => t,
        Err(e) => {
            writeln!(&mut std::io::stderr(), "Error: {:?}", e);
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

    let glade_src = include_str!("../res/ripasso.ui");
    let builder = Builder::new_from_string(glade_src);

    let window: Window = builder
        .get_object("mainWindow")
        .expect("Couldn't get window1");

    let password_list: TreeView = builder
        .get_object("passwordList")
        .expect("Couldn't get list");

    let password_search: gtk::SearchEntry = builder
        .get_object("passwordSearchBox")
        .expect("Couldn't get passwordSearchBox");

    let name_column = TreeViewColumn::new();
    let name_cell = CellRendererText::new();

    name_column.pack_start(&name_cell, true);
    name_column.add_attribute(&name_cell, "text", 0);

    password_list.set_headers_visible(false);
    password_list.append_column(&name_column);

    password_search.connect_search_changed(move |_| {
        receive();
    });

    window.connect_delete_event(|_, _| {
        gtk::main_quit();
        gtk::Inhibit(false)
    });

    GLOBAL.with(move |global| {
        *global.borrow_mut() =
            Some((password_search, password_list, passwords));
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

fn results(passwords: &pass::PasswordList, query: &str) -> ListStore {
    let model = ListStore::new(&[String::static_type()]);
    let filtered = pass::search(passwords, query);
    for (i, p) in filtered.iter().enumerate() {
        model.insert_with_values(Some(i as u32), &[0], &[&p.name]);
    }
    model
}

fn receive() -> glib::Continue {
    GLOBAL.with(|global| {
        if let Some((ref password_search, ref password_list, ref passwords)) =
            *global.borrow()
        {
            let query = password_search.get_text().unwrap();
            password_list.set_model(&results(&passwords, &query));
        }
    });
    glib::Continue(false)
}

thread_local!(
    static GLOBAL: RefCell<Option<(gtk::SearchEntry,
        TreeView,
        pass::PasswordList,
    )>> = RefCell::new(None)
);
