/*  Ripasso - a simple password manager
    Copyright (C) 2019-2020 Joakim Lundborg, Alexander Kjäll

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

use cursive::event::Key;
use cursive::traits::*;
use cursive::views::{Dialog, EditView, LinearLayout, OnEventView, SelectView, TextView};

use cursive::Cursive;
use cursive::CursiveExt;

use cursive::direction::Orientation;

use crate::helpers;
use ripasso::pass;

use std::path::PathBuf;

fn create_git_repo(ui: &mut Cursive, password_store_dir: &Option<PathBuf>, home: &Option<PathBuf>) {
    let init_res = pass::init_git_repo(&pass::password_dir(password_store_dir, home).unwrap());
    if init_res.is_err() {
        helpers::errorbox(ui, &init_res.err().unwrap());
    } else {
        let message = super::CATALOG.gettext("Initialized password repo with Ripasso");
        match pass::PasswordStore::new(
            &"default".to_string(),
            password_store_dir,
            &None,
            home,
            &None,
        ) {
            Err(err) => helpers::errorbox(ui, &err),
            Ok(store) => match store.add_and_commit(&[PathBuf::from(".gpg-id")], &message) {
                Err(err) => helpers::errorbox(ui, &err),
                Ok(_) => ui.quit(),
            },
        }
    }
}

fn do_create(ui: &mut Cursive, password_store_dir: &Option<PathBuf>, home: &Option<PathBuf>) {
    let l = ui.find_name::<EditView>("initial_key_id").unwrap();
    let key_id = (*l.get_content()).clone();
    let mut pass_home = pass::password_dir_raw(password_store_dir, home);
    let home = home.clone();
    match std::fs::create_dir_all(&pass_home) {
        Err(err) => {
            helpers::errorbox(ui, &pass::Error::IO(err));
            ui.quit();
        }
        Ok(_) => {
            pass_home.push(".gpg-id");
            std::fs::write(pass_home, key_id).unwrap_or_else(|_| {
                panic!(super::CATALOG.gettext("Unable to write file").to_string())
            });

            let password_store_dir2 = password_store_dir.clone();
            let d = Dialog::around(TextView::new(
                super::CATALOG.gettext("Also create a git repository for the encrypted files?"),
            ))
            .button(super::CATALOG.gettext("Create"), move |ui: &mut Cursive| {
                create_git_repo(ui, &password_store_dir2, &home);
            })
            .button(super::CATALOG.gettext("No"), |s| {
                s.quit();
            })
            .title(super::CATALOG.gettext("Git Init"));

            ui.add_layer(d);
        }
    }
}

fn create_store(ui: &mut Cursive, password_store_dir: &Option<PathBuf>, home: &Option<PathBuf>) {
    let password_store_dir2 = password_store_dir.clone();
    let home = home.clone();
    let home2 = home.clone();
    let d2 = Dialog::around(LinearLayout::new(Orientation::Vertical)
        .child(TextView::new(super::CATALOG.gettext("Ripasso uses GPG in order to encrypt the stored passwords.\nPlease enter your GPG key ID")))
        .child(EditView::new().with_name("initial_key_id"))
    )
        .button(super::CATALOG.gettext("Create"), move |ui: &mut Cursive| {
            do_create(ui, &password_store_dir2, &home);
        });

    let password_store_dir3 = password_store_dir.clone();
    let recipients_event = OnEventView::new(d2).on_event(Key::Enter, move |ui: &mut Cursive| {
        do_create(ui, &password_store_dir3, &home2);
    });

    ui.add_layer(recipients_event);
}

pub fn show_init_menu(password_store_dir: &Option<PathBuf>, home: &Option<PathBuf>) {
    let mut ui = Cursive::default();

    ui.load_toml(include_str!("../res/style.toml")).unwrap();

    let results = SelectView::<pass::PasswordEntry>::new()
        .with_name("results")
        .full_height();

    let search_box = EditView::new().full_width();

    ui.add_layer(
        LinearLayout::new(Orientation::Vertical)
            .child(
                Dialog::around(
                    LinearLayout::new(Orientation::Vertical)
                        .child(search_box)
                        .child(results)
                        .full_width(),
                )
                .title("Ripasso"),
            )
            .child(
                LinearLayout::new(Orientation::Horizontal)
                    .child(TextView::new(super::CATALOG.gettext("F1: Menu | ")))
                    .full_width(),
            ),
    );

    let password_store_dir2 = password_store_dir.clone();
    let home = home.clone();
    let d = Dialog::around(TextView::new(super::CATALOG.gettext("Welcome to Ripasso, it seems like you don't have a password store directory yet would you like to create it?\nIt's created in $HOME/.password-store or where the PASSWORD_STORE_DIR environmental variable points.")))
        .button(super::CATALOG.gettext("Create"), move |ui: &mut Cursive| {
            create_store(ui, &password_store_dir2, &home);
        })
        .button(super::CATALOG.gettext("Cancel"), |s| {
            s.quit();
            std::process::exit(0);
        })
        .title(super::CATALOG.gettext("Init"));

    ui.add_layer(d);

    ui.run();
}
