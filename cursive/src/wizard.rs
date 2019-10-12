/*  Ripasso - a simple password manager
    Copyright (C) 2019 Joakim Lundborg, Alexander Kjäll

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

extern crate cursive;
extern crate env_logger;
extern crate ripasso;

use self::cursive::traits::*;
use self::cursive::views::{
    Dialog, EditView, LinearLayout, SelectView, TextView,
};

use cursive::Cursive;

use self::cursive::direction::Orientation;

use std::sync::Arc;

use ripasso::pass;
use crate::helpers;

fn create_git_repo(ui: &mut Cursive) {
    let init_res = pass::init_git_repo(&pass::password_dir().unwrap());
    if init_res.is_err() {
        helpers::errorbox(ui, &init_res.err().unwrap());
    } else {
        let repo = git2::Repository::open(&pass::password_dir().unwrap()).unwrap();
        let message = "Initialized password repo with ripasso";
        let commit_res = pass::add_and_commit(Arc::new(Some(repo)), &vec![".gpg-id".to_string()], &message);

        if commit_res.is_err() {
            helpers::errorbox(ui, &commit_res.err().unwrap());
        } else {
            ui.quit();
        }
    }
}

fn create_store(ui: &mut Cursive) {
    let d2 = Dialog::around(LinearLayout::new(Orientation::Vertical)
        .child(TextView::new("Ripasso uses gpg in order to encrypt the stored passwords.\nPlease enter your gpg key id"))
        .child(EditView::new().with_id("initial_key_id"))
    )
        .button("Create", |s| {
            let l = s.find_id::<EditView>("initial_key_id").unwrap();
            let key_id = (*l.get_content()).clone();
            let mut pass_home = pass::password_dir_raw();
            let create_res = std::fs::create_dir_all(&pass_home);
            if create_res.is_err() {
                helpers::errorbox(s, &pass::Error::IO(create_res.unwrap_err()));
                s.quit();
            } else {
                pass_home.push(".gpg-id");
                std::fs::write(pass_home, key_id).expect("Unable to write file");

                let d = Dialog::around(TextView::new("Also create a git repository for the encrypted files?"))
                    .button("Create", create_git_repo)
                    .button("No", |s| {
                        s.quit();
                    })
                    .title("Git init");

                s.add_layer(d);
            }
        });

    ui.add_layer(d2);
}

pub fn show_init_menu() {
    let mut ui = Cursive::default();

    ui.load_toml(include_str!("../res/style.toml")).unwrap();

    let results = SelectView::<pass::PasswordEntry>::new()
        .with_id("results")
        .full_height();

    let searchbox = EditView::new().fixed_width(72);

    ui.add_layer(
        LinearLayout::new(Orientation::Vertical)
            .child(
                Dialog::around(
                    LinearLayout::new(Orientation::Vertical)
                        .child(searchbox)
                        .child(results)
                        .fixed_width(72),
                ).title("Ripasso"),
            ).child(
            LinearLayout::new(Orientation::Horizontal)
                .child(TextView::new("C-N: Next | "))
                .child(TextView::new("C-P: Previous | "))
                .child(TextView::new("C-Y: Copy | "))
                .child(TextView::new("C-W: Clear | "))
                .child(TextView::new("C-O: Open | "))
                .child(TextView::new("C-V: Recipients | "))
                .child(TextView::new("ins: Create | "))
                .child(TextView::new("esc: Quit"))
                .full_width(),
        ),
    );

    let d = Dialog::around(TextView::new("Welcome to ripasso, it seems like you don't have a password store directory yet
would you like to create it?"))
        .button("Create", create_store)
        .button("Cancel", |s| {
            s.quit();
        })
        .title("Init");

    ui.add_layer(d);

    ui.run();
}

