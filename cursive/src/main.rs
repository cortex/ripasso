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
    Dialog, EditView, LinearLayout, OnEventView, SelectView, TextArea, TextView, CircularFocus,
};

use cursive::Cursive;

use self::cursive::direction::Orientation;
use self::cursive::event::{Event, Key};

extern crate clipboard;
use self::clipboard::{ClipboardContext, ClipboardProvider};

use ripasso::pass;
use std::process;
use std::{thread, time};

fn down(ui: &mut Cursive) -> () {
    ui.call_on_id("results", |l: &mut SelectView<pass::PasswordEntry>| {
        l.select_down(1);
    });
}

fn up(ui: &mut Cursive) -> () {
    ui.call_on_id("results", |l: &mut SelectView<pass::PasswordEntry>| {
        l.select_up(1);
    });
}

fn errorbox(ui: &mut Cursive, err: &pass::Error) -> () {
    let d = Dialog::around(TextView::new(format!("{:?}", err)))
        .dismiss_button("Ok")
        .title("Error");

    let ev = OnEventView::new(d)
        .on_event(Key::Esc, |s| {
            s.pop_layer();
        });

    ui.add_layer(ev);
}

fn copy(ui: &mut Cursive) -> () {
    let l = ui.find_id::<SelectView<pass::PasswordEntry>>("results").unwrap();

    let sel = l.selection();

    if sel.is_none() {
        return;
    }

    let password = sel.unwrap().password();

    if password.is_err() {
        errorbox(ui, &password.unwrap_err());
        return;
    }

    let ctx_res = clipboard::ClipboardContext::new();
    if ctx_res.is_err() {
        errorbox(ui, &pass::Error::GenericDyn(format!("{}", &ctx_res.err().unwrap())));
        return;
    }
    let mut ctx: ClipboardContext = ctx_res.unwrap();
    ctx.set_contents(password.unwrap().to_owned()).unwrap();

    thread::spawn(|| {
        thread::sleep(time::Duration::from_secs(40));
        let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
        ctx.set_contents("".to_string()).unwrap();
    });
}

fn do_delete(ui: &mut Cursive) -> () {
    ui.call_on_id("results", |l: &mut SelectView<pass::PasswordEntry>| {
        let sel = l.selection();

        if sel.is_none() {
            return;
        }

        let sel = sel.unwrap();

        let r = sel.delete_file();

        if r.is_err() {
            return;
        }

        let delete_id = l.selected_id().unwrap();
        l.remove_item(delete_id);
    });

    ui.pop_layer();
}

fn delete(ui: &mut Cursive) -> () {
    ui.add_layer(CircularFocus::wrap_tab(
    Dialog::around(TextView::new("Are you sure you want to delete the password"))
        .button("Yes", do_delete)
        .dismiss_button("Cancel")));
}

fn open(ui: &mut Cursive) -> () {
    let password_entry_option: Option<Option<std::rc::Rc<ripasso::pass::PasswordEntry>>> = ui
        .call_on_id("results", |l: &mut SelectView<pass::PasswordEntry>| {
            l.selection()
        });

    let password_entry: pass::PasswordEntry = (*(match password_entry_option {
        Some(level_1) => {
            match level_1 {
                Some(level_2) => level_2,
                None => return
            }
        },
        None => return
    })).clone();

    let password = match password_entry.secret() {
        Ok(p) => p,
        Err(_e) => return
    };
    let d =
        Dialog::around(TextArea::new().content(password).with_id("editbox"))
            .button("Save", move |s| {
                let new_password = s
                    .call_on_id("editbox", |e: &mut TextArea| {
                        e.get_content().to_string()
                    }).unwrap();
                let r = password_entry.update(new_password);
                if r.is_err() {
                    errorbox(s, &r.unwrap_err())
                }
            })
            .button("Generate", move |s| {
                let new_password = ripasso::pass::generate_password(6);
                s.call_on_id("editbox", |e: &mut TextArea| {
                    e.set_content(new_password);
                });
            })
            .dismiss_button("Ok");

    let ev = OnEventView::new(d)
        .on_event(Key::Esc, |s| {
            s.pop_layer();
        });

    ui.add_layer(ev);
}

fn get_value_from_input(s: &mut Cursive, input_name: &str) -> Option<std::rc::Rc<String>> {
    let mut password= None;
    s.call_on_id(input_name, |e: &mut EditView| {
        password = Some(e.get_content());
    });
    return password;
}

fn create_save(s: &mut Cursive) -> () {
    let password = get_value_from_input(s, "new_password_input");
    if password.is_none() {
        return;
    }
    let password = password.unwrap();
    if *password == "" {
        return;
    }

    let path = get_value_from_input(s, "new_path_input");
    if path.is_none() {
        return;
    }
    let path = path.unwrap();
    if *path == "" {
        return;
    }

    let res = pass::new_password_file(path.clone(), password);

    let col = s.screen_size().x;
    if res.is_err() {
        errorbox(s, &res.err().unwrap())
    } else {
        s.call_on_id("results", |l: &mut SelectView<pass::PasswordEntry>| {
            let mut path_buf: std::path::PathBuf = pass::password_dir().unwrap();

            let path_iter = &mut path.split("/");
            while let Some(p) = path_iter.next() {
                path_buf.push(p);
            }
            path_buf.set_extension("gpg");

            match pass::to_password(&pass::password_dir().unwrap(), &path_buf) {
                Ok(e) => l.add_item(create_label(&e, col), e),
                Err(_) => println!("error")
            }
        });

        s.pop_layer();
    }
}

fn create(ui: &mut Cursive) -> () {
    let mut fields = LinearLayout::vertical();
    let mut path_fields = LinearLayout::horizontal();
    let mut password_fields = LinearLayout::horizontal();
    path_fields.add_child(TextView::new("Path: ")
        .with_id("path_name")
        .fixed_size((10, 1)));
    path_fields.add_child(EditView::new()
            .with_id("new_path_input")
            .fixed_size((50, 1)));
    password_fields.add_child(TextView::new("Password: ")
        .with_id("password_name")
        .fixed_size((10, 1)));
    password_fields.add_child(EditView::new()
        .with_id("new_password_input")
        .fixed_size((50, 1)));
    fields.add_child(path_fields);
    fields.add_child(password_fields);

    let d =
        Dialog::around(fields)
            .title("Add new password")
            .button("Generate", move |s| {
                let new_password = ripasso::pass::generate_password(6);
                s.call_on_id("new_password_input", |e: &mut EditView| {
                    e.set_content(new_password);
                });
            })
            .button("Save", create_save)
            .dismiss_button("Cancel");

    let ev = OnEventView::new(d)
        .on_event(Key::Esc, |s| {
            s.pop_layer();
        })
        .on_event(Key::Enter, create_save);

    ui.add_layer(ev);
}

fn delete_signer(ui: &mut Cursive) -> () {
    let mut l = ui.find_id::<SelectView<pass::Signer>>("signers").unwrap();
    let sel = l.selection();

    if sel.is_none() {
        return;
    }

    let r = ripasso::pass::Signer::remove_signer_from_file(&sel.unwrap());

    if r.is_err() {
        errorbox(ui, &r.unwrap_err());
    } else {
        let delete_id = l.selected_id().unwrap();
        l.remove_item(delete_id);
    }
}

fn delete_signer_verification(ui: &mut Cursive) -> () {
    ui.add_layer(CircularFocus::wrap_tab(
        Dialog::around(TextView::new("Are you sure you want to remove this person?"))
            .button("Yes", delete_signer)
            .dismiss_button("Cancel")));
}

fn add_signer(ui: &mut Cursive) -> () {
    let l = &*get_value_from_input(ui, "key_id_input").unwrap();

    let signer_result = pass::Signer::from_key_id(l.clone());

    if signer_result.is_err() {
        errorbox(ui, &signer_result.err().unwrap());
    } else {
        let res = pass::Signer::add_signer_to_file(&signer_result.unwrap());
        if res.is_err() {
            errorbox(ui, &res.unwrap_err());
        } else {
            ui.pop_layer();
        }
    }
}

fn add_signer_dialog(ui: &mut Cursive) -> () {
    let mut signer_fields = LinearLayout::horizontal();

    signer_fields.add_child(TextView::new("GPG Key Id: ")
        .with_id("key_id")
        .fixed_size((16, 1)));

    let gpg_key_edit_view = OnEventView::new(EditView::new()
        .with_id("key_id_input")
        .fixed_size((50, 1)))
        .on_event(Key::Enter, add_signer);

    signer_fields.add_child(gpg_key_edit_view);

    let cf = CircularFocus::wrap_tab(
        Dialog::around(signer_fields)
            .button("Yes", add_signer)
            .dismiss_button("Cancel"));

    let ev = OnEventView::new(cf)
        .on_event(Key::Esc, |s| {
            s.pop_layer();
        });

    ui.add_layer(ev);
}

fn view_signers(ui: &mut Cursive) -> () {
    let signers : Vec<ripasso::pass::Signer> = ripasso::pass::Signer::all_signers();

    let mut signers_view = SelectView::<pass::Signer>::new()
        .h_align(cursive::align::HAlign::Left)
        .with_id("signers");

    for signer in signers {
        signers_view.get_mut().add_item(format!("{} {}",signer.key_id.clone(), signer.name.clone()), signer);
    }

    let d = Dialog::around(signers_view)
        .title("People")
        .dismiss_button("Ok");

    let ll = LinearLayout::new(Orientation::Vertical)
        .child(d)
        .child(LinearLayout::new(Orientation::Horizontal)
            .child(TextView::new("ins: Add | "))
            .child(TextView::new("del: Remove")));

    let signers_event = OnEventView::new(ll)
        .on_event(Key::Del, delete_signer_verification)
        .on_event(Key::Ins, add_signer_dialog)
        .on_event(Key::Esc, |s| {
            s.pop_layer();
        });

    ui.add_layer(signers_event);
}

fn create_label(p: &pass::PasswordEntry, col: usize) -> String {
    return format!("{:2$}  {}",
                p.name,
                match p.updated {
                    Some(d) => format!("{}", d.format("%Y-%m-%d")),
                    None => "n/a".to_string(),
                },
                _ = col - 10 - 8, // Optimized for 80 cols
            );
}

fn search(passwords: &pass::PasswordList, ui: &mut Cursive, query: &str) -> () {
    let col = ui.screen_size().x;
    ui.call_on_id("results", |l: &mut SelectView<pass::PasswordEntry>| {
        let r = pass::search(&passwords, &String::from(query));
        l.clear();
        for p in &r {
            l.add_item(create_label(&p, col), p.clone());
        }
    });
}

fn help() {
    println!("A password manager that uses the file format of the standard unix password manager 'pass', implemented in rust.
Ripasso reads $HOME/.password-store/ by default, override this by setting the PASSWORD_STORE_DIR environmental variable.");
}

fn git_push(ui: &mut Cursive) {
    let res = pass::push();

    if res.is_err() {
        errorbox(ui, &res.unwrap_err());
    }
}

fn git_pull(ui: &mut Cursive, passwords: pass::PasswordList) {
    let pull_res = pass::pull();

    if pull_res.is_err() {
        errorbox(ui, &pull_res.unwrap_err());
    }

    let res = pass::populate_password_list(&passwords);
    if res.is_err() {
        errorbox(ui, &res.unwrap_err());
    }

    let col = ui.screen_size().x;

    ui.call_on_id("results", |l: &mut SelectView<pass::PasswordEntry>| {
        l.clear();
        for p in passwords.lock().unwrap().iter() {
            l.add_item(create_label(&p, col), p.clone());
        }
    });
}

fn show_init_menu() {
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
                .child(TextView::new("C-V: Signers | "))
                .child(TextView::new("ins: Create | "))
                .child(TextView::new("esc: Quit"))
                .full_width(),
        ),
    );

    let d = Dialog::around(TextView::new("Welcome to ripasso, it seems like you don't have a password store directory yet
would you like to create it?"))
        .button("Create", |s| {
            let d2 = Dialog::around(LinearLayout::new(Orientation::Vertical)
                    .child(TextView::new("Please enter your gpg key id"))
                    .child(EditView::new().with_id("initial_key_id"))
                )
                .button("Create", |s| {
                    let l = s.find_id::<EditView>("initial_key_id").unwrap();
                    let key_id = (*l.get_content()).clone();
                    let mut pass_home = pass::password_dir_raw();
                    let create_res = std::fs::create_dir_all(&pass_home);
                    if create_res.is_err() {
                        errorbox(s, &pass::Error::IO(create_res.unwrap_err()));
                        s.quit();
                    } else {
                        pass_home.push(".gpg-id");
                        std::fs::write(pass_home, key_id).expect("Unable to write file");
                        s.quit();
                    }
                });

            s.add_layer(d2);
        })
        .button("Cancel", |s| {
            s.quit();
        })
        .title("Init");

    ui.add_layer(d);

    ui.run();
}

fn main() {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();

    match args.len() {
        2 => {
            if args[1] == "-h" || args[1] == "--help" {
                help();
                std::process::exit(0);
            }
        },
        _ => {}
    }

    if pass::password_dir().is_err() {
        show_init_menu();
    }

    // Load and watch all the passwords in the background
    let (password_rx, passwords) = match pass::watch() {
        Ok(t) => t,
        Err(e) => {
            println!("Error {:?}", e);
            process::exit(1);
        }
    };

    let mut ui = Cursive::default();

    // Update UI on password change event
    let e = ui.cb_sink().send(Box::new(move |s: &mut Cursive| {
        let event = password_rx.try_recv();
        if let Ok(e) = event {
            if let pass::PasswordEvent::Error(ref err) = e {
                errorbox(s, err)
            }
        }
    }));

    if e.is_err() {
        eprintln!("Application error: {}", e.err().unwrap());
        return;
    }

    ui.add_global_callback(Event::CtrlChar('y'), copy);
    ui.add_global_callback(Key::Enter, copy);
    ui.add_global_callback(Key::Del, delete);

    // Movement
    ui.add_global_callback(Event::CtrlChar('n'), down);
    ui.add_global_callback(Event::CtrlChar('p'), up);

    // View list of persons that have access
    ui.add_global_callback(Event::CtrlChar('v'), view_signers);

    // Query editing
    ui.add_global_callback(Event::CtrlChar('w'), |ui| {
        ui.call_on_id("searchbox", |e: &mut EditView| {
            e.set_content("");
        });
    });

    // Editing
    ui.add_global_callback(Event::CtrlChar('o'), open);
    let passwords_git_pull_clone = std::sync::Arc::clone(&passwords);
    ui.add_global_callback(Event::CtrlChar('f'), move |ui: &mut Cursive| {
        git_pull(ui, passwords_git_pull_clone.clone())
    });
    ui.add_global_callback(Event::CtrlChar('g'), git_push);
    ui.add_global_callback(Event::Key(cursive::event::Key::Ins), create);

    ui.add_global_callback(Event::Key(cursive::event::Key::Esc), |s| s.quit());

    ui.load_toml(include_str!("../res/style.toml")).unwrap();
    let passwords_clone = std::sync::Arc::clone(&passwords);
    let searchbox = EditView::new()
        .on_edit(move |ui: &mut cursive::Cursive, query, _| {
            search(&passwords_clone, ui, query)
        }).with_id("searchbox")
        .fixed_width(72);

    // Override shortcuts on search box
    let searchbox = OnEventView::new(searchbox)
        .on_event(Key::Up, up)
        .on_event(Key::Down, down);

    let results = SelectView::<pass::PasswordEntry>::new()
        .with_id("results")
        .full_height();

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
                    .child(TextView::new("C-V: Signers | "))
                    .child(TextView::new("C-F: Git Pull | "))
                    .child(TextView::new("C-G: Git Push | "))
                    .child(TextView::new("ins: Create | "))
                    .child(TextView::new("esc: Quit"))
                    .full_width(),
            ),
    );

    // This construction is to make sure that the password list is populated when the program starts
    // it would be better to signal this somehow from the library, but that got tricky
    thread::sleep(time::Duration::from_millis(200));
    search(&passwords, &mut ui, "");

    ui.run();
}
