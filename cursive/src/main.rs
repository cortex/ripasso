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
    CircularFocus, Dialog, EditView, LinearLayout, NamedView, OnEventView, ResizedView, ScrollView,
    SelectView, TextArea, TextView,
};

use cursive::menu::MenuTree;
use cursive::Cursive;

use self::cursive::direction::Orientation;
use self::cursive::event::{Event, Key};

extern crate clipboard;
use self::clipboard::{ClipboardContext, ClipboardProvider};

use ripasso::pass;
use ripasso::pass::{OwnerTrustLevel, PasswordStore, PasswordStoreType, SignatureStatus};
use std::process;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::{thread, time};

use std::collections::HashMap;
use unic_langid::LanguageIdentifier;

mod helpers;
mod wizard;

#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref CATALOG: gettext::Catalog = get_translation_catalog();
}

fn down(ui: &mut Cursive) {
    ui.call_on_name("results", |l: &mut SelectView<pass::PasswordEntry>| {
        l.select_down(1);
    });
    ui.call_on_name(
        "scroll_results",
        |l: &mut ScrollView<ResizedView<NamedView<SelectView<pass::PasswordEntry>>>>| {
            l.scroll_to_important_area();
        },
    );
}

fn up(ui: &mut Cursive) {
    ui.call_on_name("results", |l: &mut SelectView<pass::PasswordEntry>| {
        l.select_up(1);
    });
    ui.call_on_name(
        "scroll_results",
        |l: &mut ScrollView<ResizedView<NamedView<SelectView<pass::PasswordEntry>>>>| {
            l.scroll_to_important_area();
        },
    );
}

fn page_down(ui: &mut Cursive) {
    let mut l = ui
        .find_name::<SelectView<pass::PasswordEntry>>("results")
        .unwrap();
    l.select_down(ui.screen_size().y);
    ui.call_on_name(
        "scroll_results",
        |l: &mut ScrollView<ResizedView<NamedView<SelectView<pass::PasswordEntry>>>>| {
            l.scroll_to_important_area();
        },
    );
}

fn page_up(ui: &mut Cursive) {
    let mut l = ui
        .find_name::<SelectView<pass::PasswordEntry>>("results")
        .unwrap();
    l.select_up(ui.screen_size().y);
    ui.call_on_name(
        "scroll_results",
        |l: &mut ScrollView<ResizedView<NamedView<SelectView<pass::PasswordEntry>>>>| {
            l.scroll_to_important_area();
        },
    );
}

fn copy(ui: &mut Cursive) {
    let sel = ui
        .find_name::<SelectView<pass::PasswordEntry>>("results")
        .unwrap()
        .selection();

    if sel.is_none() {
        return;
    }
    if let Err(err) = || -> pass::Result<()> {
        let password = sel.unwrap().password()?;
        let mut ctx = clipboard::ClipboardContext::new()?;
        ctx.set_contents(password)?;
        Ok(())
    }() {
        helpers::errorbox(ui, &err);
        return;
    }

    thread::spawn(|| {
        thread::sleep(time::Duration::from_secs(40));
        let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
        ctx.set_contents("".to_string()).unwrap();
    });
    ui.call_on_name("status_bar", |l: &mut TextView| {
        l.set_content(CATALOG.gettext("Copied password to copy buffer for 40 seconds"));
    });
}

fn do_delete(ui: &mut Cursive, store: &PasswordStoreType) {
    ui.call_on_name("results", |l: &mut SelectView<pass::PasswordEntry>| {
        let sel = l.selection();

        if sel.is_none() {
            return;
        }

        let sel = sel.unwrap();
        let store = store.lock().unwrap();
        let r = sel.delete_file(&store);

        if r.is_err() {
            return;
        }

        let delete_id = l.selected_id().unwrap();
        l.remove_item(delete_id);
    });

    ui.pop_layer();
}

fn delete(ui: &mut Cursive, store: PasswordStoreType) {
    ui.add_layer(CircularFocus::wrap_tab(
        Dialog::around(TextView::new(
            CATALOG.gettext("Are you sure you want to delete the password?"),
        ))
        .button(CATALOG.gettext("Yes"), move |ui: &mut Cursive| {
            do_delete(ui, &store);
            ui.call_on_name("status_bar", |l: &mut TextView| {
                l.set_content(CATALOG.gettext("Password deleted"));
            });
        })
        .dismiss_button(CATALOG.gettext("Cancel")),
    ));
}

fn get_selected_password_entry(ui: &mut Cursive) -> Option<ripasso::pass::PasswordEntry> {
    let password_entry_option: Option<Option<std::rc::Rc<ripasso::pass::PasswordEntry>>> = ui
        .call_on_name("results", |l: &mut SelectView<pass::PasswordEntry>| {
            l.selection()
        });

    let password_entry: pass::PasswordEntry = (*(match password_entry_option {
        Some(level_1) => match level_1 {
            Some(level_2) => level_2,
            None => return None,
        },
        None => return None,
    }))
    .clone();

    Some(password_entry)
}

fn show_file_history(ui: &mut Cursive, store: PasswordStoreType) {
    let password_entry_opt = get_selected_password_entry(ui);
    if password_entry_opt.is_none() {
        return;
    }
    let password_entry = password_entry_opt.unwrap();

    let mut file_history_view = SelectView::<pass::GitLogLine>::new()
        .h_align(cursive::align::HAlign::Left)
        .with_name("file_history");

    let history = password_entry.get_history(&store);

    match history {
        Ok(history) => {
            for history_line in history {
                let mut verification_status = "  ";
                if history_line.signature_status.is_some() {
                    verification_status = match history_line.signature_status.as_ref().unwrap() {
                        SignatureStatus::Good => "🔒",
                        SignatureStatus::AlmostGood => "🔓",
                        SignatureStatus::Bad => "⛔",
                    }
                }

                file_history_view.get_mut().add_item(
                    format!(
                        "{} {} {}",
                        verification_status, history_line.commit_time, history_line.message
                    ),
                    history_line,
                );
            }

            let d = Dialog::around(file_history_view)
                .title(CATALOG.gettext("File History"))
                .dismiss_button("Ok");

            let file_history_event = OnEventView::new(d).on_event(Key::Esc, |s| {
                s.pop_layer();
            });

            ui.add_layer(file_history_event);
        }
        Err(err) => helpers::errorbox(ui, &err),
    }
}

fn open(ui: &mut Cursive, store: PasswordStoreType) {
    let password_entry_opt = get_selected_password_entry(ui);
    if password_entry_opt.is_none() {
        return;
    }

    let password_entry = password_entry_opt.unwrap();

    let password = match password_entry.secret() {
        Ok(p) => p,
        Err(_e) => return,
    };
    let d = Dialog::around(TextArea::new().content(password).with_name("editbox"))
        .button(CATALOG.gettext("Save"), move |s| {
            let new_password = s
                .call_on_name("editbox", |e: &mut TextArea| e.get_content().to_string())
                .unwrap();
            let store = store.lock().unwrap();
            let r = password_entry.update(new_password, &(*store));
            if let Err(err) = r {
                helpers::errorbox(s, &err)
            } else {
                s.call_on_name("status_bar", |l: &mut TextView| {
                    l.set_content(CATALOG.gettext("Updated password entry"));
                });

                s.pop_layer();
            }
        })
        .button(CATALOG.gettext("Generate"), move |s| {
            let new_password = ripasso::words::generate_password(6);
            s.call_on_name("editbox", |e: &mut TextArea| {
                e.set_content(new_password);
            });
        })
        .dismiss_button(CATALOG.gettext("Close"));

    let ev = OnEventView::new(d).on_event(Key::Esc, |s| {
        s.pop_layer();
    });

    ui.add_layer(ev);
}

fn get_value_from_input(s: &mut Cursive, input_name: &str) -> Option<std::rc::Rc<String>> {
    let mut password = None;
    s.call_on_name(input_name, |e: &mut EditView| {
        password = Some(e.get_content());
    });
    password
}

fn create_save(s: &mut Cursive, store: PasswordStoreType) {
    let password = get_value_from_input(s, "new_password_input");
    if password.is_none() {
        return;
    }
    let mut password = password.unwrap();
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

    let note = s.call_on_name("note_input", |e: &mut TextArea| e.get_content().to_string());
    if let Some(note) = note {
        password = Rc::from(format!("{}\n{}", password, note));
    }

    let mut store = store.lock().unwrap();
    let entry = store.new_password_file(path.as_ref(), password.as_ref());

    match entry {
        Err(err) => helpers::errorbox(s, &err),
        Ok(entry) => {
            let col = s.screen_size().x;
            s.call_on_name("results", |l: &mut SelectView<pass::PasswordEntry>| {
                l.add_item(create_label(&entry, col), entry);
            });

            s.pop_layer();

            s.call_on_name("status_bar", |l: &mut TextView| {
                l.set_content(CATALOG.gettext("Created new password"));
            });
        }
    }
}

fn create(ui: &mut Cursive, store: PasswordStoreType) {
    let mut fields = LinearLayout::vertical();
    let mut path_fields = LinearLayout::horizontal();
    let mut password_fields = LinearLayout::horizontal();
    let mut note_fields = LinearLayout::horizontal();
    path_fields.add_child(
        TextView::new(CATALOG.gettext("Path: "))
            .with_name("path_name")
            .fixed_size((10, 1)),
    );
    path_fields.add_child(
        EditView::new()
            .with_name("new_path_input")
            .fixed_size((50, 1)),
    );
    password_fields.add_child(
        TextView::new(CATALOG.gettext("Password: "))
            .with_name("password_name")
            .fixed_size((10, 1)),
    );
    password_fields.add_child(
        EditView::new()
            .secret()
            .with_name("new_password_input")
            .fixed_size((50, 1)),
    );
    note_fields.add_child(
        TextView::new(CATALOG.gettext("Note: "))
            .with_name("note_name")
            .fixed_size((10, 1)),
    );
    note_fields.add_child(TextArea::new().with_name("note_input").min_size((50, 1)));
    fields.add_child(path_fields);
    fields.add_child(password_fields);
    fields.add_child(note_fields);

    let store2 = store.clone();

    let d = Dialog::around(fields)
        .title(CATALOG.gettext("Add new password"))
        .button(CATALOG.gettext("Generate"), move |s| {
            let new_password = ripasso::words::generate_password(6);
            s.call_on_name("new_password_input", |e: &mut EditView| {
                e.set_content(new_password);
            });
        })
        .button(CATALOG.gettext("Save"), move |ui: &mut Cursive| {
            create_save(ui, store.clone())
        })
        .dismiss_button(CATALOG.gettext("Cancel"));

    let ev = OnEventView::new(d)
        .on_event(Key::Esc, |s| {
            s.pop_layer();
        })
        .on_event(Key::Enter, move |ui: &mut Cursive| {
            create_save(ui, store2.clone())
        });

    ui.add_layer(ev);
}

fn delete_recipient(ui: &mut Cursive, store: PasswordStoreType) {
    let mut l = ui
        .find_name::<SelectView<pass::Recipient>>("recipients")
        .unwrap();
    let sel = l.selection();

    if sel.is_none() {
        return;
    }

    let store = store.lock().unwrap();
    match store.remove_recipient(&sel.unwrap()) {
        Err(err) => helpers::errorbox(ui, &err),
        Ok(_) => {
            let delete_id = l.selected_id().unwrap();
            l.remove_item(delete_id);
            ui.call_on_name("status_bar", |l: &mut TextView| {
                l.set_content(CATALOG.gettext("Deleted team member from password store"));
            });
        }
    }
}

fn delete_recipient_verification(ui: &mut Cursive, store: PasswordStoreType) {
    ui.add_layer(CircularFocus::wrap_tab(
        Dialog::around(TextView::new(
            CATALOG.gettext("Are you sure you want to remove this person?"),
        ))
        .button(CATALOG.gettext("Yes"), move |ui: &mut Cursive| {
            delete_recipient(ui, store.clone());
            ui.pop_layer();
        })
        .dismiss_button(CATALOG.gettext("Cancel")),
    ));
}

fn add_recipient(ui: &mut Cursive, store: PasswordStoreType) {
    let l = &*get_value_from_input(ui, "key_id_input").unwrap();

    match pass::Recipient::new(l.clone()) {
        Err(err) => helpers::errorbox(ui, &err),
        Ok(recipient) => {
            if recipient.trust_level != OwnerTrustLevel::Ultimate {
                helpers::errorbox(ui, &pass::Error::Generic(CATALOG.gettext("Can't import team member due to that the GPG trust relationship level isn't Ultimate")));
                return;
            }

            let res = store.lock().unwrap().add_recipient(&recipient);
            match res {
                Err(err) => helpers::errorbox(ui, &err),
                Ok(_) => match store.lock().unwrap().all_recipients() {
                    Err(err) => helpers::errorbox(ui, &err),
                    Ok(recipients) => {
                        let mut max_width_key = 0;
                        let mut max_width_name = 0;
                        for recipient in &recipients {
                            if recipient.key_id.len() > max_width_key {
                                max_width_key = recipient.key_id.len();
                            }
                            if recipient.name.len() > max_width_name {
                                max_width_name = recipient.name.len();
                            }
                        }

                        let mut recipients_view = ui
                            .find_name::<SelectView<pass::Recipient>>("recipients")
                            .unwrap();
                        recipients_view.add_item(
                            render_recipient_label(&recipient, max_width_key, max_width_name),
                            recipient,
                        );

                        ui.pop_layer();
                        ui.call_on_name("status_bar", |l: &mut TextView| {
                            l.set_content(CATALOG.gettext("Added team member to password store"));
                        });
                    }
                },
            }
        }
    }
}

fn add_recipient_dialog(ui: &mut Cursive, store: PasswordStoreType) {
    let mut recipient_fields = LinearLayout::horizontal();

    recipient_fields.add_child(
        TextView::new(CATALOG.gettext("GPG Key ID: "))
            .with_name("key_id")
            .fixed_size((16, 1)),
    );

    let store2 = store.clone();

    let gpg_key_edit_view = OnEventView::new(
        EditView::new()
            .with_name("key_id_input")
            .fixed_size((50, 1)),
    )
    .on_event(Key::Enter, move |ui: &mut Cursive| {
        add_recipient(ui, store.clone())
    });

    recipient_fields.add_child(gpg_key_edit_view);

    let cf = CircularFocus::wrap_tab(
        Dialog::around(recipient_fields)
            .button(CATALOG.gettext("Yes"), move |ui: &mut Cursive| {
                add_recipient(ui, store2.clone())
            })
            .dismiss_button(CATALOG.gettext("Cancel")),
    );

    let ev = OnEventView::new(cf).on_event(Key::Esc, |s| {
        s.pop_layer();
    });

    ui.add_layer(ev);
}

fn render_recipient_label(
    recipient: &pass::Recipient,
    max_width_key: usize,
    max_width_name: usize,
) -> String {
    let symbol = match &recipient.key_ring_status {
        pass::KeyRingStatus::NotInKeyRing => "⚠️ ",
        pass::KeyRingStatus::InKeyRing => "  ️",
    };

    let trust = match &recipient.trust_level {
        OwnerTrustLevel::Ultimate => CATALOG.gettext("Ultimate"),
        OwnerTrustLevel::Full => CATALOG.gettext("Full"),
        OwnerTrustLevel::Marginal => CATALOG.gettext("Marginal"),
        OwnerTrustLevel::Never => CATALOG.gettext("Never"),
        OwnerTrustLevel::Undefined => CATALOG.gettext("Undefined"),
        OwnerTrustLevel::Unknown => CATALOG.gettext("Unknown"),
    };
    return format!(
        "{} {:width_key$} {:width_name$} {}   ",
        symbol,
        &recipient.key_id,
        &recipient.name,
        trust,
        width_key = max_width_key,
        width_name = max_width_name
    );
}

fn view_recipients(ui: &mut Cursive, store: PasswordStoreType) {
    let recipients_res = store.lock().unwrap().all_recipients();

    if let Err(err) = recipients_res {
        helpers::errorbox(ui, &err);
        return;
    }
    let recipients = recipients_res.unwrap();

    let mut recipients_view = SelectView::<pass::Recipient>::new()
        .h_align(cursive::align::HAlign::Left)
        .with_name("recipients");

    let mut max_width_key = 0;
    let mut max_width_name = 0;
    for recipient in &recipients {
        if recipient.key_id.len() > max_width_key {
            max_width_key = recipient.key_id.len();
        }
        if recipient.name.len() > max_width_name {
            max_width_name = recipient.name.len();
        }
    }
    for recipient in recipients {
        recipients_view.get_mut().add_item(
            render_recipient_label(&recipient, max_width_key, max_width_name),
            recipient,
        );
    }

    let d = Dialog::around(recipients_view)
        .title(CATALOG.gettext("Team Members"))
        .dismiss_button("Ok");

    let ll = LinearLayout::new(Orientation::Vertical).child(d).child(
        LinearLayout::new(Orientation::Horizontal)
            .child(TextView::new(CATALOG.gettext("ins: Add | ")))
            .child(TextView::new(CATALOG.gettext("del: Remove"))),
    );

    let store2 = store.clone();

    let recipients_event = OnEventView::new(ll)
        .on_event(Key::Del, move |ui: &mut Cursive| {
            delete_recipient_verification(ui, store.clone())
        })
        .on_event(Key::Ins, move |ui: &mut Cursive| {
            add_recipient_dialog(ui, store2.clone())
        })
        .on_event(Key::Esc, |s| {
            s.pop_layer();
        });

    ui.add_layer(recipients_event);
}

fn substr(str: &str, start: usize, len: usize) -> String {
    str.chars().skip(start).take(len).collect()
}

fn create_label(p: &pass::PasswordEntry, col: usize) -> String {
    let committed_by = p.committed_by.clone();
    let updated = p.updated;
    let name = substr(
        &match committed_by {
            Some(d) => d,
            None => CATALOG.gettext("n/a").to_string(),
        },
        0,
        15,
    );
    let mut verification_status = "  ";
    if p.signature_status.is_some() {
        verification_status = match p.signature_status.as_ref().unwrap() {
            SignatureStatus::Good => "🔒",
            SignatureStatus::AlmostGood => "🔓",
            SignatureStatus::Bad => "⛔",
        }
    }
    return format!("{:4$} {} {} {}",
        p.name,
        verification_status,
        name,
        match updated {
            Some(d) => format!("{}", d.format("%Y-%m-%d")),
            None => CATALOG.gettext("n/a").to_string(),
        },
        _ = col - 12 - 15 - 9, // Optimized for 80 cols
    );
}

fn search(store: &PasswordStoreType, ui: &mut Cursive, query: &str) {
    let col = ui.screen_size().x;
    let mut l = ui
        .find_name::<SelectView<pass::PasswordEntry>>("results")
        .unwrap();

    let r_res = pass::search(&store, &String::from(query));
    if let Err(err) = r_res {
        helpers::errorbox(ui, &err);
        return;
    }
    let r = r_res.unwrap();
    l.clear();
    for p in &r {
        l.add_item(create_label(&p, col), p.clone());
    }
}

fn help() {
    println!("{}", CATALOG.gettext("A password manager that uses the file format of the standard unix password manager 'pass', implemented in Rust. Ripasso reads $HOME/.password-store/ by default, override this by setting the PASSWORD_STORE_DIR environmental variable."));
}

fn git_push(ui: &mut Cursive, store: PasswordStoreType) {
    match pass::push(&(*store.lock().unwrap())) {
        Err(err) => helpers::errorbox(ui, &err),
        Ok(_) => {
            ui.call_on_name("status_bar", |l: &mut TextView| {
                l.set_content(CATALOG.gettext("Pushed to remote git repository"));
            });
        }
    }
}

fn git_pull(ui: &mut Cursive, store: PasswordStoreType) {
    let mut store = store.lock().unwrap();
    let _ = pass::pull(&store).map_err(|err| helpers::errorbox(ui, &err));
    let _ = store
        .reload_password_list()
        .map_err(|err| helpers::errorbox(ui, &err));

    let col = ui.screen_size().x;

    ui.call_on_name("results", |l: &mut SelectView<pass::PasswordEntry>| {
        l.clear();
        for p in store.passwords.iter() {
            l.add_item(create_label(&p, col), p.clone());
        }
    });
    ui.call_on_name("status_bar", |l: &mut TextView| {
        l.set_content(CATALOG.gettext("Pulled from remote git repository"));
    });
}

fn do_delete_last_word(ui: &mut Cursive, store: PasswordStoreType) {
    ui.call_on_name("search_box", |e: &mut EditView| {
        let s = e.get_content();
        let last_space = s.trim().rfind(' ');
        match last_space {
            Some(pos) => {
                e.set_content(s[0..pos + 1].to_string());
            }
            None => {
                e.set_content("");
            }
        };
    });
    let search_text = ui
        .find_name::<EditView>("search_box")
        .unwrap()
        .get_content();
    search(&store, ui, &search_text);
}

fn get_translation_catalog() -> gettext::Catalog {
    let locale = locale_config::Locale::current();

    let mut translation_locations = vec!["/usr/share/ripasso"];
    if let Some(path) = option_env!("TRANSLATION_INPUT_PATH") {
        translation_locations.insert(0, path);
    }
    if cfg!(debug_assertions) {
        translation_locations.insert(0, "./cursive/res");
    }

    for preferred in locale.tags_for("messages") {
        for loc in &translation_locations {
            let langid_res: Result<LanguageIdentifier, _> = format!("{}", preferred).parse();

            if let Ok(langid) = langid_res {
                let file = std::fs::File::open(format!("{}/{}.mo", loc, langid.get_language()));
                if let Ok(file) = file {
                    if let Ok(catalog) = gettext::Catalog::parse(file) {
                        return catalog;
                    }
                }
            }
        }
    }

    gettext::Catalog::empty()
}

fn get_stores(config: &config::Config) -> pass::Result<Vec<Arc<Mutex<PasswordStore>>>> {
    let mut final_stores: Vec<Arc<Mutex<PasswordStore>>> = vec![];
    let stores_res = config.get("stores");
    if let Ok(stores) = stores_res {
        let stores: HashMap<String, config::Value> = stores;

        for store_name in stores.keys() {
            let store: HashMap<String, config::Value> = stores
                .get(store_name)
                .unwrap()
                .clone()
                .into_table()
                .unwrap();

            let password_store_dir_opt = store.get("path");
            let valid_signing_keys_opt = store.get("valid_signing_keys");

            if password_store_dir_opt.is_some() {
                let password_store_dir = Some(password_store_dir_opt.unwrap().clone().into_str()?);

                let valid_signing_keys = match valid_signing_keys_opt {
                    Some(k) => Some(k.clone().into_str()?),
                    None => None,
                };

                final_stores.push(Arc::new(Mutex::new(PasswordStore::new(
                    store_name,
                    &password_store_dir,
                    &valid_signing_keys,
                )?)));
            }
        }
    }

    Ok(final_stores)
}

/// validates a vec of password stores.
/// Returns true if the new user wizard should be shown
fn validate_stores(stores: &[Arc<Mutex<PasswordStore>>]) -> pass::Result<bool> {
    if stores.is_empty() {
        return Ok(true);
    }

    for store in stores {
        let store = (*store).lock().unwrap();
        let validate_res = store.validate();
        if validate_res.is_err() {
            if stores.len() == 1 && store.is_default() {
                return Ok(true);
            }
            return validate_res;
        }
    }

    Ok(false)
}

fn main() {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();

    match args.len() {
        1 => (),
        2 => {
            if args[1] == "-h" || args[1] == "--help" {
                help();
                std::process::exit(0);
            } else {
                eprintln!(
                    "{}",
                    CATALOG.gettext("Unknown argument, usage: ripasso-cursive [-h|--help]")
                );
                process::exit(1);
            }
        }
        _ => {
            eprintln!(
                "{}",
                CATALOG.gettext("Unknown argument, usage: ripasso-cursive [-h|--help]")
            );
            process::exit(1);
        }
    }

    let config = {
        let password_store_dir = match std::env::var("PASSWORD_STORE_DIR") {
            Ok(p) => Some(p),
            Err(_) => None,
        };
        let password_store_signing_key = match std::env::var("PASSWORD_STORE_SIGNING_KEY") {
            Ok(p) => Some(p),
            Err(_) => None,
        };

        pass::read_config(password_store_dir, password_store_signing_key)
    };
    if config.is_err() {
        eprintln!("Error {:?}", config.err().unwrap());
        process::exit(1);
    }
    let config = config.unwrap();

    let stores = get_stores(&config);
    if stores.is_err() {
        eprintln!("Error {:?}", stores.err().unwrap());
        process::exit(1);
    }
    let stores: Vec<Arc<Mutex<PasswordStore>>> = stores.unwrap();

    match validate_stores(&stores) {
        Ok(b) => {
            if b {
                wizard::show_init_menu(&None);
                match validate_stores(&stores) {
                    Ok(_b) => {}
                    Err(err) => {
                        eprintln!("Error {:?}", err);
                        process::exit(1);
                    }
                }
            }
        }
        Err(err) => {
            eprintln!("Error {:?}", err);
            process::exit(1);
        }
    }

    let store = Arc::new(Mutex::new(
        PasswordStore::new(&"".to_string(), &None, &None).unwrap(),
    ));
    {
        let ss = stores[0].lock().unwrap();
        let ss_store_path = ss.get_store_path();
        let ss_signing_keys = ss.get_valid_gpg_signing_keys().clone();

        let change_res = store
            .lock()
            .unwrap()
            .reset(&ss_store_path, &ss_signing_keys);

        if let Err(err) = change_res {
            eprintln!("error loading passwords: {:?}", err);
            process::exit(1);
        }
    }

    // verify that the git config is correct
    if !(*store).lock().unwrap().has_configured_username() {
        eprintln!("{}", CATALOG.gettext("You haven't configured you name and email in git, doing so will make cooperation with your team easier, you can do it like this:\ngit config --global user.name \"John Doe\"\ngit config --global user.email \"email@example.com\"\n\nAlso consider configuring git to sign your commits with GPG:\ngit config --global user.signingkey 3AA5C34371567BD2\ngit config --global commit.gpgsign true"));
        process::exit(1);
    }

    for password in &(*store).lock().unwrap().passwords {
        if password.is_in_git == pass::RepositoryStatus::NotInRepo {
            eprintln!("{}", CATALOG.gettext("The password store is backed by a git repository, but there is passwords there that's not in git. Please add them, otherwise they might get lost."));
            process::exit(1);
        }
    }

    let mut ui = Cursive::default();

    ui.add_global_callback(Event::CtrlChar('y'), copy);
    ui.add_global_callback(Key::Enter, copy);
    ui.add_global_callback(Key::Del, {
        let store = store.clone();
        move |ui: &mut Cursive| delete(ui, store.clone())
    });

    // Movement
    ui.add_global_callback(Event::CtrlChar('n'), down);
    ui.add_global_callback(Event::CtrlChar('p'), up);
    ui.add_global_callback(Event::Key(cursive::event::Key::PageDown), page_down);
    ui.add_global_callback(Event::Key(cursive::event::Key::PageUp), page_up);

    // View list of persons that have access
    ui.add_global_callback(Event::CtrlChar('v'), {
        let store = store.clone();
        move |ui: &mut Cursive| view_recipients(ui, store.clone())
    });

    // Show git history of a file
    ui.add_global_callback(Event::CtrlChar('h'), {
        let store = store.clone();
        move |ui: &mut Cursive| show_file_history(ui, store.clone())
    });

    // Query editing
    ui.add_global_callback(Event::CtrlChar('w'), {
        let store = store.clone();
        move |ui: &mut Cursive| {
            do_delete_last_word(ui, store.clone());
        }
    });

    // Editing
    ui.add_global_callback(Event::CtrlChar('o'), {
        let store = store.clone();
        move |ui: &mut Cursive| open(ui, store.clone())
    });
    ui.add_global_callback(Event::CtrlChar('f'), {
        let store = store.clone();
        move |ui: &mut Cursive| git_pull(ui, store.clone())
    });
    ui.add_global_callback(Event::CtrlChar('g'), {
        let store = store.clone();
        move |ui: &mut Cursive| git_push(ui, store.clone())
    });
    ui.add_global_callback(Event::Key(cursive::event::Key::Ins), {
        let store = store.clone();
        move |ui: &mut Cursive| create(ui, store.clone())
    });

    ui.add_global_callback(Event::Key(cursive::event::Key::Esc), |s| s.quit());

    ui.load_toml(include_str!("../res/style.toml")).unwrap();
    let search_box = EditView::new()
        .on_edit({
            let store = store.clone();
            move |ui: &mut cursive::Cursive, query, _| search(&store, ui, query)
        })
        .with_name("search_box")
        .full_width();

    // Override shortcuts on search box
    let search_box = OnEventView::new(search_box)
        .on_event(Key::Up, up)
        .on_event(Key::Down, down);

    let results = SelectView::<pass::PasswordEntry>::new()
        .with_name("results")
        .full_height();

    let scroll_results = ScrollView::new(results).with_name("scroll_results");

    ui.add_layer(
        LinearLayout::new(Orientation::Vertical)
            .child(
                Dialog::around(
                    LinearLayout::new(Orientation::Vertical)
                        .child(search_box)
                        .child(scroll_results)
                        .full_width(),
                )
                .title("Ripasso"),
            )
            .child(
                LinearLayout::new(Orientation::Horizontal)
                    .child(TextView::new(CATALOG.gettext("F1: Menu | ")))
                    .child(TextView::new("").with_name("status_bar"))
                    .full_width(),
            ),
    );

    ui.menubar().add_subtree(
        CATALOG.gettext("Operations"),
        MenuTree::new()
            .leaf(CATALOG.gettext("Copy (ctrl-y)"), copy)
            .leaf(CATALOG.gettext("Open (ctrl-o)"), {
                let store = store.clone();
                move |ui: &mut Cursive| open(ui, store.clone())
            })
            .leaf(CATALOG.gettext("File History (ctrl-h)"), {
                let store = store.clone();
                move |ui: &mut Cursive| show_file_history(ui, store.clone())
            })
            .leaf(CATALOG.gettext("Create (ins) "), {
                let store = store.clone();
                move |ui: &mut Cursive| create(ui, store.clone())
            })
            .leaf(CATALOG.gettext("Delete (del)"), {
                let store = store.clone();
                move |ui: &mut Cursive| delete(ui, store.clone())
            })
            .leaf(CATALOG.gettext("Team Members (ctrl-v)"), {
                let store = store.clone();
                move |ui: &mut Cursive| view_recipients(ui, store.clone())
            })
            .delimiter()
            .leaf(CATALOG.gettext("Git Pull (ctrl-f)"), {
                let store = store.clone();
                move |ui: &mut Cursive| git_pull(ui, store.clone())
            })
            .leaf(CATALOG.gettext("Git Push (ctrl-g)"), {
                let store = store.clone();
                move |ui: &mut Cursive| git_push(ui, store.clone())
            })
            .delimiter()
            .leaf(CATALOG.gettext("Quit (esc)"), |s| s.quit()),
    );

    let mut tree = MenuTree::new();
    for s in stores {
        let ss = (*s).lock().unwrap();
        let store_name = ss.get_name().clone();
        let store = store.clone();
        let ss_store_path = ss.get_store_path();
        let ss_signing_keys = ss.get_valid_gpg_signing_keys().clone();
        tree.add_leaf(store_name, move |ui: &mut Cursive| {
            let change_res = store
                .lock()
                .unwrap()
                .reset(&ss_store_path, &ss_signing_keys);

            if let Err(err) = change_res {
                helpers::errorbox(ui, &err);
            }

            search(&store, ui, "");
        });
    }
    ui.menubar().add_subtree(CATALOG.gettext("Stores"), tree);

    ui.add_global_callback(Key::F1, |s| s.select_menubar());

    // This construction is to make sure that the password list is populated when the program starts
    // it would be better to signal this somehow from the library, but that got tricky
    thread::sleep(time::Duration::from_millis(200));
    search(&store, &mut ui, "");

    ui.run();
}
