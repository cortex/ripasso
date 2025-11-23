/*  Ripasso - a simple password manager
    Copyright (C) 2019-2020 Joakim Lundborg, Alexander Kjäll

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 3 of the License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    process,
    sync::{Arc, Mutex},
    thread, time,
};

use cursive::{
    Cursive, CursiveExt,
    direction::Orientation,
    event::{Event, Key},
    menu::Tree,
    traits::*,
    views::{
        Checkbox, CircularFocus, Dialog, EditView, LinearLayout, NamedView, OnEventView,
        RadioGroup, ResizedView, ScrollView, SelectView, TextArea, TextView,
    },
};
use hex::FromHex;
use pass::Result;
use ripasso::{
    crypto::CryptoImpl,
    git::{pull, push},
    pass,
    pass::{
        OwnerTrustLevel, PasswordStore, Recipient, SignatureStatus, all_recipients_from_stores,
    },
    passphrase_generator::passphrase_generator,
    password_generator::password_generator,
};
use unic_langid::LanguageIdentifier;

mod helpers;
mod wizard;

use lazy_static::lazy_static;
use zeroize::Zeroize;

use crate::helpers::{
    get_value_from_input, is_checkbox_checked, is_radio_button_selected, recipients_widths,
};

/// The 'pointer' to the current PasswordStore is of this convoluted type.
type PasswordStoreType = Arc<Mutex<Arc<Mutex<PasswordStore>>>>;
/// The list of stores that the user have.
type StoreListType = Arc<Mutex<Vec<Arc<Mutex<PasswordStore>>>>>;

lazy_static! {
    static ref CATALOG: gettext::Catalog = get_translation_catalog();
    static ref DEFAULT_TERMINAL_SIZE: (usize, usize) = match terminal_size::terminal_size() {
        Some((terminal_size::Width(w), terminal_size::Height(h))) =>
            (usize::from(w + 8), usize::from(h)),
        _ => (0, 0),
    };
}

fn screen_width(ui: &Cursive) -> usize {
    match ui.screen_size().x {
        0 => DEFAULT_TERMINAL_SIZE.0,
        w => w,
    }
}

fn screen_height(ui: &Cursive) -> usize {
    match ui.screen_size().y {
        0 => DEFAULT_TERMINAL_SIZE.1,
        h => h,
    }
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
    let rows = screen_height(ui) - 7;
    ui.call_on_name("results", |l: &mut SelectView<pass::PasswordEntry>| {
        l.select_down(rows);
    });
    ui.call_on_name(
        "scroll_results",
        |l: &mut ScrollView<ResizedView<NamedView<SelectView<pass::PasswordEntry>>>>| {
            l.scroll_to_important_area();
        },
    );
}

fn page_up(ui: &mut Cursive) {
    let rows = screen_height(ui) - 7;
    ui.call_on_name("results", |l: &mut SelectView<pass::PasswordEntry>| {
        l.select_up(rows);
    });
    ui.call_on_name(
        "scroll_results",
        |l: &mut ScrollView<ResizedView<NamedView<SelectView<pass::PasswordEntry>>>>| {
            l.scroll_to_important_area();
        },
    );
}

fn copy(ui: &mut Cursive, store: PasswordStoreType) {
    let sel = ui
        .find_name::<SelectView<pass::PasswordEntry>>("results")
        .unwrap()
        .selection();

    if sel.is_none() {
        return;
    }
    if let Err(err) = || -> Result<()> {
        let mut secret: String = sel.unwrap().secret(&*store.lock()?.lock()?)?;
        helpers::set_clipboard(&secret)?;
        secret.zeroize();
        Ok(())
    }() {
        helpers::errorbox(ui, &err);
        return;
    }

    thread::spawn(|| {
        thread::sleep(time::Duration::from_secs(40));
        helpers::set_clipboard(&String::new()).unwrap();
    });
    ui.call_on_name("status_bar", |l: &mut TextView| {
        l.set_content(CATALOG.gettext("Copied password to copy buffer for 40 seconds"));
    });
}

fn copy_first_line(ui: &mut Cursive, store: PasswordStoreType) {
    let sel = ui
        .find_name::<SelectView<pass::PasswordEntry>>("results")
        .unwrap()
        .selection();

    if sel.is_none() {
        return;
    }
    if let Err(err) = || -> Result<()> {
        let mut secret = sel.unwrap().password(&*store.lock()?.lock()?)?;
        helpers::set_clipboard(&secret)?;
        secret.zeroize();
        Ok(())
    }() {
        helpers::errorbox(ui, &err);
        return;
    }

    thread::spawn(|| {
        thread::sleep(time::Duration::from_secs(40));
        helpers::set_clipboard(&String::new()).unwrap();
    });
    ui.call_on_name("status_bar", |l: &mut TextView| {
        l.set_content(
            CATALOG.gettext("Copied first line of password to copy buffer for 40 seconds"),
        );
    });
}

fn copy_mfa(ui: &mut Cursive, store: PasswordStoreType) {
    let sel = ui
        .find_name::<SelectView<pass::PasswordEntry>>("results")
        .unwrap()
        .selection();

    if sel.is_none() {
        return;
    }
    if let Err(err) = || -> Result<()> {
        let mut secret = sel.unwrap().mfa(&*store.lock()?.lock()?)?;
        helpers::set_clipboard(&secret)?;
        secret.zeroize();
        Ok(())
    }() {
        helpers::errorbox(ui, &err);
        return;
    }

    ui.call_on_name("status_bar", |l: &mut TextView| {
        l.set_content(CATALOG.gettext("Copied MFA code to copy buffer"));
    });
}

fn copy_name(ui: &mut Cursive) {
    let sel = ui
        .find_name::<SelectView<pass::PasswordEntry>>("results")
        .unwrap()
        .selection();

    if sel.is_none() {
        return;
    }
    let sel = sel.unwrap();

    if let Err(err) = || -> Result<()> {
        let name = sel.name.split('/').next_back();
        helpers::set_clipboard(&name.unwrap_or("").to_string())?;
        Ok(())
    }() {
        helpers::errorbox(ui, &err);
        return;
    }

    ui.call_on_name("status_bar", |l: &mut TextView| {
        l.set_content(CATALOG.gettext("Copied file name to copy buffer"));
    });
}

fn do_delete(ui: &mut Cursive, store: PasswordStoreType) {
    ui.call_on_name(
        "results",
        |l: &mut SelectView<pass::PasswordEntry>| -> Result<()> {
            let sel = l.selection();

            if sel.is_none() {
                return Ok(());
            }

            let sel = sel.unwrap();
            let r = sel.delete_file(&*store.lock()?.lock()?);

            if r.is_err() {
                return Ok(());
            }

            if let Some(delete_id) = l.selected_id() {
                l.remove_item(delete_id);
            }

            Ok(())
        },
    );

    ui.pop_layer();
}

fn delete(ui: &mut Cursive, store: PasswordStoreType) {
    ui.add_layer(CircularFocus::new(
        Dialog::around(TextView::new(
            CATALOG.gettext("Are you sure you want to delete the password?"),
        ))
        .button(CATALOG.gettext("Yes"), move |ui: &mut Cursive| {
            do_delete(ui, store.clone());
            ui.call_on_name("status_bar", |l: &mut TextView| {
                l.set_content(CATALOG.gettext("Password deleted"));
            });
        })
        .dismiss_button(CATALOG.gettext("Cancel")),
    ));
}

fn get_selected_password_entry(ui: &mut Cursive) -> Option<pass::PasswordEntry> {
    let password_entry_option: Option<Option<Arc<pass::PasswordEntry>>> = ui
        .call_on_name("results", |l: &mut SelectView<pass::PasswordEntry>| {
            l.selection()
        });

    let password_entry: pass::PasswordEntry = (*(match password_entry_option {
        Some(Some(entry)) => entry,
        _ => return None,
    }))
    .clone();

    Some(password_entry)
}

fn show_file_history(ui: &mut Cursive, store: PasswordStoreType) -> Result<()> {
    let password_entry_opt = get_selected_password_entry(ui);
    if password_entry_opt.is_none() {
        return Ok(());
    }
    let password_entry = password_entry_opt.unwrap();

    let mut file_history_view = SelectView::<pass::GitLogLine>::new()
        .h_align(cursive::align::HAlign::Left)
        .with_name("file_history");

    let history = password_entry.get_history(&*store.lock()?.lock()?)?;

    for history_line in history {
        let mut verification_status = "  ";
        if let Some(h_line) = &history_line.signature_status {
            verification_status = match h_line {
                SignatureStatus::Good => "🔒",
                SignatureStatus::AlmostGood => "🔓",
                SignatureStatus::Bad => "⛔",
                _ => "?",
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
        .dismiss_button(CATALOG.gettext("Ok"));

    let file_history_event = OnEventView::new(d).on_event(Key::Esc, |s| {
        s.pop_layer();
    });

    ui.add_layer(file_history_event);

    Ok(())
}

fn do_show_file_history(ui: &mut Cursive, store: PasswordStoreType) {
    let res = show_file_history(ui, store);

    if let Err(err) = res {
        helpers::errorbox(ui, &err);
    }
}

fn do_password_save(ui: &mut Cursive, password: &str, store: PasswordStoreType, do_pop: bool) {
    let res = password_save(ui, password, store, do_pop);
    if let Err(err) = res {
        helpers::errorbox(ui, &err);
    }
}

fn password_save(
    ui: &mut Cursive,
    password: &str,
    store: PasswordStoreType,
    do_pop: bool,
) -> Result<()> {
    let password_entry_opt = get_selected_password_entry(ui);
    if password_entry_opt.is_none() {
        return Ok(());
    }

    let password_entry = password_entry_opt.unwrap();

    let r = password_entry.update(password.to_string(), &*store.lock()?.lock()?);

    if let Err(err) = r {
        helpers::errorbox(ui, &err)
    } else {
        if do_pop {
            ui.pop_layer();
        }
        ui.call_on_name("status_bar", |l: &mut TextView| {
            l.set_content(CATALOG.gettext("Updated password entry"));
        });

        ui.pop_layer();
    }

    Ok(())
}

fn do_open(ui: &mut Cursive, store: PasswordStoreType) {
    let res = open(ui, store);
    if let Err(err) = res {
        helpers::errorbox(ui, &err);
    }
}

fn open(ui: &mut Cursive, store: PasswordStoreType) -> Result<()> {
    let password_entry_opt = get_selected_password_entry(ui);
    if password_entry_opt.is_none() {
        return Ok(());
    }

    let password_entry = password_entry_opt.unwrap();

    let mut password = {
        match password_entry.secret(&*store.lock()?.lock()?) {
            Ok(p) => p,
            Err(err) => {
                helpers::errorbox(ui, &err);
                return Ok(());
            }
        }
    };
    let d = Dialog::around(TextArea::new().content(&password).with_name("editbox"))
        .button(CATALOG.gettext("Save"), move |s| {
            let mut new_secret = s
                .call_on_name("editbox", |e: &mut TextArea| e.get_content().to_string())
                .unwrap();

            if new_secret.contains("otpauth://") {
                let store = store.clone();
                let d = Dialog::around(TextView::new(CATALOG.gettext("It seems like you are trying to save a TOTP code to the password store. This will reduce your 2FA solution to just 1FA, do you want to proceed?")))
                    .button(CATALOG.gettext("Save"), move |s| {
                        let mut confirmed_new_secret = s
                            .call_on_name("editbox", |e: &mut TextArea| e.get_content().to_string())
                            .unwrap();
                        do_password_save(s, &confirmed_new_secret, store.clone(), true);
                        confirmed_new_secret.zeroize();
                    })
                    .dismiss_button(CATALOG.gettext("Close"));

                let ev = OnEventView::new(d).on_event(Key::Esc, |s| {
                    s.pop_layer();
                });
                s.add_layer(ev);
            } else {
                do_password_save(s, &new_secret, store.clone(), false);
            };
            new_secret.zeroize();

        })
        .button(CATALOG.gettext("Generate Password"), move |s| {
            let mut new_password = password_generator(20, 0);
            s.call_on_name("editbox", |e: &mut TextArea| {
                e.set_content(&new_password);
            });
            new_password.zeroize()
        })


        .button(CATALOG.gettext("Generate Passphrase"), move |s| {
            let mut new_password = match passphrase_generator(6) {
                Ok(words) => words.join(" "),
                Err(err) => {
                    helpers::errorbox(s, &ripasso::pass::Error::from(err));
                    return;
                }
            };
            s.call_on_name("editbox", |e: &mut TextArea| {
                e.set_content(&new_password);
            });
            new_password.zeroize();
        })
        .dismiss_button(CATALOG.gettext("Close"));

    let ev = OnEventView::new(d).on_event(Key::Esc, |s| {
        s.pop_layer();
    });

    ui.add_layer(ev);
    password.zeroize();
    Ok(())
}

fn do_rename_file(ui: &mut Cursive, store: PasswordStoreType) -> Result<()> {
    let old_name = ui
        .find_name::<TextView>("old_name_input")
        .unwrap()
        .get_content();

    let new_name = ui
        .find_name::<EditView>("new_name_input")
        .unwrap()
        .get_content();

    let res = store
        .lock()?
        .lock()?
        .rename_file(old_name.source(), &new_name);
    match res {
        Err(err) => {
            helpers::errorbox(ui, &err);
        }
        Ok(index) => {
            let mut l = ui
                .find_name::<SelectView<pass::PasswordEntry>>("results")
                .unwrap();

            if let Some(delete_id) = l.selected_id() {
                l.remove_item(delete_id);
            }

            let col = screen_width(ui);
            let store = store.lock()?;
            let entry = &store.lock()?.passwords[index];
            l.add_item(create_label(entry, col), entry.clone());
            l.sort_by_label();

            ui.pop_layer();
        }
    }

    Ok(())
}

fn rename_file_dialog(ui: &mut Cursive, store: PasswordStoreType) {
    let sel = ui
        .find_name::<SelectView<pass::PasswordEntry>>("results")
        .unwrap()
        .selection();

    if sel.is_none() {
        return;
    }
    let sel = sel.unwrap();
    let old_name = sel.name.clone();

    let mut fields = LinearLayout::vertical();
    let mut old_name_fields = LinearLayout::horizontal();
    let mut new_name_fields = LinearLayout::horizontal();

    old_name_fields.add_child(
        TextView::new(CATALOG.gettext("Old file name: "))
            .with_name("old_name_name")
            .fixed_size((10_usize, 1_usize)),
    );
    old_name_fields.add_child(
        TextView::new(old_name)
            .with_name("old_name_input")
            .fixed_size((50_usize, 1_usize)),
    );
    new_name_fields.add_child(
        TextView::new(CATALOG.gettext("New file name: "))
            .with_name("new_name_name")
            .fixed_size((10_usize, 1_usize)),
    );
    new_name_fields.add_child(
        EditView::new()
            .with_name("new_name_input")
            .fixed_size((50_usize, 1_usize)),
    );

    fields.add_child(old_name_fields);
    fields.add_child(new_name_fields);
    let store2 = store.clone();

    let d = Dialog::around(fields)
        .title(CATALOG.gettext("Rename File"))
        .button(CATALOG.gettext("Rename"), move |ui: &mut Cursive| {
            if let Err(e) = do_rename_file(ui, store.clone()) {
                helpers::errorbox(ui, &e);
            }
        })
        .dismiss_button(CATALOG.gettext("Cancel"));

    let ev = OnEventView::new(d)
        .on_event(Key::Esc, |s| {
            s.pop_layer();
        })
        .on_event(Key::Enter, move |ui: &mut Cursive| {
            if let Err(e) = do_rename_file(ui, store2.clone()) {
                helpers::errorbox(ui, &e);
            }
        });

    ui.add_layer(ev);
}

fn do_new_password_save(
    s: &mut Cursive,
    path: &str,
    password: &str,
    store: PasswordStoreType,
    do_pop: bool,
) {
    let res = new_password_save(s, path, password, store, do_pop);
    if let Err(err) = res {
        helpers::errorbox(s, &err);
    }
}

fn new_password_save(
    s: &mut Cursive,
    path: &str,
    password: &str,
    store: PasswordStoreType,
    do_pop: bool,
) -> Result<()> {
    let entry = store
        .lock()?
        .lock()?
        .new_password_file(path.as_ref(), password.as_ref());

    if do_pop {
        s.pop_layer();
    }

    match entry {
        Err(err) => helpers::errorbox(s, &err),
        Ok(entry) => {
            let col = screen_width(s);
            s.call_on_name("results", |l: &mut SelectView<pass::PasswordEntry>| {
                l.add_item(create_label(&entry, col), entry);
                l.sort_by_label();
            });

            s.pop_layer();

            s.call_on_name("status_bar", |l: &mut TextView| {
                l.set_content(CATALOG.gettext("Created new password"));
            });
        }
    }

    Ok(())
}

fn create_save(s: &mut Cursive, store: PasswordStoreType) {
    let password = get_value_from_input(s, "new_password_input");
    if password.is_none() {
        return;
    }
    let mut password = password.unwrap();
    if password.is_empty() {
        return;
    }

    let path = get_value_from_input(s, "new_path_input");
    if path.is_none() {
        return;
    }
    let path = path.unwrap();
    if path.is_empty() {
        return;
    }

    let note = s.call_on_name("note_input", |e: &mut TextArea| e.get_content().to_string());
    if let Some(note) = note {
        password = Arc::from(format!("{password}\n{note}"));
    }

    if password.contains("otpauth://") {
        let d = Dialog::around(TextView::new(CATALOG.gettext("It seems like you are trying to save a TOTP code to the password store. This will reduce your 2FA solution to just 1FA, do you want to proceed?")))
            .button(CATALOG.gettext("Save"), move |s| {
                do_new_password_save(s, path.as_ref(), password.as_ref(), store.clone(), true);
            })
            .dismiss_button(CATALOG.gettext("Close"));

        let ev = OnEventView::new(d).on_event(Key::Esc, |s| {
            s.pop_layer();
        });

        s.add_layer(ev);
    } else {
        do_new_password_save(s, path.as_ref(), password.as_ref(), store, false);
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
            .fixed_size((10_usize, 1_usize)),
    );
    path_fields.add_child(
        EditView::new()
            .with_name("new_path_input")
            .fixed_size((50_usize, 1_usize)),
    );

    password_fields.add_child(
        TextView::new(CATALOG.gettext("Password: "))
            .with_name("password_name")
            .fixed_size((10_usize, 1_usize)),
    );
    password_fields.add_child(
        EditView::new()
            .secret()
            .with_name("new_password_input")
            .fixed_size((50_usize, 1_usize)),
    );

    note_fields.add_child(
        TextView::new(CATALOG.gettext("Note: "))
            .with_name("note_name")
            .fixed_size((10_usize, 1_usize)),
    );
    note_fields.add_child(TextArea::new().with_name("note_input").min_size((50, 1)));

    fields.add_child(path_fields);
    fields.add_child(password_fields);
    fields.add_child(note_fields);

    let store2 = store.clone();

    let category_value = Arc::new(Mutex::new(0));
    let reveal_flag = Arc::new(Mutex::new(false));
    let password_length = Arc::new(Mutex::new(20_usize));

    let d = Dialog::around(fields)
        .title(CATALOG.gettext("Add new password"))
        .button(CATALOG.gettext("Password Options"), {
            let category_value = category_value.clone();
            let reveal_flag = reveal_flag.clone();
            let password_length = password_length.clone();
            move |s| {
                let mut select = SelectView::<usize>::new();
                select.add_item("Category 0 (ASCII 33–126)", 0);
                select.add_item("Category 1 (ASCII 33–255)", 1);
                select.set_selection(*category_value.lock().unwrap());
                let select = select.with_name("password_category");

                let length_input = EditView::new()
                    .content(password_length.lock().unwrap().to_string())
                    .with_name("password_length")
                    .fixed_width(5);

                let reveal_checkbox = LinearLayout::horizontal()
                    .child(cursive::views::Checkbox::new().on_change({
                        let reveal_flag = reveal_flag.clone();
                        move |siv, checked| {
                            siv.call_on_name("new_password_input", |e: &mut EditView| {
                                e.set_secret(!checked);
                            });
                            *reveal_flag.lock().unwrap() = checked;
                        }
                    }))
                    .child(TextView::new("Reveal password"));

                let dialog_content = LinearLayout::vertical()
                    .child(select.scrollable().fixed_size((30, 5)))
                    .child(
                        LinearLayout::horizontal()
                            .child(TextView::new("Length: "))
                            .child(length_input),
                    )
                    .child(reveal_checkbox);

                let save_selection = {
                    let category_value = category_value.clone();
                    let password_length = password_length.clone();
                    move |s: &mut Cursive| {
                        s.call_on_name("password_category", |view: &mut SelectView<usize>| {
                            if let Some(sel) = view.selection() {
                                *category_value.lock().unwrap() = *sel;
                            }
                        });

                        s.call_on_name("password_length", |view: &mut EditView| {
                            if let Ok(len) = view.get_content().parse::<usize>() {
                                *password_length.lock().unwrap() = len;
                            }
                        });

                        s.pop_layer();
                    }
                };

                let popup = OnEventView::new(
                    Dialog::around(dialog_content)
                        .title("Password Options")
                        .button("OK", save_selection.clone())
                        .dismiss_button("Cancel"),
                )
                .on_event(Key::Enter, save_selection);

                s.add_layer(popup);
            }
        })
        .button(CATALOG.gettext("Generate Password"), {
            let category_value = category_value.clone();
            let password_length = password_length.clone();
            move |s| {
                let category = *category_value.lock().unwrap();
                let length = *password_length.lock().unwrap();
                let new_password =
                    ripasso::password_generator::password_generator(length, category);

                s.call_on_name("new_password_input", |e: &mut EditView| {
                    e.set_content(new_password);
                });
            }
        })
        .button(CATALOG.gettext("Generate Passphrase"), move |s| {
            let new_password = match ripasso::passphrase_generator::passphrase_generator(6) {
                Ok(words) => words.join(" "),
                Err(err) => {
                    helpers::errorbox(s, &ripasso::pass::Error::from(err));
                    return;
                }
            };
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
            if ui.screen_mut().len() == 1 {
                create_save(ui, store2.clone());
            }
        });

    ui.add_layer(ev);
}

fn delete_recipient(ui: &mut Cursive, store: PasswordStoreType) -> Result<()> {
    let mut l = ui
        .find_name::<SelectView<Option<(PathBuf, Recipient)>>>("recipients")
        .unwrap();
    let sel = l.selection();

    if sel.is_none() || sel.as_ref().unwrap().is_none() {
        return Err(pass::Error::Generic("Selection is empty"));
    }

    let binding = sel.unwrap();
    let (path, recipient): &(PathBuf, Recipient) = binding.as_ref().as_ref().unwrap();

    let store = store.lock()?;
    let store = store.lock()?;
    let remove_recipient_res = store.remove_recipient(recipient, path);
    if remove_recipient_res.is_ok() {
        let delete_id = l.selected_id().unwrap();
        l.remove_item(delete_id);
        ui.call_on_name("status_bar", |l: &mut TextView| {
            l.set_content(CATALOG.gettext("Deleted team member from password store"));
        });
        Ok(())
    } else {
        Err(remove_recipient_res.err().unwrap())
    }
}

fn delete_recipient_verification(ui: &mut Cursive, store: PasswordStoreType) {
    ui.add_layer(CircularFocus::new(
        Dialog::around(TextView::new(
            CATALOG.gettext("Are you sure you want to remove this person?"),
        ))
        .button(CATALOG.gettext("Yes"), move |ui: &mut Cursive| {
            let res = delete_recipient(ui, store.clone());
            if let Err(err) = res {
                helpers::errorbox(ui, &err)
            } else {
                ui.pop_layer();
            }
        })
        .dismiss_button(CATALOG.gettext("Cancel")),
    ));
}

fn add_recipient(ui: &mut Cursive, store: PasswordStoreType, config_path: &Path) -> Result<()> {
    let l = &*get_value_from_input(ui, "key_id_input").unwrap();
    let dir = &*get_value_from_input(ui, "dir_id_input").unwrap();

    let store = store.lock()?;
    let mut store = store.lock()?;
    let recipient_from_res = store.recipient_from(l, &[], None);
    match recipient_from_res {
        Err(err) => helpers::errorbox(ui, &err),
        Ok(recipient) => {
            if recipient.trust_level != OwnerTrustLevel::Ultimate {
                helpers::errorbox(ui, &pass::Error::Generic(CATALOG.gettext("Can't import team member due to that the GPG trust relationship level isn't Ultimate")));
                return Ok(());
            }

            let dir_path = std::path::PathBuf::from(dir);
            let res = store.add_recipient(&recipient, &dir_path, config_path);
            match res {
                Err(err) => helpers::errorbox(ui, &err),
                Ok(_) => {
                    let all_recipients_res = store.recipients_for_path(&dir_path);
                    match all_recipients_res {
                        Err(err) => helpers::errorbox(ui, &err),
                        Ok(recipients) => {
                            let (max_width_key, max_width_name) = recipients_widths(&recipients);

                            let mut recipients_view = ui
                                .find_name::<SelectView<Option<(PathBuf, Recipient)>>>("recipients")
                                .unwrap();
                            recipients_view.add_item(
                                render_recipient_label(&recipient, max_width_key, max_width_name),
                                Some((dir_path, recipient)),
                            );

                            ui.pop_layer();
                            ui.call_on_name("status_bar", |l: &mut TextView| {
                                l.set_content(
                                    CATALOG.gettext("Added team member to password store"),
                                );
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

fn add_recipient_dialog(ui: &mut Cursive, store: PasswordStoreType, config_path: &Path) {
    let mut all_fields = LinearLayout::vertical();
    let mut recipient_fields = LinearLayout::horizontal();
    let mut dir_fields = LinearLayout::horizontal();

    recipient_fields.add_child(
        TextView::new(CATALOG.gettext("GPG Key ID: "))
            .with_name("key_id")
            .fixed_size((16_usize, 1_usize)),
    );
    recipient_fields.add_child(
        EditView::new()
            .with_name("key_id_input")
            .fixed_size((50_usize, 1_usize)),
    );

    dir_fields.add_child(
        TextView::new(CATALOG.gettext("Directory: "))
            .with_name("dir_id")
            .fixed_size((16_usize, 1_usize)),
    );
    dir_fields.add_child(
        EditView::new()
            .with_name("dir_id_input")
            .fixed_size((50_usize, 1_usize)),
    );

    all_fields.add_child(recipient_fields);
    all_fields.add_child(dir_fields);

    let config_path = config_path.to_path_buf();
    let cf = CircularFocus::new(
        Dialog::around(all_fields)
            .button(CATALOG.gettext("Yes"), move |ui: &mut Cursive| {
                let res = add_recipient(ui, store.clone(), &config_path);
                if let Err(err) = res {
                    helpers::errorbox(ui, &err)
                }
            })
            .dismiss_button(CATALOG.gettext("Cancel")),
    );

    let ev = OnEventView::new(cf).on_event(Key::Esc, |s| {
        s.pop_layer();
    });

    ui.add_layer(ev);
}

fn render_recipient_label(
    recipient: &Recipient,
    max_width_key: usize,
    max_width_name: usize,
) -> String {
    let symbol = match &recipient.key_ring_status {
        pass::KeyRingStatus::NotInKeyRing => "⚠️ ",
        _ => "  ️",
    };

    let trust = match &recipient.trust_level {
        OwnerTrustLevel::Ultimate => CATALOG.gettext("Ultimate"),
        OwnerTrustLevel::Full => CATALOG.gettext("Full"),
        OwnerTrustLevel::Marginal => CATALOG.gettext("Marginal"),
        OwnerTrustLevel::Never => CATALOG.gettext("Never"),
        OwnerTrustLevel::Undefined => CATALOG.gettext("Undefined"),
        _ => CATALOG.gettext("Unknown"),
    };

    format!(
        "{} {:width_key$} {:width_name$} {}  {}  ",
        symbol,
        &recipient.key_id,
        &recipient.name,
        trust,
        if recipient.not_usable {
            CATALOG.gettext("Not Usable")
        } else {
            CATALOG.gettext("Usable")
        },
        width_key = max_width_key,
        width_name = max_width_name
    )
}

fn get_sub_dirs(dir: &PathBuf) -> Result<Vec<PathBuf>> {
    let mut to_visit = vec![dir.clone()];
    let mut all = vec![PathBuf::from("./")];
    while let Some(d) = to_visit.pop() {
        for entry in std::fs::read_dir(d)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() && path.file_name() != Some(std::ffi::OsStr::new(".git")) {
                to_visit.push(path.clone());
                if path.join(".gpg-id").exists() {
                    all.push(path.strip_prefix(dir)?.to_path_buf());
                }
            }
        }
    }

    Ok(all)
}

fn view_recipients(ui: &mut Cursive, store: PasswordStoreType, config_path: &Path) -> Result<()> {
    let sub_dirs = get_sub_dirs(&store.lock()?.lock()?.get_store_path());
    if let Err(err) = sub_dirs {
        helpers::errorbox(ui, &err);
        return Ok(());
    }
    let sub_dirs = sub_dirs?;

    match sub_dirs.len().cmp(&1) {
        std::cmp::Ordering::Greater => {
            let mut path_to_recipients: HashMap<PathBuf, Vec<Recipient>> = HashMap::new();

            for dir in sub_dirs {
                let recipients_res = store.lock()?.lock()?.recipients_for_path(&dir);
                if let Err(err) = recipients_res {
                    helpers::errorbox(ui, &err);
                    return Ok(());
                }

                path_to_recipients.insert(dir.clone(), recipients_res?);
            }

            view_recipients_for_many_dirs(ui, store, path_to_recipients, config_path);
        }
        std::cmp::Ordering::Equal => {
            do_view_recipients_for_dir(ui, store, sub_dirs[0].clone(), config_path);
        }
        std::cmp::Ordering::Less => {
            helpers::errorbox(ui, &pass::Error::Generic("no subdirectories found"));
        }
    }

    Ok(())
}

fn do_view_recipients(ui: &mut Cursive, store: PasswordStoreType, config_path: &Path) {
    let res = view_recipients(ui, store, config_path);
    if let Err(err) = res {
        helpers::errorbox(ui, &err);
    }
}

fn view_recipients_for_many_dirs(
    ui: &mut Cursive,
    store: PasswordStoreType,
    path_to_recipients: HashMap<PathBuf, Vec<Recipient>>,
    config_path: &Path,
) {
    let mut recipients_view = SelectView::<Option<(PathBuf, Recipient)>>::new()
        .h_align(cursive::align::HAlign::Left)
        .with_name("recipients");

    for (path, recipients) in &path_to_recipients {
        recipients_view
            .get_mut()
            .add_item(path.to_string_lossy(), None);
        let (max_width_key, max_width_name) = recipients_widths(recipients);
        for recipient in recipients {
            recipients_view.get_mut().add_item(
                render_recipient_label(recipient, max_width_key, max_width_name),
                Some((path.to_path_buf(), recipient.clone())),
            );
        }
    }
    let d = Dialog::around(recipients_view)
        .title(CATALOG.gettext("Team Members"))
        .dismiss_button(CATALOG.gettext("Ok"));

    let ll = LinearLayout::new(Orientation::Vertical).child(d).child(
        LinearLayout::new(Orientation::Horizontal)
            .child(TextView::new(CATALOG.gettext("ins: Add | ")))
            .child(TextView::new(CATALOG.gettext("del: Remove"))),
    );

    let store2 = store.clone();
    let config_path = config_path.to_path_buf();

    let recipients_event = OnEventView::new(ll)
        .on_event(Key::Del, move |ui: &mut Cursive| {
            delete_recipient_verification(ui, store.clone())
        })
        .on_event(Key::Ins, move |ui: &mut Cursive| {
            add_recipient_dialog(ui, store2.clone(), &config_path)
        })
        .on_event(Key::Esc, |s| {
            s.pop_layer();
        });

    ui.add_layer(recipients_event);
}

fn do_view_recipients_for_dir(
    ui: &mut Cursive,
    store: PasswordStoreType,
    dir: PathBuf,
    config_path: &Path,
) {
    let res = view_recipients_for_dir(ui, store, dir, config_path);
    if let Err(err) = res {
        helpers::errorbox(ui, &err);
    }
}

fn view_recipients_for_dir(
    ui: &mut Cursive,
    store: PasswordStoreType,
    dir: PathBuf,
    config_path: &Path,
) -> Result<()> {
    let path = store.lock()?.lock()?.get_store_path().join(dir.clone());
    let recipients_res = store.lock()?.lock()?.recipients_for_path(&path);

    if let Err(err) = recipients_res {
        helpers::errorbox(ui, &err);
        return Ok(());
    }
    let recipients = recipients_res?;

    let mut recipients_view = SelectView::<Option<(PathBuf, Recipient)>>::new()
        .h_align(cursive::align::HAlign::Left)
        .with_name("recipients");

    let (max_width_key, max_width_name) = recipients_widths(&recipients);
    for recipient in recipients {
        recipients_view.get_mut().add_item(
            render_recipient_label(&recipient, max_width_key, max_width_name),
            Some((dir.clone(), recipient)),
        );
    }

    let d = Dialog::around(recipients_view)
        .title(CATALOG.gettext("Team Members"))
        .dismiss_button(CATALOG.gettext("Ok"));

    let ll = LinearLayout::new(Orientation::Vertical).child(d).child(
        LinearLayout::new(Orientation::Horizontal)
            .child(TextView::new(CATALOG.gettext("ins: Add | ")))
            .child(TextView::new(CATALOG.gettext("del: Remove"))),
    );

    let store2 = store.clone();
    let config_path = config_path.to_path_buf();

    let recipients_event = OnEventView::new(ll)
        .on_event(Key::Del, move |ui: &mut Cursive| {
            delete_recipient_verification(ui, store.clone())
        })
        .on_event(Key::Ins, move |ui: &mut Cursive| {
            add_recipient_dialog(ui, store2.clone(), &config_path)
        })
        .on_event(Key::Esc, |s| {
            s.pop_layer();
        });

    ui.add_layer(recipients_event);

    Ok(())
}

fn substr(str: &str, start: usize, len: usize) -> String {
    str.chars().skip(start).take(len).collect()
}

fn create_label(p: &pass::PasswordEntry, col: usize) -> String {
    let committed_by = p.committed_by.clone();
    let updated = p.updated;
    let name = substr(
        &committed_by.unwrap_or_else(|| CATALOG.gettext("n/a").to_string()),
        0,
        15,
    );
    let mut verification_status = "  ";
    if let Some(s_status) = &p.signature_status {
        verification_status = match s_status {
            SignatureStatus::Good => "🔒",
            SignatureStatus::AlmostGood => "🔓",
            SignatureStatus::Bad => "⛔",
            _ => "?",
        }
    }

    format!(
        "{:4$} {} {} {}",
        p.name,
        verification_status,
        name,
        match updated {
            Some(d) => format!("{}", d.format("%Y-%m-%d")),
            None => CATALOG.gettext("n/a").to_string(),
        },
        col - 12 - 15 - 9, // Optimized for 80 cols
    )
}

fn search(store: &PasswordStoreType, ui: &mut Cursive, query: &str) -> Result<()> {
    let col = screen_width(ui);
    let mut l = ui
        .find_name::<SelectView<pass::PasswordEntry>>("results")
        .unwrap();

    let r = pass::search(&*store.lock()?.lock()?, &String::from(query));

    l.clear();
    for p in &r {
        l.add_item(create_label(p, col), p.clone());
    }
    l.sort_by_label();

    Ok(())
}

fn do_search(store: &PasswordStoreType, ui: &mut Cursive, query: &str) {
    let res = search(store, ui, query);
    if let Err(err) = res {
        helpers::errorbox(ui, &err);
    }
}

fn help() {
    println!("{}", CATALOG.gettext("A password manager that uses the file format of the standard unix password manager 'pass', implemented in Rust. Ripasso reads $HOME/.password-store/ by default, override this by setting the PASSWORD_STORE_DIR environmental variable."));
}

fn do_git_push(ui: &mut Cursive, store: PasswordStoreType) {
    let res = git_push(ui, store);
    if let Err(err) = res {
        helpers::errorbox(ui, &err);
    }
}

fn git_push(ui: &mut Cursive, store: PasswordStoreType) -> Result<()> {
    let push_result = push(&*store.lock()?.lock()?);
    match push_result {
        Err(err) => helpers::errorbox(ui, &err),
        Ok(_) => {
            ui.call_on_name("status_bar", |l: &mut TextView| {
                l.set_content(CATALOG.gettext("Pushed to remote git repository"));
            });
        }
    }
    Ok(())
}

fn do_git_pull(ui: &mut Cursive, store: PasswordStoreType) {
    let res = git_pull(ui, store);
    if let Err(err) = res {
        helpers::errorbox(ui, &err);
    }
}

fn git_pull(ui: &mut Cursive, store: PasswordStoreType) -> Result<()> {
    let _ = pull(&*store.lock()?.lock()?).map_err(|err| helpers::errorbox(ui, &err));
    let _ = store
        .lock()?
        .lock()?
        .reload_password_list()
        .map_err(|err| helpers::errorbox(ui, &err));

    let col = screen_width(ui);

    ui.call_on_name(
        "results",
        |l: &mut SelectView<pass::PasswordEntry>| -> Result<()> {
            l.clear();
            #[allow(clippy::significant_drop_in_scrutinee)]
            for p in store.lock()?.lock()?.passwords.iter() {
                l.add_item(create_label(p, col), p.clone());
            }
            Ok(())
        },
    );
    ui.call_on_name("status_bar", |l: &mut TextView| {
        l.set_content(CATALOG.gettext("Pulled from remote git repository"));
    });

    Ok(())
}

fn do_gpg_import(ui: &mut Cursive, store: PasswordStoreType, config_path: &Path) -> Result<()> {
    let ta = ui.find_name::<TextArea>("gpg_import_text_area").unwrap();
    let text = ta.get_content();

    ui.pop_layer();

    let result = pass::pgp_import(&mut *store.lock()?.lock()?, text, config_path)?;

    let d = Dialog::around(TextView::new(result))
        .dismiss_button(CATALOG.gettext("Ok"))
        .title(CATALOG.gettext("Import Results"));

    let ev = OnEventView::new(d).on_event(Key::Esc, |s| {
        s.pop_layer();
    });

    ui.add_layer(ev);

    Ok(())
}

fn pgp_import(ui: &mut Cursive, store: PasswordStoreType, config_path: &Path) {
    let config_path = config_path.to_owned();
    let d = Dialog::around(
        TextArea::new()
            .with_name("gpg_import_text_area")
            .min_size((50, 20)),
    )
    .title(CATALOG.gettext("Manual GPG Import"))
    .dismiss_button(CATALOG.gettext("Cancel"))
    .button(CATALOG.gettext("Import"), move |s| {
        let res = do_gpg_import(s, store.clone(), &config_path);
        if let Err(err) = res {
            helpers::errorbox(s, &err);
        }
    });

    let ev = OnEventView::new(d).on_event(Key::Esc, |s| {
        s.pop_layer();
    });

    ui.add_layer(ev);
}

fn do_gpg_pull(ui: &mut Cursive, store: PasswordStoreType, config_path: &Path) -> Result<()> {
    ui.pop_layer();

    let result = pass::pgp_pull(&mut *store.lock()?.lock()?, config_path)?;

    let d = Dialog::around(TextView::new(result))
        .dismiss_button(CATALOG.gettext("Ok"))
        .title(CATALOG.gettext("Import Results"));

    let ev = OnEventView::new(d).on_event(Key::Esc, |s| {
        s.pop_layer();
    });

    ui.add_layer(ev);

    Ok(())
}

fn pgp_pull(ui: &mut Cursive, store: PasswordStoreType, config_path: &Path) {
    let config_path = config_path.to_owned();
    let d = Dialog::around(TextView::new(CATALOG.gettext(
        "Download pgp data from keys.openpgp.org and import them into your key ring?",
    )))
    .dismiss_button(CATALOG.gettext("Cancel"))
    .button(CATALOG.gettext("Download"), move |ui| {
        let res = do_gpg_pull(ui, store.clone(), &config_path);
        if let Err(err) = res {
            helpers::errorbox(ui, &err);
        }
    })
    .title(CATALOG.gettext("GPG Download"));

    let ev = OnEventView::new(d).on_event(Key::Esc, |s| {
        s.pop_layer();
    });

    ui.add_layer(ev);
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
    do_search(&store, ui, &search_text);
}

fn get_translation_catalog() -> gettext::Catalog {
    let locale = locale_config::Locale::current();

    let mut translation_locations = vec![];
    if let Some(path) = option_env!("TRANSLATION_INPUT_PATH") {
        translation_locations.insert(0, path);
    }
    if cfg!(debug_assertions) {
        translation_locations.insert(0, "./cursive/res");
    }

    for preferred in locale.tags_for("messages") {
        for loc in &translation_locations {
            let langid_res: std::result::Result<LanguageIdentifier, _> =
                format!("{preferred}").parse();

            if let Ok(langid) = langid_res {
                let file = std::fs::File::open(format!("{}/{}.mo", loc, langid.language));
                if let Ok(file) = file
                    && let Ok(catalog) = gettext::Catalog::parse(file)
                {
                    return catalog;
                }
            }
        }
    }

    for preferred in locale.tags_for("messages") {
        let langid_res: std::result::Result<LanguageIdentifier, _> = format!("{preferred}").parse();

        if let Ok(langid) = langid_res {
            let file = std::fs::File::open(format!(
                "/usr/share/locale/{}/LC_MESSAGES/ripasso-cursive.mo",
                langid.language
            ));
            if let Ok(file) = file
                && let Ok(catalog) = gettext::Catalog::parse(file)
            {
                return catalog;
            }
        }
    }

    gettext::Catalog::empty()
}

fn get_stores(config: &config::Config, home: &Option<PathBuf>) -> Result<Vec<PasswordStore>> {
    let mut final_stores: Vec<PasswordStore> = vec![];
    let stores_res = config.get("stores");
    if let Ok(stores) = stores_res {
        let stores: HashMap<String, config::Value> = stores;

        for store_name in stores.keys() {
            let store: HashMap<String, config::Value> =
                stores.get(store_name).unwrap().clone().into_table()?;

            let password_store_dir_opt = store.get("path");
            let valid_signing_keys_opt = store.get("valid_signing_keys");

            if let Some(store_dir) = password_store_dir_opt {
                let password_store_dir = Some(PathBuf::from(store_dir.clone().into_string()?));

                let valid_signing_keys = match valid_signing_keys_opt {
                    Some(k) => match k.clone().into_string() {
                        Err(_) => None,
                        Ok(key) => {
                            if key == "-1" {
                                None
                            } else {
                                Some(key)
                            }
                        }
                    },
                    None => None,
                };
                let style_path_opt = match store.get("style_path") {
                    Some(path) => match path.clone().into_string() {
                        Ok(p) => Some(PathBuf::from(p)),
                        Err(_err) => None,
                    },
                    None => None,
                };

                let pgp_impl = match store.get("pgp") {
                    Some(pgp_str) => CryptoImpl::try_from(pgp_str.clone().into_string()?.as_str()),
                    None => Ok(CryptoImpl::GpgMe),
                }?;

                let own_fingerprint = store.get("own_fingerprint");
                let own_fingerprint = match own_fingerprint {
                    None => None,
                    Some(k) => match k.clone().into_string() {
                        Err(_) => None,
                        Ok(key) => <[u8; 20]>::from_hex(key).ok(),
                    },
                };

                final_stores.push(PasswordStore::new(
                    store_name,
                    &password_store_dir,
                    &valid_signing_keys,
                    home,
                    &style_path_opt,
                    &pgp_impl,
                    &own_fingerprint,
                )?);
            }
        }
    } else if final_stores.is_empty() && home.is_some() {
        let default_path = home.clone().unwrap().join(".password_store");
        if default_path.exists() {
            final_stores.push(PasswordStore::new(
                "default",
                &Some(default_path),
                &None,
                home,
                &None,
                &CryptoImpl::GpgMe,
                &None,
            )?);
        }
    }

    Ok(final_stores)
}

/// Validates the config for password stores.
/// Returns a list of paths that the new store wizard should be run for
fn validate_stores_config(settings: &config::Config, home: &Option<PathBuf>) -> Vec<PathBuf> {
    let mut incomplete_stores: Vec<PathBuf> = vec![];

    let stores_res = settings.get("stores");
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

            if let Some(p) = password_store_dir_opt {
                let p_path = PathBuf::from(p.clone().into_string().unwrap());
                let gpg_id = p_path.clone().join(".gpg-id");

                if !p_path.exists() || !gpg_id.exists() {
                    incomplete_stores.push(PathBuf::from(p.clone().into_string().unwrap()));
                }
            }
        }
    } else if incomplete_stores.is_empty() && home.is_some() {
        incomplete_stores.push(home.clone().unwrap().join(".password_store"));
    }

    incomplete_stores
}

fn do_save_edit_config(
    ui: &mut Cursive,
    stores: StoreListType,
    name: &str,
    config_file_location: &Path,
    home: &Option<PathBuf>,
) {
    let res = save_edit_config(ui, stores, name, config_file_location, home);
    if let Err(err) = res {
        helpers::errorbox(ui, &err);
    }
}

fn save_edit_config(
    ui: &mut Cursive,
    stores: StoreListType,
    name: &str,
    config_file_location: &Path,
    home: &Option<PathBuf>,
) -> Result<()> {
    let e_n = &*get_value_from_input(ui, "edit_name_input").unwrap();
    let e_d = &*get_value_from_input(ui, "edit_directory_input").unwrap();
    let e_k_bool = is_checkbox_checked(ui, "edit_keys_input");
    let e_sequoia_selected = &is_radio_button_selected(ui, "edit_sequoia_button_name");
    let own_fingerprint = &*get_value_from_input(ui, "edit_own_fingerprint_input").unwrap();

    let e_k = if e_k_bool {
        let mut recipients: Vec<Recipient> = vec![];
        for (i, r) in all_recipients_from_stores(stores.clone())?
            .iter()
            .enumerate()
        {
            if is_checkbox_checked(ui, &format!("edit_recipient_{i}")) && r.fingerprint.is_some() {
                recipients.push(r.clone());
            }
        }
        Some(
            recipients
                .iter()
                .map(|f| hex::encode_upper(f.fingerprint.unwrap()))
                .collect::<Vec<String>>()
                .join(","),
        )
    } else {
        None
    };

    let pgp_impl = match e_sequoia_selected {
        true => CryptoImpl::Sequoia,
        false => CryptoImpl::GpgMe,
    };

    let own_fingerprint = <[u8; 20]>::from_hex(own_fingerprint).ok();

    let new_store = PasswordStore::new(
        e_n,
        &Some(PathBuf::from(e_d.clone())),
        &e_k,
        home,
        &None,
        &pgp_impl,
        &own_fingerprint,
    );
    if let Err(err) = new_store {
        helpers::errorbox(ui, &err);
        return Ok(());
    }
    let new_store = new_store?;

    let l = ui.find_name::<SelectView<String>>("stores").unwrap();

    let sel = l.selection();

    if sel.is_some() {
        let mut stores_borrowed = stores.lock()?;
        #[allow(clippy::significant_drop_in_scrutinee)]
        for (i, store) in stores_borrowed.iter().enumerate() {
            if store.lock()?.get_name() == name {
                stores_borrowed[i] = Arc::new(Mutex::new(new_store));
                break;
            }
        }
    }

    let save_res = pass::save_config(stores, config_file_location);
    if let Err(err) = save_res {
        helpers::errorbox(ui, &err);
    }

    ui.call_on_name("status_bar", |l: &mut TextView| {
        l.set_content(CATALOG.gettext("Updated config file"));
    });

    Ok(())
}

fn save_new_config(
    ui: &mut Cursive,
    stores: StoreListType,
    config_file_location: &Path,
    home: &Option<PathBuf>,
    all_recipients: &[Recipient],
) -> Result<()> {
    let e_n = &*get_value_from_input(ui, "new_name_input").unwrap();
    let e_d = &*get_value_from_input(ui, "new_directory_input").unwrap();
    let e_k = is_checkbox_checked(ui, "new_keys_input");

    let mut recipients = vec![];
    for (i, r) in all_recipients.iter().enumerate() {
        if is_checkbox_checked(ui, &format!("new_recipient_{i}")) {
            recipients.push(r.clone());
        }
    }

    let new_store = PasswordStore::create(
        e_n,
        &Some(PathBuf::from(e_d.clone())),
        &recipients,
        e_k,
        home,
        &None,
    )?;

    {
        let mut stores_borrowed = stores.lock()?;
        stores_borrowed.push(Arc::new(Mutex::new(new_store)));
    }

    pass::save_config(stores, config_file_location)?;

    let mut l = ui.find_name::<SelectView<String>>("stores").unwrap();

    l.add_item(e_n, e_n.clone());

    ui.call_on_name("status_bar", |l: &mut TextView| {
        l.set_content(CATALOG.gettext("Updated config file"));
    });

    Ok(())
}

fn edit_store_in_config(
    ui: &mut Cursive,
    stores: StoreListType,
    config_file_location: &Path,
    home: &Option<PathBuf>,
) -> Result<()> {
    let all_recipients = all_recipients_from_stores(stores.clone())?;

    let l = ui.find_name::<SelectView<String>>("stores").unwrap();

    let sel = l.selection();

    if sel.is_none() {
        return Ok(());
    }
    let sel = sel.unwrap();
    let name = sel.as_ref();

    let mut store_opt: Option<&Arc<Mutex<PasswordStore>>> = None;
    let stores_borrowed = stores.lock()?;
    #[allow(clippy::significant_drop_in_scrutinee)]
    for store in stores_borrowed.iter() {
        if store.lock()?.get_name() == name {
            store_opt = Some(store);
        }
    }

    if store_opt.is_none() {
        return Ok(());
    }
    let store = store_opt.unwrap().lock()?;

    let mut fields = LinearLayout::vertical();
    let mut name_fields = LinearLayout::horizontal();
    let mut directory_fields = LinearLayout::horizontal();
    let mut keys_fields = LinearLayout::horizontal();
    let mut pgp_fields = LinearLayout::horizontal();
    let mut fingerprint_fields = LinearLayout::horizontal();
    name_fields.add_child(
        TextView::new(CATALOG.gettext("Name: "))
            .with_name("name_name")
            .fixed_size((10_usize, 1_usize)),
    );
    name_fields.add_child(
        EditView::new()
            .content(store.get_name())
            .with_name("edit_name_input")
            .fixed_size((50_usize, 1_usize)),
    );
    directory_fields.add_child(
        TextView::new(CATALOG.gettext("Directory: "))
            .with_name("directory_name")
            .fixed_size((10_usize, 1_usize)),
    );
    directory_fields.add_child(
        EditView::new()
            .content(store.get_store_path().to_string_lossy().into_owned())
            .with_name("edit_directory_input")
            .fixed_size((50_usize, 1_usize)),
    );
    keys_fields.add_child(
        TextView::new(CATALOG.gettext("Enforce signing of .gpg-id file: "))
            .with_name("keys_name")
            .fixed_size((30_usize, 1_usize)),
    );
    let mut c_b = Checkbox::new();
    if !store.get_valid_gpg_signing_keys().is_empty() {
        c_b.set_checked(true);
    }
    keys_fields.add_child(c_b.with_name("edit_keys_input"));

    pgp_fields.add_child(
        TextView::new(CATALOG.gettext("PGP Implementation: "))
            .with_name("edit_pgp_name")
            .fixed_size((10_usize, 1_usize)),
    );
    let mut pgp_radio = RadioGroup::new();
    let gpg_me_button = pgp_radio
        .button(CryptoImpl::GpgMe, "GPG")
        .with_name("edit_pgp_me_button_name");
    let sequoia_button = pgp_radio
        .button(CryptoImpl::Sequoia, "Sequoia")
        .with_name("edit_sequoia_button_name");
    pgp_fields.add_child(gpg_me_button);
    pgp_fields.add_child(sequoia_button);
    fingerprint_fields.add_child(
        TextView::new(CATALOG.gettext("Own key fingerprint: "))
            .with_name("name_own_fingerprint")
            .fixed_size((10_usize, 1_usize)),
    );
    fingerprint_fields.add_child(
        EditView::new()
            .content(hex::encode_upper(
                store.get_crypto().own_fingerprint().unwrap_or([0; 20]),
            ))
            .with_name("edit_own_fingerprint_input")
            .fixed_size((50_usize, 1_usize)),
    );

    fields.add_child(name_fields);
    fields.add_child(directory_fields);
    fields.add_child(keys_fields);
    fields.add_child(pgp_fields);
    fields.add_child(fingerprint_fields);

    fields.add_child(
        TextView::new(CATALOG.gettext("Store Members: ")).fixed_size((30_usize, 1_usize)),
    );
    let store_recipients = store.all_recipients()?;
    for (i, recipient) in all_recipients.iter().enumerate() {
        let mut row = LinearLayout::horizontal();
        row.add_child(TextView::new(&recipient.name).fixed_size((30_usize, 1_usize)));
        let mut c = Checkbox::new();
        if store_recipients.contains(recipient) {
            c.set_checked(true);
        }
        row.add_child(c.with_name(format!("new_recipient_{i}")));
        fields.add_child(row);
    }

    let stores2 = stores.clone();
    let stores3 = stores.clone();
    let name2 = store.get_name().clone();
    let name3 = store.get_name().clone();
    #[allow(clippy::redundant_clone)]
    let config_file_location = config_file_location.to_path_buf();
    #[allow(clippy::redundant_clone)]
    let config_file_location2 = config_file_location.to_path_buf();
    let home = home.clone();
    let home2 = home.clone();

    let d = Dialog::around(fields)
        .title(CATALOG.gettext("Edit store config"))
        .button(CATALOG.gettext("Save"), move |ui: &mut Cursive| {
            do_save_edit_config(ui, stores2.clone(), &name2, &config_file_location, &home);
            ui.pop_layer();
        })
        .dismiss_button(CATALOG.gettext("Cancel"));

    let ev = OnEventView::new(d)
        .on_event(Key::Esc, |s| {
            s.pop_layer();
        })
        .on_event(Key::Enter, move |ui: &mut Cursive| {
            do_save_edit_config(ui, stores3.clone(), &name3, &config_file_location2, &home2);
            ui.pop_layer();
        });

    ui.add_layer(ev);

    Ok(())
}

fn delete_store_from_config(
    ui: &mut Cursive,
    stores: StoreListType,
    config_file_location: &Path,
) -> Result<()> {
    let mut l = ui.find_name::<SelectView<String>>("stores").unwrap();

    let sel = l.selection();

    if sel.is_none() {
        return Ok(());
    }
    let sel = sel.unwrap();
    let name = sel.as_ref();

    {
        let mut stores_borrowed = stores.lock()?;
        stores_borrowed.retain(|store| store.lock().unwrap().get_name() != name);
    }

    let save_res = pass::save_config(stores, config_file_location);
    if let Err(err) = save_res {
        helpers::errorbox(ui, &err);
        return Ok(());
    }

    let delete_id = l.selected_id().unwrap();
    l.remove_item(delete_id);

    ui.call_on_name("status_bar", |l: &mut TextView| {
        l.set_content(CATALOG.gettext("Updated config file"));
    });

    Ok(())
}

fn add_store_to_config(
    ui: &mut Cursive,
    stores: StoreListType,
    config_file_location: &Path,
    home: &Option<PathBuf>,
) -> Result<()> {
    let all_recipients = all_recipients_from_stores(stores.clone())?;

    let mut fields = LinearLayout::vertical();
    let mut name_fields = LinearLayout::horizontal();
    let mut directory_fields = LinearLayout::horizontal();
    let mut keys_fields = LinearLayout::horizontal();
    let mut pgp_fields = LinearLayout::horizontal();
    name_fields.add_child(
        TextView::new(CATALOG.gettext("Name: "))
            .with_name("new_name_name")
            .fixed_size((30_usize, 1_usize)),
    );
    name_fields.add_child(
        EditView::new()
            .with_name("new_name_input")
            .fixed_size((50_usize, 1_usize)),
    );
    directory_fields.add_child(
        TextView::new(CATALOG.gettext("Directory: "))
            .with_name("new_directory_name")
            .fixed_size((30_usize, 1_usize)),
    );
    directory_fields.add_child(
        EditView::new()
            .with_name("new_directory_input")
            .fixed_size((50_usize, 1_usize)),
    );
    keys_fields.add_child(
        TextView::new(CATALOG.gettext("Enforce signing of .gpg-id file: "))
            .with_name("new_keys_name")
            .fixed_size((30_usize, 1_usize)),
    );
    keys_fields.add_child(Checkbox::new().with_name("new_keys_input"));

    pgp_fields.add_child(
        TextView::new(CATALOG.gettext("PGP Implementation: "))
            .with_name("new_pgp_name")
            .fixed_size((10_usize, 1_usize)),
    );
    let mut pgp_radio = RadioGroup::new();
    let gpg_me_button = pgp_radio
        .button(CryptoImpl::GpgMe, "GPG")
        .with_name("new_pgp_me_button_name");
    let sequoia_button = pgp_radio
        .button(CryptoImpl::Sequoia, "Sequoia")
        .with_name("new_sequoia_button_name");
    pgp_fields.add_child(gpg_me_button);
    pgp_fields.add_child(sequoia_button);

    fields.add_child(name_fields);
    fields.add_child(directory_fields);
    fields.add_child(keys_fields);
    fields.add_child(
        TextView::new(CATALOG.gettext("Store Members: ")).fixed_size((30_usize, 1_usize)),
    );
    for (i, recipient) in all_recipients.iter().enumerate() {
        let mut row = LinearLayout::horizontal();
        row.add_child(TextView::new(&recipient.name).fixed_size((30_usize, 1_usize)));
        row.add_child(Checkbox::new().with_name(format!("new_recipient_{i}")));
        fields.add_child(row);
    }
    fields.add_child(pgp_fields);

    let stores2 = stores.clone();
    #[allow(clippy::redundant_clone)]
    let config_file_location = config_file_location.to_path_buf();
    #[allow(clippy::redundant_clone)]
    let config_file_location2 = config_file_location.to_path_buf();
    let home = home.clone();
    let home2 = home.clone();
    let all_recipients2 = all_recipients.clone();

    let d = Dialog::around(fields)
        .title(CATALOG.gettext("New store config"))
        .button(CATALOG.gettext("Save"), move |ui: &mut Cursive| {
            let res = save_new_config(
                ui,
                stores.clone(),
                &config_file_location,
                &home,
                &all_recipients,
            );
            if let Err(err) = res {
                helpers::errorbox(ui, &err);
            } else {
                ui.pop_layer();
            }
        })
        .dismiss_button(CATALOG.gettext("Cancel"));

    let ev = OnEventView::new(d)
        .on_event(Key::Esc, |s| {
            s.pop_layer();
        })
        .on_event(Key::Enter, move |ui: &mut Cursive| {
            let res = save_new_config(
                ui,
                stores2.clone(),
                &config_file_location2,
                &home2,
                &all_recipients2,
            );
            if let Err(err) = res {
                helpers::errorbox(ui, &err);
            } else {
                ui.pop_layer();
            }
        });

    ui.add_layer(ev);

    Ok(())
}

fn do_show_manage_config_dialog(
    ui: &mut Cursive,
    stores: StoreListType,
    config_file_location: PathBuf,
    home: &Option<PathBuf>,
) {
    let res = show_manage_config_dialog(ui, stores, config_file_location, home);
    if let Err(err) = res {
        helpers::errorbox(ui, &err);
    }
}

fn show_manage_config_dialog(
    ui: &mut Cursive,
    stores: StoreListType,
    config_file_location: PathBuf,
    home: &Option<PathBuf>,
) -> Result<()> {
    let mut stores_view = SelectView::<String>::new()
        .h_align(cursive::align::HAlign::Left)
        .with_name("stores");

    for store in stores.lock()?.iter() {
        let store = store.lock()?;
        stores_view
            .get_mut()
            .add_item(store.get_name(), store.get_name().clone());
    }

    let d = Dialog::around(stores_view)
        .title(CATALOG.gettext("Edit password stores"))
        .dismiss_button(CATALOG.gettext("Ok"));

    let ll = LinearLayout::new(Orientation::Vertical).child(d).child(
        LinearLayout::new(Orientation::Horizontal)
            .child(TextView::new(CATALOG.gettext("ctrl-e: Edit | ")))
            .child(TextView::new(CATALOG.gettext("ins: Add | ")))
            .child(TextView::new(CATALOG.gettext("del: Remove"))),
    );

    let stores2 = stores.clone();
    let stores3 = stores.clone();

    let config_file_location2 = config_file_location.clone();
    let config_file_location3 = config_file_location.clone();
    let home = home.clone();
    let home2 = home.clone();

    let recipients_event = OnEventView::new(ll)
        .on_event(Event::CtrlChar('e'), move |ui: &mut Cursive| {
            let res = edit_store_in_config(ui, stores.clone(), &config_file_location, &home);
            if let Err(err) = res {
                helpers::errorbox(ui, &err);
            }
        })
        .on_event(Key::Del, move |ui: &mut Cursive| {
            let res = delete_store_from_config(ui, stores2.clone(), &config_file_location2);
            if let Err(err) = res {
                helpers::errorbox(ui, &err);
            }
        })
        .on_event(Key::Ins, move |ui: &mut Cursive| {
            let res = add_store_to_config(ui, stores3.clone(), &config_file_location3, &home2);
            if let Err(err) = res {
                helpers::errorbox(ui, &err);
            }
        })
        .on_event(Key::Esc, |s| {
            s.pop_layer();
        });

    ui.add_layer(recipients_event);
    Ok(())
}

fn get_style(style_file: &Option<PathBuf>) -> String {
    if let Some(style_file) = style_file {
        let content = std::fs::read_to_string(style_file);
        if let Ok(content) = content {
            return content;
        }
    }

    include_str!("../res/style.toml").to_string()
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    match args.len() {
        1 => (),
        2 => {
            if args[1] == "-h" || args[1] == "--help" {
                help();
                process::exit(0);
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

    let home = match std::env::var("HOME") {
        Err(_) => None,
        Ok(home_path) => Some(PathBuf::from(home_path)),
    };
    let xdg_data_home = match std::env::var("XDG_DATA_HOME") {
        Err(_) => match &home {
            Some(home_path) => home_path.join(".local"),
            None => {
                eprintln!("{}", CATALOG.gettext("No home directory set"));
                process::exit(1);
            }
        },
        Ok(data_home_path) => PathBuf::from(data_home_path),
    };

    let config_res = {
        let password_store_dir = std::env::var("PASSWORD_STORE_DIR").ok();
        let password_store_signing_key = std::env::var("PASSWORD_STORE_SIGNING_KEY").ok();
        let xdg_config_home = match std::env::var("XDG_CONFIG_HOME") {
            Err(_) => None,
            Ok(config_home_path) => Some(PathBuf::from(config_home_path)),
        };

        pass::read_config(
            &password_store_dir,
            &password_store_signing_key,
            &home,
            &xdg_config_home,
        )
    };
    if let Err(err) = config_res {
        eprintln!("Error {err}");
        process::exit(1);
    }
    let (config, config_file_location) = config_res?;

    for path in validate_stores_config(&config, &home) {
        wizard::show_init_menu(&Some(path), &home);
    }

    let stores = get_stores(&config, &home);
    if let Err(err) = stores {
        eprintln!("Error {err}");
        process::exit(1);
    }

    let stores: StoreListType = Arc::new(Mutex::new(
        stores?
            .into_iter()
            .map(|s| Arc::new(Mutex::new(s)))
            .collect(),
    ));

    if !config_file_location.exists() && stores.lock()?.len() == 1 {
        let mut config_file_dir = config_file_location.clone();
        config_file_dir.pop();
        if let Err(err) = std::fs::create_dir_all(config_file_dir) {
            eprintln!("Error {err}");
            process::exit(1);
        }
        if let Err(err) = pass::save_config(stores.clone(), &config_file_location) {
            eprintln!("Error {err}");
            process::exit(1);
        }
    }

    let store: PasswordStoreType = Arc::new(Mutex::new(stores.lock()?[0].clone()));
    #[allow(clippy::significant_drop_in_scrutinee)]
    for ss in stores.lock()?.iter() {
        if ss.lock()?.get_name() == "default" {
            let mut s = store.lock()?;
            *s = ss.clone();
        }
    }
    let res = store.lock()?.lock()?.reload_password_list();
    if let Err(err) = res {
        eprintln!("Error {err}");
        process::exit(1);
    }

    // verify that the git config is correct
    if !store.lock()?.lock()?.has_configured_username() {
        eprintln!("{}", CATALOG.gettext("You haven't configured you name and email in git, doing so will make cooperation with your team easier, you can do it like this:\ngit config --global user.name \"John Doe\"\ngit config --global user.email \"email@example.com\"\n\nAlso consider configuring git to sign your commits with GPG:\ngit config --global user.signingkey 3AA5C34371567BD2\ngit config --global commit.gpgsign true"));
        process::exit(1);
    }

    for password in &store.lock()?.lock()?.passwords {
        if password.is_in_git == pass::RepositoryStatus::NotInRepo {
            eprintln!("{}", CATALOG.gettext("The password store is backed by a git repository, but there is passwords there that's not in git. Please add them, otherwise they might get lost."));
            process::exit(1);
        }
    }

    let mut ui = Cursive::default();

    ui.add_global_callback(Event::CtrlChar('y'), {
        let store = store.clone();
        move |ui: &mut Cursive| copy(ui, store.clone())
    });
    ui.add_global_callback(Event::CtrlChar('u'), copy_name);
    ui.add_global_callback(Key::Enter, {
        let store = store.clone();
        move |ui: &mut Cursive| copy_first_line(ui, store.clone())
    });
    ui.add_global_callback(Event::CtrlChar('b'), {
        let store = store.clone();
        move |ui: &mut Cursive| copy_mfa(ui, store.clone())
    });
    ui.add_global_callback(Key::Del, {
        let store = store.clone();
        move |ui: &mut Cursive| delete(ui, store.clone())
    });

    // Movement
    ui.add_global_callback(Event::CtrlChar('n'), down);
    ui.add_global_callback(Event::CtrlChar('p'), up);
    ui.add_global_callback(Event::Key(Key::PageDown), page_down);
    ui.add_global_callback(Event::Key(Key::PageUp), page_up);

    // View list of persons that have access
    ui.add_global_callback(Event::CtrlChar('v'), {
        let store = store.clone();
        let xdg_data_home = xdg_data_home.clone();
        move |ui: &mut Cursive| do_view_recipients(ui, store.clone(), &xdg_data_home)
    });

    // Show git history of a file
    ui.add_global_callback(Event::CtrlChar('h'), {
        let store = store.clone();
        move |ui: &mut Cursive| do_show_file_history(ui, store.clone())
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
        move |ui: &mut Cursive| {
            do_open(ui, store.clone());
        }
    });
    ui.add_global_callback(Event::CtrlChar('r'), {
        let store = store.clone();
        move |ui: &mut Cursive| {
            rename_file_dialog(ui, store.clone());
        }
    });
    ui.add_global_callback(Event::CtrlChar('f'), {
        let store = store.clone();
        move |ui: &mut Cursive| {
            do_git_pull(ui, store.clone());
        }
    });
    ui.add_global_callback(Event::CtrlChar('g'), {
        let store = store.clone();
        move |ui: &mut Cursive| {
            do_git_push(ui, store.clone());
        }
    });
    ui.add_global_callback(Event::Key(Key::Ins), {
        let store = store.clone();
        move |ui: &mut Cursive| {
            create(ui, store.clone());
        }
    });

    ui.add_global_callback(Event::Key(Key::Esc), |s| s.quit());

    if let Err(err) = ui.load_toml(&get_style(&store.lock()?.lock()?.get_style_file())) {
        eprintln!("Error {err:?}");
        process::exit(1);
    }
    let search_box = EditView::new()
        .on_edit({
            let store = store.clone();
            move |ui: &mut Cursive, query, _| {
                do_search(&store, ui, query);
            }
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
        Tree::new()
            .leaf(CATALOG.gettext("Copy (ctrl-y)"), {
                let store = store.clone();
                move |ui: &mut Cursive| {
                    copy(ui, store.clone());
                }
            })
            .leaf(CATALOG.gettext("Copy Name (ctrl-u)"), copy_name)
            .leaf(CATALOG.gettext("Copy MFA Code (ctrl-b)"), {
                let store = store.clone();
                move |ui: &mut Cursive| {
                    copy_mfa(ui, store.clone());
                }
            })
            .leaf(CATALOG.gettext("Open (ctrl-o)"), {
                let store = store.clone();
                move |ui: &mut Cursive| {
                    do_open(ui, store.clone());
                }
            })
            .leaf(CATALOG.gettext("File History (ctrl-h)"), {
                let store = store.clone();
                move |ui: &mut Cursive| {
                    do_show_file_history(ui, store.clone());
                }
            })
            .leaf(CATALOG.gettext("Create (ins) "), {
                let store = store.clone();
                move |ui: &mut Cursive| {
                    create(ui, store.clone());
                }
            })
            .leaf(CATALOG.gettext("Delete (del)"), {
                let store = store.clone();
                move |ui: &mut Cursive| {
                    delete(ui, store.clone());
                }
            })
            .leaf(CATALOG.gettext("Rename file (ctrl-r)"), {
                let store = store.clone();
                move |ui: &mut Cursive| {
                    rename_file_dialog(ui, store.clone());
                }
            })
            .leaf(CATALOG.gettext("Team Members (ctrl-v)"), {
                let store = store.clone();
                let xdg_data_home = xdg_data_home.clone();
                move |ui: &mut Cursive| {
                    do_view_recipients(ui, store.clone(), &xdg_data_home);
                }
            })
            .delimiter()
            .leaf(CATALOG.gettext("Git Pull (ctrl-f)"), {
                let store = store.clone();
                move |ui: &mut Cursive| {
                    do_git_pull(ui, store.clone());
                }
            })
            .leaf(CATALOG.gettext("Git Push (ctrl-g)"), {
                let store = store.clone();
                move |ui: &mut Cursive| {
                    do_git_push(ui, store.clone());
                }
            })
            .delimiter()
            .leaf(CATALOG.gettext("Pull PGP Certificates"), {
                let store = store.clone();
                let xdg_data_home = xdg_data_home.clone();
                move |ui: &mut Cursive| {
                    pgp_pull(ui, store.clone(), &xdg_data_home);
                }
            })
            .leaf(CATALOG.gettext("Import PGP Certificate from text"), {
                let store = store.clone();
                move |ui: &mut Cursive| {
                    pgp_import(ui, store.clone(), &xdg_data_home);
                }
            })
            .delimiter()
            .leaf(CATALOG.gettext("Quit (esc)"), |s| s.quit()),
    );

    let mut tree = Tree::new();
    #[allow(clippy::significant_drop_in_scrutinee)]
    for s in stores.lock()?.iter() {
        let s = s.clone();
        let store_name = s.lock()?.get_name().clone();
        let store = store.clone();
        tree.add_leaf(store_name, move |ui: &mut Cursive| {
            {
                let mut to_store = store.lock().unwrap();
                *to_store = s.clone();

                let res = to_store.lock().unwrap().reload_password_list();
                if let Err(err) = res {
                    eprintln!("Error {err}");
                    process::exit(1);
                }
            }

            if let Err(err) = ui.load_toml(&get_style(
                &store.lock().unwrap().lock().unwrap().get_style_file(),
            )) {
                eprintln!("Error {err:?}");
                process::exit(1);
            }

            ui.call_on_name("search_box", |e: &mut EditView| {
                e.set_content("");
            });
            do_search(&store, ui, "");
        });
    }
    tree.add_delimiter();
    tree.add_leaf(CATALOG.gettext("Manage"), move |ui: &mut Cursive| {
        do_show_manage_config_dialog(ui, stores.clone(), config_file_location.clone(), &home);
    });
    ui.menubar().add_subtree(CATALOG.gettext("Stores"), tree);

    ui.add_global_callback(Key::F1, |s| s.select_menubar());

    // This construction is to make sure that the password list is populated when the program starts
    // it would be better to signal this somehow from the library, but that got tricky
    thread::sleep(time::Duration::from_millis(200));
    do_search(&store, &mut ui, "");

    ui.run();
    Ok(())
}

#[cfg(test)]
#[path = "tests/main.rs"]
mod cursive_tests;
