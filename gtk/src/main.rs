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

use gdk::keys::constants;
use gdk::ModifierType;
use glib::ObjectExt;
use gtk::prelude::BuilderExtManual;
use gtk::prelude::GtkListStoreExtManual;
use gtk::*;

use glib::Cast;
use glib::StaticType;

use clipboard::{ClipboardContext, ClipboardProvider};
use ripasso::pass;
use std::cell::RefCell;
use std::path::PathBuf;
use std::process;
use std::sync::{atomic::Ordering, Arc, Mutex};
use std::{thread, time};

use pass::PasswordStoreType;

#[macro_use]
extern crate lazy_static;

lazy_static! {
    static ref SHOWN_PASSWORDS: Arc<Mutex<Vec<pass::PasswordEntry>>> = Arc::new(Mutex::new(vec![]));
}

fn setup_menu(
    builder: &Builder,
    menu_bar: Arc<MenuBar>,
    window: &Window,
    password_list: &TreeView,
    status_bar: Arc<TextView>,
    store: PasswordStoreType,
) {
    let file_menu_item: Arc<MenuItem> = Arc::new(
        builder
            .get_object("fileMenu")
            .expect("Couldn't get fileMenu"),
    );

    let stores_menu_item: Arc<MenuItem> = Arc::new(
        builder
            .get_object("storesMenu")
            .expect("Couldn't get storesMenu"),
    );

    let menu_bar2 = menu_bar.clone();
    let alt_just_pressed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let alt_just_pressed2 = alt_just_pressed.clone();

    window.connect_key_press_event(move |_, key| {
        if key.get_keyval() == constants::Alt_L && menu_bar.is_visible() {
            menu_bar.hide();
            alt_just_pressed.store(true, Ordering::Relaxed);
        }
        if key.get_keyval() == constants::f && key.get_state().intersects(ModifierType::MOD1_MASK) {
            menu_bar.show();
            file_menu_item.activate();
        }
        if key.get_keyval() == constants::s && key.get_state().intersects(ModifierType::MOD1_MASK) {
            menu_bar.show();
            stores_menu_item.activate();
        }

        Inhibit(false)
    });

    window.connect_key_release_event(move |_, key| {
        if key.get_keyval() == constants::Alt_L {
            if !menu_bar2.is_visible() && !alt_just_pressed2.load(Ordering::Relaxed) {
                menu_bar2.show();
            }
            alt_just_pressed2.store(false, Ordering::Relaxed);
        }

        Inhibit(false)
    });

    setup_menu_copy(builder, password_list, status_bar.clone());
    setup_menu_copy_name(builder, password_list, status_bar);
    setup_menu_open(builder, password_list, store.clone());
    setup_menu_file_history(builder, password_list, store);
    setup_menu_quit(builder, window);
}

fn setup_menu_copy(builder: &Builder, password_list: &TreeView, status_bar: Arc<TextView>) {
    let copy_menu_item: MenuItem = builder
        .get_object("menuItemCopy")
        .expect("Couldn't get menuItemCopy");

    let password_list = password_list.clone();
    copy_menu_item.connect_activate(move |_| {
        let password_list = password_list.clone();
        let (path, _) = password_list.get_selection().get_selected_rows();

        if path.is_empty() {
            return;
        }

        let passwords = SHOWN_PASSWORDS.lock().unwrap();

        let mut ctx = clipboard::ClipboardContext::new().unwrap();

        let password_res = passwords[path[0].get_indices()[0] as usize].password();

        match password_res {
            Err(err) => {
                error_box(err);
            }
            Ok(password) => {
                let clipboard_res = ctx.set_contents(password);
                if let Err(err) = clipboard_res {
                    error_box(pass::Error::from(err));
                }

                let buf_opt = status_bar.get_buffer();
                if let Some(buf) = buf_opt {
                    buf.set_text("Copied password to copy buffer for 40 seconds");
                }

                thread::spawn(|| {
                    thread::sleep(time::Duration::from_secs(40));
                    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
                    ctx.set_contents("".to_string()).unwrap();
                });
            }
        }
    });
}

fn setup_menu_copy_name(builder: &Builder, password_list: &TreeView, status_bar: Arc<TextView>) {
    let copy_menu_item: MenuItem = builder
        .get_object("menuItemCopyName")
        .expect("Couldn't get menuItemCopyName");

    let password_list = password_list.clone();
    copy_menu_item.connect_activate(move |_| {
        let password_list = password_list.clone();
        let (path, _) = password_list.get_selection().get_selected_rows();

        if path.is_empty() {
            return;
        }

        let passwords = SHOWN_PASSWORDS.lock().unwrap();

        let mut ctx = clipboard::ClipboardContext::new().unwrap();

        let name_res = passwords[path[0].get_indices()[0] as usize]
            .name
            .split('/')
            .next_back();

        match name_res {
            None => {
                error_box(pass::Error::Generic("can't find end of filename"));
            }
            Some(name) => {
                let clipboard_res = ctx.set_contents(name.to_string());
                if let Err(err) = clipboard_res {
                    error_box(pass::Error::from(err));
                }

                let buf_opt = status_bar.get_buffer();
                if let Some(buf) = buf_opt {
                    buf.set_text("Copied name of password to copy buffer");
                }

                thread::spawn(|| {
                    thread::sleep(time::Duration::from_secs(40));
                    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
                    ctx.set_contents("".to_string()).unwrap();
                });
            }
        }
    });
}

fn setup_menu_open(builder: &Builder, password_list: &TreeView, store: PasswordStoreType) {
    let open_menu_item: MenuItem = builder
        .get_object("menuItemOpen")
        .expect("Couldn't get menuItemCopyName");

    let password_list = password_list.clone();
    open_menu_item.connect_activate(move |_| {
        let password_list = password_list.clone();
        let (path, _) = password_list.get_selection().get_selected_rows();

        if path.is_empty() {
            return;
        }

        let passwords = SHOWN_PASSWORDS.lock().unwrap();

        let password = &passwords[path[0].get_indices()[0] as usize];

        if let Err(err) = open_dialog(password, store.clone()) {
            error_box(err);
        }
    });
}

fn open_dialog(password: &pass::PasswordEntry, store: PasswordStoreType) -> pass::Result<()> {
    let buttons = vec![
        ("Save", ResponseType::Apply),
        ("Generate", ResponseType::Other(777)),
        ("Close", ResponseType::Close),
    ];
    let dialog = Dialog::with_buttons(None, None::<&Window>, DialogFlags::empty(), &buttons);

    let text_view = TextView::new();
    let buf = text_view.get_buffer().unwrap();
    buf.insert(&mut buf.get_start_iter(), &password.password()?);
    let content = dialog.get_content_area();
    content.add(&text_view);

    let password = password.clone();
    let c_res = dialog.connect("response", true, move |arg| {
        let dialog = arg[0].get::<Dialog>().unwrap().unwrap();
        let content = dialog.get_content_area();
        let t = &content.get_children()[0];
        let text_view = t.downcast_ref::<TextView>().unwrap();
        let buf = text_view.get_buffer().unwrap();
        let signal = arg[1].get::<i32>().unwrap().unwrap();

        match ResponseType::from(signal) {
            ResponseType::Apply => {
                let new_password = buf
                    .get_text(&buf.get_start_iter(), &buf.get_end_iter(), true)
                    .unwrap();
                let res = password.update(new_password.to_string(), &store.lock().unwrap());

                if let Err(err) = res {
                    error_box(err);
                }
            }
            ResponseType::Other(_) => {
                let new_password = ripasso::words::generate_password(6);
                buf.delete(&mut buf.get_start_iter(), &mut buf.get_end_iter());
                buf.insert(&mut buf.get_start_iter(), &new_password);
            }
            ResponseType::Close | ResponseType::DeleteEvent => {
                arg[0].get::<Dialog>().unwrap().unwrap().close();
            }
            _ => {
                eprintln!("unknown signal: {}", signal);
            }
        }
        None
    });
    if let Err(err) = c_res {
        eprintln!("{:?}", err);
        process::exit(0x01);
    }
    dialog.show_all();
    dialog.run();
    Ok(())
}

fn setup_menu_file_history(builder: &Builder, password_list: &TreeView, store: PasswordStoreType) {
    let file_history_menu_item: MenuItem = builder
        .get_object("menuItemFileHistory")
        .expect("Couldn't get menuItemCopyName");

    let password_list = password_list.clone();
    file_history_menu_item.connect_activate(move |_| {
        let password_list = password_list.clone();
        let (path, _) = password_list.get_selection().get_selected_rows();

        if path.is_empty() {
            return;
        }

        let passwords = SHOWN_PASSWORDS.lock().unwrap();

        let password = &passwords[path[0].get_indices()[0] as usize];

        if let Err(err) = file_history_dialog(password, store.clone()) {
            error_box(err);
        }
    });
}

fn file_history_dialog(
    password: &pass::PasswordEntry,
    store: PasswordStoreType,
) -> pass::Result<()> {
    let buttons = vec![("Close", ResponseType::Close)];

    let dialog = Dialog::with_buttons(
        Some("File History"),
        None::<&Window>,
        DialogFlags::empty(),
        &buttons,
    );

    let c_res = dialog.connect("response", true, move |arg| {
        arg[0].get::<Dialog>().unwrap().unwrap().close();
        None
    });
    if let Err(err) = c_res {
        eprintln!("{:?}", err);
        process::exit(0x01);
    }

    let tree_view = TreeView::new();

    let model = ListStore::new(&[String::static_type(), String::static_type()]);

    let commit_msg_col = TreeViewColumn::new();
    let author_col = TreeViewColumn::new();

    let commit_cell = CellRendererText::new();
    let author_cell = CellRendererText::new();

    commit_msg_col.pack_start(&commit_cell, true);
    commit_msg_col.add_attribute(&commit_cell, "text", 0);
    author_col.pack_start(&author_cell, true);
    author_col.add_attribute(&author_cell, "text", 1);

    tree_view.append_column(&commit_msg_col);
    tree_view.append_column(&author_col);

    let history = password.get_history(&store)?;

    for (i, history_line) in history.iter().enumerate() {
        model.insert_with_values(
            Some(i as u32),
            &[0, 1],
            &[&history_line.message, &history_line.commit_time.to_string()],
        );
    }

    tree_view.set_model(Some(&model));

    let content = dialog.get_content_area();
    content.add(&tree_view);

    dialog.show_all();
    dialog.run();
    Ok(())
}

fn setup_menu_quit(builder: &Builder, window: &Window) {
    let quit_menu_item: MenuItem = builder
        .get_object("menuItemQuit")
        .expect("Couldn't get menuItemQuit");

    let window2 = window.clone();
    quit_menu_item.connect_activate(move |_| {
        window2.close();
    });
}

fn error_box(err: pass::Error) {
    let dialog = MessageDialog::new(
        None::<&Window>,
        DialogFlags::empty(),
        MessageType::Info,
        ButtonsType::Close,
        &format!("{:?}", err),
    );

    let c_res = dialog.connect("response", true, move |arg| {
        arg[0].get::<MessageDialog>().unwrap().unwrap().close();
        None
    });
    if let Err(err) = c_res {
        eprintln!("{:?}", err);
        process::exit(0x01);
    }
    dialog.run();
}

fn main() {
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
            &"default".to_string(),
            &password_store_dir,
            &password_store_signing_key,
            &home,
        )
        .unwrap(),
    ));

    let reload_res = store.lock().unwrap().reload_password_list();
    if let Err(e) = reload_res {
        eprintln!("Error: {:?}", e);
        process::exit(0x01);
    }

    if gtk::init().is_err() {
        panic!("failed to initialize GTK.");
    }

    let settings = gtk::Settings::get_default();
    settings
        .unwrap()
        .set_property_gtk_application_prefer_dark_theme(true);

    let glade_src = include_str!("../res/ripasso.ui.xml");
    let builder = Builder::from_string(glade_src);

    let window: Window = builder
        .get_object("mainWindow")
        .expect("Couldn't get window1");

    let password_list: Arc<TreeView> = Arc::new(
        builder
            .get_object("passwordList")
            .expect("Couldn't get list"),
    );

    let status_bar: Arc<TextView> = Arc::new(
        builder
            .get_object("statusBar")
            .expect("Couldn't get statusBar"),
    );

    let status_bar_clone = status_bar.clone();
    password_list.connect_row_activated(move |_, path, _column| {
        let passwords = SHOWN_PASSWORDS.lock().unwrap();

        let mut ctx = clipboard::ClipboardContext::new().unwrap();

        let password_res = passwords[path.get_indices()[0] as usize].password();

        match password_res {
            Err(err) => {
                error_box(err);
            }
            Ok(password) => {
                let clipboard_res = ctx.set_contents(password);
                if let Err(err) = clipboard_res {
                    error_box(pass::Error::from(err));
                }

                let buf_opt = status_bar_clone.get_buffer();
                if let Some(buf) = buf_opt {
                    buf.set_text("Copied password to copy buffer for 40 seconds");
                }

                thread::spawn(|| {
                    thread::sleep(time::Duration::from_secs(40));
                    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
                    ctx.set_contents("".to_string()).unwrap();
                });
            }
        }
    });

    let menu_bar: Arc<MenuBar> =
        Arc::new(builder.get_object("menuBar").expect("Couldn't get menuBar"));

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

    window.show_all();
    menu_bar.hide();

    setup_menu(
        &builder,
        menu_bar,
        &window,
        &password_list,
        status_bar,
        store.clone(),
    );

    GLOBAL.with(move |global| {
        *global.borrow_mut() = Some((password_search, password_list, store));
    });

    gtk::main();
}

fn results(store: &pass::PasswordStoreType, query: &str) -> ListStore {
    let model = ListStore::new(&[String::static_type()]);
    let filtered = pass::search(store, query).unwrap();
    let mut passwords = SHOWN_PASSWORDS.lock().unwrap();
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
            let query = password_search.get_text();
            password_list.set_model(Some(&results(&store, &query)));
        }
    });
    glib::Continue(false)
}

thread_local!(
    static GLOBAL: RefCell<Option<(gtk::SearchEntry,
        Arc<TreeView>,
        pass::PasswordStoreType,
    )>> = RefCell::new(None)
);
