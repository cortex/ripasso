use std::sync::{Arc, Mutex};

use gtk4::prelude::{Cast, IsA};
use libadwaita::{AlertDialog, prelude::*};
use ripasso::pass::{Error, PasswordStore};

#[derive(Clone, glib::SharedBoxed)]
#[shared_boxed_type(name = "PasswordStoreBoxed")]
pub struct PasswordStoreBoxed(pub Arc<Mutex<PasswordStore>>);

pub fn error_dialog(error: &Error, transient_for: &impl IsA<gtk4::Widget>) {
    let dialog = AlertDialog::builder()
        .heading("Application Error")
        .body(format!("{error}"))
        .build();
    dialog.add_response("ok", "OK");
    dialog.set_default_response(Some("ok"));
    dialog.set_close_response("ok");

    dialog.present(Some(transient_for));
}

pub fn error_dialog_standalone(error: &Error) {
    let dialog = AlertDialog::builder()
        .heading("Application Error")
        .body(format!("{error}"))
        .build();
    dialog.add_response("ok", "OK");
    dialog.set_default_response(Some("ok"));
    dialog.set_close_response("ok");

    // No explicit parent is available here, so present the dialog relative to
    // the application's active window if there is one.
    let parent = gtk4::gio::Application::default()
        .and_then(|app| app.downcast::<libadwaita::Application>().ok())
        .and_then(|app| app.active_window());
    dialog.present(parent.as_ref());
}
