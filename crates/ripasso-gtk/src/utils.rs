use std::sync::{Arc, Mutex};

use gtk4::{MessageDialog, prelude::IsA};
use libadwaita::prelude::{DialogExt, GtkWindowExt, WidgetExt};
use ripasso::pass::{Error, PasswordStore};

#[derive(Clone, glib::SharedBoxed)]
#[shared_boxed_type(name = "PasswordStoreBoxed")]
pub struct PasswordStoreBoxed(pub Arc<Mutex<PasswordStore>>);

pub fn error_dialog(error: &Error, transient_for: &impl IsA<gtk4::Window>) {
    let dialog = MessageDialog::builder()
        .buttons(gtk4::ButtonsType::Ok)
        .title("Application Error")
        .use_header_bar(0)
        .transient_for(transient_for)
        .secondary_text(format!("{error}"))
        .build();

    dialog.connect_response(move |dialog, _| {
        // Destroy dialog
        dialog.destroy();
    });

    dialog.show();
}

pub fn error_dialog_standalone(error: &Error) {
    let dialog = MessageDialog::builder()
        .buttons(gtk4::ButtonsType::Ok)
        .title("Application Error")
        .use_header_bar(0)
        .secondary_text(format!("{error}"))
        .build();

    dialog.connect_response(move |dialog, _| {
        // Destroy dialog
        dialog.destroy();
    });

    dialog.show();
}
