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

use std::sync::{Arc, Mutex};

use arboard::Clipboard;
use cursive::{
    event::Key,
    views::{Checkbox, Dialog, EditView, OnEventView, RadioButton, TextView},
    Cursive,
};
use lazy_static::lazy_static;
use pass::Result;
use ripasso::pass::Recipient;
use ripasso::{crypto::CryptoImpl, pass};

lazy_static! {
    static ref CLIPBOARD: Arc<Mutex<Clipboard>> = Arc::new(Mutex::new(Clipboard::new().unwrap()));
}

/// Displays an error in a cursive dialog
pub fn errorbox(ui: &mut Cursive, err: &pass::Error) {
    let text = match err {
        pass::Error::RecipientNotInKeyRing(key_id) => super::CATALOG
            .gettext("Team member with key id {} isn't in your GPG keyring, fetch it first")
            .to_string()
            .replace("{}", key_id),
        _ => format!("{err}"),
    };

    let d = Dialog::around(TextView::new(text))
        .dismiss_button(super::CATALOG.gettext("Ok"))
        .title(super::CATALOG.gettext("Error"));

    let ev = OnEventView::new(d).on_event(Key::Esc, |s| {
        s.pop_layer();
    });

    ui.add_layer(ev);
}

/// Copies content to the clipboard.
pub fn set_clipboard(content: &String) -> Result<()> {
    Ok(CLIPBOARD.lock().unwrap().set_text(content)?)
}

pub fn get_value_from_input(s: &mut Cursive, input_name: &str) -> Option<Arc<String>> {
    let mut password = None;
    s.call_on_name(input_name, |e: &mut EditView| {
        password = Some(e.get_content());
    });
    password
}

pub fn is_checkbox_checked(ui: &mut Cursive, name: &str) -> bool {
    let mut checked = false;
    ui.call_on_name(name, |l: &mut Checkbox| {
        checked = l.is_checked();
    });

    checked
}

pub fn is_radio_button_selected(s: &mut Cursive, button_name: &str) -> bool {
    let mut selected = false;
    s.call_on_name(button_name, |e: &mut RadioButton<CryptoImpl>| {
        selected = e.is_selected();
    });
    selected
}

pub fn recipients_widths(recipients: &[Recipient]) -> (usize, usize) {
    let mut max_width_key = 0;
    let mut max_width_name = 0;
    for recipient in recipients {
        if recipient.key_id.len() > max_width_key {
            max_width_key = recipient.key_id.len();
        }
        if recipient.name.len() > max_width_name {
            max_width_name = recipient.name.len();
        }
    }
    (max_width_key, max_width_name)
}

#[cfg(test)]
#[path = "tests/helpers.rs"]
mod helpers_tests;
