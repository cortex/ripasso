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

use self::cursive::views::{Dialog, OnEventView, TextView};

use self::cursive::event::Key;
use cursive::Cursive;

use ripasso::pass;

pub fn errorbox(ui: &mut Cursive, err: &pass::Error)  {
    let text = match err {
        pass::Error::RecipientNotInKeyRing(key_id) => super::CATALOG.gettext("Team member with key id {} isn't in your GPG keyring, fetch it first").to_string().replace("{}", key_id),
        _ => format!("{:?}", err)
    };

    let d = Dialog::around(TextView::new(text))
        .dismiss_button(super::CATALOG.gettext("Ok"))
        .title(super::CATALOG.gettext("Error"));

    let ev = OnEventView::new(d).on_event(Key::Esc, |s| {
        s.pop_layer();
    });

    ui.add_layer(ev);
}
