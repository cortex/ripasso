#![cfg(feature = "use-tui")]
extern crate cursive;

use self::cursive::Cursive;
use self::cursive::traits::*;
use self::cursive::views::{
    Dialog,
    EditView,
    LinearLayout,
    ListView,
    OnEventView,
    SelectView,
    TextView,
};

use self::cursive::align::HAlign;
use self::cursive::direction::Orientation;
use self::cursive::event::{Event, Key};

extern crate clipboard;
use self::clipboard::{ClipboardContext, ClipboardProvider};

use pass;
use std;
use std::process;

pub fn main() {
    // Load and watch all the passwords in the background
    let (password_rx, passwords) = match pass::watch() {
        Ok(t) => t,
        Err(e) => {
            process::exit(1);
        }
    };

    let mut siv = Cursive::new();

    fn down(s: &mut Cursive) -> () {
        s.call_on_id("results", |l: &mut SelectView<pass::PasswordEntry>| {
            l.select_down(1);
        });
    }
    fn up(s: &mut Cursive) -> () {
        s.call_on_id("results", |l: &mut SelectView<pass::PasswordEntry>| {
            l.select_up(1);
        });
    }

    // Copy
    fn copy(s: &mut Cursive) -> () {
        s.call_on_id("results", |l: &mut SelectView<pass::PasswordEntry>| {
            let password = l.selection().password().unwrap();
            let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
            ctx.set_contents(password.to_owned()).unwrap();
        });
    };
    siv.add_global_callback(Event::CtrlChar('y'), copy);
    siv.add_global_callback(Key::Enter, copy);

    // Movement
    siv.add_global_callback(Event::CtrlChar('n'), down);
    siv.add_global_callback(Event::CtrlChar('p'), up);

    // Editing
    siv.add_global_callback(Event::CtrlChar('w'), |s| {
        s.call_on_id("searchbox", |e: &mut EditView| {
            e.set_content("");
        });
    });

    siv.load_theme(include_str!("../res/style.toml")).unwrap();
    siv.load_theme_file("res/style.toml").unwrap();
    let searchbox = EditView::new()
        .on_edit(move |s, q, l| {
            s.call_on_id("results", |l: &mut SelectView<pass::PasswordEntry>| {
                let r = pass::search(&passwords, String::from(q));
                l.clear();
                for p in r.iter() {
                    l.add_item(p.name.clone(), p.clone());
                }
            });
        })
        .with_id("searchbox")
        .fixed_width(72);

    // Override shortcuts on search box
    let searchbox = OnEventView::new(searchbox)
        .on_event(Key::Up, up)
        .on_event(Key::Down, down);

    let results = SelectView::<pass::PasswordEntry>::new()
        .with_id("results")
        .full_height();

    siv.add_layer(
        LinearLayout::new(Orientation::Vertical)
            .child(
                Dialog::around(
                    LinearLayout::new(Orientation::Vertical)
                        .child(searchbox)
                        .child(results)
                        .fixed_width(72),
                ).title("Ripasso"),
            )
            .child(
                LinearLayout::new(Orientation::Horizontal)
                    .child(TextView::new("CTRL-N: Next "))
                    .child(TextView::new("CTRL-P: Previous "))
                    .child(TextView::new("CTRL-Y: Copy "))
                    .child(TextView::new("CTRL-W: Clear"))
                    .full_width(),
            ),
    );
    siv.run();
}
