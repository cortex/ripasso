#![cfg(feature = "use-tui")]
extern crate cursive;

extern crate env_logger;

use self::cursive::Cursive;
use self::cursive::traits::*;
use self::cursive::views::{Dialog, EditView, LinearLayout, OnEventView, SelectView, TextView};

use self::cursive::direction::Orientation;
use self::cursive::event::{Event, Key};

extern crate clipboard;
use self::clipboard::{ClipboardContext, ClipboardProvider};

use pass;
use std::process;

use std::sync::{Mutex};

pub fn main() {
    env_logger::init();

    // Load and watch all the passwords in the background
    let (_password_rx, passwords) = match pass::watch() {
        Ok(t) => t,
        Err(e) => {
            println!("Error {:?}", e);
            process::exit(1);
        }
    };

    let mut ui = Cursive::new();
    let rrx = Mutex::new(_password_rx);

    ui.set_fps(10);

    ui.cb_sink().send(Box::new(move|s: &mut Cursive| {
        let event = rrx.lock().unwrap().try_recv();
        match event {
            Ok(e) => match e{
                pass::PasswordEvent::Error(ref err)=> {
                    let d = Dialog::around(
                        TextView::new(format!("{:?}", err)))
                        .dismiss_button("Ok");
                        s.add_layer(d);
                    },
                    _ => ()
                },
                _ => ()
            }
        }));

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

    // Copy
    fn copy(ui: &mut Cursive) -> () {
        ui.call_on_id("results", |l: &mut SelectView<pass::PasswordEntry>| {
            let password = l.selection().password().unwrap();
            let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
            ctx.set_contents(password.to_owned()).unwrap();
        });
    };
    ui.add_global_callback(Event::CtrlChar('y'), copy);
    ui.add_global_callback(Key::Enter, copy);

    // Movement
    ui.add_global_callback(Event::CtrlChar('n'), down);
    ui.add_global_callback(Event::CtrlChar('p'), up);

    // Query editing
    ui.add_global_callback(Event::CtrlChar('w'), |ui| {
        ui.call_on_id("searchbox", |e: &mut EditView| {
            e.set_content("");
        });
    });

    // Editing
    ui.add_global_callback(Event::CtrlChar('o'), |ui| {
        let password: String = ui.call_on_id(
            "results",
            |l: &mut SelectView<pass::PasswordEntry>| l.selection().password().unwrap(),
        ).unwrap();

        let d = Dialog::around(TextView::new(password)).dismiss_button("Ok");

        ui.add_layer(d);
    });

    ui.load_theme(include_str!("../res/style.toml")).unwrap();
    ui.load_theme_file("res/style.toml").unwrap();
    let searchbox = EditView::new()
        .on_edit(move |ui, query, _| {
            ui.call_on_id("results", |l: &mut SelectView<pass::PasswordEntry>| {
                let r = pass::search(&passwords, &String::from(query));
                l.clear();
                for p in &r {
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

    ui.add_layer(
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
                    .child(TextView::new("CTRL-W: Clear "))
                    .child(TextView::new("CTRL-O: Open"))
                    .full_width(),
            ),
    );
    ui.run();
}
