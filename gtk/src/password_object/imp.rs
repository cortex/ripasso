use std::{
    cell::RefCell,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use adw::{prelude::*, subclass::prelude::*};
use chrono::{DateTime, Local};
use glib::{ParamSpec, ParamSpecBoxed, ParamSpecString, Value};
use gtk::glib;
use once_cell::sync::Lazy;
use ripasso::pass::{PasswordEntry, PasswordStore};

use crate::utils::{PasswordStoreBoxed, error_dialog_standalone};

// Object holding the state
#[derive(Default)]
pub struct PasswordObject {
    pub data: RefCell<PasswordEntry>,
    pub store: RefCell<Arc<Mutex<PasswordStore>>>,
}

// The central trait for subclassing a GObject
#[glib::object_subclass]
impl ObjectSubclass for PasswordObject {
    const NAME: &'static str = "RipassoPasswordObject";
    type Type = super::PasswordObject;
}

// Trait shared by all GObjects
impl ObjectImpl for PasswordObject {
    fn properties() -> &'static [ParamSpec] {
        static PROPERTIES: Lazy<Vec<ParamSpec>> = Lazy::new(|| {
            vec![
                ParamSpecString::builder("name").build(),
                ParamSpecString::builder("path").build(),
                ParamSpecString::builder("committed-by").build(),
                ParamSpecString::builder("updated").build(),
                ParamSpecString::builder("secret").build(),
                ParamSpecBoxed::builder::<PasswordStoreBoxed>("store").build(),
            ]
        });
        PROPERTIES.as_ref()
    }

    fn set_property(&self, _id: usize, value: &Value, pspec: &ParamSpec) {
        match pspec.name() {
            "name" => {
                let input_value: String = value
                    .get()
                    .expect("The value needs to be of type `String`.");
                self.data.borrow_mut().name = input_value;
            }
            "path" => {
                let input_value: String = value
                    .get()
                    .expect("The value needs to be of type `String`.");
                self.data.borrow_mut().path = PathBuf::from(input_value);
            }
            "updated" => {
                let input_value: String = value
                    .get()
                    .expect("The value needs to be of type `String`.");

                self.data.borrow_mut().updated = Some(
                    input_value
                        .parse::<DateTime<Local>>()
                        .expect("Failed to parse date"),
                );
            }
            "committed-by" => {
                let input_value = value
                    .get()
                    .expect("The value needs to be of type `String`.");
                self.data.borrow_mut().committed_by = Some(input_value);
            }
            "secret" => {}
            "store" => {
                let input_value: PasswordStoreBoxed = value
                    .get()
                    .expect("The value needs to be of type `PasswordStoreBoxed`.");

                *self.store.borrow_mut() = input_value.into_refcounted();
            }
            _ => unimplemented!(),
        }
    }

    fn property(&self, _id: usize, pspec: &ParamSpec) -> Value {
        match pspec.name() {
            "name" => self.data.borrow().name.to_value(),
            "updated" => format!(
                "{}",
                self.data
                    .borrow()
                    .updated
                    .expect("Expected a git repo")
                    .format("%Y-%m-%d")
            )
            .to_value(),
            "committed-by" => self.data.borrow().committed_by.to_value(),
            "secret" => {
                let store = self.store.borrow();
                let store = store.as_ref().lock().expect("locked store");

                let res = self.data.borrow().secret(&store);

                match res {
                    Ok(secret) => secret.to_value(),
                    Err(e) => {
                        error_dialog_standalone(&e);
                        "".to_value()
                    }
                }
            }
            _ => unimplemented!(),
        }
    }
}
