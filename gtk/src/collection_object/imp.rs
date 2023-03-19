use std::{
    cell::RefCell,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use adw::{prelude::*, subclass::prelude::*};
use glib::{ParamSpec, ParamSpecString, Value};
use gtk::{
    gio, glib,
    glib::{ParamSpecBoxed, ParamSpecObject},
};
use once_cell::sync::{Lazy, OnceCell};
use ripasso::pass::PasswordStore;

use crate::utils::PasswordStoreBoxed;

// Object holding the state
#[derive(Default)]
pub struct CollectionObject {
    pub title: RefCell<String>,
    pub passwords: OnceCell<gio::ListStore>,
    pub store: RefCell<Arc<Mutex<PasswordStore>>>,
    pub user_config_dir: RefCell<PathBuf>,
}

// The central trait for subclassing a GObject
#[glib::object_subclass]
impl ObjectSubclass for CollectionObject {
    const NAME: &'static str = "RipassoCollectionObject";
    type Type = super::CollectionObject;
}

// Trait shared by all GObjects
impl ObjectImpl for CollectionObject {
    fn properties() -> &'static [ParamSpec] {
        static PROPERTIES: Lazy<Vec<ParamSpec>> = Lazy::new(|| {
            vec![
                ParamSpecString::builder("title").build(),
                ParamSpecObject::builder::<gio::ListStore>("passwords").build(),
                ParamSpecBoxed::builder::<PasswordStoreBoxed>("store").build(),
                ParamSpecString::builder("user-config-dir").build(),
            ]
        });
        PROPERTIES.as_ref()
    }

    fn set_property(&self, _id: usize, value: &Value, pspec: &ParamSpec) {
        match pspec.name() {
            "title" => {
                let input_value = value
                    .get()
                    .expect("The value needs to be of type `String`.");
                self.title.replace(input_value);
            }
            "passwords" => {
                let input_value = value
                    .get()
                    .expect("The value needs to be of type `gio::ListStore`.");
                self.passwords
                    .set(input_value)
                    .expect("Could not set password");
            }
            "store" => {
                let input_value: PasswordStoreBoxed = value
                    .get()
                    .expect("The value needs to be of type `PasswordStoreBoxed`.");

                *self.store.borrow_mut() = input_value.into_refcounted();
            }
            "user-config-dir" => {
                let input_value: String = value
                    .get()
                    .expect("The value needs to be of type `String`.");

                *self.user_config_dir.borrow_mut() = PathBuf::from(input_value);
            }
            _ => unimplemented!(),
        }
    }

    fn property(&self, _id: usize, pspec: &ParamSpec) -> Value {
        match pspec.name() {
            "title" => self.title.borrow().to_value(),
            "passwords" => self
                .passwords
                .get()
                .expect("Could not get passwords.")
                .to_value(),
            _ => unimplemented!(),
        }
    }
}
