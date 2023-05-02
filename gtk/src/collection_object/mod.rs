mod imp;

use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use adw::{
    prelude::{ListModelExtManual, *},
    subclass::prelude::*,
};
use glib::Object;
use gtk::{gio, glib};
use ripasso::pass::{PasswordEntry, PasswordStore};

use crate::{
    password_object::PasswordObject,
    utils::{error_dialog, PasswordStoreBoxed},
};

glib::wrapper! {
    pub struct CollectionObject(ObjectSubclass<imp::CollectionObject>);
}

impl CollectionObject {
    pub fn new(
        title: &str,
        passwords: gio::ListStore,
        store: Arc<Mutex<PasswordStore>>,
        user_config_dir: &Path,
    ) -> Self {
        let co = Object::builder()
            .property("title", title)
            .property("passwords", passwords)
            .property("store", PasswordStoreBoxed(store))
            .property(
                "user-config-dir",
                user_config_dir
                    .to_str()
                    .expect("can't have non-utf8 in path"),
            )
            .build();

        co
    }

    pub fn passwords(&self) -> gio::ListStore {
        self.imp()
            .passwords
            .get()
            .expect("Could not get passwords.")
            .clone()
    }

    pub fn git_pull(&self, parent_window: &impl IsA<gtk::Window>) {
        let res = ripasso::git::pull(&self.imp().store.borrow().as_ref().lock().unwrap());

        if let Err(e) = res {
            error_dialog(&e, parent_window);
        }
    }

    pub fn git_push(&self, parent_window: &impl IsA<gtk::Window>) {
        let res = ripasso::git::push(&self.imp().store.borrow().as_ref().lock().unwrap());

        if let Err(e) = res {
            error_dialog(&e, parent_window);
        }
    }

    pub fn pgp_download(&self, parent_window: &impl IsA<gtk::Window>) {
        let res = ripasso::pass::pgp_pull(
            &mut self.imp().store.borrow_mut().lock().unwrap(),
            &self.imp().user_config_dir.borrow(),
        );

        if let Err(e) = res {
            error_dialog(&e, parent_window);
        }
    }

    pub fn to_collection_data(&self) -> CollectionData {
        let title = self.imp().title.borrow().clone();
        let passwords_data = self
            .passwords()
            .snapshot()
            .iter()
            .filter_map(Cast::downcast_ref::<PasswordObject>)
            .map(PasswordObject::password_entry)
            .collect();

        CollectionData {
            title,
            passwords_data,
        }
    }

    pub fn from_store_data(collection_data: PasswordStore, user_config_dir: &Path) -> Self {
        let title = collection_data.get_name().to_string();

        let mut vec = collection_data
            .all_passwords()
            .expect("Error loading password list");

        vec.sort_by(|a, b| a.name.partial_cmp(&b.name).unwrap());

        let store = Arc::new(Mutex::new(collection_data));

        let passwords_to_extend: Vec<PasswordObject> = vec
            .into_iter()
            .map(|p| PasswordObject::from_password_entry(p, store.clone()))
            .collect();

        let passwords = gio::ListStore::new(PasswordObject::static_type());
        passwords.extend_from_slice(&passwords_to_extend);

        Self::new(&title, passwords, store, user_config_dir)
    }
}

#[derive(Default, Clone)]
pub struct CollectionData {
    pub title: String,
    pub passwords_data: Vec<PasswordEntry>,
}
