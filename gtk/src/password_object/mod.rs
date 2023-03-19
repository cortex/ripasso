mod imp;

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use adw::subclass::prelude::*;
use chrono::{DateTime, Local};
use glib::Object;
use gtk::glib;
use ripasso::pass::{PasswordEntry, PasswordStore, Error};

use crate::utils::PasswordStoreBoxed;
use crate::utils::error_dialog_standalone;

glib::wrapper! {
    pub struct PasswordObject(ObjectSubclass<imp::PasswordObject>);
}

impl PasswordObject {
    pub fn new(
        name: String,
        path: PathBuf,
        updated: DateTime<Local>,
        committed_by: String,
        store: Arc<Mutex<PasswordStore>>,
    ) -> Self {
        let po: Self = Object::builder()
            .property("name", name)
            .property("path", path.to_string_lossy().to_string())
            .property("updated", updated.to_rfc3339())
            .property("committed-by", committed_by)
            .property("store", PasswordStoreBoxed(store))
            .build();

        po
    }

    pub fn password_entry(&self) -> PasswordEntry {
        self.imp().data.borrow().clone()
    }

    pub fn from_password_entry(p_e: PasswordEntry, store: Arc<Mutex<PasswordStore>>) -> Self {
        let file_date: DateTime<Local> = match p_e.updated {
            Some(d) => d,
            None => {
                match std::fs::metadata(&p_e.path) {
                    Ok(md) => {
                        match md.modified() {
                            Ok(st) => {
                                st.into()
                            },
                            Err(e) => {
                                error_dialog_standalone(&Error::Io(e));
                                DateTime::<Local>::default()
                            }
                        }
                    },
                    Err(e) => {
                        error_dialog_standalone(&Error::Io(e));
                        DateTime::<Local>::default()
                    }
                }
            }
        };

        let commit_name = match p_e.committed_by {
            Some(n) => n,
            None => {
                "".into()
            }
        };

        Self::new(
            p_e.name,
            p_e.path,
            file_date,
            commit_name,
            store,
        )
    }
}
