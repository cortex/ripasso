mod imp;

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use adw::{prelude::*, subclass::prelude::*, ActionRow, NavigationDirection};
use glib::{clone, Object};
use gtk::{
    gio, glib, glib::BindingFlags, pango, AboutDialog, CustomFilter, Dialog, DialogFlags, Entry,
    FilterListModel, Label, ListBox, ListBoxRow, NoSelection, ResponseType, SelectionMode,
};
use hex::FromHex;
use ripasso::{crypto::CryptoImpl, pass::PasswordStore};

use crate::{collection_object::CollectionObject, password_object::PasswordObject};

glib::wrapper! {
    pub struct Window(ObjectSubclass<imp::Window>)
        @extends adw::ApplicationWindow, gtk::ApplicationWindow, gtk::Window, gtk::Widget,
        @implements gio::ActionGroup, gio::ActionMap, gtk::Accessible, gtk::Buildable,
                    gtk::ConstraintTarget, gtk::Native, gtk::Root, gtk::ShortcutManager;
}

impl Window {
    pub fn new(app: &adw::Application) -> Self {
        // Create new window
        Object::builder().property("application", app).build()
    }

    fn passwords(&self) -> gio::ListStore {
        self.current_collection().passwords()
    }

    fn current_collection(&self) -> CollectionObject {
        self.imp()
            .current_collection
            .borrow()
            .clone()
            .expect("`current_collection` should be set in `set_current_collections`.")
    }

    fn collections(&self) -> gio::ListStore {
        self.imp()
            .collections
            .get()
            .expect("`collections` should be set in `setup_collections`.")
            .clone()
    }

    fn set_filter(&self) {
        self.imp()
            .current_filter_model
            .borrow()
            .clone()
            .expect("`current_filter_model` should be set in `set_current_collection`.")
            .set_filter(Some(&self.filter()));
    }

    fn filter(&self) -> CustomFilter {
        CustomFilter::new(clone!(
            #[weak(rename_to = window)]
            self,
            #[upgrade_or_panic]
            move |obj| {
                let text = window.imp().entry.text();

                // Get `PasswordObject` from `glib::Object`
                let password_object = obj
                    .downcast_ref::<PasswordObject>()
                    .expect("The object needs to be of type `PasswordObject`.");

                password_object
                    .property::<String>("name")
                    .contains(&text.to_string())
            }
        ))
    }

    fn setup_collections(&self) {
        let collections = gio::ListStore::new::<CollectionObject>();
        self.imp()
            .collections
            .set(collections.clone())
            .expect("Could not set collections");

        self.imp().collections_list.bind_model(
            Some(&collections),
            clone!(
                #[weak(rename_to = window)]
                self,
                #[upgrade_or_panic]
                move |obj| {
                    let collection_object = obj
                        .downcast_ref()
                        .expect("The object should be of type `CollectionObject`.");
                    let row = window.create_collection_row(collection_object);
                    row.upcast()
                }
            ),
        )
    }

    fn restore_data(&self, home_dir: Option<PathBuf>, user_config_dir: Option<PathBuf>) {
        let (config, home) = ripasso::pass::read_config(&None, &None, &home_dir, &user_config_dir)
            .expect("No config file present");

        let stores = get_stores(&config, &Some(home)).expect("Problem constructing stores");
        // Convert `Vec<CollectionData>` to `Vec<CollectionObject>`
        let collections: Vec<CollectionObject> = stores
            .into_iter()
            .map(|s| CollectionObject::from_store_data(s, &user_config_dir.clone().unwrap()))
            .collect();

        // Insert restored objects into model
        self.collections().extend_from_slice(&collections);

        // Set first collection as current
        if let Some(first_collection) = collections.first() {
            self.set_current_collection(first_collection.clone());
        }
    }

    fn create_collection_row(&self, collection_object: &CollectionObject) -> ListBoxRow {
        let label = Label::builder()
            .ellipsize(pango::EllipsizeMode::End)
            .xalign(0.0)
            .build();

        collection_object
            .bind_property("title", &label, "label")
            .flags(BindingFlags::SYNC_CREATE)
            .build();

        ListBoxRow::builder().child(&label).build()
    }

    fn set_current_collection(&self, collection: CollectionObject) {
        // Wrap model with filter and selection and pass it to the list box
        let passwords = collection.passwords();
        let filter_model = FilterListModel::new(Some(passwords.clone()), Some(self.filter()));
        let selection_model = NoSelection::new(Some(filter_model.clone()));
        self.imp().passwords_list.bind_model(
            Some(&selection_model),
            clone!(
                #[weak(rename_to = window)]
                self,
                #[upgrade_or_panic]
                move |obj| {
                    let password_object = obj
                        .downcast_ref()
                        .expect("The object should be of type `PasswordObject`.");
                    let row = window.create_password_row(password_object);
                    row.upcast()
                }
            ),
        );

        // Store filter model
        self.imp().current_filter_model.replace(Some(filter_model));

        // If present, disconnect old `passwords_changed` handler
        if let Some(handler_id) = self.imp().passwords_changed_handler_id.take() {
            self.passwords().disconnect(handler_id);
        }

        // Assure that the task list is only visible when it is supposed to
        self.set_task_list_visible(&passwords);
        let passwords_changed_handler_id = passwords.connect_items_changed(clone!(
            #[weak(rename_to = window)]
            self,
            #[upgrade_or_panic]
            move |passwords, _, _, _| {
                window.set_task_list_visible(passwords);
            }
        ));
        self.imp()
            .passwords_changed_handler_id
            .replace(Some(passwords_changed_handler_id));

        // Set current passwords
        self.imp().current_collection.replace(Some(collection));

        self.select_collection_row();
    }

    fn set_task_list_visible(&self, passwords: &gio::ListStore) {
        self.imp()
            .passwords_list
            .set_visible(passwords.n_items() > 0);
    }

    fn select_collection_row(&self) {
        if let Some(index) = self.collections().find(&self.current_collection()) {
            let row = self.imp().collections_list.row_at_index(index as i32);
            self.imp().collections_list.select_row(row.as_ref());
        }
    }

    fn create_password_row(&self, password_object: &PasswordObject) -> ActionRow {
        let list_box = ListBox::builder()
            .can_focus(false)
            .can_target(false)
            .css_classes(["card"])
            .build();

        // Create the name of committer
        let label_committed_by = Label::builder()
            .label("")
            .lines(1)
            .can_focus(false)
            .can_target(false)
            .build();

        // Create the commit time section
        let label_updated = Label::builder()
            .label("")
            .lines(1)
            .can_focus(false)
            .can_target(false)
            .build();

        list_box.insert(&label_committed_by, 0);
        list_box.insert(&label_updated, 0);

        // Create row
        let row = ActionRow::builder()
            .can_focus(true)
            .activatable(true)
            .build();
        row.add_suffix(&list_box);

        // Bind properties
        password_object
            .bind_property("committed-by", &label_committed_by, "label")
            .flags(BindingFlags::SYNC_CREATE)
            .build();
        password_object
            .bind_property("updated", &label_updated, "label")
            .flags(BindingFlags::SYNC_CREATE)
            .build();
        password_object
            .bind_property("name", &row, "title")
            .flags(BindingFlags::SYNC_CREATE)
            .build();

        // Return row
        row
    }

    fn setup_callbacks(&self) {
        self.imp().entry.connect_changed(clone!(
            #[weak(rename_to = window)]
            self,
            #[upgrade_or_panic]
            move |_| {
                window.set_filter();
            }
        ));

        // Setup callback when items of collections change
        self.set_stack();
        self.collections().connect_items_changed(clone!(
            #[weak(rename_to = window)]
            self,
            #[upgrade_or_panic]
            move |_, _, _, _| {
                window.set_stack();
            }
        ));

        // Setup callback for activating a row of collections list
        self.imp().collections_list.connect_row_activated(clone!(
            #[weak(rename_to = window)]
            self,
            #[upgrade_or_panic]
            move |_, row| {
                let index = row.index();
                let selected_collection = window
                    .collections()
                    .item(index as u32)
                    .expect("There needs to be an object at this position.")
                    .downcast::<CollectionObject>()
                    .expect("The object needs to be a `CollectionObject`.");
                window.set_current_collection(selected_collection);
                window.imp().leaflet.navigate(NavigationDirection::Forward);
            }
        ));

        // Setup callback for activating a row in the password list
        self.imp().passwords_list.connect_row_activated(clone!(
            #[weak(rename_to = window)]
            self,
            #[upgrade_or_panic]
            move |_, row| {
                let index = row.index();

                let password = window
                    .current_collection()
                    .passwords()
                    .item(index as u32)
                    .expect("There needs to be an object at this position.")
                    .downcast::<PasswordObject>()
                    .expect("The object needs to be a `PasswordObject`.");

                let display = gtk::gdk::Display::default().unwrap();
                let clipboard = display.clipboard();
                clipboard.set_text(&password.property::<String>("secret"));
            }
        ));

        // Setup callback for folding the leaflet
        self.imp().leaflet.connect_folded_notify(clone!(
            #[weak(rename_to = window)]
            self,
            #[upgrade_or_panic]
            move |leaflet| {
                if leaflet.is_folded() {
                    window
                        .imp()
                        .collections_list
                        .set_selection_mode(SelectionMode::None)
                } else {
                    window
                        .imp()
                        .collections_list
                        .set_selection_mode(SelectionMode::Single);
                    window.select_collection_row();
                }
            }
        ));

        self.imp().back_button.connect_clicked(clone!(
            #[weak(rename_to = window)]
            self,
            #[upgrade_or_panic]
            move |_| {
                window.imp().leaflet.navigate(NavigationDirection::Back);
            }
        ));
    }

    fn set_stack(&self) {
        if self.collections().n_items() > 0 {
            self.imp().stack.set_visible_child_name("main");
        } else {
            self.imp().stack.set_visible_child_name("placeholder");
        }
    }

    fn setup_actions(&self) {
        // Create action to do a git pull for the current repository
        let action_git_pull = gio::SimpleAction::new("git-pull", None);
        action_git_pull.connect_activate(clone!(
            #[weak(rename_to = window)]
            self,
            #[upgrade_or_panic]
            move |_, _| {
                window.current_collection().git_pull(&window);
            }
        ));
        self.add_action(&action_git_pull);

        // Create action to do a git push for the current repository
        let action_git_push = gio::SimpleAction::new("git-push", None);
        action_git_push.connect_activate(clone!(
            #[weak(rename_to = window)]
            self,
            #[upgrade_or_panic]
            move |_, _| {
                window.current_collection().git_push(&window);
            }
        ));
        self.add_action(&action_git_push);

        // Create action to download pgp certificates for the current repository
        let action_pgp_download = gio::SimpleAction::new("pgp-download", None);
        action_pgp_download.connect_activate(clone!(
            #[weak(rename_to = window)]
            self,
            #[upgrade_or_panic]
            move |_, _| {
                window.current_collection().pgp_download(&window);
            }
        ));
        self.add_action(&action_pgp_download);

        // Create action to download pgp certificates for the current repository
        let action_about = gio::SimpleAction::new("about", None);
        action_about.connect_activate(clone!(
            #[weak(rename_to = window)]
            self,
            #[upgrade_or_panic]
            move |_, _| {
                window.about_dialog();
            }
        ));
        self.add_action(&action_about);

        // Create action to create new collection and add to action group "win"
        let action_new_list = gio::SimpleAction::new("new-collection", None);
        action_new_list.connect_activate(clone!(
            #[weak(rename_to = window)]
            self,
            #[upgrade_or_panic]
            move |_, _| {
                window.new_collection();
            }
        ));
        self.add_action(&action_new_list);
    }

    fn about_dialog(&self) {
        let about_dialog = AboutDialog::builder()
            .authors(["Alexander Kjäll"])
            .license("GPL-3")
            .comments("A password manager that implements the pass store disk format")
            .logo(
                &gtk::Image::from_file("/usr/share/ripasso-gtk/logo.svg")
                    .paintable()
                    .expect("logo must be paintable"),
            )
            .build();

        about_dialog.present();
    }

    fn new_collection(&self) {
        // Create new Dialog
        let dialog = Dialog::with_buttons(
            Some("New Collection"),
            Some(self),
            DialogFlags::MODAL | DialogFlags::DESTROY_WITH_PARENT | DialogFlags::USE_HEADER_BAR,
            &[
                ("Cancel", ResponseType::Cancel),
                ("Create", ResponseType::Accept),
            ],
        );
        dialog.set_default_response(ResponseType::Accept);

        // Make the dialog button insensitive initially
        let dialog_button = dialog
            .widget_for_response(ResponseType::Accept)
            .expect("The dialog needs to have a widget for response type `Accept`.");
        dialog_button.set_sensitive(false);

        // Create entry and add it to the dialog
        let entry = Entry::builder()
            .margin_top(12)
            .margin_bottom(12)
            .margin_start(12)
            .margin_end(12)
            .placeholder_text("Name")
            .activates_default(true)
            .build();
        dialog.content_area().append(&entry);

        // Set entry's css class to "error", when there is no text in it
        entry.connect_changed(clone!(
            #[weak(rename_to = _window)]
            self,
            #[weak]
            dialog,
            #[upgrade_or_panic]
            move |entry| {
                let text = entry.text();
                let dialog_button = dialog
                    .widget_for_response(ResponseType::Accept)
                    .expect("The dialog needs to have a widget for response type `Accept`.");
                let empty = text.is_empty();

                dialog_button.set_sensitive(!empty);

                if empty {
                    entry.add_css_class("error");
                } else {
                    entry.remove_css_class("error");
                }
            }
        ));

        // Connect response to dialog
        dialog.connect_response(clone!(
            #[weak(rename_to = window)]
            self,
            #[weak]
            entry,
            #[weak]
            dialog,
            #[upgrade_or_panic]
            move |_, response| {
                // Destroy dialog
                dialog.destroy();

                // Return if the user chose a response different from `Accept`
                if response != ResponseType::Accept {
                    return;
                }

                // Create a new list store
                let passwords = gio::ListStore::new::<PasswordObject>();

                // Create a new collection object from the title the user provided
                let title = entry.text().to_string();
                let collection = CollectionObject::new(
                    &title,
                    passwords,
                    Arc::new(Mutex::new(
                        PasswordStore::new(
                            "default",
                            &None,
                            &None,
                            &None,
                            &None,
                            &CryptoImpl::GpgMe,
                            &None,
                        )
                        .expect("Created store"),
                    )),
                    &window.imp().user_config_dir.borrow(),
                );

                // Add new collection object and set current passwords
                window.collections().append(&collection);
                window.set_current_collection(collection);

                // Let the leaflet navigate to the next child
                window.imp().leaflet.navigate(NavigationDirection::Forward);
            }
        ));
        dialog.present();
    }
}

fn get_stores(
    config: &config::Config,
    home: &Option<PathBuf>,
) -> Result<Vec<PasswordStore>, ripasso::pass::Error> {
    let mut final_stores: Vec<PasswordStore> = vec![];
    let stores_res = config.get("stores");
    if let Ok(stores) = stores_res {
        let stores: HashMap<String, config::Value> = stores;

        for store_name in stores.keys() {
            let store: HashMap<String, config::Value> =
                stores.get(store_name).unwrap().clone().into_table()?;

            let password_store_dir_opt = store.get("path");
            let valid_signing_keys_opt = store.get("valid_signing_keys");

            if let Some(store_dir) = password_store_dir_opt {
                let password_store_dir = Some(PathBuf::from(store_dir.clone().into_string()?));

                let valid_signing_keys = match valid_signing_keys_opt {
                    Some(k) => match k.clone().into_string() {
                        Err(_) => None,
                        Ok(key) => {
                            if key == "-1" {
                                None
                            } else {
                                Some(key)
                            }
                        }
                    },
                    None => None,
                };
                let style_path_opt = match store.get("style_path") {
                    Some(path) => match path.clone().into_string() {
                        Ok(p) => Some(PathBuf::from(p)),
                        Err(_err) => None,
                    },
                    None => None,
                };

                let pgp_impl = match store.get("pgp") {
                    Some(pgp_str) => CryptoImpl::try_from(pgp_str.clone().into_string()?.as_str()),
                    None => Ok(CryptoImpl::GpgMe),
                }?;

                let own_fingerprint = store.get("own_fingerprint");
                let own_fingerprint = match own_fingerprint {
                    None => None,
                    Some(k) => match k.clone().into_string() {
                        Err(_) => None,
                        Ok(key) => match <[u8; 20]>::from_hex(key) {
                            Err(_) => None,
                            Ok(fp) => Some(fp),
                        },
                    },
                };

                final_stores.push(PasswordStore::new(
                    store_name,
                    &password_store_dir,
                    &valid_signing_keys,
                    home,
                    &style_path_opt,
                    &pgp_impl,
                    &own_fingerprint,
                )?);
            }
        }
    } else if final_stores.is_empty() && home.is_some() {
        let default_path = home.clone().unwrap().join(".password_store");
        if default_path.exists() {
            final_stores.push(PasswordStore::new(
                "default",
                &Some(default_path),
                &None,
                home,
                &None,
                &CryptoImpl::GpgMe,
                &None,
            )?);
        }
    }

    Ok(final_stores)
}
