use std::{cell::RefCell, path::PathBuf};

use adw::{Leaflet, subclass::prelude::*};
use glib::{Propagation, subclass::InitializingObject};
use gtk::{
    Button, CompositeTemplate, Entry, FilterListModel, ListBox, Stack, gio, glib,
    glib::SignalHandlerId,
};
use once_cell::sync::OnceCell;

use crate::collection_object::CollectionObject;

// Object holding the state
#[derive(CompositeTemplate, Default)]
#[template(resource = "/com/github/cortex/ripasso-gtk/window.ui")]
pub struct Window {
    #[template_child]
    pub entry: TemplateChild<Entry>,
    #[template_child]
    pub passwords_list: TemplateChild<ListBox>,
    // 👇 all members below are new
    #[template_child]
    pub collections_list: TemplateChild<ListBox>,
    #[template_child]
    pub leaflet: TemplateChild<Leaflet>,
    #[template_child]
    pub stack: TemplateChild<Stack>,
    #[template_child]
    pub back_button: TemplateChild<Button>,
    pub collections: OnceCell<gio::ListStore>,
    pub current_collection: RefCell<Option<CollectionObject>>,
    pub current_filter_model: RefCell<Option<FilterListModel>>,
    pub passwords_changed_handler_id: RefCell<Option<SignalHandlerId>>,
    pub user_config_dir: RefCell<PathBuf>,
}

// The central trait for subclassing a GObject
#[glib::object_subclass]
impl ObjectSubclass for Window {
    // `NAME` needs to match `class` attribute of template
    const NAME: &'static str = "RipassoWindow";
    type Type = super::Window;
    type ParentType = adw::ApplicationWindow;

    fn class_init(klass: &mut Self::Class) {
        klass.bind_template();
    }

    fn instance_init(obj: &InitializingObject<Self>) {
        obj.init_template();
    }
}

// Trait shared by all GObjects
impl ObjectImpl for Window {
    fn constructed(&self) {
        // Call "constructed" on parent
        self.parent_constructed();

        let home_dir = match std::env::var("HOME") {
            Err(_) => None,
            Ok(home_path) => Some(PathBuf::from(home_path)),
        };

        let user_config_dir = match std::env::var("XDG_CONFIG_HOME") {
            Err(_) => match &home_dir {
                None => None,
                Some(home_path) => {
                    let home_path = home_path.join(".config");
                    Some(home_path)
                }
            },
            Ok(config_home_path) => Some(PathBuf::from(config_home_path)),
        };

        // Setup
        let obj = self.obj();
        obj.setup_collections();
        obj.restore_data(home_dir, user_config_dir);
        obj.setup_callbacks();
        obj.setup_actions();
    }
}

// Trait shared by all widgets
impl WidgetImpl for Window {}

// Trait shared by all windows
impl WindowImpl for Window {
    fn close_request(&self) -> Propagation {
        // Pass close request on to the parent
        self.parent_close_request()
    }
}

// Trait shared by all application windows
impl ApplicationWindowImpl for Window {}

// Trait shared by all adwaita application windows
impl AdwApplicationWindowImpl for Window {}
