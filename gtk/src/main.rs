mod collection_object;
mod password_object;
mod utils;
mod window;

use adw::prelude::*;
use gtk::{gio, glib};
use window::Window;

static APP_ID: &str = "com.github.cortex.ripasso-gtk";

fn main() -> glib::ExitCode {
    // ripasso-gtk.gresource is produced in the build.rs file
    gio::resources_register_include!("ripasso-gtk.gresource")
        .expect("Failed to register resources.");

    // Create a new application
    let app = adw::Application::builder().application_id(APP_ID).build();

    // Connect to signals
    app.connect_startup(setup_shortcuts);
    app.connect_activate(build_ui);

    // Run the application
    app.run()
}

fn setup_shortcuts(app: &adw::Application) {
    app.set_accels_for_action("win.git-pull", &["<Ctrl>f"]);
    app.set_accels_for_action("win.git-push", &["<Ctrl>g"]);
    app.set_accels_for_action("win.pgp-download", &["<Ctrl>p"]);
}

fn build_ui(app: &adw::Application) {
    // Create a new custom window and show it
    let window = Window::new(app);
    window.show();
}
