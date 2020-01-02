extern crate qmetaobject;
use qmetaobject::*;
use ripasso::pass;
use std::sync::{Arc, Mutex};
#[macro_use] extern crate cstr;

#[derive(QObject,Default)]
struct PasswordStore {
    base : qt_base_class!(trait QObject),
    name : qt_property!(QString; NOTIFY name_changed),
    name_changed : qt_signal!(),
    query : qt_method!(fn query(&self, verb : String) -> QString {
        return (verb + " " + &self.name.to_string()).into()
    })
}
fn main() {
    qml_register_type::<PasswordStore>(cstr!("PasswordStore"), 1, 0, cstr!("PasswordStore"));


    let password_store_dir = Arc::new(match std::env::var("PASSWORD_STORE_DIR") {
        Ok(p) => Some(p),
        Err(_) => None
    });

    let repo_opt = Arc::new(Some(Mutex::new(git2::Repository::open(pass::password_dir(password_store_dir.clone()).unwrap()).unwrap())));


    let mut engine = QmlEngine::new();

    engine.load_file(r#"res/main.qml"#.into());
    engine.exec();

}