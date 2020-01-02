extern crate cpp_build;
use std::process::Command;

fn qmake_query(var: &str) -> String {
    String::from_utf8(
        Command::new("qmake")
            .args(&["-query", var])
            .output()
            .expect("Failed to execute qmake. Make sure 'qmake' is in your path")
            .stdout,
    ).expect("UTF-8 conversion failed")
}

fn main() {
    let _qt_include_path = qmake_query("QT_INSTALL_HEADERS");
    let _qt_library_path = qmake_query("QT_INSTALL_LIBS");

    cpp_build::Config::new()
        .include(_qt_include_path.trim())
        .include(_qt_include_path.trim().to_owned() + "/QtQuick")
        .include(_qt_include_path.trim().to_owned() + "/QtGui")
        .build("src/main.rs");


    //cpp_build::build("src/main.rs");
}