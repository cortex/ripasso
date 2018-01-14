extern crate ripasso;

#[cfg(feature = "use-gtk")]
fn start_gtk() {
    use ripasso::gtkui;
    gtkui::main()
}

#[cfg(not(feature = "use-gtk"))]
fn start_gtk() {
    print!("GTK UI not enabled, compile with --features=use-gtk to enable")
}

#[cfg(feature = "use-qml")]
fn start_qml() {
    use ripasso::qmlui;
    qmlui::main()
}

#[cfg(not(feature = "use-qml"))]
fn start_qml() {
    print!("QML UI not enabled, compile with --features=use-gtk to enable")
}

#[cfg(feature = "use-tui")]
fn start_tui() {
    use ripasso::tui;
    tui::main()
}

#[cfg(not(feature = "use-tui"))]
fn start_tui() {
    print!("Text UI not enabled, compile with --features=use-tui to enable")
}

fn main() {
    println!("Welcome to ripasso");
    if cfg!(feature = "use-qml") {
        return start_qml();
    }
    if cfg!(feature = "use-gtk") {
        return start_gtk();
    }
    if cfg!(feature = "use-tui") {
        return start_tui();
    }
    println!("No UI compiled, compile with --features=use-gtk or --features=use-qml to enable")
}
