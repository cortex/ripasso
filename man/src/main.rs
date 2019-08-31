extern crate man;

fn main() {
    let page = man::prelude::Manual::new("ripasso")
        .about("A password manager that uses the file format of the standard unix password manager 'pass', implemented in rust.")
        .author(man::prelude::Author::new("Joakim Lundborg").email("joakim.lundborg@gmail.com"))
        .author(man::prelude::Author::new("Alexander Kjäll").email("alexander.kjall@gmail.com"))
        .flag(man::prelude::Flag::new()
                .short("-h")
                .long("--help")
                .help("Print a help text"),
        )
        .custom(man::prelude::Section::new("usage note")
                .paragraph("Ripasso reads $HOME/.password-store/ by default, override this by setting
 the PASSWORD_STORE_DIR environmental variable.")
        )
        .render();

    println!("{}", page);
}
