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
        .description("The ripasso password manager is an ncurses application that lets you manage your or your teams passwords.\
The passwords are encrypted with gpg and optionally stored in an gpg repository. The list of encryption recipients are stored \
in the file .gpg-id, one gpg key id per line.")

        .custom(man::prelude::Section::new("Keyboard shortcuts")
                    .paragraph("Enter : Copy the current selected password to the copy buffer for 40 seconds")
                    .paragraph("Delete : Delete the marked password")
                    .paragraph("Insert : Create a new password entry")
                    .paragraph("Control + y : same as Enter")
                    .paragraph("Control + n : move marker down")
                    .paragraph("Control + p : move marker up")
                    .paragraph("Control + v : view the list of encryption recipients")
                    .paragraph("Control + o : open en password edit dialog")
                    .paragraph("Control + f : pull from the git repository")
                    .paragraph("Control + g : push to the git repository")
                    .paragraph("Escape : quit "))
        .custom(man::prelude::Section::new("usage note")
                .paragraph("Ripasso reads $HOME/.password-store/ by default, override this by setting
the PASSWORD_STORE_DIR environmental variable.")
        )
        .render();

    println!("{}", page);
}
