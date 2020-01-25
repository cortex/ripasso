use glob;

use std::process::Command;
use std::io::prelude::*;

fn generate_man_page() -> String {
    let page = man::prelude::Manual::new("ripasso-cursive")
        .about("A password manager that uses the file format of the standard unix password manager 'pass', implemented in rust.")
        .author(man::prelude::Author::new("Joakim Lundborg").email("joakim.lundborg@gmail.com"))
        .author(man::prelude::Author::new("Alexander Kjäll").email("alexander.kjall@gmail.com"))
        .flag(man::prelude::Flag::new()
                  .short("-h")
                  .long("--help")
                  .help("Print a help text"),
        )
        .description("ripasso-cursive is an ncurses application that lets you manage your or your teams passwords.\
The passwords are encrypted with gpg and optionally stored in an gpg repository. The list of team members are stored \
in the file .gpg-id, one gpg key id per line.")

        .custom(man::prelude::Section::new("Keyboard shortcuts")
            .paragraph("Enter : Copy the current selected password to the copy buffer for 40 seconds")
            .paragraph("Delete : Delete the marked password")
            .paragraph("Insert : Create a new password entry")
            .paragraph("Control + y : same as Enter")
            .paragraph("Control + n : move marker down")
            .paragraph("Control + p : move marker up")
            .paragraph("Control + v : view the list of team members")
            .paragraph("Control + o : open en password edit dialog")
            .paragraph("Control + f : pull from the git repository")
            .paragraph("Control + g : push to the git repository")
            .paragraph("Escape : quit "))
        .custom(man::prelude::Section::new("usage note")
            .paragraph("ripasso-cursive reads $HOME/.password-store/ by default, override this by setting
the PASSWORD_STORE_DIR environmental variable.")
            .paragraph("If you specify the PASSWORD_STORE_SIGNING_KEY environmental variable, then
ripasso will verify that the .gpg-id file is correctly signed. Valid values are one or more 40 character gpg key ids,
separated by commas.")
        )
        .render();

    return format!("{}", page);
}

fn generate_man_page_file() {
    let mut dest_path = std::env::current_exe().unwrap();
    dest_path.pop();
    dest_path.pop();
    dest_path.pop();
    dest_path.pop();
    dest_path.push("man-page");
    print!("creating directory: {:?} ", &dest_path);
    let res = std::fs::create_dir(&dest_path);
    if res.is_ok() {
        println!("success");
    } else {
        println!("error: {:?}", res.err().unwrap());
    }
    dest_path.push("cursive");
    print!("creating directory: {:?} ", &dest_path);
    let res = std::fs::create_dir(&dest_path);
    if res.is_ok() {
        println!("success");
    } else {
        println!("error: {:?}", res.err().unwrap());
    }

    dest_path.push("ripasso-cursive.1");

    let mut file = std::fs::File::create(dest_path).unwrap();
    file.write_all(generate_man_page().as_bytes()).unwrap();
}

fn generate_translation_files() {
    let mut dest_path = std::env::current_exe().unwrap();
    dest_path.pop();
    dest_path.pop();
    dest_path.pop();
    dest_path.pop();
    dest_path.push("translations");
    print!("creating directory: {:?} ", &dest_path);
    let res = std::fs::create_dir(&dest_path);
    if res.is_ok() {
        println!("success");
    } else {
        println!("error: {:?}", res.err().unwrap());
    }
    dest_path.push("cursive");
    print!("creating directory: {:?} ", &dest_path);
    let res = std::fs::create_dir(&dest_path);
    if res.is_ok() {
        println!("success");
    } else {
        println!("error: {:?}", res.err().unwrap());
    }

    let mut dir = std::env::current_exe().unwrap();
    dir.pop();
    dir.pop();
    dir.pop();
    dir.pop();
    dir.pop();
    dir.push("cursive");
    dir.push("res");

    let password_path_glob = dir.join("**/*.po");
    let existing_iter = glob::glob(&password_path_glob.to_string_lossy()).unwrap();

    for existing_file in existing_iter {
        let file = existing_file.unwrap();
        let mut filename = format!("{}", file.file_name().unwrap().to_str().unwrap());
        filename.replace_range(3..4, "m");

        print!("generating .mo file for {:?} to {}/{} ", &file, dest_path.display(), &filename);
        let res = Command::new("msgfmt")
            .arg(format!("--output-file={}/{}", dest_path.display(), &filename))
            .arg(format!("{}", &file.display()))
            .output();

        if res.is_ok() {
            println!("success");
        } else {
            println!("error: {:?}", res.err().unwrap());
        }

    }
}

fn main() {
    generate_translation_files();
    generate_man_page_file();
}