use glob;

use std::process::Command;

fn main() {
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