extern crate flate2;
extern crate tar;

use flate2::read::GzDecoder;
use std::fs::File;
use std::path::PathBuf;
use tar::Archive;

use ripasso::pass;

use criterion::{criterion_group, criterion_main, Criterion};

fn unpack_tar_gz(mut base_path: PathBuf, tar_gz_name: &str) -> Result<(), std::io::Error> {
    let target = format!("{}", base_path.as_path().display());
    base_path.push(tar_gz_name);

    let path = format!("{}", base_path.as_path().display());

    let tar_gz = File::open(path)?;
    let tar = GzDecoder::new(tar_gz);
    let mut archive = Archive::new(tar);
    archive.unpack(target)?;

    Ok(())
}

fn cleanup(mut base_path: PathBuf, path_name: &str) -> Result<(), std::io::Error> {
    base_path.push(path_name);

    std::fs::remove_dir_all(base_path)?;

    Ok(())
}

fn pop_list(password_dir: PathBuf) -> pass::Result<()> {
    let store =
        pass::PasswordStore::new(&Some(String::from(password_dir.to_str().unwrap())), &None)?;
    let results = store.all_passwords().unwrap();

    assert_eq!(results.len(), 4);
    Ok(())
}

fn criterion_benchmark_load_4_passwords(c: &mut Criterion) {
    let mut base_path: PathBuf = std::env::current_exe().unwrap();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.pop();
    base_path.push("testres");

    let mut password_dir: PathBuf = base_path.clone();
    password_dir.push("populate_password_list_large_repo");

    unpack_tar_gz(
        base_path.clone(),
        "populate_password_list_large_repo.tar.gz",
    )
    .unwrap();

    c.bench_function("populate_password_list 4 passwords", |b| {
        b.iter(|| pop_list(password_dir.clone()))
    });

    cleanup(base_path, "populate_password_list_large_repo").unwrap();
}

criterion_group!(benches, criterion_benchmark_load_4_passwords);
criterion_main!(benches);
