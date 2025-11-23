use std::{
    fs::File,
    io::{self, BufRead},
};

use rand::seq::SliceRandom;

pub fn passphrase_generator(wordcount: i32) -> io::Result<Vec<String>> {
    let filename = "share/wordlists/eff_large.wordlist";
    let file = File::open(filename)?;
    let reader = io::BufReader::new(file);

    let words: Vec<String> = reader
        .lines()
        .map_while(Result::ok)
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect();

    if words.is_empty() {
        eprintln!("The word list is empty!");
        return Ok(Vec::new());
    }

    let mut rng = rand::thread_rng();

    let selected: Vec<String> = if (words.len() as i32) <= wordcount {
        words.clone()
    } else {
        words
            .choose_multiple(&mut rng, wordcount as usize)
            .cloned()
            .collect()
    };

    Ok(selected)
}
