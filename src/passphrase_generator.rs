use std::io;

use rand::prelude::IndexedRandom;

static WORDLIST: &str = include_str!("wordlists/eff_large.wordlist");

pub fn passphrase_generator(wordcount: i32) -> io::Result<Vec<String>> {
    let words: Vec<String> = WORDLIST
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .map(String::from)
        .collect();

    if words.is_empty() {
        eprintln!("The word list is empty!");
        return Ok(Vec::new());
    }

    let mut rng = rand::rng();

    let selected = if words.len() <= wordcount as usize {
        words.clone()
    } else {
        words
            .choose_multiple(&mut rng, wordcount as usize)
            .cloned()
            .collect()
    };

    Ok(selected)
}
