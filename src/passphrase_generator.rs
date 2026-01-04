use crate::error::Result;
use crate::pass::Error;
use rand::prelude::IndexedRandom;

static WORDLIST: &str = include_str!("wordlists/eff_large.wordlist");

/// Returns a pass phrase consisting of `word_count` number of
///words from the large wordlist from EFF.
///
/// # Errors
/// Fails if the loading of the wordlist fails.
pub fn passphrase_generator(word_count: usize) -> Result<Vec<String>> {
    let words: Vec<String> = WORDLIST
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(String::from)
        .collect();

    if words.is_empty() {
        return Err(Error::Generic("empty wordlist"));
    }

    let mut rng = rand::rng();

    let selected = if words.len() <= word_count {
        words.clone()
    } else {
        words
            .choose_multiple(&mut rng, word_count)
            .cloned()
            .collect()
    };

    Ok(selected)
}
