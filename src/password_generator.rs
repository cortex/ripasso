use rand::Rng;

#[non_exhaustive]
#[derive(Debug, Copy, Clone)]
pub enum PasswordGenerationCategory {
    AsciiOnly,
    AsciiExtended,
}

/// generates a password with the specified `length`.
///
/// # Panics
/// If the random function returns a value outside the
/// specified range, this can't happen.
#[must_use]
pub fn password_generator(length: usize, category: PasswordGenerationCategory) -> String {
    let mut rng = rand::rng();

    match category {
        PasswordGenerationCategory::AsciiOnly => (0..length)
            .map(|_| {
                let ascii_val = rng.random_range(33..=126);
                char::from(u8::try_from(ascii_val).expect("Invalid character"))
            })
            .collect(),
        PasswordGenerationCategory::AsciiExtended => (0..length)
            .map(|_| {
                let ascii_val = rng.random_range(33..=255);
                char::from(u8::try_from(ascii_val).expect("Invalid character"))
            })
            .collect(),
    }
}

#[cfg(test)]
#[path = "tests/password_generator.rs"]
mod password_generator_tests;
