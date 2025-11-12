use rand::Rng;

pub fn password_generator(length: usize, category: usize) -> String {
    let mut rng = rand::thread_rng();

    if category == 0 {
        (0..length)
            .map(|_| {
                let ascii_val = rng.gen_range(33..=126);
                ascii_val as u8 as char
            })
            .collect()
    } else {
        (0..length)
            .map(|_| {
                let ascii_val = rng.gen_range(33..=255);
                ascii_val as u8 as char
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "tests/password_generator.rs"]
mod password_generator;
