use crate::password_generator::password_generator;

#[test]
fn password_length_varies_correctly() {
    for len in [8, 12, 20] {
        let pass = password_generator(len, 0);
        assert_eq!(
            pass.len(),
            len,
            "Expected {} chars, got {}",
            len,
            pass.len()
        );
    }
}
