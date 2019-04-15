extern crate ripasso;
use ripasso::pass;

#[cfg(test)]
mod tests {
    use super::*;

    fn detect_dir(){
    	// Should find directory 
    	// Should respect env var
    	// Should give error 
    }

    #[test]
    fn test_save() {
        // Saving should work
        pass::save("secret".to_string(), "test".to_string()).unwrap()
    }
}
