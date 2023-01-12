//! This implements a handling of a pass directory compatible with <https://www.passwordstore.org/> .
//! The encryption is handled by `GPGme` or `sequoia` and the git integration is with libgit2.

/// This is the library part that handles all encryption and decryption
pub mod crypto;
/// All functions and structs related to error handling
pub(crate) mod error;
/// All git related operations.
pub mod git;
/// This is the library part of ripasso, it implements the functions needed to manipulate a pass
/// directory.
pub mod pass;
/// All functions and structs related to handling the identity and signing of things
pub(crate) mod signature;
/// This is the library that handles password generation, based on the long word list from EFF
/// <https://www.eff.org/sv/deeplinks/2016/07/new-wordlists-random-passphrases>
pub mod words;

#[cfg(test)]
#[path = "tests/test_helpers.rs"]
pub mod test_helpers;
