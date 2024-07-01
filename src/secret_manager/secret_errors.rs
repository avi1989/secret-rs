#[derive(Debug)]
pub enum SecretAddError{
    DuplicateKey(String),
    SecretWriteFailed(String),
}

#[derive(Debug)]
pub enum SecretGetError {
    KeyNotFound,
    DecryptionFailed(String),
}