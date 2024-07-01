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

pub enum SecretDeleteError {
    KeyNotFound,
    WriteFailed(String),
}