#[derive(Debug)]
pub enum SecretAddError {
    DuplicateKey(),
    SecretWriteFailed(String),
}

#[derive(Debug)]
pub enum SecretGetError {
    KeyNotFound,
    DecryptionFailed(String),
}

pub enum SecretDeleteError {
    KeyNotFound,
    SecretWriteFailed(String),
}

pub enum SecretSetError {
    SecretWriteFailed(String),
}
