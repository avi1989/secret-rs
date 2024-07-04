use keyring::Entry;

const USER_ACCOUNT_NAME: &str = "com.avi1989.secret_manager";

pub fn store_encryption_key(value: String) {
    let entry = Entry::new("secret_encryption_key", USER_ACCOUNT_NAME);
    entry.unwrap().set_password(&value).unwrap();
}

pub fn retrieve_encryption_key() -> Option<String> {
    let entry = Entry::new("secret_encryption_key", USER_ACCOUNT_NAME).unwrap();
    match entry.get_password() {
        Ok(value) => Some(value),
        Err(_) => None,
    }
}
