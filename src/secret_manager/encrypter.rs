use magic_crypt::{new_magic_crypt, MagicCrypt256, MagicCryptError, MagicCryptTrait};

pub fn encrypt(value: impl Into<String>, key: &str) -> String {
    let mc = get_encrypter(key);

    let value = value.into();
    mc.encrypt_str_to_base64(value)
}

pub fn decrypt(
    value: impl Into<String>,
    key: impl Into<String>,
) -> Result<std::string::String, MagicCryptError> {
    let key = key.into();
    let mc = get_encrypter(&key);
    let value = value.into();
    mc.decrypt_base64_to_string(value)
}

fn get_encrypter(key: &str) -> MagicCrypt256 {
    new_magic_crypt!(key, 256)
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn should_encrypt_and_decrypt() {
        let val = "This is a test".to_string();
        let val_copy = val.to_owned();

        let key = "Test";

        let encrypted_val = encrypt(val, key);
        let encrypted_val_copy = encrypted_val.to_owned();

        println!("{} encrypted to {}", val_copy, encrypted_val);

        let decrypted_val = decrypt(encrypted_val, key).unwrap();

        println!("{} decrypted to {}", &encrypted_val_copy, val_copy);

        assert_eq!(val_copy, decrypted_val);
    }
}
