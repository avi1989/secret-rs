use encrypter::{decrypt, encrypt};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
pub use secret_errors::{SecretAddError, SecretGetError};

mod encrypter;
mod secret_errors;

pub fn initialize() -> PathBuf {
    let secrets_dir = dirs::config_dir().unwrap().join("secret");
    fs::create_dir_all(&secrets_dir).unwrap();

    let secret_file_path = secrets_dir.join("secrets");

    if !secret_file_path.exists() {
        File::create(&secret_file_path).unwrap();
    }

    secret_file_path
}

pub fn get(
    secrets_file: &PathBuf,
    name: impl Into<String>,
    encryption_key: impl Into<String>,
) -> Result<String, SecretGetError> {
    let file = File::options().read(true).open(secrets_file).unwrap();
    let reader = BufReader::new(&file);
    let encryption_key = encryption_key.into();

    let name = name.into();

    for line in reader.lines() {
        let line = line.unwrap();
        let (key, value) = read_line(&line);

        if key != name {
            continue;
        }

        let result = decrypt(value, encryption_key);
        match result {
            Ok(result) => return Ok(result),
            Err(err) => {
                let error_message = format!("{}", err);
                return Err(SecretGetError::DecryptionFailed(error_message))
            }
        }
    }

    Err(SecretGetError::KeyNotFound)
}

pub fn add(
    secrets_file: &PathBuf,
    name: impl Into<String>,
    value: impl Into<String>,
    secret_key: &str,
) -> Result<(), SecretAddError> {
    let value = value.into();
    let name = name.into();

    let value = encrypt(value, secret_key);

    let mut file = File::options()
        .append(true)
        .read(true)
        .open(secrets_file)
        .unwrap();

    let reader = BufReader::new(&file);
    for line in reader.lines() {
        let line = line.unwrap();
        let (key, _) = read_line(&line);
        if key == name {
            return Err(SecretAddError::DuplicateKey(key.to_string()));
        }
    }

    match writeln!(file, "{{{}}}{}:{}", name.len(), name, value) {
        Err(e) => Err(SecretAddError::SecretWriteFailed(e.to_string())),
        // Err(e) => panic!("Failed to write {}", e),
        Ok(()) => Ok(())
    }
}

fn read_line(line: &str) -> (&str, &str) {
    let key_size = get_key_size(line);
    let mut key_start: usize = 0;

    if key_size < 10 {
        key_start = 3;
    } else if key_size < 100 {
        key_start = 4
    }
    let key_end = key_size + key_start;

    let key = &line[key_start..key_end];
    let val = &line[key_end + 1..];
    (key, val)
}

fn get_key_size(line: &str) -> usize {
    let mut line_chars = line.chars();
    let idx_end = line_chars.position(|c| c == '}').unwrap();

    let key_size = &line[1..idx_end];
    key_size.parse().unwrap()
}

#[cfg(test)]
mod tests {
    use crate::secret_manager;

    use super::*;

    macro_rules! read_line_test  {
        ($($name:ident: $value:expr,)*) => {
            $(
                #[test]
                fn $name() {
                    let (line, expected_key, expected_value) = $value;
                    let (key, value) = read_line(&line);
                    assert_eq!(key, expected_key);
                    assert_eq!(value, expected_value);
                }
            )*
        };
    }

    read_line_test! {
        simple_test: ("{4}test:This is a test".to_string(), "test", "This is a test"),
        longer_key: ("{10}This iskey:This is a test".to_string(), "This iskey", "This is a test"),
        key_with_colon: ("{6}Key:Ke:Value:Value".to_string(), "Key:Ke", "Value:Value"),
    }

    #[test]
    fn add_should_add_new_encrypted_text_to_file() {
        let file_path = dirs::cache_dir()
            .unwrap()
            .join("should_add_new_encrypted_text_to_file");
        let mut file = File::create(&file_path).unwrap();
        let _ = writeln!(file, "{}:{}", "{2}T1", "T2");
        let _ = writeln!(file, "{}:{}", "{4}Mega", "Password");
        let _ = writeln!(
            file,
            "{}:{}",
            "{11}BeetleJuice", "BeetleJuice BeetleJuice BeetleJuice"
        );
        let _ = writeln!(file, "{}:{}", "{2}T1", "T2");

        let _ = secret_manager::add(&file_path, "NewKey", "NewValue", "Default_Key");
        let last_line = get_last_line(&file_path);
        let _ = fs::remove_file(file_path);
        assert_eq!("{6}NewKey:VHvrPpJj4ymIhDsJtSZWSA==", last_line);
    }

    #[test]
    fn add_should_not_allow_duplicates_in_file() {
        let file_path = dirs::cache_dir()
            .unwrap()
            .join("should_not_allow_duplicates_in_file");
        let mut file = File::create(&file_path).unwrap();
        let _ = writeln!(file, "{}:{}", "{2}T1", "T2");
        let _ = writeln!(file, "{}:{}", "{4}Mega", "Password");
        let _ = writeln!(
            file,
            "{}:{}",
            "{11}BeetleJuice", "BeetleJuice BeetleJuice BeetleJuice"
        );
        let _ = writeln!(file, "{}:{}", "{2}T1", "T2");

        let _ = secret_manager::add(&file_path, "Mega", "NewValue", "Default_Key");
        let last_line = get_last_line(&file_path);
        let _ = fs::remove_file(file_path);
        assert_eq!("{2}T1:T2", last_line);
    }

    #[test]
    fn get_should_return_decrypted_text() {
        let file_path = dirs::cache_dir()
            .unwrap()
            .join("get_should_return_decrypted_text1");

        let default_key = "Default_Key";

        let mut file = File::create(&file_path).unwrap();
        let _ = writeln!(file, "{}:{}", "{4}Mega", "0h/oRBXYpzAbLRqyY3XfVQ==");
        let result = secret_manager::get(&file_path, "Mega", default_key);
        assert_eq!("Password", result.unwrap())
    }

    fn get_last_line(file_path: &PathBuf) -> String {
        let file = File::open(file_path).unwrap();
        let reader = BufReader::new(file);
        let mut last_line = String::from("");
        for line in reader.lines() {
            last_line = line.unwrap();
        }

        return last_line;
    }
}
