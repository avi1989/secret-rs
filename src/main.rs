mod secret_manager;
use clap::{Parser, Subcommand};
use secret_manager::{SecretDeleteError, SecretGetError, SecretSetError};

#[derive(Debug, Parser)]
#[command(name = "secret")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Delete {
        /// The case insensitive name the secret to get
        name: String,
    },
    Get {
        /// The case insensitive name the secret to get
        name: String,
    },
    Set {
        name: String,
        value: String,
    },
    Path {},
}

fn main() {
    let (secret_file_path, secret_key) = secret_manager::initialize();

    let args = Cli::parse();

    match args.command {
        Commands::Get { name } => {
            let value = secret_manager::get(&secret_file_path, name, secret_key);
            match value {
                Ok(value) => println!("{}", value),
                Err(SecretGetError::DecryptionFailed(error)) => {
                    eprintln!("Unable to decrypt value, {}", error)
                }
                _ => eprintln!("Not found"),
            }
        }
        Commands::Set { name, value } => {
            let result = secret_manager::set(&secret_file_path, name, value, secret_key);
            match result {
                Ok(()) => println!("Updated"),
                Err(SecretSetError::SecretWriteFailed(err)) => {
                    eprintln!("Unable to write file {}", err)
                }
            }
        }
        Commands::Delete { name } => {
            let result = secret_manager::delete(&secret_file_path, &name);
            match result {
                Ok(()) => println!("Deleted"),
                Err(SecretDeleteError::SecretWriteFailed(err)) => {
                    eprintln!("Unable to write file {}", err)
                }
                Err(SecretDeleteError::KeyNotFound) => {
                    eprintln!("Key {} not found", name)
                }
            }
        }
        Commands::Path {} => {
            println!("{:?}", secret_file_path);
        }
    }
}
