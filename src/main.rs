mod secret_manager;
use clap::{Parser, Subcommand};
use secret_manager::{SecretAddError, SecretGetError};

#[derive(Debug, Parser)]
#[command(name = "secret")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Get {
        /// The case insensitive name the secret to get
        name: String,
    },
    Add {
        name: String,
        value: String,
    },
    Path {
        
    }
}

fn main() {
    let secret_file_path = secret_manager::initialize();
    let secret_key = "This is a test";

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
        Commands::Add { name, value } => {
            let result = secret_manager::add(&secret_file_path, name, value, secret_key);
            match result {
                Ok(()) => println!("Added"),
                Err(SecretAddError::DuplicateKey(key)) => eprintln!("{} already exists", key),
                Err(SecretAddError::SecretWriteFailed(err)) => {
                    eprintln!("Unable to write to file due to {:?}", err)
                }
                _ => eprintln!("Key add failed"),
            }
        },
        Commands::Path { } => {
            println!("{:?}", secret_file_path);
        }
    }
}
