mod crypto;
mod file_handler;
mod message;

use inquire::{Password, PasswordDisplayMode};
use std::{env, path::Path};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} (enc/dec) [path/text]", args[0]);
        return;
    }

    let salt = match crypto::handle_salt_file() {
        Ok(salt) => salt,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    let mode = &args[1];
    let candidate = &args[2];

    if !matches!(mode.as_str(), "enc" | "encrypt" | "dec" | "decrypt") {
        eprint!("Error in your arguments");
        return;
    }

    let pwd = Password::new("Enter the password:")
        .with_display_mode(PasswordDisplayMode::Masked)
        .prompt()
        .unwrap();

    let path = Path::new(candidate);
    let key = crypto::hash_string(&pwd.trim().to_string(), &salt);

    if !path.exists() {
        if matches!(mode.as_str(), "enc" | "encrypt") {
            let ciphertext = message::encrypt_message(candidate, &key);
            println!("Encrypting as a Text");
            println!("Encrypted: {}", ciphertext);
        } else {
            let msg = match message::decrypt_message(candidate, &key) {
                Ok(msg) => msg,
                Err(e) => {
                    println!("{}", e);
                    return;
                }
            };
            println!("Decrypting as a Text");
            println!("Decrypted: {}", msg);
        }
        return;
    }

    if path.is_dir() {
        let target_file = file_handler::list_files_in_dir(&path);
        if matches!(mode.as_str(), "enc" | "encrypt") {
            for file in target_file {
                file_handler::encrypt_file(&file, &key);
                file_handler::handle_renaming(Path::new(&file), true);
            }
        } else {
            for file in target_file {
                file_handler::decrypt_file(&file, &key);
                file_handler::handle_renaming(Path::new(&file), false);
            }
        }
    } else {
        if matches!(mode.as_str(), "enc" | "encrypt") {
            file_handler::encrypt_file(&path.to_string_lossy().into_owned(), &key);
            file_handler::handle_renaming(Path::new(path), true);
        } else {
            file_handler::decrypt_file(&path.to_string_lossy().into_owned(), &key);
            file_handler::handle_renaming(Path::new(path), false);
        }
    }
}