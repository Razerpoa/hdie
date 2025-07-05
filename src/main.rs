mod crypto;
mod file_handler;
mod message;
mod vdf;
use inquire::{Password, PasswordDisplayMode};
use std::{env, fs, path::Path};
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        println!("Usage: {} (enc/dec/vdf-enc/vdf-dec) [path/text]", args[0]);
        return;
    }

    let mode = &args[1];

    if mode == "vdf-enc" || mode == "vdf-dec" {
        if args.len() != 4 {
            println!("Usage: {} {} [path] [difficulty]", args[0], mode);
            return;
        }
        let path = &args[2];
        let t = args[3].parse::<u64>().unwrap_or_else(|_| {
            eprintln!("Error: Invalid difficulty");
            std::process::exit(1);
        });

        if mode == "vdf-enc" {
            let salt = crypto::handle_salt_file().unwrap_or_else(|e| {
                eprintln!("Error handling salt file: {}", e);
                std::process::exit(1);
            });

            let input_path = Path::new(path);
            if input_path.is_dir() {
                let files = file_handler::list_files_in_dir(input_path);
                for file_path_str in files {
                    let file_content = fs::read(&file_path_str).unwrap_or_else(|_| {
                        eprintln!("Error: Could not read file {}", file_path_str);
                        std::process::exit(1);
                    });
                    let encrypted_bytes = vdf::encrypt(&file_content, t, &salt);
                    fs::write(Path::new(&file_path_str), encrypted_bytes).unwrap_or_else(|_| {
                        eprintln!("Error: Could not write file {}", file_path_str);
                        std::process::exit(1);
                    });
                    file_handler::handle_renaming(Path::new(&file_path_str), true);
                    
                }
                
            } else if input_path.is_file() {
                let file_content = fs::read(input_path).unwrap_or_else(|_| {
                    eprintln!("Error: Could not read file");
                    std::process::exit(1);
                });
                let encrypted_bytes = vdf::encrypt(&file_content, t, &salt);
                fs::write(input_path, encrypted_bytes).unwrap_or_else(|_| {
                    eprintln!("Error: Could not write file");
                    std::process::exit(1);
                });
                file_handler::handle_renaming(input_path, true);
                
            } else {
                // Treat as a message
                let message_bytes = path.as_bytes().to_vec();
                let message_file_path = PathBuf::from(format!("{}.txt", path)); // Create a temporary file for the message
                fs::write(&message_file_path, &message_bytes).unwrap_or_else(|_| {
                    eprintln!("Error: Could not write message to temporary file");
                    std::process::exit(1);
                });
                let encrypted_bytes = vdf::encrypt(&message_bytes, t, &salt);
                fs::write(&message_file_path, encrypted_bytes).unwrap_or_else(|_| {
                    eprintln!("Error: Could not write encrypted message to file");
                    std::process::exit(1);
                });
                file_handler::handle_renaming(&message_file_path, true);
                println!("Encrypted message: {}", message_file_path.display());
            }
        } else {
            let salt = crypto::handle_salt_file().unwrap_or_else(|e| {
                eprintln!("Error handling salt file: {}", e);
                std::process::exit(1);
            });

            let input_path = Path::new(path);
            if input_path.is_dir() {
                let files = file_handler::list_files_in_dir(input_path);
                for file_path_str in files {
                    let encrypted_content = fs::read(&file_path_str).unwrap_or_else(|_| {
                        eprintln!("Error: Could not read file {}", file_path_str);
                        std::process::exit(1);
                    });
                    let decrypted_plaintext = vdf::decrypt(&encrypted_content, t, &salt);

                    // Determine original filename and path
                    let temp_filename = Path::new(&file_path_str).file_name().unwrap().to_string_lossy().into_owned();
                    let original_filename = file_handler::handle_decoding(".temp-[", temp_filename).unwrap_or_else(|e| {
                        eprintln!("Error decoding filename {}: {}", file_path_str, e);
                        std::process::exit(1);
                    });
                    let original_path = input_path.join(original_filename);

                    fs::remove_file(&file_path_str).unwrap_or_else(|e| {
                        eprintln!("Error removing encrypted file {}: {}", file_path_str, e);
                    });
                    fs::write(&original_path, decrypted_plaintext).unwrap_or_else(|_| {
                        eprintln!("Error: Could not write file {}", original_path.display());
                        std::process::exit(1);
                    });
                    println!("Decrypted file: {}", original_path.display());
                }
                println!("Decrypted directory: {}", path);
            } else if input_path.is_file() {
                let encrypted_content = fs::read(input_path).unwrap_or_else(|_| {
                    eprintln!("Error: Could not read file");
                    std::process::exit(1);
                });
                let decrypted_plaintext = vdf::decrypt(&encrypted_content, t, &salt);

                // Determine original filename and path
                let original_filename = file_handler::handle_decoding(".temp-[", Path::new(path).file_name().unwrap().to_string_lossy().into_owned()).unwrap_or_else(|e| {
                    eprintln!("Error decoding filename {}: {}", path, e);
                    std::process::exit(1);
                });
                let original_path = input_path.parent().unwrap_or(Path::new(".")).join(original_filename);

                fs::remove_file(input_path).unwrap_or_else(|e| {
                    eprintln!("Error removing encrypted file {}: {}", input_path.display(), e);
                });
                fs::write(&original_path, decrypted_plaintext).unwrap_or_else(|_| {
                    eprintln!("Error: Could not write file");
                    std::process::exit(1);
                });
                println!("Decrypted file: {}", original_path.display());
            } else {
                // Treat as a message
                let encrypted_content = fs::read(format!("{}.vdf", path)).unwrap_or_else(|_| {
                    eprintln!("Error: Could not read message file");
                    std::process::exit(1);
                });
                let decrypted_plaintext = vdf::decrypt(&encrypted_content, t, &salt);
                let decrypted_message = String::from_utf8_lossy(&decrypted_plaintext).to_string();
                println!("Decrypted message: {}", decrypted_message);
                fs::remove_file(format!("{}.vdf", path)).unwrap_or_else(|e| {
                    eprintln!("Error removing message file: {}", e);
                });
            }
        }
        return;
    }

    let salt = match crypto::handle_salt_file() {
        Ok(salt) => salt,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    let candidate = &args[2];

    if !matches!(mode.as_str(), "enc" | "encrypt" | "dec" | "decrypt") {
        eprint!("Error in your arguments");
        return;
    }

    let pwd = Password::new("Enter the password:")
        .with_display_mode(PasswordDisplayMode::Masked)        .prompt()
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
