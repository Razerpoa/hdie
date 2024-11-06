use data_encoding;
use rand;
use ring::{
    aead,
    error::Unspecified,
    rand::{generate, SystemRandom},
};
use sha3::{Digest, Sha3_256};
use std::{
    env,
    fs::{remove_file, rename, File, OpenOptions},
    io::{self, stdin, stdout, BufReader, BufWriter, ErrorKind, Read, Write},
    path::{Path, PathBuf},
    process::exit,
    vec,
};
use walkdir::WalkDir;
use winreg::enums::*;
use winreg::RegKey;

const SALT_REGISTRY_KEY: &str = r"SOFTWARE\BigBottle"; // Change this to your desired registry path

fn encrypt_aes_gcm(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Unspecified> {
    let nonce = generate(&SystemRandom::new()).unwrap().expose();

    let sealing_key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, key)?);
    let mut ciphertext = plaintext.to_vec();
    sealing_key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::empty(),
        &mut ciphertext,
    )?;

    let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

fn decrypt_aes_gcm(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Unspecified> {
    // Create an opening key for AES-256-GCM
    let opening_key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, key)?);

    // Extract the nonce
    let (nonce, ciphertext_with_tag) = ciphertext.split_at(12);

    // Calculate the length of the ciphertext without the tag
    let ciphertext_len = ciphertext_with_tag.len() - aead::AES_256_GCM.tag_len();
    let (ciphertext, tag) = ciphertext_with_tag.split_at(ciphertext_len);

    // Create a buffer to hold the plaintext, with the same length as the ciphertext
    let mut plaintext = vec![0; ciphertext.len()];

    // Prepare the full buffer (ciphertext + tag) for decryption
    let mut full_buffer = ciphertext.to_vec();
    full_buffer.extend_from_slice(tag);

    // Decrypt the ciphertext
    let nonce: [u8; 12] = nonce.try_into().map_err(|_| Unspecified)?;
    opening_key.open_in_place(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::empty(),
        &mut full_buffer,
    )?;

    // Trim the plaintext to the actual decrypted length
    plaintext.copy_from_slice(&full_buffer[..ciphertext.len()]);

    Ok(plaintext)
}

fn list_files_in_dir<P: AsRef<Path>>(dir: P) -> Vec<String> {
    let mut file_paths = Vec::new();

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            file_paths.push(path.to_string_lossy().to_string());
        }
    }

    file_paths
}

fn encrypt_file(path: &String, key: &[u8]) {
    let file = match OpenOptions::new().read(true).write(true).open(&path) {
        Ok(file) => file,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    let mut reader = BufReader::new(&file);
    let mut buffer = Vec::new();
    match reader.read_to_end(&mut buffer) {
        Ok(_size) => (),
        Err(e) => {
            eprintln!("{}", e)
        }
    }

    let encrypted: Vec<u8> = match encrypt_aes_gcm(key, &buffer) {
        Ok(ciphertext) => ciphertext,
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    };
    match remove_file(&path) {
        Ok(()) => (),
        Err(e) => {
            eprintln!("{}", e);
        }
    }

    let file_create = match File::create(&path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("{}", e);
            return;
        }
    };

    let mut writer = BufWriter::new(&file_create);
    match writer.write_all(&encrypted) {
        Ok(()) => (),
        Err(e) => match e.kind() {
            ErrorKind::PermissionDenied => {
                eprintln!("Permission denied");
                return;
            }
            _ => {
                eprintln!("Other error occured {}", e);
                return;
            }
        },
    }
}

fn decrypt_file(path: &String, key: &[u8]) {
    let file = match OpenOptions::new().read(true).write(true).open(&path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("{}", e);
            return;
        }
    };
    let mut reader = BufReader::new(&file);
    let mut buffer = Vec::new();
    match reader.read_to_end(&mut buffer) {
        Ok(_size) => (),
        Err(e) => {
            eprintln!("{}", e)
        }
    }

    let plaintext = match decrypt_aes_gcm(key, &buffer) {
        Ok(plaintext) => plaintext,
        Err(_e) => {
            eprintln!("Wrong password or target path isn't encrypted");
            exit(1);
        }
    };

    let file_create = match File::create(&path) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    };

    let mut writer = BufWriter::new(&file_create);
    match writer.write_all(&plaintext) {
        Ok(()) => (),
        Err(e) => match e.kind() {
            ErrorKind::PermissionDenied => {
                eprintln!("Permission denied");
                return;
            }
            _ => {
                eprintln!("Other error occured {}", e);
                return;
            }
        },
    }
}

fn hash_string(plaintext: &String, salt: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(plaintext.as_bytes());
    hasher.update(salt);
    let hashed = hasher.finalize().to_vec();
    hashed
}

fn generate_random_salt() -> Vec<u8> {
    use rand::{thread_rng, RngCore};

    let mut salt = vec![0u8; 64];
    thread_rng().fill_bytes(&mut salt);
    salt
}

fn handle_registry() -> io::Result<Vec<u8>> {
    let salt_value_name = "Salto";
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    // Create or open the registry key with better error handling
    let app_key = match hkcu.open_subkey(SALT_REGISTRY_KEY) {
        Ok(key) => key,
        Err(_) => {
            let (key, _) = hkcu.create_subkey(SALT_REGISTRY_KEY)?;
            key
        }
    };

    // Try to get existing salt or create new one
    let salt: String = match app_key.get_value(salt_value_name) {
        Ok(existing_salt) => existing_salt,
        Err(_) => {
            let new_salt = generate_random_salt();
            app_key.set_value(salt_value_name, &data_encoding::BASE64URL.encode(&new_salt))?;
            data_encoding::BASE64URL.encode(&new_salt)
        }
    };
    let decoded = data_encoding::BASE64URL
        .decode(salt.as_bytes())
        .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))?;
    Ok(decoded)
}

fn handle_renaming(path: &Path, mode: bool) {
    let prefix = ".temp-[";
    let filename = path.file_name().unwrap().to_string_lossy().into_owned();

    match mode {
        // Encoding and renaming
        true => {
            // Encode the filename and prepend the prefix
            let encoded_filename = data_encoding::BASE64URL.encode(filename.as_bytes());
            let new_name = format!("{}{}]", prefix, encoded_filename);

            // Create a new full path with the encoded filename
            let new_path = append_filename_to_path(path, &new_name);

            // Rename the file
            match rename(path, &new_path) {
                Ok(()) => (),
                Err(e) => println!("Error renaming file: {}", e),
            };
        }
        // Decoding and renaming back
        false => {
            // Remove the prefix from the filename before decoding
            if filename.starts_with(prefix) && filename.ends_with(']') {
                let encoded_filename = &filename[prefix.len()..filename.len() - 1]; // Strip prefix and suffix
                let decoded_filename =
                    match data_encoding::BASE64URL.decode(encoded_filename.as_bytes()) {
                        Ok(decoded_bytes) => String::from_utf8_lossy(&decoded_bytes).into_owned(),
                        Err(e) => {
                            println!("Error decoding filename: {}", e);
                            return;
                        }
                    };

                // Create new full path with the decoded filename
                let new_path = append_filename_to_path(path, &decoded_filename);

                // Rename the file back to the original name
                match rename(path, &new_path) {
                    Ok(()) => (),
                    Err(e) => {
                        if path.is_dir() {
                            println!("Error renaming directory: {}", e)
                        } else {
                            println!("Error renaming file: {}", e)
                        }
                    }
                };
            } else {
                println!("Filename does not have the expected prefix.");
            }
        }
    }
}

// Helper function to append a filename to an existing path
fn append_filename_to_path(original_path: &Path, new_filename: &str) -> PathBuf {
    let mut new_path = original_path.to_path_buf();
    new_path.pop(); // Remove the old filename
    new_path.push(new_filename); // Append the new filename
    new_path
}

// fn list_dir_in_dir(path: &Path) -> Vec<String> {
//     WalkDir::new(path)
//         .into_iter()
//         .filter_map(|entry| entry.ok())
//         .filter(|entry| entry.file_type().is_dir())
//         .map(|entry| entry.path().to_string_lossy().into_owned())
//         .collect() // Collect into a Vec<String>
// }

fn encrypt_message<T: AsRef<str>>(msg: T, key: &[u8]) -> String {
    let msg = msg.as_ref();
    let ciphertext = match encrypt_aes_gcm(key, msg.as_bytes()) {
        Ok(cipher) => cipher,
        Err(e) => {
            println!("{}", e);
            exit(1)
        }
    };
    let cipher = data_encoding::BASE64URL.encode(&ciphertext);
    cipher
}

fn decrypt_message<T: AsRef<str>>(
    ciphertext: T,
    key: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
    let ciphertext = data_encoding::BASE64URL.decode(ciphertext.as_ref().as_bytes())?;
    let plaintext = match decrypt_aes_gcm(key, &ciphertext) {
        Ok(plaintext) => plaintext,
        Err(e) => {
            println!("{}", e);
            exit(1)
        }
    };
    let msg = String::from_utf8_lossy(&plaintext).into_owned();
    Ok(msg)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} (enc/dec) [path/text]", args[0]);
        return;
    }

    let salt = match handle_registry() {
        Ok(salt) => salt,
        Err(e) => {
            println!("{}", e);
            return;
        }
    };

    let mode = &args[1];
    let candidate = &args[2];

    if !matches!(mode.as_str(), "enc" | "encrypt" | "dec" | "decrypt") {
        eprintln!("Choose between enc or dec for encrypt/decrypt the folder contents\nChoose enc-file or dec-file for encrypt/decrypt a file");
        return;
    }

    let mut pwd = String::new();
    print!("Enter the password: ");
    stdout().flush().expect("Failed to flush");
    stdin().read_line(&mut pwd).expect("Failed to read line");

    let path = Path::new(candidate);
    let key = hash_string(&pwd.trim().to_string(), &salt);

    if !path.exists() {
        if matches!(mode.as_str(), "enc" | "encrypt") {
            let ciphertext = encrypt_message(candidate, &key);
            println!("Encrypted: {}", ciphertext);
        } else {
            let msg = match decrypt_message(candidate, &key) {
                Ok(msg) => msg,
                Err(e) => {
                    println!("{}", e);
                    return;
                }
            };
            println!("Decrypted: {}", msg);
        }
        return;
    }

    if path.is_dir() {
        let target_file = list_files_in_dir(&path);
        if matches!(mode.as_str(), "enc" | "encrypt") {
            for file in target_file {
                encrypt_file(&file, &key);
                handle_renaming(Path::new(&file), true);
            }
        } else {
            for file in target_file {
                decrypt_file(&file, &key);
                handle_renaming(Path::new(&file), false);
            }
        }
    } else {
        if matches!(mode.as_str(), "enc" | "encrypt") {
            encrypt_file(&path.to_string_lossy().into_owned(), &key);
            handle_renaming(Path::new(path), true);
        } else {
            decrypt_file(&path.to_string_lossy().into_owned(), &key);
            handle_renaming(Path::new(path), false);
        }
    }
}
