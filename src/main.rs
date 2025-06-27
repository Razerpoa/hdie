use data_encoding;
use rand;
use ring::{
    aead,
    error::Unspecified,
    rand::{generate, SystemRandom},
};
use sha3::{Digest, Sha3_256};
use inquire::{Password, PasswordDisplayMode};
use std::{
    env,
    fs::{create_dir_all, remove_file, rename, File, OpenOptions},
    io::{self, BufReader, BufWriter, ErrorKind, Read, Write},
    path::{Path, PathBuf},
    process::exit,
    vec,
};
use walkdir::WalkDir;

const SALT_FILE_PATH: &str = "~/.config/bigbottle/salt";
const PREFIX: &str = ".temp-[";

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
    let opening_key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_256_GCM, key)?);

    let (nonce, ciphertext_with_tag) = ciphertext.split_at(12);
    let ciphertext_len = ciphertext_with_tag.len() - aead::AES_256_GCM.tag_len();
    let (ciphertext, tag) = ciphertext_with_tag.split_at(ciphertext_len);

    let mut plaintext = vec![0; ciphertext.len()];
    let mut full_buffer = ciphertext.to_vec();
    full_buffer.extend_from_slice(tag);

    let nonce: [u8; 12] = nonce.try_into().map_err(|_| Unspecified)?;
    opening_key.open_in_place(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::empty(),
        &mut full_buffer,
    )?;

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
    // Ignore files that already have the PREFIX
    if let Some(filename) = Path::new(path).file_name() {
        let filename_str = filename.to_string_lossy();
        if filename_str.starts_with(PREFIX) && filename_str.ends_with(']') {
            println!("Skipping file '{}' as it already has the PREFIX.", filename_str);
            return;
        }
    }

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
                eprintln!("Other error occurred {}", e);
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
                eprintln!("Other error occurred {}", e);
                return;
            }
        },
    }
}

fn hash_string(plaintext: &String, salt: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(plaintext.as_bytes());
    hasher.update(salt);
    hasher.finalize().to_vec()
}

fn generate_random_salt() -> Vec<u8> {
    use rand::{thread_rng, RngCore};

    let mut salt = vec![0u8; 64];
    thread_rng().fill_bytes(&mut salt);
    salt
}

fn handle_salt_file() -> io::Result<Vec<u8>> {
    let salt_path = shellexpand::tilde(SALT_FILE_PATH).to_string();
    let salt_path = Path::new(&salt_path);
    let salt_dir = salt_path.parent().ok_or_else(|| {
        io::Error::new(ErrorKind::InvalidData, "Invalid salt file path")
    })?;

    // Create the directory if it doesn't exist
    create_dir_all(salt_dir)?;

    // Try to read existing salt or create a new one
    match File::open(salt_path) {
        Ok(file) => {
            let mut reader = BufReader::new(file);
            let mut salt = String::new();
            reader.read_to_string(&mut salt)?;
            data_encoding::BASE64URL
                .decode(salt.as_bytes())
                .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let new_salt = generate_random_salt();
            let mut file = File::create(salt_path)?;
            file.write_all(&data_encoding::BASE64URL.encode(&new_salt).as_bytes())?;
            Ok(new_salt)
        }
        Err(e) => Err(e),
    }
}

fn handle_encoding(prefix: &str, filename: String) -> String {
    let encoded_filename = data_encoding::BASE64URL.encode(filename.as_bytes());
    format!("{}{}]", prefix, encoded_filename)
}

fn handle_decoding(prefix: &str, filename: String) -> Result<String, String> {
    let encoded_filename = &filename[prefix.len()..filename.len() - 1];
    match data_encoding::BASE64URL.decode(encoded_filename.as_bytes()) {
        Ok(decoded_bytes) => Ok(String::from_utf8_lossy(&decoded_bytes).into_owned()),
        Err(e) => Err(format!("Decoding error: {}", e)),
    }
}

fn handle_renaming(path: &Path, mode: bool) {
    let filename = path.file_name().unwrap().to_string_lossy().into_owned();

    match mode {
        true => {
            // Skip renaming if file already has the PREFIX
            if filename.starts_with(PREFIX) && filename.ends_with(']') {
                println!("Skipping renaming '{}' as it already has the PREFIX.", filename);
                return;
            }
            let new_name = handle_encoding(PREFIX, filename);
            let new_path = append_filename_to_path(path, &new_name);
            match rename(path, &new_path) {
                Ok(()) => (),
                Err(e) => println!("Error renaming file: {}", e),
            };
        }
        false => {
            if filename.starts_with(PREFIX) && filename.ends_with(']') {
                let decoded_filename = match handle_decoding(&PREFIX, filename.to_string()) {
                    Ok(decoded) => decoded,
                    Err(e) => {
                        eprintln!("Error: {:?}", e);
                        String::from("InvalidBase64")
                    }
                };
                let new_path = append_filename_to_path(path, &decoded_filename);
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

fn append_filename_to_path(original_path: &Path, new_filename: &str) -> PathBuf {
    let mut new_path = original_path.to_path_buf();
    new_path.pop();
    new_path.push(new_filename);
    new_path
}

fn encrypt_message<T: AsRef<str>>(msg: T, key: &[u8]) -> String {
    let msg = msg.as_ref();
    let ciphertext = match encrypt_aes_gcm(key, msg.as_bytes()) {
        Ok(cipher) => cipher,
        Err(e) => {
            println!("{}", e);
            exit(1)
        }
    };
    data_encoding::BASE64URL.encode(&ciphertext)
}

fn decrypt_message<T: AsRef<str>>(ciphertext: T, key: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let ciphertext = data_encoding::BASE64URL.decode(ciphertext.as_ref().as_bytes())?;
    let plaintext = match decrypt_aes_gcm(key, &ciphertext) {
        Ok(plaintext) => plaintext,
        Err(_) => {
            eprintln!("Wrong password or target path isn't encrypted");
            exit(1);
        }
    };
    Ok(String::from_utf8_lossy(&plaintext).into_owned())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        println!("Usage: {} (enc/dec) [path/text]", args[0]);
        return;
    }

    let salt = match handle_salt_file() {
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
    let key = hash_string(&pwd.trim().to_string(), &salt);

    if !path.exists() {
        if matches!(mode.as_str(), "enc" | "encrypt") {
            let ciphertext = encrypt_message(candidate, &key);
            println!("Encrypting as a Text");
            println!("Encrypted: {}", ciphertext);
        } else {
            let msg = match decrypt_message(candidate, &key) {
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