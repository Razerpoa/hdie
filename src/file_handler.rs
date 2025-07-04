use crate::crypto::{decrypt_aes_gcm, encrypt_aes_gcm};
use std::{
    fs::{remove_file, rename, File, OpenOptions},
    io::{BufReader, BufWriter, ErrorKind, Read, Write},
    path::{Path, PathBuf},
    process::exit,
};
use walkdir::WalkDir;

const PREFIX: &str = ".temp-[";

pub fn list_files_in_dir<P: AsRef<Path>>(dir: P) -> Vec<String> {
    let mut file_paths = Vec::new();

    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            file_paths.push(path.to_string_lossy().to_string());
        }
    }

    file_paths
}

pub fn encrypt_file(path: &String, key: &[u8]) {
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

pub fn decrypt_file(path: &String, key: &[u8]) {
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

pub fn handle_renaming(path: &Path, mode: bool) {
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