use data_encoding;
use rand;
use ring::{
    aead,
    error::Unspecified,
    rand::{generate, SystemRandom},
};
use sha3::{Digest, Sha3_256};
use std::{
    fs::{create_dir_all, File},
    io::{self, BufReader, ErrorKind, Read, Write},
    path::Path,
};

const SALT_FILE_PATH: &str = "~/.config/bigbottle/salt";

pub fn encrypt_aes_gcm(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Unspecified> {
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

pub fn decrypt_aes_gcm(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Unspecified> {
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

pub fn hash_string(plaintext: &String, salt: &[u8]) -> Vec<u8> {
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

pub fn handle_salt_file() -> io::Result<Vec<u8>> {
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