use crate::crypto::{decrypt_aes_gcm, encrypt_aes_gcm};
use std::process::exit;

pub fn encrypt_message<T: AsRef<str>>(msg: T, key: &[u8]) -> String {
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

pub fn decrypt_message<T: AsRef<str>>(
    ciphertext: T,
    key: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
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