use crate::crypto::{decrypt_aes_gcm, encrypt_aes_gcm};
use rand::{thread_rng, Rng};
use sha3::{Digest, Sha3_256};
use std::process::exit;
use vdf::{VDF, VDFParams, WesolowskiVDFParams};

pub fn encrypt(plaintext: &[u8], t: u64, salt: &[u8]) -> Vec<u8> {
    let mut k_e = [0u8; 32];
    thread_rng().fill(&mut k_e);

    let mut vdf_input_seed = [0u8; 32];
    thread_rng().fill(&mut vdf_input_seed);

    let mut hasher = Sha3_256::new();
    hasher.update(&vdf_input_seed);
    hasher.update(salt);
    let vdf_input: [u8; 32] = hasher.finalize().into();

    
    let vdf = WesolowskiVDFParams(2048).new();
    let vdf_solution = match vdf.solve(&vdf_input, t) {
        Ok(res) => res,
        Err(e) => {
            eprintln!("Error: {:?}", e);
            exit(1);
        }
    };
    let int_size = (2048 + 16) >> 4;
    let (vdf_output, _vdf_proof) = vdf_solution.split_at(2 * int_size);

    let mut hasher = Sha3_256::new();
    hasher.update(&vdf_output);
    let k_vdf = hasher.finalize();

    let ciphertext = encrypt_aes_gcm(&k_e, plaintext).unwrap_or_else(|e| {
        eprintln!("{:?}", e);
        exit(1);
    });
    let wrapped_k_e = encrypt_aes_gcm(&k_vdf, &k_e).unwrap_or_else(|e| {
        eprintln!("{:?}", e);
        exit(1);
    });

    let mut result = Vec::new();
    result.extend_from_slice(&vdf_input_seed);
    result.extend_from_slice(&(vdf_solution.len() as u64).to_le_bytes());
    result.extend_from_slice(&vdf_solution);
    result.extend_from_slice(&(wrapped_k_e[..12].len() as u64).to_le_bytes());
    result.extend_from_slice(&wrapped_k_e[..12]);
    result.extend_from_slice(&(wrapped_k_e[12..].len() as u64).to_le_bytes());
    result.extend_from_slice(&wrapped_k_e[12..]);
    result.extend_from_slice(&(ciphertext[..12].len() as u64).to_le_bytes());
    result.extend_from_slice(&ciphertext[..12]);
    result.extend_from_slice(&(ciphertext[12..].len() as u64).to_le_bytes());
    result.extend_from_slice(&ciphertext[12..]);

    result
}

pub fn decrypt(encrypted_bytes: &[u8], t: u64, salt: &[u8]) -> Vec<u8> {
    let mut offset = 0;

    let vdf_input_seed: [u8; 32] = encrypted_bytes[offset..offset + 32].try_into().unwrap();
    offset += 32;

    let vdf_solution_len = u64::from_le_bytes(encrypted_bytes[offset..offset + 8].try_into().unwrap()) as usize;
    offset += 8;
    let vdf_solution = encrypted_bytes[offset..offset + vdf_solution_len].to_vec();
    offset += vdf_solution_len;

    let nonce_wrap_len = u64::from_le_bytes(encrypted_bytes[offset..offset + 8].try_into().unwrap()) as usize;
    offset += 8;
    let nonce_wrap = encrypted_bytes[offset..offset + nonce_wrap_len].to_vec();
    offset += nonce_wrap_len;

    let wrapped_k_e_len = u64::from_le_bytes(encrypted_bytes[offset..offset + 8].try_into().unwrap()) as usize;
    offset += 8;
    let wrapped_k_e = encrypted_bytes[offset..offset + wrapped_k_e_len].to_vec();
    offset += wrapped_k_e_len;

    let nonce_file_len = u64::from_le_bytes(encrypted_bytes[offset..offset + 8].try_into().unwrap()) as usize;
    offset += 8;
    let nonce_file = encrypted_bytes[offset..offset + nonce_file_len].to_vec();
    offset += nonce_file_len;

    let ciphertext_len = u64::from_le_bytes(encrypted_bytes[offset..offset + 8].try_into().unwrap()) as usize;
    offset += 8;
    let ciphertext = encrypted_bytes[offset..offset + ciphertext_len].to_vec();

    let mut hasher = Sha3_256::new();
    hasher.update(&vdf_input_seed);
    hasher.update(salt);
    let vdf_input: [u8; 32] = hasher.finalize().into();

    
    
    let vdf = WesolowskiVDFParams(2048).new();
    if vdf.verify(&vdf_input, t, &vdf_solution).is_err() {
        eprintln!("Error: VDF Proof is invalid. Cannot decrypt.");
        exit(1);
    }
    

    
    let int_size = (2048 + 16) >> 4;
    let (vdf_output, _) = vdf_solution.split_at(2 * int_size);
    

    let mut hasher = Sha3_256::new();
    hasher.update(&vdf_output);
    let k_vdf = hasher.finalize();

    let mut wrapped_k_e_full = Vec::new();
    wrapped_k_e_full.extend_from_slice(&nonce_wrap);
    wrapped_k_e_full.extend_from_slice(&wrapped_k_e);

    let k_e = decrypt_aes_gcm(&k_vdf, &wrapped_k_e_full).unwrap_or_else(|e| {
        eprintln!("{:?}", e);
        exit(1);
    });

    let mut ciphertext_full = Vec::new();
    ciphertext_full.extend_from_slice(&nonce_file);
    ciphertext_full.extend_from_slice(&ciphertext);

    decrypt_aes_gcm(&k_e, &ciphertext_full).unwrap_or_else(|e| {
        eprintln!("{:?}", e);
        exit(1);
    })
}
