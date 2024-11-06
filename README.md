# File Encryption and Decryption Script

This script allows for encryption and decryption of files and directories using AES-256-GCM. It also supports message encryption and decryption, using a combination of a user-provided password and a randomly generated salt stored in the Windows registry. The script handles renaming files for additional obfuscation.

## Features
- **AES-256-GCM encryption** for secure file and message encryption.
- **File and directory encryption**: Encrypts or decrypts all files in a directory.
- **Registry-based salt storage**: Generates and stores a random salt in the Windows registry.
- **Filename obfuscation**: Encodes and decodes filenames during encryption and decryption processes.
- **Support for message encryption**: Encrypts and decrypts single-line messages.

## Requirements

The script uses the following crates:
- `ring` for encryption and random number generation.
- `sha3` for SHA3-256 hashing.
- `rand` for salt generation.
- `data_encoding` for Base64 encoding/decoding.
- `walkdir` for directory traversal.
- `winreg` for accessing the Windows registry.

Ensure these dependencies are listed in your `Cargo.toml`.

## Usage

To use the script, compile it with Rust. Then, run it with one of the following commands:

```bash
# For encrypting or decrypting text
./<script_name> (enc/dec) [text]

# For encrypting or decrypting files or directories
./<script_name> (enc/dec) [path_to_file_or_directory]
```

### Example:

1. **Encrypt a directory:**
   ```bash
   ./<script_name> enc /path/to/directory
   ```
2. **Decrypt a directory:**
   ```bash
   ./<script_name> dec /path/to/directory
   ```

### Parameters:
- `enc` or `encrypt`: Encrypts the provided text, file, or directory.
- `dec` or `decrypt`: Decrypts the provided text, file, or directory.
  
**Note**: You will be prompted to enter a password which is hashed with the salt from the registry.

### Windows Registry:
The script uses the Windows registry to store a salt, located at `SOFTWARE\BigBottle`. This salt is used to generate the encryption key from the password.

## Error Handling

- If the provided path does not exist, the script will treat the input as a message to encrypt or decrypt.
- The script verifies that files and directories exist before attempting encryption/decryption.
- Errors are logged when file access is denied or if decryption fails.

## Security Considerations

- The encryption key is derived using the password and a salt, hashed using SHA3-256.
- Encrypted files and filenames are secured using AES-256-GCM with a 12-byte nonce.
  
## License
This project is protected under the [MIT License](https://github.com/Razerpoa/hdie/blob/master/LICENSE)