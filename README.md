# File Encryption and Decryption Script

This script allows for encryption and decryption of files and directories using AES-256-GCM. It also supports message encryption and decryption, using a combination of a user-provided password and a randomly generated salt stored in the user's configuration directory. The script handles renaming files for additional obfuscation.

## Features
- **AES-256-GCM encryption** for secure file and message encryption.
- **File and directory encryption**: Encrypts or decrypts all files in a directory.
- **Configuration-based salt storage**: Generates and stores a random salt in the user's configuration directory (`~/.config/bigbottle/salt`).
- **Filename obfuscation**: Encodes and decodes filenames during encryption and decryption processes.
- **Support for message encryption**: Encrypts and decrypts single-line messages.

## Requirements

The script uses the following crates:
- `ring` for encryption and random number generation.
- `sha3` for SHA3-256 hashing.
- `rand` for salt generation.
- `data_encoding` for Base64 encoding/decoding.
- `walkdir` for directory traversal.

Ensure these dependencies are listed in your `Cargo.toml`.

## Usage

To use the script, compile it with Rust. Then, run it with one of the following commands:

```bash
# For encrypting or decrypting text
./<script_name> (enc/dec) [text]

# For encrypting or decrypting files or directories
./<script_name> (enc/dec) [path_to_file_or_directory]

# For VDF-based encryption or decryption of files, directories, or messages
./<script_name> (vdf-enc/vdf-dec) [path_to_file_or_directory_or_message] [difficulty]
```

### Example:

1. **Encrypt a directory (standard AES):**
   ```bash
   ./<script_name> enc /path/to/directory
   ```
2. **Decrypt a directory (standard AES):**
   ```bash
   ./<script_name> dec /path/to/directory
   ```
3. **Encrypt a file with VDF:**
   ```bash
   ./<script_name> vdf-enc /path/to/file.txt 100000
   ```
4. **Decrypt a directory with VDF:**
   ```bash
   ./<script_name> vdf-dec /path/to/directory 100000
   ```

### Parameters:
- `enc` or `encrypt`: Encrypts the provided text, file, or directory using standard AES-256-GCM.
- `dec` or `decrypt`: Decrypts the provided text, file, or directory using standard AES-256-GCM.
- `vdf-enc`: Encrypts the provided file, directory, or message using a Verifiable Delay Function (VDF).
- `vdf-dec`: Decrypts the provided file, directory, or message using a Verifiable Delay Function (VDF).
- `[difficulty]`: (Only for VDF operations) An integer representing the computational difficulty for the VDF. Higher values mean longer computation times for both encryption and decryption.
  
**Note**: You will be prompted to enter a password which is hashed with the salt from your configuration directory. VDF operations also utilize this salt for enhanced security.

### Verifiable Delay Function (VDF)

The VDF implementation introduces a verifiable delay into the encryption/decryption process. This means that even with the correct key, a certain amount of computational work (defined by the `difficulty` parameter) must be performed before the data can be accessed. This can be useful for scenarios where you want to enforce a minimum time delay for decryption.



## Filename Obfuscation
For file and directory encryption/decryption (both standard AES and VDF), the script obfuscates filenames by encoding them with a `.temp-` prefix. This provides an additional layer of obscurity.

## Error Handling

- If the provided path does not exist, the script will treat the input as a message to encrypt or decrypt.
- The script verifies that files and directories exist before attempting encryption/decryption.
- Errors are logged when file access is denied or if decryption fails.

## Security Considerations

- The encryption key is derived using the password and a salt, hashed using SHA3-256.
- Encrypted files and filenames are secured using AES-256-GCM with a 12-byte nonce.
  
## License
This project is protected under the [MIT License](https://github.com/Razerpoa/hdie/blob/master/LICENSE)