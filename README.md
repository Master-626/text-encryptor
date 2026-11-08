# Text Encryptor

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)

A secure text encryption and decryption tool with AES encryption support.

## 🌟 Features

- 🔒 **Text Encryption** - Encrypt any text with a password
- 🔓 **Text Decryption** - Decrypt encrypted text
- 📄 **File Encryption** - Encrypt entire files
- 🛡️ **Secure** - Uses AES encryption with PBKDF2 key derivation
- 🐍 **Python API** - Use as a library in your code

## 📦 Installation

```bash
git clone https://github.com/Master-626/text-encryptor.git
cd text-encryptor
pip install .
```

## 🚀 Usage

### Encrypt Text
```bash
text-encryptor encrypt -t "Hello World" -p "mypassword"
```

### Decrypt Text
```bash
text-encryptor decrypt -t "gAAAAAB..." -p "mypassword"
```

### Encrypt File
```bash
text-encryptor encrypt-file -i secret.txt -o secret.enc -p "mypassword"
```

### Decrypt File
```bash
text-encryptor decrypt-file -i secret.enc -o recovered.txt -p "mypassword"
```

File outputs must use a new path. Existing files, the input itself, hard links,
and symbolic links are never overwritten. Choose another output name if one
already exists. New output files are owner-readable/writable only on POSIX.
An interrupted or failed write may leave an incomplete new output; keep the
original input until you have successfully decrypted and checked the result.

Commands return a nonzero exit status on invalid input, a wrong password,
corrupted ciphertext, or file errors. Errors go to standard error.

The `-p` examples use demonstration passwords. Real passwords supplied on the
command line can be exposed in shell history and process listings.

## 🐍 Python API

```python
from text_encryptor import encrypt_text, decrypt_text, encrypt_file, decrypt_file

# Encrypt text
encrypted = encrypt_text("My secret message", "password123")

# Decrypt text
decrypted = decrypt_text(encrypted, "password123")

# Encrypt file
encrypt_file("input.txt", "output.enc", "password123")
```

## 🧪 Testing

```bash
pip install -e ".[dev]"
pytest
```

## 📄 License

MIT License
