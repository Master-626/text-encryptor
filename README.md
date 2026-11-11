# Text Encryptor

## 简要说明

text-encryptor 用密码加密、解密文本和文件（Fernet / AES，密钥由 PBKDF2-HMAC-SHA256 派生）。支持 Python 3.8+，命令为 `text-encryptor` 或 `texenc`，也可作为 Python 库调用。命令行上的密码会出现在 shell 历史和进程列表里；请改用 `--password-file` 从文件读取密码。

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)

Password-based encryption for short text and whole files. Ciphertext is authenticated with Fernet (AES-CBC + HMAC). The key is derived with PBKDF2-HMAC-SHA256 (100,000 iterations and a random 16-byte salt). A wrong password or a modified ciphertext raises an error instead of returning garbage.

## Features

- Encrypt and decrypt text from the command line or from Python
- Encrypt and decrypt regular files without replacing an existing output
- Read the password from a file so it is not part of the process command line
- URL-safe base64 text tokens, including tokens whose `=` padding was removed
- Owner-only permissions (`0600`) on new output files on POSIX

## Installation

Python 3.8 or newer is required.

```bash
git clone https://github.com/Master-626/text-encryptor.git
cd text-encryptor
python -m pip install .
```

Install the test and lint tools as well when you are developing:

```bash
python -m pip install -e ".[dev]"
```

The `text-encryptor` and `texenc` commands are equivalent.

## Usage

Encrypt and decrypt a string:

```bash
text-encryptor encrypt -t "Hello World" -p "mypassword"
text-encryptor decrypt -t "gAAAAAB..." -p "mypassword"
```

`decrypt` prints `🔓 Decrypted: ` plus the original text. Text tokens are URL-safe base64. Whitespace is ignored, and missing `=` padding is accepted.

Encrypt and decrypt a file:

```bash
text-encryptor encrypt-file -i secret.txt -o secret.enc -p "mypassword"
text-encryptor decrypt-file -i secret.enc -o recovered.txt -p "mypassword"
```

The file format is binary (`16-byte salt` + Fernet token). It is not the same string that `encrypt` prints, so a text token cannot be decrypted with `decrypt-file`.

Read the password from a UTF-8 file instead of `-p`:

```bash
umask 077
printf '%s\n' 'mypassword' > ./password.txt
text-encryptor encrypt-file -i secret.txt -o secret.enc --password-file ./password.txt
text-encryptor decrypt-file -i secret.enc -o recovered.txt --password-file ./password.txt
```

One trailing newline (LF or CRLF) is removed, and a leading UTF-8 BOM is ignored. Newlines before that trailing newline stay part of the password. `-p` and `--password-file` cannot be used together.

## Options

| Command | Option | Meaning |
| --- | --- | --- |
| `encrypt`, `decrypt` | `-t`, `--text` | Text to encrypt, or a text token to decrypt (required) |
| `encrypt-file`, `decrypt-file` | `-i`, `--input` | Input path (required, must be a regular file) |
| `encrypt-file`, `decrypt-file` | `-o`, `--output` | New output path (required) |
| all four commands | `-p`, `--password` | Password. Omit this when using `--password-file` |
| all four commands | `--password-file` | UTF-8 file to read the password from |
| `text-encryptor`, `texenc` | `--version` | Print the installed version |
| any command | `--help` | Print that command's options |

Commands return a nonzero exit status on invalid input, a wrong password, corrupted ciphertext, or file errors. Usage mistakes (missing text, both password sources, an unknown option) exit with status 2. Other failures exit with status 1. Errors go to standard error.

File outputs must use a new path. Existing files, the input itself, hard links, and symbolic links are never overwritten. Choose another output name if one already exists. New output files are owner-readable/writable only on POSIX. If writing a new output fails, that incomplete file is removed when it is still the file this process created, so the same path can be retried. A crash can still leave a partial file. Keep the original input until you have successfully decrypted and checked the result.

Inputs must be regular files. Directories, FIFOs, and device files are rejected and no output is created.

The `-p` examples use demonstration passwords. A password passed on the command line can be exposed in shell history and process listings. Prefer `--password-file` with a file that other users cannot read.

## Python API

```python
from text_encryptor import encrypt_text, decrypt_text, encrypt_file, decrypt_file

encrypted = encrypt_text("My secret message", "password123")
decrypted = decrypt_text(encrypted, "password123")

encrypt_file("input.txt", "output.enc", "password123")
decrypt_file("output.enc", "restored.txt", "password123")
```

`encrypt_text` / `decrypt_text` use `str`. `encrypt_file` / `decrypt_file` preserve arbitrary bytes. `decrypt_text` raises `binascii.Error` for impossible base64 and `cryptography.fernet.InvalidToken` for a wrong password or damaged token. File helpers raise `FileNotFoundError`, `IsADirectoryError`, `FileExistsError`, or `OSError` (including `Not a regular file`) before writing when the paths are unusable. A wrong file password raises `InvalidToken` and does not create the output.

## Tests and lint

```bash
python -m pip install -e ".[dev]"
python -m ruff check .
python -m pytest
```

Continuous integration runs `ruff` and `pytest` on Python 3.8 through 3.13 (3.8 on Ubuntu 24.04) and on Windows with Python 3.12. The 3.8 job also reinstalls the oldest declared Click, cryptography, and pytest versions.

## License

MIT License
