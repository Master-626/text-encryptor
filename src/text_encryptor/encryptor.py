"""
Core encryption/decryption logic.
"""

import base64
import os
from pathlib import Path
from typing import Optional, Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def derive_key(password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
    """Derive encryption key from password."""
    if salt is None:
        salt = os.urandom(16)

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt


def encrypt_text(text: str, password: str) -> str:
    """Encrypt text with password."""
    key, salt = derive_key(password)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(text.encode())

    # Combine salt + encrypted data
    result = base64.urlsafe_b64encode(salt + encrypted).decode()
    return result


def decrypt_text(encrypted_text: str, password: str) -> str:
    """Decrypt text with password."""
    data = base64.urlsafe_b64decode(encrypted_text.encode())
    salt = data[:16]
    encrypted = data[16:]

    key, _ = derive_key(password, salt)
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted).decode()
    return decrypted


def _private_opener(path, flags):
    """Create new output files readable only by their owner on POSIX."""
    return os.open(path, flags, 0o600)


def _write_new_file(output_path, content):
    """Create an output without replacing a file or following a symlink.

    Exclusive creation is checked by the OS, rather than a racy exists()
    check. This also rejects input aliases, hard links, and dangling symlinks.
    """
    with open(output_path, "xb", opener=_private_opener) as output:
        output.write(content)


def encrypt_file(input_path: str, output_path: str, password: str):
    """Encrypt a file to a new path; raise FileExistsError if it exists."""
    content = Path(input_path).read_bytes()
    key, salt = derive_key(password)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(content)

    _write_new_file(output_path, salt + encrypted)


def decrypt_file(input_path: str, output_path: str, password: str):
    """Decrypt a file to a new path; raise FileExistsError if it exists."""
    data = Path(input_path).read_bytes()
    salt = data[:16]
    encrypted = data[16:]

    key, _ = derive_key(password, salt)
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted)

    _write_new_file(output_path, decrypted)
