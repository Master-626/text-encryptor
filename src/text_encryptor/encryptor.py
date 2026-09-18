"""
Core encryption/decryption logic.
"""

import base64
import os
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def derive_key(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
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


def encrypt_file(input_path: str, output_path: str, password: str):
    """Encrypt a file."""
    content = Path(input_path).read_bytes()
    key, salt = derive_key(password)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(content)

    Path(output_path).write_bytes(salt + encrypted)


def decrypt_file(input_path: str, output_path: str, password: str):
    """Decrypt a file."""
    data = Path(input_path).read_bytes()
    salt = data[:16]
    encrypted = data[16:]

    key, _ = derive_key(password, salt)
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted)

    Path(output_path).write_bytes(decrypted)
