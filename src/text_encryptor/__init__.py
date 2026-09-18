"""
text-encryptor - Secure text encryption and decryption.
"""

from .encryptor import encrypt_text, decrypt_text, encrypt_file, decrypt_file

__version__ = "0.1.0"
__all__ = ["encrypt_text", "decrypt_text", "encrypt_file", "decrypt_file"]
