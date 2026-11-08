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
    if os.name == "nt":
        return _open_windows_new_file(path)
    return os.open(path, flags, 0o600)


def _open_windows_new_file(path):
    """Create a Windows file without traversing a final symlink/reparse point.

    The Windows CRT's O_EXCL can follow a dangling symlink and create its
    target. CREATE_NEW with OPEN_REPARSE_POINT rejects the link itself in
    one operation, including links created concurrently with this call.
    """
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL

    handle = create_file(
        os.fsdecode(path),
        0x40000000,  # GENERIC_WRITE
        0,  # Do not share the output while it is being written.
        None,
        1,  # CREATE_NEW: fail if the destination already exists.
        0x00200080,  # FILE_FLAG_OPEN_REPARSE_POINT | FILE_ATTRIBUTE_NORMAL
        None,
    )
    if handle == ctypes.c_void_p(-1).value:
        error = ctypes.WinError(ctypes.get_last_error())
        error.filename = os.fsdecode(path)
        raise error
    try:
        # The descriptor owns the handle after a successful conversion.
        return msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY | os.O_NOINHERIT)
    except BaseException:
        close_handle(handle)
        raise


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
