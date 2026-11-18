"""
Core encryption/decryption logic.
"""

import base64
import binascii
import errno
import os
import stat
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


def _decode_text_payload(encrypted_text: str) -> bytes:
    """Decode an encrypt_text token, including one whose padding was stripped."""
    encoded = encrypted_text.encode()
    try:
        return base64.urlsafe_b64decode(encoded)
    except binascii.Error:
        # Whitespace is ignored by the decoder, but it still counts toward the
        # padding check. Drop it, then restore the missing "=" characters.
        stripped = b"".join(encoded.split())
        padding = (-len(stripped)) % 4
        if padding == 0:
            raise
        return base64.urlsafe_b64decode(stripped + b"=" * padding)


def decrypt_text(encrypted_text: str, password: str) -> str:
    """Decrypt text with password.

    Tokens are URL-safe base64. Omitted padding and whitespace are accepted.
    """
    data = _decode_text_payload(encrypted_text)
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


def _require_regular_file(path, info):
    """Reject directories, FIFOs, and devices before their bytes are consumed."""
    if stat.S_ISDIR(info.st_mode):
        raise IsADirectoryError(errno.EISDIR, "Is a directory", os.fspath(path))
    if not stat.S_ISREG(info.st_mode):
        raise OSError(errno.EINVAL, "Not a regular file", os.fspath(path))


def _read_regular_file(path) -> bytes:
    """Read a regular file. Refuse FIFOs and devices before touching their data.

    stat() does not block on a FIFO and does not drain a device, so those
    inputs are rejected before open(). O_NONBLOCK covers the race where the
    path becomes a FIFO after the check. Symlinks to regular files are
    followed, which is the normal way to read an input path.
    """
    _require_regular_file(path, os.stat(path))
    flags = os.O_RDONLY
    if os.name == "nt":
        flags |= getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    fd = os.open(path, flags)
    try:
        _require_regular_file(path, os.fstat(fd))
        chunks = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _write_all(fd, content):
    view = memoryview(content)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError(errno.EIO, "Failed to write output file")
        view = view[written:]


def _discard_incomplete_output(output_path, info):
    """Remove an unfinished output when it is still the file we created."""
    try:
        current = os.lstat(output_path)
    except OSError:
        return
    if not stat.S_ISREG(current.st_mode):
        return
    # st_ino is 0 on some Windows filesystems; samestat cannot help there.
    if info.st_ino and not os.path.samestat(info, current):
        return
    try:
        os.unlink(output_path)
    except OSError:
        return


def _write_new_file(output_path, content):
    """Create an output without replacing a file or following a symlink.

    Exclusive creation is checked by the OS, rather than a racy exists()
    check. This also rejects input aliases, hard links, and dangling symlinks.
    A failed write removes that new file so a partial ciphertext does not
    block a retry. A crash can still leave a partial file behind.
    """
    handle = open(output_path, "xb", opener=_private_opener)
    info = os.fstat(handle.fileno())
    try:
        raw = handle.detach()
    except BaseException:
        handle.close()
        _discard_incomplete_output(output_path, info)
        raise
    try:
        _write_all(raw.fileno(), content)
    except BaseException:
        try:
            raw.close()
        except BaseException:
            pass
        _discard_incomplete_output(output_path, info)
        raise
    raw.close()


def encrypt_file(input_path: str, output_path: str, password: str):
    """Encrypt a file to a new path; raise FileExistsError if it exists."""
    content = _read_regular_file(input_path)
    key, salt = derive_key(password)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(content)

    _write_new_file(output_path, salt + encrypted)


def decrypt_file(input_path: str, output_path: str, password: str):
    """Decrypt a file to a new path; raise FileExistsError if it exists."""
    data = _read_regular_file(input_path)
    salt = data[:16]
    encrypted = data[16:]

    key, _ = derive_key(password, salt)
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted)

    _write_new_file(output_path, decrypted)
