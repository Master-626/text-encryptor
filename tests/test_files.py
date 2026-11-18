import errno
import os
import stat
from pathlib import Path

import pytest
from cryptography.fernet import InvalidToken

from text_encryptor import decrypt_file, encrypt_file, encryptor


@pytest.fixture(params=[encrypt_file, decrypt_file], ids=["encrypt", "decrypt"])
def operation(request, tmp_path):
    source = tmp_path / "source"
    original = b"Disposable test data\x00\xff\n"
    if request.param is encrypt_file:
        source.write_bytes(original)
    else:
        plain = tmp_path / "plain"
        plain.write_bytes(original)
        encrypt_file(plain, source, "test-password")
    return request.param, source


@pytest.mark.parametrize("content", [b"", b"hello\n", bytes(range(256)) * 16])
def test_binary_file_round_trip(tmp_path, content):
    source = tmp_path / "source"
    encrypted = tmp_path / "encrypted"
    restored = tmp_path / "restored"
    source.write_bytes(content)

    encrypt_file(source, encrypted, "test-password")
    decrypt_file(encrypted, restored, "test-password")

    assert source.read_bytes() == content
    assert encrypted.read_bytes() != content
    assert restored.read_bytes() == content


def test_existing_output_is_unchanged(operation, tmp_path):
    transform, source = operation
    original = source.read_bytes()
    output = tmp_path / "existing"
    output.write_bytes(b"Keep this existing file")

    with pytest.raises(FileExistsError):
        transform(source, output, "test-password")

    assert source.read_bytes() == original
    assert output.read_bytes() == b"Keep this existing file"


@pytest.mark.parametrize("alias", ["same", "relative", "hardlink", "symlink"])
def test_input_aliases_are_unchanged(operation, tmp_path, monkeypatch, alias):
    transform, source = operation
    original = source.read_bytes()
    output = tmp_path / "alias"
    if alias == "same":
        output = source
    elif alias == "relative":
        monkeypatch.chdir(tmp_path)
        output = Path(".") / source.name
    elif alias == "hardlink":
        os.link(source, output)
    else:
        try:
            output.symlink_to(source)
        except OSError as exc:
            if os.name == "nt":
                pytest.skip(f"Symlinks unavailable for this Windows user: {exc}")
            raise

    with pytest.raises(FileExistsError):
        transform(source, output, "test-password")

    assert source.read_bytes() == original
    assert output.read_bytes() == original
    if alias == "symlink":
        assert output.is_symlink()


def test_dangling_symlink_is_not_followed(operation, tmp_path):
    transform, source = operation
    original = source.read_bytes()
    target = tmp_path / "missing-target"
    output = tmp_path / "link"
    try:
        output.symlink_to(target)
    except OSError as exc:
        if os.name == "nt":
            pytest.skip(f"Symlinks unavailable for this Windows user: {exc}")
        raise

    with pytest.raises(FileExistsError):
        transform(source, output, "test-password")

    assert output.is_symlink()
    assert not target.exists()
    assert source.read_bytes() == original


def test_output_created_during_operation_is_not_overwritten(
    operation, tmp_path, monkeypatch
):
    transform, source = operation
    original = source.read_bytes()
    output = tmp_path / "raced-output"
    real_opener = encryptor._private_opener

    def racing_opener(path, flags):
        Path(path).write_bytes(b"Created by another writer")
        return real_opener(path, flags)

    monkeypatch.setattr(encryptor, "_private_opener", racing_opener)
    with pytest.raises(FileExistsError):
        transform(source, output, "test-password")

    assert source.read_bytes() == original
    assert output.read_bytes() == b"Created by another writer"


def test_dangling_symlink_created_during_open_is_not_followed(
    operation, tmp_path, monkeypatch
):
    transform, source = operation
    original = source.read_bytes()
    output = tmp_path / "raced-link"
    target = tmp_path / "missing-target"
    real_opener = encryptor._private_opener

    def racing_opener(path, flags):
        try:
            Path(path).symlink_to(target)
        except OSError as exc:
            if os.name == "nt":
                pytest.skip(f"Symlinks unavailable for this Windows user: {exc}")
            raise
        return real_opener(path, flags)

    monkeypatch.setattr(encryptor, "_private_opener", racing_opener)
    with pytest.raises(FileExistsError):
        transform(source, output, "test-password")

    assert source.read_bytes() == original
    assert output.is_symlink()
    assert not target.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_new_outputs_are_private(operation, tmp_path):
    transform, source = operation
    output = tmp_path / "private-output"
    old_umask = os.umask(0)
    try:
        transform(source, output, "test-password")
    finally:
        os.umask(old_umask)
    assert stat.S_IMODE(output.stat().st_mode) == 0o600


@pytest.mark.parametrize("failure", ["wrong-password", "truncated", "tampered"])
@pytest.mark.parametrize("existing_output", [False, True])
def test_failed_decryption_does_not_touch_output(tmp_path, failure, existing_output):
    plain = tmp_path / "plain"
    source = tmp_path / "ciphertext"
    output = tmp_path / "output"
    plain.write_bytes(b"Do not publish unauthenticated plaintext")
    encrypt_file(plain, source, "correct-password")
    password = "correct-password"
    if failure == "wrong-password":
        password = "wrong-password"
    elif failure == "truncated":
        source.write_bytes(source.read_bytes()[:12])
    else:
        data = bytearray(source.read_bytes())
        data[0] ^= 1
        source.write_bytes(data)
    original = source.read_bytes()
    if existing_output:
        output.write_bytes(b"Existing output")

    with pytest.raises(InvalidToken):
        decrypt_file(source, output, password)

    assert source.read_bytes() == original
    if existing_output:
        assert output.read_bytes() == b"Existing output"
    else:
        assert not output.exists()


def test_missing_input_does_not_create_output(tmp_path):
    for transform in (encrypt_file, decrypt_file):
        output = tmp_path / "output"
        with pytest.raises(FileNotFoundError):
            transform(tmp_path / "missing", output, "test-password")
        assert not output.exists()


def test_missing_output_parent_does_not_change_input(operation, tmp_path):
    transform, source = operation
    original = source.read_bytes()
    with pytest.raises(FileNotFoundError):
        transform(source, tmp_path / "missing" / "output", "test-password")
    assert source.read_bytes() == original


def test_directory_input_is_rejected(tmp_path):
    output = tmp_path / "output"
    for transform in (encrypt_file, decrypt_file):
        with pytest.raises(IsADirectoryError):
            transform(tmp_path, output, "test-password")
        assert not output.exists()


@pytest.mark.skipif(not os.path.exists("/dev/null"), reason="no /dev/null")
def test_device_input_is_rejected(tmp_path):
    output = tmp_path / "output"
    for transform in (encrypt_file, decrypt_file):
        with pytest.raises(OSError, match="Not a regular file") as exc_info:
            transform("/dev/null", output, "test-password")
        assert not isinstance(exc_info.value, FileNotFoundError)
        assert not output.exists()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are not supported")
def test_fifo_input_is_rejected_without_blocking(tmp_path):
    fifo = tmp_path / "fifo"
    try:
        os.mkfifo(fifo)
    except OSError as exc:
        pytest.skip(f"Could not create a FIFO: {exc}")
    output = tmp_path / "output"
    for transform in (encrypt_file, decrypt_file):
        with pytest.raises(OSError, match="Not a regular file"):
            transform(fifo, output, "test-password")
        assert not output.exists()


def test_symlink_to_regular_file_can_be_read(tmp_path):
    source = tmp_path / "source"
    link = tmp_path / "link"
    encrypted = tmp_path / "encrypted"
    restored = tmp_path / "restored"
    source.write_bytes(b"via-symlink")
    try:
        link.symlink_to(source)
    except OSError as exc:
        if os.name == "nt":
            pytest.skip(f"Symlinks unavailable for this Windows user: {exc}")
        raise

    encrypt_file(link, encrypted, "test-password")
    decrypt_file(encrypted, restored, "test-password")
    assert restored.read_bytes() == b"via-symlink"


def test_failed_write_removes_partial_output_and_can_be_retried(tmp_path, monkeypatch):
    source = tmp_path / "source"
    output = tmp_path / "output"
    restored = tmp_path / "restored"
    source.write_bytes(b"retry-me")
    real_write = encryptor.os.write
    calls = {"n": 0}

    def fail_once(fd, data):
        calls["n"] += 1
        if calls["n"] == 1:
            real_write(fd, data[:4])
            raise OSError(errno.ENOSPC, "No space left on device")
        return real_write(fd, data)

    monkeypatch.setattr(encryptor.os, "write", fail_once)
    with pytest.raises(OSError, match="No space left"):
        encrypt_file(source, output, "test-password")
    assert not output.exists()
    assert source.read_bytes() == b"retry-me"

    encrypt_file(source, output, "test-password")
    decrypt_file(output, restored, "test-password")
    assert restored.read_bytes() == b"retry-me"
