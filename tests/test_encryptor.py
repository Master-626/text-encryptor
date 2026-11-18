import binascii

import pytest
from cryptography.fernet import InvalidToken

from text_encryptor.encryptor import decrypt_text, encrypt_text


def test_encrypt_decrypt():
    """Test text encryption and decryption."""
    password = "mypassword123"
    original = "Hello, World!"

    encrypted = encrypt_text(original, password)
    assert encrypted != original

    decrypted = decrypt_text(encrypted, password)
    assert decrypted == original


def test_wrong_password():
    """Test that wrong password fails."""
    encrypted = encrypt_text("secret", "correct_password")

    with pytest.raises(InvalidToken):
        decrypt_text(encrypted, "wrong_password")


def test_missing_base64_padding_still_decrypts():
    """Tokens copied through tools that strip '=' must still decrypt."""
    encrypted = encrypt_text("padding check", "correct_password")
    assert encrypted.endswith("=")
    stripped = encrypted.rstrip("=")
    assert "=" not in stripped

    assert decrypt_text(stripped, "correct_password") == "padding check"
    assert decrypt_text(encrypted + "\n\n", "correct_password") == "padding check"


def test_wrapped_unpadded_token_still_decrypts():
    encrypted = encrypt_text("line wrap", "correct_password").rstrip("=")
    wrapped = "\n".join(encrypted[i : i + 16] for i in range(0, len(encrypted), 16))
    assert decrypt_text("  " + wrapped + "\n", "correct_password") == "line wrap"


def test_impossible_base64_length_still_fails():
    with pytest.raises(binascii.Error):
        decrypt_text("A", "correct_password")
