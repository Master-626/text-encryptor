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
