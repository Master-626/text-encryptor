"""
CLI interface for text-encryptor.
"""

import binascii

import click
from cryptography.fernet import InvalidToken

from .encryptor import decrypt_file, decrypt_text, encrypt_file, encrypt_text


@click.group()
@click.version_option()
def main():
    """Text Encryptor - Secure text encryption and decryption."""


@main.command()
@click.option("-t", "--text", required=True, help="Text to encrypt")
@click.option("-p", "--password", required=True, help="Encryption password")
def encrypt(text, password):
    """Encrypt text."""
    encrypted = encrypt_text(text, password)
    click.echo(f"🔒 Encrypted: {encrypted}")


@main.command()
@click.option("-t", "--text", required=True, help="Text to decrypt")
@click.option("-p", "--password", required=True, help="Decryption password")
def decrypt(text, password):
    """Decrypt text."""
    try:
        decrypted = decrypt_text(text, password)
        click.echo(f"🔓 Decrypted: {decrypted}")
    except (InvalidToken, binascii.Error, UnicodeError) as exc:
        raise click.ClickException(
            "Decryption failed - wrong password or corrupted data"
        ) from exc


@main.command("encrypt-file")
@click.option("-i", "--input", required=True, help="Input file")
@click.option("-o", "--output", required=True, help="Output encrypted file")
@click.option("-p", "--password", required=True, help="Encryption password")
def encrypt_file_cmd(input, output, password):
    """Encrypt a file."""
    try:
        encrypt_file(input, output, password)
    except FileExistsError as exc:
        raise click.ClickException(
            f"Output already exists: {output}. Choose a new output path."
        ) from exc
    except OSError as exc:
        raise click.ClickException(f"Could not encrypt file: {exc}") from exc
    click.echo(f"✅ File encrypted: {output}")


@main.command("decrypt-file")
@click.option("-i", "--input", required=True, help="Input encrypted file")
@click.option("-o", "--output", required=True, help="Output decrypted file")
@click.option("-p", "--password", required=True, help="Decryption password")
def decrypt_file_cmd(input, output, password):
    """Decrypt a file."""
    try:
        decrypt_file(input, output, password)
        click.echo(f"✅ File decrypted: {output}")
    except InvalidToken as exc:
        raise click.ClickException(
            "Decryption failed - wrong password or corrupted file"
        ) from exc
    except FileExistsError as exc:
        raise click.ClickException(
            f"Output already exists: {output}. Choose a new output path."
        ) from exc
    except OSError as exc:
        raise click.ClickException(f"Could not decrypt file: {exc}") from exc


if __name__ == "__main__":
    main()
