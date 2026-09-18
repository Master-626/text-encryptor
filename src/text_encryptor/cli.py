"""
CLI interface for text-encryptor.
"""

import click
from .encryptor import encrypt_text, decrypt_text, encrypt_file, decrypt_file


@click.group()
@click.version_option()
def main():
    """Text Encryptor - Secure text encryption and decryption."""
    pass


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
    except Exception:
        click.echo("❌ Decryption failed - wrong password or corrupted data", err=True)


@main.command()
@click.option("-i", "--input", required=True, help="Input file")
@click.option("-o", "--output", required=True, help="Output encrypted file")
@click.option("-p", "--password", required=True, help="Encryption password")
def encrypt_file_cmd(input, output, password):
    """Encrypt a file."""
    encrypt_file(input, output, password)
    click.echo(f"✅ File encrypted: {output}")


@main.command()
@click.option("-i", "--input", required=True, help="Input encrypted file")
@click.option("-o", "--output", required=True, help="Output decrypted file")
@click.option("-p", "--password", required=True, help="Decryption password")
def decrypt_file_cmd(input, output, password):
    """Decrypt a file."""
    try:
        decrypt_file(input, output, password)
        click.echo(f"✅ File decrypted: {output}")
    except Exception:
        click.echo("❌ Decryption failed - wrong password or corrupted file", err=True)


if __name__ == "__main__":
    main()
