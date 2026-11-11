"""
CLI interface for text-encryptor.
"""

import binascii
from pathlib import Path

import click
from cryptography.fernet import InvalidToken

from .encryptor import decrypt_file, decrypt_text, encrypt_file, encrypt_text


def _read_password_file(path):
    """Return a password from a UTF-8 file.

    A leading UTF-8 BOM is ignored, and one trailing newline (LF or CRLF) is
    removed so a line written by a text editor matches the typed password.
    Any earlier newlines stay part of the password.
    """
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise click.ClickException(f"Could not read password file: {exc}") from exc
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise click.ClickException("Password file is not valid UTF-8 text.") from exc
    if text.endswith("\r\n"):
        return text[:-2]
    if text.endswith("\n"):
        return text[:-1]
    return text


def _resolve_password(password, password_file):
    if password is not None and password_file is not None:
        raise click.UsageError("Use only one of -p/--password and --password-file.")
    if password_file is not None:
        return _read_password_file(password_file)
    if password is None:
        raise click.UsageError(
            "Missing option '-p' / '--password'. "
            "Or pass --password-file to read the password from a file."
        )
    return password


def _with_password_options(command):
    command = click.option(
        "--password-file",
        type=click.Path(exists=True, dir_okay=False),
        help="Read the password from a UTF-8 file instead of -p.",
    )(command)
    command = click.option(
        "-p",
        "--password",
        help="Password. Cannot be combined with --password-file.",
    )(command)
    return command


@click.group()
@click.version_option()
def main():
    """Text Encryptor - Secure text encryption and decryption."""


@main.command()
@click.option("-t", "--text", required=True, help="Text to encrypt")
@_with_password_options
def encrypt(text, password, password_file):
    """Encrypt text."""
    password = _resolve_password(password, password_file)
    encrypted = encrypt_text(text, password)
    click.echo(f"🔒 Encrypted: {encrypted}")


@main.command()
@click.option("-t", "--text", required=True, help="Text to decrypt")
@_with_password_options
def decrypt(text, password, password_file):
    """Decrypt text."""
    password = _resolve_password(password, password_file)
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
@_with_password_options
def encrypt_file_cmd(input, output, password, password_file):
    """Encrypt a file."""
    password = _resolve_password(password, password_file)
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
@_with_password_options
def decrypt_file_cmd(input, output, password, password_file):
    """Decrypt a file."""
    password = _resolve_password(password, password_file)
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
