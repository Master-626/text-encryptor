import os
import subprocess
import sys

import pytest
from click.testing import CliRunner

from text_encryptor import cli, encrypt_file, encrypt_text
from text_encryptor.cli import main


@pytest.mark.parametrize("text", ["", "a", "not-a-token!", "密文"])
def test_malformed_text_returns_failure(text):
    result = CliRunner().invoke(main, ["decrypt", "-t", text, "-p", "password"])
    assert result.exit_code == 1
    assert "wrong password or corrupted data" in result.output
    assert "Decrypted:" not in result.output


def test_wrong_password_returns_failure():
    token = encrypt_text("secret", "correct-password")
    result = CliRunner().invoke(main, ["decrypt", "-t", token, "-p", "wrong"])
    assert result.exit_code == 1
    assert "wrong password or corrupted data" in result.output


def test_text_round_trip():
    runner = CliRunner()
    encrypted = runner.invoke(main, ["encrypt", "-t", "你好 🌍", "-p", "test"])
    assert encrypted.exit_code == 0
    token = encrypted.output.split("Encrypted: ", 1)[1].strip()
    decrypted = runner.invoke(main, ["decrypt", "-t", token, "-p", "test"])
    assert decrypted.exit_code == 0
    assert "Decrypted: 你好 🌍" in decrypted.output


def test_documented_file_commands_round_trip(tmp_path):
    source = tmp_path / "plain"
    encrypted = tmp_path / "encrypted"
    restored = tmp_path / "restored"
    source.write_bytes(b"binary\x00\xff")
    runner = CliRunner()
    for command, input_path, output_path in [
        ("encrypt-file", source, encrypted),
        ("decrypt-file", encrypted, restored),
    ]:
        result = runner.invoke(
            main, [command, "-i", str(input_path), "-o", str(output_path), "-p", "test"]
        )
        assert result.exit_code == 0, result.output
    assert restored.read_bytes() == source.read_bytes()


@pytest.mark.parametrize("command", ["encrypt-file", "decrypt-file"])
def test_existing_file_output_returns_failure(command, tmp_path):
    source = tmp_path / "source"
    output = tmp_path / "output"
    if command == "encrypt-file":
        source.write_bytes(b"plain")
    else:
        plain = tmp_path / "plain"
        plain.write_bytes(b"plain")
        encrypt_file(plain, source, "test")
    original = source.read_bytes()
    output.write_bytes(b"Keep this")

    result = CliRunner().invoke(
        main, [command, "-i", str(source), "-o", str(output), "-p", "test"]
    )

    assert result.exit_code == 1
    assert "Output already exists" in result.output
    assert "Choose a new output path" in result.output
    assert "✅" not in result.output
    assert source.read_bytes() == original
    assert output.read_bytes() == b"Keep this"


@pytest.mark.parametrize("command", ["encrypt-file", "decrypt-file"])
def test_missing_input_reports_file_error(command, tmp_path):
    output = tmp_path / "output"
    result = CliRunner().invoke(
        main,
        [command, "-i", str(tmp_path / "missing"), "-o", str(output), "-p", "test"],
    )
    assert result.exit_code == 1
    assert "Could not" in result.output
    assert "wrong password" not in result.output
    assert "✅" not in result.output
    assert not output.exists()


@pytest.mark.parametrize("corrupted", [False, True])
def test_file_decryption_error_has_nonzero_process_exit(tmp_path, corrupted):
    plain = tmp_path / "plain"
    source = tmp_path / "ciphertext"
    output = tmp_path / "output"
    plain.write_bytes(b"disposable")
    encrypt_file(plain, source, "correct")
    if corrupted:
        source.write_bytes(b"not encrypted data")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "text_encryptor.cli",
            "decrypt-file",
            "-i",
            str(source),
            "-o",
            str(output),
            "-p",
            "wrong",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert not result.stdout
    assert "wrong password or corrupted file" in result.stderr
    assert "Traceback" not in result.stderr
    assert not output.exists()


def test_text_error_goes_to_stderr():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "text_encryptor.cli",
            "decrypt",
            "-t",
            "bad",
            "-p",
            "test",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert not result.stdout
    assert "wrong password or corrupted data" in result.stderr
    assert "Traceback" not in result.stderr


@pytest.mark.parametrize(
    "command, function",
    [
        ("encrypt-file", "encrypt_file"),
        ("decrypt-file", "decrypt_file"),
    ],
)
def test_permission_errors_are_not_misreported_as_password_errors(
    command, function, monkeypatch
):
    def denied(*args):
        raise PermissionError("Access denied for test file")

    monkeypatch.setattr(cli, function, denied)
    result = CliRunner().invoke(
        main, [command, "-i", "source", "-o", "output", "-p", "test"]
    )
    assert result.exit_code == 1
    assert "Access denied for test file" in result.output
    assert "wrong password" not in result.output


def test_unexpected_errors_are_not_hidden_as_wrong_password(monkeypatch):
    def unexpected(*args):
        raise RuntimeError("Unexpected programming error")

    monkeypatch.setattr(cli, "decrypt_text", unexpected)
    result = CliRunner().invoke(main, ["decrypt", "-t", "data", "-p", "test"])
    assert result.exit_code != 0
    assert isinstance(result.exception, RuntimeError)
    assert "wrong password" not in result.output


def test_missing_password_is_a_usage_error():
    result = CliRunner().invoke(main, ["encrypt", "-t", "hello"])
    assert result.exit_code == 2
    assert "Missing option '-p' / '--password'" in result.output
    assert "--password-file" in result.output


def test_password_and_password_file_are_mutually_exclusive(tmp_path):
    password_file = tmp_path / "password.txt"
    password_file.write_bytes(b"from-file\n")
    result = CliRunner().invoke(
        main,
        [
            "encrypt",
            "-t",
            "hello",
            "-p",
            "from-flag",
            "--password-file",
            str(password_file),
        ],
    )
    assert result.exit_code == 2
    assert "only one" in result.output
    assert "Encrypted:" not in result.output


def test_password_file_text_round_trip(tmp_path):
    password_file = tmp_path / "password.txt"
    # A Notepad-style BOM and one trailing newline are not part of the password.
    password_file.write_bytes("\ufeff密码\n".encode("utf-8"))
    runner = CliRunner()
    encrypted = runner.invoke(
        main,
        ["encrypt", "-t", "secret 文字", "--password-file", str(password_file)],
    )
    assert encrypted.exit_code == 0, encrypted.output
    token = encrypted.output.split("Encrypted: ", 1)[1].strip()
    decrypted = runner.invoke(
        main,
        ["decrypt", "-t", token, "--password-file", str(password_file)],
    )
    assert decrypted.exit_code == 0, decrypted.output
    assert "Decrypted: secret 文字" in decrypted.output
    wrong_flag = runner.invoke(main, ["decrypt", "-t", token, "-p", "密码\n"])
    assert wrong_flag.exit_code == 1


def test_password_file_keeps_internal_newlines(tmp_path):
    password_file = tmp_path / "password.txt"
    password_file.write_bytes(b"first\nsecond\n")
    runner = CliRunner()
    encrypted = runner.invoke(
        main, ["encrypt", "-t", "body", "--password-file", str(password_file)]
    )
    assert encrypted.exit_code == 0, encrypted.output
    token = encrypted.output.split("Encrypted: ", 1)[1].strip()
    with_flag = runner.invoke(main, ["decrypt", "-t", token, "-p", "first\nsecond"])
    assert with_flag.exit_code == 0
    assert "Decrypted: body" in with_flag.output


def test_password_file_commands_round_trip(tmp_path):
    password_file = tmp_path / "password.txt"
    password_file.write_bytes(b"file-secret\r\n")
    source = tmp_path / "plain"
    encrypted = tmp_path / "encrypted"
    restored = tmp_path / "restored"
    source.write_bytes(b"binary\x00\xff")
    runner = CliRunner()
    for command, input_path, output_path in [
        ("encrypt-file", source, encrypted),
        ("decrypt-file", encrypted, restored),
    ]:
        result = runner.invoke(
            main,
            [
                command,
                "-i",
                str(input_path),
                "-o",
                str(output_path),
                "--password-file",
                str(password_file),
            ],
        )
        assert result.exit_code == 0, result.output
    assert restored.read_bytes() == source.read_bytes()


def test_cli_decrypts_token_without_padding():
    token = encrypt_text("pad me", "pw")
    assert token.endswith("=")
    result = CliRunner().invoke(main, ["decrypt", "-t", token.rstrip("="), "-p", "pw"])
    assert result.exit_code == 0
    assert "Decrypted: pad me" in result.output


def test_directory_input_is_a_file_error(tmp_path):
    output = tmp_path / "out"
    result = CliRunner().invoke(
        main,
        ["encrypt-file", "-i", str(tmp_path), "-o", str(output), "-p", "test"],
    )
    assert result.exit_code == 1
    assert "Is a directory" in result.output
    assert "wrong password" not in result.output
    assert not output.exists()


@pytest.mark.skipif(not os.path.exists("/dev/null"), reason="no /dev/null")
def test_device_input_is_a_file_error(tmp_path):
    output = tmp_path / "out"
    result = CliRunner().invoke(
        main,
        ["encrypt-file", "-i", "/dev/null", "-o", str(output), "-p", "test"],
    )
    assert result.exit_code == 1
    assert "Not a regular file" in result.output
    assert "wrong password" not in result.output
    assert not output.exists()


def test_non_utf8_password_file_is_rejected(tmp_path):
    password_file = tmp_path / "password.txt"
    password_file.write_bytes(b"\xff\xfe not utf-8")
    result = CliRunner().invoke(
        main,
        ["encrypt", "-t", "hello", "--password-file", str(password_file)],
    )
    assert result.exit_code == 1
    assert "not valid UTF-8" in result.output
    assert "Encrypted:" not in result.output
