import os
from cryptography.fernet import Fernet

from ft_otp.utils import open_file


def get_fernet_key() -> str:
    """Retrieve or generate the Fernet encryption key.

    Returns:
        Fernet key as a string.
    """
    file_key_path = "filekey.key"
    try:
        fernet_key = open_file(file_key_path, "rb")
    except FileNotFoundError:
        fernet_key = Fernet.generate_key()
        with open(file_key_path, "wb") as file:
            file.write(fernet_key)
        os.chmod(file_key_path, 0o600)
        fernet_key = open_file(file_key_path, "rb")

    return fernet_key


def decrypt_file(key_file: str) -> str:
    """Decrypt a Fernet-encrypted file and return its content.

    Args:
        key_file: Path to the encrypted file to decrypt.

    Returns:
        Decrypted content as a stripped string.
    """
    encrypted = open_file(key_file, "rb")

    fernet_key = get_fernet_key()
    fernet = Fernet(fernet_key)

    decrypted_key = fernet.decrypt(encrypted).decode('utf-8')

    return decrypted_key


def encrypt_file(hex_file: str) -> None:
    """Encrypt a file using Fernet and save it as ft_otp.key.

    Args:
        hex_file: Path to the plaintext file to encrypt.
    """
    fernet_key = get_fernet_key()
    fernet = Fernet(fernet_key)

    original = open_file(hex_file).strip()
    encrypted = fernet.encrypt(original.encode("utf-8"))

    with open("ft_otp.key", "wb") as file:
        file.write(encrypted)
