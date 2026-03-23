import string


def open_file(file: str, mode: str = "r") -> str:
    """Read and return the entire content of a text file.

    Args:
        file: Path to the file to read.

    Returns:
        Content of the file as a string.
    """
    with open(file, mode) as file:
        data = file.read()

    return data


def is_hexadecimal(hex_key: str) -> bool:
    """Check whether a string is a valid hexadecimal key of at least 64 chars.

    Args:
        hex_key: String to validate.

    Returns:
        True if the string is at least 64 hexadecimal characters.
    """
    is_correct_len = len(hex_key) >= 64
    is_hex = all(char in string.hexdigits for char in hex_key)

    return is_correct_len and is_hex
