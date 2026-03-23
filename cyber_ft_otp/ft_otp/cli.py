from argparse import ArgumentParser, Namespace

from ft_otp.crypto import decrypt_file, encrypt_file
from ft_otp.otp import dynamic_truncation, generate_hmac
from ft_otp.utils import is_hexadecimal, open_file


def process_key_file(key_file: str) -> int:
    """Decrypt a key file and generate a 6-digit TOTP code.

    Args:
        key_file: Path to the encrypted key file.

    Returns:
        6-digit OTP string zero-padded.
    """
    decrypted_key = decrypt_file(key_file)

    if not is_hexadecimal(decrypted_key):
        raise ValueError(f"{key_file}: key must be 64 hexadecimal characters.")

    bytes_key = bytes.fromhex(decrypted_key)
    hs_hmac = generate_hmac(bytes_key)
    hmac_bytes = hs_hmac.digest()
    code = dynamic_truncation(hmac_bytes)
    otp = code % 1_000_000

    return str(otp).zfill(6)


def process_hex_file(hex_file: str) -> None:
    """Validate and encrypt a hexadecimal key file.

    Args:
        hex_file: Path to the file containing the hexadecimal key.
    """
    hex_key = open_file(hex_file).strip()

    if not is_hexadecimal(hex_key):
        raise ValueError(f"{hex_file}: key must be 64 hexadecimal characters.")

    encrypt_file(hex_file)


def validate_arg(parser: ArgumentParser) -> Namespace:
    """Define mutually exclusive CLI arguments and parse them.

    Args:
        parser: ArgumentParser instance to configure.

    Returns:
        Parsed arguments as a Namespace object.
    """
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-g",
        dest="hex_file",
        metavar="HEXADECIMAL KEY FILE",
        type=str,
        help=(
            "Hexadecimal key of at least 64 characters"
            " to create a ft_otp.key file."
        )
    )
    group.add_argument(
        "-k",
        dest="key_file",
        choices=["ft_otp.key"],
        metavar="ENCRYPTED KEY FILE",
        type=str,
        help="ft_otp.key file to generate a temporary password."
    )

    args = parser.parse_args()

    return args


def main() -> int:
    """Entry point for the HOTP generator CLI."""
    try:
        description = "HMAC-based one-time password (HOTP) generator"
        parser = ArgumentParser(description=description)
        args = validate_arg(parser)

        if args.hex_file:
            process_hex_file(args.hex_file)
            print("Key was successfully saved in ft_otp.key.")

        elif args.key_file:
            otp = process_key_file(args.key_file)
            print(otp)

    except (OSError, ValueError) as e:
        print(f"{type(e).__name__}: {e}")
        return 1

    return 0
