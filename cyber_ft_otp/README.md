# ft_otp

## Introduction

This project implements a **TOTP (Time-based One-Time Password)** system capable of generating ephemeral passwords from a master key.

## Requirements

- Python >= 3.10
- [Poetry](https://python-poetry.org/)

## Installation

```bash
poetry install
```

## Usage

```
ft_otp [-g <key_file>] [-k <key_file>]
```

| Option | Description |
|--------|-------------|
| `-g <key_file>` | Store a hexadecimal key (64+ characters) from `<key_file>` into an encrypted file `ft_otp.key`. |
| `-k ft_otp.key` | Generate a temporary 6-digit password from the encrypted key and print it to stdout. |

### Examples

```bash
$ echo -n "NEVER GONNA GIVE YOU UP" > key.txt
$ ft_otp -g key.txt
ValueError: key.txt: key must be 64 hexadecimal characters.

$ cat key.hex | wc -c
64
$ ft_otp -g key.hex
Key was successfully saved in ft_otp.key.

$ ft_otp -k ft_otp.key
836492

$ sleep 60
$ ft_otp -k ft_otp.key
123518
```

### Verification

Generated passwords can be verified with `oathtool`:

```bash
oathtool --totp $(cat key.hex)
```

## Testing

```bash
poetry run pytest -v
```

## Project structure

```
ft_otp/
├── __init__.py      # Package marker
├── __main__.py      # Entry point for python -m ft_otp
├── cli.py           # Argument parsing and main()
├── otp.py           # HMAC-SHA1 and dynamic truncation (RFC 4226)
├── crypto.py        # Fernet encryption/decryption of keys
└── utils.py         # File I/O and hex validation
tests/
└── test_ft_otp.py   # Integration tests
```
