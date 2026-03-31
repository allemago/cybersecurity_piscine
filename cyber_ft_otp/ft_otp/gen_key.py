from secrets import token_hex


def generate_key() -> None:
    """Generate a 64-char hex key and write it to key.hex."""
    key = token_hex(32)
    with open("key.hex", "w") as file:
        file.write(key)
    print(f"Key written to key.hex ({len(key)} hex chars)")
