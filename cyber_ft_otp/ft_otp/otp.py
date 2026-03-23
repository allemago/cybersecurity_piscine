import hashlib
import hmac
import time


def generate_hmac(key: bytes) -> hmac.HMAC:
    """Generate an HMAC-SHA1 from a key and a time-based counter.

    Args:
        key: Secret key as bytes used to compute the HMAC.

    Returns:
        HMAC object computed with SHA-1.
    """
    counter = int(time.time()) // 30
    counter_bytes = counter.to_bytes(8, byteorder="big")

    hs_hmac = hmac.new(key, counter_bytes, hashlib.sha1)

    return hs_hmac


def dynamic_truncation(hmac_bytes: bytes) -> int:
    """Extract a 31-bit integer from an HMAC digest via dynamic truncation.

    Args:
        hmac_bytes: Raw HMAC digest bytes (20 bytes for SHA-1).

    Returns:
        31-bit truncated integer derived from the HMAC digest.
    """
    offset_bits = hmac_bytes[19]
    offset = offset_bits & 0x0F

    four_bytes = hmac_bytes[offset:offset+4]

    code_32bits = int.from_bytes(four_bytes, byteorder='big')

    code_31bits = code_32bits & 0x7FFFFFFF

    return code_31bits
