from urllib.parse import ParseResult, urlparse, urlunparse


def normalize_url(url: str) -> str:
    """Normalize a URL by stripping its fragment and validating it.

    Args:
        url: The raw URL string to normalize.

    Returns:
        The normalized URL without a fragment component.
    """
    parsed_url = urlparse(url)
    if not is_valid_url(parsed_url):
        raise ValueError("invalid URL")
    components = (
        parsed_url.scheme,
        parsed_url.netloc,
        parsed_url.path,
        parsed_url.params,
        parsed_url.query,
        ""
    )
    return urlunparse(components)


def is_valid_url(result: ParseResult) -> bool:
    """Check that a parsed URL uses HTTP(S) and has a host.

    Args:
        result: A ParseResult obtained from urllib.parse.urlparse.

    Returns:
        True if the URL scheme is http or https and a netloc is present.
    """
    if result.scheme.lower() not in ("http", "https"):
        return False
    if not result.netloc:
        return False
    return True


def is_same_domain(result: ParseResult, base_netloc: str) -> bool:
    """Check if a parsed URL belongs to the crawler's base domain.

    Args:
        result: A ParseResult obtained from urllib.parse.urlparse.
        base_netloc: The netloc of the original target URL.

    Returns:
        True if the URL is valid and its netloc matches base_netloc.
    """
    if not is_valid_url(result):
        return False
    if result.netloc != base_netloc:
        return False
    return True
