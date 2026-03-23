from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup

from src.url import (
    normalize_url,
    is_same_domain,
)

EXTENSIONS = (".jpg", ".jpeg", ".png", ".gif", ".bmp")


def extract_links(html: str, url: str, base_netloc: str) -> list[str]:
    """Extract same-domain links from an HTML page.

    Parses all ``<a>`` tags, resolves relative hrefs, and keeps only
    links whose netloc matches the base domain.

    Args:
        html: The raw HTML content of the page.
        url: The absolute URL of the page (used to resolve relative hrefs).
        base_netloc: The netloc of the original target URL.

    Returns:
        A sorted list of unique, absolute, same-domain URLs.
    """
    soup = BeautifulSoup(html, "html.parser")
    links: set[str] = set()

    for a in soup.find_all('a'):
        href = a.get("href")
        if not href:
            continue
        if href.startswith("#"):
            continue
        absolute_url = urljoin(url, href)
        try:
            absolute_url = normalize_url(absolute_url)
        except ValueError:
            continue
        parsed_url = urlparse(absolute_url)
        if not is_same_domain(parsed_url, base_netloc):
            continue
        links.add(absolute_url)

    return sorted(links)


def extract_images(html: str, url: str) -> list[str]:
    """Extract image URLs from an HTML page.

    Inspects ``<img>`` src attributes and ``<a>`` href attributes,
    keeping only those whose path ends with a supported image extension.

    Args:
        html: The raw HTML content of the page.
        url: The absolute URL of the page (used to resolve relative paths).

    Returns:
        A sorted list of unique, absolute image URLs.
    """
    soup = BeautifulSoup(html, "html.parser")
    images: set[str] = set()

    for img in soup.find_all("img"):
        src = img.get("src")
        if not src:
            continue
        img_url = urljoin(url, src)
        try:
            img_url = normalize_url(img_url)
        except ValueError:
            continue
        if has_allowed_ext(img_url):
            images.add(img_url)

    for a in soup.find_all("a"):
        href = a.get("href")
        if not href:
            continue
        img_url = urljoin(url, href)
        try:
            img_url = normalize_url(img_url)
        except ValueError:
            continue
        if has_allowed_ext(img_url):
            images.add(img_url)

    return sorted(images)


def has_allowed_ext(url: str) -> bool:
    """Check whether a URL path ends with a supported image extension.

    Args:
        url: The URL to inspect.

    Returns:
        True if the path ends with one of the EXTENSIONS entries.
    """
    return urlparse(url).path.lower().endswith(EXTENSIONS)
