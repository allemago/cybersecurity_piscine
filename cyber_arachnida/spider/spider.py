#!/usr/bin/env python3

import argparse
import os
from urllib.parse import ParseResult, urlparse, urlunparse, urljoin
from urllib.robotparser import RobotFileParser

import requests
from bs4 import BeautifulSoup
from requests.exceptions import RequestException

DEBUG = False
DEBUG_URL = "http://localhost:8000/index.html"

USER_AGENT = "SpiderBot/1.0"
BASE_DIR = "./data/"
EXTENSIONS = (".jpg", ".jpeg", ".png", ".gif", ".bmp")


class Color:
    """ANSI color codes used for terminal output."""
    BOLD = "\033[1m"
    BOLD_GREEN = "\033[1;32m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RESET = "\033[0m"


class SpiderState:
    """Tracks crawl configuration and visited/downloaded URLs."""

    def __init__(self, is_recursive: bool, depth: int, path: str):
        """Initialize the spider state.

        Args:
            is_recursive: Whether the crawl follows links recursively.
            depth: Maximum recursion depth allowed.
            path: Directory path where downloaded images are saved.
        """
        self.base_netloc = ""
        self.is_recursive = is_recursive
        self.max_depth = depth
        self.path = path
        self.visited = set()
        self.dl_imgs = set()

    def has_visited(self, url: str) -> bool:
        """Check whether a page URL has already been crawled.

        Args:
            url: The page URL to look up.

        Returns:
            True if the URL was already visited, False otherwise.
        """
        return url in self.visited

    def mark_visited(self, url: str) -> None:
        """Record a page URL as visited.

        Args:
            url: The page URL to mark.
        """
        self.visited.add(url)

    def has_downloaded(self, img_url: str) -> bool:
        """Check whether an image URL has already been downloaded.

        Args:
            img_url: The image URL to look up.

        Returns:
            True if the image was already downloaded, False otherwise.
        """
        return img_url in self.dl_imgs

    def mark_downloaded(self, img_url: str) -> None:
        """Record an image URL as downloaded.

        Args:
            img_url: The image URL to mark.
        """
        self.dl_imgs.add(img_url)


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


def get_name(url: str) -> str:
    """Return the basename component of a URL path.

    Args:
        url: A URL or file path string.

    Returns:
        The last component of the path (e.g. ``"image.jpg"``).
    """
    return os.path.basename(url)


def download_image(img_url: str, path: str, state: SpiderState) -> None:
    """Download an image to disk if it has not already been saved.

    Fetches the image from ``img_url``, verifies the response is an
    image, and writes it into ``path`` with a unique filename.

    Args:
        img_url: The absolute URL of the image to download.
        path: The local directory where the image will be saved.
        state: The current SpiderState used to track downloads.
    """
    if state.has_downloaded(img_url):
        print(
            f"{Color.YELLOW}Skipping:{Color.RESET} \"{get_name(img_url)}\""
            f"{Color.YELLOW}, image already processed{Color.RESET}"
        )
        return

    parsed_url = urlparse(img_url)
    base_name = get_name(parsed_url.path)
    if not base_name:
        return

    name, ext = os.path.splitext(base_name)
    dest = os.path.join(path, base_name)

    i = 1
    while os.path.exists(dest):
        dest = os.path.join(path, f"{name}_{i}{ext}")
        i += 1

    try:
        headers = {"User-Agent": USER_AGENT}
        img_response = requests.get(img_url, timeout=10, headers=headers)
        img_response.raise_for_status()
    except RequestException as e:
        print(f"Request error for {img_url}: {e}")
        return

    content_type = img_response.headers.get("Content-Type", "").lower()
    if not content_type.startswith("image/"):
        print(
            f"{Color.YELLOW}Skipped non-image content:{Color.RESET} "
            f"\"{img_url}\" ({content_type})"
        )
        return

    try:
        with open(dest, "wb") as image_file:
            image_file.write(img_response.content)
        print(
            f"{Color.GREEN}Downloaded image:{Color.RESET} "
            f"\"{get_name(dest)}\""
        )
        state.mark_downloaded(img_url)
    except OSError as e:
        print(f"File error for {dest}: {e}")
        return


def has_allowed_ext(url: str) -> bool:
    """Check whether a URL path ends with a supported image extension.

    Args:
        url: The URL to inspect.

    Returns:
        True if the path ends with one of the EXTENSIONS entries.
    """
    return urlparse(url).path.lower().endswith(EXTENSIONS)


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


def is_allowed_by_robots(url: str, robots: RobotFileParser | None) -> bool:
    """Check whether robots.txt permits fetching a URL.

    Args:
        url: The URL to check.
        robots: A parsed RobotFileParser, or None if unavailable.

    Returns:
        True if no robots parser is loaded or if the URL is allowed.
    """
    if robots is None:
        return True
    return robots.can_fetch(USER_AGENT, url)


def crawl(
    url: str,
    state: SpiderState,
    robots: RobotFileParser | None,
    depth: int
) -> None:
    """Crawl a page, download its images, and optionally follow links.

    Fetches the page at ``url``, downloads every same-domain image
    that has a supported extension, and recurses into same-domain
    links up to the configured depth.

    Args:
        url: The absolute URL of the page to crawl.
        state: The current SpiderState tracking visits and downloads.
        robots: A parsed RobotFileParser, or None if unavailable.
        depth: The current recursion depth (starts at 0).
    """
    if depth > state.max_depth:
        return

    if state.has_visited(url):
        return

    if not is_allowed_by_robots(url, robots):
        print(
            f"{Color.YELLOW}Blocked by robots.txt:"
            f"{Color.RESET} \"{url}\""
        )
        return

    state.mark_visited(url)

    print(
        f"{Color.BOLD}\n>> Depth {depth}\n> Pages seen: "
        f"{len(state.visited)}{Color.RESET} -> {url}"
    )

    try:
        headers = {"User-Agent": USER_AGENT}
        response = requests.get(url, timeout=10, headers=headers)
        response.raise_for_status()
    except RequestException as e:
        print(f"Request error for page {url}: {e}")
        return

    images = extract_images(response.text, url)
    for img_url in images:
        img_parsed = urlparse(img_url)
        if img_parsed.netloc != state.base_netloc:
            continue
        if not is_allowed_by_robots(img_url, robots):
            print(
                f"{Color.YELLOW}Blocked by robots.txt:"
                f"{Color.RESET} \"{img_url}\""
            )
            continue
        download_image(img_url, state.path, state)

    if not state.is_recursive:
        return

    links = extract_links(response.text, url, state.base_netloc)
    for link in links:
        if not state.has_visited(link):
            crawl(link, state, robots, depth + 1)


def get_folder_path(path: str) -> str:
    """Resolve an absolute folder path, avoiding collision with files.

    If ``path`` resolves to an existing regular file, a numeric suffix
    is appended until a free name is found.

    Args:
        path: The desired directory path (absolute or relative).

    Returns:
        An absolute path suitable for use as a directory.
    """
    folder_path = os.path.abspath(path)
    if os.path.isfile(folder_path):
        base_dir = os.path.dirname(folder_path)
        base_name = os.path.basename(folder_path)
        i = 1
        while True:
            candidate = os.path.join(base_dir, f"{base_name}_{i}")
            if not os.path.exists(candidate):
                folder_path = candidate
                break
            i += 1
    return folder_path


def create_folder(path: str) -> str:
    """Create the destination directory if it does not exist.

    Args:
        path: The desired directory path.

    Returns:
        The absolute path of the created (or existing) directory.
    """
    folder_path = get_folder_path(path)
    try:
        os.makedirs(folder_path, exist_ok=True)
    except OSError as e:
        raise OSError(f"Cannot create directory '{path}': {e}")
    return folder_path


def load_robots_txt(url: str) -> RobotFileParser | None:
    """Fetch and parse the robots.txt file for a given URL's domain.

    Args:
        url: Any URL belonging to the target domain.

    Returns:
        A populated RobotFileParser, or None if the file could not
        be retrieved.
    """
    robots = RobotFileParser()
    try:
        parsed = urlparse(url)
        robots_url = urlunparse(
            (parsed.scheme, parsed.netloc, "/robots.txt", "", "", ""))
        robots.set_url(robots_url)
        robots.read()
    except Exception as e:
        print(
            f"{Color.YELLOW}Warning:{Color.RESET} "
            f"unable to read robots.txt ({e}), continuing without it."
        )
        return None
    return robots


def spider(url: str, state: SpiderState) -> None:
    """Set up the crawl environment and start crawling.

    Resolves the base domain, loads robots.txt, creates the output
    directory, and launches the recursive crawl.

    Args:
        url: The normalized starting URL.
        state: The SpiderState holding crawl configuration.
    """
    state.base_netloc = urlparse(url).netloc
    robots = load_robots_txt(url)
    state.path = create_folder(state.path)
    crawl(url, state, robots, 0)


def non_negative_int(value: str) -> int:
    """Convert a string to a non-negative integer for argparse.

    Args:
        value: The raw string supplied on the command line.

    Returns:
        The converted non-negative integer.
    """
    try:
        n = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError("DEPTH must be an integer")
    if n < 0:
        raise argparse.ArgumentTypeError("DEPTH must be a positive integer")
    return n


def parse_spider(parser: argparse.ArgumentParser) -> argparse.Namespace:
    """Register arguments and parse the command line for the spider tool.

    Args:
        parser: An ArgumentParser instance to populate with options.

    Returns:
        A Namespace containing the parsed and validated arguments.
    """
    parser.add_argument(
        "-r",
        dest="is_recursive",
        action="store_true",
        help="Activate recursive mode",
    )
    parser.add_argument(
        "-l",
        dest="depth",
        metavar="DEPTH",
        type=non_negative_int,
        help="Maximum recursion (default: 5)",
    )
    parser.add_argument(
        "-p",
        dest="path",
        metavar="PATH",
        default=BASE_DIR,
        help="Path where images will be saved",
    )
    parser.add_argument(
        "url",
        nargs="?",
        help="Target URL to crawl",
    )

    args = parser.parse_args()

    if DEBUG and args.url is None:
        args.url = DEBUG_URL

    if not DEBUG and args.url is None:
        parser.error("missing [url]")

    if args.depth is not None and not args.is_recursive:
        parser.error("option [-l] requires [-r]")

    if args.depth is None:
        args.depth = 5

    return args


def main() -> None:
    """CLI entry point."""
    description = "Spider - Web Image Downloader"
    parser = argparse.ArgumentParser(description=description)
    args = parse_spider(parser)
    print(f"{Color.BOLD}\n{description}{Color.RESET}")
    try:
        url = normalize_url(args.url)
        state = SpiderState(args.is_recursive, args.depth, args.path)
        spider(url, state)
    except (
        ValueError,
        OSError,
        RequestException
    ) as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    main()
