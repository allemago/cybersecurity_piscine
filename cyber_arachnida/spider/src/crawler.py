import os
from urllib.parse import urlparse


import requests
from requests.exceptions import RequestException

from src.console import Color
from src.spider_state import SpiderState
from src.downloader import download_image
from src.parser import extract_images, extract_links
from src.robot import (
    load_robots_txt,
    is_allowed_by_robots,
    USER_AGENT,
    RobotFileParser,
)


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
