import os
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException

from src.console import Color
from src.spider_state import SpiderState
from src.robot import USER_AGENT


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
