import os
import tempfile
import threading
from functools import partial
from http.server import HTTPServer, SimpleHTTPRequestHandler

from src.spider_state import SpiderState
from src.crawler import spider


TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
BASE_URL = "http://localhost:8000"


def setup_module() -> None:
    """Start the HTTP server before running the tests."""
    handler = partial(SimpleHTTPRequestHandler, directory=TESTS_DIR)
    server = HTTPServer(("localhost", 8000), handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()


def test_non_recursive() -> None:
    """Without -r, only images from the target page are downloaded."""
    with tempfile.TemporaryDirectory() as path:
        state = SpiderState(is_recursive=False, depth=5, path=path)
        spider(f"{BASE_URL}/index.html", state)
        assert set(os.listdir(path)) == {"shrek.gif", "view.bmp"}


def test_recursive() -> None:
    """With -r, images from all reachable pages are downloaded."""
    with tempfile.TemporaryDirectory() as path:
        state = SpiderState(is_recursive=True, depth=5, path=path)
        spider(f"{BASE_URL}/index.html", state)
        assert set(os.listdir(path)) == {
            "dance.gif", "dog.jpg", "frog.png",
            "shrek.gif", "snail.bmp", "troll.jpeg", "view.bmp",
        }


def test_depth_limit() -> None:
    """With -r -l 1, only the first level of links is followed."""
    with tempfile.TemporaryDirectory() as path:
        state = SpiderState(is_recursive=True, depth=1, path=path)
        spider(f"{BASE_URL}/index.html", state)
        assert set(os.listdir(path)) == {
            "shrek.gif", "view.bmp",
            "dance.gif", "frog.png", "snail.bmp",
        }


def test_unsupported_extension_skipped() -> None:
    """Files with unsupported extensions (.webp) are not downloaded."""
    with tempfile.TemporaryDirectory() as path:
        state = SpiderState(is_recursive=False, depth=5, path=path)
        spider(f"{BASE_URL}/index.html", state)
        assert "meme.webp" not in set(os.listdir(path))
