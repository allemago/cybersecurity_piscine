#!/usr/bin/env python3

import argparse

from requests.exceptions import RequestException

from src.spider_state import SpiderState
from src.crawler import spider
from src.url import normalize_url


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


def parse_spider() -> argparse.Namespace:
    """Register arguments and parse the command line for the spider tool.

    Args:
        parser: An ArgumentParser instance to populate with options.

    Returns:
        A Namespace containing the parsed and validated arguments.
    """
    description = "Spider - Web Image Downloader"
    parser = argparse.ArgumentParser(description=description)
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
        default=None,
        type=non_negative_int,
        help="Maximum recursion (default: 5)",
    )
    parser.add_argument(
        "-p",
        dest="path",
        metavar="PATH",
        default="./data/",
        help="Path where images will be saved",
    )
    parser.add_argument(
        "url",
        help="Target URL to crawl",
    )

    args = parser.parse_args()

    if args.depth is not None and not args.is_recursive:
        parser.error("option [-l] requires [-r]")

    if args.depth is None:
        args.depth = 5

    return args


def run() -> None:
    """CLI entry point."""
    args = parse_spider()
    try:
        url = normalize_url(args.url)
        state = SpiderState(args.is_recursive, args.depth, args.path)
        spider(url, state)
    except (ValueError, OSError, RequestException) as e:
        print(f"{type(e).__name__}: {e}")
