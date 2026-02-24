#!/usr/bin/env python3
"""Simple CLI to inspect image EXIF metadata."""

import argparse
import os
from pathlib import Path

import exifread
from PIL import Image, UnidentifiedImageError

EXTENSIONS = (".jpg", ".jpeg", ".png", ".gif", ".bmp")

IGNORED_TAGS = (
    'JPEGThumbnail',
    'TIFFThumbnail',
    'Thumbnail JPEGInterchangeFormat',
    'Thumbnail JPEGInterchangeFormatLength',
    'MakerNote',
)


class Color:
    """ANSI color helpers for terminal output."""
    BOLD = "\033[1m"
    BLUE = "\033[1;36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    RESET = "\033[0m"


def display_image_metadata(img_path: str) -> None:
    """Display basic image metadata to stdout.

    Args:
        img_path: Absolute or relative path to the image file.
    """
    with Image.open(img_path) as img:
        print(f"Format: {img.format}")
        print(f"Mode: {img.mode}")
        print(f"Size: {img.size}")
        print(f"Palette: {img.palette}")


def get_creation_date(tags: dict) -> str | None:
    """Extract the creation date from EXIF tags.

    Args:
        tags: Dictionary of EXIF tags as returned by exifread.

    Returns:
        The creation date as a string, or None if no date tag is found.
    """
    date_keys = (
        "EXIF DateTimeOriginal",
        "Image DateTime",
        "EXIF DateTimeDigitized",
    )
    for key in date_keys:
        if key in tags:
            return str(tags[key])
    return None


def display_exif_data(img_path: str) -> None:
    """Read and display EXIF data and basic metadata for an image.

    Args:
        img_path: Absolute or relative path to the image file.
    """
    with open(img_path, "rb") as img_file:
        tags = exifread.process_file(img_file)
        creation_date = get_creation_date(tags)

        print(
            f"\n************\n{Color.BOLD}Current image: "
            f"\"{os.path.basename(img_path)}\"{Color.RESET}"
        )

        print(f"{Color.BOLD}\n>> BASIC METADATA{Color.RESET}")
        if creation_date:
            print(f"Creation date: {creation_date}")

        display_image_metadata(img_path)

        print(f"{Color.BOLD}\n>> EXIF DATA{Color.RESET}")
        if tags:
            print(f"{Color.GREEN}EXIF data found{Color.RESET}")
            for tag, value in tags.items():
                if tag not in IGNORED_TAGS:
                    print(f"{tag}: {value}")
        else:
            print(f"{Color.YELLOW}No EXIF data found{Color.RESET}")


def scorpion(img_files: list[str]) -> None:
    """Process a list of image files and display their metadata.

    Args:
        img_files: List of file paths to inspect.
    """
    for img in img_files:
        img_path = os.path.abspath(img)
        extension = Path(img_path).suffix.lower()

        if extension not in EXTENSIONS:
            print(
                f"{Color.YELLOW}Skipping unsupported file type: "
                f"{img}{Color.RESET}\n")
            continue
        try:
            display_exif_data(img_path)
        except (
            FileNotFoundError,
            IsADirectoryError,
            PermissionError,
            UnidentifiedImageError,
            OSError,
        ) as e:
            print(f"Error: {img}: {e}")
            print(f"{Color.YELLOW}Skipping to next image{Color.RESET}\n")
            continue


def parse_scorpion(parser: argparse.ArgumentParser) -> argparse.Namespace:
    """Configure and parse command-line arguments.

    Args:
        parser: An ArgumentParser instance to configure.

    Returns:
        Parsed arguments as an argparse.Namespace.
    """
    parser.add_argument("img_files", nargs="+", metavar="FILE",
                        type=str, help="File(s) to process")
    args = parser.parse_args()
    return args


def main() -> None:
    """Entry point for the scorpion CLI."""
    description = "Scorpion - Image EXIF metadata analyzer"
    parser = argparse.ArgumentParser(description=description)
    args = parse_scorpion(parser)
    print(f"{Color.BLUE}\n{description}{Color.RESET}")
    scorpion(args.img_files)


if __name__ == "__main__":
    main()
