# Scorpion

Read and display EXIF metadata from image files.

Supported formats: `.jpg`, `.jpeg`, `.png`, `.gif`, `.bmp`

## Setup

```bash
poetry install
```

## Usage

```bash
poetry run scorpion FILE [FILE ...]
```

**Example:**

```bash
poetry run scorpion photo.jpg img1.png img2.jpg
```

For each file, scorpion prints basic metadata (format, mode, size) and all available EXIF tags.

## Run tests

```bash
poetry run pytest -v -s
```
