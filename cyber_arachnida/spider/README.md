# Spider

Downloads images from a website, optionally following links recursively.

## Usage

| Option | Description | Default |
|--------|-------------|---------|
| `-r` | Follow links recursively | disabled |
| `-l DEPTH` | Max recursion depth (requires `-r`) | `5` |
| `-p PATH` | Directory to save images | `./data/` |

Supported extensions: `.jpg`, `.jpeg`, `.png`, `.gif`, `.bmp`

## Install

```bash
poetry install
```

## Examples

```bash
# Start a local server from the tests directory
cd tests && python3 -m http.server 8000
```

```bash
# Download images from a single page
poetry run spider https://books.toscrape.com/ # http://localhost:8000/index.html

# Recursively crawl up to 2 levels deep
poetry run spider -r -l 2 https://books.toscrape.com/ # http://localhost:8000/index.html

# Save to a custom folder
poetry run spider -r -p ./images https://books.toscrape.com/ # http://localhost:8000/index.html
```

## Tests

```bash
# Run tests
poetry run pytest
```
