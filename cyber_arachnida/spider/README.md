# Spider

Downloads images from a website, optionally following links recursively.

## Usage

```
spider [-r] [-l DEPTH] [-p PATH] URL
```

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
# Download images from a single page
poetry run spider https://example.com

# Recursively crawl up to 2 levels deep
poetry run spider -r -l 2 https://example.com

# Save to a custom folder
poetry run spider -r -p ./images https://example.com
```

## Tests

```bash
# Start a local server from the tests directory
cd tests && python3 -m http.server 8000

# Run tests
poetry run pytest
```
