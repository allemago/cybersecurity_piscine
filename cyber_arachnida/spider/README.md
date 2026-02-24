# Spider

Command-line crawler that grabs images from a website, optionally following links on the same domain with a bounded depth. Uses `requests` + `BeautifulSoup` to fetch pages, collect image URLs, and save them locally with de-duplicated filenames.

## Features
- Downloads images with common extensions (`.jpg`, `.jpeg`, `.png`, `.gif`, `.bmp`) from a starting URL.
- Optional recursive mode restricted to the same domain; configurable depth `0-5` (default `5`).
- Saves files into a chosen folder, creating it if needed.
- Skips already-downloaded images to avoid duplicates.

## Requirements
- Python 3.10+ recommended.
- Dependencies: `requests`, `beautifulsoup4`.

Install deps:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install requests beautifulsoup4
./spider.py [options] <url>
deactivate
```

## Usage
Run from the project root:
```bash
./spider.py [options] <url>
```

Local testing with localhost:

Set `DEBUG = True` in `spider.py` if you want the default URL fallback to point to the local server.
```bash
cd test
python3 -m http.server 8000
# In another shell
../spider.py [options]
```

Options:
- `-r` – enable recursive crawl.
- `-l DEPTH` – max recursion depth when `-r` is set (`0-5`, default `5`).
- `-p PATH` – directory to save images (default `./data/`).

Examples:
```bash
# Single page download
./spider.py https://books.toscrape.com/

# Recursive crawl up to 2 levels, save under ./downloads
./spider.py -r -l 2 -p downloads https://books.toscrape.com/
```

The script validates that the URL has `http`/`https` and stays within the starting domain while crawling. Downloads are reported in the console; errors are printed but do not stop the crawl.

## Notes
- Depth flag `-l` requires `-r`; without recursion only the initial page is processed.
- Default URL in `DEBUG_URL` is used only when `DEBUG` is set to `True` and no URL is provided.
