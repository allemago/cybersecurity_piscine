"""Command-line interface for the vaccine SQL injection scanner."""
from argparse import ArgumentParser, Namespace
from requests.exceptions import RequestException

from vaccine.sqli_scanner import SqliScanner


def validate_args() -> Namespace:
    """
    Parse and return command-line arguments.

    Returns:
        Namespace with attributes: url, method, output, cookies.
    """
    description = "Vaccine - SQL injection detection tool"
    parser = ArgumentParser(description=description)
    parser.add_argument(
        "-o",
        dest="output",
        type=str,
        default="output.json",
        help="Output file (default: output.json)",
    )
    parser.add_argument(
        "-X",
        dest="method",
        type=str,
        default="GET",
        help="HTTP method: GET or POST (default: GET)",
    )
    parser.add_argument(
        "-C",
        dest="cookies",
        type=str,
        default=None,
        help='Cookies string ("PHPSESSID=abc; security=low")',
    )
    parser.add_argument(
        "url",
        type=str,
        help="Target URL to test",
    )
    args = parser.parse_args()
    return args


def run() -> int:
    """
    Entry point for the vaccine CLI.

    Parses arguments, runs the scanner, and handles top-level errors.

    Returns:
        0 on success or clean exit, 1 on error.
    """
    try:
        args = validate_args()
        scan = SqliScanner(args.url, args.method, args.output, args.cookies)
        scan._sql_injection()
        return 0
    except KeyboardInterrupt as e:
        print(f"{type(e).__name__}: shutting down.")
        return 0
    except RequestException:
        return 1
    except (ValueError, OSError, Exception) as e:
        print(f"{type(e).__name__}: {e}")
        return 1
