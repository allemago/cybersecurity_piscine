from urllib.parse import urlparse, urlunparse

from urllib.robotparser import RobotFileParser

from src.console import Color

USER_AGENT = "SpiderBot/1.0"


def load_robots_txt(url: str) -> RobotFileParser | None:
    """Fetch and parse the robots.txt file for a given URL's domain.

    Args:
        url: Any URL belonging to the target domain.

    Returns:
        A populated RobotFileParser, or None if the file could not
        be retrieved.
    """
    robots = RobotFileParser()
    try:
        parsed = urlparse(url)
        robots_url = urlunparse(
            (parsed.scheme, parsed.netloc, "/robots.txt", "", "", ""))
        robots.set_url(robots_url)
        robots.read()
    except Exception as e:
        print(
            f"{Color.YELLOW}Warning:{Color.RESET} "
            f"unable to read robots.txt ({e}), continuing without it."
        )
        return None
    return robots


def is_allowed_by_robots(url: str, robots: RobotFileParser | None) -> bool:
    """Check whether robots.txt permits fetching a URL.

    Args:
        url: The URL to check.
        robots: A parsed RobotFileParser, or None if unavailable.

    Returns:
        True if no robots parser is loaded or if the URL is allowed.
    """
    if robots is None:
        return True
    return robots.can_fetch(USER_AGENT, url)
