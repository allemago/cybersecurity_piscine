class SpiderState:
    """Tracks crawl configuration and visited/downloaded URLs."""

    def __init__(self, is_recursive: bool, depth: int, path: str):
        """Initialize the spider state.

        Args:
            is_recursive: Whether the crawl follows links recursively.
            depth: Maximum recursion depth allowed.
            path: Directory path where downloaded images are saved.
        """
        self.base_netloc = ""
        self.is_recursive = is_recursive
        self.max_depth = depth
        self.path = path
        self.visited = set()
        self.dl_imgs = set()

    def has_visited(self, url: str) -> bool:
        """Check whether a page URL has already been crawled.

        Args:
            url: The page URL to look up.

        Returns:
            True if the URL was already visited, False otherwise.
        """
        return url in self.visited

    def mark_visited(self, url: str) -> None:
        """Record a page URL as visited.

        Args:
            url: The page URL to mark.
        """
        self.visited.add(url)

    def has_downloaded(self, img_url: str) -> bool:
        """Check whether an image URL has already been downloaded.

        Args:
            img_url: The image URL to look up.

        Returns:
            True if the image was already downloaded, False otherwise.
        """
        return img_url in self.dl_imgs

    def mark_downloaded(self, img_url: str) -> None:
        """Record an image URL as downloaded.

        Args:
            img_url: The image URL to mark.
        """
        self.dl_imgs.add(img_url)
