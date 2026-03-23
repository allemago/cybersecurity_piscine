"""Daemon entry point: sets up logging, monitoring threads, and inotify."""

import os
import sys
import logging as log
from threading import Thread

from src.inotify_watcher import InotifyWatcher

from src.monitors import (
    memory_usage_monitoring,
    disk_read_abuse_monitoring,
)


def main(path: list[str]) -> None:
    """Start the daemon: configure logging, spawn monitor threads, run watcher.

    Args:
        path: List of directories or files to watch.
    """
    try:
        log.basicConfig(
            filename="/var/log/irondome/irondome.log",
            encoding="utf-8",
            filemode="a",
            level=log.INFO,
            format="{asctime} - {levelname} - {message}",
            style="{",
            datefmt="%Y-%m-%d %H:%M",
        )
        log.info(
            f"Iron Dome daemon initialized - PID: {os.getpid()}, "
            f"Monitoring: {path}, Memory limit: 100 MB"
        )

        Thread(target=memory_usage_monitoring, daemon=True).start()
        Thread(target=disk_read_abuse_monitoring, daemon=True).start()

        inotify_watcher = InotifyWatcher(path)
        if not inotify_watcher._path:
            log.critical("No valid path to monitor - shutting down")
            raise ValueError("no valid path to monitor.")

        while True:
            inotify_watcher.inotify_events_monitoring()

    except Exception as e:
        print(f"{type(e).__name__}: {e}")
        sys.exit(1)
