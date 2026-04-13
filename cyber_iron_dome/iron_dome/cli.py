"""CLI entry point: validates arguments and launches the daemon."""

import os
import sys
import signal
import platform
import logging as log
from argparse import ArgumentParser

import daemon
from daemon.pidfile import PIDLockFile
from lockfile import LockError

from iron_dome.daemon import main


def shutdown(signum, frame) -> None:
    """Handle SIGTERM by exiting cleanly."""
    try:
        with open("/var/run/irondome_perf.pid") as file:
            pid = int(file.read().strip())
        os.unlink("/var/run/irondome_perf.pid")
        os.kill(pid, signal.SIGTERM)
    except (OSError, ValueError):
        pass
    log.info("Iron Dome daemon stopped (SIGTERM received)")
    log.shutdown()
    sys.exit(0)


def validate_args() -> list[str]:
    """Parse and resolve CLI paths.

    Returns:
        List of absolute paths to monitor.
    """
    description = (
        "Iron Dome - Monitor files/directories "
        "for ransomware-like behavior on Linux."
    )
    parser = ArgumentParser(description=description)
    parser.add_argument(
        "path",
        nargs="*",
        default=["/home"],
        metavar="PATH",
        help="One or more file/directory paths"
    )

    args = parser.parse_args()

    args.path = [os.path.realpath(path) for path in args.path]

    return args.path


def run() -> int:
    """Validate the runtime environment and start the daemon."""
    if platform.system() != "Linux":
        print("Error: this program is only compatible with Linux systems.")
        return 1

    if os.getuid() != 0:
        print("Error: program must be executed as root.")
        return 1

    try:
        path = validate_args()
        os.makedirs("/var/log/irondome", exist_ok=True)
    except OSError as e:
        print(f"Error: {e}")
        return 1

    try:
        with daemon.DaemonContext(
            pidfile=PIDLockFile('/var/run/irondome.pid'),
            umask=0o077,
            stderr=open('/var/log/irondome/irondome_error.log', 'a'),
            signal_map={
                signal.SIGINT: shutdown,
                signal.SIGTERM: shutdown,
            }
        ):
            main(path)
    except LockError as e:
        print(f"{type(e).__name__}: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(
            f"{type(e).__name__}: an unexpected error occured", file=sys.stderr
        )
        return 1

    return 0
