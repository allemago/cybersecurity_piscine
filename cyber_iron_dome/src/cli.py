"""CLI entry point: validates arguments and launches the daemon."""

import os
import sys
import signal
import platform
from argparse import ArgumentParser

import daemon
from daemon.pidfile import PIDLockFile
from lockfile import LockError

from src.iron_dome import main


def shutdown() -> None:
    """Handle SIGTERM by exiting cleanly."""
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


def run() -> None:
    """Validate the runtime environment and start the daemon."""
    if platform.system() != "Linux":
        print("Error: this program is only compatible with Linux systems.")
        sys.exit(1)

    if os.getuid() != 0:
        print("Error: program must be executed as root.")
        sys.exit(1)

    try:
        path = validate_args()
        os.makedirs("/var/log/irondome", exist_ok=True)
    except OSError as e:
        print(f"Error: {e}")
        sys.exit(1)

    try:
        with daemon.DaemonContext(
            pidfile=PIDLockFile('/var/run/irondome.pid'),
            umask=0o077,
            stderr=open('/var/log/irondome/irondome_error.log', 'a'),
            signal_map={
                signal.SIGTERM: shutdown,
            }
        ):
            main(path)
    except LockError as e:
        print(f"{type(e).__name__}: {e}", file=sys.stderr)
        sys.exit(1)
