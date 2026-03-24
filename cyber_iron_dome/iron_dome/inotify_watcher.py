"""File system watcher using inotify with entropy-based anomaly detection."""

import os
import math
import logging as log

from inotify_simple import INotify, flags


class InotifyWatcher:
    """Watch directories recursively using inotify.

    On each file write, computes Shannon entropy and compares it to
    the stored baseline.
    Also checks for processes reading /dev/urandom to
    detect cryptographic activity.
    """

    ENTROPY_READ_SIZE = 65_536

    def __init__(self, path: list[str]) -> None:
        self._inotify = INotify()
        self._watch_flags = (
            flags.CREATE
            | flags.CLOSE_WRITE
            | flags.ISDIR
        )
        self._baseline_readers = self._get_urandom_readers()
        self._path: set[str] = set()
        self._file_entropy: dict[str, float] = {}
        self._wd_to_path: dict[int, str] = {}
        self._set_path_and_file(path)

    def _set_path_and_file(self, path: list[str]) -> None:
        """Walk each path and register watches + initial entropy.

        Args:
            path: List of file or directory paths to monitor.
        """
        for monitored_path in path:
            try:
                dir_path = self._get_dir_path(monitored_path)
                for root, _, files in os.walk(dir_path):
                    if root not in self._path:
                        self._set_path_and_wd(root)
                        self._set_file_and_entropy(root, files)
            except OSError as e:
                log.error(e)

    def _get_dir_path(self, monitored_path: str) -> str:
        """Return the directory for a given path, resolving files to parent.

        Args:
            monitored_path: Path to a file or directory.

        Returns:
            The directory path to watch.
        """
        dir_path = monitored_path
        if not os.path.exists(monitored_path):
            raise FileNotFoundError(
                f"{monitored_path}: not found - skipping"
            )

        if os.path.isfile(monitored_path):
            dir_path = os.path.dirname(monitored_path)
        return dir_path

    def _set_path_and_wd(self, root: str) -> None:
        """Add a directory to the watch list and map its watch descriptor.

        Args:
            root: Directory path to register with inotify.
        """
        self._path.add(root)
        wd = self._inotify.add_watch(root, self._watch_flags)
        self._wd_to_path[wd] = root

    def _set_file_and_entropy(self, root: str, files: list[str]) -> None:
        """Compute and store the initial entropy baseline for a list of files.

        Args:
            root: Parent directory of the files.
            files: Filenames to process (relative to root).
        """
        for file in files:
            full_path = os.path.join(root, file)
            if full_path not in self._file_entropy:
                try:
                    with open(full_path, 'rb') as f:
                        data = f.read(self.ENTROPY_READ_SIZE)
                except OSError:
                    pass
                else:
                    if data:
                        entropy = self._shannon_entropy(data)
                        self._file_entropy[full_path] = entropy

    def _join_path(self, wd: int, name: str) -> str:
        """Build the full path from a watch descriptor and a filename.

        Args:
            wd: inotify watch descriptor.
            name: Filename reported in the event.

        Returns:
            Absolute path to the file.
        """
        root_path = self._wd_to_path[wd]
        full_path = os.path.join(root_path, name)
        return full_path

    def _shannon_entropy(self, data: bytes) -> float:
        """Compute the Shannon entropy of a byte sequence.

        Args:
            data: Raw bytes to measure.

        Returns:
            Entropy value in bits per byte (0.0 to 8.0).
        """
        possible = dict(((chr(x), 0) for x in range(0, 256)))

        for byte in data:
            possible[chr(byte)] += 1

        data_len = len(data)
        entropy = 0.0

        for i in possible:
            if possible[i] == 0:
                continue

            p = float(possible[i] / data_len)
            entropy -= p * math.log2(p)
        return entropy

    def _detect_entropy_anomaly(self, full_path: str) -> None:
        """Check a file for suspicious entropy after a write event.

        Compares current entropy to the stored baseline and checks for
        processes reading /dev/urandom. Logs a warning on anomalies.

        Args:
            full_path: Absolute path to the file to inspect.
        """
        data = bytes()
        try:
            with open(full_path, "rb") as file:
                data = file.read(self.ENTROPY_READ_SIZE)
        except OSError:
            log.warning(f"File deleted after write: {full_path}")
        else:
            if not data:
                log.warning(f"File empty after write: {full_path}")
                return

            current_entropy = self._shannon_entropy(data)
            crypto_pids = self._get_urandom_readers() - self._baseline_readers

            if full_path not in self._file_entropy:
                if current_entropy > 7.5:
                    if crypto_pids:
                        log.warning(
                            f"Cryptographic activity detected: {full_path} "
                            f"(entropy: {current_entropy:.2f}, "
                            f"suspicious PIDs {crypto_pids})"
                        )
                    else:
                        log.warning(
                            f"New file high entropy detected: {full_path} "
                            f"(entropy: {current_entropy:.2f})"
                        )
            else:
                prev_entropy = self._file_entropy[full_path]
                delta = current_entropy - prev_entropy
                if current_entropy > 7.5 or delta > 1.5:
                    if crypto_pids:
                        log.warning(
                            f"Cryptographic activity detected: {full_path} "
                            f"({prev_entropy:.2f} -> {current_entropy:.2f}"
                            f", delta: {delta:.2f}"
                            f", suspicious PIDs: {crypto_pids})"
                        )
                    else:
                        log.warning(
                            f"High entropy detected: {full_path} "
                            f"({prev_entropy:.2f} -> {current_entropy:.2f}"
                            f", delta: {delta:.2f})"
                        )

            self._file_entropy[full_path] = current_entropy

    def inotify_events_monitoring(self) -> None:
        """Read pending inotify events and dispatch handlers."""
        for event in self._inotify.read():
            full_path = self._join_path(event.wd, event.name)

            if event.mask & flags.CREATE and event.mask & flags.ISDIR:
                self._set_path_and_file([full_path])

            if event.mask & flags.CLOSE_WRITE:
                self._detect_entropy_anomaly(full_path)

    @staticmethod
    def _get_urandom_readers() -> set[int]:
        """Return the set of PIDs that currently have /dev/urandom open."""
        pids = set()
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                for fd in os.scandir(f"/proc/{pid}/fd"):
                    if os.readlink(fd.path) == "/dev/urandom":
                        pids.add(int(pid))
                        break
            except OSError:
                pass
        return pids
