import os
import sys
import time
import signal
import subprocess
import logging
import pytest
from pathlib import Path
from unittest.mock import patch

from src.inotify_watcher import InotifyWatcher
from src.monitors import (
    memory_usage_monitoring,
    disk_read_abuse_monitoring,
)

LOG_PATH = "/var/log/irondome/irondome.log"


def make_watcher(tmp_path):
    return InotifyWatcher([str(tmp_path)])


# Shannon entropy

class TestShannonEntropy:

    def test_uniform_bytes_zero_entropy(self, tmp_path):
        """All identical bytes: entropy = 0"""
        watcher = make_watcher(tmp_path)
        assert watcher._shannon_entropy(b'\x00' * 1000) == 0.0

    def test_all_byte_values_max_entropy(self, tmp_path):
        """All 256 byte values equally distributed: entropy ~8.0"""
        watcher = make_watcher(tmp_path)
        data = bytes(range(256)) * 4
        assert watcher._shannon_entropy(data) > 7.9

    def test_plaintext_low_entropy(self, tmp_path):
        """Readable text: entropy < 5.0"""
        watcher = make_watcher(tmp_path)
        assert watcher._shannon_entropy(b"hello world " * 200) < 5.0

    def test_random_bytes_high_entropy(self, tmp_path):
        """Random bytes: entropy > 7.5"""
        watcher = make_watcher(tmp_path)
        assert watcher._shannon_entropy(os.urandom(4096)) > 7.5


# Entropy anomaly detection

class TestEntropyAnomalyDetection:

    def test_no_alert_low_entropy_new_file(self, tmp_path, caplog):
        """New file with low entropy: no alert"""
        watcher = make_watcher(tmp_path)
        f = tmp_path / "plain.txt"
        f.write_bytes(b"hello world " * 500)
        with caplog.at_level(logging.WARNING):
            watcher._detect_entropy_anomaly(str(f))
        assert "detected" not in caplog.text.lower()

    def test_alert_high_entropy_new_file(self, tmp_path, caplog):
        """New file with entropy > 7.5: alert logged"""
        watcher = make_watcher(tmp_path)
        f = tmp_path / "encrypted.bin"
        f.write_bytes(os.urandom(4096))
        with caplog.at_level(logging.WARNING):
            watcher._detect_entropy_anomaly(str(f))
        assert "entropy" in caplog.text.lower()

    def test_alert_entropy_spike_on_known_file(self, tmp_path, caplog):
        """Known file whose entropy jumps by > 1.5: alert logged"""
        watcher = make_watcher(tmp_path)
        f = tmp_path / "file.bin"
        f.write_bytes(b"aaaa" * 1000)
        watcher._file_entropy[str(f)] = 0.5
        f.write_bytes(os.urandom(4096))
        with caplog.at_level(logging.WARNING):
            watcher._detect_entropy_anomaly(str(f))
        assert "detected" in caplog.text.lower()

    def test_entropy_updated_after_check(self, tmp_path):
        """Entropy baseline is updated after each check"""
        watcher = make_watcher(tmp_path)
        f = tmp_path / "file.bin"
        f.write_bytes(b"aaaa" * 1000)
        watcher._detect_entropy_anomaly(str(f))
        assert str(f) in watcher._file_entropy

    def test_deleted_file_logs_warning(self, tmp_path, caplog):
        """File deleted before read: warning, no crash"""
        watcher = make_watcher(tmp_path)
        ghost = str(tmp_path / "ghost.txt")
        with caplog.at_level(logging.WARNING):
            watcher._detect_entropy_anomaly(ghost)
        assert "deleted" in caplog.text.lower()

    def test_empty_file_logs_warning(self, tmp_path, caplog):
        """Empty file after write: warning, no crash"""
        watcher = make_watcher(tmp_path)
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")
        with caplog.at_level(logging.WARNING):
            watcher._detect_entropy_anomaly(str(f))
        assert "empty" in caplog.text.lower()

    def test_crypto_activity_logs_warning(self, tmp_path, caplog):
        """High-entropy write + new /dev/urandom reader: crypto alert"""
        watcher = make_watcher(tmp_path)
        f = tmp_path / "encrypted.bin"
        f.write_bytes(os.urandom(4096))
        fake_readers = watcher._baseline_readers | {99999}
        with patch.object(
            InotifyWatcher, "_get_urandom_readers",
            return_value=fake_readers
        ):
            with caplog.at_level(logging.WARNING):
                watcher._detect_entropy_anomaly(str(f))
        assert "cryptographic activity" in caplog.text.lower()


# Memory monitoring

class TestMemoryMonitoring:

    def test_memory_above_limit_logs_critical(self, caplog):
        """Memory > 100 MB: critical logged"""
        with patch("src.monitors.get_memory_usage",
                   return_value=101):
            with patch("src.monitors.time.sleep",
                       side_effect=StopIteration):
                with caplog.at_level(logging.CRITICAL):
                    try:
                        memory_usage_monitoring()
                    except StopIteration:
                        pass
        assert "memory limit exceeded" in caplog.text.lower()

    def test_memory_below_limit_no_critical(self, caplog):
        """Memory < 80 MB: no critical logged"""
        with patch("src.monitors.get_memory_usage",
                   side_effect=[50, StopIteration]):
            with patch("src.monitors.time.sleep"):
                with caplog.at_level(logging.CRITICAL):
                    try:
                        memory_usage_monitoring()
                    except StopIteration:
                        pass
        assert "memory limit exceeded" not in caplog.text.lower()


# Disk read monitoring

class TestDiskReadMonitoring:

    def _run_one_iteration(self, sectors_before, sectors_after, elapsed):
        time_values = iter([0.0, elapsed])
        sector_values = iter([sectors_before, sectors_after])

        with patch("src.monitors.get_disk_sectors_read",
                   side_effect=sector_values):
            with patch("src.monitors.time.sleep"):
                with patch("src.monitors.time.time",
                           side_effect=time_values):
                    try:
                        disk_read_abuse_monitoring()
                    except StopIteration:
                        pass

    def test_high_disk_read_logs_warning(self, caplog):
        """200 MB/s disk read rate: warning logged"""
        sectors_200mb = (200 * 1024 * 1024) // 512
        with caplog.at_level(logging.WARNING):
            self._run_one_iteration(0, sectors_200mb, 1.0)
        assert "High disk read" in caplog.text

    def test_low_disk_read_no_warning(self, caplog):
        """10 MB/s disk read rate: no warning"""
        sectors_10mb = (10 * 1024 * 1024) // 512
        with caplog.at_level(logging.WARNING):
            self._run_one_iteration(0, sectors_10mb, 1.0)
        assert "High disk read" not in caplog.text


# Path handling

class TestPathHandling:

    def test_nonexistent_path_logs_error(self, tmp_path, caplog):
        """Nonexistent path: error logged, no crash"""
        watcher = make_watcher(tmp_path)
        with caplog.at_level(logging.ERROR):
            watcher._set_path_and_file(["/nonexistent/path/xyz"])
        assert (
            "nonexistent" in caplog.text.lower()
            or "not found" in caplog.text.lower()
        )

    def test_nonexistent_path_not_registered(self, tmp_path):
        """Nonexistent path: not added to monitored paths"""
        watcher = make_watcher(tmp_path)
        before = set(watcher._path)
        watcher._set_path_and_file(["/nonexistent/path/xyz"])
        assert watcher._path == before

    def test_file_path_monitors_parent_directory(self, tmp_path):
        """Monitoring a file path: parent directory is watched"""
        f = tmp_path / "file.txt"
        f.write_text("hello")
        watcher = InotifyWatcher([str(f)])
        assert str(tmp_path) in watcher._path

    def test_multiple_paths_all_monitored(self, tmp_path):
        """Multiple valid paths: all directories registered"""
        dir1 = tmp_path / "dir1"
        dir2 = tmp_path / "dir2"
        dir1.mkdir()
        dir2.mkdir()
        watcher = InotifyWatcher([str(dir1), str(dir2)])
        assert str(dir1) in watcher._path
        assert str(dir2) in watcher._path

    def test_subdirectories_are_monitored(self, tmp_path):
        """os.walk: subdirectories are recursively registered"""
        sub = tmp_path / "sub"
        sub.mkdir()
        watcher = InotifyWatcher([str(tmp_path)])
        assert str(sub) in watcher._path

    def test_initial_file_entropy_computed(self, tmp_path):
        """Files present at startup: entropy baseline stored"""
        f = tmp_path / "existing.txt"
        f.write_bytes(b"hello world " * 100)
        watcher = InotifyWatcher([str(tmp_path)])
        assert str(f) in watcher._file_entropy


# Integration

class TestFullWorkflow:

    PID_FILE = "/var/run/irondome.pid"

    def setup_method(self):
        if os.getuid() != 0:
            return
        os.makedirs("/var/log/irondome", exist_ok=True)
        if os.path.exists(LOG_PATH):
            os.remove(LOG_PATH)

    def teardown_method(self):
        if os.path.exists(self.PID_FILE):
            with open(self.PID_FILE) as f:
                pid = int(f.read().strip())
            os.kill(pid, signal.SIGTERM)

    def test(self, tmp_path):
        """Writing a high-entropy file: alert appears in irondome.log"""
        if os.getuid() != 0:
            pytest.skip("Integration test requires root")

        irondome_bin = Path(sys.executable).parent / "irondome"
        subprocess.Popen(
            [str(irondome_bin), str(tmp_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(1)

        encrypted = tmp_path / "secret.bin"
        encrypted.write_bytes(os.urandom(4096))
        time.sleep(2)

        assert os.path.exists(LOG_PATH)
        log_content = open(LOG_PATH).read()
        assert (
            "entropy" in log_content.lower()
            or "cryptographic" in log_content.lower()
        )
