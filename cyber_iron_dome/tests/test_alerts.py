"""Integration tests that launch the real daemon and trigger alerts.

Must be run as root:
    sudo $(which poetry) run pytest tests/test_alerts.py -v
"""

import os
import sys
import time
import signal
import subprocess

import pytest
from pathlib import Path


LOG_PATH = "/var/log/irondome/irondome.log"
PID_FILE = "/var/run/irondome.pid"

requires_root = pytest.mark.skipif(
    os.getuid() != 0, reason="requires root"
)


def read_log():
    if os.path.exists(LOG_PATH):
        with open(LOG_PATH) as f:
            return f.read()
    return ""


@pytest.fixture(autouse=True)
def daemon(tmp_path):
    """Start irondome on tmp_path before each test, stop it after."""
    if os.getuid() != 0:
        yield
        return

    if os.path.exists(PID_FILE):
        with open(PID_FILE) as f:
            pid = int(f.read().strip())
        try:
            os.kill(pid, signal.SIGTERM)
            time.sleep(1)
        except ProcessLookupError:
            pass
        try:
            os.remove(PID_FILE)
        except OSError:
            pass

    os.makedirs("/var/log/irondome", exist_ok=True)

    irondome_bin = Path(sys.executable).parent / "irondome"
    subprocess.Popen(
        [str(irondome_bin), str(tmp_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(2)

    yield tmp_path

    if os.path.exists(PID_FILE):
        with open(PID_FILE) as f:
            pid = int(f.read().strip())
        try:
            os.kill(pid, signal.SIGTERM)
            time.sleep(1)
        except ProcessLookupError:
            pass


@requires_root
class TestEntropyDetection:

    def test_entropy_spike_on_overwritten_files(self, daemon):
        """Overwrite text files with random data: entropy alert logged."""
        tmp_path = daemon

        for i in range(5):
            p = tmp_path / f"file_{i}.txt"
            p.write_bytes(b"hello world " * 500)
        time.sleep(2)

        for i in range(5):
            p = tmp_path / f"file_{i}.txt"
            p.write_bytes(os.urandom(4096))
        time.sleep(3)

        log = read_log()
        assert "entropy" in log.lower(
        ), f"Expected entropy alert in log:\n{log}"

    def test_high_entropy_new_file(self, daemon):
        """Create a new file with random content: entropy alert logged."""
        tmp_path = daemon

        p = tmp_path / "random.bin"
        p.write_bytes(os.urandom(8192))
        time.sleep(3)

        log = read_log()
        assert "entropy" in log.lower(
        ), f"Expected entropy alert in log:\n{log}"


@requires_root
class TestCryptoDetection:

    def test_openssl_encryption_detected(self, daemon):
        """Encrypt files with openssl: crypto and entropy alerts logged."""
        tmp_path = daemon

        for i in range(10):
            p = tmp_path / f"crypto_{i}.txt"
            p.write_bytes(b"some data to encrypt\n" * 400)
        time.sleep(2)

        urandom_reader = subprocess.Popen(
            ["tail", "-f", "/dev/urandom"],
            stdout=subprocess.DEVNULL,
        )

        for i in range(10):
            subprocess.run(
                [
                    "openssl", "enc", "-aes-256-cbc",
                    "-in", str(tmp_path / f"crypto_{i}.txt"),
                    "-out", str(tmp_path / f"crypto_{i}.enc"),
                    "-pass", "pass:testpassword",
                    "-pbkdf2",
                ],
                capture_output=True,
            )
        time.sleep(3)
        urandom_reader.terminate()

        log = read_log()
        assert "entropy" in log.lower(), \
            f"Expected entropy alert in log:\n{log}"
        assert "cryptographic" in log.lower(), \
            f"Expected cryptographic activity alert in log:\n{log}"


@requires_root
class TestDiskReadAbuse:

    def test_high_disk_read_detected(self, daemon):
        """Read 512 MB from disk with dd: disk read alert logged."""
        devices = ["/dev/sda", "/dev/vda", "/dev/nvme0n1"]
        device = None
        for d in devices:
            if os.path.exists(d):
                device = d
                break

        if device is None:
            pytest.skip("No block device found for disk read test")

        subprocess.run(
            ["dd", f"if={device}", "of=/dev/null", "bs=1M", "count=512",
             "iflag=direct"],
            capture_output=True,
        )
        time.sleep(3)

        log = read_log()
        assert (
            "high disk read" in log.lower()
        ), f"Expected disk read alert in log:\n{log}"
