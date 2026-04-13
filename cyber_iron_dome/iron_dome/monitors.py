"""Background threads for memory and disk I/O monitoring."""

import os
import time
import signal
import subprocess
import logging as log

PHYSICAL_DISK_MAJORS = {8, 65, 66, 67, 252, 253, 259}


def get_memory_usage() -> int:
    """Return current RSS memory usage in MB."""
    with open("/proc/self/status") as file:
        for line in file:
            if line.startswith("VmRSS"):
                parts = line.split()
                memory_kb = int(parts[1])
                return int(memory_kb / 1024)
    return 0


def memory_usage_monitoring() -> None:
    """Poll RSS every 5s; kill the daemon if usage exceeds 100 MB."""
    while True:
        memory_usage = get_memory_usage()
        if memory_usage > 100:
            log.critical(
                f"Memory limit exceeded: {memory_usage:} MB / 100 MB "
            )
            os.kill(os.getpid(), signal.SIGTERM)
        elif memory_usage > 80:
            log.warning(f"Memory usage high: {memory_usage} MB / 100 MB")
        time.sleep(5)


def get_disk_sectors_read() -> int:
    """Return total sectors read across all physical disks."""
    total = 0
    with open("/proc/diskstats") as file:
        for line in file:
            parts = line.split()
            major = int(parts[0])
            minor = int(parts[1])
            if major in PHYSICAL_DISK_MAJORS and minor % 16 == 0:
                total += int(parts[5])
    return total


def disk_read_abuse_monitoring() -> None:
    """Check disk read rate every second; warn if it exceeds 100 MB/s."""
    prev_sectors_read = get_disk_sectors_read()
    prev_timestamp = time.time()
    while True:
        time.sleep(1)
        current_sectors_read = get_disk_sectors_read()
        current_timestamp = time.time()

        sectors_delta = current_sectors_read - prev_sectors_read
        time_delta = current_timestamp - prev_timestamp

        bytes_read = sectors_delta * 512
        mb_read = bytes_read / (1024 * 1024)
        read_rate_mb_s = mb_read / time_delta

        if read_rate_mb_s > 100:
            log.critical(f"High disk read activity: {read_rate_mb_s:.2f} MB/s")

        prev_sectors_read = current_sectors_read
        prev_timestamp = current_timestamp


def cryptographic_activity_monitoring() -> None:
    proc = subprocess.Popen(
        ["perf", "trace", "-e", "getrandom"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )

    try:
        with open("/var/run/irondome_perf.pid", "w") as file:
            file.write(str(proc.pid))
    except OSError as e:
        log.warning(f"Could not write perf PID ({proc.pid}) file: {e}")

    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            if "getrandom" in line:
                log.critical(
                    f"Cryptographic activity, getrandom() detected: {line}"
                )
    except OSError:
        pass
    finally:
        proc.terminate()
        proc.wait()
