# Iron Dome

A Linux daemon that watches directories for ransomware-like behavior.
It runs in the background and logs alerts to `/var/log/irondome/irondome.log`.

## What it detects

- **Entropy spikes** — files whose content suddenly becomes highly random
  (a common sign of encryption)
- **Cryptographic activity** — processes calling `getrandom()` (via `perf trace`)
  or reading `/dev/urandom` while writing to monitored directories
- **Disk read abuse** — sustained high read rates across physical disks

## Requirements

- Linux
- Python 3.10+
- Must be run as root
- Poetry

## Installation

```bash
poetry install
```

## Usage

```bash
# Monitor /home (default)
sudo poetry run irondome

# Monitor specific paths
sudo poetry run irondome /etc /var/www
```

The daemon writes a PID file to `/var/run/irondome.pid` and logs
all alerts to `/var/log/irondome/irondome.log`.

To stop it:

```bash
sudo kill $(sudo cat /var/run/irondome.pid)
```

## Running the tests

Integration tests launch the real daemon on a temporary directory, trigger
each type of alert with real commands (`dd`, `openssl`), then check
the log for expected entries. They require root.

```bash
sudo poetry run pytest -v
```

What they cover:
- **Entropy** — overwrite text files with random data, create new high-entropy files
- **Crypto** — encrypt files with `openssl enc` (reads `/dev/urandom`)
- **Disk read** — read 512 MB from a block device with `dd`


## Manual testing

Trigger an entropy alert (write random data to the monitored directory):

```bash
sudo dd if=/dev/urandom of=/home/test_entropy.bin bs=4096 count=2 && sudo rm /home/test_entropy.bin
```

Trigger a cryptographic activity alert (encrypt a file with openssl):

```bash
echo "test data" > /tmp/test.txt && sudo openssl enc -aes-256-cbc -in /tmp/test.txt -out /home/test.enc -pass pass:testpassword -pbkdf2 && sudo rm /home/test.enc
```

Trigger a disk read abuse alert (read 512 MB directly from disk):

```bash
sudo dd if=/dev/sda of=/dev/null bs=1M count=512 iflag=direct
```

Check the log:

```bash
sudo cat /var/log/irondome/irondome.log
```
