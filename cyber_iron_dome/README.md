# Iron Dome

A Linux daemon that watches directories for ransomware-like behavior.
It runs in the background and logs alerts to `/var/log/irondome/irondome.log`.

## What it detects

- **Entropy spikes** — files whose content suddenly becomes highly random
  (a common sign of encryption)
- **Cryptographic activity** — processes reading `/dev/urandom` while
  writing to monitored directories
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
sudo $(which poetry) run irondome

# Monitor specific paths
sudo $(which poetry) run irondome /etc /var/www
```

The daemon writes a PID file to `/var/run/irondome.pid` and logs
all alerts to `/var/log/irondome/irondome.log`.

To stop it:

```bash
sudo kill $(sudo cat /var/run/irondome.pid)
```

## Running the tests

```bash
sudo $(which poetry) run pytest -v --log-cli-level=DEBUG
```
