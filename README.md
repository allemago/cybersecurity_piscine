# Cybersecurity Piscine - 42

A series of small projects covering different areas of cybersecurity, done as part of the 42 school curriculum. Each module is self-contained and focuses on a specific concept.

---

## Modules

### cyber_arachnida - Web Scraping & Metadata
Two tools built around image handling:
- **spider**: crawls a website recursively and downloads images up to a configurable depth
- **scorpion**: reads and displays EXIF metadata from image files

### cyber_ft_otp - One-Time Passwords
Implementation of a TOTP system (Time-based One-Time Password) following RFC 6238. Takes a hex key, stores it encrypted, and generates a fresh 6-digit code every 30 seconds - compatible with standard authenticator apps.

### cyber_ft_onion - Tor Hidden Service
Docker Compose setup that runs a small web server (nginx) accessible only through the Tor network, with SSH access. The goal is to understand how .onion addresses work and how to route traffic through Tor.

### cyber_reverse_me - Reverse Engineering
Three small compiled binaries to analyze. Each one hides a password that has to be found through static or dynamic analysis - no source code provided.

### cyber_stockholm - Ransomware Simulation
Educational simulation of how ransomware works. The program encrypts files in a target directory using a generated key, appending `.ft` to each filename. The `-r` flag decrypts them back. Runs in Docker.

### cyber_iron_dome - Ransomware Detection
A Linux daemon that monitors the filesystem for signs of ransomware activity: high entropy writes, mass file modifications, known crypto patterns. Written in Python using inotify.

---

## Stack

- **Languages**: Python, C++, C
- **Tools**: Docker, Docker Compose, Tor, Nginx, Poetry
- **Concepts**: TOTP/HOTP, AES encryption, filesystem monitoring, reverse engineering, .onion services, web scraping

---

## Structure

```
cybersecurity_piscine/
├── cyber_arachnida/
├── cyber_ft_otp/
├── cyber_ft_onion/
├── cyber_reverse_me/
├── cyber_stockholm/
└── cyber_iron_dome/
```

Each module has its own README with setup and usage instructions.

---

> All offensive tools in this repo (stockholm, arachnida) are strictly educational and designed to run in isolated environments.
