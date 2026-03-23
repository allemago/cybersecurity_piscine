# inquisitor

ARP spoofing tool that intercepts traffic between two hosts on a local network.
It poisons the ARP tables of both hosts so their traffic flows through the
machine running inquisitor. FTP file transfers are displayed in real time.
ARP tables are restored when the program exits.

## Requirements

- Linux
- Docker
- Make

## Usage

```
make
```

This builds and starts three containers on an isolated network:

- **server** - vsftpd FTP server at `192.168.1.2`
- **client** - repeatedly uploads and downloads a file over FTP
- **inquisitor** - poisons the ARP tables and prints intercepted transfers

The MAC addresses of the client and server are retrieved automatically.

To stop the attack and restore ARP tables:

```
make kill
```

Or press `CTRL+C` in the inquisitor container's terminal.

To stop and remove all containers:

```
make down
```

## Parameters

The `inquisitor` binary takes four arguments:

```
inquisitor <IP-src> <MAC-src> <IP-target> <MAC-target>
```

| Argument | Description |
|---|---|
| `IP-src` | IP address of the first host |
| `MAC-src` | MAC address of the first host |
| `IP-target` | IP address of the second host |
| `MAC-target` | MAC address of the second host |

Only IPv4 addresses are supported.
