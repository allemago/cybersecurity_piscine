import os
import sys
import time
import platform
from argparse import ArgumentParser

import pcap
import dpkt


def validate_args():
    return


def run() -> None:
    if platform.system() != "Linux":
        print("Error: this program is only compatible with Linux systems.")
        sys.exit(1)

    try:
        validate_args()
    except OSError as e:
        print(f"{type(e).__name__}: {e}")
        sys.exit(1)


# args:

# IP source (la cible, ex: le client FTP)
# MAC source (MAC de la cible)
# IP destination (le gateway ou le serveur FTP)
# MAC destination (MAC du gateway/serveur)
