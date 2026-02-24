#!/bin/bash
set -eu

IP_CLIENT="192.168.1.2"
IP_SERVER="192.168.1.1"

poetry run inquisitor $IP_SERVER $MAC_SERVER $IP_CLIENT $MAC_CLIENT
