#!/bin/bash
set -eu

exec poetry run inquisitor $IP_SERVER $MAC_SERVER $IP_CLIENT $MAC_CLIENT
