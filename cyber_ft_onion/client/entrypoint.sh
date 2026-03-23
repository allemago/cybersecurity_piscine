#!/bin/bash
tor &

echo "Waiting for Tor to start..."
sleep 10

exec "$@"
