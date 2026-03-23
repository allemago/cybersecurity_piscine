#!/bin/bash
echo "root:$ROOT_PASSWORD" | chpasswd
exec "$@"
