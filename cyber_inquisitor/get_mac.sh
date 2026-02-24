#!/bin/bash
set -eux

MAC_CLIENT=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.MacAddress}}{{end}}' client)
MAC_SERVER=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.MacAddress}}{{end}}' server)

echo "$MAC_CLIENT"
echo "$MAC_SERVER"
