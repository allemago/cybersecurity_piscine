#!/bin/bash

while true; do
    lftp -u myuser,mypass 192.168.1.2 <<EOF
put topsecret.txt
get topsecret.txt
bye
EOF
    sleep 2
done
