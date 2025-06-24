#!/bin/sh

for f in ./payload.*; do
    mosquitto_pub -h localhost -p 1883 -t "my/topic" -f "$f"
done
