#!/usr/bin/env bash

$DNSPERF -p $port -s localhost -d ./add-zone/stress/tmp/list -c 10 -n 100 -S 10
