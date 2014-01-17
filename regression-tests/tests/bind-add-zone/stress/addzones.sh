#!/usr/bin/env bash

for f in $(seq 1 $AMOUNT); do
    f=addzone$f.com
    dig ns1.$f @localhost -p $port > /dev/null 2>&1
    ../pdns/pdns_control --config-dir=. bind-add-zone $f $TMP/$f
    ../pdns/pdns_control --config-dir=. purge $f
    sleep 0.5;
    dig ns1.$f @localhost -p $port > /dev/null 2>&1

    RESULT=$(dig ns1.$f @localhost -p $port | grep -v '^ns1')
    if [ -z "$RESULT" ]; then
        echo "FAILED TO LOAD $f";
        exit 1;
    fi
done
