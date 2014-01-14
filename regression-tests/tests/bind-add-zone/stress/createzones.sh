#!/usr/bin/env bash

for f in $(seq 1 $AMOUNT); do
    f=addzone$f.com
    sed -e "s/addzone.com/$f/g" addzone.com > $TMP/$f
done
