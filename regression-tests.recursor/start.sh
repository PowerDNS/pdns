#!/bin/sh
set -e
set -x

. ./test.vars
. ./vars

if [ -z "$PREFIX" ] 
then
    echo "config not found or PREFIX not set"
    exit 1
fi

cd configs

for dir in $PREFIX.* recursor-service
do
	supervise $dir &
done

sleep 1
