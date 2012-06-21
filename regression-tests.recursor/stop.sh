#!/bin/sh
set -e
set -x

. ./vars

if [ -z "$PREFIX" ] 
then
    echo "config not found or PREFIX not set"
    exit 1
fi

cd configs

for dir in $PREFIX.* recursor-service
do
	svc -d $dir
	svc -k $dir
	svc -x $dir
done
