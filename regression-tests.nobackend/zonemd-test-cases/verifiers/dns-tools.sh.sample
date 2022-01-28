#!/bin/sh
set -e

origin=$1 ; shift
file=$1; shift

TF=`mktemp`
trap 'rm -f $TF' EXIT

/path/to/dns-tools verify --zone $origin --file $file 2>$TF
cat $TF
grep -q 'Zone Digest: Verified Successfully' $TF
