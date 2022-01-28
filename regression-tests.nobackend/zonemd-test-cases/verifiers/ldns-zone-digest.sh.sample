#!/bin/sh
set -e

origin=$1 ; shift
file=$1; shift

# If ldns-zone-digest was linked against a specific ldns library version,
# might need to set LD_LIBRARY_PATH here
#
# export LD_LIBRARY_PATH=/usr/local/lib
/path/to/ldns-zone-digest -v $origin $file
