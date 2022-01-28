#!/bin/sh
set -e

origin=$1 ; shift
file=$1; shift

$PDNSUTIL zonemd-verify-file $origin $file
