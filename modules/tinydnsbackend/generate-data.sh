#!/usr/bin/env bash
set -exu

# You'll need the following binaries
# `tcpclient`    : from the `ucspi-tcp` package (https://cr.yp.to/ucspi-tcp.html)
# `axfr-get`     : https://cr.yp.to/djbdns.html
# `tinydns-data` : ^ also from the djbdns package

startdir=`pwd`
TCPCLIENT=${TCPCLIENT:-tcpclient}
AXFRGET=${AXFRGET:-axfr-get}
TINYDNSDATA=${TINYDNSDATA:-tinydns-data}

# Copy original zones because the test might modify them (well only the dyndns stuff, but let's make this work for others as well)
for zone in $(grep 'zone ' ../../regression-tests/named.conf | cut -f2 -d\")
do
  if [ -f ../../regression-tests/zones/$zone.orig ]
  then
    cp -f ../../regression-tests/zones/$zone.orig ../../regression-tests/zones/$zone
  fi
done


# CD to regression testt because named.conf has relative paths.
cd ../../regression-tests
../pdns/pdns_server --daemon=no --local-port=5300 --socket-dir=./ \
  --no-shuffle --launch=bind --bind-config=../regression-tests/named.conf \
  --query-logging --loglevel=0 \
  --cache-ttl=0 --no-config --local-address=127.0.0.1 \
  --bind-ignore-broken-records=yes --module-dir=modules &

# wait for pdns to start up
sleep 5


cd $startdir
[ -e data ] && rm data

for zone in $(grep 'zone ' ../../regression-tests/named.conf | cut -f2 -d\")
do
  $TCPCLIENT 127.0.0.1 5300 $AXFRGET $zone $zone.out $zone.out.tmp
  LC_ALL=C sort $zone.out >> data
  rm $zone.out
done

$TINYDNSDATA

kill $(cat ../../regression-tests/pdns.pid)
