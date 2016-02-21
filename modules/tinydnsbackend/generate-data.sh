#!/usr/bin/env bash
set -exu

startdir=`pwd`
tcpclient=/usr/bin/tcpclient
axfrget=$1
tinydnsdata=$2

[ -z "$axfrget" ] && axfrget=/service/tinydns/bin/axfr-get
[ -z "$tinydnsdata" ] && tinydnsdata=/service/tinydns/bin/tinydns-data



if [ ! -x $axfrget ] || [ "$axfrget" = help ] || [ ! -x $tinydnsdata ] || [ "$tinydnsdata" = help ]
then
  echo "Usage: ./generate-data.sh <axfr-get location> <tinydns-data location>";
  exit 1
fi


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
  --query-logging --send-root-referral --loglevel=0 \
  --cache-ttl=0 --no-config --local-address=127.0.0.1 \
  --bind-ignore-broken-records=yes &

# wait for pdns to start up
sleep 5


cd $startdir
[ -e data ] && rm data

for zone in $(grep 'zone ' ../../regression-tests/named.conf | cut -f2 -d\")
do
  $tcpclient 127.0.0.1 5300 $axfrget $zone $zone.out $zone.out.tmp
  cat $zone.out >> data
  rm $zone.out
done

$tinydnsdata  

kill $(cat ../../regression-tests/pdns.pid)
