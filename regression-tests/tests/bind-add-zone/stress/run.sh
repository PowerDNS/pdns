#!/usr/bin/env bash
set -e
if [ "${PDNS_DEBUG}" = "YES" ]; then
  set -x
fi

PDNS=../pdns/pdns_server
AMOUNT=${1:-1000}
DNSPERF=${DNSPERF}
[ -z "$DNSPERF" ] && DNSPERF=$(which dnsperf)

ROOT=./add-zone/stress/tmp

if [ ! -x $PDNS ]; then
    echo "Could not find PDNS, run from ./regression-test"
    exit 1;
fi
if [ -z "$DNSPERF" -o ! -x "$DNSPERF" ]; then
    echo "Could not find DNSPERF"
    exit 1;
fi


bindwait ()
{
	check_process
	configname=$1
	domcount=$(grep -c zone named.conf)
	if [ ! -x $PDNSCONTROL ]; then
		echo "No pdns_control found"
		exit 1
	fi
	loopcount=0

	while [ $loopcount -lt 20 ]; do
		sleep 10
		done=$( ($PDNSCONTROL --config-name=$configname --socket-dir=. --no-config bind-domain-status || true) | grep -c 'parsed into memory' || true )
		if [ $done = $domcount ]; then
			return
		fi
		let loopcount=loopcount+1
	done

	if [ $done != $domcount ]; then
		echo "Domain parsing failed" >> failed_tests
	fi
}

check_process ()
{
	set +e
	loopcount=0
	while [ $loopcount -lt 5 ]; do
		sleep 1
		pids=$(cat pdns*.pid 2>/dev/null)
		if [ ! -z "$pids" ]; then
			kill -0 $pids >/dev/null 2>&1
			if [ $? -eq 0 ]; then
				set -e
				return
			fi
		fi
	let loopcount=loopcount+1
	done
	echo "PowerDNS did not start"
	exit 1
}

port=$1
[ -z "$port" ] && port=5300

mkdir $ROOT || :
TMP=$(mktemp -d --tmpdir=${ROOT})

onexit()
{
    rm -fr $TMP
    rm -f $ROOT/list
    kill $(cat pdns.pid)
}
trap 'onexit' SIGINT SIGKILL

AMOUNT=$AMOUNT TMP=$TMP ./add-zone/stress/createzones.sh

grep '^host' example.com | grep -e 'IN\s*A' | \
     sed -e 's/\t.*/.example.com A/g' | shuf > $ROOT/list

#cat $ROOT/list
#exit

$PDNS --daemon=no --local-port=$port --socket-dir=./ \
      --no-shuffle --launch=bind --bind-config=./named.conf \
      --fancy-records --cache-ttl=0 --no-config &
bindwait

DNSPERF=$DNSPERF port=$port ./add-zone/stress/dnsperf.sh &

AMOUNT=$AMOUNT TMP=$TMP port=$port ./add-zone/stress/addzones.sh

onexit
