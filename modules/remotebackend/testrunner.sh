#!/usr/bin/env bash
new_api=0
mode=$1

# keep the original arguments for new test harness api
orig="$*"

# we could be ran with new API
while [ "$1" != "" ]
do
 if [ "$1" == "--" ]; then
   new_api=1
   mode=$2
   break
 fi
 shift
done

webrick_pid=""
socat_pid=""
zeromq_pid=""
socat=$(which socat)

function start_web() {
  local service_logfile="${mode%\.test}_server.log"

  ./unittest_${1}.rb >> ${service_logfile} 2>&1 &
  webrick_pid=$!

  local timeout=0
  while [ ${timeout} -lt 20 ]; do
    local res=$(curl http://localhost:62434/ping 2>/dev/null)
    if [ "x$res" == "xpong" ]; then
      # server is up and running
      return 0
    fi

    sleep 1
    let timeout=timeout+1
  done

  if kill -0 ${webrick_pid} 2>/dev/null; then
    # if something is wrong with curl (i.e. curl isn't installed, localhost is firewalled ...)
    # the status check will fail -- cleanup required!
    echo >&2 "WARNING: Timeout (${timeout}s) reached: \"${1}\" test service process is running but status check failed"
    kill -KILL ${webrick_pid} 2>/dev/null
  fi

  echo >&2 "ERROR: A timeout (${timeout}s) was reached while waiting for \"${1}\" test service to start!"
  echo >&2 "       See \"modules/remotebackend/${service_logfile}\" for more details."
  exit 69
}

function stop_web() {
  if [ -z "${webrick_pid}" ]; then
    # should never happen - why was stop_web() called?
    echo >&2 "ERROR: Unable to stop \"${1}\" test service: Did we ever start the service?"
    exit 99
  fi

  if ! kill -0 ${webrick_pid} 2>/dev/null; then
    # should never happen - did the test crashed the service?
    echo >&2 "ERROR: Unable to stop \"${1}\" test service: service (${webrick_pid}) not running"
    exit 69
  fi

  kill -TERM ${webrick_pid}
  local timeout=0
  while [ ${timeout} -lt 5 ]; do
    if ! kill -0 ${webrick_pid} 2>/dev/null; then
      # service was stopped
      return 0
    fi

    sleep 1
    let timeout=timeout+1
  done

  if kill -0 ${webrick_pid} 2>/dev/null; then
    echo >&2 "WARNING: Timeout (${timeout}s) reached - killing \"${1}\" test service ..."
    kill -KILL ${webrick_pid} 2>/dev/null
    return $?
  fi
}

function start_zeromq() {
  if [ x"$REMOTEBACKEND_ZEROMQ" != "xyes" ]; then
    echo "INFO: Skipping \"ZeroMQ\" test because PowerDNS was built without \"--enable-remotebackend-zeromq\"!"
    exit 77
  fi

  local service_logfile="${mode%\.test}_server.log"

  ./unittest_zeromq.rb >> ${service_logfile} 2>&1 &
  zeromq_pid=$!

  local timeout=0
  while [ ${timeout} -lt 5 ]; do
    if [ -S "/tmp/remotebackend.0" ]; then
      # service is up and running
      return 0
    fi

    sleep 1
    let timeout=timeout+1
  done

  if kill -0 ${zeromq_pid} 2>/dev/null; then
    # not sure when this can happen but we should cleanup any process we started
    echo >&2 "WARNING: Timeout (${timeout}s) reached: \"ZeroMQ\" test service process is running but status check failed"
    kill -KILL ${zeromq_pid} 2>/dev/null
  fi

  echo >&2 "ERROR: A timeout (${timeout}s) was reached while waiting for \"ZeroMQ\" test service to start!"
  echo >&2 "       See \"modules/remotebackend/${service_logfile}\" for more details."
  exit 69
}

function stop_zeromq() {
  if [ -z "${zeromq_pid}" ]; then
    # should never happen - why was stop_zeromq() called?
    echo >&2 "ERROR: Unable to stop \"ZeroMQ\" test service: Did we ever start the service?"
    exit 99
  fi

  if ! kill -0 ${zeromq_pid} 2>/dev/null; then
    # should never happen - did the test crashed the service?
    echo >&2 "ERROR: Unable to stop \"ZeroMQ\" test service: service (${zeromq_pid}) not running"
    exit 69
  fi

  kill -TERM ${zeromq_pid}
  local timeout=0
  while [ ${timeout} -lt 5 ]; do
    if ! kill -0 ${zeromq_pid} 2>/dev/null; then
      # service was stopped
      return 0
    fi

    sleep 1
    let timeout=timeout+1
  done

  if kill -0 ${zeromq_pid} 2>/dev/null; then
    echo >&2 "WARNING: Timeout (${timeout}s) reached - killing \"ZeroMQ\" test service ..."
    kill -KILL ${zeromq_pid} 2>/dev/null
    return $?
  fi
}

function start_unix() {
  if [ -z "$socat" -o ! -x "$socat" ]; then
    echo "INFO: Skipping \"UNIX socket\" test because \"socat\" executable wasn't found!"
    exit 77
  fi

  $socat unix-listen:/tmp/remotebackend.sock exec:./unittest_pipe.rb &
  socat_pid=$!

  local timeout=0
  while [ ${timeout} -lt 5 ]; do
    if [ -S "/tmp/remotebackend.sock" ]; then
      # service is up and running
      return 0
    fi

    sleep 1
    let timeout=timeout+1
  done

  if kill -0 ${socat_pid} 2>/dev/null; then
    # not sure when this can happen but we should cleanup any process we started
    echo >&2 "WARNING: Timeout (${timeout}s) reached: \"UNIX socket\" test service process is running but status check failed"
    kill -KILL ${socat_pid} 2>/dev/null
  fi

  echo >&2 "ERROR: A timeout (${timeout}s) was reached while waiting for \"UNIX socket\" test service to start!"
  exit 69
}

function stop_unix() {
  if [ -z "${socat_pid}" ]; then
    # should never happen - why was stop_unix() called?
    echo >&2 "ERROR: Unable to stop \"UNIX socket\" test service: Did we ever start the service?"
    exit 99
  fi

  if ! kill -0 ${socat_pid} 2>/dev/null; then
    # might very well happen, since socat will stop after getting EOF
    return 0
  fi

  kill -TERM ${socat_pid}
  local timeout=0
  while [ ${timeout} -lt 5 ]; do
    if ! kill -0 ${socat_pid} 2>/dev/null; then
      # service was stopped
      return 0
    fi

    sleep 1
    let timeout=timeout+1
  done

  if kill -0 ${socat_pid} 2>/dev/null; then
    echo >&2 "WARNING: Timeout (${timeout}s) reached - killing \"UNIX socket\" test service ..."
    kill -KILL ${socat_pid} 2>/dev/null
    return $?
  fi
}

function run_test() {
 if [ $new_api -eq 0 ]; then
   ./$mode
 else
    $orig
 fi
}

mode=`basename "$mode"`

case "$mode" in
  remotebackend_pipe.test)
    run_test
  ;;
  remotebackend_unix.test)
    start_unix
    run_test
    stop_unix
  ;;
  remotebackend_http.test)
    start_web "http"
    run_test
    stop_web "http"
  ;;
  remotebackend_post.test)
    start_web "post"
    run_test
    stop_web "post"
  ;;
  remotebackend_json.test)
    start_web "json"
    run_test
    stop_web "json"
  ;;
  remotebackend_zeromq.test)
    start_zeromq
    run_test
    stop_zeromq
  ;;
  *)
    echo "Usage: $0 remotebackend_(pipe|unix|http|post|json|zeromq).test"
    exit 1
  ;;
esac

exit $?
