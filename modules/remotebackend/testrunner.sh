#!/bin/bash 

webrick_pid=""
socat_pid=""
socat=/usr/bin/socat

function start_web() {
  if [ x"$REMOTEBACKEND_HTTP" == "xyes" ]; then
   ./unittest_$1.rb &
   webrick_pid=$!
   loopcount=0
   while [ $loopcount -lt 20 ]; do
     res=$(curl http://localhost:62434/ping 2>/dev/null)
     if [ "x$res" == "xpong" ]; then break; fi
     sleep 1
     let loopcount=loopcount+1
   done
  fi
}

function stop_web() {
 if [ ! -z "$webrick_pid" ]; then
   kill -TERM $webrick_pid
   # wait a moment for it to die
   i=0
   while [ $i -lt 5 ]; do
     sleep 1
     kill -0 $webrick_pid 2>/dev/null
     if [ $? -ne 0 ]; then break; fi
     let i=i+1
   done
 fi
}

function start_unix() {
  if [ ! -x $socat ]; then
     echo "Cannot find socat - cannot test (non-fatal)"
     exit 0
  fi
  
  $socat unix-listen:/tmp/remotebackend.sock exec:./unittest_pipe.rb &
  socat_pid=$!
  sleep 1
}

function stop_unix() {
 if [ ! -z "$socat_pid" ]; then
   kill -TERM $socat_pid 2>/dev/null
   if [ $? -ne 0 ]; then
     # already dead
     return 
   fi
   # wait a moment for it to die
   i=0
   while [ $i -lt 5 ]; do
     sleep 1
     kill -0 $socat_pid 2>/dev/null
     if [ $? -ne 0 ]; then break; fi
     let i=i+1
   done
 fi
}

mode=`basename "$1"`

case "$mode" in
  test_remotebackend_pipe)
    ./test_remotebackend_pipe
    rv=$?
  ;;
  test_remotebackend_unix)
    start_unix
    ./test_remotebackend_unix
    rv=$?
    stop_unix
  ;;
  test_remotebackend_http)
    start_web "http"
    ./test_remotebackend_http
    rv=$?
    stop_web
  ;;
  test_remotebackend_post)
    start_web "post"
    ./test_remotebackend_post
    rv=$?
    stop_web
  ;;
  test_remotebackend_json)
    start_web "json"
    ./test_remotebackend_json
    rv=$?
    stop_web
  ;;
  *)
     echo "Usage: $0 test_remotebackend_(pipe|http|post|json)"
  ;;
esac

exit $rv
