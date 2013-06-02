#!/bin/bash 

webrick_pid=""

if [ x"$REMOTEBACKEND_HTTP" == "xyes" ]; then 

if [ `basename "$1"` == "test_remotebackend_http" ]; then 
 ./unittest_http.rb &  
 webrick_pid=$!
 sleep 1
fi

$1
rv=$?

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

else

$1
rv=$?

fi

exit $rv
