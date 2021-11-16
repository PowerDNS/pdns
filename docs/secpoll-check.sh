#!/bin/sh
if [ $# -ne 1 ]; then
  echo usage: $0 file
  exit 1
fi
if egrep -v '^(@|;|$)' "$1" | egrep -v 'ubuntu|debian|raspbian|fedora' | egrep -v '(auth|recursor|dnsdist)-[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)[0-9]+)?\.security-status +60 IN TXT "[1-3].*"' 
then
  echo Not OK
  exit 1
fi
echo OK
exit 0
