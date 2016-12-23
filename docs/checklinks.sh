#!/bin/sh
OUTPUT=$(linkchecker \
  --anchors \
  --ignore-url=.eot$ \
  --ignore-url=\.svg \
  --ignore-url=mailto \
  --ignore-url=.ttf$ \
  --ignore-url=woff$ \
  html/index.html 2>&1)

# For some reason, the exit code _can_ be misleading. see
# https://github.com/PowerDNS/pdns/pull/2539#issuecomment-105659608 and
# https://github.com/wummel/linkchecker/issues/217

echo "$OUTPUT" | grep -q '0 errors found'

if [ $? -ne 0 ]; then
  echo "Errors in links detected, log follows:"
  echo "$OUTPUT"
  exit 1
else
  echo "Links OK!"
  exit 0
fi

