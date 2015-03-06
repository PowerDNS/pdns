#!/bin/sh
OUTPUT=$(linkchecker \
  --anchors \
  --ignore-url=.eot$ \
  --ignore-url=\.svg \
  --ignore-url=mailto \
  --ignore-url=.ttf$ \
  --ignore-url=woff$ \
  html/index.html 2>&1)

if [ $? -ne 0 ]; then
  echo "Errors in links detected, log follows:"
  echo "$OUTPUT"
  exit 1
else
  echo "Links OK!"
  exit 0
fi

