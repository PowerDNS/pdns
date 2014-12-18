#!/bin/sh -e

pre() {
  for file in `find doc-build -name '*.md' -type f -print`; do
    pandoc -f markdown_github+pipe_tables -t markdown_github+pipe_tables -F markdown/process-includes.py $file -o $file
  done
}

post() {
  # Change the following:
  # 1. Add class="table-bordered" to tables
  # 2. Fix &gt; and &lt; escaping fuckery
  # 3. Fix $-sign escaping insanity
  find html-new -type f -name '*.html' -exec perl -i -p \
    -e 's/\<table>/<table class="table-bordered">/;' \
    -e 's/\\&(gt|lt)/&\1/;' \
    -e 's/\\\\/\\/g;' \
    {} +
}

$1
