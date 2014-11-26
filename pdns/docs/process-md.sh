#!/bin/sh

pre() {
  for file in `find doc-build -name '*.md' -type f -print`; do
    pandoc -f markdown_github+pipe_tables -t markdown_github+pipe_tables -F markdown/process-includes.py $file -o $file
  done
}

post() {
  find html-new -type f -name '*.html' -exec sed -i \
    -e 's/<table>/<table class="table-bordered">/' \
    -e 's/\\&\(gt\|lt\)/\&\1/' \
    {} +
}

$1
