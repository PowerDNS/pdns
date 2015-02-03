#!/bin/sh -e

pre() {
  for file in `find doc-build -name '*.md' -type f -print`; do
    pandoc -f markdown_github+pipe_tables -t markdown_github+pipe_tables -F markdown/process-includes.py $file -o $file
    perl -i -p \
    -e 's/\\([\$\*\^><])/\1/g;' \
    $file
  done
  sed 's|\([0-9a-f]\{9\}\)\([0-9a-f]*\)|[\1](https://github.com/PowerDNS/pdns/commit/\1\2)|g' < markdown/changelog.md.raw > doc-build/changelog.md
}

post() {
  # Change the following:
  # Add class="table-bordered" to tables
  find html -type f -name '*.html' -exec perl -i -p \
    -e 's/\<table>/<table class="table-bordered">/;' \
    {} +
}

$1
