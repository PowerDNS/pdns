#!/bin/sh

for file in `find doc-build -name '*.md' -type f -print`; do
  pandoc -f markdown_github+pipe_tables -t markdown_github+pipe_tables -F markdown/process-includes.py $file -o $file
done
