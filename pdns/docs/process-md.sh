#!/bin/sh

for file in `find doc-build -name '*.md' -type f -print`; do
  pandoc -f markdown_github -t markdown_mmd -F markdown/process-includes.py $file -o $file
done
