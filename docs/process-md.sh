#!/bin/sh -e

set -x

pre() {
  # Test if there are wrong PR links in the changelog
  CL_PR_LINKS="$(grep -E '\[#([0-9]+)\]\(.*[0-9]+\)' markdown/changelog.raw.md | grep -v -E '\[#([0-9]+)\]\(.*\1\)' || true)"
  if [ -n "${CL_PR_LINKS}" ]; then
    echo "Broken PR links in the changelog:" >&2
    echo "${CL_PR_LINKS}" >&2
    exit 1
  fi
  for file in `find doc-build -name '*.md' -type f -print`; do
    # Remove lines starting with '%' from manpages
    if echo "$file" | grep -q -e '\.1\.md$'; then
      cat $file | perl -n -e '!/^%/ && print;' > ${file}.tmp
      mv -f ${file}.tmp $file
    fi

    # Process include statements
    pandoc -f markdown_github+pipe_tables -t markdown_github+pipe_tables -F markdown/process-includes.py $file -o $file

    # Remove crap:
    #  * Escaped symbols
    perl -i -p \
    -e 's/\\([\$\^><])/\1/g;' \
    $file
  done
  sed 's|\([0-9a-f]\{9\}\)\([0-9a-f]*\)|[\1](https://github.com/PowerDNS/pdns/commit/\1\2)|g' < markdown/changelog.raw.md > doc-build/changelog.md
}

post() {
  # Change the following:
  # Add class="table-bordered" to tables
  find html -type f -name '*.html' -exec perl -i -p \
    -e 's/\<table>/<table class="table-bordered">/;' \
    -e 's/\<title>None\<\/title>/<title>PowerDNS<\/title>/' \
    {} +

  # Remove files we don't need on the site
  rm -rf html/process-* \
        html/changelog.raw.md \
        html/theme
}

$1
