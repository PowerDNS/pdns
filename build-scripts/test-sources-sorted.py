#!/usr/bin/env python3

import re
import sys

REGEX = re.compile(r'(?s)[a-z0-9][a-z0-9_]+_SOURCES ?= ?\\.*?^$', re.MULTILINE)


def test_sources(fname) -> int:
    text = ""
    with open(fname, mode="r") as f:
        text = f.read()

    matches = re.findall(REGEX, text)
    ret = 0
    for match in matches:
        lines = match.split(" \\\n\t")
        elem = lines[0].rstrip(' =')
        lines = lines[1:]
        sorted_lines = sorted(lines)

        if sorted_lines != lines:
            ret = 1
            print(f'Source files for {elem} in {fname} is not sorted properly'
                  .format(elem=elem, fname=fname))
    return ret


if __name__ == "__main__":
    sys.exit(test_sources(sys.argv[1]))
