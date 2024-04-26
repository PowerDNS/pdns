"""Produce BIND DNSSEC schema usable from C."""

import sys

sql_filename = sys.argv[1]

with open(sql_filename, mode="r", encoding="utf-8") as f_in:
    contents = f_in.read()

    print("#pragma once")
    print()
    print("static char sqlCreate[] __attribute__((unused)) =")
    for line in contents.split("\n"):
        print(f'"{line}"')
    print(";")
