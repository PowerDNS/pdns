#!/usr/bin/env python3

import fileinput
import re


def main():
    pr_number_regex = re.compile(r"#(\d+)")
    prs = []

    for line in fileinput.input():
        line = line.rstrip()
        numbers = re.findall(pr_number_regex, line)
        for number in numbers:
            prs.append(number)

    for pr in prs:
        print(pr, end=" ")
    print()


if __name__ == "__main__":
    main()
