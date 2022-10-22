#!/usr/bin/python3
import re
import sys

import requests
import yaml


PACKAGE_NAMES = ["pdns", "pdns-recursor", "dnsdist"]


def get_bugs_titles(bugs):
    ret = []
    title_regex = re.compile(r"<title>(.*) - Debian Bug report logs</title>")
    for bug in bugs:
        bug_r = requests.get("https://bugs.debian.org/cgi-bin/bugreport.cgi", params={"bug": bug})
        lines = bug_r.text.split("\n")
        for line in lines:
            match = title_regex.search(line)
            if match:
                ret.append(match.group(1))
                break
    return ret


def get_all_autoremovals():
    r = requests.get("https://udd.debian.org/cgi-bin/autoremovals.yaml.cgi")
    return yaml.load(r.text, Loader=yaml.SafeLoader)


def warn_removal(all_autoremovals, package_name):
    removal = all_autoremovals.get(package_name)
    if not removal:
        return False

    reason = "there are bugged dependencies." if removal["dependencies_only"] else "of a bug in PowerDNS!"
    msg = (
        f"::warning ::{package_name} slated for removal from Debian on "
        f"{removal['removal_date']} (https://tracker.debian.org/pkg/{package_name}) "
        f"because {reason}\n\n"
    )

    bugs = get_bugs_titles(removal.get("bugs_dependencies", []))
    if len(bugs):
        msg += f"This is caused by the following dependency bug{'s' if len(bugs) > 1 else ''}:\n  "
        msg += ("\n  ".join(bugs)) + "\n"

    bugs = get_bugs_titles(removal["bugs"])
    if len(bugs):
        msg += f"This is caused by the following bug{'s' if len(bugs) > 1 else ''} in PowerDNS:\n  "
        msg += ("\n  ".join(bugs)) + "\n"

    print(msg)
    return True


def main():
    all_autoremovals = get_all_autoremovals()
    removals = []
    for package_name in PACKAGE_NAMES:
        if warn_removal(all_autoremovals, package_name):
            removals.append(package_name)

    if removals:
        sys.exit(1)
    else:
        print("::notice ::No packages marked for autoremoval from Debian (yay!)")
        sys.exit(0)


if __name__ == "__main__":
    main()
