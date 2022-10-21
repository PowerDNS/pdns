#!/usr/bin/python3
import yaml
import requests
import sys
import re

def getTitleForBugs(bugs):
    ret = []
    title_regex = re.compile(r'<title>(.*) - Debian Bug report logs</title>')
    for bug in bugs:
        bug_r = requests.get('https://bugs.debian.org/cgi-bin/bugreport.cgi', params={'bug':bug})
        lines = bug_r.text.split('\n')
        for line in lines:
            match = title_regex.search(line)
            if match:
                ret.append(match.group(1))
                break
    return ret


r = requests.get('https://udd.debian.org/cgi-bin/autoremovals.yaml.cgi')
data = yaml.load(r.text, Loader=yaml.SafeLoader)
msg = ''

keys = ['pdns', 'pdns-recursor', 'dnsdist']

removals = []

for key in keys:
    if not key in data.keys():
        continue
    removals.append(key)
    msg += "::warning ::%s slated for removal from Debian on %s (https://tracker.debian.org/pkg/%s) " % (key, data[key]['removal_date'], key)
    if data[key]['dependencies_only']:
        msg += "because there are bugged dependencies.\n\n"
    else:
        msg += "because of a bug in PowerDNS!\n\n"

    bugs = getTitleForBugs(data[key].get('bugs_dependencies', []))
    if len(bugs):
        msg += "This is caused by the following dependency bug%s:\n  " % ('s' if len(bugs) > 1 else '')
        msg += '\n  '.join(bugs)

    bugs = getTitleForBugs(data[key]['bugs'])
    if len(bugs):
        msg += "This is caused by the following bug%s in PowerDNS:\n  " % ('s' if len(bugs) > 1 else '')
        msg += '\n  '.join(bugs)

    msg += "\n"

    print(msg)

if removals:
    sys.exit(1)
else:
    print("::notice ::No packages marked for autoremoval from Debian (yay!)")
    sys.exit(0)
