#!/usr/bin/env python
from __future__ import print_function
import json, sys

runs = json.load(sys.stdin)

selectors = dict(s.split('=',1) for s in sys.argv[1:])

selected=list()

names=set()

for run in runs:
	match = True
	for k,v in selectors.iteritems():
		# print k, v, run[k]
		if run[k] != v:
			match = False
			break

	if match:
		selected.append((run['tag'], run))
		names.update(run)

selected.sort()

names.discard('tag')

fmt=''.join('%%%ds' % max(15, i+4) for i in [3]+map(len, sorted(names)))
print(fmt % tuple(['tag']+sorted(names)))
for tag, stats in selected:
	print(fmt % tuple([tag] + [stats.get(s) for s in sorted(names)]))
