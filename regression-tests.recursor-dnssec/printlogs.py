#!/usr/bin/env python2

from __future__ import print_function
import xml.etree.ElementTree
import os.path
import glob

e = xml.etree.ElementTree.parse('nosetests.xml')
root = e.getroot()

for child in root:
    if len(child):
        for elem in child:
            if elem.tag in ["failure", "error"]:
                confdirname = child.get("classname").split('_')[1].split('.')[0]
                confdir = os.path.join("configs", confdirname)
                recursorlog = os.path.join(confdir, "recursor.log")
                if os.path.exists(recursorlog):
                    print("==============> %s <==============" % recursorlog)
                    with open(recursorlog) as f:
                        print(''.join(f.readlines()))
                authdirs = glob.glob(os.path.join(confdir, "auth-*"))
                for authdir in authdirs:
                    authlog = os.path.join(authdir, "pdns.log")
                    if os.path.exists(recursorlog):
                        print("==============> %s <==============" % authlog)
                        with open(authlog) as f:
                            print(''.join(f.readlines()))
