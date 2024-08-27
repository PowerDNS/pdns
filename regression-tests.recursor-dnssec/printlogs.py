#!/usr/bin/env python3

from __future__ import print_function
import xml.etree.ElementTree
import os.path
import glob

e = xml.etree.ElementTree.parse('pytest.xml')
testsuites = e.getroot()

for testsuite in testsuites:
    if len(testsuite):
        getstdout = False
        for testcase in testsuite:
            cls = testcase.get("classname")
            name = testcase.get("name")
            if '_' not in cls or '.' not in cls:
                print('Unexpected classname %s; name %s' % (cls, name))
                getstdout = True
                continue

            confdirnames = [cls.split('_')[1].split('.')[0], cls.split('.')[1].split('Test')[0]]
            found = False
            for confdirname in confdirnames:
                confdir = os.path.join("configs", confdirname)
                recursorlog = os.path.join(confdir, "recursor.log")
                if os.path.exists(recursorlog):
                    found = True
                    for elem in testcase:
                        if elem.tag in ["failure", "error"]:
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
            if not found and confdirnames[0] != 'Flags': 
                print("%s not found, configdir does not mach expected pattern" % confdirnames)
        if getstdout and elem.tag == 'system-out':
            print("==============> STDOUT LOG FROM XML <==============")
            print(elem.text)
            print("==============> END STDOUT LOG FROM XML <==============")
