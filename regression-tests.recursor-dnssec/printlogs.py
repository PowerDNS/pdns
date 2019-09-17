#!/usr/bin/env python2

from __future__ import print_function
import xml.etree.ElementTree
import os.path
import glob

e = xml.etree.ElementTree.parse('nosetests.xml')
root = e.getroot()

for child in root:
    if len(child):
        getstdout = False
        for elem in child:
            if elem.tag in ["failure", "error"]:
                cls = child.get("classname")
                name = child.get("name")
                if '_' not in cls or '.' not in cls:
                    print('Unexpected classname %s; name %s' % (cls, name))
                    getstdout = True
                    continue

                confdirnames = [cls.split('_')[1].split('.')[0], cls.split('.')[1].split('Test')[0]]
                for confdirname in confdirnames:
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
            if getstdout and elem.tag == 'system-out':
                print("==============> STDOUT LOG FROM XML <==============")
                print(elem.text)
                print("==============> END STDOUT LOG FROM XML <==============")
           
