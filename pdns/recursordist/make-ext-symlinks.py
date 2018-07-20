#!/usr/bin/env python2

import os
import shutil
import os.path

for extdir in ['yahttp', 'json11', 'probds']:
    try:
        shutil.rmtree(os.path.join('ext', extdir))
    except OSError:
        pass

    try:
        os.rmdir(os.path.join('ext', extdir))
    except OSError:
        pass

    for root, dirs, files in os.walk(os.path.join('../../ext', extdir)):
        stripped_root = root.replace('../', '')
        os.mkdir(stripped_root)
        num_dirs = len(root.split('/')) - root.split('/').count('..')
        for dirfile in files:
            os.symlink(os.path.join(num_dirs * '../', root, dirfile),
                       os.path.join(stripped_root, dirfile))
