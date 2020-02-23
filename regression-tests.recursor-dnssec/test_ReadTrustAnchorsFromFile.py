from __future__ import print_function
import os
import subprocess
from recursortests import RecursorTest


class testReadTrustAnchorsFromFile(RecursorTest):
    _confdir = 'ReadTAsFromFile'

    _config_template = """dnssec=validate"""
    _lua_config_file = """clearTA()
readTrustAnchorsFromFile('root.keys')"""

    def testCorrectFile(self):
        """Ensure the file is read correctly"""
        rec_controlCmd = [os.environ['RECCONTROL'],
                          '--config-dir=%s' % 'configs/' + self._confdir,
                          'get-tas']
        expected = """Configured Trust Anchors:
.
\t\t36914 13 2 c94ed457ff79afe03804c26ce4fa832687db92bc231aff98617791fc71a65870
\t\t42924 13 2 b49e0aafd6e147742afb9eab0e76af0546357dc6c61bf67d7c745cf6f43f460e
"""
        try:
            ret = subprocess.check_output(rec_controlCmd, stderr=subprocess.STDOUT)
            self.assertEqual(ret, expected)

        except subprocess.CalledProcessError as e:
            print(e.output)
            raise

