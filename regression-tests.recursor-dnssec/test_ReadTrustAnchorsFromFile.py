from __future__ import print_function
import os
import subprocess
import tempfile
from recursortests import RecursorTest


class ReadTrustAnchorsFromFileTest(RecursorTest):
    _confdir = "ReadTrustAnchorsFromFile"

    _config_template = """dnssec=validate"""
    _lua_config_file = """clearTA()
readTrustAnchorsFromFile('root.keys')"""

    def testCorrectFile(self):
        """Ensure the file is read correctly"""
        rec_controlCmd = [os.environ["RECCONTROL"], "--config-dir=%s" % "configs/" + self._confdir, "get-tas"]
        expected = b"""Configured Trust Anchors:
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


class ReadTrustAnchorsFromFileYAMLTest(RecursorTest):
    _confdir = "ReadTrustAnchorsFromFileYAML"

    _config_template = """
dnssec:
    validation: validate
    trustanchorfile: root.keys
"""

    @classmethod
    def generateRecursorConfig(cls, confdir):
        super(ReadTrustAnchorsFromFileYAMLTest, cls).generateRecursorYamlConfig(confdir, False)

    def testCorrectFile(self):
        """Ensure the file is read correctly in the YAML case"""
        expected = """Configured Trust Anchors:
.
\t\t36914 13 2 c94ed457ff79afe03804c26ce4fa832687db92bc231aff98617791fc71a65870
\t\t42924 13 2 b49e0aafd6e147742afb9eab0e76af0546357dc6c61bf67d7c745cf6f43f460e
"""
        confdir = os.path.join("configs", self._confdir)
        ret = self.recControl(confdir, "get-tas")
        self.assertEqual(ret, expected)


class ReadTrustAnchorsFromEmptyFileYAMLTest(RecursorTest):
    _confdir = "ReadTrustAnchorsFromEmptyFileYAML"

    _file = tempfile.NamedTemporaryFile()
    _config_template = (
        """
dnssec:
    validation: validate
    trustanchorfile: %s
"""
        % _file.name
    )

    _file.write(b"""
. 3600 DS 36914 13 2 c94ed457ff79afe03804c26ce4fa832687db92bc231aff98617791fc71a65870
""")
    _file.flush()

    @classmethod
    def generateRecursorConfig(cls, confdir):
        super(ReadTrustAnchorsFromEmptyFileYAMLTest, cls).generateRecursorYamlConfig(confdir, False)

    def testIncorrectFile(self):
        """Ensure a reload of an invalid file does not destroy the existing config"""
        expected = """Configured Trust Anchors:
.
\t\t36914 13 2 c94ed457ff79afe03804c26ce4fa832687db92bc231aff98617791fc71a65870
"""
        confdir = os.path.join("configs", self._confdir)
        ret = self.recControl(confdir, "get-tas")
        self.assertEqual(ret, expected)
        self._file.write(b"""xxx""")
        self._file.flush()
        try:
            ret = self.recControl(confdir, "reload-yaml")
            raise AssertError("Expected rec_control to fail")
        except Exception:
            pass

        self.assertEqual(ret, expected)
