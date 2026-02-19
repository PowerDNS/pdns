import os
import pathlib
from setuptools import setup, find_packages

# reads requirements.txt file and extracts package_name and version (if set)
def read_requirements_file(fname):
    reqs = []

    with pathlib.Path(fname).open() as f:
        for line in f:
            line = line.strip()
            # do not consider comments, hashes and remove trailing "\" if needed
            if line and not line.startswith(('#', '-')):
                reqs.append(line.rstrip('\\').strip())

    return reqs


def exists(fname):
    return os.path.exists(os.path.join(os.path.dirname(__file__), fname))


# Utility function to read the README file.
# Used for the long_description.  It's nice, because now 1) we have a top level
# README file and 2) it's easier to type in the README file than to put a raw
# string in below ...
def read(fname):
    with open(os.path.join(os.path.dirname(__file__), fname),
              'r', encoding='utf-8') as f:
        return f.read()


version = os.environ.get('BUILDER_VERSION', '0.0.0')

if exists('version.txt'):
    version = read('version.txt').strip()

setup(
    name = "pdns-keyroller",
    version = version,
    author = "PowerDNS.COM BV",
    author_email = "powerdns.support@powerdns.com",
    description = ("PowerDNS keyroller"),
    license = "GNU GPLv2",
    keywords = "PowerDNS keyroller",
    url = "https://www.powerdns.com/",
    packages = find_packages(),
    install_requires=read_requirements_file("requirements.txt"),
    include_package_data = True,
    scripts=['pdns-keyroller.py', 'pdns-keyroller-ctl.py'],
    long_description=read('README.md'),
    classifiers=[],
)
