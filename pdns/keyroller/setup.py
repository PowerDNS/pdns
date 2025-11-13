import os
from setuptools import setup, find_packages

install_reqs = list()

# Use pipenv for dependencies, setuptools otherwise.
# This makes the installation for the packages easier (no pipenv needed)
try:
    from pipenv.project import Project
    from pipenv.utils import convert_deps_to_pip
    pfile = Project(chdir=False).parsed_pipfile
    install_reqs = convert_deps_to_pip(pfile['packages'], r=False)
except ImportError:
    from pkg_resources import parse_requirements
    import pathlib
    with pathlib.Path('requirements.txt').open() as requirements_txt:
        install_reqs = [
            str(r)
            for r
            in parse_requirements(requirements_txt)]


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
    install_requires=install_reqs,
    include_package_data = True,
    scripts=['pdns-keyroller.py', 'pdns-keyroller-ctl.py'],
    long_description=read('README.md'),
    classifiers=[],
)
