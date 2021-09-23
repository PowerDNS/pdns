#!/usr/bin/env python3
#
# Given Python's versioning history I'm going with `python3`.
#
# Usage:
# - `python3 -m venv venv`
# - `bash`
# - `source venv/bin/activate`
# - `pip install --upgrade pip`
# - `pip install -r requirements.txt`
# - `./generate-repo-files.py auth-41`

# Modules

import argparse
import subprocess
import sys

from pathlib import Path

# since we use this at OX (or Ansible uses it, whatever)
from jinja2 import Environment, FileSystemLoader


# Globals

g_version = '0.0.1'

g_verbose = False

g_env = Environment(
    loader=FileSystemLoader('templates/')
)

g_dockerfile = 'Dockerfile.'
g_run_output = False


# Init Functions

def init_argparser():
    parser = argparse.ArgumentParser(description='Generate Docker files to ' +
                                                 'test PowerDNS repositories.')
    parser.add_argument('release', metavar='RELEASE',
                        choices=[# Authoritative Server
                                 'auth-42', 'auth-43', 'auth-44', 'auth-master',
                                 # Recursor
                                 'rec-42', 'rec-43', 'rec-44', 'rec-45',
                                 'rec-master',
                                 # DNSDist
                                 'dnsdist-15', 'dnsdist-16', 'dnsdist-17',
                                 'dnsdist-master'
                                 ],
                        help='the release to generate Docker files for: ' +
                             '%(choices)s')
    parser.add_argument('--run-output', action='store_true',
                        help='always show output from running a container')
    parser.add_argument('--test', action='store_true',
                        help='test the release')
    parser.add_argument('--verbose', action='store_true',
                        help='verbose output')
    parser.add_argument('--version', action='store_true',
                        help='print version')
    return parser


# Release File Functions

def write_dockerfile (os, os_version, release):
    tpl = g_env.get_template('Dockerfile-{}.jinja2'.format(os))

    if os == 'raspbian':
        os_image = 'resin/rpi-raspbian'
    else:
        os_image = os

    if release.startswith('auth-'):
        if os == 'centos':
            pkg = 'pdns'
        else:
            pkg = 'pdns-server'
        cmd = 'pdns_server'
    elif release.startswith('rec-'):
        pkg = 'pdns-recursor'
        cmd = 'pdns_recursor'
    elif release.startswith('dnsdist-'):
        pkg = 'dnsdist'
        cmd = 'dnsdist'

    f = open('{}{}.{}-{}'.format(g_dockerfile, release, os, os_version), 'w')

    # This comment was in the template for the `--nobest` part but that makes
    # the template look even more different than the final output, so:
    #
    # > When should the logic be in the code and when in the template? :shrug:
    # > I prefer it to be in the code but I also do not want to add extra vars
    # > and logic to the code unless necessary.
    f.write(tpl.render({ "os": os,
                         "os_image": os_image,
                         "os_version": os_version,
                         "release": release,
                         "cmd": cmd,
                         "pkg": pkg }))
    f.close()


def write_list_file (os, os_version, release):
    tpl = g_env.get_template('pdns-list.jinja2')

    if os in ['debian', 'ubuntu']:
        arch = ' [arch=amd64] '
    else:
        arch = ' '

    f = open('pdns.list.{}.{}-{}'.format(release, os, os_version), 'w')
    f.write(tpl.render({ "os": os,
                         "os_version": os_version,
                         "release": release,
                         "arch": arch }))
    f.close()


def write_pkg_pin_file (release):
    tpl = g_env.get_template('pkg-pin.jinja2')

    if release.startswith('auth-') or  release.startswith('rec-'):
        pkg = 'pdns-'
    elif release.startswith('dnsdist-'):
        pkg = 'dnsdist'

    f = open('pkg-pin', 'w')
    f.write(tpl.render({ "pkg": pkg }))
    f.close()


def write_release_files (release):
    if g_verbose:
        print("Writing release files...")

    if release in ['auth-43', 'auth-master']:
        write_dockerfile('centos', '6', release)

    if release in ['auth-41', 'auth-42', 'auth-43', 'auth-44', 'auth-master',
                   'rec-42', 'rec-43', 'rec-44', 'rec-45', 'rec-master',
                   'dnsdist-15', 'dnsdist-16', 'dnsdist-17', 'dnsdist-master']:
        write_dockerfile('centos', '7', release)
        write_dockerfile('ubuntu', 'bionic', release)
        write_list_file('ubuntu', 'bionic', release)
        write_pkg_pin_file(release)

    if release in ['auth-42', 'auth-43', 'auth-44',
                   'rec-42', 'rec-43', 'rec-44',
                   'dnsdist-14', 'dnsdist-15']:
        write_dockerfile('raspbian', 'buster', release)
        write_list_file('raspbian', 'buster', release)

    if release in ['auth-42', 'auth-43', 'auth-44', 'auth-master',
                   'rec-42', 'rec-43', 'rec-44', 'rec-45', 'rec-master',
                   'dnsdist-15', 'dnsdist-16', 'dnsdist-17', 'dnsdist-master']:
        write_dockerfile('centos', '8', release)
        write_dockerfile('debian', 'buster', release)
        write_list_file('debian', 'buster', release)

    if release in ['auth-43', 'auth-44', 'auth-master',
                   'rec-43', 'rec-44', 'rec-45', 'rec-master',
                   'dnsdist-15', 'dnsdist-16', 'dnsdist-17', 'dnsdist-master']:
        write_dockerfile('ubuntu', 'focal', release)
        write_list_file('ubuntu', 'focal', release)

    if release in ['dnsdist-16', 'dnsdist-17', 'dnsdist-master']:
        write_dockerfile('debian', 'bullseye', release)
        write_list_file('debian', 'bullseye', release)


# Test Release Functions

def build (dockerfile):
    # Maybe create `determine_tag` function.
    if len(str(dockerfile)) <= len(g_dockerfile):
        print('Unable to determine tag for {}'.format(dockerfile))
        return (None, None)
    tag = str(dockerfile)[len(g_dockerfile):]
    print('Building Docker image using {}...'.format(dockerfile))
    if g_verbose:
        print('  - tag = {}'.format(tag))
    cp = subprocess.run(['docker', 'build', '--no-cache', '--pull', '--file',
                         dockerfile, '--tag', tag, '.'],
                        capture_output=not(g_verbose))
    # FIXME write failed output to log
    if cp.returncode != 0:
        print('Error building {}: {}'.format(tag, repr(cp.returncode)))
        return ( tag, cp.returncode )
    return ( tag, cp.returncode )


def run (tag):
    if g_run_output:
        capture_run_output = False
    else:
        capture_run_output = not(g_verbose)
    print('Running Docker container tagged {}...'.format(tag))
    cp = subprocess.run(['docker', 'run', tag],
                        capture_output=capture_run_output)
    # for some reason 99 is returned on  `cmd --version` :shrug:
    if cp.returncode != 0 and cp.returncode != 99:
        # FIXME write failed output to log
        print('Error running {}: {}'.format(tag, repr(cp.returncode)))
        return cp.returncode
    return cp.returncode


def collect_dockerfiles (release):
    if g_verbose:
        print('Collecting release files for {}...'.format(release))
    p = Path('.')
    files = list(p.glob('{}{}.*'.format(g_dockerfile, release)))
    if g_verbose:
        for file in files:
            print('  - {}'.format(file))
    return files


def test_release (release):
    # sorted because we want determinism
    dockerfiles = sorted(collect_dockerfiles(release))
    failed_builds = []
    failed_runs = []
    print('=== testing {} ==='.format(release))
    for df in dockerfiles:
        if g_verbose:
            print('--- {} ---'.format(df))
        (tag, returncode) = build(df)
        if returncode != 0:
            print('Skipping running {} due to build error: {}'
                  .format(df, returncode))
            failed_builds.append((str(df), returncode))
        elif tag is None:
            print('Skipping running {} due to undetermined tag.'.format(df))
            failed_builds.append((str(df), returncode))
        else:
            returncode = run(tag)
            # for some reason 99 is returned on  `cmd --version` :shrug:
            if returncode != 0 and returncode != 99:
                failed_runs.append((tag, returncode))
    print('Test done.')
    if len(failed_builds) > 0:
        print('- failed builds:')
        for fb in failed_builds:
            print('    - {}'.format(fb))
    if len(failed_runs) > 0:
        print('- failed runs:')
        for fr in failed_runs:
            print('    - {}'.format(fr))


# Main Program

parser = init_argparser()
args = parser.parse_args()

if args.version:
    print('generate-repo-files v' + g_version)
    sys.exit(0)

if args.verbose:
    g_verbose = True

if args.run_output:
    g_run_output = True

write_release_files(args.release)

if args.test:
    test_release(args.release)
