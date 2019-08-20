#!/usr/bin/env python3

import requests
import sys
import subprocess
import argparse


def get_commits(pr):
    try:
        res = requests.get('https://api.github.com/repos/PowerDNS/pdns/pulls/'
                           '{}/commits'.format(pr)).json()
        return [c['sha'] for c in res]
    except (ValueError, requests.exceptions.HTTPError) as e:
        print(e)
        sys.exit(1)


def run_command(cmd):
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError as e:
        print(e)
        sys.exit(1)


a = argparse.ArgumentParser()
action = a.add_mutually_exclusive_group(required=True)
action.add_argument(
    '-b', '--backport-unto', metavar='REF', nargs=1, help='Backport, using '
    'cherry-pick, all commits from PULL_REQUEST onto REF. This is done on a '
    'branch called "backport-PULL_REQUEST-to-basename(REF)". When the cherry-pick fails, solve '
    'the conflict as usual and run "git cherry-pick --continue --allow-empty"')
action.add_argument(
    '-m', '--merge-into', metavar='REF', nargs=1, help='Take the backport-'
    'PULL_REQUEST branch and merge it into REF')
a.add_argument(
    'pull_request', metavar='PULL_REQUEST', type=int,
    help='The PR number to backport')

args = a.parse_args()

if args.backport_unto:
    command = ['git', 'checkout', '-b',
               'backport-{}-to-{}'.format(args.pull_request, args.backport_unto[0].split('/')[-1]), args.backport_unto[0]]
    run_command(command)

    commits = get_commits(args.pull_request)
    command = ['git', 'cherry-pick', '-x', '--allow-empty'] + commits
    run_command(command)

if args.merge_into:
    command = ['git', 'checkout', args.merge_into[0]]
    run_command(command)

    command = ['git', 'merge', '--no-ff',
               'backport-{}-to-{}'.format(args.pull_request, args.merge_into[0].split('/')[-1]), '-m',
               'Backport #{}'.format(args.pull_request)]
    run_command(command)
