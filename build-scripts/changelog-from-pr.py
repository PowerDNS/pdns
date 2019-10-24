#!/usr/bin/env python3

import requests
import sys
import argparse
import re
import getpass

argp = argparse.ArgumentParser()
argp.add_argument('--oneline', action='store_true',
                  help='Make one-lined changelog entries (for 4.0 and older)')
argp.add_argument('--username',
                  help='Use the specified username for Basic Authentication to the GitHub API, allowing a higher rate limit')
argp.add_argument('--access_token',
                  help='Use API access token instead of username & password combination')
argp.add_argument('pullrequest', metavar='PULL_REQUEST', nargs='+',
                  help='Make changelogs for these Pull Request #\'s')
arguments = argp.parse_args()

ticket_regex = re.compile(r'(?:[Cc]loses|[Ff]ixes)? #(\d+)')

out = ''
httpAuth = None
if arguments.username:
    password = getpass.getpass("GitHub password for '" + arguments.username + "': ")
    httpAuth = requests.auth.HTTPBasicAuth(arguments.username, password)

# https://github.com/settings/tokens
# A token with `repo` and `user` access will definitely work.
access_token = arguments.access_token

for pr in arguments.pullrequest:
    if pr[0] == '#':
        pr = pr[1:]
    try:
        if access_token:
            res = requests.get('https://api.github.com/repos/PowerDNS/pdns/pulls/'
                               '{}?access_token={}'.format(pr, access_token))
        else:
            res = requests.get('https://api.github.com/repos/PowerDNS/pdns/pulls/'
                               '{}'.format(pr), auth=httpAuth)
        pr_info = res.json()
    except (requests.exceptions.HTTPError, ValueError) as e:
        print(e)
        sys.exit(1)

    if arguments.oneline:
        out += '- `#{pr} <{url}>`__: {title}'.format(
            pr=pr, url=pr_info['html_url'], title=pr_info['title']
        )
    else:
        out += '  .. change::\n' + \
               '    :tags: XXXXXX\n' + \
               '    :pullreq: {}\n'.format(pr)
        body = pr_info.get('body', None)
        if pr_info.get('message', None) and not body:
            # A bit blunt but better than we had.
            print('{}'.format(pr_info['message']))
            sys.exit(1)
        elif body:
            tickets = re.findall(ticket_regex, body)
            if len(tickets):
                out += '    :tickets: {}\n'.format(', '.join(tickets))
        out += '\n    {}'.format(pr_info['title'][0].capitalize() + pr_info['title'][1:])

    if pr_info['user']['login'].lower() not in ['ahupowerdns', 'habbie',
                                                'pieterlexis', 'rgacogne',
                                                'aerique', 'chbruyand',
                                                'omoerbeek']:
        try:
            if access_token:
                user_info = requests.get(pr_info['user']['url'] + '?access_token=' + access_token, auth=httpAuth).json()
            else:
                user_info = requests.get(pr_info['user']['url'], auth=httpAuth).json()
        except (requests.exceptions.HTTPError, ValueError) as e:
            print(e)
            sys.exit(1)
        if 'name'in user_info:
            out += ' ({})'.format(user_info['name'])
        else:
            out += ' (@{})'.format(user_info['login'])
    out += '\n'

    if not arguments.oneline:
        out += '\n'

print(out)
