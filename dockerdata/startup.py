#!/usr/bin/env python3
import os
import sys

program = sys.argv[0].split('-')[0]
product = os.path.basename(program)

apiconffile = None
apienvvar = None
apiconftemplate = None
args = []

if product == 'pdns_recursor':
    args = ['--disable-syslog']
    apiconffile = '/etc/powerdns-api.conf'
    apienvvar = 'PDNS_RECURSOR_API_KEY'
    apiconftemplate = """webserver
api-key={apikey}
webserver-address=0.0.0.0
webserver-allow-from=0.0.0.0/0
webserver-password={apikey}
    """
elif product == 'pdns_server':
    args = ['--disable-syslog']
    apiconffile = '/etc/powerdns-api.conf'
    apienvvar = 'PDNS_AUTH_API_KEY'
    apiconftemplate = """webserver
api
api-key={apikey}
webserver-address=0.0.0.0
webserver-allow-from=0.0.0.0/0
webserver-password={apikey}
    """
elif product == 'dnsdist':
    args = ['--supervised', '--disable-syslog']
    apiconffile = '/etc/dnsdist-api.conf'
    apienvvar = 'DNSDIST_API_KEY'
    apiconftemplate = """webserver("0.0.0.0:8083", '{apikey}', '{apikey}', {{}}, '0.0.0.0/0')
controlSocket('0.0.0.0:5199')
setKey('{apikey}')
setConsoleACL('0.0.0.0/0')
    """

apikey = os.getenv(apienvvar)
print("apikey=", apikey)
if apikey is not None:
    with open(apiconffile, 'w') as conf:
        conf.write(apiconftemplate.format(apikey=apikey))

os.execv(program, [program]+args+sys.argv[1:])
