#!/usr/bin/env python3
import os
import sys
import jinja2

program = sys.argv[0].split('-')[0]
product = os.path.basename(program)

apienvvar = None
apiconftemplate = None
templateroot = '/etc/powerdns/templates.d'
templatedestination = ''
args = []

if product == 'pdns_recursor':
    args = ['--disable-syslog']
    apienvvar = 'PDNS_RECURSOR_API_KEY'
    apiconftemplate = """webserver
api-key={{ apikey }}
webserver-address=0.0.0.0
webserver-allow-from=0.0.0.0/0
webserver-password={{ apikey }}
    """
    templatedestination = '/etc/powerdns/recursor.d'
elif product == 'pdns_server':
    args = ['--disable-syslog']
    apienvvar = 'PDNS_AUTH_API_KEY'
    apiconftemplate = """webserver
api
api-key={{ apikey }}
webserver-address=0.0.0.0
webserver-allow-from=0.0.0.0/0
webserver-password={{ apikey }}
    """
    templatedestination = '/etc/powerdns/pdns.d'
elif product == 'dnsdist':
    args = ['--supervised', '--disable-syslog']
    apienvvar = 'DNSDIST_API_KEY'
    apiconftemplate = """webserver("0.0.0.0:8083", '{{ apikey }}', '{{ apikey }}', {}, '0.0.0.0/0')
controlSocket('0.0.0.0:5199')
setKey('{{ apikey }}')
setConsoleACL('0.0.0.0/0')
    """
    templateroot = '/etc/dnsdist/templates.d'
    templatedestination = '/etc/dnsdist/conf.d'

apikey = os.getenv(apienvvar)
if apikey is not None:
    webserver_conf = jinja2.Template(apiconftemplate).render(apikey=apikey)
    conffile = os.path.join(templatedestination, '_api.conf')
    with open(conffile, 'w') as f:
        f.write(webserver_conf)

templates = os.getenv('TEMPLATE_FILES')
if templates is not None:
    for templateFile in templates.split(','):
        template = None
        with open(os.path.join(templateroot, templateFile + '.j2')) as f:
            template = jinja2.Template(f.read())
        rendered = template.render(os.environ)
        with open(os.path.join(templatedestination, templateFile + '.conf'), 'w') as f:
            f.write(rendered)

os.execv(program, [program]+args+sys.argv[1:])
