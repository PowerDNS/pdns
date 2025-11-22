#!/usr/bin/env -S python3 -u
import os
import sys
import jinja2

program = sys.argv[0].split("-")[0]
product = os.path.basename(program)

apienvvar = None
apiconftemplate = None
templateroot = "/etc/powerdns/templates.d"
templatedestination = ""
args = []
suffix = ".conf"  # default suffix, rec uses .yml

if product == "pdns_recursor":
    args = ["--disable-syslog"]
    apienvvar = "PDNS_RECURSOR_API_KEY"
    suffix = ".yml"
    apiconftemplate = """webservice:
  webserver: true
  api_key: '{{ apikey }}'
  address: 0.0.0.0
  allow_from: [0.0.0.0/0]
  password: '{{ apikey }}'
"""
    templatedestination = "/etc/powerdns/recursor.d"
elif product == "pdns_server":
    args = ["--disable-syslog"]
    apienvvar = "PDNS_AUTH_API_KEY"
    apiconftemplate = """webserver
api
api-key={{ apikey }}
webserver-address=0.0.0.0
webserver-allow-from=0.0.0.0/0
webserver-password={{ apikey }}
    """
    templatedestination = "/etc/powerdns/pdns.d"
elif product == "dnsdist":
    args = ["--supervised", "--disable-syslog"]
    apienvvar = "DNSDIST_API_KEY"
    apiconftemplate = """webserver("0.0.0.0:8083")
    setWebserverConfig({password='{{ apikey }}', apiKey='{{ apikey }}', acl='0.0.0.0/0'})
controlSocket('0.0.0.0:5199')
setKey('{{ apikey }}')
setConsoleACL('0.0.0.0/0')
    """
    templateroot = "/etc/dnsdist/templates.d"
    templatedestination = "/etc/dnsdist/conf.d"

debug = os.getenv("DEBUG_CONFIG", "no").lower() == "yes"

apikey = os.getenv(apienvvar)
if apikey is not None:
    webserver_conf = jinja2.Template(apiconftemplate).render(apikey=apikey)
    conffile = os.path.join(templatedestination, "_api" + suffix)
    with open(conffile, "w") as f:
        f.write(webserver_conf)
    if debug:
        print("Created {} with content:\n{}\n".format(conffile, webserver_conf))

templates = os.getenv("TEMPLATE_FILES")
if templates is not None:
    for templateFile in templates.split(","):
        template = None
        with open(os.path.join(templateroot, templateFile + ".j2")) as f:
            template = jinja2.Template(f.read())
        rendered = template.render(os.environ)
        target = os.path.join(templatedestination, templateFile + suffix)
        with open(target, "w") as f:
            f.write(rendered)
        if debug:
            print("Created {} with content:\n{}\n".format(target, rendered))

os.execv(program, [program] + args + sys.argv[1:])
