import os
import sys
import shutil
import metrics_table

# default: 'type': uint64
# ptype: "'counter' (vs gauge')

srcdir = "."
builddir = "."
if len(sys.argv) == 3:
    print("metrics.py: using srcdir and builddir from arguments")
    srcdir = sys.argv[1]
    builddir = sys.argv[2]

print("Generating metrics related files")
print("metrics.py cwd: " + os.getcwd())
print("metrics.py srcdir: " + srcdir + " = " + os.path.realpath(srcdir))
print("metrics.py builddir: " + builddir + " = " + os.path.realpath(builddir))


def dedashForSNMP(name):
    cap = False
    ret = ""
    for ch in name:
        if ch == "-":
            cap = True
        elif cap:
            ret += ch.upper()
            cap = False
        else:
            ret += ch
    ret = ret.replace("Nsec", "NSEC")
    return ret


table = metrics_table.table

#
# We create various files in the srcdir but copy them into the builddir if needed to satisfy meson
# FIXME: only generate in builddir once autotools have been dropped
#
with open(srcdir + "/rec-oids-gen.h", "w", encoding="utf-8") as file:
    file.write("// THIS IS A GENERATED FILE. DO NOT EDIT. SOURCE metrics.py AND metrics_table.py\n")
    for entry in table:
        if "snmp" not in entry:
            continue
        if "ifdef" in entry:
            ifdef = entry["ifdef"]
            file.write(f"#ifdef {ifdef}\n")
        name = dedashForSNMP(entry["name"])
        snmp = entry["snmp"]
        file.write(f"static const oid10 {name}OID = {{RECURSOR_STATS_OID, {snmp}}};\n")
        if "ifdef" in entry:
            file.write(f"#endif\n")
if srcdir != builddir:
    shutil.copy(srcdir + "/rec-oids-gen.h", builddir)

with open(srcdir + "/rec-snmp-gen.h", "w", encoding="utf-8") as file:
    file.write("// THIS IS A GENERATED FILE. DO NOT EDIT. SOURCE metrics.py AND metrics_table.py\n")
    for entry in table:
        if "snmp" not in entry:
            continue
        name = entry["name"]
        dname = dedashForSNMP(name)
        if "ifdef" in entry:
            ifdef = entry["ifdef"]
            file.write(f"#ifdef {ifdef}\n")
        file.write(f'registerCounter64Stat("{name}", {dname}OID);\n')
        if "ifdef" in entry:
            file.write(f"#endif\n")
if srcdir != builddir:
    shutil.copy(srcdir + "/rec-snmp-gen.h", builddir)

with open(srcdir + "/rec-prometheus-gen.h", "w", encoding="utf-8") as file:
    file.write("// THIS IS A GENERATED FILE. DO NOT EDIT. SOURCE metrics.py AND metrics_table.py\n")
    for entry in table:
        name = entry["name"]
        if "pname" in entry:
            name = entry["pname"]
        desc = ""
        desc = entry["desc"]
        if "pdesc" in entry:
            desc = entry["pdesc"]
            if desc == "":
                continue
        ptype = "counter"
        if "ptype" in entry:
            ptype = entry["ptype"]
        file.write(f'{{"{name}", MetricDefinition(PrometheusMetricType::{ptype}, "{desc}")}},\n')
if srcdir != builddir:
    shutil.copy(srcdir + "/rec-prometheus-gen.h", builddir)

with open(srcdir + "/rec-metrics-gen.h", "w", encoding="utf-8") as file:
    file.write("// THIS IS A GENERATED FILE. DO NOT EDIT. SOURCE metrics.py AND metrics_table.py\n")
    for entry in table:
        name = entry["name"]
        if "lambda" not in entry:
            continue
        lam = entry["lambda"]
        if "ifdef" in entry:
            ifdef = entry["ifdef"]
            file.write(f"#ifdef {ifdef}\n")
        if "if" in entry:
            iff = entry["if"]
            file.write(f"if ({iff}) {{\n")
        file.write(f'addGetStat("{name}", {lam});\n')
        if "if" in entry:
            file.write(f"}}\n")
        if "ifdef" in entry:
            file.write(f"#endif\n")
if srcdir != builddir:
    shutil.copy(srcdir + "/rec-metrics-gen.h", builddir)

if os.path.isdir(srcdir + "/docs"):
    with open(srcdir + "/docs/rec-metrics-gen.rst", "w", encoding="utf-8") as file:
        file.write(".. THIS IS A GENERATED FILE. DO NOT EDIT. SOURCE metrics.py AND metrics_table.py\n")
        sortedtable = sorted(table, key=lambda value: value["name"])
        file.write(".. csv-table:: **Metrics**\n")
        file.write('    :header: "rec_control name", "Description", "SNMP Object and OID"\n')
        file.write("    :widths: 20, 50, 20\n\n")
        for entry in sortedtable:
            name = entry["name"]
            desc = entry["desc"]
            if not desc.endswith("."):
                desc += "."
            if "longdesc" in entry:
                desc = desc + " " + entry["longdesc"].strip()
            if not desc.endswith("."):
                desc += "."
            file.write(f'    "**{name}**", ')
            file.write(f'"{desc}"')
            if "snmp" in entry:
                snmp = entry["snmp"]
                snmpname = dedashForSNMP(name)
                if "snmpname" in entry:
                    name = entry["snmpname"]
                file.write(f', "{snmpname} ({snmp})"')
            else:
                file.write(",")
            file.write("\n")

str1 = ""
for entry in table:
    if "snmp" not in entry:
        continue
    name = dedashForSNMP(entry["name"])
    if "snmpname" in entry:
        name = entry["snmpname"]
    snmp = entry["snmp"]
    desc = entry["desc"]
    type = "Counter64"
    if "ptype" in entry and entry["ptype"] == "gauge":
        type = "CounterBasedGauge64"
    str1 += f'''
{name} OBJECT-TYPE
    SYNTAX {type}
    MAX-ACCESS read-only
    STATUS current
    DESCRIPTION
        "{desc}"
    ::= {{ stats {snmp} }}
'''

str2 = "        trapReason"
for entry in table:
    if "snmp" not in entry:
        continue
    name = dedashForSNMP(entry["name"])
    if "snmpname" in entry:
        name = entry["snmpname"]
    str2 += f",\n        {name}"


with open(srcdir + "/RECURSOR-MIB.in", mode="r", encoding="utf-8") as file:
    text = file.read()
    text = text.replace("REPL_OBJECTS1", str1)
    text = text.replace("REPL_OBJECTS2", str2)
    with open(srcdir + "/RECURSOR-MIB.txt", "w", encoding="utf-8") as file2:
        file2.write(text)
if srcdir != builddir:
    shutil.copy(srcdir + "/RECURSOR-MIB.txt", builddir)
