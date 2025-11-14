#!/usr/bin/env python3
"""
This script uses dnf to generate a Software Bill of Materials
(SBOM) in CycloneDX JSON format.
"""

import datetime
import dnf
import json
import os
import sys
import uuid


def licenseToSPDXIdentifier(licenseName):
    licenseMap = {
        "BSD": "BSD-3-Clause",
        "GPLv2": "GPL-2.0-only",
        "GPLv2+": "GPL-2.0-or-later",
        "LGPLv2+": "LGPL-2.0-or-later",
        "MIT": "MIT",
        "OpenLDAP": "OLDAP-2.8",
    }
    if licenseName in licenseMap:
        return licenseMap[licenseName]
    return None


def getPackageDatabase():
    with dnf.Base() as db:
        conf = db.conf
        conf.installroot = "/"
        conf.substitutions.update_from_etc("/")
        db.read_all_repos()

        db.fill_sack(load_system_repo="auto", load_available_repos=True)
        query = db.sack.query()
        return query.installed()


def getPURL(pkg):
    # from https://github.com/package-url/purl-spec/blob/main/types-doc/rpm-definition.md
    # pkg:rpm/<namespace>/<name>@<version>?<qualifiers>#<subpath>
    name = pkg.name
    version = pkg.version
    if hasattr(pkg, "cargo"):
        return f"pkg:cargo/{name}@{version}"

    vendor = pkg.vendor.lower()
    if vendor == "oracle america":
        vendor = "oracle"
    elif vendor == "rocky enterprise software foundation":
        vendor = "rocky"
    elif vendor == "fedora project":
        vendor = "fedora"

    if pkg.release:
        version += "-" + pkg.release
    qualifiers = ""
    if hasattr(pkg, "arch"):
        if len(qualifiers) != 0:
            qualifiers += "&"
        qualifiers += "arch=" + pkg.arch
    if pkg.epoch != 0:
        if len(qualifiers) != 0:
            qualifiers += "&"
        qualifiers += "epoch=" + str(pkg.epoch)
    return f"pkg:rpm/{vendor}/{name}@{version}?{qualifiers}"


def getPackageInformations(pkgDB, packageName):
    matches = pkgDB.filter(name=packageName).run()
    if len(matches) == 0:
        print(f"-> Package {packageName} not found")
        return None
    return matches[0]


def addDependencyToSBOM(sbom, appInfos, pkg):
    bomRef = "lib:" + pkg.name
    component = {"name": pkg.name, "bom-ref": bomRef, "type": "library"}
    if pkg.release:
        component["version"] = (
            (pkg.version if pkg.epoch == 0 else str(pkg.epoch) + ":" + pkg.version) + "-" + pkg.release
        )
    else:
        component["version"] = pkg.version if pkg.epoch == 0 else str(pkg.epoch) + ":" + pkg.version
    if hasattr(pkg, "arch"):
        component["version"] += "." + pkg.arch
    if hasattr(pkg, "vendor") and pkg.vendor is not None:
        component["supplier"] = {"name": pkg.vendor}
    if hasattr(pkg, "publisher") and pkg.publisher is not None:
        component["publisher"] = pkg.publisher
    spdxLicense = licenseToSPDXIdentifier(pkg.license)
    if spdxLicense is None:
        component["licenses"] = [{"license": {"name": pkg.license}}]
    else:
        component["licenses"] = [{"license": {"id": spdxLicense}}]
    if hasattr(pkg, "sha256") and pkg.sha256 is not None:
        component["hashes"] = [{"alg": "SHA-256", "content": pkg.sha256}]
    component["purl"] = getPURL(pkg)

    sbom["components"].append(component)


def processDependencies(pkgDB, sbom, appInfos, depRelations):
    seenDeps = {}
    for require in appInfos.requires:
        if hasattr(require, "name"):
            depName = require.name.split("(")[0]
            depSpec = require.name
        else:
            # hawkey.Reldep, el-8
            depName = str(require).split("(")[0]
            depSpec = require
        if depName in ["/bin/sh", "config", "ld-linux-x86-64.so.2", "rpmlib", "rtld"]:
            continue
        if depName in seenDeps:
            continue
        seenDeps[depName] = True

        matches = pkgDB.filter(name=depName).run()
        if len(matches) == 0:
            flags = []
            matches = pkgDB.filter(*flags, provides__glob=[depSpec]).run()
            if len(matches) == 0:
                print(f"Unable to find a match for {depName}")
                continue
        if len(matches) > 1:
            print(f"Got {len(matches)} matches for {depName}")

        dep = matches[0]
        depRef = "lib:" + dep.name
        if depRef in seenDeps:
            continue
        seenDeps[depRef] = True

        addDependencyToSBOM(sbom, appInfos, dep)
        depRelations["pkg:" + appInfos.name].append(depRef)


class StaticLibDep(object):
    pass


def processAdditionalDependencies(sbom, appInfos, additionalDeps, depRelations):
    for additionalDepFile in additionalDeps:
        with open(additionalDepFile) as depDataFile:
            depData = json.load(depDataFile)
            pkg = StaticLibDep()
            pkg.name = os.path.splitext(os.path.basename(additionalDepFile))[0]
            pkg.version = depData["version"]
            pkg.epoch = 0
            pkg.release = None
            pkg.supplier = "PowerDNS.COM BV"
            if "license" in depData:
                pkg.license = depData["license"]
            if "publisher" in depData:
                pkg.publisher = depData["publisher"]
            if "SHA256SUM" in depData:
                pkg.sha256 = depData["SHA256SUM"]
            elif "SHA256SUM_x86_64" in depData:
                pkg.sha256 = depData["SHA256SUM_x86_64"]
            pkg.cargo = True

            depRef = "lib:" + pkg.name
            addDependencyToSBOM(sbom, appInfos, pkg)
            depRelations["pkg:" + appInfos.name].append(depRef)


def generateSBOM(packageName, additionalDeps):
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1}
    sbom["serialNumber"] = "urn:uuid:" + str(uuid.uuid4())
    depRelations = {}

    pkgDB = getPackageDatabase()
    appName = packageName
    appInfos = getPackageInformations(pkgDB, packageName)
    component = {"name": appName, "bom-ref": "pkg:" + appName, "type": "application"}

    version = appInfos.version
    qualifiers = ""
    if appInfos.release:
        version += "-" + appInfos.release
    version_without_epoch_or_arch = version

    if hasattr(appInfos, "arch"):
        version += "." + appInfos.arch
        if len(qualifiers) != 0:
            qualifiers += "&"
        qualifiers += "arch=" + appInfos.arch

    if appInfos.epoch != 0:
        version = str(appInfos.epoch) + ":" + version
        if len(qualifiers) != 0:
            qualifiers += "&"
        qualifiers += "epoch=" + str(appInfos.epoch)

    component["version"] = version

    component["supplier"] = {
        "name": appInfos.vendor if appInfos.vendor != "<NULL>" else "PowerDNS.COM BV",
        "url": ["https://www.powerdns.com"],
    }
    component["licenses"] = [{"license": {"id": licenseToSPDXIdentifier(appInfos.license)}}]
    component["purl"] = f"pkg:rpm/powerdns/{appName}@{version_without_epoch_or_arch}?{qualifiers}"

    depRelations["pkg:" + appName] = []

    sbom["metadata"] = {
        "timestamp": datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
        "authors": [{"name": "PowerDNS.COM BV"}],
        "component": component,
    }
    sbom["components"] = []
    sbom["dependencies"] = []

    processDependencies(pkgDB, sbom, appInfos, depRelations)
    processAdditionalDependencies(sbom, appInfos, additionalDeps, depRelations)

    for pkg, deps in depRelations.items():
        sbom["dependencies"].append({"ref": pkg, "dependsOn": deps})

    return sbom


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("Usage: %s <output file> <package> [static dependencies ...]" % (sys.argv[0]))

    staticDeps = []
    if len(sys.argv) > 3:
        staticDeps = sys.argv[3:]

    sbom = generateSBOM(sys.argv[2], staticDeps)

    with open(sys.argv[1], "w") as f:
        f.write(json.dumps(sbom))
