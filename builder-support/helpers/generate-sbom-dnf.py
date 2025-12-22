#!/usr/bin/env python3
"""
This script uses dnf to generate a Software Bill of Materials
(SBOM) in CycloneDX JSON format.
"""
import datetime
import json
import os
import sys
import uuid

import dnf

def licenseToSPDXIdentifier(licenseName):
    licenseMap = {
        'BSD': 'BSD-3-Clause',
        'GPLv2': 'GPL-2.0-only',
        'GPLv2+': 'GPL-2.0-or-later',
        'LGPLv2+': 'LGPL-2.0-or-later',
        'MIT': 'MIT',
        'OpenLDAP': 'OLDAP-2.8',
        }
    if licenseName in licenseMap:
        return licenseMap[licenseName]
    return None

def getPackageDatabase():
    with dnf.Base() as db:
        conf = db.conf
        conf.installroot = '/'
        conf.substitutions.update_from_etc('/')
        db.read_all_repos()

        db.fill_sack(load_system_repo='auto', load_available_repos=True)
        query = db.sack.query()
        return query.installed()

def getPURL(pkg):
    # from https://github.com/package-url/purl-spec/blob/main/types-doc/rpm-definition.md
    # pkg:rpm/<namespace>/<name>@<version>?<qualifiers>#<subpath>
    name = pkg.name
    version = pkg.version
    if hasattr(pkg, 'cargo'):
        return f'pkg:cargo/{name}@{version}'

    vendor = pkg.vendor.lower()
    if vendor == 'oracle america':
        vendor = 'oracle'
    elif vendor == 'rocky enterprise software foundation':
        vendor = 'rocky'
    elif vendor == 'fedora project':
        vendor = 'fedora'

    if pkg.release:
        version += '-' + pkg.release
    qualifiers = ''
    if hasattr(pkg, 'arch'):
        if len(qualifiers) != 0:
            qualifiers += '&'
        qualifiers += 'arch=' + pkg.arch
    if pkg.epoch != 0:
        if len(qualifiers) != 0:
            qualifiers += '&'
        qualifiers += 'epoch=' + str(pkg.epoch)
    return f'pkg:rpm/{vendor}/{name}@{version}?{qualifiers}'

def getPackageInformations(pkgDB, packageName):
    matches = pkgDB.filter(name=packageName).run()
    if len(matches) == 0:
        print(f'-> Package {packageName} not found')
        return None
    return matches[0]

def getPackageVersion(pkg):
    if pkg.release:
        version = (pkg.version if pkg.epoch == 0 else str(pkg.epoch) + ':' + pkg.version) + '-' + pkg.release
    else:
        version = (pkg.version if pkg.epoch == 0 else str(pkg.epoch) + ':' + pkg.version)
    if hasattr(pkg, 'arch'):
        version += '.' + pkg.arch
    return version

def getLibraryBOMReference(pkg):
    return 'lib:' + pkg.name + '_' + getPackageVersion(pkg)

def addDependencyToSBOM(sbom, pkg, seen_deps):
    version = getPackageVersion(pkg)
    bom_ref = getLibraryBOMReference(pkg)
    if bom_ref in seen_deps:
        return False

    seen_deps[bom_ref] = True

    component = { 'name': pkg.name, 'bom-ref': bom_ref, 'type': 'library', 'version': version}

    if hasattr(pkg, 'vendor') and pkg.vendor is not None:
        component['supplier'] = {'name': pkg.vendor}
    if hasattr(pkg, 'publisher') and pkg.publisher is not None:
        component['publisher'] = pkg.publisher
    if hasattr(pkg, 'author') and pkg.author is not None:
        component['author'] = pkg.author
    if hasattr(pkg, 'purl'):
        component['purl'] = pkg.purl
    if hasattr(pkg, 'externalReferences'):
        component['externalReferences'] = pkg.externalReferences
    spdx_license = licenseToSPDXIdentifier(pkg.license)
    if spdx_license is None:
        component['licenses'] = [{'license': {'name': pkg.license}}]
    else:
        component['licenses'] = [{'license': {'id': spdx_license}}]
    if hasattr(pkg, 'sha256') and pkg.sha256 is not None:
        component['hashes'] = [{'alg': 'SHA-256', 'content': pkg.sha256}]
    component['purl'] = getPURL(pkg)

    sbom['components'].append(component)
    return True

def processDependencies(pkg_db, sbom, appInfos, depRelations, seen_deps):
    for require in appInfos.requires:
        if hasattr(require, 'name'):
            depName = require.name.split('(')[0]
            depSpec = require.name
        else:
            # hawkey.Reldep, el-8
            depName = str(require).split('(', maxsplit=1)[0]
            depSpec = require
        if depName in ['/bin/sh', 'config', 'ld-linux-x86-64.so.2', 'rpmlib', 'rtld']:
            continue
        if depName in seen_deps:
            continue
        seen_deps[depName] = True

        matches = pkg_db.filter(name=depName).run()
        if len(matches) == 0:
            flags = []
            matches = pkg_db.filter(*flags, provides__glob=[depSpec]).run()
            if len(matches) == 0:
                print(f'Unable to find a match for {depName}')
                continue
        if len(matches) > 1:
            print(f'Got {len(matches)} matches for {depName}')

        dep = matches[0]
        depRef = getLibraryBOMReference(dep)

        if addDependencyToSBOM(sbom, dep, seen_deps):
            depRelations['pkg:' + appInfos.name].append(depRef)

class StaticLibDep:
    def __init__(self, name, version, description, purl, external_refs, author, license_, sha256):
        self.epoch = 0
        self.release = None
        self.name = name
        self.version = version
        if description:
            self.description = description
        if purl:
            self.purl = purl
        self.externalReferences = external_refs
        if author:
            self.author = author
        self.supplier = None
        self.publisher = None
        self.license = license_
        if sha256:
            self.sha256 = sha256
        self.cargo = True

def mergeLibSBOM(sbom, appInfos, lib_sbom_path, depRelations, seen_deps):
    with open(lib_sbom_path, encoding="utf-8") as fd:
        lib_sbom_data = json.load(fd)
        component = lib_sbom_data['metadata']['component']
        main_component_name = component['name']
        pkg = StaticLibDep(main_component_name, component['version'], component['description'], component.get('purl'), component.get('externalReferences') or [], component.get('author') or None, component['licenses'][0]['expression'], component['hashes'][0]['content'] if 'hashes' in component else None)

        addDependencyToSBOM(sbom, pkg, seen_deps)
        depRef = 'lib:' + pkg.name
        depRelations['pkg:' + appInfos.name].append(depRef)

        sub_components = lib_sbom_data['components']
        for component in sub_components:
            pkg = StaticLibDep(component['name'], component['version'], None, component.get('purl'), component.get('externalReferences') or [], component.get('author') or None, component['licenses'][0]['expression'], component['hashes'][0]['content'] if 'hashes' in component else None)

            addDependencyToSBOM(sbom, pkg, seen_deps)
            depRef = getLibraryBOMReference(pkg)
            if not 'lib:' + main_component_name in depRelations:
                depRelations['lib:' + main_component_name] = []
            depRelations['lib:' + main_component_name].append(depRef)

def addAdditionalLibraryToSBOM(depFile, sbom, appInfos, depRelations, seen_deps):
    with open(depFile, encoding="utf-8") as depDataFile:
        depData = json.load(depDataFile)
        pkg = StaticLibDep(os.path.splitext(os.path.basename(depFile))[0], depData['version'], None, None, [], None, depData.get('license') or None, None)
        pkg.supplier = 'PowerDNS.COM BV'
        if 'publisher' in depData:
            pkg.publisher = depData['publisher']
        if 'SHA256SUM' in depData:
            pkg.sha256 = depData['SHA256SUM']
        elif 'SHA256SUM_x86_64' in depData:
            pkg.sha256 = depData['SHA256SUM_x86_64']
        if 'cargo-based' in depData:
            pkg.cargo = depData['cargo-based']

        depRef = 'lib:' + pkg.name
        addDependencyToSBOM(sbom, pkg, seen_deps)
        depRelations['pkg:' + appInfos.name].append(depRef)

def processAdditionalDependencies(sbom, appInfos, additionalDeps, depRelations, seen_deps):
    for additionalDepFile in additionalDeps:
        if additionalDepFile.endswith('cdx.json'):
            mergeLibSBOM(sbom, appInfos, additionalDepFile, depRelations, seen_deps)
        else:
            addAdditionalLibraryToSBOM(additionalDepFile, sbom, appInfos, depRelations, seen_deps)

def generateSBOM(packageName, additionalDeps):
    sbom = { 'bomFormat': 'CycloneDX', 'specVersion': '1.5', 'version': 1 }
    sbom['serialNumber'] = 'urn:uuid:' + str(uuid.uuid4())
    depRelations = {}

    pkg_db = getPackageDatabase()
    appName = packageName
    appInfos = getPackageInformations(pkg_db, packageName)
    component = { 'name': appName, 'bom-ref': 'pkg:' + appName, 'type': 'application'}

    version = appInfos.version
    qualifiers = ''
    if appInfos.release:
        version += '-' + appInfos.release
    version_without_epoch_or_arch = version

    if hasattr(appInfos, 'arch'):
        version += '.' + appInfos.arch
        if len(qualifiers) != 0:
            qualifiers += '&'
        qualifiers += 'arch=' + appInfos.arch

    if appInfos.epoch != 0:
        version = str(appInfos.epoch) + ':' + version
        if len(qualifiers) != 0:
            qualifiers += '&'
        qualifiers += 'epoch=' + str(appInfos.epoch)

    component['version'] = version

    component['supplier'] = {'name': appInfos.vendor if appInfos.vendor != '<NULL>' else 'PowerDNS.COM BV', 'url': ['https://www.powerdns.com']}
    component['licenses'] = [{'license': {'id': licenseToSPDXIdentifier(appInfos.license)}}]
    component['purl'] = f'pkg:rpm/powerdns/{appName}@{version_without_epoch_or_arch}?{qualifiers}'

    depRelations['pkg:' + appName] = []

    sbom['metadata'] = { 'timestamp': datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
                         'authors': [{'name': 'PowerDNS.COM BV'}],
                         'component': component }
    sbom['components'] = []
    sbom['dependencies'] = []

    seen_deps = {}
    processDependencies(pkg_db, sbom, appInfos, depRelations, seen_deps)
    processAdditionalDependencies(sbom, appInfos, additionalDeps, depRelations, seen_deps)

    for pkg, deps in depRelations.items():
        sbom['dependencies'].append({'ref': pkg, 'dependsOn': deps})

    return sbom

if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(f'Usage: {sys.argv[0]} <output file> <package> [static dependencies ...]')

    staticDeps = []
    if len(sys.argv) > 3:
        staticDeps = sys.argv[3:]

    sbom_content = generateSBOM(sys.argv[2], staticDeps)

    with open(sys.argv[1], "w", encoding="utf-8") as f:
        f.write(json.dumps(sbom_content))
