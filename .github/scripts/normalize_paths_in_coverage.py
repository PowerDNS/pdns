#!/usr/bin/env python

import os
import sys

if __name__ == '__main__':
    repositoryRoot = os.path.realpath(sys.argv[1])
    version = sys.argv[2]
    inputFile = sys.argv[3]
    outputFile = sys.argv[4]
    with open(inputFile, mode='r') as inputFilePtr:
        with open(outputFile, mode='w') as outputFilePtr:
            for line in inputFilePtr:
                if not line.startswith('SF:'):
                    outputFilePtr.write(line)
                    continue

                parts = line.split(':')
                if len(parts) != 2:
                    outputFilePtr.write(line)
                    continue

                source_file = parts[1].rstrip()
                # get rid of symbolic links
                target = os.path.realpath(source_file)

                # get rid of the distdir path, to get file paths as they are in the repository
                if f'pdns-{version}' in target:
                    # authoritative or tool
                    authPath = os.path.join(repositoryRoot, f'pdns-{version}')
                    relativeToAuth = os.path.relpath(target, authPath)
                    target = relativeToAuth
                elif f'pdns-recursor-{version}' in target:
                    recPath = os.path.join(repositoryRoot, 'pdns', 'recursordist', f'pdns-recursor-{version}')
                    relativeToRec = os.path.relpath(target, recPath)
                    target = os.path.join('pdns', 'recursordist', relativeToRec)
                elif f'dnsdist-{version}' in target:
                    distPath = os.path.join(repositoryRoot, 'pdns', 'dnsdistdist', f'dnsdist-{version}')
                    relativeToDist = os.path.relpath(target, distPath)
                    target = os.path.join('pdns', 'dnsdistdist', relativeToDist)
                else:
                    print(f'Ignoring {target} that we could not map to a distdir', file=sys.stderr)
                    continue

                # we need to properly map symbolic links
                fullPath = os.path.join(repositoryRoot, target)
                if os.path.islink(fullPath):
                    # get the link target
                    realPath = os.path.realpath(fullPath)
                    # and make it relative again
                    target = os.path.relpath(realPath, repositoryRoot)

                outputFilePtr.write(f"SF:{target}\n")
