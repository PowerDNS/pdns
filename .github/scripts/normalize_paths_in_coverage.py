#!/usr/bin/env python

import os
import sys
from pathlib import Path

DEBUG = False


def debug_print(string):
    if DEBUG:
        print(string)


def get_relative_to_product_source_dir(product, target):
    if product == "auth":
        # authoritative or tool
        return target
    if product == "recursor":
        return os.path.join("pdns", "recursordist", target)
    if product == "dnsdist":
        return os.path.join("pdns", "dnsdistdist", target)
    return None


def remove_meson_dist_path(product, target):
    # target looks like this: /tmp/dnsdist-meson-dist-build/meson-dist/dnsdist-0.0.0-git1/xsk.hh
    path = Path(target)
    index = path.parts.index("meson-dist")
    # skip up to meson-dist and the directory below that,
    # so we now have: xsk.hh
    relevant = str(path.relative_to(path.parents[len(path.parts) - (index + 3)]))
    return get_relative_to_product_source_dir(product, relevant)


def remove_dist_dir_path(repositoryRoot, version, target):
    # get rid of the distdir path, to get file paths as they are in the repository
    # if we are building from meson, it might look like this:
    # /__w/pdns/pdns/pdns/dnsdistdist/dnsdist-0.0.0-git1/config.h
    if f"pdns-{version}" in target:
        # authoritative or tool
        authPath = os.path.join(repositoryRoot, f"pdns-{version}")
        relativeToAuth = os.path.relpath(target, authPath)
        target = get_relative_to_product_source_dir("auth", relativeToAuth)
        return target
    if f"pdns-recursor-{version}" in target:
        recPath = os.path.join(repositoryRoot, "pdns", "recursordist", f"pdns-recursor-{version}")
        relativeToRec = os.path.relpath(target, recPath)
        return get_relative_to_product_source_dir("recursor", relativeToRec)
    if f"dnsdist-{version}" in target:
        distPath = os.path.join(repositoryRoot, "pdns", "dnsdistdist", f"dnsdist-{version}")
        relativeToDist = os.path.relpath(target, distPath)
        target = get_relative_to_product_source_dir("dnsdist", relativeToDist)
        return target

    # let's assume we already have a full path to the repository, like
    # /__w/pdns/pdns/pdns/auth-catalogzone.hh
    distPath = os.path.join(repositoryRoot)
    relativeToDist = os.path.relpath(target, distPath)
    return relativeToDist


def process():
    repositoryRoot = os.path.realpath(sys.argv[1])
    product = sys.argv[2]
    version = sys.argv[3]
    inputFile = sys.argv[4]
    outputFile = sys.argv[5]
    with open(inputFile, mode="r", encoding="utf-8") as inputFilePtr:
        with open(outputFile, mode="w", encoding="utf-8") as outputFilePtr:
            for line in inputFilePtr:
                if not line.startswith("SF:"):
                    outputFilePtr.write(line)
                    continue

                parts = line.split(":")
                if len(parts) != 2:
                    outputFilePtr.write(line)
                    continue

                source_file = parts[1].rstrip()
                # get rid of symbolic links
                target = os.path.realpath(source_file)
                debug_print(f"- Got source_file={source_file}, target={target}")

                if "/meson-dist/" in target:
                    # this is a file that comes from a meson dist tarball
                    target = remove_meson_dist_path(product, target)
                    debug_print(f"meson-dist -> target={target}")
                else:
                    target = remove_dist_dir_path(repositoryRoot, version, target)
                    debug_print(f"dist dir -> target={target}")

                if target is None:
                    continue

                # we need to properly map symbolic links
                fullPath = os.path.join(repositoryRoot, target)
                debug_print(f"fullPath is {fullPath}")
                if os.path.islink(fullPath):
                    # get the link target
                    realPath = os.path.realpath(fullPath)
                    # and make it relative again
                    target = os.path.relpath(realPath, repositoryRoot)

                debug_print(f"=> final target is {target}")
                outputFilePtr.write(f"SF:{target}\n")


if __name__ == "__main__":
    process()
