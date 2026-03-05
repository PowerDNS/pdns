#!/usr/bin/env python3

"""Filter git diff files that are not in the product.

Filter files out of a git diff output that are not part of the product found in
the current directory.

"""

import argparse
import os
import sys
from pathlib import Path

import helpers
import unidiff


def create_argument_parser():
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(description="Filter git diff files that are not in the product")
    parser.add_argument(
        "--product",
        type=str,
        required=True,
        help="Product (auth, dnsdist or rec)",
    )
    return parser.parse_args()


def main():
    """Start the script."""
    args = create_argument_parser()
    product = args.product

    compdb = helpers.load_compdb("compile_commands.json")
    compdb = helpers.index_compdb(compdb)

    cwd = Path(os.getcwd())

    diff = sys.stdin.read()
    patch_set = unidiff.PatchSet(diff)
    for patch in patch_set:
        # We have to deal with several possible cases for input files, as shown
        # by git:
        #
        # - in ext/: ext/lmdb-safe/lmdb-safe.cc
        # - in modules/: modules/lmdbbackend/lmdbbackend.cc
        # - files that live in the dnsdist or rec dir only:
        #   pdns/dnsdistdist/dnsdist-dnsparser.cc or
        #   pdns/recursordist/rec-tcp.cc
        # - files that live in pdns/ and are used by several products (but
        #   possibly not with the same compilation flags, so it is actually
        #   important that they are processed for all products: pdns/misc.cc
        path = Path(patch.path)
        if product == "auth":
            path = Path(cwd).joinpath(path)
        else:
            if str(path).startswith("modules"):
                print(
                    f"Skipping {path}: modules do not apply to {product}",
                    file=sys.stderr,
                )
                continue

            if str(path).startswith("ext"):
                subpath = Path(cwd).joinpath(path)
            else:
                subpath = Path(cwd).joinpath(path.name)

            if not subpath.exists():
                print(
                    f"Skip {path}: doesn't exist for {product} ({subpath})",
                    file=sys.stderr,
                )
                continue

            path = subpath
            if patch.source_file is not None:
                patch.source_file = str(path)
            patch.target_file = str(path)

        if not str(path) in compdb:
            print(
                f"Skipping {path}: it is not in the compilation db",
                file=sys.stderr,
            )
            continue

        print(patch, file=sys.stderr)
        print(patch)

    return 0


if __name__ == "__main__":
    sys.exit(main())
