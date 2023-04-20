#!/usr/bin/env python3

"""Filter git diff files that are not in the product.

Filter files out of a git diff output that are not part of the product found in
the current directory.

"""

import os
import sys

import helpers
import unidiff


def main():
    """Start the script."""
    compdb = helpers.load_compdb("compile_commands.json")
    compdb = helpers.index_compdb(compdb)

    root = helpers.get_repo_root()

    diff = sys.stdin.read()
    patch_set = unidiff.PatchSet(diff)
    for patch in patch_set:
        path = os.path.join(root, patch.path)
        if path in compdb:
            print(patch)

    return 0


if __name__ == "__main__":
    sys.exit(main())
