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
    # It might be tempting to normalize the paths here instead of
    # rewriting the compilation database, but then clang-tidy
    # loses the depth of files in the repository, outputing for
    # example "credentials.cc" instead of "pdns/credentials.cc"
    compdb = helpers.load_compdb("compile_commands.json")
    compdb = helpers.index_compdb(compdb)

    pdns_path = os.path.join("pdns", "")
    cwd = os.getcwd()
    root = helpers.get_repo_root()

    diff = sys.stdin.read()
    patch_set = unidiff.PatchSet(diff)
    for patch in patch_set:
        path = os.path.join(root, patch.path)
        if path in compdb:
            if not patch.path.startswith(pdns_path):
                # If the file being diffed is not under the pdns/ directory, we
                # need to reconstruct its filename in the patch adding extra
                # paths that clang-tidy-diff will get rid of: this way
                # clang-tidy can work with the correct file path.
                #
                # Example with a source file under modules/:
                #   patch.path = modules/foo/foo.cc
                #   path       = /home/user/workspace/pdns/modules/foo/foo.cc
                #   cwd        = /home/user/workspace/pdns/pdns/
                #   relpath    = ../modules/foo/foo.cc
                #
                # Then the patch filenames would be:
                #   patch.source_file = a/pdns/../modules/foo/foo.cc
                #   patch.target_file = b/pdns/../modules/foo/foo.cc
                relpath = os.path.relpath(path, cwd)
                if patch.source_file is not None:
                    patch.source_file = os.path.join("a", "pdns", relpath)
                patch.target_file = os.path.join("b", "pdns", relpath)
            print(patch)
        else:
            msg = f"Skipping {path}: it is not in the compilation db"
            print(msg, file=sys.stderr)

    return 0


if __name__ == "__main__":
    sys.exit(main())
