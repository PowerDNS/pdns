#!/usr/bin/env python3

"""Clang-tidy to Github Actions annotations converter.

Convert the YAML file produced by clang-tidy-diff containing warnings and
suggested fixes to Github Actions annotations.

"""

import argparse
import os
import sys

import yaml


def create_argument_parser():
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Convert clang-tidy output to Github Actions"
    )
    parser.add_argument(
        "--fixes-file",
        type=str,
        required=True,
        help="Path to the clang-tidy fixes YAML",
    )
    # parser.add_argument(
    #     "--prefix-dir",
    #     type=str,
    #     required=True,
    #     help="Project subdirectory",
    # )
    return parser.parse_args()


def get_line_from_offset(file_contents, offset):
    """Calculate line number from byte offset in source file."""
    return file_contents[:offset].count("\n") + 1


def load_fixes_file(filename):
    """Load the clang-tidy YAML fixes file."""
    with open(filename, encoding="utf_8") as file:
        return yaml.safe_load(file)


def load_file(filename):
    """Load the entire contents of a file."""
    with open(filename, encoding="utf-8") as file:
        contents = file.read()
        return contents


def main():
    """Start the script."""
    args = create_argument_parser()

    fixes = load_fixes_file(args.fixes_file)
    fixes = fixes["Diagnostics"]
    have_warnings = False
    for fix in fixes:
        name = fix["DiagnosticName"]
        level = fix["Level"]
        directory = fix["BuildDirectory"]
        diagnostic = fix["DiagnosticMessage"]
        offset = diagnostic["FileOffset"]
        filename = diagnostic["FilePath"]
        message = diagnostic["Message"]

        full_filename = directory + os.path.sep + filename
        try:
            file_contents = load_file(full_filename)
        except OSError:
            # Skip in case the file can't be found. This is usually one of
            # those "too many errors emitted, stopping now" clang messages.
            print(f"Skipping {full_filename}")
            continue

        line = get_line_from_offset(file_contents, offset)

        annotation = "".join(
            [
                f"::warning file={full_filename},line={line}",
                f"::{message} ({name} - Level={level})",
            ]
        )
        print(annotation)

        # User-friendly printout
        print(f"{level}: {full_filename}:{line}: {message} ({name})")

        have_warnings = True

    return 1 if have_warnings else 0


if __name__ == "__main__":
    sys.exit(main())
