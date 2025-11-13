#!/usr/bin/env python3

"""Clang-tidy to Github Actions annotations converter.

Convert the YAML file produced by clang-tidy-diff containing warnings and
suggested fixes to Github Actions annotations.

"""

import argparse
import os
import sys
from pathlib import Path

import helpers


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
    return parser.parse_args()


def main():
    """Start the script."""
    args = create_argument_parser()

    repo_root_dir = Path(helpers.get_repo_root())
    fixes_path = Path(args.fixes_file)
    compdb_filename = os.path.join(fixes_path.parent, "compile_commands.json")
    compdb = helpers.load_compdb(compdb_filename)
    compdb = helpers.index_compdb(compdb)

    fixes = helpers.load_fixes_file(args.fixes_file)

    if not fixes:
        print("No diagnostics or warnings produced by clang-tidy")
        return 0

    gh_step_summary = os.getenv("GITHUB_STEP_SUMMARY")
    if gh_step_summary:
        # Print Markdown summary
        with open(gh_step_summary, "a", encoding="utf-8") as summary_fp:
            print("### clang-tidy summary", file=summary_fp)

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

        if filename == "":
            print(f"Meta error message from `{directory}`: {message}")
            continue

        full_filename = filename
        full_filename = Path(full_filename)
        full_filename = (
            full_filename.as_posix()
            if full_filename.is_absolute()
            else os.path.join(directory, filename)
        )

        try:
            file_contents = helpers.load_file(full_filename)
        except OSError:
            # Skip in case the file can't be found. This is usually one of
            # those "too many errors emitted, stopping now" clang messages.
            print(f"Skipping `{full_filename}` because it is not found")
            continue

        line = helpers.get_line_from_offset(file_contents, offset)

        rel_filename = Path(full_filename).resolve().relative_to(repo_root_dir)
        annotation = "".join(
            [
                f"::warning file={rel_filename},line={line}",
                f"::{message} ({name} - Level={level})",
            ]
        )
        print(annotation)

        # User-friendly printout
        print(f"{level}: {rel_filename}:{line}: {message} ({name})")

        if gh_step_summary:
            print(
                f"- **{rel_filename}:{line}** {message} (`{name}`)",
                file=summary_fp,
            )

        have_warnings = True

    return 1 if have_warnings else 0


if __name__ == "__main__":
    sys.exit(main())
