"""Generate docs using sphinx in a venv."""

import argparse
import glob
import itertools
import os
import subprocess
import sys
import venv
from pathlib import Path


def main():
    """Start the script."""
    args = create_argument_parser()

    source_root = args.source_root
    build_root = args.build_root

    # Create the venv.
    venv_directory = build_root.joinpath(args.venv_name)
    venv.create(
        venv_directory,
        with_pip=True,
        clear=True,
        upgrade_deps=True,
        prompt=args.venv_name,
    )

    # Install some stuff into the venv.
    requirements_file = source_root.joinpath(args.requirements_file)
    pip = venv_directory.joinpath("bin").joinpath("pip")
    subprocess.run([pip, "install", "-U", "pip", "setuptools"], check=True)
    subprocess.run([pip, "install", "-r", requirements_file], check=True)

    # Run sphinx to generate the docs
    source_directory = source_root.joinpath(args.source_directory)
    target_directory = build_root.joinpath(args.target_directory)
    files = [glob.glob(str(source_root.joinpath(pat))) for pat in args.files]
    files = list(itertools.chain.from_iterable(files))
    sphinx_build = venv_directory.joinpath("bin").joinpath("sphinx-build")

    if args.pdf_name:
        build_args = [
            sphinx_build,
            "-M",
            "latexpdf",
            source_directory,
            '.'
        ]
    else:
        build_args = [
            sphinx_build,
            "-b",
            "html",
            source_directory,
            target_directory,
        ]
    subprocess.run(
        build_args + files, # if files is empty, it means do all files
        check=True
    )
    if args.pdf_name:
        os.rename(build_root.joinpath('latex').joinpath(args.pdf_name), args.pdf_name)

def create_argument_parser():
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Build html and pdf docs for PowerDNS open source products"
    )
    parser.add_argument(
        "--build-root",
        type=Path,
        required=True,
        help="Build root",
    )
    parser.add_argument(
        "--source-root",
        type=Path,
        required=True,
        help="Source root",
    )
    parser.add_argument(
        "--venv-name",
        type=str,
        required=True,
        help="Name for the virtualenv",
    )
    parser.add_argument(
        "--requirements-file",
        type=Path,
        required=True,
        help="Package requirements file relative to the source root",
    )
    parser.add_argument(
        "--source-directory",
        type=Path,
        required=True,
        help="Docs directory relative to the source root (contains conf.py)",
    )
    parser.add_argument(
        "--target-directory",
        type=Path,
        required=True,
        help="Target directory relative to the build root",
    )
    parser.add_argument(
        "--pdf-name",
        type=Path,
        required=False,
        help="Generate pdf instead of html",
    )
    parser.add_argument(
        "files",
        type=Path,
        nargs="*",
        help="Input files relative to the source root",
    )
    return parser.parse_args()


if __name__ == "__main__":
    sys.exit(main())
