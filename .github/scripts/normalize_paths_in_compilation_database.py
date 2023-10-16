#!/usr/bin/env python3

import argparse
import os

import json

import helpers

def create_argument_parser():
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="Normalize paths in compilation database"
    )
    parser.add_argument(
        "--version",
        type=str,
        required=True,
        help="Version number of the current build",
    )
    parser.add_argument('database')
    return parser.parse_args()

if __name__ == "__main__":
    """Start the script."""
    args = create_argument_parser()

    compDB = helpers.load_compdb(args.database)
    for entry in compDB:
        for key in ['file', 'directory']:
            if key in entry:
                entry[key] = helpers.normalize_dist_dir(args.version, entry[key])

    with open(args.database + '.temp', 'w', encoding='utf-8') as outputFile:
        json.dump(compDB, outputFile, ensure_ascii=False, indent=2)

    os.rename(args.database + '.temp', args.database)
