#!/usr/bin/python3
"""Update the Rust library version in the Cargo.toml file to keep it in sync with the product version."""

import shutil
import sys
import tempfile
import re

def main():
    if len(sys.argv) != 4:
        print(f'Usage: {sys.argv[0]} <path/to/Cargo.toml> <package name> <version to set>')
        sys.exit(1)

    file_name = sys.argv[1]
    package_name = sys.argv[2]
    version = sys.argv[3]

    # convert the serial so that it conforms to Rust rules: x.x.x-whatever
    version = re.sub(r'([0-9]+\.[0-9]+\.[0-9]+)\.', r'\1-', version)
    with tempfile.NamedTemporaryFile(mode='w+t', encoding='utf-8', delete=False) as generated_fp:
        with open(file_name, 'r', encoding='utf-8') as cargo_file:
            in_rust_package_section = False
            for line in cargo_file:
                if line.startswith('['):
                    in_rust_package_section = False
                elif line == f'name = "{package_name}"\n':
                    in_rust_package_section = True
                elif in_rust_package_section and line.startswith("version ="):
                    generated_fp.write(f"version = \"{version}\"\n")
                    continue
                generated_fp.write(line)
    shutil.move(generated_fp.name, file_name)

if __name__ == '__main__':
    main()
