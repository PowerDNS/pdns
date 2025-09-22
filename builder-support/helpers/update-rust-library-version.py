#!/usr/bin/python3
"""Update the Rust library version in the Cargo.toml file to keep it in sync with the product version."""

import shutil
import sys
import tempfile

def main():
    if len(sys.argv) != 4:
        print(f'Usage: {sys.argv[0]} <path/to/Cargo.toml> <package name> <version to set>')
        sys.exit(1)

    file_name = sys.argv[1]
    package_name = sys.argv[2]
    version = sys.argv[3]

    with tempfile.NamedTemporaryFile(mode='w+t', encoding='utf-8', delete=False) as generated_fp:
        with open(file_name, "r") as cargo_file:
            in_dnsdist_rust_package_section = False
            for line in cargo_file:
                if line.startswith('['):
                    in_dnsdist_rust_package_section = False
                elif line == f'name = "{package_name}"\n':
                    in_dnsdist_rust_package_section = True
                elif in_dnsdist_rust_package_section and line.startswith("version ="):
                    generated_fp.write(f"version = \"{version}\"\n")
                    continue
                generated_fp.write(line)
    shutil.move(generated_fp.name, file_name)

if __name__ == '__main__':
    main()
