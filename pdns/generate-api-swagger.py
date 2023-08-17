"""Produce API swagger YAML and JSON representations usable from C."""

import json
import sys

import yaml


def dump_hex(contents, array_name, string_name):
    """Dump the hex contents to stdout."""
    array = "static const unsigned char {0}[] = {{"
    string = "static const std::string {0}{{(const char*){1}, sizeof({1})}};"
    close_array = "};"

    print(array.format(array_name))
    for index, byte in enumerate(contents.encode()):
        if (index + 1) % 15 == 0:
            print()
        print(f"{byte:#x}", end=", ")
    print()
    print(close_array)

    print()
    print(string.format(string_name, array_name))


yaml_filename = sys.argv[1]

with open(yaml_filename, mode="r", encoding="utf-8") as f_in:
    yaml_contents = f_in.read()
    contents = yaml.safe_load(yaml_contents)
    json_contents = json.dumps(contents, indent=2, separators=(",", ": "))

    header = "#pragma once\n#include <string>"
    print(header)
    print()

    dump_hex(yaml_contents, "api_swagger_yamlData", "g_api_swagger_yaml")
    print()
    print("// -----------------------------------------------------------")
    print()
    dump_hex(json_contents, "api_swagger_jsonData", "g_api_swagger_json")
