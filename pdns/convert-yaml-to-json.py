"""Convert a YAML file to JSON."""

import json
import sys

import yaml

yaml_filename = sys.argv[1]
json_filename = sys.argv[2]

with open(yaml_filename, mode="r", encoding="utf-8") as f_in:
    with open(json_filename, mode="w", encoding="utf-8") as f_out:
        contents = yaml.safe_load(f_in.read())
        json.dump(contents, f_out, indent=2, separators=(",", ": "))
