#!/usr/bin/env python3

import yaml
import argparse

from typing import Dict, Any, overload, cast
from collections.abc import Mapping

# This function was taken (and slightly modified) from https://github.com/instrumenta/openapi2jsonschema


# overload function signatures for different input types
@overload
def change_dict_values(
    d: Mapping[str, Any], prefix: str, version: str
) -> Dict[str, Any]: ...
@overload
def change_dict_values(d: list[Any], prefix: str, version: str) -> list[Any]: ...
@overload
def change_dict_values(d: Any, prefix: str, version: str) -> Any: ...


def change_dict_values(d: Any, prefix: str, version: str) -> Any:
    """
    Recursively traverses a dictionary, list, or scalar value, modifying values associated with the "$ref" key.

    Other values are left unchanged. The function handles nested dictionaries and lists.

    Args:
        d (Any): The input data structure (dict, list, or scalar) to process.
        prefix (str): The prefix to prepend to "$ref" values for versions less than "3".
        version (str): The version string used to determine how "$ref" values are modified.

    Returns:
        Any: The processed data structure with updated "$ref" values.
    """
    # Mapping case
    if isinstance(d, Mapping):
        m = cast(Mapping[str, Any], d)
        new: Dict[str, Any] = {}
        for k, v in m.items():  # k: str, v: Any
            if isinstance(v, Mapping):
                mv = cast(Mapping[str, Any], v)
                new[k] = change_dict_values(mv, prefix, version)
            elif isinstance(v, list):
                lv = cast(list[Any], v)
                new_list: list[Any] = []
                for x in lv:
                    new_list.append(change_dict_values(x, prefix, version))
                new[k] = new_list
            elif isinstance(v, str):
                if k == "$ref":
                    new[k] = (
                        f"{prefix}{v}"
                        if (version < "3")
                        else v.replace("#/components/schemas/", prefix)
                    )
                else:
                    new[k] = v
            else:
                new[k] = v
        return new

    # List case
    if isinstance(d, list):
        lv = cast(list[Any], d)
        out: list[Any] = []
        for x in lv:
            out.append(change_dict_values(x, prefix, version))
        return out

    # Scalar case
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("infile", type=str)
    ap.add_argument("outfile", type=str)
    args = ap.parse_args()

    data: dict | None = None
    with open(args.infile, "r") as r:
        data = yaml.safe_load(r)
    if data is None:
        return

    out = {"$id": "PowerDNS Auth Objects"}
    out["definitions"] = (
        change_dict_values(data, "", version=data["openapi"])
        .get("components", {})
        .get("schemas")
    )

    with open(args.outfile, "w") as w:
        yaml.safe_dump(out, w)


if __name__ == "__main__":
    main()
