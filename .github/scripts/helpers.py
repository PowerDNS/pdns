"""Helpers for dealing with git, compilation databases, etc."""

import json
import os

import git
import yaml


def load_file(filename):
    """Load the entire contents of a file."""
    with open(filename, encoding="utf-8") as file:
        contents = file.read()
        return contents


def get_line_from_offset(file_contents, offset):
    """Calculate line number from byte offset in source file."""
    return file_contents[:offset].count("\n") + 1


def get_repo_root():
    """Get the git repo's root directory."""
    cwd = os.getcwd()
    repo = git.Repo(cwd, search_parent_directories=True)
    root = repo.git.rev_parse("--show-toplevel")
    return root


def load_fixes_file(filename):
    """Load the clang-tidy YAML fixes file."""
    with open(filename, encoding="utf_8") as file:
        return yaml.safe_load(file)


def load_compdb(filename):
    """Load the compilation database."""
    with open(filename, encoding="utf_8") as file:
        return json.load(file)


def index_compdb(file_contents):
    """Index the compilation database."""
    result = set()
    for item in file_contents:
        filename = os.path.join(item["directory"], item["file"])
        result.add(filename)
    return result
