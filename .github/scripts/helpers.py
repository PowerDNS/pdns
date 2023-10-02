"""Helpers for dealing with git, compilation databases, etc."""

import pathlib
import json
import os
import sys

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

def normalize_dist_dir(version, distPath):
    """Map the path of a source file from inside the dist directory
       to its path in the git repository."""
    # get rid of the distdir path, to get file paths as they are in the repository
    repositoryPath = pathlib.Path(get_repo_root()).resolve()
    distPath = pathlib.Path(distPath).resolve()
    if f'pdns-{version}' in distPath.parts:
        # authoritative or tool
        authPath = repositoryPath.joinpath(f'pdns-{version}').resolve()
        relativeToAuth = distPath.relative_to(authPath)
        return str(repositoryPath.joinpath(relativeToAuth))

    if f'pdns-recursor-{version}' in distPath.parts:
        recPath = repositoryPath.joinpath('pdns', 'recursordist', f'pdns-recursor-{version}').resolve()
        relativeToRec = distPath.relative_to(recPath)
        return str(repositoryPath.joinpath('pdns', 'recursordist', relativeToRec).resolve())

    if f'dnsdist-{version}' in distPath.parts:
        dnsdistPath = repositoryPath.joinpath('pdns', 'dnsdistdist', f'dnsdist-{version}').resolve()
        relativeToDist = distPath.relative_to(dnsdistPath)
        return str(repositoryPath.joinpath('pdns', 'dnsdistdist', relativeToDist).resolve())

    print(f'Unable to map {distPath}', file=sys.stderr)
    return str(distPath)
