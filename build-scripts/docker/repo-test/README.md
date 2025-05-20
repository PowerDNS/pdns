# Tool for Testing PowerDNS Packages & Repositories

This directory contains the `generate-repo-files.py` script which can
generate all the required files to build and run a Docker image which
can download and run the latest version of a PowerDNS Authoritative
Server, Recursor or DNSDist release.

To see the supported releases do `./generate-repo-files.py --help`.

This tool is mainly used internally to test releases but might be useful
for others.

## Known Issues

- `--test-aarch64` really only makes sense if the test script is running on
  another platform (and so far we've assumed `x86_64` to be the default)

## Dependencies

- Python 3
  - Jinja2

## Usage

The steps assume you just want to run the script and have no experience
with Python.  If you do you can evaluate for yourself whether you need
some of these steps.

In the directory of this README and `generate-repo-files.py` file do:

- `python3 -m venv venv`
- `bash`
- `source venv/bin/activate`
- `pip install --upgrade pip`
- `pip install -r requirements.txt`
- `./generate-repo-files.py rec-45`
    - where `rec-45` is an example release, do
      `./generate-repo-files.py --help` to see all supported releases
    - do `./generate-repo-files.py --test rec-45` to also test the
      release

This will create files like `Dockerfile.rec-45.centos-7` and some
additional support file like `pdns.list.rec-45.*` and `pkg-pin`.

The Docker file can then be used to build an image: `docker build --no-cache --pull --file Dockerfile.rec-45.centos-7 --tag rec-45.centos-7 .`

And this image can be run with `docker run -it rec-45.centos-7` which
just runs `pdns_recursor --version`.

The image can be entered with `docker run -it rec-45.centos-7 /bin/bash`
where you can do `pdns_recursor` or whatever you like.

## Elaborations

### `--test`

This also tests the release by using the generated Docker files to build
an image and run a container using that image.

### `--run-output`

This argument can be a little unclear.  It is only applicable when
`--test` is also supplied and `--verbose` is *NOT* supplied; otherwise,
it is ignored.

Since run output is not a lot when testing releases it can be nice to
show the output from running the container even when `--verbose` is off
(where it can be drowned out in the verbose output).

## To Do

- medium priority:
    - make not using `--no-cache` and `--pull` for building a Docker
      image an option, currently these are always used
- low priority:
    - option to test a specific release version and not just the latest
- maybe:
    - make error codes we get for building and running containers
      readable if we can find a lib for this; otherwise, it requires too
      much maintenance
        - `errno` https://joeyh.name/code/moreutils/
    - parameter to test all the things!  (this can currently easily done
      by a shell script / command)
      - `for RELEASE in auth-42 auth-43 auth-44 auth-master rec-42 rec-43 rec-44 rec-45 rec-master dnsdist-15 dnsdist-16 dnsdist-master; do ./generate-repo-files.py --test $RELEASE; done`
