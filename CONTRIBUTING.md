Contributing to PowerDNS
------------------------
Thank you for you interest to contribute to the PowerDNS project. This document
will explain some of the things you need to keep in mind when contributing to
ease the workflow of this.

# Issue Tracker
When you post an issue or feature request to the
[issue tracker](https://github.com/PowerDNS/pdns/issues), make sure this hasn't
been reported before. If there is an open issue, add extra information on this
issue or show that you have the same issue/want this feature by adding a `:+1:`.

If there is no similar issue, feature request or you're not sure, open a new
issue.

## Filing a Feature Request
When filing a feature request, please use the Feature request template provided.

Please be as elaborate as possible when describing the feature you need. Provide
at least the following information (if they are relevant):

* Use case (what is the 'masterplan' that requires this feature)
* Description of what the feature should do

## Filing an Issue or Bug
**Note:** if you're planning to file a security bug, look at our
[Security Policy](https://github.com/PowerDNS/pdns/security/policy) first.

When filing an issue or bug report, write a very short summary (e.g.
"Recursor crashes when some-setting is set to 'crash'") for the title. In the
content of the issue, be as detailed as possible. Supply at least the following
information:

* PowerDNS version
* Where you got the software from (e.g. distribution, compiled yourself)
* Operating System and version
* Steps to reproduce: How can we reproduce the issue
* Expected behavior: what did you expect what would happen?
* Observed behavior: what actually happened when following the steps?
* Relevant logs: Please use code blocks (\`\`\`) to format console output, logs, and code as it's very hard to read otherwise.

We provide convenient templates that make it easy to not forget any of these steps.

If you have already looked deeper into the problem, provide what you found as
well.

# Filing a Pull Request
Code contributions are sent as a pull request on [GitHub](https://github.com/PowerDNS/pdns/pulls).
By submitting a Pull Request you agree to your code becoming GPLv2 licensed.

## Pull Request Guidelines
A pull request, at the least, should have:

* A clear and concise title (not e.g. 'Issue #1234')
* A description of the patch (what issue does it solve or what feature does it add)
* Documentation for the feature or when current behaviour changes
* Regression and/or unit tests

And must:
* Be filed against the master branch before any release branch
* Pass all tests in our CI (currently GitHub Actions and CircleCI)

Information on the tests can be found in the repository at
[/regression-tests/README.md](https://github.com/PowerDNS/pdns/blob/master/regression-tests/README.md)
,
[/regression-tests.recursor/README.md](https://github.com/PowerDNS/pdns/blob/master/regression-tests.recursor/README.md),
plus various other directories with `regression-tests.*` names.

## Commit Guidelines
* Tell why the change does what it does, not how it does it.
* The first line should be short (preferably less than 50 characters)
* The rest of the commit body should be wrapped at 72 characters (see [this](https://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html) for more info)
* If this commit fixes an issue, put "Closes #XXXX" in the message
* Do not put whitespace fixes/cleanup and functionality changes in the same commit
* Include a valid Signed-Off line as a [Developer Certificate of Origin](https://en.wikipedia.org/wiki/Developer_Certificate_of_Origin), version [1.1](https://github.com/PowerDNS/pdns/blob/master/DCO)

# Developer Certificate of Origin

We require a "Signed-Off" on all commits contributed to the PowerDNS codebase, as a [Developer Certificate of Origin](https://en.wikipedia.org/wiki/Developer_Certificate_of_Origin), version [1.1](https://github.com/PowerDNS/pdns/blob/master/DCO)

If you have properly configured `user.name` and `user.email` in your `Git` configuration, `Git` includes a `-s` command line option to append this line automatically to your commit message:

```sh
git commit -s -m 'Commit message'
```

If you already committed your changes, and you have only one commit on your branch, you can use `git commit --amend --signoff` to add a sign-off to the latest commit.
If you have more than one commit on your branch, you can instead use `git rebase` to add a sign-off to existing commits. For example, if your branch is based on the `master` one:

```sh
git rebase --signoff master
```

# Formatting and Coding Guidelines

## `clang-format`

We have `clang-format` in place, but not for all files yet. We are working towards a fully formatted codebase in an incremental fashion.

If you're adding new code, adhering to the formatting configuration available in `.clang-format` is appreciated. If you are touching code that is not yet formatted, it would also be very appreciated to format it in a separate commit first.

Any formatting breakage in already formatted files will be caught by the CI. To format all files that are supposed to be formatted, run `make format-code` in the root of the tree.

## Formatting guidelines

* Don't have end-of-line whitespace.
* Use spaces instead of tabs.

## Coding guidelines

The coding guidelines can be found in the repository at
[CODING_GUIDELINES.md](https://github.com/PowerDNS/pdns/blob/master/CODING_GUIDELINES.md)

## Code Checkers

### `clang-tidy`

`clang-tidy` requires a [compilation database](https://clang.llvm.org/docs/JSONCompilationDatabase.html) to work.
See the ["Compilation Database" section of the DEVELOPMENT document](DEVELOPMENT.md#compilation-database) on how to generate a compilation database.

Once the compilation database has been generated, you can pick one of the two available `clang-tidy` configuration files to run checks on source files.
Picking a configuration file is a matter of creating a symbolic link called `.clang-tidy` to said file in the topmost level of the sub-project you're working on (or the toplevel repository directory if you're working on PowerDNS auth).

We provide two configuration files for `clang-tidy`:

1. A minimal [.clang-tidy.bugs](.clang-tidy.bugs) which only enables a few checks for common bugs.
   This configuration can be enabled using `ln -sf .clang-tidy.bugs .clang-tidy`.

2. A more complete [.clang-tidy.full](.clang-tidy.full) which enables almost all available checks.
   This configuration can be enabled using `ln -sf .clang-tidy.full .clang-tidy` and is recommended for all new code.

### `clang-tidy` and CI

We run `clang-tidy` using the `.clang-tidy.full` configuration as part of our CI. `clang-tidy` warnings will show up on a pull request if any are introduced.

However, it may happen that existing code could produce warnings and can show up too due to being part of the pull request. In such a case there are two options:

1. Fix the warnings in a separate commit.
2. If fixing the warning would be too much trouble at this point in time, disabling the specific warning using the `// NOLINTNEXTLINE` or `// NOLINT` directives can be acceptable given the following is adhered to:

Any added `// NOLINTNEXTLINE` or `// NOLINT` directive or others need to have a GitHub issue title, issue number and link next to them in the description along with the name or GitHub nickname of the person that wrote it. The GitHub issue must have an assignee and an accurate description of what needs to be done. As an example:

`// NOLINTNEXTLINE(<warning-name>) <issue-number> <issue-link> <person-name>: <issue-title> + a short comment if needed.`

If the warning cannot be avoided in any way, a good explanation is needed. As an example:

`// NOLINTNEXTLINE(*-cast): Using the OpenSSL C APIs.`

### Additional checkers

Even though we don't automatically run any of the code checkers listed below as part of our CI, it might make sense to run them manually, not only on newly added code, but to also improve existing code.

* `clang`'s static analyzer, sometimes also referred as `scan-build`
* `cppcheck`

# Development Environment

Information about setting up a development environment using a language server like [`clangd`](https://clangd.llvm.org/) or [`ccls`](https://github.com/MaskRay/ccls) can be found in [DEVELOPMENT.md](DEVELOPMENT.md).

# Debugging

## Using GDB

To get a good debugging experience with `gdb`, it is recommended to build PowerDNS using the following flags:

* `CC` and `CXX` set to `gcc` and `g++`, respectively.
* `CFLAGS` and `CXXFLAGS` set to `-ggdb -Og -fno-inline`.

These variables need to be set during the `configure` step, as follows:

```sh
export CC=clang CXX=clang++
export CFLAGS="-ggdb -Og -fno-inline" CXXFLAGS="-ggdb -Og -fno-inline"
./configure --with-modules=gsqlite3 --disable-lua-records --enable-unit-tests
make -j 8
```

[GDB Dashboard](https://github.com/cyrus-and/gdb-dashboard) can be used to vastly improve the GDB debugging experience.
