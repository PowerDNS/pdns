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
When filing a feature request, please start your issue title with "Feature request:",
this allows for quick distinguishing between issues and these requests.

Please be as elaborate as possible when describing the feature you need. Provide
at least the following information (if they are relevant):

* Use case (what is the 'masterplan' that requires this feature)
* Description of what the feature should do

## Filing an Issue or Bug
**Note:** if you're planning to file a security bug, look at our
[Security Policy](https://doc.powerdns.com/md/security/) first.

When filing an issue or bug report, make the title of the issue a very short
summary (e.g. "Recursor crash when some-setting is set to 'crash'"). In the
content of the issue, be as detailed as possible. Supply at least the following
information:

* PowerDNS version
* Where you got the software from (e.g. distribution, compiled yourself)
* Operating System and version
* Steps to reproduce: How can we reproduce the issue
* Expected behavior: what did you expect what would happen?
* Observed behavior: what actually happened when following the steps?
* Relevant logs: Please use code blocks (\`\`\`) to format console output, logs, and code as it's very hard to read otherwise.

If you have already looked deeper into the problem, provide what you found as
well.

# Filing a Pull Request
Code contributions are sent as a pull request on [GitHub](https://github.com/PowerDNS/pdns/pulls).
By submitting a Pull Request you agree to your code become GPLv2 licensed.

## Pull Request Guidelines
A pull request, at the least, should have:

* A clear and concise title (not e.g. 'Issue #1234')
* A description of the patch (what issue does it solve or what feature does it add)
* Documentation for the feature or when current behaviour changes
* Regression and/or unit tests

And must:
* Be filed against the master branch before any release branch
* Pass all tests in Travis

Information on the tests can be found in the repository at
[/regression-tests/README.md](https://github.com/PowerDNS/pdns/blob/master/regression-tests/README.md)
and
[/regression-tests.recursor/README.md](https://github.com/PowerDNS/pdns/blob/master/regression-tests.recursor/README.md).

## Commit Guidelines
* Tell why the change does what it does, not how it does it.
* The first line should be short (preferably less than 50 characters)
* The rest of the commit body should be wrapped at 72 characters (see [this](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html) for more info)
* If this commit fixes an issue, put "Closes #XXXX" in the message.
* Do not put whitespace fixes/cleanup and functionality changes in the same commit

# Coding Guidelines
At the moment there is no established coding guideline, but here are some
general guidelines:

* Don't have end-of-line whitespace
* Use spaces instead of tabs
* Stick to the style of the file you're editing
* Functions and classes must have a [docblock](http://www.stack.nl/~dimitri/doxygen/manual/docblocks.html)
