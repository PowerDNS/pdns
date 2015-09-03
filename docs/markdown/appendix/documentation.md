# Documentation details
The PowerDNS documentation started life as SGML DocBook, and was later converted (with great pain) to XML DocBook. Late 2014, 
Pieter Lexis contributed a Markdown conversion, which is the basis of the current documentation.

If you note an issue with the new documentation, please open a ticket on
[GitHub](https://github.com/powerdns/pdns/issues) and tell us about it. Or, even
better, fork our repo, and edit the files in docs/markdown to improve things.

If your change is simple (say, a typo or a new paragraph), you can do all this 
entirely from GitHub. Simply fork PowerDNS, find the Markdown file you want to change, 
edit in place, commit, and create a pull request.

## Building and testing
It's recommended to use a [virtualenv](https://virtualenv.pypa.io/en/latest/)
with the required packages to build the documentation.
[Virtualenvwrapper](http://virtualenvwrapper.readthedocs.org/en/latest/) can be
used to easily create and use a virtualenv.

Once you're in a virtualenv, `pip install mkdocs==0.14 pandocfilters==1.2.3 click==5.1 LinkChecker==9.3`.

To test-build the documentation, `make html/index.html` in the docs
directory will build the documentation into `html/`.

To test your changes live, use `cd docs/html && mkdocs serve && python -m SimpleHTTPServer`,
and the new version of your documentation will appear on port 8000 of your machine.
