# Documentation details
The PowerDNS documentation started life as SGML DocBook, and was later converted (with great pain) to XML DocBook. Late 2014, 
Pieter Lexis contributed a Markdown conversion, which is the basis of the current documentation.

If you note an issue with the new documentation, please open a ticket on
https://github.com/powerdns/pdns/issues and tell us about it. Or, even
better, fork our repo, and edit the files in
https://github.com/PowerDNS/pdns/tree/master/pdns/docs/markdown to improve
things.

If your change is simple (say, a typo or a new paragraph), you can do all this 
entirely from GitHub. Simply fork PowerDNS, find the Markdown file you want to change, 
edit in place, commit, and create a fork request. 

To test-build the documentation, run ''pip install mkdocs'', ''pip install
pandoc'' and ''pip install pandocfilters'', followed by ''make
html-new/index.html'' in the pdns/docs directory.

To test your changes live, use ''mkdocs serve --dev-addr=0.0.0.0:8000'', and the new version
of your documentation will appear on port 8000 of your machine.

