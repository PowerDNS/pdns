# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line.
SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
SPHINXPROJ    = dnsdist
SOURCEDIR     = .
BUILDDIR      = _build

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

upload: html latexpdf
	rsync -r $(BUILDDIR)/html/* mango.plexis.eu:/srv/www/dump.plexis.eu/pdns/dnsdist-docs/html
	rsync $(BUILDDIR)/latex/dnsdist.pdf mango.plexis.eu:/srv/www/dump.plexis.eu/pdns/dnsdist-docs


.PHONY: help Makefile

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
