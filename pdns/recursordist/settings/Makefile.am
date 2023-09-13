EXTRA_DIST = \
	cxxsettings-private.hh \
	cxxsettings.hh \
	docs-old-preamble-in.rst \
	docs-new-preamble-in.rst \
	generate.py \
	rust-bridge-in.rs \
	rust-preamble-in.rs \
	table.py

all: cxxsettings-generated.cc

BUILT_SOURCES=cxxsettings-generated.cc

# It's a bit dirty that this target also generated a file inside rust/src (lib.rs)
cxxsettings-generated.cc: table.py generate.py rust-preamble-in.rs rust-bridge-in.rs docs-old-preamble-in.rst docs-new-preamble-in.rst
	$(PYTHON) generate.py

clean-local:
	rm -f cxxsettings-generated.cc settings-old-generated.rst

