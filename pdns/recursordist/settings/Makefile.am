# It's a bit dirty that this Makefile also generates a file inside rust/src (lib.rs). 

EXTRA_DIST = \
	cxxsettings-generated.cc \
	cxxsettings-private.hh \
	cxxsettings.hh \
	docs-new-preamble-in.rst \
	docs-old-preamble-in.rst \
	generate.py \
	rust-bridge-in.rs \
	rust-preamble-in.rs \
	table.py \
	rust/src/lib.rs

all: cxxsettings-generated.cc rust/src/lib.rs

BUILT_SOURCES=cxxsettings-generated.cc rust/src/lib.rs

# We need to clean in the Rust dir, as in some cases the Serde/CXX derive/generate code does not get
# re-run by cargo after rust/src/lib.rs changed because of a generate.py run. In that case we end up
# with an rust/src/lib.rs.h that does not contain e.g. field name or field type changes.
#
# Use patterns to avoid having two instances of generate run simultaneously, a well-known hack for GNU make
cxxsettings-generated%cc rust/src/lib%rs: table.py generate.py rust-preamble-in.rs rust-bridge-in.rs docs-old-preamble-in.rst docs-new-preamble-in.rst
	$(MAKE) -C rust clean
	$(PYTHON) generate.py

clean-local:
	rm -f cxxsettings-generated.cc rust/src/lib.rs

