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

# It's a bit dirty that this target also generates a file inside rust/src (lib.rs). Also, we need to
# clean in the Rust dir, as in some cases the Serde/CXX derive/generate code does not get re-run by
# cargo after rust/src/lib.rs changed because of a generate.py run. In that case we end up with an
# rust/src/lib.rs.h that does not contain e.g. field name or field type changes.
cxxsettings-generated.cc: table.py generate.py rust-preamble-in.rs rust-bridge-in.rs docs-old-preamble-in.rst docs-new-preamble-in.rst
	$(MAKE) -C rust clean
	$(PYTHON) generate.py

clean-local:
	rm -f cxxsettings-generated.cc settings-old-generated.rst

