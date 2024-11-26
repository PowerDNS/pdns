EXTRA_DIST = \
	settings-generator.py \
	dnsdist-settings-definitions.yml \
	rust/src/lib.rs

BUILT_SOURCES=rust/src/lib.rs

all: rust/src/lib.rs

rust/src/lib.rs: settings-generator.py dnsdist-settings-definitions.yml rust-pre-in.rs rust-middle-in.rs rust-post-in.rs dnsdist-configuration-yaml-items-cxx-pre-in.cc ../dnsdist-actions-definitions.yml ../dnsdist-response-actions-definitions.yml ../dnsdist-selectors-definitions.yml
	@if test "$(PYTHON)" = ":"; then echo "Settings definitions have changed, python is needed to regenerate the related settings files but python was not found. Please install python and re-run configure"; exit 1; fi
	@if ! $(PYTHON) --version | grep -q "Python 3"; then echo $(PYTHON) should be at least version 3. Please install python 3 and re-run configure; exit 1; fi
	$(MAKE) -C rust clean
	(cd ${srcdir} && $(PYTHON) settings-generator.py dnsdist-settings-definitions.yml)

clean-local:
	rm -f dnsdist-configuration-yaml-items-cxx.cc
	rm -f rust/src/lib.rs
