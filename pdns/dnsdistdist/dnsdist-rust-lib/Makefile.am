EXTRA_DIST = \
	dnsdist-configuration-yaml-items-pre-in.cc \
	dnsdist-settings-generator.py \
	rust-pre-in.rs \
	rust-middle-in.rs \
	rust-post-in.rs

BUILT_SOURCES=rust/src/lib.rs \
	../dnsdist-configuration-yaml-items-generated.cc

all: rust/src/lib.rs ../dnsdist-configuration-yaml-items-generated.cc

rust/src/lib.rs ../dnsdist-configuration-yaml-items-generated.cc: dnsdist-settings-generator.py ../dnsdist-settings-definitions.yml rust-pre-in.rs rust-middle-in.rs rust-post-in.rs dnsdist-configuration-yaml-items-pre-in.cc ../dnsdist-actions-definitions.yml ../dnsdist-response-actions-definitions.yml ../dnsdist-selectors-definitions.yml
	@if test "$(PYTHON)" = ":"; then echo "Settings definitions have changed, python is needed to regenerate the related settings files but python was not found. Please install python and re-run configure"; exit 1; fi
	@if ! $(PYTHON) --version | grep -q "Python 3"; then echo $(PYTHON) should be at least version 3. Please install python 3 and re-run configure; exit 1; fi
	$(MAKE) -C rust clean
	(cd ${srcdir} && $(PYTHON) dnsdist-settings-generator.py ../ ./ ../)
