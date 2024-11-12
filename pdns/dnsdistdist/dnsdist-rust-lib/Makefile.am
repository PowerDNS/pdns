EXTRA_DIST = \
	settings-generator.py \
	dnsdist-rules-definitions.yml \
	rust/src/lib.rs

BUILT_SOURCES=rust/src/lib.rs

# all: rust/src/lib.rs libdnsdist_settings_cxx.a

# dnsdist_settings_cxx.cc rust/src/lib%rs: settings-generator.py dnsdist-rules-definitions.yml rust-pre-in.rs rust-middle-in.rs rust-post-in.rs dnsdist_settings_cxx_pre-in.cc dnsdist_settings_cxx_post-in.cc
# 	@if test "$(PYTHON)" = ":"; then echo "Settings definitions have changed, python is needed to regenerate the related settings files but python was not found. Please install python and re-run configure"; exit 1; fi
# 	@if ! $(PYTHON) --version | grep -q "Python 3"; then echo $(PYTHON) should be at least version 3. Please install python 3 and re-run configure; exit 1; fi
# 	$(MAKE) -C rust clean
# 	(cd ${srcdir} && $(PYTHON) settings-generator.py dnsdist-rules-definitions.yml)

# noinst_LIBRARIES = libdnsdist_settings_cxx.a
# libdnsdist_settings_cxx_a_SOURCES = dnsdist_settings_cxx.cc

all: rust/src/lib.rs

rust/src/lib%rs: settings-generator.py dnsdist-rules-definitions.yml rust-pre-in.rs rust-middle-in.rs rust-post-in.rs dnsdist-configuration-yaml-items-cxx-pre-in.cc
	@if test "$(PYTHON)" = ":"; then echo "Settings definitions have changed, python is needed to regenerate the related settings files but python was not found. Please install python and re-run configure"; exit 1; fi
	@if ! $(PYTHON) --version | grep -q "Python 3"; then echo $(PYTHON) should be at least version 3. Please install python 3 and re-run configure; exit 1; fi
	$(MAKE) -C rust clean
	(cd ${srcdir} && $(PYTHON) settings-generator.py dnsdist-rules-definitions.yml)

clean-local:
	rm dnsdist-configuration-yaml-items-cxx.cc
	rm -f rust/src/lib.rs
