CARGO ?= cargo

EXTRA_DIST = \
	Cargo.toml \
	Cargo.lock

if HAVE_YAML_CONFIGURATION
all install: libdnsdist_rust.a

libdnsdist_rust.a: src/lib.rs Cargo.toml Cargo.lock
	SYSCONFDIR=$(sysconfdir) $(CARGO) build --release $(RUST_TARGET) --target-dir=$(builddir)/target --manifest-path ${srcdir}/Cargo.toml
	cp target/$(RUSTC_TARGET_ARCH)/release/libdnsdist_rust.a libdnsdist_rust.a
	cp target/$(RUSTC_TARGET_ARCH)/cxxbridge/settings/src/lib.rs.h lib.rs.h
	cp target/$(RUSTC_TARGET_ARCH)/cxxbridge/rust/cxx.h cxx.h

clean-local:
	rm -rf libdnsdist_rust.a lib.rs.h cxx.h target

endif
