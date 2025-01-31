CARGO ?= cargo

all install: libsettings.a

EXTRA_DIST = \
	Cargo.lock \
	Cargo.toml \
	build.rs \
	src/bridge.rs \
	src/helpers.rs \
        src/misc.rs \
        src/web.rs

# should actually end up in a target specific dir...
libsettings.a lib.rs.h web.rs.h misc.rs.h: \
	Cargo.lock \
	Cargo.toml \
	build.rs \
	src/bridge.rs \
	src/helpers.rs \
	src/lib.rs \
	src/misc.rs \
	src/web.rs
	SYSCONFDIR=$(sysconfdir) NODCACHEDIRNOD=$(localstatedir)/nod NODCACHEDIRUDR=$(localstatedir)/udr $(CARGO) build --release $(RUST_TARGET) --target-dir=$(builddir)/target --manifest-path ${srcdir}/Cargo.toml
	cp target/$(RUSTC_TARGET_ARCH)/release/libsettings.a libsettings.a
	cp target/$(RUSTC_TARGET_ARCH)/cxxbridge/settings/src/lib.rs.h lib.rs.h
	cp target/$(RUSTC_TARGET_ARCH)/cxxbridge/settings/src/web.rs.h web.rs.h
	cp target/$(RUSTC_TARGET_ARCH)/cxxbridge/settings/src/misc.rs.h misc.rs.h
	cp target/$(RUSTC_TARGET_ARCH)/cxxbridge/rust/cxx.h cxx.h

clean-local:
	rm -rf libsettings.a src/lib.rs lib.rs.h web.rs.h cxx.h misc.rs.h target
