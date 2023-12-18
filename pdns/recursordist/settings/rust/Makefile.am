CARGO ?= cargo

all install: libsettings.a

EXTRA_DIST = \
	Cargo.toml \
	Cargo.lock \
	build.rs \
	src/bridge.rs \
	src/helpers.rs

# should actually end up in a target specific dir...
libsettings.a lib.rs.h: src/bridge.rs src/lib.rs src/helpers.rs Cargo.toml Cargo.lock build.rs
	SYSCONFDIR=$(sysconfdir) NODCACHEDIRNOD=$(localstatedir)/nod NODCACHEDIRUDR=$(localstatedir)/udr $(CARGO) build --release $(RUST_TARGET)
	cp target/$(RUSTC_TARGET_ARCH)/release/libsettings.a libsettings.a
	cp target/$(RUSTC_TARGET_ARCH)/cxxbridge/settings/src/lib.rs.h lib.rs.h
	cp target/$(RUSTC_TARGET_ARCH)/cxxbridge/rust/cxx.h cxx.h

clean-local:
	rm -rf libsettings.a src/lib.rs lib.rs.h cxx.h target
