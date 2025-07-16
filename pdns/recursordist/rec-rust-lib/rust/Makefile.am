CARGO ?= cargo

all install: librecrust.a

EXTRA_DIST = \
	Cargo.lock \
	Cargo.toml \
	build.rs \
	src/bridge.rs \
	src/helpers.rs \
        src/misc.rs \
        src/web.rs

# should actually end up in a target specific dir...
librecrust.a lib.rs.h web.rs.h misc.rs.h: \
	Cargo.lock \
	Cargo.toml \
	build.rs \
	src/bridge.rs \
	src/helpers.rs \
	src/lib.rs \
	src/misc.rs \
	src/web.rs
	SYSCONFDIR=$(sysconfdir) NODCACHEDIRNOD=$(localstatedir)/nod NODCACHEDIRUDR=$(localstatedir)/udr $(CARGO) build --release $(RUST_TARGET) --target-dir=$(builddir)/target --manifest-path ${srcdir}/Cargo.toml
	cp -pv target/$(RUSTC_TARGET_ARCH)/release/librecrust.a librecrust.a
	cp -pv target/$(RUSTC_TARGET_ARCH)/cxxbridge/recrust/src/lib.rs.h lib.rs.h
	cp -pv target/$(RUSTC_TARGET_ARCH)/cxxbridge/recrust/src/web.rs.h web.rs.h
	cp -pv target/$(RUSTC_TARGET_ARCH)/cxxbridge/recrust/src/misc.rs.h misc.rs.h
	cp -pv target/$(RUSTC_TARGET_ARCH)/cxxbridge/rust/cxx.h cxx.h

clean-local:
	rm -rf librecrust.a src/lib.rs lib.rs.h web.rs.h cxx.h misc.rs.h target
