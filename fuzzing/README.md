Fuzzing the PowerDNS products
-----------------------------

This repository contains several fuzzing targets that can be used with generic
fuzzing engines like AFL and libFuzzer.

These targets are built by passing the `--enable-fuzz-targets` option to the
configure of the authoritative server and dnsdist, then building them as usual.
You can also build only these targets manually by going into the pdns/ directory
and issuing a `make fuzz_targets` command for the authoritative server,
or going into the pdns/dnsdistdist and issuing a `make fuzz_targets` command for
dnsdist.

The current targets cover:
- the auth and rec packet cache (`fuzz_target_packetcache`) ;
- MOADNSParser (`fuzz_target_moadnsparser`) ;
- the Proxy Protocol parser (`fuzz_target_proxyprotocol`) ;
- the HTTP parser we use (YaHTTP, `fuzz_target_yahttp`) ;
- ZoneParserTNG (`fuzz_target_zoneparsertng`).
- Parts of the ragel-generated parser (`parseRFC1035CharString` in
  `fuzz_target_dnslabeltext`) ;
- the dnsdist packet cache (`fuzz_target_dnsdistcache`).

By default the targets are linked against a standalone target,
`standalone_fuzz_target_runner.cc`, which does no fuzzing but makes it easy
to check a given test file, or just that the fuzzing targets can be built properly.

This behaviour can be changed via:
- either the `LIB_FUZZING_ENGINE` variable when building with `./configure`
- or the `-Dfuzzer_ldflags` option when building with `meson`

For example, setting `LIB_FUZZING_ENGINE` to `-lFuzzer`, then building with clang
by setting `CC=clang CXX=clang++` before running the `configure`, and adding
`-fsanitize=fuzzer-no-link` to `CFLAGS` and `CXXFLAGS`, instructs the compiler
to instrument the code for efficient fuzzing but not to link directly with
`-lFuzzer`, which would make the compilation tests done during the configure phase fail.

Sanitizers
----------

In order to catch the maximum of issues during fuzzing, it makes sense to
enable the `ASAN` and `UBSAN` sanitizers via `--enable-asan` and `--enable-ubsan`
options to the configure, or to set the appropriate flags directly.

Corpus
------

This directory contains a few files used for continuous fuzzing
of the PowerDNS products.

The `corpus` directory contains three sub-directories:
- `http-raw-payloads/` contains HTTP payloads of queries, used by
  `fuzz_target_yahttp` ;
- `proxy-protocol-raw-packets/` contains DNS queries prefixed with a Proxy
  Protocol v2 header, used by `fuzz_target_proxyprotocol` ;
- `raw-dns-packets/` contains DNS queries and responses as captured on
  the wire. These are used by the `fuzz_target_dnsdistcache`,
  `fuzz_target_moadnsparser` and `fuzz_target_packetcache` targets ;
- `zones/` contains DNS zones, used by the `fuzz_target_zoneparsertng`
  target.

When run in the OSS-Fuzz environment, the zone files from the
`regression-tests/zones/` directory are added to the ones present
in the `fuzzing/corpus/zones/` directory.

Quickly getting started (using clang 11)
----------------------------------------
First, configure the authoritative server:

```
LIB_FUZZING_ENGINE="/usr/lib/clang/11.0.1/lib/linux/libclang_rt.fuzzer-x86_64.a" \
  CC=clang \
  CXX=clang++ \
  CFLAGS='-fsanitize=fuzzer-no-link' \
  CXXFLAGS='-fsanitize=fuzzer-no-link' \
  ./configure --without-dynmodules --with-modules= --disable-lua-records --disable-ixfrdist --enable-fuzz-targets --disable-dependency-tracking --disable-silent-rules --enable-asan --enable-ubsan
```

If you build the fuzzing targets only, you will need to issue the following commands first:
```
make -j2 -C ext/arc4random/
make -j2 -C ext/yahttp/
```

Then build:

```
LIB_FUZZING_ENGINE="/usr/lib/clang/11.0.1/lib/linux/libclang_rt.fuzzer-x86_64.a" \
  make -C pdns -j2 fuzz_targets
```

or, if you are using `meson` to build the authoritative server instead of `./configure`:

```
env CC=clang CXX=clang++ \
  CFLAGS=-fsanitize=fuzzer-no-link CXXFLAGS=-fsanitize=fuzzer-no-link \
  meson setup .. -Dfuzz-targets=true -Dfuzzer_ldflags=/usr/lib/clang/18/lib/linux/libclang_rt.fuzzer-x86_64.a -Db_sanitize=address,undefined
ninja
```

Now you're ready to run one of the fuzzing targets.
First, copy the starting corpus:

```
mkdir new-corpus
./pdns/fuzz_target_XXXXXXX -merge=1 new-corpus fuzzing/corpus/YYYYY
```

Then run the thing:
```
./pdns_fuzz_target_XXXXXXX new-corpus
```

The [LLVM docs](https://llvm.org/docs/LibFuzzer.html) have more info.
