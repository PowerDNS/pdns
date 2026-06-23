Fuzzing the PowerDNS products
-----------------------------

This repository contains several fuzzing targets that can be used with generic
fuzzing engines like AFL and libFuzzer. Most targets are part of the authoritative
server build, but there are also a few targets that are specific to dnsdist and are
therefore built along with dnsdist.

The targets are built by passing the `fuzz-targets=true` option to `meson`,
or the `--enable-fuzz-targets` option to `configure` when building with `autotools`,
then building as usual.
You can also build only these targets manually by:
- issuing `meson compile fuzz-targets` when using `meson`, or going into the pdns/
directory and issuing a `make fuzz_targets` command for the authoritative server targets,
- going into the pdns/dnsdistdist directorty and issuing `meson compile -C ${build_dir} fuzz-targets`
or a `make fuzz_targets` command for dnsdist targets.

The current targets cover:
- the auth and rec packet cache (`fuzz_target_packetcache`) ;
- MOADNSParser (`fuzz_target_moadnsparser`) ;
- getEDNSOptions, getEDNSOptionsFromContent, DNSPacketWriter and MOADNSParser (`fuzz_target_dnspacketroundtrip`) ;
- DNSRecordContent (`fuzz_recordcontent`) ;
- the Proxy Protocol parser (`fuzz_target_proxyprotocol`) ;
- the HTTP parser we use (YaHTTP, `fuzz_target_yahttp`) ;
- ZoneParserTNG (`fuzz_target_zoneparsertng`).
- Parts of the ragel-generated parser (`parseRFC1035CharString` in
  `fuzz_target_dnslabeltext`) ;
- the dnsdist packet cache (`fuzz_target_dnsdistcache`) ;
- EDNS Client Subnet handling in dnsdist (`fuzz_dnsdist_ecs`).

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

The `corpus` directory contains several sub-directories:
- `http-raw-payloads/` contains HTTP payloads of queries, used by
  `fuzz_target_yahttp` ;
- `proxy-protocol-raw-packets/` contains DNS queries prefixed with a Proxy
  Protocol v2 header, used by `fuzz_target_proxyprotocol` ;
- `raw-dns-packets/` contains DNS queries and responses as captured on
  the wire. These are used by the `fuzz_target_dnsdistcache`,
  `fuzz_target_moadnsparser` and `fuzz_target_packetcache` targets ;
- `raw-xsk-frames` contains Ethernet frames containing IP-encapsulated
  DNS queries and responses, as parsed by dnsdist's `AF_XDP`/`XSK` code.
  These are used by the `fuzz_xsk` target ;
- `txt-records` contains DNS TXT records in zone format, and are used by the
  `fuzz_target_dnslabeltext_parseRFC1035CharString` target ;
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


Continuous fuzzing
------------------

PowerDNS fuzzing targets are regularly run on Google's OSS-Fuzz platform: https://google.github.io/oss-fuzz/

The PowerDNS fuzzing project configuration can be found in the OSS-Fuzz repository: https://github.com/google/oss-fuzz/tree/master/projects/powerdns

Issues uncovered on OSS-Fuzz are privately reported to the contacts listed in the `project.yaml` file, and are subject to a fixed 90-days disclosure timeline by default. A reproducer testcase is provided with the issue, and can be passed to the corresponding fuzzing target as its first argument on the command-line to reproduce the issue.
Once an issue has been fixed in the public repository and confirmed fixed by OSS-Fuzz, the issue is automatically made public. See for example: https://issues.oss-fuzz.com/issues/523165457

The current status of the project can be reviewed on OSS-Fuzz's introspector: https://introspector.oss-fuzz.com/project-profile?project=powerdns

In addition to OSS-Fuzz, the fuzzing targets are also executed for each pull request opened against the public PowerDNS repository, using CI-Fuzz via the workflow defined in `.github/workflows/fuzz.yml`.
On CI-Fuzz, only fuzzing targets related to code that has been modified by the current pull request are executed, the others are skipped. The fuzzer is executed for a short period: 600 seconds in our case, so it will not catch all issues, but it gives the fuzzer a chance to catch it early in the process, before a PR has been merged.
