Fuzzing the PowerDNS products
-----------------------------

This repository contains several fuzzing targets that can be used with generic
fuzzing engines like AFL and libFuzzer.

These targets are built by passing the --enable-fuzz-targets option to the
configure, then building as usual. You can also build only these targets
by going into the pdns/ directory and issuing a 'make fuzz_targets' command.

The current targets cover:
- the auth, dnsdist and rec packet caches (fuzz_target_packetcache and
  fuzz_target_dnsdistcache) ;
- MOADNSParser (fuzz_target_moadnsparser) ;
- ZoneParserTNG (fuzz_target_zoneparsertng).

By default the targets are linked against a standalone target,
pdns/standalone_fuzz_target_runner.cc, which does no fuzzing but makes it easy
to check a given test file, or just that the fuzzing targets can be built properly.

This behaviour can be changed via the LIB_FUZZING_ENGINE variable, for example
by setting it to -lFuzzer, building with clang by setting CC=clang CXX=clang++
before running the configure and adding '-fsanitize=fuzzer-no-link' to CFLAGS
and CXXFLAGS. Doing so instructs the compiler to instrument the code for
efficient fuzzing but not to link directly with -lFuzzer, which would make
the compilation tests done during the configure phase fail.

Sanitizers
----------

In order to catch the maximum of issues during fuzzing, it makes sense to
enable the ASAN and UBSAN sanitizers via --enable-asan and --enable-ubsan
options to the configure, or to set the appropriate flags directly.

Corpus
------

This directory contains a few files used for continuous fuzzing
of the PowerDNS products.

The 'corpus' directory contains two sub-directories:
- raw-dns-packets/ contains DNS queries and responses as captured on
  the wire. These are used by the fuzz_target_dnsdistcache,
  fuzz_target_moadnsparser and fuzz_target_packetcache targets ;
- zones/ contains DNS zones, used by the fuzz_target_zoneparsertng
  target.

When run in the OSS-Fuzz environment, the zone files from the
regression-tests/zones/ directory are added to the ones present
in the fuzzing/corpus/zones/ directory.
