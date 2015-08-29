===================
README for mbed TLS
===================

Configuration
=============

mbed TLS should build out of the box on most systems. Some platform specific options are available in the fully-documented configuration file *include/mbedtls/config.h*, which is also the place where features can be selected.
This file can be edited manually, or in a more programmatic way using the Perl
script *scripts/config.pl* (use *--help* for usage instructions).

Compiler options can be set using standard variables such as *CC* and *CFLAGS* when using the Make and CMake build system (see below).

Compiling
=========

There are currently three active build systems within the mbed TLS releases:

- Make
- CMake
- Microsoft Visual Studio (Visual Studio 6 and Visual Studio 2010)

The main system used for development is CMake. That system is always the most up-to-date. The others should reflect all changes present in the CMake build system, but some features are not ported there by default.

Make
----

We intentionally only use the absolute minimum of **Make** functionality, as we have discovered that a lot of **Make** features are not supported on all different implementations of Make on different platforms. As such, the Makefiles sometimes require some handwork or `export` statements in order to work for your platform.

In order to build the source using Make, just enter at the command line::

    make

In order to run the tests, enter::

    make check

The tests need Perl to be built and run. If you don't have Perl installed, you can skip buiding the tests with::

    make no_test

You'll still be able to run a much smaller set of tests with::

    programs/test/selftest

In order to build for a Windows platform, you should use WINDOWS_BUILD=1 if the target is Windows but the build environment is Unix-like (for instance when cross-compiling, or compiling from an MSYS shell), and WINDOWS=1 if the build environment is a Windows shell (for instance using mingw32-make) (in that case some targets will not be available).

Setting the variable SHARED in your environment will build a shared library in addition to the static library. Setting DEBUG gives you a debug build.  You can override CFLAGS and LDFLAGS by setting them in your environment or on the make command line; if you do so, essential parts such as -I will still be preserved.  Warning options may be overridden separately using WARNING_CFLAGS.

Depending on your platform, you might run into some issues. Please check the Makefiles in *library/*, *programs/* and *tests/* for options to manually add or remove for specific platforms. You can also check `the mbed TLS Knowledge Base <https://tls.mbed.org/kb>`_ for articles on your platform or issue.

In case you find that you need to do something else as well, please let us know what, so we can add it to the KB.

CMake
-----

In order to build the source using CMake, just enter at the command line::

    cmake .

    make

The test suites need Perl to be built. If you don't have Perl installed, you'll want to disable the test suites with::

    cmake -DENABLE_TESTING=Off .

There are many different build modes available within the CMake buildsystem. Most of them are available for gcc and clang, though some are compiler-specific:

- Release.
  This generates the default code without any unnecessary information in the binary files.
- Debug.
  This generates debug information and disables optimization of the code.
- Coverage.
  This generates code coverage information in addition to debug information.
- ASan.
  This instruments the code with AddressSanitizer to check for memory errors.
  (This includes LeakSanitizer, with recent version of gcc and clang.)
  (With recent version of clang, this mode also instruments the code with
  UndefinedSanitizer to check for undefined behaviour.)
- ASanDbg.
  Same as ASan but slower, with debug information and better stack traces.
- MemSan.
  This instruments the code with MemorySanitizer to check for uninitialised
  memory reads. Experimental, needs recent clang on Linux/x86_64.
- MemSanDbg.
  Same as MemSan but slower, with debug information, better stack traces and
  origin tracking.
- Check.
  This activates the compiler warnings that depend on optimization and treats
  all warnings as errors.

Switching build modes in CMake is simple. For debug mode, enter at the command line:

    cmake -D CMAKE_BUILD_TYPE:String="Debug" .

Note that, with CMake, if you want to change the compiler or its options after you already ran CMake, you need to clear its cache first, eg (using GNU find)::

    find . -iname '*cmake*' -not -name CMakeLists.txt -exec rm -rf {} +
    CC=gcc CFLAGS='-fstack-protector-strong -Wa,--noexecstack' cmake .

In order to run the tests, enter::

    make test

If you disabled the test suites, but kept the progams enabled, you can still run a much smaller set of tests with::

    programs/test/selftest

Microsoft Visual Studio
-----------------------

The build files for Microsoft Visual Studio are generated for Visual Studio 2010.

The solution file 'mbedTLS.sln' contains all the basic projects needed to build the library and all the programs. The files in tests are not generated and compiled, as these need a perl environment as well. However, the `selftest` program in *programs/test/* is still available.

Example programs
================

We've included example programs for a lot of different features and uses in *programs/*. Most programs only focus on a single feature or usage scenario, so keep that in mind when copying parts of the code.

Tests
=====

mbed TLS includes an elaborate test suite in *tests/* that initially requires Perl to generate the tests files (e.g. *test_suite_mpi.c*). These files are generates from a **function file** (e.g. *suites/test_suite_mpi.function*) and a **data file** (e.g. *suites/test_suite_mpi.data*). The **function file** contains the test functions. The **data file** contains the test cases, specified as parameters that will be passed to the test function.

For machines with a Unix shell and OpenSSL (and optionally GnuTLS) installed, additional test scripts are available:

- *tests/ssl-opt.sh* runs integration tests for various TLS options (renegotiation, resumption, etc.) and tests interoperability of these options with other implementations.
- *tests/compat.sh* tests interoperability of every ciphersuite with other implementations.
- *tests/scripts/test-ref-configs.pl* test builds in various reduced configurations.
- *tests/scripts/all.sh* runs a combination of the above tests, plus some more, with various build options (such as ASan, full *config.h*, etc).

Configurations
==============

We provide some non-standard configurations focused on specific use cases in the configs/ directory. You can read more about those in configs/README.txt

Contributing
============

We graciously accept bugs and contributions from the community. There are some requirements we need to fulfil in order to be able to integrate contributions in the main code.

Simple bug fixes to existing code do not contain copyright themselves and we can integrate those without any issue. The same goes for trivial contributions.

For larger contributions, e.g. a new feature, the code possible falls under copyright law. We then need your consent to share in the ownership of the copyright. We have a form for that, which we will mail to you in case you submit a contribution or pull request that we deem this necessary for.

Process
-------
#. `Check for open issues <https://github.com/ARMmbed/mbedtls/issues>`_ or
   `start a discussion <https://tls.mbed.org/discussions>`_ around a feature
   idea or a bug.
#. Fork the `mbed TLS repository on Github <https://github.com/ARMmbed/mbedtls>`_
   to start making your changes.
#. Write a test which shows that the bug was fixed or that the feature works
   as expected.
#. Send a pull request and bug us until it gets merged and published. We will
   include your name in the ChangeLog :)
