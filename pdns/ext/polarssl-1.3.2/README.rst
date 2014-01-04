===================
README for PolarSSL
===================

Compiling
=========

There are currently three active build systems within the PolarSSL releases:

- Make
- CMake
- Microsoft Visual Studio

The main system used for development is CMake. That system is always the most up-to-date. The others should reflect all changes present in the CMake build system, but some features are not ported there by default.

Make
----

We intentionally only use the absolute minimum of **Make** functionality, as we have discovered that a lot of **Make** features are not supported on all different implementations of Make on different platforms. As such, the Makefiles sometimes require some handwork or `export` statements in order to work for your platform.

In order to build the source using Make, just enter at the command line:

    make

In order to run the tests, enter:

    make check

Depending on your platform, you might run into some issues. Please check the Makefiles in *library/*, *programs/* and *tests/* for options to manually add or remove for specific platforms. You can also check `the PolarSSL Knowledge Base <https://polarssl.org/kb>`_ for articles on your platform or issue.

In case you find that you need to do something else as well, please let us know what, so we can add it to the KB.

CMake
-----

In order to build the source using CMake, just enter at the command line:

    cmake .

    make

There are 3 different active build modes specified within the CMake buildsystem:

- Release.
  This generates the default code without any unnecessary information in the binary files.
- Debug.
  This generates debug information and disables optimization of the code.
- Coverage.
  This generates code coverage information in addition to debug information.

Switching build modes in CMake is simple. For debug mode, enter at the command line:

    cmake -D CMAKE_BUILD_TYPE:String="Debug" .

In order to run the tests, enter:

    make test

Microsoft Visual Studio
-----------------------

The build files for Microsoft Visual Studio are generated for Visual Studio 6.0 all future Visual Studio's should be able to open and use this older version of the build files.

The workspace 'polarssl.dsw' contains all the basic projects needed to build the library and all the programs. The files in tests are not generated and compiled, as these need a perl environment as well.

Example programs
================

We've included example programs for a lot of different features and uses in *programs/*. Most programs only focus on a single feature or usage scenario, so keep that in mind when copying parts of the code.

Tests
=====

PolarSSL includes a elaborate test suite in *tests/* that initially requires Perl to generate the tests files (e.g. *test_suite_mpi.c*). These files are generates from a **function file** (e.g. *suites/test_suite_mpi.function*) and a **data file** (e.g. *suites/test_suite_mpi.data*). The **function file** contains the template for each test function. The **data file** contains the test cases, specified as parameters that should be pushed into a template function.

Contributing
============

#. `Check for open issues <https://github.com/polarssl/polarssl/issues>`_ or
   `start a discussion <https://polarssl.org/discussions>`_ around a feature
   idea or a bug.
#. Fork the `PolarSSL repository on Github <https://github.com/polarssl/polarssl>`_
   to start making your changes.
#. Write a test which shows that the bug was fixed or that the feature works
   as expected.
#. Send a pull request and bug us until it gets merged and published. We will
   include your name in the ChangeLog :)
