# Compiling PowerDNS
**Note**: For now, see [the Open Source PowerDNS site](http://wiki.powerdns.com/). `./configure ; make ; make install` will do The Right Thing for most people.

PowerDNS can be compiled with modules built in, or with modules designed to be loaded at runtime. All that is configured before compiling using the well known autoconf/automake system.

To compile in modules, specify them as `--with-modules='mod1 mod2 mod3'`, substituting the desired module names. Each backend has a module name in the table at the beginning of its section.

To compile a module for inclusion at runtime, which is great if you are a unix vendor, use `--with-dynmodules='mod1 mod2 mod3'`. These modules then end up as .so files in the compiled libdir.

Starting with version 2.9.18, PowerDNS requires 'Boost' to compile, it is available for most operating systems. Otherwise, see [the Boost website](http://www.boost.org).

### AIX
Known to compile with gcc, but only since 2.9.8. AIX lacks POSIX semaphores so they need to be emulated, as with MacOS X.

### FreeBSD
Works fine, but use gmake. Pipe backend is currently broken, for reasons, see [PipeBackend](../authoritative/backend-pipe.md). Due to the threading model of FreeBSD, PowerDNS does not benefit from additional CPUs on the system.

The FreeBSD Boost include files are installed in `/usr/local/include`, so prefix `CXXFLAGS=-I/usr/local/include` to your `./configure` invocation.

### Linux
Linux is probably the best supported platform as most of the main coders are Linux users. The static DEB distribution is known to have problems on Debian 'Sid', but that doesn't matter as PowerDNS is a native part of Debian 'Sid'. Just `apt-get`!

### MacOS X
Did compile at one point but maintenance has lapsed. Let us know if you can provide us with a login on MacOS X or if you want to help.

### OpenBSD
Compiles but then does not work very well. We hear that it may work with more recent versions of gcc, please let us know on `<pdns-dev@mailman.powerdns.com>`.

### Solaris
Solaris 7 is supported, but only just. AAAA records do not work on Solaris 7. Solaris 8 and 9 work fine. The 'Sunpro' compiler has not been tried but is reported to be lacking large parts of the Standard Template Library, which PowerDNS relies on heavily. Use gcc and gmake (if available). Regular Solaris make has some issues with some PowerDNS Makefile constructs.

When compiling, make sure that you have `/usr/ccs/bin` in your path. Furthermore, with some versions of MySQL, you may have to add `LDFLAGS=-lz` before `./configure`.
