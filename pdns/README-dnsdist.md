# dnsdist
`dnsdist` is a highly DNS-, DoS- and abuse-aware loadbalancer. Its goal in
life is to route traffic to the best server, delivering top performance
to legitimate users while shunting or blocking abusive traffic.

`dnsdist` is dynamic, in the sense that its configuration can be changed at
runtime, and that its statistics can be queried from a console-like
interface.

All `dnsdist` features are documented at [dnsdist.org](http://dnsdist.org).

## macOS Notes

Install dependencies from Homebrew:

```
$ brew install autoconf automake boost libedit libsodium libtool lua pkg-config protobuf
```

Bootstrap and let configure know where to find libedit:

```
$ ./bootstrap
$ ./configure --with-lua 'PKG_CONFIG_PATH=/usr/local/opt/libedit/lib/pkgconfig
$ make
```
