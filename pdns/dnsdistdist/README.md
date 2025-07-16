# dnsdist
`dnsdist` is a highly DNS-, DoS- and abuse-aware loadbalancer. Its goal in
life is to route traffic to the best server, delivering top performance
to legitimate users while shunting or blocking abusive traffic.

`dnsdist` is dynamic, in the sense that its configuration can be changed at
runtime, and that its statistics can be queried from a console-like
interface.

All `dnsdist` features are documented at [dnsdist.org](https://dnsdist.org).

## Compiling from git

Make sure to `autoreconf -vi` before running `configure`.

## macOS Notes

Install dependencies from Homebrew:

```sh
brew install autoconf automake boost libedit libsodium libtool lua pkg-config protobuf
```

Let configure know where to find libedit, and openssl or libressl:

```sh
./configure 'PKG_CONFIG_PATH=/usr/local/opt/libedit/lib/pkgconfig:/usr/local/opt/libressl/lib/pkgconfig'
make
```
