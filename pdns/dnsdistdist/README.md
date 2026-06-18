# dnsdist
`dnsdist` is a highly DNS-, DoS- and abuse-aware loadbalancer. Its goal in
life is to route traffic to the best server, delivering top performance
to legitimate users while shunting or blocking abusive traffic.

`dnsdist` is dynamic, in the sense that its configuration can be changed at
runtime, and that its statistics can be queried from a console-like
interface.

All `dnsdist` features are documented at [dnsdist.org](https://dnsdist.org).

## Compiling from git

We are now using [Meson](https://mesonbuild.com/) to build dnsdist.

Run `meson setup build`, then `meson compile -C build`.

You can list meson options by running `meson configure`, then set them like this
(for example for `yaml` option)

`meson setup --reconfigure build -Dyaml=enabled`

The default options for the various builds are in
[builder-support/debian/dnsdist/](builder-support/debian/dnsdist) - for example
[here for Debian bookworm](builder-support/debian/dnsdist/debian-bookworm/rules).

## macOS Notes

Install dependencies from Homebrew for the base build:

```sh
brew install meson luajit pkg-config boost cmake libsodium ragel gnutls libnghttp2 cloudflare-quiche re2
```

You also need to install pyyaml globally (make sure you are using brew pip3, not the default system one)

```sh
pip3 install pyyaml --break-system-packages
```

For yaml support (`-Dyaml=enabled`), you also need to install rust

```sh
brew install rust
```