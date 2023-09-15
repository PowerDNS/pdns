# FFI-ABI DLSO backend

Allow to link against a dynamic library respecting: `dlsobackend_api.h` foreign function interface.

Library must be in sync with `PDNS_DLSO_ABI_VERSION` version is `2` as of 2022-09-21.

## FFI-ABI DLSO Settings

### `--dlso-path`

- `Path`
- Default: `empty`
- Mandatory

Mandatory path to the 3rd party lib to load, respecting the FFI-ABI declared in `dlsobackend_api`.

Example:

```txt
--dlso-path=/path/to/your/lib.so
```

### `--dlso-args`

- `String`
- Default; `empty`

Arbitrary argument to the 3rd party library, format, separator etc is library implementation detail.

Example:

```txt
# These options may not exist check your library options.
--dlso-args="mode=legacy,db_mode=btree"
```

### `--dlso-dnssec`

Enable *DNSSEC*.

```txt
--dlso-dnssec
```

#### Warning: passing `off` or `no`, TURN OF the option

```txt
--dlso-dnssec=no
# OR
--dlso-dnssec=off
```

Note: any other argument after `=` means activation.
