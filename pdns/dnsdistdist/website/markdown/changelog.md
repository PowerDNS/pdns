# dnsdist 1.0.0-alpha2
Released February 5th 2016

Changes since 1.0.0-alpha1:

## New features

 * Lua functions now receive a DNSQuestion `dq` object instead of several parameters. This adds a greater compatibility with PowerDNS and allows adding more parameters without breaking the API ([#3198](https://github.com/PowerDNS/pdns/issues/3198))
 * Added a `source` option to `newServer()` to specify the local address or interface used to contact a downstream server ([#3138](https://github.com/PowerDNS/pdns/issues/3138))
 * CNAME and IPv6-only support have been added to spoofed responses ([#3064](https://github.com/PowerDNS/pdns/issues/3064))
 * `grepq()` can be used to search for slow queries, along with `topSlow()`
 * New Lua functions: `addDomainCNAMESpoof()`, `AllowAction()` by @bearggg, `exceedQRate()`, `MacAddrAction()`, `makeRule()`, `NotRule()`, `OrRule`, `QClassRule()`, `RCodeAction()`, `SpoofCNAMEAction()`, `SuffixMatchNodeRule()`, `TCPRule()`, `topSlow()`
 * `NetmaskGroup` support have been added in Lua ([#3144](https://github.com/PowerDNS/pdns/issues/3144))
 * Added `MacAddrAction()` to add the source MAC address to the forwarded query ([#3313](https://github.com/PowerDNS/pdns/issues/3313))

## Bug fixes

 * An issue in DelayPipe could make dnsdist crash at startup
 * `downstream-timeouts` metric was not always updated
 * `truncateTC` was unproperly updating the response length ([#3126](https://github.com/PowerDNS/pdns/issues/3126))
 * DNSCrypt responses larger than queries were unproperly truncated
 * An issue prevented info message from being displayed in non-verbose mode, fixed by Jan Broer
 * Reinstating an expired Dynamic Rule was not correctly logged ([#3323](https://github.com/PowerDNS/pdns/issues/3323))
 * Initialized counters in the TCP client thread might have cause FD and memory leak, reported by Martin Pels ([#3300](https://github.com/PowerDNS/pdns/issues/3300))
 * We now drop queries containing no question (qdcount == 0) ([#3290](https://github.com/PowerDNS/pdns/issues/3290))
 * Outstanding TCP queries count was not always correct ([#3288](https://github.com/PowerDNS/pdns/issues/3288))
 * A locking issue in exceedRespGen() might have caused crashs ([#3277](https://github.com/PowerDNS/pdns/issues/3277))
 * Useless sockets were created in client mode ([#3257](https://github.com/PowerDNS/pdns/issues/3257))
 * `addAnyTCRule()` was generating TC=1 responses even over TCP ([#3251](https://github.com/PowerDNS/pdns/issues/3251))

## Web interface
 * Cleanup of the HTML by Sander Hoentjen
 * Fixed an XSS reported by @janeczku ([#3217](https://github.com/PowerDNS/pdns/issues/3217))
 * Removed remote images
 * Set the charset to UTF-8, added some security-related and CORS HTTP headers
 * Added server latency by Jan Broer ([#3201](https://github.com/PowerDNS/pdns/issues/3201))
 * Switched to official minified versions of JS scripts, by Sander Hoentjen ([#3317](https://github.com/PowerDNS/pdns/issues/3317))
 * Don't log unauthenticated HTTP request as an authentication failure 

## Various documentation updates and minor cleanups:
 * Added documentation for Advanced DNS Protection features (Dynamic rules, `maintenance()`)
 * Make `topBandwidth()` default to the top 10 clients
 * Replaced readline with libedit
 * Added GPL2 License ([#3200](https://github.com/PowerDNS/pdns/issues/3200))
 * Added incbin License ([#3269](https://github.com/PowerDNS/pdns/issues/3269))
 * Updated completion rules
 * Removed wrong option `--daemon-no` by Stefan Schmidt
