# dnsdist 1.0.0-beta1
Released April 14th 2016

Changes since 1.0.0-alpha2:

## New features

 * Per-pool packet cache
 * Some actions do not stop the processing anymore when they match, allowing more complex setups: Delay, Disable Validation, Log, MacAddr, No Recurse and of course None
 * The new RE2Rule() is available, using the RE2 regular expression library to match queries, in addition to the existing POSIX-based RegexRule()
 * SpoofAction() now supports multiple A and AAAA records
 * Remote logging of questions and answers via Protocol Buffer

## Improvements

 * [#3405](https://github.com/PowerDNS/pdns/pull/3405) Add health check logging, `maxCheckFailures` to backend
 * [#3412](https://github.com/PowerDNS/pdns/pull/3412) Check config
 * [#3440](https://github.com/PowerDNS/pdns/pull/3440) Client operation improvements
 * [#3466](https://github.com/PowerDNS/pdns/pull/3466) Add dq binding for skipping packet cache in LuaAction (Jan Broer)
 * [#3499](https://github.com/PowerDNS/pdns/pull/3499) Add support for multiple carbon servers
 * [#3504](https://github.com/PowerDNS/pdns/pull/3504) Allow accessing the API with an optional API key
 * [#3556](https://github.com/PowerDNS/pdns/pull/3556) Add an option to limit the number of queued TCP connections
 * [#3578](https://github.com/PowerDNS/pdns/pull/3578) Add a `disable-syslog` option
 * [#3608](https://github.com/PowerDNS/pdns/pull/3608) Export cache stats to carbon
 * [#3622](https://github.com/PowerDNS/pdns/pull/3622) Display the ACL content on startup
 * [#3627](https://github.com/PowerDNS/pdns/pull/3627) Remove ECS option from response's OPT RR when necessary
 * [#3633](https://github.com/PowerDNS/pdns/pull/3633) Count "TTL too short" cache events
 * [#3677](https://github.com/PowerDNS/pdns/pull/3677) systemd-notify support

## Bug fixes

 * [#3388](https://github.com/PowerDNS/pdns/pull/3388) Lock the Lua context before executing a LuaAction
 * [#3433](https://github.com/PowerDNS/pdns/pull/3433) Check that the answer matches the initial query
 * [#3461](https://github.com/PowerDNS/pdns/pull/3461) Fix crash when calling rmServer() with an invalid index
 * [#355O](https://github.com/PowerDNS/pdns/pull/3550),[#3551](https://github.com/PowerDNS/pdns/pull/3551) Fix build failure on FreeBSD (Ruben Kerkhof)
 * [#3594](https://github.com/PowerDNS/pdns/pull/3594) Prevent EOF error for empty console response w/o sodium
 * [#3634](https://github.com/PowerDNS/pdns/pull/3634) Prevent dangling TCP fd in case setupTCPDownstream() fails
 * [#3641](https://github.com/PowerDNS/pdns/pull/3641) Under threshold, QPS action should return None, not Allow
 * [#3658](https://github.com/PowerDNS/pdns/pull/3658) Fix a race condition in MaxQPSIPRule


# dnsdist 1.0.0-alpha2
Released February 5th 2016

Changes since 1.0.0-alpha1:

## New features

 * Lua functions now receive a DNSQuestion `dq` object instead of several parameters. This adds a greater compatibility with PowerDNS and allows adding more parameters without breaking the API ([#3198](https://github.com/PowerDNS/pdns/issues/3198))
 * Added a `source` option to `newServer()` to specify the local address or interface used to contact a downstream server ([#3138](https://github.com/PowerDNS/pdns/issues/3138))
 * CNAME and IPv6-only support have been added to spoofed responses ([#3064](https://github.com/PowerDNS/pdns/issues/3064))
 * `grepq()` can be used to search for slow queries, along with `topSlow()`
 * New Lua functions: `addDomainCNAMESpoof()`, `AllowAction()` by @bearggg, `exceedQRate()`, `MacAddrAction()`, `makeRule()`, `NotRule()`, `OrRule()`, `QClassRule()`, `RCodeAction()`, `SpoofCNAMEAction()`, `SuffixMatchNodeRule()`, `TCPRule()`, `topSlow()`
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
