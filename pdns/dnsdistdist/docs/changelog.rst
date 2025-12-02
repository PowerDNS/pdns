Changelog
=========

.. changelog::
  :version: 2.0.2
  :released: 2nd of December 2025

  .. change::
    :tags: Bug Fixes
    :pullreq: 16309

    Fix query rules bypass after tagging from a dynblock

  .. change::
    :tags: Improvements
    :pullreq: 16310
    :tickets: 16137

    Update the Rust library version when generating a tarball

  .. change::
    :tags: Improvements, Performance
    :pullreq: 16315

    Make inserting to the in-memory rings a bit faster

  .. change::
    :tags: Improvements
    :pullreq: 16316
    :tickets: 16249

    Allow selecting a specific version of Lua with meson

  .. change::
    :tags: Bug Fixes
    :pullreq: 16317
    :tickets: 16248

    ComboAddress: Fix "unspecified address" test when the port is set

  .. change::
    :tags: Bug Fixes
    :pullreq: 16318
    :tickets: 16221

    Set up the dns header for timeout response rules

  .. change::
    :tags: Bug Fixes
    :pullreq: 16319
    :tickets: 16242

    Fix handling of large XSK frames (ednaq)

  .. change::
    :tags: Improvements
    :pullreq: 16320

    Make the round-robin LB policy internal counter atomic

  .. change::
    :tags: Bug Fixes
    :pullreq: 16322
    :tickets: 16221

    Properly handle exceptions when processing timeout rules

  .. change::
    :tags: Bug Fixes, Protobuf
    :pullreq: 16325

    Fix setting meta keys on response, pass them from question to response

  .. change::
    :tags: Bug Fixes
    :pullreq: 16326
    :tickets: 16139

    Initialize hash perturbation later, and only if needed

  .. change::
    :tags: Bug Fixes
    :pullreq: 16327
    :tickets: 16072

    Fix reentry issue in TCP downstream I/O on macOS/BSD (Karel Bilek)

  .. change::
    :tags: New Features
    :pullreq: 16328
    :tickets: 14060

    Add a selector to match the incoming protocol

  .. change::
    :tags: Improvements
    :pullreq: 16345
    :tickets: 15173

    luawrapper: don't segfault on failure in traceback handler

  .. change::
    :tags: Improvements
    :pullreq: 16346

    Refactor the FFI "alternate name" interface

  .. change::
    :tags: Improvements, DNS over HTTPS
    :pullreq: 16430

    Include a Date: response header for rejected HTTP1 requests

  .. change::
    :tags: Bug Fixes, DNS over TLS, DNS over HTTPS
    :pullreq: 16431

    Fix a memory leak with OCSP and OpenSSL 3.6.0

  .. change::
    :tags: Bug Fixes
    :pullreq: 16435
    :tickets: 15173

    Store Lua's ``debug.traceback`` function before user can hide it from us

  .. change::
    :tags: Bug Fixes, YAML
    :pullreq: 16439
    :tickets: 16371

    Properly handle invalid regular expressions

  .. change::
    :tags: Improvements
    :pullreq: 16508

    Prevent copies of ``dnsheader_aligned`` objects

  .. change::
    :tags: Improvements, Performance
    :pullreq: 16524

    Change bogusV4/bogusV6 addresses to static constants to avoid parse in every call (delichik)

  .. change::
    :tags: Bug Fixes, YAML
    :pullreq: 16507
    :tickets: 16462

    Fix a crash when a selector or policy cannot be found

  .. change::
    :tags: Improvements
    :pullreq: 16559

    Raise the maximum number of descriptors to 1M

  .. change::
    :tags: Improvements, Performance
    :pullreq: 16560

    Better performance when using ``recvmmsg``

  .. change::
    :tags: Improvements
    :pullreq: 16561

    Alter the qname ``BPF`` filter to make it ``const``

  .. change::
    :tags: Improvements, YAML
    :pullreq: 16562
    :tickets: 16428

    Expose ``TimedIPSet`` to ``YAML``-originated ``Lua`` contexts

.. changelog::
  :version: 2.0.1
  :released: 18th of September 2025

  .. change::
    :tags: Bug Fixes, Security, DNS over QUIC, DNS over HTTP3
    :pullreq: 15920, 16003

    Upgrade Cloudflare's Quiche to 0.24.5 in our packages (CVE-2025-4820, CVE-2025-4821, CVE-2025-7054)

  .. change::
    :tags: Improvements, Performance
    :pullreq: 15925

    Update rings' atomic counter without holding the lock

  .. change::
    :tags: Improvements, Performance
    :pullreq: 15926

    Return early when a rule chain is empty

  .. change::
    :tags: Improvements, Performance
    :pullreq: 15927

    Update a cache's atomic counter without holding the lock

  .. change::
    :tags: Bug Fixes, YAML
    :pullreq: 16017

    Fix QType rate dynamic block with YAML

  .. change::
    :tags: Bug Fixes
    :pullreq: 16018

    Fix systemd template unit and restricted network families when building with meson

  .. change::
    :tags: Bug Fixes, Performance
    :pullreq: 16019

    Clean up incoming TCP connections counters once per minute

  .. change::
    :tags: Improvements, Performance
    :pullreq: 16020

    Speed up response content matching

  .. change::
    :tags: Improvements, YAML
    :pullreq: 16029

    ``dnsdist --version``: report yaml support

  .. change::
    :tags: Improvements
    :pullreq: 16031

    Switch Docker images to Debian Trixie

  .. change::
    :tags: Improvements
    :pullreq: 16032

    Support mnemonics for the ``Opcode`` selector

  .. change::
    :tags: Bug Fixes, Security, DNS over HTTPS
    :pullreq: 16045

    Add mitigations for the HTTP/2 MadeYouReset attack (CVE-2025-8671), fix a possible DoS in incoming DoH with ``nghttp2`` (CVE-2025-30187)

  .. change::
    :tags: Bug Fixes
    :pullreq: 16048

    Add missing generated files to the dist tarball

  .. change::
    :tags: Bug Fixes
    :pullreq: 16049

    Don't increment in a potential macro argument

  .. change::
    :tags: Bug Fixes
    :pullreq: 16052

    Allow building with gcc8, which needs ``-lstdc++fs`` as link argument

  .. change::
    :tags: Improvements, Performance
    :pullreq: 16053

    Only check the freshness of the configuration when needed

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 16080

    Don't call ``nghttp2_session_send`` from a callback

  .. change::
    :tags: Bug Fixes
    :pullreq: 16081

    Properly handle truncation for UDP responses sent via ``sendmmsg``

  .. change::
    :tags: Bug Fixes
    :pullreq: 16093

    dnsdist-resolver: Fix a bug when we get new IPs for a server

  .. change::
    :tags: Bug Fixes
    :pullreq: 16095

    Fix access to frontends while in client mode

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 16096

    Fix the IO reentry guard in outgoing DoH

.. changelog::
  :version: 1.9.11
  :released: 18th of September 2025

  .. change::
    :tags: New Features
    :pullreq: 15635
    :tickets: 15610

    Add SetEDNSOptionResponseAction (Samir Aguiar)

  .. change::
    :tags: Bug Fixes, Security, DNS over QUIC, DNS over HTTP3
    :pullreq: 15921, 16004

    Upgrade Cloudflare's Quiche to 0.24.5 in our packages (CVE-2025-4820, CVE-2025-4821, CVE-2025-7054)

  .. change::
    :tags: Bug Fixes, Security, DNS over HTTPS
    :pullreq: 16036

    Upgrade h2o to 2.2.6-pdns3 in our packages (CVE-2025-8671)

  .. change::
    :tags: Bug Fixes, Security, DNS over HTTPS
    :pullreq: 16047

    Add mitigations for the HTTP/2 MadeYouReset attack (CVE-2025-8671), fix a possible DoS in incoming DoH with ``nghttp2`` (CVE-2025-30187)

  .. change::
    :tags: Bug Fixes
    :pullreq: 16051

    Don't increment in a potential macro argument

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 16086
    :tickets: 16015

    Don't call ``nghttp2_session_send`` from a callback

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 16097

    Fix the IO reentry guard in outgoing DoH

.. changelog::
  :version: 2.0.0
  :released: 21st of July 2025

  .. change::
    :tags: Bug Fixes
    :pullreq: 15875

    Fix out-of-tree builds with autotools

  .. change::
    :tags: Improvements, Performance
    :pullreq: 15876

    Improve the scalability of the MAC address cache

  .. change::
    :tags: Improvements, Performance
    :pullreq: 15877

    Small speedup for ``getEDNSUDPPayloadSizeAndZ()``

  .. change::
    :tags: Improvements, Performance
    :pullreq: 15878

    Avoid constructing a :class:`DNSResponse` object when not really needed

  .. change::
    :tags: Improvements, Performance
    :pullreq: 15879

    Use an unordered map for pools

  .. change::
    :tags: Improvements, Performance
    :pullreq: 15880

    Only parse EDNS ``Z`` once

.. changelog::
  :version: 2.0.0-rc2
  :released: 17th of July 2025

  .. change::
    :tags: Bug Fixes
    :pullreq: 15837

    dnsdist-rust-lib: honor ``RUSTC_TARGET_ARCH``

  .. change::
    :tags: Improvements, YAML
    :pullreq: 15838

    Handle named rcodes in the YAML configuration

  .. change::
    :tags: Bug Fixes, YAML
    :pullreq: 15839
    :tickets: 15810

    Properly process the YAML source parameter for backends

  .. change::
    :tags: Bug Fixes
    :pullreq: 15840
    :tickets: 15804

    Properly link with ``libdl`` when building with ``autotools``

  .. change::
    :tags: Bug Fixes, YAML
    :pullreq: 15841
    :tickets: 15822

    Allow registering NMG objects from YAML

  .. change::
    :tags: Bug Fixes, Webserver
    :pullreq: 15842
    :tickets: 15820

    Bring back listening on multiple web server addresses

  .. change::
    :tags: Bug Fixes
    :pullreq: 15843
    :tickets: 15830

    Fix narrowing conversion on 32-bit systems by using ``uint64_t`` instead of ``size_t``

.. changelog::
  :version: 2.0.0-rc1
  :released: 8th of July 2025

  .. change::
    :tags: Bug Fixes
    :pullreq: 15709
    :tickets: 15708

    Libssl depends on libcrypto

  .. change::
    :tags: Bug Fixes, YAML
    :pullreq: 15734
    :tickets: 15517

    Enforce that additional addresses are DoT/DoH only

  .. change::
    :tags: Bug Fixes
    :pullreq: 15774
    :tickets: 15699

    Prevent Lua bindings for backend from crashing on empty backend

  .. change::
    :tags: Bug Fixes
    :pullreq: 15775
    :tickets: 15699

    Return nil for non-existing Lua objects

  .. change::
    :tags: Improvements, Performance
    :pullreq: 15776
    :tickets: 15735

    lmdb-safe: Improve the scalability of transaction maps

  .. change::
    :tags: Improvements
    :pullreq: 15777

    Prevent users from opening the same LMDB twice

  .. change::
    :tags: Bug Fixes
    :pullreq: 15778

    lmdb-safe: Fix a small race in ``getMDBEnv``

  .. change::
    :tags: Bug Fixes, YAML
    :pullreq: 15779
    :tickets: 15750

    Fix logging and XSK YAML settings being ignored

  .. change::
    :tags: Improvements, YAML
    :pullreq: 15780

    Error on unsupported backend protocols from YAML

  .. change::
    :tags: Improvements, YAML
    :pullreq: 15781

    Error if backend certificate validation is enabled without a subject name

  .. change::
    :tags: Bug Fixes, YAML
    :pullreq: 15784
    :tickets: 15743

    Add a Lua binding to get objects declared in YAML

.. changelog::
  :version: 2.0.0-beta1
  :released: 20th of June 2025

  .. change::
    :tags: Bug Fixes
    :pullreq: 15578

    Fix spelling for ``setWHashedPerturbation`` (Josh Soref)

  .. change::
    :tags: Improvements
    :pullreq: 15614

    Explicitly use the versions present in ``Cargo.lock`` when building

  .. change::
    :tags: Improvements
    :pullreq: 15616

    Debian: use luajit when possible (Chris Hofstaedtler)

  .. change::
    :tags: Improvements
    :pullreq: 15615

    Update our Rust dependencies

  .. change::
    :tags: New Features
    :pullreq: 15610

    Add SetEDNSOptionResponseAction (Samir Aguiar)

  .. change::
    :tags: Bug Fixes, YAML
    :pullreq: 15650

    YAML: Correct ``enable_proxy_protocol`` value for TCP/UDP binds (Robert Edmonds)

  .. change::
    :tags: Improvements
    :pullreq: 15532

    Add option to support cache sharing between different payload sizes (@pacnal)

  .. change::
    :tags: Improvements
    :pullreq: 15656

    Remove never used argument

  .. change::
    :tags: Bug Fixes
    :pullreq: 15602

    Do not replace EDNS in answers self-generated from a packet

  .. change::
    :tags: Bug Fixes
    :pullreq: 15640

    Clean up existing records when turning query into response

  .. change::
    :tags: New Features, Protobuf
    :pullreq: 15690

    Add Lua APIs to set Meta tags in protobuf messages

  .. change::
    :tags: Bug Fixes
    :pullreq: 15691

    Generate completion and help for rule chains

  .. change::
    :tags: Improvements
    :pullreq: 15695

    Meson: followup to #15685 to avoid compiler warnings

  .. change::
    :tags: Improvements
    :pullreq: 15682

    Remove superfluous code block in YAML config (Pieter Lexis)

  .. change::
    :tags: Improvements
    :pullreq: 15685

    Meson: Pick ``-lcrypto`` up from the spot defined by ``dep_libcrypto``

  .. change::
    :tags: Improvements
    :pullreq: 15676

    Add a count to track the number of query restarts (@pacnal)

  .. change::
    :tags: New Features
    :pullreq: 15670

    Add route policy of first ordered then weighted (@pacnal)

  .. change::
    :tags: Bug Fixes
    :pullreq: 15679
    :tickets: 8060

    Provide an ``IP_OFFMASK`` value for systems lacking it

  .. change::
    :tags: Bug Fixes, YAML
    :pullreq: 15662

    Apply generic YAML configuration items early

.. changelog::
  :version: 2.0.0-alpha2
  :released: 23rd of May 2025

  .. change::
    :tags: New Features
    :pullreq: 15306

    Add support for calling Lua methods when exiting

  .. change::
    :tags: Improvements, DNS over QUIC, DNS over HTTP3
    :pullreq: 15328, 15583

    Upgrade Quiche to 0.24.2 in our packages

  .. change::
    :tags: Improvements
    :pullreq: 15329, 15584

    Upgrade Rust to 1.87.0 when building our packages

  .. change::
    :tags: Bug Fixes, YAML
    :pullreq: 15330

    Fix YAML configuration failure to build without CDB/LMDB

  .. change::
    :tags: Bug Fixes, Meson
    :pullreq: 15331

    Do not auto-enable disabled features when building with meson

  .. change::
    :tags: Bug Fixes
    :pullreq: 15333

    Fix version number in our Docker image

  .. change::
    :tags: Bug Fixes, YAML
    :pullreq: 15338

    Better handling of the ``dlsym`` missing symbol in our Rust lib

  .. change::
    :tags: Bug Fixes, YAML
    :pullreq: 15351

    Load Lua bindings before parsing YAML configuration

  .. change::
    :tags: Bug Fixes, YAML
    :pullreq: 15355

    Better handling of exceptions raised during YAML parsing

  .. change::
    :tags: Bug Fixes, YAML
    :pullreq: 15356

    Better handling of nonexistent Lua function name in YAML

  .. change::
    :tags: Bug Fixes
    :pullreq: 15362

    Do not register Xsk sockets on configuration check or client mode

  .. change::
    :tags: New Features
    :pullreq: 15376

    Add mitigations against misbehaving TCP/TLS clients

  .. change::
    :tags: Improvements, Meson
    :pullreq: 15377

    Allow alternate location for libssl

  .. change::
    :tags: New Features, DNS over TLS, DNS over HTTPS, Performance
    :pullreq: 15387

    Share tickets key between identical frontends created via YAML

  .. change::
    :tags: New Features
    :pullreq: 15388

    Enhancement to support rule action for query timeout case (@pacnal)

  .. change::
    :tags: Bug Fixes, Meson
    :pullreq: 15392

    Do not try to get the version/path of Python if not found

  .. change::
    :tags: Bug Fixes
    :pullreq: 15407

    Fix compilation with DoH3 enabled and DoH disabled

  .. change::
    :tags: New Features, DNS over TLS, DNS over HTTPS
    :pullreq: 15409

    Add support for switching certificates based on SNI with OpenSSL

  .. change::
    :tags: Bug Fixes, Meson
    :pullreq: 15416

    Fix two issues when building with meson

  .. change::
    :tags: Improvements
    :pullreq: 15419

    Refactor the packet cache settings

  .. change::
    :tags: Improvements
    :pullreq: 15423

    Add an option to cache truncated answers

  .. change::
    :tags: Improvements
    :pullreq: 15431

    Be consistent with regard to health-check modes transition

  .. change::
    :tags: Improvements
    :pullreq: 15436

    Fix a few more cases of potentially unused arguments

  .. change::
    :tags: New Features
    :pullreq: 15439

    Support DSCP marking towards downstream server (@pacnal)

  .. change::
    :tags: Bug Fixes, DNS over QUIC, DNS over HTTP3
    :pullreq: 15440
    :tickets: 15427

    If SONAME is present in the generated Quiche lib set it to the correct value

  .. change::
    :tags: Bug Fixes, DNSCrypt
    :pullreq: 15463

    Fix a confusion about contexts/frontends in :func:`getDNSCryptBind`

  .. change::
    :tags: Improvements
    :pullreq: 15467

    Add indicator for cache hit rules to know if hit a stale entry (@pacnal)

  .. change::
    :tags: Bug Fixes
    :pullreq: 15471

    Fix an iterator out-of-bound read when removing a TCP-only server

  .. change::
    :tags: Improvements
    :pullreq: 15472

    Reduce memory usage with fast-changing dynamic backends

  .. change::
    :tags: Bug Fixes, DNS over HTTPS, Security
    :pullreq: 15480
    :tickets: 15475

    Fix a crash when processing timeouts for incoming DoH queries

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 15481

    Gracefully handle timeout/response for a closed HTTP stream

  .. change::
    :tags: Bug Fixes, YAML
    :pullreq: 15496

    Fix building with YAML enabled but without TLS support

  .. change::
    :tags: Bug Fixes
    :pullreq: 15514

    Fix memory corruption when using :func:`getAddressInfo`

  .. change::
    :tags: Improvements
    :pullreq: 15477

    Provide runtime update API for some health check params (@pacnal)

  .. change::
    :tags: Bug Fixes
    :pullreq: 15520

    Fix building with GCC 15.1: missing ``cstdint`` include

  .. change::
    :tags: Bug Fixes, Meson
    :pullreq: 15521
    :tickets: 15516

    Don't build with ``libedit`` if disabled via meson

  .. change::
    :tags: Improvements, Metrics
    :pullreq: 15524

    Improve scalability of custom metrics

  .. change::
    :tags: Improvements
    :pullreq: 15525

    Upgrade to protozero 1.8.0

  .. change::
    :tags: Improvements, DNS over HTTPS
    :pullreq: 15526
    :tickets: 14791

    Deprecate the ``options`` parameter of :func:`HTTPStatusAction`

  .. change::
    :tags: Bug Fixes
    :pullreq: 15534
    :tickets: 15529

    Only set the proxy protocol payload size when actually added

  .. change::
    :tags: Bug Fixes
    :pullreq: 15539

    The second parameter to :func:`setAPIWritable` is optional

  .. change::
    :tags: Bug Fixes
    :pullreq: 15554

    Fix a crash in the TCP concurrent connections map

  .. change::
    :tags: Improvements, Meson
    :pullreq: 15558

    Switch ``eBPF`` support to ``auto`` when building with meson

  .. change::
    :tags: Bug Fixes
    :pullreq: 15563

    Suppress a warning on macOS

  .. change::
    :tags: Bug Fixes, DNS over QUIC, DNS over HTTP3
    :pullreq: 15564

    Two fixes to enable building on OpenBSD with QUIC enabled

  .. change::
    :tags: Bug Fixes, Meson
    :pullreq: 15565

    Fix our meson build not reaching a stable state

  .. change::
    :tags: Bug Fixes, Security
    :pullreq: 15571

    Fix a crash when TCP queries and responses keep coming

  .. change::
    :tags: Bug Fixes
    :pullreq: 15573

    Fix one potential issue and several false positives reported by Coverity

  .. change::
    :tags: Bug Fixes
    :pullreq: 15585

    Fix the behaviour of ``TagRule`` with an empty string as value

.. changelog::
  :version: 1.9.10
  :released: 20th of May 2025

  .. change::
    :tags: Bug Fixes
    :pullreq: 15497
    :tickets: 15432

    On FreeBSD, only pass source addresses on sockets bound to ANY

  .. change::
    :tags: Improvements
    :pullreq: 15499

    Better error when we cannot connect a backend socket

  .. change::
    :tags: Bug Fixes
    :pullreq: 15500
    :tickets: 15060

    Include ``cstdint`` to get ``uint64_t``

  .. change::
    :tags: Improvements, Metrics
    :pullreq: 15501
    :tickets: 15071

    Adjust ``Content-Type`` header for Prometheus endpoint to include version

  .. change::
    :tags: Improvements
    :pullreq: 15502

    Enable XSK in our Noble Ubuntu packages

  .. change::
    :tags: Improvements
    :pullreq: 15503

    Upgrade Quiche to 0.23.4 in our packages

  .. change::
    :tags: Bug Fixes
    :pullreq: 15504
    :tickets: 15218

    Limit # of proxy protocol-enabled outgoing TCP connections

  .. change::
    :tags: Bug Fixes
    :pullreq: 15505

    Allow ``AF_NETLINK`` and ``AF_XDP`` under ``systemd``

  .. change::
    :tags: Improvements
    :pullreq: 15506

    Upgrade Rust to 1.85.0 in our packages

  .. change::
    :tags: Improvements
    :pullreq: 15507
    :tickets: 15427

    If ``SONAME`` is present in the generated Quiche library, set it to the correct value

  .. change::
    :tags: Improvements
    :pullreq: 15508

    Add Lua bindings for the incoming network interface

  .. change::
    :tags: Bug Fixes
    :pullreq: 15510
    :tickets: 15362

    Do not register Xsk sockets on configuration check or client mode

  .. change::
    :tags: Bug Fixes
    :pullreq: 15511
    :tickets: 15337

    Fix cache lookup for unavailable TCP-only backends

  .. change::
    :tags: Bug Fixes
    :pullreq: 15519
    :tickets: 15495

    Fix memory corruption when using ``getAddressInfo``

  .. change::
    :tags: Bug Fixes
    :pullreq: 15560

    Fix building with GCC 15.1: missing ``cstdint`` include

  .. change::
    :tags: Bug Fixes
    :pullreq: 15562
    :tickets: 15529

    Only set the proxy protocol payload size when actually added

  .. change::
    :tags: Bug Fixes, Security
    :pullreq: 15572

    Fix a crash when TCP queries and responses keep coming

.. changelog::
  :version: 1.9.9
  :released: 29th of April 2025

  .. change::
    :tags: Improvements
    :pullreq: 15118

    Handle Quiche >= 0.23.0 since the API changed

  .. change::
    :tags: Improvements
    :pullreq: 15137

    Fix compatibility with `boost::lockfree` >= 1.87.0

  .. change::
    :tags: Improvements
    :pullreq: 15164

    Update Rust to 1.84.1 for our packages

  .. change::
    :tags: Security, Bug Fixes, DNS over HTTPS
    :pullreq: 15482
    :tickets: 15475

    Fix a crash when processing timeouts for incoming DoH queries

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 15485

    Gracefully handle timeout/response for a closed HTTP stream

.. changelog::
  :version: 2.0.0-alpha1
  :released: 18th of March 2025

  .. change::
    :tags: Improvements
    :pullreq: 15165

    Update Quiche to 0.23.2

  .. change::
    :tags: Improvements
    :pullreq: 15164

    Update Rust to 1.84.1 for our packages

  .. change::
    :tags: Improvements
    :pullreq: 13920

    Shrink InternalQueryState's size by reordering its fields

  .. change::
    :tags: New Features
    :pullreq: 13923

    Add a new response chain for XFR responses

  .. change::
    :tags: New Features
    :pullreq: 13922

    Add a new query rules chain triggered after a cache miss

  .. change::
    :tags: Bug Fixes
    :pullreq: 14083

    Change home directory to /var/lib/<product> on EL-based OSs

  .. change::
    :tags: Improvements
    :pullreq: 14130

    Fix TCP I/O timeout and callback being used for HTTP/2

  .. change::
    :tags: Removals
    :pullreq: 14184

    Remove XPF support

  .. change::
    :tags: Improvements
    :pullreq: 14195

    Get rid of ``assert()``

  .. change::
    :tags: Improvements
    :pullreq: 14205

    Delint the DNSCrypt code base

  .. change::
    :tags: New Features
    :pullreq: 14182
    :tickets: 13750, 13374

    Add the ability to set tags from dynamic block rules

  .. change::
    :tags: Improvements
    :pullreq: 14330

    Snmp-agent: Move net-snmp headers out of our headers

  .. change::
    :tags: Improvements
    :pullreq: 14326

    Use ``pdns::checked_stoi`` instead of ``sscanf`` for ``grepq``'s ms

  .. change::
    :tags: Improvements
    :pullreq: 14392

    Handle Quiche >= 0.22.0

  .. change::
    :tags: Improvements
    :pullreq: 14376

    Fix a race when accessing a backend health status

  .. change::
    :tags: Improvements
    :pullreq: 14367

    Refactoring of the configuration

  .. change::
    :tags: Improvements
    :pullreq: 14495

    Use atomic variables for the per-protocol latencies

  .. change::
    :tags: Improvements
    :pullreq: 14588

    Add configure args to --version output

  .. change::
    :tags: Improvements
    :pullreq: 14577

    Add Lua FFI accessors for EDNS version and extended rcode

  .. change::
    :tags: New Features, DNS over HTTPS, DNS over TLS
    :pullreq: 14938

    Allow setting keyLogFile to DoT/DoH backends (Karel Bilek)

  .. change::
    :tags: New Features, DNS over HTTP3
    :pullreq: 15002

    Add DoH3 headers, query string, path and scheme bindings

  .. change::
    :tags: Improvements
    :pullreq: 14970

    Boost > std optional (Rosen Penev)

  .. change::
    :tags: Improvements
    :pullreq: 14948

    Clang-tidy: simplify some algorithms (Rosen Penev)

  .. change::
    :tags: New Features, DNS over HTTP3
    :pullreq: 15029

    Add the ability to set custom HTTP responses over DoH3

  .. change::
    :tags: Improvements
    :pullreq: 15036

    Improve error messages on security polling failures

  .. change::
    :tags: Removals
    :pullreq: 15030

    Remove ``TLSContext``

  .. change::
    :tags: Improvements
    :pullreq: 15032

    Use getAddressInfo() instead python daemonized subprocess (Denis Kadyshev)

  .. change::
    :tags: Improvements
    :pullreq: 15046

    Better error when we cannot connect a backend socket

  .. change::
    :tags: New Features
    :pullreq: 14969

    Add a new, optional, YAML-based configuration format

  .. change::
    :tags: New Features, DNS over QUIC, DNS over HTTP3
    :pullreq: 15024
    :tickets: 14048

    Gather Server Name Indication on QUIC (DoQ, DoH3) connections

  .. change::
    :tags: Improvements
    :pullreq: 14724, 15115, 15138, 15149, 15163, 15184

    Add meson support

  .. change::
    :tags: Improvements
    :pullreq: 15118, 14134

    Handle Quiche >= 0.23.0 since the API changed

  .. change::
    :tags: Improvements
    :pullreq: 15120

    Make hard-coded values configurable in xdp.py

  .. change::
    :tags: Improvements
    :pullreq: 15132

    Add support for multiple network interfaces in the XDP helper

  .. change::
    :tags: Improvements
    :pullreq: 15137

    Fix compatibility with ``boost::lockfree`` >= 1.87.0

  .. change::
    :tags: Improvements, Protobuf, DNSTAP
    :pullreq: 15123
    :tickets: 14861

    Add pooling support for ``RemoteLoggerInterface`` (Ensar Sarajčić)

  .. change::
    :tags: Bug Fixes,
    :pullreq: 15199

    Use ``65535`` instead of ``255`` to block all types via eBPF

  .. change::
    :tags: Improvements
    :pullreq: 15247
    :tickets: 15246

    Lua comboaddress: raw docs, cleanups, dnsdist add getRaw (Karel Bilek)

  .. change::
    :tags: Improvements
    :pullreq: 15158

    Disable Lua configuration directives in YAML mode

  .. change::
    :tags: Improvements, DNSTAP
    :pullreq: 15151
    :tickets: 15108

    Add support for dnstap new http_protocol field

  .. change::
    :tags: Improvements, Protobuf
    :pullreq: 15298

    Protobuf, support packetCacheHit and outgoingQueries fields

  .. change::
    :tags: Bug Fixes
    :pullreq: 15300

    Allow ``AF_NETLINK`` and ``AF_XDP`` under ``systemd``

  .. change::
    :tags: Bug Fixes
    :pullreq: 15257

    Limit # of proxy protocol-enabled outgoing TCP connections

.. changelog::
  :version: 1.9.8
  :released: 17th of December 2024

  .. change::
    :tags: Improvements, DNS over TLS, DNS over HTTPS
    :pullreq: 14877

    Add the ability to load a given TLS tickets key

  .. change::
    :tags: Bug Fixes, DNS over TLS, DNS over HTTPS
    :pullreq: 14878

    setTicketsKeyAddedHook: pass a std::string to the hook to avoid luawrapper to truncate content at potential null chars

  .. change::
    :tags: Improvements
    :pullreq: 14887

    Add elapsed time to dq object (@phonedph1)

  .. change::
    :tags: Bug Fixes
    :pullreq: 14929

    Allow resetting ``setWeightedBalancingFactor()`` to zero

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 14977
    :tickets: 14959

    Fix ECS zero-scope caching with incoming DoH queries

  .. change::
    :tags: Improvements, Metrics
    :pullreq: 14978

    Custom metrics: better error messages, small doc improvements

.. changelog::
  :version: 1.9.7
  :released: 4th of October 2024

  .. change::
    :tags: Improvements
    :pullreq: 14638
    :tickets: 14562

    Fix build with boost 1.86.0

  .. change::
    :tags: Bug Fixes, DNS over TLS
    :pullreq: 14639
    :tickets: 14631

    Fix handling of proxy protocol payload outside of TLS for DoT

  .. change::
    :tags: Improvements
    :pullreq: 14641
    :tickets: 14568

    Stop reporting timeouts in ``topSlow()``, add ``topTimeouts()``

  .. change::
    :tags: Bug Fixes
    :pullreq: 14643
    :tickets: 14552

    Return a valid unix timestamp for Dynamic Block's ``until``

  .. change::
    :tags: Bug Fixes
    :pullreq: 14644
    :tickets: 14548

    Fix EDNS flags confusion when editing the OPT header

  .. change::
    :tags: Improvements
    :pullreq: 14645
    :tickets: 14549

    Fix compilation with GCC 15 (Holger Hoffstätte)

  .. change::
    :tags: Improvements
    :pullreq: 14646

    Add warnings about large values passed to ``setMaxTCPClientThreads``

  .. change::
    :tags: Improvements, DNS over QUIC, DNS over HTTP3
    :pullreq: 14647

    Update Quiche to 0.22.0 (in our packages)

  .. change::
    :tags: Bug Fixes
    :pullreq: 14640

    Handle a nonexistent default pool when removing a server

  .. change::
    :tags: Improvements, DNS over QUIC, DNS over HTTP3
    :pullreq: 14695

    Update the Rust version we use in our packages to 1.78

  .. change::
    :tags: Bug Fixes, DNS over TLS
    :pullreq: 14677

     Prevent a data race in incoming DNS over TLS connections by storing the ``OpenSSLTLSIOCtx`` in the connection

  .. change::
    :tags: New Features
    :pullreq: 14716
    :tickets: 14664

    Add a FFI accessor to incoming proxy protocol values

  .. change::
    :tags: Bug Fixes
    :pullreq: 14730

    Add EDNS to responses generated from raw record data

  .. change::
    :tags: Bug Fixes, DNS over QUIC, DNS over HTTP3
    :pullreq: 14740
    :tickets: 14736

    Disable eBPF filtering on QUIC (DoQ, DoH3) sockets

.. changelog::
  :version: 1.8.4
  :released: 20th of September 2024

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.8.x.

  .. change::
    :tags: Bug Fixes
    :pullreq: 14467

    Fix a compilation issue with clang by switching to ``pdns::views::UnsignedCharView``

  .. change::
    :tags: Bug Fixes
    :pullreq: 14680
    :tickets: 14562

    Fix build with boost 1.86.0

  .. change::
    :tags: Bug Fixes, DNS over TLS
    :pullreq: 14679

    Prevent a data race in incoming DNS over TLS connections by storing the ``OpenSSLTLSIOCtx`` in the connection

.. changelog::
  :version: 1.9.6
  :released: 16th of July 2024

  .. change::
    :tags: Bug Fixes
    :pullreq: 14436

    Fix a race in the XSK/AF_XDP backend handling code

  .. change::
    :tags: Bug Fixes
    :pullreq: 14437

    dns.cc: use pdns::views::UnsignedCharView

  .. change::
    :tags: Improvements
    :pullreq: 14438

    Make the logging functions available to all Lua environments

  .. change::
    :tags: Bug Fixes, Metrics
    :pullreq: 14439
    :tickets: 14395

    Dedup Prometheus help and type lines for custom metrics with labels

  .. change::
    :tags: New Features
    :pullreq: 14449

    Add support for a callback when a new tickets key is added

  .. change::
    :tags: Improvements
    :pullreq: 14450

    Handle Quiche >= 0.22.0

  .. change::
    :tags: Improvements
    :pullreq: 14452

    Don't include openssl/engine.h if it's not going to be used (Sander Hoentjen)

.. changelog::
  :version: 1.9.5
  :released: 20th of June 2024

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 14163

    Reply to HTTP/2 PING frames immediately

  .. change::
    :tags: Bug Fixes, DNS over QUIC, DNS over HTTP3
    :pullreq: 14166

    Use the correct source IP for outgoing QUIC datagrams

  .. change::
    :tags: Bug Fixes, Webserver
    :pullreq: 14170

    Prevent a race when calling ``registerWebHandler`` at runtime

  .. change::
    :tags: Bug Fixes
    :pullreq: 14331

    Syslog should be enabled by default

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 14332

    Log the correct amount of bytes sent for DoH w/ nghttp2

  .. change::
    :tags: Bug Fixes, Webserver
    :pullreq: 14333

    Enforce a maximum number of HTTP request fields and a maximum HTTP request line size

  .. change::
    :tags: Bug Fixes
    :pullreq: 14334

    Fix a warning when compiling the unit tests without XSK

  .. change::
    :tags: Bug Fixes
    :pullreq: 14335

    autoconf: allow prerelease systemd versions (Chris Hofstaedtler)

  .. change::
    :tags: Bug Fixes
    :pullreq: 14336
    :tickets: 14279

    Edit the systemd unit file, ``CAP_BPF`` is no longer enough

  .. change::
    :tags: Bug Fixes
    :pullreq: 14337

    Fix 'Error creating TCP worker' error message

  .. change::
    :tags: New Features
    :pullreq: 14338

    Add a Lua FFI function to set proxy protocol values

  .. change::
    :tags: New Features
    :pullreq: 14339

    Add Lua FFI bindings to generate SVC responses

  .. change::
    :tags: Bug Fixes, Webserver
    :pullreq: 14342

    Fix a race condition with custom Lua web handlers

.. changelog::
  :version: 1.9.4
  :released: 13th of May 2024

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 14081
    :tickets: 14046

    Fix DNS over plain HTTP broken by `reloadAllCertificates()`

  .. change::
    :tags: Improvements
    :pullreq: 14082
    :tickets: 13925

    Fix "C++ One Definition Rule" warnings in XSK

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 14105

    Fix a crash in incoming DoH with nghttp2

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 14156

    Fix handling of XFR requests over DoH

.. changelog::
  :version: 1.9.3
  :released: 5th of April 2024

  .. change::
    :tags: Bug Fixes
    :pullreq: 14040

    Revert "Release failed TCP backend connections more quickly" to fix a crash

.. changelog::
  :version: 1.9.2
  :released: 5th of April 2024

  .. change::
    :tags: Improvements
    :pullreq: 13938

    Fix compilation warnings

  .. change::
    :tags: Improvements
    :pullreq: 13939

    Docker: Only print config if debug flag is set

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 13940
    :tickets: 13850

    Use server preference algorithm for ALPN selection

  .. change::
    :tags: Bug Fixes
    :pullreq: 13941
    :tickets: 13903

    Fix first IPv6 console connection being rejected

  .. change::
    :tags: Improvements
    :pullreq: 13942

    Shrink InternalQueryState's size by reordering its fields

  .. change::
    :tags: Improvements
    :pullreq: 13943
    :tickets: 13925

    Fix annoying compiler warnings by introducing and switching to `pdns::UniqueFilePtr`

  .. change::
    :tags: Bug Fixes
    :pullreq: 13944

    Fix XSK-enabled check when reconnecting a backend

  .. change::
    :tags: Bug Fixes
    :pullreq: 13945
    :tickets: 13837

    Properly handle a failure of the first lazy health-check

  .. change::
    :tags: Bug Fixes
    :pullreq: 13976
    :tickets: 13945

    Also handle EHOSTUNREACH as a case for reconnecting the socket

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 14012

    Fix a null-deref in incoming DNS over HTTPS with the nghttp2 provider

  .. change::
    :tags: Improvements
    :pullreq: 14013
    :tickets: 13977

    Support "no server available" result from Lua FFI load-balancing policies

  .. change::
    :tags: Bug Fixes, DNS over HTTPS, Metrics
    :pullreq: 14014

    Fix DNS over HTTP connections/queries counters with the `nghttp2` provider

  .. change::
    :tags: Bug Fixes
    :pullreq: 14015

    FDWrapper: Do not try to close negative file descriptors

  .. change::
    :tags: Improvements
    :pullreq: 14016

    Release incoming TCP connection right away on backend failure

  .. change::
    :tags: Improvements
    :pullreq: 14017

    Release failed TCP backend connections more quickly

.. changelog::
  :version: 1.9.1
  :released: 14th of March 2024

  This release does not contain any dnsdist code changes compared to 1.9.0.
  The only thing that changed is the version of Quiche, because of a `security update <https://github.com/cloudflare/quiche/releases/tag/0.20.1>`_.

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading.

  .. change::
    :tags: Bug Fixes
    :pullreq: 13912

    update Quiche to 0.20.1. Fixes `CVE-2024-1410 <https://www.cve.org/CVERecord?id=CVE-2024-1410>`_ and `CVE-2024-1765 <https://www.cve.org/CVERecord?id=CVE-2024-1765>`_.

.. changelog::
  :version: 1.9.0
  :released: 16th of February 2024

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading.

  .. change::
    :tags: Improvements, DNS over QUIC, DNS over HTTP3
    :pullreq: 13755

    Better handling of short, non-initial QUIC headers

  .. change::
    :tags: Improvements
    :pullreq: 13757

    Fix a warning reported by Coverity

  .. change::
    :tags: Improvements
    :pullreq: 13768

    Add a Lua maintenance hook

  .. change::
    :tags: Bug Fixes
    :pullreq: 13771
    :tickets: 13766

    Do not allocate 16-byte aligned objects through lua(jit)

  .. change::
    :tags: Bug Fixes, DNS over QUIC, DNS over HTTP3
    :pullreq: 13774

    Fix a missing explicit atomic load of the Quiche configuration

  .. change::
    :tags: Improvements, DNS over QUIC, DNS over HTTP3
    :pullreq: 13779

    Fix performance inefficiencies reported by Coverity

.. changelog::
  :version: 1.9.0-rc1
  :released: 30th of January 2024

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading.

  .. change::
    :tags: Bug Fixes, DNS over HTTP3
    :pullreq: 13647

    Set the DNS over HTTP/3 default port to 443

  .. change::
    :tags: Bug Fixes, DNS over QUIC, DNS over HTTP3
    :pullreq: 13638
    :tickets: 13631

    Handle congested DoQ streams

  .. change::
    :tags: Bug Fixes, Metrics
    :pullreq: 13630

    Fix the 'TCP Died Reading Query" metric, as reported by Coverity

  .. change::
    :tags: Improvements, Performance, DNS over QUIC, DNS over HTTP3
    :pullreq: 13666

    Optimize the DoQ packet handling path

  .. change::
    :tags: Improvements, Performance
    :pullreq: 13664

    Increase UDP receive and send buffers to the maximum allowed

  .. change::
    :tags: Bug Fixes, DNS over QUIC, DNS over HTTP3
    :pullreq: 13670

    Make sure we enforce the ACL over DoQ and DoH3

  .. change::
    :tags: Improvements, DNS over QUIC, DNS over HTTP3
    :pullreq: 13674

    Enable DoQ and DoH3 in dockerfile-dnsdist (Denis Machard)

  .. change::
    :tags: Bug Fixes, DNS over HTTP3
    :pullreq: 13678

    Grant unidirectional HTTP/3 streams for DoH3

  .. change::
    :tags: Improvements, DNS over QUIC, DNS over HTTP3
    :pullreq: 13676

    Enable PMTU discovery and disable fragmentation on QUIC binds

  .. change::
    :tags: Improvements
    :pullreq: 13667

    Clean up the Lua objects before exiting

  .. change::
    :tags: Bug Fixes, DNS over HTTP3
    :pullreq: 13689
    :tickets: 13687

    Buffer HTTP/3 headers until the query has been dispatched

  .. change::
    :tags: Bug Fixes, DNS over HTTP3
    :pullreq: 13713
    :tickets: 13690

    Add content-type header information in DoH3 responses

  .. change::
    :tags: Improvements
    :pullreq: 13711

    Cleanup of code doing SNMP OID handling

  .. change::
    :tags: Bug Fixes, Protobuf, DNSTAP
    :pullreq: 13716

    Properly set the incoming protocol when logging via Protobuf or dnstap

  .. change::
    :tags: Improvements
    :pullreq: 13727

    Fix missed optimizations reported by Coverity

  .. change::
    :tags: Improvements, DNS over QUIC, DNS over HTTP3
    :pullreq: 13650

    Fall back to libcrypto for authenticated encryption

  .. change::
    :tags: Improvements
    :pullreq: 13735

    Move the console socket instead of copying it

  .. change::
    :tags: Improvements
    :pullreq: 13723

    DNSName: Correct len and offset types

  .. change::
    :tags: Improvements
    :pullreq: 13724

    DNSName: Optimize parsing of uncompressed labels

  .. change::
    :tags: New Features
    :pullreq: 11652

    Add AF_XDP support for UDP (Y7n05h)

.. changelog::
  :version: 1.8.3
  :released: 15th of December 2023

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.8.x.

  .. change::
    :tags: Bug Fixes, Metrics
    :pullreq: 13523
    :tickets: 13519

    Refactor the exponential back-off timer code

  .. change::
    :tags: Bug Fixes
    :pullreq: 13598

    Detect and dismiss truncated UDP responses from a backend

  .. change::
    :tags: Bug Fixes
    :pullreq: 13599

    Fix the removal of the last rule by name or UUID

  .. change::
    :tags: Improvements
    :pullreq: 13601

    Add a `DynBlockRulesGroup:removeRange()` binding

  .. change::
    :tags: Bug Fixes
    :pullreq: 13602
    :tickets: 13307

    Fix several cosmetic issues in eBPF dynamic blocks, update documentation

  .. change::
    :tags: Improvements
    :pullreq: 13605

    Add a `DNSHeader:getTC()` Lua binding

  .. change::
    :tags: Bug Fixes, Webserver
    :pullreq: 13607
    :tickets: 13050

    Fix code producing JSON

.. changelog::
  :version: 1.9.0-alpha4
  :released: 14th of December 2023

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading.

  .. change::
    :tags: Improvements
    :pullreq: 13023

    Remove legacy terms from the codebase (Kees Monshouwer)

  .. change::
    :tags: Improvements
    :pullreq: 13191

    Wrap `DIR*` objects in unique pointers to prevent memory leaks

  .. change::
    :tags: Improvements
    :pullreq: 13342

    Add a DynBlockRulesGroup:removeRange() binding

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 13381

    Fix the case where nghttp2 is available but DoH is disabled

  .. change::
    :tags: Improvements
    :pullreq: 13435

    Fix a few Coverity warnings

  .. change::
    :tags: Improvements, DNS over QUIC
    :pullreq: 13437

    Require Quiche >= 0.15.0

  .. change::
    :tags: Improvements
    :pullreq: 13445

    Fix Coverity CID 1523748: Performance inefficiencies in dolog.hh

  .. change::
    :tags: Improvements, DNS over QUIC
    :pullreq: 13472

    Add missing DoQ latency metrics

  .. change::
    :tags: New Features
    :pullreq: 13473

    Add support for setting Extended DNS Error statuses

  .. change::
    :tags: Improvements
    :pullreq: 13485
    :tickets: 13191

    Add `pdns::visit_directory()`, wrapping opendir/readdir/closedir

  .. change::
    :tags: Bug Fixes
    :pullreq: 13488

    Fix the removal of the last rule by name or UUID

  .. change::
    :tags: New Features, Webserver
    :pullreq: 13489

    Add a 'rings' endpoint to the REST API

  .. change::
    :tags: New Features
    :pullreq: 13492

    Add a cache-miss ratio dynamic block rule

  .. change::
    :tags: Improvements
    :pullreq: 13500

    Improve `NetmaskGroupRule`/`SuffixMatchNodeRule`, deprecate `makeRule`

  .. change::
    :tags: Improvements
    :pullreq: 13503

    Add `NetmaskGroup:addNMG()` to merge Netmask groups

  .. change::
    :tags: New Features
    :pullreq: 13505

    Add `getAddressInfo()` for asynchronous DNS resolution

  .. change::
    :tags: Improvements
    :pullreq: 13506

    Add an option to set the SSL proxy protocol TLV

  .. change::
    :tags: Improvements
    :pullreq: 13509

    Add Proxy Protocol v2 support to `TeeAction`

  .. change::
    :tags: Improvements
    :pullreq: 13515

    Allow setting the action from `setSuffixMatchRule{,FFI}()`'s visitor

  .. change::
    :tags: Improvements
    :pullreq: 13517

    Allow enabling incoming PROXY protocol on a per-bind basis

  .. change::
    :tags: Bug Fixes
    :pullreq: 13520

    Refactor the exponential back-off timer code

  .. change::
    :tags: Bug Fixes, DNS over QUIC
    :pullreq: 13524

    Fix building with DoQ but without DoH or DoT

  .. change::
    :tags: Bug Fixes
    :pullreq: 13536

    Detect and dismiss truncated UDP responses from a backend

  .. change::
    :tags: Improvements
    :pullreq: 13537

    Make the max size of entries in the packet cache configurable

  .. change::
    :tags: New Features, DNS over HTTP3, DNS over HTTPS
    :pullreq: 13556

    Add support for incoming DNS over HTTP/3

  .. change::
    :tags: Improvements
    :pullreq: 13560

    Spoof a raw response for ANY queries

  .. change::
    :tags: New Features
    :pullreq: 13564

    Add `PayloadSizeRule` and `TCResponseAction`

  .. change::
    :tags: Improvements
    :pullreq: 13565

    Add Lua FFI bindings: hashing arbitrary data and knowing if the query was received over IPv6

  .. change::
    :tags: Improvements
    :pullreq: 13592

    Add `QNameSuffixRule`

  .. change::
    :tags: Improvements, DNS over HTTPS
    :pullreq: 13594

    Send a HTTP 400 response to HTTP/1.1 clients

.. changelog::
  :version: 1.9.0-alpha3
  :released: 20th of October 2023

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading.

  .. change::
    :tags: New Features, Protobuf
    :pullreq: 13185

    Log Extended DNS Errors (EDE) to protobuf

  .. change::
    :tags: Bugs Fixes
    :pullreq: 13274

    Enable back h2o support in our packages

  .. change::
    :tags: Improvements
    :pullreq: 13275
    :tickets: 13201

    Add Lua binding to downstream address (Denis Machard)

  .. change::
    :tags: New Features, DNS over QUIC
    :pullreq: 13280

    Add support for incoming DNS over QUIC

  .. change::
    :tags: Bugs Fixes, DNS over HTTPS
    :pullreq: 13298

    Fix timeouts on incoming DoH connections with nghttp2

  .. change::
    :tags: Bug Fixes, Metrics
    :pullreq: 13302

    Fix a typo in 'Client timeouts'  (phonedph1)

  .. change::
    :tags: Improvements
    :pullreq: 13305

    Set proper levels when logging messages

  .. change::
    :tags: Improvements
    :pullreq: 13310

    Fix several cosmetic issues in eBPF dynamic blocks, update documentation

  .. change::
    :tags: Improvements, Webserver
    :pullreq: 13335

    Display the rule name, if any, in the web interface

  .. change::
    :tags: Bug Fixes
    :pullreq: 13340

    Netmask: Normalize subnet masks coming from a string

  .. change::
    :tags: Bug Fixes
    :pullreq: 13372
    :tickets: 13280

    Prevent DNS header alignment issues

.. changelog::
  :version: 1.9.0-alpha2
  :released: Never

  This version was never released due to a last-minute issue in RPM packaging.

.. changelog::
  :version: 1.8.2
  :released: 11th of October 2023

  This release fixes the HTTP2 rapid reset attack for the packages we provide.
  If you are compiling DNSdist yourself or using the packages provided by your distribution,
  please check that the h2o library has been patched to mitigate this vulnerability.

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.8.x.

  .. change::
    :tags: Bug Fixes, Security
    :pullreq: #13349

    Switch to our fork of h2o to mitigate the HTTP2 rapid reset attack

.. changelog::
  :version: 1.7.5
  :released: 11th of October 2023

  This release fixes the HTTP2 rapid reset attack for the packages we provide.
  If you are compiling DNSdist yourself or using the packages provided by your distribution,
  please check that the h2o library has been patched to mitigate this vulnerability.

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.7.x.

  .. change::
    :tags: Bug Fixes, Security
    :pullreq: #13351

    Switch to our fork of h2o to mitigate the HTTP2 rapid reset attack

.. changelog::
  :version: 1.9.0-alpha1
  :released: 18th of September 2023

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading.

  .. change::
    :tags: Improvements, DNS over HTTPS
    :pullreq: 12678

    Add support for incoming DoH via nghttp2

  .. change::
    :tags: Improvements
    :pullreq: 13145

    Fix building our fuzzing targets from a dist tarball

  .. change::
    :tags: Removals
    :pullreq: 13168

    Change the default for building with net-snmp from `auto` to `no`

  .. change::
    :tags: Improvements
    :pullreq: 13135

    Add a DNSHeader:getTC() Lua binding

  .. change::
    :tags: New Features
    :pullreq: 13013
    :tickets: 13007

    Add Lua bindings to access selector and action

  .. change::
    :tags: Improvements
    :pullreq: 13088

    Stop passing -u dnsdist -g dnsdist on systemd's ExecStart

  .. change::
    :tags: Improvements, Metrics
    :pullreq: 13009

    Add metrics for health-check failures

  .. change::
    :tags: Improvements
    :pullreq: 12931

    Use arc4random only for random values

  .. change::
    :tags: New Features
    :pullreq: 12689

    Add an option to write `grepq`'s output to a file

.. changelog::
  :version: 1.8.1
  :released: 8th of September 2023

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.8.x.

  .. change::
    :tags: Bug Fixes
    :pullreq: 12820

    Print the received, invalid health-check response ID

  .. change::
    :tags: Bug Fixes
    :pullreq: 12821

    Account for the health-check run time between two runs

  .. change::
    :tags: Bug Fixes
    :pullreq: 12822

    Properly set the size of the UDP health-check response

  .. change::
    :tags: Bug Fixes
    :pullreq: 12823

    Add the query ID to health-check log messages, fix nits

  .. change::
    :tags: Bug Fixes
    :pullreq: 12824

    Stop setting SO_REUSEADDR on outgoing UDP client sockets

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 12977

    Fix a crash when X-Forwarded-For overrides the initial source IP

  .. change::
    :tags: Bug Fixes
    :pullreq: 13116

    Properly handle short reads on backend upgrade discovery

  .. change::
    :tags: Bug Fixes
    :pullreq: 13117

    Undo an accidentally change of disableZeroScope to disableZeroScoping (Winfried Angele)

  .. change::
    :tags: Bug Fixes
    :pullreq: 13118
    :tickets: 13027

    Fix the group of the dnsdist.conf file when installed via RPM

  .. change::
    :tags: Bug Fixes
    :pullreq: 13119
    :tickets: 12926

    Work around Red Hat 8 messing up OpenSSL's headers and refusing to fix it

  .. change::
    :tags: Bug Fixes
    :pullreq: 13120

    Fix a typo for libedit in the dnsdist features list

  .. change::
    :tags: Improvements
    :pullreq: 13121

    Stop using the now deprecated ERR_load_CRYPTO_strings() to detect OpenSSL

  .. change::
    :tags: Improvements
    :pullreq: 13122

    Automatically load Lua FFI inspection functions

  .. change::
    :tags: New Features
    :pullreq: 13123

    Allow declaring custom metrics at runtime

  .. change::
    :tags: Bug Fixes
    :pullreq: 13124

    Fix webserver config template for our docker container (Houtworm)

  .. change::
    :tags: Improvements
    :pullreq: 13125

    Increment the "dyn blocked" counter for eBPF blocks as well

  .. change::
    :tags: Bug Fixes
    :pullreq: 13127

    YaHTTP: Prevent integer overflow on very large chunks

  .. change::
    :tags: Bug Fixes
    :pullreq: 13128

    Fix the console description of PoolAction and QPSPoolAction (phonedph1)

  .. change::
    :tags: Bug Fixes
    :pullreq: 13129
    :tickets: 12711

    Properly handle reconnection failure for backend UDP sockets

  .. change::
    :tags: Bug Fixes, DNS over HTTPS, DNS over TLS
    :pullreq: 13130

    Fix a memory leak when processing TLS tickets w/ OpenSSL 3.x

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 13131
    :tickets: 12762

    Fix cache hit and miss metrics with DoH queries

  .. change::
    :tags: Bug Fixes
    :pullreq: 13132

    SpoofAction: copy the QClass from the request (Christof Chen)

  .. change::
    :tags: Improvements
    :pullreq: 13133

    Make DNSQType.TSIG available (Jacob Bunk)

  .. change::
    :tags: Bug Fixes
    :pullreq: 13150

    Properly record self-answered UDP responses with recvmmsg

  .. change::
    :tags: Bug Fixes, DNS over TLS
    :pullreq: 13178

    Fix a race when creating the first TLS connections

.. changelog::
  :version: 1.7.4
  :released: 14th of April 2023

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.7.x.

  .. change::
    :tags: Bug Fixes
    :pullreq: 12183
    :tickets: 12177

    Fix building with boost < 1.56

  .. change::
    :tags: Bug Fixes
    :pullreq: 12460
    :tickets: 12453

    lock.hh: include <stdexcept>

  .. change::
    :tags: Bug Fixes
    :pullreq: 12569

    dnsdist-protocols.hh: include <cstdint> (Sander Hoentjen)

  .. change::
    :tags: New Features
    :pullreq: 12621
    :tickets: 12074

    Add getPoolNames() function, returning a list of pool names (Christof Chen)

  .. change::
    :tags: Bug Fixes
    :pullreq: 12535

    Fix the formatting of 'showServers'

  .. change::
    :tags: Bug Fixes
    :pullreq: 12529
    :tickets: 11905

    Properly record the incoming flags on a timeout

  .. change::
    :tags: Bug Fixes, Metrics
    :pullreq: 12484
    :tickets: 11498

    Properly update rcode-related metrics on RCodeAction hits

  .. change::
    :tags: Bug Fixes, DNS over TLS, DNS over HTTPS
    :pullreq: 12421
    :tickets: 12341

    Skip invalid OCSP files after issuing a warning

  .. change::
    :tags: Bug Fixes
    :pullreq: 12365
    :tickets: 12357

    Prevent an underflow of the TCP d_queued counter

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 12327

    Fix the health-check timeout computation for DoH backend

  .. change::
    :tags: Bug Fixes, Webserver
    :pullreq: 12260
    :tickets: 9349

    Properly encode json strings containing binary data

  .. change::
    :tags: Bug Fixes, DNS over TLS
    :pullreq: 12237
    :tickets: 12236

    Ignore unclean TLS session shutdown

  .. change::
    :tags: Bug Fixes
    :pullreq: 12100
    :tickets: 12099

    Properly handle single-SOA XFR responses

  .. change::
    :tags: Bug Fixes
    :pullreq: 11830
    :tickets: 4155

    Also reconnect on ENETUNREACH. (Asgeir Storesund Nilsen)

  .. change::
    :tags: Bug Fixes
    :pullreq: 11729
    :tickets: 11728

    Fix a bug in SetEDNSOptionAction

  .. change::
    :tags: Bug Fixes
    :pullreq: 11718

    Fix the number of concurrent queries on a backend TCP conn

.. changelog::
  :version: 1.8.0
  :released: 30th of March 2023

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.8.x.

  .. change::
    :tags: Bug Fixes
    :pullreq: 12687

    Fix 'Unknown key' issue for actions and rules parameters

  .. change::
    :tags: Bug Fixes
    :pullreq: 12672

    Fix a dnsheader unaligned case

  .. change::
    :tags: Bug Fixes
    :pullreq: 12654

    secpoll: explicitly include necessary ctime header for time_t

.. changelog::
  :version: 1.8.0-rc3
  :released: 16th of March 2023

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.8.x.

  .. change::
    :tags: Bug Fixes
    :pullreq: 12641

    Use the correct source address when harvesting failed

  .. change::
    :tags: Bug Fixes
    :pullreq: 12639

    Fix a race when a cross-protocol query triggers an IO error

  .. change::
    :tags: Improvements, Metrics, Webserver
    :pullreq: 12638

    Report per-incoming transport latencies in the web interface

  .. change::
    :tags: Improvements, Metrics
    :pullreq: 12648

    Report the TCP latency for TCP-only Do53, DoT and DoH backends

  .. change::
    :tags: Improvements
    :pullreq: 12626

    Count hits in the StatNode

.. changelog::
  :version: 1.8.0-rc2
  :released: 9th of March 2023

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.8.x.

  .. change::
    :tags: Improvements, Protobuf
    :pullreq: 12615

    Add Lua bindings for PB requestorID, deviceName and deviceID

  .. change::
    :tags: Improvements
    :pullreq: 12593

    Clean up the fortify and LTO m4 by not directly editing flags

  .. change::
    :tags: Bug Fixes
    :pullreq: 12592

    Only increment the 'servfail-responses' metric on backend responses (phonedph1)

  .. change::
    :tags: Bug Fixes
    :pullreq: 12586

    Fix the harvesting of destination addresses

  .. change::
    :tags: Improvements
    :pullreq: 12589

    YaHTTP: Better detection of whether C++11 features are available

  .. change::
    :tags: Bug Fixes, Protobuf
    :pullreq: 12588

    Fix compilation with DoH disabled (Adam Majer)

  .. change::
    :tags: Improvements
    :pullreq: 12587

    Skip signal-unsafe logging when we are about to exit, with TSAN

.. changelog::
  :version: 1.8.0-rc1
  :released: 23rd of February 2023

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.8.x.

  .. change::
    :tags: Bug Fixes
    :pullreq: 12569

    Include <cstdint> in dnsdist-protocols.hh (Sander Hoentjen)

  .. change::
    :tags: Improvements
    :pullreq: 12543

    Enable Link-Time Optimization for our packages

  .. change::
    :tags: Improvements, Metrics
    :pullreq: 12553

    Add support for custom prometheus names in custom metrics

  .. change::
    :tags: Improvements, Protobuf
    :pullreq: 12520

    Add support for metadata in protobuf messages

  .. change::
    :tags: Improvements, DNS over HTTPS, DNS over TLS, Performance
    :pullreq: 12545

    Enable experimental kTLS support with OpenSSL on Linux

  .. change::
    :tags: Improvements, Performance
    :pullreq: 12537

    Improve the scalability of MaxQPSIPRule()

  .. change::
    :tags: Improvements
    :pullreq: 12538

    Stop using the deprecated `boost::optional::get_value_or`

  .. change::
    :tags: Bug Fixes
    :pullreq: 12535

    Fix the formatting of 'showServers'

  .. change::
    :tags: Bug Fixes
    :pullreq: 12529
    :tickets: 11905

    Properly record the incoming flags on a timeout

  .. change::
    :tags: Improvements
    :pullreq: 12530
    :tickets: 10932

    List version number early

  .. change::
    :tags: Improvements, DNS over TLS, DNS over HTTPS
    :pullreq: 12423

    OpenSSL 3.0: Offer TLS providers as an alternative to TLS engines

  .. change::
    :tags: Improvements
    :pullreq: 12518

    Remove duplicate code in xdp (Y7n05h)

  .. change::
    :tags: Improvements
    :pullreq: 10115

    Warn on unsupported parameters (Aki Tuomi)

  .. change::
    :tags: Improvements
    :pullreq: 12469
    :tickets: 12417

    Add unit tests for the Lua FFI interface

  .. change::
    :tags: Improvements
    :pullreq: 12492

    Refactor 'cannot be used at runtime' handling

  .. change::
    :tags: New Features
    :pullreq: 12417

    Add the ability to change the qname and owner names in DNS packets

  .. change::
    :tags: Improvements
    :pullreq: 12481
    :tickets: 7611

    Fail if we can't check the configuration file

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 12483
    :tickets: 12019

    Apply the max number of concurrent conns per client to DoH

  .. change::
    :tags: Bug Fixes
    :pullreq: 12484
    :tickets: 11498

    Properly update rcode-related metrics on RCodeAction hits

  .. change::
    :tags: New Features, Webserver
    :pullreq: 12473
    :tickets: 6154, 10468

    Add an API endpoint to remove entries from caches

  .. change::
    :tags: Improvements, Webserver
    :pullreq: 12474
    :tickets: 10360

    Add an option for unauthenticated access to the dashboard

  .. change::
    :tags: New Features
    :pullreq: 12388

    Implement async processing of queries and responses

  .. change::
    :tags: Improvements
    :pullreq: 12441

    Add a configure option to enable LTO

  .. change::
    :tags: Bug Fixes, Metrics
    :pullreq: 12424
    :tickets: 10517, 11216

    Better handling of multiple carbon servers

  .. change::
    :tags: Improvements
    :pullreq: 12427

    Add a new configure option to initialize automatic variables

  .. change::
    :tags: Improvements, DNS over HTTPS, DNS over TLS
    :pullreq: 12421
    :tickets: 12341

    Skip invalid OCSP files after issuing a warning

  .. change::
    :tags: Improvements, DNS over HTTPS, DNS over TLS
    :pullreq: 12435

    Gracefully handle a failure to create a TLS server context

  .. change::
    :tags: Improvements
    :pullreq: 12381

    Enable FORTIFY_SOURCE=3 when supported by the compiler

  .. change::
    :tags: Improvements
    :pullreq: 12405

    Proper accounting of response and cache hits

  .. change::
    :tags: Improvements, DNS over HTTPS
    :pullreq: 12386

    Merge the 'main' and 'client' DoH threads in single acceptor mode

  .. change::
    :tags: New Features
    :pullreq: 12384

    Add the ability to cap the TTL of records after insertion into the cache

  .. change::
    :tags: Improvements
    :pullreq: 12411

    Support OpenSSL 3.0 for ipcipher CA6 encryption/decryption

  .. change::
    :tags: Improvements
    :pullreq: 12383

    Stronger guarantees against data race in the UDP path

  .. change::
    :tags: Improvements
    :pullreq: 12402

    Add bindings for the current and query times in DQ/DR

  .. change::
    :tags: New Features
    :pullreq: 12400

    Add SetReducedTTLResponseAction

  .. change::
    :tags: New Features
    :pullreq: 12385

    Add a Lua FFI interface for metrics

  .. change::
    :tags: Bug Fixes
    :pullreq: 12387

    Handle out-of-memory exceptions in the UDP receiver thread

  .. change::
    :tags: Bug Fixes
    :pullreq: 12365
    :tickets: 12357

    Prevent an underflow of the TCP d_queued counter

  .. change::
    :tags: Bug Fixes
    :pullreq: 12100
    :tickets: 12099

    Properly handle single-SOA XFR responses

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 12327

    Fix the health-check timeout computation for DoH backend

  .. change::
    :tags: New Features
    :pullreq: 12280

    Add a new chain of rules triggered after cache insertion

  .. change::
    :tags: Improvements
    :pullreq: 11554

    Raise RLIMIT_MEMLOCK automatically when eBPF is requested (Yogesh Singh)

  .. change::
    :tags: Improvements
    :pullreq: 12248
    :tickets: 11153

    Systemd: Add "After" dependency on time-sync.target (Kevin P. Fleming)

  .. change::
    :tags: Improvements, DNS over TLS
    :pullreq: 12237
    :tickets: 12236

    Ignore unclean TLS session shutdown

  .. change::
    :tags: Improvements, Performance
    :pullreq: 12276

    Reduce useless wake-ups from the event loop

  .. change::
    :tags: New Features
    :pullreq: 11020

    Added XDP middleware for dropped/redirected queries logging (Mini Pierre)

  .. change::
    :tags: Improvements
    :pullreq: 11863

    DNSName constructor use memchr instead of strchr and cleanup with string_view (Axel Viala)

  .. change::
    :tags: Improvements
    :pullreq: 12177
    :tickets: 12142

    Fix building with boost < 1.56

  .. change::
    :tags: New Features
    :pullreq: 12065

    Implement a 'lazy' health-checking mode

  .. change::
    :tags: Improvements, DNS over HTTPS, DNS over TLS
    :pullreq: 11675

    Skip DoT/DoH frontend when a tls configuration error occurs

  .. change::
    :tags: New Features
    :pullreq: 12074
    :tickets: 12073

    Add getPoolNames() function, returning a list of pool names (Christof Chen)

  .. change::
    :tags: New Features
    :pullreq: 12082

    Cleaner way of getting the IP/masks associated to a network interface

  .. change::
    :tags: Improvements
    :pullreq: 12077
    :tickets: 12075

    Retain output when expunging from multiple caches (Christof Chen)

  .. change::
    :tags: New Features
    :pullreq: 12022

    Add Lua helpers to look into the content of DNS payloads

  .. change::
    :tags: New Features
    :pullreq: 11994

    Add more Lua bindings for network-related operations

  .. change::
    :tags: Improvements, Performance, DNS over HTTPS
    :pullreq: 11901

    Faster cache-lookups for DNS over HTTPS queries

  .. change::
    :tags: Improvements, Performance
    :pullreq: 12003

    Add a 'single acceptor thread' build option, reducing the number of threads

  .. change::
    :tags: New Features
    :pullreq: 12008

    Add Lua binding for inspecting the in-memory ring buffers

  .. change::
    :tags: Bug Fixes
    :pullreq: 11729
    :tickets: 11728

    Fix a bug in SetEDNSOptionAction

  .. change::
    :tags: New Features
    :pullreq: 12007

    Add Lua bindings to look up domain and IP addresses from the cache

  .. change::
    :tags: Improvements, DNS over HTTPS
    :pullreq: 12000

    Speed up DoH handling by preventing allocations and copies

  .. change::
    :tags: Improvements, Metrics
    :pullreq: 11987

    Slightly reduce the number of allocations in API calls

  .. change::
    :tags: Improvements
    :pullreq: 11993

    Add build-time options to disable the dynamic blocks and UDP response delay

  .. change::
    :tags: Improvements
    :pullreq: 11992

    Add missing thread names

  .. change::
    :tags: Improvements
    :pullreq: 11988

    Add a build option (define) to prevent loading OpenSSL's errors

  .. change::
    :tags: Improvements
    :pullreq: 11862
    :tickets: 11853

    Properly load ciphers and digests with OpenSSL 3.0

  .. change::
    :tags: Improvements
    :pullreq: 11889

    Add local ComboAddress parameter for SBind() at TeeAction() (@FredericDT)

  .. change::
    :tags: Improvements, Performance
    :pullreq: 11883

    Make recording queries/responses in the ringbuffers optional

  .. change::
    :tags: Improvements, Performance
    :pullreq: 11852

    Slightly reduce contention around a pool's servers

  .. change::
    :tags: Improvements, Performance, DNS over HTTPS
    :pullreq: 11851

    Only call getsockname() once per incoming DoH connection

  .. change::
    :tags: Improvements
    :pullreq: 11844

    Do not keep the mplexer created for the initial health-check around

  .. change::
    :tags: Bug Fixes
    :pullreq: 11830
    :tickets: 4155

    Also reconnect on ENETUNREACH. (Asgeir Storesund Nilsen)

  .. change::
    :tags: Bug Fixes
    :pullreq: 11761

    Keep retained capabilities even when switching user/group

  .. change::
    :tags: Improvements, Performance
    :pullreq: 11734

    Set TCP_NODELAY on the TCP connection to backends

  .. change::
    :tags: Improvements
    :pullreq: 11723

    Use getrandom() if available

  .. change::
    :tags: Improvements
    :pullreq: 11713

    Implement a limit of concurrent connections to a backend

  .. change::
    :tags: Improvements, Metrics
    :pullreq: 11716

    Add more detailed metrics

  .. change::
    :tags: Bug Fixes
    :pullreq: 11718

    Fix the number of concurrent queries on a backend TCP conn

  .. change::
    :tags: Improvements
    :pullreq: 11712
    :tickets: 11585

    Fill ringbuffers with responses served from the cache

  .. change::
    :tags: Improvements
    :pullreq: 11696

    Bind to the requested src interface without a src address

  .. change::
    :tags: Improvements, Performance
    :pullreq: 11689

    Avoid allocating memory in LB policies for small number of servers

  .. change::
    :tags: Improvements, Metrics
    :pullreq: 11707

    Compute backend latency earlier, to avoid internal latency

  .. change::
    :tags: New Features
    :pullreq: 11698

    Implement `SuffixMatchTree::getBestMatch()` to get the name that matched

  .. change::
    :tags: Improvements
    :pullreq: 11711

    Log listening addresses and version at the 'info' level

  .. change::
    :tags: Improvements
    :pullreq: 11651

    Refactor sendfromto (Y7n05h)

  .. change::
    :tags: New Features
    :pullreq: 11526

    Use BPF_MAP_TYPE_LPM_TRIE for range matching (Y7n05h)

  .. change::
    :tags: Improvements, Performance
    :pullreq: 11624

    SuffixMatchTree: Improve lookup performance

  .. change::
    :tags: Improvements, Metrics
    :pullreq: 11659

    Add 'statistics' to the general API endpoint

  .. change::
    :tags: Improvements
    :pullreq: 11668

    Optionally send 'verbose' messages to a file, and log them at 'DEBUG' level otherwise

  .. change::
    :tags: New Features, Metrics
    :pullreq: 11674

    Add support for user defined metrics

  .. change::
    :tags: Improvements
    :pullreq: 11669

    Log when exiting due to a SIGTERM signal

  .. change::
    :tags: Improvements
    :pullreq: 11673

    Add the protocol (Do53, DoT, DoH, ...) of backends in the API

  .. change::
    :tags: Improvements, Metrics
    :pullreq: 11656

    Add a counter for the number of cache cleanups

  .. change::
    :tags: Improvements, Performance
    :pullreq: 11655

    Change dns_tolower() and dns_toupper() to use a table

  .. change::
    :tags: New Features
    :pullreq: 11637

    Add getVerbose() function

  .. change::
    :tags: New Features
    :pullreq: 11606

    Add Lua bindings to access the DNS payload as a string

  .. change::
    :tags: Improvements
    :pullreq: 11620
    :tickets: 11619

    Remove implicit type conversion (Y7n05h)

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 11621
    :tickets: 11604

    Fix a crash on an invalid protocol in DoH forwarded-for header

  .. change::
    :tags: Bug Fixes
    :pullreq: 11604

    Fix invalid proxy protocol payload on a DoH TC to TCP retry

  .. change::
    :tags: New Features
    :pullreq: 11567

    Add setVerbose() to switch the verbose mode at runtime

  .. change::
    :tags: Improvements, Performance
    :pullreq: 11577
    :tickets: 11576

    Scan the UDP buckets only when we have outstanding queries

  .. change::
    :tags: Improvements
    :pullreq: 11543
    :tickets: 11488

   Log when a console message exceeds the maximum size

  .. change::
    :tags: Improvements
    :pullreq: 11578

    Include the address of the backend in 'relayed to' messages

  .. change::
    :tags: Improvements, Webserver, Metrics
    :pullreq: 11514

    Add an option for unauthenticated access to the API

  .. change::
    :tags: Improvements
    :pullreq: 11573

    Better log message when no downstream server are available

  .. change::
    :tags: New Features
    :pullreq: 11547
    :tickets: 11434

    Add a 'getAddressAndPort()' method to DOHFrontend and TLSFrontend objects

  .. change::
    :tags: Bug Fixes
    :pullreq: 11545
    :tickets: 11501

    Use the correct outgoing protocol in our ring buffers

  .. change::
    :tags: Improvements
    :pullreq: 11546
    :tickets: 11383

    Raise the number of entries in a packet cache to at least 1

  .. change::
    :tags: Improvements
    :pullreq: 11535
    :tickets: 11526

    Merge multiple parameters in newBPFFilter (Y7n05h)

  .. change::
    :tags: Improvements, Performance
    :pullreq: 11531

    Prevent allocations in two corner cases

  .. change::
    :tags: Improvements
    :pullreq: 11523

    Reject BPFFilter::attachToAllBinds() at configuration time (Y7n05h)

  .. change::
    :tags: Improvements
    :pullreq: 11515

    Add more build-time options to select features

  .. change::
    :tags: Improvements
    :pullreq: 11517

    Multiplexer: Take the maximum number of events as a hint

  .. change::
    :tags: New Features
    :pullreq: 11497
    :tickets: 9994

    Add setTCPFastOpenKey() (Y7n05h)

  .. change::
    :tags: Improvements, Performance
    :pullreq: 11437
    :tickets: 11422

    Only allocate the health-check mplexer when needed

  .. change::
    :tags: Improvements, DNS over HTTPS, DNS over TLS
    :pullreq: 11415

    More useful default ports for DoT/DoH backends

  .. change::
    :tags: Improvements
    :pullreq: 11388

    Add --log-timestamps flag

  .. change::
    :tags: New Features, DNS over HTTPS, DNS over TLS
    :pullreq: 11293

    Dynamic discovery and upgrade of backends

  .. change::
    :tags: New Features, Security
    :pullreq: 11163

    Allow randomly selecting a backend UDP socket and query ID

  .. change::
    :tags: Removals
    :pullreq: 11324
    :tickets: 11201

    Remove the leak warning with GnuTLS >= 3.7.3

  .. change::
    :tags: Improvements
    :pullreq: 11174

    Add a parameter to PoolAction to keep processing rules

  .. change::
    :tags: New Features
    :pullreq: 11173

    Add Lua FFI helpers for protocol and MAC address access, proxy protocol payload generation

  .. change::
    :tags: Improvements
    :pullreq: 11196

    Fix build with OpenSSL 3.0.0

  .. change::
    :tags: Improvements, Performance
    :pullreq: 11171

    Defer the actual allocation of the ring buffer entries

  .. change::
    :tags: Improvements, DNS over HTTPS, DNS over TLS
    :pullreq: 11166

    Libssl: Load only the ciphers and digests needed for TLS, not all of them

  .. change::
    :tags: New Features
    :pullreq: 11184

    Add support to store mac address in query rings

  .. change::
    :tags: Improvements
    :pullreq: 11178

    Build with `-fvisibility=hidden` by default

  .. change::
    :tags: New Features
    :pullreq: 11126

    Add newThread() function

  .. change::
    :tags: Improvements
    :pullreq: 10950

    Add a lot more of build-time options to select features

  .. change::
    :tags: New Features
    :pullreq: 11098

    Lua support to remove resource records from a response

  .. change::
    :tags: New Features, DNS over HTTPS, DNS over TLS
    :pullreq: 11027

    Add support for password protected PKCS12 files for TLS configuration

  .. change::
    :tags: New Features
    :pullreq: 11051

    Add support to spoof a full self-generated response from lua

  .. change::
    :tags: New Features
    :pullreq: 10949

    Add a Lua FFI helper to generate proxy protocol payloads

  .. change::
    :tags: New Features
    :pullreq: 11017

    Add Lua bindings to get the list of network interfaces, addresses

  .. change::
    :tags: New Features, DNS over TLS
    :pullreq: 10734

    Add experimental support for TLS asynchronous engines

  .. change::
    :tags: New Features
    :pullreq: 11059

    Add lua support to limit TTL values of responses

.. changelog::
  :version: 1.7.3
  :released: 2nd of November 2022

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.7.x.

  dnsdist 1.7.3 contains no functional changes or bugfixes.
  This release strictly serves to bring dnsdist packages to our EL9 and Ubuntu Jammy repositories, and upgrades the dnsdist Docker image from Debian buster to Debian bullseye, as buster is officially EOL.

  .. change::
    :tags: Improvements
    :pullreq: 11948

    add el9/9stream targets

  .. change::
    :tags: Improvements
    :pullreq: 11974

    docker images: upgrade to Debian bullseye

  .. change::
    :tags: Improvements
    :pullreq: 11742

    dh_builddeb: force gzip compression (this makes the Ubuntu Jammy packages compatible with our Debian-hosted repositories)

.. changelog::
  :version: 1.7.2
  :released: 14th of June 2022

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.7.x.

  .. change::
    :tags: Improvements
    :pullreq: 11579
    :tickets: 11576

    Scan the UDP buckets only when we have outstanding queries

  .. change::
    :tags: Improvements
    :pullreq: 11580
    :tickets: 11422

    Only allocate the health-check mplexer when needed

  .. change::
    :tags: Bug Fixes, Metrics
    :pullreq: 11664
    :tickets: 11602

    Add missing descriptions for prometheus metrics

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 11665
    :tickets: 11604

    Fix invalid proxy protocol payload on a DoH TC to TCP retry

  .. change::
    :tags: Improvements
    :pullreq: 11666
    :tickets: 11606

    Add Lua bindings to access the DNS payload as a string

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 11667
    :tickets: 11621

    Fix a crash on an invalid protocol in DoH forwarded-for header

.. changelog::
  :version: 1.7.1
  :released: 25th of April 2022

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.7.x.

  .. change::
    :tags: Improvements
    :pullreq: 11195

    Fix compilation with OpenSSL 3.0.0

  .. change::
    :tags: Improvements
    :pullreq: 11094
    :tickets: 11081

    Docker images: remove capability requirements

  .. change::
    :tags: Improvements
    :pullreq: 11292
    :tickets: 11290

    Docker image: install ca-certificates

  .. change::
    :tags: Bug Fixes
    :pullreq: 11335
    :tickets: 11330

    Fix a use-after-free in case of a network error in the middle of a XFR query

  .. change::
    :tags: Bug Fixes
    :pullreq: 11550
    :tickets: 11504

    Properly use eBPF when the DynBlock is not set

  .. change::
    :tags: Improvements
    :pullreq: 11176
    :tickets: 11113

    Work around a compiler bug seen on OpenBSD/amd64 using clang-13

  .. change::
    :tags: Improvements
    :pullreq: 11197

    Stop using the now deprecated and useless std::binary_function

  .. change::
    :tags: Bug Fixes, DNS over HTTPS, DNS over TLS
    :pullreq: 11251
    :tickets: 11249

    Set Server Name Indication on outgoing TLS connections (DoT, DoH)

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 11253
    :tickets: 11250

    Fix the health-check timeout for outgoing DoH connections

  .. change::
    :tags: Bug Fixes
    :pullreq: 11255
    :tickets: 11254

    Fix 'inConfigCheck()'

  .. change::
    :tags: Bug Fixes, Metrics
    :pullreq: 11323
    :tickets: 11239

    Fix the latency-count metric

  .. change::
    :tags: Improvements, DNS over HTTPS, DNS over TLS
    :pullreq: 11324
    :tickets: 11201

    Remove the leak warning with GnuTLS >= 3.7.3

  .. change::
    :tags: Bug Fixes
    :pullreq: 11545
    :tickets: 11501

    Use the correct outgoing protocol in our ring buffers

  .. change::
    :tags: Bug Fixes
    :pullreq: 11546
    :tickets: 11383

    Raise the number of entries in a packet cache to at least 1

  .. change::
    :tags: Improvements
    :pullreq: 11547
    :tickets: 11434

    Add a 'getAddressAndPort()' method to DOHFrontend and TLSFrontend objects

  .. change::
    :tags: Bug Fixes
    :pullreq: 11565

    Fix wrong eBPF values (qtype, counter) being inserted for qnames

  .. change::
    :tags: Bug Fixes
    :pullreq: 11572
    :tickets: 11375

    The check interval applies to health-check, not timeouts

.. changelog::
  :version: 1.7.0
  :released: 17th of January 2022

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.7.x.

  .. change::
    :tags: Bug Fixes
    :pullreq: 11156
    :tickets: 11131

    Test the correct member in DynBlockRatioRule::warningRatioExceeded (Doug Freed)

.. changelog::
  :version: 1.7.0-rc1
  :released: 22nd of December 2021

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.7.x.

  .. change::
    :tags: Improvements, DNS over TLS, Performance
    :pullreq: 11037

    Reuse and save the TLS session tickets in DoT healthchecks

  .. change::
    :tags: Bug Fixes, DNS over HTTPS, Security
    :pullreq: 11075

    Fix a double-free when a DoH cross-protocol response is dropped

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 11079

    Check the size of the query when re-sending a DoH query

.. changelog::
  :version: 1.7.0-beta2
  :released: 29th of November 2021

  .. change::
    :tags: Bug Fixes
    :pullreq: 10993
    :tickets: 10988

    Fix compiler/static analyzer warnings

  .. change::
    :tags: Improvements, DNS over HTTPS, DNS over TLS
    :pullreq: 10997

    Add a function to know how many TLS sessions are currently cached

  .. change::
    :tags: Bug Fixes, DNS over HTTPS, DNS over TLS
    :pullreq: 10999

    Fix a memory leak when reusing TLS tickets for outgoing connections

  .. change::
    :tags: Improvements, DNS over HTTPS, DNS over TLS
    :pullreq: 11001

    Warn that GnuTLS 3.7.x leaks memory when validating certs

  .. change::
    :tags: Improvements
    :pullreq: 11006
    :tickets: 10135

    Add 'showWebserverConfig'

  .. change::
    :tags: Bug Fixes
    :pullreq: 11007

    Fix Lua parameters bound checks

  .. change::
    :tags: Improvements, Performance
    :pullreq: 11008
    :tickets: 10898

    Add a function to set the UDP recv/snd buffer sizes

  .. change::
    :tags: Bug Fixes
    :pullreq: 11031

    Add missing visibility attribute on `dnsdist_ffi_dnsquestion_get_qname_hash`

.. changelog::
  :version: 1.7.0-beta1
  :released: 16th of November 2021

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.7.x.

  .. change::
    :tags: Improvements
    :pullreq: 10646

    Convert make_pair to emplace (Rosen Penev)

  .. change::
    :tags: Improvements
    :pullreq: 10795
    :tickets: 10651

    Add syslog identifier to service file

  .. change::
    :tags: New Features
    :pullreq: 10815
    :tickets: 4993

    Add range support for dynamic blocks

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 10845

    Keep watching idle DoH backend connections

  .. change::
    :tags: Improvements, Performance
    :pullreq: 10862

    Use the same outgoing TCP connection for different clients

  .. change::
    :tags: Improvements
    :pullreq: 10868

    Get rid of make_pair (Rosen Penev)

  .. change::
    :tags: Improvements
    :pullreq: 10870

    Use make_unique instead of new (Rosen Penev)

  .. change::
    :tags: Bug Fixes
    :pullreq: 10874

    Properly handle I/O exceptions in the health checker

  .. change::
    :tags: Improvements, DNS over HTTPS, Performance
    :pullreq: 10875

    Read as many DoH responses as possible before yielding

  .. change::
    :tags: Improvements, DNS over HTTPS, Performance
    :pullreq: 10876

    Stop over-allocating for DoH queries

  .. change::
    :tags: Improvements, Protobuf, DNSTAP
    :pullreq: 10879
    :tickets: 9103

    Support DoT, DoH and DNSCrypt transports for protobuf and dnstap

  .. change::
    :tags: Bug Fixes
    :pullreq: 10900

    NetmaskTree: Drop the 'noexcept' qualifier on the TreeNode ctor

  .. change::
    :tags: Improvements
    :pullreq: 10907
    :tickets: 4670

    Handle existing EDNS content for SetMacAddrAction/SetEDNSOptionAction

  .. change::
    :tags: Bug Fixes, DNS over HTTPS, DNS over TLS
    :pullreq: 10920

    Fix the cleaning of TCP, DoT and DoH connections to the backend

  .. change::
    :tags: Bug Fixes
    :pullreq: 10922

    Fix build without nghttp2

  .. change::
    :tags: New Features
    :pullreq: 10923

    Add the ability to retain select capabilities at runtime

  .. change::
    :tags: Bug Fixes
    :pullreq: 10935

    Remove debug print line flooding logs (Eugen Mayer)

  .. change::
    :tags: Bug Fixes
    :pullreq: 10943
    :tickets: 10938

    Credentials: EVP_PKEY_CTX_set1_scrypt_salt() takes an `unsigned char*`

  .. change::
    :tags: New Features, Performance
    :pullreq: 10883, 10498

    Implement filesystem pinning for eBPF maps, drop and truncate via XDP (Pierre Grié)

.. changelog::
  :version: 1.7.0-alpha2
  :released: 19th of October 2021

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.7.x.

  .. change::
    :tags: Improvements
    :pullreq: 10760

    Don't create SSLKEYLOGFILE files with wide permissions

  .. change::
    :tags: Improvements
    :pullreq: 10767

    Update existing tags when calling setTagAction and setTagResponseAction

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 10772
    :tickets: 10771

    Better handling of outgoing DoH workers

  .. change::
    :tags: Improvements
    :pullreq: 10775
    :tickets: 10403

    Fix the unit tests to handle v4-only or v6-only connectivity

  .. change::
    :tags: Improvements
    :pullreq: 10782

    Improve the coverage of the outgoing DoH code

  .. change::
    :tags: Bug Fixes
    :pullreq: 10787

    Properly cache UDP queries passed to a TCP/DoT/DoH backend

  .. change::
    :tags: Improvements
    :pullreq: 10791

    Allow skipping arbitrary EDNS options when computing packet hash

  .. change::
    :tags: New Features
    :pullreq: 10814

    Add lua support for SetEDNSOptionAction

  .. change::
    :tags: Improvements, DNS over HTTPS, DNS over TLS
    :pullreq: 10823

    Disable TLS renegotiation, release buffers for outgoing TLS

  .. change::
    :tags: New Features
    :pullreq: 10832

    Rule for basing decisions on outstanding queries in a pool (phonedph1)

  .. change::
    :tags: Improvements
    :pullreq: 10833

    Add incoming and outgoing protocols to grepq

  .. change::
    :tags: Improvements
    :pullreq: 10835
    :tickets: 10559

    Allow setting the block reason from the SMT callback

  .. change::
    :tags: Bug Fixes
    :pullreq: 10841

    Use per-thread credentials for GnuTLS client connections

  .. change::
    :tags: Improvements
    :pullreq: 10844

    Clear the UDP states of TCP-only backends

  .. change::
    :tags: Improvements
    :pullreq: 10846

    Replace shared by unique ptrs, reduce structs size

  .. change::
    :tags: Bug Fixes
    :pullreq: 10848

    Only set recursion protection once we know we do not return

.. changelog::
  :version: 1.7.0-alpha1
  :released: 23rd of September 2021

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.7.x.

  .. change::
    :tags: Improvements
    :pullreq: 10157
    :tickets: 7937

    Move to hashed passwords for the web interface

 .. change::
    :tags: Improvements
    :pullreq: 10381

    Reorganize the IDState and Rings fields to reduce memory usage

  .. change::
    :tags: Improvements
    :pullreq: 10429

    Fix 'temporary used in loop' warnings reported by g++ 11.1.0

  .. change::
    :tags: Improvements
    :pullreq: 10441

    Skip some memory allocations in client mode to reduce memory usage

  .. change::
    :tags: Improvements
    :pullreq: 10414

    Support multiple ip addresses for dnsdist-resolver lua script (Wim)

  .. change::
    :tags: Improvements
    :pullreq: 10489
    :tickets: 10436

    Make DNSDist XFR aware when transfer is finished (Dimitrios Mavrommatis)

  .. change::
    :tags: New Features
    :pullreq: 10532
    :tickets: 10456

    Add FFI functions to spoof multiple raw values

  .. change::
    :tags: Improvements
    :pullreq: 10508
    :tickets: 10500

    Do not report latency metrics of down upstream servers (Holger Hoffstätte)

  .. change::
    :tags: Improvements
    :pullreq: 10537
    :tickets: 10338

    Carry the exact incoming protocol (Do53, DNSCrypt, DoT, DoH) in DQ

  .. change::
    :tags: Improvements
    :pullreq: 10527
    :tickets: 10502

    Implement 'reload()' to rotate Log(Response)Action's log file

  .. change::
    :tags: New Features, Performance
    :pullreq: 10501

    Add support for Lua per-thread FFI rules and actions

  .. change::
    :tags: Improvements, Performance
    :pullreq: 10520

    Don't look up the LMDB dbi by name for every query

  .. change::
    :tags: New Features
    :pullreq: 10525
    :tickets: 10520

    Add support for range-based lookups into a Key-Value store

  .. change::
    :tags: Improvements
    :pullreq: 10626

    Document that setECSOverride has its drawbacks (Andreas Jakum)

  .. change::
    :tags: Improvements
    :pullreq: 10649

    Convert dnsdist and the recursor to LockGuarded

  .. change::
    :tags: Improvements
    :pullreq: 10631

    Handle waiting for a descriptor to become readable OR writable

  .. change::
    :tags: Bug Fixes
    :pullreq: 10656

    Catch FDMultiplexerException in IOStateHandler's destructor

  .. change::
    :tags: New Features, DNS over TLS
    :pullreq: 10338

    Implement cross-protocol queries, including outgoing DNS over TLS

  .. change::
    :tags: Bug Fixes
    :pullreq: 10672

    Resizing LMDB map size while there might be open transactions is unsafe

  .. change::
    :tags: New Features
    :pullreq: 10597
    :tickets: 10367

    Implement SpoofSVCAction to return SVC responses

  .. change::
    :tags: Bug Fixes
    :pullreq: 10695
    :tickets: 10693

    Ignore TCAction over TCP

  .. change::
    :tags: Improvements
    :pullreq: 10687

    Clean up a bit of "cast from type [...] casts away qualifiers" warnings

  .. change::
    :tags: New Features, DNS over HTTPS
    :pullreq: 10635

    Implementation of DoH between dnsdist and the backend

  .. change::
    :tags: Bug Fixes
    :pullreq: 10704

    Stop raising the number of TCP workers to the number of TCP binds

  .. change::
    :tags: Bug Fixes
    :pullreq: 10724

    Handle exception raised in IOStateGuard's destructor

.. changelog::
  :version: 1.6.1
  :released: 15th of September 2021

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.6.x.

  .. change::
    :tags: Bug Fixes
    :pullreq: 10438

    Backport a missing mutex header

  .. change::
    :tags: Bug Fixes, DNSTAP
    :pullreq: 10538
    :tickets: 10497

    Set the dnstap/protobuf transport to TCP for DoH queries

  .. change::
    :tags: New Features
    :pullreq: 10550
    :tickets: 10418

    Add the missing DOHFronted::loadNewCertificatesAndKeys()

  .. change::
    :tags: New Features
    :pullreq: 10560
    :tickets: 10482

    Implement a web endpoint to get metrics for only one pool

  .. change::
    :tags: Bug Fixes
    :pullreq: 10619
    :tickets: 10419

    Properly handle ECS for queries with ancount or nscount > 0

  .. change::
    :tags: Bug Fixes
    :pullreq: 10656

    Catch FDMultiplexerException in IOStateHandler's destructor

  .. change::
    :tags: Bug Fixes
    :pullreq: 10706
    :tickets: 10705

    Fix outstanding counter issue on TCP error

.. changelog::
  :version: 1.6.0
  :released: 11th of May 2021

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.6.x.

.. changelog::
  :version: 1.5.2
  :released: 10th of May 2021

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.5.x.

  .. change::
    :tags: Bug Fixes
    :pullreq: 9583

    Make: two fixes

  .. change::
    :tags: Bug Fixes
    :pullreq: 9717
    :tickets: 9689

    Fix eBPF filtering of long qnames

  .. change::
    :tags: Bug Fixes, Metrics
    :pullreq: 9729
    :tickets: 9728

    Fix a typo in prometheus metrics dnsdist_frontend_tlshandshakefailures #9728 (AppliedPrivacy)

  .. change::
    :tags: Bug Fixes, Performance
    :pullreq: 9749

    Fix the DNSName move assignment operator

  .. change::
    :tags: Bug Fixes
    :pullreq: 9900

    Fix a hang when removing a server with more than one socket

  .. change::
    :tags: Bug Fixes, DNS over HTTPS, DNS over TLS
    :pullreq: 9922
    :tickets: 9921

    Fix SNI on resumed sessions by acknowledging the name sent by the client

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 9936
    :tickets: 9934

    Fix a crash when a DoH responses map is updated at runtime

  .. change::
    :tags: Bug Fixes
    :pullreq: 9980
    :tickets: 9756

    Fix Dynamic Block RCode rules messing up the queries count

  .. change::
    :tags: Bug Fixes
    :pullreq: 10012
    :tickets: 10006

    Fix EDNS in ServFail generated when no server is available

  .. change::
    :tags: Bug Fixes
    :pullreq: 10095
    :tickets: 10090

    Prevent a crash with DynBPF objects in client mode

  .. change::
    :tags: Bug Fixes
    :pullreq: 10355

    Add missing getEDNSOptions and getDO bindings for DNSResponse

.. changelog::
  :version: 1.6.0-rc2
  :released: 4th of May 2021

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.6.x.

  .. change::
    :tags: Improvements, Metrics
    :pullreq: 10323

    Make the backend queryLoad and dropRate values atomic

  .. change::
    :tags: Bug Fixes
    :pullreq: 10327
    :tickets: 10324

    Only use eBPF for "drop" actions, clean up more often

  .. change::
    :tags: Bug Fixes, DNSCrypt
    :pullreq: 10346

    Fix missing locks in DNSCrypt certificates management

.. changelog::
  :version: 1.6.0-rc1
  :released: 20th of April 2021

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.6.x.

  .. change::
    :tags: Bug Fixes
    :pullreq: 10171

    Lua: don't destroy keys during table iteration

  .. change::
    :tags: Improvements
    :pullreq: 10216
    :tickets: 10209

    Replace pthread_rwlock with std::shared_mutex

  .. change::
    :tags: Improvements
    :pullreq: 10264

    Also disable PMTU for v6

  .. change::
    :tags: Bug Fixes
    :pullreq: 10267
    :tickets: 10262

    Add missing getEDNSOptions and getDO bindings for DNSResponse

  .. change::
    :tags: Bug Fixes
    :pullreq: 10274

    Fix some issues reported by Thread Sanitizer

.. changelog::
  :version: 1.6.0-alpha3
  :released: 29th of March 2021

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.6.x.

  .. change::
    :tags: Improvements
    :pullreq: 10156

    Improve TCP connection reuse, add metrics

  .. change::
    :tags: Improvements
    :pullreq: 10161
    :tickets: 7591

    Using DATA to report memory usage is unreliable, start using RES instead, as it seems reliable and relevant

  .. change::
    :tags: Improvements, DNS over HTTPS, DNS over TLS
    :pullreq: 10179

    Set OpenSSL to release buffers when idle, saves 35 kB per connection

  .. change::
    :tags: Improvements
    :pullreq: 10184

    Add a metric for TCP listen queue full events

  .. change::
    :tags: Bug Fixes
    :pullreq: 10201

    Fix the TCP connect timeout, add metrics

  .. change::
    :tags: Improvements
    :pullreq: 10204

    Enable sharding by default, greater pipe buffer sizes

  .. change::
    :tags: Improvements
    :pullreq: 10207

    Add limits for cached TCP connections, metrics

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 10208

    Fix the handling of DoH queries with a non-zero ID

  .. change::
    :tags: Improvements, DNSCrypt, DNS over HTTPS, DNS over TLS
    :pullreq: 10214

    Unify certificate reloading syntaxes

  .. change::
    :tags: Improvements, DNS over HTTPS, DNS over TLS
    :pullreq: 10218

    Disable TLS renegotiation by default

.. changelog::
  :version: 1.6.0-alpha2
  :released: 4th of March 2021

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.6.x.

 .. change::
    :tags: Improvements
    :pullreq: 9361

    Bind __tostring instead of toString for Lua, so that conversion to string works automatically (Aki Tuomi)

  .. change::
    :tags: Improvements
    :pullreq: 10046
    :tickets: 10035

    Make NetmaskTree::fork() a bit easier to understand

  .. change::
    :tags: Bug Fixes
    :pullreq: 10050
    :tickets: 10049

    Remove forgotten debug line in the web server

  .. change::
    :tags: New Features
    :pullreq: 10063

    Add option to spoofRawAction to spoof multiple answers (Sander Hoentjen)

  .. change::
    :tags: New Features
    :pullreq: 10073

    Add 'spoof' and 'spoofRaw' Lua bindings

  .. change::
    :tags: Bug Fixes
    :pullreq: 10088

    Create TCP worker threads before acceptors ones

  .. change::
    :tags: Bug Fixes
    :pullreq: 10095
    :tickets: 10090

    Prevent a crash with DynBPF objects in client mode

  .. change::
    :tags: Bug Fixes
    :pullreq: 10108

    Fix several bugs in the TCP code path, add unit tests

  .. change::
    :tags: Improvements
    :pullreq: 10131

    Do not update the TCP error counters on idle states

  .. change::
    :tags: Bug Fixes
    :pullreq: 10139

    Fix size check during trailing data addition, regression tests

  .. change::
    :tags: Bug Fixes
    :pullreq: 10133

    Clean up expired entries from all the packet cache's shards

.. changelog::
  :version: 1.6.0-alpha1
  :released: 2nd of February 2021

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.6.x.

  .. change::
    :tags: Improvements
    :pullreq: 9273

    Add Lua bindings to get a server's latency

  .. change::
    :tags: Improvements
    :pullreq: 9225

    Wrap more FILE objects in smart pointers

  .. change::
    :tags: Bug Fixes
    :pullreq: 9222
    :tickets: 9075

    Use toStringWithPort instead of manual addr/port concat (Mischan Toosarani-Hausberger)

  .. change::
    :tags: Bug Fixes
    :pullreq: 9275

    Force a reconnection when a downstream transitions to the UP state (Nuitari, Stephane Bakhos)

  .. change::
    :tags: Improvements
    :pullreq: 9049

    Set the default EDNS buffer size on generated answers to 1232

  .. change::
    :tags: Improvements
    :pullreq: 9157
    :tickets: 9156

    Add support for FreeBSD's SO_REUSEPORT_LB

  .. change::
    :tags: Improvements, Performance
    :pullreq: 9382

    Speed up the round robin policy

  .. change::
    :tags: Bug Fixes
    :pullreq: 9381

    Handle EINTR in DelayPipe

  .. change::
    :tags: Improvements, Performance
    :pullreq: 9424

    Avoid unnecessary allocations and copies with DNSName::toDNSString()

  .. change::
    :tags: Improvements, Performance
    :pullreq: 9420
    :tickets: 8993

    Get rid of allocations in the packet cache's fast path

  .. change::
    :tags: Improvements
    :pullreq: 9428

    Accept string in DNSDistPacketCache:expungeByName

  .. change::
    :tags: Bug Fixes
    :pullreq: 9431

    Handle empty DNSNames in grepq()

  .. change::
    :tags: New Features
    :pullreq: 9175

    Add per-thread Lua FFI load-balancing policies

  .. change::
    :tags: Improvements
    :pullreq: 9466

    DNSName: add toDNSString convenience function

  .. change::
    :tags: Improvements, Security
    :pullreq: 8969

    Use more of systemd's sandboxing options when available

  .. change::
    :tags: Improvements
    :pullreq: 8993
    :tickets: 5131

    Skip EDNS Cookies in the packet cache

  .. change::
    :tags: Improvements, DNS over HTTPS, DNS over TLS
    :pullreq: 9510

    Prioritize ChaCha20-Poly1305 when client does (Sukhbir Singh)

  .. change::
    :tags: Bug Fixes
    :pullreq: 9583

    Make: two fixes

  .. change::
    :tags: Removals
    :pullreq: 9532

    Rename topRule() and friends

  .. change::
    :tags: Improvements
    :pullreq: 9677

    Add the query payload size to the verbose log over TCP

  .. change::
    :tags: New Features, webserver
    :pullreq: 9676
    :tickets: 9120

    Implement Lua custom web endpoints

  .. change::
    :tags: Bug Fixes
    :pullreq: 9689
    :tickets: 9626

    Fix eBPF filtering of long qnames

  .. change::
    :tags: Bug Fixes
    :pullreq: 9721

    Improve const-correctness of Lua bindings (Georgeto)

  .. change::
    :tags: Improvements
    :pullreq: 9737
    :tickets: 9274

    Add the response code in the packet cache dump

  .. change::
    :tags: Improvements, Performance
    :pullreq: 9749

    Fix the DNSName move assignment operator

  .. change::
    :tags: New Features
    :pullreq: 9582

    Implement TCP out-of-order

  .. change::
    :tags: Improvements
    :pullreq: 9746

    Add an optional name to rules

  .. change::
    :tags: Removals
    :pullreq: 9784
    :tickets: 9783

    Remove useless second argument for `SpoofAction`

  .. change::
    :tags: Improvements, Metrics
    :pullreq: 9756

    Add prometheus metrics for top Dynamic Blocks entries

  .. change::
    :tags: Improvements
    :pullreq: 9822

    Add the ability to set ACL from a file (Matti Hiljanen)

  .. change::
    :tags: Improvements, Performance
    :pullreq: 9850

    Don't copy the policy for every query

  .. change::
    :tags: Improvements, Performance
    :pullreq: 9832

    UUID: Use the non-cryptographic variant of the boost::uuid

  .. change::
    :tags: Improvements
    :pullreq: 9862
    :tickets: 9861

    Add a Lua binding for the number of queries dropped by a server

  .. change::
    :tags: Improvements, Metrics, DNS over HTTPS
    :pullreq: 9738

    Add per connection queries count and duration stats for DoH

  .. change::
    :tags: Bug Fixes
    :pullreq: 9900

    Fix a hang when removing a server with more than one socket

  .. change::
    :tags: Improvements, Performance
    :pullreq: 9782
    :tickets: 9756, 9756, 6763

    Use an eBPF filter for Dynamic blocks when available

  .. change::
    :tags: Improvements, Performance, Protobuf, DNSTAP
    :pullreq: 9843
    :tickets: 9780, 9781

    Use protozero for Protocol Buffer operations

  .. change::
    :tags: Bug Fixes, DNS over TLS
    :pullreq: 9921

    Fix SNI on resumed sessions by acknowledging the name sent by the client

  .. change::
    :tags: Bug Fixes
    :pullreq: 9925

    Appease clang++ 12 ASAN on macOS

  .. change::
    :tags: Improvements
    :pullreq: 9913

    Move to c++17

  .. change::
    :tags: New Features
    :pullreq: 9616

    Add support for incoming Proxy Protocol

  .. change::
    :tags: Bug Fixes
    :pullreq: 9937

    Bunch of signed vs unsigned warnings

  .. change::
    :tags: Improvements
    :pullreq: 9920
    :tickets: 9918

    Fix warnings on autoconf 2.70

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 9934
    :tickets: 9927

    Fix a crash when a DoH responses map is updated at runtime

  .. change::
    :tags: Improvements, webserver
    :pullreq: 9955

    Reduce diff to upstream yahttp, fixing a few CodeQL reports

  .. change::
    :tags: New Features
    :pullreq: 9960
    :tickets: 9536

    Add SkipCacheResponseAction

  .. change::
    :tags: Improvements, DNS over HTTPS
    :pullreq: 9962

    Add an option to allow sub-paths for DoH

  .. change::
    :tags: Improvements
    :pullreq: 9989
    :tickets: 9383

    Handle syslog facility as string, document the numerical one

  .. change::
    :tags: Improvements, webserver
    :pullreq: 9972
    :tickets: 8710, 9311

    Deprecate parameters to webserver(), add 'statsRequireAuthentication' parameter

  .. change::
    :tags: Improvements, DNS over TLS
    :pullreq: 9957

    Start all TCP worker threads on startup

  .. change::
    :tags: Improvements
    :pullreq: 9992
    :tickets: 9357

    Add a counter for queries truncated because of a rule

  .. change::
    :tags: Bug Fixes
    :pullreq: 9991
    :tickets: 9961

    Send a NotImp answer on empty (qdcount=0) queries

  .. change::
    :tags: Improvements
    :pullreq: 9993

    Replace offensive terms in our code and documentation

  .. change::
    :tags: Bug Fixes
    :pullreq: 9999
    :tickets: 7038

    Don't apply QPS to backend server on cache hits

  .. change::
    :tags: Bug Fixes
    :pullreq: 10012
    :tickets: 10006

    Fix EDNS in ServFail generated when no server is available

  .. change::
    :tags: Improvements
    :pullreq: 9998
    :tickets: 9455

    Use aligned atomics to prevent false sharing

  .. change::
    :tags: Improvements, Removals
    :pullreq: 9974
    :tickets: 8118

    Unify non-terminal actions as SetXXXAction()

  .. change::
    :tags: Improvements
    :pullreq: 10015
    :tickets: 9545

    Accept a NMG to fill DynBlockRulesGroup ranges

  .. change::
    :tags: Improvements
    :pullreq: 10023

    Silence clang 12 warning

  .. change::
    :tags: Improvements, Webserver
    :pullreq: 9997
    :tickets: 4978

    Limit the number of concurrent console and web connections

  .. change::
    :tags: Improvements
    :pullreq: 10035

    Fix a few warnings reported by clang's static analyzer and cppcheck

.. changelog::
  :version: 1.5.1
  :released: 1st of October 2020

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.5.x.

  .. change::
    :tags: Improvements
    :pullreq: 9540
    :tickets: 9372

    Add the 'clearConsoleHistory' command

  .. change::
    :tags: Bug Fixes
    :pullreq: 9541
    :tickets: 9372

    Stop the related responder thread when a backend is removed

  .. change::
    :tags: Bug Fixes
    :pullreq: 9542

    Fix getEDNSOptions() for {AN,NS}COUNT != 0 and ARCOUNT = 0

  .. change::
    :tags: Bug Fixes
    :pullreq: 9543

    Fix building with LLVM11 (@RvdE)

  .. change::
    :tags: Bug Fixes
    :pullreq: 9555

    Only add EDNS on negative answers if the query had EDNS

.. changelog::
  :version: 1.5.0
  :released: 30th of July 2020

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.5.x.

  .. change::
    :tags: Improvements
    :pullreq: 9231

    Use explicit flag for the specific version of c++ we are targeting.

  .. change::
    :tags: Bug Fixes
    :pullreq: 9320

    Prevent a possible overflow via large Proxy Protocol values. (Valentei Sergey)

  .. change::
    :tags: Bug Fixes
    :pullreq: 9348
    :tickets: 9279

    Avoid name clashes on Solaris derived systems.

  .. change::
    :tags: Bug Fixes
    :pullreq: 9343

    Resize hostname to final size in getCarbonHostname(). (Aki Tuomi)

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 9344

    Fix compilation with h2o_socket_get_ssl_server_name().

  .. change::
    :tags: Bug Fixes
    :pullreq: 9346

    Fix compilation on OpenBSD/amd64.

  .. change::
    :tags: Bug Fixes
    :pullreq: 9356

    Handle calling PacketCache methods on a nil object.

  .. change::
    :tags: Improvements
    :pullreq: 9360

    Prevent a copy of a pool's backends when selecting a server.

.. changelog::
  :version: 1.5.0-rc4
  :released: 7th of July 2020

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.5.x.

  .. change::
    :tags: Bug Fixes
    :pullreq: 9278

    Prevent a race between the DoH handling threads

.. changelog::
  :version: 1.5.0-rc3
  :released: 18th of June 2020

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.5.x.

  .. change::
    :tags: Improvements
    :pullreq: 9100

    Less negatives in secpoll error messages improves readability.

  .. change::
    :tags: Bug Fixes
    :pullreq: 9127
    :tickets: 9125

    Fix compilation on systems that do not define HOST_NAME_MAX

  .. change::
    :tags: Improvements
    :pullreq: 9207

    Use std::string_view when available (Rosen Penev)

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 9211
    :tickets: 9206

    Use non-blocking pipes to pass DoH queries/responses around

  .. change::
    :tags: Bug Fixes
    :pullreq: 9213

    Do not use `using namespace std;`

  .. change::
    :tags: New Features
    :pullreq: 9229

    Implement an ACL in the internal web server

  .. change::
    :tags: Improvements
    :pullreq: 9238
    :tickets: 8038

    Clean up dnsdistconf.lua as a default configuration file

  .. change::
    :tags: Improvements
    :pullreq: 9244

    Add optional masks to KeyValueLookupKeySourceIP

.. changelog::
  :version: 1.5.0-rc2
  :released: 13th of May 2020

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.5.x.

  .. change::
    :tags: Bug Fixes
    :pullreq: 9031
    :tickets: 9025

    Fix compilation of the ports event multiplexer

  .. change::
    :tags: Improvements
    :pullreq: 9042

    Avoid copies in for loops

  .. change::
    :tags: Improvements
    :pullreq: 9054

    Build with -Wmissing-declarations -Wredundant-decls

  .. change::
    :tags: Improvements
    :pullreq: 9016
    :tickets: 9004

    Use std::shuffle instead of std::random_shuffle

  .. change::
    :tags: Improvements
    :pullreq: 9053

    Get rid of a naked pointer in the /dev/poll event multiplexer

  .. change::
    :tags: Improvements
    :pullreq: 9059

    A few warnings fixed, reported by clang on OpenBSD

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 9068

    Fix duplicated HTTP/1 counter in 'showDOHFrontends()'

  .. change::
    :tags: Bug Fixes
    :pullreq: 9057

    Gracefully handle a failure to remove FD on (re)-connection

  .. change::
    :tags: Improvements
    :pullreq: 9067

    Wrap pthread objects

  .. change::
    :tags: Improvements, Metrics
    :pullreq: 9084

    Add the unit to the help for latency buckets

  .. change::
    :tags: Improvements
    :pullreq: 9078

    NetmaskTree: do not test node for null, the loop guarantees node is not null.

.. changelog::
  :version: 1.5.0-rc1
  :released: 16th of April 2020

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.5.x.

  .. change::
    :tags: Bug Fixes
    :pullreq: 8955

    On OpenBSD string_view is both in boost and std

  .. change::
    :tags: Improvements
    :pullreq: 8956

    Expose SuffixMatchNode::remove in Lua

  .. change::
    :tags: Improvements
    :pullreq: 8962

    Remove a std::move() preventing Return-Value Optimization in lmdb-safe.cc

  .. change::
    :tags: Bug Fixes, DNSCrypt
    :pullreq: 8974

    Keep accepting fragmented UDP datagrams on DNSCrypt binds

  .. change::
    :tags: Bug Fixes, DNSCrypt
    :pullreq: 8976
    :tickets: 8974

    Accept UDP datagrams larger than 1500 bytes for DNSCrypt

  .. change::
    :tags: Improvements
    :pullreq: 8996

    Drop responses with the QR bit set to 0

  .. change::
    :tags: Improvements
    :pullreq: 8994
    :tickets: 8986

    Add an option to control the size of the TCP listen queue

.. changelog::
  :version: 1.5.0-alpha1
  :released: 20th of March 2020

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.5.x.

  .. change::
    :tags: Improvements
    :pullreq: 7820

    Don't start as root within a systemd environment

  .. change::
    :tags: Bug Fixes
    :pullreq: 8115
    :tickets: 8098

    Fix ECS addition when the OPT record is not the last one

  .. change::
    :tags: New Features
    :pullreq: 8171
    :tickets: 4747

    Add SetNegativeAndSOAAction() and its Lua binding

  .. change::
    :tags: New Features
    :pullreq: 8274

    Implement dynamic blocking on ratio of rcode/total responses

  .. change::
    :tags: Improvements, Performance
    :pullreq: 8355

    Rework NetmaskTree for better CPU and memory efficiency. (Stephan Bosch)

  .. change::
    :tags: Improvements, DNS over TLS
    :pullreq: 8380

    Switch the default DoT provider from GnuTLS to OpenSSL

  .. change::
    :tags: Improvements
    :pullreq: 8456

    Separate the check-config and client modes

  .. change::
    :tags: Improvements, Performance
    :pullreq: 8491

    Implement parallel health checks

  .. change::
    :tags: New Features, Performance
    :pullreq: 8505
    :tickets: 7617

    Implement LuaFFIRule, LuaFFIAction and LuaFFIResponseAction

  .. change::
    :tags: Improvements
    :pullreq: 8529

    Add the number of received bytes to StatNode entries

  .. change::
    :tags: Improvements, Performance
    :pullreq: 8538

    Use move semantics when updating the content of the StateHolder

  .. change::
    :tags: Improvements
    :pullreq: 8556
    :tickets: 8534

    Support setting the value of AA, AD and RA when self-generating answers

  .. change::
    :tags: New Features
    :pullreq: 8567
    :tickets: 7387

    Add bounded loads to the consistent hashing policy

  .. change::
    :tags: Improvements
    :pullreq: 8580

    pthread_rwlock_init() should be matched by pthread_rwlock_destroy()

  .. change::
    :tags: Bug Fixes
    :pullreq: 8591

    Wait longer for the TLS ticket to arrive in our tests

  .. change::
    :tags: Bug Fixes
    :pullreq: 8604

    Add missing exception message in KVS error

  .. change::
    :tags: Improvements
    :pullreq: 8631

    Replace include guard ifdef/define with pragma once (Chris Hofstaedtler)

  .. change::
    :tags: New Features
    :pullreq: 8654

    LogResponseAction (phonedph1)

  .. change::
    :tags: Improvements
    :pullreq: 8657

    Allow retrieving and deleting a backend via its UUID

  .. change::
    :tags: Bug Fixes, DNS over TLS
    :pullreq: 8662

    Display the correct DoT provider

  .. change::
    :tags: Improvements, Protobuf
    :pullreq: 8702

    Add the source and destination ports to the protobuf msg

  .. change::
    :tags: New Features
    :pullreq: 8722

    Add spoofRawAction() to craft answers from raw bytes

  .. change::
    :tags: Improvements
    :pullreq: 8733

    Load an openssl configuration file, if any, during startup

  .. change::
    :tags: Improvements, DNS over HTTPS
    :pullreq: 8760
    :tickets: 8573

    Don't accept sub-paths of configured DoH URLs

  .. change::
    :tags: Bug Fixes, DNS over TLS
    :pullreq: 8761

    Use ref counting for the DoT TLS context

  .. change::
    :tags: Improvements, DNS over HTTPS
    :pullreq: 8762
    :tickets: 8586

    Implement Cache-Control headers in DoH

  .. change::
    :tags: Improvements, Metrics
    :pullreq: 8772
    :tickets: 8746

    Add backend status to prometheus metrics

  .. change::
    :tags: Bug Fixes
    :pullreq: 8782

    Add getTag()/setTag() Lua bindings for a DNSResponse

  .. change::
    :tags: Improvements, Metrics
    :pullreq: 8783

    Add 'IO wait' and 'steal' metrics on Linux

  .. change::
    :tags: Bug Fixes
    :pullreq: 8787
    :tickets: 8442

    Fix key logging for DNS over TLS

  .. change::
    :tags: Improvements, Performance
    :pullreq: 8812

    Keep a masked network in the Netmask class

  .. change::
    :tags: New Features
    :pullreq: 8874

    Add support for Proxy Protocol between dnsdist and the recursor

  .. change::
    :tags: Improvements
    :pullreq: 8848

    Add get*BindCount() functions

  .. change::
    :tags: Bug Fixes
    :pullreq: 8855

    Fix a typo in the help/completion for getDNSCryptBindCount

  .. change::
    :tags: Bug Fixes
    :pullreq: 8856

    Implement rmACL() (swoga)

  .. change::
    :tags: Bug Fixes
    :pullreq: 8879

    Remove unused lambda capture reported by clang++

  .. change::
    :tags: Improvements
    :pullreq: 8882

    Add sessionTimeout setting for TLS session lifetime (Matti Hiljanen)

  .. change::
    :tags: Bug Fixes, Protobuf
    :pullreq: 8883
    :tickets: 8629

    Add 'queue full' metrics for our remote logger, log at debug only

  .. change::
    :tags: Improvements, Protobuf
    :pullreq: 8887

    Better handling of reconnections in Remote Logger

  .. change::
    :tags: Improvements, DNS over HTTPS, DNS over TLS
    :pullreq: 8899
    :tickets: 8806

    Document that the 'keyLogFile' option requires OpenSSL >= 1.1.1

  .. change::
    :tags: Improvements
    :pullreq: 8900
    :tickets: 8739

    Detect {Libre,Open}SSL functions availability during configure

  .. change::
    :tags: Improvements, DNS over HTTPS
    :pullreq: 8905
    :tickets: 8819

    Change the default DoH path from / to /dns-query

  .. change::
    :tags: New Features
    :pullreq: 8909

    Implement bounded loads for the whashed and wrandom policies

  .. change::
    :tags: Improvements, DNSTAP, Performance
    :pullreq: 8937

    Make FrameStream IO parameters configurable

  .. change::
    :tags: Improvements, DNS over HTTPS
    :pullreq: 8945
    :tickets: 8661

    Add support for the processing of X-Forwarded-For headers

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 8949

    Set the DoH ticket rotation delay before loading tickets

  .. change::
    :tags: Improvements
    :pullreq: 8950
    :tickets: 8669

    Warn on startup about low weight values with chashed

.. changelog::
  :version: 1.4.0
  :released: 20th of November 2019

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.4.x.

  .. change::
    :tags: Bug Fixes
    :pullreq: 8524

    Lowercase the name blocked by a SMT dynamic block

  .. change::
    :tags: Improvements
    :pullreq: 8531

    Fix the default value of ``setMaxUDPOutstanding`` in the console's help (phonedph1)

  .. change::
    :tags: Improvements
    :pullreq: 8522

    Add bindings for the noerrors and drops members of StatNode

  .. change::
    :tags: DNS over HTTPS, DNS over TLS
    :pullreq: 8526

    Prefer the cipher suite from the server by default (DoH, DoT)

  .. change::
    :tags: Improvements
    :pullreq: 8440

    Fix -Wshadow warnings (Aki Tuomi)

  .. change::
    :tags: Improvements
    :pullreq: 8509

    Fix typo: settting to setting (Chris Hofstaedtler)

.. changelog::
  :version: 1.4.0-rc5
  :released: 30th of October 2019

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.4.x.

  .. change::
    :tags: Improvements, DNS over HTTPS, Metrics
    :pullreq: 8465

    Rename the 'address' label to 'frontend' for DoH metrics

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 8471

    Increment the DOHUnit ref count when it's set in the IDState

.. changelog::
  :version: 1.4.0-rc4
  :released: 25th of October 2019

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.4.x.

  .. change::
    :tags: New Features, DNS over HTTPS, DNS over TLS
    :pullreq: 8442

    Add support dumping TLS keys via keyLogFile

  .. change::
    :tags: Improvements, DNS over HTTPS
    :pullreq: 8416

    Implement reference counting for the DOHUnit object

  .. change::
    :tags: Improvements, DNS over HTTPS, DNS over TLS, Metrics
    :pullreq: 8447

    Add metrics about TLS handshake failures for DoH and DoT

  .. change::
    :tags: Improvements
    :pullreq: 8411
    :tickets: 8390

    Add more options to LogAction (non-verbose mode, timestamps)

  .. change::
    :tags: Improvements, DNS over HTTPS, DNS over TLS
    :pullreq: 8383

    Merge the setup of TLS contexts in DoH and DoT

  .. change::
    :tags: Bug Fixes
    :pullreq: 8408

    Fix the caching of large entries

  .. change::
    :tags: Improvements
    :pullreq: 8415

    Fix formatting in showTCPStats()

  .. change::
    :tags: Bug Fixes
    :pullreq: 8413
    :tickets: 8412

    Work around cmsg_space somehow not being a constexpr on macOS

  .. change::
    :tags: Improvements
    :pullreq: 8372

    Use SO_BINDTODEVICE when available for newServer's source interface

  .. change::
    :tags: Bug Fixes, Metrics
    :pullreq: 8409

    Add missing prometheus descriptions for cache-related metrics

  .. change::
    :tags: Improvements, DNS over HTTPS, DNS over TLS, Metrics
    :pullreq: 8406

    Add metrics about unknown/inactive TLS ticket keys

  .. change::
    :tags: Improvements, DNS over TLS, Metrics
    :pullreq: 8387

    Add metrics about TLS versions with DNS over TLS

  .. change::
    :tags: Improvements, DNS over HTTPS, Metrics
    :pullreq: 8395

    Count the number of concurrent connections for DoH as well

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 8388

    Clear the DoH session ticket encryption key in the ctor

  .. change::
    :tags: Improvements, DNS over HTTPS, DNS over TLS
    :pullreq: 8382

    Add a 'preferServerCiphers' option for DoH and DoT

  .. change::
    :tags: Bug Fixes, Metrics
    :pullreq: 8381

    Add a prometheus 'thread' label to distinguish identical frontends

  .. change::
    :tags: Bug Fixes, Metrics
    :pullreq: 8378

    Fix a typo in the prometheus description of 'senderrors'

  .. change::
    :tags: Bug Fixes, Metrics
    :pullreq: 8368

    More prometheus fixes

  .. change::
    :tags: Improvements, DNS over HTTPS
    :pullreq: 8365
    :tickets: 8353

    Lowercase custom DoH header names

  .. change::
    :tags: Improvements
    :pullreq: 8364
    :tickets: 8362

    Check the address supplied to 'webserver' in check-config

  .. change::
    :tags: Improvements, DNS over HTTPS, Metrics
    :pullreq: 8361

    Refactor DoH prometheus metrics again

  .. change::
    :tags: Bug Fixes
    :pullreq: 8359

    Fix the creation order of rules when inserted via setRules()

.. changelog::
  :version: 1.4.0-rc3
  :released: 30th of September 2019

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.4.x.


  .. change::
    :tags: Improvements
    :pullreq: 8083
    :tickets: 7845

    Clean up our interactions with errno

  .. change::
    :tags: Improvements, DNS over HTTPS, DNS over TLS
    :pullreq: 8264

    Display the DoH and DoT binds in the web view

  .. change::
    :tags: Improvements
    :pullreq: 8265
    :tickets: 5514

    Remove the 'blockfilter' stat from the web view

  .. change::
    :tags: Improvements, DNS over HTTPS
    :pullreq: 8267

    Allow accepting DoH queries over HTTP instead of HTTPS

  .. change::
    :tags: Improvements
    :pullreq: 8268

    Fix some spelling mistakes noticed by lintian (Chris Hofstaedtler)

  .. change::
    :tags: Bug Fixes
    :pullreq: 8281

    Fix the newCDBKVStore console completion when LMDB is not enabled (phonedph1)

  .. change::
    :tags: Bug Fixes
    :pullreq: 8283

    Allow configure CDB_CFLAGS to work (phonedph1)

  .. change::
    :tags: Improvements
    :pullreq: 8285

    dnsdistconf.lua use non-deprecated versions for 1.4.0 (phonedph1)

  .. change::
    :tags: Bug Fixes
    :pullreq: 8303

    Fix the warning message on an invalid secpoll answer

  .. change::
    :tags: Bug Fixes
    :pullreq: 8304
    :tickets: 8300

    Don't connect to remote logger in client/command mode

  .. change::
    :tags: Improvements
    :pullreq: 8318

    Better use of labels in our DoH prometheus export

  .. change::
    :tags: Improvements, DNS over HTTPS
    :pullreq: 8349

    Implement TLS session ticket keys management for DoH

.. changelog::
  :version: 1.4.0-rc2
  :released: 2nd of September 2019

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.4.x.


  .. change::
    :tags: New Features
    :pullreq: 8139

    Add a KeyValueStoreLookup action based on CDB or LMDB

  .. change::
    :tags: Security
    :pullreq: 8200

    Update h2o to 2.2.6, fixing CVE-2019-9512, CVE-2019-9514 and CVE-2019-9515 for repo.powerdns.com packages

  .. change::
    :tags: New Features, DNS over HTTPS
    :pullreq: 8206

    Add support for early DoH HTTP responses

  .. change::
    :tags: Improvements, DNS over HTTPS, DNS over TLS
    :pullreq: 8207
    :tickets: 8202

    Add minTLSVersion for DoH and DoT

  .. change::
    :tags: Improvements
    :pullreq: 8250

    Split dnsdist-lua-bindings.cc to reduce memory consumption during compilation

  .. change::
    :tags: Improvements
    :pullreq: 8252

    Add a Lua binding for `dynBlockRulesGroup:setQuiet(quiet)`

.. changelog::
  :version: 1.4.0-rc1
  :released: 12th of August 2019

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.4.x.

  .. change::
    :tags: Improvements
    :pullreq: 7860

    Disallow TCP disablement

  .. change::
    :tags: Improvements
    :pullreq: 7862

    Update boost.m4 to the latest version

  .. change::
    :tags: Bug Fixes
    :pullreq: 7886

    SuffixMatchTree: fix root removal, partial match of non-leaf nodes

  .. change::
    :tags: Improvements
    :pullreq: 7909

    Print stats from expungeByName (Matti Hiljanen)

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 7911
    :tickets: 7894

    Properly override the HTTP Server header for DoH

  .. change::
    :tags: Bug Fixes, DNS over HTTPS, DNS over TLS
    :pullreq: 7915

    Exit when requested DoT/DoH support is not compiled in

  .. change::
    :tags: Improvements, DNS over HTTPS
    :pullreq: 7917

    Send better HTTP status codes, handle ACL drops earlier

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 7927
    :tickets: 7917

    Proper HTTP response for timeouts over DoH

  .. change::
    :tags: Improvements, DNS over HTTPS
    :pullreq: 7933
    :tickets: 7898

    Add more stats about DoH HTTP responses

  .. change::
    :tags: Bug Fixes, Carbon, Prometheus
    :pullreq: 7934
    :tickets: 7933

    Deduplicate frontends entries with carbon and prometheus

  .. change::
    :tags: Bug Fixes
    :pullreq: 7951
    :tickets: 6942, 8084

    Update boost.m4

  .. change::
    :tags: Improvements
    :pullreq: 7952
    :tickets: 7950

    Squelch unused function warning

  .. change::
    :tags: Bug Fixes
    :pullreq: 7974
    :tickets: 7971

    Fix short IOs over TCP

  .. change::
    :tags: Improvements, DNS over TLS
    :pullreq: 7978

    Improve error messages for DoT issues

  .. change::
    :tags: Bug Fixes
    :pullreq: 7979

    Fix handling of backend connection failing over TCP

  .. change::
    :tags: Improvements
    :pullreq: 7985

    SuffixMatchNode:add(): accept more types

  .. change::
    :tags: Improvements
    :pullreq: 7990
    :tickets: 7981

    Explicitly align the buffer used for cmsgs

  .. change::
    :tags: Improvements
    :pullreq: 7992

    Add `quiet` parameter to NetmaskGroupRule

  .. change::
    :tags: Improvements
    :pullreq: 7996
    :tickets: 7981

    Clear cmsg_space(sizeof(data)) in cmsghdr to appease Valgrind

  .. change::
    :tags: Bug Fixes
    :pullreq: 8003

    Insert the response into the ringbuffer right after sending it

  .. change::
    :tags: Improvements
    :pullreq: 8007

    Add static assertions for the size of the src address control buffer

  .. change::
    :tags: Improvements
    :pullreq: 8013

    Don't create temporary strings to escape DNSName labels

  .. change::
    :tags: Bug Fixes, DNSCrypt
    :pullreq: 8015
    :tickets: 8014

    Skip non-dnscrypt binds in `showDNSCryptBinds()`

  .. change::
    :tags: Improvements
    :pullreq: 8024

    Display TCP/DoT queries and responses in verbose mode, opcode in grepq

  .. change::
    :tags: Improvements
    :pullreq: 8025

    Be a bit more explicit about what failed in testCrypto()

  .. change::
    :tags: Bug Fixes
    :pullreq: 8030
    :tickets: 8021

    Handle ENOTCONN on read() over TCP

  .. change::
    :tags: Improvements, DNSCrypt
    :pullreq: 8042
    :tickets: 8020

    Accept more than one certificate in `addDNSCryptBind()`

  .. change::
    :tags: Bug Fixes
    :pullreq: 8067

    Make sure we always compile with BOOST_CB_ENABLE_DEBUG set to 0

  .. change::
    :tags: Bug Fixes
    :pullreq: 8078

    Catch exceptions thrown when handling a TCP response

  .. change::
    :tags: Bug Fixes
    :pullreq: 8079

    Fix unlimited retries when TCP Fast Open is enabled

  .. change::
    :tags: Bug Fixes
    :pullreq: 8081

    M4/systemd.m4: fail when systemctl is not available

  .. change::
    :tags: Bug Fixes, Prometheus
    :pullreq: 8105

    Fix a typo in the Server's latency description for Prometheus (phonedph1)

  .. change::
    :tags: Improvements
    :pullreq: 8110

    Update URLs to use HTTPS scheme (Chris Hofstaedtler)

  .. change::
    :tags: Bug Fixes, DNS over HTTPS
    :pullreq: 8112

    Prevent a dangling DOHUnit pointer when send() failed

  .. change::
    :tags: Improvements
    :pullreq: 8113

    Double-check we only increment the outstanding counter once

  .. change::
    :tags: New Features
    :pullreq: 8117

    Implement ContinueAction()

  .. change::
    :tags: Bug Fixes
    :pullreq: 8131
    :tickets: 8130

    Console: flush cout after printing g_outputbuffer (Doug Freed)

  .. change::
    :tags: Improvements
    :pullreq: 8135
    :tickets: 8108

    ext/ipcrypt: ship license in tarballs (Chris Hofstaedtler)

  .. change::
    :tags: New Features, DNS over HTTPS, DNS over TLS
    :pullreq: 8141
    :tickets: 7812

    Add OCSP stapling (from files) for DoT and DoH

  .. change::
    :tags: New Features, DNS over HTTPS
    :pullreq: 8148
    :tickets: 7957, 7900

    Add support for custom DoH headers (Melissa Voegeli)

  .. change::
    :tags: New Features, DNS over HTTPS
    :pullreq: 8153
    :tickets: 8133

    Add lua bindings, rules and action for DoH

  .. change::
    :tags: Improvements
    :pullreq: 8154

    Use a counter to mark IDState usage instead of the FD

  .. change::
    :tags: Bug Fixes
    :pullreq: 8158

    Fix signedness issue in isEDNSOptionInOpt()

  .. change::
    :tags: Improvements
    :pullreq: 8175

    Increase the default value of setMaxUDPOutstanding to 65535

.. changelog::
  :version: 1.4.0-beta1
  :released: 6th of June 2019

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.4.x.

  .. change::
    :tags: Bug Fixes, DoH
    :pullreq: 7814
    :tickets: 7810

    DoH: Don't let 'self' dangling while parsing the request's qname, this could lead to a crash

  .. change::
    :tags: Bug Fixes
    :pullreq: 7823

    Fix minor issues reported by Coverity

  .. change::
    :tags: New Features, DoT, DoH
    :pullreq: 7825
    :tickets: 7210

    Implement SNIRule for DoT and DoH

  .. change::
    :tags: Bug Fixes
    :pullreq: 7833

    Remove second, incomplete copy of lua EDNSOptionCode table

  .. change::
    :tags: Improvements, Prometheus
    :pullreq: 7853
    :tickets: 6088

    Support Prometheus latency histograms (Marlin Cremers)

.. changelog::
  :version: 1.4.0-alpha2
  :released: 26th of April 2019

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.4.x.

  .. change::
    :tags: Improvements
    :pullreq: 7410

    Ignore Path MTU discovery on UDP server socket

  .. change::
    :tags: Improvements
    :pullreq: 7708

    Alternative solution to the unaligned accesses.

  .. change::
    :tags: Bug Fixes
    :pullreq: 7718

    Exit when setting ciphers fails (GnuTLS)

  .. change::
    :tags: New Features
    :pullreq: 7726
    :tickets: 6911, 7526

    Add DNS over HTTPS support based on libh2o

.. changelog::
  :version: 1.4.0-alpha1
  :released: 12th of April 2019

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.4.x.

 .. change::
    :tags: New Features
    :pullreq: 7209

    Make recursor & dnsdist communicate (ECS) 'variable' status

 .. change::
    :tags: Improvements
    :pullreq: 7167

    Fix compiler warning about returning garbage (Adam Majer)

  .. change::
    :tags: Improvements
    :pullreq: 7168

    Fix warnings, mostly unused parameters, reported by -wextra

  .. change::
    :tags: New Features
    :pullreq: 6959
    :tickets: 6941, 2362

    Add namespace and instance variable to carbon key (Gibheer)

  .. change::
    :tags: Improvements
    :pullreq: 7191

    Add optional uuid column to showServers()

  .. change::
    :tags: New Features
    :pullreq: 7087

    Allow NoRecurse for use in dynamic blocks or Lua rules (phonedph1)

  .. change::
    :tags: New Features
    :pullreq: 7197
    :tickets: 7194

    Expose secpoll status

  .. change::
    :tags: Improvements
    :pullreq: 7026

    Configure --enable-pdns-option --with-third-party-module (Josh Soref)

  .. change::
    :tags: Bug Fixes
    :pullreq: 7256

    Protect GnuTLS tickets key rotation with a read-write lock

  .. change::
    :tags: Bug Fixes
    :pullreq: 7267

    Check that ``SO_ATTACH_BPF`` is defined before enabling eBPF

  .. change::
    :tags: Improvements
    :pullreq: 7138

    Drop remaining capabilities after startup

  .. change::
    :tags: New Features
    :pullreq: 7323
    :tickets: 7236

    Add an optional 'checkTimeout' parameter to 'newServer()'

  .. change::
    :tags: New Features
    :pullreq: 7322
    :tickets: 7237

    Add a 'rise' parameter to 'newServer()'

  .. change::
    :tags: New Features
    :pullreq: 7310
    :tickets: 7239

    Add a 'keepStaleData' option to the packet cache

  .. change::
    :tags: New Features
    :pullreq: 6967
    :tickets: 6846, 6897

    Expose trailing data (Richard Gibson)

  .. change::
    :tags: Improvements
    :pullreq: 6634

    More sandboxing using systemd's features

  .. change::
    :tags: Bug Fixes
    :pullreq: 7426

    Fix off-by-one in mvRule counting

  .. change::
    :tags: Improvements
    :pullreq: 7428

    Reduce systemcall usage in Protobuf logging

  .. change::
    :tags: Improvements
    :pullreq: 7433

    Resync YaHTTP code to cmouse/yahttp@11be77a1fc4032 (Chris Hofstaedtler)

  .. change::
    :tags: New Features
    :pullreq: 7142

    Add option to set interval between health checks (1848)

  .. change::
    :tags: New Features
    :pullreq: 7406

    Add EDNS unknown version handling (Dmitry Alenichev)

  .. change::
    :tags: Improvements
    :pullreq: 7431

    Pass empty response (Dmitry Alenichev)

  .. change::
    :tags: Improvements
    :pullreq: 7502

    Change the way getRealMemusage() works on linux (using statm)

  .. change::
    :tags: Bug Fixes
    :pullreq: 7520

    Don't convert nsec to usec if we need nsec

  .. change::
    :tags: New Features
    :pullreq: 7537

    DNSNameSet and QNameSetRule (Andrey)

  .. change::
    :tags: Bug Fixes
    :pullreq: 7594

    Fix setRules()

  .. change::
    :tags: Bug Fixes
    :pullreq: 7560

    Handle EAGAIN in the GnuTLS DNS over TLS provider

  .. change::
    :tags: Bug Fixes
    :pullreq: 7586
    :tickets: 7461

    Gracefully handle a null latency in the webserver's js

  .. change::
    :tags: Improvements
    :pullreq: 7585
    :tickets: 7534

    Prevent 0-ttl cache hits

  .. change::
    :tags: Improvements
    :pullreq: 7343
    :tickets: 7139

    Add addDynBlockSMT() support to dynBlockRulesGroup

  .. change::
    :tags: Improvements
    :pullreq: 7578

    Add frontend response statistics (Matti Hiljanen)

  .. change::
    :tags: Bug Fixes
    :pullreq: 7652

   EDNSOptionView improvements

  .. change::
    :tags: New Features
    :pullreq: 7481
    :tickets: 6242

    Add support for encrypting ip addresses #gdpr

  .. change::
    :tags: Improvements
    :pullreq: 7670

    Remove addLuaAction and addLuaResponseAction

  .. change::
    :tags: Improvements
    :pullreq: 7559
    :tickets: 7526, 4814

    Refactoring of the TCP stack

  .. change::
    :tags: Bug Fixes
    :pullreq: 7674
    :tickets: 7481

    Honor libcrypto include path

  .. change::
    :tags: New Features
    :pullreq: 7677
    :tickets: 5653

    Add 'setSyslogFacility()'

  .. change::
    :tags: Improvements
    :pullreq: 7692
    :tickets: 7556

    Prevent a conflict with BADSIG being clobbered

  .. change::
    :tags: Improvements
    :pullreq: 7689

    Switch to the new 'newPacketCache()' syntax for 1.4.0

  .. change::
    :tags: New Features
    :pullreq: 7676

    Add 'reloadAllCertificates()'

  .. change::
    :tags: Improvements
    :pullreq: 7678

    Move constants to proper namespace

  .. change::
    :tags: Improvements
    :pullreq: 7694

    Unify the management of DNS/DNSCrypt/DoT frontends

.. changelog::
  :version: 1.3.3
  :released: 8th of November 2018

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.3.x.

  .. change::
    :tags: New Features
    :pullreq: 6737, 6939
    :tickets: 6932

    Add consistent hash builtin policy

  .. change::
    :tags: New Features
    :pullreq: 6803

    Add EDNSOptionRule

  .. change::
    :tags: New Features
    :pullreq: 6813

    Add DSTPortRule (phonedph1)

  .. change::
    :tags: New Features
    :pullreq: 6826

    Make getOutstanding usable from both lua and console (phonedph1)

  .. change::
    :tags: Improvements
    :pullreq: 6831

    Get rid of some allocs/copies in DNS parsing

  .. change::
    :tags: Bug Fixes
    :pullreq: 6835

    Display dynblocks' default action, None, as the global one

  .. change::
    :tags: Improvements
    :pullreq: 6847
    :tickets: 6348, 4857

    Set a correct EDNS OPT RR for self-generated answers

  .. change::
    :tags: New Features
    :pullreq: 6856

    Added :excludeRange and :includeRange methods to DynBPFFilter class (Reinier Schoof)

  .. change::
    :tags: Improvements
    :pullreq: 6877

    Fix a sign-comparison warning in isEDNSOptionInOPT()

  .. change::
    :tags: New Features
    :pullreq: 3935, 6343, 6901, 7007, 7089
    :tickets: 4947, 6002

    Add Prometheus stats support (Pavel Odintsov, Kai S)

  .. change::
    :tags: Bug Fixes
    :pullreq: 6956

    Fix compilation when SO_REUSEPORT is not defined

  .. change::
    :tags: Improvements
    :pullreq: 6986
    :tickets: 6907, 6907

    Add warning rates to DynBlockRulesGroup rules

  .. change::
    :tags: New Features
    :pullreq: 6997
    :tickets: 6974

    Name threads in the programs

  .. change::
    :tags: Improvements
    :pullreq: 7015
    :tickets: 7004, 6990

    Add support for exporting a server id in protobuf

  .. change::
    :tags: Improvements
    :pullreq: 7030

    dnsdist did not set TCP_NODELAY, causing needless latency

  .. change::
    :tags: Bug Fixes
    :pullreq: 7060

    Release memory on DNS over TLS handshake failure

  .. change::
    :tags: Improvements
    :pullreq: 7062

    Add a setting to control the number of stored sessions

  .. change::
    :tags: Improvements
    :pullreq: 7064
    :tickets: 7060

    Wrap GnuTLS and OpenSSL pointers in smart pointers

  .. change::
    :tags: New Features
    :pullreq: 7075
    :tickets: 6908

    Support the NXDomain action with dynamic blocks

  .. change::
    :tags: Improvements
    :pullreq: 7078
    :tickets: 6909

    Add a 'creationOrder' field to rules

  .. change::
    :tags: Improvements
    :pullreq: 7092
    :tickets: 7091

    Fix return-type detection with boost 1.69's tribool

  .. change::
    :tags: Improvements
    :pullreq: 7104
    :tickets: 7096

    Fix format string issue on 32bits ARM

  .. change::
    :tags: Improvements
    :pullreq: 7108

    Wrap TCP connection objects in smart pointers

  .. change::
    :tags: Improvements
    :pullreq: 7109
    :tickets: 7084

    Add the setConsoleOutputMaxMsgSize function

  .. change::
    :tags: New Features
    :pullreq: 7115

    Add security polling

  .. change::
    :tags: Improvements
    :pullreq: 7117
    :tickets: 7112

    Add the ability to update webserver credentials

  .. change::
    :tags: New Features
    :pullreq: 7140

    Add a PoolAvailableRule to easily add backup pools (Robin Geuze)

  .. change::
    :tags: Bug Fixes
    :pullreq: 7165
    :tickets: 6896

    Handle trailing data correctly when adding OPT or ECS info

.. changelog::
  :version: 1.3.2
  :released: 10th of July 2018

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.3.x.

  .. change::
    :tags: Bug Fixes
    :pullreq: 6785

    Add missing include for PRId64, fix build on CentOS 6 / SLES 12

.. changelog::
  :version: 1.3.1
  :released: 10th of July 2018

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.3.x.

  .. change::
    :tags: Improvements
    :pullreq: 6358
    :tickets: 6357

    Remove `thelog` and `thel` and replace this with a global g_log

  .. change::
    :tags: Improvements
    :pullreq: 6422

    Fix two small nits on the documentation

  .. change::
    :tags: Improvements
    :pullreq: 6426
    :tickets: 6394

    Move the el6 dnsdist package to upstart

  .. change::
    :tags: Bug Fixes
    :pullreq: 6425

    Initialize the done variable in the rings' unit tests

  .. change::
    :tags: Bug Fixes
    :pullreq: 6429

    Reorder headers to fix OpenBSD build

  .. change::
    :tags: Improvements
    :pullreq: 6435
    :tickets: 6433

    CLI option improvements (Chris Hofstaedtler)

  .. change::
    :tags: Improvements
    :pullreq: 6436

    Split pdns_enable_unit_tests (Chris Hofstaedtler)

  .. change::
    :tags: Bug Fixes
    :pullreq: 6448

    Restrict value range for weight parameter, avoid sum overflows dropping queries (Dan McCombs)

  .. change::
    :tags: Improvements
    :pullreq: 6445, 6457, 6470
    :tickets: 6423

    Re-do lua detection

  .. change::
    :tags: Improvements
    :pullreq: 6460

    Docs: fix missing ref in the dnsdist docs

  .. change::
    :tags: Improvements
    :pullreq: 6502

    Be more permissive in wrandom tests, log values on failure

  .. change::
    :tags: Improvements
    :pullreq: 6523
    :tickets: 6430

    Tests: avoid failure on not-so-optimal distribution

  .. change::
    :tags: New Features
    :pullreq: 6524
    :tickets: 6450

    Add support for more than one TLS certificate

  .. change::
    :tags: Improvements
    :pullreq: 6577

    Add syntax to dns.proto to silence compilation warning.

  .. change::
    :tags: Improvements
    :pullreq: 6590

    Fix warnings reported by gcc 8.1.0

  .. change::
    :tags: Improvements
    :pullreq: 6592
    :tickets: 6483

    Document setVerboseHealthchecks()

  .. change::
    :tags: Improvements
    :pullreq: 6615

    Update dq.rst (phonedph1)

  .. change::
    :tags: Improvements
    :pullreq: 6641

    Fix rpm scriptlets

  .. change::
    :tags: Improvements
    :pullreq: 6637

    Don't copy uninitialized values of SuffixMatchTree

  .. change::
    :tags: Improvements
    :pullreq: 6684

    Expose toString of various objects to Lua (Chris Hofstaedtler)

  .. change::
    :tags: Improvements
    :pullreq: 6674

    Remove 'expired' states from MaxQPSIPRule

  .. change::
    :tags: Bug Fixes
    :pullreq: 6672

    Fix reconnection handling

  .. change::
    :tags: Improvements
    :pullreq: 6688
    :tickets: 6664

    Mark the remote member of DownstreamState as const

  .. change::
    :tags: Bug Fixes
    :pullreq: 6706

    Dynamic blocks were being created with the wrong duration (David Freedman)

  .. change::
    :tags: Improvements
    :pullreq: 6710
    :tickets: 6706

    Test the content of dynamic blocks using the API

  .. change::
    :tags: Improvements
    :pullreq: 6711
    :tickets: 6532

    Default set "connection: close" header for web requests

  .. change::
    :tags: Improvements
    :pullreq: 6717

    Update timedipsetrule.rst (phonedph1)

  .. change::
    :tags: Improvements
    :pullreq: 6716
    :tickets: 6712

    Don't access the TCP buffer vector past its size

  .. change::
    :tags: Improvements
    :pullreq: 6563

    Show droprate in API output

  .. change::
    :tags: Bug Fixes
    :pullreq: 6718
    :tickets: 6442

    Limit qps and latency to two decimals in the web view

  .. change::
    :tags: Improvements
    :pullreq: 6715
    :tickets: 6683, 6709

    Refuse console connection without a proper key set

  .. change::
    :tags: New Features
    :pullreq: 6740
    :tickets: 6579

    Add a negative ttl option to the packet cache

  .. change::
    :tags: Bug Fixes
    :pullreq: 6747

    Check the flags to detect collisions in the packet cache

  .. change::
    :tags: New Features
    :pullreq: 6749

    Add the ability to dump a summary of the cache content

  .. change::
    :tags: Bug Fixes
    :pullreq: 6762

    Fix iterating over the results of exceed*() functions

  .. change::
    :tags: Bug Fixes
    :pullreq: 6767

    Fix duration false positive in the dynblock regression tests

  .. change::
    :tags: New Features
    :pullreq: 6760

    Add netmask-based {ex,in}clusions to DynblockRulesGroup

  .. change::
    :tags: New Features
    :pullreq: 6776
    :tickets: 6703

    Add DNSAction.NoOp to debug dynamic blocks

  .. change::
    :tags: Bug Fixes
    :pullreq: 6775
    :tickets: 6758

    Implement NoneAction()

  .. change::
    :tags: Bug Fixes
    :pullreq: 6754
    :tickets: 6747

    Detect ECS collisions in the packet cache

  .. change::
    :tags: Bug Fixes
    :pullreq: 6773

    Fix an outstanding counter race when reusing states

  .. change::
    :tags: New Features
    :pullreq: 6734
    :tickets: 6404

    Add SetECSAction to set an arbitrary outgoing ecs value

  .. change::
    :tags: Improvements
    :pullreq: 6726

    Use LRU to clean the MaxQPSIPRule's store

  .. change::
    :tags: Improvements
    :pullreq: 6769

    Disable maybe uninitialized warnings with boost optional

  .. change::
    :tags: New Features
    :pullreq: 6764

    Add support for rotating certificates and keys

  .. change::
    :tags: Improvements
    :pullreq: 6658
    :tickets: 6541

    Luawrapper: report caught std::exception as lua_error

  .. change::
    :tags: Improvements
    :pullreq: 6602

    Dnstap.rst: fix some editing errors (Chris Hofstaedtler)

  .. change::
    :tags: Improvements
    :pullreq: 6541
    :tickets: 6535

    Allow known exception types to be converted to string


.. changelog::
  :version: 1.3.0
  :released: 30th of March 2018

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.3.x.

  .. change::
    :tags: Improvements, New Features
    :pullreq: 5576, 5860
    :tickets: 5202, 5859

    Add cache sharding, ``recvmmsg`` and CPU pinning support.
    With these, the scalability of :program:`dnsdist` is drastically improved.

  .. change::
    :tags: Improvements
    :pullreq: 5970

    Add burst option to :func:`MaxQPSIPRule` (42wim).

  .. change::
    :tags: Bug Fixes
    :pullreq: 5328
    :tickets: 5327

    Handle SNMP alarms so we can reconnect to the daemon.

  .. change::
    :tags: New Features
    :pullreq: 5625

    Add an optional `status` parameter to :func:`Server:setAuto`.

  .. change::
    :tags: Bug Fixes
    :pullreq: 5597
    :tickets: 5489

    Fix signed/unsigned comparison warnings on ARM.

  .. change::
    :tags: Improvements
    :pullreq: 6022

    Add Pools, cacheHitResponseRules to the API.

  .. change::
    :tags: New Features
    :pullreq: 6072

    Add :func:`inClientStartup` function.

  .. change::
    :tags: Improvements
    :pullreq: 5929
    :tickets: 5748

    Add a class option to health checks.

  .. change::
    :tags: New Features
    :pullreq: 6037

    Add tag-based routing of queries.

  .. change::
    :tags: New Features
    :pullreq: 6117, 6175, 6176, 6177, 6189

    Add experimental :doc:`DNS-over-TLS <guides/dns-over-tls>` support.

  .. change::
    :tags: Improvements
    :pullreq: 6030

    Add UUIDs to rules, this allows tracking rules through modifications and moving them around.

  .. change::
    :tags: Bug Fixes
    :pullreq: 5770

    Keep trying if the first connection to the remote logger failed

  .. change::
    :tags: New Features
    :pullreq: 5201, 6170

    Add simple :doc:`dnstap <reference/dnstap>` support (Justin Valentini, Chris Hofstaedtler).

  .. change::
    :tags: Improvements
    :pullreq: 6185
    :tickets: 6182

    Apply ResponseRules to locally generated answers (Chris Hofstaedtler).

  .. change::
    :tags: Improvements
    :pullreq: 6283

    Report :func:`LuaAction` and :func:`LuaResponseAction` failures in the log and send SERVFAIL instead of not answering the query (Chris Hofstaedtler).

  .. change::
    :tags: Improvements
    :pullreq: 6289

    Unify global statistics accounting (Chris Hofstaedtler).

  .. change::
    :tags: Improvements
    :pullreq: 6350, 6366

    Speed up the processing of large ring buffers.
    This change will make :program:`dnsdist` more scalable with a large number of different clients.

  .. change::
    :tags: Improvements
    :pullreq: 6363
    :tickets: 6346

    Make custom :func:`addLuaAction` and :func:`addLuaResponseAction` callback's second return value optional.

  .. change::
    :tags: Improvements
    :pullreq: 6327

    Add "server-up" metric count to Carbon Reporting (Lowell Mower).

  .. change::
    :tags: Improvements
    :pullreq: 6045, 6382

    Add xchacha20 support for :doc:`DNSCrypt <guides/dnscrypt>`.

  .. change::
    :tags: Improvements
    :pullreq: 6317

    Scalability improvement: Add an option to use several source ports towards a backend.

  .. change::
    :tags: Improvements
    :pullreq: 6375, 5866
    :tickets: 4845

   Add '?' and 'help' for providing help() output on ``dnsdist -c`` (Kirill Ponomarev, Chris Hofstaedtler).

  .. change::
    :tags: Improvements
    :pullreq: 6190, 6381

    Replace the Lua mutex with a rw lock to limit contention.
    This improves the processing speed and parallelism of the policies.

  .. change::
    :tags: New Features
    :pullreq: 6220, 5594
    :tickets: 5079, 5654

    Add experimental XPF support based on `draft-bellis-dnsop-xpf-04 <https://tools.ietf.org/html/draft-bellis-dnsop-xpf-04>`__.

  .. change::
    :tags: New Features
    :pullreq: 6147

    Add :func:`ERCodeRule` to match on extended RCodes (Chris Hofstaedtler).

  .. change::
    :tags: Bug Fixes
    :pullreq: 6018

    Fix escaping unusual DNS label octets in DNSName is off by one (Kees Monshouwer).

  .. change::
    :tags: New Features
    :pullreq: 6003

    Add :func:`TempFailureCacheTTLAction` (Chris Hofstaedtler).

  .. change::
    :tags: Improvements
    :pullreq: 6146

    Ensure :program:`dnsdist` compiles on NetBSD (Tom Ivar Helbekkmo).

  .. change::
    :tags: Improvements
    :pullreq: 5845
    :tickets: 5845

    Also log eBPF dynamic blocks, as regular dynamic block already are.

  .. change::
    :tags: New Features, Improvements
    :pullreq: 6391

    Add :ref:`DynBlockRulesGroup` to improve processing speed of the :func:`maintenance` function by reducing memory usage and not walking the ringbuffers multiple times.

  .. change::
    :tags: Removals
    :pullreq: 6394
    :tickets: 6329

    Remove the ``--daemon`` option from :program:`dnsdist`.

  .. change::
    :tags: New Features
    :pullreq: 6399
    :tickets: 4654

    Add :func:`console ACL <addConsoleACL>` functions.

  .. change::
    :tags: New Features
    :pullreq: 6400
    :tickets: 6098

    Allow adding :meth:`EDNS Client Subnet information <ServerPool:setECS>` to a query before looking in the cache.
    This allows serving ECS enabled answers from the cache when all servers in a pool are down.

  .. change::
    :tags: Improvements
    :pullreq: 6401
    :tickets: 6211

    Ensure large numbers are shown correctly in the API.

  .. change::
    :tags: Improvements
    :pullreq: 6402
    :tickets: 5763

    Add option to :func:`showRules` to truncate the output length.

  .. change::
    :tags: Bug Fixes
    :pullreq: 6403

    Avoid assertion errors in :func:`NewServer` (Chris Hofstaedtler).

  .. change::
    :tags: Improvements
    :pullreq: 6407

    Fix several warnings reported by clang's analyzer and cppcheck, should lead to small performance increases.


.. changelog::
  :version: 1.2.1
  :released: 16th of February 2018

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.2.x.

  .. change::
    :tags: New Features
    :pullreq: 5880

    Add configuration option to disable IP_BIND_ADDRESS_NO_PORT (Dan McCombs).

  .. change::
    :tags: Improvements
    :pullreq: 6057

    Handle bracketed IPv6 addresses without ports (Chris Hofstaedtler).

  .. change::
    :tags: Bug Fixes
    :pullreq: 5647

    Make dnsdist dynamic truncate do right thing on TCP/IP.

  .. change::
    :tags: Bug Fixes
    :pullreq: 5686

    Add missing QPSAction

  .. change::
    :tags: Bug Fixes
    :pullreq: 5847

    Don't create a Remote Logger in client mode.

  .. change::
    :tags: Bug Fixes
    :pullreq: 5858

    Use libsodium's CFLAGS, we might need them to find the includes.

  .. change::
    :tags: Bug Fixes
    :pullreq: 6012

    Keep the TCP connection open on cache hit, generated answers.

  .. change::
    :tags: Bug Fixes
    :pullreq: 6041

    Add the missing <sys/time.h> include to mplexer.hh for struct timeval.

  .. change::
    :tags: Bug Fixes
    :pullreq: 6043

    Sort the servers based on their 'order' after it has been set.

  .. change::
    :tags: Bug Fixes
    :pullreq: 6073

    Quiet unused variable warning on macOS (Chris Hofstaedtler).

  .. change::
    :tags: Bug Fixes
    :pullreq: 6094
    :tickets: 5652

    Fix the outstanding counter when an exception is raised.

  .. change::
    :tags: Bug Fixes
    :pullreq: 6164
    :tickets: 6163

    Do not connect the snmpAgent from a dnsdist client.

.. changelog::
  :version: 1.2.0
  :released: 21st of August 2017

  Please review the :doc:`Upgrade Guide <../upgrade_guide>` before upgrading from versions < 1.2.x.

  .. change::
    :tags: Improvements
    :pullreq: 4852
    :tickets: 4851

    DNSName: Check that both first two bits are set in compressed labels.

  .. change::
    :tags: Improvements
    :pullreq: 4285
    :tickets: 4131, 4155

    Handle unreachable servers at startup, reconnect stale sockets

  .. change::
    :tags: Improvements
    :pullreq: 4474
    :tickets: 4471

    Gracefully handle invalid addresses in :func:`newServer`.

  .. change::
    :tags: New Features
    :pullreq: 4536
    :tickets: 4527

    Add an option to 'mute' UDP responses per bind.

  .. change::
    :tags: New Features, Performance
    :pullreq: 4611

    Add TCP management options from :rfc:`RFC 7766 section 10 <7766#section-10>`.

  .. change::
    :tags: Bug Fixes
    :pullreq: 4775

    LuaWrapper: Use the correct index when storing a function.

  .. change::
    :tags: New Features
    :pullreq: 4779
    :tickets: 4562

    Save history to home-dir, only use CWD as a last resort.

  .. change::
    :tags: New Features
    :pullreq: 4898

    Add the :func:`setRingBuffersSize` directive to allows changing the ringbuffer size.

  .. change::
    :tags: Improvements, Security
    :pullreq: 4815

    Merge the client and server nonces to prevent replay attacks.

  .. change::
    :tags: Improvements
    :pullreq: 4786

    Use ``IP_BIND_ADDRESS_NO_PORT`` when available.

  .. change::
    :tags: Bug Fixes
    :pullreq: 4785
    :tickets: 4689

    Send a latency of 0 over carbon, null over API for down servers.

  .. change::
    :tags: Improvements
    :pullreq: 4780
    :tickets: 4775, 4660

    Add an optional ``seconds`` parameter to :func:`statNodeRespRing`.

  .. change::
    :tags: Improvements
    :pullreq: 4910

    Report a more specific lua version and report luajit in ``--version``.

  .. change::
    :tags: Improvements, DNSCrypt
    :pullreq: 4813, 4926

    Store the computed shared key and reuse it for the response for DNSCrypt messages.

  .. change::
    :tags: New Features, Protobuf
    :pullreq: 4776
    :tickets: 4709

    Add an option to export CNAME records over protobuf.

  .. change::
    :tags: New Features
    :pullreq: 4787
    :tickets: 4707

    Allow TTL alteration via Lua.

  .. change::
    :tags: New Features
    :pullreq: 4837

    Add :func:`RDRule` to match queries with the ``RD`` flag set.

  .. change::
    :tags: New Features
    :pullreq: 4897

    Add :func:`setWHashedPertubation` for consistent ``whashed`` results.

  .. change::
    :tags: New Features
    :pullreq: 4818

    Add ``tcpConnectTimeout`` to :func:`newServer`.

  .. change::
    :tags: Bug Fixes
    :pullreq: 4911

    Fix negative port detection for IPv6 addresses on 32-bit.

  .. change::
    :tags: Bug Fixes
    :pullreq: 4877
    :tickets: 4579

    Fix crashed on SmartOS/Illumos (Roman Dayneko).

  .. change::
    :tags: New Features
    :pullreq: 4788, 5036
    :tickets: 4708

    Add cache hit response rules.

  .. change::
    :tags: Improvements, Performance
    :pullreq: 4817

    Add :func:`setTCPUseSinglePipe` to use a single TCP waiting queue.

  .. change::
    :tags: Bug Fixes
    :pullreq: 4859
    :tickets: 4857

    Change ``truncateTC`` to defaulting to off, having it enabled by default causes an incompatibility with :rfc:`6891` (Robin Geuze).

  .. change::
    :tags: Bug Fixes
    :pullreq: 4987, 5037
    :tickets: 4983

    Don't cache answers without any TTL (like SERVFAIL).

  .. change::
    :tags: Improvements, Performance
    :pullreq: 4985, 5501
    :tickets: 5494

    Add ``sendSizeAndMsgWithTimeout`` to send size and data in a single call and use it for TCP Fast Open towards backends.

  .. change::
    :tags: Improvements
    :pullreq: 5056

    Prevent issues by unshadowing variables.

  .. change::
    :tags: New Features, SNMP
    :pullreq: 4989, 5123, 5204

    Add :doc:`SNMP support <advanced/snmp>`.

  .. change::
    :tags: Bug Fixes, Performance
    :pullreq: 4950
    :tickets: 4761

    Refactor SuffixMatchNode using a SuffixMatchTree.

  .. change::
    :tags: Improvements
    :pullreq: 4920

    Register DNSName::chopOff (@plzz).

  .. change::
    :tags: New Features
    :pullreq: 5070

    Allow passing :class:`DNSName`\ s as DNSRules.

  .. change::
    :tags: Bug Fixes, Webserver
    :pullreq: 5089

    Send an HTTP 404 on unknown API paths.

  .. change::
    :tags: Improvements, Performance
    :pullreq: 4958

    Tune systemd unit-file for medium-sized installations (Winfried Angele).

  .. change::
    :tags: New Features
    :pullreq: 5113

    Add support for setting the server selection policy on a per pool basis (Robin Geuze).

  .. change::
    :tags: Improvements
    :pullreq: 5150, 5171
    :tickets: 5053

    Make :func:`includeDirectory` work sorted (Robin Geuze).

  .. change::
    :tags: Improvements, LuaWrapper
    :pullreq: 5147

    Allow embedded NULs in strings received from Lua.

  .. change::
    :tags: New Features
    :pullreq: 5159

    Add a ``suffixMatch`` parameter to :meth:`PacketCache:expungeByName` (Robin Geuze).

  .. change::
    :tags: Improvements
    :pullreq: 5163

    Cleanup closed TCP downstream connections.

  .. change::
    :tags: Bug Fixes
    :pullreq: 5194

    Fix destination port reporting on "any" binds.

  .. change::
    :tags: New Features
    :pullreq: 5136
    :tickets: 5126

    Add an option so the packet cache entries don't age.

  .. change::
    :tags: Bug Fixes, Security
    :pullreq: 5199

    Unified ``-k`` and :func:`setKey` behaviour for client and server mode now.

  .. change::
    :tags: Improvements
    :pullreq: 5230

    Improve reporting of C++ exceptions that bubble up via Lua.

  .. change::
    :tags: Improvements, Performance
    :pullreq: 5185

    Add the possibility to fill a :class:`NetmaskGroup` (using :meth:`NetmaskGroup:addMask`) from `exceeds*` results.

  .. change::
    :tags: Improvements
    :pullreq: 5253

    Add better logging on queries that get dropped, timed out or received.

  .. change::
    :tags: New Features
    :pullreq: 5235

    Add :func:`QNameRule`.

  .. change::
    :tags: Bug Fixes
    :pullreq: 5320

    Correctly truncate EDNS Client Subnetmasks.

  .. change::
    :tags: Improvements
    :pullreq: 5342

    Print useful messages when query and response actions are mixed.

  .. change::
    :tags: New Features
    :pullreq: 5337

    Add an optional action to :func:`addDynBlocks`.

  .. change::
    :tags: New Features
    :pullreq: 5344

    Add an optional interface parameter to :func:`addLocal`/:func:`setLocal`.

  .. change::
    :tags: Bug Fixes, Performance
    :pullreq: 5359

    Get rid of ``std::move()`` calls preventing copy elision.

  .. change::
    :tags: Bug Fixes
    :pullreq: 5369
    :tickets: 5365

    Fix :func:`RecordsTypeCountRule`\ 's handling of the # of records in a section.

  .. change::
    :tags: New Features
    :pullreq: 5386

    Make a ``truncate`` action available to DynBlock and Lua.

  .. change::
    :tags: Bug Fixes
    :pullreq: 5383
    :tickets: 5287

    Change stats functions to always return lowercase names (Robin Geuze).

  .. change::
    :tags: New Features
    :pullreq: 5336

    Implement a runtime changeable rule that matches IP address for a certain time called :func:`TimedIPSetRule`.

  .. change::
    :tags: Bug Fixes
    :pullreq: 5449, 5454

    Only use TCP Fast Open when supported and prevent compiler warnings.

  .. change::
    :tags: Improvements
    :pullreq: 5497

    Add ``DNSRule::toString()`` and add virtual destructors to DNSRule, DNSAction and DNSResponseAction so the destructors of derived classes are run even when deleted via the base type.

  .. change::
    :tags: New Features
    :pullreq: 5496

    Add support for returning several IPs to spoof from Lua.

  .. change::
    :tags: New Features
    :pullreq: 5490, 5508
    :tickets: 5420, 5507

    Add Lua bindings to be able to rotate DNSCrypt keys, see :doc:`guides/dnscrypt`.

  .. change::
    :tags: Improvements, Performance
    :pullreq: 5353

    Add labels count to StatNode, only set the name once.

  .. change::
    :tags: Removals
    :pullreq: 5514
    :tickets: 5513

    Remove BlockFilter.

  .. change::
    :tags: New Features
    :pullreq: 5396, 5577

    Add the capability to set arbitrary tags in protobuf messages.

  .. change::
    :tags: Bug Fixes
    :pullreq: 5563
    :tickets: 5559

    Skip timeouts on the response latency graph.

  .. change::
    :tags: Removals
    :pullreq: 5526
    :tickets: 5069

    Deprecate syntactic sugar functions.

  .. change::
    :tags: Improvements
    :pullreq: 5579
    :tickets: 5538

    Don't use square brackets for IPv6 in Carbon metrics.

  .. change::
    :tags: Bug Fixes
    :pullreq: 5580
    :tickets: 5566

    Copy the DNS header before encrypting it in place.

  .. change::
    :tags: New Features
    :pullreq: 5581
    :tickets: 5565

    Add setConsoleConnectionsLogging().

  .. change::
    :tags: Security
    :pullreq: 5630

    Fix potential pointer wrap-around on 32 bits.

  .. change::
    :tags: Security
    :pullreq: 5631

    Make the API available with an API key only.

1.1.0
-----

Released December 29th 2016

Changes since 1.1.0-beta2:

Improvements
~~~~~~~~~~~~

-  `#4783 <https://github.com/PowerDNS/pdns/pull/4783>`__: Add -latomic
   on powerpc
-  `#4812 <https://github.com/PowerDNS/pdns/pull/4812>`__: Handle
   header-only responses, handle Refused as Servfail in the cache

Bug fixes
~~~~~~~~~

-  `#4762 <https://github.com/PowerDNS/pdns/pull/4762>`__:
   SuffixMatchNode: Fix an insertion issue for an existing node
-  `#4772 <https://github.com/PowerDNS/pdns/pull/4772>`__: Fix dnsdist
   initscript config check

1.1.0-beta2
-----------

Released December 14th 2016

Changes since 1.1.0-beta1:

New features
~~~~~~~~~~~~

-  `#4518 <https://github.com/PowerDNS/pdns/pull/4518>`__: Fix dynblocks
   over TCP, allow refusing dyn blocked queries
-  `#4519 <https://github.com/PowerDNS/pdns/pull/4519>`__: Allow
   altering the ECS behavior via rules and Lua
-  `#4535 <https://github.com/PowerDNS/pdns/pull/4535>`__: Add
   ``DNSQuestion:getDO()``
-  `#4653 <https://github.com/PowerDNS/pdns/pull/4653>`__:
   ``getStatisticsCounters()`` to access counters from Lua
-  `#4657 <https://github.com/PowerDNS/pdns/pull/4657>`__: Add
   ``includeDirectory(dir)``
-  `#4658 <https://github.com/PowerDNS/pdns/pull/4658>`__: Allow editing
   the ACL via the API
-  `#4702 <https://github.com/PowerDNS/pdns/pull/4702>`__: Add
   ``setUDPTimeout(n)``
-  `#4726 <https://github.com/PowerDNS/pdns/pull/4726>`__: Add an option
   to return ServFail when no server is available
-  `#4748 <https://github.com/PowerDNS/pdns/pull/4748>`__: Add
   ``setCacheCleaningPercentage()``

Improvements
~~~~~~~~~~~~

-  `#4533 <https://github.com/PowerDNS/pdns/pull/4533>`__: Fix building
   with clang on OS X and FreeBSD
-  `#4537 <https://github.com/PowerDNS/pdns/pull/4537>`__: Replace
   luawrapper's std::forward/std::make\_tuple combo with
   std::forward\_as\_tuple (Sangwhan "fish" Moon)
-  `#4596 <https://github.com/PowerDNS/pdns/pull/4596>`__: Change the
   default max number of queued TCP conns to 1000
-  `#4632 <https://github.com/PowerDNS/pdns/pull/4632>`__: Improve
   dnsdist error message on a common typo/config mistake
-  `#4694 <https://github.com/PowerDNS/pdns/pull/4694>`__: Don't use a
   const\_iterator for erasing (fix compilation with some versions of
   gcc)
-  `#4715 <https://github.com/PowerDNS/pdns/pull/4715>`__: Specify that
   dnsmessage.proto uses protobuf version 2
-  `#4765 <https://github.com/PowerDNS/pdns/pull/4765>`__: Some service
   improvements

Bug fixes
~~~~~~~~~

-  `#4425 <https://github.com/PowerDNS/pdns/pull/4425>`__: Fix a
   protobuf regression (requestor/responder mix-up) caused by a94673e
-  `#4541 <https://github.com/PowerDNS/pdns/pull/4541>`__: Fix insertion
   issues in SuffixMatchTree, move it to dnsname.hh
-  `#4553 <https://github.com/PowerDNS/pdns/pull/4553>`__: Flush output
   in single command client mode
-  `#4578 <https://github.com/PowerDNS/pdns/pull/4578>`__: Fix
   destination address reporting
-  `#4640 <https://github.com/PowerDNS/pdns/pull/4640>`__: Don't exit
   dnsdist on an exception in maintenance
-  `#4721 <https://github.com/PowerDNS/pdns/pull/4721>`__: Handle
   exceptions in the UDP responder thread
-  `#4734 <https://github.com/PowerDNS/pdns/pull/4734>`__: Add the TCP
   socket to the map only if the connection succeeds. Closes #4733
-  `#4742 <https://github.com/PowerDNS/pdns/pull/4742>`__: Decrement the
   queued TCP conn count if writing to the pipe fails
-  `#4743 <https://github.com/PowerDNS/pdns/pull/4743>`__: Ignore
   newBPFFilter() and newDynBPFFilter() in client mode
-  `#4753 <https://github.com/PowerDNS/pdns/pull/4753>`__: Fix FD leak
   on TCP connection failure, handle TCP worker creation failure
-  `#4764 <https://github.com/PowerDNS/pdns/pull/4764>`__: Prevent race
   while creating new TCP worker threads

1.1.0-beta1
-----------

Released September 1st 2016

Changes since 1.0.0:

New features
~~~~~~~~~~~~

-  `#3762 <https://github.com/PowerDNS/pdns/pull/3762>`__ Teeaction:
   send copy of query to second nameserver, sponge responses
-  `#3876 <https://github.com/PowerDNS/pdns/pull/3876>`__ Add
   ``showResponseRules()``, ``{mv,rm,top}ResponseRule()``
-  `#3936 <https://github.com/PowerDNS/pdns/pull/3936>`__ Filter on
   opcode, records count/type, trailing data
-  `#3975 <https://github.com/PowerDNS/pdns/pull/3975>`__ Make dnsdist
   {A,I}XFR aware, document possible issues
-  `#4006 <https://github.com/PowerDNS/pdns/pull/4006>`__ Add eBPF
   source address and qname/qtype filtering
-  `#4008 <https://github.com/PowerDNS/pdns/pull/4008>`__ Node
   infrastructure for querying recent traffic
-  `#4042 <https://github.com/PowerDNS/pdns/pull/4042>`__ Add
   server-side TCP Fast Open support
-  `#4050 <https://github.com/PowerDNS/pdns/pull/4050>`__ Add
   ``clearRules()`` and ``setRules()``
-  `#4114 <https://github.com/PowerDNS/pdns/pull/4114>`__ Add
   ``QNameLabelsCountRule()`` and ``QNameWireLengthRule()``
-  `#4116 <https://github.com/PowerDNS/pdns/pull/4116>`__ Added src
   boolean to NetmaskGroupRule to match destination address (Reinier
   Schoof)
-  `#4175 <https://github.com/PowerDNS/pdns/pull/4175>`__ Implemented
   query counting (Reinier Schoof)
-  `#4244 <https://github.com/PowerDNS/pdns/pull/4244>`__ Add a
   ``setCD`` parameter to set cd=1 on health check queries
-  `#4284 <https://github.com/PowerDNS/pdns/pull/4284>`__ Add
   RCodeRule(), Allow, Delay and Drop response actions
-  `#4305 <https://github.com/PowerDNS/pdns/pull/4305>`__ Add an
   optional Lua callback for altering a Protobuf message
-  `#4309 <https://github.com/PowerDNS/pdns/pull/4309>`__ Add
   showTCPStats function (RobinGeuze)
-  `#4329 <https://github.com/PowerDNS/pdns/pull/4329>`__ Add options to
   LogAction() so it can append (instead of truncate) (Duane Wessels)

Improvements
~~~~~~~~~~~~

-  `#3714 <https://github.com/PowerDNS/pdns/pull/3714>`__ Add
   documentation links to dnsdist.service (Ruben Kerkhof)
-  `#3754 <https://github.com/PowerDNS/pdns/pull/3754>`__ Allow the use
   of custom headers in the web server
-  `#3826 <https://github.com/PowerDNS/pdns/pull/3826>`__ Implement a
   'quiet' mode for SuffixMatchNodeRule()
-  `#3836 <https://github.com/PowerDNS/pdns/pull/3836>`__ Log the
   content of webserver's exceptions
-  `#3858 <https://github.com/PowerDNS/pdns/pull/3858>`__ Only log
   YaHTTP's parser exceptions in verbose mode
-  `#3877 <https://github.com/PowerDNS/pdns/pull/3877>`__ Increase max
   FDs in systemd unit, warn if clearly too low
-  `#4019 <https://github.com/PowerDNS/pdns/pull/4019>`__ Add an
   optional ``addECS`` option to ``TeeAction()``
-  `#4029 <https://github.com/PowerDNS/pdns/pull/4029>`__ Add version
   and feature information to version output
-  `#4079 <https://github.com/PowerDNS/pdns/pull/4079>`__ Return an
   error on RemoteLog{,Response}Action() w/o protobuf
-  `#4246 <https://github.com/PowerDNS/pdns/pull/4246>`__ API now sends
   pools as a JSON array instead of a string
-  `#4302 <https://github.com/PowerDNS/pdns/pull/4302>`__ Add ``help()``
   and ``showVersion()``
-  `#4286 <https://github.com/PowerDNS/pdns/pull/4286>`__ Add response
   rules to the API and Web status page
-  `#4068 <https://github.com/PowerDNS/pdns/pull/4068>`__ Display the
   dyn eBPF filters stats in the web interface

Bug fixes
~~~~~~~~~

-  `#3755 <https://github.com/PowerDNS/pdns/pull/3755>`__ Fix RegexRule
   example in dnsdistconf.lua
-  `#3773 <https://github.com/PowerDNS/pdns/pull/3773>`__ Stop copying
   the HTTP request headers to the response
-  `#3837 <https://github.com/PowerDNS/pdns/pull/3837>`__ Remove dnsdist
   service file on trusty
-  `#3840 <https://github.com/PowerDNS/pdns/pull/3840>`__ Catch
   WrongTypeException in client mode
-  `#3906 <https://github.com/PowerDNS/pdns/pull/3906>`__ Keep the
   servers ordered inside pools
-  `#3988 <https://github.com/PowerDNS/pdns/pull/3988>`__ Fix
   ``grepq()`` output in the README
-  `#3992 <https://github.com/PowerDNS/pdns/pull/3992>`__ Fix some typos
   in the AXFR/IXFR documentation
-  `#3995 <https://github.com/PowerDNS/pdns/pull/3995>`__ Fix comparison
   between signed and unsigned integer
-  `#4049 <https://github.com/PowerDNS/pdns/pull/4049>`__ Fix dnsdist
   rpm building script #4048 (Daniel Stirnimann)
-  `#4065 <https://github.com/PowerDNS/pdns/pull/4065>`__ Include
   editline/readline.h instead of readline.h/history.h
-  `#4067 <https://github.com/PowerDNS/pdns/pull/4067>`__ Disable eBPF
   support when BPF\_FUNC\_tail\_call is not found
-  `#4069 <https://github.com/PowerDNS/pdns/pull/4069>`__ Fix a buffer
   overflow when displaying an OpcodeRule
-  `#4101 <https://github.com/PowerDNS/pdns/pull/4101>`__ Fix $
   expansion in build-dnsdist-rpm
-  `#4198 <https://github.com/PowerDNS/pdns/pull/4198>`__ newServer
   setting maxCheckFailures makes no sense (stutiredboy)
-  `#4205 <https://github.com/PowerDNS/pdns/pull/4205>`__ Prevent the
   use of "any" addresses for downstream server
-  `#4220 <https://github.com/PowerDNS/pdns/pull/4220>`__ Don't log an
   error when parsing an invalid UDP query
-  `#4348 <https://github.com/PowerDNS/pdns/pull/4348>`__ Fix invalid
   outstanding count for {A,I}XFR over TCP
-  `#4365 <https://github.com/PowerDNS/pdns/pull/4365>`__ Reset origFD
   asap to keep the outstanding count correct
-  `#4375 <https://github.com/PowerDNS/pdns/pull/4375>`__ Tuple requires
   make\_tuple to initialize
-  `#4380 <https://github.com/PowerDNS/pdns/pull/4380>`__ Fix
   compilation with clang when eBPF support is enabled

1.0.0
-----

Released April 21st 2016

Changes since 1.0.0-beta1:

Improvements
~~~~~~~~~~~~

-  `#3700 <https://github.com/PowerDNS/pdns/pull/3700>`__ Create user
   from the RPM package to drop privs
-  `#3712 <https://github.com/PowerDNS/pdns/pull/3712>`__ Make check
   should run testrunner
-  `#3713 <https://github.com/PowerDNS/pdns/pull/3713>`__ Remove
   contrib/dnsdist.service (Ruben Kerkhof)
-  `#3722 <https://github.com/PowerDNS/pdns/pull/3722>`__ Use LT\_INIT
   and disable static objects (Ruben Kerkhof)
-  `#3724 <https://github.com/PowerDNS/pdns/pull/3724>`__ Include
   PDNS\_CHECK\_OS in configure (Chris Hofstaedtler)
-  `#3728 <https://github.com/PowerDNS/pdns/pull/3728>`__ Document
   libedit Ctrl-R workaround for CentOS 6
-  `#3730 <https://github.com/PowerDNS/pdns/pull/3730>`__ Make
   ``topBandwidth()`` behave like other top\* functions
-  `#3731 <https://github.com/PowerDNS/pdns/pull/3731>`__ Clarify a bit
   the documentation of load-balancing policies

Bug fixes
~~~~~~~~~

-  `#3711 <https://github.com/PowerDNS/pdns/pull/3711>`__ Building rpm
   needs systemd headers (Ruben Kerkhof)
-  `#3736 <https://github.com/PowerDNS/pdns/pull/3736>`__ Add missing
   Lua binding for NetmaskGroupRule()
-  `#3739 <https://github.com/PowerDNS/pdns/pull/3739>`__ Drop
   privileges after daemonizing and writing our pid

1.0.0-beta1
-----------

Released April 14th 2016

Changes since 1.0.0-alpha2:

New features
~~~~~~~~~~~~

-  Per-pool packet cache
-  Some actions do not stop the processing anymore when they match,
   allowing more complex setups: Delay, Disable Validation, Log,
   MacAddr, No Recurse and of course None
-  The new RE2Rule() is available, using the RE2 regular expression
   library to match queries, in addition to the existing POSIX-based
   RegexRule()
-  SpoofAction() now supports multiple A and AAAA records
-  Remote logging of questions and answers via Protocol Buffer

Improvements
~~~~~~~~~~~~

-  `#3405 <https://github.com/PowerDNS/pdns/pull/3405>`__ Add health
   check logging, ``maxCheckFailures`` to backend
-  `#3412 <https://github.com/PowerDNS/pdns/pull/3412>`__ Check config
-  `#3440 <https://github.com/PowerDNS/pdns/pull/3440>`__ Client
   operation improvements
-  `#3466 <https://github.com/PowerDNS/pdns/pull/3466>`__ Add dq binding
   for skipping packet cache in LuaAction (Jan Broer)
-  `#3499 <https://github.com/PowerDNS/pdns/pull/3499>`__ Add support
   for multiple carbon servers
-  `#3504 <https://github.com/PowerDNS/pdns/pull/3504>`__ Allow
   accessing the API with an optional API key
-  `#3556 <https://github.com/PowerDNS/pdns/pull/3556>`__ Add an option
   to limit the number of queued TCP connections
-  `#3578 <https://github.com/PowerDNS/pdns/pull/3578>`__ Add a
   ``disable-syslog`` option
-  `#3608 <https://github.com/PowerDNS/pdns/pull/3608>`__ Export cache
   stats to carbon
-  `#3622 <https://github.com/PowerDNS/pdns/pull/3622>`__ Display the
   ACL content on startup
-  `#3627 <https://github.com/PowerDNS/pdns/pull/3627>`__ Remove ECS
   option from response's OPT RR when necessary
-  `#3633 <https://github.com/PowerDNS/pdns/pull/3633>`__ Count "TTL too
   short" cache events
-  `#3677 <https://github.com/PowerDNS/pdns/pull/3677>`__ systemd-notify
   support

Bug fixes
~~~~~~~~~

-  `#3388 <https://github.com/PowerDNS/pdns/pull/3388>`__ Lock the Lua
   context before executing a LuaAction
-  `#3433 <https://github.com/PowerDNS/pdns/pull/3433>`__ Check that the
   answer matches the initial query
-  `#3461 <https://github.com/PowerDNS/pdns/pull/3461>`__ Fix crash when
   calling rmServer() with an invalid index
-  `#3550 <https://github.com/PowerDNS/pdns/pull/3550>`__,\ `#3551 <https://github.com/PowerDNS/pdns/pull/3551>`__
   Fix build failure on FreeBSD (Ruben Kerkhof)
-  `#3594 <https://github.com/PowerDNS/pdns/pull/3594>`__ Prevent EOF
   error for empty console response w/o sodium
-  `#3634 <https://github.com/PowerDNS/pdns/pull/3634>`__ Prevent
   dangling TCP fd in case setupTCPDownstream() fails
-  `#3641 <https://github.com/PowerDNS/pdns/pull/3641>`__ Under
   threshold, QPS action should return None, not Allow
-  `#3658 <https://github.com/PowerDNS/pdns/pull/3658>`__ Fix a race
   condition in MaxQPSIPRule

1.0.0-alpha2
------------

Released February 5th 2016

Changes since 1.0.0-alpha1:

New features
~~~~~~~~~~~~

-  Lua functions now receive a DNSQuestion ``dq`` object instead of
   several parameters. This adds a greater compatibility with PowerDNS
   and allows adding more parameters without breaking the API
   (`#3198 <https://github.com/PowerDNS/pdns/issues/3198>`__)
-  Added a ``source`` option to ``newServer()`` to specify the local
   address or interface used to contact a downstream server
   (`#3138 <https://github.com/PowerDNS/pdns/issues/3138>`__)
-  CNAME and IPv6-only support have been added to spoofed responses
   (`#3064 <https://github.com/PowerDNS/pdns/issues/3064>`__)
-  ``grepq()`` can be used to search for slow queries, along with
   ``topSlow()``
-  New Lua functions: ``addDomainCNAMESpoof()``, ``AllowAction()`` by
   @bearggg, ``exceedQRate()``, ``MacAddrAction()``, ``makeRule()``,
   ``NotRule()``, ``OrRule()``, ``QClassRule()``, ``RCodeAction()``,
   ``SpoofCNAMEAction()``, ``SuffixMatchNodeRule()``, ``TCPRule()``,
   ``topSlow()``
-  ``NetmaskGroup`` support have been added in Lua
   (`#3144 <https://github.com/PowerDNS/pdns/issues/3144>`__)
-  Added ``MacAddrAction()`` to add the source MAC address to the
   forwarded query
   (`#3313 <https://github.com/PowerDNS/pdns/issues/3313>`__)

Bug fixes
~~~~~~~~~

-  An issue in DelayPipe could make dnsdist crash at startup
-  ``downstream-timeouts`` metric was not always updated
-  ``truncateTC`` was unproperly updating the response length
   (`#3126 <https://github.com/PowerDNS/pdns/issues/3126>`__)
-  DNSCrypt responses larger than queries were unproperly truncated
-  An issue prevented info message from being displayed in non-verbose
   mode, fixed by Jan Broer
-  Reinstating an expired Dynamic Rule was not correctly logged
   (`#3323 <https://github.com/PowerDNS/pdns/issues/3323>`__)
-  Initialized counters in the TCP client thread might have cause FD and
   memory leak, reported by Martin Pels
   (`#3300 <https://github.com/PowerDNS/pdns/issues/3300>`__)
-  We now drop queries containing no question (qdcount == 0)
   (`#3290 <https://github.com/PowerDNS/pdns/issues/3290>`__)
-  Outstanding TCP queries count was not always correct
   (`#3288 <https://github.com/PowerDNS/pdns/issues/3288>`__)
-  A locking issue in exceedRespGen() might have caused crashes
   (`#3277 <https://github.com/PowerDNS/pdns/issues/3277>`__)
-  Useless sockets were created in client mode
   (`#3257 <https://github.com/PowerDNS/pdns/issues/3257>`__)
-  ``addAnyTCRule()`` was generating TC=1 responses even over TCP
   (`#3251 <https://github.com/PowerDNS/pdns/issues/3251>`__)

Web interface
~~~~~~~~~~~~~

-  Cleanup of the HTML by Sander Hoentjen
-  Fixed an XSS reported by @janeczku
   (`#3217 <https://github.com/PowerDNS/pdns/issues/3217>`__)
-  Removed remote images
-  Set the charset to UTF-8, added some security-related and CORS HTTP
   headers
-  Added server latency by Jan Broer
   (`#3201 <https://github.com/PowerDNS/pdns/issues/3201>`__)
-  Switched to official minified versions of JS scripts, by Sander
   Hoentjen (`#3317 <https://github.com/PowerDNS/pdns/issues/3317>`__)
-  Don't log unauthenticated HTTP request as an authentication failure

Various documentation updates and minor cleanups:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Added documentation for Advanced DNS Protection features (Dynamic
   rules, ``maintenance()``)
-  Make ``topBandwidth()`` default to the top 10 clients
-  Replaced readline with libedit
-  Added GPL2 License
   (`#3200 <https://github.com/PowerDNS/pdns/issues/3200>`__)
-  Added incbin License
   (`#3269 <https://github.com/PowerDNS/pdns/issues/3269>`__)
-  Updated completion rules
-  Removed wrong option ``--daemon-no`` by Stefan Schmidt

1.0.0-alpha1
------------

Released December 24th 2015

Initial release
