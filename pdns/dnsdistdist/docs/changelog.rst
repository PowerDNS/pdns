Changelog
=========

.. changelog::
  :version: 1.4.0-rc4
  :released: 25th of October 2019

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

  .. change::
    :tags: Bug Fixes
    :pullreq: 6785

    Add missing include for PRId64, fix build on CentOS 6 / SLES 12

.. changelog::
  :version: 1.3.1
  :released: 10th of July 2018

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

    Don't copy unitialized values of SuffixMatchTree

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

    Handle SNMP alarms so we can reconnect to the master.

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

    Change ``truncateTC`` to defaulting to off, having it enabled by default causes an compatibility with :rfc:`6891` (Robin Geuze).

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

    Add the possiblity to fill a :class:`NetmaskGroup` (using :meth:`NetmaskGroup:addMask`) from `exceeds*` results.

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
   PDNS\_CHECK\_OS in configure (Christian Hofstaedtler)
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
-  A locking issue in exceedRespGen() might have caused crashs
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
