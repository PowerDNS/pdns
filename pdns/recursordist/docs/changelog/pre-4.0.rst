Changelogs for all pre 4.0 releases
===================================

**Note**: Beyond PowerDNS 2.9.20, the Authoritative Server and Recursor are released separately.
Hence, this changelog starts at version 3.0.

PowerDNS Recursor 3.6.4
-----------------------

Released 9th of June 2015

This is a security release fixing :doc:`Security Advisory
2015-01 <../security-advisories/powerdns-advisory-2015-01>`

Bug fixes:

-  `commit bccd068 <https://github.com/PowerDNS/pdns/commit/bccd068>`__:
   Limit the maximum length of a qname

PowerDNS Recursor 3.7.3
-----------------------

Released 9th of June 2015

Bug fixes:

-  `commit 92f7b2b <https://github.com/PowerDNS/pdns/commit/92f7b2b>`__:
   Limit the maximum length of a qname

This is a security release fixing :doc:`Security Advisory
2015-01 <../security-advisories/powerdns-advisory-2015-01>`

Improvements:

-  `commit 46366a5 <https://github.com/PowerDNS/pdns/commit/46366a5>`__,
   `commit f318a7d <https://github.com/PowerDNS/pdns/commit/f318a7d>`__:
   pdnssec: check for glue and delegations in parent zones (Kees
   Monshouwer)

PowerDNS Recursor 3.7.2
-----------------------

Released 23rd of April, 2015

Among other bug fixes and improvements (as listed below), this release
incorporates a fix for CVE-2015-1868, as detailed in :doc:`PowerDNS Security
Advisory 2015-01 <../security-advisories/powerdns-advisory-2015-01>`

Bug fixes:

-  `commit adb10be <https://github.com/PowerDNS/pdns/commit/adb10be>`__
   `commit 3ec3e0f <https://github.com/PowerDNS/pdns/commit/3ec3e0f>`__
   `commit dc02ebf <https://github.com/PowerDNS/pdns/commit/dc02ebf>`__
   Fix handling of forward references in label compressed packets; fixes
   CVE-2015-1868
-  `commit a7be3f1 <https://github.com/PowerDNS/pdns/commit/a7be3f1>`__:
   make sure we never call sendmsg with msg\_control!=NULL &&
   msg\_controllen>0. Fixes `ticket
   #2227 <https://github.com/PowerDNS/pdns/issues/2227>`__
-  `commit 9d835ed <https://github.com/PowerDNS/pdns/commit/9d835ed>`__:
   Improve robustness of root-nx-trust.

Improvements:

-  `commit 99c595b <https://github.com/PowerDNS/pdns/commit/99c595b>`__:
   Silence warnings that always occur on FreeBSD (Ruben Kerkhof)

PowerDNS Recursor 3.6.3
-----------------------

Released 23rd of April, 2015

The only difference between Recursor 3.6.2 and 3.6.3 is a fix for
CVE-2015-1868, as detailed in :doc:`PowerDNS Security Advisory
2015-01 <../security-advisories/powerdns-advisory-2015-01>`

PowerDNS Recursor 3.7.0
-----------------------

Unreleased, please see the 3.7.1 changelog below.

PowerDNS Recursor 3.7.1
-----------------------

Released February 12th, 2015.

This version contains a mix of speedups and improvements, the combined
effect of which is vastly improved resilience against traffic spikes and
malicious query overloads.

Of further note is the massive community contribution, mostly over
Christmas. Especially Ruben Kerkhof, Pieter Lexis, Kees Monshouwer and
Aki Tuomi delivered a lot of love. Thanks!

Minor changes:

-  Removal of dead code here and there
   04dc6d618734fc630122de4c56dff641ebaf0988
-  Per-qtype response counters are now 64 bit
   297bb6acf7902068693a4aae1443c424d0e8dd52 on 64 bit systems
-  Add IPv6 addresses for b and c.root-servers.net hints
   efc2595423c9a1be6f2d8f4da25445198ceb8b57
-  Add IP address to logging about terminated queries
   37aa9904d1cc967ba4b5d5e17dbe41485f8cdece
-  Improve qtype name logging fab3ed3453e15ae88e29a0e4071b214eb19caad9
   (Aki Tuomi)
-  Redefine 'BAD\_NETS' for dont-query based on newer IANA guidance
   12cd44ee0fcde5893f85dccc499bfc35152c5fff (lochiiconnectivity)
-  Add documentation links to systemd unit
   eb154adfdffa5c78624e2ea98e938d7b5787119e (Ruben Kerkhof)

Improvements:

-  Upgrade embedded PolarSSL to 1.3.9:
   d330a2ea1a93d7675ef680311f8aa0306aeefcf1
-  yahttp upgrade c290975778942ed1082ca66918695a5bd2d6bac4
   c65a57e888ee48eaa948e590c90c51420bffa847 (Aki Tuomi)
-  Replace . in hostnames by - for Carbon so as not to confuse Metronome
   46541751ed1c3bc051d78217543d5fc76733e212
-  Manpages got a lot of love and are now built from Markdown (Pieter
   Lexis)
-  Move to PolarSSL base64 488360551009784ab35c43ee4580e773a2a8a227
   (Kees Monshouwer)
-  The quiet=no query logging is now more informative
   461df9d20c560d240285f772c09b3beb89d46daa
-  We can finally bind to 0.0.0.0 and :: and guarantee answers from the
   correct source b71b60ee73ef3c86f80a2179981eda2e61c4363f
-  We use per-packet timestamps to drop ancient traffic in case of
   overload b71b60ee73ef3c86f80a2179981eda2e61c4363f, non-Linux
   portability in d63f0d83631c41eff203d30b0b7c475a88f1db59
-  Builtin webserver can be queried with the API key in the URL again
   c89f8cd022c4a9409b95d22ffa3b03e4e98dc400
-  Ringbuffers are now available via API
   c89f8cd022c4a9409b95d22ffa3b03e4e98dc400
-  Lua 5.3 compatibility 59c6fc3e3931ca87d484337daee512e716bc4cf4 (Kees
   Monshouwer)
-  No longer leave a stale UNIX domain socket around from rec\_control
   if the recursor was down 524e4f4d81f4ed9eb218715cbc8a59f0b9868234,
   ticket #2061
-  Running with 'quiet=no' would strangely actually prevent debug
   messages from being logged f48d7b657ec32517f8bfcada3bfe6353ca313314
-  Webserver now implements CORS for the API
   ea89a97e864c43c1cb03f2959ad04c4ebe7580ad, fixing ticket #1984
-  Houskeeping thread would sometimes run multiple times simultaneously,
   which worked, but was odd cc59bce675e62e2b9657b42614ce8be3312cae82

New features:

-  New ``root-nx-trust`` flag makes PowerDNS generalize NXDOMAIN
   responses from the root-servers
   01402d56846a3a61811ebd4e6bc97e53f908e568
-  ``getregisteredname()`` for Lua, which turns 'www.bbc.co.uk' into
   'bbc.co.uk' 8cd4851beb78bc6ab320926fb5cb6a09282016b1
-  Lua preoutquery filter 3457a2a0ec41d3b3aff7640f30008788e1228a6e
-  Lua IP-based filter (ipfilter) before parsing packets
   4ea949413c495254acb0bd19335142761c1efc0c
-  ``iputils`` class for Lua, to quickly process IP addresses and
   netmasks in their native format
-  ``getregisteredname`` function for Lua, to find the registered domain
   for a given name
-  Various new ringbuffers: top-servfail-remotes,
   top-largeanswer-remotes, top-servfail-queries

Speedups:

-  Remove unneeded malloc traffic
   93d4a89096e64d53740790f58fadec56f6a0af14
   8682c32bc45b6ffa7c0f6da778e1b223ae7f03ce
   a903b39cfe7364c56324038264d3db50b8cece87
-  Our nameserver-loop detection carried around a lot of baggage for
   complex domain names, plus did not differentiate IPv4 and IPv6 well
   enough 891fbf888ccac074e3edc38864641ca774f2f03c
-  Prioritize new queries over nameserver responses, improving latency
   under query bursts bf3b0cec366c090af000b066267b6f6bbb3a512a
-  Remove escaping in case there was nothing to escape
   83b746fd1d94c8742d8bd87a44beb44c154230c7
-  Our logging infrastructure had a lot of locking
   d1449e4d073595e1e1581804f121fc90e37158bf
-  Reduce logging level of certain common messages, which locked up
   synchronously logging systems
   854d44e31c76aa650520e6d462dd3a02b5936f7a
-  Add limit on total wall-clock time spent on a query
   9de3e0340fa066d4c59449e1643a1de8c343f8f2
-  Packet cache is now case-insensitive, which increases hitrate
   90974597aadaf1096e3fd0dc450be7422ea591a5

Security relevant:

-  Check for PIE, RELRO and stack protector during configure
   8d0354b189c12e1e14f5309d3b49935c17f9eeb0 (Aki Tuomi)
-  Testing for support of PIE etc was improved in
   b2053c28ccb9609e2ce7bcb6beda83f98a062aa3 and beyond, fixes #2125
   (Ruben Kerkhof)
-  Max query-per-query limit (max-qperq) is now configurable
   173d790ead08f67733010ca4c6fc404a040fe699

Bugs fixed:

-  IPv6 outgoing queries had a disproportionate effect on our query
   load. Fixed in 76f190f2a0877cd79ede2994124c1a58dc69ae49 and beyond.
-  rec\_control gave incorrect output on a timeout
   12997e9d800734da51b808767e1e2477244c30eb
-  When using the webserver AND having an error in the Lua script,
   recursor could crash during startup
   62f0ae62984adadab687c23fe1b287c1f219b2cb
-  Hugely long version strings would trip up security polling
   18b7333828a1275ae5f5574a9c8330290d8557ff (Kees Monshouwer)
-  The 'remotes' ringbuffer was sized incorrectly
   f8f243b01215d6adcb59389f09ef494f1309041f
-  Cache sizes had an off-by-one scaling problem, with the wrong number
   of entries allocated per thread
   f8f243b01215d6adcb59389f09ef494f1309041f
-  Our automatic file descriptor limit raising was attempted *after*
   setuid, which made it a lot less effective. Found and fixed by Aki
   Tuomi a6414fdce9b0ec32c340d1f2eea2254f3fedc1c1
-  Timestamps used for dropping packets were occasionally wrong
   183eb8774e4bc2569f06d5894fec65740f4b70b6 and
   4c4765c104bacc146533217bcc843efb244a8086 (RC2) with thanks to
   Winfried for debugging.
-  In RC1, our new DoS protection measures would crash the Recursor if
   too many root servers were unreachable.
   6a6fb05ad81c519b4002ed1db00f3ed9b7bce6b4. Debugging and testing by
   Fusl.

Various other documentation changes by Christian Hofstaedtler and Ruben
Kerkhof. Lots of improvements all over the place by Kees Monshouwer.

PowerDNS Recursor 3.6.2
-----------------------

**Note**: Version 3.6.2 is a bugfix update to 3.6.1. Released on the
30th of October 2014.

`Official download page <https://www.powerdns.com/downloads.html>`__

A list of changes since 3.6.1 follows.

-  `commit ab14b4f <https://github.com/PowerDNS/pdns/commit/ab14b4f>`__:
   expedite servfail generation for ezdns-like failures (fully abort
   query resolving if we hit more than 50 outqueries). This also
   prevents the issue documented in :doc:`PowerDNS Security Advisory
   2014-02 <../security-advisories/powerdns-advisory-2014-02>` (CVE-2014-8601)
-  `commit 42025be <https://github.com/PowerDNS/pdns/commit/42025be>`__:
   PowerDNS now polls the security status of a release at startup and
   periodically. More detail on this feature, and how to turn it off,
   can be found in `Security
   polling <common/security.md#security-polling>`__.
-  `commit 5027429 <https://github.com/PowerDNS/pdns/commit/5027429>`__:
   We did not transmit the right 'local' socket address to Lua for
   TCP/IP queries in the recursor. In addition, we would attempt to
   lookup a filedescriptor that wasn't there in an unlocked map which
   could conceivably lead to crashes. Closes `ticket
   1828 <https://github.com/PowerDNS/pdns/issues/1828>`__, thanks
   Winfried for reporting
-  `commit 752756c <https://github.com/PowerDNS/pdns/commit/752756c>`__:
   Sync embedded yahttp copy. API: Replace HTTP Basic auth with static
   key in custom header
-  `commit 6fdd40d <https://github.com/PowerDNS/pdns/commit/6fdd40d>`__:
   add missing ``#include <pthread.h>`` to rec-channel.hh (this fixes
   building on OS X).

PowerDNS Recursor 3.6.1
-----------------------

**Warning**: Version 3.6.1 is a mandatory security upgrade to 3.6.0!
Released on the 10th of September 2014.

PowerDNS Recursor 3.6.0 could crash with a specific sequence of packets.
For more details, see `the
advisory <security/powerdns-advisory-2014-01.md>`__. PowerDNS Recursor
3.6.1 was very well tested, and is in full production already, so it
should be a safe upgrade.

Downloads
^^^^^^^^^

-  `Official download page <https://www.powerdns.com/downloads.html>`__

In addition to various fixes related to this potential crash, 3.6.1
fixes a few minor issues and adds a debugging feature:

-  We could not encode IPv6 AAAA records that mapped to IPv4 addresses
   in some cases (:ffff.1.2.3.4). Fixed in `commit
   c90fcbd <https://github.com/PowerDNS/pdns/commit/c90fcbd>`__ ,
   closing `ticket
   1663 <https://github.com/PowerDNS/pdns/issues/1663>`__.
-  Improve systemd startup timing with respect to network availability
   (`commit
   cf86c6a <https://github.com/PowerDNS/pdns/commit/cf86c6a>`__), thanks
   to Morten Stevens.
-  Realtime telemetry can now be enabled at runtime, for example with
   'rec\_control carbon-server 82.94.213.34 ourname1234'. This ties in
   to our existing carbon-server and carbon-ourname settings, but now at
   runtime. This specific invocation will make your stats appear
   automatically on our `public telemetry
   server <http://xs.powerdns.com/metronome/?server=pdns.xs.recursor&beginTime=-3600>`__.

PowerDNS Recursor version 3.6.0
-------------------------------

This is a performance, feature and bugfix update to 3.5/3.5.3. It
contains important fixes for slightly broken domain names, which your
users expect to work anyhow. It also brings robust resilience against
certain classes of attacks.

Downloads
^^^^^^^^^

-  `Official download page <https://www.powerdns.com/downloads.html>`__
-  `native RHEL5/6 packages from Kees
   Monshouwer <https://www.monshouwer.eu/download/3rd_party/pdns-recursor/>`__

Changes between RC1 and release
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  `commit 30b13ef <https://github.com/PowerDNS/pdns/commit/30b13ef>`__:
   do not apply some of our filters to root and gtlds, plus remove some
   useless {}
-  `commit cc81d90 <https://github.com/PowerDNS/pdns/commit/cc81d90>`__:
   fix yahttp copy in dist-recursor for BSD cp
-  `commit b798618 <https://github.com/PowerDNS/pdns/commit/b798618>`__:
   define \_\_APPLE\_USE\_RFC\_3542 during recursor build on Darwin,
   fixes `ticket 1449 <https://github.com/PowerDNS/pdns/issues/1449>`__
-  `commit 1d7f863 <https://github.com/PowerDNS/pdns/commit/1d7f863>`__:
   Merge pull request `ticket
   1443 <https://github.com/PowerDNS/pdns/issues/1443>`__ from
   zeha/recursor-nostrip
-  `commit 5cdeede <https://github.com/PowerDNS/pdns/commit/5cdeede>`__:
   remove (non-working) [aaaa-]additional-processing flags from the
   recursor. Closes `ticket
   1448 <https://github.com/PowerDNS/pdns/issues/1448>`__
-  `commit 984d747 <https://github.com/PowerDNS/pdns/commit/984d747>`__:
   Support building recursor on kFreeBSD and Hurd
-  `commit 79240f1 <https://github.com/PowerDNS/pdns/commit/79240f1>`__:
   Allow not stripping of binaries in recursor's make install
-  `commit e9c2ad3 <https://github.com/PowerDNS/pdns/commit/e9c2ad3>`__:
   document pdns.DROP for recursor, add policy-drops metric for it

New features
^^^^^^^^^^^^

-  `commit aadceba <https://github.com/PowerDNS/pdns/commit/aadceba>`__:
   Implement minimum-ttl-override config setting, plus runtime
   configurability via 'rec\_control set-minimum-ttl'.
-  Lots of work on the JSON API, which is exposed via Aki Tuomi's
   'yahttp'. Massive thanks to Christian Hofstaedtler for delivering
   this exciting new functionality. Documentation & demo forthcoming,
   but code to use it is available `on
   GitHub <https://github.com/powerdns/pdnscontrol>`__.
-  Lua modules can now use 'pdnslog(INFO..'), as described in `ticket
   1074 <https://github.com/PowerDNS/pdns/issues/1074>`__, implemented
   in `commit
   674a305 <https://github.com/PowerDNS/pdns/commit/674a305>`__
-  Adopt any-to-tcp feature to the recursor. Based on a patch by
   Winfried Angele. Closes `ticket
   836 <https://github.com/PowerDNS/pdns/issues/836>`__, `commit
   56b4d21 <https://github.com/PowerDNS/pdns/commit/56b4d21>`__ and
   `commit e661a20 <https://github.com/PowerDNS/pdns/commit/e661a20>`__.
-  `commit 2c78bd5 <https://github.com/PowerDNS/pdns/commit/2c78bd5>`__:
   implement built-in statistics dumper using the 'carbon' protocol,
   which is also understood by metronome (our mini-graphite). Use
   'carbon-server', 'carbon-ourname' and 'carbon-interval' settings.
-  New setting 'udp-truncation-threshold' to configure from how many
   bytes we should truncate. `commit
   a09a8ce <https://github.com/PowerDNS/pdns/commit/a09a8ce>`__.
-  Proper support for CHaos class for CHAOS TXT queries. `commit
   c86e1f2 <https://github.com/PowerDNS/pdns/commit/c86e1f2>`__,
   addition for lua in `commit
   f94c53d <https://github.com/PowerDNS/pdns/commit/f94c53d>`__, some
   warnings in `commit
   438db54 <https://github.com/PowerDNS/pdns/commit/438db54>`__ however.
-  Added support for Lua scripts to drop queries w/o further processing.
   `commit 0478c54 <https://github.com/PowerDNS/pdns/commit/0478c54>`__.
-  Kevin Holly added qtype statistics to recursor and rec\_control
   (get-qtypelist) (`commit
   79332bf <https://github.com/PowerDNS/pdns/commit/79332bf>`__)
-  Add support for include-files in configuration, also reload ACLs and
   zones defined in them (`commit
   829849d <https://github.com/PowerDNS/pdns/commit/829849d>`__, `commit
   242b90e <https://github.com/PowerDNS/pdns/commit/242b90e>`__, `commit
   302df81 <https://github.com/PowerDNS/pdns/commit/302df81>`__).
-  Paulo Anes contributed server-down-max-fails which helps combat
   Recursive DNS based amplification attacks. Described in `this
   post <https://blog.powerdns.com/2014/04/03/further-dos-guidance-packages-and-patches-available/>`__.
   Also comes with new metric 'failed-host-entries' in `commit
   406f46f <https://github.com/PowerDNS/pdns/commit/406f46f>`__.
-  `commit 21e7976 <https://github.com/PowerDNS/pdns/commit/21e7976>`__:
   Implement "followCNAMERecords" feature in the Lua hooks.

Improvements
^^^^^^^^^^^^

-  `commit 06ea901 <https://github.com/PowerDNS/pdns/commit/06ea901>`__:
   make pdns-distributes-queries use a hash so related queries get sent
   to the same thread. Original idea by Winfried Angele. Astoundingly
   effective, approximately halves CPU usage!
-  `commit b13e737 <https://github.com/PowerDNS/pdns/commit/b13e737>`__:
   --help now writes to stdout instead of stderr. Thanks Winfried
   Angele.
-  To aid in limiting DoS attacks, when truncating a response, we
   actually truncate all the way so only the question remains. Suggested
   in `ticket 1092 <https://github.com/PowerDNS/pdns/issues/1092>`__,
   code in `commit
   add935a <https://github.com/PowerDNS/pdns/commit/add935a>`__.
-  No longer experimental, the switch 'pdns-distributes-queries' can
   improve multi-threaded performance on Linux (various cleanup
   commits).
-  Update to embedded PolarSSL, plus remove previous AES implementation
   and shift to PolarSSL (`commit
   e22d9b4 <https://github.com/PowerDNS/pdns/commit/e22d9b4>`__, `commit
   990ad9a <https://github.com/PowerDNS/pdns/commit/990ad9a>`__)
-  `commit 92c0733 <https://github.com/PowerDNS/pdns/commit/92c0733>`__
   moves various Lua magic constants into an enum namespace.
-  set group and supplementary groups before chroot (`commit
   6ee50ce <https://github.com/PowerDNS/pdns/commit/6ee50ce>`__, `ticket
   1198 <https://github.com/PowerDNS/pdns/issues/1198>`__).
-  `commit 4e9a20e <https://github.com/PowerDNS/pdns/commit/4e9a20e>`__:
   raise our socket buffer setting so it no longer generates a warning
   about lowering it.
-  `commit 4e9a20e <https://github.com/PowerDNS/pdns/commit/4e9a20e>`__:
   warn about Linux suboptimal IPv6 settings if we detect them.
-  SIGUSR2 turns on a 'trace' of all DNS traffic, a second SIGUSR2 now
   turns it off again. `commit
   4f217ce <https://github.com/PowerDNS/pdns/commit/4f217ce>`__.
-  Various fixes for Lua 5.2.
-  `commit 81859ba <https://github.com/PowerDNS/pdns/commit/81859ba>`__:
   No longer attempt to answer questions coming in from port 0, reply
   would not reach them anyhow. Thanks to Niels Bakker and 'sid3windr'
   for insight & debugging. Closes `ticket
   844 <https://github.com/PowerDNS/pdns/issues/844>`__.
-  `commit b1a2d6c <https://github.com/PowerDNS/pdns/commit/b1a2d6c>`__:
   now, I'm not one to get OCD over things, but that log message about
   stats based on 1801 seconds got to me. 1800 now.

Fixes
^^^^^

-  0c9de4fc: stay away from getaddrinfo unless we really can't help it
   for ascii ipv6 conversions to binary
-  `commit 08f3f63 <https://github.com/PowerDNS/pdns/commit/08f3f63>`__:
   fix average latency calculation, closing `ticket
   424 <https://github.com/PowerDNS/pdns/issues/424>`__.
-  `commit 75ba907 <https://github.com/PowerDNS/pdns/commit/75ba907>`__:
   Some of our counters were still 32 bits, now 64.
-  `commit 2f22827 <https://github.com/PowerDNS/pdns/commit/2f22827>`__:
   Fix statistics and stability when running with
   pdns-distributes-queries.
-  `commit 6196f90 <https://github.com/PowerDNS/pdns/commit/6196f90>`__:
   avoid merging old and new additional data, fixes an issue caused by
   weird (but probably legal) Akamai behaviour
-  `commit 3a8a4d6 <https://github.com/PowerDNS/pdns/commit/3a8a4d6>`__:
   make sure we don't exceed the number of available filedescriptors for
   mthreads. Raises performance in case of DoS. See `this
   post <https://blog.powerdns.com/2014/02/06/related-to-recent-dos-attacks-recursor-configuration-file-guidance/>`__
   for further details.
-  `commit 7313fe6 <https://github.com/PowerDNS/pdns/commit/7313fe6>`__:
   implement indexed packet cache wiping for recursor, orders of
   magnitude faster. Important when reloading all zones, which causes
   massive cache cleaning.
-  rec\_control get-all would include 'cache-bytes' and
   'packetcache-bytes', which were expensive operations, too expensive
   for frequent polling. Removed in `commit
   8e42d27 <https://github.com/PowerDNS/pdns/commit/8e42d27>`__.
-  All old workarounds for supporting Windows of the XP era have been
   removed.
-  Fix issues on S390X based systems which have unsigned characters
   (`commit
   916a0fd <https://github.com/PowerDNS/pdns/commit/916a0fd>`__)


PowerDNS Recursor version 3.5.3
-------------------------------

Released September 17th, 2013

This is a bugfix and performance update to 3.5.2. It brings serious
performance improvements for dual stack users.

Downloads
^^^^^^^^^

-  `Official download page <https://www.powerdns.com/downloads.html>`__
-  `native RHEL5/6 packages from Kees
   Monshouwer <http://www.monshouwer.eu/download/3rd_party/pdns-recursor/>`__

Changes since 3.5.2
^^^^^^^^^^^^^^^^^^^

-  3.5 replaced our ANY query with A+AAAA for users with IPv6 enabled.
   Extensive measurements by Darren Gamble showed that this change had a
   non-trivial performance impact. We now do the ANY query like before,
   but fall back to the individual A+AAAA queries when necessary. Change
   in `commit
   1147a8b <https://github.com/PowerDNS/pdns/commit/1147a8b>`__.
-  The IPv6 address for d.root-servers.net was added in `commit
   66cf384 <https://github.com/PowerDNS/pdns/commit/66cf384>`__, thanks
   Ralf van der Enden.
-  We now drop packets with a non-zero opcode (i.e. special packets like
   DNS UPDATE) earlier on. If the experimental pdns-distributes-queries
   flag is enabled, this fix avoids a crash. Normal setups were never
   susceptible to this crash. Code in `commit
   35bc40d <https://github.com/PowerDNS/pdns/commit/35bc40d>`__, closes
   `ticket 945 <https://github.com/PowerDNS/pdns/issues/945>`__.
-  TXT handling was somewhat improved in `commit
   4b57460 <https://github.com/PowerDNS/pdns/commit/4b57460>`__, closing
   `ticket 795 <https://github.com/PowerDNS/pdns/issues/795>`__.

PowerDNS Recursor version 3.5.2
-------------------------------

Released June 7th, 2013

This is a stability and bugfix update to 3.5.1. It contains important
fixes that improve operation for certain domains.

Downloads
^^^^^^^^^

-  `Official download page <https://www.powerdns.com/downloads.html>`__
-  `native RHEL5/6 packages from Kees
   Monshouwer <http://www.monshouwer.eu/download/3rd_party/pdns-recursor/>`__

Changes since 3.5.1
^^^^^^^^^^^^^^^^^^^

-  Responses without the QR bit set now get matched up to an outstanding
   query, so that resolution can be aborted early instead of waiting for
   a timeout. Code in `commit
   ee90f02 <https://github.com/PowerDNS/pdns/commit/ee90f02>`__.
-  The depth limiter changes in 3.5.1 broke some legal domains with lots
   of indirection. Improved in `commit
   d393c2d <https://github.com/PowerDNS/pdns/commit/d393c2d>`__.
-  Slightly improved logging to aid debugging. Code in `commit
   437824d <https://github.com/PowerDNS/pdns/commit/437824d>`__ and
   `commit 182005e <https://github.com/PowerDNS/pdns/commit/182005e>`__.

PowerDNS Recursor version 3.5.1
-------------------------------

Released May 3rd, 2013

This is a stability and bugfix update to 3.5. It contains important
fixes that improve operation for certain domains.

Downloads
^^^^^^^^^

-  `Official download page <https://www.powerdns.com/downloads.html>`__
-  `native RHEL5/6 packages from Kees
   Monshouwer <http://www.monshouwer.eu/download/3rd_party/pdns-recursor/>`__

Changes since 3.5
^^^^^^^^^^^^^^^^^

-  We now abort earlier while following endless glue or CNAME chains.
   Fix in `commit
   02d1742 <https://github.com/PowerDNS/pdns/commit/02d1742>`__.
-  Some unused code would crash certain gcc versions on ARM. Reported by
   Morten Stevens, fixed in `commit
   5b188e8 <https://github.com/PowerDNS/pdns/commit/5b188e8>`__.
-  The 3.5 fix for `ticket
   731 <https://github.com/PowerDNS/pdns/issues/731>`__ was too strict,
   causing trouble with at least one domain. Reported by Aki Tuomi,
   check slightly relaxed in `commit
   4134690 <https://github.com/PowerDNS/pdns/commit/4134690>`__.
-  Automake/autoconf now use non-deprecated syntax. Reported by Morten
   Stevens, change in `commit
   ca17ef2 <https://github.com/PowerDNS/pdns/commit/ca17ef2>`__.

PowerDNS Recursor version 3.5
-----------------------------

Released April 15th, 2013

This is a stability, security and bugfix update to 3.3/3.3.1. It
contains important fixes for slightly broken domain names, which your
users expect to work anyhow. **Note**: Because a semi-sanctioned 3.4-pre
was distributed for a long time, and people have come to call that 3.4,
we are skipping an actual 3.4 release to avoid confusion.

Downloads
^^^^^^^^^

-  `Official download page <https://www.powerdns.com/downloads.html>`__
-  `native RHEL5/6 packages from Kees
   Monshouwer <http://www.monshouwer.eu/download/3rd_party/pdns-recursor/>`__

Changes between RC5 and the final 3.5 release
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Winfried Angele reported that restarting a very busy recursor could
   lead to crashes. Fixed in r3153, closing `ticket
   735 <https://github.com/PowerDNS/pdns/issues/735>`__.

Changes between RC4 and RC5
^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Bernd-René Predota of Liberty Global reported that Recursor 3.3 would
   treat empty non-AA NOERROR responses as authoritative NXDATA
   responses. This bug turned out to be in 3.5-RC4 too. Fixed in `commit
   3146 <http://wiki.powerdns.com/projects/trac/changeset/3146>`__,
   related to `ticket
   731 <https://github.com/PowerDNS/pdns/issues/731>`__.

Changes between RC3 (unreleased) and RC4
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Winfried Angele spotted, even before release, that `commit
   3132 <http://wiki.powerdns.com/projects/trac/changeset/3132>`__ in
   RC3 broke outgoing IPv6 queries. We are grateful for his attention to
   detail! Fixed in `commit
   3141 <http://wiki.powerdns.com/projects/trac/changeset/3141>`__.
   Changes between RC2 and RC3 (unreleased)
-  Use private temp dir when running under systemd, thanks Morten
   Stevens and Ruben Kerkhof. Change in `commit
   3105 <http://wiki.powerdns.com/projects/trac/changeset/3105>`__.
-  NSD mistakenly compresses labels for RP and other types, violating a
   MUST in RFC 3597. Recursor does not decompress these labels,
   violating a SHOULD in RFC3597. We now decompress these labels, and
   reportedly NSD will stop compressing them. Reported by Jan-Piet Mens,
   fixed in `commit
   3109 <http://wiki.powerdns.com/projects/trac/changeset/3109>`__.
-  When forwarding to another recursor, we would handle responses to ANY
   queries incorrectly. Spotted by Jan-Piet Mens, fixed in `commit
   3116 <http://wiki.powerdns.com/projects/trac/changeset/3116>`__,
   closes `ticket 704 <https://github.com/PowerDNS/pdns/issues/704>`__.
-  Our local-nets definition (used as a default for some settings) now
   includes the networks from RFC 3927 and RFC 6598. Reported by Maik
   Zumstrull, fixed in `commit
   3122 <http://wiki.powerdns.com/projects/trac/changeset/3122>`__.
-  The RC1 change to stop using ANY queries to get A+AAAA for name
   servers in one go had a 5% performance impact. This impact is
   corrected in `commit
   3132 <http://wiki.powerdns.com/projects/trac/changeset/3132>`__.
   Thanks to Winfried Angele for measuring and reporting this. Closes
   `ticket 710 <https://github.com/PowerDNS/pdns/issues/710>`__.
-  New command 'rec\_control dump-nsspeeds' will dump our NS speeds
   (latency) cache. Code in `commit
   3131 <http://wiki.powerdns.com/projects/trac/changeset/3131>`__.

Changes between RC1 and RC2
^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  While Recursor 3.3 was not vulnerable to the specific attack noted in
   'Ghost Domain Names: Revoked Yet Still Resolvable' (more information
   at `A New DNS Exploitation Technique: Ghost Domain
   Names <http://resources.infosecinstitute.com/ghost-domain-names/>`__),
   further investigation showed that a variant of the attack could work.
   This was fixed in `commit
   3085 <http://wiki.powerdns.com/projects/trac/changeset/3085>`__. This
   should also close the slightly bogus
   `CVE-2012-1193 <http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-1193>`__.
   Closes `ticket 668 <https://github.com/PowerDNS/pdns/issues/668>`__.
-  The auth-can-lower-ttl flag was removed, as it did not have any
   effect in most situations, and thus did not operate as advertised. We
   now always comply with the related parts of RFC 2181. Change in
   `commit
   3092 <http://wiki.powerdns.com/projects/trac/changeset/3092>`__,
   closing `ticket 88 <https://github.com/PowerDNS/pdns/issues/88>`__.

New features
^^^^^^^^^^^^

-  The local zone server now understands wildcards, code in `commit
   2062 <http://wiki.powerdns.com/projects/trac/changeset/2062>`__.
-  The Lua postresolve and nodata hooks, that had been distributed as a
   '3.3-hooks' snapshot earlier, have been merged. Code in `commit
   2309 <http://wiki.powerdns.com/projects/trac/changeset/2309>`__.
-  A new feature, rec\_control trace-regex allows the tracing of lookups
   for specific names. Code in `commit
   3044 <http://wiki.powerdns.com/projects/trac/changeset/3044>`__,
   `commit
   3073 <http://wiki.powerdns.com/projects/trac/changeset/3073>`__.
-  A new setting, export-etc-hosts-search-suffix, adds a configurable
   suffix to names imported from /etc/hosts. Code in `commit
   2544 <http://wiki.powerdns.com/projects/trac/changeset/2544>`__,
   `commit
   2545 <http://wiki.powerdns.com/projects/trac/changeset/2545>`__.

Improvements
^^^^^^^^^^^^

-  We now throttle queries that don't work less aggressively, code in
   `commit
   1766 <http://wiki.powerdns.com/projects/trac/changeset/1766>`__.
-  Various improvements in tolerance against broken auths, code in
   `commit
   1996 <http://wiki.powerdns.com/projects/trac/changeset/1996>`__,
   `commit
   2188 <http://wiki.powerdns.com/projects/trac/changeset/2188>`__,
   `commit
   3074 <http://wiki.powerdns.com/projects/trac/changeset/3074>`__
   (thanks Winfried).
-  Additional processing is now optional, and disabled by default.
   Presumably this yields a performance improvement. Change in `commit
   2542 <http://wiki.powerdns.com/projects/trac/changeset/2542>`__.
-  rec\_control reload-lua-script now reports errors. Code in `commit
   2627 <http://wiki.powerdns.com/projects/trac/changeset/2627>`__,
   closing `ticket 278 <https://github.com/PowerDNS/pdns/issues/278>`__.
-  rec\_control help now lists commands. Code in `commit
   2628 <http://wiki.powerdns.com/projects/trac/changeset/2628>`__.
-  rec\_control wipe-cache now also wipes the recursor's packet cache.
   Code in `commit
   2880 <http://wiki.powerdns.com/projects/trac/changeset/2880>`__ from
   `ticket 333 <https://github.com/PowerDNS/pdns/issues/333>`__.
-  Morten Stevens contributed a systemd file. Import in `commit
   2966 <http://wiki.powerdns.com/projects/trac/changeset/2966>`__, now
   part of the recursor tarball.
-  `commit
   2990 <http://wiki.powerdns.com/projects/trac/changeset/2990>`__
   updates the address of D.root-servers.net.
-  Winfried Angele implemented and documented the ipv6-questions metric.
   Merge in `commit
   3034 <http://wiki.powerdns.com/projects/trac/changeset/3034>`__,
   closing `ticket 619 <https://github.com/PowerDNS/pdns/issues/619>`__.
-  We no longer use ANY to get A+AAAA for nameservers, because some auth
   operators have decided to break ANY lookups. As a bonus, we now track
   v4 and v6 latency separately. Change in `commit
   3064 <http://wiki.powerdns.com/projects/trac/changeset/3064>`__.

Bugs fixed
^^^^^^^^^^

-  Some unaligned memory access was corrected, code in `commit
   2060 <http://wiki.powerdns.com/projects/trac/changeset/2060>`__,
   `commit
   2122 <http://wiki.powerdns.com/projects/trac/changeset/2122>`__,
   `commit
   2123 <http://wiki.powerdns.com/projects/trac/changeset/2123>`__,
   which would cause problems on UltraSPARC.
-  Garbage encountered during reload-acls could cause crashes. Fixed in
   `commit
   2323 <http://wiki.powerdns.com/projects/trac/changeset/2323>`__,
   closing `ticket 330 <https://github.com/PowerDNS/pdns/issues/330>`__.
-  The recursor would lose its root hints in a very rare situation.
   Corrected in `commit
   2380 <http://wiki.powerdns.com/projects/trac/changeset/2380>`__.
-  We did not always drop supplemental groups while dropping privileges.
   Reported by David Black of Atlassian, fixed in `commit
   2524 <http://wiki.powerdns.com/projects/trac/changeset/2524>`__.
-  Cache aging would sometimes get confused when we had a mix of expired
   and non-expired records in cache. Spotted and fixed by Winfried
   Angele in `commit
   3068 <http://wiki.powerdns.com/projects/trac/changeset/3068>`__,
   closing `ticket 438 <https://github.com/PowerDNS/pdns/issues/438>`__.
-  rec\_control reload-acl no longer ignores arguments. Fix in `commit
   3037 <http://wiki.powerdns.com/projects/trac/changeset/3037>`__,
   closing `ticket 490 <https://github.com/PowerDNS/pdns/issues/490>`__.
-  Since we re-parse our commandline in rec\_control we've been doubling
   the commands on the commandline, causing weird output. Reported by
   Winfried Angele. Fixed in `commit
   2992 <http://wiki.powerdns.com/projects/trac/changeset/2992>`__,
   closing `ticket 618 <https://github.com/PowerDNS/pdns/issues/618>`__.
   This issue was not present in any officially released versions.
-  `commit
   2879 <http://wiki.powerdns.com/projects/trac/changeset/2879>`__ drops
   some spurious stderr logging from Lua scripts, and makes sure 'place'
   is always valid.
-  We would sometimes refuse to resolve domains with just one nameserver
   living at the apex. Fixed in `commit
   2817 <http://wiki.powerdns.com/projects/trac/changeset/2817>`__.
-  We would sometimes stick RRs in the wrong parts of response packets.
   Fixed in `commit
   2625 <http://wiki.powerdns.com/projects/trac/changeset/2625>`__.
-  The ACL parser was too liberal, sometimes causing recursors to be
   very open. Fixed in `commit
   2629 <http://wiki.powerdns.com/projects/trac/changeset/2629>`__,
   closing `ticket 331 <https://github.com/PowerDNS/pdns/issues/331>`__.
-  rec\_control now honours socket-dir from recursor.conf. Fixed in
   `commit
   2630 <http://wiki.powerdns.com/projects/trac/changeset/2630>`__.
-  When traversing CNAME chains, sometimes we would end up with multiple
   SOAs in the result. Fixed in `commit
   2633 <http://wiki.powerdns.com/projects/trac/changeset/2633>`__.


Recursor version 3.3.1
-----------------------

**Warning**:Unreleased

Version 3.3.1 contains a small number of important fixes, adds some
memory usage statistics, but no new features.

-  Discovered by John J and Robin J, the PowerDNS Recursor did not
   process packets that were truncated in mid-record, and also did not
   act on the 'truncated' (TC) flag in that case. This broke a very
   small number of domains, most of them served by very old versions of
   the PowerDNS Authoritative Server. Fix in `commit
   1740 <http://wiki.powerdns.com/projects/trac/changeset/1740>`__.
-  PowerDNS emitted a harmless, but irritating, error message on
   receiving certain very short packets. Discovered by Winfried A and
   John J, fix in `commit
   1729 <http://wiki.powerdns.com/projects/trac/changeset/1729>`__.
-  PowerDNS could crash on startup if configured to provide service on
   malformed IPv6 addresses on FreeBSD, or in case when the FreeBSD
   kernel was compiled without any form of IPv6 support. Debugged by
   Bryan Seitz, fix in `commit
   1727 <http://wiki.powerdns.com/projects/trac/changeset/1727>`__.
-  Add max-mthread-stack metric to debug rare crashes. Could be used to
   save memory on constrained systems. Implemented in `commit
   1745 <http://wiki.powerdns.com/projects/trac/changeset/1745>`__.
-  Add cache-bytes and packetcache-bytes metrics to measure our
   'pre-malloc' memory utilization. Implemented in `commit
   1750 <http://wiki.powerdns.com/projects/trac/changeset/1750>`__.

Recursor version 3.3
--------------------

Released on the 22nd of September 2010.

**Warning**: Version 3.3 fixes a number of small but persistent issues,
rounds off our IPv6 %link-level support and adds an important feature
for many users of the Lua scripts.

In addition, scalability on Solaris 10 is improved.

Bug fixes
^^^^^^^^^

-  'dist-recursor' script was not compatible with pure POSIX /bin/sh,
   discovered by Simon Kirby. Fix in `commit
   1545 <http://wiki.powerdns.com/projects/trac/changeset/1545>`__.
-  Simon Bedford, Brad Dameron and Laurient Papier discovered relatively
   high TCP/IP loads could cause TCP/IP service to shut down over time.
   Addressed in commits
   `1546 <http://wiki.powerdns.com/projects/trac/changeset/1546>`__,
   `1640 <http://wiki.powerdns.com/projects/trac/changeset/1640>`__,
   `1652 <http://wiki.powerdns.com/projects/trac/changeset/1652>`__,
   `1685 <http://wiki.powerdns.com/projects/trac/changeset/1685>`__,
   `1698 <http://wiki.powerdns.com/projects/trac/changeset/1698>`__.
   Additional information provided by Zwane Mwaikambo, Nicholas Miell
   and Jeff Roberson. Testing by Christian Hofstaedtler and Michael
   Renner.
-  The PowerDNS Recursor could not read the 'root zone' (this is
   something else than the root hints) because of an unquoted TXT
   record. This has now been addressed, allowing operators to hardcode
   the root zone. This can improve security if the root zone used is
   kept up to date. Change in `commit
   1547 <http://wiki.powerdns.com/projects/trac/changeset/1547>`__.
-  A return of an old bug, when a domain gets new nameservers, but the
   old nameservers continue to contain a copy of the domain, PowerDNS
   could get 'stuck' with the old servers. Fixed in `commit
   1548 <http://wiki.powerdns.com/projects/trac/changeset/1548>`__.
-  Discovered & reported by Alexander Gall of SWITCH, the Recursor used
   to try to resolve 'AXFR' records over UDP. Fix in `commit
   1619 <http://wiki.powerdns.com/projects/trac/changeset/1619>`__.
-  The Recursor embedded authoritative server messed up parsing a record
   like '@ IN MX 15 @'. Spotted by Aki Tuomi, fix in `commit
   1621 <http://wiki.powerdns.com/projects/trac/changeset/1621>`__.
-  The Recursor embedded authoritative server messed up parsing really
   really long lines. Spotted by Marco Davids, fix in `commit
   1624 <http://wiki.powerdns.com/projects/trac/changeset/1624>`__,
   `commit
   1625 <http://wiki.powerdns.com/projects/trac/changeset/1625>`__.
-  Packet cache was not DNS class correct. Spotted by "Robin", fix in
   `commit
   1688 <http://wiki.powerdns.com/projects/trac/changeset/1688>`__.
-  The packet cache would cache some NXDOMAINs for too long. Solving
   this bug exposed an underlying oddity where the initial NXDOMAIN
   response had an overly long (untruncated) TTL, whereas all the next
   ones would be ok. Solved in `commit
   1679 <http://wiki.powerdns.com/projects/trac/changeset/1679>`__,
   closing `ticket 281 <https://github.com/PowerDNS/pdns/issues/281>`__.
   Especially important for RBL operators. Fixed after some nagging by
   Alex Broens (thanks).

Improvements
^^^^^^^^^^^^

-  The priming of the root now uses more IPv6 addresses. Change in
   `commit
   1550 <http://wiki.powerdns.com/projects/trac/changeset/1550>`__,
   closes `ticket 287 <https://github.com/PowerDNS/pdns/issues/287>`__.
   Also, the IPv6 address of I.ROOT-SERVERS.NET was added in `commit
   1650 <http://wiki.powerdns.com/projects/trac/changeset/1650>`__.
-  The ``rec_control dump-cache`` command now also dumps the 'negative
   query' cache. Code in `commit
   1713 <http://wiki.powerdns.com/projects/trac/changeset/1713>`__.
-  PowerDNS Recursor can now bind to fe80 IPv6 space with '%eth0' link
   selection. Suggested by Darren Gamble, implemented with help from
   Niels Bakker. Change in `commit
   1620 <http://wiki.powerdns.com/projects/trac/changeset/1620>`__.
-  Solaris on x86 has a long standing bug in port\_getn(), which we now
   work around. Spotted by 'Dirk' and 'AS'. Solution suggested by the
   Apache runtime library, update in `commit
   1622 <http://wiki.powerdns.com/projects/trac/changeset/1622>`__.
-  New runtime statistic: 'tcp-clients' which lists the number of
   currently active TCP/IP clients. Code in `commit
   1623 <http://wiki.powerdns.com/projects/trac/changeset/1623>`__.
-  Deal better with UltraDNS style CNAME redirects containing SOA
   records. Spotted by Andy Fletcher from UKDedicated in `ticket
   303 <https://github.com/PowerDNS/pdns/issues/303>`__, fix in `commit
   1628 <http://wiki.powerdns.com/projects/trac/changeset/1628>`__.
-  The packet cache, which has 'ready to use' packets containing
   answers, now artificially ages the ready to use packets. Code in
   `commit
   1630 <http://wiki.powerdns.com/projects/trac/changeset/1630>`__.
-  Lua scripts can now indicate that certain queries will have
   'variable' answers, which means that the packet cache will not touch
   these answers. This is great for overriding some domains for some
   users, but not all of them. Use setvariable() in Lua to indicate such
   domains. Code in `commit
   1636 <http://wiki.powerdns.com/projects/trac/changeset/1636>`__.
-  Add query statistic called 'dont-outqueries', plus add IPv6 address
   :: and IPv4 address 0.0.0.0 to the default "dont-query" set,
   preventing the Recursor from talking to itself. Code in `commit
   1637 <http://wiki.powerdns.com/projects/trac/changeset/1637>`__.
-  Work around a gcc 4.1 bug, still in wide use on common platforms.
   Code in `commit
   1653 <http://wiki.powerdns.com/projects/trac/changeset/1653>`__.
-  Add 'ARCHFLAGS' to PowerDNS Recursor Makefile, easing 64 bit
   compilation on mainly 32 bit platforms (and vice versa).
-  Under rare circumstances, querying the Recursor for statistics under
   very high load could lead to a crash (although this has never been
   observed). Bad code removed & good code unified in `commit
   1675 <http://wiki.powerdns.com/projects/trac/changeset/1675>`__.
-  Spotted by Jeff Sipek, the rec\_control manpage did not list the new
   get-all command. `commit
   1677 <http://wiki.powerdns.com/projects/trac/changeset/1677>`__.
-  On some platforms, it may be better to have PowerDNS itself
   distribute queries over threads (instead of leaving it up to the
   kernel). This experimental feature can be enabled with the
   'pdns-distributes-queries' setting. Code in `commit
   1678 <http://wiki.powerdns.com/projects/trac/changeset/1678>`__ and
   beyond. Speeds up Solaris measurably.
-  Cache cleaning code was cleaned up, unified and expanded to cover the
   'negative cache', which used to be cleaned rather bluntly. Code in
   `commit
   1702 <http://wiki.powerdns.com/projects/trac/changeset/1702>`__,
   further tweaks in `commit
   1712 <http://wiki.powerdns.com/projects/trac/changeset/1712>`__,
   spotted by Darren Gamble, Imre Gergely and Christian Kovacic.

Changes between RC1, RC2 and RC3.
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  RC2: Fixed linking on RHEL5/CentOS5, which both ship with a gcc
   compiler that claims to support atomic operations, but doesn't. Code
   in `commit
   1714 <http://wiki.powerdns.com/projects/trac/changeset/1714>`__.
   Spotted by 'Bas' and Imre Gergely.
-  RC2: Negative query cache was configured to grow too large, and was
   not cleaned efficiently. Code in `commit
   1712 <http://wiki.powerdns.com/projects/trac/changeset/1712>`__,
   spotted by Imre Gergely.
-  RC3: Root failed to be renewed automatically, relied on fallback to
   make this happen. Code in `commit
   1716 <http://wiki.powerdns.com/projects/trac/changeset/1716>`__,
   spotted by Detlef Peeters.

Recursor version 3.2
--------------------

Released on the 7th of March 2010.

**Warning**: Lua scripts from version 3.1.7.\* are fully compatible with
version 3.2. However, scripts written for development snapshot releases,
are NOT. Please see `Scripting <recursor/scripting.md>`__ for details!

The 3.2 release is the first major release of the PowerDNS Recursor in a
long time. Partly this is because 3.1.7.\* functioned very well, and
delivered satisfying performance, partly this is because in order to
really move forward, some heavy lifting had to be done.

As always, we are grateful for the large PowerDNS community that is
actively involved in improving the quality of our software, be it by
submitting patches, by testing development versions of our software or
helping debug interesting issues. We specifically want to thank Stefan
Schmidt and Florian Weimer, who both over the years have helped
tremendously in keeping PowerDNS fast, stable and secure.

This version of the PowerDNS Recursor contains a rather novel form of
lock-free multithreading, a situation that comes close to the old
'--fork' trick, but allows the Recursor to fully utilize multiple CPUs,
while delivering unified statistics and operational control.

In effect, this delivers the best of both worlds: near linear scaling,
with almost no administrative overhead.

Compared to 'regular multithreading', whereby threads cooperate more
closely, more memory is used, since each thread maintains its own DNS
cache. However, given the economics, and the relatively limited total
amount of memory needed for high performance, this price is well worth
it.

In practical numbers, over 40,000 queries/second sustained performance
has now been measured by a third party, with a 100.0% packet response
rate. This means that the needs of around 400,000 residential
connections can now be met by a single commodity server.

In addition to the above, the PowerDNS Recursor is now providing
resolver service for many more Internet users than ever before. This has
brought with it 24/7 Service Level Agreements, and 24/7 operational
monitoring by networking personnel at some of the largest
telecommunications companies in the world.

In order to facilitate such operation, more statistics are now provided
that allow the visual verification of proper PowerDNS Recursor
operation. As an example of this there are now graphs that plot how many
queries were dropped by the operating system because of a CPU overload,
plus statistics that can be monitored to determine if the PowerDNS
deployment is under a spoofing attack. All in all, this is a large and
important PowerDNS Release, paving the way for further innovation.

**Note**: This release removes support for the 'fork' multi-processor
option. In addition, the default is now to spawn two threads. This has
been done in such a way that total memory usage will remain identical,
so each thread will use half of the allocated maximum number of cache
entries.

Changes between RC2 and -release
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  'Make install' when an existing configuration file contained a 'fork'
   statement has been fixed. Spotted by Darren Gamble, code in `commit
   1534 <http://wiki.powerdns.com/projects/trac/changeset/1534>`__.
-  Reloading a non-existent allow-from-file caused the control thread to
   stop working. Spotted by Imre Gergely, code in `commit
   1532 <http://wiki.powerdns.com/projects/trac/changeset/1532>`__.
-  Parser got confused by reading en empty line in auth-forward-zones.
   Spotted by Imre Gergely, code in `commit
   1533 <http://wiki.powerdns.com/projects/trac/changeset/1533>`__.
-  David Gavarret discovered undocumented and not-working settings to
   set the owner, group and access modes of the control socket. Code by
   Aki Tuomi and documentation in `commit
   1535 <http://wiki.powerdns.com/projects/trac/changeset/1535>`__.
   Fixup in `commit
   1536 <http://wiki.powerdns.com/projects/trac/changeset/1536>`__ for
   FreeBSD as found by Ralf van der Enden.
-  Tiny improvement possibly solving an issue on Solaris 10's completion
   port event multiplexer (`commit
   1537 <http://wiki.powerdns.com/projects/trac/changeset/1537>`__).

Changes between RC1 and RC2
^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Compilation on Solaris 10 has been fixed (various patchlevels had
   different issues), code in `commit
   1522 <http://wiki.powerdns.com/projects/trac/changeset/1522>`__.
-  Compatibility with CentOS4/RHEL4 has been restored, the gcc and glibc
   versions shipped with this distribution contain a Thread Local
   Storage bug which we now work around. Thanks to Darren Gamble and
   Imre Gergely for debugging this issue, code in `commit
   1527 <http://wiki.powerdns.com/projects/trac/changeset/1527>`__.
-  A failed setuid operation, because of misconfiguration, would result
   in a crash instead of an error message. Fixed in `commit
   1523 <http://wiki.powerdns.com/projects/trac/changeset/1523>`__.
-  Imre Gergely discovered that PowerDNS was doing spurious root
   repriming when invalidating nssets. Fixed in `commit
   1531 <http://wiki.powerdns.com/projects/trac/changeset/1531>`__.
-  Imre Gergely discovered our rrd graphs had not been changed for the
   new multithreaded world, and did not allow scaling beyond 200% cpu
   use. In addition, CPU usage graphs did not add up correctly.
   Implemented in `commit
   1524 <http://wiki.powerdns.com/projects/trac/changeset/1524>`__.
-  Andreas Jakum discovered the description of 'max-packetcache-entries'
   and 'forward-zones-recurse' was wrong in the output of '--help' and
   '--config'. In addition, some stray backup files made it into the RC1
   release. Addressed in `commit
   1529 <http://wiki.powerdns.com/projects/trac/changeset/1529>`__. Full
   release notes follow, including some overlap with the incremental
   release notes above. Improvements
-  Multithreading, allowing near linear scaling to multiple CPUs or
   cores. Configured using 'threads=' (many commits). This also
   deprecates the '--fork' option.
-  Added ability to read a configuration item of a running PowerDNS
   Recursor using 'rec\_control get-parameter' (`commit
   1243 <http://wiki.powerdns.com/projects/trac/changeset/1243>`__),
   suggested by Wouter de Jong.
-  Added ability to read all statistics in one go of a running PowerDNS
   Recursor using 'rec\_control get-all' (`commit
   1496 <http://wiki.powerdns.com/projects/trac/changeset/1496>`__),
   suggested by Michael Renner.
-  Speedups in packet generation (Commits
   `1258 <http://wiki.powerdns.com/projects/trac/changeset/1258>`__,
   `1259 <http://wiki.powerdns.com/projects/trac/changeset/1259>`__,
   `1262 <http://wiki.powerdns.com/projects/trac/changeset/1262>`__)
-  TCP deferred accept() filter is turned on again for slight DoS
   protection. Code in `commit
   1414 <http://wiki.powerdns.com/projects/trac/changeset/1414>`__.
-  PowerDNS Recursor can now do TCP/IP queries to remote IPv6 addresses
   (`commit
   1412 <http://wiki.powerdns.com/projects/trac/changeset/1412>`__).
-  Solaris 9 '/dev/poll' support added, Solaris 8 now deprecated.
   Changes in `commit
   1421 <http://wiki.powerdns.com/projects/trac/changeset/1421>`__,
   `commit
   1422 <http://wiki.powerdns.com/projects/trac/changeset/1422>`__,
   `commit
   1424 <http://wiki.powerdns.com/projects/trac/changeset/1424>`__,
   `commit
   1413 <http://wiki.powerdns.com/projects/trac/changeset/1413>`__.
-  Lua functions can now also see the address \_to\_ which a question
   was sent, using getlocaladdress(). Implemented in `commit
   1309 <http://wiki.powerdns.com/projects/trac/changeset/1309>`__ and
   `commit
   1315 <http://wiki.powerdns.com/projects/trac/changeset/1315>`__.
-  Maximum cache sizes now default to a sensible value. Suggested by
   Roel van der Made, implemented in `commit
   1354 <http://wiki.powerdns.com/projects/trac/changeset/1354>`__.
-  Domains can now be forwarded to IPv6 addresses too, using either ::1
   syntax or [::1]:25. Thanks to Wijnand Modderman for discovering this
   issue, fixed in `commit
   1349 <http://wiki.powerdns.com/projects/trac/changeset/1349>`__.
-  Lua scripts can now load libraries at runtime, for example to
   calculate md5 hashes. Code by Winfried Angele in `commit
   1405 <http://wiki.powerdns.com/projects/trac/changeset/1405>`__.
-  Periodic statistics output now includes average queries per second,
   as well as packet cache numbers (`commit
   1493 <http://wiki.powerdns.com/projects/trac/changeset/1493>`__).
-  New metrics are available for graphing, plus added to the default
   graphs (`commit
   1495 <http://wiki.powerdns.com/projects/trac/changeset/1495>`__,
   `commit
   1498 <http://wiki.powerdns.com/projects/trac/changeset/1498>`__,
   `commit
   1503 <http://wiki.powerdns.com/projects/trac/changeset/1503>`__)
-  Fix errors/crashes on more recent versions of Solaris 10, where the
   ports functions could return ENOENT under some circumstances.
   Reported and debugged by Jan Gyselinck, fixed in `commit
   1372 <http://wiki.powerdns.com/projects/trac/changeset/1372>`__.

New features
^^^^^^^^^^^^

-  Add pdnslog() function for Lua scripts, so errors or other messages
   can be logged properly.
-  New settings to set the owner, group and access modes of the control
   socket (socket-owner, socket-group, socket-mode). Code by Aki Tuomi
   and documentation in `commit
   1535 <http://wiki.powerdns.com/projects/trac/changeset/1535>`__.
   Fixup in `commit
   1536 <http://wiki.powerdns.com/projects/trac/changeset/1536>`__ for
   FreeBSD as found by Ralf van der Enden.
-  rec\_control now accepts a --timeout parameter, which can be useful
   when reloading huge Lua scripts. Implemented in `commit
   1366 <http://wiki.powerdns.com/projects/trac/changeset/1366>`__.
-  Domains can now be forwarded with the 'recursion-desired' bit on or
   off, using either **forward-zones-recurse** or by prefixing the name
   of a zone with a '+' in **forward-zones-file**. Feature suggested by
   Darren Gamble, implemented in `commit
   1451 <http://wiki.powerdns.com/projects/trac/changeset/1451>`__.
-  Access control lists can now be reloaded at runtime (implemented in
   `commit
   1457 <http://wiki.powerdns.com/projects/trac/changeset/1457>`__).
-  PowerDNS Recursor can now use a pool of query-local-addresses to
   further increase resilience against spoofing. Suggested by Ad Spelt,
   implemented in `commit
   1426 <http://wiki.powerdns.com/projects/trac/changeset/1426>`__.
-  PowerDNS Recursor now also has a packet cache, greatly speeding up
   operations. Implemented in `commit
   1426 <http://wiki.powerdns.com/projects/trac/changeset/1426>`__,
   `commit
   1433 <http://wiki.powerdns.com/projects/trac/changeset/1433>`__ and
   further.
-  Cache can be limited in how long it maximally stores records, for
   BIND compatibility (TTL limiting), by setting **max-cache-ttl**.Idea
   by Winfried Angele, implemented in `commit
   1438 <http://wiki.powerdns.com/projects/trac/changeset/1438>`__.
-  Cache cleaning turned out to be scanning more of the cache than
   necessary for cache maintenance. In addition, far more frequent but
   smaller cache cleanups improve responsiveness. Thanks to Winfried
   Angele for discovering this issue. (commits
   `1501 <http://wiki.powerdns.com/projects/trac/changeset/1501>`__,
   `1507 <http://wiki.powerdns.com/projects/trac/changeset/1507>`__)
-  Performance graphs enhanced with separate CPU load and cache
   effectiveness plots, plus display of various overload situations
   (commits
   `1503 <http://wiki.powerdns.com/projects/trac/changeset/1503>`__)

Compiler/Operating system/Library updates
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  PowerDNS Recursor can now compile against newer versions of Boost
   (verified up to and including 1.42.0). Reported & fixed by Darix in
   `commit
   1274 <http://wiki.powerdns.com/projects/trac/changeset/1274>`__.
   Further fixes in `commit
   1275 <http://wiki.powerdns.com/projects/trac/changeset/1275>`__,
   `commit
   1276 <http://wiki.powerdns.com/projects/trac/changeset/1276>`__,
   `commit
   1277 <http://wiki.powerdns.com/projects/trac/changeset/1277>`__,
   `commit
   1283 <http://wiki.powerdns.com/projects/trac/changeset/1283>`__.
-  Fix compatibility with newer versions of GCC (closes ticket `ticket
   227 <https://github.com/PowerDNS/pdns/issues/227>`__, spotted by
   Ruben Kerkhof, code in `commit
   1345 <http://wiki.powerdns.com/projects/trac/changeset/1345>`__, more
   fixes in commit
   `1394 <http://wiki.powerdns.com/projects/trac/changeset/1394>`__,
   `1416 <http://wiki.powerdns.com/projects/trac/changeset/1416>`__,
   `1440 <http://wiki.powerdns.com/projects/trac/changeset/1440>`__).
-  Rrdtool update graph is now compatible with FreeBSD out of the box.
   Thanks to Bryan Seitz (`commit
   1517 <http://wiki.powerdns.com/projects/trac/changeset/1517>`__).
-  Fix up Makefile for older versions of Make (`commit
   1229 <http://wiki.powerdns.com/projects/trac/changeset/1229>`__).
-  Solaris compilation improvements (out of the box, no handwork
   needed).
-  Solaris 9 MTasker compilation fixes, as suggested by John Levon.
   Changes in `commit
   1431 <http://wiki.powerdns.com/projects/trac/changeset/1431>`__.

Bug fixes
^^^^^^^^^

-  Under rare circumstances, the recursor could crash on 64 bit Linux
   systems running glibc 2.7, as found in Debian Lenny. These
   circumstances became a lot less rare for the 3.2 release. Discovered
   by Andreas Jakum and debugged by #powerdns, fix in `commit
   1519 <http://wiki.powerdns.com/projects/trac/changeset/1519>`__.
-  Imre Gergely discovered that PowerDNS was doing spurious root
   repriming when invalidating nssets. Fixed in `commit
   1531 <http://wiki.powerdns.com/projects/trac/changeset/1531>`__.
-  Configuration parser is now resistant against trailing tabs and other
   whitespace (`commit
   1242 <http://wiki.powerdns.com/projects/trac/changeset/1242>`__)
-  Fix typo in a Lua error message. Close `ticket
   210 <https://github.com/PowerDNS/pdns/issues/210>`__, as reported by
   Stefan Schmidt (`commit
   1319 <http://wiki.powerdns.com/projects/trac/changeset/1319>`__).
-  Profiled-build instructions were broken, discovered & fixes suggested
   by Stefan Schmidt. `ticket
   239 <https://github.com/PowerDNS/pdns/issues/239>`__, fix in `commit
   1462 <http://wiki.powerdns.com/projects/trac/changeset/1462>`__.
-  Fix up duplicate SOA from a remote authoritative server from showing
   up in our output (`commit
   1475 <http://wiki.powerdns.com/projects/trac/changeset/1475>`__).
-  All security fixes from 3.1.7.2 are included.
-  Under highly exceptional circumstances on FreeBSD the PowerDNS
   Recursor could crash because of a TCP/IP error. Reported and fixed by
   Andrei Poelov in `ticket
   192 <https://github.com/PowerDNS/pdns/issues/192>`__, fixed in
   `commit
   1280 <http://wiki.powerdns.com/projects/trac/changeset/1280>`__.
-  PowerDNS Recursor can be a root-server again. Error spotted by the
   ever vigilant Darren Gamble (ticket
   `229 <https://github.com/PowerDNS/pdns/issues/229>`__), fix in
   `commit
   1458 <http://wiki.powerdns.com/projects/trac/changeset/1458>`__.
-  Rare TCP/IP errors no longer lead to PowerDNS Recursor logging errors
   or becoming confused. Debugged by Josh Berry of Plusnet PLC. Code in
   `commit
   1457 <http://wiki.powerdns.com/projects/trac/changeset/1457>`__.
-  Do not hammer parent servers in case child zones are misconfigured,
   requery at most once every 10 seconds. Reported & investigated by
   Stefan Schmidt and Andreas Jakum, fixed in `commit
   1265 <http://wiki.powerdns.com/projects/trac/changeset/1265>`__.
-  Properly process answers from remote authoritative servers that send
   error answers without including the original question (`commit
   1329 <http://wiki.powerdns.com/projects/trac/changeset/1329>`__,
   `commit
   1327 <http://wiki.powerdns.com/projects/trac/changeset/1327>`__).
-  No longer spontaneously turn on 'export-etc-hosts' after reloading
   zones. Discovered by Paul Cairney, reported in `ticket
   225 <https://github.com/PowerDNS/pdns/issues/225>`__, addressed in
   `commit
   1348 <http://wiki.powerdns.com/projects/trac/changeset/1348>`__.
-  Very abrupt server failure of large numbers of high-volume
   authoritative servers could trigger an out of memory situation.
   Addressed in `commit
   1505 <http://wiki.powerdns.com/projects/trac/changeset/1505>`__.
-  Make timeouts for queries to remote authoritative servers
   configurable with millisecond granularity. In addition, the old code
   turned out to consider the timeout expired when the integral number
   of seconds since 1970 increased by 1 - which *on average* is after
   500ms. This might have caused spurious timeouts! New default timeout
   is 1500ms. See **network-timeout** setting for more details. Code in
   `commit
   1402 <http://wiki.powerdns.com/projects/trac/changeset/1402>`__.

Recursor version 3.1.7.2
------------------------

Released on the 6th of January 2010.

This release consist of a number of vital security updates. These
updates address issues that can in all likelihood lead to a full system
compromise. In addition, it is possible for third parties to pollute
your cache with dangerous data, exposing your users to possible harm.

This version has been well tested, and at the time of this release is
already powering millions of internet connections, and should therefore
be a risk-free upgrade from 3.1.7.1 or any earlier version of the
PowerDNS Recursor.

All known versions of the PowerDNS Recursor are impacted to a greater or
lesser extent, so an immediate update is advised.

These vulnerabilities were discovered by a third party that can't yet be
named, but who we thank for their contribution to a more secure PowerDNS
Recursor.

For more information, see :doc:`PowerDNS Security Advisory
2010-01 <../security-advisories/powerdns-advisory-2010-01>` and :doc:`PowerDNS
Security Advisory 2010-02 <../security-advisories/powerdns-advisory-2010-02>`.

Recursor version 3.1.7.1
------------------------

Released on the 2nd of August 2009.

This release consists entirely of fixes for tiny bugs that have been
reported over the past year. In addition, compatibility has been
restored with the latest versions of the gcc compiler and the 'boost'
libraries.

No features have been added, but some debugging code that very slightly
impacted performance (and polluted the console when operating in the
foreground) has been removed.

FreeBSD users may want to upgrade because of a very remote chance of
3.1.7 and previous crashing once every few years. For other operators
not currently experiencing problems, there is no reason to upgrade.

-  Improved error messages when parsing zones for authoritative serving
   (`commit
   1235 <http://wiki.powerdns.com/projects/trac/changeset/1235>`__).
-  Better resilience against whitespace in configuration (changesets
   `1237 <http://wiki.powerdns.com/projects/trac/changeset/1237>`__,
   `1240 <http://wiki.powerdns.com/projects/trac/changeset/1240>`__,
   `1242 <http://wiki.powerdns.com/projects/trac/changeset/1242>`__)
-  Slight performance increase (`commit
   1378 <http://wiki.powerdns.com/projects/trac/changeset/1378>`__)
-  Fix rare case where timeouts were not being reported to the right
   query-thread (`commit
   1260 <http://wiki.powerdns.com/projects/trac/changeset/1260>`__)
-  Fix compilation against newer versions of the Boost C++ libraries
   (`commit
   1381 <http://wiki.powerdns.com/projects/trac/changeset/1381>`__)
-  Close very rare issue with TCP/IP close reporting ECONNRESET on
   FreeBSD. Reported by Andrei Poelov in `ticket
   192 <https://github.com/PowerDNS/pdns/issues/192>`__.
-  Silence debugging output (`commit
   1286 <http://wiki.powerdns.com/projects/trac/changeset/1286>`__).
-  Fix compilation against newer versions of gcc (`commit
   1384 <http://wiki.powerdns.com/projects/trac/changeset/1384>`__)
-  No longer set export-etc-hosts to 'on' on reload-zones. Discovered by
   Paul Cairney, closes `ticket
   225 <https://github.com/PowerDNS/pdns/issues/225>`__.
-  Sane default for the maximum cache size in the Recursor, suggested by
   Roel van der Made (`commit
   1354 <http://wiki.powerdns.com/projects/trac/changeset/1354>`__).
-  No longer exit because of the changed behaviour of the Solaris
   'completion ports' in more recent versions of Solaris. Fix in `commit
   1372 <http://wiki.powerdns.com/projects/trac/changeset/1372>`__,
   reported by Jan Gyselinck.

Recursor version 3.1.7
----------------------

Released the 25th of June 2008.

This version contains powerful scripting abilities, allowing operators
to modify DNS responses in many interesting ways. Among other things,
these abilities can be used to filter out malware domains, to perform
load balancing, to comply with legal and other requirements and finally,
to implement 'NXDOMAIN' redirection.

It is hoped that the addition of Lua scripting will enable responsible
DNS modification for those that need it.

For more details about the Lua scripting, which can be modified, loaded
and unloaded at runtime, see `Scripting <recursor/scripting.md>`__. Many
thanks are due to the #lua irc channel, for excellent near-realtime Lua
support. In addition, a number of PowerDNS users have been
enthusiastically testing prereleases of the scripting support, and have
found and solved many issues.

In addition, 3.1.7 fixes a number of bugs

-  In 3.1.5 and 3.1.6, an authoritative server could continue to renew
   its authority, even though a domain had been delegated to other
   servers in the meantime.

   In the rare cases where this happened, and the old servers were not
   shut down, the observed effect is that users were fed outdated data.
   Bug spotted and analysed by Darren Gamble, fix in `commit
   1182 <http://wiki.powerdns.com/projects/trac/changeset/1182>`__ and
   `commit
   1183 <http://wiki.powerdns.com/projects/trac/changeset/1183>`__.

-  Thanks to long time PowerDNS contributor Stefan Arentz, for the first
   time, Mac OS X 10.5 users can compile and run the PowerDNS Recursor!
   Patch in `commit
   1185 <http://wiki.powerdns.com/projects/trac/changeset/1185>`__.
-  Sten Spans spotted that for outgoing TCP/IP queries, the
   **query-local-address** setting was not honored. Fixed in `commit
   1190 <http://wiki.powerdns.com/projects/trac/changeset/1190>`__.
-  **rec\_control wipe-cache** now also wipes domains from the negative
   cache, hurrying up the expiry of negatively cached records. Suggested
   by Simon Kirby, implemented in `commit
   1204 <http://wiki.powerdns.com/projects/trac/changeset/1204>`__.
-  When a forwarder server is configured for a domain, using the
   **forward-zones** setting, this server IP address was filtered using
   the **dont-query** setting, which is generally not what is desired:
   the server to which queries are forwarded will often live in private
   IP space, and the operator should be trusted to know what he is
   doing. Reported and argued by Simon Kirby, fix in `commit
   1211 <http://wiki.powerdns.com/projects/trac/changeset/1211>`__.
-  Marcus Rueckert of OpenSUSE reported that very recent gcc versions
   emitted a (correct) warning on an overly complicated line in
   syncres.cc, fixed in `commit
   1189 <http://wiki.powerdns.com/projects/trac/changeset/1189>`__.
-  Stefan Schmidt discovered that the netmask matching code, used by the
   new Lua scripts, but also by all other parts of PowerDNS, had
   problems with explicit '/32' matches. Fixed in `commit
   1205 <http://wiki.powerdns.com/projects/trac/changeset/1205>`__.

Recursor version 3.1.6
----------------------

Released on the 1st of May 2008.

This version fixes two important problems, each on its own important
enough to justify a quick upgrade.

-  Version 3.1.5 had problems resolving several slightly misconfigured
   domains, including for a time 'juniper.net'. Nameserver timeouts were
   not being processed correctly, leading PowerDNS to not update the
   internal clock, which in turn meant that any queries immediately
   following an error would time out as well. Because of retries, this
   would usually not be a problem except on very busy servers, for
   domains with different nameservers at different levels of the
   DNS-hierarchy, like 'juniper.net'.

   This issue was fixed rapidly because of the help of
   `XS4ALL <http://www.xs4all.nl>`__ (Eric Veldhuyzen, Kai Storbeck),
   Brad Dameron and Kees Monshouwer. Fix in `commit
   1178 <http://wiki.powerdns.com/projects/trac/changeset/1178>`__.

-  The new high-quality random generator was not used for all random
   numbers, especially in source port selection. This means that 3.1.5
   is still a lot more secure than 3.1.4 was, and its algorithms more
   secure than most other nameservers, but it also means 3.1.5 is not as
   secure as it could be. A quick upgrade is recommended. Discovered by
   Thomas Biege of Novell (SUSE), fixed in `commit
   1179 <http://wiki.powerdns.com/projects/trac/changeset/1179>`__.

Recursor version 3.1.5
----------------------

Released on the 31st of March 2008.

Much like 3.1.4, this release does not add a lot of major features.
Instead, performance has been improved significantly (estimated at
around 20%), and many rare and not so rare issues were addressed.
Multi-part TXT records now work as expected - the only significant
functional bug found in 15 months. One of the oldest feature requests
was fulfilled: version 3.1.5 can finally forward queries for designated
domains to multiple servers, on differing port numbers if needed.
Previously only one forwarder address was supported. This lack held back
a number of migrations to PowerDNS.

We would like to thank Amit Klein of Trusteer for bringing a serious
vulnerability to our attention which would enable a smart attacker to
'spoof' previous versions of the PowerDNS Recursor into accepting
possibly malicious data.

Details can be found on `this Trusteer
page <http://www.trusteer.com/docs/powerdnsrecursor.html>`__.

It is recommended that all users of the PowerDNS Recursor upgrade to
3.1.5 as soon as practicable, while we simultaneously note that busy
servers are less susceptible to the attack, but not immune.

The PowerDNS Security Advisory can be found in :doc:`PowerDNS Security
Advisory 2008-01 <../security-advisories/powerdns-advisory-2008-01>`.

This version can properly benefit from all IPv4 and IPv6 addresses in
use at the root-servers as of early February 2008. In order to implement
this, changes were made to how the Recursor deals internally with A and
AAAA queries for nameservers, see below for more details.

Additionally, newer releases of the G++ compiler required some fixes
(see `ticket 173 <https://github.com/PowerDNS/pdns/issues/173>`__).

This release was made possible by the help of Wichert Akkerman, Winfried
Angele, Arnoud Bakker (Fox-IT), Niels Bakker (no relation!), Leo Baltus
(Nederlandse Publieke Omroep), Marco Davids (SIDN), David Gavarret (Neuf
Cegetel), Peter Gervai, Marcus Goller (UPC), Matti Hiljanen
(Saunalahti/Elisa), Ruben Kerkhof, Alex Kiernan, Amit Klein (Trusteer),
Kenneth Marshall (Rice University), Thomas Rietz, Marcus Rueckert
(OpenSUSE), Augie Schwer (Sonix), Sten Spans (Bit), Stefan Schmidt
(Freenet), Kai Storbeck (xs4all), Alex Trull, Andrew Turnbull (No Wires)
and Aaron Thompson, and many more who filed bugs anonymously, or who we
forgot to mention.

Security related issues
^^^^^^^^^^^^^^^^^^^^^^^

-  Amit Klein has informed us that System random generator output can be
   predicted based on its past behaviour, allowing a smart attacker to
   'spoof' our nameserver. Full details in :doc:`PowerDNS Security Advisory
   2008-01 <../security-advisories/powerdns-advisory-2008-01>`.
-  The Recursor will by default no longer query private-space
   nameservers. This closes a slight security risk and simultaneously
   improves performance and stability. For more information, see
   **dont-query** in `pdns\_recursor
   settings <recursor/settings.md#dont-query>`__. Implemented in `commit
   923 <http://wiki.powerdns.com/projects/trac/changeset/923>`__.
-  Applied fix for `ticket
   110 <https://github.com/PowerDNS/pdns/issues/110>`__ ('PowerDNS
   should change directory to '/' in chroot), implemented in `commit
   944 <http://wiki.powerdns.com/projects/trac/changeset/944>`__.

Performance
^^^^^^^^^^^

-  The DNS packet writing and parsing infrastructure performance was
   improved in several ways, see commits
   `925 <http://wiki.powerdns.com/projects/trac/changeset/925>`__,
   `926 <http://wiki.powerdns.com/projects/trac/changeset/926>`__,
   `928 <http://wiki.powerdns.com/projects/trac/changeset/928>`__,
   `931 <http://wiki.powerdns.com/projects/trac/changeset/931>`__,
   `1021 <http://wiki.powerdns.com/projects/trac/changeset/1021>`__,
   `1050 <http://wiki.powerdns.com/projects/trac/changeset/1050>`__.
-  Remove multithreading overhead from the Recursor (`commit
   999 <http://wiki.powerdns.com/projects/trac/changeset/999>`__).

Bug fixes
^^^^^^^^^

-  Built-in authoritative server now properly derives the TTL from the
   SOA record if not specified. Implemented in `commit
   1165 <http://wiki.powerdns.com/projects/trac/changeset/1165>`__.
   Additionally, even when TTL was specified for the built-in
   authoritative server, it was ignored. Reported by Stefan Schmidt,
   closing `ticket 147 <https://github.com/PowerDNS/pdns/issues/147>`__.
-  Empty TXT record components can now be served. Implemented in `commit
   1166 <http://wiki.powerdns.com/projects/trac/changeset/1166>`__,
   closing `ticket 178 <https://github.com/PowerDNS/pdns/issues/178>`__.
   Spotted by Matti Hiljanen.
-  The Recursor would not properly override old data with new, sometimes
   serving old and new data concurrently. Fixed in `commit
   1137 <http://wiki.powerdns.com/projects/trac/changeset/1137>`__.
-  SOA records with embedded carriage-return characters are now parsed
   correctly. Implemented in `commit
   1167 <http://wiki.powerdns.com/projects/trac/changeset/1167>`__,
   closing `ticket 162 <https://github.com/PowerDNS/pdns/issues/162>`__.
-  Some routing conditions could cause UDP connected sockets to generate
   an error which PowerDNS did not deal with properly, leading to a
   leaked file descriptor. As these run out over time, the recursor
   could crash. This would also happen for IPv6 queries on a host with
   no IPv6 connectivity. Thanks to Kai of xs4all and Wichert Akkerman
   for reporting this issue. Fix in `commit
   1133 <http://wiki.powerdns.com/projects/trac/changeset/1133>`__.
-  Empty unknown record types can now be stored without generating a
   scary error (`commit
   1129 <http://wiki.powerdns.com/projects/trac/changeset/1129>`__)
-  Applied fix for `ticket
   111 <https://github.com/PowerDNS/pdns/issues/111>`__, `ticket
   112 <https://github.com/PowerDNS/pdns/issues/112>`__ and `ticket
   153 <https://github.com/PowerDNS/pdns/issues/153>`__ - large
   (multipart) TXT records are now retrieved and served properly. Fix in
   `commit
   996 <http://wiki.powerdns.com/projects/trac/changeset/996>`__.
-  Solaris compilation instructions in Recursor documentation were
   wrong, leading to an instant crash on startup. Luckily nobody reads
   the documentation, except for Marcus Goller who found the error.
   Fixed in `commit
   1124 <http://wiki.powerdns.com/projects/trac/changeset/1124>`__.
-  On Solaris, finally fix the issue where queries get distributed
   strangely over CPUs, or not get distributed at all. Much debugging
   and analysing performed by Alex Kiernan, who also supplied fixes.
   Implemented in `commit
   1091 <http://wiki.powerdns.com/projects/trac/changeset/1091>`__,
   `commit
   1093 <http://wiki.powerdns.com/projects/trac/changeset/1093>`__.
-  Various fixes for modern G++ versions, most spotted by Marcus
   Rueckert (commits
   `964 <http://wiki.powerdns.com/projects/trac/changeset/964>`__,
   `965 <http://wiki.powerdns.com/projects/trac/changeset/965>`__,
   `1028 <http://wiki.powerdns.com/projects/trac/changeset/1028>`__,
   `1052 <http://wiki.powerdns.com/projects/trac/changeset/1052>`__),
   and Ruben Kerkhof (`commit
   1136 <http://wiki.powerdns.com/projects/trac/changeset/1136>`__,
   closing `ticket
   175 <https://github.com/PowerDNS/pdns/issues/175>`__).
-  Recursor would not properly clean up pidfile and control socket,
   closing `ticket 120 <https://github.com/PowerDNS/pdns/issues/120>`__,
   code in `commit
   988 <http://wiki.powerdns.com/projects/trac/changeset/988>`__,
   `commit
   1098 <http://wiki.powerdns.com/projects/trac/changeset/1098>`__ (part
   of fix by Matti Hiljanen, spotted by Leo Baltus)
-  Recursor can now serve multi-line records from its limited
   authoritative server (`commit
   1014 <http://wiki.powerdns.com/projects/trac/changeset/1014>`__).
-  When parsing zones, the 'm' time specification stands for minutes,
   not months! Closing Debian bug 406462 (`commit
   1026 <http://wiki.powerdns.com/projects/trac/changeset/1026>`__)
-  Authoritative zone parser did not support '@' in the content of
   records. Spotted by Marco Davids, fixed in `commit
   1030 <http://wiki.powerdns.com/projects/trac/changeset/1030>`__.
-  Authoritative zone parser could be confused by trailing TABs on
   record lines (`commit
   1062 <http://wiki.powerdns.com/projects/trac/changeset/1062>`__).
-  EINTR error code could block entire server if received at the wrong
   time. Spotted by Arnoud Bakker, fix in `commit
   1059 <http://wiki.powerdns.com/projects/trac/changeset/1059>`__.
-  Fix crash on NetBSD on Alpha CPUs, might improve startup behaviour on
   empty caches on other architectures as well (`commit
   1061 <http://wiki.powerdns.com/projects/trac/changeset/1061>`__).
-  Outbound TCP queries were being performed sub-optimally because of an
   interaction with the 'MPlexer'. Fixes in `commit
   1115 <http://wiki.powerdns.com/projects/trac/changeset/1115>`__,
   `commit
   1116 <http://wiki.powerdns.com/projects/trac/changeset/1116>`__.

New features
^^^^^^^^^^^^

-  Implemented **rec\_control** command **get uptime**, as suggested by
   Niels Bakker (`commit
   935 <http://wiki.powerdns.com/projects/trac/changeset/935>`__). Added
   to default rrdtool scripts in `commit
   940 <http://wiki.powerdns.com/projects/trac/changeset/940>`__.
-  The Recursor Authoritative component, meant for having the Recursor
   serve some zones authoritatively, now supports $INCLUDE and
   $GENERATE. Implemented in `commit
   951 <http://wiki.powerdns.com/projects/trac/changeset/951>`__ and
   `commit
   952 <http://wiki.powerdns.com/projects/trac/changeset/952>`__,
   `commit 967 <http://wiki.powerdns.com/projects/trac/changeset/967>`__
   (discovered by Thomas Rietz),
-  Implemented **forward-zones-file** option in order to support larger
   amounts of zones which should be forwarded to another nameserver
   (`commit
   963 <http://wiki.powerdns.com/projects/trac/changeset/963>`__).
-  Both **forward-zones** and **forward-zones-file** can now specify
   multiple forwarders per domain, implemented in `commit
   1168 <http://wiki.powerdns.com/projects/trac/changeset/1168>`__,
   closing `ticket 81 <https://github.com/PowerDNS/pdns/issues/81>`__.
   Additionally, both these settings can also specify non-standard port
   numbers, as suggested in ticket `ticket
   122 <https://github.com/PowerDNS/pdns/issues/122>`__. Patch authored
   by Aaron Thompson, with additional work by Augie Schwer.
-  Sten Spans contributed **allow-from-file**, implemented in `commit
   1150 <http://wiki.powerdns.com/projects/trac/changeset/1150>`__. This
   feature allows the Recursor to read access rules from a (large) file.

General improvements
^^^^^^^^^^^^^^^^^^^^

-  Ruben Kerkhof fixed up weird permission bits as well as our SGML
   documentation code in `commit
   936 <http://wiki.powerdns.com/projects/trac/changeset/936>`__ and
   `commit
   937 <http://wiki.powerdns.com/projects/trac/changeset/937>`__.
-  Full IPv6 parity. If configured to use IPv6 for outgoing queries
   (using **query-local-address6=::0** for example), IPv6 and IPv4
   addresses are finally treated 100% identically, instead of 'mostly'.
   This feature is implemented using 'ANY' queries to find A and AAAA
   addresses in one query, which is a new approach. Treat with caution.
-  Now perform EDNS0 root refreshing queries, so as to benefit from all
   returned addresses. Relevant since early February 2008 when the
   root-servers started to respond with IPv6 addresses, which made the
   default non-EDNS0 maximum packet length reply no longer contain all
   records. Implemented in `commit
   1130 <http://wiki.powerdns.com/projects/trac/changeset/1130>`__.
   Thanks to dns-operations AT mail.oarc.isc.org for quick suggestions
   on how to deal with this change.
-  **rec\_control** now has a timeout in case the Recursor does not
   respond. Implemented in `commit
   945 <http://wiki.powerdns.com/projects/trac/changeset/945>`__.
-  (Error) messages are now logged with saner priorities (`commit
   955 <http://wiki.powerdns.com/projects/trac/changeset/955>`__).
-  Outbound query IP interface stemmed from 1997 (!) and was in dire
   need of a cleanup (`commit
   1117 <http://wiki.powerdns.com/projects/trac/changeset/1117>`__).
-  L.ROOT-SERVERS.NET moved (`commit
   1118 <http://wiki.powerdns.com/projects/trac/changeset/1118>`__).

Recursor version 3.1.4
----------------------

Released the 13th of November 2006.

This release contains almost no new features, but consists mostly of
minor and major bug fixes. It also addresses two major security issues,
which makes this release a highly recommended upgrade.

Security issues
^^^^^^^^^^^^^^^

-  Large TCP questions followed by garbage could cause the recursor to
   crash. This critical security issue has been assigned CVE-2006-4251,
   and is fixed in `commit
   915 <http://wiki.powerdns.com/projects/trac/changeset/915>`__. More
   information can be found in :doc:`“PowerDNS Security Advisory
   2006-01: Malformed TCP queries can lead to a buffer overflow which
   might be exploitable” <../security-advisories/powerdns-advisory-2006-01>`.
-  CNAME loops with zero second TTLs could cause crashes in some
   conditions. These loops could be constructed by malicious parties,
   making this issue a potential denial of service attack. This security
   issue has been assigned CVE-2006-4252 and is fixed by `commit
   919 <http://wiki.powerdns.com/projects/trac/changeset/919>`__. More
   information can be found in :doc:`“PowerDNS Security Advisory
   2006-02: Zero second CNAME TTLs can make PowerDNS exhaust allocated
   stack space, and crash” <../security-advisories/powerdns-advisory-2006-02>`.
   Many thanks to David Gavarret for helping pin down this problem.

Bugs
^^^^

-  On certain error conditions, PowerDNS would neglect to close a
   socket, which might therefore eventually run out. Spotted by Stefan
   Schmidt, fixed in commits
   `892 <http://wiki.powerdns.com/projects/trac/changeset/892>`__,
   `897 <http://wiki.powerdns.com/projects/trac/changeset/897>`__,
   `899 <http://wiki.powerdns.com/projects/trac/changeset/899>`__.
-  Some nameservers (including PowerDNS in rare circumstances) emit a
   SOA record in the authority section. The recursor mistakenly
   interpreted this as an authoritative "NXRRSET". Spotted by Bryan
   Seitz, fixed in `commit
   893 <http://wiki.powerdns.com/projects/trac/changeset/893>`__.
-  In some circumstances, PowerDNS could end up with a useless (not
   working, or no longer working) set of nameserver records for a
   domain. This release contains logic to invalidate such broken NSSETs,
   without overloading authoritative servers. This problem had
   previously been spotted by Bryan Seitz, 'Cerb' and Darren Gamble.
   Invalidations of NSSETs can be plotted using the
   "nsset-invalidations" metric, available through **rec\_control get**.
   Implemented in `commit
   896 <http://wiki.powerdns.com/projects/trac/changeset/896>`__ and
   `commit
   901 <http://wiki.powerdns.com/projects/trac/changeset/901>`__.
-  PowerDNS could crash while dumping the cache using **rec\_control
   dump-cache**. Reported by Wouter of WideXS and Stefan Schmidt and
   many others, fixed in `commit
   900 <http://wiki.powerdns.com/projects/trac/changeset/900>`__.
-  Under rare circumstances (depleted TCP buffers), PowerDNS might send
   out incomplete questions to remote servers. Additionally, on
   big-endian systems (non-Intel and non-AMD generally), sending out
   large TCP answers questions would not work at all, and possibly
   crash. Brought to our attention by David Gavarret, fixed in `commit
   903 <http://wiki.powerdns.com/projects/trac/changeset/903>`__.
-  The recursor contained the potential for a dead-lock processing an
   invalid domain name. It is not known how this might be triggered, but
   it has been observed by 'Cerb' on #powerdns. Several dead-locks where
   PowerDNS consumed all CPU, but did not answer questions, have been
   reported in the past few months. These might be fixed by `commit
   904 <http://wiki.powerdns.com/projects/trac/changeset/904>`__.
-  IPv6 'allow-from' matching had problems with the least significant
   bits, sometimes allowing disallowed addresses, but mostly disallowing
   allowed addresses. Spotted by Wouter from WideXS, fixed in `commit
   916 <http://wiki.powerdns.com/projects/trac/changeset/916>`__.

Improvements
^^^^^^^^^^^^

-  PowerDNS has support to drop answers from so called 'delegation only'
   zones. A statistic ("dlg-only-drops") is now available to plot how
   often this happens. Implemented in `commit
   890 <http://wiki.powerdns.com/projects/trac/changeset/890>`__.
-  Hint-file parameter was mistakenly named "hints-file" in the
   documentation. Spotted by my Marco Davids, fixed in `commit
   898 <http://wiki.powerdns.com/projects/trac/changeset/898>`__.
-  **rec\_control quit** should be near instantaneous now, as it no
   longer meticulously cleans up memory before exiting. Problem spotted
   by Darren Gamble, fixed in `commit
   914 <http://wiki.powerdns.com/projects/trac/changeset/914>`__,
   closing `ticket 84 <https://github.com/PowerDNS/pdns/issues/84>`__.
-  init.d script no longer refers to the Recursor as the Authoritative
   Server. Spotted by Wouter of WideXS, fixed in `commit
   913 <http://wiki.powerdns.com/projects/trac/changeset/913>`__.
-  A potentially serious warning for users of the GNU C Library version
   2.5 was fixed. Spotted by Marcus Rueckert, fixed in `commit
   920 <http://wiki.powerdns.com/projects/trac/changeset/920>`__.

Recursor version 3.1.3
----------------------

Released the 12th of September 2006.

Compared to 3.1.2, this release again consists of a number of mostly
minor bug fixes, and some slight improvements.

Many thanks are again due to Darren Gamble who together with his team
has discovered many misconfigured domains that do work with some other
name servers. DNS has long been tolerant of misconfigurations, PowerDNS
intends to uphold that tradition. Almost all of the domains found by
Darren now work as well in PowerDNS as in other name server
implementations.

Thanks to some recent migrations, this release, or something very close
to it, is powering over 40 million internet connections that we know of.
We appreciate hearing about successful as well as unsuccessful
migrations, please feel free to notify pdns.bd@powerdns.com of your
experiences, good or bad.

Bug-fixes
^^^^^^^^^

-  The MThread default stack size was too small, which led to problems,
   mostly on 64-bit platforms. This stack size is now configurable using
   the **stack-size** setting should our estimate be off. Discovered by
   Darren Gamble, Sten Spans and a number of others. Fixed in `commit
   868 <http://wiki.powerdns.com/projects/trac/changeset/868>`__.
-  Plug a small memory leak discovered by Kai and Darren Gamble, fixed
   in `commit
   870 <http://wiki.powerdns.com/projects/trac/changeset/870>`__.
-  Switch from the excellent nedmalloc to dlmalloc, based on advice by
   the nedmalloc author. Nedmalloc is optimised for multithreaded
   operation, whereas the PowerDNS recursor is single threaded. The
   version of nedmalloc shipped contained a number of possible bugs,
   which are probably resolved by moving to dlmalloc. Some reported
   crashes on hitting 2G of allocated memory on 64 bit systems might be
   solved by this switch, which should also increase performance. See
   `commit 873 <http://wiki.powerdns.com/projects/trac/changeset/873>`__
   for details.

Improvements
^^^^^^^^^^^^

-  The cache is now explicitly aware of the difference between
   authoritative and unauthoritative data, allowing it to deal with some
   domains that have different data in the parent zone than in the
   authoritative zone. Patch in `commit
   867 <http://wiki.powerdns.com/projects/trac/changeset/867>`__.
-  No longer try to parse DNS updates as if they were queries.
   Discovered and fixed by Jan Gyselinck, fix in `commit
   871 <http://wiki.powerdns.com/projects/trac/changeset/871>`__.
-  Rebalance logging priorities for less log cluttering and add IP
   address to a remote server error message. Noticed and fixed by Jan
   Gyselinck (`commit
   877 <http://wiki.powerdns.com/projects/trac/changeset/877>`__).
-  Add **logging-facility** setting, allowing syslog to send PowerDNS
   logging to a separate file. Added in `commit
   871 <http://wiki.powerdns.com/projects/trac/changeset/871>`__.

Recursor version 3.1.2
----------------------

Released Monday 26th of June 2006.

Compared to 3.1.1, this release consists almost exclusively of bug-fixes
and speedups. A quick update is recommended, as some of the bugs impact
operators of authoritative zones on the internet. This version has been
tested by some of the largest internet providers on the planet, and is
expected to perform well for everybody.

Many thanks are due to Darren Gamble, Stefan Schmidt and Bryan Seitz who
all provided excellent feedback based on their large-scale tests of the
recursor.

Bug-fixes
^^^^^^^^^

-  Internal authoritative server did not differentiate between
   'NXDOMAIN' and 'NXRRSET', in other words, it would answer 'no such
   host' when an AAAA query came in for a domain that did exist, but did
   not have an AAAA record. This only affects users with **auth-zones**
   configured. Discovered by Bryan Seitz, fixed in `commit
   848 <http://wiki.powerdns.com/projects/trac/changeset/848>`__.
-  ANY queries for hosts where nothing was present in the cache would
   not work. This did not cause real problems as ANY queries are not
   reliable (by design) for anything other than debugging, but did slow
   down the nameserver and cause unnecessary load on remote nameservers.
   Fixed in `commit
   854 <http://wiki.powerdns.com/projects/trac/changeset/854>`__.
-  When exceeding the configured maximum amount of TCP sessions, TCP
   support would break and the nameserver would waste CPU trying to
   accept TCP connections on UDP ports. Noted by Bryan Seitz, fixed in
   `commit
   849 <http://wiki.powerdns.com/projects/trac/changeset/849>`__.
-  DNS queries come in two flavours: recursion desired and non-recursion
   desired. The latter is not very useful for a recursor, but is
   sometimes (erroneously) used by monitoring software or load balancers
   to detect nameserver availability. A non-rd query would not only not
   recurse, but also not query authoritative zones, which is confusing.
   Fixed in `commit
   847 <http://wiki.powerdns.com/projects/trac/changeset/847>`__.
-  Non-standard DNS TCP queries, that did occur however, could drive the
   recursor to 100% CPU usage for extended periods of time. This did not
   disrupt service immediately, but does waste a lot of CPU, possibly
   exhausting resources. Discovered by Bryan Seitz, fixed in `commit
   858 <http://wiki.powerdns.com/projects/trac/changeset/858>`__, which
   is post-3.1.2-rc1.
-  The PowerDNS recursor did not honour the rare but standardised 'ANY'
   query class (normally 'ANY' refers to the query type, not class),
   upsetting the Wildfire Jabber server. Discovered and debugged by
   Daniel Nauck, fixed in `commit
   859 <http://wiki.powerdns.com/projects/trac/changeset/859>`__, which
   is post-3.1.2-rc1.
-  Everybody's favorite, when starting up under high load, a bogus line
   of statistics was sometimes logged. Fixed in `commit
   851 <http://wiki.powerdns.com/projects/trac/changeset/851>`__.
-  Remove some spurious debugging output on dropping a packet by an
   unauthorized host. Discovered by Kai. Fixed in `commit
   854 <http://wiki.powerdns.com/projects/trac/changeset/854>`__.

Improvements
^^^^^^^^^^^^

-  Misconfigured domains, with a broken nameserver in the parent zone,
   should now work better. Changes motivated and suggested by Darren
   Gamble. This makes PowerDNS more compliant with RFC 2181 by making it
   prefer authoritative data over non-authoritative data. Implemented in
   `commit
   856 <http://wiki.powerdns.com/projects/trac/changeset/856>`__.
-  PowerDNS can now listen on multiple ports, using the
   **local-address** setting. Added in `commit
   845 <http://wiki.powerdns.com/projects/trac/changeset/845>`__.
-  A number of speedups which should have a noticeable impact,
   implemented in commits
   `850 <http://wiki.powerdns.com/projects/trac/changeset/850>`__,
   `852 <http://wiki.powerdns.com/projects/trac/changeset/852>`__,
   `853 <http://wiki.powerdns.com/projects/trac/changeset/853>`__,
   `855 <http://wiki.powerdns.com/projects/trac/changeset/855>`__
-  The recursor now works around an issue with the Linux kernel 2.6.8,
   as shipped by Debian. Fixed by Christof Meerwald in `commit
   860 <http://wiki.powerdns.com/projects/trac/changeset/860>`__, which
   is post 3.1.2-rc1.

Recursor version 3.1.1
----------------------

Released on the 23rd of May 2006.

**Warning**: 3.1.1 is identical to 3.1 except for a bug in the packet
chaining code which would mainly manifest itself for IPv6 enabled
Konqueror users with very fast connections to their PowerDNS
installation. However, all 3.1 users are urged to upgrade to 3.1.1. Many
thanks to Alessandro Bono for his quick aid in solving this problem.

Many thanks are due to the operators of some of the largest internet
access providers in the world, each having many millions of customers,
who have tested the various 3.1 pre-releases for suitability. They have
uncovered and helped fix bugs that could impact us all, but are only
(quickly) noticeable with such vast amounts of DNS traffic.

After version 3.0.1 has proved to hold up very well under tremendous
loads, 3.1 adds important new features

-  Ability to serve authoritative data from 'BIND' style zone files
   (using **auth-zones** statement).
-  Ability to forward domains so configured to external servers (using
   **forward-zones**).
-  Possibility of 'serving' the contents of ``/etc/hosts`` over DNS,
   which is very well suited to simple domestic router/DNS setups.
   Enabled using **export-etc-hosts**.
-  As recommended by recent standards documents, the PowerDNS recursor
   is now authoritative for RFC-1918 private IP space zones by default
   (suggested by Paul Vixie).
-  Full outgoing IPv6 support (off by default) with IPv6 servers getting
   equal treatment with IPv4, nameserver addresses are chosen based on
   average response speed, irrespective of protocol.
-  Initial Windows support, including running as a service ('NET START
   "POWERDNS RECURSOR"'). **rec\_channel** is still missing, the rest
   should work. Performance appears to be below that of the UNIX
   versions, this situation is expected to improve.

Bug fixes
^^^^^^^^^

-  No longer send out SRV and MX record priorities as zero on big-endian
   platforms (UltraSPARC). Discovered by Eric Sproul, fixed in `commit
   773 <http://wiki.powerdns.com/projects/trac/changeset/773>`__.
-  SRV records need additional processing, especially in an Active
   Directory setting. Reported by Kenneth Marshall, fixed in `commit
   774 <http://wiki.powerdns.com/projects/trac/changeset/774>`__.
-  The root-records were not being refreshed, which could lead to
   problems under inconceivable conditions. Fixed in `commit
   780 <http://wiki.powerdns.com/projects/trac/changeset/780>`__.
-  Fix resolving domain names for nameservers with multiple IP
   addresses, with one of these addresses being lame. Other nameserver
   implementations were also unable to resolve these domains, so not a
   big bug. Fixed in `commit
   780 <http://wiki.powerdns.com/projects/trac/changeset/780>`__.
-  For a period of 5 minutes after expiring a negative cache entry, the
   domain would not be re-cached negatively, leading to a lot of
   duplicate outgoing queries for this short period. This fix has raised
   the average cache hit rate of the recursor by a few percent. Fixed in
   `commit
   783 <http://wiki.powerdns.com/projects/trac/changeset/783>`__.
-  Query throttling was not aggressive enough and not all sorts of
   queries were throttled. Implemented in `commit
   786 <http://wiki.powerdns.com/projects/trac/changeset/786>`__.
-  Fix possible crash during startup when parsing empty configuration
   lines (`commit
   807 <http://wiki.powerdns.com/projects/trac/changeset/807>`__).
-  Fix possible crash when the first query after wiping a cache entry
   was for the just deleted entry. Rare in production servers. Fixed in
   `commit
   820 <http://wiki.powerdns.com/projects/trac/changeset/820>`__.
-  Recursor would send out differing TTLs when receiving a
   misconfigured, standards violating, RRSET with different TTLs.
   Implement fix as mandated by RFC 2181, paragraph 5.2. Reported by
   Stephen Harker (`commit
   819 <http://wiki.powerdns.com/projects/trac/changeset/819>`__).
-  The **top-remotes** would list remotes more than once, once per
   source port. Discovered by Jorn Ekkelenkamp, fixed in `commit
   827 <http://wiki.powerdns.com/projects/trac/changeset/827>`__, which
   is post 3.1-pre1.
-  Default **allow-from** allowed queries from fe80::/16, corrected to
   fe80::/10. Spotted by Niels Bakker, fixed in `commit
   829 <http://wiki.powerdns.com/projects/trac/changeset/829>`__, which
   is post 3.1-pre1.
-  While PowerDNS blocks failing queries quickly, multiple packets could
   briefly be in flight for the same domain and nameserver. This
   situation is now explicitly detected and queries are chained to
   identical queries already in flight. Fixed in `commit
   833 <http://wiki.powerdns.com/projects/trac/changeset/833>`__ and
   `commit
   834 <http://wiki.powerdns.com/projects/trac/changeset/834>`__, post
   3.1-pre1.

Improvements
^^^^^^^^^^^^

-  ANY queries are now implemented as in other nameserver
   implementations, leading to a decrease in outgoing queries. The RFCs
   are not very clear on desired behaviour, what is implemented now
   saves bandwidth and CPU and brings us in line with existing practice.
   Previously ANY queries were not cached by the PowerDNS recursor.
   Implemented in `commit
   784 <http://wiki.powerdns.com/projects/trac/changeset/784>`__.
-  **rec\_control** was very sparse in its error reporting, and user
   unfriendly as well. Reported by Erik Bos, fixed in `commit
   818 <http://wiki.powerdns.com/projects/trac/changeset/818>`__ and
   `commit
   820 <http://wiki.powerdns.com/projects/trac/changeset/820>`__.
-  IPv6 addresses were printed in a non-standard way, fixed in `commit
   788 <http://wiki.powerdns.com/projects/trac/changeset/788>`__.
-  TTLs of records are now capped at two weeks, `commit
   820 <http://wiki.powerdns.com/projects/trac/changeset/820>`__.
-  **allow-from** IPv4 netmasks now automatically work for IP4-to-IPv6
   mapper IPv4 addresses, which appear when running on the wildcard
   **::** IPv6 address. Lack of feature noted by Marcus 'darix'
   Rueckert. Fixed in `commit
   826 <http://wiki.powerdns.com/projects/trac/changeset/826>`__, which
   is post 3.1-pre1.
-  Errors before daemonizing are now also sent to syslog. Suggested by
   Marcus 'darix' Rueckert. Fixed in `commit
   825 <http://wiki.powerdns.com/projects/trac/changeset/825>`__, which
   is post 3.1-pre1.
-  When launching without any form of configured network connectivity,
   all root-servers would be cached as 'down' for some time. Detect this
   special case and treat it as a resource-constraint, which is not
   accounted against specific nameservers. Spotted by Seth Arnold, fixed
   in `commit
   835 <http://wiki.powerdns.com/projects/trac/changeset/835>`__, which
   is post 3.1-pre1.
-  The recursor now does not allow authoritative servers to keep
   supplying its own NS records into perpetuity, which causes problems
   when a domain is redelegated but the old authoritative servers are
   not updated to this effect. Noticed and explained at length by Darren
   Gamble of Shaw Communications, addressed by `commit
   837 <http://wiki.powerdns.com/projects/trac/changeset/837>`__, which
   is post 3.1-pre2.
-  Some operators may want to follow RFC 2181 paragraph 5.2 and 5.4.
   This harms performance and does not solve any real problem, but does
   make PowerDNS more compliant. If you want this, enable
   **auth-can-lower-ttl**. Implemented in `commit
   838 <http://wiki.powerdns.com/projects/trac/changeset/838>`__, which
   is post 3.1-pre2.

Recursor version 3.0.1
----------------------

Released 25th of April 2006,
`download <http://www.powerdns.com/en/downloads.aspx>`__.

This release consists of nothing but tiny fixes to 3.0, including one
with security implications. An upgrade is highly recommended.

-  Compilation used both ``cc`` and ``gcc``, leading to the possibility
   of compiling with different compiler versions (`commit
   766 <http://wiki.powerdns.com/projects/trac/changeset/766>`__).
-  **rec\_control** would leave files named ``lsockXXXXXX`` around in
   the configured socket-dir. Operators may wish to remove these files
   from their socket-dir (often ``/var/run``), quite a few might have
   accumulated already (`commit
   767 <http://wiki.powerdns.com/projects/trac/changeset/767>`__).
-  Certain malformed packets could crash the recursor. As far as we can
   determine these packets could only lead to a crash, but as always,
   there are no guarantees. A quick upgrade is highly recommended
   (commits
   `760 <http://wiki.powerdns.com/projects/trac/changeset/760>`__,
   `761 <http://wiki.powerdns.com/projects/trac/changeset/761>`__).
   Reported by David Gavarret.
-  Recursor would not distinguish between NXDOMAIN and NXRRSET (`commit
   756 <http://wiki.powerdns.com/projects/trac/changeset/756>`__).
   Reported and debugged by Jorn Ekkelenkamp.
-  Some error messages and trace logging statements were improved
   (commits
   `756 <http://wiki.powerdns.com/projects/trac/changeset/756>`__,
   `758 <http://wiki.powerdns.com/projects/trac/changeset/758>`__,
   `759 <http://wiki.powerdns.com/projects/trac/changeset/759>`__).
-  stderr was closed during daemonizing, but not dupped to /dev/null,
   leading to slight chance of odd behaviour on reporting errors
   (`commit
   757 <http://wiki.powerdns.com/projects/trac/changeset/757>`__)

Operating system specific fixes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  The stock Debian sarge Linux kernel, 2.6.8, claims to support epoll
   but fails at runtime. The epoll self-testing code has been improved,
   and PowerDNS will fall back to a select based multiplexer if needed
   (`commit
   758 <http://wiki.powerdns.com/projects/trac/changeset/758>`__)
   Reported by Michiel van Es.
-  Solaris 8 compilation and runtime issues were addressed. See the
   README for details (`commit
   765 <http://wiki.powerdns.com/projects/trac/changeset/765>`__).
   Reported by Juergen Georgi and Kenneth Marshall.
-  Solaris 10 x86\_64 compilation issues were addressed (`commit
   755 <http://wiki.powerdns.com/projects/trac/changeset/755>`__).
   Reported and debugged by Eric Sproul.

Recursor version 3.0
--------------------

Released 20th of April 2006,
`download <http://www.powerdns.com/en/downloads.aspx>`__.

This is the first separate release of the PowerDNS Recursor. There are
many reasons for this, one of the most important ones is that previously
we could only do a release when both the recursor and the authoritative
nameserver were fully tested and in good shape. The split allows us to
release new versions when each part is ready.

Now for the real news. This version of the PowerDNS recursor powers the
network access of over two million internet connections. Two large
access providers have been running pre-releases of 3.0 for the past few
weeks and results are good. Furthermore, the various pre-releases have
been tested nearly non-stop with DNS traffic replayed at 3000
queries/second.

As expected, the 2 million households shook out some very rare bugs. But
even a rare bug happens once in a while when there are this many users.

We consider this version of the PowerDNS recursor to be the most
advanced resolver publicly available. Given current levels of spam,
phishing and other forms of internet crime we think no recursor should
offer less than the best in spoofing protection. We urge all operators
of resolvers without proper spoofing countermeasures to consider
PowerDNS, as it is a Better Internet Nameserver Daemon.

A good article on DNS spoofing can be found
`here <http://www.securesphere.net/download/papers/dnsspoof.htm>`__.
Some more information, based on a previous version of PowerDNS, can be
found on the `PowerDNS development
blog <http://blog.netherlabs.nl/articles/2006/04/14/holy-cow-1-3-million-additional-ip-addresses-served-by-powerdns>`__.

**Warning**: Because of recent DNS based denial of service attacks,
running an open recursor has become a security risk. Therefore, unless
configured otherwise this version of PowerDNS will only listen on
localhost, which means it does not resolve for hosts on your network. To
fix, configure the **local-address** setting with all addresses you want
to listen on. Additionally, by default service is restricted to RFC 1918
private IP addresses. Use **allow-from** to selectively open up the
recursor for your own network. See `pdns\_recursor
settings <recursor/settings.md#allow-from>`__ for details.

Important new features of the PowerDNS recursor 3.0
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Best spoofing protection and detection we know of. Not only is
   spoofing made harder by using a new network address for each query,
   PowerDNS detects when an attempt is made to spoof it, and temporarily
   ignores the data. For details, see
   `Anti-spoofing <recursor/security.md>`__.
-  First nameserver to benefit from epoll/kqueue/Solaris completion
   ports event reporting framework, for stellar performance.
-  Best statistics of any recursing nameserver we know of, see
   `Statistics <recursor/stats.md>`__.
-  Last-recently-used based cache cleanup algorithm, keeping the 'best'
   records in memory
-  First class Solaris support, built on a 'try and buy' Sun CoolThreads
   T 2000.
-  Full IPv6 support, implemented natively.
-  Access filtering, both for IPv4 and IPv6.
-  Experimental SMP support for nearly double performance. See `PowerDNS
   Recursor performance <recursor/performance.md>`__.

Many people helped package and test this release. Jorn Ekkelenkamp of
ISP-Services helped find the '8000 SOAs' bug and spotted many other
oddities and `XS4ALL <http://www.xs4all.nl>`__ internet funded a lot of
the recent development. Joaquín M López Muñoz of the
boost::multi\_index\_container was again of great help.
