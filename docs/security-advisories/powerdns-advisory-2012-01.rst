PowerDNS Security Advisory 2012-01: PowerDNS Authoritative Server can be caused to generate a traffic loop
----------------------------------------------------------------------------------------------------------

-  CVE: CVE-2012-0206
-  Date: 10th of January 2012
-  Credit: Ray Morris of `BetterCGI.com <http://BetterCGI.com/>`__.
-  Affects: Most PowerDNS Authoritative Server versions < 3.0.1 (with
   the exception of 2.9.22.5 and 2.9.22.6)
-  Not affected: No versions of the PowerDNS Recursor ('pdns\_recursor')
   are affected.
-  Severity: High
-  Impact: Using well crafted UDP packets, one or more PowerDNS servers
   could be made to enter a tight packet loop, causing temporary denial
   of service
-  Exploit: Proof of concept
-  Risk of system compromise: No
-  Solution: Upgrade to PowerDNS Authoritative Server 2.9.22.5 or 3.0.1
-  Workaround: Several, the easiest is setting: ``cache-ttl=0``, which
   does have a performance impact. Please see below.

Affected versions of the PowerDNS Authoritative Server can be made to
respond to DNS responses, thus enabling an attacker to setup a packet
loop between two PowerDNS servers, perpetually answering each other's
answers. In some scenarios, a server could also be made to talk to
itself, achieving the same effect.

If enough bouncing traffic is generated, this will overwhelm the server
or network and disrupt service.

As a workaround, if upgrading to a non-affected version is not possible,
several options are available. The issue is caused by the packet-cache,
which can be disabled by setting 'cache-ttl=0', although this does incur
a performance penalty. This can be partially addressed by raising the
query-cache-ttl to a (far) higher value.

Alternatively, on Linux systems with a working iptables setup,
'responses' sent to the PowerDNS Authoritative Server 'question' address
can be blocked by issuing:

.. code-block:: shell

          iptables -I INPUT -p udp --dst $AUTHIP --dport 53 \! -f -m u32 --u32 "0>>22&0x3C@8>>15&0x01=1" -j DROP 
        

If this command is used on a router or firewall, substitute FORWARD for
INPUT.

To solve this issue, we recommend upgrading to the latest packages
available for your system. Tarballs and new static builds (32/64bit,
RPM/DEB) of 2.9.22.5 and 3.0.1 have been uploaded to `our download
site <http://www.powerdns.com/content/downloads.html>`__. Kees
Monshouwer has provided updated CentOS/RHEL packages in `his
repository <http://www.monshouwer.eu/download/3th_party/>`__. Debian,
Fedora and SuSE should have packages available shortly after this
announcement.

For those running custom PowerDNS versions, just applying this patch may
be easier:

.. code-block:: diff

    --- pdns/common_startup.cc   (revision 2326)
    +++ pdns/common_startup.cc   (working copy)
    @@ -253,7 +253,9 @@
           numreceived4++;
         else
           numreceived6++;
    -
    +    if(P->d.qr)
    +      continue;
    +      
         S.ringAccount("queries", P->qdomain+"/"+P->qtype.getName());
         S.ringAccount("remotes",P->getRemote());
         if(logDNSQueries) {

It should apply cleanly to 3.0 and with little trouble to several older
releases, including 2.9.22 and 2.9.21.

This bug resurfaced because over time, the check for 'not responding to
responses' moved to the wrong place, allowing certain responses to be
processed anyhow.

We would like to thank Ray Morris of
`BetterCGI.com <http://BetterCGI.com/>`__ for bringing this issue to our
attention and Aki Tuomi for helping us reproduce the problem.
