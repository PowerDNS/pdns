Internals of the PowerDNS Recursor
==================================

**Warning**: This section is aimed at programmers wanting to contribute
to the recursor, or to help fix bugs. It is not required reading for a
PowerDNS operator, although it might prove interesting.

The PowerDNS Recursor consists of very little code, the core DNS logic
is less than a thousand lines.

This smallness is achieved through the use of some fine infrastructure:
MTasker, MOADNSParser, MPlexer and the C++ Standard Library/Boost. This
page will explain the conceptual relation between these components, and
the route of a packet through the program.

 The PowerDNS Recursor
----------------------

The Recursor started out as a tiny project, mostly a technology
demonstration. These days it consists of the core plus 9000 lines of
features. This combined with a need for very high performance has made
the recursor code less accessible than it was. The page you are reading
hopes to rectify this situation.

 Synchronous code using MTasker
-------------------------------

The original name of the program was **syncres**, which is still
reflected in the file name ``syncres.cc``, and the class SyncRes. This
means that PowerDNS is written naively, with one thread of execution per
query, synchronously waiting for packets, Normally this would lead to
very bad performance (unless running on a computer with very fast
threading, like possibly the Sun CoolThreads family), so PowerDNS
employs `MTasker <http://ds9a.nl/mtasker>`__ for very fast userspace
threading.

MTasker, which was developed separately from PowerDNS, does not provide
a full multithreading system but restricts itself to those features a
nameserver needs. It offers cooperative multitasking, which means there
is no forced preemption of threads. This in turn means that no two
**MThreads** ever really run at the same time.

This is both good and bad, but mostly good. It means PowerDNS does not
have to think about locking. No two threads will ever be talking to the
DNS cache at the same time, for example.

It also means that the recursor could block if any operation takes too
long.

The core interaction with MTasker are the waitEvent() and sendEvent()
functions. These pass around PacketID objects. Everything PowerDNS needs
to wait for is described by a PacketID event, so the name is a bit
misleading. Waiting for a TCP socket to have data available is also
passed via a PacketID, for example.

The version of MTasker in PowerDNS is newer than that described at the
MTasker site, with a vital difference being that the waitEvent()
structure passes along a copy of the exact PacketID sendEvent()
transmitted. Furthermore, threads can trawl through the list of events
being waited for and modify the respective PacketIDs. This is used for
example with **near miss** packets: packets that appear to answer
questions we asked, but differ in the DNS id. On seeing such a packet,
the recursor trawls through all PacketIDs and if it finds any
nearmisses, it updates the PacketID::nearMisses counter. The actual
PacketID thus lives inside MTasker while any thread is waiting for it.

MPlexer
-------

The Recursor uses a separate socket per outgoing query. This has the
important benefit of making spoofing 64000 times harder, and
additionally means that ICMP errors are reported back to the program. In
measurements this appears to happen to one in ten queries, which would
otherwise take a two-second timeout before PowerDNS moves on to another
nameserver.

However, this means that the program routinely needs to wait on hundreds
or even thousands of sockets. Different operating systems offer various
ways to monitor the state of sockets or more generally, file
descriptors. To abstract out the differing strategies (``select``,
``epoll``, ``kqueue``, ``completion ports``), PowerDNS contains
**MPlexer** classes, all of which descend from the FDMultiplexer class.

This class is very simple and offers only five important methods:
addReadFD(), addWriteFD(), removeReadFD(), removeWriteFD() and run.

The arguments to the **add** functions consist of an fd, a callback, and
a boost::any variable that is passed as a reference to the callback.

This might remind you of the MTasker above, and it is indeed the same
trick: state is stored within the MPlexer. As long as a file descriptor
remains within either the Read or Write active list, its state will
remain stored.

On arrival of a packet (or more generally, when an FD becomes readable
or writable, which for example might mean a new TCP connection), the
callback is called with the aforementioned reference to its parameter.

The callback is free to call removeReadFD() or removeWriteFD() to remove
itself from the active list.

PowerDNS defines such callbacks as newUDPQuestion(), newTCPConnection(),
handleRunningTCPConnection().

Finally, the run() method needs to be called whenever the program is
ready for new data. This happens in the main loop in pdns\_recursor.cc.
This loop is what MTasker refers to as **the kernel**. In this loop, any
packets or other MPlexer events get translated either into new MThreads
within MTasker, or into calls to sendEvent(), which in turn wakes up
other MThreads.

MOADNSParser
------------

Yes, this does stand for **the Mother of All DNS Parsers**. And even
that name does not do it justice! The MOADNSParser is the third attempt
I've made at writing DNS packet parser and after two miserable failures,
I think I've finally gotten it right.

Writing and parsing DNS packets, and the DNS records it contains,
consists of four things:

1. Parsing a DNS record (from packet) into memory
2. Generating a DNS record from memory (to packet)
3. Writing out memory to user-readable zone format
4. Reading said zone format into memory

This gets tedious very quickly, as one needs to implement all four
operations for each new record type, and there are dozens of them.

While writing the MOADNSParser, it was discovered there is a remarkable
symmetry between these four transitions. DNS Records are nearly always
laid out in the same order in memory as in their zone format
representation. And reading is nothing but inverse writing.

So, the MOADNSParser is built around the notion of a **Conversion**, and
we write all Conversion types once. So we have a Conversion from IP
address in memory to an IP address in a DNS packet, and vice versa. And
we have a Conversion from an IP address in zone format to memory, and
vice versa.

This in turn means that the entire implementation of the ARecordContent
is as follows (wait for it!)

::

    conv.xfrIP(d_ip);

Through the use of the magic called ``c++ Templates``, this one line
does everything needed to perform the four operations mentioned above.

At one point, I got really obsessed with PowerDNS memory use. So, how do
we store DNS data in the PowerDNS recursor? I mentioned **memory** above
a lot - this means we could just store the DNSRecordContent objects.
However, this would be wasteful.

For example, storing the following:

::

    www.example.org  3600 IN   CNAME  outpost.example.org.

Would duplicate a lot of data. So, what is actually stored is a partial
DNS packet. To store the CNAMEDNSRecordContent that corresponds to the
above, we generate a DNS packet that has **www.example.org IN CNAME** as
its question. Then we add **3600 IN CNAME outpost.example.org**. as its
answer. Then we chop off the question part, and store the rest in the
**www.example.org IN CNAME** key in our cache.

When we need to retrieve **www.example.org IN CNAME**, the inverse
happens. We find the proper partial packet, prefix it with a question
for **www.example.org IN CNAME**, and expand the resulting packet into
the answer **3600 IN CNAME outpost.example.org.**.

Why do we go through all these motions? Because of DNS compression,
which allows us to omit the whole **.example.org.** part, saving us 9
bytes. This is amplified when storing multiple MX records which all look
more or less alike. This optimization is not performed yet though.

Even without compression, it makes sense as all records are
automatically stored very compactly.

The PowerDNS recursor only parses a number of **well known record
types** and passes all other information across verbatim - it doesn't
have to know about the content it is serving.

The C++ Standard Library / Boost
--------------------------------

C++ is a powerful language. Perhaps a bit too powerful at times, you can
turn a program into a real freakshow if you so desire.

PowerDNS generally tries not to go overboard in this respect, but we do
build upon a very advanced part of the `Boost <http://www.boost.org>`__
C++ library: `boost::multi index
container <http://boost.org/libs/multi_index/doc/index.html>`__.

This container provides the equivalent of SQL indexes on multiple keys.
It also implements compound keys, which PowerDNS uses as well.

The main DNS cache is implemented as a multi index container object,
with a compound key on the name and type of a record. Furthermore, the
cache is sequenced, each time a record is accessed it is moved to the
end of the list. When cleanup is performed, we start at the beginning.
New records also get inserted at the end. For DNS correctness, the sort
order of the cache is case insensitive.

The multi index container appears in other parts of PowerDNS, and
MTasker as well.

 Actual DNS Algorithm
---------------------

The DNS RFCs do define the DNS algorithm, but you can't actually
implement it exactly that way, it was written in 1987.

Also, like what happened to HTML, it is expected that even non-standards
conforming domains work, and a sizable fraction of them is misconfigured
these days.

Everything begins with SyncRes::beginResolve(), which knows nothing
about sockets, and needs to be passed a domain name, dns type and dns
class which we are interested in. It returns a vector of
DNSResourceRecord objects, ready for writing either into an answer
packet, or for internal use.

After checking if the query is for any of the hardcoded domains
(localhost, version.bind, id.server), the query is passed to
SyncRes::doResolve, together with two vital parameters: the ``depth``
and ``beenthere`` set. As the word **recursor** implies, we will need to
recurse for answers. The **depth** parameter documents how deep we've
recursed already.

The ``beenthere`` set prevents loops. At each step, when a nameserver is
queried, it is added to the ``beenthere`` set. No nameserver in the set
will ever be queried again for the same question in the recursion
process - we know for a fact it won't help us further. This prevents the
process from getting stuck in loops.

SyncRes::doResolve first checks if there is a CNAME in cache, using
SyncRes::doCNAMECacheCheck, for the domain name and type queried and if
so, changes the query (which is passed by reference) to the domain the
CNAME points to. This is the cause of many DNS problems, a CNAME record
really means **start over with this query**.

This is followed by a call do SyncRes::doCacheCheck, which consults the
cache for a straight answer to the question (as possibly rerouted by a
CNAME). This function also consults the so called negative cache, but we
won't go into that just yet.

If this function finds the correct answer, and the answer hasn't expired
yet, it gets returned and we are (almost) done. This happens in 80 to
90% of all queries. Which is good, as what follows is a lot of work.

To recap:

1. beginResolve() - entry point, does checks for hardcoded domains
2. doResolve() - start of recursion process, gets passed ``depth`` of 0
   and empty ``beenthere`` set
3. doCNAMECacheCheck() - check if there is a CNAME in cache which would
   reroute the query
4. doCacheCheck() - see if cache contains straight answer to possibly
   rerouted query.

If the data we were queried for was in the cache, we are almost done.
One final step, which might as well be optional as nobody benefits from
it, is SyncRes::addCruft. This function does additional processing,
which means that if the query was for the MX record of a domain, we also
add the IP address of the mail exchanger.

The non-cached case
^^^^^^^^^^^^^^^^^^^

This is where things get interesting, because we start out with a nearly
empty cache and have to go out to the net to get answers to fill it.

The way DNS works, if you don't know the answer to a question, you find
somebody who does. Initially you have no other place to go than the root
servers. This is embodied in the SyncRes::getBestNSNamesFromCache
method, which gets passed the domain we are interested in, as well as
the ``depth`` and ``beenthere`` parameters mentioned earlier.

From now on, assume our query will be for **``www.powerdns.com.``**.
SyncRes::getBestNSNamesFromCache will first check if there are NS
records in cache for ``www.powerdns.com.``, but there won't be. It then
checks ``powerdns.com. NS``, and while these records do exist on the
internet, the recursor doesn't know about them yet. So, we go on to
check the cache for ``com. NS``, for which the same holds. Finally we
end up checking for ``. NS``, and these we do know about: they are the
root servers and were loaded into PowerDNS on startup.

So, SyncRes::getBestNSNamesFromCache fills out a set with the **names**
of nameservers it knows about for the **``.``** zone.

This set, together with the original query **``www.powerdns.com``** gets
passed to SyncRes::doResolveAt. This function can't yet go to work
immediately though, it only knows the names of nameservers it can try.
This is like asking for directions and instead of hearing **take the
third right** you are told **go to 123 Fifth Avenue, and take a right**
- the answer doesn't help you further unless you know where 123 Fifth
Avenue is.

SyncRes::doResolveAt first shuffles the nameservers both randomly and on
performance order. If it knows a nameserver was fast in the past, it
will get queried first. More about this later.

Ok, here is the part where things get a bit scary. How does
SyncRes::doResolveAt find the IP address of a nameserver? Well, by
calling SyncRes::getAs (**get A records**), which in turn calls..
SyncRes::doResolve. Hang on! That's where we came from! Massive
potential for loops here. Well, it turns out that for any domain which
can be resolved, this loop terminates. We do pass the ``beenthere`` set
again, which makes sure we don't keep on asking the same questions to
the same nameservers.

Ok, SyncRes::getAs will give us the IP addresses of the chosen
root-server, because these IP addresses were loaded on startup. We then
ask these IP addresses (nameservers can have several) for its best
answer for **``www.powerdns.com.``**. This is done using the LWRes class
and specifically LWRes::asyncresolve, which gets passed domain name,
type and IP address. This function interacts with MTasker and MPlexer
above in ways which needn't concern us now. When it returns, the LWRes
object contains the best answers the queried server had for our domain,
which in this case means it tells us about the nameservers of ``com.``,
and their IP addresses.

All the relevant answers it gives are stored in the cache (or actually,
merged), after which SyncRes::doResolveAt (which we are still in)
evaluates what to do now.

There are 6 options:

1. The final answer is in, we are done, return to SyncRes::doResolve and
   SyncRes::beginResolve
2. The nameserver we queried tells us the domain we asked for
   authoritatively does not exist. In case of the root-servers, this
   happens when we query for *``www.powerdns.kom.``* for example, there
   is no *``kom.``*. Return to SyncRes::beginResolve, we are done.
3. A lesser form - it tells us it is authoritative for the query we
   asked about, but there is no record matching our type. This happens
   when querying for the IPv6 address of a host which only has an IPv4
   address. Return to SyncRes::beginResolve, we are done.
4. The nameserver passed us a CNAME to another domain, and we need to
   reroute. Go to SyncRes::doResolve for the new domain.
5. The nameserver did not know about the domain, but does know who does,
   a *referral*. Stay within doResolveAt and loop to these new
   nameservers.
6. The nameserver replied saying *no idea*. This is called a *lame
   delegation*. Stay within SyncRes::doResolveAt and try the other
   nameservers we have for this domain.

When not redirected using a CNAME, this function will loop until it has
exhausted all nameservers and all their IP addresses. DNS is
surprisingly resilient that there is often only a single non-broken
nameserver left to answer queries, and we need to be prepared for that.

This is the whole DNS algorithm in PowerDNS, all in less than 700 lines
of code. It contains a lot of tricky bits though, related to the cache.

QName Minimization
------------------

Since the 4.3 release, the recursor implements a relaxed form of QName
Minimization. This is a method to enhance privacy and described in the
(draft) RFC 7816. By asking the authoritative server not the full
QName, but one more label than we already know it is athoratative for
we do not leak which exact names are queried to servers higher up in
the hierarchy.

The implemenation uses a relaxed form of QName Minimization, following
the recommendations found in the paper "A First Look at QNAME
Minimization in the Domain Name System" by De Vries et all.

We originally started with using NS probes as the example algorithm in
the RFC draft recommends.

We then quickly discovered that using NS probes were somewhat
troublesome and after reading the mentioned paper we changed to QType
A for probes, which worked better. We did not implemented the extra
label prepend, not understanding why that would be needed (a more
recent draft of the RFC came to the same conclusion).

Following the recommendations in the paper we also implemented larger
steps when many labels are present. We use steps 1-1-1-3-3-...; we
already have a limit on the number of outgoing queries induced by a
client query. We do a final full QName query if we get an unexpected
error. This happens when we encounter authoritative servers that are
not fully compliant, there are still many servers like that. The
recursor records with respect to this fallback scnenario in the
``qname-min-fallback-success`` metric.

For forwarded queries, we do not use QName Minimization.


Some of the things we glossed over
----------------------------------

Whenever a packet is sent to a remote nameserver, the response time is
stored in the SyncRes::s\_nsSpeeds map, using an exponentially weighted
moving average. This EWMA averages out different response times, and
also makes them decrease over time. This means that a nameserver that
hasn't been queried recently gradually becomes **faster** in the eyes of
PowerDNS, giving it a chance again.

A timeout is accounted as a 1s response time, which should take that
server out of the running for a while.

Furthermore, queries are throttled. This means that each query to a
nameserver that has failed is accounted in the ``s_throttle`` object.
Before performing a new query, the query and the nameserver are looked
up via shouldThrottle. If so, the query is assumed to have failed
without even being performed. This saves a lot of network traffic and
makes PowerDNS quick to respond to lame servers.

It also offers a modicum of protection against birthday attack powered
spoofing attempts, as PowerDNS will not inundate a broken server with
queries.

The negative query cache we mentioned earlier caches the cases 2 and 3
in the enumeration above. This data needs to be stored separately, as it
represents **non-data**. Each negcache query entry is the name of the
SOA record that was presented with the evidence of non-existence. This
SOA record is then retrieved from the regular cache, but with the TTL
that originally came with the NXDOMAIN (case 2) or NXRRSET (case 3).

 The Recursor Cache
-------------------

As mentioned before, the cache stores partial packets. It also stores
not the **Time To Live** of records, but in fact the **Time To Die**. If
the cache contains data, but it is expired, that data should not be
deemed present. This bit of PowerDNS has proven tricky, leading to
deadlocks in the past.

There are some other very tricky things to deal with. For example,
through a process called **more details**, a domain might have more
nameservers than listed in its parent zone. So, there might only be two
nameservers for ``powerdns.com.`` in the **``com.``** zone, but the
**``powerdns.com``** zone might list more.

This means that the cache should not, when talking to the **``com.``**
servers later on, overwrite these four nameservers with only the two
copies the **``com.``** servers pass us.

However, in other cases (like for example for SOA and CNAME records),
new data should overwrite old data.

Note that PowerDNS deviates from RFC 2181 (section 5.4.1) in this
respect.

 Some small things
------------------

The server-side part of PowerDNS (``pdns_recursor.cc``), which listens
to queries by end-users, is fully IPv6 capable using the ComboAddress
class. This class is in fact a union of a ``struct sockaddr_in`` and a
``struct sockaddr_in6``. As long as the ``sin_family`` (or
``sin6_family``) and ``sin_port`` members are in the same place, this
works just fine, allowing us to pass a ComboAddress\*, cast to a
``sockaddr*`` to the socket functions. For convenience, the ComboAddress
also offers a length() method which can be used to indicate the length -
either sizeof(sockaddr\_in) or sizeof(sockaddr\_in6).

Access to the recursor is governed through the NetmaskGroup class, which
internally contains Netmask, which in turn contain a ComboAddress.
