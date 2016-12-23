# Recursion with the Authoritative Server
From 2.9.5 onwards, PowerDNS offers both authoritative nameserving capabilities
and a [recursive nameserver](../recursor/index.md) component. These two halves
are normally separate but many users insist on combining both recursion and
authoritative service on one IP address. This can be likened to running Apache
and Squid both on port 80.

However, many sites want to do this anyhow and some with good reason. For
example, a setup like this allows the creation of fake domains which only exist
for local users. Such domains often don't end on ".com" or ".org" but on
".intern" or ".name-of-isp".

PowerDNS can cooperate with either its own recursor or any other you have
available to deliver recursive service on its port.

By specifying the [`recursor`](settings.md#recursor) option in the configuration
file, questions requiring recursive treatment will be handed over to the IP
address specified. An example configuration might be `recursor=203.0.113.7`,
which designates 203.0.113.7 as the nameserver to handle recursive queries.

**Warning**: Using `recursor` is NOT RECOMMENDED as it comes with many
potentially nasty surprises. For more info, you can read
[Dan Bernstein's article](http://cr.yp.to/djbdns/separation.html) on this topic.

Take care not to point [`recursor`](settings.md#recursor) to the PowerDNS
Authoritative Server itself, which leads to a very tight packet loop!

By specifying [`allow-recursion`](settings.md#allow-recursion), recursion can be
restricted to netmasks specified. The default is to allow recursion from
everywhere. Example: `allow-recursion=203.0.113.0/24, 198.51.100.0/26, 192.0.2.4`, `::1`.

## Details
Questions carry a number of flags. One of these is called 'Recursion Desired'.
If PowerDNS is configured to allow recursion, AND such a flag is seen, AND the
IP address of the client is allowed to recurse via PowerDNS, then the packet may
be handed to the recursing backend.

If a Recursion Desired packet arrives and PowerDNS is configured to allow
recursion, but not to the IP address of the client, resolution will proceed as
if the RD flag were unset and the answer will indicate that recursion was not
available.

It is also possible to use a resolver living on a different port. To do so,
specify a recursor like this: `recursor=192.0.2.1:5300`.

**Reminder:** [according to RFC3986](https://tools.ietf.org/html/rfc3986#section-3.2.2) for IPv6, the notation is to
encode the IPv6 IP number in square brackets like this: `recursor=[::1]:5300`, as
they explain in section 3.2.2: Host:

> A host identified by an Internet Protocol literal address, version 6 [RFC3513] or
later, is distinguished by enclosing the IP literal within square brackets ("[" and "]").
This is the only place where square bracket characters are allowed in the URI syntax.
In anticipation of future, as-yet-undefined IP literal address formats, an
implementation may use an optional version flag to indicate such a format explicitly
rather than rely on heuristic determination.

So, be careful! The authoritative `pdns` service won't communicate with `pdns-recursor` 
if you write wrongly the IPv6 IP number in the `recursor` line of `pdns.conf`. Therefore,
~~`recursor=::1:5300`~~ won't work because of the missing required square brackets ("[" and "]") 
enclosing the IP literal. Please respect IPv6 notation.

If the backend does not answer a question within a large amount of time, this is
logged as 'Recursive query for remote 198.51.100.15 with internal id 0 was not
answered by backend within timeout, reusing id'. This may happen when using
'BIND' as a recursor as it is prone to drop queries which it can't answer
immediately.

To make sure that the local authoritative database overrides recursive
information, PowerDNS first tries to answer a question from its own database.
If that succeeds, the answer packet is sent back immediately without involving
the recursor in any way. This means that for questions for which there is no
answer, PowerDNS will consult the recursor for an recursive query, even if
PowerDNS is authoritative for a domain! This will only cause problems if you
'fake' domains which don't really exist. This also means that if you delegate a
subzone to another set or authoritative servers, when a request comes in for
that sub-zone, PowerDNS will respond with a delegation response (as that is the
answer from the authoritative perspective) and will *not* involve the recursor.

If you want to create such fake domains or override existing domains, please set
the `allow-recursion-override` feature (available from 2.9.14 until 2.9.22.6).

Some packets, like those asking for MX records which are needed for SMTP
transport of email, can be subject to 'additional processing'. This means that a
recursing nameserver is obliged to try to add A records (IP addresses) for any
of the mail servers mentioned in the packet, should it have these addresses
available.

If PowerDNS encounters records needing such processing and finds that it does
not have the data in its authoritative database, it will send an opportunistic
quick query to the recursing component to see if it perhaps has such data. This
question is worded such that the recursing nameserver should return immediately
such as not to block the authoritative nameserver.

This marks a change from pre-2.9.5 behaviour where a packet was handed wholesale
to the recursor in case it needed additional processing which could not proceed
from the authoritative database.
