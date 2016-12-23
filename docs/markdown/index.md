> It is a book about a Spanish guy called Manual. You should read it.
>
>   -- Dilbert

# PowerDNS Nameserver
There are two PowerDNS nameserver products: the [Authoritative Server](authoritative/index.md) and the [Recursor](recursor/index.md). While most other nameservers fully combine these functions, PowerDNS offers them separately, but can mix both authoritative and recursive usage seamlessly.
The Authoritative Server will answer questions about domains it knows about, but will not go out on the net to resolve queries about other domains. However, it can use a recursing backend to provide that functionality. Depending on your needs, this backend can either be the PowerDNS recursor or an external one.
When the Authoritative Server answers a question, it comes out of the database, and can be trusted as being authoritative. There is no way to pollute the cache or to confuse the daemon.

The Recursor, conversely, by default has no knowledge of domains itself, but will always consult other authoritative servers to answer questions given to it.

PowerDNS has been designed to serve both the needs of small installations by
being easy to setup, as well as for serving very large query volumes on
large numbers of domains.  Additionally, through use of clever programming
techniques, PowerDNS offers very high domain resolution performance.

Another prime goal is security. By the use of language features, the PowerDNS
source code is reasonably small which makes auditing easy.  In the same way,
library features have been used to mitigate the risks of buffer overflows.

Finally, PowerDNS is able to give a lot of statistics on its operation which
is both helpful in determining the scalability of an installation as well as
for spotting problems.

# Getting help
There are several ways of getting help:

* [The pretty .com website](https://www.powerdns.com) for commercial support
* This documentation => [Getting support](common/support.md)
* [The mailing lists](https://www.powerdns.com/mailing-lists.html)
* \#powerdns on [irc.oftc.net](irc://irc.oftc.net/#powerdns)

# About this document
If you are reading this document from disk, you may want to check <http://doc.powerdns.com> for updates.

To add to the PowerDNS documentation, or to fix mistakes, head to [Documentation details](appendix/documentation.md).
