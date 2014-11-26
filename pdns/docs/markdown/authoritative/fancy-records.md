# Fancy Records
**Warning**: As of PowerDNS Authoritative Server 3.0, fancy records are no longer supported!

PDNS also supports so called 'fancy' records. A Fancy Record is actually not a DNS record, but it is translated into one. Currently, two fancy records are implemented, but not very useful without additional unreleased software. For completeness, they are listed here. The software will become available later on and is part of the Express and PowerMail suite of programs.

These records imply extra database lookups which has a performance impact. Therefore fancy records are only queried for if they are enabled with the **fancy-records** command in `pdns.conf`.

## MBOXFW
This record denotes an email forward. A typical entry looks like this:

```
        support@yourdomain.com     MBOXFW       you@yourcompany.com
```

When PDNS encounters a request for an MX record for yourdomain.com it will, if fancy records are enabled, also check for the existence of an MBOXFW record ending on '@yourdomain.com', in which case it will hand out a record containing the configured **smtpredirector**. This server should then also be able to access the PDNS database to figure out where mail to support@yourdomain.com should go to.

## URL
URL records work in much the same way, but for HTTP. A sample record:

```
        yourdomain.com     URL       http://somewhere.else.com/yourdomain
```

A URL record is converted into an A record containing the IP address configured with the **urlredirector** setting. On that IP address a webserver should live that knows how to redirect yourdomain.com to http://somewhere.else.com/yourdomain.
