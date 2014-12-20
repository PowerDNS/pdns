# Security Measures in the Recursor

## Anti-spoofing
The PowerDNS recursor 3.0 uses a fresh UDP source port for each outgoing query, making spoofing around 64000 times harder. This raises the bar from 'easily doable given some time' to 'very hard'. Under some circumstances, 'some time' has been measured at 2 seconds. This technique was first used by `dnscache` by Dan J. Bernstein.

In addition, PowerDNS detects when it is being sent too many unexpected answers, and mistrusts a proper answer if found within a clutch of unexpected ones.

This behaviour can be tuned using the **spoof-nearmiss-max**.

## Throttling
PowerDNS implements a very simple but effective nameserver. Care has been taken not to overload remote servers in case of overly active clients.

This is implemented using the 'throttle'. This accounts all recent traffic and prevents queries that have been sent out recently from going out again.

There are three levels of throttling.

-   If a remote server indicates that it is lame for a zone, the exact question won't be repeated in the next 60 seconds.
-   After 4 ServFail responses in 60 seconds, the query gets throttled too.
-   5 timeouts in 20 seconds also lead to query suppression.
