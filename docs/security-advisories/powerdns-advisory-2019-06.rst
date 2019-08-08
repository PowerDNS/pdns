PowerDNS Security Advisory 2019-06: Denial of service via crafted zone records
==============================================================================

-  CVE: CVE-2019-10203
-  Date: July 30th, 2019
-  Affects: PowerDNS Authoritative 4.0.0 and up, when using the gpgsql (PostgreSQL) backend
-  Not affected: 4.2.0, 4.1.11, 4.0.9
-  Severity: Low
-  Impact: Denial of Service
-  Exploit: This problem can be triggered via crafted records
-  Risk of system compromise: No
-  Solution: Update the database schema
-  Workaround: run the process inside the guardian or inside a supervisor

An issue has been found in PowerDNS Authoritative Server allowing an
authorized user to cause the server to exit by inserting a crafted record in a
MASTER type zone under their control. The issue is due to the fact that the
Authoritative Server will exit when it tries to store the notified serial in
the PostgreSQL database, if this serial cannot be represented in 31 bits.

This issue has been assigned CVE-2019-10203.

PowerDNS Authoritative up to and including 4.1.10 is affected. Please note
that at the time of writing, PowerDNS Authoritative 3.4 and below are no
longer supported, as described in
https://doc.powerdns.com/authoritative/appendices/EOL.html.

To fix the issue, run the following command against your PostgreSQL pdns
database: `ALTER TABLE domains ALTER notified_serial TYPE bigint USING CASE
WHEN notified_serial >= 0 THEN notified_serial::bigint END;`. No software
changes are required.

We would like to thank Klaus Darilion for finding and subsequently reporting
this issue!
