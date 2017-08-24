PowerDNS Security Advisory 2017-02 for dnsdist: Alteration of ACLs via API authentication bypass
================================================================================================

- CVE: CVE-2017-7557
- Date: 2017-08-21
- Credit: Nixu
- Affects: dnsdist 1.1.0
- Not affected: dnsdist 1.0.0, 1.2.0
- Severity: Low
- Impact: Access restriction bypass
- Exploit: This issue can be triggered by tricking an authenticated user into visiting a crafted website
- Risk of system compromise: No
- Solution: Upgrade to a non-affected version
- Workaround: Keep the API read-only (default) via setAPIWritable(false)

An issue has been found in dnsdist 1.1.0, in the API authentication mechanism. API methods should only be available to a user authenticated via an X-API-Key HTTP header, and not to a user authenticated on the webserver via Basic Authentication, but it was discovered by Nixu during a source code audit that dnsdist 1.1.0 allows access to all API methods to both kind of users.

In the default configuration, the API does not provide access to more information than the webserver does, and therefore this issue has no security implication. However if the API is allowed to make configuration changes, via the setAPIWritable(true) option, this allows a remote unauthenticated user to trick an authenticated user into editing dnsdist's ACLs by making him visit a crafted website containing a Cross-Site Request Forgery.

For those unable to upgrade to a new version, a minimal patch is `available for 1.1.0 <https://downloads.powerdns.com/patches/2017-02>`__
