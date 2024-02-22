PowerDNS Security Advisory 2024-01: crafted DNSSEC records in a zone can lead to a denial of service in Recursor
================================================================================================================

- CVE: CVE-2023-50387 and CVE-2023-50868
- Date: 13th of February 2024.
- Affects: PowerDNS Recursor up to and including 4.8.5, 4.9.2 and 5.0.1
- Not affected: PowerDNS Recursor 4.8.6, 4.9.3 and 5.0.2
- Severity: High
- Impact: Denial of service
- Exploit: This problem can be triggered by an attacker publishing a crafted zone
- Risk of system compromise: None
- Solution: Upgrade to patched version or disable DNSSEC validation

An attacker can publish a zone that contains crafted DNSSEC related records. While validating
results from queries to that zone using the RFC mandated algorithms, the Recursor's resource usage
can become so high that processing of other queries is impacted, resulting in a denial of
service. Note that any resolver following the RFCs can be impacted, this is not a problem of this
particular implementation.

CVSS Score: 7.5, see
https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H&version=3.1

The remedies are one of:

- upgrade to a patched version
- disable DNSSEC validation by setting ``dnssec=off`` or ``process-no-validate``; when using YAML settings:
  ``dnssec.validate: off`` or ``process-no-validate``.  Note that this will affect clients depending on
  DNSSEC validation.

We would like to thank Elias Heftrig, Haya Schulmann, Niklas Vogel, and Michael Waidner from the
German National Research Center for Applied Cybersecurity ATHENE for bringing this issue to the
attention of the DNS community and especially Niklas Vogel for his assistance in validating the
patches. We would also like to thank Petr Špaček from ISC for discovering and responsibly disclosing
CVE-2023-50868.
