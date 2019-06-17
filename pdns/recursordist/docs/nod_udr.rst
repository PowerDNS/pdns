Newly Observed Domain Tracking
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A common security technique for detecting domains that may be suspicious or be associated with bad actors such as hosting malware, phishing or botnet command and control, is to investigate domains that haven't been seen before, i.e. are newly observed.

Deciding whether a domain is truly a new domain would involve deterministic methods, such as maintaining a database of all domains ever seen, and comparing all domain lookups against that database. Such a mechanism would not be scalable in a recursor, and so is best suited to offline analysis. However, determining candidate domains for such an offline service is a problem that can be solved in the recursor, given that sending all domain lookups to such an offline service would still be prohibitely costly, and given that the true number of newly observed domains is likely to be relatively small in a given time period.

A simple method to determine a candidate domain would simply be to check if the domain was not in the recursor cache; indeed this is a method used by many security researchers. However, while that does produce a smaller list of candidate domains, cache misses are still relatively common, particularly in deployments where techniques such as EDNS client-subnet are used.

Therefore, a feature has been developed for the recursor which uses probablistic data structures (specifically a Stable Bloom Filter (SBF): [http://webdocs.cs.ualberta.ca/~drafiei/papers/DupDet06Sigmod.pdf]). This recursor feature is named "Newly Observed Domain" or "NOD" for short.

The use of a probablistic data structure means that the memory and CPU usage for the NOD feature is minimal, however it does mean that there can be false positives (a domain flagged as new when it is not), and false negatives (a domain that is new is not detected). The size of the SBF data structure can be tuned to reduce the FP/FN rate, although it is created with a default size (67108864 cells) that should provide a reasonably low FP/FN rate. To configure a different size use the ``new-domain-db-size`` setting to specify a higher or lower cell count. Each cell consumes 1-bit of RAM (per recursor thread) and 1-byte of disk space. 

NOD is disabled by default, and must be enabled through the use of the following setting in recursor.conf:

``new-domain-tracking=yes``

Once enabled the recursor will keep track of previously seen domains using the SBF data structure, which is periodically persisted to the directory specified in the ``new-domain-history-dir``, which defaults to /var/lib/pdns-recursor/nod.

Administrators may wish to prevent certain domains or subdomains from ever triggering the NOD algorithm, in which case those domains must be added to the ``new-domain-whitelist`` setting as a comma separated list. No domain (or subdomain of a domain) listed will be considered a newly observed domain.

There are several ways to receive the information about newly observed domains:

Logging
+++++++

The setting ``new-domain-log`` is enabled by default once the NOD feature is enabled, and will log the newly observed domain to the recursor logfile.

DNS Lookup
++++++++++

The setting ``new-domain-lookup=<base domain>`` will cause the recursor to isse a DNS A record lookup to ``<newly observed domain>.<base domain>``. This can be a suitable method to send NOD data to an offsite or remote partner, however care should be taken to ensure that data is not leaked inadvertently.

Protobuf Logging
++++++++++++++++

If both NOD and protobuf logging are enabled, then the ``newlyObservedDomain`` field of the protobuf message emitted by the recursor will be set to true. Additionally newly observed domains will be tagged in the protobuf stream using the tag ``pdns-nod`` by default. The setting ``new-domain-pb-tag=<tag>`` can be used to alter the tag.

Unique Domain Response
~~~~~~~~~~~~~~~~~~~~~~

A similar feature to NOD is Unique Domain Response (UDR). This feature uses the same probablistic data structures as NOD to store information about unique responses for a given lookup domain. Determining if a particular response is unique for a given lookup domain is extremly useful for determining potential security issues such as:

* Fast-Flux Domain Names
* Cache-Poisoning Attacks
* Botnet Command and Control Servers
  etc.

This is because well-behaved domains tend to return fairly stable results to DNS record lookups, and thus domains which don't exhibit this behaviour may be suspsicious or may indicate a domain under attack.

UDR is disabled by default - to enable it, set ``unique-response-tracking=yes`` in recursor.conf.

The data is persisted to /var/log/pdns-recursor/udr by default, which can be changed with the setting ``unique-response-history-dir=<new directory>``.

The SBF (which is maintained separately per recursor thread) cell size defaults to 67108864, which can be changed using the setting ``unique-response-db-size``. The same caveats regarding FPs/FNs apply as for NOD.

Similarly to NOD, unique domain responses can be tracked using several mechanisms:

Logging
+++++++

The setting ``unique-response-log`` is enabled by default once the NOD feature is enabled, and will log the newly observed domain to the recursor logfile.

Protobuf Logging
++++++++++++++++

If both UDR and protobuf logging are enabled, then unique domain responses will be tagged in the protobuf stream using the tag ``pdns-udr`` by default. The setting ``unique-response-pb-tag=<tag>`` can be used to alter the tag.
