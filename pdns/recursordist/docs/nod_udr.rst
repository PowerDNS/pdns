.. _Newly Observed Domain:

Newly Observed Domain Tracking
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A common security technique for detecting domains that may be suspicious or be associated with bad actors such as hosting malware, phishing or botnet command and control, is to investigate domains that haven't been seen before, i.e. are newly observed.

Deciding whether a domain is truly a new domain would involve deterministic methods, such as maintaining a database of all domains ever seen, and comparing all domain lookups against that database. Such a mechanism would not be scalable in a recursor, and so is best suited to offline analysis. However, determining candidate domains for such an offline service is a problem that can be solved in the recursor, given that sending all domain lookups to such an offline service would still be prohibitively costly, and given that the true number of newly observed domains is likely to be relatively small in a given time period.

A simple method to determine a candidate domain would simply be to check if the domain was not in the recursor cache; indeed this is a method used by many security researchers. However, while that does produce a smaller list of candidate domains, cache misses are still relatively common, particularly in deployments where techniques such as EDNS client-subnet are used.

Therefore, a feature has been developed for the recursor which uses probabilistic data structures (specifically a Stable Bloom Filter (SBF): [https://webdocs.cs.ualberta.ca/~drafiei/papers/DupDet06Sigmod.pdf]). This recursor feature is named "Newly Observed Domain" or "NOD" for short.

The use of a probabilistic data structure means that the memory and CPU usage for the NOD feature is minimal, however it does mean that there can be false positives (a domain flagged as new when it is not), and false negatives (a domain that is new is not detected). The size of the SBF data structure can be tuned to reduce the FP/FN rate, although it is created with a default size (67108864 cells) that should provide a reasonably low FP/FN rate. To configure a different size use the :ref:`setting-yaml-nod.db_size` setting to specify a higher or lower cell count. Each cell consumes 1-bit of RAM (per recursor thread) and 1-byte of disk space.

NOD is disabled by default, and must be enabled through the use of the following setting in recursor configuration:

.. code-block:: yaml

   nod:
     tracking: true

Once enabled the recursor will keep track of previously seen domains using the SBF data structure, which is periodically persisted to the directory specified in the :ref:`setting-yaml-nod.history_dir`, which defaults to /var/lib/pdns-recursor/nod.

Administrators may wish to prevent certain domains or subdomains from ever triggering the NOD algorithm, in which case those domains must be added to the :ref:`setting-yaml-nod.ignore_list` setting. No domain (or subdomain of a domain) listed will be considered a newly observed domain. It is also possible to use :ref:`setting-yaml-nod.ignore_list_file` to read a file with ignored domains, one domain per line.

There are several ways to receive the information about newly observed domains:

Logging
+++++++

The setting :ref:`setting-yaml-nod.log` is enabled by default once the NOD feature is enabled, and will log the newly observed domain to the recursor logfile.

DNS Lookup
++++++++++

The setting :ref:`setting-yaml-nod.lookup` will cause the recursor to issue a DNS A record lookup to ``<newly observed domain>.<base domain>``. This can be a suitable method to send NOD data to an offsite or remote partner, however care should be taken to ensure that data is not leaked inadvertently.
To log NOD information to a dnstap stream, refer to :ref:`setting-yaml-logging.dnstap_nod_framestream_servers`.

Protobuf Logging
++++++++++++++++

If both NOD and protobuf logging are enabled, then the ``newlyObservedDomain`` field of the protobuf message emitted by the recursor will be set to true. Additionally newly observed domains will be tagged in the protobuf stream using the tag ``pdns-nod`` by default. The setting :ref:`setting-yaml-nod.pb_tag` can be used to alter the tag.

.. _Unique Domain Response:

Unique Domain Response
~~~~~~~~~~~~~~~~~~~~~~

A similar feature to NOD is Unique Domain Response (UDR). This feature uses the same probabilistic data structures as NOD to store information about unique responses for a given lookup domain. Determining if a particular response is unique for a given lookup domain is extremely useful for determining potential security issues such as:

* Fast-Flux Domain Names
* Cache-Poisoning Attacks
* Botnet Command and Control Servers
  etc.

This is because well-behaved domains tend to return fairly stable results to DNS record lookups, and thus domains which don't exhibit this behaviour may be suspicious or may indicate a domain under attack.

UDR is disabled by default - to enable it, set :ref:`setting-yaml-nod.unique_response_tracking` in the recursor configuration.

The data is persisted to /var/lib/pdns-recursor/udr by default, which can be changed with the setting :ref:`setting-yaml-nod.unique_response_history_dir`.

The SBF cell size defaults to 67108864, which can be changed using the setting :ref:`setting-yaml-nod.unique_response_db_size`. The same caveats regarding FPs/FNs apply as for NOD.

Similarly to NOD, administrators may wish to prevent certain domains or subdomains from ever triggering the UDR algorithm, in which case those domains must be added to the :ref:`setting-yaml-nod.unique_response_ignore_list` setting. No domain (or subdomain of a domain) listed will be considered a new unique domain response. It is also possible to use :ref:`setting-yaml-nod.unique_response_ignore_list_file` to read a file with ignored domains, one domain per line.

Similarly to NOD, unique domain responses can be tracked using several mechanisms:

Logging
+++++++

The setting :ref:`setting-yaml-nod.unique_response_log` is enabled by default once the NOD feature is enabled, and will log the newly observed domain to the recursor logfile.
To log UDR information to a dnstap stream, refer to :ref:`setting-yaml-logging.dnstap_nod_framestream_servers`.

Protobuf Logging
++++++++++++++++

If both UDR and protobuf logging are enabled, then unique domain responses will be tagged in the protobuf stream using the tag ``pdns-udr`` by default. The setting :ref:`setting-yaml-nod.unique_response_pb_tag` can be used to alter the tag.
