
Features that should be doable using the API
============================================

New Console Features
--------------------

* RBAC
* User Management
* Audit Trail, light Edition
* Cache Viewing
* Versioning / Rollback
  * for Zone data?
* pcap capture triggering (-> pdnsmgr)
* Zone (de)provisioning
  * with DNSSEC
* Improved Graphite

DNSSEC Console for Recursor
---------------------------

* recent failures (not just DNSSEC)
* trigger live logging (e.g. for “*.nl”)
* DNSSEC partial blanking (“don’t check *.gov”)
* DNSSEC temporary blanking (“not for next 24h”)

Meta Features enabled by pdnsmgrd
---------------------------------

* start
* stop
* upgrade
* restart
  * TODO: can/should we do this inproc?
* *pcap*
  * TODO: How will this work?
  * Should this happen in-daemon?

