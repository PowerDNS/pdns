## The PowerDNS Web/JSON/RESTful APIs
In order to remotely control PowerDNS, both Authoritative Server and Recursor, various non-web means are available, like pdns_control 
and rec_control.

In addition, recent versions of PowerDNS can be controlled via a JSON API that is available over the web.

To make use of this API, there is a Python, flask, based web application called 'pdnscontrol', which is hosted on https://github.com/PowerDNS/pdnscontrol . pdnscontrol also contains pdns2graphite which sets up a bridge between our statistics and graphite.

Finally, there is a program called 'pdnsmgrd' that also provides an API for stopping PowerDNS, starting it, installing new versions etc. 

The JSON API suports JSON and JSONp.

Common API calls
----------------
 * config  
   Returns the currently running configuration, minus passwords
 * log-grep  
   Searches the logfile configured with 'experimental-logfile' for the terms specified in 'needle'
 * domains  
   Returns a list of all domains, including type, master details, last_check etc

API calls in PowerDNS Authoritative Server
------------------------------------------
Available from the built-in webserver as http://servername/jsonstat?command=...

For now, only enabled if the 'experimental-json-interface' parameter is configured, as this API is not yet fully stable.

 * get  
   Returns all variables found on the rest of the URL request
 * get-zone  
   Returns the zone from the 'zone' parameter of the request
 * pdns-control  
   Allows you to issue pdns_control commands, as found in a JSON post, in the field 'parameters'
 * zone-rest  
   RESTful querying and modifying of a zone, for example, request:  http://jsonstat?command=zone-rest&rest=/powerdns.nl/www.powerdns.nl/a
   Supports POST, DELETE, and GET

API calls for the PowerDNS Recursor
-----------------------------------

For now, only enabled if the 'experimental-json-interface' parameter is configured, as this API is not yet fully stable.

 * flush-cache  
   Flush from the cache the domain specified in the parameter 'domain'
 * stats  
   Returns the rec_control statistics

