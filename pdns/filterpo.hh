#pragma once
#include "iputils.hh"
#include "dns.hh"
#include "dnsparser.hh"
#include <map>

/* This class implements a filtering policy that is able to fully implement RPZ, but is not bound to it.
   In other words, it is generic enough to support RPZ, but could get its data from other places.


   We know the following actions:
   
   No action - just pass it on
   Drop - drop a query, no response
   NXDOMAIN - fake up an NXDOMAIN for the query 
   NODATA - just return no data for this qtype
   Truncate - set TC bit
   Modified - "we fake an answer for you"

   These actions can be caused by the following triggers:
   
   qname - the query name
   client-ip - the IP address of the requestor
   response-ip - an IP address in the response
   ns-name - the name of a server used in the delegation
   ns-ip - the IP address of a server used in the delegation

   This means we get several hook points:
   1) when the query comes in: qname & client-ip
   2) during processing: ns-name & ns-ip
   3) after processing: response-ip

   Triggers meanwhile can apply to:
   Verbatim domain names
   Wildcard versions (*.domain.com does NOT match domain.com)
   Netmasks (IPv4 and IPv6)
   Finally, triggers are grouped in different zones. The "first" zone that has a match
   is consulted. Then within that zone, rules again have precedences. 
*/


class DNSFilterEngine
{
public:
  enum class PolicyKind { NoAction, Drop, NXDOMAIN, NODATA, Truncate, Custom};
  struct Policy
  {
    bool operator==(const Policy& rhs) const
    {
      return d_kind == rhs.d_kind; // XXX check d_custom too!
    }
    PolicyKind d_kind;
    std::shared_ptr<DNSRecordContent> d_custom;
    std::string d_name;
    int d_ttl;
  };

  DNSFilterEngine();
  void clear();
  void clear(int zone);
  void addClientTrigger(const Netmask& nm, Policy pol, int zone=0);
  void addQNameTrigger(const DNSName& nm, Policy pol, int zone=0);
  void addNSTrigger(const DNSName& dn, Policy pol, int zone=0);
  void addResponseTrigger(const Netmask& nm, Policy pol, int zone=0);

  bool rmClientTrigger(const Netmask& nm, Policy pol, int zone=0);
  bool rmQNameTrigger(const DNSName& nm, Policy pol, int zone=0);
  bool rmNSTrigger(const DNSName& dn, Policy pol, int zone=0);
  bool rmResponseTrigger(const Netmask& nm, Policy pol, int zone=0);


  Policy getQueryPolicy(const DNSName& qname, const ComboAddress& nm) const;
  Policy getProcessingPolicy(const DNSName& qname) const;
  Policy getPostPolicy(const vector<DNSRecord>& records) const;

  size_t size() {
    return d_zones.size();
  }
private:
  void assureZones(int zone);
  struct Zone {
    std::map<DNSName, Policy> qpolName;
    NetmaskTree<Policy> qpolAddr;
    std::map<DNSName, Policy> propolName;
    NetmaskTree<Policy> postpolAddr;
  };
  vector<Zone> d_zones;

};
