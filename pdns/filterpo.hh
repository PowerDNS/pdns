/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#pragma once
#include "iputils.hh"
#include "dns.hh"
#include "dnsname.hh"
#include "dnsparser.hh"
#include <map>
#include <unordered_map>

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
  enum class PolicyType { None, QName, ClientIP, ResponseIP, NSDName, NSIP };

  struct Policy
  {
    Policy(): d_custom(nullptr), d_name(nullptr), d_kind(PolicyKind::NoAction), d_type(PolicyType::None), d_ttl(0)
    {
    }
    bool operator==(const Policy& rhs) const
    {
      return d_kind == rhs.d_kind; // XXX check d_custom too!
    }
    std::string getKindToString() const;
    DNSRecord getCustomRecord(const DNSName& qname) const;
    DNSRecord getRecord(const DNSName& qname) const;

    std::shared_ptr<DNSRecordContent> d_custom;
    std::shared_ptr<std::string> d_name;
    PolicyKind d_kind;
    PolicyType d_type;
    int32_t d_ttl;
  };

  class Zone {
  public:
    void clear()
    {
      d_qpolAddr.clear();
      d_postpolAddr.clear();
      d_propolName.clear();
      d_propolNSAddr.clear();
      d_qpolName.clear();
    }
    void reserve(size_t entriesCount)
    {
      d_qpolName.reserve(entriesCount);
    }
    void setName(const std::string& name)
    {
      d_name = std::make_shared<std::string>(name);
    }
    void setDomain(const DNSName& domain)
    {
      d_domain = domain;
    }
    void setSerial(uint32_t serial)
    {
      d_serial = serial;
    }
    void setRefresh(uint32_t refresh)
    {
      d_refresh = refresh;
    }
    const std::shared_ptr<std::string> getName() const
    {
      return d_name;
    }
    DNSName getDomain()
    {
      return d_domain;
    }
    uint32_t getRefresh()
    {
      return d_refresh;
    }
    void dump(FILE * fp) const;

    void addClientTrigger(const Netmask& nm, Policy pol);
    void addQNameTrigger(const DNSName& nm, Policy pol);
    void addNSTrigger(const DNSName& dn, Policy pol);
    void addNSIPTrigger(const Netmask& nm, Policy pol);
    void addResponseTrigger(const Netmask& nm, Policy pol);

    bool rmClientTrigger(const Netmask& nm, Policy pol);
    bool rmQNameTrigger(const DNSName& nm, Policy pol);
    bool rmNSTrigger(const DNSName& dn, Policy pol);
    bool rmNSIPTrigger(const Netmask& nm, Policy pol);
    bool rmResponseTrigger(const Netmask& nm, Policy pol);

    bool findQNamePolicy(const DNSName& qname, DNSFilterEngine::Policy& pol) const;
    bool findNSPolicy(const DNSName& qname, DNSFilterEngine::Policy& pol) const;
    bool findNSIPPolicy(const ComboAddress& addr, DNSFilterEngine::Policy& pol) const;
    bool findResponsePolicy(const ComboAddress& addr, DNSFilterEngine::Policy& pol) const;
    bool findClientPolicy(const ComboAddress& addr, DNSFilterEngine::Policy& pol) const;

  private:
    static DNSName maskToRPZ(const Netmask& nm);
    bool findNamedPolicy(const std::unordered_map<DNSName, DNSFilterEngine::Policy>& polmap, const DNSName& qname, DNSFilterEngine::Policy& pol) const;
    void dumpNamedPolicy(FILE* fp, const DNSName& name, const Policy& pol) const;
    void dumpAddrPolicy(FILE* fp, const Netmask& nm, const DNSName& name, const Policy& pol) const;

    std::unordered_map<DNSName, Policy> d_qpolName;   // QNAME trigger (RPZ)
    NetmaskTree<Policy> d_qpolAddr;         // Source address
    std::unordered_map<DNSName, Policy> d_propolName; // NSDNAME (RPZ)
    NetmaskTree<Policy> d_propolNSAddr;     // NSIP (RPZ)
    NetmaskTree<Policy> d_postpolAddr;      // IP trigger (RPZ)
    DNSName d_domain;
    std::shared_ptr<std::string> d_name;
    uint32_t d_serial{0};
    uint32_t d_refresh{0};
  };

  DNSFilterEngine();
  void clear()
  {
    for(auto& z : d_zones) {
      z->clear();
    }
  }
  const std::shared_ptr<Zone> getZone(size_t zoneIdx) const
  {
    std::shared_ptr<Zone> result{nullptr};
    if (zoneIdx < d_zones.size()) {
      result = d_zones[zoneIdx];
    }
    return result;
  }
  const std::shared_ptr<Zone> getZone(const std::string& name) const
  {
    for (const auto zone : d_zones) {
      const auto& zName = zone->getName();
      if (zName && *zName == name) {
        return zone;
      }
    }
    return nullptr;
  }
  size_t addZone(std::shared_ptr<Zone> newZone)
  {
    d_zones.push_back(newZone);
    return (d_zones.size() - 1);
  }
  void setZone(size_t zoneIdx, std::shared_ptr<Zone> newZone)
  {
    if (newZone) {
      assureZones(zoneIdx);
      d_zones[zoneIdx] = newZone;
    }
  }

  Policy getQueryPolicy(const DNSName& qname, const ComboAddress& nm, const std::unordered_map<std::string,bool>& discardedPolicies) const;
  Policy getProcessingPolicy(const DNSName& qname, const std::unordered_map<std::string,bool>& discardedPolicies) const;
  Policy getProcessingPolicy(const ComboAddress& address, const std::unordered_map<std::string,bool>& discardedPolicies) const;
  Policy getPostPolicy(const vector<DNSRecord>& records, const std::unordered_map<std::string,bool>& discardedPolicies) const;

  size_t size() const {
    return d_zones.size();
  }
private:
  void assureZones(size_t zone);
  vector<std::shared_ptr<Zone>> d_zones;
};
