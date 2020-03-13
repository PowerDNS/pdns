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
#include <limits>

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
  enum class PolicyKind : uint8_t { NoAction, Drop, NXDOMAIN, NODATA, Truncate, Custom};
  enum class PolicyType : uint8_t { None, QName, ClientIP, ResponseIP, NSDName, NSIP };
  typedef uint16_t Priority;
  static const Priority maximumPriority = std::numeric_limits<Priority>::max();
  
  static std::string getKindToString(PolicyKind kind);
  static std::string getTypeToString(PolicyType type);

  struct PolicyZoneData
  {
    /* shared by all the policies from a single zone */
    std::unordered_set<std::string> d_tags;
    std::string d_name;
    Priority d_priority{maximumPriority};
  };

  struct Policy
  {
    Policy(): d_ttl(0), d_kind(PolicyKind::NoAction), d_type(PolicyType::None)
    {
    }

    Policy(PolicyKind kind, PolicyType type, int32_t ttl=0, std::shared_ptr<PolicyZoneData> data=nullptr, const std::vector<std::shared_ptr<DNSRecordContent>>& custom={}): d_custom(custom), d_zoneData(data), d_ttl(ttl), d_kind(kind), d_type(type)
    {
    }

    bool operator==(const Policy& rhs) const
    {
      return d_kind == rhs.d_kind && d_type == rhs.d_type && d_ttl == rhs.d_ttl && d_custom == rhs.d_custom;
    }

    const std::string& getName() const
    {
      static std::string notSet;
      if (d_zoneData) {
        return d_zoneData->d_name;
      }
      return notSet;
    }

    void setName(const std::string& name)
    {
      /* until now the PolicyZoneData was shared,
         we now need to copy it, then write to it */
      std::shared_ptr<PolicyZoneData> newZoneData;
      if (d_zoneData) {
        newZoneData = std::make_shared<PolicyZoneData>(*d_zoneData);
      }
      else {
        newZoneData = std::make_shared<PolicyZoneData>();
      }
      newZoneData->d_name = name;
      d_zoneData = newZoneData;
    }

    const std::unordered_set<std::string>& getTags() const
    {
      static std::unordered_set<std::string> notSet;
      if (d_zoneData) {
        return d_zoneData->d_tags;
      }
      return notSet;
    }

    Priority getPriority() const
    {
      static Priority notSet = maximumPriority;
      if (d_zoneData) {
        return d_zoneData->d_priority;
      }
      return notSet;
    }

    std::vector<DNSRecord> getCustomRecords(const DNSName& qname, uint16_t qtype) const;
    std::vector<DNSRecord> getRecords(const DNSName& qname) const;

    std::vector<std::shared_ptr<DNSRecordContent>> d_custom;
    std::shared_ptr<PolicyZoneData> d_zoneData{nullptr};
    /* Yup, we are currently using the same TTL for every record for a given name */
    int32_t d_ttl;
    PolicyKind d_kind;
    PolicyType d_type;

  private:
    DNSRecord getRecordFromCustom(const DNSName& qname, const std::shared_ptr<DNSRecordContent>& custom) const;
  };

  class Zone {
  public:
    Zone(): d_zoneData(std::make_shared<PolicyZoneData>())
    {
    }

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
      d_zoneData->d_name = name;
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
    void setTags(std::unordered_set<std::string>&& tags)
    {
      d_zoneData->d_tags = std::move(tags);
    }
    const std::string& getName() const
    {
      return d_zoneData->d_name;
    }

    DNSName getDomain() const
    {
      return d_domain;
    }

    uint32_t getRefresh() const
    {
      return d_refresh;
    }

    uint32_t getSerial() const
    {
      return d_serial;
    }

    size_t size() const
    {
      return d_qpolAddr.size() + d_postpolAddr.size() + d_propolName.size() + d_propolNSAddr.size() + d_qpolName.size();
    }

    void dump(FILE * fp) const;

    void addClientTrigger(const Netmask& nm, Policy&& pol);
    void addQNameTrigger(const DNSName& nm, Policy&& pol, bool ignoreDuplicate=false);
    void addNSTrigger(const DNSName& dn, Policy&& pol);
    void addNSIPTrigger(const Netmask& nm, Policy&& pol);
    void addResponseTrigger(const Netmask& nm, Policy&& pol);

    bool rmClientTrigger(const Netmask& nm, const Policy& pol);
    bool rmQNameTrigger(const DNSName& nm, const Policy& pol);
    bool rmNSTrigger(const DNSName& dn, const Policy& pol);
    bool rmNSIPTrigger(const Netmask& nm, const Policy& pol);
    bool rmResponseTrigger(const Netmask& nm, const Policy& pol);

    bool findExactQNamePolicy(const DNSName& qname, DNSFilterEngine::Policy& pol) const;
    bool findExactNSPolicy(const DNSName& qname, DNSFilterEngine::Policy& pol) const;
    bool findNSIPPolicy(const ComboAddress& addr, DNSFilterEngine::Policy& pol) const;
    bool findResponsePolicy(const ComboAddress& addr, DNSFilterEngine::Policy& pol) const;
    bool findClientPolicy(const ComboAddress& addr, DNSFilterEngine::Policy& pol) const;

    bool hasClientPolicies() const
    {
      return !d_qpolAddr.empty();
    }
    bool hasQNamePolicies() const
    {
      return !d_qpolName.empty();
    }
    bool hasNSPolicies() const
    {
      return !d_propolName.empty();
    }
    bool hasNSIPPolicies() const
    {
      return !d_propolNSAddr.empty();
    }
    bool hasResponsePolicies() const
    {
      return !d_postpolAddr.empty();
    }
    Priority getPriority() const {
      return d_zoneData->d_priority;
    }
    void setPriority(Priority p) {
      d_zoneData->d_priority = p;
    }
  private:
    static DNSName maskToRPZ(const Netmask& nm);
    static bool findExactNamedPolicy(const std::unordered_map<DNSName, DNSFilterEngine::Policy>& polmap, const DNSName& qname, DNSFilterEngine::Policy& pol);
    static bool findNamedPolicy(const std::unordered_map<DNSName, DNSFilterEngine::Policy>& polmap, const DNSName& qname, DNSFilterEngine::Policy& pol);
    static void dumpNamedPolicy(FILE* fp, const DNSName& name, const Policy& pol);
    static void dumpAddrPolicy(FILE* fp, const Netmask& nm, const DNSName& name, const Policy& pol);

    std::unordered_map<DNSName, Policy> d_qpolName;   // QNAME trigger (RPZ)
    NetmaskTree<Policy> d_qpolAddr;         // Source address
    std::unordered_map<DNSName, Policy> d_propolName; // NSDNAME (RPZ)
    NetmaskTree<Policy> d_propolNSAddr;     // NSIP (RPZ)
    NetmaskTree<Policy> d_postpolAddr;      // IP trigger (RPZ)
    DNSName d_domain;
    std::shared_ptr<PolicyZoneData> d_zoneData{nullptr};
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
  void clearZones()
  {
    d_zones.clear();
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
      if (zName == name) {
        return zone;
      }
    }
    return nullptr;
  }
  size_t addZone(std::shared_ptr<Zone> newZone)
  {
    newZone->setPriority(d_zones.size());
    d_zones.push_back(newZone);
    return (d_zones.size() - 1);
  }
  void setZone(size_t zoneIdx, std::shared_ptr<Zone> newZone)
  {
    if (newZone) {
      assureZones(zoneIdx);
      newZone->setPriority(zoneIdx);
      d_zones[zoneIdx] = newZone;
    }
  }

  bool getQueryPolicy(const DNSName& qname, const ComboAddress& nm, const std::unordered_map<std::string,bool>& discardedPolicies, Policy& policy) const;
  bool getProcessingPolicy(const DNSName& qname, const std::unordered_map<std::string,bool>& discardedPolicies, Policy& policy) const;
  bool getProcessingPolicy(const ComboAddress& address, const std::unordered_map<std::string,bool>& discardedPolicies, Policy& policy) const;
  bool getPostPolicy(const vector<DNSRecord>& records, const std::unordered_map<std::string,bool>& discardedPolicies, Policy& policy) const;

  // A few convenience methods for the unit test code
  Policy getQueryPolicy(const DNSName& qname, const ComboAddress& nm, const std::unordered_map<std::string,bool>& discardedPolicies, Priority p) const {
    Policy policy;
    policy.d_zoneData = std::make_shared<PolicyZoneData>();
    policy.d_zoneData->d_priority = p;
    getQueryPolicy(qname, nm, discardedPolicies, policy);
    return policy;
  }

  Policy getProcessingPolicy(const DNSName& qname, const std::unordered_map<std::string,bool>& discardedPolicies, Priority p) const {
    Policy policy;
    policy.d_zoneData = std::make_shared<PolicyZoneData>();
    policy.d_zoneData->d_priority = p;
    getProcessingPolicy(qname, discardedPolicies, policy);
    return policy;
  }

  Policy getProcessingPolicy(const ComboAddress& address, const std::unordered_map<std::string,bool>& discardedPolicies, Priority p) const {
    Policy policy;
    policy.d_zoneData = std::make_shared<PolicyZoneData>();
    policy.d_zoneData->d_priority = p;
    getProcessingPolicy(address, discardedPolicies, policy);
    return policy;
  }

  Policy getPostPolicy(const vector<DNSRecord>& records, const std::unordered_map<std::string,bool>& discardedPolicies, Priority p) const {
    Policy policy;
    policy.d_zoneData = std::make_shared<PolicyZoneData>();
    policy.d_zoneData->d_priority = p;
    getPostPolicy(records, discardedPolicies, policy);
    return policy;
  }

  size_t size() const {
    return d_zones.size();
  }
private:
  void assureZones(size_t zone);
  vector<std::shared_ptr<Zone>> d_zones;
};

void mergePolicyTags(std::unordered_set<std::string>& tags, const std::unordered_set<std::string>& newTags);
