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
#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <mutex>
#include <condition_variable>

#include <boost/utility.hpp>

#include "dnspacket.hh"
#include "dnsbackend.hh"
#include "lock.hh"
#include "namespaces.hh"

/** This is a very magic backend that allows us to load modules dynamically,
    and query them in order. This is persistent over all UeberBackend instantiations
    across multiple threads.

    The UeberBackend is transparent for exceptions, which should fall straight through.
*/

class UeberBackend : public boost::noncopyable
{
public:
  UeberBackend(const string& pname = "default");
  ~UeberBackend();

  bool autoPrimaryBackend(const string& ip, const ZoneName& domain, const vector<DNSResourceRecord>& nsset, string* nameserver, string* account, DNSBackend** dnsBackend);

  bool autoPrimaryAdd(const AutoPrimary& primary);
  bool autoPrimaryRemove(const struct AutoPrimary& primary);
  bool autoPrimariesList(std::vector<AutoPrimary>& primaries);

  /** Tracks all created UeberBackend instances for us. We use this vector to notify
      existing threads of new modules
  */
  static LockGuarded<vector<UeberBackend*>> d_instances;

  static bool loadmodule(const string& name);
  static bool loadModules(const vector<string>& modules, const string& path);

  static void go();

  /** This contains all registered backends. The DynListener modifies this list for us when
      new modules are loaded */
  vector<std::unique_ptr<DNSBackend>> backends;

  //! the very magic handle for UeberBackend questions
  class handle
  {
  public:
    bool get(DNSZoneRecord& record);
    handle();
    ~handle();

    //! The UeberBackend class where this handle belongs to
    UeberBackend* parent{nullptr};
    //! The current real backend, which is answering questions
    DNSBackend* d_hinterBackend{nullptr};

    //! DNSPacket who asked this question
    DNSPacket* pkt_p{nullptr};
    DNSName qname;

    //! Index of the current backend within the backends vector
    unsigned int i{0};
    QType qtype;
    int zoneId{-1};

  private:
    static AtomicCounter instances;
  };

  void lookup(const QType& qtype, const DNSName& qname, int zoneId, DNSPacket* pkt_p = nullptr);
  /** Read a single record from a lookup(...) result. */
  bool get(DNSZoneRecord& resourceRecord);
  /** Close state created by lookup(...). */
  void lookupEnd();

  /** Determines if we are authoritative for a zone, and at what level */
  bool getAuth(const ZoneName& target, const QType& qtype, SOAData* soaData, bool cachedOk = true, DNSPacket* pkt_p = nullptr);
  /** Load SOA info from backends, ignoring the cache.*/
  bool getSOAUncached(const ZoneName& domain, SOAData& soaData);
  void getAllDomains(vector<DomainInfo>* domains, bool getSerial, bool include_disabled);

  void getUnfreshSecondaryInfos(vector<DomainInfo>* domains);
  void getUpdatedPrimaries(vector<DomainInfo>& domains, std::unordered_set<DNSName>& catalogs, CatalogHashMap& catalogHashes);
  bool getDomainInfo(const ZoneName& domain, DomainInfo& domainInfo, bool getSerial = true);
  bool createDomain(const ZoneName& domain, DomainInfo::DomainKind kind, const vector<ComboAddress>& primaries, const string& account);

  bool doesDNSSEC();
  bool addDomainKey(const ZoneName& name, const DNSBackend::KeyData& key, int64_t& keyID);
  bool getDomainKeys(const ZoneName& name, std::vector<DNSBackend::KeyData>& keys);
  bool getAllDomainMetadata(const ZoneName& name, std::map<std::string, std::vector<std::string>>& meta);
  bool getDomainMetadata(const ZoneName& name, const std::string& kind, std::vector<std::string>& meta);
  bool getDomainMetadata(const ZoneName& name, const std::string& kind, std::string& meta);
  bool setDomainMetadata(const ZoneName& name, const std::string& kind, const std::vector<std::string>& meta);
  bool setDomainMetadata(const ZoneName& name, const std::string& kind, const std::string& meta);

  bool removeDomainKey(const ZoneName& name, unsigned int keyID);
  bool activateDomainKey(const ZoneName& name, unsigned int keyID);
  bool deactivateDomainKey(const ZoneName& name, unsigned int keyID);
  bool publishDomainKey(const ZoneName& name, unsigned int keyID);
  bool unpublishDomainKey(const ZoneName& name, unsigned int keyID);

  void alsoNotifies(const ZoneName& domain, set<string>* ips);
  void rediscover(string* status = nullptr);
  void reload();

  bool setTSIGKey(const DNSName& name, const DNSName& algorithm, const string& content);
  bool getTSIGKey(const DNSName& name, DNSName& algorithm, string& content);
  bool getTSIGKeys(std::vector<struct TSIGKey>& keys);
  bool deleteTSIGKey(const DNSName& name);

  void viewList(vector<string>& result);
  void viewListZones(const string& view, vector<ZoneName>& result);
  bool viewAddZone(const string& /* view */, const ZoneName& /* zone */);
  bool viewDelZone(const string& /* view */, const ZoneName& /* zone */);

  bool networkSet(const Netmask& net, std::string& tag);
  void networkList(vector<pair<Netmask, string>>& networks);

  bool searchRecords(const string& pattern, vector<DNSResourceRecord>::size_type maxResults, vector<DNSResourceRecord>& result);
  bool searchComments(const string& pattern, size_t maxResults, vector<Comment>& result);

  void updateZoneCache();

  bool inTransaction();

  bool hasCreatedLocalFiles();

  unsigned int getCapabilities();

private:
  handle d_handle;
  vector<DNSZoneRecord> d_answers;
  vector<DNSZoneRecord>::const_iterator d_cachehandleiter;

  static std::mutex d_mut;
  static std::condition_variable d_cond;

  struct Question
  {
    DNSName qname;
    int zoneId;
    QType qtype;
  } d_question;

  unsigned int d_cache_ttl, d_negcache_ttl;
  uint16_t d_qtype{0};

  bool d_negcached{false};
  bool d_cached{false};
  static AtomicCounter* s_backendQueries;
  static bool d_go;
  bool d_stale{false};
  static bool s_doANYLookupsOnly;

  enum CacheResult
  {
    Miss = -1,
    NegativeMatch = 0,
    Hit = 1,
  };

  CacheResult cacheHas(const Question& question, vector<DNSZoneRecord>& resourceRecords) const;
  void addNegCache(const Question& question) const;
  void addCache(const Question& question, vector<DNSZoneRecord>&& rrs) const;

  bool fillSOAFromZoneRecord(ZoneName& shorter, int zoneId, SOAData* soaData);
  CacheResult fillSOAFromCache(SOAData* soaData, ZoneName& shorter);
};
