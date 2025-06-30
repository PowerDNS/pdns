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
#include <string>
#include <map>
#include <set>
#include <pthread.h>
#include <time.h>
#include <fstream>
#include <mutex>
#include <boost/utility.hpp>

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/member.hpp>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "pdns/lock.hh"
#include "pdns/misc.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/namespaces.hh"
#include "pdns/backends/gsql/ssql.hh"

using namespace ::boost::multi_index;

/**
  This struct is used within the Bind2Backend to store DNS information. It is
  almost identical to a DNSResourceRecord, but then a bit smaller and with
  different sorting rules, which make sure that the SOA record comes up front.
*/

struct Bind2DNSRecord
{
  DNSName qname;
  string content;
  string nsec3hash;
  uint32_t ttl;
  uint16_t qtype;
  mutable bool auth;
  bool operator<(const Bind2DNSRecord& rhs) const
  {
    if (int rc = qname.canonCompare_three_way(rhs.qname); rc != 0) {
      return rc < 0;
    }
    if (qtype == QType::SOA && rhs.qtype != QType::SOA)
      return true;
    return std::tie(qtype, content, ttl) < std::tie(rhs.qtype, rhs.content, rhs.ttl);
  }
};

struct Bind2DNSCompare : std::less<Bind2DNSRecord>
{
  using std::less<Bind2DNSRecord>::operator();
  // use operator<
  bool operator()(const DNSName& a, const Bind2DNSRecord& b) const
  {
    return a.canonCompare(b.qname);
  }
  bool operator()(const Bind2DNSRecord& a, const DNSName& b) const
  {
    return a.qname.canonCompare(b);
  }
  bool operator()(const Bind2DNSRecord& a, const Bind2DNSRecord& b) const
  {
    return a.qname.canonCompare(b.qname);
  }
};

struct NSEC3Tag
{
};
struct UnorderedNameTag
{
};

typedef multi_index_container<
  Bind2DNSRecord,
  indexed_by<
    ordered_non_unique<identity<Bind2DNSRecord>, Bind2DNSCompare>,
    hashed_non_unique<tag<UnorderedNameTag>, member<Bind2DNSRecord, DNSName, &Bind2DNSRecord::qname>>,
    ordered_non_unique<tag<NSEC3Tag>, member<Bind2DNSRecord, std::string, &Bind2DNSRecord::nsec3hash>>>>
  recordstorage_t;

template <typename T>
class LookButDontTouch
{
public:
  LookButDontTouch() = default;
  LookButDontTouch(shared_ptr<T>&& records) :
    d_records(std::move(records))
  {
  }

  shared_ptr<const T> get()
  {
    return d_records;
  }

  size_t getEntriesCount() const
  {
    if (!d_records) {
      return 0;
    }
    return d_records->size();
  }

private:
  /* we can increase the number of references to that object,
     but never update the object itself */
  shared_ptr<const T> d_records;
};

/** Class which describes all metadata of a domain for storage by the Bind2Backend, and also contains a pointer to a vector of Bind2DNSRecord's */
class BB2DomainInfo
{
public:
  BB2DomainInfo();
  void setCtime();
  bool current();
  //! configure how often this domain should be checked for changes (on disk)
  void setCheckInterval(time_t seconds);
  time_t getCheckInterval() const
  {
    return d_checkinterval;
  }

  ZoneName d_name; //!< actual name of the domain
  DomainInfo::DomainKind d_kind{DomainInfo::Native}; //!< the kind of domain
  string d_filename; //!< full absolute filename of the zone on disk
  string d_status; //!< message describing status of a domain, for human consumption
  vector<ComboAddress> d_primaries; //!< IP address of the primary of this domain
  set<string> d_also_notify; //!< IP list of hosts to also notify
  LookButDontTouch<recordstorage_t> d_records; //!< the actual records belonging to this domain
  time_t d_ctime{0}; //!< last known ctime of the file on disk
  time_t d_lastcheck{0}; //!< last time domain was checked for freshness
  uint32_t d_lastnotified{0}; //!< Last serial number we notified our secondaries of
  domainid_t d_id{0}; //!< internal id of the domain
  mutable bool d_checknow; //!< if this domain has been flagged for a check
  bool d_loaded{false}; //!< if a domain is loaded
  bool d_wasRejectedLastReload{false}; //!< if the domain was rejected during Bind2Backend::queueReloadAndStore
  bool d_nsec3zone{false};
  NSEC3PARAMRecordContent d_nsec3param;

private:
  time_t getCtime();
  time_t d_checkinterval{0};
};

class SSQLite3;
class NSEC3PARAMRecordContent;

struct NameTag
{
};

class Bind2Backend : public DNSBackend
{
public:
  Bind2Backend(const string& suffix = "", bool loadZones = true);
  ~Bind2Backend() override;
  unsigned int getCapabilities() override;
  void getUnfreshSecondaryInfos(vector<DomainInfo>* unfreshDomains) override;
  void getUpdatedPrimaries(vector<DomainInfo>& changedDomains, std::unordered_set<DNSName>& catalogs, CatalogHashMap& catalogHashes) override;
  bool getDomainInfo(const ZoneName& domain, DomainInfo& info, bool getSerial = true) override;
  time_t getCtime(const string& fname);
  // DNSSEC
  bool getBeforeAndAfterNamesAbsolute(domainid_t id, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after) override;
  void lookup(const QType& qtype, const DNSName& qname, domainid_t zoneId, DNSPacket* p = nullptr) override;
  bool list(const ZoneName& target, domainid_t domainId, bool include_disabled = false) override;
  bool get(DNSResourceRecord&) override;
  void lookupEnd() override;
  void getAllDomains(vector<DomainInfo>* domains, bool getSerial, bool include_disabled = false) override;

  static DNSBackend* maker();
  static std::mutex s_startup_lock;

  void setStale(domainid_t domain_id) override;
  void setFresh(domainid_t domain_id) override;
  void setNotified(domainid_t id, uint32_t serial) override;
  bool startTransaction(const ZoneName& qname, domainid_t domainId) override;
  bool feedRecord(const DNSResourceRecord& rr, const DNSName& ordername, bool ordernameIsNSEC3 = false) override;
  bool commitTransaction() override;
  bool abortTransaction() override;
  void alsoNotifies(const ZoneName& domain, set<string>* ips) override;
  bool searchRecords(const string& pattern, size_t maxResults, vector<DNSResourceRecord>& result) override;

  // the DNSSEC related (getDomainMetadata has broader uses too)
  bool getAllDomainMetadata(const ZoneName& name, std::map<std::string, std::vector<std::string>>& meta) override;
  bool getDomainMetadata(const ZoneName& name, const std::string& kind, std::vector<std::string>& meta) override;
  bool setDomainMetadata(const ZoneName& name, const std::string& kind, const std::vector<std::string>& meta) override;
  bool getDomainKeys(const ZoneName& name, std::vector<KeyData>& keys) override;
  bool removeDomainKey(const ZoneName& name, unsigned int keyId) override;
  bool addDomainKey(const ZoneName& name, const KeyData& key, int64_t& keyId) override;
  bool activateDomainKey(const ZoneName& name, unsigned int keyId) override;
  bool deactivateDomainKey(const ZoneName& name, unsigned int keyId) override;
  bool publishDomainKey(const ZoneName& name, unsigned int keyId) override;
  bool unpublishDomainKey(const ZoneName& name, unsigned int keyId) override;
  bool getTSIGKey(const DNSName& name, DNSName& algorithm, string& content) override;
  bool setTSIGKey(const DNSName& name, const DNSName& algorithm, const string& content) override;
  bool deleteTSIGKey(const DNSName& name) override;
  bool getTSIGKeys(std::vector<struct TSIGKey>& keys) override;
  // end of DNSSEC

  typedef multi_index_container<BB2DomainInfo,
                                indexed_by<ordered_unique<member<BB2DomainInfo, domainid_t, &BB2DomainInfo::d_id>>,
                                           ordered_unique<tag<NameTag>, member<BB2DomainInfo, ZoneName, &BB2DomainInfo::d_name>>>>
    state_t;
  static SharedLockGuarded<state_t> s_state;

  void parseZoneFile(BB2DomainInfo* bbd);
  void rediscover(string* status = nullptr) override;

  // for autoprimary support
  bool autoPrimariesList(std::vector<AutoPrimary>& primaries) override;
  bool autoPrimaryBackend(const string& ipAddress, const ZoneName& domain, const vector<DNSResourceRecord>& nsset, string* nameserver, string* account, DNSBackend** backend) override;
  static std::mutex s_autosecondary_config_lock;
  bool createSecondaryDomain(const string& ipAddress, const ZoneName& domain, const string& nameserver, const string& account) override;

private:
  void setupDNSSEC();
  void setupStatements();
  void freeStatements();
  static bool safeGetBBDomainInfo(domainid_t id, BB2DomainInfo* bbd);
  static void safePutBBDomainInfo(const BB2DomainInfo& bbd);
  static bool safeGetBBDomainInfo(const ZoneName& name, BB2DomainInfo* bbd);
  static bool safeRemoveBBDomainInfo(const ZoneName& name);
  shared_ptr<SSQLite3> d_dnssecdb;
  bool getNSEC3PARAM(const ZoneName& name, NSEC3PARAMRecordContent* ns3p);
  static void setLastCheck(domainid_t domain_id, time_t lastcheck);
  bool getNSEC3PARAMuncached(const ZoneName& name, NSEC3PARAMRecordContent* ns3p);
  class handle
  {
  public:
    bool get(DNSResourceRecord&);
    void reset();

    handle();

    handle(const handle&) = delete;
    handle& operator=(const handle&) = delete; // don't go copying this

    shared_ptr<const recordstorage_t> d_records;
    recordstorage_t::index<UnorderedNameTag>::type::const_iterator d_iter, d_end_iter;

    recordstorage_t::const_iterator d_qname_iter, d_qname_end;

    DNSName qname;
    ZoneName domain;

    domainid_t id{UnknownDomainID};
    QType qtype;
    bool d_list{false};
    bool mustlog{false};

  private:
    bool get_normal(DNSResourceRecord&);
    bool get_list(DNSResourceRecord&);
  };

  unique_ptr<SSqlStatement> d_getAllDomainMetadataQuery_stmt;
  unique_ptr<SSqlStatement> d_getDomainMetadataQuery_stmt;
  unique_ptr<SSqlStatement> d_deleteDomainMetadataQuery_stmt;
  unique_ptr<SSqlStatement> d_insertDomainMetadataQuery_stmt;
  unique_ptr<SSqlStatement> d_getDomainKeysQuery_stmt;
  unique_ptr<SSqlStatement> d_deleteDomainKeyQuery_stmt;
  unique_ptr<SSqlStatement> d_insertDomainKeyQuery_stmt;
  unique_ptr<SSqlStatement> d_GetLastInsertedKeyIdQuery_stmt;
  unique_ptr<SSqlStatement> d_activateDomainKeyQuery_stmt;
  unique_ptr<SSqlStatement> d_deactivateDomainKeyQuery_stmt;
  unique_ptr<SSqlStatement> d_publishDomainKeyQuery_stmt;
  unique_ptr<SSqlStatement> d_unpublishDomainKeyQuery_stmt;
  unique_ptr<SSqlStatement> d_getTSIGKeyQuery_stmt;
  unique_ptr<SSqlStatement> d_setTSIGKeyQuery_stmt;
  unique_ptr<SSqlStatement> d_deleteTSIGKeyQuery_stmt;
  unique_ptr<SSqlStatement> d_getTSIGKeysQuery_stmt;

  ZoneName d_transaction_qname;
  string d_transaction_tmpname;
  string d_logprefix;
  set<string> alsoNotify; //!< this is used to store the also-notify list of interested peers.
  std::unique_ptr<ofstream> d_of;
  handle d_handle;
  static string s_binddirectory; //!< this is used to store the 'directory' setting of the bind configuration
  static int s_first; //!< this is raised on construction to prevent multiple instances of us being generated
  domainid_t d_transaction_id;
  static bool s_ignore_broken_records;
  bool d_hybrid;
  bool d_upgradeContent;

  BB2DomainInfo createDomainEntry(const ZoneName& domain, const string& filename); //!< does not insert in s_state

  void queueReloadAndStore(domainid_t id);
  static bool findBeforeAndAfterUnhashed(std::shared_ptr<const recordstorage_t>& records, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after);
  static void insertRecord(std::shared_ptr<recordstorage_t>& records, const ZoneName& zoneName, const DNSName& qname, const QType& qtype, const string& content, int ttl, const std::string& hashed = string(), const bool* auth = nullptr);
  void reload() override;
  static string DLDomStatusHandler(const vector<string>& parts, Utility::pid_t ppid);
  static string DLDomExtendedStatusHandler(const vector<string>& parts, Utility::pid_t ppid);
  static string DLListRejectsHandler(const vector<string>& parts, Utility::pid_t ppid);
  static string DLReloadNowHandler(const vector<string>& parts, Utility::pid_t ppid);
  static string DLAddDomainHandler(const vector<string>& parts, Utility::pid_t ppid);
  static void fixupOrderAndAuth(std::shared_ptr<recordstorage_t>& records, const ZoneName& zoneName, bool nsec3zone, const NSEC3PARAMRecordContent& ns3pr);
  static void doEmptyNonTerminals(std::shared_ptr<recordstorage_t>& records, const ZoneName& zoneName, bool nsec3zone, const NSEC3PARAMRecordContent& ns3pr);
  void loadConfig(string* status = nullptr);
};
