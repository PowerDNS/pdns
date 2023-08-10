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

#include <algorithm>
class DNSPacket;

#include "utility.hh"
#include <string>
#include <vector>
#include <map>
#include <sys/types.h>
#include "pdnsexception.hh"
#include <set>
#include <iostream>
#include <sys/socket.h>
#include <dirent.h>
#include "misc.hh"
#include "qtype.hh"
#include "dns.hh"
#include "namespaces.hh"
#include "comment.hh"
#include "dnsname.hh"
#include "dnsrecords.hh"
#include "iputils.hh"
#include "sha.hh"
#include "auth-catalogzone.hh"

class DNSBackend;
struct SOAData;

struct DomainInfo
{
  DomainInfo() : last_check(0), backend(nullptr), id(0), notified_serial(0), receivedNotify(false), serial(0), kind(DomainInfo::Native) {}

  DNSName zone;
  DNSName catalog;
  time_t last_check{};
  string options;
  string account;
  vector<ComboAddress> masters;
  DNSBackend *backend{};

  uint32_t id{};
  uint32_t notified_serial{};

  bool receivedNotify{};

  uint32_t serial{};

  bool operator<(const DomainInfo& rhs) const
  {
    return zone < rhs.zone;
  }

  // Do not reorder (lmdbbackend)!!! One exception 'All' is always last.
  enum DomainKind : uint8_t
  {
    Master,
    Slave,
    Native,
    Producer,
    Consumer,
    All
  } kind;

  [[nodiscard]] const char *getKindString() const
  {
    return DomainInfo::getKindString(kind);
  }

  static const char *getKindString(enum DomainKind kind)
  {
    const char* kinds[] = {"Master", "Slave", "Native", "Producer", "Consumer", "All"};
    return kinds[kind];
  }

  static DomainKind stringToKind(const string& kind)
  {
    if (pdns_iequals(kind, "SECONDARY") || pdns_iequals(kind, "SLAVE")) {
      return DomainInfo::Slave;
    }
    if (pdns_iequals(kind, "PRIMARY") || pdns_iequals(kind, "MASTER")) {
      return DomainInfo::Master;
    }
    if (pdns_iequals(kind, "PRODUCER")) {
      return DomainInfo::Producer;
    }
    if (pdns_iequals(kind, "CONSUMER")) {
      return DomainInfo::Consumer;
    }
    // No "ALL" here please. Yes, I really mean it...
    return DomainInfo::Native;
  }

  [[nodiscard]] bool isPrimaryType() const { return (kind == DomainInfo::Master || kind == DomainInfo::Producer); }
  [[nodiscard]] bool isSecondaryType() const { return (kind == DomainInfo::Slave || kind == DomainInfo::Consumer); }
  [[nodiscard]] bool isCatalogType() const { return (kind == DomainInfo::Producer || kind == DomainInfo::Consumer); }

  [[nodiscard]] bool isMaster(const ComboAddress& ipAddress) const
  {
    return std::any_of(masters.begin(), masters.end(), [ipAddress](auto master) { return ComboAddress::addressOnlyEqual()(ipAddress, master); });
  }
};

struct TSIGKey {
   DNSName name;
   DNSName algorithm;
   std::string key;
};

struct AutoPrimary {
   AutoPrimary(const string& new_ip, const string& new_nameserver, const string& new_account) :
     ip(new_ip), nameserver(new_nameserver), account(new_account){};
   std::string ip;
   std::string nameserver;
   std::string account;
};

class DNSPacket;

//! This virtual base class defines the interface for backends for PowerDNS.
/** To create a backend, inherit from this class and implement functions for all virtual methods.
    Methods should not throw an exception if they are sure they did not find the requested data. However,
    if an error occurred which prevented them temporarily from performing a lockup, they should throw a DBException,
    which will cause the nameserver to send out a ServFail or take other evasive action. Probably only locking
    issues should lead to DBExceptions.

    More serious errors, which may indicate that the database connection is hosed, or a configuration error occurred, should
    lead to the throwing of an PDNSException. This exception will fall straight through the UeberBackend and the PacketHandler
    and be caught by the Distributor, which will delete your DNSBackend instance and spawn a new one.
*/
class DNSBackend
{
public:
  //! lookup() initiates a lookup. A lookup without results should not throw!
  virtual void lookup(const QType &qtype, const DNSName &qdomain, int zoneId=-1, DNSPacket *pkt_p=nullptr)=0;
  virtual bool get(DNSResourceRecord &)=0; //!< retrieves one DNSResource record, returns false if no more were available
  virtual bool get(DNSZoneRecord &r);

  //! Initiates a list of the specified domain
  /** Once initiated, DNSResourceRecord objects can be retrieved using get(). Should return false
      if the backend does not consider itself responsible for the id passed.
      \param domain_id ID of which a list is requested
  */
  virtual bool list(const DNSName &target, int domain_id, bool include_disabled=false)=0;

  virtual ~DNSBackend(){};

  //! fills the soadata struct with the SOA details. Returns false if there is no SOA.
  virtual bool getSOA(const DNSName &name, SOAData &soadata);

  virtual bool replaceRRSet(uint32_t /* domain_id */, const DNSName& /* qname */, const QType& /* qt */, const vector<DNSResourceRecord>& /* rrset */)
  {
    return false;
  }

  virtual bool listSubZone(const DNSName& /* zone */, int /* domain_id */)
  {
    return false;
  }

  // the DNSSEC related (getDomainMetadata has broader uses too)
  static bool isDnssecDomainMetadata(const string& name)
  {
    return (name == "PRESIGNED" || name == "NSEC3PARAM" || name == "NSEC3NARROW");
  }
  virtual bool getAllDomainMetadata(const DNSName& /* name */, std::map<std::string, std::vector<std::string>>& /* meta */) { return false; };
  virtual bool getDomainMetadata(const DNSName& /* name */, const std::string& /* kind */, std::vector<std::string>& /* meta */) { return false; }
  virtual bool getDomainMetadataOne(const DNSName& name, const std::string& kind, std::string& value)
  {
    std::vector<std::string> meta;
    if (getDomainMetadata(name, kind, meta)) {
      if (!meta.empty()) {
        value = *meta.begin();
        return true;
      }
    }
    return false;
  }

  virtual bool setDomainMetadata(const DNSName& /* name */, const std::string& /* kind */, const std::vector<std::string>& /* meta */) { return false; }
  virtual bool setDomainMetadataOne(const DNSName& name, const std::string& kind, const std::string& value)
  {
    const std::vector<std::string> meta(1, value);
    return setDomainMetadata(name, kind, meta);
  }

  virtual void getAllDomains(vector<DomainInfo>* domains, bool getSerial, bool include_disabled);

  /** Determines if we are authoritative for a zone, and at what level */
  virtual bool getAuth(const DNSName& target, SOAData* /* sd */);

  struct KeyData {
    std::string content;
    unsigned int id{0};
    unsigned int flags{0};
    bool active{false};
    bool published{false};
  };

  virtual bool getDomainKeys(const DNSName& /* name */, std::vector<KeyData>& /* keys */) { return false; }
  virtual bool removeDomainKey(const DNSName& /* name */, unsigned int /* id */) { return false; }
  virtual bool addDomainKey(const DNSName& /* name */, const KeyData& /* key */, int64_t& /* id */) { return false; }
  virtual bool activateDomainKey(const DNSName& /* name */, unsigned int /* id */) { return false; }
  virtual bool deactivateDomainKey(const DNSName& /* name */, unsigned int /* id */) { return false; }
  virtual bool publishDomainKey(const DNSName& /* name */, unsigned int /* id */) { return false; }
  virtual bool unpublishDomainKey(const DNSName& /* name */, unsigned int /* id */) { return false; }

  virtual bool setTSIGKey(const DNSName& /* name */, const DNSName& /* algorithm */, const string& /* content */) { return false; }
  virtual bool getTSIGKey(const DNSName& /* name */, DNSName& /* algorithm */, string& /* content */) { return false; }
  virtual bool getTSIGKeys(std::vector<struct TSIGKey>& /* keys */) { return false; }
  virtual bool deleteTSIGKey(const DNSName& /* name */) { return false; }

  virtual bool getBeforeAndAfterNamesAbsolute(uint32_t /* id */, const DNSName& /* qname */, DNSName& /* unhashed */, DNSName& /* before */, DNSName& /* after */)
  {
    std::cerr << "Default beforeAndAfterAbsolute called!" << std::endl;
    abort();
    return false;
  }

  virtual bool getBeforeAndAfterNames(uint32_t /* id */, const DNSName& zonename, const DNSName& qname, DNSName& before, DNSName& after);

  virtual bool updateDNSSECOrderNameAndAuth(uint32_t /* domain_id */, const DNSName& /* qname */, const DNSName& /* ordername */, bool /* auth */, const uint16_t /* qtype */ = QType::ANY)
  {
    return false;
  }

  virtual bool updateEmptyNonTerminals(uint32_t /* domain_id */, set<DNSName>& /* insert */, set<DNSName>& /* erase */, bool /* remove */)
  {
    return false;
  }

  virtual bool doesDNSSEC()
  {
    return false;
  }

  // end DNSSEC

  // comments support
  virtual bool listComments(uint32_t /* domain_id */)
  {
    return false; // unsupported by this backend
  }

  virtual bool getComment(Comment& /* comment */)
  {
    return false;
  }

  virtual bool feedComment(const Comment& /* comment */)
  {
    return false;
  }

  virtual bool replaceComments(const uint32_t /* domain_id */, const DNSName& /* qname */, const QType& /* qt */, const vector<Comment>& /* comments */)
  {
    return false;
  }

  //! returns true if master ip is master for domain name.
  //! starts the transaction for updating domain qname (FIXME: what is id?)
  virtual bool startTransaction(const DNSName& /* qname */, int /* id */ = -1)
  {
    return false;
  }

  //! commits the transaction started by startTransaction
  virtual bool commitTransaction()
  {
    return false;
  }

  //! aborts the transaction started by startTransaction, should leave state unaltered
  virtual bool abortTransaction()
  {
    return false;
  }

  virtual bool inTransaction()
  {
    return false;
  }

  virtual void reload()
  {
  }

  virtual void rediscover(string* /* status */ = nullptr)
  {
  }

  //! feeds a record to a zone, needs a call to startTransaction first
  virtual bool feedRecord(const DNSResourceRecord& /* rr */, const DNSName& /* ordername */, bool /* ordernameIsNSEC3 */ = false)
  {
    return false; // no problem!
  }
  virtual bool feedEnts(int /* domain_id */, map<DNSName, bool>& /* nonterm */)
  {
    return false;
  }
  virtual bool feedEnts3(int /* domain_id */, const DNSName& /* domain */, map<DNSName, bool>& /* nonterm */, const NSEC3PARAMRecordContent& /* ns3prc */, bool /* narrow */)
  {
    return false;
  }

  //! if this returns true, DomainInfo di contains information about the domain
  virtual bool getDomainInfo(const DNSName& /* domain */, DomainInfo& /* di */, bool /* getSerial */ = true)
  {
    return false;
  }
  //! slave capable backends should return a list of slaves that should be rechecked for staleness
  virtual void getUnfreshSlaveInfos(vector<DomainInfo>* /* domains */)
  {
  }

  //! get a list of IP addresses that should also be notified for a domain
  virtual void alsoNotifies(const DNSName& domain, set<string>* ips)
  {
    std::vector<std::string> meta;
    getDomainMetadata(domain, "ALSO-NOTIFY", meta);
    ips->insert(meta.begin(), meta.end());
  }

  //! get list of domains that have been changed since their last notification to slaves
  virtual void getUpdatedMasters(vector<DomainInfo>& /* domains */, std::unordered_set<DNSName>& /* catalogs */, CatalogHashMap& /* catalogHashes */)
  {
  }

  //! get list of all members in a catalog
  virtual bool getCatalogMembers(const DNSName& /* catalog */, vector<CatalogInfo>& /* members */, CatalogInfo::CatalogType /* type */)
  {
    return false;
  }

  //! Called by PowerDNS to inform a backend that a domain need to be checked for freshness
  virtual void setStale(uint32_t /* domain_id */)
  {
  }

  //! Called by PowerDNS to inform a backend that a domain has been checked for freshness
  virtual void setFresh(uint32_t /* domain_id */)
  {
  }

  //! Called by PowerDNS to inform a backend that the changes in the domain have been reported to slaves
  virtual void setNotified(uint32_t /* id */, uint32_t /* serial */)
  {
  }

  //! Called when the Master list of a domain should be changed
  virtual bool setMasters(const DNSName& /* domain */, const vector<ComboAddress>& /* masters */)
  {
    return false;
  }

  //! Called when the Kind of a domain should be changed (master -> native and similar)
  virtual bool setKind(const DNSName& /* domain */, const DomainInfo::DomainKind /* kind */)
  {
    return false;
  }

  //! Called when the options of a domain should be changed
  virtual bool setOptions(const DNSName& /* domain */, const string& /* options */)
  {
    return false;
  }

  //! Called when the catalog of a domain should be changed
  virtual bool setCatalog(const DNSName& /* domain */, const DNSName& /* catalog */)
  {
    return false;
  }

  //! Called when the Account of a domain should be changed
  virtual bool setAccount(const DNSName& /* domain */, const string& /* account */)
  {
    return false;
  }

  //! Can be called to seed the getArg() function with a prefix
  void setArgPrefix(const string &prefix);

  //! Add an entry for a super master
  virtual bool superMasterAdd(const struct AutoPrimary& /* primary */)
  {
    return false;
  }

  //! Remove an entry for a super master
  virtual bool autoPrimaryRemove(const struct AutoPrimary& /* primary */)
  {
    return false;
  }

  //! List all SuperMasters, returns false if feature not supported.
  virtual bool autoPrimariesList(std::vector<AutoPrimary>& /* primaries */)
  {
    return false;
  }

  //! determine if ip is a supermaster or a domain
  virtual bool superMasterBackend(const string& /* ip */, const DNSName& /* domain */, const vector<DNSResourceRecord>& /* nsset */, string* /* nameserver */, string* /* account */, DNSBackend** /* db */)
  {
    return false;
  }

  //! called by PowerDNS to create a new domain
  virtual bool createDomain(const DNSName& /* domain */, const DomainInfo::DomainKind /* kind */, const vector<ComboAddress>& /* masters */, const string& /* account */)
  {
    return false;
  }

  //! called by PowerDNS to create a slave record for a superMaster
  virtual bool createSlaveDomain(const string& /* ip */, const DNSName& /* domain */, const string& /* nameserver */, const string& /* account */)
  {
    return false;
  }

  //! called to delete a domain, incl. all metadata, zone contents, etc.
  virtual bool deleteDomain(const DNSName& /* domain */)
  {
    return false;
  }

  virtual string directBackendCmd(const string& /* query */)
  {
    return "directBackendCmd not supported for this backend\n";
  }

  //! Search for records, returns true if search was done successfully.
  virtual bool searchRecords(const string& /* pattern */, int /* maxResults */, vector<DNSResourceRecord>& /* result */)
  {
    return false;
  }

  //! Search for comments, returns true if search was done successfully.
  virtual bool searchComments(const string& /* pattern */, int /* maxResults */, vector<Comment>& /* result */)
  {
    return false;
  }

  const string& getPrefix() { return d_prefix; };
protected:
  bool mustDo(const string &key);
  const string &getArg(const string &key);
  int getArgAsNum(const string &key);

private:
  string d_prefix;
};

class BackendFactory
{
public:
  BackendFactory(const string &name) : d_name(name) {}
  virtual ~BackendFactory(){}
  virtual DNSBackend *make(const string &suffix)=0;
  virtual DNSBackend *makeMetadataOnly(const string &suffix)
  {
    return this->make(suffix);
  }
  virtual void declareArguments(const string& /* suffix */ = "") {}
  [[nodiscard]] const string& getName() const;

protected:
  void declare(const string &suffix, const string &param, const string &explanation, const string &value);

private:
  const string d_name;
};

class BackendMakerClass
{
public:
  void report(BackendFactory *bf);
  void launch(const string &instr);
  vector<DNSBackend *> all(bool skipBIND=false);
  void load(const string &module);
  [[nodiscard]] size_t numLauncheable() const;
  vector<string> getModules();
  void clear();

private:
  void load_all();
  using d_repository_t = map<string, BackendFactory *>;
  d_repository_t d_repository;
  vector<pair<string,string> >d_instances;
};

extern BackendMakerClass &BackendMakers();

//! Exception that can be thrown by a DNSBackend to indicate a failure
class DBException : public PDNSException
{
public:
  DBException(const string &reason_) : PDNSException(reason_){}
};


struct SOAData
{
  SOAData() : domain_id(-1) {};

  DNSName qname;
  DNSName nameserver;
  DNSName hostmaster;
  uint32_t ttl{};
  uint32_t serial{};
  uint32_t refresh{};
  uint32_t retry{};
  uint32_t expire{};
  uint32_t minimum{};
  DNSBackend *db{};
  int domain_id{};

  [[nodiscard]] uint32_t getNegativeTTL() const { return min(ttl, minimum); }
};

/** helper function for both DNSPacket and addSOARecord() - converts a line into a struct, for easier parsing */
void fillSOAData(const string &content, SOAData &data);
// same but more karmic
void fillSOAData(const DNSZoneRecord& in, SOAData& data);
// the reverse
std::shared_ptr<DNSRecordContent> makeSOAContent(const SOAData& sd);
