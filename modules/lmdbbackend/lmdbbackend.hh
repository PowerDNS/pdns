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
#include "pdns/dnsbackend.hh"
#include "ext/lmdb-safe/lmdb-typed.hh"

template <class T, typename std::enable_if<std::is_same<T, DNSName>::value, T>::type* = nullptr>
std::string keyConv(const T& t)
{
  /* www.ds9a.nl -> nl0ds9a0www0
     root -> 0   <- we need this to keep lmdb happy
     nl -> nl0
     
  */
  if (t.empty()) {
    throw std::out_of_range(std::string(__PRETTY_FUNCTION__) + " Attempt to serialize an unset dnsname");
  }

  if (t.isRoot()) {
    return std::string(1, (char)0);
  }

  std::string in = t.labelReverse().toDNSStringLC(); // www.ds9a.nl is now 2nl4ds9a3www0
  std::string ret;
  ret.reserve(in.size());

  for (auto iter = in.begin(); iter != in.end(); ++iter) {
    uint8_t len = *iter;
    if (iter != in.begin())
      ret.append(1, (char)0);
    if (!len)
      break;

    ret.append(&*(iter + 1), len);
    iter += len;
  }
  return ret;
}

class LMDBBackend : public DNSBackend
{
public:
  explicit LMDBBackend(const string& suffix = "");

  bool list(const DNSName& target, int id, bool include_disabled) override;

  bool getDomainInfo(const DNSName& domain, DomainInfo& di, bool getserial = true) override;
  bool createDomain(const DNSName& domain, const DomainInfo::DomainKind kind, const vector<ComboAddress>& primaries, const string& account) override;

  bool startTransaction(const DNSName& domain, int domain_id = -1) override;
  bool commitTransaction() override;
  bool abortTransaction() override;
  bool feedRecord(const DNSResourceRecord& r, const DNSName& ordername, bool ordernameIsNSEC3 = false) override;
  bool feedEnts(int domain_id, map<DNSName, bool>& nonterm) override;
  bool feedEnts3(int domain_id, const DNSName& domain, map<DNSName, bool>& nonterm, const NSEC3PARAMRecordContent& ns3prc, bool narrow) override;
  bool replaceRRSet(uint32_t domain_id, const DNSName& qname, const QType& qt, const vector<DNSResourceRecord>& rrset) override;
  bool replaceComments(uint32_t domain_id, const DNSName& qname, const QType& qt, const vector<Comment>& comments) override;

  void getAllDomains(vector<DomainInfo>* domains, bool doSerial, bool include_disabled) override;
  void lookup(const QType& type, const DNSName& qdomain, int zoneId, DNSPacket* p = nullptr) override;
  bool get(DNSResourceRecord& rr) override;
  bool get(DNSZoneRecord& dzr) override;

  // secondary support
  void getUnfreshSecondaryInfos(vector<DomainInfo>* domains) override;
  void setStale(uint32_t domain_id) override;
  void setFresh(uint32_t domain_id) override;

  // primary support
  void getUpdatedPrimaries(vector<DomainInfo>& updatedDomains, std::unordered_set<DNSName>& catalogs, CatalogHashMap& catalogHashes) override;
  void setNotified(uint32_t id, uint32_t serial) override;

  // catalog zones
  bool getCatalogMembers(const DNSName& catalog, vector<CatalogInfo>& members, CatalogInfo::CatalogType type) override;
  bool setOptions(const DNSName& domain, const std::string& options) override;
  bool setCatalog(const DNSName& domain, const DNSName& options) override;

  bool setPrimaries(const DNSName& domain, const vector<ComboAddress>& primaries) override;
  bool setKind(const DNSName& domain, const DomainInfo::DomainKind kind) override;
  bool getAllDomainMetadata(const DNSName& name, std::map<std::string, std::vector<std::string>>& meta) override;
  bool getDomainMetadata(const DNSName& name, const std::string& kind, std::vector<std::string>& meta) override
  {
    //    std::cout<<"Request for metadata items for zone "<<name<<", kind "<<kind<<endl;
    meta.clear();
    std::map<std::string, std::vector<std::string>> metas;
    if (getAllDomainMetadata(name, metas)) {
      for (const auto& m : metas) {
        if (m.first == kind) {
          meta = m.second;
          return true;
        }
      }
      return true;
    }
    return false;
  }

  bool setDomainMetadata(const DNSName& name, const std::string& kind, const std::vector<std::string>& meta) override;
  bool setAccount(const DNSName& domain, const std::string& account) override;
  bool deleteDomain(const DNSName& domain) override;

  bool getDomainKeys(const DNSName& name, std::vector<KeyData>& keys) override;
  bool removeDomainKey(const DNSName& name, unsigned int id) override;
  bool addDomainKey(const DNSName& name, const KeyData& key, int64_t& id) override;
  bool activateDomainKey(const DNSName& name, unsigned int id) override;
  bool deactivateDomainKey(const DNSName& name, unsigned int id) override;
  bool publishDomainKey(const DNSName& name, unsigned int id) override;
  bool unpublishDomainKey(const DNSName& name, unsigned int id) override;

  // TSIG
  bool getTSIGKey(const DNSName& name, DNSName& algorithm, string& content) override;
  bool setTSIGKey(const DNSName& name, const DNSName& algorithm, const string& content) override;
  bool deleteTSIGKey(const DNSName& name) override;
  bool getTSIGKeys(std::vector<struct TSIGKey>& keys) override;

  // DNSSEC

  bool getBeforeAndAfterNamesAbsolute(uint32_t id, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after) override;

  bool getBeforeAndAfterNames(uint32_t id, const DNSName& zonename, const DNSName& qname, DNSName& before, DNSName& after) override;

  bool updateDNSSECOrderNameAndAuth(uint32_t domain_id, const DNSName& qname, const DNSName& ordername, bool auth, const uint16_t qtype = QType::ANY) override;

  bool updateEmptyNonTerminals(uint32_t domain_id, set<DNSName>& insert, set<DNSName>& erase, bool remove) override;

  bool doesDNSSEC() override
  {
    return true;
  }

  // other
  string directBackendCmd(const string& query) override;

  // functions to use without constructing a backend object
  static std::pair<uint32_t, uint32_t> getSchemaVersionAndShards(std::string& filename);
  static bool upgradeToSchemav5(std::string& filename);

private:
  struct compoundOrdername
  {
    std::string operator()(uint32_t id, const DNSName& t, uint16_t qtype)
    {
      std::string ret = operator()(id, t);
      uint16_t qt = htons(qtype);
      ret.append((char*)&qt, 2);
      return ret;
    }
    std::string operator()(uint32_t id, const DNSName& t)
    {
      std::string ret = operator()(id);
      ret += keyConv(t);
      ret.append(1, (char)0); // this means '00' really ends the zone
      return ret;
    }
    std::string operator()(uint32_t id)
    {
      std::string ret;
      id = htonl(id);
      ret.assign((char*)&id, 4);
      return ret;
    }

    std::string operator()(const DNSResourceRecord& rr)
    {
      return operator()(rr.domain_id, rr.qname, rr.qtype.getCode());
    }

    static uint32_t getDomainID(const string_view& key)
    {
      uint32_t ret;
      memcpy(&ret, &key[0], sizeof(ret));
      return ntohl(ret);
    }

    static DNSName getQName(const string_view& key)
    {
      /* www.ds9a.nl -> nl0ds9a0www0
         root -> 0   <- we need this to keep lmdb happy
         nl -> nl0 */
      DNSName ret;
      auto iter = key.cbegin() + 4;
      auto end = key.cend() - 2;
      while (iter < end) {
        auto startpos = iter;
        while (iter != end && *iter)
          ++iter;
        if (iter == startpos)
          break;
        string part(&*startpos, iter - startpos);
        ret.prependRawLabel(part);
        //        cout << "Prepending part: "<<part<<endl;
        if (iter != end)
          ++iter;
      }
      if (ret.empty())
        return g_rootdnsname;
      return ret;
    }

    static QType getQType(const string_view& key)
    {
      uint16_t ret;
      memcpy(&ret, &key[key.size() - 2], sizeof(ret));
      return QType(ntohs(ret));
    }
  };

public:
  struct DomainMeta
  {
    DNSName domain;
    string key;
    string value;
  };
  struct KeyDataDB
  {
    DNSName domain;
    std::string content;
    unsigned int flags{0};
    bool active{true};
    bool published{true};
  };
  class LMDBResourceRecord : public DNSResourceRecord
  {
  public:
    LMDBResourceRecord() = default;
    LMDBResourceRecord(const DNSResourceRecord& rr) :
      DNSResourceRecord(rr), ordername(false) {}

    bool ordername{false};
  };

private:
  typedef TypedDBI<DomainInfo,
                   index_on<DomainInfo, DNSName, &DomainInfo::zone>>
    tdomains_t;

  typedef TypedDBI<DomainMeta,
                   index_on<DomainMeta, DNSName, &DomainMeta::domain>>
    tmeta_t;

  typedef TypedDBI<KeyDataDB,
                   index_on<KeyDataDB, DNSName, &KeyDataDB::domain>>
    tkdb_t;

  typedef TypedDBI<TSIGKey,
                   index_on<TSIGKey, DNSName, &TSIGKey::name>>
    ttsig_t;

  int d_asyncFlag;

  struct RecordsDB
  {
    shared_ptr<MDBEnv> env;
    MDBDbi dbi;
  };

  struct RecordsROTransaction
  {
    RecordsROTransaction(MDBROTransaction&& intxn) :
      txn(std::move(intxn))
    {}
    shared_ptr<RecordsDB> db;
    MDBROTransaction txn;
  };
  struct RecordsRWTransaction
  {
    RecordsRWTransaction(MDBRWTransaction&& intxn) :
      txn(std::move(intxn))
    {}
    shared_ptr<RecordsDB> db;
    MDBRWTransaction txn;
  };

  vector<RecordsDB> d_trecords;
  ;

  std::shared_ptr<MDBROCursor> d_getcursor;

  shared_ptr<tdomains_t> d_tdomains;
  shared_ptr<tmeta_t> d_tmeta;
  shared_ptr<tkdb_t> d_tkdb;
  shared_ptr<ttsig_t> d_ttsig;

  shared_ptr<RecordsROTransaction> d_rotxn; // for lookup and list
  shared_ptr<RecordsRWTransaction> d_rwtxn; // for feedrecord within begin/aborttransaction
  std::shared_ptr<RecordsRWTransaction> getRecordsRWTransaction(uint32_t id);
  std::shared_ptr<RecordsROTransaction> getRecordsROTransaction(uint32_t id, const std::shared_ptr<LMDBBackend::RecordsRWTransaction>& rwtxn = nullptr);
  int genChangeDomain(const DNSName& domain, const std::function<void(DomainInfo&)>& func);
  int genChangeDomain(uint32_t id, const std::function<void(DomainInfo&)>& func);
  void deleteDomainRecords(RecordsRWTransaction& txn, uint32_t domain_id, uint16_t qtype = QType::ANY);

  bool findDomain(const DNSName& domain, DomainInfo& info);
  bool findDomain(uint32_t domainid, DomainInfo& info);

  void getAllDomainsFiltered(vector<DomainInfo>* domains, const std::function<bool(DomainInfo&)>& allow);

  bool getSerial(DomainInfo& di);

  bool upgradeToSchemav3();

  bool get_list(DNSZoneRecord& rr);
  bool get_lookup(DNSZoneRecord& rr);
  std::string d_matchkey;
  DNSName d_lookupdomain;

  vector<LMDBResourceRecord> d_currentrrset;
  size_t d_currentrrsetpos;
  time_t d_currentrrsettime;
  MDBOutVal d_currentKey;
  MDBOutVal d_currentVal;
  bool d_includedisabled;

  DNSName d_transactiondomain;
  uint32_t d_transactiondomainid;
  bool d_dolog;
  bool d_random_ids;
  bool d_handle_dups;
  DTime d_dtime; // used only for logging
  uint64_t d_mapsize;
};
