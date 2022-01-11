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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "pdns/utility.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/dns.hh"
#include "pdns/dnspacket.hh"
#include "pdns/base32.hh"
#include "pdns/dnssecinfra.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/logger.hh"
#include "pdns/version.hh"
#include "pdns/arguments.hh"
#include "pdns/lock.hh"
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/string.hpp>
#include <boost/serialization/utility.hpp>

#include <boost/iostreams/device/back_inserter.hpp>

#include <stdio.h>
#include <unistd.h>

#include "lmdbbackend.hh"

#define SCHEMAVERSION 3

// List the class version here. Default is 0
BOOST_CLASS_VERSION(LMDBBackend::KeyDataDB, 1)

static bool s_first = true;
static int s_shards = 0;
static std::mutex s_lmdbStartupLock;

LMDBBackend::LMDBBackend(const std::string& suffix)
{
  // overlapping domain ids in combination with relative names are a recipe for disaster
  if (!suffix.empty()) {
    throw std::runtime_error("LMDB backend does not support multiple instances");
  }

  setArgPrefix("lmdb" + suffix);

  string syncMode = toLower(getArg("sync-mode"));

  if (syncMode == "nosync")
    d_asyncFlag = MDB_NOSYNC;
  else if (syncMode == "nometasync")
    d_asyncFlag = MDB_NOMETASYNC;
  else if (syncMode == "mapasync")
    d_asyncFlag = MDB_MAPASYNC;
  else if (syncMode.empty() || syncMode == "sync")
    d_asyncFlag = 0;
  else
    throw std::runtime_error("Unknown sync mode " + syncMode + " requested for LMDB backend");

  d_tdomains = std::make_shared<tdomains_t>(getMDBEnv(getArg("filename").c_str(), MDB_NOSUBDIR | d_asyncFlag, 0600), "domains");
  d_tmeta = std::make_shared<tmeta_t>(d_tdomains->getEnv(), "metadata");
  d_tkdb = std::make_shared<tkdb_t>(d_tdomains->getEnv(), "keydata");
  d_ttsig = std::make_shared<ttsig_t>(d_tdomains->getEnv(), "tsig");

  auto pdnsdbi = d_tdomains->getEnv()->openDB("pdns", MDB_CREATE);

  if (s_first) {
    std::lock_guard<std::mutex> l(s_lmdbStartupLock);
    if (s_first) {
      auto txn = d_tdomains->getEnv()->getRWTransaction();

      uint32_t schemaversion = 1;
      MDBOutVal _schemaversion;
      if (!txn->get(pdnsdbi, "schemaversion", _schemaversion)) {
        schemaversion = _schemaversion.get<uint32_t>();
      }

      if (schemaversion != SCHEMAVERSION) {
        if (getArgAsNum("schema-version") != SCHEMAVERSION) {
          throw std::runtime_error("Expected LMDB schema version " + std::to_string(SCHEMAVERSION) + " but got " + std::to_string(schemaversion));
        }
        txn->put(pdnsdbi, "schemaversion", SCHEMAVERSION);
      }

      MDBOutVal shards;
      if (!txn->get(pdnsdbi, "shards", shards)) {
        s_shards = shards.get<uint32_t>();
        if (s_shards != atoi(getArg("shards").c_str())) {
          g_log << Logger::Warning << "Note: configured number of lmdb shards (" << atoi(getArg("shards").c_str()) << ") is different from on-disk (" << s_shards << "). Using on-disk shard number" << endl;
        }
      }
      else {
        s_shards = atoi(getArg("shards").c_str());
        txn->put(pdnsdbi, "shards", s_shards);
      }

      txn->commit();

      if (schemaversion < 3) {
        if (!upgradeToSchemav3()) {
          throw std::runtime_error("Failed to perform LMDB schema version upgrade to " + std::to_string(SCHEMAVERSION) + " from " + std::to_string(schemaversion));
        }
      }
      s_first = false;
    }
  }

  d_trecords.resize(s_shards);
  d_dolog = ::arg().mustDo("query-logging");
}

namespace boost
{
namespace serialization
{

  template <class Archive>
  void save(Archive& ar, const DNSName& g, const unsigned int version)
  {
    if (!g.empty()) {
      std::string tmp = g.toDNSStringLC(); // g++ 4.8 woes
      ar& tmp;
    }
    else
      ar & "";
  }

  template <class Archive>
  void load(Archive& ar, DNSName& g, const unsigned int version)
  {
    string tmp;
    ar& tmp;
    if (tmp.empty())
      g = DNSName();
    else
      g = DNSName(tmp.c_str(), tmp.size(), 0, false);
  }

  template <class Archive>
  void save(Archive& ar, const QType& g, const unsigned int version)
  {
    uint16_t tmp = g.getCode(); // g++ 4.8 woes
    ar& tmp;
  }

  template <class Archive>
  void load(Archive& ar, QType& g, const unsigned int version)
  {
    uint16_t tmp;
    ar& tmp;
    g = QType(tmp);
  }

  template <class Archive>
  void serialize(Archive& ar, DomainInfo& g, const unsigned int version)
  {
    ar& g.zone;
    ar& g.last_check;
    ar& g.account;
    ar& g.masters;
    ar& g.id;
    ar& g.notified_serial;
    ar& g.kind;
  }

  template <class Archive>
  void serialize(Archive& ar, LMDBBackend::DomainMeta& g, const unsigned int version)
  {
    ar& g.domain& g.key& g.value;
  }

  template <class Archive>
  void save(Archive& ar, const LMDBBackend::KeyDataDB& g, const unsigned int version)
  {
    ar& g.domain& g.content& g.flags& g.active& g.published;
  }

  template <class Archive>
  void load(Archive& ar, LMDBBackend::KeyDataDB& g, const unsigned int version)
  {
    ar& g.domain& g.content& g.flags& g.active;
    if (version >= 1) {
      ar& g.published;
    }
    else {
      g.published = true;
    }
  }

  template <class Archive>
  void serialize(Archive& ar, TSIGKey& g, const unsigned int version)
  {
    ar& g.name;
    ar& g.algorithm; // this is the ordername
    ar& g.key;
  }

} // namespace serialization
} // namespace boost

BOOST_SERIALIZATION_SPLIT_FREE(DNSName);
BOOST_SERIALIZATION_SPLIT_FREE(QType);
BOOST_SERIALIZATION_SPLIT_FREE(LMDBBackend::KeyDataDB);
BOOST_IS_BITWISE_SERIALIZABLE(ComboAddress);

template <>
std::string serToString(const LMDBBackend::LMDBResourceRecord& lrr)
{
  std::string ret;
  uint16_t len = lrr.content.length();
  ret.reserve(2 + len + 7);

  ret.assign((const char*)&len, 2);
  ret += lrr.content;
  ret.append((const char*)&lrr.ttl, 4);
  ret.append(1, (char)lrr.auth);
  ret.append(1, (char)lrr.disabled);
  ret.append(1, (char)lrr.ordername);
  return ret;
}

template <>
std::string serToString(const vector<LMDBBackend::LMDBResourceRecord>& lrrs)
{
  std::string ret;
  for (const auto& lrr : lrrs) {
    ret += serToString(lrr);
  }
  return ret;
}

static inline size_t serOneRRFromString(const string_view& str, LMDBBackend::LMDBResourceRecord& lrr)
{
  uint16_t len;
  memcpy(&len, &str[0], 2);
  lrr.content.assign(&str[2], len); // len bytes
  memcpy(&lrr.ttl, &str[2] + len, 4);
  lrr.auth = str[2 + len + 4];
  lrr.disabled = str[2 + len + 4 + 1];
  lrr.ordername = str[2 + len + 4 + 2];
  lrr.wildcardname.clear();

  return 2 + len + 7;
}

template <>
void serFromString(const string_view& str, LMDBBackend::LMDBResourceRecord& lrr)
{
  serOneRRFromString(str, lrr);
}

template <>
void serFromString(const string_view& str, vector<LMDBBackend::LMDBResourceRecord>& lrrs)
{
  auto str_copy = str;
  while (str_copy.size() >= 9) { // minimum length for a record is 10
    LMDBBackend::LMDBResourceRecord lrr;
    auto rrLength = serOneRRFromString(str_copy, lrr);
    lrrs.emplace_back(lrr);
    str_copy.remove_prefix(rrLength);
  }
}

static std::string serializeContent(uint16_t qtype, const DNSName& domain, const std::string& content)
{
  auto drc = DNSRecordContent::mastermake(qtype, QClass::IN, content);
  return drc->serialize(domain, false);
}

static std::shared_ptr<DNSRecordContent> deserializeContentZR(uint16_t qtype, const DNSName& qname, const std::string& content)
{
  if (qtype == QType::A && content.size() == 4) {
    return std::make_shared<ARecordContent>(*((uint32_t*)content.c_str()));
  }
  return DNSRecordContent::deserialize(qname, qtype, content);
}

/* design. If you ask a question without a zone id, we lookup the best
   zone id for you, and answer from that. This is different than other backends, but I can't see why it would not work.

   The index we use is "zoneid,canonical relative name". This index is also used
   for AXFR.

   Note - domain_id, name and type are ONLY present on the index!
*/

#if BOOST_VERSION >= 106100
#define StringView string_view
#else
#define StringView string
#endif

void LMDBBackend::deleteDomainRecords(RecordsRWTransaction& txn, uint32_t domain_id, uint16_t qtype)
{
  compoundOrdername co;
  string match = co(domain_id);

  auto cursor = txn.txn->getCursor(txn.db->dbi);
  MDBOutVal key, val;
  //  cout<<"Match: "<<makeHexDump(match);
  if (!cursor.lower_bound(match, key, val)) {
    while (key.get<StringView>().rfind(match, 0) == 0) {
      if (qtype == QType::ANY || co.getQType(key.get<StringView>()) == qtype)
        cursor.del();
      if (cursor.next(key, val))
        break;
    }
  }
}

/* Here's the complicated story. Other backends have just one transaction, which is either
   on or not. 
   
   You can't call feedRecord without a transaction started with startTransaction.

   However, other functions can be called after startTransaction() or without startTransaction()
     (like updateDNSSECOrderNameAndAuth)



*/

bool LMDBBackend::startTransaction(const DNSName& domain, int domain_id)
{
  // cout <<"startTransaction("<<domain<<", "<<domain_id<<")"<<endl;
  int real_id = domain_id;
  if (real_id < 0) {
    auto rotxn = d_tdomains->getROTransaction();
    DomainInfo di;
    real_id = rotxn.get<0>(domain, di);
    // cout<<"real_id = "<<real_id << endl;
    if (!real_id)
      return false;
  }
  if (d_rwtxn) {
    throw DBException("Attempt to start a transaction while one was open already");
  }
  d_rwtxn = getRecordsRWTransaction(real_id);

  d_transactiondomain = domain;
  d_transactiondomainid = real_id;
  if (domain_id >= 0) {
    deleteDomainRecords(*d_rwtxn, domain_id);
  }

  return true;
}

bool LMDBBackend::commitTransaction()
{
  // cout<<"Commit transaction" <<endl;
  if (!d_rwtxn) {
    throw DBException("Attempt to commit a transaction while there isn't one open");
  }

  d_rwtxn->txn->commit();
  d_rwtxn.reset();
  return true;
}

bool LMDBBackend::abortTransaction()
{
  // cout<<"Abort transaction"<<endl;
  if (!d_rwtxn) {
    throw DBException("Attempt to abort a transaction while there isn't one open");
  }

  d_rwtxn->txn->abort();
  d_rwtxn.reset();

  return true;
}

// d_rwtxn must be set here
bool LMDBBackend::feedRecord(const DNSResourceRecord& r, const DNSName& ordername, bool ordernameIsNSEC3)
{
  LMDBResourceRecord lrr(r);
  lrr.qname.makeUsRelative(d_transactiondomain);
  lrr.content = serializeContent(lrr.qtype.getCode(), r.qname, lrr.content);

  compoundOrdername co;
  string matchName = co(lrr.domain_id, lrr.qname, lrr.qtype.getCode());

  string rrs;
  MDBOutVal _rrs;
  if (!d_rwtxn->txn->get(d_rwtxn->db->dbi, matchName, _rrs)) {
    rrs = _rrs.get<string>();
  }

  rrs += serToString(lrr);

  d_rwtxn->txn->put(d_rwtxn->db->dbi, matchName, rrs);

  if (ordernameIsNSEC3 && !ordername.empty()) {
    MDBOutVal val;
    if (d_rwtxn->txn->get(d_rwtxn->db->dbi, co(lrr.domain_id, lrr.qname, QType::NSEC3), val)) {
      lrr.ttl = 0;
      lrr.content = lrr.qname.toDNSStringLC();
      lrr.auth = 0;
      string ser = serToString(lrr);
      d_rwtxn->txn->put(d_rwtxn->db->dbi, co(lrr.domain_id, ordername, QType::NSEC3), ser);

      lrr.ttl = 1;
      lrr.content = ordername.toDNSString();
      ser = serToString(lrr);
      d_rwtxn->txn->put(d_rwtxn->db->dbi, co(lrr.domain_id, lrr.qname, QType::NSEC3), ser);
    }
  }
  return true;
}

bool LMDBBackend::feedEnts(int domain_id, map<DNSName, bool>& nonterm)
{
  LMDBResourceRecord lrr;
  lrr.ttl = 0;
  compoundOrdername co;
  for (const auto& nt : nonterm) {
    lrr.qname = nt.first.makeRelative(d_transactiondomain);
    lrr.auth = nt.second;
    lrr.ordername = true;

    std::string ser = serToString(lrr);
    d_rwtxn->txn->put(d_rwtxn->db->dbi, co(domain_id, lrr.qname, QType::ENT), ser);
  }
  return true;
}

bool LMDBBackend::feedEnts3(int domain_id, const DNSName& domain, map<DNSName, bool>& nonterm, const NSEC3PARAMRecordContent& ns3prc, bool narrow)
{
  string ser;
  DNSName ordername;
  LMDBResourceRecord lrr;
  compoundOrdername co;
  for (const auto& nt : nonterm) {
    lrr.qname = nt.first.makeRelative(domain);
    lrr.ttl = 0;
    lrr.auth = nt.second;
    lrr.ordername = nt.second;
    ser = serToString(lrr);
    d_rwtxn->txn->put(d_rwtxn->db->dbi, co(domain_id, lrr.qname, QType::ENT), ser);

    if (!narrow && lrr.auth) {
      lrr.content = lrr.qname.toDNSString();
      lrr.auth = false;
      lrr.ordername = false;
      ser = serToString(lrr);

      ordername = DNSName(toBase32Hex(hashQNameWithSalt(ns3prc, nt.first)));
      d_rwtxn->txn->put(d_rwtxn->db->dbi, co(domain_id, ordername, QType::NSEC3), ser);

      lrr.ttl = 1;
      lrr.content = ordername.toDNSString();
      ser = serToString(lrr);
      d_rwtxn->txn->put(d_rwtxn->db->dbi, co(domain_id, lrr.qname, QType::NSEC3), ser);
    }
  }
  return true;
}

// might be called within a transaction, might also be called alone
bool LMDBBackend::replaceRRSet(uint32_t domain_id, const DNSName& qname, const QType& qt, const vector<DNSResourceRecord>& rrset)
{
  // zonk qname/qtype within domain_id (go through qname, check domain_id && qtype)
  shared_ptr<RecordsRWTransaction> txn;
  bool needCommit = false;
  if (d_rwtxn && d_transactiondomainid == domain_id) {
    txn = d_rwtxn;
    //    cout<<"Reusing open transaction"<<endl;
  }
  else {
    //    cout<<"Making a new RW txn for replace rrset"<<endl;
    txn = getRecordsRWTransaction(domain_id);
    needCommit = true;
  }

  DomainInfo di;
  if (!d_tdomains->getROTransaction().get(domain_id, di)) {
    return false;
  }

  compoundOrdername co;
  auto cursor = txn->txn->getCursor(txn->db->dbi);
  MDBOutVal key, val;
  string match = co(domain_id, qname.makeRelative(di.zone), qt.getCode());
  if (!cursor.find(match, key, val)) {
    cursor.del();
  }

  if (!rrset.empty()) {
    vector<LMDBResourceRecord> adjustedRRSet;
    for (auto rr : rrset) {
      LMDBResourceRecord lrr(rr);
      lrr.content = serializeContent(lrr.qtype.getCode(), lrr.qname, lrr.content);
      lrr.qname.makeUsRelative(di.zone);

      adjustedRRSet.emplace_back(lrr);
    }
    txn->txn->put(txn->db->dbi, match, serToString(adjustedRRSet));
  }

  if (needCommit)
    txn->txn->commit();

  return true;
}

// tempting to templatize these two functions but the pain is not worth it
std::shared_ptr<LMDBBackend::RecordsRWTransaction> LMDBBackend::getRecordsRWTransaction(uint32_t id)
{
  auto& shard = d_trecords[id % s_shards];
  if (!shard.env) {
    shard.env = getMDBEnv((getArg("filename") + "-" + std::to_string(id % s_shards)).c_str(),
                          MDB_NOSUBDIR | d_asyncFlag, 0600);
    shard.dbi = shard.env->openDB("records", MDB_CREATE);
  }
  auto ret = std::make_shared<RecordsRWTransaction>(shard.env->getRWTransaction());
  ret->db = std::make_shared<RecordsDB>(shard);

  return ret;
}

std::shared_ptr<LMDBBackend::RecordsROTransaction> LMDBBackend::getRecordsROTransaction(uint32_t id, std::shared_ptr<LMDBBackend::RecordsRWTransaction> rwtxn)
{
  auto& shard = d_trecords[id % s_shards];
  if (!shard.env) {
    if (rwtxn) {
      throw DBException("attempting to start nested transaction without open parent env");
    }
    shard.env = getMDBEnv((getArg("filename") + "-" + std::to_string(id % s_shards)).c_str(),
                          MDB_NOSUBDIR | d_asyncFlag, 0600);
    shard.dbi = shard.env->openDB("records", MDB_CREATE);
  }

  if (rwtxn) {
    auto ret = std::make_shared<RecordsROTransaction>(rwtxn->txn->getROTransaction());
    ret->db = std::make_shared<RecordsDB>(shard);
    return ret;
  }
  else {
    auto ret = std::make_shared<RecordsROTransaction>(shard.env->getROTransaction());
    ret->db = std::make_shared<RecordsDB>(shard);
    return ret;
  }
}

bool LMDBBackend::upgradeToSchemav3()
{
  g_log << Logger::Warning << "Upgrading LMDB schema" << endl;

  for (auto i = 0; i < s_shards; i++) {
    string filename = getArg("filename") + "-" + std::to_string(i);
    if (rename(filename.c_str(), (filename + "-old").c_str()) < 0) {
      if (errno == ENOENT) {
        // apparently this shard doesn't exist yet, moving on
        continue;
      }
      unixDie("Rename failed during LMDB upgrade");
    }

    LMDBBackend::RecordsDB oldShard, newShard;

    oldShard.env = getMDBEnv((filename + "-old").c_str(),
                             MDB_NOSUBDIR | d_asyncFlag, 0600);
    oldShard.dbi = oldShard.env->openDB("records", MDB_CREATE | MDB_DUPSORT);
    auto txn = oldShard.env->getROTransaction();
    auto cursor = txn->getROCursor(oldShard.dbi);

    newShard.env = getMDBEnv((filename).c_str(),
                             MDB_NOSUBDIR | d_asyncFlag, 0600);
    newShard.dbi = newShard.env->openDB("records", MDB_CREATE);
    auto newTxn = newShard.env->getRWTransaction();

    MDBOutVal key, val;
    if (cursor.first(key, val) != 0) {
      cursor.close();
      txn->abort();
      newTxn->abort();
      continue;
    }
    string_view currentKey;
    string value;
    for (;;) {
      auto newKey = key.get<string_view>();
      if (currentKey.compare(newKey) != 0) {
        if (value.size() > 0) {
          newTxn->put(newShard.dbi, currentKey, value);
        }
        currentKey = newKey;
        value = "";
      }
      value += val.get<string>();
      if (cursor.next(key, val) != 0) {
        if (value.size() > 0) {
          newTxn->put(newShard.dbi, currentKey, value);
        }
        break;
      }
    }

    cursor.close();
    txn->commit();
    newTxn->commit();
  }

  return true;
}

bool LMDBBackend::deleteDomain(const DNSName& domain)
{
  auto doms = d_tdomains->getRWTransaction();

  DomainInfo di;
  auto id = doms.get<0>(domain, di);
  if (!id)
    return false;

  shared_ptr<RecordsRWTransaction> txn;
  bool needCommit = false;
  if (d_rwtxn && d_transactiondomainid == id) {
    txn = d_rwtxn;
    //    cout<<"Reusing open transaction"<<endl;
  }
  else {
    //    cout<<"Making a new RW txn for delete domain"<<endl;
    txn = getRecordsRWTransaction(id);
    needCommit = true;
  }

  doms.del(id);
  deleteDomainRecords(*txn, id);

  if (needCommit)
    txn->txn->commit();

  doms.commit();

  return true;
}

bool LMDBBackend::list(const DNSName& target, int id, bool include_disabled)
{
  d_includedisabled = include_disabled;

  DomainInfo di;
  {
    auto dtxn = d_tdomains->getROTransaction();
    if ((di.id = dtxn.get<0>(target, di)))
      ; //      cout<<"Found domain "<<target<<" on domain_id "<<di.id <<", list requested "<<id<<endl;
    else {
      // cout<<"Did not find "<<target<<endl;
      return false;
    }
  }

  d_rotxn = getRecordsROTransaction(di.id, d_rwtxn);
  d_getcursor = std::make_shared<MDBROCursor>(d_rotxn->txn->getCursor(d_rotxn->db->dbi));

  compoundOrdername co;
  d_matchkey = co(di.id);

  MDBOutVal key, val;
  if (d_getcursor->lower_bound(d_matchkey, key, val) || key.get<StringView>().rfind(d_matchkey, 0) != 0) {
    // cout<<"Found nothing for list"<<endl;
    d_getcursor.reset();
  }

  d_lookupdomain = target;

  // Make sure we start with fresh data
  d_currentrrset.clear();
  d_currentrrsetpos = 0;

  return true;
}

void LMDBBackend::lookup(const QType& type, const DNSName& qdomain, int zoneId, DNSPacket* p)
{
  if (d_dolog) {
    g_log << Logger::Warning << "Got lookup for " << qdomain << "|" << type.toString() << " in zone " << zoneId << endl;
    d_dtime.set();
  }

  d_includedisabled = false;

  DNSName hunt(qdomain);
  DomainInfo di;
  if (zoneId < 0) {
    auto rotxn = d_tdomains->getROTransaction();

    do {
      zoneId = rotxn.get<0>(hunt, di);
    } while (!zoneId && type != QType::SOA && hunt.chopOff());
    if (zoneId <= 0) {
      //      cout << "Did not find zone for "<< qdomain<<endl;
      d_getcursor.reset();
      return;
    }
  }
  else {
    if (!d_tdomains->getROTransaction().get(zoneId, di)) {
      // cout<<"Could not find a zone with id "<<zoneId<<endl;
      d_getcursor.reset();
      return;
    }
    hunt = di.zone;
  }

  DNSName relqname = qdomain.makeRelative(hunt);
  if (relqname.empty()) {
    return;
  }
  // cout<<"get will look for "<<relqname<< " in zone "<<hunt<<" with id "<<zoneId<<" and type "<<type.toString()<<endl;
  d_rotxn = getRecordsROTransaction(zoneId, d_rwtxn);

  compoundOrdername co;
  d_getcursor = std::make_shared<MDBROCursor>(d_rotxn->txn->getCursor(d_rotxn->db->dbi));
  MDBOutVal key, val;
  if (type.getCode() == QType::ANY) {
    d_matchkey = co(zoneId, relqname);
  }
  else {
    d_matchkey = co(zoneId, relqname, type.getCode());
  }

  if (d_getcursor->lower_bound(d_matchkey, key, val) || key.get<StringView>().rfind(d_matchkey, 0) != 0) {
    d_getcursor.reset();
    if (d_dolog) {
      g_log << Logger::Warning << "Query " << ((long)(void*)this) << ": " << d_dtime.udiffNoReset() << " usec to execute (found nothing)" << endl;
    }
    return;
  }

  if (d_dolog) {
    g_log << Logger::Warning << "Query " << ((long)(void*)this) << ": " << d_dtime.udiffNoReset() << " usec to execute" << endl;
  }

  d_lookupdomain = hunt;

  // Make sure we start with fresh data
  d_currentrrset.clear();
  d_currentrrsetpos = 0;
}

bool LMDBBackend::get(DNSZoneRecord& zr)
{
  for (;;) {
    if (!d_getcursor) {
      d_rotxn.reset();
      return false;
    }

    string_view key;

    if (d_currentrrset.empty()) {
      d_getcursor->current(d_currentKey, d_currentVal);

      key = d_currentKey.get<string_view>();
      zr.dr.d_type = compoundOrdername::getQType(key).getCode();

      if (zr.dr.d_type == QType::NSEC3) {
        // Hit a magic NSEC3 skipping
        if (d_getcursor->next(d_currentKey, d_currentVal) || d_currentKey.get<StringView>().rfind(d_matchkey, 0) != 0) {
          d_getcursor.reset();
        }
        continue;
      }

      serFromString(d_currentVal.get<string>(), d_currentrrset);
      d_currentrrsetpos = 0;
    }
    else {
      key = d_currentKey.get<string_view>();
    }
    try {
      const auto& lrr = d_currentrrset.at(d_currentrrsetpos++);

      zr.disabled = lrr.disabled;
      if (!zr.disabled || d_includedisabled) {
        zr.dr.d_name = compoundOrdername::getQName(key) + d_lookupdomain;
        zr.domain_id = compoundOrdername::getDomainID(key);
        zr.dr.d_type = compoundOrdername::getQType(key).getCode();
        zr.dr.d_ttl = lrr.ttl;
        zr.dr.d_content = deserializeContentZR(zr.dr.d_type, zr.dr.d_name, lrr.content);
        zr.auth = lrr.auth;
      }

      if (d_currentrrsetpos >= d_currentrrset.size()) {
        d_currentrrset.clear(); // will invalidate lrr
        if (d_getcursor->next(d_currentKey, d_currentVal) || d_currentKey.get<StringView>().rfind(d_matchkey, 0) != 0) {
          d_getcursor.reset();
        }
      }

      if (zr.disabled && !d_includedisabled) {
        continue;
      }
    }
    catch (const std::exception& e) {
      throw PDNSException(e.what());
    }

    break;
  }

  return true;
}

bool LMDBBackend::get(DNSResourceRecord& rr)
{
  DNSZoneRecord zr;
  if (!get(zr)) {
    return false;
  }

  rr.qname = zr.dr.d_name;
  rr.ttl = zr.dr.d_ttl;
  rr.qtype = zr.dr.d_type;
  rr.content = zr.dr.d_content->getZoneRepresentation(true);
  rr.domain_id = zr.domain_id;
  rr.auth = zr.auth;
  rr.disabled = zr.disabled;

  return true;
}

bool LMDBBackend::getSerial(DomainInfo& di)
{
  auto txn = getRecordsROTransaction(di.id);
  compoundOrdername co;
  MDBOutVal val;
  if (!txn->txn->get(txn->db->dbi, co(di.id, g_rootdnsname, QType::SOA), val)) {
    LMDBResourceRecord lrr;
    serFromString(val.get<string_view>(), lrr);
    if (lrr.content.size() >= 5 * sizeof(uint32_t)) {
      uint32_t serial;
      // a SOA has five 32 bit fields, the first of which is the serial
      // there are two variable length names before the serial, so we calculate from the back
      memcpy(&serial, &lrr.content[lrr.content.size() - (5 * sizeof(uint32_t))], sizeof(serial));
      di.serial = ntohl(serial);
    }
    return !lrr.disabled;
  }
  return false;
}

bool LMDBBackend::getDomainInfo(const DNSName& domain, DomainInfo& di, bool getserial)
{
  {
    auto txn = d_tdomains->getROTransaction();

    if (!(di.id = txn.get<0>(domain, di)))
      return false;
    di.backend = this;
  }

  if (getserial) {
    getSerial(di);
  }

  return true;
}

int LMDBBackend::genChangeDomain(const DNSName& domain, std::function<void(DomainInfo&)> func)
{
  auto txn = d_tdomains->getRWTransaction();

  DomainInfo di;

  auto id = txn.get<0>(domain, di);
  func(di);
  txn.put(di, id);

  txn.commit();
  return true;
}

int LMDBBackend::genChangeDomain(uint32_t id, std::function<void(DomainInfo&)> func)
{
  DomainInfo di;

  auto txn = d_tdomains->getRWTransaction();

  if (!txn.get(id, di))
    return false;

  func(di);

  txn.put(di, id);

  txn.commit();
  return true;
}

bool LMDBBackend::setKind(const DNSName& domain, const DomainInfo::DomainKind kind)
{
  return genChangeDomain(domain, [kind](DomainInfo& di) {
    di.kind = kind;
  });
}

bool LMDBBackend::setAccount(const DNSName& domain, const std::string& account)
{
  return genChangeDomain(domain, [account](DomainInfo& di) {
    di.account = account;
  });
}

void LMDBBackend::setStale(uint32_t domain_id)
{
  genChangeDomain(domain_id, [](DomainInfo& di) {
    di.last_check = 0;
  });
}

void LMDBBackend::setFresh(uint32_t domain_id)
{
  genChangeDomain(domain_id, [](DomainInfo& di) {
    di.last_check = time(0);
  });
}

void LMDBBackend::setNotified(uint32_t domain_id, uint32_t serial)
{
  genChangeDomain(domain_id, [serial](DomainInfo& di) {
    di.serial = serial;
  });
}

bool LMDBBackend::setMasters(const DNSName& domain, const vector<ComboAddress>& masters)
{
  return genChangeDomain(domain, [&masters](DomainInfo& di) {
    di.masters = masters;
  });
}

bool LMDBBackend::createDomain(const DNSName& domain, const DomainInfo::DomainKind kind, const vector<ComboAddress>& masters, const string& account)
{
  DomainInfo di;

  {
    auto txn = d_tdomains->getRWTransaction();
    if (txn.get<0>(domain, di)) {
      throw DBException("Domain '" + domain.toLogString() + "' exists already");
    }

    di.zone = domain;
    di.kind = kind;
    di.masters = masters;
    di.account = account;

    txn.put(di);
    txn.commit();
  }

  return true;
}

void LMDBBackend::getAllDomains(vector<DomainInfo>* domains, bool doSerial, bool include_disabled)
{
  domains->clear();
  auto txn = d_tdomains->getROTransaction();
  for (auto iter = txn.begin(); iter != txn.end(); ++iter) {
    DomainInfo di = *iter;
    di.id = iter.getID();

    if (!getSerial(di) && !include_disabled) {
      continue;
    }

    di.backend = this;
    domains->push_back(di);
  }
}

void LMDBBackend::getUnfreshSlaveInfos(vector<DomainInfo>* domains)
{
  //  cout<<"Start of getUnfreshSlaveInfos"<<endl;
  domains->clear();
  auto txn = d_tdomains->getROTransaction();

  time_t now = time(0);
  for (auto iter = txn.begin(); iter != txn.end(); ++iter) {
    if (iter->kind != DomainInfo::Slave)
      continue;

    auto txn2 = getRecordsROTransaction(iter.getID());
    compoundOrdername co;
    MDBOutVal val;
    uint32_t serial = 0;
    if (!txn2->txn->get(txn2->db->dbi, co(iter.getID(), g_rootdnsname, QType::SOA), val)) {
      LMDBResourceRecord lrr;
      serFromString(val.get<string_view>(), lrr);
      struct soatimes st;

      memcpy(&st, &lrr.content[lrr.content.size() - sizeof(soatimes)], sizeof(soatimes));

      if ((time_t)(iter->last_check + ntohl(st.refresh)) >= now) { // still fresh
        continue; // try next domain
      }
      //      cout << di.last_check <<" + " <<sdata.refresh<<" > = " << now << "\n";
      serial = ntohl(st.serial);
    }
    else {
      //      cout << "Could not find SOA for "<<iter->zone<<" with id "<<iter.getID()<<endl;
      serial = 0;
    }
    DomainInfo di = *iter;
    di.id = iter.getID();
    di.serial = serial;
    di.backend = this;

    domains->push_back(di);
  }
  //  cout<<"END of getUnfreshSlaveInfos"<<endl;
}

bool LMDBBackend::getAllDomainMetadata(const DNSName& name, std::map<std::string, std::vector<std::string>>& meta)
{
  meta.clear();
  auto txn = d_tmeta->getROTransaction();
  auto range = txn.equal_range<0>(name);

  for (auto& iter = range.first; iter != range.second; ++iter) {
    meta[iter->key].push_back(iter->value);
  }
  return true;
}

bool LMDBBackend::setDomainMetadata(const DNSName& name, const std::string& kind, const std::vector<std::string>& meta)
{
  auto txn = d_tmeta->getRWTransaction();

  auto range = txn.equal_range<0>(name);

  for (auto& iter = range.first; iter != range.second; ++iter) {
    if (iter->key == kind)
      iter.del();
  }

  for (const auto& m : meta) {
    DomainMeta dm{name, kind, m};
    txn.put(dm);
  }
  txn.commit();
  return true;
}

bool LMDBBackend::getDomainKeys(const DNSName& name, std::vector<KeyData>& keys)
{
  auto txn = d_tkdb->getROTransaction();
  auto range = txn.equal_range<0>(name);
  for (auto& iter = range.first; iter != range.second; ++iter) {
    KeyData kd{iter->content, iter.getID(), iter->flags, iter->active, iter->published};
    keys.push_back(kd);
  }

  return true;
}

bool LMDBBackend::removeDomainKey(const DNSName& name, unsigned int id)
{
  auto txn = d_tkdb->getRWTransaction();
  KeyDataDB kdb;
  if (txn.get(id, kdb)) {
    if (kdb.domain == name) {
      txn.del(id);
      txn.commit();
      return true;
    }
  }
  // cout << "??? wanted to remove domain key for domain "<<name<<" with id "<<id<<", could not find it"<<endl;
  return true;
}

bool LMDBBackend::addDomainKey(const DNSName& name, const KeyData& key, int64_t& id)
{
  auto txn = d_tkdb->getRWTransaction();
  KeyDataDB kdb{name, key.content, key.flags, key.active, key.published};
  id = txn.put(kdb);
  txn.commit();

  return true;
}

bool LMDBBackend::activateDomainKey(const DNSName& name, unsigned int id)
{
  auto txn = d_tkdb->getRWTransaction();
  KeyDataDB kdb;
  if (txn.get(id, kdb)) {
    if (kdb.domain == name) {
      txn.modify(id, [](KeyDataDB& kdbarg) {
        kdbarg.active = true;
      });
      txn.commit();
      return true;
    }
  }

  // cout << "??? wanted to activate domain key for domain "<<name<<" with id "<<id<<", could not find it"<<endl;
  return true;
}

bool LMDBBackend::deactivateDomainKey(const DNSName& name, unsigned int id)
{
  auto txn = d_tkdb->getRWTransaction();
  KeyDataDB kdb;
  if (txn.get(id, kdb)) {
    if (kdb.domain == name) {
      txn.modify(id, [](KeyDataDB& kdbarg) {
        kdbarg.active = false;
      });
      txn.commit();
      return true;
    }
  }
  // cout << "??? wanted to deactivate domain key for domain "<<name<<" with id "<<id<<", could not find it"<<endl;
  return true;
}

bool LMDBBackend::publishDomainKey(const DNSName& name, unsigned int id)
{
  auto txn = d_tkdb->getRWTransaction();
  KeyDataDB kdb;
  if (txn.get(id, kdb)) {
    if (kdb.domain == name) {
      txn.modify(id, [](KeyDataDB& kdbarg) {
        kdbarg.published = true;
      });
      txn.commit();
      return true;
    }
  }

  // cout << "??? wanted to hide domain key for domain "<<name<<" with id "<<id<<", could not find it"<<endl;
  return true;
}

bool LMDBBackend::unpublishDomainKey(const DNSName& name, unsigned int id)
{
  auto txn = d_tkdb->getRWTransaction();
  KeyDataDB kdb;
  if (txn.get(id, kdb)) {
    if (kdb.domain == name) {
      txn.modify(id, [](KeyDataDB& kdbarg) {
        kdbarg.published = false;
      });
      txn.commit();
      return true;
    }
  }
  // cout << "??? wanted to unhide domain key for domain "<<name<<" with id "<<id<<", could not find it"<<endl;
  return true;
}

bool LMDBBackend::getBeforeAndAfterNamesAbsolute(uint32_t id, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after)
{
  //  cout << __PRETTY_FUNCTION__<< ": "<<id <<", "<<qname << " " << unhashed<<endl;

  DomainInfo di;
  if (!d_tdomains->getROTransaction().get(id, di)) {
    // domain does not exist, tough luck
    return false;
  }
  // cout <<"Zone: "<<di.zone<<endl;

  compoundOrdername co;
  auto txn = getRecordsROTransaction(id);

  auto cursor = txn->txn->getCursor(txn->db->dbi);
  MDBOutVal key, val;

  LMDBResourceRecord lrr;

  string matchkey = co(id, qname, QType::NSEC3);
  if (cursor.lower_bound(matchkey, key, val)) {
    // this is beyond the end of the database
    // cout << "Beyond end of database!" << endl;
    cursor.last(key, val);

    for (;;) {
      if (co.getDomainID(key.get<StringView>()) != id) {
        //cout<<"Last record also not part of this zone!"<<endl;
        // this implies something is wrong in the database, nothing we can do
        return false;
      }

      if (co.getQType(key.get<StringView>()) == QType::NSEC3) {
        serFromString(val.get<StringView>(), lrr);
        if (!lrr.ttl) // the kind of NSEC3 we need
          break;
      }
      if (cursor.prev(key, val)) {
        // hit beginning of database, again means something is wrong with it
        return false;
      }
    }
    before = co.getQName(key.get<StringView>());
    unhashed = DNSName(lrr.content.c_str(), lrr.content.size(), 0, false) + di.zone;

    // now to find after .. at the beginning of the zone
    if (cursor.lower_bound(co(id), key, val)) {
      // cout<<"hit end of zone find when we shouldn't"<<endl;
      return false;
    }
    for (;;) {
      if (co.getQType(key.get<StringView>()) == QType::NSEC3) {
        serFromString(val.get<StringView>(), lrr);
        if (!lrr.ttl)
          break;
      }

      if (cursor.next(key, val) || co.getDomainID(key.get<StringView>()) != id) {
        // cout<<"hit end of zone or database when we shouldn't"<<endl;
        return false;
      }
    }
    after = co.getQName(key.get<StringView>());
    // cout<<"returning: before="<<before<<", after="<<after<<", unhashed: "<<unhashed<<endl;
    return true;
  }

  // cout<<"Ended up at "<<co.getQName(key.get<StringView>()) <<endl;

  before = co.getQName(key.get<StringView>());
  if (before == qname) {
    // cout << "Ended up on exact right node" << endl;
    before = co.getQName(key.get<StringView>());
    // unhashed should be correct now, maybe check?
    if (cursor.next(key, val)) {
      // xxx should find first hash now

      if (cursor.lower_bound(co(id), key, val)) {
        // cout<<"hit end of zone find when we shouldn't for id "<<id<< __LINE__<<endl;
        return false;
      }
      for (;;) {
        if (co.getQType(key.get<StringView>()) == QType::NSEC3) {
          serFromString(val.get<StringView>(), lrr);
          if (!lrr.ttl)
            break;
        }

        if (cursor.next(key, val) || co.getDomainID(key.get<StringView>()) != id) {
          // cout<<"hit end of zone or database when we shouldn't" << __LINE__<<endl;
          return false;
        }
      }
      after = co.getQName(key.get<StringView>());
      // cout<<"returning: before="<<before<<", after="<<after<<", unhashed: "<<unhashed<<endl;
      return true;
    }
  }
  else {
    // cout <<"Going backwards to find 'before'"<<endl;
    int count = 0;
    for (;;) {
      if (co.getQName(key.get<StringView>()).canonCompare(qname) && co.getQType(key.get<StringView>()) == QType::NSEC3) {
        // cout<<"Potentially stopping traverse at "<< co.getQName(key.get<StringView>()) <<", " << (co.getQName(key.get<StringView>()).canonCompare(qname))<<endl;
        // cout<<"qname = "<<qname<<endl;
        // cout<<"here  = "<<co.getQName(key.get<StringView>())<<endl;
        serFromString(val.get<StringView>(), lrr);
        if (!lrr.ttl)
          break;
      }

      if (cursor.prev(key, val) || co.getDomainID(key.get<StringView>()) != id) {
        // cout <<"XXX Hit *beginning* of zone or database"<<endl;
        // this can happen, must deal with it
        // should now find the last hash of the zone

        if (cursor.lower_bound(co(id + 1), key, val)) {
          // cout << "Could not find the next higher zone, going to the end of the database then"<<endl;
          cursor.last(key, val);
        }
        else
          cursor.prev(key, val);

        for (;;) {
          if (co.getDomainID(key.get<StringView>()) != id) {
            //cout<<"Last record also not part of this zone!"<<endl;
            // this implies something is wrong in the database, nothing we can do
            return false;
          }

          if (co.getQType(key.get<StringView>()) == QType::NSEC3) {
            serFromString(val.get<StringView>(), lrr);
            if (!lrr.ttl) // the kind of NSEC3 we need
              break;
          }
          if (cursor.prev(key, val)) {
            // hit beginning of database, again means something is wrong with it
            return false;
          }
        }
        before = co.getQName(key.get<StringView>());
        unhashed = DNSName(lrr.content.c_str(), lrr.content.size(), 0, false) + di.zone;
        // cout <<"Should still find 'after'!"<<endl;
        // for 'after', we need to find the first hash of this zone

        if (cursor.lower_bound(co(id), key, val)) {
          // cout<<"hit end of zone find when we shouldn't"<<endl;
          // means database is wrong, nothing we can do
          return false;
        }
        for (;;) {
          if (co.getQType(key.get<StringView>()) == QType::NSEC3) {
            serFromString(val.get<StringView>(), lrr);
            if (!lrr.ttl)
              break;
          }

          if (cursor.next(key, val)) {
            // means database is wrong, nothing we can do
            // cout<<"hit end of zone when we shouldn't 2"<<endl;
            return false;
          }
        }
        after = co.getQName(key.get<StringView>());

        // cout<<"returning: before="<<before<<", after="<<after<<", unhashed: "<<unhashed<<endl;
        return true;
      }
      ++count;
    }
    before = co.getQName(key.get<StringView>());
    unhashed = DNSName(lrr.content.c_str(), lrr.content.size(), 0, false) + di.zone;
    // cout<<"Went backwards, found "<<before<<endl;
    // return us to starting point
    while (count--)
      cursor.next(key, val);
  }
  //  cout<<"Now going forward"<<endl;
  for (int count = 0;; ++count) {
    if ((count && cursor.next(key, val)) || co.getDomainID(key.get<StringView>()) != id) {
      // cout <<"Hit end of database or zone, finding first hash then in zone "<<id<<endl;
      if (cursor.lower_bound(co(id), key, val)) {
        // cout<<"hit end of zone find when we shouldn't"<<endl;
        // means database is wrong, nothing we can do
        return false;
      }
      for (;;) {
        if (co.getQType(key.get<StringView>()) == QType::NSEC3) {
          serFromString(val.get<StringView>(), lrr);
          if (!lrr.ttl)
            break;
        }

        if (cursor.next(key, val)) {
          // means database is wrong, nothing we can do
          // cout<<"hit end of zone when we shouldn't 2"<<endl;
          return false;
        }
        // cout << "Next.. "<<endl;
      }
      after = co.getQName(key.get<StringView>());

      // cout<<"returning: before="<<before<<", after="<<after<<", unhashed: "<<unhashed<<endl;
      return true;
    }

    // cout<<"After "<<co.getQName(key.get<StringView>()) <<endl;
    if (co.getQType(key.get<StringView>()) == QType::NSEC3) {
      serFromString(val.get<StringView>(), lrr);
      if (!lrr.ttl) {
        break;
      }
    }
  }
  after = co.getQName(key.get<StringView>());
  // cout<<"returning: before="<<before<<", after="<<after<<", unhashed: "<<unhashed<<endl;
  return true;
}

bool LMDBBackend::getBeforeAndAfterNames(uint32_t id, const DNSName& zonenameU, const DNSName& qname, DNSName& before, DNSName& after)
{
  DNSName zonename = zonenameU.makeLowerCase();
  //  cout << __PRETTY_FUNCTION__<< ": "<<id <<", "<<zonename << ", '"<<qname<<"'"<<endl;

  auto txn = getRecordsROTransaction(id);
  compoundOrdername co;
  DNSName qname2 = qname.makeRelative(zonename);
  string matchkey = co(id, qname2);
  auto cursor = txn->txn->getCursor(txn->db->dbi);
  MDBOutVal key, val;
  // cout<<"Lower_bound for "<<qname2<<endl;
  if (cursor.lower_bound(matchkey, key, val)) {
    // cout << "Hit end of database, bummer"<<endl;
    cursor.last(key, val);
    if (co.getDomainID(key.get<string_view>()) == id) {
      before = co.getQName(key.get<string_view>()) + zonename;
      after = zonename;
    }
    // else
    // cout << "We were at end of database, but this zone is not there?!"<<endl;
    return true;
  }
  // cout<<"Cursor is at "<<co.getQName(key.get<string_view>()) <<", in zone id "<<co.getDomainID(key.get<string_view>())<< endl;

  if (co.getQType(key.get<string_view>()).getCode() && co.getDomainID(key.get<string_view>()) == id && co.getQName(key.get<string_view>()) == qname2) { // don't match ENTs
    // cout << "Had an exact match!"<<endl;
    before = qname2 + zonename;
    int rc;
    for (;;) {
      rc = cursor.next(key, val);
      if (rc)
        break;

      if (co.getDomainID(key.get<string_view>()) == id && key.get<StringView>().rfind(matchkey, 0) == 0)
        continue;
      LMDBResourceRecord lrr;
      serFromString(val.get<StringView>(), lrr);
      if (co.getQType(key.get<string_view>()).getCode() && (lrr.auth || co.getQType(key.get<string_view>()).getCode() == QType::NS))
        break;
    }
    if (rc || co.getDomainID(key.get<string_view>()) != id) {
      // cout << "We hit the end of the zone or database. 'after' is apex" << endl;
      after = zonename;
      return false;
    }
    after = co.getQName(key.get<string_view>()) + zonename;
    return true;
  }

  if (co.getDomainID(key.get<string_view>()) != id) {
    // cout << "Ended up in next zone, 'after' is zonename" <<endl;
    after = zonename;
    // cout << "Now hunting for previous" << endl;
    int rc;
    for (;;) {
      rc = cursor.prev(key, val);
      if (rc) {
        // cout<<"Reversed into zone, but got not found from lmdb" <<endl;
        return false;
      }

      if (co.getDomainID(key.get<string_view>()) != id) {
        // cout<<"Reversed into zone, but found wrong zone id " << co.getDomainID(key.get<string_view>()) << " != "<<id<<endl;
        // "this can't happen"
        return false;
      }
      LMDBResourceRecord lrr;
      serFromString(val.get<StringView>(), lrr);
      if (co.getQType(key.get<string_view>()).getCode() && (lrr.auth || co.getQType(key.get<string_view>()).getCode() == QType::NS))
        break;
    }

    before = co.getQName(key.get<string_view>()) + zonename;
    // cout<<"Found: "<< before<<endl;
    return true;
  }

  // cout <<"We ended up after "<<qname<<", on "<<co.getQName(key.get<string_view>())<<endl;

  int skips = 0;
  for (;;) {
    LMDBResourceRecord lrr;
    serFromString(val.get<StringView>(), lrr);
    if (co.getQType(key.get<string_view>()).getCode() && (lrr.auth || co.getQType(key.get<string_view>()).getCode() == QType::NS)) {
      after = co.getQName(key.get<string_view>()) + zonename;
      // cout <<"Found auth ("<<lrr.auth<<") or an NS record "<<after<<", type: "<<co.getQType(key.get<string_view>()).toString()<<", ttl = "<<lrr.ttl<<endl;
      // cout << makeHexDump(val.get<string>()) << endl;
      break;
    }
    // cout <<"  oops, " << co.getQName(key.get<string_view>()) << " was not auth "<<lrr.auth<< " type=" << lrr.qtype.toString()<<" or NS, so need to skip ahead a bit more" << endl;
    int rc = cursor.next(key, val);
    if (!rc)
      ++skips;
    if (rc || co.getDomainID(key.get<string_view>()) != id) {
      // cout << "  oops, hit end of database or zone. This means after is apex" <<endl;
      after = zonename;
      break;
    }
  }
  // go back to where we were
  while (skips--)
    cursor.prev(key, val);

  for (;;) {
    int rc = cursor.prev(key, val);
    if (rc || co.getDomainID(key.get<string_view>()) != id) {
      // XX I don't think this case can happen
      // cout << "We hit the beginning of the zone or database.. now what" << endl;
      return false;
    }
    before = co.getQName(key.get<string_view>()) + zonename;
    LMDBResourceRecord lrr;
    serFromString(val.get<string_view>(), lrr);
    // cout<<"And before to "<<before<<", auth = "<<rr.auth<<endl;
    if (co.getQType(key.get<string_view>()).getCode() && (lrr.auth || co.getQType(key.get<string_view>()) == QType::NS))
      break;
    // cout << "Oops, that was wrong, go back one more"<<endl;
  }

  return true;
}

bool LMDBBackend::updateDNSSECOrderNameAndAuth(uint32_t domain_id, const DNSName& qname, const DNSName& ordername, bool auth, const uint16_t qtype)
{
  //  cout << __PRETTY_FUNCTION__<< ": "<< domain_id <<", '"<<qname <<"', '"<<ordername<<"', "<<auth<< ", " << qtype << endl;
  shared_ptr<RecordsRWTransaction> txn;
  bool needCommit = false;
  if (d_rwtxn && d_transactiondomainid == domain_id) {
    txn = d_rwtxn;
    //    cout<<"Reusing open transaction"<<endl;
  }
  else {
    //    cout<<"Making a new RW txn for " << __PRETTY_FUNCTION__ <<endl;
    txn = getRecordsRWTransaction(domain_id);
    needCommit = true;
  }

  DomainInfo di;
  if (!d_tdomains->getROTransaction().get(domain_id, di)) {
    //    cout<<"Could not find domain_id "<<domain_id <<endl;
    return false;
  }

  DNSName rel = qname.makeRelative(di.zone);

  compoundOrdername co;
  string matchkey = co(domain_id, rel);

  auto cursor = txn->txn->getCursor(txn->db->dbi);
  MDBOutVal key, val;
  if (cursor.lower_bound(matchkey, key, val)) {
    // cout << "Could not find anything"<<endl;
    return false;
  }

  bool hasOrderName = !ordername.empty();
  bool needNSEC3 = hasOrderName;

  for (; key.get<StringView>().rfind(matchkey, 0) == 0;) {
    vector<LMDBResourceRecord> lrrs;

    if (co.getQType(key.get<StringView>()) != QType::NSEC3) {
      serFromString(val.get<StringView>(), lrrs);
      bool changed = false;
      vector<LMDBResourceRecord> newRRs;
      for (auto lrr : lrrs) {
        lrr.qtype = co.getQType(key.get<StringView>());
        if (!needNSEC3 && qtype != QType::ANY) {
          needNSEC3 = (lrr.ordername && QType(qtype) != lrr.qtype);
        }

        if ((qtype == QType::ANY || QType(qtype) == lrr.qtype) && (lrr.ordername != hasOrderName || lrr.auth != auth)) {
          lrr.auth = auth;
          lrr.ordername = hasOrderName;
          changed = true;
        }
        newRRs.push_back(lrr);
      }
      if (changed) {
        cursor.put(key, serToString(newRRs));
      }
    }

    if (cursor.next(key, val))
      break;
  }

  bool del = false;
  LMDBResourceRecord lrr;
  matchkey = co(domain_id, rel, QType::NSEC3);
  if (!txn->txn->get(txn->db->dbi, matchkey, val)) {
    serFromString(val.get<string_view>(), lrr);

    if (needNSEC3) {
      if (hasOrderName && lrr.content != ordername.toDNSStringLC()) {
        del = true;
      }
    }
    else {
      del = true;
    }
    if (del) {
      txn->txn->del(txn->db->dbi, co(domain_id, DNSName(lrr.content.c_str(), lrr.content.size(), 0, false), QType::NSEC3));
      txn->txn->del(txn->db->dbi, matchkey);
    }
  }
  else {
    del = true;
  }

  if (hasOrderName && del) {
    matchkey = co(domain_id, rel, QType::NSEC3);

    lrr.ttl = 0;
    lrr.auth = 0;
    lrr.content = rel.toDNSStringLC();

    string str = serToString(lrr);
    txn->txn->put(txn->db->dbi, co(domain_id, ordername, QType::NSEC3), str);
    lrr.ttl = 1;
    lrr.content = ordername.toDNSStringLC();
    str = serToString(lrr);
    txn->txn->put(txn->db->dbi, matchkey, str); // 2
  }

  if (needCommit)
    txn->txn->commit();
  return false;
}

bool LMDBBackend::updateEmptyNonTerminals(uint32_t domain_id, set<DNSName>& insert, set<DNSName>& erase, bool remove)
{
  // cout << __PRETTY_FUNCTION__<< ": "<< domain_id << ", insert.size() "<<insert.size()<<", "<<erase.size()<<", " <<remove<<endl;

  bool needCommit = false;
  shared_ptr<RecordsRWTransaction> txn;
  if (d_rwtxn && d_transactiondomainid == domain_id) {
    txn = d_rwtxn;
    //    cout<<"Reusing open transaction"<<endl;
  }
  else {
    //    cout<<"Making a new RW txn for delete domain"<<endl;
    txn = getRecordsRWTransaction(domain_id);
    needCommit = true;
  }

  // if remove is set, all ENTs should be removed & nothing else should be done
  if (remove) {
    deleteDomainRecords(*txn, domain_id, 0);
  }
  else {
    DomainInfo di;
    auto rotxn = d_tdomains->getROTransaction();
    if (!rotxn.get(domain_id, di)) {
      // cout <<"No such domain with id "<<domain_id<<endl;
      return false;
    }
    compoundOrdername co;
    for (const auto& n : insert) {
      LMDBResourceRecord lrr;
      lrr.qname = n.makeRelative(di.zone);
      lrr.ttl = 0;
      lrr.auth = true;

      std::string ser = serToString(lrr);

      txn->txn->put(txn->db->dbi, co(domain_id, lrr.qname, 0), ser);

      // cout <<" +"<<n<<endl;
    }
    for (auto n : erase) {
      // cout <<" -"<<n<<endl;
      n.makeUsRelative(di.zone);
      txn->txn->del(txn->db->dbi, co(domain_id, n, 0));
    }
  }
  if (needCommit)
    txn->txn->commit();
  return false;
}

/* TSIG */
bool LMDBBackend::getTSIGKey(const DNSName& name, DNSName* algorithm, string* content)
{
  auto txn = d_ttsig->getROTransaction();

  TSIGKey tk;
  if (!txn.get<0>(name, tk))
    return false;
  if (algorithm)
    *algorithm = tk.algorithm;
  if (content)
    *content = tk.key;
  return true;
}
// this deletes an old key if it has the same algorithm
bool LMDBBackend::setTSIGKey(const DNSName& name, const DNSName& algorithm, const string& content)
{
  auto txn = d_ttsig->getRWTransaction();

  for (auto range = txn.equal_range<0>(name); range.first != range.second; ++range.first) {
    if (range.first->algorithm == algorithm)
      range.first.del();
  }

  TSIGKey tk;
  tk.name = name;
  tk.algorithm = algorithm;
  tk.key = content;

  txn.put(tk);
  txn.commit();

  return true;
}
bool LMDBBackend::deleteTSIGKey(const DNSName& name)
{
  auto txn = d_ttsig->getRWTransaction();
  TSIGKey tk;

  for (auto range = txn.equal_range<0>(name); range.first != range.second; ++range.first) {
    range.first.del();
  }
  txn.commit();
  return true;
}
bool LMDBBackend::getTSIGKeys(std::vector<struct TSIGKey>& keys)
{
  auto txn = d_ttsig->getROTransaction();

  keys.clear();
  for (auto iter = txn.begin(); iter != txn.end(); ++iter) {
    keys.push_back(*iter);
  }
  return false;
}

class LMDBFactory : public BackendFactory
{
public:
  LMDBFactory() :
    BackendFactory("lmdb") {}
  void declareArguments(const string& suffix = "") override
  {
    declare(suffix, "filename", "Filename for lmdb", "./pdns.lmdb");
    declare(suffix, "sync-mode", "Synchronisation mode: nosync, nometasync, mapasync, sync", "mapasync");
    // there just is no room for more on 32 bit
    declare(suffix, "shards", "Records database will be split into this number of shards", (sizeof(long) == 4) ? "2" : "64");
    declare(suffix, "schema-version", "Maximum allowed schema version to run on this DB. If a lower version is found, auto update is performed", std::to_string(SCHEMAVERSION));
  }
  DNSBackend* make(const string& suffix = "") override
  {
    return new LMDBBackend(suffix);
  }
};

/* THIRD PART */

class LMDBLoader
{
public:
  LMDBLoader()
  {
    BackendMakers().report(new LMDBFactory);
    g_log << Logger::Info << "[lmdbbackend] This is the lmdb backend version " VERSION
#ifndef REPRODUCIBLE
          << " (" __DATE__ " " __TIME__ ")"
#endif
          << " reporting" << endl;
  }
};

static LMDBLoader randomLoader;
