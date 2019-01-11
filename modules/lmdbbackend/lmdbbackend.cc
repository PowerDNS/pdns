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
#include "pdns/pdnsexception.hh"
#include "pdns/logger.hh"
#include "pdns/version.hh"
#include "pdns/arguments.hh"
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/string.hpp>
#include <boost/serialization/utility.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/iostreams/stream_buffer.hpp>

#include <boost/iostreams/device/back_inserter.hpp>
#include <sstream>


#include "lmdbbackend.hh"

LMDBBackend::LMDBBackend(const std::string& suffix)
{
  setArgPrefix("lmdb"+suffix);
  
  string syncMode = toLower(getArg("sync-mode"));

  if(syncMode == "nosync")
    d_asyncFlag = MDB_NOSYNC;
  else if(syncMode == "nometasync")
    d_asyncFlag = MDB_NOMETASYNC;
  else if(syncMode == "mapasync")
    d_asyncFlag = MDB_MAPASYNC;
  else if(syncMode.empty())
    d_asyncFlag = 0;
  else
    throw std::runtime_error("Unknown sync mode "+syncMode+" requested for LMDB backend");

  d_tdomains = std::make_shared<tdomains_t>(getMDBEnv(getArg("filename").c_str(), MDB_NOSUBDIR | d_asyncFlag, 0600), "domains");
  d_tmeta = std::make_shared<tmeta_t>(d_tdomains->getEnv(), "metadata");
  d_tkdb = std::make_shared<tkdb_t>(d_tdomains->getEnv(), "keydata");
  d_ttsig = std::make_shared<ttsig_t>(d_tdomains->getEnv(), "tsig");
  
  auto pdnsdbi = d_tdomains->getEnv()->openDB("pdns", MDB_CREATE);
  auto txn = d_tdomains->getEnv()->getRWTransaction();
  MDBOutVal shards;
  if(!txn.get(pdnsdbi, "shards", shards)) {
    
    d_shards = shards.get<uint32_t>();
    if(d_shards != atoi(getArg("shards").c_str())) {
      g_log << Logger::Warning<<"Note: configured number of lmdb shards ("<<atoi(getArg("shards").c_str())<<") is different from on-disk ("<<d_shards<<"). Using on-disk shard number"<<endl;
    }
  }
  else {
    d_shards = atoi(getArg("shards").c_str());
    txn.put(pdnsdbi, "shards", d_shards);
    txn.commit();
  }
    d_trecords.resize(d_shards);
  d_dolog = ::arg().mustDo("query-logging");
}



namespace boost {
namespace serialization {

template<class Archive>
void save(Archive & ar, const DNSName& g, const unsigned int version)
{
  if(!g.empty()) {
    std::string tmp = g.toDNSStringLC(); // g++ 4.8 woes
    ar & tmp;
  }
  else
    ar & "";
}

template<class Archive>
void load(Archive & ar, DNSName& g, const unsigned int version)
{
  string tmp;
  ar & tmp;
  if(tmp.empty())
    g = DNSName();
  else
    g = DNSName(tmp.c_str(), tmp.size(), 0, false);
}

template<class Archive>
void save(Archive & ar, const QType& g, const unsigned int version)
{
  uint16_t tmp = g.getCode(); // g++ 4.8 woes
  ar & tmp;
}

template<class Archive>
void load(Archive & ar, QType& g, const unsigned int version)
{
  uint16_t tmp;
  ar & tmp; 
  g = QType(tmp);
}
  
template<class Archive>
void serialize(Archive & ar, DomainInfo& g, const unsigned int version)
{
  ar & g.zone;
  ar & g.last_check;
  ar & g.account;
  ar & g.masters;
  ar & g.id;
  ar & g.notified_serial;
  ar & g.kind;
}

template<class Archive>
void serialize(Archive & ar, LMDBBackend::DomainMeta& g, const unsigned int version)
{
  ar & g.domain & g.key & g.value;
}

template<class Archive>
void serialize(Archive & ar, LMDBBackend::KeyDataDB& g, const unsigned int version)
{
  ar & g.domain & g.content & g.flags & g.active;
}

template<class Archive>
void serialize(Archive & ar, TSIGKey& g, const unsigned int version)
{
  ar & g.name;
  ar & g.algorithm; // this is the ordername
  ar & g.key;
}


  
} // namespace serialization
} // namespace boost

BOOST_SERIALIZATION_SPLIT_FREE(DNSName);
BOOST_SERIALIZATION_SPLIT_FREE(QType);
BOOST_IS_BITWISE_SERIALIZABLE(ComboAddress);

template<>
std::string serToString(const DNSResourceRecord& rr)
{
  std::string ret;
  uint16_t len = rr.content.length();
  ret.reserve(2+len+8); 
  ret.assign((const char*)&len, 2);
  ret += rr.content;
  ret.append((const char*)&rr.ttl, 4);
  ret.append(1, (char)rr.auth);
  return ret;
}

template<>
void serFromString(const string_view& str, DNSResourceRecord& rr)
{
  uint16_t len;
  memcpy(&len, &str[0], 2);
  rr.content.assign(&str[2], len);
  memcpy(&rr.ttl, &str[2] + len, 4);
  rr.auth = str[2+len+4];
  rr.wildcardname.clear();
}


std::string serializeContent(uint16_t qtype, const DNSName& domain, const std::string& content)
{
  auto drc = DNSRecordContent::mastermake(qtype, 1, content);
  return drc->serialize(domain, false);
}

std::string unserializeContent(uint16_t qtype, const DNSName& qname, const std::string& content)
{
  return DNSRecordContent::unserialize(qname, qtype, content)->getZoneRepresentation();
}

std::shared_ptr<DNSRecordContent> unserializeContentZR(uint16_t qtype, const DNSName& qname, const std::string& content)
{
  return DNSRecordContent::unserialize(qname, qtype, content);
}


/* design. If you ask a question without a zone id, we lookup the best
   zone id for you, and answer from that. This is different than other backends, but I can't see why it would not work.

   The index we use is "zoneid,canonical relative name". This index is also used
   for AXFR.

   Note - domain_id, name and type are ONLY present on the index!
*/

#if BOOST_VERSION <= 105400
#define StringView string
#else
#define StringView string_view
#endif

void LMDBBackend::deleteDomainRecords(RecordsRWTransaction& txn, uint32_t domain_id)
{
  compoundOrdername co;
  string match = co(domain_id);

  auto cursor = txn.txn.getCursor(txn.db->dbi);
  MDBOutVal key, val;
  //  cout<<"Match: "<<makeHexDump(match);
  if(!cursor.lower_bound(match, key, val) ) {
    while(key.get<StringView>().rfind(match, 0) == 0) {
      cursor.del(MDB_NODUPDATA);
      if(cursor.next(key, val)) break;
    } 
  }
}

bool LMDBBackend::startTransaction(const DNSName &domain, int domain_id)
{
  d_rwtxn = getRecordsRWTransaction(domain_id);
  d_transactiondomain = domain;
  d_transactiondomainid = domain_id;
  if(domain_id >= 0) {
    deleteDomainRecords(*d_rwtxn, domain_id);
  }

  return true;
}

bool LMDBBackend::commitTransaction()
{
  cout<<"Commit transaction" <<endl;
  d_rwtxn->txn.commit();
  d_rwtxn.reset();
  return true;
}

bool LMDBBackend::abortTransaction()
{
  cout<<"Abort transaction"<<endl;
  d_rwtxn->txn.abort();
  d_rwtxn.reset();

  return true;
}

bool LMDBBackend::feedRecord(const DNSResourceRecord &r, const DNSName &ordername)
{
  DNSResourceRecord rr2(r);
  rr2.qname.makeUsRelative(d_transactiondomain);
  //  rr2.wildcardname = ordername;
  //  cout<<"Going to serialize '"<<rr2.content<<"': ";
  rr2.content = serializeContent(rr2.qtype.getCode(), r.qname, rr2.content);
  //  cout<<makeHexDump(rr2.content)<<endl;
  compoundOrdername co;
  d_rwtxn->txn.put(d_rwtxn->db->dbi, co(r.domain_id, rr2.qname, rr2.qtype.getCode()), serToString(rr2));
  return true;
}

bool LMDBBackend::replaceRRSet(uint32_t domain_id, const DNSName& qname, const QType& qt, const vector<DNSResourceRecord>& rrset)
{
  // zonk qname/qtype within domain_id (go through qname, check domain_id && qtype)
  shared_ptr<RecordsRWTransaction> txn;
  if(d_rwtxn) {
    txn = d_rwtxn;
    cout<<"Reusing open transaction"<<endl;
  }
  else {
    cout<<"Making a new RW txn for replace rrset"<<endl;
    txn = getRecordsRWTransaction(domain_id);
  }

  DomainInfo di;
  d_tdomains->getROTransaction().get(domain_id, di); // XX error checking
  
  compoundOrdername co;
  auto cursor = txn->txn.getCursor(txn->db->dbi);
  MDBOutVal key, val;
  string match =co(domain_id, qname.makeRelative(di.zone), qt.getCode());
  if(!cursor.find(match, key, val)) {
    do {
      cursor.del(MDB_NODUPDATA);
    } while(!cursor.next(key, val) && key.get<StringView>().rfind(match, 0) == 0);
  }

  for(auto rr : rrset) {
    rr.content = serializeContent(rr.qtype.getCode(), rr.qname, rr.content);
    rr.qname.makeUsRelative(di.zone);
    txn->txn.put(txn->db->dbi, match, serToString(rr));
  }
  
  if(!d_rwtxn)
    txn->txn.commit();

  return true;
}

std::shared_ptr<LMDBBackend::RecordsRWTransaction> LMDBBackend::getRecordsRWTransaction(uint32_t id)
{
  auto& shard =d_trecords[id % d_shards];
  if(!shard.env) {
    shard.env = getMDBEnv( (getArg("filename")+"-"+std::to_string(id % d_shards)).c_str(),
                           MDB_NOSUBDIR | d_asyncFlag, 0600);
    shard.dbi = shard.env->openDB("records", MDB_CREATE | MDB_DUPSORT);
  }
  auto ret = std::make_shared<RecordsRWTransaction>(shard.env->getRWTransaction());
  ret->db = std::make_shared<RecordsDB>(shard);

  return ret;
}

std::shared_ptr<LMDBBackend::RecordsROTransaction> LMDBBackend::getRecordsROTransaction(uint32_t id)
{
  auto& shard =d_trecords[id % d_shards];
  if(!shard.env) {
    shard.env = getMDBEnv( (getArg("filename")+"-"+std::to_string(id % d_shards)).c_str(),
                           MDB_NOSUBDIR | d_asyncFlag, 0600);
    shard.dbi = shard.env->openDB("records", MDB_CREATE | MDB_DUPSORT);
    
  }
  
  auto ret = std::make_shared<RecordsROTransaction>(shard.env->getROTransaction());
  ret->db = std::make_shared<RecordsDB>(shard);
  return ret;
}


bool LMDBBackend::deleteDomain(const DNSName &domain)
{
  auto doms = d_tdomains->getRWTransaction();

  DomainInfo di;
  auto id = doms.get<0>(domain, di); 
  if(!id)
    return false;
  
  shared_ptr<RecordsRWTransaction> txn;
  if(d_rwtxn) {
    txn = d_rwtxn;
    cout<<"Reusing open transaction"<<endl;
  }
  else {
    cout<<"Making a new RW txn for delete domain"<<endl;
    txn = getRecordsRWTransaction(id);
  }

  
  doms.del(id);
  compoundOrdername co;
  string match=co(id);

  auto cursor = txn->txn.getCursor(txn->db->dbi);
  MDBOutVal key, val;
  if(!cursor.find(match, key, val)) {
    do {
      cursor.del(MDB_NODUPDATA);
    } while(!cursor.next(key, val) && key.get<StringView>().rfind(match, 0) == 0);
  }

  if(!d_rwtxn)
    txn->txn.commit();
  
  doms.commit();

  return true;
}

bool LMDBBackend::list(const DNSName &target, int id, bool include_disabled)
{
  d_inlist=true;
  DomainInfo di;
  {
    auto dtxn = d_tdomains->getROTransaction();
    
    if((di.id = dtxn.get<0>(target, di))) 
      ; //      cout<<"Found domain "<<target<<" on domain_id "<<di.id <<", list requested "<<id<<endl;
    else {
      cout<<"Did not find "<<target<<endl;
      return false;
    }
  }
  
  d_rotxn = getRecordsROTransaction(di.id);
  compoundOrdername co;
  d_matchkey = co(di.id);
  d_getcursor = std::make_shared<MDBROCursor>(d_rotxn->txn.getCursor(d_rotxn->db->dbi));
  MDBOutVal key, val;
  d_inlist = true;
  
  if(d_getcursor->lower_bound(d_matchkey, key, val) || key.get<StringView>().rfind(d_matchkey, 0) != 0) {
    cout<<"Found nothing for list"<<endl;
    d_getcursor.reset();
    return true;
  }
  
  d_lookupqname = target;
  
  return true;
}

void LMDBBackend::lookup(const QType &type, const DNSName &qdomain, DNSPacket *p, int zoneId)
{
  if(d_dolog) {
    g_log << Logger::Warning << "Got lookup for "<<qdomain<<"|"<<type.getName()<<" in zone "<< zoneId<<endl;
    d_dtime.set();
  }
  DNSName hunt(qdomain);
  if(zoneId < 0) {
    for(;;) {
      DomainInfo di;
    
      if((zoneId = d_tdomains->getROTransaction().get<0>(hunt, di))) {
        break;
      }
      if(!hunt.chopOff())
        break;
    }
    if(zoneId <= 0) {
      //      cout << "Did not find zone for "<< qdomain<<endl;
      d_getcursor.reset();
      return;
    }
  }
  else {
    DomainInfo di;
    if(!d_tdomains->getROTransaction().get(zoneId, di)) {
      cout<<"Could not find a zone with id "<<zoneId<<endl;
      d_getcursor.reset();
      return;
    }
    hunt = di.zone;
  }
    
  DNSName relqname = qdomain.makeRelative(hunt);
  //  cout<<"get will look for "<<relqname<< " in zone "<<hunt<<" with id "<<zoneId<<endl;
  d_rotxn = getRecordsROTransaction(zoneId);

  compoundOrdername co;
  d_getcursor = std::make_shared<MDBROCursor>(d_rotxn->txn.getCursor(d_rotxn->db->dbi));
  MDBOutVal key, val;
  if(type.getCode() == QType::ANY) {
    d_matchkey = co(zoneId,relqname);
  }
  else {
    d_matchkey= co(zoneId,relqname, type.getCode());
  }
  d_inlist=false;
  
  if(d_getcursor->lower_bound(d_matchkey, key, val) || key.get<StringView>().rfind(d_matchkey, 0) != 0) {
    d_getcursor.reset();
    if(d_dolog) {
      g_log<<Logger::Warning<< "Query "<<((long)(void*)this)<<": "<<d_dtime.udiffNoReset()<<" usec to execute (found nothing)"<<endl;
    }
    return;
  }
  
  if(d_dolog) {
    g_log<<Logger::Warning<< "Query "<<((long)(void*)this)<<": "<<d_dtime.udiffNoReset()<<" usec to execute"<<endl;
  }
    
  d_lookuptype=type;
  d_lookupqname = qdomain;
  d_lookupdomain = hunt;
  d_lookupdomainid = zoneId;
}

bool LMDBBackend::get(DNSZoneRecord& rr)
{
  if(d_inlist)
    return get_list(rr);
  else
    return get_lookup(rr);
}

bool LMDBBackend::get(DNSResourceRecord& rr)
{
  cout <<"Old-school get called"<<endl;
  DNSZoneRecord dzr;
  if(d_inlist) {
    if(!get_list(dzr))
      return false;
  }
  else {
    if(!get_lookup(dzr))
      return false;
  }
  rr.qname = dzr.dr.d_name;
  rr.ttl = dzr.dr.d_ttl;
  rr.qtype =dzr.dr.d_type;
  rr.content = dzr.dr.d_content->getZoneRepresentation();
  rr.domain_id = dzr.domain_id;
  cout<<"old school called for "<<rr.qname<<", "<<rr.qtype.getName()<<endl;
  return true;
}

bool LMDBBackend::getSOA(const DNSName &domain, SOAData &sd)
{
  //  cout <<"Native getSOA called"<<endl;
  lookup(QType(QType::SOA), domain, 0, -1);
  DNSZoneRecord dzr;
  bool found=false;
  while(get(dzr)) {
    auto src = getRR<SOARecordContent>(dzr.dr);
    sd.domain_id = dzr.domain_id;
    sd.ttl = dzr.dr.d_ttl;
    sd.qname = dzr.dr.d_name;
    
    sd.nameserver = src->d_mname;
    sd.serial = src->d_st.serial;
    sd.refresh = src->d_st.refresh;
    sd.retry = src->d_st.retry;
    sd.expire = src->d_st.expire;
    sd.default_ttl = src->d_st.minimum;
    
    sd.db = this;
    found=true;
  }
  return found;
}
bool LMDBBackend::get_list(DNSZoneRecord& rr)
{
  if(!d_getcursor)  {
    d_rotxn.reset();
    return false;
  }

  MDBOutVal keyv, val;
  d_getcursor->current(keyv, val);
  DNSResourceRecord drr;
  serFromString(val.get<string>(), drr);

  auto key = keyv.get<string_view>();
  rr.dr.d_name = compoundOrdername::getQName(key) + d_lookupqname;
  rr.domain_id = compoundOrdername::getDomainID(key);
  rr.dr.d_type = compoundOrdername::getQType(key).getCode();
  rr.dr.d_ttl = drr.ttl;
  rr.dr.d_content = unserializeContentZR(drr.qtype.getCode(), rr.dr.d_name, drr.content);

  if(d_getcursor->next(keyv, val) || keyv.get<StringView>().rfind(d_matchkey, 0) != 0) {
    d_getcursor.reset();
  }
  return true;
}


bool LMDBBackend::get_lookup(DNSZoneRecord& rr)
{
  if(!d_getcursor) {
    d_rotxn.reset();
    return false;
  }
  MDBOutVal keyv, val;
  d_getcursor->current(keyv, val);
  DNSResourceRecord drr;
  serFromString(val.get<string>(), drr);

  auto key = keyv.get<string_view>();

  rr.dr.d_name = compoundOrdername::getQName(key) + d_lookupdomain;

  rr.domain_id = compoundOrdername::getDomainID(key);
  //  cout << "We found "<<rr.qname<< " in zone id "<<rr.domain_id <<endl;
  rr.dr.d_type = compoundOrdername::getQType(key).getCode();
  rr.dr.d_ttl = drr.ttl;
  //  cout<<"Going to deserialize "<<makeHexDump(rr.content)<<" into: ";
  rr.dr.d_content = unserializeContentZR(rr.dr.d_type, rr.dr.d_name, drr.content);
  //  cout <<rr.content<<endl;

  if(d_getcursor->next(keyv, val) || keyv.get<StringView>().rfind(d_matchkey, 0) != 0) {
    d_getcursor.reset();
    d_rotxn.reset();
    //    cout<<"Signing EOF"<<endl;
  }

  
  return true;
}


bool LMDBBackend::getDomainInfo(const DNSName &domain, DomainInfo &di, bool getSerial)
{
  auto txn = d_tdomains->getROTransaction();

  if(!(di.id=txn.get<0>(domain, di)))
    return false;
  di.backend = this;
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

  if(!txn.get(id , di))
    return false;
  
  func(di);
  
  txn.put(di, id);

  txn.commit();
  return true;
}


bool LMDBBackend::setKind(const DNSName &domain, const DomainInfo::DomainKind kind)
{
  return genChangeDomain(domain, [kind](DomainInfo& di) {
      di.kind = kind;
    });
}

bool LMDBBackend::setAccount(const DNSName &domain, const std::string& account)
{
  return genChangeDomain(domain, [account](DomainInfo& di) {
      di.account = account;
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


bool LMDBBackend::setMaster(const DNSName &domain, const std::string& ips)
{
  vector<ComboAddress> masters;
  masters.push_back(ComboAddress(ips)); // XXX WRONG!! 
  
  return genChangeDomain(domain, [&masters](DomainInfo& di) {
      di.masters = masters;
    });
}

bool LMDBBackend::createDomain(const DNSName &domain)
{
  return createDomain(domain, "NATIVE", "", "");
}
          
bool LMDBBackend::createDomain(const DNSName &domain, const string &type, const string &masters, const string &account)
{
  cout<<"Creating domain "<<domain<<endl;
  DomainInfo di;
  di.zone = domain;
  di.kind = DomainInfo::Native;
  di.account = account;
  
  auto txn = d_tdomains->getRWTransaction();
  txn.put(di);
  txn.commit();

  return true;
}

void LMDBBackend::getAllDomains(vector<DomainInfo> *domains, bool include_disabled)
{
  domains->clear();
  auto txn = d_tdomains->getROTransaction();
  for(auto iter = txn.begin(); iter != txn.end(); ++iter) {
    DomainInfo di=*iter;
    di.id = iter.getID();
    domains->push_back(di);
  }
}

void LMDBBackend::getUnfreshSlaveInfos(vector<DomainInfo>* domains)
{
  //  cout<<"Start of getUnfreshSlaveInfos"<<endl;
  domains->clear();
  auto txn = d_tdomains->getROTransaction();

  time_t now = time(0);
  for(auto iter = txn.begin(); iter != txn.end(); ++iter) {
    if(iter->kind != DomainInfo::Slave)
      continue;

    auto txn2 = getRecordsROTransaction(iter.getID());
    compoundOrdername co;
    MDBOutVal val;
    uint32_t serial = 0;
    if(!txn2->txn.get(txn2->db->dbi, co(iter.getID(), g_rootdnsname, QType::SOA), val)) {
      DNSResourceRecord rr;
      serFromString(val.get<string_view>(), rr);
      struct soatimes 
      {
        uint32_t serial;
        uint32_t refresh;
        uint32_t retry;
        uint32_t expire;
        uint32_t minimum;
      } st;

      memcpy(&st, &rr.content[rr.content.size()-sizeof(soatimes)], sizeof(soatimes));

      if((time_t)(iter->last_check + ntohl(st.refresh)) >= now) { // still fresh
        continue; // try next domain
      }
      //      cout << di.last_check <<" + " <<sdata.refresh<<" > = " << now << "\n";
      serial = ntohl(st.serial);
    }
    else {
      cout << "Could not find SOA for "<<iter->zone<<" with id "<<iter.getID()<<endl;
      serial=0;  
    }
    DomainInfo di=*iter;    
    di.id = iter.getID();
    di.serial = serial;

    domains->push_back(di);
  }
  //  cout<<"END of getUnfreshSlaveInfos"<<endl;
}

bool LMDBBackend::getAllDomainMetadata(const DNSName& name, std::map<std::string, std::vector<std::string> >& meta)
{
  meta.clear();
  auto txn = d_tmeta->getROTransaction();
  auto range = txn.equal_range<0>(name);
  
  for(auto& iter = range.first; iter != range.second; ++iter) {
    meta[iter->key].push_back(iter->value);
  }
  return true;
}

bool LMDBBackend::setDomainMetadata(const DNSName& name, const std::string& kind, const std::vector<std::string>& meta)
{
  cout<<"Wants to set "<<kind<<" for domain "<<name<<endl;
  auto txn = d_tmeta->getRWTransaction();

  auto range = txn.equal_range<0>(name);

  for(auto& iter = range.first; iter != range.second; ++iter) {
    if(iter-> key == kind)
      iter.del();
  }

  for(const auto& m : meta) {
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
  for(auto& iter = range.first; iter != range.second; ++iter) {
    KeyData kd{iter->content, iter.getID(), iter->flags, iter->active};
    keys.push_back(kd);
  }

  return true;
}

bool LMDBBackend::removeDomainKey(const DNSName& name, unsigned int id)
{
  auto txn = d_tkdb->getRWTransaction();
  KeyDataDB kdb;
  if(txn.get(id, kdb)) {
    if(kdb.domain == name) {
      txn.del(id);
      txn.commit();
      return true;
    }
  }
  cout << "??? wanted to remove domain key for domain "<<name<<" with id "<<id<<", could not find it"<<endl;
  return true;
}

bool LMDBBackend::addDomainKey(const DNSName& name, const KeyData& key, int64_t& id)
{
  auto txn = d_tkdb->getRWTransaction();
  KeyDataDB kdb{name, key.content, key.flags, key.active};
  id = txn.put(kdb);
  txn.commit();
    
  return true;
}

bool LMDBBackend::activateDomainKey(const DNSName& name, unsigned int id)
{
  auto txn = d_tkdb->getRWTransaction();
  KeyDataDB kdb;
  if(txn.get(id, kdb)) {
    if(kdb.domain == name) {
      txn.modify(id, [](KeyDataDB& kdb)
                 {
                   kdb.active = true;
                 });
      txn.commit();
      return true;
    }
  }

  cout << "??? wanted to activate domain key for domain "<<name<<" with id "<<id<<", could not find it"<<endl;
  return true;
}

bool LMDBBackend::deactivateDomainKey(const DNSName& name, unsigned int id)
{
  auto txn = d_tkdb->getRWTransaction();
  KeyDataDB kdb;
  if(txn.get(id, kdb)) {
    if(kdb.domain == name) {
      txn.modify(id, [](KeyDataDB& kdb)
                 {
                   kdb.active = false;
                 });
      txn.commit();
      return true;
    }
  }
  cout << "??? wanted to activate domain key for domain "<<name<<" with id "<<id<<", could not find it"<<endl;
  return true;
}

bool LMDBBackend::getBeforeAndAfterNamesAbsolute(uint32_t id, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after) 
{
  cout << __PRETTY_FUNCTION__<< ": "<<id <<", "<<qname << endl;
#if 0
  auto txn = getRecordsROTransaction(id);
  compoundOrdername co;
  DNSResourceRecord rr;
  rr.domain_id = id;
  
  if(qname == zonename)
    rr.wildcardname = DNSName(".");
  else
    rr.wildcardname = qname.makeRelative(zonename);
  
  auto iter = txn->lower_bound<2>(co(rr));

  if(iter == txn->end()) {
    cout << "Found nothing.. need to pick the very last entry" << endl;
    // this means name is beyond the end
    // before now needs to be the last name that does exist
    // after first name that exists

    rr.domain_id++;
    rr.wildcardname = DNSName(".");
    auto iter2 = txn->rbegin<2>();
    cout<<"Before = " <<iter2->qname<<", domain_id = "<<iter2->domain_id<<endl;
    before = iter2->qname;

    rr.domain_id--;
    rr.wildcardname = DNSName(".");
    auto iter3 = txn->find<2>(co(rr));
    if(iter3 == txn->end()) {
      cout <<"Hmf, zone has no beginning?!"<<endl;
      cout << makeHexDump(co(rr)) << endl;
      return false;
    }
    cout<<"Found: '"<<iter3->qname<<"'"<<endl;
    after = iter3->qname;
    return true;
    
  }
  else if((unsigned)iter->domain_id != id) {
    cout << "We fell off the end of the domain!" <<endl;
    --iter;
    before = iter->qname; // this is now the last name

    rr.wildcardname = DNSName(".");
    auto iter3 = txn->find<2>(co(rr));
    if(iter3 == txn->end()) {
      cout <<"Hmf, zone has no beginning?!"<<endl;
      cout << makeHexDump(co(rr)) << endl;
      return false;
    }
    cout<<"Found: '"<<iter3->qname<<"'"<<endl;
    after = iter3->qname;
    return true;
  }
  else {
    if(iter->wildcardname == rr.wildcardname) {
      cout<<"Name existed!" << endl;
      before = iter->qname;
      for(++iter; iter != txn->end();  ++iter) {
        cout<<"Trying "<<iter.getID()<<" '" << iter->qname<< "' '" <<iter->domain_id << "' '" << iter->wildcardname<< "' < '" << rr.wildcardname << "' " <<iter->wildcardname.canonCompare(rr.wildcardname)<<endl;
        if(iter->qname != before) {
          cout<<"Hit!"<<endl;
          after = iter->qname;
          return true;
        }
      }
      cout << "Shit, could not find the next name!" << endl;
      return false;
        
    }
    after = iter->qname;    
    try {
      for(; iter != txn->end() && (unsigned) iter->domain_id == id; --iter) {
        cout<<"Trying "<<iter.getID()<<" '" << iter->qname<< "' '" <<iter->domain_id << "' '" << iter->wildcardname<< "' < '" << rr.wildcardname << "' " <<iter->wildcardname.canonCompare(rr.wildcardname)<<endl;
        if(iter->wildcardname.canonCompare(rr.wildcardname)) {
          before = iter->qname;
          cout << "Returning "<<before<<" " <<after<<endl;
          return true;
        }
      }
    }
    catch(std::runtime_error& e) {
    }
    cout << "We hit the beginning of the zone or the database.. now what" <<endl;
  } 
#endif   
  return false;
}

bool LMDBBackend::getBeforeAndAfterNames(uint32_t id, const DNSName& zonenameU, const DNSName& qname, DNSName& before, DNSName& after)
{
  DNSName zonename = zonenameU.makeLowerCase();
  cout << __PRETTY_FUNCTION__<< ": "<<id <<", "<<zonename << ", '"<<qname<<"'"<<endl;

  auto txn = getRecordsROTransaction(id);
  compoundOrdername co;
  DNSName qname2 = qname.makeRelative(zonename);
  string matchkey=co(id,qname2);
  auto cursor = txn->txn.getCursor(txn->db->dbi);
  MDBOutVal key, val;
  cout<<"Lower_bound for "<<qname2<<endl;
  if(cursor.lower_bound(matchkey, key, val)) {
    cout << "Hit end of database, bummer"<<endl;
    cursor.last(key, val);
    if(co.getDomainID(key.get<string_view>()) == id) {
      before = co.getQName(key.get<string_view>()) + zonename;
      after = zonename;
    }
    else
      cout << "We were at end of database, but this zone is not there?!"<<endl;
    return true;
  }
  cout<<"Cursor is at "<<co.getQName(key.get<string_view>()) <<", in zone id "<<co.getDomainID(key.get<string_view>())<< endl;

  if(co.getDomainID(key.get<string_view>()) != id) {
    cout << "Ended up in next zone!" <<endl;
    cursor.prev(key, val);
    before = co.getQName(key.get<string_view>()) + zonename;
    after = zonename;
    return true;
  }
  if(co.getQName(key.get<string_view>()) == qname2) {
    cout << "Had an exact match!"<<endl;
    before = qname2 + zonename;
    while(!cursor.next(key, val) && key.get<StringView>().rfind(matchkey, 0)==0)
      ;
    if(co.getDomainID(key.get<string_view>()) != id) {
      cout << "We hit the end of the zone. Next is apex" << endl;
      after=zonename;
      return false;
    }
    after = co.getQName(key.get<string_view>()) + zonename;
    return true;
  }
  else {
    after = co.getQName(key.get<string_view>()) + zonename;
    cout <<"We ended up after "<<qname<<", set 'after' to "<<after<<endl;
    while(!cursor.prev(key, val) && key.get<StringView>().rfind(matchkey, 0)==0)
      ;
    // we don't check if 'prev' failed XXX
    if(co.getDomainID(key.get<string_view>()) != id) {
      // XX I don't think this case can happen
      cout << "We hit the beginning of the zone or database.. now what" << endl;
      return false;
    }
    
    before = co.getQName(key.get<string_view>()) + zonename;
    cout<<"And before to "<<before<<endl;
    return true;
  }

  return true;

}

// XXX this function does not actually update ordername, which it should do for NSEC3
bool LMDBBackend::updateDNSSECOrderNameAndAuth(uint32_t domain_id, const DNSName& qname, const DNSName& ordername, bool auth, const uint16_t qtype)
{
  cout << __PRETTY_FUNCTION__<< ": "<< domain_id <<", '"<<qname <<"', '"<<ordername<<"', "<<auth<< endl;
  shared_ptr<RecordsRWTransaction> txn;
  if(0 && d_rwtxn) { // we might reuse one for the wrong domain_id
    txn = d_rwtxn;
    cout<<"Reusing open transaction"<<endl;
  }
  else {
    cout<<"Making a new RW txn for " << __PRETTY_FUNCTION__ <<endl;
    txn = getRecordsRWTransaction(domain_id);
  }

  compoundOrdername co;
  string matchkey;
  if(qtype ==QType::ANY)
    matchkey = co(domain_id, qname);
  else
    matchkey = co(domain_id, qname, qtype);

  auto cursor = txn->txn.getCursor(txn->db->dbi);
  MDBOutVal key, val;
  if(cursor.lower_bound(matchkey, key, val)) {
    return false;
  }
  
  for(; key.get<StringView>().rfind(matchkey,0) == 0; ) {
    DNSResourceRecord rr;
    serFromString(val.get<StringView>(), rr);
    if(rr.auth != auth) {
      rr.auth = auth;
      string repl = serToString(rr);
      cursor.put(key, repl);
    }
    if(cursor.next(key, val))
      break;
  }
  //  if(!d_rwtxn)
    txn->txn.commit();
  return false;
}

bool LMDBBackend::updateEmptyNonTerminals(uint32_t domain_id, set<DNSName>& insert, set<DNSName>& erase, bool remove) 
{
  cout << __PRETTY_FUNCTION__<< ": "<< domain_id << ", insert.size() "<<insert.size()<<", "<<erase.size()<<", " <<remove<<endl;
  return false;
}

/* TSIG */
bool LMDBBackend::getTSIGKey(const DNSName& name, DNSName* algorithm, string* content)
{
  auto txn = d_ttsig->getROTransaction();

  TSIGKey tk;
  if(!txn.get<0>(name, tk))
    return false;
  if(algorithm)
    *algorithm = tk.algorithm;
  if(content)
    *content = tk.key;
  return true;

}
// this deletes an old key if it has the same algorithm
bool LMDBBackend::setTSIGKey(const DNSName& name, const DNSName& algorithm, const string& content)
{
  auto txn = d_ttsig->getRWTransaction();

  for(auto range = txn.equal_range<0>(name); range.first != range.second; ++range.first) {
    if(range.first->algorithm == algorithm)
      range.first.del();
  }

  TSIGKey tk;
  tk.name = name;
  tk.algorithm = algorithm;
  tk.key=content;
  
  txn.put(tk);
  txn.commit();
  
  return true;
}
bool LMDBBackend::deleteTSIGKey(const DNSName& name)
{
  auto txn = d_ttsig->getRWTransaction();
  TSIGKey tk;

  for(auto range = txn.equal_range<0>(name); range.first != range.second; ++range.first) {
    range.first.del();
  }
  txn.commit();
  return true;
}
bool LMDBBackend::getTSIGKeys(std::vector< struct TSIGKey > &keys)
{
  auto txn = d_ttsig->getROTransaction();

  keys.clear();
  for(auto iter = txn.begin(); iter != txn.end(); ++iter) {
    keys.push_back(*iter);
  }
  return false;
}




class LMDBFactory : public BackendFactory
{
public:
  LMDBFactory() : BackendFactory("lmdb") {}
  void declareArguments(const string &suffix="")
  {
    declare(suffix,"filename","Filename for lmdb","./pdns.lmdb");
    declare(suffix,"sync-mode","Synchronisation mode: nosync, nometasync, mapasync","mapasync");
    declare(suffix,"shards","Records database will be split into this number of shards","64");
  }
  DNSBackend *make(const string &suffix="")
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
