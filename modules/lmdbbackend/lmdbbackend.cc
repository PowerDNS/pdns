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
template<>
std::string keyConv(const DNSName& t)
{
  return t.toDNSStringLC();
}

LMDBBackend::LMDBBackend(const std::string& suffix)
{
  setArgPrefix("lmdb"+suffix);
  
  string syncMode = toLower(getArg("sync-mode"));
  int asyncFlag = 0;
  if(syncMode == "nosync")
    asyncFlag = MDB_NOSYNC;
  else if(syncMode == "nometasync")
    asyncFlag = MDB_NOMETASYNC;
  else if(syncMode == "mapasync")
    asyncFlag = MDB_MAPASYNC;
  else if(syncMode.empty())
    asyncFlag = 0;
  else
    throw std::runtime_error("Unknown sync mode "+syncMode+" requested for LMDB backend");
  
  d_trecords = std::make_shared<trecords_t>(getMDBEnv(getArg("filename").c_str(), MDB_NOSUBDIR | asyncFlag | MDB_WRITEMAP, 0600), "records");
  d_tdomains = std::make_shared<tdomains_t>(d_trecords->getEnv(), "domains");
  d_tmeta = std::make_shared<tmeta_t>(d_trecords->getEnv(), "metadata");
  d_tkdb = std::make_shared<tkdb_t>(d_trecords->getEnv(), "keydata");
    
  d_dolog = ::arg().mustDo("query-logging");
}



namespace boost {
namespace serialization {

template<class Archive>
void save(Archive & ar, const DNSName& g, const unsigned int version)
{
  ar & g.toDNSStringLC();
}

template<class Archive>
void load(Archive & ar, DNSName& g, const unsigned int version)
{
  string tmp;
  ar & tmp;
  g = DNSName(tmp.c_str(), tmp.size(), 0, false);
}

template<class Archive>
void save(Archive & ar, const QType& g, const unsigned int version)
{
  ar & g.getCode();
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
void serialize(Archive & ar, DNSResourceRecord& g, const unsigned int version)
{
  ar & g.qtype;
  ar & g.qname;
  ar & g.content;
  ar & g.ttl;
  ar & g.domain_id;
  ar & g.auth;
}


} // namespace serialization
} // namespace boost

BOOST_SERIALIZATION_SPLIT_FREE(DNSName);
BOOST_SERIALIZATION_SPLIT_FREE(QType);
BOOST_IS_BITWISE_SERIALIZABLE(ComboAddress);

void LMDBBackend::deleteDomainRecords(trecords_t::RWTransaction& txn, uint32_t domain_id)
{
  cout << "Going to delete domain with id "<<domain_id << endl;
  auto range = txn.equal_range<1>(domain_id);
  for(auto& iter = range.first; iter != range.second; ++iter) {
    txn.del(iter.getID());
  }  
}

bool LMDBBackend::startTransaction(const DNSName &domain, int domain_id)
{
  //  cout<<"Start transaction for domain "<<domain_id<<endl;
  
  d_rwtxn = std::make_shared<trecords_t::RWTransaction>(d_trecords->getRWTransaction());

  if(domain_id >= 0) {
    deleteDomainRecords(*d_rwtxn, domain_id);
  }

  return true;
}

bool LMDBBackend::commitTransaction()
{
  d_rwtxn->commit();
  d_rwtxn.reset();
  return true;
}

bool LMDBBackend::abortTransaction()
{
  cout<<"Abort transaction"<<endl;
  d_rwtxn->abort();
  d_rwtxn.reset();

  return true;
}

bool LMDBBackend::feedRecord(const DNSResourceRecord &r, const DNSName &ordername)
{
  d_rwtxn->put(r); // stuff in ordername somehow
  return true;
}

bool LMDBBackend::replaceRRSet(uint32_t domain_id, const DNSName& qname, const QType& qt, const vector<DNSResourceRecord>& rrset)
{
  // zonk qname/qtype within domain_id (go through qname, check domain_id && qtype)
  shared_ptr<trecords_t::RWTransaction> txn;
  if(d_rwtxn) {
    txn = d_rwtxn;
    cout<<"Reusing open transaction"<<endl;
  }
  else {
    cout<<"Making a new RW txn for replace rrset"<<endl;
    txn = std::make_shared<trecords_t::RWTransaction>(d_trecords->getRWTransaction());
  }

  auto range = txn->equal_range<0>(qname); // XXX dangerous (why?)
  for(auto& iter = range.first; iter != range.second; ++iter) {
    if(iter->domain_id == (int32_t)domain_id && iter->qtype == qt) {
      iter.del();
    }
  }

  for(const auto& rr : rrset) {
    txn->put(rr);
  }
  
  if(!d_rwtxn)
    txn->commit();
  return true;
}

bool LMDBBackend::deleteDomain(const DNSName &domain)
{
  shared_ptr<trecords_t::RWTransaction> txn;
  if(d_rwtxn) {
    txn = d_rwtxn;
    cout<<"Reusing open transaction"<<endl;
  }
  else {
    cout<<"Making a new RW txn for delete domain"<<endl;
    txn = std::make_shared<trecords_t::RWTransaction>(d_trecords->getRWTransaction());
  }


  auto doms = d_tdomains->getRWTransaction(txn->getTransactionHandle());

  DomainInfo di;
  auto id = doms.get<0>(domain, di); 
  if(id) {
    doms.del(id);
    auto range = txn->equal_range<1>(id);
    for(auto& iter = range.first; iter != range.second; ++iter)
      iter.del();

  }
  else
    return false;
  
  if(!d_rwtxn)
    txn->commit();
  return true;
}

bool LMDBBackend::list(const DNSName &target, int id, bool include_disabled)
{
//  cout<<"In list for id "<<id<<endl;
  d_inlist=true;
  DomainInfo di;

  {
    auto dtxn = d_tdomains->getROTransaction();
    
    if((di.id = dtxn.get<0>(target, di))) 
  ;//     cout<<"Found domain "<<target<<" on domain_id "<<di.id << endl;
    else {
      cout<<"Did not find "<<target<<endl;
      return false;
    }
  }
  
  d_rotxn = std::make_shared<trecords_t::ROTransaction>(d_trecords->getROTransaction());  
  auto range = d_rotxn->equal_range<1>(di.id);
  d_listrange = std::make_shared<listrange_t::element_type>(std::move(range));
  d_inlist = true;
  
  return true;
}

bool LMDBBackend::get(DNSResourceRecord& rr)
{
  if(d_inlist)
    return get_list(rr);
  else
    return get_lookup(rr);
}

bool LMDBBackend::get_list(DNSResourceRecord& rr)
{
  if(!d_listrange || d_listrange->first == d_listrange->second)  {
    d_listrange.reset();
    d_rotxn.reset();
    return false;
  }
  rr = *d_listrange->first;
  ++d_listrange->first;
  return true;
}


void LMDBBackend::lookup(const QType &type, const DNSName &qdomain, DNSPacket *p, int zoneId)
{
  if(d_dolog) {
    g_log << Logger::Warning << "Got lookup for "<<qdomain<<"|"<<type.getName()<<" in zone "<< zoneId<<endl;
    d_dtime.set();
  }
  d_rotxn = std::make_shared<trecords_t::ROTransaction>(d_trecords->getROTransaction());

  d_listrange = std::make_shared<listrange_t::element_type>(d_rotxn->equal_range<0>(qdomain));

  if(d_dolog) {
    g_log<<Logger::Warning<< "Query "<<((long)(void*)this)<<": "<<d_dtime.udiffNoReset()<<" usec to execute"<<endl;
  }
    
  d_inlist=false;
  d_lookuptype=type;
  d_lookupdomainid = zoneId;
}


bool LMDBBackend::get_lookup(DNSResourceRecord& rr)
{
  for(auto& iter = d_listrange->first; iter != d_listrange->second; ++iter)
  {
    if(d_lookupdomainid >=0 && iter->domain_id != (int32_t)d_lookupdomainid)
      continue;

    if(d_lookuptype != QType::ANY && iter->qtype != d_lookuptype)
      continue;
    rr = *iter;
    rr.auth = true; // XXX why??
    ++iter;
    return true;
  }

  d_listrange.reset();
  d_rotxn.reset();
  return false;
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
  shared_ptr<tdomains_t::RWTransaction> txn;
  if(d_rwtxn) {
    txn = std::make_shared<tdomains_t::RWTransaction>(d_tdomains->getRWTransaction(d_rwtxn->getTransactionHandle()));
    cout<<"Reusing open transaction"<<endl;
  }
  else {
    cout<<"Making a new RW txn for genChangeDomain record"<<endl;
    txn = std::make_shared<tdomains_t::RWTransaction>(d_tdomains->getRWTransaction());
  }

  DomainInfo di;

  auto id = txn->get<0>(domain, di);
  func(di);
  txn->put(di, id);
  
  if(!d_rwtxn)
    txn->commit();
  return true;
}

int LMDBBackend::genChangeDomain(uint32_t id, std::function<void(DomainInfo&)> func)
{
  shared_ptr<tdomains_t::RWTransaction> txn;
  if(d_rwtxn) {
    txn = std::make_shared<tdomains_t::RWTransaction>(d_tdomains->getRWTransaction(d_rwtxn->getTransactionHandle()));
    cout<<"Reusing open transaction"<<endl;
  }
  else {
    cout<<"Making a new RW txn for genChangeDomain record"<<endl;
    txn = std::make_shared<tdomains_t::RWTransaction>(d_tdomains->getRWTransaction());
  }

  DomainInfo di;

  // XXXX this likely is wrong
  txn->get(id , di);
  
  func(di);
  
  txn->put(di, id);

  if(!d_rwtxn)
    txn->commit();
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
  domains->clear();
  auto txn = d_tdomains->getROTransaction();
  auto rectxn = d_trecords->getROTransaction(txn.getTransactionHandle());
  for(auto iter = txn.begin(); iter != txn.end(); ++iter) {
    DomainInfo di=*iter;
    di.serial=0;
    if(di.kind != DomainInfo::Slave)
      continue;
    
    di.id = iter.getID();

    auto range = rectxn.equal_range<0>(di.zone);
    string content;
    for(auto& iter2 = range.first ; iter2 != range.second; ++iter2) {
      if(iter2->qtype.getCode() == QType::SOA && iter2->domain_id == (int32_t)di.id) {
        content = iter2->content;
        break;
      }
    }
    if(!content.empty()) {
      SOAData sdata;
      sdata.serial=0;
      sdata.refresh=0;
      fillSOAData(content, sdata);
        
      if((time_t)(di.last_check+sdata.refresh) >= time(0)) { // still fresh
        continue; // try next domain
      }
      di.serial=sdata.serial;
    }
    domains->push_back(di);
  }
}

bool LMDBBackend::getAllDomainMetadata(const DNSName& name, std::map<std::string, std::vector<std::string> >& meta)
{
  meta.clear();
  if(d_rwtxn) { // within transaction already
    auto txn = d_tmeta->getRWTransaction(d_rwtxn->getTransactionHandle());
    auto range = txn.equal_range<0>(name);
    
    for(auto& iter = range.first; iter != range.second; ++iter) {
      meta[iter->key].push_back(iter->value);
    }

  }
  else {
    auto txn = d_tmeta->getROTransaction();
    auto range = txn.equal_range<0>(name);
    
    for(auto& iter = range.first; iter != range.second; ++iter) {
      meta[iter->key].push_back(iter->value);
    }
  }
  return true;
}

bool LMDBBackend::setDomainMetadata(const DNSName& name, const std::string& kind, const std::vector<std::string>& meta)
{
  cout<<"Wants to set "<<kind<<" for domain "<<name<<endl;
  shared_ptr<tmeta_t::RWTransaction> txn;
  if(d_rwtxn) {
    txn = std::make_shared<tmeta_t::RWTransaction>(d_tmeta->getRWTransaction(d_rwtxn->getTransactionHandle()));
    cout<<"Reusing open transaction for setdomainmetadata"<<endl;
  }
  else {
    //    cout<<"Making a new RW txn for setdomainmetadata"<<endl;
    txn = std::make_shared<tmeta_t::RWTransaction>(d_tmeta->getRWTransaction());
  }

  auto range = txn->equal_range<0>(name);

  for(auto& iter = range.first; iter != range.second; ++iter) {
    if(iter-> key == kind)
      iter.del();
  }

  for(const auto& m : meta) {
    DomainMeta dm{name, kind, m};
    txn->put(dm);
  }
  if(!d_rwtxn)
    txn->commit();
  return true;
}

bool LMDBBackend::getDomainKeys(const DNSName& name, std::vector<KeyData>& keys)
{
  if(d_rwtxn) {
    auto txn = d_tkdb->getRWTransaction(d_rwtxn->getTransactionHandle());
    auto range = txn.equal_range<0>(name);
    for(auto& iter = range.first; iter != range.second; ++iter) {
      KeyData kd{iter->content, iter.getID(), iter->flags, iter->active};
      keys.push_back(kd);
    }
  }
  else {
    auto txn = d_tkdb->getROTransaction();
    auto range = txn.equal_range<0>(name);
    for(auto& iter = range.first; iter != range.second; ++iter) {
      KeyData kd{iter->content, iter.getID(), iter->flags, iter->active};
      keys.push_back(kd);
    }
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
  if(!d_rwtxn) {
    auto txn = d_tkdb->getRWTransaction();
    KeyDataDB kdb{name, key.content, key.flags, key.active};
    id = txn.put(kdb);
    txn.commit();
  }
  else {
    auto txn = d_tkdb->getRWTransaction(d_rwtxn->getTransactionHandle());
    KeyDataDB kdb{name, key.content, key.flags, key.active};
    id = txn.put(kdb);
  }
    
  return true;
}

bool LMDBBackend::activateDomainKey(const DNSName& name, unsigned int id)
{
  // XX needs to sense transaction
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
  // XX needs to sense transaction
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


class LMDBFactory : public BackendFactory
{
public:
  LMDBFactory() : BackendFactory("lmdb") {}
  void declareArguments(const string &suffix="")
  {
    declare(suffix,"filename","Filename for lmdb","./pdns.lmdb");
    declare(suffix,"sync-mode","Synchronisation mode: nosync, nometasync, mapasync","mapasync");
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
