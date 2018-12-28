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
  
  //  d_trecords = std::make_shared<trecords_t>(getMDBEnv(getArg("filename").c_str(), MDB_NOSUBDIR | asyncFlag | MDB_WRITEMAP, 0600), "records");

  d_tdomains = std::make_shared<tdomains_t>(getMDBEnv(getArg("filename").c_str(), MDB_NOSUBDIR | d_asyncFlag | MDB_WRITEMAP, 0600), "domains");
  d_tmeta = std::make_shared<tmeta_t>(d_tdomains->getEnv(), "metadata");
  d_tkdb = std::make_shared<tkdb_t>(d_tdomains->getEnv(), "keydata");
    
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
void serialize(Archive & ar, DNSResourceRecord& g, const unsigned int version)
{
  ar & g.qtype;
  ar & g.qname;
  ar & g.content;
  ar & g.wildcardname; // this is the ordername
  ar & g.ttl;
  ar & g.domain_id;
  ar & g.auth;
}


} // namespace serialization
} // namespace boost

BOOST_SERIALIZATION_SPLIT_FREE(DNSName);
BOOST_SERIALIZATION_SPLIT_FREE(QType);
BOOST_IS_BITWISE_SERIALIZABLE(ComboAddress);

/* design. If you ask a question without a zone id, we lookup the best
   zone id for you, and answer from that. This is different than other backends, but I can't see why it would not work.

   The index we use is "zoneid,canonical relative name". This index is also used
   for AXFR.
*/



void LMDBBackend::deleteDomainRecords(trecords_t::RWTransaction& txn, uint32_t domain_id)
{
  cout << "Going to delete records from domain with id "<<domain_id << endl;
  compoundOrdername co;

  for(auto range = txn.prefix_range<0>(co(domain_id)); range.first != range.second; ++range.first) {
    txn.del(range.first.getID());
  }  
}

bool LMDBBackend::startTransaction(const DNSName &domain, int domain_id)
{
  d_rwtxn = getRecordsRWTransaction(domain_id);

  if(domain_id >= 0) {
    deleteDomainRecords(*d_rwtxn, domain_id);
  }

  return true;
}

bool LMDBBackend::commitTransaction()
{
  cout<<"Commit transaction" <<endl;
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
  DNSResourceRecord rr2(r);
  rr2.wildcardname = ordername;
  d_rwtxn->put(rr2); 
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
    txn = getRecordsRWTransaction(domain_id);
  }

  compoundOrdername co;
  
  for(auto range = txn->prefix_range<0>(co(domain_id,qname,qt.getCode()));  range.first != range.second; ++range.first) {
    range.first.del();
  }

  for(const auto& rr : rrset) {
    txn->put(rr);
  }
  
  if(!d_rwtxn)
    txn->commit();

  return true;
}

std::shared_ptr<LMDBBackend::trecords_t::RWTransaction> LMDBBackend::getRecordsRWTransaction(uint32_t id)
{
  auto& shard =d_trecords[id % s_shards];
  if(!shard)
    shard = std::make_shared<trecords_t>(getMDBEnv( (getArg("filename")+"-"+std::to_string(id % s_shards)).c_str(),
                                                    MDB_NOSUBDIR | d_asyncFlag | MDB_WRITEMAP, 0600), "records");

  return std::make_shared<trecords_t::RWTransaction>(shard->getRWTransaction());
}

std::shared_ptr<LMDBBackend::trecords_t::ROTransaction> LMDBBackend::getRecordsROTransaction(uint32_t id)
{
  auto& shard =d_trecords[id % s_shards];
  if(!shard)
    shard = std::make_shared<trecords_t>(getMDBEnv( (getArg("filename")+"-"+std::to_string(id % s_shards)).c_str(),
                                                    MDB_NOSUBDIR | d_asyncFlag | MDB_WRITEMAP, 0600), "records");

  return std::make_shared<trecords_t::ROTransaction>(shard->getROTransaction());
}


bool LMDBBackend::deleteDomain(const DNSName &domain)
{
  auto doms = d_tdomains->getRWTransaction();

  DomainInfo di;
  auto id = doms.get<0>(domain, di); 
  if(!id)
    return false;
  
  shared_ptr<trecords_t::RWTransaction> txn;
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
  
  for(auto range = txn->prefix_range<0>(co(id)); range.first != range.second; ++range.first)
    range.first.del();
  
  if(!d_rwtxn)
    txn->commit();
  
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
      cout<<"Found domain "<<target<<" on domain_id "<<di.id <<", list requested "<<id<<endl;
    else {
      cout<<"Did not find "<<target<<endl;
      return false;
    }
  }
  
  d_rotxn = getRecordsROTransaction(di.id);
  compoundOrdername co;
  d_getiter = std::make_shared<trecords_t::ROTransaction::iter_t>(d_rotxn->prefix_range<0>(co(di.id)).first );
  d_inlist = true;
  
  return true;
}

void LMDBBackend::lookup(const QType &type, const DNSName &qdomain, DNSPacket *p, int zoneId)
{
  if(d_dolog) {
    g_log << Logger::Warning << "Got lookup for "<<qdomain<<"|"<<type.getName()<<" in zone "<< zoneId<<endl;
    d_dtime.set();
  }

  if(zoneId < 0) {
    DNSName hunt(qdomain);
    for(;;) {
      DomainInfo di;
    
      if((zoneId = d_tdomains->getROTransaction().get<0>(hunt, di))) {
        break;
      }
      if(!hunt.chopOff())
        break;
    }
    if(zoneId <= 0) {
      cout << "Did not find zone"<<endl;
      d_getiter.reset();
      return;
    }
  }
    
  
  d_rotxn = getRecordsROTransaction(zoneId);

  compoundOrdername co;
  if(type.getCode() == QType::ANY)
    d_getiter = std::make_shared<trecords_t::ROTransaction::iter_t>(d_rotxn->prefix_range<0>(co(zoneId,qdomain)).first);
  else
    d_getiter = std::make_shared<trecords_t::ROTransaction::iter_t>(d_rotxn->prefix_range<0>(co(zoneId,qdomain, type.getCode())).first);

  if(d_dolog) {
    g_log<<Logger::Warning<< "Query "<<((long)(void*)this)<<": "<<d_dtime.udiffNoReset()<<" usec to execute"<<endl;
  }
    
  d_inlist=false;
  d_lookuptype=type;
  d_lookupqname = qdomain;
  d_lookupdomainid = zoneId;
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
  if(d_getiter && (*d_getiter == d_rotxn->end())) {
    d_getiter.reset();
    d_rotxn.reset();
    return false;
  }
  if(!d_getiter)  {
    d_rotxn.reset();
    return false;
  }

  rr = **d_getiter;
  ++(*d_getiter);
  return true;
}


bool LMDBBackend::get_lookup(DNSResourceRecord& rr)
{
  if(!d_getiter)
    return false;
  
  for(auto& iter = *d_getiter; iter != d_rotxn->end() ; ++iter)
  {
    if(d_lookuptype != QType::ANY && iter->qtype != d_lookuptype)
      continue;
    rr = *iter;
    rr.auth = true; // XXX why??
    ++iter;
    return true;
  }

  d_getiter.reset();
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
  cout<<"Start of getUnfreshSlaveInfos"<<endl;
  domains->clear();
  auto txn = d_tdomains->getROTransaction();

  time_t now = time(0);
  for(auto iter = txn.begin(); iter != txn.end(); ++iter) {
    if(iter->kind != DomainInfo::Slave)
      continue;
    
    DomainInfo di=*iter;    
    di.id = iter.getID();
    di.serial=0;

    auto txn2 = getRecordsROTransaction(di.id);
    compoundOrdername co;
    auto range = txn2->prefix_range<0>(co(di.id, di.zone, QType::SOA));
    if(range.first != range.second) {
      SOAData sdata;
      sdata.serial=0;
      sdata.refresh=0;
      fillSOAData(range.first->content, sdata);
        
      if((time_t)(di.last_check + sdata.refresh) >= now) { // still fresh
        continue; // try next domain
      }
      di.serial = sdata.serial;
    }
    domains->push_back(di);
  }
  cout<<"END of getUnfreshSlaveInfos"<<endl;
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

bool LMDBBackend::getBeforeAndAfterNames(uint32_t id, const DNSName& zonename, const DNSName& qname, DNSName& before, DNSName& after)
{
  cout << __PRETTY_FUNCTION__<< ": "<<id <<", "<<zonename << ", '"<<qname<<"'"<<endl;

  auto txn = getRecordsROTransaction(id);
  compoundOrdername co;
  auto iter = txn->lower_bound<0>(co(id,qname));
  if(iter == txn->end()) {
    cout << "Hit end of database, bummer"<<endl;
    return false;
  }
  else if(iter->qname == qname) { 
    before = iter->qname;
    while(iter->qname == qname)
      ++iter;
    after = iter->qname; 
    return true;
  }
  else {
    after = iter->qname;    
    try {
      for(; iter != txn->end() && (unsigned) iter->domain_id == id; --iter) {
        if(iter->qname.canonCompare(qname)) {
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

  return true;
  
}

// XXX this function should not update ordername for NSEC, only for NSEC3
bool LMDBBackend::updateDNSSECOrderNameAndAuth(uint32_t domain_id, const DNSName& qname, const DNSName& ordername, bool auth, const uint16_t qtype)
{
  cout << __PRETTY_FUNCTION__<< ": "<< domain_id <<", '"<<qname <<"', '"<<ordername<<"', "<<auth<< endl;
  shared_ptr<trecords_t::RWTransaction> txn;
  if(0 && d_rwtxn) { // we might reuse one for the wrong domain_id
    txn = d_rwtxn;
    cout<<"Reusing open transaction"<<endl;
  }
  else {
    cout<<"Making a new RW txn for " << __PRETTY_FUNCTION__ <<endl;
    txn = getRecordsRWTransaction(domain_id);
  }

  compoundOrdername co;
  auto iter = txn->lower_bound<0>(co(domain_id, qname));
  if(iter == txn->end())
    cout << "Found nothing for "<<qname<<endl;
  for(; iter != txn->end(); ++iter) {
    if((unsigned)iter->domain_id != domain_id || iter->qname != qname) {
      break;
    }
    if(qtype != QType::ANY && qtype != iter->qtype.getCode()) {
      cout << "QType is wrong "<<endl;
      continue;
    }
    cout << "Modifying " << iter.getID() << " to set ordername to '"<<ordername<<"' and auth to "<< auth<<endl;
    if(iter->wildcardname != ordername || iter->auth != auth) {
      txn->modify(iter.getID(), [&ordername, &auth](DNSResourceRecord& rr) {
          rr.wildcardname = ordername;
          rr.auth=auth;
        });
    }
    
  }
  //  if(!d_rwtxn)
    txn->commit();
  return false;
}

bool LMDBBackend::updateEmptyNonTerminals(uint32_t domain_id, set<DNSName>& insert, set<DNSName>& erase, bool remove) 
{
  cout << __PRETTY_FUNCTION__<< ": "<< domain_id << ", insert.size() "<<insert.size()<<", "<<erase.size()<<", " <<remove<<endl;
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
