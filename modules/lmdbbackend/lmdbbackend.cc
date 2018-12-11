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
#include "pdns/dnsbackend.hh"
#include "pdns/dnspacket.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/logger.hh"
#include "pdns/version.hh"
#include <boost/algorithm/string.hpp>
#include <boost/archive/binary_oarchive.hpp>
#include <boost/archive/binary_iarchive.hpp>
#include <boost/serialization/vector.hpp>
#include <boost/serialization/string.hpp>
#include <sstream>

#include "lmdb-safe.hh"
/* FIRST PART */
class LMDBBackend : public DNSBackend
{
public:
  LMDBBackend(const string &suffix="") :
    d_env(getMDBEnv("./pdns.lmdb", MDB_NOSUBDIR, 0600)),
    d_recordsdbi(d_env->openDB("records", MDB_CREATE | MDB_INTEGERKEY)),
    d_recordsnameidxdbi(d_env->openDB("records_nameidx", MDB_CREATE | MDB_DUPSORT)),
    d_recordsdomainididxdbi(d_env->openDB("records_domainidx", MDB_CREATE | MDB_INTEGERKEY | MDB_DUPSORT | MDB_INTEGERDUP)),
    d_domainsdbi(d_env->openDB("domains", MDB_CREATE)),
    d_domainsnameidxdbi(d_env->openDB("domains_nameidx", MDB_CREATE))

  {
    setArgPrefix("lmdb"+suffix);
  }

  bool list(const DNSName &target, int id, bool include_disabled) override;

  bool getDomainInfo(const DNSName &domain, DomainInfo &di, bool getSerial=true) override;
  bool createDomain(const DNSName &domain, const string &type, const string &masters, const string &account);

  bool createDomain(const DNSName &domain) override;
  
  bool startTransaction(const DNSName &domain, int domain_id=-1) override;
  bool commitTransaction() override;
  bool abortTransaction() override;
  bool feedRecord(const DNSResourceRecord &r, const DNSName &ordername) override;
  bool replaceRRSet(uint32_t domain_id, const DNSName& qname, const QType& qt, const vector<DNSResourceRecord>& rrset) override;

  void getAllDomains(vector<DomainInfo> *domains, bool include_disabled=false) override;
  void lookup(const QType &type, const DNSName &qdomain, DNSPacket *p, int zoneId) override;
  bool get(DNSResourceRecord &rr) override;
  void getUnfreshSlaveInfos(vector<DomainInfo>* domains) override;

  
  bool setMaster(const DNSName &domain, const string &ip) override;
  bool setKind(const DNSName &domain, const DomainInfo::DomainKind kind) override;
  
private:
  int genChangeDomain(const DNSName& domain, std::function<void(DomainInfo&)> func);
  bool get_list(DNSResourceRecord &rr);
  bool get_lookup(DNSResourceRecord &rr);
  bool d_inlist{false};
  QType d_lookuptype;
  uint32_t d_lookupdomainid;
  shared_ptr<MDBEnv> d_env;
  shared_ptr<MDBROTransaction> d_rotxn;
  shared_ptr<MDBRWTransaction> d_rwtxn;
  uint32_t d_recordid;
  shared_ptr<MDBROCursor> d_cursor;
  MDBDbi d_recordsdbi, d_recordsnameidxdbi, d_recordsdomainididxdbi;
  MDBDbi d_domainsdbi, d_domainsnameidxdbi;
};

static unsigned int getMaxID(MDBRWTransaction& txn, MDBDbi& dbi)
{
  auto cursor = txn.getCursor(dbi);
  MDBOutVal maxidval, maxcontent;
  unsigned int maxid{0};
  if(!cursor.get(maxidval, maxcontent, MDB_LAST)) {
    maxid = maxidval.get<unsigned int>();
  }
  return maxid;
}


template<typename T>
std::string serToString(const T& t)
{
  ostringstream oss;
  boost::archive::binary_oarchive oa(oss,boost::archive::no_header );
  oa << t;
  return oss.str();
}

template<typename T>
void serFromString(const std::string& str, T& ret)
{
  ret = T();
  std::istringstream istr{str};
  boost::archive::binary_iarchive oi(istr,boost::archive::no_header );
  oi >> ret;
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
void serialize(Archive & ar, DNSResourceRecord& g, const unsigned int version)
{
  ar & g.qname;
  ar & g.content;
  ar & g.ttl;
  ar & g.domain_id;
  ar & g.qtype;
  ar & g.auth;
}


} // namespace serialization
} // namespace boost

BOOST_SERIALIZATION_SPLIT_FREE(DNSName);
BOOST_SERIALIZATION_SPLIT_FREE(QType);
//BOOST_SERIALIZATION_SPLIT_FREE(ComboAddress);  
BOOST_IS_BITWISE_SERIALIZABLE(ComboAddress)
bool LMDBBackend::startTransaction(const DNSName &domain, int domain_id)
{
  cout<<"Start transaction";
  d_rwtxn = std::make_shared<MDBRWTransaction>(d_env->getRWTransaction());
  // should clear all records now
  // from records table & indexes (two, name, domain idx)
  d_recordid = getMaxID(*d_rwtxn, d_recordsdbi);
  return true;
}

bool LMDBBackend::commitTransaction()
{
  cout<<"Commit transaction"<<endl;
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
  ++d_recordid;
  if(!(d_recordid % 16384))
    cout<<"Got feedrecord, "<<d_recordid<<endl;

  d_rwtxn->put(d_recordsdbi, d_recordid, serToString(r), MDB_APPEND);
  
  // insert name index
  d_rwtxn->put(d_recordsnameidxdbi, r.qname.toDNSStringLC(), d_recordid);
  
  // insert domain_id index
  d_rwtxn->put(d_recordsdomainididxdbi, r.domain_id, d_recordid, MDB_APPENDDUP);
  

  return true;
}

bool LMDBBackend::replaceRRSet(uint32_t domain_id, const DNSName& qname, const QType& qt, const vector<DNSResourceRecord>& rrset)
{
  // zonk qname/qtype within domain_id (go through qname, check domain_id && qtype)
  shared_ptr<MDBRWTransaction> txn;
  if(d_rwtxn) {
    txn = d_rwtxn;
    cout<<"Reusing open transaction"<<endl;
  }
  else {
    cout<<"Making a new RW txn for feed record"<<endl;
    txn = std::make_shared<MDBRWTransaction>(d_env->getRWTransaction());
  }
  
  auto cursor = txn->getCursor(d_recordsnameidxdbi);
  MDBOutVal key, data;
  const MDBInVal in(qname.toDNSStringLC());
  key.d_mdbval = in.d_mdbval;
  bool first = true;
  while(!cursor.get(key, data, first ? MDB_SET : MDB_NEXT_DUP)) {
    first=false;
    cout<<"Got "<<data.get<uint32_t>() <<" as possible id to delete"<<endl;
    MDBOutVal record;
    if(!txn->get(d_recordsdbi, data, record)) {
      cout<<"  found a record"<<endl;
      DNSResourceRecord rr;
      serFromString(record.get<string>(), rr);
      if(rr.qtype == qt && (uint32_t)rr.domain_id == domain_id)  {
        cout<<"  it matches type and domain id, deleting"<<endl;
        cursor.del();
        txn->del(d_recordsnameidxdbi, in, data);
        txn->del(d_recordsdomainididxdbi, domain_id, data);
      }
      else {
        cout << "  does not match type or domain_id, leaving it"<<endl;
      }
    }
  }
    
  // insert new truth
  uint32_t id=getMaxID(*txn, d_recordsdbi);
  for(const auto& rr : rrset) {
    ++id;
    txn->put(d_recordsdbi, id, serToString(rr));
  
    // insert name index
    txn->put(d_recordsnameidxdbi, rr.qname.toDNSStringLC(), id);
    
    // insert domain_id index
    txn->put(d_recordsdomainididxdbi, rr.domain_id, id);
  }

  if(!d_rwtxn)
    txn->commit();
  return true;
}

bool LMDBBackend::list(const DNSName &target, int id, bool include_disabled)
{
  cout<<"In list"<<endl;
  d_inlist=true;
  d_rotxn = std::make_shared<MDBROTransaction>(d_env->getROTransaction());
  MDBOutVal domainid;
  if(d_rotxn->get(d_domainsnameidxdbi, target.toDNSStringLC(), domainid)) {
    cout << "Could not find domain "<<target<<" for list"<<endl;
    return false;
  }
  
  d_cursor = std::make_shared<MDBROCursor>(d_rotxn->getCursor(d_recordsdomainididxdbi));
  MDBOutVal recordid;
  if(d_cursor->find(domainid, domainid, recordid)) {
    cout<<"Could not find record for domainid "<<domainid.get<uint32_t>()<<endl;
    return false;
  }
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
  if(!d_cursor) {
    cout<<"Cursor wasn't set so we are done"<<endl;
    return false;
  }
  MDBOutVal key, id;
  if(d_cursor->get(key, id, MDB_GET_CURRENT)) {
    cout<<"Could not get current!"<<endl;
    d_cursor.reset();
    d_rotxn.reset();

    return false;
  }
  cout<<"Got a record id "<<id.get<uint32_t>()<<endl;

  MDBOutVal record;
  if(d_rotxn->get(d_recordsdbi, id, record)) {
    cout<<"Could not find record with id "<<id.get<uint32_t>()<<"??"<<endl;
    d_cursor.reset();
    d_rotxn.reset();

    return false;
  }
  serFromString(record.get<string>(), rr);

  if(int rc=d_cursor->get(key, id, MDB_NEXT_DUP)) {
    cout<<"Got rc "<<mdb_strerror(rc)<<" on going to next dup"<<endl;
    d_cursor.reset();
    d_rotxn.reset();
  }
  else
    cout<<"Got id "<< id.get<uint32_t>()<<" after MDB_NEXT_DUP"<<endl;
  return true;
}


void LMDBBackend::lookup(const QType &type, const DNSName &qdomain, DNSPacket *p, int zoneId)
{
  cout << "Got lookup for "<<qdomain<<" in zone "<< zoneId<<endl;
  d_rotxn = std::make_shared<MDBROTransaction>(d_env->getROTransaction());
  
  d_cursor = std::make_shared<MDBROCursor>(d_rotxn->getCursor(d_recordsnameidxdbi));
  MDBOutVal key, data;
  if(d_cursor->find(qdomain.toDNSStringLC(), key, data) == MDB_NOTFOUND) {
    cout<<"Found nothing!"<<endl;
    d_cursor.reset();
    d_rotxn.reset();
    return;
  }
  
  d_inlist=false;
  d_lookuptype=type;
  d_lookupdomainid = zoneId;
}


bool LMDBBackend::get_lookup(DNSResourceRecord& rr)
{
  if(!d_cursor) {
    cout<<"Cursor not set, so get_lookup is done"<<endl;
    return false;
  }

  for(;;) {
    MDBOutVal key, id;
    if(d_cursor->get(key, id, MDB_GET_CURRENT)) {
      cout<<"Could not get current!"<<endl;
      return false;
    }
    cout<<"Got a record id "<<id.get<uint32_t>()<<endl;
    MDBOutVal record;
    if(d_rotxn->get(d_recordsdbi, id, record)) {
      cout << "Could not find record id "<<id.get<uint32_t>()<<endl;
      d_cursor.reset();
      d_rotxn.reset();
      return false;
    }
    serFromString(record.get<string>(), rr);
    rr.auth=1;
    cout<<"Found: "<<rr.qname<<", "<<rr.qtype.getName()<<endl;
    if(int rc=d_cursor->get(key, id, MDB_NEXT_DUP)) {
      cout<<"Got rc "<<mdb_strerror(rc)<<" on going to next dup"<<endl;
      d_cursor.reset();
      d_rotxn.reset();
    }
    else
      cout<<"Got id "<< id.get<uint32_t>()<<" after MDB_NEXT_DUP"<<endl;

    if(d_lookuptype != QType::ANY && rr.qtype != d_lookuptype) { // this is not what we were looking for
      cout << "Request was for "<<d_lookuptype.getName() <<", got "<<rr.qtype.getName()<<endl;
      if(d_cursor)
        continue;
      else
        return false;
    }
    break;
  }
  return true;
}


bool LMDBBackend::getDomainInfo(const DNSName &domain, DomainInfo &di, bool getSerial)
{
  auto txn = d_env->getROTransaction();
  MDBOutVal id;

  if(txn.get(d_domainsnameidxdbi, domain.toDNSStringLC(), id)) {
    cout<<"Not found in name index"<<endl;
    return false;
  }
  MDBOutVal data;
  if(txn.get(d_domainsdbi, id , data))
    return false;
  // domaininfo has: zone, last_check, account, masters, id, notified serial, serial,
  // kind

  serFromString(data.get<string>(), di);
  di.id = id.get<uint32_t>();
  di.backend = this;
  return true;
}

int LMDBBackend::genChangeDomain(const DNSName& domain, std::function<void(DomainInfo&)> func)
{
    shared_ptr<MDBRWTransaction> txn;
  if(d_rwtxn) {
    txn = d_rwtxn;
    cout<<"Reusing open transaction"<<endl;
  }
  else {
    cout<<"Making a new RW txn for feed record"<<endl;
    txn = std::make_shared<MDBRWTransaction>(d_env->getRWTransaction());
  }
  MDBOutVal id;
  if(txn->get(d_domainsnameidxdbi, domain.toDNSStringLC(), id)) {
    cout<<"Not found in name index"<<endl;
    return false;
  }
  MDBOutVal data;
  if(txn->get(d_domainsdbi, id , data))
    return false;
  // domaininfo has: zone, last_check, account, masters, id, notified serial, serial,
  // kind

  DomainInfo di;
  serFromString(data.get<string>(), di);

  func(di);
  
  txn->put(d_domainsdbi, id, serToString(di));

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
  
  auto txn = d_env->getRWTransaction();
  di.id = getMaxID(txn, d_domainsdbi);
  cout<<"Assigned id "<<di.id<<endl;
  txn.put(d_domainsnameidxdbi, di.zone.toDNSStringLC(), di.id);
  cout<<"Stored in index"<<endl;
  txn.put(d_domainsdbi, di.id, serToString(di));
  cout<<"Stored in domains"<<endl;
  txn.commit();
  cout<<"Commit"<< endl;
  return true;
}

void LMDBBackend::getAllDomains(vector<DomainInfo> *domains, bool include_disabled)
{
  auto txn = d_env->getROTransaction();
  auto cursor = txn.getCursor(d_domainsdbi);
  MDBOutVal key, value;
  bool start=true;
  domains->clear();
  DomainInfo di;
  cout<<"Getting all domains.."<<endl;
  while(!cursor.get(key, value, start ? MDB_FIRST : MDB_NEXT)) {
    serFromString(value.get<string>(), di);
    di.id = key.get<uint32_t>();
    domains->push_back(di);
    start=false;
  }
}

void LMDBBackend::getUnfreshSlaveInfos(vector<DomainInfo>* domains)
{
  getAllDomains(domains);
}

/* SECOND PART */

class LMDBFactory : public BackendFactory
{
public:
  LMDBFactory() : BackendFactory("lmdb") {}
  void declareArguments(const string &suffix="")
  {
    declare(suffix,"filename","Filename for lmdb","./pdns.lmdb");
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
