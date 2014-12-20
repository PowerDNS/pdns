/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2001 - 2012  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "dnsseckeeper.hh"
#include "dnssecinfra.hh"
#include "ueberbackend.hh"
#include "statbag.hh"
#include <iostream>
#include <boost/foreach.hpp>
#include <sys/stat.h>
#include <sys/types.h>
#include <fstream>
#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>
#include <boost/assign/std/vector.hpp> // for 'operator+=()'
#include <boost/assign/list_inserter.hpp>
#include "base64.hh"
#include "cachecleaner.hh"
#include "arguments.hh"


using namespace boost::assign;
#include "namespaces.hh"


DNSSECKeeper::keycache_t DNSSECKeeper::s_keycache;
DNSSECKeeper::metacache_t DNSSECKeeper::s_metacache;
pthread_rwlock_t DNSSECKeeper::s_metacachelock = PTHREAD_RWLOCK_INITIALIZER;
pthread_rwlock_t DNSSECKeeper::s_keycachelock = PTHREAD_RWLOCK_INITIALIZER;
AtomicCounter DNSSECKeeper::s_ops;
time_t DNSSECKeeper::s_last_prune;

bool DNSSECKeeper::isSecuredZone(const std::string& zone) 
{
  if(isPresigned(zone))
    return true;

  keyset_t keys = getKeys(zone, true); // does the cache
  
  BOOST_FOREACH(keyset_t::value_type& val, keys) {
    if(val.second.active) {
      return true;
    }
  }
  return false;
}

bool DNSSECKeeper::isPresigned(const std::string& name)
{
  string meta;
  getFromMeta(name, "PRESIGNED", meta);
  return meta=="1";
}

bool DNSSECKeeper::addKey(const std::string& name, bool keyOrZone, int algorithm, int bits, bool active)
{
  if(!bits) {
    if(algorithm <= 10)
      bits = keyOrZone ? 2048 : 1024;
    else {
      if(algorithm == 12 || algorithm == 13 || algorithm == 250) // ECDSA, GOST, ED25519
        bits = 256;
      else if(algorithm == 14)
        bits = 384;
      else {
        throw runtime_error("Can't guess key size for algorithm "+lexical_cast<string>(algorithm));
      }
    }
  }
  DNSSECPrivateKey dspk;
  shared_ptr<DNSCryptoKeyEngine> dpk(DNSCryptoKeyEngine::make(algorithm)); // defaults to RSA for now, could be smart w/algorithm! XXX FIXME
  dpk->create(bits);
  dspk.setKey(dpk);
  dspk.d_algorithm = algorithm;
  dspk.d_flags = keyOrZone ? 257 : 256;
  return addKey(name, dspk, active);
}

void DNSSECKeeper::clearAllCaches() {
  {
    WriteLock l(&s_keycachelock);
    s_keycache.clear();
  }
  WriteLock l(&s_metacachelock);
  s_metacache.clear();
}

void DNSSECKeeper::clearCaches(const std::string& name)
{
  {
    WriteLock l(&s_keycachelock);
    s_keycache.erase(name); 
  }
  WriteLock l(&s_metacachelock);
  pair<metacache_t::iterator, metacache_t::iterator> range = s_metacache.equal_range(name);
  while(range.first != range.second)
    s_metacache.erase(range.first++);
}


bool DNSSECKeeper::addKey(const std::string& name, const DNSSECPrivateKey& dpk, bool active)
{
  clearCaches(name);
  DNSBackend::KeyData kd;
  kd.flags = dpk.d_flags; // the dpk doesn't get stored, only they key part
  kd.active = active;
  kd.content = dpk.getKey()->convertToISC();
 // now store it
  return d_keymetadb->addDomainKey(name, kd) >= 0; // >= 0 == s
}


static bool keyCompareByKindAndID(const DNSSECKeeper::keyset_t::value_type& a, const DNSSECKeeper::keyset_t::value_type& b)
{
  return make_pair(!a.second.keyOrZone, a.second.id) <
         make_pair(!b.second.keyOrZone, b.second.id);
}

DNSSECPrivateKey DNSSECKeeper::getKeyById(const std::string& zname, unsigned int id)
{  
  vector<DNSBackend::KeyData> keys;
  d_keymetadb->getDomainKeys(zname, 0, keys);
  BOOST_FOREACH(const DNSBackend::KeyData& kd, keys) {
    if(kd.id != id) 
      continue;
    
    DNSSECPrivateKey dpk;
    DNSKEYRecordContent dkrc;
    dpk.setKey(shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::makeFromISCString(dkrc, kd.content)));
    dpk.d_flags = kd.flags;
    dpk.d_algorithm = dkrc.d_algorithm;
    
    if(dpk.d_algorithm == 5 && getNSEC3PARAM(zname)) {
      dpk.d_algorithm += 2;
    }
    
    return dpk;    
  }
  throw runtime_error("Can't find a key with id "+lexical_cast<string>(id)+" for zone '"+zname+"'");
}


bool DNSSECKeeper::removeKey(const std::string& zname, unsigned int id)
{
  clearCaches(zname);
  return d_keymetadb->removeDomainKey(zname, id);
}

bool DNSSECKeeper::deactivateKey(const std::string& zname, unsigned int id)
{
  clearCaches(zname);
  return d_keymetadb->deactivateDomainKey(zname, id);
}

bool DNSSECKeeper::activateKey(const std::string& zname, unsigned int id)
{
  clearCaches(zname);
  return d_keymetadb->activateDomainKey(zname, id);
}


void DNSSECKeeper::getFromMeta(const std::string& zname, const std::string& key, std::string& value)
{
  value.clear();
  unsigned int now = time(0);

  if(!((++s_ops) % 100000)) {
    cleanup();
  }

  {
    ReadLock l(&s_metacachelock); 
    
    metacache_t::const_iterator iter = s_metacache.find(tie(zname, key));
    if(iter != s_metacache.end() && iter->d_ttd > now) {
      value = iter->d_value;
      return;
    }
  }
  vector<string> meta;
  d_keymetadb->getDomainMetadata(zname, key, meta);
  if(!meta.empty())
    value=*meta.begin();
    
  METACacheEntry nce;
  nce.d_domain=zname;
  nce.d_ttd = now+60;
  nce.d_key= key;
  nce.d_value = value;
  { 
    WriteLock l(&s_metacachelock);
    replacing_insert(s_metacache, nce);
  }
}

uint64_t DNSSECKeeper::dbdnssecCacheSizes(const std::string& str)
{
  if(str=="meta-cache-size") {
    ReadLock l(&s_metacachelock); 
    return s_metacache.size();
  }
  else if(str=="key-cache-size") {
    ReadLock l(&s_keycachelock);
    return s_keycache.size();
  }
  return (uint64_t)-1;
}

bool DNSSECKeeper::getNSEC3PARAM(const std::string& zname, NSEC3PARAMRecordContent* ns3p, bool* narrow)
{
  string value;
  getFromMeta(zname, "NSEC3PARAM", value);
  if(value.empty()) { // "no NSEC3"
    return false;
  }

  static int maxNSEC3Iterations=::arg().asNum("max-nsec3-iterations");
  if(ns3p) {
    NSEC3PARAMRecordContent* tmp=dynamic_cast<NSEC3PARAMRecordContent*>(DNSRecordContent::mastermake(QType::NSEC3PARAM, 1, value));
    *ns3p = *tmp;
    delete tmp;
    if (ns3p->d_iterations > maxNSEC3Iterations) {
      ns3p->d_iterations = maxNSEC3Iterations;
      L<<Logger::Error<<"Number of NSEC3 iterations for zone '"<<zname<<"' is above 'max-nsec3-iterations'. Value adjusted to: "<<maxNSEC3Iterations<<endl;
    }
  }
  if(narrow) {
    getFromMeta(zname, "NSEC3NARROW", value);
    *narrow = (value=="1");
  }
  return true;
}

bool DNSSECKeeper::setNSEC3PARAM(const std::string& zname, const NSEC3PARAMRecordContent& ns3p, const bool& narrow)
{
  static int maxNSEC3Iterations=::arg().asNum("max-nsec3-iterations");
  if (ns3p.d_iterations > maxNSEC3Iterations)
    throw runtime_error("Can't set NSEC3PARAM for zone '"+zname+"': number of NSEC3 iterations is above 'max-nsec3-iterations'");

  clearCaches(zname);
  string descr = ns3p.getZoneRepresentation();
  vector<string> meta;
  meta.push_back(descr);
  if (d_keymetadb->setDomainMetadata(zname, "NSEC3PARAM", meta)) {
    meta.clear();
    
    if(narrow)
      meta.push_back("1");
    
    return d_keymetadb->setDomainMetadata(zname, "NSEC3NARROW", meta);
  }
  return false;
}

bool DNSSECKeeper::unsetNSEC3PARAM(const std::string& zname)
{
  clearCaches(zname);
  return (d_keymetadb->setDomainMetadata(zname, "NSEC3PARAM", vector<string>()) && d_keymetadb->setDomainMetadata(zname, "NSEC3NARROW", vector<string>()));
}


bool DNSSECKeeper::setPresigned(const std::string& zname)
{
  clearCaches(zname);
  vector<string> meta;
  meta.push_back("1");
  return d_keymetadb->setDomainMetadata(zname, "PRESIGNED", meta);
}

bool DNSSECKeeper::unsetPresigned(const std::string& zname)
{
  clearCaches(zname);
  return d_keymetadb->setDomainMetadata(zname, "PRESIGNED", vector<string>());
}


DNSSECKeeper::keyset_t DNSSECKeeper::getKeys(const std::string& zone, boost::tribool allOrKeyOrZone, bool useCache)
{
  unsigned int now = time(0);

  if(!((++s_ops) % 100000)) {
    cleanup();
  }

  if (useCache) {
    ReadLock l(&s_keycachelock);
    keycache_t::const_iterator iter = s_keycache.find(zone);
      
    if(iter != s_keycache.end() && iter->d_ttd > now) { 
      keyset_t ret;
      BOOST_FOREACH(const keyset_t::value_type& value, iter->d_keys) {
        if(boost::indeterminate(allOrKeyOrZone) || allOrKeyOrZone == value.second.keyOrZone)
          ret.push_back(value);
      }
      return ret;
    }
  }    
  keyset_t retkeyset, allkeyset;
  vector<UeberBackend::KeyData> dbkeyset;
  
  d_keymetadb->getDomainKeys(zone, 0, dbkeyset);
  
  BOOST_FOREACH(UeberBackend::KeyData& kd, dbkeyset) 
  {
    DNSSECPrivateKey dpk;

    DNSKEYRecordContent dkrc;
    
    dpk.setKey(shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::makeFromISCString(dkrc, kd.content)));
    
    dpk.d_flags = kd.flags;
    dpk.d_algorithm = dkrc.d_algorithm;
    if(dpk.d_algorithm == 5 && getNSEC3PARAM(zone))
      dpk.d_algorithm+=2;
    
    KeyMetaData kmd;

    kmd.active = kd.active;
    kmd.keyOrZone = (kd.flags == 257);
    kmd.id = kd.id;
    
    if(boost::indeterminate(allOrKeyOrZone) || allOrKeyOrZone == kmd.keyOrZone)
      retkeyset.push_back(make_pair(dpk, kmd));
    allkeyset.push_back(make_pair(dpk, kmd));
  }
  sort(retkeyset.begin(), retkeyset.end(), keyCompareByKindAndID);
  sort(allkeyset.begin(), allkeyset.end(), keyCompareByKindAndID);
  
  KeyCacheEntry kce;
  kce.d_domain=zone;
  kce.d_keys = allkeyset;
  kce.d_ttd = now + 30;
  {
    WriteLock l(&s_keycachelock);
    replacing_insert(s_keycache, kce);
  }
  
  return retkeyset;
}

bool DNSSECKeeper::secureZone(const std::string& name, int algorithm, int size)
{
  clearCaches(name); // just to be sure ;)
  return addKey(name, true, algorithm, size);
}

bool DNSSECKeeper::getPreRRSIGs(DNSBackend& db, const std::string& signer, const std::string& qname,
        const std::string& wildcardname, const QType& qtype,
        DNSPacketWriter::Place signPlace, vector<DNSResourceRecord>& rrsigs, uint32_t signTTL)
{
  vector<DNSResourceRecord> sigs;
  if(db.getDirectRRSIGs(toLower(signer), toLower(wildcardname.empty() ? qname : wildcardname), qtype, sigs)) {
    BOOST_FOREACH(DNSResourceRecord &rr, sigs) {
      if (!wildcardname.empty())
        rr.qname = toLower(qname);
      rr.d_place = (DNSResourceRecord::Place)signPlace;
      rr.ttl = signTTL;
      rrsigs.push_back(rr);
    }
    return true;
  }

  // cerr<<"Doing DB lookup for precomputed RRSIGs for '"<<(wildcardname.empty() ? qname : wildcardname)<<"'"<<endl;
        SOAData sd;
        sd.db=(DNSBackend *)-1; // force uncached answer
        if(!db.getSOA(signer, sd)) {
                DLOG(L<<"Could not get SOA for domain"<<endl);
                return false;
        }
        db.lookup(QType(QType::RRSIG), wildcardname.empty() ? qname : wildcardname, NULL, sd.domain_id);
        DNSResourceRecord rr;
        while(db.get(rr)) { 
                // cerr<<"Considering for '"<<qtype.getName()<<"' RRSIG '"<<rr.content<<"'\n";
                vector<string> parts;
                stringtok(parts, rr.content);
                if(parts[0] == qtype.getName() && pdns_iequals(parts[7], signer+".")) {
                        // cerr<<"Got it"<<endl;
                        if (!wildcardname.empty())
                                rr.qname = qname;
                        rr.d_place = (DNSResourceRecord::Place)signPlace;
                        rr.ttl = signTTL;
                        rrsigs.push_back(rr);
                }
                // else cerr<<"Skipping!"<<endl;
        }
        return true;
}

bool DNSSECKeeper::TSIGGrantsAccess(const string& zone, const string& keyname)
{
  vector<string> allowed;
  
  d_keymetadb->getDomainMetadata(zone, "TSIG-ALLOW-AXFR", allowed);
  
  BOOST_FOREACH(const string& dbkey, allowed) {
    if(pdns_iequals(dbkey, keyname))
      return true;
  }
  return false;
}

bool DNSSECKeeper::getTSIGForAccess(const string& zone, const string& master, string* keyname)
{
  vector<string> keynames;
  d_keymetadb->getDomainMetadata(zone, "AXFR-MASTER-TSIG", keynames);
  keyname->clear();
  
  // XXX FIXME this should check for a specific master!
  BOOST_FOREACH(const string& dbkey, keynames) {
    *keyname=dbkey;
    return true;
  }
  return false;
}

void DNSSECKeeper::cleanup()
{
  struct timeval now;
  Utility::gettimeofday(&now, 0);

  if(now.tv_sec - s_last_prune > (time_t)(30)) {
    {
        WriteLock l(&s_metacachelock);
        pruneCollection(s_metacache, ::arg().asNum("max-cache-entries"));
    }
    {
        WriteLock l(&s_keycachelock);
        pruneCollection(s_keycache, ::arg().asNum("max-cache-entries"));
    }
    s_last_prune=time(0);
  }
}
