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
#include "dnsseckeeper.hh"
#include "dnssecinfra.hh"
#include "ueberbackend.hh"
#include "statbag.hh"
#include <iostream>

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

bool DNSSECKeeper::isSecuredZone(const DNSName& zone) 
{
  if(isPresigned(zone))
    return true;

  keyset_t keys = getKeys(zone); // does the cache

  for(keyset_t::value_type& val :  keys) {
    if(val.second.active) {
      return true;
    }
  }
  return false;
}

bool DNSSECKeeper::isPresigned(const DNSName& name)
{
  string meta;
  getFromMeta(name, "PRESIGNED", meta);
  return meta=="1";
}

bool DNSSECKeeper::addKey(const DNSName& name, bool setSEPBit, int algorithm, int bits, bool active)
{
  if(!bits) {
    if(algorithm <= 10)
      throw runtime_error("Creating an algorithm " +std::to_string(algorithm)+" ("+algorithm2name(algorithm)+") key requires the size (in bits) to be passed");
    else {
      if(algorithm == 12 || algorithm == 13 || algorithm == 250) // GOST, ECDSAP256SHA256, ED25519SHA512
        bits = 256;
      else if(algorithm == 14) // ECDSAP384SHA384
        bits = 384;
      else {
        throw runtime_error("Can't guess key size for algorithm "+std::to_string(algorithm));
      }
    }
  }
  DNSSECPrivateKey dspk;
  shared_ptr<DNSCryptoKeyEngine> dpk(DNSCryptoKeyEngine::make(algorithm));
  dpk->create(bits);
  dspk.setKey(dpk);
  dspk.d_algorithm = algorithm;
  dspk.d_flags = setSEPBit ? 257 : 256;
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

void DNSSECKeeper::clearCaches(const DNSName& name)
{
  {
    WriteLock l(&s_keycachelock);
    s_keycache.erase(name); 
  }
  WriteLock l(&s_metacachelock);
  pair<metacache_t::iterator, metacache_t::iterator> range = s_metacache.equal_range(tie(name));
  while(range.first != range.second)
    s_metacache.erase(range.first++);
}


bool DNSSECKeeper::addKey(const DNSName& name, const DNSSECPrivateKey& dpk, bool active)
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
  return make_pair(!a.second.keyType, a.second.id) <
         make_pair(!b.second.keyType, b.second.id);
}

DNSSECPrivateKey DNSSECKeeper::getKeyById(const DNSName& zname, unsigned int id)
{  
  vector<DNSBackend::KeyData> keys;
  d_keymetadb->getDomainKeys(zname, 0, keys);
  for(const DNSBackend::KeyData& kd :  keys) {
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
  throw runtime_error("Can't find a key with id "+std::to_string(id)+" for zone '"+zname.toString()+"'");
}


bool DNSSECKeeper::removeKey(const DNSName& zname, unsigned int id)
{
  clearCaches(zname);
  return d_keymetadb->removeDomainKey(zname, id);
}

bool DNSSECKeeper::deactivateKey(const DNSName& zname, unsigned int id)
{
  clearCaches(zname);
  return d_keymetadb->deactivateDomainKey(zname, id);
}

bool DNSSECKeeper::activateKey(const DNSName& zname, unsigned int id)
{
  clearCaches(zname);
  return d_keymetadb->activateDomainKey(zname, id);
}


void DNSSECKeeper::getFromMeta(const DNSName& zname, const std::string& key, std::string& value)
{
  static int ttl = ::arg().asNum("domain-metadata-cache-ttl");
  value.clear();
  unsigned int now = time(0);

  if(!((++s_ops) % 100000)) {
    cleanup();
  }

  if (ttl > 0) {
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

  if (ttl > 0) {
    METACacheEntry nce;
    nce.d_domain=zname;
    nce.d_ttd = now + ttl;
    nce.d_key= key;
    nce.d_value = value;
    {
      WriteLock l(&s_metacachelock);
      replacing_insert(s_metacache, nce);
    }
  }
}

void DNSSECKeeper::getSoaEdit(const DNSName& zname, std::string& value)
{
  static const string soaEdit(::arg()["default-soa-edit"]);
  static const string soaEditSigned(::arg()["default-soa-edit-signed"]);

  getFromMeta(zname, "SOA-EDIT", value);

  if ((!soaEdit.empty() || !soaEditSigned.empty()) && value.empty() && !isPresigned(zname)) {
    if (!soaEditSigned.empty() && isSecuredZone(zname))
      value=soaEditSigned;
    if (value.empty())
      value=soaEdit;
  }

  return;
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

bool DNSSECKeeper::getNSEC3PARAM(const DNSName& zname, NSEC3PARAMRecordContent* ns3p, bool* narrow)
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
    if (ns3p->d_algorithm != 1) {
      L<<Logger::Error<<"Invalid hash algorithm for NSEC3: '"<<std::to_string(ns3p->d_algorithm)<<"', setting to 1 for zone '"<<zname<<"'."<<endl;
      ns3p->d_algorithm = 1;
    }
  }
  if(narrow) {
    getFromMeta(zname, "NSEC3NARROW", value);
    *narrow = (value=="1");
  }
  return true;
}

bool DNSSECKeeper::setNSEC3PARAM(const DNSName& zname, const NSEC3PARAMRecordContent& ns3p, const bool& narrow)
{
  static int maxNSEC3Iterations=::arg().asNum("max-nsec3-iterations");
  if (ns3p.d_iterations > maxNSEC3Iterations)
    throw runtime_error("Can't set NSEC3PARAM for zone '"+zname.toString()+"': number of NSEC3 iterations is above 'max-nsec3-iterations'");

  if (ns3p.d_algorithm != 1)
    throw runtime_error("Invalid hash algorithm for NSEC3: '"+std::to_string(ns3p.d_algorithm)+"' for zone '"+zname.toString()+"'. The only valid value is '1'");

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

bool DNSSECKeeper::unsetNSEC3PARAM(const DNSName& zname)
{
  clearCaches(zname);
  return (d_keymetadb->setDomainMetadata(zname, "NSEC3PARAM", vector<string>()) && d_keymetadb->setDomainMetadata(zname, "NSEC3NARROW", vector<string>()));
}


bool DNSSECKeeper::setPresigned(const DNSName& zname)
{
  clearCaches(zname);
  vector<string> meta;
  meta.push_back("1");
  return d_keymetadb->setDomainMetadata(zname, "PRESIGNED", meta);
}

bool DNSSECKeeper::unsetPresigned(const DNSName& zname)
{
  clearCaches(zname);
  return d_keymetadb->setDomainMetadata(zname, "PRESIGNED", vector<string>());
}

/**
 * Add domainmetadata to allow publishing CDS records for zone zname
 *
 * @param zname        DNSName of the zone
 * @param digestAlgos  string with comma-separated numbers that describe the
 *                     used digest algorithms. This is copied to the database
 *                     verbatim
 * @return             true if the data was inserted, false otherwise
 */
bool DNSSECKeeper::setPublishCDS(const DNSName& zname, const string& digestAlgos)
{
  clearCaches(zname);
  vector<string> meta;
  meta.push_back(digestAlgos);
  return d_keymetadb->setDomainMetadata(zname, "PUBLISH-CDS", meta);
}

/**
 * Remove domainmetadata to stop publishing CDS records for zone zname
 *
 * @param zname        DNSName of the zone
 * @return             true if the operation was successful, false otherwise
 */
bool DNSSECKeeper::unsetPublishCDS(const DNSName& zname)
{
  clearCaches(zname);
  return d_keymetadb->setDomainMetadata(zname, "PUBLISH-CDS", vector<string>());
}

/**
 * Add domainmetadata to allow publishing CDNSKEY records.for zone zname
 *
 * @param zname        DNSName of the zone
 * @return             true if the data was inserted, false otherwise
 */
bool DNSSECKeeper::setPublishCDNSKEY(const DNSName& zname)
{
  clearCaches(zname);
  vector<string> meta;
  meta.push_back("1");
  return d_keymetadb->setDomainMetadata(zname, "PUBLISH-CDNSKEY", meta);
}

/**
 * Remove domainmetadata to stop publishing CDNSKEY records for zone zname
 *
 * @param zname        DNSName of the zone
 * @return             true if the operation was successful, false otherwise
 */
bool DNSSECKeeper::unsetPublishCDNSKEY(const DNSName& zname)
{
  clearCaches(zname);
  return d_keymetadb->setDomainMetadata(zname, "PUBLISH-CDNSKEY", vector<string>());
}

/**
 * Returns all keys that are used to sign the DNSKEY RRSet in a zone
 *
 * @param zname        DNSName of the zone
 * @return             a keyset_t with all keys that are used to sign the DNSKEY
 *                     RRSet (these are the entrypoint(s) to the zone)
 */
DNSSECKeeper::keyset_t DNSSECKeeper::getEntryPoints(const DNSName& zname)
{
  DNSSECKeeper::keyset_t ret;
  DNSSECKeeper::keyset_t keys = getKeys(zname);

  for(auto const &keymeta : keys)
    if(keymeta.second.active && (keymeta.second.keyType == KSK || keymeta.second.keyType == CSK))
      ret.push_back(keymeta);
  return ret;
}

DNSSECKeeper::keyset_t DNSSECKeeper::getKeys(const DNSName& zone, bool useCache)
{
  static int ttl = ::arg().asNum("dnssec-key-cache-ttl");
  unsigned int now = time(0);

  if(!((++s_ops) % 100000)) {
    cleanup();
  }

  if (useCache && ttl > 0) {
    ReadLock l(&s_keycachelock);
    keycache_t::const_iterator iter = s_keycache.find(zone);

    if(iter != s_keycache.end() && iter->d_ttd > now) {
      keyset_t ret;
      for(const keyset_t::value_type& value :  iter->d_keys)
        ret.push_back(value);
      return ret;
    }
  }

  keyset_t retkeyset;
  vector<DNSBackend::KeyData> dbkeyset;

  d_keymetadb->getDomainKeys(zone, 0, dbkeyset);

  // Determine the algorithms that have a KSK/ZSK split
  set<uint8_t> algoSEP, algoNoSEP;
  vector<uint8_t> algoHasSeparateKSK;
  for(const DNSBackend::KeyData &keydata : dbkeyset) {
    DNSSECPrivateKey dpk;
    DNSKEYRecordContent dkrc;

    dpk.setKey(shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::makeFromISCString(dkrc, keydata.content)));

    if(keydata.active) {
      if(keydata.flags == 257)
        algoSEP.insert(dkrc.d_algorithm);
      else
        algoNoSEP.insert(dkrc.d_algorithm);
    }
  }
  set_intersection(algoSEP.begin(), algoSEP.end(), algoNoSEP.begin(), algoNoSEP.end(), std::back_inserter(algoHasSeparateKSK));

  for(DNSBackend::KeyData& kd : dbkeyset)
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
    kmd.hasSEPBit = (kd.flags == 257);
    kmd.id = kd.id;

    if (find(algoHasSeparateKSK.begin(), algoHasSeparateKSK.end(), dpk.d_algorithm) == algoHasSeparateKSK.end())
      kmd.keyType = CSK;
    else if(kmd.hasSEPBit)
      kmd.keyType = KSK;
    else
      kmd.keyType = ZSK;

    retkeyset.push_back(make_pair(dpk, kmd));
  }
  sort(retkeyset.begin(), retkeyset.end(), keyCompareByKindAndID);

  if (ttl > 0) {
    KeyCacheEntry kce;
    kce.d_domain=zone;
    kce.d_keys = retkeyset;
    kce.d_ttd = now + ttl;
    {
      WriteLock l(&s_keycachelock);
      replacing_insert(s_keycache, kce);
    }
  }

  return retkeyset;
}

bool DNSSECKeeper::checkKeys(const DNSName& zone)
{
  vector<DNSBackend::KeyData> dbkeyset;
  d_keymetadb->getDomainKeys(zone, 0, dbkeyset);

  for(const DNSBackend::KeyData &keydata : dbkeyset) {
    DNSKEYRecordContent dkrc;
    shared_ptr<DNSCryptoKeyEngine> dke(DNSCryptoKeyEngine::makeFromISCString(dkrc, keydata.content));
    if (!dke->checkKey()) {
      return false;
    }
  }

  return true;
}

bool DNSSECKeeper::getPreRRSIGs(UeberBackend& db, const DNSName& signer, const DNSName& qname,
        const DNSName& wildcardname, const QType& qtype,
        DNSResourceRecord::Place signPlace, vector<DNSResourceRecord>& rrsigs, uint32_t signTTL)
{
  // cerr<<"Doing DB lookup for precomputed RRSIGs for '"<<(wildcardname.empty() ? qname : wildcardname)<<"'"<<endl;
        SOAData sd;
        if(!db.getSOAUncached(signer, sd)) {
                DLOG(L<<"Could not get SOA for domain"<<endl);
                return false;
        }
        db.lookup(QType(QType::RRSIG), wildcardname.countLabels() ? wildcardname : qname, NULL, sd.domain_id);
        DNSResourceRecord rr;
        while(db.get(rr)) { 
                // cerr<<"Considering for '"<<qtype.getName()<<"' RRSIG '"<<rr.content<<"'\n";
                vector<string> parts;
                stringtok(parts, rr.content);
                if(parts[0] == qtype.getName() && DNSName(parts[7])==signer) {
                        // cerr<<"Got it"<<endl;
                        if (wildcardname.countLabels())
                                rr.qname = qname;
                        rr.d_place = signPlace;
                        rr.ttl = signTTL;
                        rrsigs.push_back(rr);
                }
                // else cerr<<"Skipping!"<<endl;
        }
        return true;
}

bool DNSSECKeeper::TSIGGrantsAccess(const DNSName& zone, const DNSName& keyname)
{
  vector<string> allowed;
  
  d_keymetadb->getDomainMetadata(zone, "TSIG-ALLOW-AXFR", allowed);
  
  for(const string& dbkey :  allowed) {
    if(DNSName(dbkey)==keyname)
      return true;
  }
  return false;
}

bool DNSSECKeeper::getTSIGForAccess(const DNSName& zone, const string& master, DNSName* keyname)
{
  vector<string> keynames;
  d_keymetadb->getDomainMetadata(zone, "AXFR-MASTER-TSIG", keynames);
  keyname->trimToLabels(0);
  
  // XXX FIXME this should check for a specific master!
  for(const string& dbkey :  keynames) {
    *keyname=DNSName(dbkey);
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
