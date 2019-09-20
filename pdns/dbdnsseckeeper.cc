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
#include "base32.hh"
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

bool DNSSECKeeper::doesDNSSEC()
{
  return d_keymetadb->doesDNSSEC();
}

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

bool DNSSECKeeper::addKey(const DNSName& name, bool setSEPBit, int algorithm, int64_t& id, int bits, bool active)
{
  if(!bits) {
    if(algorithm <= 10)
      throw runtime_error("Creating an algorithm " +std::to_string(algorithm)+" ("+algorithm2name(algorithm)+") key requires the size (in bits) to be passed.");
    else {
      if(algorithm == DNSSECKeeper::ECCGOST || algorithm == DNSSECKeeper::ECDSA256 || algorithm == DNSSECKeeper::ED25519)
        bits = 256;
      else if(algorithm == DNSSECKeeper::ECDSA384)
        bits = 384;
      else if(algorithm == DNSSECKeeper::ED448)
        bits = 456;
      else {
        throw runtime_error("Can not guess key size for algorithm "+std::to_string(algorithm));
      }
    }
  }
  DNSSECPrivateKey dspk;
  shared_ptr<DNSCryptoKeyEngine> dpk(DNSCryptoKeyEngine::make(algorithm));
  try{
    dpk->create(bits);
  } catch (const std::runtime_error& error){
    throw runtime_error("The algorithm does not support the given bit size.");
  }
  dspk.setKey(dpk);
  dspk.d_algorithm = algorithm;
  dspk.d_flags = setSEPBit ? 257 : 256;
  return addKey(name, dspk, id, active);
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


bool DNSSECKeeper::addKey(const DNSName& name, const DNSSECPrivateKey& dpk, int64_t& id, bool active)
{
  clearCaches(name);
  DNSBackend::KeyData kd;
  kd.flags = dpk.d_flags; // the dpk doesn't get stored, only they key part
  kd.active = active;
  kd.content = dpk.getKey()->convertToISC();
 // now store it
  return d_keymetadb->addDomainKey(name, kd, id);
}


static bool keyCompareByKindAndID(const DNSSECKeeper::keyset_t::value_type& a, const DNSSECKeeper::keyset_t::value_type& b)
{
  return make_pair(!a.second.keyType, a.second.id) <
         make_pair(!b.second.keyType, b.second.id);
}

DNSSECPrivateKey DNSSECKeeper::getKeyById(const DNSName& zname, unsigned int id)
{  
  vector<DNSBackend::KeyData> keys;
  d_keymetadb->getDomainKeys(zname, keys);
  for(const DNSBackend::KeyData& kd :  keys) {
    if(kd.id != id) 
      continue;
    
    DNSSECPrivateKey dpk;
    DNSKEYRecordContent dkrc;
    dpk.setKey(shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::makeFromISCString(dkrc, kd.content)));
    dpk.d_flags = kd.flags;
    dpk.d_algorithm = dkrc.d_algorithm;
    
    if(dpk.d_algorithm == DNSSECKeeper::RSASHA1 && getNSEC3PARAM(zname)) {
      dpk.d_algorithm = DNSSECKeeper::RSASHA1NSEC3SHA1;
    }
    
    return dpk;    
  }
  throw runtime_error("Can't find a key with id "+std::to_string(id)+" for zone '"+zname.toLogString()+"'");
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
      lruReplacingInsert(s_metacache, nce);
    }
  }
}

void DNSSECKeeper::getSoaEdit(const DNSName& zname, std::string& value)
{
  static const string soaEdit(::arg()["default-soa-edit"]);
  static const string soaEditSigned(::arg()["default-soa-edit-signed"]);

  if (isPresigned(zname)) {
    // SOA editing on a presigned zone never makes sense
    return;
  }

  getFromMeta(zname, "SOA-EDIT", value);

  if ((!soaEdit.empty() || !soaEditSigned.empty()) && value.empty()) {
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
    *ns3p = NSEC3PARAMRecordContent(value);
    if (ns3p->d_iterations > maxNSEC3Iterations) {
      ns3p->d_iterations = maxNSEC3Iterations;
      g_log<<Logger::Error<<"Number of NSEC3 iterations for zone '"<<zname<<"' is above 'max-nsec3-iterations'. Value adjusted to: "<<maxNSEC3Iterations<<endl;
    }
    if (ns3p->d_algorithm != 1) {
      g_log<<Logger::Error<<"Invalid hash algorithm for NSEC3: '"<<std::to_string(ns3p->d_algorithm)<<"', setting to 1 for zone '"<<zname<<"'."<<endl;
      ns3p->d_algorithm = 1;
    }
  }
  if(narrow) {
    getFromMeta(zname, "NSEC3NARROW", value);
    *narrow = (value=="1");
  }
  return true;
}

/*
 * Check is the provided NSEC3PARAM record is something we can work with
 *
 * \param ns3p NSEC3PARAMRecordContent to check
 * \param msg string to fill with an error message
 * \return true on valid, false otherwise
 */
bool DNSSECKeeper::checkNSEC3PARAM(const NSEC3PARAMRecordContent& ns3p, string& msg)
{
  static int maxNSEC3Iterations=::arg().asNum("max-nsec3-iterations");
  bool ret = true;
  if (ns3p.d_iterations > maxNSEC3Iterations) {
    msg += "Number of NSEC3 iterations is above 'max-nsec3-iterations'.";
    ret = false;
  }

  if (ns3p.d_algorithm != 1) {
    if (!ret)
      msg += ' ';
    msg += "Invalid hash algorithm for NSEC3: '"+std::to_string(ns3p.d_algorithm)+"', the only valid value is '1'.";
    ret = false;
  }

  return ret;
}

bool DNSSECKeeper::setNSEC3PARAM(const DNSName& zname, const NSEC3PARAMRecordContent& ns3p, const bool& narrow)
{
  string error_msg = "";
  if (!checkNSEC3PARAM(ns3p, error_msg))
    throw runtime_error("NSEC3PARAMs provided for zone '"+zname.toLogString()+"' are invalid: " + error_msg);

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
    if(keymeta.second.keyType == KSK || keymeta.second.keyType == CSK)
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

  d_keymetadb->getDomainKeys(zone, dbkeyset);

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
    if(dpk.d_algorithm == DNSSECKeeper::RSASHA1 && getNSEC3PARAM(zone)) {
      g_log<<Logger::Warning<<"Zone '"<<zone<<"' has NSEC3 semantics, but the "<< (kd.active ? "" : "in" ) <<"active key with id "<<kd.id<<" has 'Algorithm: 5'. This should be corrected to 'Algorithm: 7' in the database (or NSEC3 should be disabled)."<<endl;
      dpk.d_algorithm = DNSSECKeeper::RSASHA1NSEC3SHA1;
    }

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
      lruReplacingInsert(s_keycache, kce);
    }
  }

  return retkeyset;
}

bool DNSSECKeeper::checkKeys(const DNSName& zone, vector<string>* errorMessages)
{
  vector<DNSBackend::KeyData> dbkeyset;
  d_keymetadb->getDomainKeys(zone, dbkeyset);
  bool retval = true;

  for(const DNSBackend::KeyData &keydata : dbkeyset) {
    DNSKEYRecordContent dkrc;
    shared_ptr<DNSCryptoKeyEngine> dke(DNSCryptoKeyEngine::makeFromISCString(dkrc, keydata.content));
    retval = dke->checkKey(errorMessages) && retval;
  }

  return retval;
}

bool DNSSECKeeper::getPreRRSIGs(UeberBackend& db, const DNSName& signer, const DNSName& qname,
        const DNSName& wildcardname, const QType& qtype,
        DNSResourceRecord::Place signPlace, vector<DNSZoneRecord>& rrsigs, uint32_t signTTL)
{
  // cerr<<"Doing DB lookup for precomputed RRSIGs for '"<<(wildcardname.empty() ? qname : wildcardname)<<"'"<<endl;
        SOAData sd;
        if(!db.getSOAUncached(signer, sd)) {
                DLOG(g_log<<"Could not get SOA for domain"<<endl);
                return false;
        }
        db.lookup(QType(QType::RRSIG), wildcardname.countLabels() ? wildcardname : qname, sd.domain_id);
        DNSZoneRecord rr;
        while(db.get(rr)) {
          auto rrsig = getRR<RRSIGRecordContent>(rr.dr);
          if(rrsig->d_type == qtype.getCode() && rrsig->d_signer==signer) {
            if (wildcardname.countLabels())
              rr.dr.d_name = qname;
            rr.dr.d_place = signPlace;
            rr.dr.d_ttl = signTTL;
            rrsigs.push_back(rr);
          }
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

bool DNSSECKeeper::getTSIGForAccess(const DNSName& zone, const ComboAddress& master, DNSName* keyname)
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

bool DNSSECKeeper::unSecureZone(const DNSName& zone, string& error, string& info) {
  // Not calling isSecuredZone(), as it will return false for zones with zero
  // active keys.
  DNSSECKeeper::keyset_t keyset=getKeys(zone);

  if(keyset.empty())  {
    error = "No keys for zone '" + zone.toLogString() + "'.";
    return false;
  }

  for(auto& key : keyset) {
    deactivateKey(zone, key.second.id);
    removeKey(zone, key.second.id);
  }

  unsetNSEC3PARAM(zone);
  unsetPresigned(zone);
  return true;
}

/* Rectifies the zone
 *
 * \param zone The zone to rectify
 * \param error& A string where error messages are added
 * \param info& A string where informational messages are added
 * \param doTransaction Whether or not to wrap the rectify in a transaction
 */
bool DNSSECKeeper::rectifyZone(const DNSName& zone, string& error, string& info, bool doTransaction) {
  if (isPresigned(zone)) {
    error =  "Rectify presigned zone '"+zone.toLogString()+"' is not allowed/necessary.";
    return false;
  }

  UeberBackend* B = d_keymetadb;
  std::unique_ptr<UeberBackend> b;

  if (d_ourDB) {
    if (!doTransaction) {
      error = "Can not rectify a zone with a new Ueberbackend inside a transaction.";
      return false;
    }
    // We don't have a *full* Ueberbackend, just a key-only one.
    // Let's create one and use it
    b = std::unique_ptr<UeberBackend>(new UeberBackend());
    B = b.get();
  }

  SOAData sd;

  if(!B->getSOAUncached(zone, sd)) {
    error = "No SOA known for '" + zone.toLogString() + "', is such a zone in the database?";
    return false;
  }

  sd.db->list(zone, sd.domain_id);

  ostringstream infostream;
  DNSResourceRecord rr;
  set<DNSName> qnames, nsset, dsnames, insnonterm, delnonterm;
  map<DNSName,bool> nonterm;
  vector<DNSResourceRecord> rrs;

  while(sd.db->get(rr)) {
    rr.qname.makeUsLowerCase();
    if (rr.qtype.getCode())
    {
      rrs.push_back(rr);
      qnames.insert(rr.qname);
      if(rr.qtype.getCode() == QType::NS && rr.qname != zone)
        nsset.insert(rr.qname);
      if(rr.qtype.getCode() == QType::DS)
        dsnames.insert(rr.qname);
    }
    else
      delnonterm.insert(rr.qname);
  }

  NSEC3PARAMRecordContent ns3pr;
  bool securedZone = isSecuredZone(zone);
  bool haveNSEC3 = false, isOptOut = false, narrow = false;

  if(securedZone) {
    haveNSEC3 = getNSEC3PARAM(zone, &ns3pr, &narrow);
    isOptOut = (haveNSEC3 && ns3pr.d_flags);

    if(!haveNSEC3) {
      infostream<<"Adding NSEC ordering information ";
    }
    else if(!narrow) {
      if(!isOptOut) {
        infostream<<"Adding NSEC3 hashed ordering information for '"<<zone<<"'";
      }
      else {
        infostream<<"Adding NSEC3 opt-out hashed ordering information for '"<<zone<<"'";
      }
    } else {
      infostream<<"Erasing NSEC3 ordering since we are narrow, only setting 'auth' fields";
    }
  }
  else {
    infostream<<"Adding empty non-terminals for non-DNSSEC zone";
  }

  set<DNSName> nsec3set;
  if (haveNSEC3 && (!narrow || !isOptOut)) {
    for (auto &loopRR: rrs) {
      bool skip=false;
      DNSName shorter = loopRR.qname;
      if (shorter != zone && shorter.chopOff() && shorter != zone) {
        do {
          if(nsset.count(shorter)) {
            skip=true;
            break;
          }
        } while(shorter.chopOff() && shorter != zone);
      }
      shorter = loopRR.qname;
      if(!skip && (loopRR.qtype.getCode() != QType::NS || !isOptOut)) {

        do {
          if(!nsec3set.count(shorter)) {
            nsec3set.insert(shorter);
          }
        } while(shorter != zone && shorter.chopOff());
      }
    }
  }

  if (doTransaction)
    sd.db->startTransaction(zone, -1);

  bool realrr=true;
  bool doent=true;
  uint32_t maxent = ::arg().asNum("max-ent-entries");

  dononterm:;
  for (const auto& qname: qnames)
  {
    bool auth=true;
    DNSName ordername;
    auto shorter(qname);

    if(realrr) {
      do {
        if(nsset.count(shorter)) {
          auth=false;
          break;
        }
      } while(shorter.chopOff());
    } else {
      auth=nonterm.find(qname)->second;
    }

    if(haveNSEC3) // NSEC3
    {
      if(nsec3set.count(qname)) {
        if(!narrow)
          ordername=DNSName(toBase32Hex(hashQNameWithSalt(ns3pr, qname)));
        if(!realrr && !isOptOut)
          auth=true;
      }
    }
    else if (realrr && securedZone) // NSEC
      ordername=qname.makeRelative(zone);

    sd.db->updateDNSSECOrderNameAndAuth(sd.domain_id, qname, ordername, auth);

    if(realrr)
    {
      if (dsnames.count(qname))
        sd.db->updateDNSSECOrderNameAndAuth(sd.domain_id, qname, ordername, true, QType::DS);
      if (!auth || nsset.count(qname)) {
        ordername.clear();
        if(isOptOut && !dsnames.count(qname))
          sd.db->updateDNSSECOrderNameAndAuth(sd.domain_id, qname, ordername, false, QType::NS);
        sd.db->updateDNSSECOrderNameAndAuth(sd.domain_id, qname, ordername, false, QType::A);
        sd.db->updateDNSSECOrderNameAndAuth(sd.domain_id, qname, ordername, false, QType::AAAA);
      }

      if(doent)
      {
        shorter=qname;
        while(shorter!=zone && shorter.chopOff())
        {
          if(!qnames.count(shorter))
          {
            if(!(maxent))
            {
              g_log<<Logger::Warning<<"Zone '"<<zone<<"' has too many empty non terminals."<<endl;
              insnonterm.clear();
              delnonterm.clear();
              doent=false;
              break;
            }

            if (!delnonterm.count(shorter) && !nonterm.count(shorter))
              insnonterm.insert(shorter);
            else
              delnonterm.erase(shorter);

            if (!nonterm.count(shorter)) {
              nonterm.insert(pair<DNSName, bool>(shorter, auth));
              --maxent;
            } else if (auth)
              nonterm[shorter]=true;
          }
        }
      }
    }
  }

  if(realrr)
  {
    //cerr<<"Total: "<<nonterm.size()<<" Insert: "<<insnonterm.size()<<" Delete: "<<delnonterm.size()<<endl;
    if(!insnonterm.empty() || !delnonterm.empty() || !doent)
    {
      sd.db->updateEmptyNonTerminals(sd.domain_id, insnonterm, delnonterm, !doent);
    }
    if(doent)
    {
      realrr=false;
      qnames.clear();
      for(const auto& nt :  nonterm){
        qnames.insert(nt.first);
      }
      goto dononterm;
    }
  }

  if (doTransaction)
    sd.db->commitTransaction();

  info = infostream.str();
  return true;
}

void DNSSECKeeper::cleanup()
{
  struct timeval now;
  Utility::gettimeofday(&now, 0);

  if(now.tv_sec - s_last_prune > (time_t)(30)) {
    {
        WriteLock l(&s_metacachelock);
        pruneCollection(*this, s_metacache, ::arg().asNum("max-cache-entries"));
    }
    {
        WriteLock l(&s_keycachelock);
        pruneCollection(*this, s_keycache, ::arg().asNum("max-cache-entries"));
    }
    s_last_prune=time(0);
  }
}
