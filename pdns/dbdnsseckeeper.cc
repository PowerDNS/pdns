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
#include <unordered_map>
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


SharedLockGuarded<DNSSECKeeper::keycache_t> DNSSECKeeper::s_keycache;
SharedLockGuarded<DNSSECKeeper::metacache_t> DNSSECKeeper::s_metacache;
int64_t DNSSECKeeper::s_metaCacheCleanActions = 0;
AtomicCounter DNSSECKeeper::s_ops;
time_t DNSSECKeeper::s_last_prune;
size_t DNSSECKeeper::s_maxEntries = 0;

bool DNSSECKeeper::doesDNSSEC()
{
  return d_keymetadb->doesDNSSEC();
}

bool DNSSECKeeper::isSecuredZone(const ZoneName& zone, bool useCache)
{
  if(isPresigned(zone, useCache))
    return true;

  keyset_t keys = getKeys(zone); // does the cache

  for(keyset_t::value_type& val :  keys) {
    if(val.second.active) {
      return true;
    }
  }
  return false;
}

bool DNSSECKeeper::isPresigned(const ZoneName& name, bool useCache)
{
  string meta;
  if (useCache) {
    getFromMeta(name, "PRESIGNED", meta);
  }
  else {
    getFromMetaNoCache(name, "PRESIGNED", meta);
  }
  return meta=="1";
}

bool DNSSECKeeper::isSignalingZone(const ZoneName& name, bool useCache)
{
  string meta;
  if (useCache) {
    getFromMeta(name, "SIGNALING-ZONE", meta);
  }
  else {
    getFromMetaNoCache(name, "SIGNALING-ZONE", meta);
  }
  return meta=="1";
}

bool DNSSECKeeper::addKey(const ZoneName& name, bool setSEPBit, int algorithm, int64_t& keyId, int bits, bool active, bool published)
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
  shared_ptr<DNSCryptoKeyEngine> dpk(DNSCryptoKeyEngine::make(algorithm));
  try{
    dpk->create(bits);
  } catch (const std::runtime_error& error){
    throw runtime_error("The algorithm does not support the given bit size.");
  }
  DNSSECPrivateKey dspk;
  dspk.setKey(dpk, setSEPBit ? 257 : 256, algorithm);
  return addKey(name, dspk, keyId, active, published) && clearKeyCache(name);
}

void DNSSECKeeper::clearAllCaches() {
  s_keycache.write_lock()->clear();
  s_metacache.write_lock()->clear();
}

/* This function never fails, the return value is to simplify call chains
   elsewhere so we can do mutate<cache> && clear<cache> */
bool DNSSECKeeper::clearKeyCache(const ZoneName& name)
{
  s_keycache.write_lock()->erase(name);
  return true;
}

bool DNSSECKeeper::clearMetaCache(const ZoneName& name)
{
  s_metacache.write_lock()->erase(name);
  ++s_metaCacheCleanActions;
  return true;
}

void DNSSECKeeper::clearCaches(const ZoneName& name)
{
  (void)clearKeyCache(name);
  (void)clearMetaCache(name);
}

bool DNSSECKeeper::addKey(const ZoneName& name, const DNSSECPrivateKey& dpk, int64_t& keyId, bool active, bool published)
{
  DNSBackend::KeyData kd;
  kd.flags = dpk.getFlags(); // the dpk doesn't get stored, only they key part
  kd.active = active;
  kd.published = published;
  kd.content = dpk.getKey()->convertToISC();
 // now store it
  return d_keymetadb->addDomainKey(name, kd, keyId) && clearKeyCache(name);
}


static bool keyCompareByKindAndID(const DNSSECKeeper::keyset_t::value_type& a, const DNSSECKeeper::keyset_t::value_type& b)
{
  return pair(!a.second.keyType, a.second.id) <
         pair(!b.second.keyType, b.second.id);
}

DNSSECPrivateKey DNSSECKeeper::getKeyById(const ZoneName& zname, unsigned int keyId)
{
  vector<DNSBackend::KeyData> keys;
  d_keymetadb->getDomainKeys(zname, keys);
  for(const DNSBackend::KeyData& kd :  keys) {
    if(kd.id != keyId) {
      continue;
    }

    DNSKEYRecordContent dkrc;
    auto key = shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::makeFromISCString(dkrc, kd.content));
    DNSSECPrivateKey dpk;
    dpk.setKey(key, kd.flags, dkrc.d_algorithm);

    return dpk;
  }
  throw runtime_error("Can't find a key with id "+std::to_string(keyId)+" for zone '"+zname.toLogString()+"'");
}


bool DNSSECKeeper::removeKey(const ZoneName& zname, unsigned int keyId)
{
  return d_keymetadb->removeDomainKey(zname, keyId) && clearKeyCache(zname);
}

bool DNSSECKeeper::deactivateKey(const ZoneName& zname, unsigned int keyId)
{
  return d_keymetadb->deactivateDomainKey(zname, keyId) && clearKeyCache(zname);
}

bool DNSSECKeeper::activateKey(const ZoneName& zname, unsigned int keyId)
{
  return d_keymetadb->activateDomainKey(zname, keyId) && clearKeyCache(zname);
}

bool DNSSECKeeper::unpublishKey(const ZoneName& zname, unsigned int keyId)
{
  return d_keymetadb->unpublishDomainKey(zname, keyId) && clearKeyCache(zname);
}

bool DNSSECKeeper::publishKey(const ZoneName& zname, unsigned int keyId)
{
  return d_keymetadb->publishDomainKey(zname, keyId) && clearKeyCache(zname);
}

void DNSSECKeeper::getFromMetaOrDefault(const ZoneName& zname, const std::string& key, std::string& value, const std::string& defaultvalue)
{
  if (getFromMeta(zname, key, value))
    return;
  else
    value = defaultvalue;
}

bool DNSSECKeeper::getFromMeta(const ZoneName& zname, const std::string& key, std::string& value)
{
  if (d_metaUpdate) {
    if (d_keymetadb->inTransaction()) {
      throw runtime_error("DNSSECKeeper::getFromMeta() called after an update from within a transaction.");
    }
    d_metaUpdate=false;
  }

  static int ttl = ::arg().asNum("zone-metadata-cache-ttl");

  if(!((++s_ops) % 100000)) {
    cleanup();
  }

  value.clear();
  time_t now = time(nullptr);

  bool ret = false;
  bool fromCache = false;
  METAValues meta;

  if (ttl) {
    auto metacache = s_metacache.read_lock();
    auto iter = metacache->find(zname);
    if(iter != metacache->end() && iter->d_ttd > now) {
      meta = iter->d_value;
      fromCache = true;
    }
    else {
      d_metaCacheCleanAction = s_metaCacheCleanActions;
    }
  }

  if (!fromCache) {
    d_keymetadb->getAllDomainMetadata(zname, meta);
  }

  auto iter = meta.find(key);
  if (iter != meta.end()) {
    if (!iter->second.empty()) {
      value = *iter->second.begin();
    }
    ret = true;
  }

  if (ttl && !fromCache) {
    METACacheEntry nce;
    nce.d_domain=zname;
    nce.d_ttd = now + ttl;
    nce.d_value = std::move(meta);
    {
      auto metacache = s_metacache.write_lock();
      if(d_metaCacheCleanAction != s_metaCacheCleanActions) {
        return false;
      }
      lruReplacingInsert<SequencedTag>(*metacache, nce);
    }
  }

  return ret;
}

bool DNSSECKeeper::getFromMetaNoCache(const ZoneName& name, const std::string& kind, std::string& value)
{
  std::vector<std::string> meta;
  if (d_keymetadb->getDomainMetadata(name, kind, meta)) {
    if(!meta.empty()) {
      value = *meta.begin();
      return true;
    }
  }
  return false;
}

void DNSSECKeeper::getSoaEdit(const ZoneName& zname, std::string& value, bool useCache)
{
  static const string soaEdit(::arg()["default-soa-edit"]);
  static const string soaEditSigned(::arg()["default-soa-edit-signed"]);

  if (isPresigned(zname, useCache)) {
    // SOA editing on a presigned zone never makes sense
    return;
  }

  getFromMeta(zname, "SOA-EDIT", value);

  if ((!soaEdit.empty() || !soaEditSigned.empty()) && value.empty()) {
    if (!soaEditSigned.empty() && isSecuredZone(zname, useCache))
      value=soaEditSigned;
    if (value.empty())
      value=soaEdit;
  }

  return;
}

uint64_t DNSSECKeeper::dbdnssecCacheSizes(const std::string& str)
{
  if(str=="meta-cache-size") {
    return s_metacache.read_lock()->size();
  }
  else if(str=="key-cache-size") {
    return s_keycache.read_lock()->size();
  }
  return (uint64_t)-1;
}

bool DNSSECKeeper::getNSEC3PARAM(const ZoneName& zname, NSEC3PARAMRecordContent* ns3p, bool* narrow, bool useCache)
{
  string value;
  if(useCache) {
    getFromMeta(zname, "NSEC3PARAM", value);
  }
  else {
    getFromMetaNoCache(zname, "NSEC3PARAM", value);
  }
  if(value.empty()) { // "no NSEC3"
    return false;
  }

  static int maxNSEC3Iterations=::arg().asNum("max-nsec3-iterations");
  if(ns3p != nullptr) {
    *ns3p = NSEC3PARAMRecordContent(value);
    if (ns3p->d_iterations > maxNSEC3Iterations && !isPresigned(zname, useCache)) {
      ns3p->d_iterations = maxNSEC3Iterations;
      g_log<<Logger::Error<<"Number of NSEC3 iterations for zone '"<<zname<<"' is above 'max-nsec3-iterations'. Value adjusted to: "<<maxNSEC3Iterations<<endl;
    }
    if (ns3p->d_algorithm != 1) {
      g_log<<Logger::Error<<"Invalid hash algorithm for NSEC3: '"<<std::to_string(ns3p->d_algorithm)<<"', setting to 1 for zone '"<<zname<<"'."<<endl;
      ns3p->d_algorithm = 1;
    }
  }
  if(narrow != nullptr) {
    if(useCache) {
      getFromMeta(zname, "NSEC3NARROW", value);
    }
    else {
      getFromMetaNoCache(zname, "NSEC3NARROW", value);
    }
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

bool DNSSECKeeper::setNSEC3PARAM(const ZoneName& zname, const NSEC3PARAMRecordContent& ns3p, const bool& narrow)
{
  if (auto wirelength = zname.operator const DNSName&().wirelength(); wirelength > 222) {
    throw runtime_error("Cannot enable NSEC3 for zone '" + zname.toLogString() + "' as it is too long (" + std::to_string(wirelength) + " bytes, maximum is 222 bytes)");
  }
  if(ns3p.d_algorithm != 1) {
    throw runtime_error("NSEC3PARAM algorithm set to '" + std::to_string(ns3p.d_algorithm) + "', but '1' is the only valid value");
  }

  if (d_keymetadb->inTransaction()) {
    d_metaUpdate = true;
  }

  string error_msg = "";
  if (!checkNSEC3PARAM(ns3p, error_msg))
    throw runtime_error("NSEC3PARAMs provided for zone '"+zname.toLogString()+"' are invalid: " + error_msg);

  string descr = ns3p.getZoneRepresentation();
  vector<string> meta;
  meta.emplace_back(std::move(descr));
  if (d_keymetadb->setDomainMetadata(zname, "NSEC3PARAM", meta)) {
    meta.clear();

    if(narrow)
      meta.push_back("1");

    return d_keymetadb->setDomainMetadata(zname, "NSEC3NARROW", meta) && clearMetaCache(zname);
  }
  return false;
}

bool DNSSECKeeper::unsetNSEC3PARAM(const ZoneName& zname)
{
  if (d_keymetadb->inTransaction()) {
    d_metaUpdate = true;
  }

  return (d_keymetadb->setDomainMetadata(zname, "NSEC3PARAM", vector<string>()) && d_keymetadb->setDomainMetadata(zname, "NSEC3NARROW", vector<string>())) && clearMetaCache(zname);
}


bool DNSSECKeeper::setPresigned(const ZoneName& zname)
{
  if (d_keymetadb->inTransaction()) {
    d_metaUpdate = true;
  }

  vector<string> meta;
  meta.push_back("1");
  return d_keymetadb->setDomainMetadata(zname, "PRESIGNED", meta) && clearMetaCache(zname);
}

bool DNSSECKeeper::unsetPresigned(const ZoneName& zname)
{
  if (d_keymetadb->inTransaction()) {
    d_metaUpdate = true;
  }

  return d_keymetadb->setDomainMetadata(zname, "PRESIGNED", vector<string>()) && clearMetaCache(zname);
}

/**
 * Add domainmetadata to allow publishing CDS records for zone zname
 *
 * @param zname        ZoneName of the zone
 * @param digestAlgos  string with comma-separated numbers that describe the
 *                     used digest algorithms. This is copied to the database
 *                     verbatim
 * @return             true if the data was inserted, false otherwise
 */
bool DNSSECKeeper::setPublishCDS(const ZoneName& zname, const string& digestAlgos)
{
  if (d_keymetadb->inTransaction()) {
    d_metaUpdate = true;
  }

  vector<string> meta;
  meta.push_back(digestAlgos);
  return d_keymetadb->setDomainMetadata(zname, "PUBLISH-CDS", meta) && clearMetaCache(zname);
}

void DNSSECKeeper::getPublishCDS(const ZoneName& zname, std::string& value)
{
  getFromMetaOrDefault(zname, "PUBLISH-CDS", value, ::arg()["default-publish-cds"]);
}

/**
 * Remove domainmetadata to stop publishing CDS records for zone zname
 *
 * @param zname        ZoneName of the zone
 * @return             true if the operation was successful, false otherwise
 */
bool DNSSECKeeper::unsetPublishCDS(const ZoneName& zname)
{
  if (d_keymetadb->inTransaction()) {
    d_metaUpdate = true;
  }

  return d_keymetadb->setDomainMetadata(zname, "PUBLISH-CDS", vector<string>()) && clearMetaCache(zname);
}

/**
 * Add domainmetadata to allow publishing CDNSKEY records.for zone zname
 *
 * @param zname        ZoneName of the zone
 * @return             true if the data was inserted, false otherwise
 */
bool DNSSECKeeper::setPublishCDNSKEY(const ZoneName& zname, bool deleteAlg)
{
  if (d_keymetadb->inTransaction()) {
    d_metaUpdate = true;
  }

  vector<string> meta;
  meta.push_back(deleteAlg ? "0" : "1");
  return d_keymetadb->setDomainMetadata(zname, "PUBLISH-CDNSKEY", meta) && clearMetaCache(zname);
}

void DNSSECKeeper::getPublishCDNSKEY(const ZoneName& zname, std::string& value)
{
  getFromMetaOrDefault(zname, "PUBLISH-CDNSKEY", value, ::arg()["default-publish-cdnskey"]);
}

/**
 * Remove domainmetadata to stop publishing CDNSKEY records for zone zname
 *
 * @param zname        ZoneName of the zone
 * @return             true if the operation was successful, false otherwise
 */
bool DNSSECKeeper::unsetPublishCDNSKEY(const ZoneName& zname)
{
  if (d_keymetadb->inTransaction()) {
    d_metaUpdate = true;
  }

  return d_keymetadb->setDomainMetadata(zname, "PUBLISH-CDNSKEY", vector<string>()) && clearMetaCache(zname);
}

/**
 * Returns all keys that are used to sign the DNSKEY RRSet in a zone
 *
 * @param zname        ZoneName of the zone
 * @return             a keyset_t with all keys that are used to sign the DNSKEY
 *                     RRSet (these are the entrypoint(s) to the zone)
 */
DNSSECKeeper::keyset_t DNSSECKeeper::getEntryPoints(const ZoneName& zname)
{
  DNSSECKeeper::keyset_t ret;
  DNSSECKeeper::keyset_t keys = getKeys(zname);

  for(auto const &keymeta : keys)
    if(keymeta.second.keyType == KSK || keymeta.second.keyType == CSK)
      ret.push_back(keymeta);
  return ret;
}

DNSSECKeeper::keyset_t DNSSECKeeper::getKeys(const ZoneName& zone, bool useCache)
{
  static int ttl = ::arg().asNum("dnssec-key-cache-ttl");
  // coverity[store_truncates_time_t]
  unsigned int now = time(nullptr);

  if(!((++s_ops) % 100000)) {
    cleanup();
  }

  if (useCache && ttl > 0) {
    auto keycache = s_keycache.read_lock();
    auto iter = keycache->find(zone);

    if (iter != keycache->end() && iter->d_ttd > now) {
      keyset_t ret;
      ret.reserve(iter->d_keys.size());
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
    DNSKEYRecordContent dkrc;
    auto key = shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::makeFromISCString(dkrc, keydata.content));
    DNSSECPrivateKey dpk;
    dpk.setKey(key, dkrc.d_flags);

    if(keydata.active) {
      if(keydata.flags == 257)
        algoSEP.insert(dkrc.d_algorithm);
      else
        algoNoSEP.insert(dkrc.d_algorithm);
    }
  }
  set_intersection(algoSEP.begin(), algoSEP.end(), algoNoSEP.begin(), algoNoSEP.end(), std::back_inserter(algoHasSeparateKSK));
  retkeyset.reserve(dbkeyset.size());

  for(DNSBackend::KeyData& kd : dbkeyset)
  {
    DNSKEYRecordContent dkrc;
    auto key = shared_ptr<DNSCryptoKeyEngine>(DNSCryptoKeyEngine::makeFromISCString(dkrc, kd.content));
    DNSSECPrivateKey dpk;
    dpk.setKey(key, kd.flags, dkrc.d_algorithm);

    KeyMetaData kmd;

    kmd.active = kd.active;
    kmd.published = kd.published;
    kmd.hasSEPBit = (kd.flags == 257);
    kmd.id = kd.id;

    if (find(algoHasSeparateKSK.begin(), algoHasSeparateKSK.end(), dpk.getAlgorithm()) == algoHasSeparateKSK.end())
      kmd.keyType = CSK;
    else if(kmd.hasSEPBit)
      kmd.keyType = KSK;
    else
      kmd.keyType = ZSK;

    retkeyset.emplace_back(dpk, kmd);
  }
  sort(retkeyset.begin(), retkeyset.end(), keyCompareByKindAndID);

  if (ttl > 0) {
    KeyCacheEntry kce;
    kce.d_domain=zone;
    kce.d_keys = retkeyset;
    kce.d_ttd = now + ttl;
    {
      lruReplacingInsert<SequencedTag>(*(s_keycache.write_lock()), kce);
    }
  }

  return retkeyset;
}

bool DNSSECKeeper::checkKeys(const ZoneName& zone, std::optional<std::reference_wrapper<std::vector<std::string>>> errorMessages)
{
  vector<DNSBackend::KeyData> dbkeyset;
  d_keymetadb->getDomainKeys(zone, dbkeyset);
  bool retval = true;

  for(const DNSBackend::KeyData &keydata : dbkeyset) {
    DNSKEYRecordContent dkrc;
    auto dke = DNSCryptoKeyEngine::makeFromISCString(dkrc, keydata.content);
    retval = dke->checkKey(errorMessages) && retval;
  }

  return retval;
}

void DNSSECKeeper::getPreRRSIGs(UeberBackend& db, vector<DNSZoneRecord>& rrs, uint32_t signTTL, DNSPacket* packet)
{
  if(rrs.empty()) {
    return;
  }

  const auto rr = *rrs.rbegin();

  DNSZoneRecord dzr;

  db.lookup(QType(QType::RRSIG), !rr.wildcardname.empty() ? rr.wildcardname : rr.dr.d_name, rr.domain_id, packet);
  while(db.get(dzr)) {
    auto rrsig = getRR<RRSIGRecordContent>(dzr.dr);
    if (rrsig->d_type == rr.dr.d_type) {
      if(!rr.wildcardname.empty()) {
        dzr.dr.d_name = rr.dr.d_name;
      }
      dzr.dr.d_place = rr.dr.d_place;
      dzr.dr.d_ttl = signTTL;

      rrs.emplace_back(dzr);
    }
  }
}

bool DNSSECKeeper::TSIGGrantsAccess(const ZoneName& zone, const DNSName& keyname)
{
  vector<string> allowed;

  d_keymetadb->getDomainMetadata(zone, "TSIG-ALLOW-AXFR", allowed);

  for(const string& dbkey :  allowed) {
    if(DNSName(dbkey)==keyname)
      return true;
  }
  return false;
}

bool DNSSECKeeper::getTSIGForAccess(const ZoneName& zone, const ComboAddress& /* primary */, DNSName* keyname)
{
  vector<string> keynames;
  d_keymetadb->getDomainMetadata(zone, "AXFR-MASTER-TSIG", keynames);
  keyname->trimToLabels(0);

  // XXX FIXME this should check for a specific primary!
  for(const string& dbkey :  keynames) {
    *keyname=DNSName(dbkey);
    return true;
  }
  return false;
}

bool DNSSECKeeper::unSecureZone(const ZoneName& zone, string& error) {
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


struct RecordStatus
{
  DNSName ordername;
  bool auth{false};
  bool update{false};
};


/* Rectifies the zone
 *
 * \param zone The zone to rectify
 * \param error& A string where error messages are added
 * \param info& A string where informational messages are added
 * \param doTransaction Whether or not to wrap the rectify in a transaction
 */
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
bool DNSSECKeeper::rectifyZone(const ZoneName& zone, string& error, string& info, bool doTransaction) {
  if (isPresigned(zone, doTransaction)) {
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
    b = std::make_unique<UeberBackend>();
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
  std::unordered_map<DNSName,bool> nonterm;
  vector<DNSResourceRecord> rrs;
  std::unordered_map<DNSName,RecordStatus> rss;

  NSEC3PARAMRecordContent ns3pr;
  bool securedZone = isSecuredZone(zone, doTransaction);
  bool haveNSEC3 = false, isOptOut = false, narrow = false;

  if(securedZone) {
    haveNSEC3 = getNSEC3PARAM(zone, &ns3pr, &narrow, doTransaction);
    isOptOut = (haveNSEC3 && ns3pr.d_flags);
  }

  while(sd.db->get(rr)) {
    rr.qname.makeUsLowerCase();

    auto res=rss.insert({rr.qname,{rr.ordername, rr.auth, rr.ordername.empty() != (!securedZone || narrow)}}); // only a set ordername is reliable
    if (!res.second && !res.first->second.update) {
      res.first->second.update = res.first->second.auth != rr.auth || res.first->second.ordername != rr.ordername;
    }
    else if ((!securedZone || narrow) && rr.qname == zone.operator const DNSName&()) {
      res.first->second.update = true;
    }

    if (rr.qtype.getCode())
    {
      qnames.insert(rr.qname);
      if(rr.qtype.getCode() == QType::NS && rr.qname != zone.operator const DNSName&()) {
        nsset.insert(rr.qname);
      }
      if(rr.qtype.getCode() == QType::DS)
        dsnames.insert(rr.qname);
      rrs.emplace_back(rr);
    }
    else
      delnonterm.insert(std::move(rr.qname));
  }

  if(securedZone) {
    if(!haveNSEC3) {
      infostream<<"Adding NSEC ordering information for zone '"<<zone<<"'";
    }
    else if(!narrow) {
      if(!isOptOut) {
        infostream<<"Adding NSEC3 hashed ordering information for zone '"<<zone<<"'";
      }
      else {
        infostream<<"Adding NSEC3 opt-out hashed ordering information for zone '"<<zone<<"'";
      }
    } else {
      infostream<<"Erasing NSEC3 ordering since we are narrow, only setting 'auth' fields for zone '"<<zone<<"'";
    }
  }
  else {
    infostream<<"Adding empty non-terminals for non-DNSSEC zone '"<<zone<<"'";
  }

  set<DNSName> nsec3set;
  if (haveNSEC3 && (!narrow || !isOptOut)) {
    for (auto &loopRR: rrs) {
      bool skip=false;
      DNSName shorter = loopRR.qname;
      if (shorter != zone.operator const DNSName&() && shorter.chopOff() && shorter != zone.operator const DNSName&()) {
        do {
          if(nsset.count(shorter)) {
            skip=true;
            break;
          }
        } while(shorter.chopOff() && shorter != zone.operator const DNSName&());
      }
      shorter = loopRR.qname;
      if(!skip && (loopRR.qtype.getCode() != QType::NS || !isOptOut)) {

        do {
          if(!nsec3set.count(shorter)) {
            nsec3set.insert(shorter);
          }
        } while(shorter != zone.operator const DNSName&() && shorter.chopOff());
      }
    }
  }

  if (doTransaction)
    sd.db->startTransaction(zone, UnknownDomainID);

  sd.db->rectifyZoneHook(sd.domain_id, true);

  bool realrr=true;
  bool doent=true;
  int updates=0;
  uint32_t maxent = ::arg().asNum("max-ent-entries");

  dononterm:;
  std::unordered_map<DNSName,RecordStatus>::const_iterator it;
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
    {
      ordername=qname.makeRelative(zone);
    }

    it = rss.find(qname);
    if(it == rss.end() || it->second.update || it->second.auth != auth || it->second.ordername != ordername) {
      sd.db->updateDNSSECOrderNameAndAuth(sd.domain_id, qname, ordername, auth, QType::ANY, haveNSEC3 && !narrow);
      ++updates;
    }

    if(realrr)
    {
      if (dsnames.count(qname)) {
        sd.db->updateDNSSECOrderNameAndAuth(sd.domain_id, qname, ordername, true, QType::DS, haveNSEC3 && !narrow);
        ++updates;
      }
      if (!auth || nsset.count(qname)) {
        ordername.clear();
        if(isOptOut && !dsnames.count(qname)){
          sd.db->updateDNSSECOrderNameAndAuth(sd.domain_id, qname, ordername, false, QType::NS, haveNSEC3 && !narrow);
          ++updates;
        }
        sd.db->updateDNSSECOrderNameAndAuth(sd.domain_id, qname, ordername, false, QType::A, haveNSEC3 && !narrow);
        ++updates;
        sd.db->updateDNSSECOrderNameAndAuth(sd.domain_id, qname, ordername, false, QType::AAAA, haveNSEC3 && !narrow);
        ++updates;
      }

      if(doent)
      {
        shorter=qname;
        while(shorter!=zone.operator const DNSName&() && shorter.chopOff())
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

  sd.db->rectifyZoneHook(sd.domain_id, false);

  if (doTransaction)
    sd.db->commitTransaction();

  infostream<<", "<<updates<<" updates";
  info = infostream.str();
  return true;
}

void DNSSECKeeper::cleanup()
{
  struct timeval now;
  Utility::gettimeofday(&now, nullptr);

  if(now.tv_sec - s_last_prune > (time_t)(30)) {
    {
      pruneCollection<SequencedTag>((*s_metacache.write_lock()), s_maxEntries);
    }
    {
      pruneCollection<SequencedTag>((*s_keycache.write_lock()), s_maxEntries);
    }
    s_last_prune = time(nullptr);
  }
}

void DNSSECKeeper::setMaxEntries(size_t maxEntries)
{
  s_maxEntries = maxEntries;
#if BOOST_VERSION >= 105600
  s_keycache.write_lock()->get<KeyCacheTag>().reserve(s_maxEntries);
#endif /* BOOST_VERSION >= 105600 */
}
