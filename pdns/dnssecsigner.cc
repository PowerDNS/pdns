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
#include "dnssecinfra.hh"
#include "namespaces.hh"

#include "digests.hh"
#include "dnsseckeeper.hh"
#include "dns_random.hh"
#include "lock.hh"
#include "arguments.hh"
#include "statbag.hh"
#include "sha.hh"

extern StatBag S;

using signaturecache_t = map<pair<string, string>, string>;
static SharedLockGuarded<signaturecache_t> g_signatures;
static int g_cacheweekno;

const static std::set<uint16_t> g_KSKSignedQTypes {QType::DNSKEY, QType::CDS, QType::CDNSKEY};
AtomicCounter* g_signatureCount;

static std::string getLookupKeyFromMessage(const std::string& msg)
{
  try {
    return pdns::md5(msg);
  }
  catch(const std::runtime_error& e) {
    return pdns::sha1(msg);
  }
}

static std::string getLookupKeyFromPublicKey(const std::string& pubKey)
{
  /* arbitrarily cut off at 64 bytes, the main idea is to save space
     for very large keys like RSA ones (1024+ bits so 128+ bytes) by storing a 20 bytes hash
     instead */
  if (pubKey.size() <= 64) {
    return pubKey;
  }
  return pdns::sha1sum(pubKey);
}

static void fillOutRRSIG(DNSSECPrivateKey& dpk, const DNSName& signQName, RRSIGRecordContent& rrc, const sortedRecords_t& toSign)
{
  if(!g_signatureCount)
    g_signatureCount = S.getPointer("signatures");

  DNSKEYRecordContent drc = dpk.getDNSKEY();
  const std::shared_ptr<DNSCryptoKeyEngine>& rc = dpk.getKey();
  rrc.d_tag = drc.getTag();
  rrc.d_algorithm = drc.d_algorithm;

  string msg = getMessageForRRSET(signQName, rrc, toSign); // this is what we will hash & sign
  pair<string, string> lookup(getLookupKeyFromPublicKey(drc.d_key), getLookupKeyFromMessage(msg));  // this hash is a memory saving exercise

  bool doCache = true;
  if (doCache) {
    auto signatures = g_signatures.read_lock();
    signaturecache_t::const_iterator iter = signatures->find(lookup);
    if (iter != signatures->end()) {
      rrc.d_signature=iter->second;
      return;
    }
    // else cerr<<"Miss!"<<endl;
  }

  rrc.d_signature = rc->sign(msg);
  (*g_signatureCount)++;
  if(doCache) {
    /* we add some jitter here so not all your secondaries start pruning their caches at the very same millisecond */
    int weekno = (time(nullptr) - dns_random(3600)) / (86400*7);  // we just spent milliseconds doing a signature, microsecond more won't kill us
    const static int maxcachesize=::arg().asNum("max-signature-cache-entries", INT_MAX);

    auto signatures = g_signatures.write_lock();
    if (g_cacheweekno < weekno || signatures->size() >= (uint) maxcachesize) {  // blunt but effective (C) Habbie, mind04
      g_log<<Logger::Warning<<"Cleared signature cache."<<endl;
      signatures->clear();
      g_cacheweekno = weekno;
    }
    (*signatures)[lookup] = rrc.d_signature;
  }
}

/* this is where the RRSIGs begin, keys are retrieved,
   but the actual signing happens in fillOutRRSIG */
static int getRRSIGsForRRSET(DNSSECKeeper& dsk, const ZoneName& signer, const DNSName& signQName, uint16_t signQType, uint32_t signTTL,
                             const sortedRecords_t& toSign, vector<RRSIGRecordContent>& rrcs)
{
  if(toSign.empty())
    return -1;
  uint32_t startOfWeek = getStartOfWeek();
  RRSIGRecordContent rrc;
  rrc.d_type=signQType;

  rrc.d_labels=signQName.countLabels()-signQName.isWildcard();
  rrc.d_originalttl=signTTL;
  rrc.d_siginception=startOfWeek - 7*86400; // XXX should come from zone metadata
  rrc.d_sigexpire=startOfWeek + 14*86400;
  rrc.d_signer = signer.operator const DNSName&();
  rrc.d_tag = 0;

  DNSSECKeeper::keyset_t keys = dsk.getKeys(signer);

  for(DNSSECKeeper::keyset_t::value_type& keymeta : keys) {
    if(!keymeta.second.active)
      continue;

    bool signWithKSK = g_KSKSignedQTypes.count(signQType) != 0;
    // Do not sign DNSKEY RRsets with the ZSK
    if((signQType == QType::DNSKEY && keymeta.second.keyType == DNSSECKeeper::ZSK) ||
       // Do not sign any other RRset than DNSKEY, CDS and CDNSKEY with a KSK
       (!signWithKSK && keymeta.second.keyType == DNSSECKeeper::KSK)) {
      continue;
    }

    fillOutRRSIG(keymeta.first, signQName, rrc, toSign);
    rrcs.push_back(rrc);
  }
  return 0;
}

// this is the entrypoint from DNSPacket
static void addSignature(DNSSECKeeper& dsk, UeberBackend& ueber, const ZoneName& signer, const DNSName& signQName, const DNSName& wildcardname, uint16_t signQType,
                         uint32_t signTTL, DNSResourceRecord::Place signPlace,
                         sortedRecords_t& toSign, vector<DNSZoneRecord>& outsigned, uint32_t origTTL, DNSPacket* packet)
{
  static bool directDNSKEYSignature = ::arg().mustDo("direct-dnskey-signature");

  //cerr<<"Asked to sign '"<<signQName<<"'|"<<DNSRecordContent::NumberToType(signQType)<<", "<<toSign.size()<<" records\n";
  if(toSign.empty())
    return;
  vector<RRSIGRecordContent> rrcs;
  if(dsk.isPresigned(signer) || (directDNSKEYSignature && signQType == QType::DNSKEY)) {
    //cerr<<"Doing presignatures"<<endl;
    dsk.getPreRRSIGs(ueber, outsigned, origTTL, packet); // does it all
  }
  else {
    if(getRRSIGsForRRSET(dsk, signer, wildcardname.countLabels() != 0 ? wildcardname : signQName, signQType, signTTL, toSign, rrcs) < 0)  {
      // cerr<<"Error signing a record!"<<endl;
      return;
    }

    DNSZoneRecord rr;
    rr.dr.d_name=signQName;
    rr.dr.d_type=QType::RRSIG;
    if(origTTL)
      rr.dr.d_ttl=origTTL;
    else
      rr.dr.d_ttl=signTTL;
    rr.auth=false;
    rr.dr.d_place = signPlace;
    for(RRSIGRecordContent& rrc :  rrcs) {
      rr.dr.setContent(std::make_shared<RRSIGRecordContent>(rrc));
      outsigned.push_back(rr);
    }
  }
  toSign.clear();
}

uint64_t signatureCacheSize(const std::string& /* str */)
{
  return g_signatures.read_lock()->size();
}

static bool rrsigncomp(const DNSZoneRecord& a, const DNSZoneRecord& b)
{
  return std::tie(a.dr.d_place, a.dr.d_type) < std::tie(b.dr.d_place, b.dr.d_type);
}

static bool getBestAuthFromSet(const set<ZoneName>& authSet, const DNSName& name, ZoneName& signer)
{
  signer.trimToLabels(0);
  ZoneName sname(name);
  do {
    if(authSet.find(sname) != authSet.end()) {
      signer = std::move(sname);
      return true;
    }
  }
  while(sname.chopOff());

  return false;
}

void addRRSigs(DNSSECKeeper& dsk, UeberBackend& ueber, const set<ZoneName>& authSet, vector<DNSZoneRecord>& rrs, DNSPacket* packet)
{
  stable_sort(rrs.begin(), rrs.end(), rrsigncomp);

  DNSName authQName, signQName, wildcardQName;
  uint16_t signQType=0;
  uint32_t signTTL=0;
  uint32_t origTTL=0;

  DNSResourceRecord::Place signPlace=DNSResourceRecord::ANSWER;
  sortedRecords_t toSign;

  vector<DNSZoneRecord> signedRecords;
  signedRecords.reserve(rrs.size()*1.5);
  //  cout<<rrs.size()<<", "<<sizeof(DNSZoneRecord)<<endl;
  ZoneName signer;
  for(auto pos = rrs.cbegin(); pos != rrs.cend(); ++pos) {
    if(pos != rrs.cbegin() && (signQType != pos->dr.d_type  || signQName != pos->dr.d_name)) {
      if (getBestAuthFromSet(authSet, authQName, signer))
        addSignature(dsk, ueber, signer, signQName, wildcardQName, signQType, signTTL, signPlace, toSign, signedRecords, origTTL, packet);
    }
    signedRecords.push_back(*pos);
    signQName = pos->dr.d_name.makeLowerCase();
    if (pos->dr.d_type == QType::NSEC) {
      authQName = signQName.getCommonLabels(getRR<NSECRecordContent>(pos->dr)->d_next);
    }
    else {
      authQName = signQName;
    }
    if(!pos->wildcardname.empty())
      wildcardQName = pos->wildcardname.makeLowerCase();
    else
      wildcardQName.clear();
    signQType = pos->dr.d_type;
    if(pos->signttl)
      signTTL = pos->signttl;
    else
      signTTL = pos->dr.d_ttl;
    origTTL = pos->dr.d_ttl;
    signPlace = pos->dr.d_place;
    if(pos->auth || pos->dr.d_type == QType::DS) {
      toSign.insert(pos->dr.getContent()); // so ponder.. should this be a deep copy perhaps?
    }
  }
  if (getBestAuthFromSet(authSet, authQName, signer))
    addSignature(dsk, ueber, signer, signQName, wildcardQName, signQType, signTTL, signPlace, toSign, signedRecords, origTTL, packet);
  rrs.swap(signedRecords);
}
