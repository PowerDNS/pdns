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
#include "dnssecinfra.hh"
#include "namespaces.hh"
#include <boost/foreach.hpp>
#include "md5.hh"
#include "dnsseckeeper.hh"
#include "dns_random.hh"
#include "lock.hh"
#include "arguments.hh"
#include "statbag.hh"
extern StatBag S;

/* this is where the RRSIGs begin, keys are retrieved,
   but the actual signing happens in fillOutRRSIG */
int getRRSIGsForRRSET(DNSSECKeeper& dk, const std::string& signer, const std::string signQName, uint16_t signQType, uint32_t signTTL,
                     vector<shared_ptr<DNSRecordContent> >& toSign, vector<RRSIGRecordContent>& rrcs)
{
  if(toSign.empty())
    return -1;
  uint32_t startOfWeek = getStartOfWeek();
  RRSIGRecordContent rrc;
  rrc.d_type=signQType;

  rrc.d_labels=countLabels(signQName); 
  rrc.d_originalttl=signTTL; 
  rrc.d_siginception=startOfWeek - 7*86400; // XXX should come from zone metadata
  rrc.d_sigexpire=startOfWeek + 14*86400;
  rrc.d_signer = signer.empty() ? "." : toLower(signer);
  rrc.d_tag = 0;
  
  // we sign the RRSET in toSign + the rrc w/o hash
  
  DNSSECKeeper::keyset_t keys = dk.getKeys(signer); // we don't want the . for the root!
  set<int> algoHasKSK, algoHasZSK;
  vector<DNSSECPrivateKey> signingKeys;

  BOOST_FOREACH(DNSSECKeeper::keyset_t::value_type& keymeta, keys) {
    if(keymeta.second.active) {
      if(keymeta.second.keyOrZone)
        algoHasKSK.insert(keymeta.first.d_algorithm);
      else
        algoHasZSK.insert(keymeta.first.d_algorithm);
    }
  }

  BOOST_FOREACH(DNSSECKeeper::keyset_t::value_type& keymeta, keys) {
    if(!keymeta.second.active)
      continue;

    if(signQType == QType::DNSKEY) {
      // skip ZSK, if this algorithm has a KSK
      if(!keymeta.second.keyOrZone && algoHasKSK.count(keymeta.first.d_algorithm))
        continue;
    } else {
      // skip KSK, if this algorithm has a ZSK
      if(keymeta.second.keyOrZone && algoHasZSK.count(keymeta.first.d_algorithm))
        continue;
    }

    signingKeys.push_back(keymeta.first);
  }

  BOOST_FOREACH(DNSSECPrivateKey& dpk, signingKeys) {
    fillOutRRSIG(dpk, signQName, rrc, toSign);
    rrcs.push_back(rrc);
  }
  return 0;
}

// this is the entrypoint from DNSPacket
void addSignature(DNSSECKeeper& dk, DNSBackend& db, const std::string& signer, const std::string signQName, const std::string& wildcardname, uint16_t signQType, 
  uint32_t signTTL, DNSPacketWriter::Place signPlace, 
  vector<shared_ptr<DNSRecordContent> >& toSign, vector<DNSResourceRecord>& outsigned, uint32_t origTTL)
{
  //cerr<<"Asked to sign '"<<signQName<<"'|"<<DNSRecordContent::NumberToType(signQType)<<", "<<toSign.size()<<" records\n";
  if(toSign.empty())
    return;
  vector<RRSIGRecordContent> rrcs;
  if(dk.isPresigned(signer)) {
    //cerr<<"Doing presignatures"<<endl;
    dk.getPreRRSIGs(db, signer, signQName, wildcardname, QType(signQType), signPlace, outsigned, origTTL); // does it all
  }
  else {
    if(getRRSIGsForRRSET(dk, signer, wildcardname.empty() ? signQName : wildcardname, signQType, signTTL, toSign, rrcs) < 0)  {
      // cerr<<"Error signing a record!"<<endl;
      return;
    } 
  
    DNSResourceRecord rr;
    rr.qname=signQName;
    rr.qtype=QType::RRSIG;
    if(origTTL)
      rr.ttl=origTTL;
    else
      rr.ttl=signTTL;
    rr.auth=false;
    rr.d_place = (DNSResourceRecord::Place) signPlace;
    BOOST_FOREACH(RRSIGRecordContent& rrc, rrcs) {
      rr.content = rrc.getZoneRepresentation();
      outsigned.push_back(rr);
    }
  }
  toSign.clear();
}

static pthread_rwlock_t g_signatures_lock = PTHREAD_RWLOCK_INITIALIZER;
typedef map<pair<string, string>, string> signaturecache_t;
static signaturecache_t g_signatures;
static int g_cacheweekno;

AtomicCounter* g_signatureCount;

uint64_t signatureCacheSize(const std::string& str)
{
  ReadLock l(&g_signatures_lock);
  return g_signatures.size();
}

void fillOutRRSIG(DNSSECPrivateKey& dpk, const std::string& signQName, RRSIGRecordContent& rrc, vector<shared_ptr<DNSRecordContent> >& toSign) 
{
  if(!g_signatureCount)
    g_signatureCount = S.getPointer("signatures");
    
  DNSKEYRecordContent drc = dpk.getDNSKEY(); 
  const DNSCryptoKeyEngine* rc = dpk.getKey();
  rrc.d_tag = drc.getTag();
  rrc.d_algorithm = drc.d_algorithm;
  
  string msg=getMessageForRRSET(signQName, rrc, toSign); // this is what we will hash & sign
  pair<string, string> lookup(rc->getPubKeyHash(), pdns_md5sum(msg));  // this hash is a memory saving exercise
  
  bool doCache=1;
  if(doCache)
  {
    ReadLock l(&g_signatures_lock);
    signaturecache_t::const_iterator iter = g_signatures.find(lookup);
    if(iter != g_signatures.end()) {
      rrc.d_signature=iter->second;
      return;
    }
    // else cerr<<"Miss!"<<endl;  
  }
  
  rrc.d_signature = rc->sign(msg);
  (*g_signatureCount)++;
  if(doCache) {
    /* we add some jitter here so not all your slaves start pruning their caches at the very same millisecond */
    int weekno = (time(0) - dns_random(3600)) / (86400*7);  // we just spent milliseconds doing a signature, microsecond more won't kill us
    const static int maxcachesize=::arg().asNum("max-signature-cache-entries", INT_MAX);

    WriteLock l(&g_signatures_lock);
    if(g_cacheweekno < weekno || g_signatures.size() >= (uint) maxcachesize) {  // blunt but effective (C) Habbie, mind04
      L<<Logger::Warning<<"Cleared signature cache."<<endl;
      g_signatures.clear();
      g_cacheweekno = weekno;
    }
    g_signatures[lookup] = rrc.d_signature;
  }
}

static bool rrsigncomp(const DNSResourceRecord& a, const DNSResourceRecord& b)
{
  return tie(a.d_place, a.qtype) < tie(b.d_place, b.qtype);
}

static bool getBestAuthFromSet(const set<string, CIStringCompare>& authSet, const string& name, string& auth)
{
  auth.clear();
  string sname(name);
  do {
    if(authSet.find(sname) != authSet.end()) {
      auth = sname;
      return true;
    }
  }
  while(chopOff(sname));
  
  return false;
}

void addRRSigs(DNSSECKeeper& dk, DNSBackend& db, const set<string, CIStringCompare>& authSet, vector<DNSResourceRecord>& rrs)
{
  stable_sort(rrs.begin(), rrs.end(), rrsigncomp);
  
  string signQName, wildcardQName;
  uint16_t signQType=0;
  uint32_t signTTL=0;
  uint32_t origTTL=0;
  
  DNSPacketWriter::Place signPlace=DNSPacketWriter::ANSWER;
  vector<shared_ptr<DNSRecordContent> > toSign;

  vector<DNSResourceRecord> signedRecords;
  
  string signer;
  for(vector<DNSResourceRecord>::const_iterator pos = rrs.begin(); pos != rrs.end(); ++pos) {
    if(pos != rrs.begin() && (signQType != pos->qtype.getCode()  || signQName != pos->qname)) {
      if(getBestAuthFromSet(authSet, signQName, signer))
        addSignature(dk, db, signer, signQName, wildcardQName, signQType, signTTL, signPlace, toSign, signedRecords, origTTL);
    }
    signedRecords.push_back(*pos);
    signQName= pos->qname;
    wildcardQName = pos->wildcardname;
    signQType = pos ->qtype.getCode();
    if(pos->signttl)
      signTTL = pos->signttl;
    else
      signTTL = pos->ttl;
    origTTL = pos->ttl;
    signPlace = (DNSPacketWriter::Place) pos->d_place;
    if(pos->auth || pos->qtype.getCode() == QType::DS) {
      string content = pos->content;
      if(pos->qtype.getCode()==QType::MX || pos->qtype.getCode() == QType::SRV) {  
        content = lexical_cast<string>(pos->priority) + " " + pos->content;
      }
      if(!pos->content.empty() && pos->qtype.getCode()==QType::TXT && pos->content[0]!='"') {
        content="\""+pos->content+"\"";
      }
      if(pos->content.empty())  // empty contents confuse the MOADNS setup
        content=".";
      
      shared_ptr<DNSRecordContent> drc(DNSRecordContent::mastermake(pos->qtype.getCode(), 1, content)); 
      toSign.push_back(drc);
    }
  }
  if(getBestAuthFromSet(authSet, signQName, signer))
    addSignature(dk, db, signer, signQName, wildcardQName, signQType, signTTL, signPlace, toSign, signedRecords, origTTL);
  rrs.swap(signedRecords);
}
