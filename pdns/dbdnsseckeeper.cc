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
using namespace boost::assign;
using namespace std;
using namespace boost;

bool DNSSECKeeper::haveActiveKSKFor(const std::string& zone) 
{
  keyset_t keys = getKeys(zone, true);
  // need to get an *active* one!
  //cerr<<__FUNCTION__<<"Got "<<keys.size()<<" keys"<<endl;
  BOOST_FOREACH(keyset_t::value_type& val, keys) {
    if(val.second.active) {
      return true;
    }
  }
  return false;
}


void DNSSECKeeper::addKey(const std::string& name, bool keyOrZone, int algorithm, int bits, bool active)
{
  if(!bits)
    bits = keyOrZone ? 2048 : 1024;
  DNSSECPrivateKey dpk;
  dpk.d_key.create(bits); 
  dpk.d_algorithm = algorithm;
  addKey(name, keyOrZone, dpk, active);
}

void DNSSECKeeper::addKey(const std::string& name, bool keyOrZone, const DNSSECPrivateKey& dpk, bool active)
{
  DNSBackend::KeyData kd;
  kd.flags = 256 + keyOrZone;
  kd.active = active;
  kd.content = dpk.d_key.convertToISC(dpk.d_algorithm);
 // now store it
  d_db.addDomainKey(name, kd);
}


static bool keyCompareByKindAndID(const DNSSECKeeper::keyset_t::value_type& a, const DNSSECKeeper::keyset_t::value_type& b)
{
  return make_pair(!a.second.keyOrZone, a.second.id) <
         make_pair(!b.second.keyOrZone, b.second.id);
}

DNSSECPrivateKey DNSSECKeeper::getKeyById(const std::string& zname, unsigned int id)
{  
  vector<DNSBackend::KeyData> keys;
  d_db.getDomainKeys(zname, 0, keys);
  BOOST_FOREACH(const DNSBackend::KeyData& kd, keys) {
    if(kd.id != id) 
      continue;
    
    DNSSECPrivateKey dpk;
    DNSKEYRecordContent dkrc = getRSAKeyFromISCString(&dpk.d_key.getContext(), kd.content);
    dpk.d_flags = kd.flags;
    dpk.d_algorithm = dkrc.d_algorithm;
    
    if(dpk.d_algorithm == 5 && getNSEC3PARAM(zname)) {
      dpk.d_algorithm += 2;
    }
    
    return dpk;    
  }
  throw runtime_error("Can't find a key with id "+lexical_cast<string>(id)+" for zone '"+zname+"'");
}


void DNSSECKeeper::removeKey(const std::string& zname, unsigned int id)
{
  d_db.removeDomainKey(zname, id);
}

void DNSSECKeeper::deactivateKey(const std::string& zname, unsigned int id)
{
  d_db.deactivateDomainKey(zname, id);
}

void DNSSECKeeper::activateKey(const std::string& zname, unsigned int id)
{
  d_db.activateDomainKey(zname, id);
}

bool DNSSECKeeper::getNSEC3PARAM(const std::string& zname, NSEC3PARAMRecordContent* ns3p, bool* narrow)
{
  vector<string> meta;
  if(narrow) {
    d_db.getDomainMetadata(zname, "NSEC3NARROW", meta);
    *narrow=false;
    if(!meta.empty() && meta[0]=="1")
      *narrow=true;
  }
  meta.clear();
  d_db.getDomainMetadata(zname, "NSEC3PARAM", meta);
  
  if(meta.empty())
    return false;
    
  if(ns3p) {
    string descr = *meta.begin();
    reportAllTypes();
    NSEC3PARAMRecordContent* tmp=dynamic_cast<NSEC3PARAMRecordContent*>(DNSRecordContent::mastermake(QType::NSEC3PARAM, 1, descr));
    if(!tmp) {
      cerr<<"descr: '"<<descr<<"'\n";
      return false;
    }
    *ns3p = *tmp;
    delete tmp;
  }
  return true;
}

void DNSSECKeeper::setNSEC3PARAM(const std::string& zname, const NSEC3PARAMRecordContent& ns3p, const bool& narrow)
{
  string descr = ns3p.getZoneRepresentation();
  vector<string> meta;
  meta.push_back(descr);
  d_db.setDomainMetadata(zname, "NSEC3PARAM", meta);
  
  meta.clear();
  if(narrow)
    meta.push_back("1");
  d_db.setDomainMetadata(zname, "NSEC3NARROW", meta);
}

void DNSSECKeeper::unsetNSEC3PARAM(const std::string& zname)
{
  d_db.setDomainMetadata(zname, "NSEC3PARAM", vector<string>());
}


DNSSECKeeper::keyset_t DNSSECKeeper::getKeys(const std::string& zone, boost::tribool allOrKeyOrZone) 
{
  keyset_t keyset;
  vector<UeberBackend::KeyData> dbkeyset;
  
  d_db.getDomainKeys(zone, 0, dbkeyset);
  // do db thing
  //cerr<<"Here: received " <<dbkeyset.size()<<" keys"<<endl;
  BOOST_FOREACH(UeberBackend::KeyData& kd, dbkeyset) 
  {
    DNSSECPrivateKey dpk;

    DNSKEYRecordContent dkrc=getRSAKeyFromISCString(&dpk.d_key.getContext(), kd.content);
    dpk.d_flags = kd.flags;
    dpk.d_algorithm = dkrc.d_algorithm;
    if(dpk.d_algorithm == 5 && getNSEC3PARAM(zone))
      dpk.d_algorithm+=2;
    
    KeyMetaData kmd;

    kmd.active = kd.active;
    kmd.keyOrZone = (kd.flags == 257);
    kmd.id = kd.id;
    
    if(boost::indeterminate(allOrKeyOrZone) || allOrKeyOrZone == kmd.keyOrZone)
      keyset.push_back(make_pair(dpk, kmd));
  }
  sort(keyset.begin(), keyset.end(), keyCompareByKindAndID);
  return keyset;
}

void DNSSECKeeper::secureZone(const std::string& name, int algorithm)
{
  addKey(name, true, algorithm);
}

// nobody should ever call this function, you know the SOA/auth already!
bool getSignerApexFor(DNSSECKeeper& dk, const std::string& qname, std::string &signer)
{
  // cerr<<"getSignerApexFor: called, and should not be, should go away!"<<endl;
  signer=qname;
  do {
    if(dk.haveActiveKSKFor(signer)) {
      return true;
    }
  } while(chopOff(signer));
  return false;
}

/* this is where the RRSIG gets filled out, the hashing gets done, key apex *name* gets found,
   but the actual signing happens in fillOutRRSIG */
int getRRSIGsForRRSET(DNSSECKeeper& dk, const std::string signQName, uint16_t signQType, uint32_t signTTL, 
		     vector<shared_ptr<DNSRecordContent> >& toSign, vector<RRSIGRecordContent>& rrcs, bool ksk)
{
  if(toSign.empty())
    return -1;
  RRSIGRecordContent rrc;
  rrc.d_type=signQType;

  // d_algorithm gets filled out by getSignerAPEX, since only it looks up the key
  rrc.d_labels=countLabels(signQName); 
  rrc.d_originalttl=signTTL; 
  rrc.d_siginception=getCurrentInception();;
  rrc.d_sigexpire = rrc.d_siginception + 14*86400; // XXX should come from zone metadata
  rrc.d_tag = 0;
  
  // XXX we know the apex already.. is is the SOA name which we determined earlier
  if(!getSignerApexFor(dk, signQName, rrc.d_signer)) {
    cerr<<"No signer known for '"<<signQName<<"'\n";
    return -1;
  }
  // we sign the RRSET in toSign + the rrc w/o key
  
  DNSSECKeeper::keyset_t keys = dk.getKeys(rrc.d_signer);
  vector<DNSSECPrivateKey> KSKs, ZSKs;
  vector<DNSSECPrivateKey>* signingKeys;
  
  // if ksk==1, only get KSKs
  // if ksk==0, get ZSKs, unless there is no ZSK, then get KSK
  BOOST_FOREACH(DNSSECKeeper::keyset_t::value_type& keymeta, keys) {
    if(!keymeta.second.active) 
      continue;
      
    if(keymeta.second.keyOrZone)
      KSKs.push_back(keymeta.first);
    else if(!ksk)
      ZSKs.push_back(keymeta.first);
  }
  if(ksk)
    signingKeys = &KSKs;
  else {
    if(ZSKs.empty())
      signingKeys = &KSKs;
    else
      signingKeys =&ZSKs;
  }
  
  BOOST_FOREACH(DNSSECPrivateKey& dpk, *signingKeys) {
    fillOutRRSIG(dpk, signQName, rrc, toSign);
    rrcs.push_back(rrc);
  }
  return 0;
}

// this is the entrypoint from DNSPacket
void addSignature(DNSSECKeeper& dk, const std::string signQName, const std::string& wildcardname, uint16_t signQType, 
  uint32_t signTTL, DNSPacketWriter::Place signPlace, 
  vector<shared_ptr<DNSRecordContent> >& toSign, uint16_t maxReplyLen, DNSPacketWriter& pw)
{
  // cerr<<"Asked to sign '"<<signQName<<"'|"<<DNSRecordContent::NumberToType(signQType)<<", "<<toSign.size()<<" records\n";

  vector<RRSIGRecordContent> rrcs;
  if(toSign.empty())
    return;

  if(getRRSIGsForRRSET(dk, wildcardname.empty() ? signQName : wildcardname, signQType, signTTL, toSign, rrcs, signQType == QType::DNSKEY) < 0) {
    cerr<<"Error signing a record!"<<endl;
    return;
  }
  BOOST_FOREACH(RRSIGRecordContent& rrc, rrcs) {
    pw.startRecord(signQName, QType::RRSIG, 3600, 1, 
      signQType==QType::DNSKEY ? DNSPacketWriter:: ANSWER : signPlace); 
    rrc.toPacket(pw);
    if(maxReplyLen &&  (pw.size() + 20) > maxReplyLen) {
      pw.rollback();
      pw.getHeader()->tc=1;
      return;
    }
  }
  pw.commit();

  toSign.clear();
}

static pthread_mutex_t g_signatures_lock = PTHREAD_MUTEX_INITIALIZER;
static map<pair<RSAContext, string>, string> g_signatures;

void fillOutRRSIG(DNSSECPrivateKey& dpk, const std::string& signQName, RRSIGRecordContent& rrc, vector<shared_ptr<DNSRecordContent> >& toSign) 
{
  DNSKEYRecordContent drc= dpk.getDNSKEY(); 
  RSAContext& rc = dpk.d_key;
  rrc.d_tag = drc.getTag();
  rrc.d_algorithm = drc.d_algorithm;
  string realhash=getHashForRRSET(signQName, rrc, toSign); // this is what we sign

  unsigned char signature[mpi_size(&rc.getContext().N)];

  {
    Lock l(&g_signatures_lock);
    if(g_signatures.count(make_pair(rc, realhash))) {
      rrc.d_signature=g_signatures[make_pair(rc, realhash)];
      return;
    }
  }
  
  int ret=rsa_pkcs1_sign(&rc.getContext(), RSA_PRIVATE, 
    rrc.d_algorithm < 8 ? SIG_RSA_SHA1 : SIG_RSA_SHA256, 
    rrc.d_algorithm < 8 ? 20 : 32,
    (unsigned char*) realhash.c_str(), signature);
  
  if(ret!=0) {
    cerr<<"signing returned: "<<ret<<endl;
    exit(1);
  }
  
  rrc.d_signature.assign((char*)signature, sizeof(signature));

  Lock l(&g_signatures_lock);
  g_signatures[make_pair(rc, realhash)] = rrc.d_signature;
}
