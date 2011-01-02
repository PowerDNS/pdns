#include "dnsseckeeper.hh"
#include "dnssecinfra.hh"
#include "ueberbackend.hh"
#include "statbag.hh"
#include <iostream>
#include <boost/filesystem/operations.hpp>
#include <boost/filesystem/path.hpp>
#include <boost/foreach.hpp>
#include <sys/stat.h>
#include <sys/types.h>
#include <fstream>
#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>
#include <boost/assign/std/vector.hpp> // for 'operator+=()'
#include <boost/assign/list_inserter.hpp>
using namespace boost::assign;
namespace fs = boost::filesystem;

using namespace std;
using namespace boost;

bool DNSSECKeeper::haveActiveKSKFor(const std::string& zone, DNSSECPrivateKey* dpk)
{
  keyset_t keys = getKeys(zone, true);
  // need to get an *active* one!
  //cerr<<__FUNCTION__<<"Got "<<keys.size()<<" keys"<<endl;
  if(dpk && !keys.empty()) {
    *dpk = keys.begin()->first;
  }
  return !keys.empty();
}


void DNSSECKeeper::addKey(const std::string& name, bool keyOrZone, int algorithm, int bits, bool active)
{
  if(!bits)
    bits = keyOrZone ? 2048 : 1024;
  DNSSECPrivateKey dpk;
  dpk.d_key.create(bits); 
  addKey(name, keyOrZone, dpk, active);
}

void DNSSECKeeper::addKey(const std::string& name, bool keyOrZone, const DNSSECPrivateKey& dpk, bool active)
{
  DNSBackend::KeyData kd;
  kd.flags = 256 + keyOrZone;
  kd.active = active;
  kd.content = dpk.d_key.convertToISC(5);
 
 // now store it
  UeberBackend db;
  db.addDomainKey(name, kd);
}


static bool keyCompareByKindAndID(const DNSSECKeeper::keyset_t::value_type& a, const DNSSECKeeper::keyset_t::value_type& b)
{
  return make_pair(!a.second.keyOrZone, a.second.id) <
         make_pair(!b.second.keyOrZone, b.second.id);
}

DNSSECPrivateKey DNSSECKeeper::getKeyById(const std::string& zname, unsigned int id)
{  
  UeberBackend db;
  vector<DNSBackend::KeyData> keys;
  db.getDomainKeys(zname, 0, keys);
  BOOST_FOREACH(const DNSBackend::KeyData& kd, keys) {
    if(kd.id != id) 
      continue;
    
    DNSSECPrivateKey dpk;

    getRSAKeyFromISCString(&dpk.d_key.getContext(), kd.content);
    dpk.d_flags = kd.flags;
    dpk.d_algorithm = 5 + 2*getNSEC3PARAM(zname);
    
    KeyMetaData kmd;

    kmd.active = kd.active;
    kmd.keyOrZone = (kd.flags == 257);
    kmd.id = kd.id;
    
    return dpk;    
  }
  throw runtime_error("Can't find a key with id "+lexical_cast<string>(id)+" for zone '"+zname+"'");
}


void DNSSECKeeper::removeKey(const std::string& zname, unsigned int id)
{
  UeberBackend db;
  db.removeDomainKey(zname, id);
}

void DNSSECKeeper::deactivateKey(const std::string& zname, unsigned int id)
{
  UeberBackend db;
  db.deactivateDomainKey(zname, id);
}

void DNSSECKeeper::activateKey(const std::string& zname, unsigned int id)
{
  UeberBackend db;
  db.activateDomainKey(zname, id);
}

bool DNSSECKeeper::getNSEC3PARAM(const std::string& zname, NSEC3PARAMRecordContent* ns3p)
{
  UeberBackend db;
  vector<string> meta;
  db.getDomainMetadata(zname, "NSEC3PARAM", meta);
  
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

void DNSSECKeeper::setNSEC3PARAM(const std::string& zname, const NSEC3PARAMRecordContent& ns3p)
{
  string descr = ns3p.getZoneRepresentation();
  vector<string> meta;
  meta.push_back(descr);
  UeberBackend db;
  db.setDomainMetadata(zname, "NSEC3PARAM", meta);
}

void DNSSECKeeper::unsetNSEC3PARAM(const std::string& zname)
{
  UeberBackend db;
  db.setDomainMetadata(zname, "NSEC3PARAM", vector<string>());
}


DNSSECKeeper::keyset_t DNSSECKeeper::getKeys(const std::string& zone, boost::tribool allOrKeyOrZone)
{
  keyset_t keyset;
  UeberBackend db;
  vector<UeberBackend::KeyData> dbkeyset;
  
  db.getDomainKeys(zone, 0, dbkeyset);
  // do db thing
  //cerr<<"Here: received " <<dbkeyset.size()<<" keys"<<endl;
  BOOST_FOREACH(UeberBackend::KeyData& kd, dbkeyset) 
  {
    DNSSECPrivateKey dpk;

    getRSAKeyFromISCString(&dpk.d_key.getContext(), kd.content);
    dpk.d_flags = kd.flags;
    dpk.d_algorithm = 5 + 2*getNSEC3PARAM(zone);
    
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
 
bool getSignerFor(const std::string& qname, std::string &signer)
{
  DNSSECKeeper dk;

  signer=qname;
  do {
    if(dk.haveActiveKSKFor(signer)) 
      return true;
  } while(chopOff(signer));
  return false;
}

DNSKEYRecordContent getDNSKEYFor(const std::string& qname, bool withKSK, RSAContext* rc)
{
  DNSSECKeeper dk;
  cerr<<"Asked for a DNSKEY for '"<<qname<<"', withKSK="<<withKSK<<"\n";
  DNSSECPrivateKey dpk;

  if(!withKSK) {
    DNSSECKeeper::keyset_t zskset=dk.getKeys(qname, false);
    BOOST_FOREACH(DNSSECKeeper::keyset_t::value_type value, zskset) {
      if(value.second.active) {
        cerr<<"Found a ZSK for '"<<qname<<"', key tag = "<<value.first.getDNSKEY().getTag()<<endl;
        *rc=value.first.d_key;
        return value.first.getDNSKEY();
      }
      else 
        cerr<<"Found an inactive ZSK for '"<<qname<<"', key tag = "<<value.first.getDNSKEY().getTag()<<endl;
    }
    cerr<<"Could not find an active ZSK for '"<<qname<<"'"<<endl;
    exit(1);
  }
  else if(dk.haveActiveKSKFor(qname, &dpk)) {
    cerr<<"Found a KSK for '"<<qname<<"'"<<endl;
    *rc=dpk.d_key;
    return dpk.getDNSKEY();
  } else {
      cerr<<"DID NOT FIND A ZSK for '"<<qname<<"'"<<endl;
      exit(1);
  }
}

int getRRSIGForRRSET(const std::string signQName, uint16_t signQType, uint32_t signTTL, 
		     vector<shared_ptr<DNSRecordContent> >& toSign, RRSIGRecordContent& rrc, bool ksk)
{
  if(toSign.empty())
    return -1;

  rrc.d_type=signQType;

  // d_algorithm gets filled out by fillOutRRSIG, since it  gets the key
  rrc.d_labels=countLabels(signQName); 
  rrc.d_originalttl=signTTL; 
  rrc.d_siginception=getCurrentInception();;
  rrc.d_sigexpire = rrc.d_siginception + 14*86400;

  rrc.d_tag=0;
  if(!getSignerFor(signQName, rrc.d_signer)) {
    cerr<<"No signer known for '"<<signQName<<"'\n";
    return -1;
  }
    
  string hash= getSHA1HashForRRSET(signQName,  rrc, toSign);
  fillOutRRSIG(signQName, rrc, hash, toSign, ksk);
  return 0;
}

void addSignature(const std::string signQName, const std::string& wildcardname, uint16_t signQType, uint32_t signTTL, DNSPacketWriter::Place signPlace, vector<shared_ptr<DNSRecordContent> >& toSign, DNSPacketWriter& pw)
{
  // cerr<<"Asked to sign '"<<signQName<<"'|"<<DNSRecordContent::NumberToType(signQType)<<", "<<toSign.size()<<" records\n";

  RRSIGRecordContent rrc;
  if(toSign.empty())
    return;

  for(int ksk = 0; ksk < 2; ++ksk) {
    if(getRRSIGForRRSET(wildcardname.empty() ? signQName : wildcardname, signQType, signTTL, toSign, rrc, ksk) < 0) {
      cerr<<"Error signing a record!"<<endl;
      return;
    }
    
    pw.startRecord(signQName, QType::RRSIG, 3600, 1, 
		   signQType==QType::DNSKEY ? DNSPacketWriter:: ANSWER : signPlace); 
    rrc.toPacket(pw);
    
    pw.commit();
    if(signQType != QType::DNSKEY)
      break;
  }

  toSign.clear();
}

// XXXX FIXME THINK ABOUT LOCKING HERE
map<pair<string, uint16_t>, RRSIGRecordContent> g_rrsigs;

void fillOutRRSIG(const std::string& signQName, RRSIGRecordContent& rrc, const std::string& hash, vector<shared_ptr<DNSRecordContent> >& toSign, bool withKSK) 
{
  RSAContext rc;

  DNSKEYRecordContent drc=getDNSKEYFor(rrc.d_signer, withKSK, &rc);
  rrc.d_tag = drc.getTag();
  rrc.d_algorithm = drc.d_algorithm;
  
  if(g_rrsigs.count(make_pair(hash, rrc.d_tag))) {
    // cerr<<"RRSIG cache hit !"<<endl;
    rrc = g_rrsigs[make_pair(hash, rrc.d_tag)];
    return;
  }
    
  string realhash=getSHA1HashForRRSET(signQName, rrc, toSign);

  unsigned char signature[mpi_size(&rc.getContext().N)];

  int ret=rsa_pkcs1_sign(&rc.getContext(), RSA_PRIVATE, SIG_RSA_SHA1, 20, (unsigned char*) realhash.c_str(), signature);
  
  if(ret!=0) {
    cerr<<"signing returned: "<<ret<<endl;
    exit(1);
  }
  
  rrc.d_signature.assign((char*)signature, sizeof(signature));
  
  g_rrsigs[make_pair(hash, rrc.d_tag)] = rrc;

}
