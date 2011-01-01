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
 
  DNSBackend::KeyData kd;
  kd.flags = 256 + keyOrZone;
  kd.active = active;
  kd.content = dpk.d_key.convertToISC(algorithm);
 
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
  // XXX
}

void DNSSECKeeper::deactivateKey(const std::string& zname, unsigned int id)
{
  // XX
}

void DNSSECKeeper::activateKey(const std::string& zname, unsigned int id)
{
  // XXX
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
  
  // XXX do db
}

void DNSSECKeeper::unsetNSEC3PARAM(const std::string& zname)
{
  // XXX do db
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
 

