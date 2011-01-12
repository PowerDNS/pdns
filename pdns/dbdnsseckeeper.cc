/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2001 - 2011  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

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


using namespace boost::assign;
using namespace std;
using namespace boost;

DNSSECKeeper::keycache_t DNSSECKeeper::s_keycache;
DNSSECKeeper::nseccache_t DNSSECKeeper::s_nseccache;
pthread_mutex_t DNSSECKeeper::s_nseccachelock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t DNSSECKeeper::s_keycachelock = PTHREAD_MUTEX_INITIALIZER;

bool DNSSECKeeper::haveActiveKSKFor(const std::string& zone) 
{
  {
    Lock l(&s_keycachelock);
    keycache_t::const_iterator iter = s_keycache.find(zone);
    if(iter != s_keycache.end() && iter->d_ttd > time(0)) { 
      if(iter->d_keys.empty())
        return false;
      else
        return true;
    }
    else
      ; 
  }
  keyset_t keys = getKeys(zone, true);
  
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
  dpk.d_flags = keyOrZone ? 257 : 256;
  addKey(name, dpk, active);
}

void DNSSECKeeper::addKey(const std::string& name, const DNSSECPrivateKey& dpk, bool active)
{
  DNSBackend::KeyData kd;
  kd.flags = dpk.d_flags; // the dpk doesn't get stored, only they key part
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
  time_t now = time(0);
  {
    Lock l(&s_nseccachelock); 
    
    nseccache_t::const_iterator iter = s_nseccache.find(zname);
    if(iter != s_nseccache.end() && iter->d_ttd > now)
    {
      if(iter->d_nsec3param.empty()) // this says: no NSEC3
        return false;
        
      if(ns3p) {
        NSEC3PARAMRecordContent* tmp=dynamic_cast<NSEC3PARAMRecordContent*>(DNSRecordContent::mastermake(QType::NSEC3PARAM, 1, iter->d_nsec3param));
        *ns3p = *tmp;
        delete tmp;
      }
      if(narrow)
        *narrow = iter->d_narrow;
      return true;
    }
  }
  vector<string> meta;
  d_db.getDomainMetadata(zname, "NSEC3PARAM", meta);
  
  NSECCacheEntry nce;
  nce.d_domain=zname;
  nce.d_ttd = now+60;
  
  if(meta.empty()) {
    nce.d_nsec3param.clear(); // store 'no nsec3'
    nce.d_narrow = false;
    Lock l(&s_nseccachelock);
    replacing_insert(s_nseccache, nce);
    
    return false;
  }
  nce.d_nsec3param = *meta.begin();
  
  meta.clear();
  d_db.getDomainMetadata(zname, "NSEC3NARROW", meta);
  nce.d_narrow = !meta.empty() && meta[1]=="1";
  
  if(narrow) {
    *narrow=nce.d_narrow;
  }
  
  if(ns3p) {
    string descr = nce.d_nsec3param;
    reportAllTypes();
    NSEC3PARAMRecordContent* tmp=dynamic_cast<NSEC3PARAMRecordContent*>(DNSRecordContent::mastermake(QType::NSEC3PARAM, 1, descr));
    if(!tmp) {
      cerr<<"descr: '"<<descr<<"'\n";
      return false;
    }
    *ns3p = *tmp;
    delete tmp;
  }
  Lock l(&s_nseccachelock);
  replacing_insert(s_nseccache, nce);
  
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
  time_t now = time(0);
  {
    Lock l(&s_keycachelock);
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
  
  d_db.getDomainKeys(zone, 0, dbkeyset);
  
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
      retkeyset.push_back(make_pair(dpk, kmd));
    allkeyset.push_back(make_pair(dpk, kmd));
  }
  sort(retkeyset.begin(), retkeyset.end(), keyCompareByKindAndID);
  sort(allkeyset.begin(), allkeyset.end(), keyCompareByKindAndID);
  Lock l(&s_keycachelock);
  
  KeyCacheEntry kce;
  kce.d_domain=zone;
  kce.d_keys = allkeyset;
  kce.d_ttd = now + 30;
  replacing_insert(s_keycache, kce);
  
  return retkeyset;
}

void DNSSECKeeper::secureZone(const std::string& name, int algorithm)
{
  addKey(name, true, algorithm);
}
