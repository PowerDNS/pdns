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
