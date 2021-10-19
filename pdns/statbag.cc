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
#include "utility.hh"
#include "statbag.hh"
#include "pdnsexception.hh"
#include <iostream>
#include <sstream>
#include <algorithm>
#include <utility>
#include "arguments.hh"
#include "lock.hh"
#include "iputils.hh"


#include "namespaces.hh"

StatBag::StatBag()
{
  d_doRings=false;
  d_allowRedeclare=false;
}

void StatBag::exists(const string &key)
{
  if (!d_keyDescriptions.count(key)) {
    throw PDNSException("Trying to deposit into unknown StatBag key '"+key+"'");
  }
}

string StatBag::directory(const string &prefix)
{
  string dir;
  ostringstream o;

  for(const auto& val : d_stats) {
    if (d_blacklist.find(val.first) != d_blacklist.end())
      continue;
    if (val.first.find(prefix) != 0)
      continue;
    o << val.first<<"="<<*(val.second)<<",";
  }


  for(const funcstats_t::value_type& val :  d_funcstats) {
    if (d_blacklist.find(val.first) != d_blacklist.end())
      continue;
    if (val.first.find(prefix) != 0)
      continue;
    o << val.first<<"="<<val.second(val.first)<<",";
  }
  dir=o.str();
  return dir;
}

vector<string>StatBag::getEntries()
{
  vector<string> ret;

  for(const auto& i: d_stats) {
    if (d_blacklist.find(i.first) != d_blacklist.end())
      continue;
    ret.push_back(i.first);
  }

  for(const funcstats_t::value_type& val :  d_funcstats) {
    if (d_blacklist.find(val.first) != d_blacklist.end())
      continue;
    ret.push_back(val.first);
  }


  return ret;

}

string StatBag::getDescrip(const string &item)
{
  exists(item);
  return d_keyDescriptions[item];
}

StatType StatBag::getStatType(const string &item)
{
  exists(item);
  return d_statTypes[item];
}

void StatBag::declare(const string &key, const string &descrip, StatType statType)
{
  if(d_stats.count(key)) {
    if (d_allowRedeclare) {
      *d_stats[key] = 0;
      return;
    }
    else {
      throw PDNSException("Attempt to re-declare statbag '"+key+"'");
    }
  }

  auto i=make_unique<AtomicCounter>(0);
  d_stats[key]=std::move(i);
  d_keyDescriptions[key]=descrip;
  d_statTypes[key]=statType;
}

void StatBag::declare(const string &key, const string &descrip, StatBag::func_t func, StatType statType)
{
  if(d_funcstats.count(key) && !d_allowRedeclare) {
    throw PDNSException("Attempt to re-declare func statbag '"+key+"'");
  }

  d_funcstats[key]=std::move(func);
  d_keyDescriptions[key]=descrip;
  d_statTypes[key]=statType;
}

          
void StatBag::set(const string &key, unsigned long value)
{
  exists(key);
  d_stats[key]->store(value);
}

unsigned long StatBag::read(const string &key)
{
  exists(key);
  funcstats_t::const_iterator iter = d_funcstats.find(key);
  if (iter != d_funcstats.end()) {
    return iter->second(iter->first);
  }
  return *d_stats[key];
}

string StatBag::getValueStr(const string &key)
{
  ostringstream o;
  o<<read(key);
  return o.str();
}

AtomicCounter *StatBag::getPointer(const string &key)
{
  exists(key);
  return d_stats[key].get();
}

StatBag::~StatBag()
{
}

template<typename T, typename Comp>
StatRing<T,Comp>::StatRing(unsigned int size)
{
  d_items.set_capacity(size);
}

template<typename T, typename Comp>
void StatRing<T,Comp>::account(const T& t)
{
  d_items.push_back(t);
}

template<typename T, typename Comp>
uint64_t StatRing<T,Comp>::getSize() const
{
  return d_items.capacity();
}

template<typename T, typename Comp>
uint64_t StatRing<T,Comp>::getEntriesCount() const
{
  return d_items.size();
}

template<typename T, typename Comp>
void StatRing<T,Comp>::resize(unsigned int newsize)
{
  d_items.set_capacity(newsize);
}

template<typename T, typename Comp>
void StatRing<T,Comp>::setHelp(const string &str)
{
  d_help = str;
}

template<typename T, typename Comp>
string StatRing<T,Comp>::getHelp() const
{
  return d_help;
}


template<typename T, typename Comp>
vector<pair<T, unsigned int> >StatRing<T,Comp>::get() const
{
  map<T,unsigned int, Comp> res;
  for (typename boost::circular_buffer<T>::const_iterator i = d_items.begin(); i != d_items.end(); ++i) {
    res[*i]++;
  }
  
  vector<pair<T ,unsigned int> > tmp;
  for(typename map<T, unsigned int>::const_iterator i=res.begin();i!=res.end();++i) 
    tmp.push_back(*i);

  sort(tmp.begin(),tmp.end(),popisort);

  return tmp;
}

void StatBag::registerRingStats(const string& name)
{
  declare("ring-" + name + "-size", "Number of entries in the " + name + " ring", [this,name](const std::string&) { return static_cast<uint64_t>(getRingEntriesCount(name)); }, StatType::gauge);
  declare("ring-" + name + "-capacity", "Maximum number of entries in the " + name + " ring", [this,name](const std::string&) { return static_cast<uint64_t>(getRingSize(name)); }, StatType::gauge);
}

void StatBag::declareRing(const string &name, const string &help, unsigned int size)
{
  d_rings.emplace(name, size);
  d_rings[name].lock()->setHelp(help);
  registerRingStats(name);
}

void StatBag::declareComboRing(const string &name, const string &help, unsigned int size)
{
  d_comboRings.emplace(name, size);
  d_comboRings[name].lock()->setHelp(help);
  registerRingStats(name);
}

void StatBag::declareDNSNameQTypeRing(const string &name, const string &help, unsigned int size)
{
  d_dnsnameqtyperings.emplace(name, size);
  d_dnsnameqtyperings[name].lock()->setHelp(help);
  registerRingStats(name);
}

vector<pair<string, unsigned int> > StatBag::getRing(const string &name)
{
  if (d_rings.count(name)) {
    return d_rings[name].lock()->get();
  }
  vector<pair<string, unsigned int> > ret;

  if (d_comboRings.count(name)) {
    typedef pair<SComboAddress, unsigned int> stor_t;
    vector<stor_t> raw =d_comboRings[name].lock()->get();
    for(const stor_t& stor :  raw) {
      ret.emplace_back(stor.first.ca.toString(), stor.second);
    }
  } else if (d_dnsnameqtyperings.count(name)) {
    auto raw = d_dnsnameqtyperings[name].lock()->get();
    for (auto const &e : raw) {
      ret.emplace_back(std::get<0>(e.first).toLogString() + "/" + std::get<1>(e.first).toString(), e.second);
    }
  }
  return ret;
}

template<typename T, typename Comp>
void StatRing<T,Comp>::reset()
{
  d_items.clear();
}

void StatBag::resetRing(const string &name)
{
  if(d_rings.count(name))
    d_rings[name].lock()->reset();
  if(d_comboRings.count(name))
    d_comboRings[name].lock()->reset();
  if(d_dnsnameqtyperings.count(name))
    d_dnsnameqtyperings[name].lock()->reset();
}

void StatBag::resizeRing(const string &name, unsigned int newsize)
{
  if(d_rings.count(name))
    d_rings[name].lock()->resize(newsize);
  if(d_comboRings.count(name))
    d_comboRings[name].lock()->resize(newsize);
  if(d_dnsnameqtyperings.count(name))
    return d_dnsnameqtyperings[name].lock()->resize(newsize);
}


uint64_t StatBag::getRingSize(const string &name)
{
  if(d_rings.count(name))
    return d_rings[name].lock()->getSize();
  if(d_comboRings.count(name))
    return d_comboRings[name].lock()->getSize();
  if(d_dnsnameqtyperings.count(name))
    return d_dnsnameqtyperings[name].lock()->getSize();
  return 0;
}

uint64_t StatBag::getRingEntriesCount(const string &name)
{
  if(d_rings.count(name))
    return d_rings[name].lock()->getEntriesCount();
  if(d_comboRings.count(name))
    return d_comboRings[name].lock()->getEntriesCount();
  if(d_dnsnameqtyperings.count(name))
    return d_dnsnameqtyperings[name].lock()->getEntriesCount();
  return 0;
}

string StatBag::getRingTitle(const string &name)
{
  if(d_rings.count(name))
    return d_rings[name].lock()->getHelp();
  if(d_comboRings.count(name))
    return d_comboRings[name].lock()->getHelp();
  if(d_dnsnameqtyperings.count(name))
    return d_dnsnameqtyperings[name].lock()->getHelp();
  return "";
}

vector<string>StatBag::listRings() const
{
  vector<string> ret;
  for(auto & d_ring : d_rings)
    ret.push_back(d_ring.first);
  for(auto & d_comboRing : d_comboRings)
    ret.push_back(d_comboRing.first);
  for(const auto &i : d_dnsnameqtyperings)
    ret.push_back(i.first);

  return ret;
}

bool StatBag::ringExists(const string &name) const
{
  return d_rings.count(name) || d_comboRings.count(name) || d_dnsnameqtyperings.count(name);
}

void StatBag::blacklist(const string& str) {
  d_blacklist.insert(str);
}

template class StatRing<std::string, CIStringCompare>;
template class StatRing<SComboAddress>;
template class StatRing<std::tuple<DNSName, QType> >;
