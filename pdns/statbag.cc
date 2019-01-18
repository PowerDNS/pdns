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
#include "arguments.hh"
#include "lock.hh"
#include "iputils.hh"


#include "namespaces.hh"

StatBag::StatBag()
{
  d_doRings=false;
}

void StatBag::exists(const string &key)
{
  if(!d_keyDescrips.count(key))
    {
      throw PDNSException("Trying to deposit into unknown StatBag key '"+key+"'");
    }
}

string StatBag::directory()
{
  string dir;
  ostringstream o;

  for(const auto& i: d_stats) {
    o<<i.first<<"="<<*(i.second)<<",";
  }


  for(const funcstats_t::value_type& val :  d_funcstats) {
    o << val.first<<"="<<val.second(val.first)<<",";
  }
  dir=o.str();
  return dir;
}


vector<string>StatBag::getEntries()
{
  vector<string> ret;

  for(const auto& i: d_stats) {
      ret.push_back(i.first);
  }

  for(const funcstats_t::value_type& val :  d_funcstats) {
    ret.push_back(val.first);
  }


  return ret;

}

string StatBag::getDescrip(const string &item)
{
  exists(item);
  return d_keyDescrips[item];
}

void StatBag::declare(const string &key, const string &descrip)
{
  AtomicCounter *i=new AtomicCounter(0);
  d_stats[key]=i;
  d_keyDescrips[key]=descrip;
}

void StatBag::declare(const string &key, const string &descrip, StatBag::func_t func)
{

  d_funcstats[key]=func;
  d_keyDescrips[key]=descrip;
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
  if(iter != d_funcstats.end())
    return iter->second(iter->first);
  return *d_stats[key];
}

unsigned long StatBag::readZero(const string &key)
{
  exists(key);
  unsigned long tmp=*d_stats[key];
  d_stats[key]=0;
  return tmp;
}


string StatBag::getValueStr(const string &key)
{
  ostringstream o;
  o<<read(key);
  return o.str();
}

string StatBag::getValueStrZero(const string &key)
{
  ostringstream o;
  o<<readZero(key);
  return o.str();
}

AtomicCounter *StatBag::getPointer(const string &key)
{
  exists(key);
  return d_stats[key];
}

StatBag::~StatBag()
{
  for(const auto& i: d_stats) {
    delete i.second;
  }
  
}

template<typename T, typename Comp>
StatRing<T,Comp>::StatRing(unsigned int size)
{
  d_items.set_capacity(size);
  pthread_mutex_init(&d_lock, 0);
}

template<typename T, typename Comp>
void StatRing<T,Comp>::account(const T& t)
{
  Lock l(&d_lock);
  d_items.push_back(t);
}

template<typename T, typename Comp>
unsigned int StatRing<T,Comp>::getSize()
{
  Lock l(&d_lock);
  return d_items.capacity();
}

template<typename T, typename Comp>
void StatRing<T,Comp>::resize(unsigned int newsize)
{
  Lock l(&d_lock);
  d_items.set_capacity(newsize);
}


template<typename T, typename Comp>
void StatRing<T,Comp>::setHelp(const string &str)
{
  d_help=str;
}

template<typename T, typename Comp>
string StatRing<T,Comp>::getHelp()
{
  return d_help;
}


template<typename T, typename Comp>
vector<pair<T, unsigned int> >StatRing<T,Comp>::get() const
{
  Lock l(&d_lock);
  map<T,unsigned int, Comp> res;
  for(typename boost::circular_buffer<T>::const_iterator i=d_items.begin();i!=d_items.end();++i) {
    res[*i]++;
  }
  
  vector<pair<T ,unsigned int> > tmp;
  for(typename map<T, unsigned int>::const_iterator i=res.begin();i!=res.end();++i) 
    tmp.push_back(*i);

  sort(tmp.begin(),tmp.end(),popisort);

  return tmp;
}

void StatBag::declareRing(const string &name, const string &help, unsigned int size)
{
  d_rings[name]=StatRing<string>(size);
  d_rings[name].setHelp(help);
}

void StatBag::declareComboRing(const string &name, const string &help, unsigned int size)
{
  d_comborings[name]=StatRing<SComboAddress>(size);
  d_comborings[name].setHelp(help);
}


vector<pair<string, unsigned int> > StatBag::getRing(const string &name)
{
  if(d_rings.count(name))
    return d_rings[name].get();
  else {
    typedef pair<SComboAddress, unsigned int> stor_t;
    vector<stor_t> raw =d_comborings[name].get();
    vector<pair<string, unsigned int> > ret;
    for(const stor_t& stor :  raw) {
      ret.push_back(make_pair(stor.first.ca.toString(), stor.second));
    }
    return ret;
  }
    
}

template<typename T, typename Comp>
void StatRing<T,Comp>::reset()
{
  Lock l(&d_lock);
  d_items.clear();
}

void StatBag::resetRing(const string &name)
{
  if(d_rings.count(name))
    d_rings[name].reset();
  else
    d_comborings[name].reset();
}

void StatBag::resizeRing(const string &name, unsigned int newsize)
{
  if(d_rings.count(name))
    d_rings[name].resize(newsize);
  else
    d_comborings[name].resize(newsize);
}


unsigned int StatBag::getRingSize(const string &name)
{
  if(d_rings.count(name))
    return d_rings[name].getSize();
  else
    return d_comborings[name].getSize();
}

string StatBag::getRingTitle(const string &name)
{
  if(d_rings.count(name))
    return d_rings[name].getHelp();
  else 
    return d_comborings[name].getHelp();
}

vector<string>StatBag::listRings()
{
  vector<string> ret;
  for(map<string,StatRing<string> >::const_iterator i=d_rings.begin();i!=d_rings.end();++i)
    ret.push_back(i->first);
  for(map<string,StatRing<SComboAddress> >::const_iterator i=d_comborings.begin();i!=d_comborings.end();++i)
    ret.push_back(i->first);

  return ret;
}

bool StatBag::ringExists(const string &name)
{
  return d_rings.count(name) || d_comborings.count(name);
}

template class StatRing<std::string>;
template class StatRing<SComboAddress>;
