/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation

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

#include "utility.hh"
#include "statbag.hh"
#include "pdnsexception.hh"
#include <iostream>
#include <sstream>
#include <algorithm>
#include "arguments.hh"
#include "lock.hh"
#include <boost/foreach.hpp>

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

  for(map<string, AtomicCounter *>::const_iterator i=d_stats.begin();
      i!=d_stats.end();
      i++)
    {
      o<<i->first<<"="<<*(i->second)<<",";
    }


  BOOST_FOREACH(const funcstats_t::value_type& val, d_funcstats) {
    o << val.first<<"="<<val.second(val.first)<<",";
  }
  dir=o.str();
  return dir;
}


vector<string>StatBag::getEntries()
{
  vector<string> ret;

  for(map<string, AtomicCounter *>::const_iterator i=d_stats.begin();
      i!=d_stats.end();
      i++)
      ret.push_back(i->first);

  BOOST_FOREACH(const funcstats_t::value_type& val, d_funcstats) {
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

          
void StatBag::set(const string &key, AtomicCounter::native_t value)
{
  exists(key);
  *d_stats[key]=AtomicCounter(value);
}

AtomicCounter::native_t StatBag::read(const string &key)
{
  exists(key);
  funcstats_t::const_iterator iter = d_funcstats.find(key);
  if(iter != d_funcstats.end())
    return iter->second(iter->first);
  return *d_stats[key];
}

AtomicCounter::native_t StatBag::readZero(const string &key)
{
  exists(key);
  AtomicCounter::native_t tmp=*d_stats[key];
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
  for(map<string, AtomicCounter *>::const_iterator i=d_stats.begin();
      i!=d_stats.end();
      i++)
    {
      delete i->second;
    }
  
}

StatRing::StatRing(unsigned int size)
{
  d_size=size;
  d_items.resize(d_size);
  d_lock=0;
  d_pos=0;
  d_lock=new pthread_mutex_t;
  pthread_mutex_init(d_lock, 0);
}

void StatRing::resize(unsigned int newsize)
{
  if(d_size==newsize)
    return;
  Lock l(d_lock);

  // this is the hard part, shrink
  if(newsize<d_size) {
    unsigned int startpos=0;
    if (d_pos>newsize)
      startpos=d_pos-newsize;

    vector<string>newring;
    for(unsigned int i=startpos;i<d_pos;++i) {
      newring.push_back(d_items[i%d_size]);
    }

    d_items=newring;
    d_size=newring.size();
    d_pos=min(d_pos,newsize);
  }

  if(newsize>d_size) {
    d_size=newsize;
    d_items.resize(d_size);
  }
}

StatRing::~StatRing()
{
  // do not clean up d_lock, it is shared
}

void StatRing::setHelp(const string &str)
{
  d_help=str;
}

string StatRing::getHelp()
{
  return d_help;
}

static bool popisort(const pair<string,int> &a, const pair<string,int> &b)
{
  return (a.second > b.second);
}

vector<pair<string,unsigned int> >StatRing::get() const
{
  Lock l(d_lock);
  map<string,unsigned int> res;
  for(vector<string>::const_iterator i=d_items.begin();i!=d_items.end();++i) {
    if(!i->empty())
      res[*i]++;
  }
  
  vector<pair<string,unsigned int> > tmp;
  for(map<string,unsigned int>::const_iterator i=res.begin();i!=res.end();++i) 
    tmp.push_back(*i);

  sort(tmp.begin(),tmp.end(),popisort);

  return tmp;
}

void StatBag::declareRing(const string &name, const string &help, unsigned int size)
{
  d_rings[name]=StatRing(size);
  d_rings[name].setHelp(help);
}

vector<pair<string, unsigned int> > StatBag::getRing(const string &name)
{
  return d_rings[name].get();
}

void StatRing::reset()
{
  Lock l(d_lock);
  for(vector<string>::iterator i=d_items.begin();i!=d_items.end();++i) {
    if(!i->empty())
      *i="";
  }
}

void StatBag::resetRing(const string &name)
{
  d_rings[name].reset();
}

void StatBag::resizeRing(const string &name, unsigned int newsize)
{
  d_rings[name].resize(newsize);
}


unsigned int StatBag::getRingSize(const string &name)
{
  return d_rings[name].getSize();
}


string StatBag::getRingTitle(const string &name)
{
  return d_rings[name].getHelp();
}

vector<string>StatBag::listRings()
{
  vector<string> ret;
  for(map<string,StatRing>::const_iterator i=d_rings.begin();i!=d_rings.end();++i)
    ret.push_back(i->first);
  return ret;
}

bool StatBag::ringExists(const string &name)
{
  return d_rings.count(name);
}
