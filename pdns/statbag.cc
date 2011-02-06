/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2
    as published by the Free Software Foundation
    

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
#include "ahuexception.hh"
#include <iostream>
#include <sstream>
#include <algorithm>
#include "arguments.hh"
#include "lock.hh"

#include "namespaces.hh"

StatBag::StatBag()
{
  d_doRings=false;
  pthread_mutex_init(&d_lock,0);
}



/** this NEEDS TO HAVE THE LOCK held already! */
void StatBag::exists(const string &key)
{
  if(!d_stats.count(key))
    {
      unlock(); // it's the details that count
      throw AhuException("Trying to deposit into unknown StatBag key '"+key+"'");
    }
}

string StatBag::directory()
{
  string dir;
  ostringstream o;
  lock();
  for(map<string, unsigned int *>::const_iterator i=d_stats.begin();
      i!=d_stats.end();
      i++)
    {
      o<<i->first<<"="<<*(i->second)<<",";
    }
  unlock();
  dir=o.str();
  return dir;
}


vector<string>StatBag::getEntries()
{
  vector<string> ret;
  lock();
  for(map<string, unsigned int *>::const_iterator i=d_stats.begin();
      i!=d_stats.end();
      i++)
      ret.push_back(i->first);

  unlock();
  return ret;

}

string StatBag::getDescrip(const string &item)
{
  lock();
  string tmp=d_keyDescrips[item];
  unlock();
  return tmp;
}

void StatBag::declare(const string &key, const string &descrip)
{
  lock();
  unsigned int *i=new unsigned int(0);
  d_stats[key]=i;
  d_keyDescrips[key]=descrip;
  unlock();
}


          
void StatBag::set(const string &key, int value)
{
  lock();
  exists(key);
  *d_stats[key]=value;

  unlock();
}

int StatBag::read(const string &key)
{
  lock();

  if(!d_stats.count(key))
    {
      unlock();
      return 0;
    }

  int tmp=*d_stats[key];

  unlock();
  return tmp;

}

int StatBag::readZero(const string &key)
{
  lock();


  if(!d_stats.count(key))
    {
      unlock();
      return 0;
    }

  
  int tmp=*d_stats[key];
  d_stats[key]=0;

  unlock();

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

unsigned int *StatBag::getPointer(const string &key)
{
  exists(key);
  return d_stats[key];
}

StatBag::~StatBag()
{
  for(map<string,unsigned int *>::const_iterator i=d_stats.begin();
      i!=d_stats.end();
      i++)
    {
      delete i->second;
    }
  
}

StatRing::StatRing(int size)
{
  d_size=size;
  d_items.resize(d_size);
  d_lock=0;
  d_pos=0;
  d_lock=new pthread_mutex_t;
  pthread_mutex_init(d_lock, 0);
}

void StatRing::resize(int newsize)
{
  if(d_size==newsize)
    return;
  Lock l(d_lock);

  if(newsize>d_size) {
    d_size=newsize;
    d_items.resize(d_size);
    return;
  }

  // this is the hard part, shrink
  int startpos=d_pos-newsize;
  int rpos;
  vector<string>newring;
  for(int i=startpos;i<d_pos;++i) {
    rpos=i>=0 ? i : i+d_size;

    newring.push_back(d_items[rpos%d_size]);
  }
  d_items=newring;
  d_size=newsize;
  d_pos=d_size-1;

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

vector<pair<string,int> >StatRing::get() const
{
  Lock l(d_lock);
  map<string,int> res;
  for(vector<string>::const_iterator i=d_items.begin();i!=d_items.end();++i) {
    if(!i->empty())
      res[*i]++;
  }
  
  vector<pair<string,int> > tmp;
  for(map<string,int>::const_iterator i=res.begin();i!=res.end();++i) 
    tmp.push_back(*i);

  sort(tmp.begin(),tmp.end(),popisort);

  return tmp;
}

void StatBag::declareRing(const string &name, const string &help, unsigned int size)
{
  d_rings[name]=StatRing(size);
  d_rings[name].setHelp(help);
}

vector<pair<string,int> > StatBag::getRing(const string &name)
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

void StatBag::resizeRing(const string &name, int newsize)
{
  d_rings[name].resize(newsize);
}


int StatBag::getRingSize(const string &name)
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


