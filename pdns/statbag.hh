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
#ifndef STATBAG_HH
#define STATBAG_HH
#include <pthread.h>
#include <map>
#include <string>
#include <vector>
#include "lock.hh"
#include "namespaces.hh"

class StatRing
{
public:
  StatRing(unsigned int size=10000);
  ~StatRing();
  void account(const string &item)
  {
    Lock l(d_lock);
    d_items[d_pos++ % d_size]=item;
  }


  unsigned int getSize()
  {
    return d_size;
  }
  void resize(unsigned int newsize);  
  void reset();
  void setHelp(const string &str);
  string getHelp();
  vector<pair<string,unsigned int> >get() const;
private:
  unsigned int d_size;
  unsigned int d_pos;
  vector<string> d_items;
  pthread_mutex_t *d_lock;
  string d_help;
};


//! use this to gather and query statistics
class StatBag
{
  map<string, unsigned int *> d_stats;
  map<string, string> d_keyDescrips;
  map<string,StatRing>d_rings;
  bool d_doRings;
  pthread_mutex_t d_lock;

public:
  StatBag(); //!< Naked constructor. You need to declare keys before this class becomes useful
  ~StatBag();
  void declare(const string &key, const string &descrip=""); //!< Before you can store or access a key, you need to declare it

  void declareRing(const string &name, const string &title, unsigned int size=10000);
  vector<pair<string, unsigned int> >getRing(const string &name);
  string getRingTitle(const string &name);
  void ringAccount(const string &name, const string &item)
  {
    if(d_doRings)
      d_rings[name].account(item);
  }
  void doRings()
  {
    d_doRings=true;
  }

  vector<string>listRings();
  void resetRing(const string &name);
  void resizeRing(const string &name, unsigned int newsize);
  unsigned int getRingSize(const string &name);

  string directory(); //!< Returns a list of all data stored
  vector<string> getEntries(); //!< returns a vector with datums (items)
  string getDescrip(const string &item); //!< Returns the description of this datum/item
  void exists(const string &key); //!< call this function to throw an exception in case a key does not exist
  inline void deposit(const string &key, int value); //!< increment the statistics behind this key by value amount
  inline void inc(const string &key); //!< increase this key's value by one
  void set(const string &key, unsigned int value); //!< set this key's value
  unsigned int read(const string &key); //!< read the value behind this key
  unsigned int readZero(const string &key); //!< read the value behind this key, and zero it afterwards
  unsigned int *getPointer(const string &key); //!< get a direct pointer to the value behind a key. Use this for high performance increments
  string getValueStr(const string &key); //!< read a value behind a key, and return it as a string
  string getValueStrZero(const string &key); //!< read a value behind a key, and return it as a string, and zero afterwards

private:
  void lock(){pthread_mutex_lock(&d_lock);}
  void unlock(){pthread_mutex_unlock(&d_lock);}
};

inline void StatBag::deposit(const string &key, int value)
{
  lock();
  exists(key);

  *d_stats[key]+=value;

  unlock();
}

inline void StatBag::inc(const string &key)
{
  deposit(key,1);
}


#endif /* STATBAG_HH */
