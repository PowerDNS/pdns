/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2014  PowerDNS.COM BV

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
  map<string, AtomicCounter *> d_stats;
  map<string, string> d_keyDescrips;
  map<string,StatRing>d_rings;
  typedef boost::function<uint64_t(const std::string&)> func_t;
  typedef map<string, func_t> funcstats_t;
  funcstats_t d_funcstats;
  bool d_doRings;

public:
  StatBag(); //!< Naked constructor. You need to declare keys before this class becomes useful
  ~StatBag();
  void declare(const string &key, const string &descrip=""); //!< Before you can store or access a key, you need to declare it
  void declare(const string &key, const string &descrip, func_t func); //!< Before you can store or access a key, you need to declare it

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
  bool ringExists(const string &name);
  void resetRing(const string &name);
  void resizeRing(const string &name, unsigned int newsize);
  unsigned int getRingSize(const string &name);

  string directory(); //!< Returns a list of all data stored
  vector<string> getEntries(); //!< returns a vector with datums (items)
  string getDescrip(const string &item); //!< Returns the description of this datum/item
  void exists(const string &key); //!< call this function to throw an exception in case a key does not exist
  inline void deposit(const string &key, int value); //!< increment the statistics behind this key by value amount
  inline void inc(const string &key); //!< increase this key's value by one
  void set(const string &key, AtomicCounter::native_t value); //!< set this key's value
  AtomicCounter::native_t read(const string &key); //!< read the value behind this key
  AtomicCounter::native_t readZero(const string &key); //!< read the value behind this key, and zero it afterwards
  AtomicCounter *getPointer(const string &key); //!< get a direct pointer to the value behind a key. Use this for high performance increments
  string getValueStr(const string &key); //!< read a value behind a key, and return it as a string
  string getValueStrZero(const string &key); //!< read a value behind a key, and return it as a string, and zero afterwards
};

inline void StatBag::deposit(const string &key, int value)
{
  exists(key);

  *d_stats[key]+=value;
}

inline void StatBag::inc(const string &key)
{
  deposit(key,1);
}


#endif /* STATBAG_HH */
