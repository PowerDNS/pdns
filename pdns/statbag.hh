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
#ifndef STATBAG_HH
#define STATBAG_HH
#include <pthread.h>
#include <map>
#include <mutex>
#include <functional>
#include <string>
#include <vector>
#include "lock.hh"
#include "namespaces.hh"
#include "iputils.hh"
#include "circular_buffer.hh"



template<typename T, typename Comp=std::less<T> >
class StatRing
{
public:
  StatRing(unsigned int size=10000);
  // Some older C++ libs have trouble emplacing without a copy-contructor, so provide one
  StatRing(const StatRing &);
  StatRing & operator=(const StatRing &) = delete;
  
  void account(const T &item);

  unsigned int getSize();
  void resize(unsigned int newsize);  
  void reset();
  void setHelp(const string &str);
  string getHelp();

  vector<pair<T, unsigned int> > get() const;
private:
  static bool popisort(const pair<T,int> &a, const pair<T,int> &b) 
  {
    return (a.second > b.second);
  }

  boost::circular_buffer<T> d_items;
  mutable std::mutex d_lock;
  string d_help;
};


//! use this to gather and query statistics
class StatBag
{
  map<string, std::unique_ptr<AtomicCounter>> d_stats;
  map<string, string> d_keyDescrips;
  map<string,StatRing<string, CIStringCompare> >d_rings;
  map<string,StatRing<SComboAddress> >d_comborings;
  map<string,StatRing<std::tuple<DNSName, QType> > >d_dnsnameqtyperings;
  typedef boost::function<uint64_t(const std::string&)> func_t;
  typedef map<string, func_t> funcstats_t;
  funcstats_t d_funcstats;
  bool d_doRings;
  std::set<string> d_blacklist;

public:
  StatBag(); //!< Naked constructor. You need to declare keys before this class becomes useful
  ~StatBag();
  void declare(const string &key, const string &descrip=""); //!< Before you can store or access a key, you need to declare it
  void declare(const string &key, const string &descrip, func_t func); //!< Before you can store or access a key, you need to declare it

  void declareRing(const string &name, const string &title, unsigned int size=10000);
  void declareComboRing(const string &name, const string &help, unsigned int size=10000);
  void declareDNSNameQTypeRing(const string &name, const string &help, unsigned int size=10000);
  vector<pair<string, unsigned int> >getRing(const string &name);
  string getRingTitle(const string &name);
  void ringAccount(const char* name, const string &item)
  {
    if(d_doRings)  {
      if(!d_rings.count(name))
	throw runtime_error("Attempting to account to non-existent ring '"+std::string(name)+"'");

      d_rings[name].account(item);
    }
  }
  void ringAccount(const char* name, const ComboAddress &item)
  {
    if(d_doRings) {
      if(!d_comborings.count(name))
	throw runtime_error("Attempting to account to non-existent comboring '"+std::string(name)+"'");
      d_comborings[name].account(item);
    }
  }
  void ringAccount(const char* name, const DNSName &dnsname, const QType &qtype)
  {
    if(d_doRings) {
      if(!d_dnsnameqtyperings.count(name))
	throw runtime_error("Attempting to account to non-existent dnsname+qtype ring '"+std::string(name)+"'");
      d_dnsnameqtyperings[name].account(std::make_tuple(dnsname, qtype));
    }
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
  void set(const string &key, unsigned long value); //!< set this key's value
  unsigned long read(const string &key); //!< read the value behind this key
  unsigned long readZero(const string &key); //!< read the value behind this key, and zero it afterwards
  AtomicCounter *getPointer(const string &key); //!< get a direct pointer to the value behind a key. Use this for high performance increments
  string getValueStr(const string &key); //!< read a value behind a key, and return it as a string
  string getValueStrZero(const string &key); //!< read a value behind a key, and return it as a string, and zero afterwards
  void blacklist(const string &str);
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
