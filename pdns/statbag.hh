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
#pragma once
#include <map>
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
  StatRing(const StatRing&) = delete;
  StatRing& operator=(const StatRing&) = delete;
  StatRing& operator=(StatRing&&) = delete;
  StatRing(StatRing&&) = default;
  
  void account(const T &item);

  uint64_t getSize() const;
  uint64_t getEntriesCount() const;
  void resize(unsigned int newsize);  
  void reset();
  void setHelp(const string &str);
  string getHelp() const;

  vector<pair<T, unsigned int> > get() const;
private:
  static bool popisort(const pair<T,int> &a, const pair<T,int> &b) 
  {
    return (a.second > b.second);
  }

  boost::circular_buffer<T> d_items;
  string d_help;
};

enum class StatType : uint8_t {
  counter = 1,
  gauge = 2,
};

//! use this to gather and query statistics
class StatBag
{
  map<string, std::unique_ptr<AtomicCounter>> d_stats;
  map<string, string> d_keyDescriptions;
  map<string, StatType> d_statTypes;
  map<string, LockGuarded<StatRing<string, CIStringCompare> > > d_rings;
  map<string, LockGuarded<StatRing<SComboAddress> > > d_comboRings;
  map<string, LockGuarded<StatRing<std::tuple<DNSName, QType> > > > d_dnsnameqtyperings;
  typedef std::function<uint64_t(const std::string&)> func_t;
  typedef map<string, func_t> funcstats_t;
  funcstats_t d_funcstats;
  bool d_doRings;

  std::set<string> d_blacklist;

  void registerRingStats(const string& name);

public:
  StatBag(); //!< Naked constructor. You need to declare keys before this class becomes useful
  ~StatBag();
  void declare(const string &key, const string &descrip="", StatType statType=StatType::counter); //!< Before you can store or access a key, you need to declare it
  void declare(const string &key, const string &descrip, func_t func, StatType statType); //!< Before you can store or access a key, you need to declare it

  void declareRing(const string &name, const string &title, unsigned int size=10000);
  void declareComboRing(const string &name, const string &help, unsigned int size=10000);
  void declareDNSNameQTypeRing(const string &name, const string &help, unsigned int size=10000);
  vector<pair<string, unsigned int> >getRing(const string &name);
  string getRingTitle(const string &name);
  void ringAccount(const char* name, const string &item)
  {
    if (d_doRings)  {
      auto it = d_rings.find(name);
      if (it == d_rings.end()) {
	throw runtime_error("Attempting to account to nonexistent ring '"+std::string(name)+"'");
      }

      it->second.lock()->account(item);
    }
  }
  void ringAccount(const char* name, const ComboAddress &item)
  {
    if (d_doRings) {
      auto it = d_comboRings.find(name);
      if (it == d_comboRings.end()) {
	throw runtime_error("Attempting to account to nonexistent comboRing '"+std::string(name)+"'");
      }
      it->second.lock()->account(item);
    }
  }
  void ringAccount(const char* name, const DNSName &dnsname, const QType &qtype)
  {
    if (d_doRings) {
      auto it = d_dnsnameqtyperings.find(name);
      if (it == d_dnsnameqtyperings.end()) {
	throw runtime_error("Attempting to account to nonexistent dnsname+qtype ring '"+std::string(name)+"'");
      }
      it->second.lock()->account(std::make_tuple(dnsname, qtype));
    }
  }

  void doRings()
  {
    d_doRings=true;
  }

  vector<string>listRings() const;
  bool ringExists(const string &name) const;
  void resetRing(const string &name);
  void resizeRing(const string &name, unsigned int newsize);
  uint64_t getRingSize(const string &name);
  uint64_t getRingEntriesCount(const string &name);

  string directory(const string &prefix = ""); //!< Returns a list of all data stored. If prefix is given, only stats named with this prefix are returned.
  vector<string> getEntries(); //!< returns a vector with datums (items)
  string getDescrip(const string &item); //!< Returns the description of this datum/item
  StatType getStatType(const string &item); //!< Returns the stats type for the metrics endpoint
  void exists(const string &key); //!< call this function to throw an exception in case a key does not exist
  inline void deposit(const string &key, int value); //!< increment the statistics behind this key by value amount
  inline void inc(const string &key); //!< increase this key's value by one
  void set(const string &key, unsigned long value); //!< set this key's value
  unsigned long read(const string &key); //!< read the value behind this key
  AtomicCounter *getPointer(const string &key); //!< get a direct pointer to the value behind a key. Use this for high performance increments
  string getValueStr(const string &key); //!< read a value behind a key, and return it as a string
  void blacklist(const string &str);

  bool d_allowRedeclare; // only set this true during tests, never in production code
};

inline void StatBag::deposit(const string &key, int value)
{
  exists(key);

  *d_stats[key]+=value;
}

inline void StatBag::inc(const string &key)
{
  deposit(key, 1);
}
