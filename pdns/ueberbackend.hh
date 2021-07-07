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
#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <mutex>
#include <condition_variable>

#include <boost/utility.hpp>

#include "dnspacket.hh"
#include "dnsbackend.hh"
#include "lock.hh"
#include "namespaces.hh"

/** This is a very magic backend that allows us to load modules dynamically,
    and query them in order. This is persistent over all UeberBackend instantiations
    across multiple threads. 

    The UeberBackend is transparent for exceptions, which should fall straight through.
*/

class UeberBackend : public boost::noncopyable
{
public:
  UeberBackend(const string &pname="default");
  ~UeberBackend();

  bool superMasterBackend(const string &ip, const DNSName &domain, const vector<DNSResourceRecord>&nsset, string *nameserver, string *account, DNSBackend **db);

  bool superMasterAdd(const string &ip, const string &nameserver, const string &account); 

  /** Tracks all created UeberBackend instances for us. We use this vector to notify
      existing threads of new modules 
  */
  static LockGuarded<vector<UeberBackend *>> d_instances;

  static bool loadmodule(const string &name);
  static bool loadModules(const vector<string>& modules, const string& path);

  static void go(void);

  /** This contains all registered backends. The DynListener modifies this list for us when
      new modules are loaded */
  vector<DNSBackend*> backends; 

  void cleanup();

  //! the very magic handle for UeberBackend questions
  class handle
  {
  public:
    bool get(DNSZoneRecord &dr);
    handle();
    ~handle();

    //! The UeberBackend class where this handle belongs to
    UeberBackend *parent;
    //! The current real backend, which is answering questions
    DNSBackend *d_hinterBackend;

    //! DNSPacket who asked this question
    DNSPacket* pkt_p;
    DNSName qname;

    //! Index of the current backend within the backends vector
    unsigned int i;
    QType qtype;
    int zoneId;

  private:

    static AtomicCounter instances;
  };

  void lookup(const QType &, const DNSName &qdomain, int zoneId, DNSPacket *pkt_p=nullptr);

  /** Determines if we are authoritative for a zone, and at what level */
  bool getAuth(const DNSName &target, const QType &qtype, SOAData* sd, bool cachedOk=true);
  /** Load SOA info from backends, ignoring the cache.*/
  bool getSOAUncached(const DNSName &domain, SOAData &sd);
  bool get(DNSZoneRecord &r);
  void getAllDomains(vector<DomainInfo> *domains, bool include_disabled=false);

  void getUnfreshSlaveInfos(vector<DomainInfo>* domains);
  void getUpdatedMasters(vector<DomainInfo>* domains);
  bool getDomainInfo(const DNSName &domain, DomainInfo &di, bool getSerial=true);
  bool createDomain(const DNSName &domain, const DomainInfo::DomainKind kind, const vector<ComboAddress> &masters, const string &account);
  
  bool doesDNSSEC();
  bool addDomainKey(const DNSName& name, const DNSBackend::KeyData& key, int64_t& id);
  bool getDomainKeys(const DNSName& name, std::vector<DNSBackend::KeyData>& keys);
  bool getAllDomainMetadata(const DNSName& name, std::map<std::string, std::vector<std::string> >& meta);
  bool getDomainMetadata(const DNSName& name, const std::string& kind, std::vector<std::string>& meta);
  bool setDomainMetadata(const DNSName& name, const std::string& kind, const std::vector<std::string>& meta);

  bool removeDomainKey(const DNSName& name, unsigned int id);
  bool activateDomainKey(const DNSName& name, unsigned int id);
  bool deactivateDomainKey(const DNSName& name, unsigned int id);
  bool publishDomainKey(const DNSName& name, unsigned int id);
  bool unpublishDomainKey(const DNSName& name, unsigned int id);

  bool getTSIGKey(const DNSName& name, DNSName* algorithm, string* content);
  bool setTSIGKey(const DNSName& name, const DNSName& algorithm, const string& content);
  bool deleteTSIGKey(const DNSName& name);
  bool getTSIGKeys(std::vector< struct TSIGKey > &keys);

  void alsoNotifies(const DNSName &domain, set<string> *ips); 
  void rediscover(string* status=0);
  void reload();
  bool searchRecords(const string &pattern, int maxResults, vector<DNSResourceRecord>& result);
  bool searchComments(const string &pattern, int maxResults, vector<Comment>& result);

  void updateZoneCache();

  bool inTransaction();
private:
  handle d_handle;
  vector<DNSZoneRecord> d_answers;
  vector<DNSZoneRecord>::const_iterator d_cachehandleiter;

  static std::mutex d_mut;
  static std::condition_variable d_cond;

  struct Question
  {
    DNSName qname;
    int zoneId;
    QType qtype;
  }d_question;

  unsigned int d_cache_ttl, d_negcache_ttl;
  uint16_t d_qtype;

  bool d_negcached;
  bool d_cached;
  static AtomicCounter* s_backendQueries;
  static bool d_go;
  bool d_stale;
  static bool s_doANYLookupsOnly;

  int cacheHas(const Question &q, vector<DNSZoneRecord> &rrs);
  void addNegCache(const Question &q);
  void addCache(const Question &q, vector<DNSZoneRecord>&& rrs);
};
