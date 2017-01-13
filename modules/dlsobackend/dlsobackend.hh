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
#ifndef REMOTEBACKEND_REMOTEBACKEND_HH

#include <sys/types.h>
#include <sys/wait.h>
#include <stdint.h>

#include <string>
#include "pdns/arguments.hh"
#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/dnspacket.hh"
#include "pdns/logger.hh"
#include "pdns/namespaces.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/sstuff.hh"
#include "pdns/ueberbackend.hh"
#include "pdns/lock.hh"

#include "./dlsobackend_api.h"

struct before_after_t;

class DlsoBackend : public DNSBackend
{
public:
  DlsoBackend(const std::string &suffix="");
  ~DlsoBackend();

  //static DNSBackend *maker();

  void lookup(const QType &qtype, const DNSName& qdomain, DNSPacket *pkt_p=0, int zoneId=-1);
  bool get(DNSResourceRecord &rr);
  bool list(const DNSName& target, int domain_id, bool include_disabled=false);

  bool getAllDomainMetadata(const DNSName& name, std::map<std::string, std::vector<std::string> >& meta);
  bool getDomainMetadata(const DNSName& name, const std::string& kind, std::vector<std::string>& meta);
  bool setDomainMetadata(const DNSName& name, const std::string& kind, const std::vector<std::string>& meta);
  bool getDomainKeys(const DNSName& name, std::vector<KeyData>& keys);
  bool removeDomainKey(const DNSName& name, unsigned int id);
  bool addDomainKey(const DNSName& name, const KeyData& key, int64_t& id);
  bool activateDomainKey(const DNSName& name, unsigned int id);
  bool deactivateDomainKey(const DNSName& name, unsigned int id);
  bool getTSIGKey(const DNSName& name, DNSName* algorithm, string* content);
  bool setTSIGKey(const DNSName& name, const DNSName& algorithm, const string& content);
  bool deleteTSIGKey(const DNSName& name);
  bool getTSIGKeys(std::vector< struct TSIGKey > &keys);
  bool doesDNSSEC();

  bool getBeforeAndAfterNamesAbsolute(uint32_t id, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after);

  bool updateDNSSECOrderNameAndAuth(uint32_t domain_id, const DNSName& qname, const DNSName& ordername, bool auth, const uint16_t qtype=QType::ANY);
  bool updateEmptyNonTerminals(uint32_t domain_id, set<DNSName>& insert, set<DNSName>& erase, bool remove);
  bool getDomainInfo(const DNSName &domain, DomainInfo &di);

  bool startTransaction(const DNSName &domain, int domain_id=-1);
  bool commitTransaction();
  bool abortTransaction();

  void getUnfreshSlaveInfos(vector<DomainInfo> *unfreshDomains);
  void setNotified(uint32_t domain_id, uint32_t serial);
  void setFresh(uint32_t domain_id);

  bool replaceRRSet(uint32_t domain_id, const DNSName& qname, const QType& qt, const vector<DNSResourceRecord>& rrset);
  bool feedRecord(const DNSResourceRecord &rr, string *ordername=0);
  bool feedEnts(int domain_id, map<DNSName,bool> &nonterm);
  bool feedEnts3(int domain_id, const DNSName &domain, map<DNSName,bool> &nonterm, const NSEC3PARAMRecordContent& ns3prc, bool narrow);

private:
  int build();
  void * dlhandle;
  struct lib_so_api * api;
  bool d_dnssec;

  bool in_query;
};


#endif
