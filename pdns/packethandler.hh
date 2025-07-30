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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ueberbackend.hh"
#include "dnspacket.hh"
#include "packetcache.hh"
#include "dnsseckeeper.hh"
#include "lua-auth4.hh"

#include "namespaces.hh"

// silly Solaris people define PC
#undef PC

/** Central DNS logic according to RFC1034. Ask this class a question in the form of a DNSPacket
    and it will return, synchronously, a DNSPacket answer, suitable for 
    sending out over the network. 

    The PacketHandler gives your question to the PacketCache for possible inclusion
    in the cache.

    In order to do so, the PacketHandler contains a reference to the global extern PacketCache PC

    It also contains an UeberBackend instance for answering the subqueries needed to generate
    a complete reply.

*/
class NSEC3PARAMRecordContent;

class PacketHandler
{
public:
  std::unique_ptr<DNSPacket> doQuestion(DNSPacket&); //!< hand us a DNS packet with a question, we give you an answer
  std::unique_ptr<DNSPacket> question(DNSPacket&); //!< hand us a DNS packet with a question, we give you an answer
  PacketHandler(); 
  ~PacketHandler(); // defined in packethandler.cc, and does --count
  static int numRunning(){return s_count;}; //!< Returns the number of running PacketHandlers. Called by Distributor
 
  UeberBackend *getBackend();

  int tryAutoPrimarySynchronous(const DNSPacket& p, const DNSName& tsigkeyname);
  bool checkForCorrectTSIG(const DNSPacket& packet, DNSName* tsigkeyname, string* secret, TSIGRecordContent* tsigContent);
  static NetmaskGroup s_allowNotifyFrom;
  static set<string> s_forwardNotify;
  static bool s_SVCAutohints;
  static const std::shared_ptr<CDNSKEYRecordContent> s_deleteCDNSKEYContent;
  static const std::shared_ptr<CDSRecordContent> s_deleteCDSContent;

private:
  int tryAutoPrimary(const DNSPacket& p, const DNSName& tsigkeyname);
  int processNotify(const DNSPacket& );
  void addRootReferral(DNSPacket& r);
  int doChaosRequest(const DNSPacket& p, std::unique_ptr<DNSPacket>& r, DNSName &target) const;
  bool addDNSKEY(DNSPacket& p, std::unique_ptr<DNSPacket>& r);
  bool addCDNSKEY(DNSPacket& p, std::unique_ptr<DNSPacket>& r, SOAData &sd);
  bool addCDNSKEY(DNSPacket& p, std::unique_ptr<DNSPacket>& r);
  bool addCDS(DNSPacket& p, std::unique_ptr<DNSPacket>& r, SOAData &sd);
  bool addCDS(DNSPacket& p, std::unique_ptr<DNSPacket>& r);
  bool addNSEC3PARAM(const DNSPacket& p, std::unique_ptr<DNSPacket>& r);
  void doAdditionalProcessing(DNSPacket& p, std::unique_ptr<DNSPacket>& r);
  DNSName doAdditionalServiceProcessing(const DNSName &firstTarget, const uint16_t &qtype, std::unique_ptr<DNSPacket>& r, vector<DNSZoneRecord>& extraRecords);

  //! Get all IPv4 or IPv6 addresses (based on |qtype|) for |target|.
  vector<ComboAddress> getIPAddressFor(const DNSName &target, const uint16_t qtype);
  void addNSECX(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const DNSName &target, const DNSName &wildcard, int mode);
  void addNSEC(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const DNSName &target, const DNSName &wildcard, int mode);
  bool getNSEC3Hashes(bool narrow, const std::string& hashed, bool decrement, DNSName& unhashed, std::string& before, std::string& after, int mode=0);
  void addNSEC3(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const DNSName &target, const DNSName &wildcard, const NSEC3PARAMRecordContent& nsec3param, bool narrow, int mode);
  void emitNSEC(std::unique_ptr<DNSPacket>& r, const DNSName& name, const DNSName& next, int mode);
  void emitNSEC3(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const NSEC3PARAMRecordContent &ns3prc, const DNSName& name, const string& namehash, const string& nexthash, int mode);
  int processUpdate(DNSPacket& p);
  int forwardPacket(const string &msgPrefix, const DNSPacket& p, const DomainInfo& di);
  uint performUpdate(const string &msgPrefix, const DNSRecord *rr, DomainInfo *di, bool isPresigned, bool* narrow, bool* haveNSEC3, NSEC3PARAMRecordContent *ns3pr, bool *updatedSerial);
  int checkUpdatePrescan(const DNSRecord *rr);
  int checkUpdatePrerequisites(const DNSRecord *rr, DomainInfo *di);
  void increaseSerial(const string &msgPrefix, const DomainInfo *di, const string& soaEditSetting, bool haveNSEC3, bool narrow, const NSEC3PARAMRecordContent *ns3pr);

  void makeNXDomain(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const DNSName& target, const DNSName& wildcard);
  void makeNOError(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const DNSName& target, const DNSName& wildcard, int mode);
  vector<DNSZoneRecord> getBestReferralNS(DNSPacket& p, const DNSName &target);
  void getBestDNAMESynth(DNSPacket& p, DNSName &target, vector<DNSZoneRecord> &ret);
  bool tryAuthSignal(DNSPacket& p, std::unique_ptr<DNSPacket>& r, DNSName &target);
  bool tryDNAME(DNSPacket& p, std::unique_ptr<DNSPacket>& r, DNSName &target);
  bool tryReferral(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const DNSName &target, bool retargeted);

  bool getBestWildcard(DNSPacket& p, const DNSName &target, DNSName &wildcard, vector<DNSZoneRecord>* ret);
  bool tryWildcard(DNSPacket& p, std::unique_ptr<DNSPacket>& r, DNSName &target, DNSName &wildcard, bool& retargeted, bool& nodata);
  bool addDSforNS(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const DNSName& dsname);
  void completeANYRecords(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const DNSName &target);

  void tkeyHandler(const DNSPacket& p, std::unique_ptr<DNSPacket>& r); //<! process TKEY record, and adds TKEY record to (r)eply, or error code.

  struct queryState {
    std::unique_ptr<DNSPacket> r{nullptr};
    set<ZoneName> authSet;
    DNSName target;
    bool doSigs{false};
    bool noCache{false};
    bool retargeted{false};
  };
  bool opcodeQueryInner(DNSPacket&, queryState&);
  bool opcodeQueryInner2(DNSPacket&, queryState&, bool);
  std::unique_ptr<DNSPacket> opcodeQuery(DNSPacket&, bool);
  std::unique_ptr<DNSPacket> opcodeNotify(DNSPacket&, bool);
  std::unique_ptr<DNSPacket> opcodeUpdate(DNSPacket&, bool);
  std::unique_ptr<DNSPacket> opcodeNotImplemented(DNSPacket&, bool);

  bool doLuaRecords();
  std::optional<bool> d_doLua;
  // Wrapper around d_dk.isPresigned(d_sd.zonename), caching its result
  bool isPresigned();
  std::optional<bool> d_ispresigned;
  // Wrapper around d_dk.isSecuredZone(d_sd.zonename), caching its result
  bool isSecuredZone();
  std::optional<bool> d_issecuredzone;

  static AtomicCounter s_count;
  static std::mutex s_rfc2136lock;
  bool d_logDNSDetails;
  bool d_doDNAME;
  bool d_doExpandALIAS;
  bool d_doResolveAcrossZones;
  bool d_dnssec{false};
  SOAData d_sd;
  std::unique_ptr<AuthLua4> d_pdl;
  std::unique_ptr<AuthLua4> d_update_policy_lua;
  std::unique_ptr<AuthLua4> s_LUA;
  UeberBackend B; // every thread an own instance
  DNSSECKeeper d_dk; // B is shared with DNSSECKeeper
};

