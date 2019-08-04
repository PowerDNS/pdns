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
#ifndef PACKETHANDLER_HH
#define PACKETHANDLER_HH

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ueberbackend.hh"
#include "dnspacket.hh"
#include "packetcache.hh"
#include "dnsseckeeper.hh"
#include "lua-auth4.hh"
#include "gss_context.hh"

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

  int trySuperMasterSynchronous(const DNSPacket& p, const DNSName& tsigkeyname);
  static NetmaskGroup s_allowNotifyFrom;
  static set<string> s_forwardNotify;

private:
  int trySuperMaster(const DNSPacket& p, const DNSName& tsigkeyname);
  int processNotify(const DNSPacket& );
  void addRootReferral(DNSPacket& r);
  int doChaosRequest(const DNSPacket& p, std::unique_ptr<DNSPacket>& r, DNSName &target) const;
  bool addDNSKEY(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const SOAData& sd);
  bool addCDNSKEY(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const SOAData& sd);
  bool addCDS(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const SOAData& sd);
  bool addNSEC3PARAM(const DNSPacket& p, std::unique_ptr<DNSPacket>& r, const SOAData& sd);
  int doAdditionalProcessingAndDropAA(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const SOAData& sd, bool retargeted);
  void addNSECX(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const DNSName &target, const DNSName &wildcard, const DNSName &auth, int mode);
  void addNSEC(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const DNSName &target, const DNSName &wildcard, const DNSName& auth, int mode);
  void addNSEC3(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const DNSName &target, const DNSName &wildcard, const DNSName& auth, const NSEC3PARAMRecordContent& nsec3param, bool narrow, int mode);
  void emitNSEC(std::unique_ptr<DNSPacket>& r, const SOAData& sd, const DNSName& name, const DNSName& next, int mode);
  void emitNSEC3(std::unique_ptr<DNSPacket>& r, const SOAData& sd, const NSEC3PARAMRecordContent &ns3rc, const DNSName& unhashed, const string& begin, const string& end, int mode);
  int processUpdate(DNSPacket& p);
  int forwardPacket(const string &msgPrefix, const DNSPacket& p, const DomainInfo& di);
  uint performUpdate(const string &msgPrefix, const DNSRecord *rr, DomainInfo *di, bool isPresigned, bool* narrow, bool* haveNSEC3, NSEC3PARAMRecordContent *ns3pr, bool *updatedSerial);
  int checkUpdatePrescan(const DNSRecord *rr);
  int checkUpdatePrerequisites(const DNSRecord *rr, DomainInfo *di);
  void increaseSerial(const string &msgPrefix, const DomainInfo *di, bool haveNSEC3, bool narrow, const NSEC3PARAMRecordContent *ns3pr);

  void makeNXDomain(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const DNSName& target, const DNSName& wildcard, const SOAData& sd);
  void makeNOError(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const DNSName& target, const DNSName& wildcard, const SOAData& sd, int mode);
  vector<DNSZoneRecord> getBestReferralNS(DNSPacket& p, const SOAData& sd, const DNSName &target);
  vector<DNSZoneRecord> getBestDNAMESynth(DNSPacket& p, const SOAData& sd, DNSName &target);
  bool tryDNAME(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const SOAData& sd, DNSName &target);
  bool tryReferral(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const SOAData& sd, const DNSName &target, bool retargeted);

  bool getBestWildcard(DNSPacket& p, const SOAData& sd, const DNSName &target, DNSName &wildcard, vector<DNSZoneRecord>* ret);
  bool tryWildcard(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const SOAData& sd, DNSName &target, DNSName &wildcard, bool& retargeted, bool& nodata);
  bool addDSforNS(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const SOAData& sd, const DNSName& dsname);
  void completeANYRecords(DNSPacket& p, std::unique_ptr<DNSPacket>& r, const SOAData& sd, const DNSName &target);

  void tkeyHandler(const DNSPacket& p, std::unique_ptr<DNSPacket>& r); //<! process TKEY record, and adds TKEY record to (r)eply, or error code.

  static AtomicCounter s_count;
  static pthread_mutex_t s_rfc2136lock;
  bool d_logDNSDetails;
  bool d_doIPv6AdditionalProcessing;
  bool d_doDNAME;
  bool d_doExpandALIAS;
  bool d_dnssec;
  std::unique_ptr<AuthLua4> d_pdl;
  std::unique_ptr<AuthLua4> d_update_policy_lua;

  UeberBackend B; // every thread an own instance
  DNSSECKeeper d_dk; // B is shared with DNSSECKeeper
};

std::shared_ptr<DNSRecordContent> makeSOAContent(const SOAData& sd);
#endif /* PACKETHANDLER */
