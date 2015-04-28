/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2011  PowerDNS.COM BV

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
#ifndef PACKETHANDLER_HH
#define PACKETHANDLER_HH

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ueberbackend.hh"
#include "dnspacket.hh"
#include "packetcache.hh"
#include "dnsseckeeper.hh"
#include "lua-auth.hh"

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
  DNSPacket *questionOrRecurse(DNSPacket *, bool* shouldRecurse); //!< hand us a DNS packet with a question, we'll tell you answer, or that you should recurse
  DNSPacket *question(DNSPacket *); //!< hand us a DNS packet with a question, we give you an answer
  PacketHandler(); 
  ~PacketHandler(); // defined in packethandler.cc, and does --count
  static int numRunning(){return s_count;}; //!< Returns the number of running PacketHandlers. Called by Distributor
 
  UeberBackend *getBackend();

  int trySuperMasterSynchronous(DNSPacket *p);
  static NetmaskGroup s_allowNotifyFrom;

private:
  int trySuperMaster(DNSPacket *p);
  int processNotify(DNSPacket *);
  void addRootReferral(DNSPacket *r);
  int doChaosRequest(DNSPacket *p, DNSPacket *r, string &target);
  bool addDNSKEY(DNSPacket *p, DNSPacket *r, const SOAData& sd);
  bool addNSEC3PARAM(DNSPacket *p, DNSPacket *r, const SOAData& sd);
  int doAdditionalProcessingAndDropAA(DNSPacket *p, DNSPacket *r, const SOAData& sd, bool retargeted);
  void addNSECX(DNSPacket *p, DNSPacket* r, const string &target, const string &wildcard, const std::string &auth, int mode);
  void addNSEC(DNSPacket *p, DNSPacket* r, const string &target, const string &wildcard, const std::string& auth, int mode);
  void addNSEC3(DNSPacket *p, DNSPacket* r, const string &target, const string &wildcard, const std::string& auth, const NSEC3PARAMRecordContent& nsec3param, bool narrow, int mode);
  void emitNSEC(const std::string& before, const std::string& after, const std::string& toNSEC, const SOAData& sd, DNSPacket *r, int mode);
  void emitNSEC3(const NSEC3PARAMRecordContent &ns3rc, const SOAData& sd, const std::string& unhashed, const std::string& begin, const std::string& end, const std::string& toNSEC3, DNSPacket *r, int mode);
  int processUpdate(DNSPacket *p);
  int forwardPacket(const string &msgPrefix, DNSPacket *p, DomainInfo *di);
  uint performUpdate(const string &msgPrefix, const DNSRecord *rr, DomainInfo *di, bool isPresigned, bool* narrow, bool* haveNSEC3, NSEC3PARAMRecordContent *ns3pr, bool *updatedSerial);
  int checkUpdatePrescan(const DNSRecord *rr);
  int checkUpdatePrerequisites(const DNSRecord *rr, DomainInfo *di);
  void increaseSerial(const string &msgPrefix, const DomainInfo *di, bool haveNSEC3, bool narrow, const NSEC3PARAMRecordContent *ns3pr);

  void makeNXDomain(DNSPacket* p, DNSPacket* r, const std::string& target, const std::string& wildcard, SOAData& sd);
  void makeNOError(DNSPacket* p, DNSPacket* r, const std::string& target, const std::string& wildcard, SOAData& sd, int mode);
  vector<DNSResourceRecord> getBestReferralNS(DNSPacket *p, SOAData& sd, const string &target);
  vector<DNSResourceRecord> getBestDNAMESynth(DNSPacket *p, SOAData& sd, string &target);
  bool tryDNAME(DNSPacket *p, DNSPacket*r, SOAData& sd, string &target);
  bool tryReferral(DNSPacket *p, DNSPacket*r, SOAData& sd, const string &target, bool retargeted);

  bool getBestWildcard(DNSPacket *p, SOAData& sd, const string &target, string &wildcard, vector<DNSResourceRecord>* ret);
  bool tryWildcard(DNSPacket *p, DNSPacket*r, SOAData& sd, string &target, string &wildcard, bool& retargeted, bool& nodata);
  bool addDSforNS(DNSPacket* p, DNSPacket* r, SOAData& sd, const string& dsname);
  void completeANYRecords(DNSPacket *p, DNSPacket*r, SOAData& sd, const string &target);

  void tkeyHandler(DNSPacket *p, DNSPacket *r);

  static AtomicCounter s_count;
  static pthread_mutex_t s_rfc2136lock;
  bool d_doRecursion;
  bool d_logDNSDetails;
  bool d_doIPv6AdditionalProcessing;
  bool d_doDNAME;
  int d_sendRootReferral;
  AuthLua* d_pdl;

  UeberBackend B; // every thread an own instance
  DNSSECKeeper d_dk; // B is shared with DNSSECKeeper
};
bool getNSEC3Hashes(bool narrow, DNSBackend* db, int id, const std::string& hashed, bool decrement, string& unhashed, string& before, string& after, int mode=0);
#endif /* PACKETHANDLER */
