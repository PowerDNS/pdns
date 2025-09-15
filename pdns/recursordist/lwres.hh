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
#include <string>
#include <vector>
#include <sys/types.h>
#include "misc.hh"
#include "iputils.hh"
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "dnsparser.hh"
#include <arpa/inet.h>
#undef res_mkquery

#include "pdnsexception.hh"
#include "dns.hh"
#include "namespaces.hh"
#include "remote_logger.hh"
#include "fstrm_logger.hh"
#include "resolve-context.hh"
#include "noinitvector.hh"
#include "logger.hh"
#include "logr.hh"

// Helper to be defined by main program: queue data and log based on return value of queueData()
void remoteLoggerQueueData(RemoteLoggerInterface&, const std::string&);

extern std::shared_ptr<Logr::Logger> g_slogout;
extern bool g_paddingOutgoing;
extern bool g_ECSHardening;

class LWResException : public PDNSException
{
public:
  LWResException(const string& reason_) :
    PDNSException(reason_) {}
};

//! LWRes class
class LWResult
{
public:
  enum class Result : uint8_t
  {
    Timeout = 0,
    Success = 1,
    PermanentError = 2 /* not transport related */,
    OSLimitError = 3,
    Spoofed = 4, /* Spoofing attempt (too many near-misses) */
    ChainLimitError = 5,
    ECSMissing = 6,
    BadCookie = 7,
    BindError = 8,
  };

  [[nodiscard]] static bool isLimitError(Result res)
  {
    return res == Result::OSLimitError || res == Result::ChainLimitError;
  }

  vector<DNSRecord> d_records;
  uint32_t d_usec{0};
  int d_rcode{0};
  bool d_validpacket{false};
  bool d_aabit{false}, d_tcbit{false};
  bool d_haveEDNS{false};
};

class EDNSSubnetOpts;

LWResult::Result asendto(const void* data, size_t len, int flags, const ComboAddress& toAddress,
                         std::optional<ComboAddress>& localAddress, uint16_t qid,
                         const DNSName& domain, uint16_t qtype, const std::optional<EDNSSubnetOpts>& ecs, int* fileDesc, timeval& now);
LWResult::Result arecvfrom(PacketBuffer& packet, int flags, const ComboAddress& fromAddr, size_t& len, uint16_t qid,
                           const DNSName& domain, uint16_t qtype, int fileDesc, const std::optional<EDNSSubnetOpts>& ecs, const struct timeval& now);

LWResult::Result asyncresolve(const OptLog& log, const ComboAddress& address, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, const ResolveContext& context, const std::shared_ptr<std::vector<std::unique_ptr<RemoteLogger>>>& outgoingLoggers, const std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>>& fstrmLoggers, const std::set<uint16_t>& exportTypes, LWResult* lwr, bool* chained);
uint64_t dumpCookies(int fileDesc);
uint64_t clearCookies(vector<string>::iterator begin, vector<string>::iterator end, string& errors);
uint64_t addCookiesUnsupported(vector<string>::iterator begin, vector<string>::iterator end, string& errors);
void pruneCookies(time_t cutoff);
std::string enableOutgoingCookies(bool flag, const std::string& unsupported);
