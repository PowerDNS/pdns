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
#ifndef PDNS_LWRES_HH
#define PDNS_LWRES_HH
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


int asendto(const char *data, size_t len, int flags, const ComboAddress& ip, uint16_t id,
            const DNSName& domain, uint16_t qtype,  int* fd);
int arecvfrom(std::string& packet, int flags, const ComboAddress& ip, size_t *d_len, uint16_t id,
              const DNSName& domain, uint16_t qtype, int fd, struct timeval* now);

class LWResException : public PDNSException
{
public:
  LWResException(const string &reason_) : PDNSException(reason_){}
};

//! LWRes class 
class LWResult
{
public:
  LWResult() : d_usec(0) {}

  vector<DNSRecord> d_records;
  int d_rcode{0};
  bool d_validpacket{false};
  bool d_aabit{false}, d_tcbit{false};
  uint32_t d_usec{0};
  bool d_haveEDNS{false};
};

int asyncresolve(const ComboAddress& ip, const DNSName& domain, int type, bool doTCP, bool sendRDQuery, int EDNS0Level, struct timeval* now, boost::optional<Netmask>& srcmask, boost::optional<const ResolveContext&> context, const std::shared_ptr<std::vector<std::unique_ptr<RemoteLogger>>>& outgoingLoggers, const std::shared_ptr<std::vector<std::unique_ptr<FrameStreamLogger>>>& fstrmLoggers, const std::set<uint16_t>& exportTypes, LWResult* res, bool* chained);
#endif // PDNS_LWRES_HH
