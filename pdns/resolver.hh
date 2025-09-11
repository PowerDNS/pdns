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
#include "iputils.hh"
#include <netdb.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#undef res_mkquery

#include "pdnsexception.hh"
#include "dns.hh"
#include "namespaces.hh"
#include "dnsrecords.hh"
#include "dnssecinfra.hh"
#include "tsigverifier.hh"

class ResolverException : public PDNSException
{
public:
  ResolverException(const string &reason_) : PDNSException(reason_){}
};

// make an IPv4 or IPv6 query socket 
int makeQuerySocket(const ComboAddress& local, bool udpOrTCP, bool nonLocalBind=false);
//! Resolver class. Can be used synchronously and asynchronously, over IPv4 and over IPv6 (simultaneously)
class Resolver  : public boost::noncopyable
{
public:
  Resolver();
  ~Resolver();

  typedef vector<DNSResourceRecord> res_t;
  //! synchronously resolve domain|type at IP, store result in result, rcode in ret
  int resolve(const ComboAddress &ip, const DNSName &domain, int type, res_t* result, const ComboAddress& local);

  int resolve(const ComboAddress &ip, const DNSName &domain, int type, res_t* result);

  //! only send out a resolution request
  uint16_t sendResolve(const ComboAddress& remote, const ComboAddress& local, const DNSName &domain, int type, int& localsock, bool useTCP, bool dnssecOk=false,
    const DNSName& tsigkeyname=DNSName(), const DNSName& tsigalgorithm=DNSName(), const string& tsigsecret="");

  //! see if we got a SOA response from our sendResolve
  bool tryGetSOASerial(DNSName& theirDomain, ComboAddress& remote, uint32_t* theirSerial, uint32_t* theirInception, uint32_t* theirExpire, uint16_t& id, bool *tc);
  
  //! convenience function that calls resolve above
  void getSoaSerial(const ComboAddress&, const DNSName &, uint32_t *);
  
private:
  std::map<std::string, int> locals;
  bool d_nonlocalbind;
};

namespace pdns {
  namespace resolver {
    int parseResult(MOADNSParser& mdp, const DNSName& origQname, uint16_t origQtype, uint16_t id, Resolver::res_t* result);
  } // namespace resolver
} // namespace pdns
