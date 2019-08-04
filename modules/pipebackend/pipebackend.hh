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
#ifndef PIPEBACKEND_HH
#define PIPEBACKEND_HH

#include <string>
#include <map>
#include <sys/types.h>


#include "pdns/namespaces.hh"
#include "pdns/misc.hh"


/** The CoWrapper class wraps around a coprocess and restarts it if needed.
    It may also send out pings and expect banners */
class CoWrapper
{
public:
  CoWrapper(const string &command, int timeout, int abiVersion);
  ~CoWrapper();
  void send(const string &line);
  void receive(string &line);
private:
  std::unique_ptr<CoRemote> d_cp;
  string d_command;
  void launch();
  int d_timeout;
  int d_abiVersion;
};

class PipeBackend : public DNSBackend
{
public:
  PipeBackend(const string &suffix="");
  ~PipeBackend();
  void lookup(const QType&, const DNSName& qdomain, int zoneId, DNSPacket *p=nullptr) override;
  bool list(const DNSName& target, int domain_id, bool include_disabled=false) override;
  bool get(DNSResourceRecord &r) override;
  string directBackendCmd(const string &query) override;
  static DNSBackend *maker();
  
private:
  void launch();
  void cleanup();
  std::unique_ptr<CoWrapper> d_coproc;
  std::unique_ptr<Regex> d_regex;
  DNSName d_qname;
  QType d_qtype;
  string d_regexstr;
  bool d_disavow;
  int d_abiVersion;
};


#endif

