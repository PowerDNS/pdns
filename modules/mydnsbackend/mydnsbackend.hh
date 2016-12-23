/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 * originally authored by Jonathan Oddy
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
#ifndef MYDNSBACKEND_HH
#define MYDNSBACKEND_HH

#include <string>
#include <map>

#include "pdns/namespaces.hh"

#include <modules/gmysqlbackend/smysql.hh>

class MyDNSBackend : public DNSBackend
{
public:
  MyDNSBackend(const string &suffix);
  ~MyDNSBackend();
  
  void lookup(const QType &, const DNSName &qdomain, DNSPacket *p=0, int zoneId=-1);
  bool list(const DNSName &target, int domain_id, bool include_disabled=false);
  bool get(DNSResourceRecord &r);
  bool getSOA(const DNSName& name, SOAData& soadata, DNSPacket*);
    
private:
  SMySQL *d_db; 

  string d_qname;
  string d_origin;
  bool d_useminimalttl;
  unsigned int d_minimum;

  SSqlStatement::result_t d_result;

  SSqlStatement* d_query_stmt;
  SSqlStatement* d_domainIdQuery_stmt;
  SSqlStatement* d_domainNoIdQuery_stmt;
  SSqlStatement* d_listQuery_stmt;
  SSqlStatement* d_soaQuery_stmt;
  SSqlStatement* d_basicQuery_stmt;
  SSqlStatement* d_anyQuery_stmt;
};

#endif /* MYDNSBACKEND_HH */
