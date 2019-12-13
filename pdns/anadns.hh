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
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <string>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "dnsparser.hh"
#include "iputils.hh"
#include "namespaces.hh"

struct QuestionIdentifier
{
  QuestionIdentifier() 
  {}

  bool operator<(const QuestionIdentifier& rhs) const
  {
    return 
      tie(d_id,         d_qtype,     d_source,     d_dest,     d_qname) < 
      tie(rhs.d_id, rhs.d_qtype, rhs.d_source, rhs.d_dest, rhs.d_qname);
  }


  // the canonical direction is that of the question
  static QuestionIdentifier create(const ComboAddress& src, const ComboAddress& dst, const struct dnsheader& header, const DNSName& qname, uint16_t qtype)
  {
    QuestionIdentifier ret;

    if(header.qr) {
      ret.d_source = dst;
      ret.d_dest = src;
    }
    else {
      ret.d_source = src;
      ret.d_dest = dst;
    }
    ret.d_qname=qname;
    ret.d_qtype=qtype;
    ret.d_id=ntohs(header.id);
    return ret;
  }

  // the canonical direction is that of the question
  static QuestionIdentifier create(const ComboAddress& src, const ComboAddress& dst, const MOADNSParser& mdp)
  {
    return create(src, dst, mdp.d_header, mdp.d_qname, mdp.d_qtype);
  }

  
  ComboAddress d_source, d_dest;

  DNSName d_qname;
  uint16_t d_qtype;
  uint16_t d_id;
};

inline ostream& operator<<(ostream &s, const QuestionIdentifier& qi) 
{
  s<< "'"<<qi.d_qname<<"|"<<DNSRecordContent::NumberToType(qi.d_qtype)<<"', with id " << qi.d_id <<" from "<<qi.d_source.toStringWithPort();
  
  s<<" to " << qi.d_dest.toStringWithPort();
  return s;
}
