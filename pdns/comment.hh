/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2014 PowerDNS.COM BV

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
#ifndef PDNS_COMMENT_HH
#define PDNS_COMMENT_HH

#include "utility.hh"
#include "qtype.hh"
#include <sys/types.h>

class Comment
{
public:
  Comment() : modified_at(0), domain_id(0)  {};
  ~Comment() {};

  // data
  DNSName qname; //!< the name of the associated RRset, for example: www.powerdns.com
  time_t modified_at;
  string account; //!< account last updating this comment
  string content; //!< The actual comment. Example: blah blah

  int domain_id;
  QType qtype; //!< qtype of the associated RRset, ie A, CNAME, MX etc
};

#endif /* PDNS_COMMENT_HH */
