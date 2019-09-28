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
#include <time.h>
#include <stdlib.h>
#include "pdns/misc.hh"
#include "pdns/utility.hh"

using std::string;
using std::vector;


inline string ptr2ip4( vector<string>& parts )
{
  string ip;
  parts.pop_back();
  parts.pop_back();


  ip = parts.back();
  parts.pop_back();

  while( !parts.empty() )
  {
    ip += "." + parts.back();
    parts.pop_back();
  }

  return ip;
}


inline string ptr2ip6( vector<string>& parts )
{
  int i = 0;
  string ip;


  parts.pop_back();
  parts.pop_back();

  while( i < 3 && parts.size() > 1 && parts.back() == "0" )
  {
    parts.pop_back();
    i++;
  }

  while( i++ < 4 && !parts.empty() )
  {
    ip += parts.back();
    parts.pop_back();
  }

  while( !parts.empty() )
  {
    i = 0;
    ip += ":";

    while( i < 3 && parts.size() > 1 && parts.back() == "0" )
    {
      parts.pop_back();
      i++;
    }

    while( i++ < 4 && !parts.empty() )
    {
      ip += parts.back();
      parts.pop_back();
    }
  }

  return ip;
}


inline string ip2ptr4( const string& ip )
{
  string ptr;
  vector<string> parts;

  stringtok( parts, ip, "." );
  while( !parts.empty() )
  {
    ptr += parts.back() +  ".";
    parts.pop_back();
  }

  return ptr + "in-addr.arpa";
}


inline string ip2ptr6( const string& ip )
{
  string ptr, part, defstr;
  vector<string> parts;

  stringtok( parts, ip, ":" );
  while( !parts.empty() )
  {
    defstr = "0.0.0.0.";
    part = parts.back();

    while( part.length() < 4 )
    {
      part = "0" + part;
    }

    defstr[0] = part[3];
    defstr[2] = part[2];
    defstr[4] = part[1];
    defstr[6] = part[0];
    ptr += defstr;
    parts.pop_back();
  }

  return ptr + "ip6.arpa";
}


inline string strbind( const string& search, const string& replace, string subject )
{
  size_t pos = 0;


  while( ( pos = subject.find( search, pos ) ) != string::npos )
  {
    subject.replace( pos, search.size(), replace );
    pos += replace.size();
  }

  return subject;
}

/*
 *  Convert a LDAP time string to a time_t. Return 0 if unable to convert
 */

inline time_t str2tstamp( const string& str )
{
  char* tmp;
  struct tm tm;

  tmp =  strptime( str.c_str(), "%Y%m%d%H%M%SZ", &tm );

  if( tmp != NULL && *tmp == 0 )
  {
    return Utility::timegm( &tm );
  }

  return 0;
}

