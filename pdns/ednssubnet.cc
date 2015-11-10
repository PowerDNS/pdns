/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2015  Netherlabs Computer Consulting BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "ednssubnet.hh"
#include "dns.hh"

namespace {
        struct EDNSSubnetOptsWire
        {
                uint16_t family;
                uint8_t sourceMask;
                uint8_t scopeMask;
        } GCCPACKATTRIBUTE;  // BRRRRR

}


bool getEDNSSubnetOptsFromString(const string& options, EDNSSubnetOpts* eso)
{
  //cerr<<"options.size:"<<options.size()<<endl;
  if(options.size() <= 4)
    return false;  
  EDNSSubnetOptsWire esow;
  memcpy(&esow, options.c_str(), sizeof(esow));
  esow.family = ntohs(esow.family);
  //cerr<<"Family when parsing from string: "<<esow.family<<endl;
  ComboAddress address;
  unsigned int octetsin = ((esow.sourceMask - 1)>> 3)+1;
  //cerr<<"octetsin:"<<octetsin<<endl;
  if(esow.family == 1) {
    if(options.size() != 4+octetsin)
      return false;
    if(octetsin > 4)
      return false;
    memset(&address, 0, sizeof(address));
    address.sin4.sin_family = AF_INET;
    memcpy(&address.sin4.sin_addr.s_addr, options.c_str()+4, octetsin);
  } else if(esow.family == 2) {
    if(options.size() != 4+octetsin)
      return false;
    if(octetsin > 16)
      return false;
    memset(&address, 0, sizeof(address));
    address.sin4.sin_family = AF_INET6;
    memcpy(&address.sin6.sin6_addr.s6_addr, options.c_str()+4, octetsin);
  }
  else
    return false;
 // cerr<<"Source address: "<<address.toString()<<", mask: "<<(int)esow.sourceMask<<endl;
  eso->source = Netmask(address, esow.sourceMask);
  eso->scope = Netmask(address, esow.scopeMask);
  return true;
}

string makeEDNSSubnetOptsString(const EDNSSubnetOpts& eso)
{
  string ret;
  EDNSSubnetOptsWire esow;
  uint16_t family = htons(eso.source.getNetwork().sin4.sin_family == AF_INET ? 1 : 2);
  memcpy(&esow.family, &family, 2);
  esow.sourceMask = eso.source.getBits();
  esow.scopeMask = eso.scope.getBits();
  ret.assign((const char*)&esow, sizeof(esow));
  int octetsout = ((esow.sourceMask - 1)>> 3)+1;

  if(family == htons(1)) 
    ret.append((const char*) &eso.source.getNetwork().sin4.sin_addr.s_addr, octetsout);
  else
    ret.append((const char*) &eso.source.getNetwork().sin6.sin6_addr.s6_addr, octetsout);
  return ret;
}

