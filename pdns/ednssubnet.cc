/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2011  Netherlabs Computer Consulting BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "ednssubnet.hh"
#include "dns.hh"

namespace {
	struct EDNSSubnetOptsWire
	{
		uint16_t family;
		uint8_t sourceMask;
		uint8_t scopeMask;
	} GCCPACKATTRIBUTE;

}


bool getEDNSSubnetOptsFromString(const string& options, EDNSSubnetOpts* eso)
{
  if(options.size() <= 4)
    return false;  
  EDNSSubnetOptsWire esow;
  memcpy(&esow, options.c_str(), sizeof(esow));
  esow.family = ntohs(esow.family);
  cerr<<"Family: "<<esow.family<<endl;
  ComboAddress address;
  if(esow.family == 1) {
    if(options.size() != 8)
      return false;
    address.sin4.sin_family = AF_INET;
    memcpy(&address.sin4.sin_addr.s_addr, options.c_str()+4, 4);
    cerr<<"Source address: "<<address.toString()<<", mask: "<<(int)esow.sourceMask<<endl;
    eso->source = Netmask(address, esow.sourceMask);
    eso->scope = Netmask(address, esow.scopeMask);
    return true;
  }
  return false;
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
  if(family == htons(1)) 
    ret.append((const char*) &eso.source.getNetwork().sin4.sin_addr.s_addr, 4);
  else
    ret.append((const char*) &eso.source.getNetwork().sin6.sin6_addr.s6_addr, 16);
  return ret;
}

