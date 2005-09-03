/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
#ifndef PDNS_IPUTILSHH
#define PDNS_IPUTILSHH

#include <string>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif // WIN32

#include <iostream>
#include <stdio.h>
#include <functional>
#include "ahuexception.hh"

using namespace std;

/** This exception is thrown by the Netmask class and by extension by the NetmaskGroup class */
class NetmaskException: public AhuException 
{
public:
  NetmaskException(const string &a) : AhuException(a) {}
};

/** This class represents a netmask and can be queried to see if a certain
    IP address is matched by this mask */

class Netmask
{
public:
  //! Constructor supplies the mask, which cannot be changed 
  Netmask(const string &mask) 
  {
    char *p;
    uint8_t bits=32;
    d_mask=0xFFFFFFFF;

    if((p=strchr(mask.c_str(),'/')))
      bits = (uint8_t) atoi(p+1);

    if( bits < 32 )
    d_mask=~(0xFFFFFFFF>>bits);

    struct in_addr a;
    if(!Utility::inet_aton(mask.substr(0,p-mask.c_str()).c_str(), &a))
      throw NetmaskException("Unable to convert '"+mask+"' to a netmask");
    d_network=htonl(a.s_addr);
  }

  //! If this IP address in socket address matches
  bool match(const struct sockaddr_in *ip) const
  {
    return match(htonl((unsigned int)ip->sin_addr.s_addr));
  }

  //! If this ASCII IP address matches
  bool match(const string &ip) const
  {
    struct in_addr a;
    Utility::inet_aton(ip.c_str(), &a);
    return match(htonl(a.s_addr));
  }

  //! If this IP address in native format matches
  bool match(uint32_t ip) const
  {
    return (ip & d_mask) == (d_network & d_mask);
  }


private:
  uint32_t d_network;
  uint32_t d_mask;
};

/** This class represents a group of supplemental Netmask classes. An IP address matchs
    if it is matched by zero or more of the Netmask classes within.
*/
class NetmaskGroup
{
public:
  //! If this IP address is matched by any of the classes within
  bool match(struct sockaddr_in *ip)
  {
    for(container_t::const_iterator i=d_masks.begin();i!=d_masks.end();++i)
      if(i->match(ip))
	return true;

    return false;
  }
  //! Add this Netmask to the list of possible matches
  void addMask(const string &ip)
  {
    d_masks.push_back(Netmask(ip));
  }
  
  bool empty()
  {
    return d_masks.empty();
  }

private:
  typedef vector<Netmask> container_t;
  container_t d_masks;
  
};

#endif
