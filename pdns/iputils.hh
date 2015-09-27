/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2002 - 2014  PowerDNS.COM BV

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
#ifndef PDNS_IPUTILSHH
#define PDNS_IPUTILSHH

#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <stdio.h>
#include <functional>
#include "pdnsexception.hh"
#include "misc.hh"
#include <sys/socket.h>
#include <netdb.h>

#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/lexical_cast.hpp>

#include "namespaces.hh"

union ComboAddress {
  struct sockaddr_in sin4;
  struct sockaddr_in6 sin6;

  bool operator==(const ComboAddress& rhs) const
  {
    if(boost::tie(sin4.sin_family, sin4.sin_port) != boost::tie(rhs.sin4.sin_family, rhs.sin4.sin_port))
      return false;
    if(sin4.sin_family == AF_INET)
      return sin4.sin_addr.s_addr == rhs.sin4.sin_addr.s_addr;
    else
      return memcmp(&sin6.sin6_addr.s6_addr, &rhs.sin6.sin6_addr.s6_addr, 16)==0;
  }

  bool operator<(const ComboAddress& rhs) const
  {
    if(boost::tie(sin4.sin_family, sin4.sin_port) < boost::tie(rhs.sin4.sin_family, rhs.sin4.sin_port))
      return true;
    if(boost::tie(sin4.sin_family, sin4.sin_port) > boost::tie(rhs.sin4.sin_family, rhs.sin4.sin_port))
      return false;
    
    if(sin4.sin_family == AF_INET)
      return sin4.sin_addr.s_addr < rhs.sin4.sin_addr.s_addr;
    else
      return memcmp(&sin6.sin6_addr.s6_addr, &rhs.sin6.sin6_addr.s6_addr, 16) < 0;
  }

  bool operator>(const ComboAddress& rhs) const
  {
    if(boost::tie(sin4.sin_family, sin4.sin_port) > boost::tie(rhs.sin4.sin_family, rhs.sin4.sin_port))
      return true;
    if(boost::tie(sin4.sin_family, sin4.sin_port) < boost::tie(rhs.sin4.sin_family, rhs.sin4.sin_port))
      return false;
    
    if(sin4.sin_family == AF_INET)
      return sin4.sin_addr.s_addr > rhs.sin4.sin_addr.s_addr;
    else
      return memcmp(&sin6.sin6_addr.s6_addr, &rhs.sin6.sin6_addr.s6_addr, 16) > 0;
  }

  struct addressOnlyLessThan: public std::binary_function<ComboAddress, ComboAddress, bool>
  {
    bool operator()(const ComboAddress& a, const ComboAddress& b) const
    {
      if(a.sin4.sin_family < b.sin4.sin_family)
        return true;
      if(a.sin4.sin_family > b.sin4.sin_family)
        return false;
      if(a.sin4.sin_family == AF_INET)
        return a.sin4.sin_addr.s_addr < b.sin4.sin_addr.s_addr;
      else
        return memcmp(&a.sin6.sin6_addr.s6_addr, &b.sin6.sin6_addr.s6_addr, 16) < 0;
    }
  };

  struct addressOnlyEqual: public std::binary_function<ComboAddress, ComboAddress, bool>
  {
    bool operator()(const ComboAddress& a, const ComboAddress& b) const
    {
      if(a.sin4.sin_family != b.sin4.sin_family)
        return false;
      if(a.sin4.sin_family == AF_INET)
        return a.sin4.sin_addr.s_addr == b.sin4.sin_addr.s_addr;
      else
        return !memcmp(&a.sin6.sin6_addr.s6_addr, &b.sin6.sin6_addr.s6_addr, 16);
    }
  };


  socklen_t getSocklen() const
  {
    if(sin4.sin_family == AF_INET)
      return sizeof(sin4);
    else
      return sizeof(sin6);
  }
  
  ComboAddress() 
  {
    sin4.sin_family=AF_INET;
    sin4.sin_addr.s_addr=0;
    sin4.sin_port=0;
  }

  ComboAddress(const struct sockaddr *sa, socklen_t salen) {
    setSockaddr(sa, salen);
  };

  ComboAddress(const struct sockaddr_in6 *sa) {
    setSockaddr((const struct sockaddr*)sa, sizeof(struct sockaddr_in6));
  };

  ComboAddress(const struct sockaddr_in *sa) {
    setSockaddr((const struct sockaddr*)sa, sizeof(struct sockaddr_in));
  };

  void setSockaddr(const struct sockaddr *sa, socklen_t salen) {
    if (salen > sizeof(struct sockaddr_in6)) throw PDNSException("ComboAddress can't handle other than sockaddr_in or sockaddr_in6");
    memcpy(this, sa, salen);
  }

  // 'port' sets a default value in case 'str' does not set a port
  explicit ComboAddress(const string& str, uint16_t port=0)
  {
    memset(&sin6, 0, sizeof(sin6));
    sin4.sin_family = AF_INET;
    sin4.sin_port = 0;
    if(makeIPv4sockaddr(str, &sin4)) {
      sin6.sin6_family = AF_INET6;
      if(makeIPv6sockaddr(str, &sin6) < 0)
        throw PDNSException("Unable to convert presentation address '"+ str +"'"); 
      
    }
    if(!sin4.sin_port) // 'str' overrides port!
      sin4.sin_port=htons(port);
  }

  bool isMappedIPv4()  const
  {
    if(sin4.sin_family!=AF_INET6)
      return false;
    
    int n=0;
    const unsigned char*ptr = (unsigned char*) &sin6.sin6_addr.s6_addr;
    for(n=0; n < 10; ++n)
      if(ptr[n])
        return false;
    
    for(; n < 12; ++n)
      if(ptr[n]!=0xff)
        return false;
    
    return true;
  }
  
  ComboAddress mapToIPv4() const
  {
    if(!isMappedIPv4())
      throw PDNSException("ComboAddress can't map non-mapped IPv6 address back to IPv4");
    ComboAddress ret;
    ret.sin4.sin_family=AF_INET;
    ret.sin4.sin_port=sin4.sin_port;
    
    const unsigned char*ptr = (unsigned char*) &sin6.sin6_addr.s6_addr;
    ptr+=12;
    memcpy(&ret.sin4.sin_addr.s_addr, ptr, 4);
    return ret;
  }

  string toString() const
  {
    char host[1024];
    getnameinfo((struct sockaddr*) this, getSocklen(), host, sizeof(host),0, 0, NI_NUMERICHOST);
      
    return host;
  }

  string toStringWithPort() const
  {
    if(sin4.sin_family==AF_INET)
      return toString() + ":" + boost::lexical_cast<string>(ntohs(sin4.sin_port));
    else
      return "["+toString() + "]:" + boost::lexical_cast<string>(ntohs(sin4.sin_port));
  }

  void truncate(unsigned int bits);
};

/** This exception is thrown by the Netmask class and by extension by the NetmaskGroup class */
class NetmaskException: public PDNSException 
{
public:
  NetmaskException(const string &a) : PDNSException(a) {}
};

inline ComboAddress makeComboAddress(const string& str)
{
  ComboAddress address;
  address.sin4.sin_family=AF_INET;
  if(inet_pton(AF_INET, str.c_str(), &address.sin4.sin_addr) <= 0) {
    address.sin4.sin_family=AF_INET6;
    if(makeIPv6sockaddr(str, &address.sin6) < 0)
      throw NetmaskException("Unable to convert '"+str+"' to a netmask");        
  }
  return address;
}

/** This class represents a netmask and can be queried to see if a certain
    IP address is matched by this mask */
class Netmask
{
public:
  Netmask()
  {
	d_network.sin4.sin_family=0; // disable this doing anything useful
  }
  
  Netmask(const ComboAddress& network, uint8_t bits=0xff)
  {
    d_network = network;
    
    if(bits == 0xff)
      bits = (network.sin4.sin_family == AF_INET) ? 32 : 128;
    
    d_bits = bits;
    if(d_bits<32)
      d_mask=~(0xFFFFFFFF>>d_bits);
    else
      d_mask=0xFFFFFFFF; // not actually used for IPv6
  }
  
  //! Constructor supplies the mask, which cannot be changed 
  Netmask(const string &mask) 
  {
    pair<string,string> split=splitField(mask,'/');
    d_network=makeComboAddress(split.first);
    
    if(!split.second.empty()) {
      d_bits = lexical_cast<unsigned int>(split.second);
      if(d_bits<32)
        d_mask=~(0xFFFFFFFF>>d_bits);
      else
        d_mask=0xFFFFFFFF;
    }
    else if(d_network.sin4.sin_family==AF_INET) {
      d_bits = 32;
      d_mask = 0xFFFFFFFF;
    }
    else {
      d_bits=128;
      d_mask=0;  // silence silly warning - d_mask is unused for IPv6
    }
  }

  bool match(const ComboAddress& ip) const
  {
    return match(&ip);
  }

  //! If this IP address in socket address matches
  bool match(const ComboAddress *ip) const
  {
    if(d_network.sin4.sin_family != ip->sin4.sin_family) {
      return false;
    }
    if(d_network.sin4.sin_family == AF_INET) {
      return match4(htonl((unsigned int)ip->sin4.sin_addr.s_addr));
    }
    if(d_network.sin6.sin6_family == AF_INET6) {
      uint8_t bytes=d_bits/8, n;
      const uint8_t *us=(const uint8_t*) &d_network.sin6.sin6_addr.s6_addr;
      const uint8_t *them=(const uint8_t*) &ip->sin6.sin6_addr.s6_addr;
      
      for(n=0; n < bytes; ++n) {
        if(us[n]!=them[n]) {
          return false;
        }
      }
      // still here, now match remaining bits
      uint8_t bits= d_bits % 8;
      uint8_t mask= ~(0xFF>>bits);

      return((us[n] & mask) == (them[n] & mask));
    }
    return false;
  }

  //! If this ASCII IP address matches
  bool match(const string &ip) const
  {
    ComboAddress address=makeComboAddress(ip);
    return match(&address);
  }

  //! If this IP address in native format matches
  bool match4(uint32_t ip) const
  {
    return (ip & d_mask) == (ntohl(d_network.sin4.sin_addr.s_addr) & d_mask);
  }

  string toString() const
  {
    return d_network.toString()+"/"+boost::lexical_cast<string>((unsigned int)d_bits);
  }

  string toStringNoMask() const
  {
    return d_network.toString();
  }
  const ComboAddress& getNetwork() const
  {
    return d_network;
  }
  int getBits() const
  {
    return d_bits;
  }
  bool isIpv6() const 
  {
    return d_network.sin6.sin6_family == AF_INET6;
  }
  bool isIpv4() const
  {
    return d_network.sin4.sin_family == AF_INET;
  }
private:
  ComboAddress d_network;
  uint32_t d_mask;
  uint8_t d_bits;
};

/** This class represents a group of supplemental Netmask classes. An IP address matchs
    if it is matched by zero or more of the Netmask classes within.
*/
class NetmaskGroup
{
public:
  //! If this IP address is matched by any of the classes within

  bool match(const ComboAddress *ip) const
  {
    for(container_t::const_iterator i=d_masks.begin();i!=d_masks.end();++i)
      if(i->match(ip) || (ip->isMappedIPv4() && i->match(ip->mapToIPv4()) ))
        return true;

    return false;
  }

  bool match(const ComboAddress& ip) const
  {
    return match(&ip);
  }

  //! Add this Netmask to the list of possible matches
  void addMask(const string &ip)
  {
    d_masks.push_back(Netmask(ip));
  }

  void clear()
  {
    d_masks.clear();
  }

  bool empty()
  {
    return d_masks.empty();
  }

  unsigned int size()
  {
    return (unsigned int)d_masks.size();
  }

  string toString() const
  {
    ostringstream str;
    for(container_t::const_iterator iter = d_masks.begin(); iter != d_masks.end(); ++iter) {
      if(iter != d_masks.begin())
        str <<", ";
      str<<iter->toString();
    }
    return str.str();
  }

  void toStringVector(vector<string>* vec) const
  {
    for(container_t::const_iterator iter = d_masks.begin(); iter != d_masks.end(); ++iter) {
      vec->push_back(iter->toString());
    }
  }

  void toMasks(const string &ips)
  {
    vector<string> parts;
    stringtok(parts, ips, ", \t");

    for (vector<string>::const_iterator iter = parts.begin(); iter != parts.end(); ++iter)
      addMask(*iter);
  }

private:
  typedef vector<Netmask> container_t;
  container_t d_masks;
};


struct SComboAddress
{
  SComboAddress(const ComboAddress& orig) : ca(orig) {}
  ComboAddress ca;
  bool operator<(const SComboAddress& rhs) const
  {
    return ComboAddress::addressOnlyLessThan()(ca, rhs.ca);
  }
  operator const ComboAddress&()
  {
    return ca;
  }
};


int SSocket(int family, int type, int flags);
int SConnect(int sockfd, const ComboAddress& remote);
int SBind(int sockfd, const ComboAddress& local);
int SAccept(int sockfd, ComboAddress& remote);
int SListen(int sockfd, int limit);
int SSetsockopt(int sockfd, int level, int opname, int value);

#if defined(IP_PKTINFO)
  #define GEN_IP_PKTINFO IP_PKTINFO
#elif defined(IP_RECVDSTADDR)
  #define GEN_IP_PKTINFO IP_RECVDSTADDR 
#endif
bool IsAnyAddress(const ComboAddress& addr);
bool HarvestDestinationAddress(struct msghdr* msgh, ComboAddress* destination);
bool HarvestTimestamp(struct msghdr* msgh, struct timeval* tv);
void fillMSGHdr(struct msghdr* msgh, struct iovec* iov, char* cbuf, size_t cbufsize, char* data, size_t datalen, ComboAddress* addr);
int sendfromto(int sock, const char* data, int len, int flags, const ComboAddress& from, const ComboAddress& to);
#endif
