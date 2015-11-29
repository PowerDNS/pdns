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
#include <bitset>
#include "pdnsexception.hh"
#include "misc.hh"
#include <sys/socket.h>
#include <netdb.h>

#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <boost/lexical_cast.hpp>

#include "namespaces.hh"

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>

#define htobe16(x) OSSwapHostToBigInt16(x)
#define htole16(x) OSSwapHostToLittleInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define le16toh(x) OSSwapLittleToHostInt16(x)

#define htobe32(x) OSSwapHostToBigInt32(x)
#define htole32(x) OSSwapHostToLittleInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define le32toh(x) OSSwapLittleToHostInt32(x)

#define htobe64(x) OSSwapHostToBigInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)
#endif

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
	d_mask=0;
	d_bits=0;
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

  bool operator<(const Netmask& rhs) const 
  {
    return tie(d_network, d_bits) < tie(rhs.d_network, rhs.d_bits);
  }

  bool operator==(const Netmask& rhs) const 
  {
    return tie(d_network, d_bits) == tie(rhs.d_network, rhs.d_bits);
  }

  bool empty() const 
  {
    return d_network.sin4.sin_family==0;
  }

private:
  ComboAddress d_network;
  uint32_t d_mask;
  uint8_t d_bits;
};

/** Per-bit binary tree map implementation with <Netmask,T> pair.
 *
 * This is an binary tree implementation for storing attributes for IPv4 and IPv6 prefixes.
 * The most simple use case is simple NetmaskTree<bool> used by NetmaskGroup, which only
 * wants to know if given IP address is matched in the prefixes stored.
 *
 * This element is useful for anything that needs to *STORE* prefixes, and *MATCH* IP addresses
 * to a *LIST* of *PREFIXES*. Not the other way round.
 *
 * You can store IPv4 and IPv6 addresses to same tree, separate payload storage is kept per AFI.
 *
 * To erase something copy values to new tree sans the value you want to erase.
 *
 * Use swap if you need to move the tree to another NetmaskTree instance, it is WAY faster
 * than using copy ctor or assigment operator, since it moves the nodes and tree root to
 * new home instead of actually recreating the tree.
 *
 * Please see NetmaskGroup for example of simple use case. Other usecases can be found
 * from GeoIPBackend and Sortlist, and from dnsdist.
 */
template <typename T>
class NetmaskTree {
public:
  typedef Netmask key_type;
  typedef T value_type;
  typedef std::pair<key_type,value_type> node_type;
  typedef size_t size_type;

private:
  /** Single node in tree, internal use only.
    */
  class TreeNode : boost::noncopyable {
  public:
     explicit TreeNode(int bits) noexcept : parent(NULL),d_bits(bits) {
     }

     //<! Makes a left node with one more bit than parent
     TreeNode* make_left() {
       if (!left) {
         left = unique_ptr<TreeNode>(new TreeNode(d_bits+1));
         left->parent = this;
       }
       return left.get();
     }

     //<! Makes a right node with one more bit than parent
     TreeNode* make_right() {
       if (!right) {
         right = unique_ptr<TreeNode>(new TreeNode(d_bits+1));
         right->parent = this;
       }
       return right.get();
     }

     unique_ptr<TreeNode> left;
     unique_ptr<TreeNode> right;
     TreeNode* parent;

     unique_ptr<node_type> node4; //<! IPv4 value-pair
     unique_ptr<node_type> node6; //<! IPv6 value-pair

     int d_bits; //<! How many bits have been used so far
  };

public:
  NetmaskTree() noexcept {
  }

  NetmaskTree(const NetmaskTree& rhs) {
    // it is easier to copy the nodes than tree.
    // also acts as handy compactor
    for(auto const& node: rhs._nodes)
      insert(node->first).second = node->second;
  }

  NetmaskTree& operator=(const NetmaskTree& rhs) {
    clear();
    // see above.
    for(auto const& node: rhs._nodes)
      insert(node->first).second = node->second;
    return *this;
  }

  const typename std::vector<node_type*>::const_iterator begin() const { return _nodes.begin(); }
  const typename std::vector<node_type*>::const_iterator end() const { return _nodes.end(); }

  typename std::vector<node_type*>::iterator begin() { return _nodes.begin(); }
  typename std::vector<node_type*>::iterator end() { return _nodes.end(); }

  node_type& insert(const string &mask) {
    return insert(key_type(mask));
  }

  //<! Creates new value-pair in tree and returns it.
  node_type& insert(const key_type& key) {
    // lazily initialize tree on first insert.
    if (!root) root = unique_ptr<TreeNode>(new TreeNode(0));
    TreeNode* node = root.get();
    node_type* value = nullptr;

    if (key.getNetwork().sin4.sin_family == AF_INET) {
      std::bitset<32> addr(be32toh(key.getNetwork().sin4.sin_addr.s_addr));
      int bits = 0;
      // we turn left on 0 and right on 1
      while(bits < key.getBits()) {
        uint8_t val = addr[31-bits];
        if (val)
          node = node->make_right();
        else
          node = node->make_left();
        bits++;
      }
      // only create node if not yet assigned
      if (!node->node4) {
        node->node4 = unique_ptr<node_type>(new node_type());
        _nodes.push_back(node->node4.get());
      }
      value = node->node4.get();
    } else {
      uint64_t* addr = (uint64_t*)key.getNetwork().sin6.sin6_addr.s6_addr;
      std::bitset<64> addr_low(be64toh(addr[1]));
      std::bitset<64> addr_high(be64toh(addr[0]));
      int bits = 0;
      while(bits < key.getBits()) {
        uint8_t val;
        // we use high address until we are
        if (bits < 64) val = addr_high[63-bits];
        // past 64 bits, and start using low address
        else val = addr_low[127-bits];

        // we turn left on 0 and right on 1
        if (val)
          node = node->make_right();
        else
          node = node->make_left();
        bits++;
      }
      // only create node if not yet assigned
      if (!node->node6) {
        node->node6 = unique_ptr<node_type>(new node_type());
        _nodes.push_back(node->node6.get());
      }
      value = node->node6.get();
    }
    // assign key
    value->first = key;
    return *value;
  }

  //<! Creates or updates value
  void insert_or_assign(const key_type& mask, const value_type& value) {
    insert(mask).second = value;
  }

  void insert_or_assign(const string& mask, const value_type& value) {
    insert(key_type(mask)).second = value;
  }

  //<! check if given key is present in TreeMap
  bool has_key(const key_type& key) const {
    const node_type *ptr = lookup(key);
    return ptr && ptr->first == key;
  }

  //<! Returns "best match" for key_type, which might not be value
  const node_type* lookup(const key_type& value) const {
    return lookup(value.getNetwork(), value.getBits());
  }

  //<! Perform best match lookup for value, using at most max_bits
  const node_type* lookup(const ComboAddress& value, int max_bits = 128) const {
    if (!root) return nullptr;

    TreeNode *node = root.get();
    node_type *ret = nullptr;

    // exact same thing as above, except
    if (value.sin4.sin_family == AF_INET) {
      max_bits = std::max(0,std::min(max_bits,32));
      std::bitset<32> addr(be32toh(value.sin4.sin_addr.s_addr));
      int bits = 0;

      while(bits < max_bits) {
        // ...we keep track of last non-empty node
        if (node->node4) ret = node->node4.get();
        uint8_t val = addr[31-bits];
        // ...and we don't create left/right hand
        if (val) {
          if (node->right) node = node->right.get();
          // ..and we break when road ends
          else break;
        } else {
          if (node->left) node = node->left.get();
          else break;
        }
        bits++;
      }
      // needed if we did not find one in loop
      if (node->node4) ret = node->node4.get();
    } else {
      uint64_t* addr = (uint64_t*)value.sin6.sin6_addr.s6_addr;
      max_bits = std::max(0,std::min(max_bits,128));
      std::bitset<64> addr_low(be64toh(addr[1]));
      std::bitset<64> addr_high(be64toh(addr[0]));
      int bits = 0;
      while(bits < max_bits) {
        if (node->node6) ret = node->node6.get();
        uint8_t val;
        if (bits < 64) val = addr_high[63-bits];
        else val = addr_low[127-bits];
        if (val) {
          if (node->right) node = node->right.get();
          else break;
        } else {
          if (node->left) node = node->left.get();
          else break;
        }
        bits++;
      }
      if (node->node6) ret = node->node6.get();
    }

    // this can be nullptr.
    return ret;
  }

  //<! Removes key from TreeMap. This does not clean up the tree.
  void erase(const key_type& key) {
    TreeNode *node = root.get();

    // no tree, no value
    if ( node == nullptr ) return;

    // exact same thing as above, except
    if (key.getNetwork().sin4.sin_family == AF_INET) {
      std::bitset<32> addr(be32toh(key.getNetwork().sin4.sin_addr.s_addr));
      int bits = 0;
      while(node && bits < key.getBits()) {
        uint8_t val = addr[31-bits];
        if (val) {
          node = node->right.get();
        } else {
          node = node->left.get();
        }
        bits++;
      }
      if (node) {
        for(auto it = _nodes.begin(); it != _nodes.end(); it++)
           if (node->node4.get() == *it) _nodes.erase(it);
        node->node4.reset();
      }
    } else {
      uint64_t* addr = (uint64_t*)key.getNetwork().sin6.sin6_addr.s6_addr;
      std::bitset<64> addr_low(be64toh(addr[1]));
      std::bitset<64> addr_high(be64toh(addr[0]));
      int bits = 0;
      while(node && bits < key.getBits()) {
        uint8_t val;
        if (bits < 64) val = addr_high[63-bits];
        else val = addr_low[127-bits];
        if (val) {
          node = node->right.get();
        } else {
          node = node->left.get();
        }
        bits++;
      }
      if (node) {
        for(auto it = _nodes.begin(); it != _nodes.end(); it++)
           if (node->node4.get() == *it) _nodes.erase(it);
        node->node6.reset();
      }
    }
  }

  void erase(const string& key) {
    erase(key_type(key));
  }

  //<! checks whether the container is empty.
  bool empty() const {
    return _nodes.empty();
  }

  //<! returns the number of elements
  size_type size() const {
    return _nodes.size();
  }

  //<! See if given ComboAddress matches any prefix
  bool match(const ComboAddress& value) const {
    return (lookup(value) != nullptr);
  }

  bool match(const std::string& value) const {
    return match(ComboAddress(value));
  }

  //<! Clean out the tree
  void clear() {
    _nodes.clear();
    root.reset(nullptr);
  }

  //<! swaps the contents, rhs is left with nullptr.
  void swap(NetmaskTree& rhs) {
    root.swap(rhs.root);
    _nodes.swap(rhs._nodes);
  }

private:
  unique_ptr<TreeNode> root; //<! Root of our tree
  std::vector<node_type*> _nodes; //<! Container for actual values
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
    return tree.match(*ip);
  }

  bool match(const ComboAddress& ip) const
  {
    return match(&ip);
  }

  //! Add this string to the list of possible matches
  void addMask(const string &ip)
  {
    addMask(Netmask(ip));
  }

  //! Add this Netmask to the list of possible matches
  void addMask(const Netmask& nm)
  {
    tree.insert(nm);
  }

  void clear()
  {
    tree.clear();
  }

  bool empty() const
  {
    return tree.empty();
  }

  size_t size() const
  {
    return tree.size();
  }

  string toString() const
  {
    ostringstream str;
    for(auto iter = tree.begin(); iter != tree.end(); ++iter) {
      if(iter != tree.begin())
        str <<", ";
      str<<(*iter)->first.toString();
    }
    return str.str();
  }

  void toStringVector(vector<string>* vec) const
  {
    for(auto iter = tree.begin(); iter != tree.end(); ++iter)
      vec->push_back((*iter)->first.toString());
  }

  void toMasks(const string &ips)
  {
    vector<string> parts;
    stringtok(parts, ips, ", \t");

    for (vector<string>::const_iterator iter = parts.begin(); iter != parts.end(); ++iter)
      addMask(*iter);
  }

private:
  NetmaskTree<bool> tree;
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

extern template class NetmaskTree<bool>;
