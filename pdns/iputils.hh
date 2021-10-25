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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <stdio.h>
#include <functional>
#include <bitset>
#include "pdnsexception.hh"
#include "misc.hh"
#include <netdb.h>
#include <sstream>
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>

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

#ifdef __sun

#define htobe16(x) BE_16(x)
#define htole16(x) LE_16(x)
#define be16toh(x) BE_IN16(&(x))
#define le16toh(x) LE_IN16(&(x))

#define htobe32(x) BE_32(x)
#define htole32(x) LE_32(x)
#define be32toh(x) BE_IN32(&(x))
#define le32toh(x) LE_IN32(&(x))

#define htobe64(x) BE_64(x)
#define htole64(x) LE_64(x)
#define be64toh(x) BE_IN64(&(x))
#define le64toh(x) LE_IN64(&(x))

#endif

#ifdef __FreeBSD__
#include <sys/endian.h>
#endif

#if defined(__NetBSD__) && defined(IP_PKTINFO) && !defined(IP_SENDSRCADDR)
// The IP_PKTINFO option in NetBSD was incompatible with Linux until a
// change that also introduced IP_SENDSRCADDR for FreeBSD compatibility.
#undef IP_PKTINFO
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
      return memcmp(&sin6.sin6_addr.s6_addr, &rhs.sin6.sin6_addr.s6_addr, sizeof(sin6.sin6_addr.s6_addr))==0;
  }

  bool operator!=(const ComboAddress& rhs) const
  {
    return(!operator==(rhs));
  }

  bool operator<(const ComboAddress& rhs) const
  {
    if(sin4.sin_family == 0) {
      return false;
    }
    if(boost::tie(sin4.sin_family, sin4.sin_port) < boost::tie(rhs.sin4.sin_family, rhs.sin4.sin_port))
      return true;
    if(boost::tie(sin4.sin_family, sin4.sin_port) > boost::tie(rhs.sin4.sin_family, rhs.sin4.sin_port))
      return false;

    if(sin4.sin_family == AF_INET)
      return sin4.sin_addr.s_addr < rhs.sin4.sin_addr.s_addr;
    else
      return memcmp(&sin6.sin6_addr.s6_addr, &rhs.sin6.sin6_addr.s6_addr, sizeof(sin6.sin6_addr.s6_addr)) < 0;
  }

  bool operator>(const ComboAddress& rhs) const
  {
    return rhs.operator<(*this);
  }

  struct addressOnlyHash
  {
    uint32_t operator()(const ComboAddress& ca) const
    {
      const unsigned char* start = nullptr;
      uint32_t len = 0;
      if (ca.sin4.sin_family == AF_INET) {
        start = reinterpret_cast<const unsigned char*>(&ca.sin4.sin_addr.s_addr);
        len = 4;
      }
      else {
        start = reinterpret_cast<const unsigned char*>(&ca.sin6.sin6_addr.s6_addr);
        len = 16;
      }
      return burtle(start, len, 0);
    }
  };

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
        return memcmp(&a.sin6.sin6_addr.s6_addr, &b.sin6.sin6_addr.s6_addr, sizeof(a.sin6.sin6_addr.s6_addr)) < 0;
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
        return !memcmp(&a.sin6.sin6_addr.s6_addr, &b.sin6.sin6_addr.s6_addr, sizeof(a.sin6.sin6_addr.s6_addr));
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
    sin6.sin6_scope_id = 0;
    sin6.sin6_flowinfo = 0;
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

  bool isIPv6() const
  {
    return sin4.sin_family == AF_INET6;
  }
  bool isIPv4() const
  {
    return sin4.sin_family == AF_INET;
  }

  bool isMappedIPv4()  const
  {
    if(sin4.sin_family!=AF_INET6)
      return false;

    int n=0;
    const unsigned char* ptr = reinterpret_cast<const unsigned char*>(&sin6.sin6_addr.s6_addr);
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

    const unsigned char* ptr = reinterpret_cast<const unsigned char*>(&sin6.sin6_addr.s6_addr);
    ptr+=(sizeof(sin6.sin6_addr.s6_addr) - sizeof(ret.sin4.sin_addr.s_addr));
    memcpy(&ret.sin4.sin_addr.s_addr, ptr, sizeof(ret.sin4.sin_addr.s_addr));
    return ret;
  }

  string toString() const
  {
    char host[1024];
    int retval = 0;
    if(sin4.sin_family && !(retval = getnameinfo(reinterpret_cast<const struct sockaddr*>(this), getSocklen(), host, sizeof(host),0, 0, NI_NUMERICHOST)))
      return string(host);
    else
      return "invalid "+string(gai_strerror(retval));
  }

  //! Ignores any interface specifiers possibly available in the sockaddr data.
  string toStringNoInterface() const
  {
    char host[1024];
    if(sin4.sin_family == AF_INET && (nullptr != inet_ntop(sin4.sin_family, &sin4.sin_addr, host, sizeof(host))))
      return string(host);
    else if(sin4.sin_family == AF_INET6 && (nullptr != inet_ntop(sin4.sin_family, &sin6.sin6_addr, host, sizeof(host))))
      return string(host);
    else
      return "invalid "+stringerror();
  }

  string toStringWithPort() const
  {
    if(sin4.sin_family==AF_INET)
      return toString() + ":" + std::to_string(ntohs(sin4.sin_port));
    else
      return "["+toString() + "]:" + std::to_string(ntohs(sin4.sin_port));
  }

  string toStringWithPortExcept(int port) const
  {
    if(ntohs(sin4.sin_port) == port)
      return toString();
    if(sin4.sin_family==AF_INET)
      return toString() + ":" + std::to_string(ntohs(sin4.sin_port));
    else
      return "["+toString() + "]:" + std::to_string(ntohs(sin4.sin_port));
  }

  string toLogString() const
  {
    return toStringWithPortExcept(53);
  }

  string toByteString() const
  {
    if (isIPv4()) {
      return string(reinterpret_cast<const char*>(&sin4.sin_addr.s_addr), sizeof(sin4.sin_addr.s_addr));
    }
    return string(reinterpret_cast<const char*>(&sin6.sin6_addr.s6_addr), sizeof(sin6.sin6_addr.s6_addr));
  }

  void truncate(unsigned int bits) noexcept;

  uint16_t getPort() const
  {
    return ntohs(sin4.sin_port);
  }

  void setPort(uint16_t port)
  {
    sin4.sin_port = htons(port);
  }

  void reset()
  {
    memset(&sin4, 0, sizeof(sin4));
    memset(&sin6, 0, sizeof(sin6));
  }

  //! Get the total number of address bits (either 32 or 128 depending on IP version)
  uint8_t getBits() const
  {
    if (isIPv4())
      return 32;
    if (isIPv6())
      return 128;
    return 0;
  }
  /** Get the value of the bit at the provided bit index. When the index >= 0,
      the index is relative to the LSB starting at index zero. When the index < 0,
      the index is relative to the MSB starting at index -1 and counting down.
   */
  bool getBit(int index) const
  {
    if(isIPv4()) {
      if (index >= 32)
        return false;
      if (index < 0) {
        if (index < -32)
          return false;
        index = 32 + index;
      }

      uint32_t ls_addr = ntohl(sin4.sin_addr.s_addr);

      return ((ls_addr & (1U<<index)) != 0x00000000);
    }
    if(isIPv6()) {
      if (index >= 128)
        return false;
      if (index < 0) {
        if (index < -128)
          return false;
        index = 128 + index;
      }

      const uint8_t* ls_addr = reinterpret_cast<const uint8_t*>(sin6.sin6_addr.s6_addr);
      uint8_t byte_idx = index / 8;
      uint8_t bit_idx = index % 8;

      return ((ls_addr[15-byte_idx] & (1U << bit_idx)) != 0x00);
    }
    return false;
  }

  /*! Returns a comma-separated string of IP addresses
   *
   * \param c  An stl container with ComboAddresses
   * \param withPort  Also print the port (default true)
   * \param portExcept  Print the port, except when this is the port (default 53)
   */
  template < template < class ... > class Container, class ... Args >
  static string caContainerToString(const Container<ComboAddress, Args...>& c, const bool withPort = true, const uint16_t portExcept = 53) {
  vector<string> strs;
  for (const auto& ca : c) {
    if (withPort) {
      strs.push_back(ca.toStringWithPortExcept(portExcept));
      continue;
    }
    strs.push_back(ca.toString());
  }
  return boost::join(strs, ",");
  };
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

inline ComboAddress makeComboAddressFromRaw(uint8_t version, const char* raw, size_t len)
{
  ComboAddress address;

  if (version == 4) {
    address.sin4.sin_family = AF_INET;
    if (len != sizeof(address.sin4.sin_addr)) throw NetmaskException("invalid raw address length");
    memcpy(&address.sin4.sin_addr, raw, sizeof(address.sin4.sin_addr));
  }
  else if (version == 6) {
    address.sin6.sin6_family = AF_INET6;
    if (len != sizeof(address.sin6.sin6_addr)) throw NetmaskException("invalid raw address length");
    memcpy(&address.sin6.sin6_addr, raw, sizeof(address.sin6.sin6_addr));
  }
  else throw NetmaskException("invalid address family");

  return address;
}

inline ComboAddress makeComboAddressFromRaw(uint8_t version, const string &str)
{
  return makeComboAddressFromRaw(version, str.c_str(), str.size());
}

/** This class represents a netmask and can be queried to see if a certain
    IP address is matched by this mask */
class Netmask
{
public:
  Netmask()
  {
    d_network.sin4.sin_family = 0; // disable this doing anything useful
    d_network.sin4.sin_port = 0; // this guarantees d_network compares identical
    d_mask = 0;
    d_bits = 0;
  }

  Netmask(const ComboAddress& network, uint8_t bits=0xff): d_network(network)
  {
    d_network.sin4.sin_port = 0;
    setBits(network.isIPv4() ? std::min(bits, static_cast<uint8_t>(32)) : std::min(bits, static_cast<uint8_t>(128)));
  }

  void setBits(uint8_t value)
  {
    d_bits = value;

    if (d_bits < 32) {
      d_mask = ~(0xFFFFFFFF >> d_bits);
    }
    else {
      // note that d_mask is unused for IPv6
      d_mask = 0xFFFFFFFF;
    }

    if (isIPv4()) {
      d_network.sin4.sin_addr.s_addr = htonl(ntohl(d_network.sin4.sin_addr.s_addr) & d_mask);
    }
    else if (isIPv6()) {
      uint8_t bytes = d_bits/8;
      uint8_t *us = (uint8_t*) &d_network.sin6.sin6_addr.s6_addr;
      uint8_t bits = d_bits % 8;
      uint8_t mask = (uint8_t) ~(0xFF>>bits);

      if (bytes < sizeof(d_network.sin6.sin6_addr.s6_addr)) {
        us[bytes] &= mask;
      }

      for(size_t idx = bytes + 1; idx < sizeof(d_network.sin6.sin6_addr.s6_addr); ++idx) {
        us[idx] = 0;
      }
    }
  }

  //! Constructor supplies the mask, which cannot be changed
  Netmask(const string &mask)
  {
    pair<string,string> split = splitField(mask,'/');
    d_network = makeComboAddress(split.first);

    if (!split.second.empty()) {
      setBits(static_cast<uint8_t>(pdns_stou(split.second)));
    }
    else if (d_network.sin4.sin_family == AF_INET) {
      setBits(32);
    }
    else {
      setBits(128);
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
      uint8_t mask= (uint8_t) ~(0xFF>>bits);

      return((us[n]) == (them[n] & mask));
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
    return (ip & d_mask) == (ntohl(d_network.sin4.sin_addr.s_addr));
  }

  string toString() const
  {
    return d_network.toStringNoInterface()+"/"+std::to_string((unsigned int)d_bits);
  }

  string toStringNoMask() const
  {
    return d_network.toStringNoInterface();
  }

  const ComboAddress& getNetwork() const
  {
    return d_network;
  }

  const ComboAddress& getMaskedNetwork() const
  {
    return getNetwork();
  }

  uint8_t getBits() const
  {
    return d_bits;
  }

  bool isIPv6() const
  {
    return d_network.sin6.sin6_family == AF_INET6;
  }

  bool isIPv4() const
  {
    return d_network.sin4.sin_family == AF_INET;
  }

  bool operator<(const Netmask& rhs) const
  {
    if (empty() && !rhs.empty())
      return false;

    if (!empty() && rhs.empty())
      return true;

    if (d_bits > rhs.d_bits)
      return true;
    if (d_bits < rhs.d_bits)
      return false;

    return d_network < rhs.d_network;
  }

  bool operator>(const Netmask& rhs) const
  {
    return rhs.operator<(*this);
  }

  bool operator==(const Netmask& rhs) const
  {
    return tie(d_network, d_bits) == tie(rhs.d_network, rhs.d_bits);
  }

  bool empty() const
  {
    return d_network.sin4.sin_family==0;
  }

  //! Get normalized version of the netmask. This means that all address bits below the network bits are zero.
  Netmask getNormalized() const {
    return Netmask(getMaskedNetwork(), d_bits);
  }
  //! Get Netmask for super network of this one (i.e. with fewer network bits)
  Netmask getSuper(uint8_t bits) const {
    return Netmask(d_network, std::min(d_bits, bits));
  }

  //! Get the total number of address bits for this netmask (either 32 or 128 depending on IP version)
  uint8_t getFullBits() const
  {
    return d_network.getBits();
  }

  /** Get the value of the bit at the provided bit index. When the index >= 0,
      the index is relative to the LSB starting at index zero. When the index < 0,
      the index is relative to the MSB starting at index -1 and counting down.
      When the index points outside the network bits, it always yields zero.
   */
  bool getBit(int bit) const
  {
    if (bit < -d_bits)
      return false;
    if (bit >= 0) {
      if(isIPv4()) {
        if (bit >= 32 || bit < (32 - d_bits))
          return false;
      }
      if(isIPv6()) {
        if (bit >= 128 || bit < (128 - d_bits))
          return false;
      }
    }
    return d_network.getBit(bit);
  }

private:
  ComboAddress d_network;
  uint32_t d_mask;
  uint8_t d_bits;
};

/** Binary tree map implementation with <Netmask,T> pair.
 *
 * This is an binary tree implementation for storing attributes for IPv4 and IPv6 prefixes.
 * The most simple use case is simple NetmaskTree<bool> used by NetmaskGroup, which only
 * wants to know if given IP address is matched in the prefixes stored.
 *
 * This element is useful for anything that needs to *STORE* prefixes, and *MATCH* IP addresses
 * to a *LIST* of *PREFIXES*. Not the other way round.
 *
 * You can store IPv4 and IPv6 addresses to same tree, separate payload storage is kept per AFI.
 * Network prefixes (Netmasks) are always recorded in normalized fashion, meaning that only
 * the network bits are set. This is what is returned in the insert() and lookup() return
 * values.
 *
 * Use swap if you need to move the tree to another NetmaskTree instance, it is WAY faster
 * than using copy ctor or assignment operator, since it moves the nodes and tree root to
 * new home instead of actually recreating the tree.
 *
 * Please see NetmaskGroup for example of simple use case. Other usecases can be found
 * from GeoIPBackend and Sortlist, and from dnsdist.
 */
template <typename T, class K = Netmask>
class NetmaskTree {
public:
  class Iterator;

  typedef K key_type;
  typedef T value_type;
  typedef std::pair<const key_type,value_type> node_type;
  typedef size_t size_type;
  typedef class Iterator iterator;

private:
  /** Single node in tree, internal use only.
    */
  class TreeNode : boost::noncopyable {
  public:
    explicit TreeNode() noexcept :
      parent(nullptr), node(), assigned(false), d_bits(0) {
    }
    explicit TreeNode(const key_type& key) noexcept :
      parent(nullptr), node({key.getNormalized(), value_type()}),
      assigned(false), d_bits(key.getFullBits()) {
    }

    //<! Makes a left leaf node with specified key.
    TreeNode* make_left(const key_type& key) {
      d_bits = node.first.getBits();
      left = make_unique<TreeNode>(key);
      left->parent = this;
      return left.get();
    }

    //<! Makes a right leaf node with specified key.
    TreeNode* make_right(const key_type& key) {
      d_bits = node.first.getBits();
      right = make_unique<TreeNode>(key);
      right->parent = this;
      return right.get();
    }

    //<! Splits branch at indicated bit position by inserting key
    TreeNode* split(const key_type& key, int bits) {
      if (parent == nullptr) {
        // not to be called on the root node
        throw std::logic_error(
          "NetmaskTree::TreeNode::split(): must not be called on root node");
      }

      // determine reference from parent
      unique_ptr<TreeNode>& parent_ref =
        (parent->left.get() == this ? parent->left : parent->right);
      if (parent_ref.get() != this) {
        throw std::logic_error(
          "NetmaskTree::TreeNode::split(): parent node reference is invalid");
      }

      // create new tree node for the new key
      TreeNode* new_node = new TreeNode(key);
      new_node->d_bits = bits;

      // attach the new node under our former parent
      unique_ptr<TreeNode> new_child(new_node);
      std::swap(parent_ref, new_child); // hereafter new_child points to "this"
      new_node->parent = parent;

      // attach "this" node below the new node
      // (left or right depending on bit)
      new_child->parent = new_node;
      if (new_child->node.first.getBit(-1-bits)) {
        std::swap(new_node->right, new_child);
      } else {
        std::swap(new_node->left, new_child);
      }

      return new_node;
    }

    //<! Forks branch for new key at indicated bit position
    TreeNode* fork(const key_type& key, int bits) {
      if (parent == nullptr) {
        // not to be called on the root node
        throw std::logic_error(
          "NetmaskTree::TreeNode::fork(): must not be called on root node");
      }

      // determine reference from parent
      unique_ptr<TreeNode>& parent_ref =
        (parent->left.get() == this ? parent->left : parent->right);
      if (parent_ref.get() != this) {
        throw std::logic_error(
          "NetmaskTree::TreeNode::fork(): parent node reference is invalid");
      }

      // create new tree node for the branch point
      TreeNode* branch_node = new TreeNode(node.first.getSuper(bits));
      branch_node->d_bits = bits;

      // the current node will now be a child of the new branch node
      // (hereafter new_child1 points to "this")
      unique_ptr<TreeNode> new_child1 = std::move(parent_ref);
      // attach the branch node under our former parent
      parent_ref = std::unique_ptr<TreeNode>(branch_node);
      branch_node->parent = parent;

      // create second new leaf node for the new key
      unique_ptr<TreeNode> new_child2 = make_unique<TreeNode>(key);
      TreeNode* new_node = new_child2.get();

      // attach the new child nodes below the branch node
      // (left or right depending on bit)
      new_child1->parent = branch_node;
      new_child2->parent = branch_node;
      if (new_child1->node.first.getBit(-1-bits)) {
        branch_node->right = std::move(new_child1);
        branch_node->left = std::move(new_child2);
      } else {
        branch_node->right = std::move(new_child2);
        branch_node->left = std::move(new_child1);
      }
      // now we have attached the new unique pointers to the tree:
      // - branch_node is below its parent
      // - new_child1 (ourselves) is below branch_node
      // - new_child2, the new leaf node, is below branch_node as well

      return new_node;
    }

    //<! Traverse left branch depth-first
    TreeNode *traverse_l()
    {
      TreeNode *tnode = this;

      while (tnode->left)
        tnode = tnode->left.get();
      return tnode;
    }

    //<! Traverse tree depth-first and in-order (L-N-R)
    TreeNode *traverse_lnr()
    {
      TreeNode *tnode = this;

      // precondition: descended left as deep as possible
      if (tnode->right) {
        // descend right
        tnode = tnode->right.get();
        // descend left as deep as possible and return next node
        return tnode->traverse_l();
      }

      // ascend to parent
      while (tnode->parent != nullptr) {
        TreeNode *prev_child = tnode;
        tnode = tnode->parent;

        // return this node, but only when we come from the left child branch
        if (tnode->left && tnode->left.get() == prev_child)
          return tnode;
      }
      return nullptr;
    }

    //<! Traverse only assigned nodes
    TreeNode *traverse_lnr_assigned()
    {
      TreeNode *tnode = traverse_lnr();

      while (tnode != nullptr && !tnode->assigned)
        tnode = tnode->traverse_lnr();
      return tnode;
    }

    unique_ptr<TreeNode> left;
    unique_ptr<TreeNode> right;
    TreeNode* parent;

    node_type node;
    bool assigned; //<! Whether this node is assigned-to by the application

    int d_bits; //<! How many bits have been used so far
  };

  void cleanup_tree(TreeNode* node)
  {
    // only cleanup this node if it has no children and node not assigned
    if (!(node->left || node->right || node->assigned)) {
      // get parent node ptr
      TreeNode* pparent = node->parent;
      // delete this node
      if (pparent) {
        if (pparent->left.get() == node)
          pparent->left.reset();
        else
          pparent->right.reset();
        // now recurse up to the parent
        cleanup_tree(pparent);
      }
    }
  }

  void copyTree(const NetmaskTree& rhs)
  {
    TreeNode *node;

    node = rhs.d_root.get();
    if (node != nullptr)
      node = node->traverse_l();
    while (node != nullptr) {
      if (node->assigned)
        insert(node->node.first).second = node->node.second;
      node = node->traverse_lnr();
    }
  }

public:
  class Iterator {
  public:
    typedef node_type value_type;
    typedef node_type& reference;
    typedef node_type* pointer;
    typedef std::forward_iterator_tag iterator_category;
    typedef size_type difference_type;

  private:
    friend class NetmaskTree;

    const NetmaskTree* d_tree;
    TreeNode* d_node;

    Iterator(const NetmaskTree* tree, TreeNode* node): d_tree(tree), d_node(node) {
    }

  public:
    Iterator(): d_tree(nullptr), d_node(nullptr) {}

    Iterator& operator++() // prefix
    {
      if (d_node == nullptr) {
        throw std::logic_error(
          "NetmaskTree::Iterator::operator++: iterator is invalid");
      }
      d_node = d_node->traverse_lnr_assigned();
      return *this;
    }
    Iterator operator++(int) // postfix
    {
      Iterator tmp(*this);
      operator++();
      return tmp;
    }

    reference operator*()
    {
      if (d_node == nullptr) {
        throw std::logic_error(
          "NetmaskTree::Iterator::operator*: iterator is invalid");
      }
      return d_node->node;
    }

    pointer operator->()
    {
      if (d_node == nullptr) {
        throw std::logic_error(
          "NetmaskTree::Iterator::operator->: iterator is invalid");
      }
      return &d_node->node;
    }

    bool operator==(const Iterator& rhs)
    {
      return (d_tree == rhs.d_tree && d_node == rhs.d_node);
    }
    bool operator!=(const Iterator& rhs)
    {
      return !(*this == rhs);
    }
  };

public:
  NetmaskTree() noexcept: d_root(new TreeNode()), d_left(nullptr), d_size(0) {
  }

  NetmaskTree(const NetmaskTree& rhs): d_root(new TreeNode()), d_left(nullptr), d_size(0) {
    copyTree(rhs);
  }

  NetmaskTree& operator=(const NetmaskTree& rhs) {
    clear();
    copyTree(rhs);
    return *this;
  }

  const iterator begin() const {
    return Iterator(this, d_left);
  }
  const iterator end() const {
    return Iterator(this, nullptr);
  }
  iterator begin() {
    return Iterator(this, d_left);
  }
  iterator end() {
    return Iterator(this, nullptr);
  }

  node_type& insert(const string &mask) {
    return insert(key_type(mask));
  }

  //<! Creates new value-pair in tree and returns it.
  node_type& insert(const key_type& key) {
    TreeNode* node;
    bool is_left = true;

    // we turn left on IPv4 and right on IPv6
    if (key.isIPv4()) {
      node = d_root->left.get();
      if (node == nullptr) {
        node = new TreeNode(key);
        node->assigned = true;
        node->parent = d_root.get();

        d_root->left = unique_ptr<TreeNode>(node);
        d_size++;
        d_left = node;
        return node->node;
      }
    } else if (key.isIPv6()) {
      node = d_root->right.get();
      if (node == nullptr) {
        node = new TreeNode(key);
        node->assigned = true;
        node->parent = d_root.get();

        d_root->right = unique_ptr<TreeNode>(node);
        d_size++;
        if (!d_root->left)
          d_left = node;
        return node->node;
      }
      if (d_root->left)
        is_left = false;
    } else
      throw NetmaskException("invalid address family");

    // we turn left on 0 and right on 1
    int bits = 0;
    for(; bits < key.getBits(); bits++) {
      bool vall = key.getBit(-1-bits);

      if (bits >= node->d_bits) {
        // the end of the current node is reached; continue with the next
        if (vall) {
          if (node->left || node->assigned)
            is_left = false;
          if (!node->right) {
            // the right branch doesn't exist yet; attach our key here
            node = node->make_right(key);
            break;
          }
          node = node->right.get();
        } else {
          if (!node->left) {
            // the left branch doesn't exist yet; attach our key here
            node = node->make_left(key);
            break;
          }
          node = node->left.get();
        }
        continue;
      }
      if (bits >= node->node.first.getBits()) {
        // the matching branch ends here, yet the key netmask has more bits; add a
        // child node below the existing branch leaf.
        if (vall) {
          if (node->assigned)
            is_left = false;
          node = node->make_right(key);
        } else {
          node = node->make_left(key);
        }
        break;
      }
      bool valr = node->node.first.getBit(-1-bits);
      if (vall != valr) {
        if (vall)
          is_left = false;
        // the branch matches just upto this point, yet continues in a different
        // direction; fork the branch.
        node = node->fork(key, bits);
        break;
      }
    }

    if (node->node.first.getBits() > key.getBits()) {
      // key is a super-network of the matching node; split the branch and
      // insert a node for the key above the matching node.
      node = node->split(key, key.getBits());
    }

    if (node->left)
      is_left = false;

    node_type& value = node->node;

    if (!node->assigned) {
      // only increment size if not assigned before
      d_size++;
      // update the pointer to the left-most tree node
      if (is_left)
        d_left = node;
      node->assigned = true;
    } else {
      // tree node exists for this value
      if (is_left && d_left != node) {
        throw std::logic_error(
          "NetmaskTree::insert(): lost track of left-most node in tree");
      }
    }

    return value;
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
    uint8_t max_bits = value.getBits();
    return lookupImpl(value, max_bits);
  }

  //<! Perform best match lookup for value, using at most max_bits
  const node_type* lookup(const ComboAddress& value, int max_bits = 128) const {
    uint8_t addr_bits = value.getBits();
    if (max_bits < 0 || max_bits > addr_bits) {
      max_bits = addr_bits;
    }

    return lookupImpl(key_type(value, max_bits), max_bits);
  }

  //<! Removes key from TreeMap.
  void erase(const key_type& key) {
    TreeNode *node = nullptr;

    if (key.isIPv4())
      node = d_root->left.get();
    else if (key.isIPv6())
      node = d_root->right.get();
    else
      throw NetmaskException("invalid address family");
    // no tree, no value
    if (node == nullptr) return;

    int bits = 0;
    for(; node && bits < key.getBits(); bits++) {
      bool vall = key.getBit(-1-bits);
      if (bits >= node->d_bits) {
        // the end of the current node is reached; continue with the next
        if (vall) {
          node = node->right.get();
        } else {
          node = node->left.get();
        }
        continue;
      }
      if (bits >= node->node.first.getBits()) {
        // the matching branch ends here
        if (key.getBits() != node->node.first.getBits())
          node = nullptr;
        break;
      }
      bool valr = node->node.first.getBit(-1-bits);
      if (vall != valr) {
        // the branch matches just upto this point, yet continues in a different
        // direction
        node = nullptr;
        break;
      }
    }
    if (node) {
      if (d_size == 0) {
        throw std::logic_error(
          "NetmaskTree::erase(): size of tree is zero before erase");
      }
      d_size--;
      node->assigned = false;
      node->node.second = value_type();

      if (node == d_left)
        d_left = d_left->traverse_lnr_assigned();

      cleanup_tree(node);
    }
  }

  void erase(const string& key) {
    erase(key_type(key));
  }

  //<! checks whether the container is empty.
  bool empty() const {
    return (d_size == 0);
  }

  //<! returns the number of elements
  size_type size() const {
    return d_size;
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
    d_root.reset(new TreeNode());
    d_left = nullptr;
    d_size = 0;
  }

  //<! swaps the contents with another NetmaskTree
  void swap(NetmaskTree& rhs) {
    std::swap(d_root, rhs.d_root);
    std::swap(d_left, rhs.d_left);
    std::swap(d_size, rhs.d_size);
  }

private:

  const node_type* lookupImpl(const key_type& value, uint8_t max_bits) const {
    TreeNode *node = nullptr;

    if (value.isIPv4())
      node = d_root->left.get();
    else if (value.isIPv6())
      node = d_root->right.get();
    else
      throw NetmaskException("invalid address family");
    if (node == nullptr) return nullptr;

    node_type *ret = nullptr;

    int bits = 0;
    for(; bits < max_bits; bits++) {
      bool vall = value.getBit(-1-bits);
      if (bits >= node->d_bits) {
        // the end of the current node is reached; continue with the next
        // (we keep track of last assigned node)
        if (node->assigned && bits == node->node.first.getBits())
          ret = &node->node;
        if (vall) {
          if (!node->right)
            break;
          node = node->right.get();
        } else {
          if (!node->left)
            break;
          node = node->left.get();
        }
        continue;
      }
      if (bits >= node->node.first.getBits()) {
        // the matching branch ends here
        break;
      }
      bool valr = node->node.first.getBit(-1-bits);
      if (vall != valr) {
        // the branch matches just upto this point, yet continues in a different
        // direction
        break;
      }
    }
    // needed if we did not find one in loop
    if (node->assigned && bits == node->node.first.getBits())
      ret = &node->node;

    // this can be nullptr.
    return ret;
  }

  unique_ptr<TreeNode> d_root; //<! Root of our tree
  TreeNode *d_left;
  size_type d_size;
};

/** This class represents a group of supplemental Netmask classes. An IP address matches
    if it is matched by one or more of the Netmask objects within.
*/
class NetmaskGroup
{
public:
  NetmaskGroup() noexcept {
  }

  //! If this IP address is matched by any of the classes within

  bool match(const ComboAddress *ip) const
  {
    const auto &ret = tree.lookup(*ip);
    if(ret) return ret->second;
    return false;
  }

  bool match(const ComboAddress& ip) const
  {
    return match(&ip);
  }

  bool lookup(const ComboAddress* ip, Netmask* nmp) const
  {
    const auto &ret = tree.lookup(*ip);
    if (ret) {
      if (nmp != nullptr)
        *nmp = ret->first;

      return ret->second;
    }
    return false;
  }

  bool lookup(const ComboAddress& ip, Netmask* nmp) const
  {
    return lookup(&ip, nmp);
  }

  //! Add this string to the list of possible matches
  void addMask(const string &ip, bool positive=true)
  {
    if(!ip.empty() && ip[0] == '!') {
      addMask(Netmask(ip.substr(1)), false);
    } else {
      addMask(Netmask(ip), positive);
    }
  }

  //! Add this Netmask to the list of possible matches
  void addMask(const Netmask& nm, bool positive=true)
  {
    tree.insert(nm).second=positive;
  }

  void addMasks(const NetmaskGroup& group, boost::optional<bool> positive)
  {
    for (const auto& entry : group.tree) {
      addMask(entry.first, positive ? *positive : entry.second);
    }
  }

  //! Delete this Netmask from the list of possible matches
  void deleteMask(const Netmask& nm)
  {
    tree.erase(nm);
  }

  void deleteMask(const std::string& ip)
  {
    if (!ip.empty())
      deleteMask(Netmask(ip));
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
      if(!(iter->second))
        str<<"!";
      str<<iter->first.toString();
    }
    return str.str();
  }

  void toStringVector(vector<string>* vec) const
  {
    for(auto iter = tree.begin(); iter != tree.end(); ++iter) {
      vec->push_back((iter->second ? "" : "!") + iter->first.toString());
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

class NetworkError : public runtime_error
{
public:
  NetworkError(const string& why="Network Error") : runtime_error(why.c_str())
  {}
  NetworkError(const char *why="Network Error") : runtime_error(why)
  {}
};

class AddressAndPortRange
{
public:
  AddressAndPortRange(): d_addrMask(0), d_portMask(0)
  {
    d_addr.sin4.sin_family = 0; // disable this doing anything useful
    d_addr.sin4.sin_port = 0; // this guarantees d_network compares identical
  }

  AddressAndPortRange(ComboAddress ca, uint8_t addrMask, uint8_t portMask = 0): d_addr(std::move(ca)), d_addrMask(addrMask), d_portMask(portMask)
  {
    if (!d_addr.isIPv4()) {
      d_portMask = 0;
    }

    uint16_t port = d_addr.getPort();
    if (d_portMask < 16) {
      uint16_t mask = ~(0xFFFF >> d_portMask);
      port = port & mask;
    }

    if (d_addrMask < d_addr.getBits()) {
      if (d_portMask > 0) {
        throw std::runtime_error("Trying to create a AddressAndPortRange with a reduced address mask (" + std::to_string(d_addrMask) + ") and a port range (" + std::to_string(d_portMask) + ")");
      }
      d_addr = Netmask(d_addr, d_addrMask).getMaskedNetwork();
    }
    d_addr.setPort(port);
  }

  uint8_t getFullBits() const
  {
    return d_addr.getBits() + 16;
  }

  uint8_t getBits() const
  {
    if (d_addrMask < d_addr.getBits()) {
      return d_addrMask;
    }

    return d_addr.getBits() + d_portMask;
  }

  /** Get the value of the bit at the provided bit index. When the index >= 0,
      the index is relative to the LSB starting at index zero. When the index < 0,
      the index is relative to the MSB starting at index -1 and counting down.
  */
  bool getBit(int index) const
  {
    if (index >= getFullBits()) {
      return false;
    }
    if (index < 0) {
      index = getFullBits() + index;
    }

    if (index < 16) {
      /* we are into the port bits */
      uint16_t port = d_addr.getPort();
      return ((port & (1U<<index)) != 0x0000);
    }

    index -= 16;

    return d_addr.getBit(index);
  }

  bool isIPv4() const
  {
    return d_addr.isIPv4();
  }

  bool isIPv6() const
  {
    return d_addr.isIPv6();
  }

  AddressAndPortRange getNormalized() const
  {
    return AddressAndPortRange(d_addr, d_addrMask, d_portMask);
  }

  AddressAndPortRange getSuper(uint8_t bits) const
  {
    if (bits <= d_addrMask) {
      return AddressAndPortRange(d_addr, bits, 0);
    }
    if (bits <= d_addrMask + d_portMask) {
      return AddressAndPortRange(d_addr, d_addrMask, d_portMask - (bits - d_addrMask));
    }

    return AddressAndPortRange(d_addr, d_addrMask, d_portMask);
  }

  const ComboAddress& getNetwork() const
  {
    return d_addr;
  }

  string toString() const
  {
    if (d_addrMask < d_addr.getBits() || d_portMask == 0) {
      return d_addr.toStringNoInterface() + "/" + std::to_string(d_addrMask);
    }
    return d_addr.toStringNoInterface() + ":" + std::to_string(d_addr.getPort()) + "/" + std::to_string(d_portMask);
  }

  bool empty() const
  {
    return d_addr.sin4.sin_family == 0;
  }

  bool operator==(const AddressAndPortRange& rhs) const
  {
    return tie(d_addr, d_addrMask, d_portMask) == tie(rhs.d_addr, rhs.d_addrMask, rhs.d_portMask);
  }

  bool operator<(const AddressAndPortRange& rhs) const
  {
    if (empty() && !rhs.empty()) {
      return false;
    }

    if (!empty() && rhs.empty()) {
      return true;
    }

    if (d_addrMask > rhs.d_addrMask) {
      return true;
    }

    if (d_addrMask < rhs.d_addrMask) {
      return false;
    }

    if (d_addr < rhs.d_addr) {
      return true;
    }

    if (d_addr > rhs.d_addr) {
      return false;
    }

    if (d_portMask > rhs.d_portMask) {
      return true;
    }

    if (d_portMask < rhs.d_portMask) {
      return false;
    }

    return d_addr.getPort() < rhs.d_addr.getPort();
  }

  bool operator>(const AddressAndPortRange& rhs) const
  {
    return rhs.operator<(*this);
  }

  struct hash
  {
    uint32_t operator()(const AddressAndPortRange& apr) const
    {
      ComboAddress::addressOnlyHash hashOp;
      uint16_t port = apr.d_addr.getPort();
      /* it's fine to hash the whole address and port because the non-relevant parts have
         been masked to 0 */
      return burtle(reinterpret_cast<const unsigned char*>(&port), sizeof(port), hashOp(apr.d_addr));
    }
  };

private:
  ComboAddress d_addr;
  uint8_t d_addrMask;
  /* only used for v4 addresses */
  uint8_t d_portMask;
};

int SSocket(int family, int type, int flags);
int SConnect(int sockfd, const ComboAddress& remote);
/* tries to connect to remote for a maximum of timeout seconds.
   sockfd should be set to non-blocking beforehand.
   returns 0 on success (the socket is writable), throw a
   runtime_error otherwise */
int SConnectWithTimeout(int sockfd, const ComboAddress& remote, const struct timeval& timeout);
int SBind(int sockfd, const ComboAddress& local);
int SAccept(int sockfd, ComboAddress& remote);
int SListen(int sockfd, int limit);
int SSetsockopt(int sockfd, int level, int opname, int value);
void setSocketIgnorePMTU(int sockfd, int family);
bool setReusePort(int sockfd);

#if defined(IP_PKTINFO)
  #define GEN_IP_PKTINFO IP_PKTINFO
#elif defined(IP_RECVDSTADDR)
  #define GEN_IP_PKTINFO IP_RECVDSTADDR
#endif

bool IsAnyAddress(const ComboAddress& addr);
bool HarvestDestinationAddress(const struct msghdr* msgh, ComboAddress* destination);
bool HarvestTimestamp(struct msghdr* msgh, struct timeval* tv);
void fillMSGHdr(struct msghdr* msgh, struct iovec* iov, cmsgbuf_aligned* cbuf, size_t cbufsize, char* data, size_t datalen, ComboAddress* addr);
int sendOnNBSocket(int fd, const struct msghdr *msgh);
ssize_t sendfromto(int sock, const void* data, size_t len, int flags, const ComboAddress& from, const ComboAddress& to);
size_t sendMsgWithOptions(int fd, const char* buffer, size_t len, const ComboAddress* dest, const ComboAddress* local, unsigned int localItf, int flags);

/* requires a non-blocking, connected TCP socket */
bool isTCPSocketUsable(int sock);

extern template class NetmaskTree<bool>;
ComboAddress parseIPAndPort(const std::string& input, uint16_t port);
