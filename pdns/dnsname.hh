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
#include <set>
#include <deque>
#include <strings.h>
#include <stdexcept>
#include <sstream>
#include <iterator>
#include <unordered_set>

#include <boost/version.hpp>

// it crashes on OSX and doesn't compile on OpenBSD
#if BOOST_VERSION >= 105300 && ! defined( __APPLE__ ) && ! defined(__OpenBSD__)
#include <boost/container/string.hpp>
#endif

#include "ascii.hh"

uint32_t burtleCI(const unsigned char* k, uint32_t length, uint32_t init);

// #include "dns.hh"
// #include "logger.hh"

//#include <ext/vstring.h>

/* Quest in life: 
     accept escaped ascii presentations of DNS names and store them "natively"
     accept a DNS packet with an offset, and extract a DNS name from it
     build up DNSNames with prepend and append of 'raw' unescaped labels

   Be able to turn them into ASCII and "DNS name in a packet" again on request

   Provide some common operators for comparison, detection of being part of another domain 

   NOTE: For now, everything MUST be . terminated, otherwise it is an error
*/

class DNSName
{
public:
  DNSName()  {}          //!< Constructs an *empty* DNSName, NOT the root!
  explicit DNSName(const char* p);      //!< Constructs from a human formatted, escaped presentation
  explicit DNSName(const std::string& str) : DNSName(str.c_str()) {}; //!< Constructs from a human formatted, escaped presentation
  DNSName(const char* p, int len, int offset, bool uncompress, uint16_t* qtype=0, uint16_t* qclass=0, unsigned int* consumed=0, uint16_t minOffset=0); //!< Construct from a DNS Packet, taking the first question if offset=12
  
  bool isPartOf(const DNSName& rhs) const;   //!< Are we part of the rhs name?
  inline bool operator==(const DNSName& rhs) const; //!< DNS-native comparison (case insensitive) - empty compares to empty
  bool operator!=(const DNSName& other) const { return !(*this == other); }

  std::string toString(const std::string& separator=".", const bool trailing=true) const;              //!< Our human-friendly, escaped, representation
  std::string toLogString() const; //!< like plain toString, but returns (empty) on empty names
  std::string toStringNoDot() const { return toString(".", false); }
  std::string toStringRootDot() const { if(isRoot()) return "."; else return toString(".", false); }
  std::string toDNSString() const;           //!< Our representation in DNS native format
  std::string toDNSStringLC() const;           //!< Our representation in DNS native format, lower cased
  void appendRawLabel(const std::string& str); //!< Append this unescaped label
  void appendRawLabel(const char* start, unsigned int length); //!< Append this unescaped label
  void prependRawLabel(const std::string& str); //!< Prepend this unescaped label
  std::vector<std::string> getRawLabels() const; //!< Individual raw unescaped labels
  std::string getRawLabel(unsigned int pos) const; //!< Get the specified raw unescaped label
  DNSName getLastLabel() const; //!< Get the DNSName of the last label
  bool chopOff();                               //!< Turn www.powerdns.com. into powerdns.com., returns false for .
  DNSName makeRelative(const DNSName& zone) const;
  DNSName makeLowerCase() const
  {
    DNSName ret(*this);
    ret.makeUsLowerCase();
    return ret;
  }
  void makeUsLowerCase()
  {
    for(auto & c : d_storage) {
      c=dns_tolower(c);
    }
  }
  void makeUsRelative(const DNSName& zone);
  DNSName getCommonLabels(const DNSName& other) const; //!< Return the list of common labels from the top, for example 'c.d' for 'a.b.c.d' and 'x.y.c.d'
  DNSName labelReverse() const;
  bool isWildcard() const;
  bool isHostname() const;
  unsigned int countLabels() const;
  size_t wirelength() const; //!< Number of total bytes in the name
  bool empty() const { return d_storage.empty(); }
  bool isRoot() const { return d_storage.size()==1 && d_storage[0]==0; }
  void clear() { d_storage.clear(); }
  void trimToLabels(unsigned int);
  size_t hash(size_t init=0) const
  {
    return burtleCI((const unsigned char*)d_storage.c_str(), d_storage.size(), init);
  }
  DNSName& operator+=(const DNSName& rhs)
  {
    if(d_storage.size() + rhs.d_storage.size() > 256) // one extra byte for the second root label
      throw std::range_error("name too long");
    if(rhs.empty())
      return *this;

    if(d_storage.empty())
      d_storage+=rhs.d_storage;
    else
      d_storage.replace(d_storage.length()-1, rhs.d_storage.length(), rhs.d_storage);

    return *this;
  }

  bool operator<(const DNSName& rhs)  const // this delivers _some_ kind of ordering, but not one useful in a DNS context. Really fast though.
  {
    return std::lexicographical_compare(d_storage.rbegin(), d_storage.rend(), 
				 rhs.d_storage.rbegin(), rhs.d_storage.rend(),
				 [](const unsigned char& a, const unsigned char& b) {
					  return dns_tolower(a) < dns_tolower(b);
					}); // note that this is case insensitive, including on the label lengths
  }

  inline bool canonCompare(const DNSName& rhs) const;
  bool slowCanonCompare(const DNSName& rhs) const;  

#if BOOST_VERSION >= 105300 && ! defined( __APPLE__ ) && ! defined(__OpenBSD__)
  typedef boost::container::string string_t;
#else
  typedef std::string string_t;
#endif
  const string_t& getStorage() const {
    return d_storage;
  }
private:
  string_t d_storage;

  void packetParser(const char* p, int len, int offset, bool uncompress, uint16_t* qtype, uint16_t* qclass, unsigned int* consumed, int depth, uint16_t minOffset);
  static void appendEscapedLabel(std::string& appendTo, const char* orig, size_t len);
  static std::string unescapeLabel(const std::string& orig);
};

size_t hash_value(DNSName const& d);


inline bool DNSName::canonCompare(const DNSName& rhs) const
{
  //      01234567890abcd
  // us:  1a3www4ds9a2nl
  // rhs: 3www6online3com
  // to compare, we start at the back, is nl < com? no -> done
  //
  // 0,2,6,a
  // 0,4,a
  
  uint8_t ourpos[64], rhspos[64];
  uint8_t ourcount=0, rhscount=0;
  //cout<<"Asked to compare "<<toString()<<" to "<<rhs.toString()<<endl;
  for(const unsigned char* p = (const unsigned char*)d_storage.c_str(); p < (const unsigned char*)d_storage.c_str() + d_storage.size() && *p && ourcount < sizeof(ourpos); p+=*p+1)
    ourpos[ourcount++]=(p-(const unsigned char*)d_storage.c_str());
  for(const unsigned char* p = (const unsigned char*)rhs.d_storage.c_str(); p < (const unsigned char*)rhs.d_storage.c_str() + rhs.d_storage.size() && *p && rhscount < sizeof(rhspos); p+=*p+1)
    rhspos[rhscount++]=(p-(const unsigned char*)rhs.d_storage.c_str());

  if(ourcount == sizeof(ourpos) || rhscount==sizeof(rhspos)) {
    return slowCanonCompare(rhs);
  }
  
  for(;;) {
    if(ourcount == 0 && rhscount != 0)
      return true;
    if(rhscount == 0)
      return false;
    ourcount--;
    rhscount--;

    bool res=std::lexicographical_compare(
					  d_storage.c_str() + ourpos[ourcount] + 1, 
					  d_storage.c_str() + ourpos[ourcount] + 1 + *(d_storage.c_str() + ourpos[ourcount]),
					  rhs.d_storage.c_str() + rhspos[rhscount] + 1, 
					  rhs.d_storage.c_str() + rhspos[rhscount] + 1 + *(rhs.d_storage.c_str() + rhspos[rhscount]),
					  [](const unsigned char& a, const unsigned char& b) {
					    return dns_tolower(a) < dns_tolower(b);
					  });
    
    //    cout<<"Forward: "<<res<<endl;
    if(res)
      return true;

    res=std::lexicographical_compare(	  rhs.d_storage.c_str() + rhspos[rhscount] + 1, 
					  rhs.d_storage.c_str() + rhspos[rhscount] + 1 + *(rhs.d_storage.c_str() + rhspos[rhscount]),
					  d_storage.c_str() + ourpos[ourcount] + 1, 
					  d_storage.c_str() + ourpos[ourcount] + 1 + *(d_storage.c_str() + ourpos[ourcount]),
					  [](const unsigned char& a, const unsigned char& b) {
					    return dns_tolower(a) < dns_tolower(b);
					  });
    //    cout<<"Reverse: "<<res<<endl;
    if(res)
      return false;
  }
  return false;
}


struct CanonDNSNameCompare: public std::binary_function<DNSName, DNSName, bool>
{
  bool operator()(const DNSName&a, const DNSName& b) const
  {
    return a.canonCompare(b);
  }
};

inline DNSName operator+(const DNSName& lhs, const DNSName& rhs)
{
  DNSName ret=lhs;
  ret += rhs;
  return ret;
}

template<typename T>
struct SuffixMatchTree
{
  SuffixMatchTree(const std::string& name="", bool endNode_=false) : d_name(name), endNode(endNode_)
  {}

  SuffixMatchTree(const SuffixMatchTree& rhs): d_name(rhs.d_name), children(rhs.children), endNode(rhs.endNode)
  {
    if (endNode) {
      d_value = rhs.d_value;
    }
  }
  SuffixMatchTree & operator=(const SuffixMatchTree &rhs)
  {
    d_name = rhs.d_name;
    children = rhs.children;
    endNode = rhs.endNode;
    if (endNode) {
      d_value = rhs.d_value;
    }
    return *this;
  }
  
  std::string d_name;
  mutable std::set<SuffixMatchTree> children;
  mutable bool endNode;
  mutable T d_value;
  bool operator<(const SuffixMatchTree& rhs) const
  {
    return strcasecmp(d_name.c_str(), rhs.d_name.c_str()) < 0;
  }
  typedef SuffixMatchTree value_type;

  template<typename V>
  void visit(const V& v) const {
    for(const auto& c : children)
      c.visit(v);
    if(endNode)
      v(*this);
  }

  void add(const DNSName& name, const T& t)
  {
    add(name.getRawLabels(), t);
  }

  void add(std::vector<std::string> labels, const T& value) const
  {
    if(labels.empty()) { // this allows insertion of the root
      endNode=true;
      d_value=value;
    }
    else if(labels.size()==1) {
      auto res=children.emplace(*labels.begin(), true);
      if(!res.second) {
        // we might already have had the node as an
        // intermediary one, but it's now an end node
        if(!res.first->endNode) {
          res.first->endNode = true;
        }
      }
      res.first->d_value = value;
    }
    else {
      auto res=children.emplace(*labels.rbegin(), false);
      labels.pop_back();
      res.first->add(labels, value);
    }
  }

  void remove(const DNSName &name) const
  {
    remove(name.getRawLabels());
  }

  /* Removes the node at `labels`, also make sure that no empty
   * children will be left behind in memory
   */
  void remove(std::vector<std::string> labels) const
  {
    if (labels.empty()) { // this allows removal of the root
      endNode = false;
      return;
    }

    SuffixMatchTree smt(*labels.rbegin());
    auto child = children.find(smt);
    if (child == children.end()) {
      // No subnode found, we're done
      return;
    }

    // We have found a child
    labels.pop_back();
    if (labels.empty()) {
      // The child is no longer an endnode
      child->endNode = false;

      // If the child has no further children, just remove it from the set.
      if (child->children.empty()) {
        children.erase(child);
      }
      return;
    }

    // We are not at the end, let the child figure out what to do
    child->remove(labels);
  }

  T* lookup(const DNSName& name)  const
  {
    if(children.empty()) { // speed up empty set
      if(endNode)
        return &d_value;
      return nullptr;
    }

    return lookup(name.getRawLabels());
  }

  T* lookup(std::vector<std::string> labels) const
  {
    if(labels.empty()) { // optimization
      if(endNode)
        return &d_value;
      return nullptr;
    }

    SuffixMatchTree smn(*labels.rbegin());
    auto child = children.find(smn);
    if(child == children.end()) {
      if(endNode)
        return &d_value;
      return nullptr;
    }
    labels.pop_back();
    auto result = child->lookup(labels);
    if (result) {
      return result;
    }
    return endNode ? &d_value : nullptr;
  }

  // Returns all end-nodes, fully qualified (not as separate labels)
  std::vector<DNSName> getNodes() const {
    std::vector<DNSName> ret;
    if (endNode) {
      ret.push_back(DNSName(d_name));
    }
    for (const auto& child : children) {
      auto nodes = child.getNodes();
      for (const auto &node: nodes) {
        ret.push_back(node + DNSName(d_name));
      }
    }
    return ret;
  }
};

/* Quest in life: serve as a rapid block list. If you add a DNSName to a root SuffixMatchNode,
   anything part of that domain will return 'true' in check */
struct SuffixMatchNode
{
  public:
    SuffixMatchNode()
    {}
    SuffixMatchTree<bool> d_tree;

    void add(const DNSName& dnsname)
    {
      d_tree.add(dnsname, true);
      d_nodes.insert(dnsname);
    }

    void add(const std::string& name)
    {
      add(DNSName(name));
    }

    void add(std::vector<std::string> labels)
    {
      d_tree.add(labels, true);
      DNSName tmp;
      while (!labels.empty()) {
        tmp.appendRawLabel(labels.back());
        labels.pop_back(); // This is safe because we have a copy of labels
      }
      d_nodes.insert(tmp);
    }

    void remove(const DNSName& name)
    {
      d_tree.remove(name);
      d_nodes.erase(name);
    }

    void remove(std::vector<std::string> labels)
    {
      d_tree.remove(labels);
      DNSName tmp;
      while (!labels.empty()) {
        tmp.appendRawLabel(labels.back());
        labels.pop_back(); // This is safe because we have a copy of labels
      }
      d_nodes.erase(tmp);
    }

    bool check(const DNSName& dnsname) const
    {
      return d_tree.lookup(dnsname) != nullptr;
    }

    std::string toString() const
    {
      std::string ret;
      bool first = true;
      for (const auto& n : d_nodes) {
        if (!first) {
          ret += ", ";
        }
        first = false;
        ret += n.toString();
      }
      return ret;
    }

  private:
    mutable std::set<DNSName> d_nodes; // Only used for string generation
};

std::ostream & operator<<(std::ostream &os, const DNSName& d);
namespace std {
    template <>
    struct hash<DNSName> {
        size_t operator () (const DNSName& dn) const { return dn.hash(0); }
    };
}

DNSName::string_t segmentDNSNameRaw(const char* input); // from ragel
bool DNSName::operator==(const DNSName& rhs) const
{
  if(rhs.empty() != empty() || rhs.d_storage.size() != d_storage.size())
    return false;

  auto us = d_storage.cbegin();
  auto p = rhs.d_storage.cbegin();
  for(; us != d_storage.cend() && p != rhs.d_storage.cend(); ++us, ++p) { 
    if(dns_tolower(*p) != dns_tolower(*us))
      return false;
  }
  return true;
}

extern const DNSName g_rootdnsname, g_wildcarddnsname;

struct DNSNameSet: public std::unordered_set<DNSName> {
    std::string toString() const {
        std::ostringstream oss;
        std::copy(begin(), end(), std::ostream_iterator<DNSName>(oss, "\n"));
        return oss.str();
    }
};
