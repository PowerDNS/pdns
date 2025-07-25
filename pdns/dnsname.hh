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
#include <array>
#include <cstring>
#include <optional>
#include <string>
#include <utility>
#include <vector>
#include <set>
#include <strings.h>
#include <stdexcept>
#include <sstream>
#include <iterator>
#include <unordered_set>
#include <string_view>

using namespace std::string_view_literals;

#include <boost/version.hpp>
#include <boost/container/string.hpp>

inline bool dns_isspace(char c)
{
  return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

extern const unsigned char dns_toupper_table[256],  dns_tolower_table[256];

inline unsigned char dns_toupper(unsigned char c)
{
  return dns_toupper_table[c];
}

inline unsigned char dns_tolower(unsigned char c)
{
  return dns_tolower_table[c];
}

#include "burtle.hh"
#include "views.hh"

/* Quest in life:
     accept escaped ascii presentations of DNS names and store them "natively"
     accept a DNS packet with an offset, and extract a DNS name from it
     build up DNSNames with prepend and append of 'raw' unescaped labels

   Be able to turn them into ASCII and "DNS name in a packet" again on request

   Provide some common operators for comparison, detection of being part of another domain

   NOTE: For now, everything MUST be . terminated, otherwise it is an error
*/

// DNSName: represents a case-insensitive string, allowing for non-printable
// characters. It is used for all kinds of name (of hosts, domains, keys,
// algorithm...) overall the PowerDNS codebase.
//
// The following type traits are provided:
// - EqualityComparable
// - LessThanComparable
// - Hash
#if defined(PDNS_AUTH)
class ZoneName;
#endif
class DNSName
{
public:
  static const size_t s_maxDNSNameLength = 255;

  DNSName() = default; //!< Constructs an *empty* DNSName, NOT the root!
  // Work around assertion in some boost versions that do not like self-assignment of boost::container::string
  DNSName& operator=(const DNSName& rhs)
  {
    if (this != &rhs) {
      d_storage = rhs.d_storage;
    }
    return *this;
  }
  DNSName& operator=(DNSName&& rhs) noexcept
  {
    if (this != &rhs) {
      d_storage = std::move(rhs.d_storage);
    }
    return *this;
  }
  DNSName(const DNSName& a) = default;
  DNSName(DNSName&& a) = default;

  explicit DNSName(std::string_view sw); //!< Constructs from a human formatted, escaped presentation
  DNSName(const char* p, size_t len, size_t offset, bool uncompress, uint16_t* qtype = nullptr, uint16_t* qclass = nullptr, unsigned int* consumed = nullptr, uint16_t minOffset = 0); //!< Construct from a DNS Packet, taking the first question if offset=12. If supplied, consumed is set to the number of bytes consumed from the packet, which will not be equal to the wire length of the resulting name in case of compression.

  bool isPartOf(const DNSName& rhs) const;   //!< Are we part of the rhs name? Note that name.isPartOf(name).
  inline bool operator==(const DNSName& rhs) const; //!< DNS-native comparison (case insensitive) - empty compares to empty
  bool operator!=(const DNSName& other) const { return !(*this == other); }
  bool matches(const std::string_view& wire_uncompressed) const; // DNS-native (case insensitive) comparison against raw data in wire format

  std::string toString(const std::string& separator=".", const bool trailing=true) const;              //!< Our human-friendly, escaped, representation
  void toString(std::string& output, const std::string& separator=".", const bool trailing=true) const;
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
    if(d_storage.size() + rhs.d_storage.size() > s_maxDNSNameLength + 1) // one extra byte for the second root label
      throwSafeRangeError("resulting name too long", rhs.d_storage.data(), rhs.d_storage.size());
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

  typedef boost::container::string string_t;

  const string_t& getStorage() const {
    return d_storage;
  }

  [[nodiscard]] size_t sizeEstimate() const
  {
    return d_storage.size(); // knowingly overestimating small strings as most string
                             // implementations have internal capacity and we always include
                             // sizeof(*this)
  }

  bool has8bitBytes() const; /* returns true if at least one byte of the labels forming the name is not included in [A-Za-z0-9_*./@ \\:-] */

  class RawLabelsVisitor
  {
  public:
    /* Zero-copy, zero-allocation raw labels visitor.
       The general idea is that we walk the labels in the constructor,
       filling up our array of labels position and setting the initial
       value of d_position at the number of labels.
       We then can easily provide string_view into the first and last label.
       pop_back() moves d_position one label closer to the start, so we
       can also easily walk back the labels in reverse order.
       There is no copy because we use a reference into the DNSName storage,
       so it is absolutely forbidden to alter the DNSName for as long as we
       exist, and no allocation because we use a static array (there cannot
       be more than 128 labels in a DNSName).
    */
    RawLabelsVisitor(const string_t& storage);
    std::string_view front() const;
    std::string_view back() const;
    bool pop_back();
    bool empty() const;
  private:
    std::array<uint8_t, 128> d_labelPositions;
    const string_t& d_storage;
    size_t d_position{0};
  };
  RawLabelsVisitor getRawLabelsVisitor() const;

#if defined(PDNS_AUTH) // [
  // Sugar while ZoneName::operator DNSName are made explicit
  bool isPartOf(const ZoneName& rhs) const;
  DNSName makeRelative(const ZoneName& zone) const;
  void makeUsRelative(const ZoneName& zone);
#endif // ]

private:
  string_t d_storage;

  void packetParser(const char* qpos, size_t len, size_t offset, bool uncompress, uint16_t* qtype, uint16_t* qclass, unsigned int* consumed, int depth, uint16_t minOffset);
  size_t parsePacketUncompressed(const pdns::views::UnsignedCharView& view, size_t position, bool uncompress);
  static void appendEscapedLabel(std::string& appendTo, const char* orig, size_t len);
  static std::string unescapeLabel(const std::string& orig);
  static void throwSafeRangeError(const std::string& msg, const char* buf, size_t length);
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


struct CanonDNSNameCompare
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

extern const DNSName g_rootdnsname, g_wildcarddnsname;

#if defined(PDNS_AUTH) // [
// ZoneName: this is equivalent to DNSName, but intended to only store zone
// names. In addition to the name, an optional variant is allowed. The
// variant is never part of a DNS packet; it can only be used by backends to
// perform specific extra processing.
// Variant names are limited to [a-z0-9_-].
// Conversions between DNSName and ZoneName are allowed, but must be explicit;
// conversions to DNSName lose the variant part.
class ZoneName
{
public:
  ZoneName() = default; //!< Constructs an *empty* ZoneName, NOT the root!
  // Work around assertion in some boost versions that do not like self-assignment of boost::container::string
  ZoneName& operator=(const ZoneName& rhs)
  {
    if (this != &rhs) {
      d_name = rhs.d_name;
      d_variant = rhs.d_variant;
    }
    return *this;
  }
  ZoneName& operator=(ZoneName&& rhs) noexcept
  {
    if (this != &rhs) {
      d_name = std::move(rhs.d_name);
      d_variant = std::move(rhs.d_variant);
    }
    return *this;
  }
  ZoneName(const ZoneName& a) = default;
  ZoneName(ZoneName&& a) = default;

  explicit ZoneName(std::string_view name);
  explicit ZoneName(std::string_view name, std::string_view variant) : d_name(name), d_variant(variant) {}
  explicit ZoneName(const DNSName& name, std::string_view variant = ""sv) : d_name(name), d_variant(variant) {}
  explicit ZoneName(std::string_view name, std::string_view::size_type sep);

  bool isPartOf(const ZoneName& rhs) const { return d_name.isPartOf(rhs.d_name); }
  bool isPartOf(const DNSName& rhs) const { return d_name.isPartOf(rhs); }
  bool operator==(const ZoneName& rhs) const { return d_name == rhs.d_name && d_variant == rhs.d_variant; }
  bool operator!=(const ZoneName& rhs) const { return !operator==(rhs); }

  // IMPORTANT! None of the "toString" routines will output the variant, but toLogString() and toStringFull().
  std::string toString(const std::string& separator=".", const bool trailing=true) const { return d_name.toString(separator, trailing); }
  void toString(std::string& output, const std::string& separator=".", const bool trailing=true) const { d_name.toString(output, separator, trailing); }
  std::string toLogString() const;
  std::string toStringNoDot() const { return d_name.toStringNoDot(); }
  std::string toStringRootDot() const { return d_name.toStringRootDot(); }
  std::string toStringFull(const std::string& separator=".", const bool trailing=true) const;

  bool chopOff() { return d_name.chopOff(); }
  ZoneName makeLowerCase() const
  {
    ZoneName ret(*this);
    ret.d_name.makeUsLowerCase();
    return ret;
  }
  void makeUsLowerCase() { d_name.makeUsLowerCase(); }
  bool empty() const { return d_name.empty(); }
  void clear() { d_name.clear(); d_variant.clear(); }
  void trimToLabels(unsigned int trim) { d_name.trimToLabels(trim); }
  size_t hash(size_t init=0) const;

  bool operator<(const ZoneName& rhs)  const;

  bool canonCompare(const ZoneName& rhs) const;

  // Conversion from ZoneName to DNSName
  explicit operator const DNSName&() const { return d_name; }
  explicit operator DNSName&() { return d_name; }

  bool hasVariant() const { return !d_variant.empty(); }
  std::string getVariant() const { return d_variant; }
  void setVariant(std::string_view);

  // Search for a variant separator: mandatory (when variants are used) trailing
  // dot followed by another dot and the variant name, and return the length of
  // the zone name without its variant part, or npos if there is no variant
  // present.
  static std::string_view::size_type findVariantSeparator(std::string_view name);

private:
  DNSName d_name;
  std::string d_variant{};
};

size_t hash_value(ZoneName const& zone);

std::ostream & operator<<(std::ostream &ostr, const ZoneName& zone);
namespace std {
    template <>
    struct hash<ZoneName> {
        size_t operator () (const ZoneName& dn) const { return dn.hash(0); }
    };
}

struct CanonZoneNameCompare
{
  bool operator()(const ZoneName& a, const ZoneName& b) const
  {
    return a.canonCompare(b);
  }
};
#else // ] [
using ZoneName = DNSName;
using CanonZoneNameCompare = CanonDNSNameCompare;
#endif // ]

extern const ZoneName g_rootzonename;

template<typename T>
struct SuffixMatchTree
{
  SuffixMatchTree(std::string name = "", bool endNode_ = false) :
    d_name(std::move(name)), endNode(endNode_)
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
  bool operator<(const SuffixMatchTree& rhs) const
  {
    return strcasecmp(d_name.c_str(), rhs.d_name.c_str()) < 0;
  }

  std::string d_name;
  mutable std::set<SuffixMatchTree, std::less<>> children;
  mutable bool endNode;
  mutable T d_value{};

  /* this structure is used to do a lookup without allocating and
     copying a string, using C++14's heterogeneous lookups in ordered
     containers */
  struct LightKey
  {
    std::string_view d_name;
    bool operator<(const SuffixMatchTree& smt) const
    {
      auto compareUpTo = std::min(this->d_name.size(), smt.d_name.size());
      auto ret = strncasecmp(this->d_name.data(), smt.d_name.data(), compareUpTo);
      if (ret != 0) {
        return ret < 0;
      }
      if (this->d_name.size() == smt.d_name.size()) {
        return ret < 0;
      }
      return this->d_name.size() < smt.d_name.size();
    }
  };

  bool operator<(const LightKey& lk) const
  {
    auto compareUpTo = std::min(this->d_name.size(), lk.d_name.size());
    auto ret = strncasecmp(this->d_name.data(), lk.d_name.data(), compareUpTo);
    if (ret != 0) {
      return ret < 0;
    }
    if (this->d_name.size() == lk.d_name.size()) {
      return ret < 0;
    }
    return this->d_name.size() < lk.d_name.size();
  }

  template<typename V>
  void visit(const V& v) const {
    for(const auto& c : children) {
      c.visit(v);
    }

    if (endNode) {
      v(*this);
    }
  }

  void add(const DNSName& name, T&& t)
  {
    auto labels = name.getRawLabels();
    add(labels, std::move(t));
  }

  void add(std::vector<std::string>& labels, T&& value) const
  {
    if (labels.empty()) { // this allows insertion of the root
      endNode = true;
      d_value = std::move(value);
    }
    else if(labels.size()==1) {
      auto res = children.emplace(*labels.begin(), true);
      if (!res.second) {
        // we might already have had the node as an
        // intermediary one, but it's now an end node
        if (!res.first->endNode) {
          res.first->endNode = true;
        }
      }
      res.first->d_value = std::move(value);
    }
    else {
      auto res = children.emplace(*labels.rbegin(), false);
      labels.pop_back();
      res.first->add(labels, std::move(value));
    }
  }

  void remove(const DNSName &name, bool subtree=false) const
  {
    auto labels = name.getRawLabels();
    remove(labels, subtree);
  }

  /* Removes the node at `labels`, also make sure that no empty
   * children will be left behind in memory
   */
  void remove(std::vector<std::string>& labels, bool subtree = false) const
  {
    if (labels.empty()) { // this allows removal of the root
      endNode = false;
      if (subtree) {
        children.clear();
      }
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

      if (subtree) {
        child->children.clear();
      }

      // If the child has no further children, just remove it from the set.
      if (child->children.empty()) {
        children.erase(child);
      }
      return;
    }

    // We are not at the end, let the child figure out what to do
    child->remove(labels);
  }

  T* lookup(const DNSName& name) const
  {
    auto bestNode = getBestNode(name);
    if (bestNode) {
      return &bestNode->d_value;
    }
    return nullptr;
  }

  std::optional<DNSName> getBestMatch(const DNSName& name) const
  {
    if (children.empty()) { // speed up empty set
      return endNode ? std::optional<DNSName>(g_rootdnsname) : std::nullopt;
    }

    auto visitor = name.getRawLabelsVisitor();
    return getBestMatch(visitor);
  }

  // Returns all end-nodes, fully qualified (not as separate labels)
  std::vector<DNSName> getNodes() const {
    std::vector<DNSName> ret;
    if (endNode) {
      ret.push_back(DNSName(d_name));
    }
    for (const auto& child : children) {
      auto nodes = child.getNodes();
      ret.reserve(ret.size() + nodes.size());
      for (const auto &node: nodes) {
        ret.push_back(node + DNSName(d_name));
      }
    }
    return ret;
  }

private:
  const SuffixMatchTree* getBestNode(const DNSName& name)  const
  {
    if (children.empty()) { // speed up empty set
      if (endNode) {
        return this;
      }
      return nullptr;
    }

    auto visitor = name.getRawLabelsVisitor();
    return getBestNode(visitor);
  }

  const SuffixMatchTree* getBestNode(DNSName::RawLabelsVisitor& visitor) const
  {
    if (visitor.empty()) { // optimization
      if (endNode) {
        return this;
      }
      return nullptr;
    }

    const LightKey lk{visitor.back()};
    auto child = children.find(lk);
    if (child == children.end()) {
      if (endNode) {
        return this;
      }
      return nullptr;
    }
    visitor.pop_back();
    auto result = child->getBestNode(visitor);
    if (result) {
      return result;
    }
    return endNode ? this : nullptr;
  }

  std::optional<DNSName> getBestMatch(DNSName::RawLabelsVisitor& visitor) const
  {
    if (visitor.empty()) { // optimization
      if (endNode) {
        return std::optional<DNSName>(d_name);
      }
      return std::nullopt;
    }

    const LightKey lk{visitor.back()};
    auto child = children.find(lk);
    if (child == children.end()) {
      if (endNode) {
        return std::optional<DNSName>(d_name);
      }
      return std::nullopt;
    }
    visitor.pop_back();
    auto result = child->getBestMatch(visitor);
    if (result) {
      if (!d_name.empty()) {
        result->appendRawLabel(d_name);
      }
      return result;
    }
    return endNode ? std::optional<DNSName>(d_name) : std::nullopt;
  }
};

/* Quest in life: serve as a rapid block list. If you add a DNSName to a root SuffixMatchNode,
   anything part of that domain will return 'true' in check */
struct SuffixMatchNode
{
  public:
    SuffixMatchNode() = default;
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

    std::optional<DNSName> getBestMatch(const DNSName& name) const
    {
      return d_tree.getBestMatch(name);
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

DNSName::string_t segmentDNSNameRaw(const char* input, size_t inputlen); // from ragel

bool DNSName::operator==(const DNSName& rhs) const
{
  if (rhs.empty() != empty() || rhs.d_storage.size() != d_storage.size()) {
    return false;
  }

  const auto* us = d_storage.cbegin();
  const auto* p = rhs.d_storage.cbegin();
  for (; us != d_storage.cend() && p != rhs.d_storage.cend(); ++us, ++p) {
    if (dns_tolower(*p) != dns_tolower(*us)) {
      return false;
    }
  }
  return true;
}

struct DNSNameSet: public std::unordered_set<DNSName> {
    std::string toString() const {
        std::ostringstream oss;
        std::copy(begin(), end(), std::ostream_iterator<DNSName>(oss, "\n"));
        return oss.str();
    }
};
