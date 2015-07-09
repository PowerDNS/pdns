#pragma once
#include <string>
#include <vector>
#include <set>
#include <deque>
#include <strings.h>
#include <stdexcept>
// #include "dns.hh"
// #include "logger.hh"

// #include <ext/vstring.h>

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
  DNSName() : d_empty(true) {}                 //!< Don't constructs the root name
  DNSName(const char* p);      //!< Constructs from a human formatted, escaped presentation
  DNSName(const std::string& str) : DNSName(str.c_str()) {}   //!< Constructs from a human formatted, escaped presentation
  DNSName(const char* p, int len, int offset, bool uncompress, uint16_t* qtype=0, uint16_t* qclass=0, unsigned int* consumed=0); //!< Construct from a DNS Packet, taking the first question
  
  bool isPartOf(const DNSName& rhs) const;   //!< Are we part of the rhs name?
  bool operator==(const DNSName& rhs) const; //!< DNS-native comparison (case insensitive)
  bool operator!=(const DNSName& other) const { return !(*this == other); }

  std::string toString(const std::string& separator=".", const bool trailing=true) const;              //!< Our human-friendly, escaped, representation
  std::string toStringNoDot() const { return toString(".", false); }
  std::string toDNSString() const;           //!< Our representation in DNS native format
  void appendRawLabel(const std::string& str); //!< Append this unescaped label
  void prependRawLabel(const std::string& str); //!< Prepend this unescaped label
  std::vector<std::string> getRawLabels() const; //!< Individual raw unescaped labels
  bool chopOff();                               //!< Turn www.powerdns.com. into powerdns.com., returns false for .
  DNSName makeRelative(const DNSName& zone) const;
  DNSName labelReverse() const;
  bool isWildcard() const;
  unsigned int countLabels() const;
  size_t length() const; // FIXME400 remove me?
  bool empty() const { return d_empty; }
  bool isRoot() const { return !d_empty && d_storage.empty(); }
  void clear() { d_storage.clear(); d_empty=true; }
  void trimToLabels(unsigned int);
  DNSName& operator+=(const DNSName& rhs)
  {
    if(d_storage.size() + rhs.d_storage.size() > 254) // reserve one byte for the root label
      throw std::range_error("name too long");

    d_storage+=rhs.d_storage;
    d_empty&=rhs.d_empty;
    return *this;
  }

  bool operator<(const DNSName& rhs)  const // this delivers _some_ kind of ordering, but not one useful in a DNS context. Really fast though.
  {
    return std::lexicographical_compare(d_storage.rbegin(), d_storage.rend(), 
				 rhs.d_storage.rbegin(), rhs.d_storage.rend(),
				 [](const char& a, const char& b) {
					  return tolower(a) < tolower(b); 
					}); // note that this is case insensitive, including on the label lengths
  }

  template<class Archive>
  void serialize(Archive &ar, const unsigned int version)
  {
    ar & d_storage;
    ar & d_empty;
  }

  bool canonCompare(const DNSName& rhs) const;
  
private:
  //  typedef __gnu_cxx::__sso_string string_t;
  typedef std::string string_t;
  string_t d_storage;
  bool d_empty;
  int d_recurse;

  void packetParser(const char* p, int len, int offset, bool uncompress, uint16_t* qtype=0, uint16_t* qclass=0, unsigned int* consumed=0);
  static std::string escapeLabel(const std::string& orig);
  static std::string unescapeLabel(const std::string& orig);
};

size_t hash_value(DNSName const& d);

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

/* Quest in life: serve as a rapid block list. If you add a DNSName to a root SuffixMatchNode, 
   anything part of that domain will return 'true' in check */
struct SuffixMatchNode
{
  SuffixMatchNode(const std::string& name_="", bool endNode_=false) : name(name_), endNode(endNode_)
  {}
  std::string name;
  std::string d_human;
  mutable std::set<SuffixMatchNode> children;
  mutable bool endNode;
  bool operator<(const SuffixMatchNode& rhs) const
  {
    return strcasecmp(name.c_str(), rhs.name.c_str()) < 0;
  }

  void add(const DNSName& name) 
  {
    if(!d_human.empty())
      d_human.append(", ");
    d_human += name.toString();
    add(name.getRawLabels());
  }

  void add(std::vector<std::string> labels) const
  {
    if(labels.empty()) { // this allows insertion of the root
      endNode=true;
    }
    else if(labels.size()==1) {
      children.insert(SuffixMatchNode(*labels.begin(), true));
    }
    else {
      auto res=children.insert(SuffixMatchNode(*labels.rbegin(), false));
      labels.pop_back();
      res.first->add(labels);
    }
  }

  bool check(const DNSName& name)  const
  {
    if(children.empty()) // speed up empty set
      return endNode;
    return check(name.getRawLabels());
  }

  bool check(std::vector<std::string> labels) const
  {
    if(labels.empty()) // optimization
      return endNode; 

    SuffixMatchNode smn(*labels.rbegin());
    auto child = children.find(smn);
    if(child == children.end())
      return endNode;
    labels.pop_back();
    return child->check(labels);
  }
  
  std::string toString() const
  {
    return d_human;
  }

};
