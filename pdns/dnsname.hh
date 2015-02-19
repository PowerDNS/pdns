#pragma once
#include <string>
#include <deque>

/* Quest in life: 
     accept escaped ascii presentations of DNS names and store them "natively"
     accept a DNS packet with an offset, and extract a DNS name from it
     build up DNSNames with prepend and append of 'raw' unescaped labels

   Be able to turn them into ASCII and "DNS name in a packet" again on request

   Provide some common operators for comparison, detection of being part of another domain 

   NOTE: For now, everything MUST be . terminated, otherwise it is an error
*/

// As a side note, we currently store the labels in a fancy deque<>, but we could go for native format storage easily

class DNSName
{
public:
  DNSName() {}                 //!< Constructs the root name
  DNSName(const char* p);      //!< Constructs from a human formatted, escaped presentation
  DNSName(const std::string& str) : DNSName(str.c_str()) {}   //!< Constructs from a human formatted, escaped presentation
  DNSName(const char* p, int len, uint16_t* qtype); //!< Construct from a DNS Packet, taking the first question
  
  bool isPartOf(const DNSName& rhs) const;   //!< Are we part of the rhs name?
  bool operator==(const DNSName& rhs) const; //!< DNS-native comparison (case insensitive)
  std::string toString() const;              //!< Our human-friendly, escaped, representation
  std::string toDNSString() const;           //!< Our representation in DNS native format
  void appendRawLabel(const std::string& str); //!< Append this unescaped label
  void prependRawLabel(const std::string& str); //!< Prepend this unescaped label
  std::deque<std::string> getRawLabels() const; //!< Individual raw unescaped labels
  bool chopOff();                               //!< Turn www.powerdns.com. into powerdns.com., returns false for .
private:
  std::deque<std::string> d_labels;
  static std::string escapeLabel(const std::string& orig);
  static std::string unescapeLabel(const std::string& orig);
};
