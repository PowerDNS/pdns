#ifndef PDNS_ANADNS_HH
#define PDNS_ANADNS_HH
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <string>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "dnsparser.hh"
#include "iputils.hh"
#include "namespaces.hh"
#include "namespaces.hh"

struct QuestionIdentifier
{
  QuestionIdentifier() 
  {}

  bool operator<(const QuestionIdentifier& rhs) const
  {
    return 
      tie(d_source, d_dest, d_qname, d_qtype, d_id) < 
      tie(rhs.d_source, rhs.d_dest, rhs.d_qname, rhs.d_qtype, rhs.d_id);
  }

  // the canonical direction is that of the question
  static QuestionIdentifier create(const ComboAddress& src, const ComboAddress& dst, const MOADNSParser& mdp)
  {
    QuestionIdentifier ret;

    if(mdp.d_header.qr) {
      ret.d_source = dst;
      ret.d_dest = src;
    }
    else {
      ret.d_source = src;
      ret.d_dest = dst;
    }
    ret.d_qname=mdp.d_qname;
    ret.d_qtype=mdp.d_qtype;
    ret.d_id=mdp.d_header.id;
    return ret;
  }

  ComboAddress d_source, d_dest;

  string d_qname;
  uint16_t d_qtype;
  uint16_t d_id;
};

inline ostream& operator<<(ostream &s, const QuestionIdentifier& qi) 
{
  s<< "'"<<qi.d_qname<<"|"<<DNSRecordContent::NumberToType(qi.d_qtype)<<"', with id " << qi.d_id <<" from "<<qi.d_source.toStringWithPort();
  
  s<<" to " << qi.d_dest.toStringWithPort();
  return s;
}


#endif
