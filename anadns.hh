#ifndef PDNS_ANADNS_HH
#define PDNS_ANADNS_HH
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include <string>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include "dnsparser.hh"

using namespace boost;
using namespace std;

struct QuestionIdentifier
{
  QuestionIdentifier() 
  {}

  bool operator<(const QuestionIdentifier& rhs) const
  {
    return 
      tie(d_sourceip, d_destip, d_sourceport, d_destport, d_qname, d_qtype, d_id) < 
      tie(rhs.d_sourceip, rhs.d_destip, rhs.d_sourceport, rhs.d_destport, rhs.d_qname, rhs.d_qtype, rhs.d_id);
  }

  // the canonical direction is that of the question
  static QuestionIdentifier create(const struct ip* ip, const struct udphdr* udp, const MOADNSParser& mdp)
  {
    QuestionIdentifier ret;
    if(mdp.d_header.qr) {
      memcpy(&ret.d_sourceip, &ip->ip_dst, sizeof(ret.d_sourceip));
      ret.d_sourceip=htonl(ret.d_sourceip);

      memcpy(&ret.d_destip, &ip->ip_src, sizeof(ret.d_destip));
      ret.d_destip=htonl(ret.d_destip);

      ret.d_sourceport=htons(udp->uh_dport);
      ret.d_destport=htons(udp->uh_sport);
    }
    else {
      memcpy(&ret.d_sourceip, &ip->ip_src, sizeof(ret.d_sourceip));
      ret.d_sourceip=htonl(ret.d_sourceip);

      memcpy(&ret.d_destip, &ip->ip_dst, sizeof(ret.d_destip));
      ret.d_destip=htonl(ret.d_destip);

      ret.d_sourceport=htons(udp->uh_sport);
      ret.d_destport=htons(udp->uh_dport);
    }
    ret.d_qname=mdp.d_qname;
    ret.d_qtype=mdp.d_qtype;
    ret.d_id=mdp.d_header.id;
    return ret;
  }

  uint32_t d_sourceip;
  uint32_t d_destip;
  uint16_t d_sourceport;
  uint16_t d_destport;

  string d_qname;
  uint16_t d_qtype;
  uint16_t d_id;
};

inline ostream& operator<<(ostream &s, const QuestionIdentifier& qi) 
{
  s<< "'"<<qi.d_qname<<"|"<<DNSRecordContent::NumberToType(qi.d_qtype)<<"', with id " << qi.d_id <<" from ";
  uint32_t rint=qi.d_sourceip;

  s<< (rint>>24 & 0xff)<<".";
  s<< (rint>>16 & 0xff)<<".";
  s<< (rint>>8  & 0xff)<<".";
  s<< (rint     & 0xff);
  s<<":"<<qi.d_sourceport;
  
  s<<" to ";
  rint=qi.d_destip;
  s<< (rint>>24 & 0xff)<<".";
  s<< (rint>>16 & 0xff)<<".";
  s<< (rint>>8  & 0xff)<<".";
  s<< (rint     & 0xff);
  return s<<":"<<qi.d_destport;
}


#endif
