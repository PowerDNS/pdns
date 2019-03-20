#include "responsestats.hh"
#include "dnspacket.hh"
#include "statbag.hh"

extern StatBag S;
/**
 *  Function that creates all the stats
 *  when udpOrTCP is true, it is udp
 */
void ResponseStats::submitResponse(DNSPacket &p, bool udpOrTCP) {
  const string& buf=p.getString();
  static AtomicCounter &udpnumanswered=*S.getPointer("udp-answers");
  static AtomicCounter &udpnumanswered4=*S.getPointer("udp4-answers");
  static AtomicCounter &udpnumanswered6=*S.getPointer("udp6-answers");
  static AtomicCounter &udpbytesanswered=*S.getPointer("udp-answers-bytes");
  static AtomicCounter &udpbytesanswered4=*S.getPointer("udp4-answers-bytes");
  static AtomicCounter &udpbytesanswered6=*S.getPointer("udp6-answers-bytes");
  static AtomicCounter &tcpnumanswered=*S.getPointer("tcp-answers");
  static AtomicCounter &tcpnumanswered4=*S.getPointer("tcp4-answers");
  static AtomicCounter &tcpnumanswered6=*S.getPointer("tcp6-answers");
  static AtomicCounter &tcpbytesanswered=*S.getPointer("tcp-answers-bytes");
  static AtomicCounter &tcpbytesanswered4=*S.getPointer("tcp4-answers-bytes");
  static AtomicCounter &tcpbytesanswered6=*S.getPointer("tcp6-answers-bytes");

  if(p.d.aa) {
    if (p.d.rcode==RCode::NXDomain)
      S.ringAccount("nxdomain-queries", p.qdomain, p.qtype);
  } else if (p.d.rcode == RCode::Refused) {
    S.ringAccount("unauth-queries", p.qdomain, p.qtype);
    S.ringAccount("remotes-unauth",p.d_remote);
  }

  if (udpOrTCP) { // udp
    udpnumanswered++;
    udpbytesanswered+=buf.length();
    if(p.d_remote.sin4.sin_family==AF_INET) {
      udpnumanswered4++;
      udpbytesanswered4+=buf.length();
    } else {
      udpnumanswered6++;
      udpbytesanswered6+=buf.length();
    }
  } else { //tcp
    tcpnumanswered++;
    tcpbytesanswered+=buf.length();
    if(p.d_remote.sin4.sin_family==AF_INET) {
      tcpnumanswered4++;
      tcpbytesanswered4+=buf.length();
    } else {
      tcpnumanswered6++;
      tcpbytesanswered6+=buf.length();
    }
  }

  submitResponse(p.qtype.getCode(), buf.length(), p.d.rcode, udpOrTCP);
}
