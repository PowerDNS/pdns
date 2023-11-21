#include "responsestats.hh"
#include "dnspacket.hh"
#include "statbag.hh"

/**
 *  Function that creates all the stats
 *  when udpOrTCP is true, it is udp
 */
void ResponseStats::submitResponse(DNSPacket &p, bool udpOrTCP, bool last) const {
  const string& buf=p.getString();
  static AtomicCounter &udpnumanswered=*StatBag::getStatBag().getPointer("udp-answers");
  static AtomicCounter &udpnumanswered4=*StatBag::getStatBag().getPointer("udp4-answers");
  static AtomicCounter &udpnumanswered6=*StatBag::getStatBag().getPointer("udp6-answers");
  static AtomicCounter &udpbytesanswered=*StatBag::getStatBag().getPointer("udp-answers-bytes");
  static AtomicCounter &udpbytesanswered4=*StatBag::getStatBag().getPointer("udp4-answers-bytes");
  static AtomicCounter &udpbytesanswered6=*StatBag::getStatBag().getPointer("udp6-answers-bytes");
  static AtomicCounter &tcpnumanswered=*StatBag::getStatBag().getPointer("tcp-answers");
  static AtomicCounter &tcpnumanswered4=*StatBag::getStatBag().getPointer("tcp4-answers");
  static AtomicCounter &tcpnumanswered6=*StatBag::getStatBag().getPointer("tcp6-answers");
  static AtomicCounter &tcpbytesanswered=*StatBag::getStatBag().getPointer("tcp-answers-bytes");
  static AtomicCounter &tcpbytesanswered4=*StatBag::getStatBag().getPointer("tcp4-answers-bytes");
  static AtomicCounter &tcpbytesanswered6=*StatBag::getStatBag().getPointer("tcp6-answers-bytes");

  ComboAddress accountremote = p.d_remote;
  if (p.d_inner_remote) accountremote = *p.d_inner_remote;

  if(p.d.aa) {
    if (p.d.rcode==RCode::NXDomain) {
      StatBag::getStatBag().inc("nxdomain-packets");
      StatBag::getStatBag().ringAccount("nxdomain-queries", p.qdomain, p.qtype);
    }
  } else if (p.d.rcode == RCode::Refused) {
    StatBag::getStatBag().inc("unauth-packets");
    StatBag::getStatBag().ringAccount("unauth-queries", p.qdomain, p.qtype);
    StatBag::getStatBag().ringAccount("remotes-unauth", accountremote);
  }

  if (udpOrTCP) { // udp
    udpnumanswered++;
    udpbytesanswered+=buf.length();
    if(accountremote.sin4.sin_family==AF_INET) {
      udpnumanswered4++;
      udpbytesanswered4+=buf.length();
    } else {
      udpnumanswered6++;
      udpbytesanswered6+=buf.length();
    }
  } else { //tcp
    tcpbytesanswered+=buf.length();
    if(accountremote.sin4.sin_family==AF_INET) {
      tcpbytesanswered4+=buf.length();
    } else {
      tcpbytesanswered6+=buf.length();
    }
    if(last) {
     tcpnumanswered++;
     if(accountremote.sin4.sin_family==AF_INET) {
      tcpnumanswered4++;
     } else {
      tcpnumanswered6++;
     }
    }
  }

  submitResponse(p.qtype.getCode(), buf.length(), p.d.rcode, udpOrTCP);
}
