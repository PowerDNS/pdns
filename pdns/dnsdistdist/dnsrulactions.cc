#include "dnsrulactions.hh"
#include <iostream>

using namespace std;

TeeAction::TeeAction(const ComboAddress& ca, bool addECS) : d_remote(ca), d_addECS(addECS)
{
  d_fd=SSocket(d_remote.sin4.sin_family, SOCK_DGRAM, 0);
  SConnect(d_fd, d_remote);
  setNonBlocking(d_fd);
  d_worker=std::thread(std::bind(&TeeAction::worker, this));  
}

TeeAction::~TeeAction()
{
  d_pleaseQuit=true;
  close(d_fd);
  d_worker.join();
}

DNSAction::Action TeeAction::operator()(DNSQuestion* dq, string* ruleresult) const 
{
  if(dq->tcp) 
    d_tcpdrops++;
  else {
    ssize_t res;
    d_queries++;

    if(d_addECS) {
      std::string query;
      std::string larger;
      uint16_t len = dq->len;
      bool ednsAdded = false;
      bool ecsAdded = false;
      query.reserve(dq->size);
      query.assign((char*) dq->dh, len);

      handleEDNSClientSubnet((char*) query.c_str(), query.size(), dq->qname->wirelength(), &len, larger, &ednsAdded, &ecsAdded, *dq->remote);

      if (larger.empty()) {
        res = send(d_fd, query.c_str(), len, 0);
      }
      else {
        res = send(d_fd, larger.c_str(), larger.length(), 0);
      }
    }
    else {
      res = send(d_fd, (char*)dq->dh, dq->len, 0);
    }

    if (res <= 0)
      d_senderrors++;
  }
  return DNSAction::Action::None;
}

string TeeAction::toString() const
{
  return "tee to "+d_remote.toStringWithPort();
}

std::unordered_map<string,double> TeeAction::getStats() const
{
  return {{"queries", d_queries},
          {"responses", d_responses},
          {"recv-errors", d_recverrors},
          {"send-errors", d_senderrors},
          {"noerrors", d_noerrors},
          {"nxdomains", d_nxdomains},
          {"refuseds", d_refuseds},
          {"servfails", d_servfails},
          {"other-rcode", d_otherrcode},
          {"tcp-drops", d_tcpdrops}
  };
}

void TeeAction::worker()
{
  char packet[1500];
  int res=0;
  struct dnsheader* dh=(struct dnsheader*)packet;
  for(;;) {
    res=waitForData(d_fd, 0, 250000);
    if(d_pleaseQuit)
      break;
    if(res < 0) {
      usleep(250000);
      continue;
    }
    if(res==0)
      continue;
    res=recv(d_fd, packet, sizeof(packet), 0);
    if(res <= (int)sizeof(struct dnsheader)) 
      d_recverrors++;
    else if(res > 0)
      d_responses++;

    if(dh->rcode == RCode::NoError)
      d_noerrors++;
    else if(dh->rcode == RCode::ServFail)
      d_servfails++;
    else if(dh->rcode == RCode::NXDomain)
      d_nxdomains++;
    else if(dh->rcode == RCode::Refused)
      d_refuseds++;
    else if(dh->rcode == RCode::FormErr)
      d_formerrs++;
    else if(dh->rcode == RCode::NotImp)
      d_notimps++;
  }
}
