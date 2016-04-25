#include "dnsrulactions.hh"
#include <iostream>

using namespace std;

TeeAction::TeeAction(const ComboAddress& ca) : d_remote(ca)
{
  cerr<<"Created!"<<endl;
  d_fd=SSocket(d_remote.sin4.sin_family, SOCK_DGRAM, 0);
  SConnect(d_fd, d_remote);
  d_worker=std::thread(std::bind(&TeeAction::worker, this));
  
}

TeeAction::~TeeAction()
{
  cerr<<"Closding down!"<<endl;
  d_pleaseQuit=true;
  close(d_fd);
  d_worker.join();
}

DNSAction::Action TeeAction::operator()(DNSQuestion* dq, string* ruleresult) const 
{
  d_queries++;
  send(d_fd, (char*)dq->dh, dq->len, 0);
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
        {"socket-errors", d_errors}};
}

void TeeAction::worker()
{
  char packet[1500];
  int res=0;
  for(;;) {
    res=recv(d_fd, packet, sizeof(packet), 0);
    if(res < 0) 
      d_errors++;
    else if(res > 0)
      d_responses++;
    if(d_pleaseQuit)
      break;
  }
}
