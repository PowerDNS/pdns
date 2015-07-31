#pragma once
#include "misc.hh"
#include "dnspacket.hh"

class ResponseStats
{
public:
  ResponseStats();

  void submitResponse(DNSPacket &p, bool udpOrTCP);
  void submitResponse(uint16_t qtype, uint16_t respsize, bool udpOrTCP);
  map<uint16_t, uint64_t> getQTypeResponseCounts();
  map<uint16_t, uint64_t> getSizeResponseCounts();
  string getQTypeReport();

private:
  vector<AtomicCounter> d_qtypecounters;
  typedef vector<pair<uint16_t, uint64_t> > sizecounters_t;
  sizecounters_t d_sizecounters;
};

extern ResponseStats g_rs;
