
#pragma once

#include "dnsrecords.hh"
#include "iputils.hh"

class TSIGTCPVerifier
{
public:
  TSIGTCPVerifier(const TSIGTriplet& tt, const ComboAddress& remote, TSIGRecordContent& trc) :
    d_tt(tt),
    d_remote(remote),
    d_trc(trc)
  {
  }
  bool check(const string& data, const MOADNSParser& mdp);

private:
  const TSIGTriplet& d_tt;
  const ComboAddress& d_remote;
  TSIGRecordContent& d_trc;
  string d_prevMac; // RFC2845 4.4
  string d_signData;
  size_t d_tsigPos{0};
  uint8_t d_nonSignedMessages{0}; // RFC2845 4.4
};
