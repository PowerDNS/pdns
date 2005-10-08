#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"

int main(int argc, char** argv)
{
  vector<uint8_t> packet;
  
  for(unsigned int n=0; n < 1000000; ++n) {
    DNSPacketWriter pw(packet, "test.nl", 1);
    ARecordContent arc("1.2.3.4");
    arc.toPacket(pw);
    pw.commit();
  }
}

  
