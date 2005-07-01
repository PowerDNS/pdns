#ifndef PDNS_DNSPCAP_HH
#define PDNS_DNSPCAP_HH
#include <cstdio>
#include <stdexcept>
#include <string>

using namespace std;

class PcapPacketReader
{
public:
  class EofException : public runtime_error
  {
  public:
    EofException(const string& str="") : runtime_error(str)
    {
    }
  };

  PcapPacketReader(const string& fname); 

  ~PcapPacketReader();

  template<typename T>
  void checkedFread(T* ptr)
  {
    checkedFreadSize(ptr, sizeof(*ptr));
  }

  void checkedFreadSize(void* ptr, size_t size) ;

  bool getUDPPacket();

  struct iphdr *d_ip;
  const struct tcphdr *d_tcp;
  const struct udphdr *d_udp;
  const uint8_t* d_payload;
  int d_len;
  struct pcap_pkthdr d_pheader;
  pcap_file_header d_pfh;
  unsigned int d_runts, d_oversized, d_packets;
  char d_buffer[5000];
private:
  FILE* d_fp;
  string d_fname;
};

class PcapPacketWriter
{
public: 
  PcapPacketWriter(const string& fname, PcapPacketReader& ppr);
  
  void write();

  ~PcapPacketWriter();

private:
  string d_fname;
  const PcapPacketReader& d_ppr;

  FILE *d_fp;
}; 

#endif // DNSPCAP_HH
