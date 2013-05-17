#ifndef PDNS_DNSPCAP_HH
#define PDNS_DNSPCAP_HH

#include <cstdio>
#include <stdexcept>
#include <string>
#include "misc.hh"
#include <iostream>
#define __FAVOR_BSD
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#if defined(__NetBSD__)
#include <net/if.h>
#include <net/if_ether.h>
#elif defined (__OpenBSD__)
#include <net/if.h>
#include <netinet/if_ether.h>
#elif defined (__SVR4) && defined (__sun)
#include <sys/ethernet.h>
#else
#include <net/ethernet.h>
#endif
#include <vector>
#include <boost/format.hpp>
#include "namespaces.hh"

struct pdns_pcap_file_header {
  uint32_t magic;
  uint16_t version_major;
  uint16_t version_minor;
  uint32_t thiszone;     /* gmt to local correction */
  uint32_t sigfigs;    /* accuracy of timestamps */
  uint32_t snaplen;    /* max length saved portion of each pkt */
  uint32_t linktype;   /* data link type (LINKTYPE_*) */
};


struct pdns_timeval
{
  uint32_t tv_sec;
  uint32_t tv_usec;
};

struct pdns_pcap_pkthdr {
  struct pdns_timeval ts;      /* time stamp */
  uint32_t caplen;     /* length of portion present */
  uint32_t len;        /* length this packet (off wire) */
};

struct pdns_lcc_header {
  uint16_t lcc_pkttype;/* packet type */
  uint16_t lcc_hatype;/* link-layer address type */
  uint16_t lcc_halen;/* link-layer address length */
  uint8_t lcc_addr[8];/* link-layer address */
  uint16_t lcc_protocol;/* protocol */
};

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

  struct pdns_lcc_header* d_lcc;
  struct ether_header* d_ether;
  struct ip *d_ip;
  const struct tcphdr *d_tcp;
  const struct udphdr *d_udp;
  const uint8_t* d_payload;
  int d_len;
  struct pdns_pcap_pkthdr d_pheader;

  pdns_pcap_file_header d_pfh;
  unsigned int d_runts, d_oversized, d_correctpackets, d_nonetheripudp;
  char d_buffer[32768];
private:
  FILE* d_fp;
  string d_fname;
  int d_skipMediaHeader;
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
