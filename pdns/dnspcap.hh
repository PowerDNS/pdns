/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#pragma once
#include <cstdio>
#include <stdexcept>
#include "iputils.hh"
#include <string>
#include "misc.hh"
#include <iostream>
#define __FAVOR_BSD
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
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
  uint32_t tv_sec{0};
  uint32_t tv_usec{0};
};

struct pdns_pcap_pkthdr {
  struct pdns_timeval ts;      /* time stamp */
  uint32_t caplen{0};     /* length of portion present */
  uint32_t len{0};        /* length this packet (off wire) */
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
    EofException(const string& str="PcapPacketReader::EofException") : runtime_error(str)
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

  ComboAddress getSource() const;
  ComboAddress getDest() const;

  struct pdns_lcc_header* d_lcc{nullptr};
  struct ether_header* d_ether{nullptr};
  struct ip *d_ip{nullptr};
  struct ip6_hdr *d_ip6{nullptr};
  const struct tcphdr *d_tcp{nullptr};
  const struct udphdr *d_udp{nullptr};
  const uint8_t* d_payload{nullptr};
  unsigned int d_len{0};
  struct pdns_pcap_pkthdr d_pheader;

  pdns_pcap_file_header d_pfh;
  unsigned int d_runts, d_oversized, d_correctpackets, d_nonetheripudp;
  char d_buffer[32768];
private:
  FILE* d_fp;
  string d_fname;
  unsigned int d_skipMediaHeader;
};

class PcapPacketWriter
{
public: 
  PcapPacketWriter(const string& fname, const PcapPacketReader& ppr);
  PcapPacketWriter(const string& fname);
  
  void write();
  void setPPR(const PcapPacketReader& ppr) { d_ppr = &ppr; }
  ~PcapPacketWriter();

private:
  string d_fname;
  const PcapPacketReader* d_ppr{nullptr};

  FILE *d_fp;
  bool d_first{true};
}; 
