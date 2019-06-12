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
#define __FAVOR_BSD
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "dnspcap.hh"
#include <boost/format.hpp>
#include <fcntl.h>

#include "namespaces.hh"
PcapPacketReader::PcapPacketReader(const string& fname) : d_fname(fname)
{
  d_fp=fopen(fname.c_str(),"r");
  if(!d_fp)
    unixDie("Unable to open file " + fname);
  
  int flags=fcntl(fileno(d_fp),F_GETFL,0);
  fcntl(fileno(d_fp), F_SETFL,flags&(~O_NONBLOCK)); // bsd needs this in stdin (??)
  
  checkedFread(&d_pfh);
  
  if(d_pfh.magic != 2712847316UL)
    throw runtime_error((format("PCAP file %s has bad magic %x, should be %x") % fname % d_pfh.magic % 2712847316UL).str());
  
  if( d_pfh.linktype==1) {
    d_skipMediaHeader=sizeof(struct ether_header);
  }
  else if(d_pfh.linktype==101) {
    d_skipMediaHeader=0;
  }
  else if(d_pfh.linktype==113) {
    d_skipMediaHeader=16;
  }
  else throw runtime_error((format("Unsupported link type %d") % d_pfh.linktype).str());
  
  d_runts = d_oversized = d_correctpackets = d_nonetheripudp = 0;
}

PcapPacketReader::~PcapPacketReader()
{
  fclose(d_fp);
}


void PcapPacketReader::checkedFreadSize(void* ptr, size_t size) 
{
  int ret=fread(ptr, 1, size, d_fp);
  if(ret < 0)
    unixDie( (format("Error reading %d bytes from %s") % size % d_fname).str());
  
  if(!ret)
    throw EofException();
  
  if((size_t)ret != size)
    throw EofException((format("Incomplete read from '%s', got only %d bytes") % d_fname % ret).str());
}

bool PcapPacketReader::getUDPPacket()
try
{
  for(;;) {
    checkedFread(&d_pheader);
    if(!d_pheader.caplen) {
      d_runts++;
      continue;
    }

    if(d_pheader.caplen > sizeof(d_buffer)) {
      d_oversized++;
      throw runtime_error((format("Can't handle a %d byte packet, have space for %d")  % d_pheader.caplen % sizeof(d_buffer)).str());
    }

    checkedFreadSize(d_buffer, d_pheader.caplen);

    if(d_pheader.caplen < d_pheader.len) {
      d_runts++;
      continue;
    }

    if (d_pheader.caplen < d_skipMediaHeader) {
      d_runts++;
      continue;
    }

    d_ip=reinterpret_cast<struct ip*>(d_buffer + d_skipMediaHeader);
    d_ip6=reinterpret_cast<struct ip6_hdr*>(d_buffer + d_skipMediaHeader);
    uint16_t contentCode=0;

    if(d_pfh.linktype==1) {
      if (d_pheader.caplen < sizeof(*d_ether)) {
        d_runts++;
        continue;
      }
      d_ether=reinterpret_cast<struct ether_header*>(d_buffer);
      contentCode=ntohs(d_ether->ether_type);
    }
    else if(d_pfh.linktype==101) {
      if (d_pheader.caplen < (d_skipMediaHeader + sizeof(*d_ip))) {
        d_runts++;
        continue;
      }
      if(d_ip->ip_v==4)
	contentCode = 0x0800;
      else
	contentCode = 0x86dd;
    }
    else if(d_pfh.linktype==113) {
      if (d_pheader.caplen < sizeof(*d_lcc)) {
        d_runts++;
        continue;
      }
      d_lcc=reinterpret_cast<struct pdns_lcc_header*>(d_buffer);
      contentCode=ntohs(d_lcc->lcc_protocol);
    }

    if(contentCode==0x0800 && (d_pheader.caplen >= (d_skipMediaHeader + sizeof(*d_ip))) && d_ip->ip_p==17) { // udp
      if (d_pheader.caplen < (d_skipMediaHeader + (4 * d_ip->ip_hl) + sizeof(*d_udp))) {
        d_runts++;
        continue;
      }
      d_udp=reinterpret_cast<const struct udphdr*>(d_buffer + d_skipMediaHeader + 4 * d_ip->ip_hl);
      d_payload = (unsigned char*)d_udp + sizeof(struct udphdr);
      d_len = ntohs(d_udp->uh_ulen) - sizeof(struct udphdr);
      if (d_pheader.caplen < (d_skipMediaHeader + (4 * d_ip->ip_hl) + sizeof(*d_udp) + d_len)) {
        d_runts++;
        continue;
      }
      if((const char*)d_payload + d_len > d_buffer + d_pheader.caplen) {
	d_runts++;
	continue;
      }
      d_correctpackets++;
      return true;
    }
    else if(contentCode==0x86dd && (d_pheader.caplen >= (d_skipMediaHeader + sizeof(*d_ip6))) && d_ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt==17) { // udpv6, we ignore anything with extension hdr
      if (d_pheader.caplen < (d_skipMediaHeader + sizeof(struct ip6_hdr) + sizeof(struct udphdr))) {
        d_runts++;
        continue;
      }
      d_udp=reinterpret_cast<const struct udphdr*>(d_buffer + d_skipMediaHeader + sizeof(struct ip6_hdr));
      d_payload = (unsigned char*)d_udp + sizeof(struct udphdr);
      d_len = ntohs(d_udp->uh_ulen) - sizeof(struct udphdr);
      if (d_pheader.caplen < (d_skipMediaHeader + sizeof(struct ip6_hdr) + sizeof(struct udphdr) + d_len)) {
        d_runts++;
        continue;
      }
      if((const char*)d_payload + d_len > d_buffer + d_pheader.caplen) {
	d_runts++;
	continue;
      }

      d_correctpackets++;
      return true;
    }
    else {
      d_nonetheripudp++;
    }
  }
}
catch(const EofException&) {
  return false;
}

ComboAddress PcapPacketReader::getSource() const
{
  ComboAddress ret;
  if(d_ip->ip_v == 4) {
    ret.sin4.sin_family = AF_INET;
    ret.sin4.sin_addr = d_ip->ip_src;
    ret.sin4.sin_port = d_udp->uh_sport; // should deal with TCP too!
  } else {
    ret.sin6.sin6_family = AF_INET6;
    ret.sin6.sin6_addr = d_ip6->ip6_src;
    ret.sin6.sin6_port = d_udp->uh_sport; // should deal with TCP too!
  }
  return ret;
}

ComboAddress PcapPacketReader::getDest() const
{
  ComboAddress ret;
  if(d_ip->ip_v == 4) {
    ret.sin4.sin_family = AF_INET;
    ret.sin4.sin_addr = d_ip->ip_dst;
    ret.sin4.sin_port = d_udp->uh_dport; // should deal with TCP too!
  } else {
    ret.sin6.sin6_family = AF_INET6;
    ret.sin6.sin6_addr = d_ip6->ip6_dst;
    ret.sin6.sin6_port = d_udp->uh_dport; // should deal with TCP too!
  }
  return ret;
}

PcapPacketWriter::PcapPacketWriter(const string& fname, const PcapPacketReader& ppr) : PcapPacketWriter(fname)
{
  setPPR(ppr);
}

PcapPacketWriter::PcapPacketWriter(const string& fname) : d_fname(fname)
{
  d_fp=fopen(fname.c_str(),"w");
  if(!d_fp)
    unixDie("Unable to open file");
  
  int flags=fcntl(fileno(d_fp),F_GETFL,0);
  fcntl(fileno(d_fp), F_SETFL,flags&(~O_NONBLOCK)); // bsd needs this in stdin (??)
}

void PcapPacketWriter::write()
{
  if (!d_ppr) {
    return;
  }

  if(d_first) {
    fwrite(&d_ppr->d_pfh, 1, sizeof(d_ppr->d_pfh), d_fp);
    d_first=false;
  }
  fwrite(&d_ppr->d_pheader, 1, sizeof(d_ppr->d_pheader), d_fp);
  fwrite(d_ppr->d_buffer, 1, d_ppr->d_pheader.caplen, d_fp);
}

PcapPacketWriter::~PcapPacketWriter()
{
  fclose(d_fp);
}
