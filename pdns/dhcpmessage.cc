/*
 * Copyright 2006, 2007 Stefan Rompf <sux@loplof.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation
 *
 */

#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include "iputils.hh"
#include "dhcpmessage.hh"

static const unsigned char vendcookie[] = { 99, 130, 83, 99 };
void dm_init(struct dhcp_message *msg) {
  memset(msg, 0, sizeof(*msg));
  msg->pos = msg->options+4;
  // msg->flags = htons(0x8000);
  memcpy(msg->options, vendcookie, 4);
}

void dm_add_option(struct dhcp_message *msg, u_int8_t option,
        	   u_int8_t length, void *opt) {
  u_int8_t *pos = msg->pos;

  if (&msg->options[MAX_OPT_LEN] - pos < length + 2) abort();

  *pos++ = option;
  *pos++ = length;
  memcpy(pos, opt, length);
  pos += length;

  msg->pos = pos;
}


void dm_finish_options(struct dhcp_message *msg) {
  if (msg->pos == &msg->options[MAX_OPT_LEN]) abort();

  *msg->pos++ = 255;
}


u_int8_t *dm_next_option(struct dhcp_message *msg) {
  u_int8_t *pos = msg->pos;
  u_int8_t length;

  /* End of packet */
  if (pos >= msg->last) return NULL;

  /* skip pad packets */
  while(!*pos) if (++pos >= msg->last) return NULL;

  /* End of option marker */
  while (*pos == 255) {
    /* Overload option handling */
    if (msg->currentblock < msg->overload) { // currentblock: 0,1,3
      msg->currentblock = (dhcp_overload_opts)(msg->currentblock+1);
      if (msg->overload & DHCP_OVERLOAD_FILE & msg->currentblock) {
        pos = &msg->file[0];
        msg->last = &msg->file[128];
      } else { // SNAME or BOTH
        pos = &msg->sname[0];
        msg->last = &msg->sname[64];
        msg->currentblock = DHCP_OVERLOAD_BOTH; // definitely last block
      }
      /* skip pad packets */
      while(!*pos) if (++pos >= msg->last) return NULL;
    } else {
      return NULL;
    }
  }

  /* Actually, this is extra paranoia. Even if pos+1
   * leaves the dhcp_message structure, the next
   * check would catch this as long as we don't
   * try to access an unmapped page ;-)
   */   
  if (pos+1 >= msg->last) return NULL;
  
  length = *(pos+1);
  /* Length overflow */
  if (pos + length + 2 > msg->last) return NULL;

  msg->pos = pos + length+2;

  return pos;
}


DHCPCommunicator::DHCPCommunicator(const std::string& remoteAddr)
{
  ComboAddress remote(remoteAddr, 67); // 195.241.76.195,  82.169.27.254
  d_socket =socket(AF_INET, SOCK_DGRAM, 0);
  Utility::setCloseOnExec(d_socket)

  int tmp = 1;
  if(setsockopt(d_socket, SOL_SOCKET,SO_REUSEADDR,(char*)&tmp,sizeof tmp)<0) 
    unixDie("Setting reuse flag");

  ComboAddress local("0.0.0.0", 67);

  if(bind(d_socket, (struct sockaddr*)&local, local.getSocklen()) < 0)
    unixDie("binding");

  if(connect(d_socket, (struct sockaddr*)&remote, remote.getSocklen()) < 0)
    unixDie("connecting");

}

string DHCPCommunicator::getMac(const std::string& ip)
{
  struct dhcp_message msg;

  dm_init(&msg);
  msg.xid = random();
  msg.op = BOOTP_OPCODE_REQUEST;
  msg.htype = 0;
  msg.hlen = 0;
  memset(&msg.chaddr, 0, sizeof(msg.chaddr));

  ComboAddress about(ip);

  msg.ciaddr = about.sin4.sin_addr.s_addr; // 0x0c01000a; // 0xda837bd4; // ask about 4.3.2.1

  struct sockaddr_in local;
  socklen_t locallen=sizeof(local);
  getsockname(d_socket, (struct sockaddr*)&local, &locallen);

  msg.giaddr = local.sin_addr.s_addr; // 0x0c01000a; // 0xda837bd4; // or IP is also 4.3.2.1 (it ain't)

  int dhcptype = 10; // 13; // DHCP_TYPE_LEASEQUERY cisco style
  dm_add_option(&msg, DHCP_OPTION_TYPE, 1, &dhcptype);

  dhcptype = 51;
  dm_add_option(&msg, DHCP_OPTION_PARAMREQ, 1, &dhcptype);

  dhcptype = 82;
  dm_add_option(&msg, DHCP_OPTION_PARAMREQ, 1, &dhcptype);

  send(d_socket, (char*)&msg.op, msg.pos - &msg.op, 0);

  char packet[1500];

  int ret=recv(d_socket, packet, sizeof(packet), 0);
  if(ret > 0) {
    memcpy((char*)&msg.op, packet, ret);
    char mac[19];
    snprintf(mac, 19, "%02x:%02x:%02x:%02x:%02x:%02x", msg.chaddr[0], msg.chaddr[1], msg.chaddr[2], 
             msg.chaddr[3], msg.chaddr[4], msg.chaddr[5]);
    return mac;
  }

  return "unknown";
}


#if 0

int dm_parse_msg_raw(char *dframe, int plen,
        	     struct in_addr *from_ip, struct dhcp_message *msg) {
  struct iphdr *ip;
  struct udphdr *udp;
  int iphlen, udplen;
  u_short checksum;

  if (plen < sizeof(*ip)) return -1;

  /* Verify IP: IP, UDP, ... */
  ip = (struct iphdr *)dframe;
  iphlen = 4 * ip->ihl;
  if (ip->version != 4) return -1; /* no ipv4 packet */
  if (plen < iphlen || iphlen < 20) return -1; /* ip header too short */
  if (plen < ntohs(ip->tot_len)) return -1; /* packet too short */
  if (in_cksum((u_short *)ip, iphlen, 0)) return -1; /* checksum wrong */
  if (ip->protocol != IPPROTO_UDP) return -1; /* no udp */
  if (ip->frag_off & htons(IP_OFFMASK)) return -1; /* won't parse fragments */

  from_ip->s_addr = ip->saddr;

  /* UDP src, destination */
  udp = (struct udphdr *)&dframe[iphlen];
  if (udp->source != htons(BOOTP_SERVER_PORT)) return -1;
  if (udp->dest != htons(BOOTP_CLIENT_PORT)) return -1;

  udplen = ntohs(udp->len);
  if (iphlen + udplen > plen) return -1; /* truncated BOOTPREPLY */

  /* check udp checksum */
  if (udp->check != 0 && udp->check != 0xffff) {
    /* FIXME: checksum 0xffff has to be treated as 0. Until I've constructed
       a testcase, treat 0xffff as no checksum */
    /* RFC 768: Calculate the checksum including the pseudo header
       s-ip(4), d-ip(4), 0x00(1), proto(1), udp-length(2) */
    checksum = htons(IPPROTO_UDP);
    checksum = in_cksum((u_short *)&udp->len, 2, checksum);
    checksum = in_cksum((u_short *)&ip->saddr, 8, ~checksum); // ip options might follow
    checksum = in_cksum((u_short *)udp, udplen, ~checksum); // saddr + daddr + udp
    if (checksum) return -1; /* udp packet checksum wrong */
  }
  udplen -= sizeof(*udp); /* udplen is now dhcplen! */
  if (udplen < &msg->options[4] - &msg->op) return -1; /* BOOTPREPLY too short */

  memcpy(&msg->op, &dframe[iphlen+sizeof(*udp)], udplen);

  if (memcmp(msg->options, vendcookie, 4)) return -1; /* No DHCP message */

  msg->pos = msg->options+4;
  msg->last = msg->pos + (udplen + &msg->options[0] - &msg->op);
  msg->overload = DHCP_OVERLOAD_NONE;
  msg->currentblock = DHCP_OVERLOAD_NONE;

  return 0;
}

#endif

