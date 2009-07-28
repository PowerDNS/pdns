#ifndef DHCPMESSAGE_HH
#define DHCPMESSAGE_HH


/*
 * Copyright 2006, 2007 Stefan Rompf <sux@loplof.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <string>
extern "C" {

#define MAX_OPT_LEN 512 // RFC 2131 Minimumsize: 312 FIXME: add OPTION_MAXSIZE to use additional bytes


// RFC 2132, 3.3
#define BOOTP_OPTION_NETMASK            1
// RFC 2132, 3.5
#define BOOTP_OPTION_GATEWAY            3
// RFC 2132, 3.8
#define BOOTP_OPTION_DNS                6
// RFC 2132, 3.14
#define BOOTP_OPTION_HOSTNAME           12
// RFC 2132, 3.15
#define BOOTP_OPTION_BOOTFILE_SIZE      13
// RFC 2132, 3.17
#define BOOTP_OPTION_DOMAIN             15
// RFC 2132, 5.3
#define BOOTP_OPTION_BROADCAST          28
// RFC 2132, 8.1
#define BOOTP_OPTION_NISDOMAIN          40

// RFC 2132, 3.9
#define DHCP_OPTION_LOGSRVS             7
// RFC 2132, 3.11
#define DHCP_OPTION_LPRSRVS             9
// RFC 2132, 8.3
#define DHCP_OPTION_NTPSRVS             42
// RFC 2132, 8.9
#define DHCP_OPTION_XFNTSRVS            48
// RFC 2132, 8.10
#define DHCP_OPTION_XDMSRVS             49
// RFC 2132, 9.1
#define DHCP_OPTION_REQADDR             50
// RFC 2132, 9.2
#define DHCP_OPTION_LEASE               51
// RFC 2132, 9.3
#define DHCP_OPTION_OVERLOAD            52
// RFC 2132, 9.6
#define DHCP_OPTION_TYPE                53
// RFC 2132, 9.7
#define DHCP_OPTION_SERVER              54
// RFC 2132, 9.8
#define DHCP_OPTION_OPTIONREQ           55
// RFC 2132, 9.10
#define DHCP_OPTION_PARAMREQ           56

#define DHCP_OPTION_MAXSIZE             57
// RFC 2132, 9.11
#define DHCP_OPTION_T1                  58
// RFC 2132, 9.12
#define DHCP_OPTION_T2                  59
// RFC 2132, 9.13
#define DHCP_OPTION_CLASS_IDENTIFIER    60
// RFC 2132, 9.14
#define DHCP_OPTION_CLIENT_IDENTIFIER   61
// RFC 4039
#define DHCP_OPTION_RAPID_COMMIT	80

#define BOOTP_CLIENT_PORT       68
#define BOOTP_SERVER_PORT       67

#define BOOTP_OPCODE_REQUEST    1
#define BOOTP_OPCODE_REPLY      2

#define NORESPONSE              -10
#define DHCP_TYPE_DISCOVER      1
#define DHCP_TYPE_OFFER         2
#define DHCP_TYPE_REQUEST       3
#define DHCP_TYPE_DECLINE       4
#define DHCP_TYPE_ACK           5
#define DHCP_TYPE_NAK           6
#define DHCP_TYPE_RELEASE       7
#define DHCP_TYPE_INFORM        8

typedef enum {
  DHCP_OVERLOAD_NONE,
  DHCP_OVERLOAD_FILE,
  DHCP_OVERLOAD_SNAME,
  DHCP_OVERLOAD_BOTH
} dhcp_overload_opts;

struct dhcp_message {
  u_int8_t *pos, *last;
  dhcp_overload_opts overload, currentblock;

  /* embedded DHCP message */
  u_int8_t op;
  u_int8_t htype;
  u_int8_t hlen;
  u_int8_t hops;
  u_int32_t xid;
  u_int16_t secs;
  u_int16_t flags;
  u_int32_t ciaddr;
  u_int32_t yiaddr;
  u_int32_t siaddr;
  u_int32_t giaddr;
  u_int8_t chaddr[16];
  u_int8_t sname[64];
  u_int8_t file[128];
  u_int8_t options[MAX_OPT_LEN];
} __attribute__((packed)) ;


void dm_init(struct dhcp_message *msg);

void dm_finish_options(struct dhcp_message *msg);

void dm_add_option(struct dhcp_message *msg, u_int8_t option,
		   u_int8_t length, void *opt);

u_int8_t *dm_next_option(struct dhcp_message *msg);


int dm_parse_msg_raw(char *dframe, int plen,
		     struct in_addr *from_ip, struct dhcp_message *msg);

}

class DHCPCommunicator
{
public:
  DHCPCommunicator(const std::string& remote);
  std::string getMac(const std::string& ip);
private:
  int d_socket;
};

#endif

