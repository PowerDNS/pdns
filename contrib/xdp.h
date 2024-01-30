#ifndef __XDP_H__
#define __XDP_H__

#include <net/sock.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>

#define DNS_PORT      53

// do not use libc includes because this causes clang
// to include 32bit headers on 64bit ( only ) systems.
typedef __u8  uint8_t;
typedef __u16 uint16_t;
typedef __u32 uint32_t;
typedef __u64 uint64_t;
#define memcpy __builtin_memcpy

/*
 * Helper pointer to parse the incoming packets
 * Copyright 2020, NLnet Labs, All rights reserved.
 */
struct cursor {
  void *pos;
  void *end;
};

/*
 * Store the VLAN header
 * Copyright 2020, NLnet Labs, All rights reserved.
 */
struct vlanhdr {
  uint16_t tci;
  uint16_t encap_proto;
};

/*
 * Store the DNS header
 * Copyright 2020, NLnet Labs, All rights reserved.
 */
struct dnshdr {
  uint16_t id;
  union {
  	struct {
#if BYTE_ORDER == LITTLE_ENDIAN
  		uint8_t  rd     : 1;
  		uint8_t  tc     : 1;
  		uint8_t  aa     : 1;
  		uint8_t  opcode : 4;
  		uint8_t  qr     : 1;

  		uint8_t  rcode  : 4;
  		uint8_t  cd     : 1;
  		uint8_t  ad     : 1;
  		uint8_t  z      : 1;
  		uint8_t  ra     : 1;
#elif BYTE_ORDER == BIG_ENDIAN || BYTE_ORDER == PDP_ENDIAN
  		uint8_t  qr     : 1;
  		uint8_t  opcode : 4;
  		uint8_t  aa     : 1;
  		uint8_t  tc     : 1;
  		uint8_t  rd     : 1;

  		uint8_t  ra     : 1;
  		uint8_t  z      : 1;
  		uint8_t  ad     : 1;
  		uint8_t  cd     : 1;
  		uint8_t  rcode  : 4;
#endif
  	}        as_bits_and_pieces;
  	uint16_t as_value;
  } flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
};

/*
 * Store the qname and qtype
 */
struct dns_qname
{
  uint8_t qname[255];
  uint16_t qtype;
};

/*
 * The possible actions to perform on the packet
 * PASS: XDP_PASS
 * DROP: XDP_DROP
 * TC: set TC bit and XDP_TX
 */
enum dns_action : uint8_t {
  PASS = 0,
  DROP = 1,
  TC = 2
};

struct CIDR4
{
  uint32_t cidr;
  uint32_t addr;
};
struct CIDR6
{
  uint32_t cidr;
  struct in6_addr addr;
};

struct IPv4AndPort
{
  uint32_t addr;
  uint16_t port;
};

struct IPv6AndPort
{
  struct in6_addr addr;
  uint16_t port;
};

/*
 * Store the matching counter and the associated action for a blocked element
 */
struct map_value
{
  uint64_t counter;
  enum dns_action action;
};


/*
 * Initializer of a cursor pointer
 *  Copyright 2020, NLnet Labs, All rights reserved.
 */
static inline void cursor_init(struct cursor *c, struct xdp_md *ctx)
{
  c->end = (void *)(long)ctx->data_end;
  c->pos = (void *)(long)ctx->data;
}

/*
 * Header parser functions
 * Copyright 2020, NLnet Labs, All rights reserved.
 */
#define PARSE_FUNC_DECLARATION(STRUCT)                            \
static inline struct STRUCT *parse_ ## STRUCT (struct cursor *c)  \
{                                                                 \
  struct STRUCT *ret = c->pos;                                    \
  if (c->pos + sizeof(struct STRUCT) > c->end)                    \
  	return 0;                                                 \
  c->pos += sizeof(struct STRUCT);                                \
  return ret;                                                     \
}

PARSE_FUNC_DECLARATION(ethhdr)
PARSE_FUNC_DECLARATION(vlanhdr)
PARSE_FUNC_DECLARATION(iphdr)
PARSE_FUNC_DECLARATION(ipv6hdr)
PARSE_FUNC_DECLARATION(udphdr)
PARSE_FUNC_DECLARATION(dnshdr)

/*
 * Parse ethernet frame and fill the struct
 * Copyright 2020, NLnet Labs, All rights reserved.
 */
static inline struct ethhdr *parse_eth(struct cursor *c, uint16_t *eth_proto)
{
  struct ethhdr  *eth;

  if (!(eth = parse_ethhdr(c)))
  	return 0;

  *eth_proto = eth->h_proto;
  if (*eth_proto == bpf_htons(ETH_P_8021Q)
  ||  *eth_proto == bpf_htons(ETH_P_8021AD)) {
  	struct vlanhdr *vlan;

  	if (!(vlan = parse_vlanhdr(c)))
  		return 0;

  	*eth_proto = vlan->encap_proto;
  	if (*eth_proto == bpf_htons(ETH_P_8021Q)
  	||  *eth_proto == bpf_htons(ETH_P_8021AD)) {
  		if (!(vlan = parse_vlanhdr(c)))
  			return 0;

  		*eth_proto = vlan->encap_proto;
  	}
  }
  return eth;
}

#endif
