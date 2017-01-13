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

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#define PDNS_DLSO_ABI_VERSION 1

struct resource_record {
  uint16_t qtype;
  uint8_t qname_len;
  uint8_t scope_mask;
  uint32_t content_len;
  const char * qname;
  const char * content;
  uint32_t ttl;
  int32_t domain_id;
  bool auth;
};

struct dnskey {
  uint32_t id;
  uint16_t flags;
  uint16_t data_len;
  const char * data;
  bool active;
};

struct nsec3_param {
  const char * salt;
  uint8_t salt_len;
  uint8_t alg;
  uint16_t iterations;
  uint8_t flags;
};

struct dns_value {
  const char * value;
  uint8_t value_len;
};

struct dns_meta {
  char * property;
  const struct dns_value * values;
  uint8_t property_len;
  uint8_t value_len;
};

#define DOMAIN_INFO_KIND_MASTER 0
#define DOMAIN_INFO_KIND_SLAVE 1
#define DOMAIN_INFO_KIND_NATIVE 2

struct domain_info {
  uint32_t id;
  uint32_t serial;
  uint32_t notified_serial;
  uint8_t kind;
  uint8_t zone_len;
  uint8_t master_len;
  uint8_t account_len;
  const char * zone;
  const struct dns_value * masters;
  const char * account;
  time_t last_check;
};

typedef void (*fill_cb_t)(const void *, const struct resource_record *);
typedef void (*fill_key_cb_t)(const void *, const struct dnskey *);
typedef void (*fill_tsig_key_cb_t)(const void *, uint8_t alg_len, const char * alg, uint8_t key_len, const char * key);
typedef void (*fill_meta_cb_t)(const void *, uint8_t value_len, const struct dns_value *);
typedef void (*fill_metas_cb_t)(const void *, uint8_t meta_len, const struct dns_meta *);
typedef void (*fill_before_after_cb_t)(const void *, uint8_t unhashed_len, const char * unhashed, uint8_t before_len, const char * before, uint8_t after_len, const char * after);
typedef void (*fill_domain_info_cb_t)(const void *, struct domain_info * di);

struct lib_so_api {
  uint32_t abi_version;
  void * handle;
  void (*release)(struct lib_so_api * handle);

  bool (*lookup)(void * handle, const uint16_t qtype, uint8_t qlen, const char * qname, const struct sockaddr * client_ip, int32_t domain_id);
  bool (*list)(void * handle, uint8_t qlen, const char * qname, int32_t domain_id);
  bool (*get)(void * handle, fill_cb_t cb, void * rr);

  bool (*get_domain_keys)(void * handle, uint8_t qlen, const char * qname, fill_key_cb_t cb, const void * keys);
  bool (*add_domain_key)(void * handle, uint8_t qlen, const char * qname, struct dnskey * key, int64_t *id);

  bool (*get_metas)(void * handle, uint8_t qlen, const char * qname, fill_metas_cb_t cb, const void * metas);
  bool (*get_meta)(void * handle, uint8_t qlen, const char * qname, uint8_t kind_len, const char * kind, fill_meta_cb_t cb, const void * meta);
  bool (*set_meta)(void * handle, uint8_t qlen, const char * qname, uint8_t kind_len, const char * kind, uint8_t value_len, struct dns_value * values);

  bool (*get_before_after)(void * handle, uint32_t domain_id,
                           uint8_t qlen, const char * qname,
                           uint8_t unhashed_len, const char * unhashed_name,
                           uint8_t before_len, const char * before_name,
                           uint8_t after_len, const char * after_name,
                           fill_before_after_cb_t cb, void * beforeAfter);

  bool (*get_tsig_key)(void * handle, uint8_t qlen, const char * qname, fill_tsig_key_cb_t cb, const void * data);
  bool (*set_tsig_key)(void * handle, uint8_t qlen, const char * qname, uint8_t alg_len, const char * alg, uint8_t content_len, const char * content);

  bool (*update_dnssec_order_name_and_auth)(void * handle, uint32_t domain_id,
                                            uint8_t qlen, const char * qname,
                                            uint8_t ordername_len, const char * ordername,
                                            bool auth, uint16_t qtype);

  bool (*update_empty_non_terminals)(void * handle, uint32_t domain_id,
                                     uint8_t qlen, const char * qname,
                                     bool add);
  bool (*remove_empty_non_terminals)(void * handle, uint32_t domain_id);

  bool (*get_domain_info)(void * handle, uint8_t qlen, const char * qname, fill_domain_info_cb_t cb, void * di);

  bool (*start_transaction)(void * handle, uint32_t domain_id, uint8_t qlen, const char * qname);
  bool (*commit_transaction)(void * handle);
  bool (*abort_transaction)(void * handle);

  bool (*get_unfresh_slave)(void * ptr, fill_domain_info_cb_t cb, void * data);
  void (*set_fresh)(void * ptr, uint32_t domain_id);
  void (*set_notified)(void * ptr, uint32_t domain_id, uint32_t serial);

  bool (*add_record)(void * ptr, const struct resource_record *, uint8_t ordername_len, const char * ordername);
  bool (*replace_record)(void * ptr, uint32_t domain_id, uint8_t qlen, const char * qname, uint16_t qtype, uint16_t record_size, const struct resource_record * records);
  bool (*add_record_ent)(void * ptr, uint32_t domain_id, bool auth, uint8_t qlen, const char * qname);
  bool (*add_record_ent_nsec3)(void * ptr, uint32_t domain_id, uint8_t domain_len, const char * domain, bool narrow, bool auth, uint8_t qlen, const char * qname, const struct nsec3_param * ns3);
};

typedef bool (*dlso_register_t)(uint32_t abi_version, struct lib_so_api** api, bool dnssec, const char * args);
