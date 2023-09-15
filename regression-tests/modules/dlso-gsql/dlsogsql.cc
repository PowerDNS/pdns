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
#include "pdns/dnsbackend.hh"
#include "pdns/backends/gsql/gsqlbackend.hh"
#include "../../../modules/dlsobackend/dlsobackend_api.h"
#include "../../../modules/gsqlite3backend/gsqlite3backend.hh"
#include "pdns/logger.hh"
#include "pdns/logging.hh"
#include <sys/socket.h>
#include <sys/types.h>
#include <cstdlib>
#include <mutex>
#include <vector>

struct dlso_gsql
{
  DNSBackend* module;
  bool in_error;
};

void release(struct lib_so_api* api)
{
  if (api != nullptr) {
    auto* handle = static_cast<struct dlso_gsql*>(api->handle);

    if (handle != nullptr) {
      delete handle->module;
      free(handle);
      api->handle = nullptr;
    }

    free(api);
  }
}

bool lookup(void* ptr, const uint16_t qtype, uint8_t qlen, const char* qname, const struct sockaddr* client_ip, int32_t domain_id)
{
  auto* handle = static_cast<struct dlso_gsql*>(ptr);
  if (handle == nullptr) {
    return false;
  }
  handle->in_error = false;

  auto type = QType(qtype);
  auto qname_ = DNSName(string(qname, qlen));
  try {
    handle->module->lookup(type, qname_, domain_id);
  }
  catch (const PDNSException& e) {
    handle->in_error = true;
  }

  return true;
}

bool list(void* ptr, uint8_t qlen, const char* qname, int32_t domain_id)
{
  auto* handle = static_cast<struct dlso_gsql*>(ptr);
  if (handle == nullptr) {
    return false;
  }
  handle->in_error = false;

  auto qname_ = DNSName(string(qname, qlen));
  try {
    handle->module->list(qname_, domain_id, false);
  }
  catch (const PDNSException& e) {
    handle->in_error = true;
  }

  return true;
}

bool get(void* ptr, fill_cb_t cb, void* rr)
{
  auto* handle = static_cast<struct dlso_gsql*>(ptr);
  if (handle->in_error) {
    return false;
  }
  DNSResourceRecord record;

  if (handle->module->get(record)) {
    string qname = record.qname.toString();
    string content = record.content;
    struct resource_record resource_record = {
      .qtype = record.qtype.getCode(),
      .qname_len = static_cast<uint8_t>(qname.size()),
      .scope_mask = record.scopeMask,
      .content_len = static_cast<uint8_t>(content.size()),
      .qname = qname.c_str(),
      .content = content.c_str(),
      .ttl = record.ttl,
      .domain_id = record.domain_id,
      .auth = record.auth,
    };

    cb(rr, &resource_record);

    return true;
  }
  return false;
}

bool get_tsig_key(
  void* ptr,
  uint8_t qlen,
  const char* qname_,
  fill_tsig_key_cb_t cb,
  void* data)
{
  auto* handle = static_cast<struct dlso_gsql*>(ptr);
  auto qname = DNSName(string(qname_, qlen));
  DNSName alg;
  string content;

  if (handle->module->getTSIGKey(qname, alg, content)) {
    if (!alg.empty()) {
      string alg_ = alg.toString();
      cb(data, alg_.size(), alg_.c_str(), content.size(), content.c_str());
    }
    else {
      cb(data, 0, nullptr, content.size(), content.c_str());
    }
    return true;
  }
  return false;
}

bool set_tsig_key(
  void* ptr,
  uint8_t qlen,
  const char* qname_,
  uint8_t alg_len,
  const char* alg_,
  uint8_t content_len,
  const char* content_)
{
  auto* handle = static_cast<struct dlso_gsql*>(ptr);
  auto qname = DNSName(string(qname_, qlen));
  auto alg = DNSName(string(alg_, alg_len));
  string content = string(content_, content_len);

  return handle->module->setTSIGKey(qname, alg, content);
}

bool get_meta(
  void* ptr,
  uint8_t qlen,
  const char* qname_,
  uint8_t kind_len,
  const char* kind_,
  fill_meta_cb_t cb,
  void* meta)
{
  auto* handle = static_cast<struct dlso_gsql*>(ptr);
  auto qname = DNSName(string(qname_, qlen));
  auto kind = string(kind_, kind_len);
  auto* meta_ = static_cast<std::vector<std::string>*>(meta);
  // TODO meta should be reparsed

  return handle->module->getDomainMetadata(qname, kind, *meta_);
}

bool set_meta(void* ptr, uint8_t qlen, const char* qname_, uint8_t kind_len, const char* kind_, uint8_t value_len, struct dns_value* values)
{
  auto* handle = static_cast<struct dlso_gsql*>(ptr);
  auto qname = DNSName(string(qname_, qlen));
  auto kind = string(kind_, kind_len);

  for (size_t i = 0; i < value_len; i++) {
    auto value = string(values[i].value, values[i].value_len);
    if (!handle->module->setDomainMetadataOne(qname, kind, value)) {
      return false;
    }
  }

  return true;
}

bool remove_empty_non_terminals(void* ptr, uint32_t domain_id)
{
  auto* handle = static_cast<struct dlso_gsql*>(ptr);
  set<DNSName> insert;
  set<DNSName> erase;

  return handle->module->updateEmptyNonTerminals(domain_id, insert, erase, true);
}

bool update_empty_non_terminals(void* ptr, uint32_t domain_id, uint8_t qlen, const char* qname, bool add)
{
  auto* handle = static_cast<struct dlso_gsql*>(ptr);

  set<DNSName> empty;
  set<DNSName> values_set;

  auto value = DNSName(string(qname, qlen));
  values_set.insert(value);

  auto result = false;
  if (add) {
    result = handle->module->updateEmptyNonTerminals(domain_id, values_set, empty, false);
  }
  else {
    result = handle->module->updateEmptyNonTerminals(domain_id, empty, values_set, false);
  }
  return result;
}

bool get_domain_info(void* ptr, uint8_t qlen, const char* qname_, fill_domain_info_cb_t cb, void* di)
{
  auto* handle = static_cast<struct dlso_gsql*>(ptr);
  auto qname = DNSName(string(qname_, qlen));
  DomainInfo my_di;

  if (handle->module->getDomainInfo(qname, my_di)) {
    string zone = my_di.zone.toString();

    auto master_len = my_di.masters.size();

    vector<combo_address_t> masters;
    masters.resize(master_len);
    for (const auto& ip_address : my_di.masters) {
      auto salen = ip_address.sin4.sin_family == AF_INET ? sizeof(ip_address.sin4) : sizeof(ip_address.sin6);
      combo_address_t addr{};
      memcpy(&addr, &ip_address, salen);
    }

    struct domain_info info
    {
      .id = my_di.id,
      .serial = my_di.serial,
      .notified_serial = my_di.notified_serial,
      .kind = my_di.kind,
      .zone_len = static_cast<uint8_t>(zone.size()),
      .master_len = static_cast<uint8_t>(master_len),
      .account_len = static_cast<uint8_t>(my_di.account.size()),
      .zone = zone.c_str(),
      .masters = masters.data(),
      .account = my_di.account.c_str(),
      .last_check = my_di.last_check,
    };

    cb(di, &info);
    return true;
  }
  return false;
}

bool add_domain_key(void* ptr, uint8_t qlen, const char* qname_, struct dnskey* dnskey, int64_t* id)
{
  auto* handle = static_cast<struct dlso_gsql*>(ptr);
  auto qname = DNSName(string(qname_, qlen));
  DNSBackend::KeyData key = {
    .content = string(dnskey->data, dnskey->data_len),
    .id = dnskey->id,
    .flags = dnskey->flags,
    .active = dnskey->active,
    .published = dnskey->published,
  };

  g_log <<
  Logger::Debug << "id=" << key.id << ",flags=" << key.flags << ",active=" << (key.active ? "true" : "false") << ",published=" << (key.published ? "true" : "false")
  << endl;

  return handle->module->addDomainKey(qname, key, *id);
}

bool get_domain_keys(void* ptr, uint8_t qlen, const char* qname_, fill_key_cb_t cb, void* keys_)
{
  auto* handle = static_cast<struct dlso_gsql*>(ptr);
  auto qname = DNSName(string(qname_, qlen));

  std::vector<DNSBackend::KeyData> keys;

  if (handle->module->getDomainKeys(qname, keys)) {
    for (const DNSBackend::KeyData& key : keys) {
      struct dnskey dnskey
      {
        .id = key.id,
        .flags = static_cast<uint16_t>(key.flags),
        .data_len = static_cast<uint16_t>(key.content.size()),
        .data = key.content.c_str(),
        .active = key.active,
        .published = key.published,
      };

      cb(keys_, &dnskey);
    }
    return true;
  }
  return false;
}

bool get_before_after(
  void* ptr,
  uint32_t domain_id,
  uint8_t qname_len, const char* qname_,
  uint8_t unhashed_len, const char* unhashed_,
  uint8_t before_len, const char* before_,
  uint8_t after_len, const char* after_,
  fill_before_after_cb_t cb, void* beforeAfter)
{
  auto* handle = static_cast<struct dlso_gsql*>(ptr);
  auto qname = DNSName(string(qname_, qname_len));
  DNSName unhashed;
  if (unhashed_len > 0) {
    unhashed = DNSName(string(unhashed_, unhashed_len));
  }
  DNSName before;
  if (before_len > 0) {
    before = DNSName(string(before_, before_len));
  }
  DNSName after;
  if (after_len > 0) {
    after = DNSName(string(after_, after_len));
  }

  if (handle->module->getBeforeAndAfterNamesAbsolute(domain_id, qname, unhashed, before, after)) {
    // cout << "get_before_after before:" << before.wirelength() << endl;
    // cout << "get_before_after after:" << after.wirelength() << endl;
    string unhashed_str;
    string before_str;
    string after_str;

    if (!unhashed.empty()) {
      unhashed_str = unhashed.toString();
    }
    if (!before.empty()) {
      before_str = before.toString();
    }
    if (!after.empty()) {
      after_str = after.toString();
    }

    cb(beforeAfter, unhashed_str.size(), unhashed_str.c_str(), before_str.size(), before_str.c_str(), after_str.size(), after_str.c_str());
    return true;
  }
  // cout << "nope getBeforeAndAfterNamesAbsolute" << endl;
  return false;
}

bool update_dnssec_order_name_and_auth(
  void* ptr,
  uint32_t domain_id,
  uint8_t qname_len,
  const char* qname_,
  uint8_t ordername_len,
  const char* ordername_,
  bool auth, uint16_t qtype)
{
  auto* handle = static_cast<struct dlso_gsql*>(ptr);

  auto qname = DNSName(string(qname_, qname_len));
  DNSName ordername;
  if (ordername_len != 0U) {
    ordername = DNSName(string(ordername_, ordername_len));
  }

  return handle->module->updateDNSSECOrderNameAndAuth(domain_id, qname, ordername, auth, qtype);
}

bool start_transaction(
  void* ptr,
  uint32_t domain_id,
  uint8_t qname_len,
  const char* qname_)
{
  auto* handle = static_cast<struct dlso_gsql*>(ptr);
  auto qname = DNSName(string(qname_, qname_len));
  return handle->module->startTransaction(qname, domain_id);
}

bool abort_transaction(void* ptr)
{
  auto* handle = static_cast<struct dlso_gsql*>(ptr);
  return handle->module->abortTransaction();
}

bool commit_transaction(void* ptr)
{
  auto* handle = static_cast<struct dlso_gsql*>(ptr);
  return handle->module->commitTransaction();
}

bool get_unfresh_slave(void* ptr, fill_domain_info_cb_t cb, void* data)
{
  auto* handle = static_cast<struct dlso_gsql*>(ptr);

  vector<DomainInfo> unfresh;
  struct domain_info info = {};

  handle->module->getUnfreshSlaveInfos(&unfresh);

  for (auto& my_di : unfresh) {
    info.id = my_di.id;
    info.notified_serial = my_di.notified_serial;
    info.serial = my_di.serial;
    info.last_check = my_di.last_check;
    info.kind = my_di.kind;

    string zone = my_di.zone.toString();
    info.zone_len = zone.size();
    info.zone = zone.c_str();

    info.account_len = my_di.account.size();
    info.account = my_di.account.c_str();

    info.master_len = my_di.masters.size();

    vector<combo_address_t> masters;
    masters.resize(info.master_len);
    for (const auto& ip_address : my_di.masters) {
      auto salen = ip_address.sin4.sin_family == AF_INET ? sizeof(ip_address.sin4) : sizeof(ip_address.sin6);
      combo_address_t addr{};
      memcpy(&addr, &ip_address, salen);
      masters.push_back(addr);
    }
    info.masters = masters.data();

    cb(data, &info);
  }

  return true;
}

void set_fresh(void* ptr, uint32_t domain_id)
{
  auto* handle = static_cast<struct dlso_gsql*>(ptr);

  handle->module->setFresh(domain_id);
}

void set_notified(void* ptr, uint32_t domain_id, uint32_t serial)
{
  auto* handle = static_cast<struct dlso_gsql*>(ptr);

  handle->module->setNotified(domain_id, serial);
}

bool add_record(void* ptr, const struct resource_record* record, uint8_t ordername_len, const char* ordername_)
{
  auto* handle = static_cast<struct dlso_gsql*>(ptr);

  DNSResourceRecord rr;
  rr.qtype = record->qtype;
  auto qname = string(record->qname, record->qname_len);
  rr.qname = DNSName(qname);
  rr.qclass = QClass::IN;
  rr.content = string(record->content, record->content_len);
  rr.ttl = record->ttl;
  rr.auth = record->auth;
  rr.scopeMask = record->scope_mask;
  rr.domain_id = record->domain_id;

  auto dnsordername = DNSName();
  if (ordername_ != nullptr) {
    auto ordername = string(ordername_, ordername_len);
    dnsordername = DNSName(ordername);
  }
  return handle->module->feedRecord(rr, dnsordername);
}

bool replace_record(
  void* ptr,
  uint32_t domain_id,
  uint8_t qlen,
  const char* qname,
  uint16_t qtype,
  uint16_t record_size,
  const struct resource_record* records)
{
  auto* handle = static_cast<struct dlso_gsql*>(ptr);

  vector<DNSResourceRecord> rrset;

  for (uint16_t i = 0; i < record_size; i++) {
    const struct resource_record* record = &(records[i]);

    DNSResourceRecord rr;
    rr.qtype = record->qtype;
    string qname_ = string(record->qname, record->qname_len);
    rr.qname = DNSName(qname_);
    rr.qclass = QClass::IN;
    rr.content = string(record->content, record->content_len);
    rr.ttl = record->ttl;
    rr.auth = record->auth;
    rr.scopeMask = record->scope_mask;
    rr.domain_id = record->domain_id;

    rrset.push_back(rr);
  }

  auto qtype_ = QType(qtype);
  auto qname_ = DNSName(string(qname, qlen));

  return handle->module->replaceRRSet(domain_id, qname_, qtype_, rrset);
}

bool add_record_ent(void* ptr, uint32_t domain_id, bool auth, uint8_t qlen, const char* qname_)
{
  auto* handle = static_cast<struct dlso_gsql*>(ptr);

  auto qname = DNSName(string(qname_, qlen));
  map<DNSName, bool> nonterm;
  nonterm.insert({qname, auth});

  return handle->module->feedEnts(domain_id, nonterm);
}

bool add_record_ent_nsec3(void* ptr, uint32_t domain_id, uint8_t domain_len, const char* domain_, bool narrow, bool auth, uint8_t qlen, const char* qname_, const struct nsec3_param* ns3)
{
  auto* handle = static_cast<struct dlso_gsql*>(ptr);

  auto qname = DNSName(string(qname_, qlen));
  map<DNSName, bool> nonterm;
  nonterm.insert({qname, auth});

  DNSName domain;
  if (domain_len > 0) {
    domain = DNSName(string(domain_, domain_len));
  }

  NSEC3PARAMRecordContent ns3prc;
  ns3prc.d_algorithm = ns3->alg;
  ns3prc.d_flags = ns3->flags;
  ns3prc.d_iterations = ns3->iterations;
  ns3prc.d_salt = string(ns3->salt, ns3->salt_len);

  return handle->module->feedEnts3(domain_id, domain, nonterm, ns3prc, narrow);
}

std::mutex g_configuration_mutex;

extern "C" bool pdns_dlso_register(uint32_t abi_version, struct lib_so_api** ptr, bool dnssec, const char* args)
{
  auto* gsql = static_cast<struct dlso_gsql*>(malloc(sizeof(struct dlso_gsql)));
  if (gsql == nullptr) {
    return false;
  }
  auto* api = static_cast<struct lib_so_api*>(malloc(sizeof(struct lib_so_api)));
  if (api == nullptr) {
    free(gsql);
    return false;
  }

  memset(api, 0, sizeof(*api));
  *ptr = api;

  // Configuration and its underlying std::map does not allow two thread
  // to write to it concurrently. When two threads concurrently
  // declareArguments() the map could do double-free. This is bad and this
  // shouldn't happen.
  // Powerdns normally does declare argument and parse configuration
  // in its very beginning in a single-thread. This is not ArgvMap
  // responsability to protect from current access. This test backend
  // being a wrapper Our test backend here may be executed multiple times
  // by different threads (signing thread, packet receiver)
  // For this reason, I chose to have a simple mutex, to not allow two
  // threads to register simultinaeously.
  std::lock_guard<std::mutex> guard(g_configuration_mutex);

  // First load the sqlite3 backend, and declare arguments
  gSQLite3Factory* factory = nullptr;
  try {
    factory = new gSQLite3Factory("gsqlite3");
    factory->declareArguments();
  }
  catch (const PDNSException& e) {
    free(gsql);
    free(api);
    return false;
  }

  // Then, loads configuration from file (gsqlite3 arguments are
  // only parsed after being declared)
  string s_programname = "pdns";
  if (!arg()["config-name"].empty()) {
    s_programname += "-" + arg()["config-name"];
  }

  string configname = arg()["config-dir"] + "/" + s_programname + "-sqlite3.conf";
  arg().laxFile(configname.c_str());

  // And finaly build the module
  try {
    gsql->module = factory->make();
  }
  catch (const PDNSException& e) {
    free(gsql);
    free(api);
    return false;
  }
  if (gsql->module == nullptr) {
    free(gsql);
    free(api);
    return false;
  }

  api->abi_version = PDNS_DLSO_ABI_VERSION;

  api->handle = gsql;
  api->release = release;

  api->lookup = lookup;
  api->get = get;
  api->list = list;

  api->get_tsig_key = get_tsig_key;
  api->set_tsig_key = set_tsig_key;

  api->get_meta = get_meta;
  api->set_meta = set_meta;

  api->update_empty_non_terminals = update_empty_non_terminals;
  api->remove_empty_non_terminals = remove_empty_non_terminals;

  api->get_domain_info = get_domain_info;

  api->get_domain_keys = get_domain_keys;
  api->add_domain_key = add_domain_key;

  api->get_before_after = get_before_after;
  api->update_dnssec_order_name_and_auth = update_dnssec_order_name_and_auth;

  api->start_transaction = start_transaction;
  api->commit_transaction = commit_transaction;
  api->abort_transaction = abort_transaction;

  api->get_unfresh_slave = get_unfresh_slave;
  api->set_fresh = set_fresh;
  api->set_notified = set_notified;

  api->add_record = add_record;
  api->replace_record = replace_record;
  api->add_record_ent = add_record_ent;
  api->add_record_ent_nsec3 = add_record_ent_nsec3;

  return true;
}
