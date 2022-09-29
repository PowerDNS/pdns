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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "dlsobackend.hh"
#include <dlfcn.h>
#include "pdns/namespaces.hh"
#include "pdns/logger.hh"

static const char* kBackendId = "[DlsoBackend]";

extern "C"
{
  void fill_cb(void* ptr, const struct resource_record* record);
  void fill_key_cb(void* ptr, const struct dnskey* dnskey);
  void fill_tsig_key(void* ptr, uint8_t alg_len, const char* alg, uint8_t key_len, const char* key);
  void fill_meta_cb(void* ptr, uint8_t value_len, const struct dns_value* values);
  void fill_metas_cb(void* ptr, uint8_t meta_len, const struct dns_meta* c_metas);
  void fill_before_after(void* ptr, uint8_t unhashed_len, const char* unhashed_, uint8_t before_len, const char* before_, uint8_t after_len, const char* after_);
  void fill_domain_info(void* ptr, struct domain_info* domain_info);
  void fill_unfresh_slave(void* ptr, struct domain_info* domain_info);
}
/**
 * Standard ctor and dtor
 */
DlsoBackend::DlsoBackend(const std::string& suffix)
{
  setArgPrefix("dlso" + suffix);

  std::string libpath = getArg("path");
  std::string args = getArg("args");

  this->d_dnssec = mustDo("dnssec");

  this->dlhandle = dlopen(libpath.c_str(), RTLD_LAZY);

  if (this->dlhandle == nullptr) {
    throw PDNSException("Unable to load library: " + libpath + ":\n" + dlerror());
  }

  auto register_api = reinterpret_cast<dlso_register_t>(dlsym(this->dlhandle, "pdns_dlso_register"));
  if (register_api == nullptr) {
    dlclose(this->dlhandle);
    throw PDNSException("Failed to initialize dlso, no pdns_dlso_register symbol exposed");
  }

  bool success = register_api(PDNS_DLSO_ABI_VERSION, &this->api, this->d_dnssec, args.c_str());
  if (!success) {
    dlclose(this->dlhandle);
    throw PDNSException("Failed to initialize dlso, pdns_dlso_register returned false");
  }

  // Check pointer safety
  if (this->api == nullptr) {
    dlclose(this->dlhandle);
    throw PDNSException("Failed to initialize dlso, library did not reply with its pointer");
  }

  // Check version
  if (this->api->abi_version != PDNS_DLSO_ABI_VERSION) {
    if (this->api->release != nullptr) {
      this->api->release(this->api);
    }

    dlclose(this->dlhandle);
    throw PDNSException("Failed to initialize dlso, library does not use the same abi version than pdns");
  }

  // Sanity checks
  if (this->api->get == nullptr) {
    if (this->api->release != nullptr) {
      this->api->release(this->api);
    }

    dlclose(this->dlhandle);
    throw PDNSException("Failed to initialize dlso, lib did not register a mandatory get function");
  }
  if (this->api->lookup == nullptr) {
    if (this->api->release != nullptr) {
      this->api->release(this->api);
    }

    dlclose(this->dlhandle);
    throw PDNSException("Failed to initialize dlso, lib did not register a mandatory lookup function");
  }
}

DlsoBackend::~DlsoBackend()
{
  if (this->api->release != nullptr) {
    this->api->release(this->api);
  }
  dlclose(this->dlhandle);
}

void DlsoBackend::lookup(const QType& qtype, const DNSName& qdomain, int32_t zoneId, DNSPacket* pkt_p)
{
  DLOG(
    g_log << Logger::Debug << __PRETTY_FUNCTION__ << " qtype: " << qtype.toString() << " qdomain: " << qdomain << " zoneId: " << zoneId << " pkt_p: " << pkt_p << endl;
  );
  if (in_query) {
    throw PDNSException("Attempt to lookup while one running");
  }

  string qname = qdomain.toString();
  bool success = false;

  if (pkt_p != nullptr) {
    ComboAddress edns_or_resolver_ip = pkt_p->getRealRemote().getNetwork();
    // TODO expose the whole union to 3rd party lib.
    // clang-tidy: This reinterpret_cast is needed as we expose a generic `sockaddr`.
    auto* sockaddr = reinterpret_cast<struct sockaddr*>(std::addressof(edns_or_resolver_ip.sin4));
    success = api->lookup(api->handle, qtype.getCode(), qname.size(), qname.c_str(), sockaddr, zoneId);
  }
  else {
    success = api->lookup(api->handle, qtype.getCode(), qname.size(), qname.c_str(), nullptr, zoneId);
  }

  if (!success) {
    throw PDNSException("Backend failed");
  }
}

bool DlsoBackend::list(const DNSName& target, int domain_id, bool include_disabled)
{
  DLOG(
    g_log << Logger::Debug << __PRETTY_FUNCTION__ << " target: " << target << " domain_id " << domain_id << endl;
  );
  if (api->list == nullptr) {
    return false;
  }

  string qname = target.toString();
  bool success = api->list(api->handle, qname.size(), qname.c_str(), domain_id);

  if (!success) {
    throw PDNSException("Backend failed");
  }

  return success;
}

extern "C" void fill_cb(void* ptr, const struct resource_record* record)
{
  auto* rr = static_cast<DNSResourceRecord*>(ptr);
  rr->qtype = record->qtype;
  string qname = string(record->qname, record->qname_len);
  rr->qname = DNSName(qname);
  rr->qclass = QClass::IN;
  rr->content = string(record->content, record->content_len);
  rr->ttl = record->ttl;
  rr->auth = record->auth;
  rr->scopeMask = record->scope_mask;
  rr->domain_id = record->domain_id;
  DLOG(
    g_log << Logger::Debug << __PRETTY_FUNCTION__
      << " DNSResourceRecord qtype: " << rr->qtype
      << " qname: " << rr->qname
      << " content: " << rr->content
      << " ttl: " << rr->ttl
      << " domain_id: " << rr->domain_id
      << " auth: " << rr->auth << endl;
  );
}

bool DlsoBackend::get(DNSResourceRecord& rr)
{
  DLOG(
    g_log << Logger::Debug << __PRETTY_FUNCTION__ << endl;
  );
  bool success = api->get(api->handle, fill_cb, &rr);

  if (!success) {
    in_query = false;
    return false;
  }

  return true;
}

extern "C" void fill_meta_cb(void* ptr, uint8_t value_len, const struct dns_value* values)
{
  auto* meta = static_cast<std::vector<std::string>*>(ptr);
  meta->resize(meta->size() + value_len);

  for (uint8_t i = 0; i < value_len; i++) {
    const struct dns_value* value = &values[i];
    string value_s = string(value->value, value->value_len);

    (*meta).emplace_back(value_s);
  }
}

extern "C" void fill_metas_cb(void* ptr, uint8_t meta_len, const struct dns_meta* c_metas)
{
  auto* metas = static_cast<std::map<std::string, std::vector<std::string>>*>(ptr);
  for (uint8_t i = 0; i < meta_len; i++) {
    const struct dns_meta* meta = &c_metas[i];
    string property = string(meta->property, meta->property_len);
    const struct dns_value* values = meta->values;

    fill_meta_cb(&(*metas)[property], meta->value_len, values);
  }
}

bool DlsoBackend::getAllDomainMetadata(const DNSName& name, std::map<std::string, std::vector<std::string>>& metas)
{
  DLOG(g_log << Logger::Debug << __PRETTY_FUNCTION__ << " name: " << name << endl);
  if (!d_dnssec || api->get_metas == nullptr) {
    return false;
  }

  metas.clear();

  string qname = name.toString();
  return api->get_metas(api->handle, qname.size(), qname.c_str(), fill_metas_cb, &metas);
}

bool DlsoBackend::getDomainMetadata(const DNSName& name, const std::string& kind, std::vector<std::string>& meta)
{
  DLOG(
    g_log << Logger::Debug << __PRETTY_FUNCTION__ << " qname: " << name << " kind:" << kind << endl;
  );
  if (api->get_meta == nullptr) {
    return false;
  }

  meta.clear();

  string qname = name.toString();
  auto ret = api->get_meta(api->handle, qname.size(), qname.c_str(), kind.size(), kind.c_str(), fill_meta_cb, &meta);

  DLOG(
    g_log << Logger::Debug << __PRETTY_FUNCTION__ << " metadata: [";
    for (const auto& iter_m : meta) {
      g_log << Logger::Debug << " <" << iter_m << ">,";
    }
    g_log << Logger::Debug << "]" << endl;
  );
  return ret;
}

bool DlsoBackend::setDomainMetadata(const DNSName& name, const std::string& kind, const std::vector<std::string>& meta)
{
  if (api->set_meta == nullptr) {
    return false;
  }

  vector<dns_value> values;
  values.resize(meta.size());
  for (const auto& iter : meta) {
    values.push_back(
      dns_value{
        .value = iter.c_str(),
        .value_len = static_cast<uint8_t>(iter.size()),
      });
  }

  string qname = name.toString();
  bool status = api->set_meta(api->handle, qname.size(), qname.c_str(), kind.size(), kind.c_str(), values.size(), values.data());
  return status;
}

extern "C" void fill_key_cb(void* ptr, const struct dnskey* dnskey)
{
  auto* keys = static_cast<std::vector<DNSBackend::KeyData>*>(ptr);
  DNSBackend::KeyData key = {
    .content = string(dnskey->data, dnskey->data_len),
    .id = dnskey->id,
    .flags = dnskey->flags,
    .active = dnskey->active,
    .published = dnskey->published,
  };
  keys->push_back(key);
  DLOG(
    g_log << Logger::Debug << __PRETTY_FUNCTION__
      << " KeyData content: " << key.content
      << " id: " << key.id
      << " flags: " << key.flags
      << " active: " << key.active
      << " published: " << key.published << endl;
  );
}

bool DlsoBackend::getDomainKeys(const DNSName& name, std::vector<DNSBackend::KeyData>& keys)
{
  DLOG(
    g_log << Logger::Debug << __PRETTY_FUNCTION__ << " name: " << endl;
  );
  // no point doing dnssec if it's not supported
  if (!d_dnssec || api->get_domain_keys == nullptr) {
    return false;
  }
  keys.clear();

  string qname = name.toString();
  return api->get_domain_keys(api->handle, qname.size(), qname.c_str(), fill_key_cb, &keys);
}

bool DlsoBackend::removeDomainKey(const DNSName& name, unsigned int id)
{
  return false; // TODO
}

bool DlsoBackend::addDomainKey(const DNSName& name, const KeyData& key, int64_t& id)
{
  // no point doing dnssec if it's not supported
  if (!d_dnssec || api->add_domain_key == nullptr) {
    return false;
  }

  string qname = name.toString();
  struct dnskey dnskey
  {
    .id = key.id,
    .flags = static_cast<uint16_t>(key.flags),
    .data_len = static_cast<uint16_t>(key.content.size()),
    .data = key.content.c_str(),
    .active = key.active,
    .published = key.published,
  };

  return api->add_domain_key(api->handle, qname.size(), qname.c_str(), &dnskey, &id);
}

bool DlsoBackend::activateDomainKey(const DNSName& name, unsigned int id)
{
  return false; // TODO
}

bool DlsoBackend::deactivateDomainKey(const DNSName& name, unsigned int id)
{
  return false; // TODO
}

bool DlsoBackend::doesDNSSEC()
{
  return d_dnssec;
}

struct fill_tsig
{
  DNSName* algorithm;
  std::string* content;
};

extern "C" void fill_tsig_key(void* ptr, uint8_t alg_len, const char* alg, uint8_t key_len, const char* key)
{
  auto* data = static_cast<struct fill_tsig*>(ptr);
  data->content->operator=(string(key, key_len));
  if (alg_len > 0) {
    data->algorithm->operator=(DNSName(string(alg, alg_len)));
  }
  DLOG(
    g_log << Logger::Debug << __PRETTY_FUNCTION__ << " algorithm " << *data->algorithm
          << " content: <" << *data->content << ">"
          << endl;
  );
}

bool DlsoBackend::getTSIGKey(const DNSName& name, DNSName& algorithm, std::string& content)
{
  DLOG(
    g_log << Logger::Debug
        << __PRETTY_FUNCTION__ << " name: <" << name
        << "> algorithm: <" << algorithm
        << "> content: <" << content << ">"
        << endl;
  );
  if (api->get_tsig_key == nullptr) {
    return false;
  }

  struct fill_tsig data = {.algorithm = std::addressof(algorithm), .content = std::addressof(content)};

  string qname;
  if (!name.empty()) {
    qname = name.toString();
  }

  g_log << Logger::Info
        << __PRETTY_FUNCTION__ << " name: <" << qname
        << "> size: <" << qname.size()
        << "> algorithm: <" << algorithm
        << "> content: <" << content << ">"
        << std::endl;
  return api->get_tsig_key(api->handle, qname.size(), qname.c_str(), fill_tsig_key, &data);
}

bool DlsoBackend::setTSIGKey(const DNSName& name, const DNSName& algorithm, const std::string& content)
{
  if (api->set_tsig_key == nullptr) {
    return false;
  }

  string qname = name.toString();
  string alg = algorithm.toString();

  return api->set_tsig_key(api->handle, qname.size(), qname.c_str(), alg.size(), alg.c_str(), content.size(), content.c_str());
}

bool DlsoBackend::deleteTSIGKey(const DNSName& name)
{
  return false; // TODO
}

bool DlsoBackend::getTSIGKeys(std::vector<struct TSIGKey>& keys)
{
  return false; // TODO
}

struct before_after_t
{
  DNSName* unhashed;
  DNSName* before;
  DNSName* after;
};

extern "C" void fill_before_after(void* ptr, uint8_t unhashed_len, const char* unhashed_, uint8_t before_len, const char* before_, uint8_t after_len, const char* after_)
{
  auto* ba = static_cast<struct before_after_t*>(ptr);

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

  (*ba->unhashed).clear();
  (*ba->unhashed) += unhashed;
  (*ba->before).clear();
  (*ba->before) += before;
  (*ba->after).clear();
  (*ba->after) += after;
}

bool DlsoBackend::getBeforeAndAfterNamesAbsolute(uint32_t id, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after)
{
  if (!d_dnssec || api->get_before_after == nullptr) {
    return false;
  }

  string qname_ = qname.toString();
  string unhashed_;
  if (!unhashed.empty()) {
    unhashed_ = unhashed.toString();
  }
  string before_;
  if (!before.empty()) {
    before_ = before.toString();
  }
  string after_;
  if (!after.empty()) {
    after_ = after.toString();
  }

  struct before_after_t ba = {
    ba.unhashed = &unhashed,
    ba.before = &before,
    ba.after = &after,
  };

  return api->get_before_after(
    api->handle, id,
    qname_.size(), qname_.c_str(),
    unhashed_.size(), unhashed_.c_str(),
    before_.size(), before_.c_str(),
    after_.size(), after_.c_str(),
    fill_before_after, &ba);
}

bool DlsoBackend::updateDNSSECOrderNameAndAuth(uint32_t domain_id, const DNSName& qname_, const DNSName& ordername_, bool auth, const uint16_t qtype)
{
  if (api->update_dnssec_order_name_and_auth == nullptr) {
    return false;
  }

  string qname;
  if (!qname_.empty()) {
    qname = qname_.toString();
  }
  string ordername;
  if (!ordername_.empty()) {
    ordername = ordername_.toString();
  }

  return api->update_dnssec_order_name_and_auth(api->handle, domain_id, qname.size(), qname.c_str(), ordername.size(), ordername.c_str(), auth, qtype);
}

bool DlsoBackend::updateEmptyNonTerminals(uint32_t domain_id, set<DNSName>& insert, set<DNSName>& erase, bool remove)
{
  if (api->update_empty_non_terminals == nullptr || api->remove_empty_non_terminals == nullptr) {
    return false;
  }

  if (remove && !api->remove_empty_non_terminals(api->handle, domain_id)) {
    return false;
  }

  for (const auto& it : insert) {
    auto value = it.toString();

    if (!api->update_empty_non_terminals(api->handle, domain_id, value.size(), value.c_str(), true)) {
      return false;
    }
  }

  for (const auto& it : erase) {
    auto value = it.toString();

    if (!api->update_empty_non_terminals(api->handle, domain_id, value.size(), value.c_str(), false)) {
      return false;
    }
  }

  return true;
}

extern "C" void fill_domain_info(void* ptr, struct domain_info* domain_info)
{
  auto* di = static_cast<DomainInfo*>(ptr);

  di->masters.clear();
  for (int i = 0; i < domain_info->master_len; i++) {
    auto addr = di->masters[i];
    auto salen = addr.sin4.sin_family == AF_INET ? sizeof(addr.sin4) : sizeof(addr.sin6);
    const auto* master_addr = std::addressof(di->masters[i]);
    auto* sockaddr = reinterpret_cast<const struct sockaddr*>(master_addr);
    auto ca = ComboAddress(sockaddr, salen);
    di->masters.push_back(ca);
  }

  DNSName zone;
  if (domain_info->zone_len > 0) {
    zone = DNSName(string(domain_info->zone, domain_info->zone_len));
  }

  di->zone = zone;
  di->last_check = domain_info->last_check;
  di->account = string(domain_info->account, domain_info->account_len);
  di->id = domain_info->id;
  di->notified_serial = domain_info->notified_serial;
  di->serial = domain_info->serial;

  switch (domain_info->kind) {
  case DOMAIN_INFO_KIND_SLAVE:
    di->kind = DomainInfo::Slave;
    break;
  case DOMAIN_INFO_KIND_NATIVE:
    di->kind = DomainInfo::Native;
    break;
  case DOMAIN_INFO_KIND_PRODUCER:
    di->kind = DomainInfo::Producer;
    break;
  case DOMAIN_INFO_KIND_CONSUMER:
    di->kind = DomainInfo::Consumer;
    break;
  case DOMAIN_INFO_KIND_ALL:
    di->kind = DomainInfo::All;
    break;
  default:
  case DOMAIN_INFO_KIND_MASTER:
    di->kind = DomainInfo::Master;
    break;
  }
}

bool DlsoBackend::getDomainInfo(const DNSName& domain, DomainInfo& di, bool getSerial)
{
  if (api->get_domain_info == nullptr) {
    return false;
  }

  string qname = domain.toString();
  di.backend = this;

  return api->get_domain_info(api->handle, qname.size(), qname.c_str(), fill_domain_info, &di);
}

bool DlsoBackend::startTransaction(const DNSName& domain, int domain_id)
{
  if (api->start_transaction == nullptr) {
    return false;
  }

  string domain_ = domain.toString();

  return api->start_transaction(api->handle, domain_id, domain_.size(), domain_.c_str());
}

bool DlsoBackend::abortTransaction()
{
  if (api->abort_transaction == nullptr) {
    return false;
  }
  return api->abort_transaction(api->handle);
}

bool DlsoBackend::commitTransaction()
{
  if (api->commit_transaction == nullptr) {
    return false;
  }
  return api->commit_transaction(api->handle);
}

void fill_unfresh_slave(void* ptr, struct domain_info* domain_info)
{
  auto* unfresh = static_cast<vector<DomainInfo>*>(ptr);

  DomainInfo di;
  fill_domain_info(&di, domain_info);

  unfresh->push_back(di);
}

void DlsoBackend::getUnfreshSlaveInfos(vector<DomainInfo>* unfreshDomains)
{
  if (api->get_unfresh_slave == nullptr) {
    return;
  }

  bool status = api->get_unfresh_slave(api->handle, fill_unfresh_slave, unfreshDomains);

  if (!status) {
    throw PDNSException("DlsoBackend unable to retrieve list of slave domains");
  }
}

void DlsoBackend::setNotified(uint32_t domain_id, uint32_t serial)
{
  if (api->set_notified == nullptr) {
    return;
  }

  api->set_notified(api->handle, domain_id, serial);
}

void DlsoBackend::setFresh(uint32_t domain_id)
{
  if (api->set_fresh == nullptr) {
    return;
  }

  api->set_fresh(api->handle, domain_id);
}

bool DlsoBackend::replaceRRSet(uint32_t domain_id, const DNSName& qname, const QType& qt, const vector<DNSResourceRecord>& rrset)
{
  if (api->replace_record == nullptr) {
    return false;
  }

  vector<string> qnames;
  vector<resource_record> records;
  records.resize(rrset.size());

  for (const auto& rr : rrset) {
    qnames.push_back(rr.qname.toString());

    const string qname_ = qnames.back();
    records.push_back(resource_record{
      .qtype = rr.qtype.getCode(),
      .qname_len = static_cast<uint8_t>(qname_.size()),
      .scope_mask = rr.scopeMask,
      .content_len = static_cast<uint8_t>(rr.content.size()),
      .qname = qname_.c_str(),
      .content = rr.content.c_str(),
      .ttl = rr.ttl,
      .domain_id = rr.domain_id,
      .auth = rr.auth,
    });
  }

  string qname_ = qname.toString();

  try {
    bool status = api->replace_record(api->handle, domain_id, qname_.size(), qname_.c_str(), qt.getCode(), records.size(), records.data());
    return status;
  }
  catch (PDNSException& e) {
    throw e;
  }
}

bool DlsoBackend::feedRecord(const DNSResourceRecord& rr, const DNSName& ordername, bool _ordernameIsNSEC3)
{
  if (api->add_record == nullptr) {
    return false;
  }

  string qname = rr.qname.toString();

  struct resource_record record = {
    .qtype = rr.qtype.getCode(),
    .qname_len = static_cast<uint8_t>(qname.size()),
    .scope_mask = rr.scopeMask,
    .content_len = static_cast<uint8_t>(rr.content.size()),
    .qname = qname.c_str(),
    .content = rr.content.c_str(),
    .ttl = rr.ttl,
    .domain_id = rr.domain_id,
    .auth = rr.auth,
  };

  if (!ordername.empty()) {
    auto ordername_str = ordername.toString();
    return api->add_record(api->handle, &record, ordername_str.size(), ordername_str.c_str());
  }
  return api->add_record(api->handle, &record, 0, nullptr);
}

bool DlsoBackend::feedEnts(int domain_id, map<DNSName, bool>& nonterm)
{
  if (api->add_record_ent == nullptr) {
    return false;
  }

  for (const auto& nt : nonterm) {
    bool auth = nt.second;
    string qname = nt.first.toString();

    if (!api->add_record_ent(api->handle, domain_id, auth, qname.size(), qname.c_str())) {
      return false;
    }
  }

  return true;
}

bool DlsoBackend::feedEnts3(int domain_id, const DNSName& domain, map<DNSName, bool>& nonterm, const NSEC3PARAMRecordContent& ns3prc, bool narrow)
{
  if (api->add_record_ent_nsec3 == nullptr) {
    return false;
  }

  struct nsec3_param ns3 = {
    .salt = ns3prc.d_salt.c_str(),
    .salt_len = static_cast<uint8_t>(ns3prc.d_salt.size()),
    .alg = ns3prc.d_algorithm,
    .iterations = ns3prc.d_iterations,
    .flags = ns3prc.d_flags,
  };

  string domain_ = domain.toString();

  for (const auto& nt : nonterm) {
    bool auth = nt.second;
    string qname = nt.first.toString();
    if (!api->add_record_ent_nsec3(api->handle, domain_id, domain_.size(), domain_.c_str(), narrow, auth, qname.size(), qname.c_str(), &ns3)) {
      return false;
    }
  }

  return true;
}

class DlsoBackendFactory : public BackendFactory
{
public:
  DlsoBackendFactory() :
    BackendFactory("dlso") {}

  void declareArguments(const std::string& suffix = "") override
  {
    declare(suffix, "dnssec", "Enable dnssec support", "no");
    declare(suffix, "path", "Path", "");
    declare(suffix, "args", "args", "");
  }

  DNSBackend* make(const std::string& suffix = "") override
  {
    return new DlsoBackend(suffix);
  }
};

class DlsoLoader
{
public:
  DlsoLoader();
};

DlsoLoader::DlsoLoader()
{
  BackendMakers().report(new DlsoBackendFactory);
  g_log << Logger::Info << kBackendId << "This is the dlso backend version " VERSION
#ifndef REPRODUCIBLE
        << " (" __DATE__ " " __TIME__ ")"
#endif
        << " reporting" << endl;
}

static DlsoLoader dlsoloader;
