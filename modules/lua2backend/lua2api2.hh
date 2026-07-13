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
 * MERCHANTAPILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#pragma once
#include "boost/algorithm/string/join.hpp"
#include "pdns/arguments.hh"

#include "pdns/dnsbackend.hh"
#include "pdns/lua-auth4.hh"

class Lua2BackendAPIv2 : public DNSBackend, AuthLua4
{
private:
  typedef std::function<void()> init_call_t;
  typedef std::function<void()> deinit_call_t;

  typedef std::vector<std::pair<string, string>> lookup_context_t;

  typedef std::vector<std::pair<int, std::vector<std::pair<string, boost::variant<bool, int, DNSName, string, QType>>>>> lookup_result_t;
  typedef std::function<lookup_result_t(const QType& qtype, const DNSName& qname, domainid_t domain_id, const lookup_context_t& ctx)> lookup_call_t;

  typedef boost::variant<bool, lookup_result_t> list_result_t;
  typedef std::function<list_result_t(const DNSName& qname, domainid_t domain_id)> list_call_t;

  typedef vector<pair<string, boost::variant<bool, long, string, vector<string>>>> domaininfo_result_t;
  typedef boost::variant<bool, domaininfo_result_t> get_domaininfo_result_t;
  typedef vector<pair<DNSName, domaininfo_result_t>> get_all_domains_result_t;
  typedef std::function<get_domaininfo_result_t(const DNSName& domain)> get_domaininfo_call_t;
  typedef std::function<get_all_domains_result_t()> get_all_domains_call_t;

  typedef vector<pair<int, string>> domain_metadata_result_t;
  typedef boost::variant<bool, domain_metadata_result_t> get_domain_metadata_result_t;
  typedef boost::variant<bool, vector<pair<string, domain_metadata_result_t>>> get_all_domain_metadata_result_t;
  typedef std::function<get_domain_metadata_result_t(const DNSName& domain, const string& kind)> get_domain_metadata_call_t;
  typedef std::function<get_all_domain_metadata_result_t(const DNSName& domain)> get_all_domain_metadata_call_t;

  typedef vector<pair<string, boost::variant<bool, int, string>>> keydata_result_t;
  typedef boost::variant<bool, vector<pair<int, keydata_result_t>>> get_domain_keys_result_t;
  typedef std::function<get_domain_keys_result_t(const DNSName& domain)> get_domain_keys_call_t;

  typedef std::vector<std::pair<string, boost::variant<string, DNSName>>> before_and_after_names_result_t;
  typedef boost::variant<bool, before_and_after_names_result_t> get_before_and_after_names_absolute_result_t;
  typedef std::function<get_before_and_after_names_absolute_result_t(domainid_t id, const DNSName& qname)> get_before_and_after_names_absolute_call_t;

  typedef std::function<void(domainid_t, long)> set_notified_call_t;

  typedef std::function<string(const string& cmd)> direct_backend_cmd_call_t;

public:
  Lua2BackendAPIv2(Logr::log_t slog, const string& suffix);
  ~Lua2BackendAPIv2() override;

  void postPrepareContext() override;
  void postLoad() override;
  unsigned int getCapabilities() override;
  bool list(const ZoneName& target, domainid_t domain_id, bool /* include_disabled */ = false) override;
  void lookup(const QType& qtype, const DNSName& qname, domainid_t domain_id, DNSPacket* p = nullptr) override;
  bool get(DNSResourceRecord& rr) override;
  string directBackendCmd(const string& querystr) override;
  void setNotified(domainid_t id, uint32_t serial) override;
  void parseDomainInfo(const domaininfo_result_t& row, DomainInfo& di);
  bool getDomainInfo(const ZoneName& domain, DomainInfo& di, bool /* getSerial */ = true) override;
  void getAllDomains(vector<DomainInfo>* domains, bool /* getSerial */, bool /* include_disabled */) override;
  bool getAllDomainMetadata(const ZoneName& name, std::map<std::string, std::vector<std::string>>& meta) override;
  bool getDomainMetadata(const ZoneName& name, const std::string& kind, std::vector<std::string>& meta) override;
  bool getDomainKeys(const ZoneName& name, std::vector<DNSBackend::KeyData>& keys) override;
  bool getBeforeAndAfterNamesAbsolute(domainid_t id, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after) override;

private:
  std::list<DNSResourceRecord> d_result;
  bool d_debug_log{false};
  bool d_dnssec{false};

  lookup_call_t f_lookup;
  list_call_t f_list;

  get_domaininfo_call_t f_get_domaininfo;
  get_all_domains_call_t f_get_all_domains;

  get_domain_metadata_call_t f_get_domain_metadata;
  get_all_domain_metadata_call_t f_get_all_domain_metadata;

  get_domain_keys_call_t f_get_domain_keys;

  get_before_and_after_names_absolute_call_t f_get_before_and_after_names_absolute;

  set_notified_call_t f_set_notified;

  deinit_call_t f_deinit;

  void parseLookup(const lookup_result_t& result);
};
