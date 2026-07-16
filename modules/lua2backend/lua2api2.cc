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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "lua2backend.hh"

Lua2BackendAPIv2::Lua2BackendAPIv2(Logr::log_t slog, const string& suffix)
{
  d_slog = slog;
  d_include_path = ::arg()["lua-global-include-dir"];
  setArgPrefix("lua2" + suffix);
  d_debug_log = mustDo("query-logging");
  prepareContext();
  loadFile(getArg("filename"));
}

Lua2BackendAPIv2::~Lua2BackendAPIv2()
{
  if (f_deinit) {
    f_deinit();
  }
}

void Lua2BackendAPIv2::postPrepareContext()
{
  AuthLua4::postPrepareContext();
}

void Lua2BackendAPIv2::postLoad()
{
  // NOLINTNEXTLINE(clang-analyzer-cplusplus.NewDeleteLeaks): clang-tidy is adamant readVariable may leak a std::function in LuaContext::Reader(), but only warns for the first readVariable call.
  f_lookup = d_lw->readVariable<boost::optional<lookup_call_t>>("dns_lookup").get_value_or(nullptr);
  f_list = d_lw->readVariable<boost::optional<list_call_t>>("dns_list").get_value_or(nullptr);
  f_get_all_domains = d_lw->readVariable<boost::optional<get_all_domains_call_t>>("dns_get_all_domains").get_value_or(nullptr);
  f_get_domaininfo = d_lw->readVariable<boost::optional<get_domaininfo_call_t>>("dns_get_domaininfo").get_value_or(nullptr);
  f_get_domain_metadata = d_lw->readVariable<boost::optional<get_domain_metadata_call_t>>("dns_get_domain_metadata").get_value_or(nullptr);
  f_get_all_domain_metadata = d_lw->readVariable<boost::optional<get_all_domain_metadata_call_t>>("dns_get_all_domain_metadata").get_value_or(nullptr);
  f_get_domain_keys = d_lw->readVariable<boost::optional<get_domain_keys_call_t>>("dns_get_domain_keys").get_value_or(nullptr);
  f_get_before_and_after_names_absolute = d_lw->readVariable<boost::optional<get_before_and_after_names_absolute_call_t>>("dns_get_before_and_after_names_absolute").get_value_or(nullptr);
  f_set_notified = d_lw->readVariable<boost::optional<set_notified_call_t>>("dns_set_notified").get_value_or(nullptr);

  auto init = d_lw->readVariable<boost::optional<init_call_t>>("dns_init").get_value_or(nullptr);
  if (init) {
    init();
  }

  f_deinit = d_lw->readVariable<boost::optional<deinit_call_t>>("dns_deinit").get_value_or(nullptr);

  if (f_lookup == nullptr) {
    throw PDNSException("dns_lookup missing");
  }

  /* see if dnssec support is wanted */
  d_dnssec = d_lw->readVariable<boost::optional<bool>>("dns_dnssec").get_value_or(false);
  if (d_dnssec) {
    if (f_get_domain_metadata == nullptr) {
      throw PDNSException("dns_dnssec is true but dns_get_domain_metadata is missing");
    }
    if (f_get_before_and_after_names_absolute == nullptr) {
      throw PDNSException("dns_dnssec is true but dns_get_before_and_after_names_absolute is missing");
    }
    /* domain keys is not strictly speaking necessary for dnssec backend */
    if (f_get_domain_keys == nullptr) {
      SLOG(g_log << Logger::Warning << "dns_get_domain_keys missing - cannot do live signing" << endl,
           d_slog->info(Logr::Warning, "dns_get_domain_keys missing - cannot perform live signing"));
    }
  }
}

unsigned int Lua2BackendAPIv2::getCapabilities()
{
  unsigned int caps = CAP_DIRECT | CAP_LIST;
  if (d_dnssec) {
    caps |= CAP_DNSSEC;
  }
  if (f_get_all_domains != nullptr) {
    caps |= CAP_SEARCH;
  }
  return caps;
}

void Lua2BackendAPIv2::parseLookup(const lookup_result_t& result)
{
  for (const auto& row : result) {
    DNSResourceRecord rec;
    for (const auto& item : row.second) {
      try {
        if (item.first == "type") {
          if (item.second.which() == 1) {
            rec.qtype = QType(boost::get<int>(item.second));
          }
          else if (item.second.which() == 3) {
            rec.qtype = boost::get<string>(item.second);
          }
          else { // assuming item.second.which() == 4 here
            rec.qtype = boost::get<QType>(item.second);
          }
        }
        else if (item.first == "name") {
          if (item.second.which() == 3) {
            rec.qname = DNSName(boost::get<string>(item.second));
          }
          else { // assuming item.second.which() == 2 here
            rec.qname = boost::get<DNSName>(item.second);
          }
        }
        else if (item.first == "domain_id") {
          rec.domain_id = boost::get<int>(item.second);
        }
        else if (item.first == "auth") {
          if (item.second.which() == 1) {
            rec.auth = boost::get<int>(item.second) != 0;
          }
          else { // assuming item.second.which() == 0 here
            rec.auth = boost::get<bool>(item.second);
          }
        }
        else if (item.first == "last_modified") {
          rec.last_modified = static_cast<time_t>(boost::get<int>(item.second));
        }
        else if (item.first == "ttl") {
          rec.ttl = boost::get<int>(item.second);
        }
        else if (item.first == "content") {
          if (item.second.which() == 1) {
            rec.setContent(std::to_string(boost::get<int>(item.second)));
          }
          else { // assuming item.second.which() == 3 here
            rec.setContent(boost::get<string>(item.second));
          }
        }
        else if (item.first == "scopeMask") {
          rec.scopeMask = boost::get<int>(item.second);
        }
        else {
          SLOG(g_log << Logger::Warning << "Unsupported key '" << item.first << "' in lookup or list result" << endl,
               d_slog->info(Logr::Warning, "Unsupported key in lookup or list result", "key", Logging::Loggable(item.first)));
        }
      }
      catch (const std::exception& e) {
        std::stringstream value;
        value << item.second;
        throw PDNSException("Unable to parse " + item.first + " value (" + value.str() + ") of variant type " + std::to_string(item.second.which()) + " in lookup or list result: " + e.what());
      }
    }
    if (d_debug_log) {
      SLOG(g_log << Logger::Debug << "[" << getPrefix() << "] Got result " << "'" << rec.qname << " IN " << rec.qtype.toString() << " " << rec.ttl << " " << rec.getZoneRepresentation() << "'" << endl,
           d_slog->info(Logr::Debug, "Got result", "name", Logging::Loggable(rec.qname), "type", Logging::Loggable(rec.qtype), "ttl", Logging::Loggable(rec.ttl), "data", Logging::Loggable(rec.getZoneRepresentation())));
    }
    d_result.push_back(std::move(rec));
  }
  if (d_result.empty() && d_debug_log) {
    SLOG(g_log << Logger::Debug << "[" << getPrefix() << "] Got empty result" << endl,
         d_slog->info(Logr::Debug, "Got empty result"));
  }
}

bool Lua2BackendAPIv2::list(const ZoneName& target, domainid_t domain_id, bool /* include_disabled */)
{
  if (f_list == nullptr) {
    SLOG(g_log << Logger::Error << "[" << getPrefix() << "] dns_list missing - cannot do AXFR" << endl,
         d_slog->info(Logr::Error, "dns_list missing - cannot perform AXFR"));
    return false;
  }

  if (!d_result.empty()) {
    throw PDNSException("list attempted while another was running");
  }

  if (d_debug_log) {
    SLOG(g_log << Logger::Debug << "[" << getPrefix() << "] Calling " << "list" << "(" << "target=" << target << ",domain_id=" << domain_id << ")" << endl,
         d_slog->info(Logr::Debug, "Calling list", "target", Logging::Loggable(target), "domain id", Logging::Loggable(domain_id)));
  }
  list_result_t result = f_list(target.operator const DNSName&(), domain_id);

  if (result.which() == 0) {
    return false;
  }

  parseLookup(boost::get<lookup_result_t>(result));

  return true;
}

void Lua2BackendAPIv2::lookup(const QType& qtype, const DNSName& qname, domainid_t domain_id, DNSPacket* pkt)
{
  if (!d_result.empty()) {
    throw PDNSException("lookup attempted while another was running");
  }

  lookup_context_t ctx;
  if (pkt != nullptr) {
    ctx.emplace_back(lookup_context_t::value_type{"source_address", pkt->getInnerRemote().toString()});
    ctx.emplace_back(lookup_context_t::value_type{"real_source_address", pkt->getRealRemote().toString()});
  }

  if (d_debug_log) {
    SLOG(g_log << Logger::Debug << "[" << getPrefix() << "] Calling " << "lookup" << "(" << "qtype=" << qtype.toString() << ",qname=" << qname << ",domain_id=" << domain_id << ")" << endl,
         d_slog->info(Logr::Debug, "Calling lookup", "type", Logging::Loggable(qtype), "name", Logging::Loggable(qname), "domain id", Logging::Loggable(domain_id)));
  }
  lookup_result_t result = f_lookup(qtype, qname, domain_id, ctx);
  parseLookup(result);
}

bool Lua2BackendAPIv2::get(DNSResourceRecord& drr)
{
  if (d_result.empty()) {
    return false;
  }
  drr = std::move(d_result.front());
  d_result.pop_front();
  return true;
}

void Lua2BackendAPIv2::lookupEnd()
{
  d_result.clear();
}

string Lua2BackendAPIv2::directBackendCmd(const string& querystr)
{
  string::size_type pos = querystr.find_first_of(" \t");
  string cmd = querystr;
  string par{};
  if (pos != string::npos) {
    cmd = querystr.substr(0, pos);
    par = querystr.substr(pos + 1);
  }
  direct_backend_cmd_call_t dbc = d_lw->readVariable<boost::optional<direct_backend_cmd_call_t>>(cmd).get_value_or(nullptr);
  if (dbc == nullptr) {
    return cmd + "not found";
  }
  if (d_debug_log) {
    SLOG(g_log << Logger::Debug << "[" << getPrefix() << "] Calling " << cmd << "(" << "parameter=" << par << ")" << endl,
         d_slog->info(Logr::Debug, "Direct backend command", "command", Logging::Loggable(cmd), "parameters", Logging::Loggable(par)));
  }
  return dbc(par);
}

void Lua2BackendAPIv2::setNotified(domainid_t domain_id, uint32_t serial)
{
  if (f_set_notified == nullptr) {
    return;
  }
  if (d_debug_log) {
    SLOG(g_log << Logger::Debug << "[" << getPrefix() << "] Calling " << "dns_set_notified" << "(" << "id=" << domain_id << ",serial=" << serial << ")" << endl,
         d_slog->info(Logr::Debug, "Calling dns_set_notified", "id", Logging::Loggable(domain_id), "serial", Logging::Loggable(serial)));
  }
  f_set_notified(domain_id, serial);
}

void Lua2BackendAPIv2::parseDomainInfo(const domaininfo_result_t& row, DomainInfo& info)
{
  info.id = UnknownDomainID;
  for (const auto& item : row) {
    try {
      if (item.first == "account") {
        if (item.second.which() == 1) { // should the account name be all-digits...
          info.account = std::to_string(boost::get<long>(item.second));
        }
        else { // assuming item.second.which() == 2 here
          info.account = boost::get<string>(item.second);
        }
      }
      else if (item.first == "last_check") {
        info.last_check = static_cast<time_t>(boost::get<long>(item.second));
      }
      else if (item.first == "masters") {
        for (const auto& primary : boost::get<vector<string>>(item.second)) {
          info.primaries.emplace_back(ComboAddress(primary, 53));
        }
      }
      else if (item.first == "id") {
        info.id = static_cast<domainid_t>(boost::get<long>(item.second));
      }
      else if (item.first == "notified_serial") {
        info.notified_serial = static_cast<unsigned int>(boost::get<long>(item.second));
      }
      else if (item.first == "serial") {
        info.serial = static_cast<unsigned int>(boost::get<long>(item.second));
      }
      else if (item.first == "kind") {
        info.kind = DomainInfo::stringToKind(boost::get<string>(item.second));
      }
      else {
        SLOG(g_log << Logger::Warning << "Unsupported key '" << item.first << "' in domaininfo result" << endl,
             d_slog->info(Logr::Warning, "Unsupported key in domaininfo result", "key", Logging::Loggable(item.first)));
      }
    }
    catch (const std::exception& e) {
      // We can't get a printable version of the contents, because of the
      // vector<string> case, which is not OutputStreamable.
      throw PDNSException("Unable to parse " + item.first + " value of variant type " + std::to_string(item.second.which()) + " in domaininfo result: " + e.what());
    }
  }
  info.backend = this;
  if (d_debug_log) {
    SLOG(g_log << Logger::Debug << "[" << getPrefix() << "] Got result " << "'" << "zone=" << info.zone << ",serial=" << info.serial << ",kind=" << info.getKindString() << "'" << endl,
         d_slog->info(Logr::Debug, "Got domain info", "zone", Logging::Loggable(info.zone), "serial", Logging::Loggable(info.serial), "kind", Logging::Loggable(info.getKindString())));
  }
}

bool Lua2BackendAPIv2::getDomainInfo(const ZoneName& domain, DomainInfo& info, bool /* getSerial */)
{
  if (f_get_domaininfo == nullptr) {
    // use getAuth instead... but getAuth wraps getSOA which will call
    // getDomainInfo if this is a domain variant, so protect against this
    // would-be infinite recursion.
    if (domain.hasVariant()) {
      SLOG(g_log << Logger::Info << "Unable to return domain information for '" << domain.toLogString() << "' due to unimplemented dns_get_domaininfo" << endl,
           d_slog->info(Logr::Info, "Unable to return domain information due to unimplemented dns_get_domaininfo", "domain", Logging::Loggable(domain)));
      return false;
    }
    SOAData soa;
    if (!getAuth(domain, &soa)) {
      return false;
    }

    info.id = soa.domain_id;
    info.zone = domain;
    info.backend = this;
    info.serial = soa.serial;
    return true;
  }

  if (d_debug_log) {
    SLOG(g_log << Logger::Debug << "[" << getPrefix() << "] Calling " << "get_domaininfo" << "(" << "domain=" << domain << ")" << endl,
         d_slog->info(Logr::Debug, "Calling get_domaininfo", "domain", Logging::Loggable(domain)));
  }
  get_domaininfo_result_t result = f_get_domaininfo(domain.operator const DNSName&());

  if (result.which() == 0) {
    return false;
  }

  info.zone = domain;
  parseDomainInfo(boost::get<domaininfo_result_t>(result), info);

  return true;
}

void Lua2BackendAPIv2::getAllDomains(vector<DomainInfo>* domains, bool /* getSerial */, bool /* include_disabled */)
{
  if (f_get_all_domains == nullptr) {
    return;
  }

  if (d_debug_log) {
    SLOG(g_log << Logger::Debug << "[" << getPrefix() << "] Calling " << "get_all_domains" << "(" << "" << ")" << endl,
         d_slog->info(Logr::Debug, "Calling get_all_domains"));
  }
  for (const auto& row : f_get_all_domains()) {
    DomainInfo info;
    info.zone = ZoneName(row.first);
    if (d_debug_log) {
      SLOG(g_log << Logger::Debug << "[" << getPrefix() << "] Got result " << "'" << info.zone << "'" << endl,
           d_slog->info(Logr::Debug, "Got result", "domain", Logging::Loggable(info.zone)));
    }
    parseDomainInfo(row.second, info);
    domains->push_back(std::move(info));
  }
}

bool Lua2BackendAPIv2::getAllDomainMetadata(const ZoneName& name, std::map<std::string, std::vector<std::string>>& meta)
{
  if (f_get_all_domain_metadata == nullptr) {
    return false;
  }

  if (d_debug_log) {
    SLOG(g_log << Logger::Debug << "[" << getPrefix() << "] Calling " << "get_all_domain_metadata" << "(" << "name=" << name << ")" << endl,
         d_slog->info(Logr::Debug, "Calling get_all_domain_metadata", "domain", Logging::Loggable(name)));
  }
  get_all_domain_metadata_result_t result = f_get_all_domain_metadata(name.operator const DNSName&());
  if (result.which() == 0) {
    return false;
  }

  for (const auto& row : boost::get<vector<pair<string, domain_metadata_result_t>>>(result)) {
    meta[row.first].clear();
    for (const auto& item : row.second) {
      meta[row.first].push_back(item.second);
    }
    if (d_debug_log) {
      SLOG(g_log << Logger::Debug << "[" << getPrefix() << "] Got result " << "'" << "kind=" << row.first << ",value=" << boost::algorithm::join(meta[row.first], ", ") << "'" << endl,
           d_slog->info(Logr::Debug, "Got result", "kind", Logging::Loggable(row.first), "value", Logging::Loggable(boost::algorithm::join(meta[row.first], ", "))));
    }
  }

  return true;
}

bool Lua2BackendAPIv2::getDomainMetadata(const ZoneName& name, const std::string& kind, std::vector<std::string>& meta)
{
  if (f_get_domain_metadata == nullptr) {
    return false;
  }

  if (d_debug_log) {
    SLOG(g_log << Logger::Debug << "[" << getPrefix() << "] Calling " << "get_domain_metadata" << "(" << "name=" << name << ",kind=" << kind << ")" << endl,
         d_slog->info(Logr::Debug, "Calling get_domain_metadata", "domain", Logging::Loggable(name), "kind", Logging::Loggable(kind)));
  }
  get_domain_metadata_result_t result = f_get_domain_metadata(name.operator const DNSName&(), kind);
  if (result.which() == 0) {
    return false;
  }

  meta.clear();
  for (const auto& item : boost::get<domain_metadata_result_t>(result)) {
    meta.push_back(item.second);
  }

  if (d_debug_log) {
    SLOG(g_log << Logger::Debug << "[" << getPrefix() << "] Got result " << "'" << "value=" << boost::algorithm::join(meta, ", ") << "'" << endl,
         d_slog->info(Logr::Debug, "Got result", "value", Logging::Loggable(boost::algorithm::join(meta, ", "))));
  }
  return true;
}

bool Lua2BackendAPIv2::getDomainKeys(const ZoneName& name, std::vector<DNSBackend::KeyData>& keys)
{
  if (f_get_domain_keys == nullptr) {
    return false;
  }

  if (d_debug_log) {
    SLOG(g_log << Logger::Debug << "[" << getPrefix() << "] Calling " << "get_domain_keys" << "(" << "name=" << name << ")" << endl,
         d_slog->info(Logr::Debug, "Calling get_domain_keys", "domain", Logging::Loggable(name)));
  }
  get_domain_keys_result_t result = f_get_domain_keys(name.operator const DNSName&());

  if (result.which() == 0) {
    return false;
  }

  for (const auto& row : boost::get<vector<pair<int, keydata_result_t>>>(result)) {
    DNSBackend::KeyData key;
    key.published = true;
    for (const auto& item : row.second) {
      try {
        if (item.first == "content") {
          key.content = boost::get<string>(item.second);
        }
        else if (item.first == "id") {
          key.id = static_cast<unsigned int>(boost::get<int>(item.second));
        }
        else if (item.first == "flags") {
          key.flags = static_cast<unsigned int>(boost::get<int>(item.second));
        }
        else if (item.first == "active") {
          if (item.second.which() == 1) {
            key.active = boost::get<int>(item.second) != 0;
          }
          else { // assuming item.second.which() == 0 here
            key.active = boost::get<bool>(item.second);
          }
        }
        else if (item.first == "published") {
          if (item.second.which() == 1) {
            key.published = boost::get<int>(item.second) != 0;
          }
          else { // assuming item.second.which() == 0 here
            key.published = boost::get<bool>(item.second);
          }
        }
        else {
          SLOG(g_log << Logger::Warning << "[" << getPrefix() << "] Unsupported key '" << item.first << "' in keydata result" << endl,
               d_slog->info(Logr::Warning, "Unsupported key in keydata result", "key", Logging::Loggable(item.first)));
        }
      }
      catch (const std::exception& e) {
        std::stringstream value;
        value << item.second;
        throw PDNSException("Unable to parse " + item.first + " value (" + value.str() + ") of variant type " + std::to_string(item.second.which()) + " in keydata result: " + e.what());
      }
    }
    if (d_debug_log) {
      SLOG(g_log << Logger::Debug << "[" << getPrefix() << "] Got result " << "'" << "id=" << key.id << ",flags=" << key.flags << ",active=" << (key.active ? "true" : "false") << ",published=" << (key.published ? "true" : "false") << "'" << endl,
           d_slog->info(Logr::Debug, "Got result", "id", Logging::Loggable(key.id), "flags", Logging::Loggable(key.flags), "active", Logging::Loggable(key.active ? "true" : "false"), "published", Logging::Loggable(key.published ? "true" : "false")));
    }
    keys.emplace_back(std::move(key));
  }

  return true;
}

bool Lua2BackendAPIv2::getBeforeAndAfterNamesAbsolute(domainid_t domain_id, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after)
{
  if (f_get_before_and_after_names_absolute == nullptr) {
    return false;
  }

  if (d_debug_log) {
    SLOG(g_log << Logger::Debug << "[" << getPrefix() << "] Calling " << "get_before_and_after_names_absolute" << "(" << "id=<<" << domain_id << ",qname=" << qname << ")" << endl,
         d_slog->info(Logr::Debug, "Calling get_before_and_after_names_absolute", "id", Logging::Loggable(domain_id), "name", Logging::Loggable(qname)));
  }
  get_before_and_after_names_absolute_result_t result = f_get_before_and_after_names_absolute(domain_id, qname);

  if (result.which() == 0) {
    return false;
  }

  before_and_after_names_result_t row = boost::get<before_and_after_names_result_t>(result);
  if (row.size() != 3) {
    SLOG(g_log << Logger::Error << "Invalid result from dns_get_before_and_after_names_absolute, expected array with 3 items, got " << row.size() << "item(s)" << endl,
         d_slog->info(Logr::Error, "Invalid result from dns_get_before_and_after_names_absolute, expected array with 3 rows", "rows returned", Logging::Loggable(row.size())));
    return false;
  }
  for (const auto& item : row) {
    DNSName value;
    if (item.second.which() == 0) {
      value = DNSName(boost::get<string>(item.second));
    }
    else {
      value = DNSName(boost::get<DNSName>(item.second));
    }
    if (item.first == "unhashed") {
      unhashed = std::move(value);
    }
    else if (item.first == "before") {
      before = std::move(value);
    }
    else if (item.first == "after") {
      after = std::move(value);
    }
    else {
      SLOG(g_log << Logger::Error << "Invalid result from dns_get_before_and_after_names_absolute, unexpected key " << item.first << endl,
           d_slog->info(Logr::Error, "Invalid result from dns_get_before_and_after_names_absolute, unexpected key", "key", Logging::Loggable(item.first)));
      return false;
    }
  }

  if (d_debug_log) {
    SLOG(g_log << Logger::Debug << "[" << getPrefix() << "] Got result " << "'" << "unhashed=" << unhashed << ",before=" << before << ",after=" << after << "'" << endl,
         d_slog->info(Logr::Debug, "Got result", "unhashed", Logging::Loggable(unhashed), "before", Logging::Loggable(before), "after", Logging::Loggable(after)));
  }
  return true;
}
