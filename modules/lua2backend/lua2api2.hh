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
#ifndef LUA2API_2_HH
#define LUA2API_2_HH 1

#include "boost/lexical_cast.hpp"
#include "boost/algorithm/string/join.hpp"
#include "pdns/arguments.hh"

class Lua2BackendAPIv2 : public DNSBackend, AuthLua4 {
private:
  typedef std::function<void()> init_call_t;
  typedef std::function<void()> deinit_call_t;

  typedef std::vector<std::pair<string, string> > lookup_context_t;

  typedef std::vector<std::pair<int, std::vector<std::pair<string, boost::variant<bool, int, DNSName, string, QType> > > > > lookup_result_t;
  typedef std::function<lookup_result_t(const QType& qtype, const DNSName& qname, int domain_id, const lookup_context_t &ctx)> lookup_call_t;

  typedef boost::variant<bool, lookup_result_t> list_result_t;
  typedef std::function<list_result_t(const DNSName& qname, int domain_id)> list_call_t;

  typedef vector<pair<string, boost::variant<bool, long, string, vector<string> > > > domaininfo_result_t;
  typedef boost::variant<bool, domaininfo_result_t> get_domaininfo_result_t;
  typedef vector<pair<DNSName, domaininfo_result_t> > get_all_domains_result_t;
  typedef std::function<get_domaininfo_result_t(const DNSName& domain)> get_domaininfo_call_t;
  typedef std::function<get_all_domains_result_t()> get_all_domains_call_t;

  typedef vector<pair<int, string> > domain_metadata_result_t;
  typedef boost::variant<bool, domain_metadata_result_t> get_domain_metadata_result_t;
  typedef boost::variant<bool, vector<pair<string, domain_metadata_result_t> > > get_all_domain_metadata_result_t;
  typedef std::function<get_domain_metadata_result_t(const DNSName& domain, const string& kind)> get_domain_metadata_call_t;
  typedef std::function<get_all_domain_metadata_result_t(const DNSName& domain)> get_all_domain_metadata_call_t;

  typedef vector<pair<string, boost::variant<bool, int, string> > > keydata_result_t;
  typedef boost::variant<bool, vector<pair<int, keydata_result_t> > > get_domain_keys_result_t;
  typedef std::function<get_domain_keys_result_t(const DNSName& domain)> get_domain_keys_call_t;

  typedef std::vector<std::pair<string, boost::variant<string, DNSName> > > before_and_after_names_result_t;
  typedef boost::variant<bool, before_and_after_names_result_t> get_before_and_after_names_absolute_result_t;
  typedef std::function<get_before_and_after_names_absolute_result_t(int id, const DNSName& qname)> get_before_and_after_names_absolute_call_t;

  typedef std::function<void(int, long)> set_notified_call_t;

  typedef std::function<string(const string& cmd)> direct_backend_cmd_call_t;
public:
  Lua2BackendAPIv2(const string& suffix) {
    setArgPrefix("lua2"+suffix);
    d_debug_log = mustDo("query-logging");
    prepareContext();
    loadFile(getArg("filename"));
  }

  ~Lua2BackendAPIv2();

  #define logCall(func, var) { if (d_debug_log) {  g_log<<Logger::Debug<<"["<<getPrefix()<<"] Calling "<<func<<"("<<var<<")"<< endl; } }
  #define logResult(var) { if (d_debug_log) { g_log<<Logger::Debug<<"["<<getPrefix()<<"] Got result " << "'" << var << "'" << endl; } }

  virtual void postPrepareContext() override {
    AuthLua4::postPrepareContext();
  }

  virtual void postLoad() override {
    f_lookup = d_lw->readVariable<boost::optional<lookup_call_t>>("dns_lookup").get_value_or(0);
    f_list = d_lw->readVariable<boost::optional<list_call_t>>("dns_list").get_value_or(0);
    f_get_all_domains = d_lw->readVariable<boost::optional<get_all_domains_call_t>>("dns_get_all_domains").get_value_or(0);
    f_get_domaininfo = d_lw->readVariable<boost::optional<get_domaininfo_call_t>>("dns_get_domaininfo").get_value_or(0);
    f_get_domain_metadata = d_lw->readVariable<boost::optional<get_domain_metadata_call_t>>("dns_get_domain_metadata").get_value_or(0);
    f_get_all_domain_metadata = d_lw->readVariable<boost::optional<get_all_domain_metadata_call_t>>("dns_get_all_domain_metadata").get_value_or(0);
    f_get_domain_keys = d_lw->readVariable<boost::optional<get_domain_keys_call_t>>("dns_get_domain_keys").get_value_or(0);
    f_get_before_and_after_names_absolute = d_lw->readVariable<boost::optional<get_before_and_after_names_absolute_call_t>>("dns_get_before_and_after_names_absolute").get_value_or(0);
    f_set_notified = d_lw->readVariable<boost::optional<set_notified_call_t>>("dns_set_notified").get_value_or(0);

    auto init = d_lw->readVariable<boost::optional<init_call_t>>("dns_init").get_value_or(0);
    if (init)
      init();

    f_deinit = d_lw->readVariable<boost::optional<deinit_call_t>>("dns_deinit").get_value_or(0);

    if (f_lookup == nullptr)
      throw PDNSException("dns_lookup missing");

    /* see if dnssec support is wanted */
    d_dnssec = d_lw->readVariable<boost::optional<bool>>("dns_dnssec").get_value_or(false);
    if (d_dnssec) {
      if (f_get_domain_metadata == nullptr)
        throw PDNSException("dns_dnssec is true but dns_get_domain_metadata is missing");
      if (f_get_before_and_after_names_absolute == nullptr)
        throw PDNSException("dns_dnssec is true but dns_get_before_and_after_names_absolute is missing");
      /* domain keys is not strictly speaking necessary for dnssec backend */
      if (f_get_domain_keys == nullptr)
        g_log<<Logger::Warning<<"dns_get_domain_keys missing - cannot do live signing"<<endl;
    }
  }

  bool doesDNSSEC() override {
    return d_dnssec;
  }

  void parseLookup(const lookup_result_t& result) {
    for(const auto& row: result) {
      DNSResourceRecord rec;
      for(const auto& item: row.second) {
         if (item.first == "type") {
           if (item.second.which() == 1)
             rec.qtype = QType(boost::get<int>(item.second));
           else if (item.second.which() == 3)
             rec.qtype = boost::get<string>(item.second);
           else if (item.second.which() == 4)
             rec.qtype = boost::get<QType>(item.second);
           else
             throw PDNSException("Unsupported value for type");
        } else if (item.first == "name") {
          if (item.second.which() == 3)
            rec.qname = DNSName(boost::get<string>(item.second));
          else if (item.second.which() == 2)
            rec.qname = boost::get<DNSName>(item.second);
          else
            throw PDNSException("Unsupported value for name");
        } else if (item.first == "domain_id")
          rec.domain_id = boost::get<int>(item.second);
        else if (item.first == "auth")
          rec.auth = boost::get<bool>(item.second);
        else if (item.first == "last_modified")
          rec.last_modified = static_cast<time_t>(boost::get<int>(item.second));
        else if (item.first == "ttl")
          rec.ttl = boost::get<int>(item.second);
        else if (item.first == "content")
          rec.setContent(boost::get<string>(item.second));
        else if (item.first == "scopeMask")
          rec.scopeMask = boost::get<int>(item.second);
        else
          g_log<<Logger::Warning<<"Unsupported key '"<<item.first<<"' in lookup or list result"<<endl;

      }
      logResult(rec.qname<<" IN "<<rec.qtype.getName()<<" "<<rec.ttl<<" "<<rec.getZoneRepresentation());
      d_result.push_back(rec);
    }
    if (d_result.empty() && d_debug_log)
      g_log<<Logger::Debug<<"["<<getPrefix()<<"] Got empty result"<<endl;
  }

  bool list(const DNSName &target, int domain_id, bool include_disabled=false) override {
    if (f_list == nullptr) {
      g_log<<Logger::Error<<"["<<getPrefix()<<"] dns_list missing - cannot do AXFR"<<endl;
      return false;
    }

    if (d_result.size() != 0)
      throw PDNSException("list attempted while another was running");

    logCall("list", "target="<<target<<",domain_id="<<domain_id);
    list_result_t result = f_list(target, domain_id);

    if (result.which() == 0)
      return false;

    parseLookup(boost::get<lookup_result_t>(result));

    return true;
  }

  void lookup(const QType &qtype, const DNSName &qname, int domain_id, DNSPacket *p=nullptr) override {
    if (d_result.size() != 0)
      throw PDNSException("lookup attempted while another was running");

    lookup_context_t ctx;
    if (p != NULL) {
      ctx.emplace_back(lookup_context_t::value_type{"source_address", p->getRemote().toString()});
      ctx.emplace_back(lookup_context_t::value_type{"real_source_address", p->getRealRemote().toString()});
    }

    logCall("lookup", "qtype="<<qtype.getName()<<",qname="<<qname<<",domain_id="<<domain_id);
    lookup_result_t result = f_lookup(qtype, qname, domain_id, ctx);
    parseLookup(result);
  }

  bool get(DNSResourceRecord &rr) override {
    if (d_result.size() == 0)
      return false;
    rr = std::move(d_result.front());
    d_result.pop_front();
    return true;
  }

  string directBackendCmd(const string& querystr) override {
    string::size_type pos = querystr.find_first_of(" \t");
    string cmd = querystr;
    string par = "";
    if (pos != string::npos) {
      cmd = querystr.substr(0, pos);
      par = querystr.substr(pos+1);
    }
    direct_backend_cmd_call_t f = d_lw->readVariable<boost::optional<direct_backend_cmd_call_t>>(cmd).get_value_or(0);
    if (f == nullptr) {
      return cmd + "not found";
    }
    logCall(cmd, "parameter="<<par);
    return f(par);
  }

  void setNotified(uint32_t id, uint32_t serial) override {
    if (f_set_notified == NULL)
      return;
    logCall("dns_set_notified", "id="<<static_cast<int>(id)<<",serial="<<serial);
    f_set_notified(static_cast<int>(id), serial);
  }

  void parseDomainInfo(const domaininfo_result_t& row, DomainInfo& di) {
     for(const auto& item: row) {
       if (item.first == "account")
         di.account = boost::get<string>(item.second);
       else if (item.first == "last_check")
         di.last_check = static_cast<time_t>(boost::get<long>(item.second));
       else if (item.first == "masters")
         for(const auto& master: boost::get<vector<string>>(item.second))
           di.masters.push_back(ComboAddress(master, 53));
       else if (item.first == "id")
         di.id = static_cast<int>(boost::get<long>(item.second));
       else if (item.first == "notified_serial")
         di.notified_serial = static_cast<unsigned int>(boost::get<long>(item.second));
       else if (item.first == "serial")
         di.serial = static_cast<unsigned int>(boost::get<long>(item.second));
       else if (item.first == "kind")
         di.kind = DomainInfo::stringToKind(boost::get<string>(item.second));
       else
         g_log<<Logger::Warning<<"Unsupported key '"<<item.first<<"' in domaininfo result"<<endl;
     }
     di.backend = this;
     logResult("zone="<<di.zone<<",serial="<<di.serial<<",kind="<<di.getKindString());
  }

  bool getDomainInfo(const DNSName& domain, DomainInfo& di, bool getSerial=true) override {
    if (f_get_domaininfo == nullptr) {
      // use getAuth instead
      SOAData sd;
      if (!getAuth(domain, &sd))
        return false;

      di.zone = domain;
      di.backend = this;
      di.serial = sd.serial;
      return true;
    }

    logCall("get_domaininfo","domain="<<domain);
    get_domaininfo_result_t result = f_get_domaininfo(domain);

    if (result.which() == 0)
      return false;

    di.zone = domain;
    parseDomainInfo(boost::get<domaininfo_result_t>(result), di);

    return true;
  }

  void getAllDomains(vector<DomainInfo> *domains, bool include_disabled=false) override {
     if (f_get_all_domains == nullptr)
       return;

     logCall("get_all_domains", "");
     for(const auto& row: f_get_all_domains()) {
       DomainInfo di;
       di.zone = row.first;
       logResult(di.zone);
       parseDomainInfo(row.second, di);
       domains->push_back(di);
     }
  }

  bool getAllDomainMetadata(const DNSName& name, std::map<std::string, std::vector<std::string> >& meta) override {
    if (f_get_all_domain_metadata == nullptr)
      return false;

    logCall("get_all_domain_metadata","name="<<name);
    get_all_domain_metadata_result_t result = f_get_all_domain_metadata(name);
    if (result.which() == 0)
      return false;

    for(const auto& row: boost::get< vector<pair<string, domain_metadata_result_t> > >(result)) {
       meta[row.first].clear();
       for(const auto& item: row.second)
          meta[row.first].push_back(item.second);
       logResult("kind="<<row.first<<",value="<<boost::algorithm::join(meta[row.first], ", "));
    }

    return true;
  }

  bool getDomainMetadata(const DNSName& name, const std::string& kind, std::vector<std::string>& meta) override {
    if (f_get_domain_metadata == nullptr)
      return false;

    logCall("get_domain_metadata","name="<<name<<",kind="<<kind);
    get_domain_metadata_result_t result = f_get_domain_metadata(name, kind);
    if (result.which() == 0)
      return false;

    meta.clear();
    for(const auto& item: boost::get<domain_metadata_result_t>(result))
      meta.push_back(item.second);

    logResult("value="<<boost::algorithm::join(meta, ", "));
    return true;
  }

  bool getDomainKeys(const DNSName& name, std::vector<DNSBackend::KeyData>& keys) override {
    if (f_get_domain_keys == nullptr)
      return false;

    logCall("get_domain_keys","name="<<name);
    get_domain_keys_result_t result = f_get_domain_keys(name);

    if (result.which() == 0)
      return false;

    for(const auto& row: boost::get<vector<pair<int, keydata_result_t> > >(result)) {
      DNSBackend::KeyData key;
      for(const auto& item: row.second) {
        if (item.first == "content")
          key.content = boost::get<string>(item.second);
        else if (item.first == "id")
          key.id = static_cast<unsigned int>(boost::get<int>(item.second));
        else if (item.first == "flags")
          key.flags = static_cast<unsigned int>(boost::get<int>(item.second));
        else if (item.first == "active")
          key.active = boost::get<bool>(item.second);
        else
          g_log<<Logger::Warning<<"["<<getPrefix()<<"] Unsupported key '"<<item.first<<"' in keydata result"<<endl;
      }
      logResult("id="<<key.id<<",flags="<<key.flags<<",active="<<(key.active ? "true" : "false"));
      keys.push_back(key);
    }

    return true;
  }

  bool getBeforeAndAfterNamesAbsolute(uint32_t id, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after) override {
    if (f_get_before_and_after_names_absolute == nullptr)
      return false;

    logCall("get_before_and_after_names_absolute", "id=<<"<<id<<",qname="<<qname);
    get_before_and_after_names_absolute_result_t result = f_get_before_and_after_names_absolute(id, qname);

    if (result.which() == 0)
      return false;

    before_and_after_names_result_t row = boost::get<before_and_after_names_result_t>(result);
    if (row.size() != 3) {
      g_log<<Logger::Error<<"Invalid result from dns_get_before_and_after_names_absolute, expected array with 3 items, got "<<row.size()<<"item(s)"<<endl;
      return false;
    }
    for(const auto& item: row) {
      DNSName value;
      if (item.second.which() == 0)
         value = DNSName(boost::get<string>(item.second));
      else
         value = DNSName(boost::get<DNSName>(item.second));
      if (item.first == "unhashed")
        unhashed = value;
      else if (item.first == "before")
        before = value;
      else if (item.first == "after")
        after = value;
      else {
        g_log<<Logger::Error<<"Invalid result from dns_get_before_and_after_names_absolute, unexpected key "<<item.first<<endl;
        return false;
      }
    }

    logResult("unhashed="<<unhashed<<",before="<<before<<",after="<<after);
    return true;
  }

private:
  std::list<DNSResourceRecord> d_result;
  bool d_debug_log;
  bool d_dnssec;

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
};

#endif
