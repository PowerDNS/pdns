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
#pragma once
#include "iputils.hh"
#include "dnsname.hh"
#include "namespaces.hh"
#include "dnsrecords.hh"
#include "filterpo.hh"
#include <unordered_map>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

string GenUDPQueryResponse(const ComboAddress& dest, const string& query);
unsigned int getRecursorThreadId();

class LuaContext;

class RecursorLua4 : public boost::noncopyable
{
private:
#ifdef HAVE_LUA
  std::unique_ptr<LuaContext> d_lw; // this is way on top because it must get destroyed _last_
#endif

public:
  explicit RecursorLua4(const std::string& fname);
  ~RecursorLua4(); // this is so unique_ptr works with an incomplete type
  bool prerpz(const ComboAddress& remote,const ComboAddress& local, const DNSName& query, const QType& qtype, bool isTcp, vector<DNSRecord>& res, const vector<pair<uint16_t,string> >* ednsOpts, unsigned int tag, int& ret, bool* wantsRPZ, std::unordered_map<std::string,bool>* discardedPolicies);
  bool preresolve(const ComboAddress& remote,const ComboAddress& local, const DNSName& query, const QType& qtype, bool isTcp, vector<DNSRecord>& res, const vector<pair<uint16_t,string> >* ednsOpts, unsigned int tag, DNSFilterEngine::Policy* appliedPolicy, std::vector<std::string>* policyTags, int& ret, bool* variable, bool* wantsRPZ);
  bool nxdomain(const ComboAddress& remote, const ComboAddress& local, const DNSName& query, const QType& qtype, bool isTcp, vector<DNSRecord>& res, int& ret, bool* variable);
  bool nodata(const ComboAddress& remote, const ComboAddress& local, const DNSName& query, const QType& qtype, bool isTcp, vector<DNSRecord>& res, int& ret, bool* variable);
  bool postresolve(const ComboAddress& remote, const ComboAddress& local, const DNSName& query, const QType& qtype, bool isTcp, vector<DNSRecord>& res, DNSFilterEngine::Policy* appliedPolicy, std::vector<std::string>* policyTags, int& ret, bool* variable);

  bool preoutquery(const ComboAddress& ns, const ComboAddress& requestor, const DNSName& query, const QType& qtype, bool isTcp, vector<DNSRecord>& res, int& ret);
  bool ipfilter(const ComboAddress& remote, const ComboAddress& local, const struct dnsheader&);

  int gettag(const ComboAddress& remote, const Netmask& ednssubnet, const ComboAddress& local, const DNSName& query, uint16_t qtype, std::vector<std::string>* policyTags);

  typedef std::function<std::tuple<int,boost::optional<std::unordered_map<int,string> > >(ComboAddress, Netmask, ComboAddress, DNSName, uint16_t)> gettag_t;
  gettag_t d_gettag; // public so you can query if we have this hooked

private:
  struct DNSQuestion
  {
    DNSName qname;
    uint16_t qtype;
    ComboAddress local, remote;
    int rcode{0};
    // struct dnsheader, packet length would be great
    int tag{0};
    vector<DNSRecord> records;
    void addAnswer(uint16_t type, const std::string& content, boost::optional<int> ttl, boost::optional<string> name);
    void addRecord(uint16_t type, const std::string& content, DNSResourceRecord::Place place, boost::optional<int> ttl, boost::optional<string> name);
    vector<pair<int,DNSRecord> > getRecords();
    vector<pair<uint16_t, string> > getEDNSOptions();
    boost::optional<string> getEDNSOption(uint16_t code);
    boost::optional<Netmask> getEDNSSubnet();
    void setRecords(const vector<pair<int,DNSRecord> >& records);
    bool variable{false};
    
    string followupFunction;
    string followupPrefix;

    string udpQuery;
    ComboAddress udpQueryDest;
    string udpAnswer;
    string udpCallback;
    
    std::unordered_map<string,string> data;
    const std::vector<pair<uint16_t, string>>* ednsOptions;
    DNSName followupName;

    DNSFilterEngine::Policy* appliedPolicy;
    std::vector<std::string>* policyTags;
    std::unordered_map<std::string,bool>* discardedPolicies;
    bool isTcp;
    bool wantsRPZ{true};
  };

  typedef std::function<bool(std::shared_ptr<DNSQuestion>)> luacall_t;
  luacall_t d_prerpz, d_preresolve, d_nxdomain, d_nodata, d_postresolve, d_preoutquery, d_postoutquery;
  bool genhook(luacall_t& func, const ComboAddress& remote,const ComboAddress& local, const DNSName& query, const QType& qtype, bool isTcp, vector<DNSRecord>& res,  const vector<pair<uint16_t,string> >* ednsOpts, unsigned int tag, DNSFilterEngine::Policy* appliedPolicy, std::vector<std::string>* policyTags, int& ret, bool* variable, bool* wantsRPZ, std::unordered_map<std::string,bool>* discardedPolicies);
  typedef std::function<bool(ComboAddress,ComboAddress, struct dnsheader)> ipfilter_t;
  ipfilter_t d_ipfilter;
};

