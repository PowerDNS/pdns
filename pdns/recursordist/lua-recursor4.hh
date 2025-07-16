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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "iputils.hh"
#include "dnsname.hh"
#include "namespaces.hh"
#include "dnsrecords.hh"
#include "filterpo.hh"
#include "ednsoptions.hh"
#include "validate.hh"
#include "lua-base4.hh"
#include "proxy-protocol.hh"
#include "noinitvector.hh"
#include "rec-eventtrace.hh"

#include <unordered_map>

#include "lua-recursor4-ffi.hh"

// pdns_ffi_param_t is a lightuserdata
template <>
struct LuaContext::Pusher<pdns_ffi_param*>
{
  static const int minSize = 1;
  static const int maxSize = 1;

  static PushedObject push(lua_State* state, pdns_ffi_param* ptr) noexcept
  {
    lua_pushlightuserdata(state, ptr);
    return PushedObject{state, 1};
  }
};

// pdns_postresolve_ffi_handle is a lightuserdata
template <>
struct LuaContext::Pusher<pdns_postresolve_ffi_handle*>
{
  static const int minSize = 1;
  static const int maxSize = 1;

  static PushedObject push(lua_State* state, pdns_postresolve_ffi_handle* ptr) noexcept
  {
    lua_pushlightuserdata(state, ptr);
    return PushedObject{state, 1};
  }
};

class RecursorLua4 : public BaseLua4
{
public:
  RecursorLua4(const std::string& includePath = "") :
    BaseLua4(includePath)
  {
    prepareContext();
  };
  RecursorLua4(const RecursorLua4&) = delete;
  RecursorLua4(RecursorLua4&&) = delete;
  RecursorLua4& operator=(const RecursorLua4&) = delete;
  RecursorLua4& operator=(RecursorLua4&&) = delete;
  ~RecursorLua4() override; // this is so unique_ptr works with an incomplete type

  struct MetaValue
  {
    std::unordered_set<std::string> stringVal;
    std::unordered_set<int64_t> intVal;
  };
  struct DNSQuestion
  {
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    DNSQuestion(const ComboAddress& prem, const ComboAddress& ploc, const ComboAddress& rem, const ComboAddress& loc, const DNSName& query, uint16_t type, bool tcp, bool& variable_, bool& wantsRPZ_, bool& logResponse_, bool& addPaddingToResponse_, const struct timeval& queryTime_) :
      qname(query), interface_local(ploc), interface_remote(prem), local(loc), remote(rem), variable(variable_), wantsRPZ(wantsRPZ_), logResponse(logResponse_), addPaddingToResponse(addPaddingToResponse_), queryTime(queryTime_), qtype(type), isTcp(tcp)
    {
    }
    const DNSName& qname;
    const ComboAddress& interface_local;
    const ComboAddress& interface_remote;
    const ComboAddress& local;
    const ComboAddress& remote;
    const ComboAddress* fromAuthIP{nullptr};
    const struct dnsheader* dh{nullptr};
    const std::vector<pair<uint16_t, string>>* ednsOptions{nullptr};
    const uint16_t* ednsFlags{nullptr};
    vector<DNSRecord>* currentRecords{nullptr};
    DNSFilterEngine::Policy* appliedPolicy{nullptr};
    std::unordered_set<std::string>* policyTags{nullptr};
    const std::vector<ProxyProtocolValue>* proxyProtocolValues{nullptr};
    std::unordered_map<std::string, bool>* discardedPolicies{nullptr};
    std::string* extendedErrorExtra{nullptr};
    boost::optional<uint16_t>* extendedErrorCode{nullptr};
    std::string requestorId;
    std::string deviceId;
    std::string deviceName;
    bool& variable;
    bool& wantsRPZ;
    bool& logResponse;
    bool& addPaddingToResponse;
    std::map<std::string, MetaValue> meta;
    struct timeval queryTime;

    vector<DNSRecord> records;

    string followupFunction;
    string followupPrefix;

    string udpQuery;
    string udpAnswer;
    string udpCallback;

    LuaContext::LuaObject data;
    DNSName followupName;
    ComboAddress udpQueryDest;

    unsigned int tag{0};
    int rcode{0};
    const uint16_t qtype;
    bool isTcp;
    vState validationState{vState::Indeterminate};

    void addAnswer(uint16_t type, const std::string& content, boost::optional<int> ttl, boost::optional<string> name);
    void addRecord(uint16_t type, const std::string& content, DNSResourceRecord::Place place, boost::optional<int> ttl, boost::optional<string> name);
    [[nodiscard]] vector<pair<int, DNSRecord>> getRecords() const;
    [[nodiscard]] boost::optional<dnsheader> getDH() const;
    [[nodiscard]] vector<pair<uint16_t, string>> getEDNSOptions() const;
    [[nodiscard]] boost::optional<string> getEDNSOption(uint16_t code) const;
    [[nodiscard]] boost::optional<Netmask> getEDNSSubnet() const;
    [[nodiscard]] std::vector<std::pair<int, ProxyProtocolValue>> getProxyProtocolValues() const;
    [[nodiscard]] vector<string> getEDNSFlags() const;
    [[nodiscard]] bool getEDNSFlag(const string& flag) const;
    void setRecords(const vector<pair<int, DNSRecord>>& arg);
  };

  struct PolicyEvent
  {
    PolicyEvent(const ComboAddress& rem, const DNSName& name, const QType& type, bool tcp) :
      qname(name), qtype(type), remote(rem), isTcp(tcp)
    {
    }
    const DNSName& qname;
    const QType qtype;
    const ComboAddress& remote;
    const bool isTcp;
    DNSFilterEngine::Policy* appliedPolicy{nullptr};
    std::unordered_set<std::string>* policyTags{nullptr};
    std::unordered_map<std::string, bool>* discardedPolicies{nullptr};
  };

  struct FFIParams
  {
  public:
    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    FFIParams(const DNSName& qname_, uint16_t qtype_, const ComboAddress& plocal_, const ComboAddress& premote_, const ComboAddress& local_, const ComboAddress& remote_, const Netmask& ednssubnet_, LuaContext::LuaObject& data_, std::unordered_set<std::string>& policyTags_, std::vector<DNSRecord>& records_, const EDNSOptionViewMap& ednsOptions_, const std::vector<ProxyProtocolValue>& proxyProtocolValues_, std::string& requestorId_, std::string& deviceId_, std::string& deviceName_, std::string& routingTag_, boost::optional<int>& rcode_, uint32_t& ttlCap_, bool& variable_, bool tcp_, bool& logQuery_, bool& logResponse_, bool& followCNAMERecords_, boost::optional<uint16_t>& extendedErrorCode_, std::string& extendedErrorExtra_, bool& disablePadding_, std::map<std::string, MetaValue>& meta_) :
      data(data_), qname(qname_), interface_local(plocal_), interface_remote(premote_), local(local_), remote(remote_), ednssubnet(ednssubnet_), policyTags(policyTags_), records(records_), ednsOptions(ednsOptions_), proxyProtocolValues(proxyProtocolValues_), requestorId(requestorId_), deviceId(deviceId_), deviceName(deviceName_), routingTag(routingTag_), extendedErrorExtra(extendedErrorExtra_), rcode(rcode_), extendedErrorCode(extendedErrorCode_), ttlCap(ttlCap_), variable(variable_), logQuery(logQuery_), logResponse(logResponse_), followCNAMERecords(followCNAMERecords_), disablePadding(disablePadding_), qtype(qtype_), tcp(tcp_), meta(meta_)
    {
    }

    LuaContext::LuaObject& data;
    const DNSName& qname;
    const ComboAddress& interface_local;
    const ComboAddress& interface_remote;
    const ComboAddress& local;
    const ComboAddress& remote;
    const Netmask& ednssubnet;
    std::unordered_set<std::string>& policyTags;
    std::vector<DNSRecord>& records;
    const EDNSOptionViewMap& ednsOptions;
    const std::vector<ProxyProtocolValue>& proxyProtocolValues;
    std::string& requestorId;
    std::string& deviceId;
    std::string& deviceName;
    std::string& routingTag;
    std::string& extendedErrorExtra;
    boost::optional<int>& rcode;
    boost::optional<uint16_t>& extendedErrorCode;
    uint32_t& ttlCap;
    bool& variable;
    bool& logQuery;
    bool& logResponse;
    bool& followCNAMERecords;
    bool& disablePadding;

    unsigned int tag{0};
    uint16_t qtype;
    bool tcp;

    std::map<std::string, MetaValue>& meta;
  };

  unsigned int gettag(const ComboAddress& remote, const Netmask& ednssubnet, const ComboAddress& local, const DNSName& qname, uint16_t qtype, std::unordered_set<std::string>* policyTags, LuaContext::LuaObject& data, const EDNSOptionViewMap&, bool tcp, std::string& requestorId, std::string& deviceId, std::string& deviceName, std::string& routingTag, const std::vector<ProxyProtocolValue>& proxyProtocolValues) const;
  unsigned int gettag_ffi(FFIParams&) const;

  void maintenance() const;
  bool prerpz(DNSQuestion& dnsQuestion, int& ret, RecEventTrace&) const;
  bool preresolve(DNSQuestion& dnsQuestion, int& ret, RecEventTrace&) const;
  bool nxdomain(DNSQuestion& dnsQuestion, int& ret, RecEventTrace&) const;
  bool nodata(DNSQuestion& dnsQuestion, int& ret, RecEventTrace&) const;
  bool postresolve(DNSQuestion& dnsQuestion, int& ret, RecEventTrace&) const;

  bool preoutquery(const ComboAddress& nameserver, const ComboAddress& requestor, const DNSName& query, const QType& qtype, bool& isTcp, vector<DNSRecord>& res, int& ret, RecEventTrace& eventTrace, const struct timeval& theTime) const;
  bool ipfilter(const ComboAddress& remote, const ComboAddress& local, const struct dnsheader&, RecEventTrace&) const;

  bool policyHitEventFilter(const ComboAddress& remote, const DNSName& qname, const QType& qtype, bool tcp, DNSFilterEngine::Policy& policy, std::unordered_set<std::string>& tags, std::unordered_map<std::string, bool>& discardedPolicies) const;

  void runStartStopFunction(const std::string& script, bool start, Logr::log_t log);

  [[nodiscard]] bool needDQ() const
  {
    return (d_prerpz || d_preresolve || d_nxdomain || d_nodata || d_postresolve);
  }

  struct PostResolveFFIHandle
  {
    PostResolveFFIHandle(DNSQuestion& dnsQuestion) :
      d_dq(dnsQuestion)
    {
    }
    DNSQuestion& d_dq;
    bool d_ret{false};
  };
  bool postresolve_ffi(PostResolveFFIHandle&) const;

  [[nodiscard]] bool hasGettagFunc() const
  {
    return static_cast<bool>(d_gettag);
  }
  [[nodiscard]] bool hasGettagFFIFunc() const
  {
    return static_cast<bool>(d_gettag_ffi);
  }
  [[nodiscard]] bool hasPostResolveFFIfunc() const
  {
    return static_cast<bool>(d_postresolve_ffi);
  }

protected:
  void postPrepareContext() override;
  void postLoad() override;
  void getFeatures(Features& features) override;

private:
  using gettag_t = std::function<std::tuple<unsigned int, boost::optional<std::unordered_map<int, string>>, boost::optional<LuaContext::LuaObject>, boost::optional<std::string>, boost::optional<std::string>, boost::optional<std::string>, boost::optional<string>>(ComboAddress, Netmask, ComboAddress, DNSName, uint16_t, const EDNSOptionViewMap&, bool, const std::vector<std::pair<int, const ProxyProtocolValue*>>&)>;
  gettag_t d_gettag; // public so you can query if we have this hooked

  using gettag_ffi_t = std::function<boost::optional<LuaContext::LuaObject>(pdns_ffi_param_t*)>;
  gettag_ffi_t d_gettag_ffi;

  using postresolve_ffi_t = std::function<bool(pdns_postresolve_ffi_handle_t*)>;
  postresolve_ffi_t d_postresolve_ffi;

  using luamaintenance_t = std::function<void()>;
  luamaintenance_t d_maintenance;

  using luacall_t = std::function<bool(DNSQuestion*)>;
  luacall_t d_prerpz, d_preresolve, d_nxdomain, d_nodata, d_postresolve, d_preoutquery, d_postoutquery;
  bool genhook(const luacall_t& func, DNSQuestion& dnsQuestion, int& ret) const;

  using ipfilter_t = std::function<bool(ComboAddress, ComboAddress, struct dnsheader)>;
  ipfilter_t d_ipfilter;

  using policyEventFilter_t = std::function<bool(PolicyEvent&)>;
  policyEventFilter_t d_policyHitEventFilter;
};
