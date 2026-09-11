#pragma once
#include "iputils.hh"
#include "dnsname.hh"
#include "dnspacket.hh"
#include "dnsparser.hh"
#include "logging.hh"
#include <unordered_map>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "lua-base4.hh"

class AuthLua4 : public BaseLua4
{
public:
  AuthLua4(const std::string& includePath="");
  ~AuthLua4() override = default; // this is so unique_ptr works with an incomplete type

  LuaContext* getLua();

  bool axfrfilter(const ComboAddress&, const DNSName&, const DNSResourceRecord&, std::vector<DNSResourceRecord>&);
  std::unique_ptr<DNSPacket> prequery(const DNSPacket& p);
  bool updatePolicy(const DNSName &qname, const QType& qtype, const DNSName &zonename, const DNSPacket& packet);

  void setExecLimit();

  static int s_luaRecordExecLimit;

protected:
  void postPrepareContext() override;
  void postLoad() override;

private:
  struct UpdatePolicyQuery {
    DNSName qname;
    DNSName zonename;
    uint16_t qtype;
    ComboAddress local, remote;
    Netmask realRemote;
    DNSName tsigName;
    std::string peerPrincipal;
  };

  typedef std::function<bool(const UpdatePolicyQuery&)> luacall_update_policy_t;
  typedef std::function<std::tuple<int, std::unordered_map<int, std::unordered_map<std::string,boost::variant<unsigned int,std::string> > > >(const ComboAddress&, const DNSName&, const DNSResourceRecord&)> luacall_axfr_filter_t;
  typedef std::function<bool(DNSPacket*)> luacall_prequery_t;

  luacall_update_policy_t d_update_policy;
  luacall_axfr_filter_t d_axfr_filter;
  luacall_prequery_t d_prequery;
};
std::vector<shared_ptr<DNSRecordContent>> luaSynth(Logr::log_t slog, const std::string& code, const DNSName& query, const DNSZoneRecord& zone_record,
                                                   const DNSName& zone, const DNSPacket& dnsp, uint16_t qtype, unique_ptr<AuthLua4>& LUA);
