#pragma once
#include "iputils.hh"
#include "dnsname.hh"
#include "dnspacket.hh"
#include "dnsparser.hh"
#include <unordered_map>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "lua-base4.hh"

class AuthLua4 : public BaseLua4
{
public:
  AuthLua4();
  bool updatePolicy(const DNSName &qname, QType qtype, const DNSName &zonename, const DNSPacket& packet);
  bool axfrfilter(const ComboAddress&, const DNSName&, const DNSResourceRecord&, std::vector<DNSResourceRecord>&);
  LuaContext* getLua();

  std::unique_ptr<DNSPacket> prequery(const DNSPacket& p);

  ~AuthLua4(); // this is so unique_ptr works with an incomplete type
protected:
  virtual void postPrepareContext() override;
  virtual void postLoad() override;
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
std::vector<shared_ptr<DNSRecordContent>> luaSynth(const std::string& code, const DNSName& qname,
                                                   const DNSName& zone, int zoneid, const DNSPacket& dnsp, uint16_t qtype);
