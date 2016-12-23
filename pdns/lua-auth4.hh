#pragma once
#include "iputils.hh"
#include "dnsname.hh"
#include "namespaces.hh"
#include "dnsrecords.hh"
#include "dnspacket.hh"
#include <unordered_map>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

class LuaContext;

class AuthLua4 : public boost::noncopyable
{
private:
#ifdef HAVE_LUA
  std::unique_ptr<LuaContext> d_lw; // this is way on top because it must get destroyed _last_
#endif

public:
  explicit AuthLua4(const std::string& fname);
  bool updatePolicy(const DNSName &qname, QType qtype, const DNSName &zonename, DNSPacket *packet);

  ~AuthLua4(); // this is so unique_ptr works with an incomplete type
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

  luacall_update_policy_t d_update_policy;
};
