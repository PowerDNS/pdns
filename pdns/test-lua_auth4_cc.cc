#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include "arguments.hh"
#include <utility>
#include "lua-auth4.hh"

struct SetupArgFixture {
  SetupArgFixture() {
    ::arg().set("resolver") = "127.0.0.1";
  };
};

BOOST_FIXTURE_TEST_SUITE(lua_auth4_cc, SetupArgFixture)

BOOST_AUTO_TEST_CASE(test_prequery) {
  const std::string script =
"function prequery(q)\n"
"  if q.qdomain == newDN(\"mod.unit.test.\")\n"
"  then\n"
"    return true\n"
"  end\n"
"  return false\n"
"end";
  AuthLua4 lua;
  DNSPacket p(true);
  p.qdomain = DNSName("mod.unit.test.");
  lua.loadString(script);
  std::unique_ptr<DNSPacket> r{nullptr};
  try {
    r = lua.prequery(p);
    BOOST_REQUIRE(r != nullptr);
    BOOST_CHECK_EQUAL(r->qdomain.toString(), "mod.unit.test.");
  } catch (const LuaContext::ExecutionErrorException& e) {
    try {
     std::rethrow_if_nested(e);
    } catch(const std::exception& exp) {
     g_log<<"Extra info: "<<exp.what();
    }
  }
}

BOOST_AUTO_TEST_CASE(test_updatePolicy) {
  const std::string script =
"function updatepolicy(query)\n"
"  princ = query:getPeerPrincipal()\n"
"  if princ == \"admin@DOMAIN\" or tostring(query:getRemote()) == \"192.168.1.1\"\n"
"  then\n"
"    return true\n"
"  end\n"
"  return false\n"
"end";
  AuthLua4 lua;
  DNSPacket p(true);
  ComboAddress ca(std::string("192.168.1.1"));
  lua.loadString(script);
  p.setRemote(&ca);
  p.d_peer_principal = "admin@DOMAIN";
  BOOST_CHECK_EQUAL(lua.updatePolicy(DNSName("mod.example.com."), QType(QType::A), DNSName("example.com."), p), true);
  p.d_peer_principal = "";
  BOOST_CHECK_EQUAL(lua.updatePolicy(DNSName("mod.example.com."), QType(QType::A), DNSName("example.com."), p), true);
  ca = ComboAddress(std::string("192.168.1.2"));
  p.setRemote(&ca);
  BOOST_CHECK_EQUAL(lua.updatePolicy(DNSName("mod.example.com."), QType(QType::A), DNSName("example.com."), p), false);
}

BOOST_AUTO_TEST_SUITE_END()
