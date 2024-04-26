#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/test/unit_test.hpp>
#include "ext/luawrapper/include/LuaContext.hpp"

BOOST_AUTO_TEST_SUITE(test_lua_lightuserdata)

BOOST_AUTO_TEST_CASE(test_registerFunction)
{
  // This test comes from luawrapper/tests/custom_types.cc, TEST(CustomTypes, MemberFunctions).
  // In some versions of luajit, as shipped by Debian Buster and others, Lua lightuserdata
  // objects can only hold 47 bits of the address of a pointer. If the kernel puts our heap
  // above that 47 bit limit, this test crashes. Many arm64 Linux kernels are known to put
  // the heap in that problematic area.
  struct Object
  {
    void increment() { ++value; }
    int value;
  };

  LuaContext context;
  context.registerFunction("increment", &Object::increment);

  context.writeVariable("obj", Object{10});
  context.executeCode("obj:increment()");

  BOOST_CHECK_EQUAL(11, context.readVariable<Object>("obj").value);
}

BOOST_AUTO_TEST_SUITE_END()
