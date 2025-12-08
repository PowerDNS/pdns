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

BOOST_AUTO_TEST_SUITE(test_luawrapper)

BOOST_AUTO_TEST_CASE(test_boost_optional)
{
  LuaContext context;
  context.writeFunction("testOptional", [](boost::optional<int> incoming) -> boost::optional<int> {
    return incoming;
  });

  BOOST_REQUIRE(!context.executeCode<boost::optional<int>>("return testOptional(nil)"));

  {
    auto result = context.executeCode<boost::optional<int>>("return testOptional(1)");
    BOOST_REQUIRE(result);
    BOOST_CHECK_EQUAL(*result, 1);
  }
}

BOOST_AUTO_TEST_CASE(test_std_optional)
{
  LuaContext context;
  context.writeFunction("testOptional", [](std::optional<int> incoming) -> std::optional<int> {
    return incoming;
  });

  BOOST_REQUIRE(!context.executeCode<std::optional<int>>("return testOptional(nil)"));

  {
    auto result = context.executeCode<std::optional<int>>("return testOptional(1)");
    BOOST_REQUIRE(result);
    BOOST_CHECK_EQUAL(*result, 1);
  }
}

BOOST_AUTO_TEST_CASE(test_std_variant)
{
  LuaContext context;
  context.writeFunction("testVariant", [](std::variant<int, std::string> incoming) -> std::variant<int, std::string> {
    return incoming;
  });

  {
    auto result = context.executeCode<std::variant<int, std::string>>("return testVariant(1)");
    BOOST_REQUIRE(std::holds_alternative<int>(result));
    BOOST_CHECK_EQUAL(std::get<int>(result), 1);
  }

  {
    auto result = context.executeCode<std::variant<int, std::string>>("return testVariant('foo')");
    BOOST_REQUIRE(std::holds_alternative<std::string>(result));
    BOOST_CHECK_EQUAL(std::get<std::string>(result), "foo");
  }

  {
    auto func = [&]() {
      context.executeCode<std::variant<int, std::string>>("return testVariant(nil)");
    };
    BOOST_CHECK_THROW(func(), LuaContext::ExecutionErrorException);
  }
}

BOOST_AUTO_TEST_SUITE_END()
