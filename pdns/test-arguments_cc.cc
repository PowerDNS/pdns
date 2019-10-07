#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdlib.h>
#include <unistd.h>
#include <boost/test/unit_test.hpp>
#include "arguments.hh"
#include "namespaces.hh" 

BOOST_AUTO_TEST_SUITE(test_arguments_cc)

BOOST_AUTO_TEST_CASE(test_file_parse) {
  char path[]="/tmp/pdns-test-conf.XXXXXX";
  int fd=mkstemp(path);
  if(fd < 0)
    BOOST_FAIL("Unable to generate a temporary file");

  string config=
R"(launch=launch=1234
test=123\
456
test2=here # and here it stops
fail=no
success=on
really=yes)";

  ssize_t len=write(fd, config.c_str(), config.size());

  BOOST_CHECK_EQUAL(len, static_cast<ssize_t>(config.size()));
  if(!len)
    return;
  close(fd);
  
  try {
    ArgvMap arg;
    for(auto& a : {"launch", "test", "test2", "fail", "success", "really"} )
      arg.set(a,a);
    arg.set("default", "default")="no";
    arg.file(path);
    unlink(path);

    BOOST_CHECK_EQUAL(arg["launch"], "launch=1234");
    BOOST_CHECK_EQUAL(arg["test"], "123456");
    BOOST_CHECK_EQUAL(arg.asNum("test"), 123456);
    BOOST_CHECK_EQUAL(arg["test2"], "here");
    BOOST_CHECK_EQUAL(arg.mustDo("fail"), false);
    BOOST_CHECK_EQUAL(arg.mustDo("success"), true);
    BOOST_CHECK_EQUAL(arg.mustDo("really"), true);
    BOOST_CHECK_EQUAL(arg["default"], "no");

  }
  catch(PDNSException& e) {
    unlink(path);
    cerr<<"Exception: "<<e.reason<<endl;
    BOOST_FAIL("Exception: "+e.reason);
  }
};

BOOST_AUTO_TEST_SUITE_END();
