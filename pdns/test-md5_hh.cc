#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#include <boost/test/unit_test.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/foreach.hpp>
#include "md5.hh"
#include "misc.hh"

using namespace boost;

BOOST_AUTO_TEST_SUITE(test_md5_hh)

BOOST_AUTO_TEST_CASE(test_md5summer) 
{
   std::string result = "a3 24 8c e3 1a 88 a6 40 e6 30 73 98 57 6d 06 9e ";
   std::vector<std::string> cases = boost::assign::list_of
     ("a ")
     ("quick ")
     ("brown ")
     ("fox ")
     ("jumped ")
     ("over ")
     ("the ")
     ("lazy ")
     ("dog");
 
     MD5Summer s;
     BOOST_FOREACH(std::string item, cases) {
       s.feed(item);
     }

     BOOST_CHECK_EQUAL(makeHexDump(s.get()), result);
}

BOOST_AUTO_TEST_CASE(test_pdns_md5sum)
{
   std::string result = "a3 24 8c e3 1a 88 a6 40 e6 30 73 98 57 6d 06 9e ";
   std::string sum = pdns_md5sum("a quick brown fox jumped over the lazy dog");
   
   BOOST_CHECK_EQUAL(makeHexDump(sum), result);
}

BOOST_AUTO_TEST_SUITE_END()
