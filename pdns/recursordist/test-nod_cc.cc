#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN
#include <boost/test/unit_test.hpp>
#include "nod.hh"
#include "pdnsexception.hh"
using namespace boost;
using std::string;
using namespace nod;

BOOST_AUTO_TEST_SUITE(nod_cc)

bool pdns_exception( PDNSException const& ex ) { return true; }

BOOST_AUTO_TEST_CASE(test_basic) {
  DNSName new_domain1("abc.com."), new_domain2("xyz.com.");

  {
    NODDB noddb;

    BOOST_CHECK_EXCEPTION( noddb.setCacheDir("/xyz/abc"), PDNSException, pdns_exception);

    noddb.setCacheDir("/tmp");
  
    BOOST_CHECK_EQUAL(noddb.init(), true);

    BOOST_CHECK_EQUAL(noddb.isNewDomain(new_domain1), true);
    BOOST_CHECK_EQUAL(noddb.isNewDomain(new_domain1), false);
    BOOST_CHECK_EQUAL(noddb.isNewDomain(new_domain2), true);
    BOOST_CHECK_EQUAL(noddb.isNewDomain(new_domain1), false);

    for (int i=0; i<1000000; ++i) {
      noddb.isNewDomain("foo.com.");
      }

    noddb.addDomain("abc.com.");
    DNSName new_subdomain("foo.abc.com.");
    std::string parent;
    bool res = noddb.isNewDomainWithParent(new_subdomain, parent);

    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(parent, string("abc.com."));
  }
  {
    NODDB newnod;
    newnod.setCacheDir(".");
    BOOST_CHECK_EQUAL(newnod.init(), true);
    BOOST_CHECK_EQUAL(newnod.isNewDomain(new_domain1), true);
    BOOST_CHECK_EQUAL(newnod.isNewDomain(new_domain2), true);
    BOOST_CHECK_EQUAL(newnod.isNewDomain(new_domain1), false);
    BOOST_CHECK_EQUAL(newnod.isNewDomain(new_domain2), false);
    BOOST_CHECK_EQUAL(newnod.snapshotCurrent(), true);
  }
  {
    NODDB newnod;
    newnod.setCacheDir(".");
    BOOST_CHECK_EQUAL(newnod.init(true), true);
    BOOST_CHECK_EQUAL(newnod.isNewDomain(new_domain2), false);
    BOOST_CHECK_EQUAL(newnod.isNewDomain(new_domain1), false);
  }
}

BOOST_AUTO_TEST_SUITE_END()
