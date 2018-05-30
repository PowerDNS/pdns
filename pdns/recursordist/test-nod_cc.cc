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

    BOOST_CHECK_EXCEPTION( noddb.isNewDomain("foo.com."), PDNSException, pdns_exception);

    BOOST_CHECK_EXCEPTION( noddb.setCacheDir("/xyz/abc"), PDNSException, pdns_exception);

    noddb.setCacheDir("/tmp");
  
    noddb.init();

    BOOST_CHECK_EQUAL(noddb.isNewDomain(new_domain1), true);
    BOOST_CHECK_EQUAL(noddb.isNewDomain(new_domain1), false);
    BOOST_CHECK_EQUAL(noddb.isNewDomain(new_domain2), true);
    BOOST_CHECK_EQUAL(noddb.isNewDomain(new_domain1), false);

    for (int i=0; i<100000; ++i) {
      noddb.isNewDomain("foo.com.");
    }
  
    DNSName new_subdomain("foo.abc.com.");
    std::string parent;
    bool res = noddb.isNewDomainWithParent(new_subdomain, parent);

    BOOST_CHECK_EQUAL(res, true);
    BOOST_CHECK_EQUAL(parent, string("abc.com."));
  }
  {
    NODDB newnod;
    newnod.setCacheDir(".");
    newnod.init();
    BOOST_CHECK_EQUAL(newnod.isNewDomain(new_domain1), true);
    BOOST_CHECK_EQUAL(newnod.isNewDomain(new_domain2), true);
    BOOST_CHECK_EQUAL(newnod.isNewDomain(new_domain1), false);
    BOOST_CHECK_EQUAL(newnod.isNewDomain(new_domain2), false);
    BOOST_CHECK_EQUAL(newnod.snapshotCurrent(), true);
    BOOST_CHECK_EQUAL(newnod.rotateCurrent(), true);
  }
  {
    NODDB newnod;
    newnod.setCacheDir(".");
    newnod.init();
    BOOST_CHECK_EQUAL(newnod.isNewDomain(new_domain2), false);
    BOOST_CHECK_EQUAL(newnod.isNewDomain(new_domain1), false);
    BOOST_CHECK_EQUAL(newnod.removeCacheFiles(), true);
  }
  {
    NODDB newnod;
    newnod.setCacheDir(".");
    newnod.init();
    newnod.setMaxFiles(1);
    BOOST_CHECK_EQUAL(newnod.rotateCurrent(), true);
    sleep(1);
    BOOST_CHECK_EQUAL(newnod.rotateCurrent(), true);
    sleep(1);
    BOOST_CHECK_EQUAL(newnod.rotateCurrent(), true);
    BOOST_CHECK_EQUAL(newnod.pruneCacheFiles(), true);
    BOOST_CHECK_EQUAL(newnod.removeCacheFiles(), true);
  }
}

BOOST_AUTO_TEST_SUITE_END()
