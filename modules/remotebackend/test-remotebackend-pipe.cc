#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MAIN
#define BOOST_TEST_MODULE unit

#include <boost/test/unit_test.hpp>
#include <boost/assign/list_of.hpp>
#include <boost/foreach.hpp>
#include <boost/tuple/tuple.hpp>
#include "pdns/namespaces.hh"
#include <pdns/dns.hh>
#include <pdns/dnsbackend.hh>
#include <pdns/dnspacket.hh>
#include <pdns/ueberbackend.hh>
#include <pdns/ahuexception.hh>
#include <pdns/logger.hh>
#include <pdns/arguments.hh>
#include "pdns/dnsrecords.hh"
#include <boost/lexical_cast.hpp>
#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include "pdns/json.hh"
#include "pdns/statbag.hh"
#include "pdns/packetcache.hh"

StatBag S;
PacketCache PC;
ArgvMap &arg()
{
  static ArgvMap arg;
  return arg;
};

class RemoteLoader
{
   public:
      RemoteLoader();
};

DNSBackend *be;

struct RemotebackendSetup {
    RemotebackendSetup()  {
	be = 0; 
	try {
		// setup minimum arguments
		::arg().set("module-dir")="";
                new RemoteLoader();
		BackendMakers().launch("remote");
                // then get us a instance of it 
                ::arg().set("remote-connection-string")="pipe:command=unittest_pipe.rb";
                ::arg().set("remote-dnssec")="yes";
                be = BackendMakers().all()[0];
		// load few record types to help out
		SOARecordContent::report();
		NSRecordContent::report();
                ARecordContent::report();
	} catch (AhuException &ex) {
		BOOST_TEST_MESSAGE("Cannot start remotebackend: " << ex.reason );
	};
    }
    ~RemotebackendSetup()  {  }
};

BOOST_GLOBAL_FIXTURE( RemotebackendSetup );

