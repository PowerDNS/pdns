#include "pdnsutil.hh"
#include <boost/foreach.hpp>
#include <boost/assign/list_of.hpp>

using namespace std;

class PdnsUtilMetaHandler: public PdnsUtilNamespaceHandler {
public:
   PdnsUtilMetaHandler(): PdnsUtilNamespaceHandler("meta") {};

   virtual int help(const string &prefix, const vector<string>& args) {
      cout << formatHelp(prefix, "get zone [kind kind ..]", "Get domain meta for zone (if no kinds given, well known metas are queried)") << endl;
      cout << formatHelp(prefix, "set zone kind [value value..]", "Set/clear domain meta for zone") << endl;
      return 0;
   }
   
   virtual int execute(const string &prefix, const vector<string>& args) {
       if (args.size() < 2) return help(prefix, args);
       if (args[0] == "get") {
          string zone = args[1];
          vector<string> keys;
          DomainInfo di;

          if (!B()->getDomainInfo(zone, di)) {
             cerr << "Invalid zone '" << zone << "'" << endl;
             return 1;
          }

          if (args.size() > 2) {
             keys.assign(args.begin() + 2, args.end());
          } else {
             keys = boost::assign::list_of("ALLOW-2136-FROM")
                              ("ALLOW-AXFR-FROM")("ALSO-NOTIFY")("AXFR-MASTER-TSIG")
                              ("AXFR-SOURCE")("LUA-AXFR-SCRIPT")("NSEC3NARROW")
                              ("NSEC3PARAM")("PRESIGNED")("SOA-EDIT")
                              ("TSIG-ALLOW-2136")("TSIG-ALLOW-AXFR"); // NOTE: Add new metas here
          }
          cout << "Metadata for '" << zone << "'" << endl;
          BOOST_FOREACH(const string kind, keys) {
            vector<string> meta;
            meta.clear();
            if (B()->getDomainMetadata(zone, kind, meta)) {
               cout << kind << " = " << boost::join(meta, ", ") << endl;
            }
          }
           
       }
   }

};

PdnsUtilMetaHandler util_meta_handler;
