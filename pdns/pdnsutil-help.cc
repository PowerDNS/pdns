#include "pdnsutil.hh"
#include <boost/foreach.hpp>

class PdnsUtilHelpHandler: public PdnsUtilNamespaceHandler {
public:
   PdnsUtilHelpHandler(): PdnsUtilNamespaceHandler("help") {};

   virtual int help(const std::string &prefix, const std::vector<std::string> args) {
      std::cout << formatHelp(prefix, "command", "show help on particular command") << std::endl;
      return 0;
   }
   
   virtual int execute(const std::string &prefix, const std::vector<std::string> args) {
      int rv = 0;

	std::cerr << "Hippa" << std::endl;

      // prefix is assumably help, and we just re-call the namespace thingie with help + args-1 for each namespace
      if (args.size() == 0) {
          // call each namespace with empty args
          std::vector<std::string> keys;
          PdnsUtilNamespace::getInstance()->getNamespaces(keys);
          BOOST_FOREACH(std::string &prefix, keys) {
              rv += PdnsUtilNamespace::getInstance()->help(prefix, args);
          }
      }
   
      return rv;
   }
};

PdnsUtilHelpHandler util_help_handler;
