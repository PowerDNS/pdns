#include <vector>
#include <map>
#include "pdnsexception.hh"
#include <boost/range/algorithm.hpp>
#include <boost/format.hpp>
#include <iostream>
#include <sstream>

class PdnsUtilNamespaceHandler;
class PdnsUtilNamespace;

class PdnsUtilNamespace {
private:
   PdnsUtilNamespace() {};

   std::map<std::string, PdnsUtilNamespaceHandler*> namespaces;
   static PdnsUtilNamespace *instance;

public:
  static PdnsUtilNamespace* getInstance() {
    if (instance == NULL)
      instance = new PdnsUtilNamespace();
    return instance;
  };

  void registerHandler(const std::string &prefix, PdnsUtilNamespaceHandler *handler) {
     if (namespaces.find(prefix) != namespaces.end())
        throw new PDNSException("Namespace '" + prefix + "' already registered");
     namespaces[prefix] = handler;
  };

  PdnsUtilNamespaceHandler * get(const std::string &prefix) {
     if (namespaces.find(prefix) != namespaces.end()) 
       return namespaces[prefix];
     return NULL;
  };

  void getNamespaces(std::vector<std::string>& keys) {
     for(std::map<std::string, PdnsUtilNamespaceHandler*>::iterator iter = namespaces.begin(); iter != namespaces.end(); iter++)
        keys.push_back(iter->first);
     boost::sort(keys);
  }

  int execute(const std::string &prefix, std::vector<std::string> args);
  int help(const std::string &prefix, std::vector<std::string> args);
};

class PdnsUtilNamespaceHandler {
protected:
     PdnsUtilNamespaceHandler(const std::string &prefix) {
          PdnsUtilNamespace::getInstance()->registerHandler(prefix, this);
     };

     std::string formatHelp(const std::string &prefix, const std::string &cmd, const std::string helpText) {
        std::stringstream iss;
        iss << boost::format("%s %-20s - %s") % prefix % cmd % helpText;
        return iss.str();
     };
public:
     virtual int help(const std::string &prefix, const std::vector<std::string> args) { return -1; };
     virtual int execute(const std::string &prefix, const std::vector<std::string> args) { return -1; };
};
