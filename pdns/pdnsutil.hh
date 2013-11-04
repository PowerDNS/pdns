#ifndef _PDNS_PDNSUTIL_HH
#define _PDNS_PDNSUTIL_HH 1 
#include "dnsseckeeper.hh"
#include "dnssecinfra.hh"
#include "statbag.hh"
#include "base32.hh"
#include "base64.hh"
#include <boost/foreach.hpp>
#include <boost/program_options.hpp>
#include <boost/assign/list_of.hpp>
#include "dnsbackend.hh"
#include "ueberbackend.hh"
#include "arguments.hh"
#include "packetcache.hh"
#include "zoneparser-tng.hh"
#include "signingpipe.hh"
#include <boost/scoped_ptr.hpp>
#include "dns_random.hh"
#ifdef HAVE_SQLITE3
#include "ssqlite3.hh"
#include "bind-dnssec.schema.sqlite3.sql.h"
#endif
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

  UeberBackend *B;
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
     
     UeberBackend *B() {
         return PdnsUtilNamespace::getInstance()->B;
     }
public:
     virtual int help(const std::string &prefix, const std::vector<std::string>& args) = 0;
     virtual int execute(const std::string &prefix, const std::vector<std::string>& args) = 0;
};

#endif
