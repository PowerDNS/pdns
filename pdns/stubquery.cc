#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "arguments.hh"
#include "dnsrecords.hh"
#include "dns_random.hh"
#include "stubresolver.hh"
#include "statbag.hh"

StatBag S;

ArgvMap &arg()
{
  static ArgvMap theArg;
  return theArg;
}

void usage() {
  cerr<<"stubquery"<<endl;
  cerr<<"Syntax: stubquery QUESTION [QUESTION-TYPE]"<<endl;
}

int main(int argc, char** argv)
try
{
  DNSName qname;
  QType qtype;

  for(int i=1; i<argc; i++) {
    if ((string) argv[i] == "--help") {
      usage();
      exit(EXIT_SUCCESS);
    }

    if ((string) argv[i] == "--version") {
      cerr<<"stubquery "<<VERSION<<endl;
      exit(EXIT_SUCCESS);
    }
  }

  if(argc <= 1) {
    usage();
    exit(EXIT_FAILURE);
  }

  string type(argc == 2 ? "A" : argv[2]);

  ::arg().set("resolver","Use this resolver for ALIAS and the internal stub resolver")="no"; 

  reportAllTypes();
  stubParseResolveConf();

  vector<DNSZoneRecord> ret;

  int res=stubDoResolve(DNSName(argv[1]), DNSRecordContent::TypeToNumber(type), ret);

  cout<<"res: "<<res<<endl;
  for(const auto& r : ret) {
    cout<<r.dr.d_content->getZoneRepresentation()<<endl;
  }
}
catch(std::exception &e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}
catch(PDNSException &e)
{
  cerr<<"Fatal: "<<e.reason<<endl;
}
