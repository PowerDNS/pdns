#include "pdnsutil.hh"

PdnsUtilNamespace *PdnsUtilNamespace::instance = NULL;

StatBag S;
PacketCache PC;

using boost::scoped_ptr;
namespace po = boost::program_options;
po::variables_map g_vm;

string s_programname="pdns";

namespace {
  bool g_verbose; // doesn't yet do anything though
}

ArgvMap &arg()
{
  static ArgvMap arg;
  return arg;
}

int PdnsUtilNamespace::execute(const std::string &prefix, std::vector<std::string> args) {
     PdnsUtilNamespaceHandler *handler = get(prefix);
     if (handler == NULL) {
        std::cerr << "Invalid namespace '" << prefix << "' given. Try help. " << std::endl;
        return -1;
     }
     return handler->execute(prefix, args);
  }

int PdnsUtilNamespace::help(const std::string &prefix, std::vector<std::string> args) {
     PdnsUtilNamespaceHandler *handler = get(prefix);
     if (handler == NULL) {
	std::cerr << "Invalid namespace '" << prefix << "' given. Try help. " << std::endl;
        return -1;
     }
     return handler->help(prefix, args);
}


void loadMainConfig(const std::string& configdir)
{
  ::arg().set("config-dir","Location of configuration directory (pdns.conf)")=configdir;
  ::arg().set("pipebackend-abi-version","Version of the pipe backend ABI")="1";
  ::arg().set("default-ttl","Seconds a result is valid if not set otherwise")="3600";
  ::arg().set("launch","Which backends to launch");
  ::arg().set("dnssec","if we should do dnssec")="true";
  ::arg().set("config-name","Name of this virtual configuration - will rename the binary image")=g_vm["config-name"].as<string>();
  ::arg().setCmd("help","Provide a helpful message");
  //::arg().laxParse(argc,argv);

  if(::arg().mustDo("help")) {
    cerr<<"syntax:"<<endl<<endl;
    cerr<<::arg().helpstring(::arg()["help"])<<endl;
    exit(99);
  }

  if(::arg()["config-name"]!="")
    s_programname+="-"+::arg()["config-name"];

  string configname=::arg()["config-dir"]+"/"+s_programname+".conf";
  cleanSlashes(configname);

  ::arg().set("default-ksk-algorithms","Default KSK algorithms")="rsasha256";
  ::arg().set("default-ksk-size","Default KSK size (0 means default)")="0";
  ::arg().set("default-zsk-algorithms","Default ZSK algorithms")="rsasha256";
  ::arg().set("default-zsk-size","Default KSK size (0 means default)")="0";
  ::arg().set("max-ent-entries", "Maximum number of empty non-terminals in a zone")="100000";
  ::arg().set("module-dir","Default directory for modules")=LIBDIR;
  ::arg().set("entropy-source", "If set, read entropy from this file")="/dev/urandom";

  ::arg().setSwitch("experimental-direct-dnskey","EXPERIMENTAL: fetch DNSKEY RRs from backend during DNSKEY synthesis")="no";
  ::arg().laxFile(configname.c_str());

  BackendMakers().launch(::arg()["launch"]); // vrooooom!
  ::arg().laxFile(configname.c_str());
  //cerr<<"Backend: "<<::arg()["launch"]<<", '" << ::arg()["gmysql-dbname"] <<"'" <<endl;

  S.declare("qsize-q","Number of questions waiting for database attention");

  S.declare("deferred-cache-inserts","Amount of cache inserts that were deferred because of maintenance");
  S.declare("deferred-cache-lookup","Amount of cache lookups that were deferred because of maintenance");

  S.declare("query-cache-hit","Number of hits on the query cache");
  S.declare("query-cache-miss","Number of misses on the query cache");
  ::arg().set("max-cache-entries", "Maximum number of cache entries")="1000000";
  ::arg().set("recursor","If recursion is desired, IP address of a recursing nameserver")="no";
  ::arg().set("recursive-cache-ttl","Seconds to store packets for recursive queries in the PacketCache")="10";
  ::arg().set("cache-ttl","Seconds to store packets in the PacketCache")="20";
  ::arg().set("negquery-cache-ttl","Seconds to store negative query results in the QueryCache")="60";
  ::arg().set("query-cache-ttl","Seconds to store query results in the QueryCache")="20";
  ::arg().set("default-soa-name","name to insert in the SOA record if none set in the backend")="a.misconfigured.powerdns.server";
  ::arg().set("default-soa-mail","mail address to insert in the SOA record if none set in the backend")="";
  ::arg().set("soa-refresh-default","Default SOA refresh")="10800";
  ::arg().set("soa-retry-default","Default SOA retry")="3600";
  ::arg().set("soa-expire-default","Default SOA expire")="604800";
  ::arg().setSwitch("query-logging","Hint backends that queries should be logged")="no";
  ::arg().set("soa-minimum-ttl","Default SOA minimum ttl")="3600";

  UeberBackend::go();
}

int main(int argc, const char *argv[]) {
  po::options_description desc("Allowed options");
  desc.add_options()
    ("help,h", "produce help message")
    ("verbose,v", "be verbose")
    ("force", "force an action")
    ("config-name", po::value<string>()->default_value(""), "virtual configuration name")
    ("config-dir", po::value<string>()->default_value(SYSCONFDIR), "location of pdns.conf")
    ("commands", po::value<vector<string> >());

  po::positional_options_description p;
  p.add("commands", -1);
  po::store(po::command_line_parser(argc, argv).options(desc).positional(p).run(), g_vm);
  po::notify(g_vm);

  vector<string> cmds;

  if(g_vm.count("commands"))
    cmds = g_vm["commands"].as<vector<string> >();

  if (cmds.size() == 0) {
     cerr << "Usage: " << argv[0] << " command ..." << endl;
     return 1;
  }

  g_verbose = g_vm.count("verbose");

  loadMainConfig(g_vm["config-dir"].as<string>());
  reportAllTypes();

  std::string prefix = cmds[0];  
  std::vector<std::string> args(cmds.begin()+1, cmds.end()); // it should be reduced by one

  try {
    PdnsUtilNamespace::getInstance()->B = new UeberBackend("default");
  } catch (PDNSException ex) {
    std::cerr << "Unable to initialize backends: " << ex.reason << std::endl;
    return 1;
  }

  return PdnsUtilNamespace::getInstance()->execute(prefix, args);
}
