#include "pdns/utility.hh"
#include "xtdb.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/dnspacket.hh"
#include "pdns/ahuexception.hh"
#include "pdns/logger.hh"
#include "pdns/arguments.hh"

/* FIRST PART */
class XDBBackend : public DNSBackend
{
public:
  XDBBackend(const string &suffix="") 
  {
    setArgPrefix("xdb"+suffix);
    try {
      d_db=new XTDBWrapper(getArg("filename"));
    }
    catch(XDBException &e) {
      L<<Logger::Error<<"[XDBBackend] Error: "<<e.what<<endl;
      throw AhuException(e.what);
    }
    L<<Logger::Error<<"[XDBBackend] Open"<<endl;
  }

  ~XDBBackend()
  {
    delete d_db;
  }

  bool list(int id) {
    return false; // we don't support AXFR (go away)
  }
    
  void lookup(const QType &type, const string &qdomain, DNSPacket *p, int zoneId)
  {
    d_answer="";
    /*
    if(arg().mustDo("query-logging"))
      L<<Logger::Error<<"Query: '"<<qdomain+"|"+type.getName()<<"'"<<endl;
    */

    bool ret=d_db->get(qdomain, d_answer);   // think about lowercasing here

    /*
    if(arg().mustDo("query-logging")) {
      if(ret)
	L<<Logger::Error<<"Raw Answer: '"<<d_answer<<"'"<<endl;
      else
	L<<Logger::Error<<"No answer"<<endl;
    }
    */

    d_qtype=type;
  }

  bool get(DNSResourceRecord &rr)
  {
    while(!d_answer.empty()) {
      int len=rr.unSerialize(d_answer);
      d_answer=d_answer.substr(len);
      if(d_qtype.getCode()==QType::ANY || rr.qtype==d_qtype) {
	/*
	if(arg().mustDo("query-logging")) {
	  L<<Logger::Error<<"Real answer: "<<rr.qtype.getName()<<"/"<<rr.content<<endl;
	*/
	return true;
      }
    }
    return false;                                                   // no more data
  }
  
private:
  string d_answer;
  QType d_qtype;
  XDBWrapper *d_db;
};

/* SECOND PART */

class XDBFactory : public BackendFactory
{
public:
  XDBFactory() : BackendFactory("xdb") {}
  void declareArguments(const string &suffix="")
  {
    declare(suffix,"filename","filename which is to be xdb","/tmp/powerdns.xdb");
  }
  DNSBackend *make(const string &suffix="")
  {
    return new XDBBackend(suffix);
  }
};

/* THIRD PART */

class XDBLoader
{
public:
  XDBLoader()
  {
    BackendMakers().report(new XDBFactory);
    
    L<<Logger::Info<<" [XDBBackend] This is the xdbbackend ("__DATE__", "__TIME__") reporting"<<endl;
  }  
};

static XDBLoader xdbLoader;

