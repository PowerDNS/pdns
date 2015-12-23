#include "lua-recursor4.hh"
#include <fstream>
#include "logger.hh"
#include "dnsparser.hh"
#include "syncres.hh"
#include "namespaces.hh"

#if !defined(HAVE_LUA)

RecursorLua4::RecursorLua4(const std::string &fname)
{
  // empty
}

bool RecursorLua4::nxdomain(const ComboAddress& remote,const ComboAddress& local, const DNSName& query, const QType& qtype, vector<DNSRecord>& ret, int& res, bool* variable)
{
  return false;
}

bool RecursorLua4::nodata(const ComboAddress& remote,const ComboAddress& local, const DNSName& query, const QType& qtype, vector<DNSRecord>& ret, int& res, bool* variable)
{
  return false;
}

bool RecursorLua4::postresolve(const ComboAddress& remote,const ComboAddress& local, const DNSName& query, const QType& qtype, vector<DNSRecord>& ret, int& res, bool* variable)
{
  return false;
}


bool RecursorLua4::preresolve(const ComboAddress& remote, const ComboAddress& local, const DNSName& query, const QType& qtype, vector<DNSRecord>& ret, int& res, bool* variable)
{
  return false;
}

bool RecursorLua4::preoutquery(const ComboAddress& remote, const ComboAddress& local,const DNSName& query, const QType& qtype, vector<DNSRecord>& ret, int& res)
{
  return false;
}

bool RecursorLua4::ipfilter(const ComboAddress& remote, const ComboAddress& local, const struct dnsheader& dh)
{
  return false;
}


#else
#undef L
#include "ext/luawrapper/include/LuaContext.hpp"

static int followCNAMERecords(vector<DNSRecord>& ret, const QType& qtype)
{
  vector<DNSRecord> resolved;
  DNSName target;
  for(const DNSRecord& rr :  ret) {
    if(rr.d_type == QType::CNAME) {
      target=getRR<CNAMERecordContent>(rr)->getTarget();
      break;
    }
  }
  if(target.empty())
    return 0;
  
  int rcode=directResolve(target, qtype, 1, resolved); // 1 == class
  
  for(const DNSRecord& rr :  resolved) {
    ret.push_back(rr);
  }
  return rcode;
 
}

static int getFakeAAAARecords(const DNSName& qname, const std::string& prefix, vector<DNSRecord>& ret)
{
  int rcode=directResolve(qname, QType(QType::A), 1, ret);

  ComboAddress prefixAddress(prefix);

  for(DNSRecord& rr :  ret)
  {
    if(rr.d_type == QType::A && rr.d_place==DNSResourceRecord::ANSWER) {
      ComboAddress ipv4(getRR<ARecordContent>(rr)->getCA());
      uint32_t tmp;
      memcpy((void*)&tmp, &ipv4.sin4.sin_addr.s_addr, 4);
      // tmp=htonl(tmp);
      memcpy(((char*)&prefixAddress.sin6.sin6_addr.s6_addr)+12, &tmp, 4);
      rr.d_content = std::make_shared<AAAARecordContent>(prefixAddress);
      rr.d_type = QType::AAAA;
    }
  }
  return rcode;
}

static int getFakePTRRecords(const DNSName& qname, const std::string& prefix, vector<DNSRecord>& ret)
{
  /* qname has a reverse ordered IPv6 address, need to extract the underlying IPv4 address from it
     and turn it into an IPv4 in-addr.arpa query */
  ret.clear();
  vector<string> parts = qname.getRawLabels();

  if(parts.size() < 8)
    return -1;

  string newquery;
  for(int n = 0; n < 4; ++n) {
    newquery +=
      std::to_string(strtol(parts[n*2].c_str(), 0, 16) + 16*strtol(parts[n*2+1].c_str(), 0, 16));
    newquery.append(1,'.');
  }
  newquery += "in-addr.arpa.";


  int rcode = directResolve(DNSName(newquery), QType(QType::PTR), 1, ret);
  for(DNSRecord& rr :  ret)
  {
    if(rr.d_type == QType::PTR && rr.d_place==DNSResourceRecord::ANSWER) {
      rr.d_name = qname;
    }
  }
  return rcode;

}

vector<pair<int, DNSRecord> > RecursorLua4::DNSQuestion::getRecords()
{
  vector<pair<int, DNSRecord> > ret;
  int num=1;
  for(const auto& r : records) {
    ret.push_back({num++, r});
  }
  return ret;
}
void RecursorLua4::DNSQuestion::setRecords(const vector<pair<int, DNSRecord> >& recs)
{
  records.clear();
  for(const auto& p : recs) {
    records.push_back(p.second);
    cout<<"Setting: "<<p.second.d_content->getZoneRepresentation()<<endl;
  }
}

void RecursorLua4::DNSQuestion::addRecord(uint16_t type, const std::string& content, DNSResourceRecord::Place place, boost::optional<int> ttl, boost::optional<string> name)
{
  DNSRecord dr;
  dr.d_name=name ? DNSName(*name) : qname;
  dr.d_ttl=ttl.get_value_or(3600);
  dr.d_type = type;
  dr.d_place = place;
  dr.d_content = shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(type, 1, content));
  records.push_back(dr);
}

void RecursorLua4::DNSQuestion::addAnswer(uint16_t type, const std::string& content, boost::optional<int> ttl, boost::optional<string> name)
{
  addRecord(type, content, DNSResourceRecord::ANSWER, ttl, name);
}
  
RecursorLua4::RecursorLua4(const std::string& fname)
{
  d_lw = new LuaContext;
  d_lw->writeFunction("newDN", [](const std::string& dom){ return DNSName(dom); });  
  d_lw->registerFunction("isPartOf", &DNSName::isPartOf);
  d_lw->registerFunction<bool(DNSName::*)(const std::string&)>("equal",
							      [](const DNSName& lhs, const std::string& rhs) { return lhs==DNSName(rhs); });
  d_lw->registerFunction("__eq", &DNSName::operator==);

  d_lw->registerFunction<string(ComboAddress::*)()>("toString", [](const ComboAddress& ca) { return ca.toString(); });
  d_lw->writeFunction("newCA", [](const std::string& a) { return ComboAddress(a); });
  d_lw->writeFunction("newNMG", []() { return NetmaskGroup(); });
  d_lw->registerFunction<void(NetmaskGroup::*)(const std::string&mask)>("addMask", [](NetmaskGroup&nmg, const std::string& mask)
			 {
			   nmg.addMask(mask);
			 });

  d_lw->registerFunction("match", (bool (NetmaskGroup::*)(const ComboAddress&) const)&NetmaskGroup::match);
  d_lw->registerFunction<string(DNSName::*)()>("toString", [](const DNSName&dn ) { return dn.toString(); });
  d_lw->registerMember("qname", &DNSQuestion::qname);
  d_lw->registerMember("qtype", &DNSQuestion::qtype);
  d_lw->registerMember("localaddr", &DNSQuestion::local);
  d_lw->registerMember("remoteaddr", &DNSQuestion::remote);
  d_lw->registerMember("rcode", &DNSQuestion::rcode);
  d_lw->registerMember("variable", &DNSQuestion::variable);
  d_lw->registerMember("followupFunction", &DNSQuestion::followupFunction);
  d_lw->registerMember("followupPrefix", &DNSQuestion::followupPrefix);
  d_lw->registerMember("followupName", &DNSQuestion::followupName);
  d_lw->registerMember("name", &DNSRecord::d_name);
  d_lw->registerMember("type", &DNSRecord::d_type);
  d_lw->registerMember("ttl", &DNSRecord::d_ttl);
  
  d_lw->registerFunction<string(DNSRecord::*)()>("getContent", [](const DNSRecord& dr) { return dr.d_content->getZoneRepresentation(); });


  d_lw->registerFunction<void(DNSRecord::*)(const std::string&)>("changeContent", [](DNSRecord& dr, const std::string& newContent) { dr.d_content = shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(dr.d_type, 1, newContent)); });
  d_lw->registerFunction("addAnswer", &DNSQuestion::addAnswer);
  d_lw->registerFunction("getRecords", &DNSQuestion::getRecords);
  d_lw->registerFunction("setRecords", &DNSQuestion::setRecords);

  d_lw->writeFunction("newDS", []() { return SuffixMatchNode(); });
  d_lw->registerFunction<void(SuffixMatchNode::*)(boost::variant<string,DNSName, vector<pair<unsigned int,string> > >)>("add",
										   [](SuffixMatchNode&smn, const boost::variant<string,DNSName,vector<pair<unsigned int,string> > >& in)
										   {
										     try {
										     if(auto s = boost::get<string>(&in)) {
										       smn.add(DNSName(*s));
										     }
										     else if(auto v = boost::get<vector<pair<unsigned int, string> > >(&in)) {
										       for(const auto& s : *v)
											 smn.add(DNSName(s.second));
										     }
										     else
										       smn.add(boost::get<DNSName>(in));
										     }
										     catch(std::exception& e) { cerr<<e.what()<<endl; }
										   });
  d_lw->registerFunction("check",(bool (SuffixMatchNode::*)(const DNSName&) const) &SuffixMatchNode::check);


  d_lw->writeFunction("pdnslog", [](const std::string& msg, int loglevel) {
      theL() << (Logger::Urgency)loglevel << msg<<endl;
    });
  typedef vector<pair<string, int> > in_t;
  vector<pair<string, boost::variant<int, in_t > > >  pd{
    {"PASS", (int)PolicyDecision::PASS}, {"DROP",  (int)PolicyDecision::DROP},
    {"TRUNCATE", (int)PolicyDecision::TRUNCATE}
  };

  pd.push_back({"loglevels", in_t{
	{"Critical", LOG_CRIT},
	{"Debug", LOG_DEBUG},
	{"Info", LOG_INFO},
	{"Notice", LOG_NOTICE},
	{"Warning", LOG_WARNING},
	{"Error", LOG_ERR}
	  }});
  
  for(const auto& n : QType::names)
    pd.push_back({n.first, n.second});
  d_lw->writeVariable("pdns", pd);
  
  ifstream ifs(fname);
  if(!ifs) {
    theL()<<Logger::Error<<"Unable to read configuration file from '"<<fname<<"': "<<strerror(errno)<<endl;
    return;
  }  	
  d_lw->executeCode(ifs);

  d_preresolve = d_lw->readVariable<boost::optional<luacall_t>>("preresolve").get_value_or(0);
  d_nodata = d_lw->readVariable<boost::optional<luacall_t>>("nodata").get_value_or(0);
  d_nxdomain = d_lw->readVariable<boost::optional<luacall_t>>("nxdomain").get_value_or(0);
  d_postresolve = d_lw->readVariable<boost::optional<luacall_t>>("postresolve").get_value_or(0);
  d_preoutquery = d_lw->readVariable<boost::optional<luacall_t>>("preoutquery").get_value_or(0);

  d_ipfilter = d_lw->readVariable<boost::optional<ipfilter_t>>("ipfilter").get_value_or(0);

}

bool RecursorLua4::preresolve(const ComboAddress& remote,const ComboAddress& local, const DNSName& query, const QType& qtype, vector<DNSRecord>& res, int& ret, bool* variable)
{
  return genhook(d_preresolve, remote, local, query, qtype, res, ret, variable);
}

bool RecursorLua4::nxdomain(const ComboAddress& remote,const ComboAddress& local, const DNSName& query, const QType& qtype, vector<DNSRecord>& res, int& ret, bool* variable)
{
  return genhook(d_nxdomain, remote, local, query, qtype, res, ret, variable);
}

bool RecursorLua4::nodata(const ComboAddress& remote,const ComboAddress& local, const DNSName& query, const QType& qtype, vector<DNSRecord>& res, int& ret, bool* variable)
{
  return genhook(d_nodata, remote, local, query, qtype, res, ret, variable);
}

bool RecursorLua4::postresolve(const ComboAddress& remote,const ComboAddress& local, const DNSName& query, const QType& qtype, vector<DNSRecord>& res, int& ret, bool* variable)
{
  return genhook(d_postresolve, remote, local, query, qtype, res, ret, variable);
}

bool RecursorLua4::preoutquery(const ComboAddress& ns, const ComboAddress& requestor, const DNSName& query, const QType& qtype, vector<DNSRecord>& res, int& ret)
{
  return genhook(d_preoutquery, ns, requestor, query, qtype, res, ret, 0);
}

bool RecursorLua4::ipfilter(const ComboAddress& remote, const ComboAddress& local, const struct dnsheader& dh)
{
  if(d_ipfilter)
    return d_ipfilter({remote}, {local});
  return false; // don't block
}

bool RecursorLua4::genhook(luacall_t& func, const ComboAddress& remote,const ComboAddress& local, const DNSName& query, const QType& qtype, vector<DNSRecord>& res, int& ret, bool* variable)
{
  if(!func)
    return false;

  auto dq = std::make_shared<DNSQuestion>();
  dq->qname = query;
  dq->qtype = qtype.getCode();
  dq->local=local;
  dq->remote=remote;
  dq->records = res;

  bool handled=func(dq);
  if(variable) *variable |= dq->variable; // could still be set to indicate this *name* is variable

  if(handled) {
    ret=dq->rcode;
  loop:;
    if(!dq->followupFunction.empty()) {
      if(dq->followupFunction=="followCNAMERecords") {
	ret = followCNAMERecords(dq->records, qtype);
      }
      else if(dq->followupFunction=="getFakeAAAARecords") {
	ret=getFakeAAAARecords(dq->followupName, dq->followupPrefix, dq->records);
      }
      else if(dq->followupFunction=="getFakePTRRecords") {
	ret=getFakePTRRecords(dq->followupName, dq->followupPrefix, dq->records);
      }
      else if(dq->followupFunction=="udpQueryResponse") {
	dq->udpAnswer = GenUDPQueryResponse(dq->udpQueryDest, dq->udpQuery);
	auto func = d_lw->readVariable<boost::optional<luacall_t>>(dq->udpCallback).get_value_or(0);
	if(!func) {
	  theL()<<Logger::Error<<"Attempted callback for Lua UDP Query/Response which could not be found"<<endl;
	  return false;
	}
	goto loop;
      }
      
    }
    res=dq->records;
  }


  // see if they added followup work for us too
  return handled;
}
#endif
