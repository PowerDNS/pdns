#pragma once
#include "iputils.hh"
#include "dnsname.hh"
#include "namespaces.hh"
#include "dnsrecords.hh"
string GenUDPQueryResponse(const ComboAddress& dest, const string& query);

class LuaContext;
class RecursorLua4 : public boost::noncopyable
{
public:
  explicit RecursorLua4(const std::string& fname);

  bool preresolve(const ComboAddress& remote,const ComboAddress& local, const DNSName& query, const QType& qtype, vector<DNSRecord>& res, int& ret, bool* variable);
  bool nxdomain(const ComboAddress& remote, const ComboAddress& local, const DNSName& query, const QType& qtype, vector<DNSRecord>& res, int& ret, bool* variable);
  bool nodata(const ComboAddress& remote, const ComboAddress& local, const DNSName& query, const QType& qtype, vector<DNSRecord>& res, int& ret, bool* variable);
  bool postresolve(const ComboAddress& remote, const ComboAddress& local, const DNSName& query, const QType& qtype, vector<DNSRecord>& res, int& ret, bool* variable);

  bool preoutquery(const ComboAddress& ns, const ComboAddress& requestor, const DNSName& query, const QType& qtype, vector<DNSRecord>& res, int& ret);
  bool ipfilter(const ComboAddress& remote, const ComboAddress& local, const struct dnsheader&);

private:
  struct DNSQuestion
  {
    DNSName qname;
    uint16_t qtype;
    ComboAddress local, remote;
    int rcode{0};
    // struct dnsheader, packet length would be great
    vector<DNSRecord> records;
    void addAnswer(uint16_t type, const std::string& content, boost::optional<int> ttl, boost::optional<string> name);
    void addRecord(uint16_t type, const std::string& content, DNSResourceRecord::Place place, boost::optional<int> ttl, boost::optional<string> name);
    vector<pair<int,DNSRecord> > getRecords();
    void setRecords(const vector<pair<int,DNSRecord> >& records);
    bool variable{false};
    
    string followupFunction;
    string followupPrefix;

    string udpQuery;
    ComboAddress udpQueryDest;
    string udpAnswer;
    string udpCallback;
    
    DNSName followupName;
  };

  LuaContext* d_lw;
  typedef std::function<bool(std::shared_ptr<DNSQuestion>)> luacall_t;
  luacall_t d_preresolve, d_nxdomain, d_nodata, d_postresolve, d_preoutquery, d_postoutquery;
  bool genhook(luacall_t& func, const ComboAddress& remote,const ComboAddress& local, const DNSName& query, const QType& qtype, vector<DNSRecord>& res, int& ret, bool* variable);
  typedef std::function<bool(ComboAddress,ComboAddress)> ipfilter_t;
  ipfilter_t d_ipfilter;
};

