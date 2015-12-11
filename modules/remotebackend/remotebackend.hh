#ifndef REMOTEBACKEND_REMOTEBACKEND_HH

#include <string>
#include <sstream>
#include "pdns/arguments.hh"
#include "pdns/dns.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/dnspacket.hh"
#include "pdns/json.hh"
#include "pdns/logger.hh"
#include "pdns/namespaces.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/sstuff.hh"
#include "pdns/ueberbackend.hh"
#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include "yahttp/yahttp.hpp"
#include <sstream>

#ifdef REMOTEBACKEND_ZEROMQ
#include <zmq.h>

// If the available ZeroMQ library version is < 2.x, create macros for the zmq_msg_send/recv functions
#ifndef HAVE_ZMQ_MSG_SEND
#define zmq_msg_send(msg, socket, flags) zmq_send(socket, msg, flags)
#define zmq_msg_recv(msg, socket, flags) zmq_recv(socket, msg, flags)
#endif
#endif
#define JSON_GET(obj,val,def) (obj.HasMember(val)?obj["" val ""]:def)
#define JSON_ADD_MEMBER(obj, name, val, alloc) { rapidjson::Value __xval; __xval = val; obj.AddMember(name, __xval, alloc); }
#define JSON_ADD_MEMBER_DNSNAME(obj, name, val, alloc) { rapidjson::Value __xval(val.toString().c_str(), alloc); obj.AddMember(name, __xval, alloc); }

class Connector {
   public:
    virtual ~Connector() {};
    bool send(rapidjson::Document &value);
    bool recv(rapidjson::Document &value);
    virtual int send_message(const rapidjson::Document &input) = 0;
    virtual int recv_message(rapidjson::Document &output) = 0;
   protected:
    bool getBool(rapidjson::Value &value);
    std::string getString(rapidjson::Value &value);
};

// fwd declarations
class UnixsocketConnector: public Connector {
  public:
    UnixsocketConnector(std::map<std::string,std::string> options);
    virtual ~UnixsocketConnector();
    virtual int send_message(const rapidjson::Document &input);
    virtual int recv_message(rapidjson::Document &output);
  private:
    ssize_t read(std::string &data);
    ssize_t write(const std::string &data);
    void reconnect();
    std::map<std::string,std::string> options;
    int fd;
    std::string path;
    bool connected;
    int timeout;
};

class HTTPConnector: public Connector {
  public:

  HTTPConnector(std::map<std::string,std::string> options);
  ~HTTPConnector();

  virtual int send_message(const rapidjson::Document &input);
  virtual int recv_message(rapidjson::Document &output);
  private:
    std::string d_url;
    std::string d_url_suffix;
    std::string d_data;
    int timeout;
    bool d_post; 
    bool d_post_json;
    bool json2string(const rapidjson::Value &input, std::string &output);
    void restful_requestbuilder(const std::string &method, const rapidjson::Value &parameters, YaHTTP::Request& req);
    void post_requestbuilder(const rapidjson::Document &input, YaHTTP::Request& req);
    void addUrlComponent(const rapidjson::Value &parameters, const char *element, std::stringstream& ss);
    Socket* d_socket;
    ComboAddress d_addr;
};

#ifdef REMOTEBACKEND_ZEROMQ
class ZeroMQConnector: public Connector {
   public:
    ZeroMQConnector(std::map<std::string,std::string> options);
    virtual ~ZeroMQConnector();
    virtual int send_message(const rapidjson::Document &input);
    virtual int recv_message(rapidjson::Document &output);
   private:
    void connect();
    std::string d_endpoint;
    int d_timeout;
    int d_timespent;
    std::map<std::string,std::string> d_options;
    void *d_ctx;
    void *d_sock; 
};
#endif

class PipeConnector: public Connector {
  public:

  PipeConnector(std::map<std::string,std::string> options);
  ~PipeConnector();

  virtual int send_message(const rapidjson::Document &input);
  virtual int recv_message(rapidjson::Document &output);

  private:

  void launch();
  bool checkStatus();

  std::string command;
  std::map<std::string,std::string> options;
 
  int d_fd1[2], d_fd2[2];
  int d_pid;
  int d_timeout;
  FILE *d_fp;
};

class RemoteBackend : public DNSBackend
{
  public:
  RemoteBackend(const std::string &suffix="");
  ~RemoteBackend();

  void lookup(const QType &qtype, const DNSName& qdomain, DNSPacket *pkt_p=0, int zoneId=-1);
  bool get(DNSResourceRecord &rr);
  bool list(const DNSName& target, int domain_id, bool include_disabled=false);

  virtual bool getAllDomainMetadata(const DNSName& name, std::map<std::string, std::vector<std::string> >& meta);
  virtual bool getDomainMetadata(const DNSName& name, const std::string& kind, std::vector<std::string>& meta);
  virtual bool getDomainKeys(const DNSName& name, unsigned int kind, std::vector<DNSBackend::KeyData>& keys);
  virtual bool getTSIGKey(const DNSName& name, DNSName* algorithm, std::string* content);
  virtual bool getBeforeAndAfterNamesAbsolute(uint32_t id, const string& qname, DNSName& unhashed, string& before, string& after);
  virtual bool setDomainMetadata(const DNSName& name, const string& kind, const std::vector<std::basic_string<char> >& meta);
  virtual bool removeDomainKey(const DNSName& name, unsigned int id);
  virtual int addDomainKey(const DNSName& name, const KeyData& key);
  virtual bool activateDomainKey(const DNSName& name, unsigned int id);
  virtual bool deactivateDomainKey(const DNSName& name, unsigned int id);
  virtual bool getDomainInfo(const DNSName& domain, DomainInfo& di);
  virtual void setNotified(uint32_t id, uint32_t serial);
  virtual bool doesDNSSEC();
  virtual bool isMaster(const DNSName& name, const string &ip);
  virtual bool superMasterBackend(const string &ip, const DNSName& domain, const vector<DNSResourceRecord>&nsset, string *nameserver, string *account, DNSBackend **ddb);
  virtual bool createSlaveDomain(const string &ip, const DNSName& domain, const string& nameserver, const string &account);
  virtual bool replaceRRSet(uint32_t domain_id, const DNSName& qname, const QType& qt, const vector<DNSResourceRecord>& rrset);
  virtual bool feedRecord(const DNSResourceRecord &r, string *ordername);
  virtual bool feedEnts(int domain_id, map<DNSName,bool>& nonterm);
  virtual bool feedEnts3(int domain_id, const DNSName& domain, map<DNSName,bool>& nonterm, const NSEC3PARAMRecordContent& ns3prc, bool narrow);
  virtual bool startTransaction(const DNSName& domain, int domain_id);
  virtual bool commitTransaction();
  virtual bool abortTransaction();
  virtual bool calculateSOASerial(const DNSName& domain, const SOAData& sd, time_t& serial);
  virtual bool setTSIGKey(const DNSName& name, const DNSName& algorithm, const string& content);
  virtual bool deleteTSIGKey(const DNSName& name);
  virtual bool getTSIGKeys(std::vector< struct TSIGKey > &keys);
  virtual string directBackendCmd(const string& querystr);
  virtual bool searchRecords(const string &pattern, int maxResults, vector<DNSResourceRecord>& result);
  virtual bool searchComments(const string &pattern, int maxResults, vector<Comment>& result);

  static DNSBackend *maker();

  private:
    int build();
    Connector *connector;
    bool d_dnssec;
    rapidjson::Document *d_result;
    int d_index;
    int64_t d_trxid;
    std::string d_connstr;

    bool getBool(rapidjson::Value &value);
    int getInt(rapidjson::Value &value);
    unsigned int getUInt(rapidjson::Value &value);
    int64_t getInt64(rapidjson::Value &value);
    std::string getString(rapidjson::Value &value);
    double getDouble(rapidjson::Value &value);

    bool send(rapidjson::Document &value);
    bool recv(rapidjson::Document &value);
};
#endif
