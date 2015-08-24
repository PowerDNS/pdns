#ifndef REMOTEBACKEND_REMOTEBACKEND_HH

#include <string>
#include <sstream>
#include "pdns/namespaces.hh"
#include <pdns/dns.hh>
#include <pdns/dnsbackend.hh>
#include <pdns/dnspacket.hh>
#include <pdns/ueberbackend.hh>
#include <pdns/pdnsexception.hh>
#include <pdns/logger.hh>
#include <pdns/arguments.hh>
#include <boost/lexical_cast.hpp>
#include <rapidjson/rapidjson.h>
#include <rapidjson/document.h>
#include "pdns/json.hh"
#include "yahttp/yahttp.hpp"
#include "sstuff.hh"

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
    std::string d_capath;
    std::string d_cafile;
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

  void lookup(const QType &qtype, const std::string &qdomain, DNSPacket *pkt_p=0, int zoneId=-1);
  bool get(DNSResourceRecord &rr);
  bool list(const std::string &target, int domain_id, bool include_disabled=false);

  virtual bool getAllDomainMetadata(const string& name, std::map<std::string, std::vector<std::string> >& meta);
  virtual bool getDomainMetadata(const std::string& name, const std::string& kind, std::vector<std::string>& meta);
  virtual bool getDomainKeys(const std::string& name, unsigned int kind, std::vector<DNSBackend::KeyData>& keys);
  virtual bool getTSIGKey(const std::string& name, std::string* algorithm, std::string* content);
  virtual bool getBeforeAndAfterNamesAbsolute(uint32_t id, const std::string& qname, std::string& unhashed, std::string& before, std::string& after);
  virtual bool setDomainMetadata(const string& name, const string& kind, const std::vector<std::basic_string<char> >& meta);
  virtual bool removeDomainKey(const string& name, unsigned int id);
  virtual int addDomainKey(const string& name, const KeyData& key);
  virtual bool activateDomainKey(const string& name, unsigned int id);
  virtual bool deactivateDomainKey(const string& name, unsigned int id);
  virtual bool getDomainInfo(const string&, DomainInfo&);
  virtual void setNotified(uint32_t id, uint32_t serial);
  virtual bool doesDNSSEC();
  virtual bool isMaster(const string &name, const string &ip);
  virtual bool superMasterBackend(const string &ip, const string &domain, const vector<DNSResourceRecord>&nsset, string *nameserver, string *account, DNSBackend **ddb);
  virtual bool createSlaveDomain(const string &ip, const string &domain, const string &nameserver, const string &account);
  virtual bool replaceRRSet(uint32_t domain_id, const string& qname, const QType& qt, const vector<DNSResourceRecord>& rrset);
  virtual bool feedRecord(const DNSResourceRecord &r, string *ordername);
  virtual bool feedEnts(int domain_id, map<string,bool>& nonterm);
  virtual bool feedEnts3(int domain_id, const string &domain, map<string,bool> &nonterm, unsigned int times, const string &salt, bool narrow);
  virtual bool startTransaction(const string &domain, int domain_id);
  virtual bool commitTransaction();
  virtual bool abortTransaction();
  virtual bool calculateSOASerial(const string& domain, const SOAData& sd, time_t& serial);
  virtual bool setTSIGKey(const string& name, const string& algorithm, const string& content);
  virtual bool deleteTSIGKey(const string& name);
  virtual bool getTSIGKeys(std::vector< struct TSIGKey > &keys);

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
