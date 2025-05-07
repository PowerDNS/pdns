/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <boost/format.hpp>
#include <sstream>
#include <sys/time.h>
#include <sys/resource.h>
#include <thread>

#include "ext/json11/json11.hpp"
#include <yahttp/yahttp.hpp>

#include "base64.hh"
#include "connection-management.hh"
#include "dnsdist.hh"
#include "dnsdist-dynblocks.hh"
#include "dnsdist-healthchecks.hh"
#include "dnsdist-prometheus.hh"
#include "dnsdist-web.hh"
#include "dolog.hh"
#include "gettime.hh"
#include "threadname.hh"
#include "sstuff.hh"

struct WebserverConfig
{
  WebserverConfig()
  {
    acl.toMasks("127.0.0.1, ::1");
  }

  NetmaskGroup acl;
  std::unique_ptr<CredentialsHolder> password;
  std::unique_ptr<CredentialsHolder> apiKey;
  boost::optional<std::unordered_map<std::string, std::string> > customHeaders;
  bool apiRequiresAuthentication{true};
  bool dashboardRequiresAuthentication{true};
  bool statsRequireAuthentication{true};
};

bool g_apiReadWrite{false};
LockGuarded<WebserverConfig> g_webserverConfig;
std::string g_apiConfigDirectory;

static ConcurrentConnectionManager s_connManager(100);

std::string getWebserverConfig()
{
  ostringstream out;

  {
    auto config = g_webserverConfig.lock();
    out << "Current web server configuration:" << endl;
    out << "ACL: " << config->acl.toString() << endl;
    out << "Custom headers: ";
    if (config->customHeaders) {
      out << endl;
      for (const auto& header : *config->customHeaders) {
        out << " - " << header.first << ": " << header.second << endl;
      }
    }
    else {
      out << "None" << endl;
    }
    out << "API requires authentication: " << (config->apiRequiresAuthentication ? "yes" : "no") << endl;
    out << "Dashboard requires authentication: " << (config->dashboardRequiresAuthentication ? "yes" : "no") << endl;
    out << "Statistics require authentication: " << (config->statsRequireAuthentication ? "yes" : "no") << endl;
    out << "Password: " << (config->password ? "set" : "unset") << endl;
    out << "API key: " << (config->apiKey ? "set" : "unset") << endl;
  }
  out << "API writable: " << (g_apiReadWrite ? "yes" : "no") << endl;
  out << "API configuration directory: " << g_apiConfigDirectory << endl;
  out << "Maximum concurrent connections: " << s_connManager.getMaxConcurrentConnections() << endl;

  return out.str();
}

class WebClientConnection
{
public:
  WebClientConnection(const ComboAddress& client, int fd): d_client(client), d_socket(fd)
  {
    if (!s_connManager.registerConnection()) {
      throw std::runtime_error("Too many concurrent web client connections");
    }
  }
  WebClientConnection(WebClientConnection&& rhs): d_client(rhs.d_client), d_socket(std::move(rhs.d_socket))
  {
  }

  WebClientConnection(const WebClientConnection&) = delete;
  WebClientConnection& operator=(const WebClientConnection&) = delete;

  ~WebClientConnection()
  {
    if (d_socket.getHandle() != -1) {
      s_connManager.releaseConnection();
    }
  }

  const Socket& getSocket() const
  {
    return d_socket;
  }

  const ComboAddress& getClient() const
  {
    return d_client;
  }

private:
  ComboAddress d_client;
  Socket d_socket;
};

#ifndef DISABLE_PROMETHEUS
static MetricDefinitionStorage s_metricDefinitions;

std::map<std::string, MetricDefinition> MetricDefinitionStorage::metrics{
  { "responses",                             MetricDefinition(PrometheusMetricType::counter, "Number of responses received from backends") },
  { "servfail-responses",                    MetricDefinition(PrometheusMetricType::counter, "Number of SERVFAIL answers received from backends") },
  { "queries",                               MetricDefinition(PrometheusMetricType::counter, "Number of received queries")},
  { "frontend-nxdomain",                     MetricDefinition(PrometheusMetricType::counter, "Number of NXDomain answers sent to clients")},
  { "frontend-servfail",                     MetricDefinition(PrometheusMetricType::counter, "Number of SERVFAIL answers sent to clients")},
  { "frontend-noerror",                      MetricDefinition(PrometheusMetricType::counter, "Number of NoError answers sent to clients")},
  { "acl-drops",                             MetricDefinition(PrometheusMetricType::counter, "Number of packets dropped because of the ACL")},
  { "rule-drop",                             MetricDefinition(PrometheusMetricType::counter, "Number of queries dropped because of a rule")},
  { "rule-nxdomain",                         MetricDefinition(PrometheusMetricType::counter, "Number of NXDomain answers returned because of a rule")},
  { "rule-refused",                          MetricDefinition(PrometheusMetricType::counter, "Number of Refused answers returned because of a rule")},
  { "rule-servfail",                         MetricDefinition(PrometheusMetricType::counter, "Number of SERVFAIL answers received because of a rule")},
  { "rule-truncated",                        MetricDefinition(PrometheusMetricType::counter, "Number of truncated answers returned because of a rule")},
  { "self-answered",                         MetricDefinition(PrometheusMetricType::counter, "Number of self-answered responses")},
  { "downstream-timeouts",                   MetricDefinition(PrometheusMetricType::counter, "Number of queries not answered in time by a backend")},
  { "downstream-send-errors",                MetricDefinition(PrometheusMetricType::counter, "Number of errors when sending a query to a backend")},
  { "trunc-failures",                        MetricDefinition(PrometheusMetricType::counter, "Number of errors encountered while truncating an answer")},
  { "no-policy",                             MetricDefinition(PrometheusMetricType::counter, "Number of queries dropped because no server was available")},
  { "latency0-1",                            MetricDefinition(PrometheusMetricType::counter, "Number of queries answered in less than 1ms")},
  { "latency1-10",                           MetricDefinition(PrometheusMetricType::counter, "Number of queries answered in 1-10 ms")},
  { "latency10-50",                          MetricDefinition(PrometheusMetricType::counter, "Number of queries answered in 10-50 ms")},
  { "latency50-100",                         MetricDefinition(PrometheusMetricType::counter, "Number of queries answered in 50-100 ms")},
  { "latency100-1000",                       MetricDefinition(PrometheusMetricType::counter, "Number of queries answered in 100-1000 ms")},
  { "latency-slow",                          MetricDefinition(PrometheusMetricType::counter, "Number of queries answered in more than 1 second")},
  { "latency-avg100",                        MetricDefinition(PrometheusMetricType::gauge,   "Average response latency in microseconds of the last 100 packets")},
  { "latency-avg1000",                       MetricDefinition(PrometheusMetricType::gauge,   "Average response latency in microseconds of the last 1000 packets")},
  { "latency-avg10000",                      MetricDefinition(PrometheusMetricType::gauge,   "Average response latency in microseconds of the last 10000 packets")},
  { "latency-avg1000000",                    MetricDefinition(PrometheusMetricType::gauge,   "Average response latency in microseconds of the last 1000000 packets")},
  { "latency-tcp-avg100",                    MetricDefinition(PrometheusMetricType::gauge,   "Average response latency, in microseconds, of the last 100 packets received over TCP")},
  { "latency-tcp-avg1000",                   MetricDefinition(PrometheusMetricType::gauge,   "Average response latency, in microseconds, of the last 1000 packets received over TCP")},
  { "latency-tcp-avg10000",                  MetricDefinition(PrometheusMetricType::gauge,   "Average response latency, in microseconds, of the last 10000 packets received over TCP")},
  { "latency-tcp-avg1000000",                MetricDefinition(PrometheusMetricType::gauge,   "Average response latency, in microseconds, of the last 1000000 packets received over TCP")},
  { "latency-dot-avg100",                    MetricDefinition(PrometheusMetricType::gauge,   "Average response latency, in microseconds, of the last 100 packets received over DoT")},
  { "latency-dot-avg1000",                   MetricDefinition(PrometheusMetricType::gauge,   "Average response latency, in microseconds, of the last 1000 packets received over DoT")},
  { "latency-dot-avg10000",                  MetricDefinition(PrometheusMetricType::gauge,   "Average response latency, in microseconds, of the last 10000 packets received over DoT")},
  { "latency-dot-avg1000000",                MetricDefinition(PrometheusMetricType::gauge,   "Average response latency, in microseconds, of the last 1000000 packets received over DoT")},
  { "latency-doh-avg100",                    MetricDefinition(PrometheusMetricType::gauge,   "Average response latency, in microseconds, of the last 100 packets received over DoH")},
  { "latency-doh-avg1000",                   MetricDefinition(PrometheusMetricType::gauge,   "Average response latency, in microseconds, of the last 1000 packets received over DoH")},
  { "latency-doh-avg10000",                  MetricDefinition(PrometheusMetricType::gauge,   "Average response latency, in microseconds, of the last 10000 packets received over DoH")},
  { "latency-doh-avg1000000",                MetricDefinition(PrometheusMetricType::gauge,   "Average response latency, in microseconds, of the last 1000000 packets received over DoH")},
  { "uptime",                                MetricDefinition(PrometheusMetricType::gauge,   "Uptime of the dnsdist process in seconds")},
  { "real-memory-usage",                     MetricDefinition(PrometheusMetricType::gauge,   "Current memory usage in bytes")},
  { "noncompliant-queries",                  MetricDefinition(PrometheusMetricType::counter, "Number of queries dropped as non-compliant")},
  { "noncompliant-responses",                MetricDefinition(PrometheusMetricType::counter, "Number of answers from a backend dropped as non-compliant")},
  { "rdqueries",                             MetricDefinition(PrometheusMetricType::counter, "Number of received queries with the recursion desired bit set")},
  { "empty-queries",                         MetricDefinition(PrometheusMetricType::counter, "Number of empty queries received from clients")},
  { "cache-hits",                            MetricDefinition(PrometheusMetricType::counter, "Number of times an answer was retrieved from cache")},
  { "cache-misses",                          MetricDefinition(PrometheusMetricType::counter, "Number of times an answer not found in the cache")},
  { "cpu-iowait",                            MetricDefinition(PrometheusMetricType::counter, "Time waiting for I/O to complete by the whole system, in units of USER_HZ")},
  { "cpu-user-msec",                         MetricDefinition(PrometheusMetricType::counter, "Milliseconds spent by dnsdist in the user state")},
  { "cpu-steal",                             MetricDefinition(PrometheusMetricType::counter, "Stolen time, which is the time spent by the whole system in other operating systems when running in a virtualized environment, in units of USER_HZ")},
  { "cpu-sys-msec",                          MetricDefinition(PrometheusMetricType::counter, "Milliseconds spent by dnsdist in the system state")},
  { "fd-usage",                              MetricDefinition(PrometheusMetricType::gauge,   "Number of currently used file descriptors")},
  { "dyn-blocked",                           MetricDefinition(PrometheusMetricType::counter, "Number of queries dropped because of a dynamic block")},
  { "dyn-block-nmg-size",                    MetricDefinition(PrometheusMetricType::gauge,   "Number of dynamic blocks entries") },
  { "security-status",                       MetricDefinition(PrometheusMetricType::gauge,   "Security status of this software. 0=unknown, 1=OK, 2=upgrade recommended, 3=upgrade mandatory") },
  { "doh-query-pipe-full",                   MetricDefinition(PrometheusMetricType::counter, "Number of DoH queries dropped because the internal pipe used to distribute queries was full") },
  { "doh-response-pipe-full",                MetricDefinition(PrometheusMetricType::counter, "Number of DoH responses dropped because the internal pipe used to distribute responses was full") },
  { "outgoing-doh-query-pipe-full",          MetricDefinition(PrometheusMetricType::counter, "Number of outgoing DoH queries dropped because the internal pipe used to distribute queries was full") },
  { "tcp-query-pipe-full",                   MetricDefinition(PrometheusMetricType::counter, "Number of TCP queries dropped because the internal pipe used to distribute queries was full") },
  { "tcp-cross-protocol-query-pipe-full",    MetricDefinition(PrometheusMetricType::counter, "Number of TCP cross-protocol queries dropped because the internal pipe used to distribute queries was full") },
  { "tcp-cross-protocol-response-pipe-full", MetricDefinition(PrometheusMetricType::counter, "Number of TCP cross-protocol responses dropped because the internal pipe used to distribute queries was full") },
  { "udp-in-errors",                         MetricDefinition(PrometheusMetricType::counter, "From /proc/net/snmp InErrors") },
  { "udp-noport-errors",                     MetricDefinition(PrometheusMetricType::counter, "From /proc/net/snmp NoPorts") },
  { "udp-recvbuf-errors",                    MetricDefinition(PrometheusMetricType::counter, "From /proc/net/snmp RcvbufErrors") },
  { "udp-sndbuf-errors",                     MetricDefinition(PrometheusMetricType::counter, "From /proc/net/snmp SndbufErrors") },
  { "udp-in-csum-errors",                    MetricDefinition(PrometheusMetricType::counter, "From /proc/net/snmp InCsumErrors") },
  { "udp6-in-errors",                        MetricDefinition(PrometheusMetricType::counter, "From /proc/net/snmp6 Udp6InErrors") },
  { "udp6-recvbuf-errors",                   MetricDefinition(PrometheusMetricType::counter, "From /proc/net/snmp6 Udp6RcvbufErrors") },
  { "udp6-sndbuf-errors",                    MetricDefinition(PrometheusMetricType::counter, "From /proc/net/snmp6 Udp6SndbufErrors") },
  { "udp6-noport-errors",                    MetricDefinition(PrometheusMetricType::counter, "From /proc/net/snmp6 Udp6NoPorts") },
  { "udp6-in-csum-errors",                   MetricDefinition(PrometheusMetricType::counter, "From /proc/net/snmp6 Udp6InCsumErrors") },
  { "tcp-listen-overflows",                  MetricDefinition(PrometheusMetricType::counter, "From /proc/net/netstat ListenOverflows") },
  { "proxy-protocol-invalid",                MetricDefinition(PrometheusMetricType::counter, "Number of queries dropped because of an invalid Proxy Protocol header") },
};
#endif /* DISABLE_PROMETHEUS */

bool addMetricDefinition(const std::string& name, const std::string& type, const std::string& description, const std::string& customName) {
#ifndef DISABLE_PROMETHEUS
  return MetricDefinitionStorage::addMetricDefinition(name, type, description, customName);
#else
  return true;
#endif /* DISABLE_PROMETHEUS */
}

#ifndef DISABLE_WEB_CONFIG
static bool apiWriteConfigFile(const string& filebasename, const string& content)
{
  if (!g_apiReadWrite) {
    errlog("Not writing content to %s since the API is read-only", filebasename);
    return false;
  }

  if (g_apiConfigDirectory.empty()) {
    vinfolog("Not writing content to %s since the API configuration directory is not set", filebasename);
    return false;
  }

  string filename = g_apiConfigDirectory + "/" + filebasename + ".conf";
  ofstream ofconf(filename.c_str());
  if (!ofconf) {
    errlog("Could not open configuration fragment file '%s' for writing: %s", filename, stringerror());
    return false;
  }
  ofconf << "-- Generated by the REST API, DO NOT EDIT" << endl;
  ofconf << content << endl;
  ofconf.close();
  return true;
}

static void apiSaveACL(const NetmaskGroup& nmg)
{
  vector<string> vec;
  nmg.toStringVector(&vec);

  string acl;
  for(const auto& s : vec) {
    if (!acl.empty()) {
      acl += ", ";
    }
    acl += "\"" + s + "\"";
  }

  string content = "setACL({" + acl + "})";
  apiWriteConfigFile("acl", content);
}
#endif /* DISABLE_WEB_CONFIG */

static bool checkAPIKey(const YaHTTP::Request& req, const std::unique_ptr<CredentialsHolder>& apiKey)
{
  if (!apiKey) {
    return false;
  }

  const auto header = req.headers.find("x-api-key");
  if (header != req.headers.end()) {
    return apiKey->matches(header->second);
  }

  return false;
}

static bool checkWebPassword(const YaHTTP::Request& req, const std::unique_ptr<CredentialsHolder>& password, bool dashboardRequiresAuthentication)
{
  if (!dashboardRequiresAuthentication) {
    return true;
  }

  static const char basicStr[] = "basic ";

  const auto header = req.headers.find("authorization");

  if (header != req.headers.end() && toLower(header->second).find(basicStr) == 0) {
    string cookie = header->second.substr(sizeof(basicStr) - 1);

    string plain;
    B64Decode(cookie, plain);

    vector<string> cparts;
    stringtok(cparts, plain, ":");

    if (cparts.size() == 2) {
      if (password) {
        return password->matches(cparts.at(1));
      }
      return true;
    }
  }

  return false;
}

static bool isAnAPIRequest(const YaHTTP::Request& req)
{
  return req.url.path.find("/api/") == 0;
}

static bool isAnAPIRequestAllowedWithWebAuth(const YaHTTP::Request& req)
{
  return req.url.path == "/api/v1/servers/localhost";
}

static bool isAStatsRequest(const YaHTTP::Request& req)
{
  return req.url.path == "/jsonstat" || req.url.path == "/metrics";
}

static bool handleAuthorization(const YaHTTP::Request& req)
{
  auto config = g_webserverConfig.lock();

  if (isAStatsRequest(req)) {
    if (config->statsRequireAuthentication) {
      /* Access to the stats is allowed for both API and Web users */
      return checkAPIKey(req, config->apiKey) || checkWebPassword(req, config->password, config->dashboardRequiresAuthentication);
    }
    return true;
  }

  if (isAnAPIRequest(req)) {
    /* Access to the API requires a valid API key */
    if (!config->apiRequiresAuthentication  || checkAPIKey(req, config->apiKey)) {
      return true;
    }

    return isAnAPIRequestAllowedWithWebAuth(req) && checkWebPassword(req, config->password, config->dashboardRequiresAuthentication);
  }

  return checkWebPassword(req, config->password, config->dashboardRequiresAuthentication);
}

static bool isMethodAllowed(const YaHTTP::Request& req)
{
  if (req.method == "GET") {
    return true;
  }
  if (req.method == "PUT" && g_apiReadWrite) {
    if (req.url.path == "/api/v1/servers/localhost/config/allow-from") {
      return true;
    }
  }
#ifndef DISABLE_WEB_CACHE_MANAGEMENT
  if (req.method == "DELETE") {
    if (req.url.path == "/api/v1/cache") {
      return true;
    }
  }
#endif /* DISABLE_WEB_CACHE_MANAGEMENT */
  return false;
}

static bool isClientAllowedByACL(const ComboAddress& remote)
{
  return g_webserverConfig.lock()->acl.match(remote);
}

static void handleCORS(const YaHTTP::Request& req, YaHTTP::Response& resp)
{
  const auto origin = req.headers.find("Origin");
  if (origin != req.headers.end()) {
    if (req.method == "OPTIONS") {
      /* Pre-flight request */
      if (g_apiReadWrite) {
        resp.headers["Access-Control-Allow-Methods"] = "GET, PUT";
      }
      else {
        resp.headers["Access-Control-Allow-Methods"] = "GET";
      }
      resp.headers["Access-Control-Allow-Headers"] = "Authorization, X-API-Key";
    }

    resp.headers["Access-Control-Allow-Origin"] = origin->second;

    if (isAStatsRequest(req) || isAnAPIRequestAllowedWithWebAuth(req)) {
      resp.headers["Access-Control-Allow-Credentials"] = "true";
    }
  }
}

static void addSecurityHeaders(YaHTTP::Response& resp, const boost::optional<std::unordered_map<std::string, std::string> >& customHeaders)
{
  static const std::vector<std::pair<std::string, std::string> > headers = {
    { "X-Content-Type-Options", "nosniff" },
    { "X-Frame-Options", "deny" },
    { "X-Permitted-Cross-Domain-Policies", "none" },
    { "X-XSS-Protection", "1; mode=block" },
    { "Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'" },
  };

  for (const auto& h : headers) {
    if (customHeaders) {
      const auto& custom = customHeaders->find(h.first);
      if (custom != customHeaders->end()) {
        continue;
      }
    }
    resp.headers[h.first] = h.second;
  }
}

static void addCustomHeaders(YaHTTP::Response& resp, const boost::optional<std::unordered_map<std::string, std::string> >& customHeaders)
{
  if (!customHeaders)
    return;

  for (const auto& c : *customHeaders) {
    if (!c.second.empty()) {
      resp.headers[c.first] = c.second;
    }
  }
}

template<typename T>
static json11::Json::array someResponseRulesToJson(GlobalStateHolder<vector<T>>* someResponseRules)
{
  using namespace json11;
  Json::array responseRules;
  int num=0;
  auto localResponseRules = someResponseRules->getLocal();
  responseRules.reserve(localResponseRules->size());
  for (const auto& a : *localResponseRules) {
    responseRules.push_back(Json::object{
        {"id", num++},
        {"creationOrder", (double)a.d_creationOrder},
        {"uuid", boost::uuids::to_string(a.d_id)},
        {"name", a.d_name},
        {"matches", (double)a.d_rule->d_matches},
        {"rule", a.d_rule->toString()},
        {"action", a.d_action->toString()},
      });
  }
  return responseRules;
}

#ifndef DISABLE_PROMETHEUS
template<typename T>
static void addRulesToPrometheusOutput(std::ostringstream& output, GlobalStateHolder<vector<T> >& rules)
{
  auto localRules = rules.getLocal();
  for (const auto& entry : *localRules) {
    std::string id = !entry.d_name.empty() ? entry.d_name : boost::uuids::to_string(entry.d_id);
    output << "dnsdist_rule_hits{id=\"" << id << "\"} " << entry.d_rule->d_matches << "\n";
  }
}

static void handlePrometheus(const YaHTTP::Request& req, YaHTTP::Response& resp)
{
  handleCORS(req, resp);
  resp.status = 200;

  std::ostringstream output;
  static const std::set<std::string> metricBlacklist = { "special-memory-usage", "latency-count", "latency-sum" };
  {
    auto entries = g_stats.entries.read_lock();
    for (const auto& entry : *entries) {
      const auto& metricName = entry.d_name;

      if (metricBlacklist.count(metricName) != 0) {
        continue;
      }

      MetricDefinition metricDetails;
      if (!s_metricDefinitions.getMetricDetails(metricName, metricDetails)) {
        vinfolog("Do not have metric details for %s", metricName);
        continue;
      }

      const std::string prometheusTypeName = s_metricDefinitions.getPrometheusStringMetricType(metricDetails.prometheusType);
      if (prometheusTypeName.empty()) {
        vinfolog("Unknown Prometheus type for %s", metricName);
        continue;
      }

      // Prometheus suggest using '_' instead of '-'
      std::string prometheusMetricName;
      if (metricDetails.customName.empty()) {
        prometheusMetricName = "dnsdist_" + boost::replace_all_copy(metricName, "-", "_");
      }
      else {
        prometheusMetricName = metricDetails.customName;
      }

      // for these we have the help and types encoded in the sources
      // but we need to be careful about labels in custom metrics
      std::string helpName = prometheusMetricName.substr(0, prometheusMetricName.find('{'));
      output << "# HELP " << helpName << " " << metricDetails.description    << "\n";
      output << "# TYPE " << helpName << " " << prometheusTypeName << "\n";
      output << prometheusMetricName << " ";

      if (const auto& val = boost::get<pdns::stat_t*>(&entry.d_value)) {
        output << (*val)->load();
      }
      else if (const auto& adval = boost::get<pdns::stat_t_trait<double>*>(&entry.d_value)) {
        output << (*adval)->load();
      }
      else if (const auto& dval = boost::get<double*>(&entry.d_value)) {
        output << **dval;
      }
      else if (const auto& func = boost::get<DNSDistStats::statfunction_t>(&entry.d_value)) {
        output << (*func)(entry.d_name);
      }

      output << "\n";
    }
  }

  // Latency histogram buckets
  output << "# HELP dnsdist_latency Histogram of responses by latency (in milliseconds)\n";
  output << "# TYPE dnsdist_latency histogram\n";
  uint64_t latency_amounts = g_stats.latency0_1;
  output << "dnsdist_latency_bucket{le=\"1\"} " << latency_amounts << "\n";
  latency_amounts += g_stats.latency1_10;
  output << "dnsdist_latency_bucket{le=\"10\"} " << latency_amounts << "\n";
  latency_amounts += g_stats.latency10_50;
  output << "dnsdist_latency_bucket{le=\"50\"} " << latency_amounts << "\n";
  latency_amounts += g_stats.latency50_100;
  output << "dnsdist_latency_bucket{le=\"100\"} " << latency_amounts << "\n";
  latency_amounts += g_stats.latency100_1000;
  output << "dnsdist_latency_bucket{le=\"1000\"} " << latency_amounts << "\n";
  latency_amounts += g_stats.latencySlow; // Should be the same as latency_count
  output << "dnsdist_latency_bucket{le=\"+Inf\"} " << latency_amounts << "\n";
  output << "dnsdist_latency_sum " << g_stats.latencySum << "\n";
  output << "dnsdist_latency_count " << g_stats.latencyCount << "\n";

  auto states = g_dstates.getLocal();
  const string statesbase = "dnsdist_server_";

  output << "# HELP " << statesbase << "status "                          << "Whether this backend is up (1) or down (0)"                                           << "\n";
  output << "# TYPE " << statesbase << "status "                          << "gauge"                                                                                << "\n";
  output << "# HELP " << statesbase << "queries "                         << "Amount of queries relayed to server"                                                  << "\n";
  output << "# TYPE " << statesbase << "queries "                         << "counter"                                                                              << "\n";
  output << "# HELP " << statesbase << "responses "                       << "Amount of responses received from this server"                                        << "\n";
  output << "# TYPE " << statesbase << "responses "                       << "counter"                                                                              << "\n";
  output << "# HELP " << statesbase << "noncompliantresponses "           << "Amount of non-compliant responses received from this server"                          << "\n";
  output << "# TYPE " << statesbase << "noncompliantresponses "           << "counter"                                                                              << "\n";
  output << "# HELP " << statesbase << "drops "                           << "Amount of queries not answered by server"                                             << "\n";
  output << "# TYPE " << statesbase << "drops "                           << "counter"                                                                              << "\n";
  output << "# HELP " << statesbase << "latency "                         << "Server's latency when answering questions in milliseconds"                            << "\n";
  output << "# TYPE " << statesbase << "latency "                         << "gauge"                                                                                << "\n";
  output << "# HELP " << statesbase << "senderrors "                      << "Total number of OS send errors while relaying queries"                                << "\n";
  output << "# TYPE " << statesbase << "senderrors "                      << "counter"                                                                              << "\n";
  output << "# HELP " << statesbase << "outstanding "                     << "Current number of queries that are waiting for a backend response"                    << "\n";
  output << "# TYPE " << statesbase << "outstanding "                     << "gauge"                                                                                << "\n";
  output << "# HELP " << statesbase << "order "                           << "The order in which this server is picked"                                             << "\n";
  output << "# TYPE " << statesbase << "order "                           << "gauge"                                                                                << "\n";
  output << "# HELP " << statesbase << "weight "                          << "The weight within the order in which this server is picked"                           << "\n";
  output << "# TYPE " << statesbase << "weight "                          << "gauge"                                                                                << "\n";
  output << "# HELP " << statesbase << "tcpdiedsendingquery "             << "The number of TCP I/O errors while sending the query"                                 << "\n";
  output << "# TYPE " << statesbase << "tcpdiedsendingquery "             << "counter"                                                                              << "\n";
  output << "# HELP " << statesbase << "tcpdiedreadingresponse "          << "The number of TCP I/O errors while reading the response"                              << "\n";
  output << "# TYPE " << statesbase << "tcpdiedreadingresponse "          << "counter"                                                                              << "\n";
  output << "# HELP " << statesbase << "tcpgaveup "                       << "The number of TCP connections failing after too many attempts"                        << "\n";
  output << "# TYPE " << statesbase << "tcpgaveup "                       << "counter"                                                                              << "\n";
  output << "# HELP " << statesbase << "tcpconnecttimeouts "              << "The number of TCP connect timeouts"                                                   << "\n";
  output << "# TYPE " << statesbase << "tcpconnecttimeouts "              << "counter"                                                                              << "\n";
  output << "# HELP " << statesbase << "tcpreadtimeouts "                 << "The number of TCP read timeouts"                                                      << "\n";
  output << "# TYPE " << statesbase << "tcpreadtimeouts "                 << "counter"                                                                              << "\n";
  output << "# HELP " << statesbase << "tcpwritetimeouts "                << "The number of TCP write timeouts"                                                     << "\n";
  output << "# TYPE " << statesbase << "tcpwritetimeouts "                << "counter"                                                                              << "\n";
  output << "# HELP " << statesbase << "tcpcurrentconnections "           << "The number of current TCP connections"                                                << "\n";
  output << "# TYPE " << statesbase << "tcpcurrentconnections "           << "gauge"                                                                                << "\n";
  output << "# HELP " << statesbase << "tcpmaxconcurrentconnections "     << "The maximum number of concurrent TCP connections"                                     << "\n";
  output << "# TYPE " << statesbase << "tcpmaxconcurrentconnections "     << "counter"                                                                              << "\n";
  output << "# HELP " << statesbase << "tcptoomanyconcurrentconnections " << "Number of times we had to enforce the maximum number of concurrent TCP connections"   << "\n";
  output << "# TYPE " << statesbase << "tcptoomanyconcurrentconnections " << "counter"                                                                              << "\n";
  output << "# HELP " << statesbase << "tcpnewconnections "               << "The number of established TCP connections in total"                                   << "\n";
  output << "# TYPE " << statesbase << "tcpnewconnections "               << "counter"                                                                              << "\n";
  output << "# HELP " << statesbase << "tcpreusedconnections "            << "The number of times a TCP connection has been reused"                                 << "\n";
  output << "# TYPE " << statesbase << "tcpreusedconnections "            << "counter"                                                                              << "\n";
  output << "# HELP " << statesbase << "tcpavgqueriesperconn "            << "The average number of queries per TCP connection"                                     << "\n";
  output << "# TYPE " << statesbase << "tcpavgqueriesperconn "            << "gauge"                                                                                << "\n";
  output << "# HELP " << statesbase << "tcpavgconnduration "              << "The average duration of a TCP connection (ms)"                                        << "\n";
  output << "# TYPE " << statesbase << "tcpavgconnduration "              << "gauge"                                                                                << "\n";
  output << "# HELP " << statesbase << "tlsresumptions "                  << "The number of times a TLS session has been resumed"                                   << "\n";
  output << "# TYPE " << statesbase << "tlsresumptions "                  << "counter"                                                                              << "\n";
  output << "# HELP " << statesbase << "tcplatency "                      << "Server's latency when answering TCP questions in milliseconds"                        << "\n";
  output << "# TYPE " << statesbase << "tcplatency "                      << "gauge"                                                                                << "\n";
  output << "# HELP " << statesbase << "healthcheckfailures "             << "Number of health check attempts that failed (total)"                                  << "\n";
  output << "# TYPE " << statesbase << "healthcheckfailures "             << "counter"                                                                              << "\n";
  output << "# HELP " << statesbase << "healthcheckfailuresparsing "      << "Number of health check attempts where the response could not be parsed"               << "\n";
  output << "# TYPE " << statesbase << "healthcheckfailuresparsing "      << "counter"                                                                              << "\n";
  output << "# HELP " << statesbase << "healthcheckfailurestimeout "      << "Number of health check attempts where the response did not arrive in time"            << "\n";
  output << "# TYPE " << statesbase << "healthcheckfailurestimeout "      << "counter"                                                                              << "\n";
  output << "# HELP " << statesbase << "healthcheckfailuresnetwork "      << "Number of health check attempts that experienced a network issue"                     << "\n";
  output << "# TYPE " << statesbase << "healthcheckfailuresnetwork "      << "counter"                                                                              << "\n";
  output << "# HELP " << statesbase << "healthcheckfailuresmismatch "     << "Number of health check attempts where the response did not match the query"           << "\n";
  output << "# TYPE " << statesbase << "healthcheckfailuresmismatch "     << "counter"                                                                              << "\n";
  output << "# HELP " << statesbase << "healthcheckfailuresinvalid "      << "Number of health check attempts where the DNS response was invalid"                   << "\n";
  output << "# TYPE " << statesbase << "healthcheckfailuresinvalid "      << "counter"                                                                              << "\n";

  for (const auto& state : *states) {
    string serverName;

    if (state->getName().empty()) {
      serverName = state->d_config.remote.toStringWithPort();
    }
    else {
      serverName = state->getName();
    }

    boost::replace_all(serverName, ".", "_");

    const std::string label = boost::str(boost::format("{server=\"%1%\",address=\"%2%\"}")
                                         % serverName % state->d_config.remote.toStringWithPort());

    output << statesbase << "status"                           << label << " " << (state->isUp() ? "1" : "0")            << "\n";
    output << statesbase << "queries"                          << label << " " << state->queries.load()                  << "\n";
    output << statesbase << "responses"                        << label << " " << state->responses.load()                << "\n";
    output << statesbase << "noncompliantresponses"            << label << " " << state->nonCompliantResponses.load()    << "\n";
    output << statesbase << "drops"                            << label << " " << state->reuseds.load()                  << "\n";
    if (state->isUp()) {
      output << statesbase << "latency"                        << label << " " << state->latencyUsec/1000.0              << "\n";
      output << statesbase << "tcplatency"                     << label << " " << state->latencyUsecTCP/1000.0           << "\n";
    }
    output << statesbase << "senderrors"                       << label << " " << state->sendErrors.load()               << "\n";
    output << statesbase << "outstanding"                      << label << " " << state->outstanding.load()              << "\n";
    output << statesbase << "order"                            << label << " " << state->d_config.order                  << "\n";
    output << statesbase << "weight"                           << label << " " << state->d_config.d_weight               << "\n";
    output << statesbase << "tcpdiedsendingquery"              << label << " " << state->tcpDiedSendingQuery             << "\n";
    output << statesbase << "tcpdiedreadingresponse"           << label << " " << state->tcpDiedReadingResponse          << "\n";
    output << statesbase << "tcpgaveup"                        << label << " " << state->tcpGaveUp                       << "\n";
    output << statesbase << "tcpreadtimeouts"                  << label << " " << state->tcpReadTimeouts                 << "\n";
    output << statesbase << "tcpwritetimeouts"                 << label << " " << state->tcpWriteTimeouts                << "\n";
    output << statesbase << "tcpconnecttimeouts"               << label << " " << state->tcpConnectTimeouts              << "\n";
    output << statesbase << "tcpcurrentconnections"            << label << " " << state->tcpCurrentConnections           << "\n";
    output << statesbase << "tcpmaxconcurrentconnections"      << label << " " << state->tcpMaxConcurrentConnections     << "\n";
    output << statesbase << "tcptoomanyconcurrentconnections"  << label << " " << state->tcpTooManyConcurrentConnections << "\n";
    output << statesbase << "tcpnewconnections"                << label << " " << state->tcpNewConnections               << "\n";
    output << statesbase << "tcpreusedconnections"             << label << " " << state->tcpReusedConnections            << "\n";
    output << statesbase << "tcpavgqueriesperconn"             << label << " " << state->tcpAvgQueriesPerConnection      << "\n";
    output << statesbase << "tcpavgconnduration"               << label << " " << state->tcpAvgConnectionDuration        << "\n";
    output << statesbase << "tlsresumptions"                   << label << " " << state->tlsResumptions                  << "\n";
    output << statesbase << "healthcheckfailures"              << label << " " << state->d_healthCheckMetrics.d_failures << "\n";
    output << statesbase << "healthcheckfailuresparsing"       << label << " " << state->d_healthCheckMetrics.d_parseErrors << "\n";
    output << statesbase << "healthcheckfailurestimeout"       << label << " " << state->d_healthCheckMetrics.d_timeOuts << "\n";
    output << statesbase << "healthcheckfailuresnetwork"       << label << " " << state->d_healthCheckMetrics.d_networkErrors << "\n";
    output << statesbase << "healthcheckfailuresmismatch"      << label << " " << state->d_healthCheckMetrics.d_mismatchErrors << "\n";
    output << statesbase << "healthcheckfailuresinvalid"        << label << " " << state->d_healthCheckMetrics.d_invalidResponseErrors << "\n";
  }

  const string frontsbase = "dnsdist_frontend_";
  output << "# HELP " << frontsbase << "queries " << "Amount of queries received by this frontend" << "\n";
  output << "# TYPE " << frontsbase << "queries " << "counter" << "\n";
  output << "# HELP " << frontsbase << "noncompliantqueries " << "Amount of non-compliant queries received by this frontend" << "\n";
  output << "# TYPE " << frontsbase << "noncompliantqueries " << "counter" << "\n";
  output << "# HELP " << frontsbase << "responses " << "Amount of responses sent by this frontend" << "\n";
  output << "# TYPE " << frontsbase << "responses " << "counter" << "\n";
  output << "# HELP " << frontsbase << "tcpdiedreadingquery " << "Amount of TCP connections terminated while reading the query from the client" << "\n";
  output << "# TYPE " << frontsbase << "tcpdiedreadingquery " << "counter" << "\n";
  output << "# HELP " << frontsbase << "tcpdiedsendingresponse " << "Amount of TCP connections terminated while sending a response to the client" << "\n";
  output << "# TYPE " << frontsbase << "tcpdiedsendingresponse " << "counter" << "\n";
  output << "# HELP " << frontsbase << "tcpgaveup " << "Amount of TCP connections terminated after too many attempts to get a connection to the backend" << "\n";
  output << "# TYPE " << frontsbase << "tcpgaveup " << "counter" << "\n";
  output << "# HELP " << frontsbase << "tcpclientimeouts " << "Amount of TCP connections terminated by a timeout while reading from the client" << "\n";
  output << "# TYPE " << frontsbase << "tcpclientimeouts " << "counter" << "\n";
  output << "# HELP " << frontsbase << "tcpdownstreamtimeouts " << "Amount of TCP connections terminated by a timeout while reading from the backend" << "\n";
  output << "# TYPE " << frontsbase << "tcpdownstreamtimeouts " << "counter" << "\n";
  output << "# HELP " << frontsbase << "tcpcurrentconnections " << "Amount of current incoming TCP connections from clients" << "\n";
  output << "# TYPE " << frontsbase << "tcpcurrentconnections " << "gauge" << "\n";
  output << "# HELP " << frontsbase << "tcpmaxconcurrentconnections " << "Maximum number of concurrent incoming TCP connections from clients" << "\n";
  output << "# TYPE " << frontsbase << "tcpmaxconcurrentconnections " << "counter" << "\n";
  output << "# HELP " << frontsbase << "tcpavgqueriesperconnection " << "The average number of queries per TCP connection" << "\n";
  output << "# TYPE " << frontsbase << "tcpavgqueriesperconnection " << "gauge" << "\n";
  output << "# HELP " << frontsbase << "tcpavgconnectionduration " << "The average duration of a TCP connection (ms)" << "\n";
  output << "# TYPE " << frontsbase << "tcpavgconnectionduration " << "gauge" << "\n";
  output << "# HELP " << frontsbase << "tlsqueries " << "Number of queries received by dnsdist over TLS, by TLS version" << "\n";
  output << "# TYPE " << frontsbase << "tlsqueries " << "counter" << "\n";
  output << "# HELP " << frontsbase << "tlsnewsessions " << "Amount of new TLS sessions negotiated" << "\n";
  output << "# TYPE " << frontsbase << "tlsnewsessions " << "counter" << "\n";
  output << "# HELP " << frontsbase << "tlsresumptions " << "Amount of TLS sessions resumed" << "\n";
  output << "# TYPE " << frontsbase << "tlsresumptions " << "counter" << "\n";
  output << "# HELP " << frontsbase << "tlsunknownticketkeys " << "Amount of attempts to resume TLS session from an unknown key (possibly expired)" << "\n";
  output << "# TYPE " << frontsbase << "tlsunknownticketkeys " << "counter" << "\n";
  output << "# HELP " << frontsbase << "tlsinactiveticketkeys " << "Amount of TLS sessions resumed from an inactive key" << "\n";
  output << "# TYPE " << frontsbase << "tlsinactiveticketkeys " << "counter" << "\n";
  output << "# HELP " << frontsbase << "tlshandshakefailures " << "Amount of TLS handshake failures" << "\n";
  output << "# TYPE " << frontsbase << "tlshandshakefailures " << "counter" << "\n";

  std::map<std::string,uint64_t> frontendDuplicates;
  for (const auto& front : g_frontends) {
    if (front->udpFD == -1 && front->tcpFD == -1)
      continue;

    const string frontName = front->local.toStringWithPort();
    const string proto = front->getType();
    const string fullName = frontName + "_" + proto;
    uint64_t threadNumber = 0;
    auto dupPair = frontendDuplicates.emplace(fullName, 1);
    if (!dupPair.second) {
      threadNumber = dupPair.first->second;
      ++(dupPair.first->second);
    }
    const std::string label = boost::str(boost::format("{frontend=\"%1%\",proto=\"%2%\",thread=\"%3%\"} ")
                                         % frontName % proto % threadNumber);

    output << frontsbase << "queries" << label << front->queries.load() << "\n";
    output << frontsbase << "noncompliantqueries" << label << front->nonCompliantQueries.load() << "\n";
    output << frontsbase << "responses" << label << front->responses.load() << "\n";
    if (front->isTCP()) {
      output << frontsbase << "tcpdiedreadingquery" << label << front->tcpDiedReadingQuery.load() << "\n";
      output << frontsbase << "tcpdiedsendingresponse" << label << front->tcpDiedSendingResponse.load() << "\n";
      output << frontsbase << "tcpgaveup" << label << front->tcpGaveUp.load() << "\n";
      output << frontsbase << "tcpclientimeouts" << label << front->tcpClientTimeouts.load() << "\n";
      output << frontsbase << "tcpdownstreamtimeouts" << label << front->tcpDownstreamTimeouts.load() << "\n";
      output << frontsbase << "tcpcurrentconnections" << label << front->tcpCurrentConnections.load() << "\n";
      output << frontsbase << "tcpmaxconcurrentconnections" << label << front->tcpMaxConcurrentConnections.load() << "\n";
      output << frontsbase << "tcpavgqueriesperconnection" << label << front->tcpAvgQueriesPerConnection.load() << "\n";
      output << frontsbase << "tcpavgconnectionduration" << label << front->tcpAvgConnectionDuration.load() << "\n";
      if (front->hasTLS()) {
        output << frontsbase << "tlsnewsessions" << label << front->tlsNewSessions.load() << "\n";
        output << frontsbase << "tlsresumptions" << label << front->tlsResumptions.load() << "\n";
        output << frontsbase << "tlsunknownticketkeys" << label << front->tlsUnknownTicketKey.load() << "\n";
        output << frontsbase << "tlsinactiveticketkeys" << label << front->tlsInactiveTicketKey.load() << "\n";

        output << frontsbase << "tlsqueries{frontend=\"" << frontName << "\",proto=\"" << proto << "\",thread=\"" << threadNumber << "\",tls=\"tls10\"} " << front->tls10queries.load() << "\n";
        output << frontsbase << "tlsqueries{frontend=\"" << frontName << "\",proto=\"" << proto << "\",thread=\"" << threadNumber << "\",tls=\"tls11\"} " << front->tls11queries.load() << "\n";
        output << frontsbase << "tlsqueries{frontend=\"" << frontName << "\",proto=\"" << proto << "\",thread=\"" << threadNumber << "\",tls=\"tls12\"} " << front->tls12queries.load() << "\n";
        output << frontsbase << "tlsqueries{frontend=\"" << frontName << "\",proto=\"" << proto << "\",thread=\"" << threadNumber << "\",tls=\"tls13\"} " << front->tls13queries.load() << "\n";
        output << frontsbase << "tlsqueries{frontend=\"" << frontName << "\",proto=\"" << proto << "\",thread=\"" << threadNumber << "\",tls=\"unknown\"} " << front->tlsUnknownqueries.load() << "\n";

        const TLSErrorCounters* errorCounters = nullptr;
        if (front->tlsFrontend != nullptr) {
          errorCounters = &front->tlsFrontend->d_tlsCounters;
        }
        else if (front->dohFrontend != nullptr) {
          errorCounters = &front->dohFrontend->d_tlsCounters;
        }

        if (errorCounters != nullptr) {
          output << frontsbase << "tlshandshakefailures{frontend=\"" << frontName << "\",proto=\"" << proto << "\",thread=\"" << threadNumber << "\",error=\"dhKeyTooSmall\"} " << errorCounters->d_dhKeyTooSmall << "\n";
          output << frontsbase << "tlshandshakefailures{frontend=\"" << frontName << "\",proto=\"" << proto << "\",thread=\"" << threadNumber << "\",error=\"inappropriateFallBack\"} " << errorCounters->d_inappropriateFallBack << "\n";
          output << frontsbase << "tlshandshakefailures{frontend=\"" << frontName << "\",proto=\"" << proto << "\",thread=\"" << threadNumber << "\",error=\"noSharedCipher\"} " << errorCounters->d_noSharedCipher << "\n";
          output << frontsbase << "tlshandshakefailures{frontend=\"" << frontName << "\",proto=\"" << proto << "\",thread=\"" << threadNumber << "\",error=\"unknownCipherType\"} " << errorCounters->d_unknownCipherType << "\n";
          output << frontsbase << "tlshandshakefailures{frontend=\"" << frontName << "\",proto=\"" << proto << "\",thread=\"" << threadNumber << "\",error=\"unknownKeyExchangeType\"} " << errorCounters->d_unknownKeyExchangeType << "\n";
          output << frontsbase << "tlshandshakefailures{frontend=\"" << frontName << "\",proto=\"" << proto << "\",thread=\"" << threadNumber << "\",error=\"unknownProtocol\"} " << errorCounters->d_unknownProtocol << "\n";
          output << frontsbase << "tlshandshakefailures{frontend=\"" << frontName << "\",proto=\"" << proto << "\",thread=\"" << threadNumber << "\",error=\"unsupportedEC\"} " << errorCounters->d_unsupportedEC << "\n";
          output << frontsbase << "tlshandshakefailures{frontend=\"" << frontName << "\",proto=\"" << proto << "\",thread=\"" << threadNumber << "\",error=\"unsupportedProtocol\"} " << errorCounters->d_unsupportedProtocol << "\n";
        }
      }
    }
  }

  output << "# HELP " << frontsbase << "http_connects " << "Number of DoH TCP connections established to this frontend" << "\n";
  output << "# TYPE " << frontsbase << "http_connects " << "counter" << "\n";

  output << "# HELP " << frontsbase << "doh_http_method_queries " << "Number of DoH queries received by dnsdist, by HTTP method" << "\n";
  output << "# TYPE " << frontsbase << "doh_http_method_queries " << "counter" << "\n";

  output << "# HELP " << frontsbase << "doh_http_version_queries " << "Number of DoH queries received by dnsdist, by HTTP version" << "\n";
  output << "# TYPE " << frontsbase << "doh_http_version_queries " << "counter" << "\n";

  output << "# HELP " << frontsbase << "doh_bad_requests " << "Number of requests that could not be converted to a DNS query" << "\n";
  output << "# TYPE " << frontsbase << "doh_bad_requests " << "counter" << "\n";

  output << "# HELP " << frontsbase << "doh_responses " << "Number of responses sent, by type" << "\n";
  output << "# TYPE " << frontsbase << "doh_responses " << "counter" << "\n";

  output << "# HELP " << frontsbase << "doh_version_status_responses " << "Number of requests that could not be converted to a DNS query" << "\n";
  output << "# TYPE " << frontsbase << "doh_version_status_responses " << "counter" << "\n";

#ifdef HAVE_DNS_OVER_HTTPS
  std::map<std::string,uint64_t> dohFrontendDuplicates;
  for(const auto& doh : g_dohlocals) {
    const string frontName = doh->d_local.toStringWithPort();
    uint64_t threadNumber = 0;
    auto dupPair = frontendDuplicates.emplace(frontName, 1);
    if (!dupPair.second) {
      threadNumber = dupPair.first->second;
      ++(dupPair.first->second);
    }
    const std::string addrlabel = boost::str(boost::format("frontend=\"%1%\",thread=\"%2%\"") % frontName % threadNumber);
    const std::string label = "{" + addrlabel + "} ";

    output << frontsbase << "http_connects" << label << doh->d_httpconnects << "\n";
    output << frontsbase << "doh_http_method_queries{method=\"get\"," << addrlabel << "} " << doh->d_getqueries << "\n";
    output << frontsbase << "doh_http_method_queries{method=\"post\"," << addrlabel << "} " << doh->d_postqueries << "\n";

    output << frontsbase << "doh_http_version_queries{version=\"1\"," << addrlabel << "} " << doh->d_http1Stats.d_nbQueries << "\n";
    output << frontsbase << "doh_http_version_queries{version=\"2\"," << addrlabel << "} " << doh->d_http2Stats.d_nbQueries << "\n";

    output << frontsbase << "doh_bad_requests{" << addrlabel << "} " << doh->d_badrequests << "\n";

    output << frontsbase << "doh_responses{type=\"error\"," << addrlabel << "} " << doh->d_errorresponses << "\n";
    output << frontsbase << "doh_responses{type=\"redirect\"," << addrlabel << "} " << doh->d_redirectresponses << "\n";
    output << frontsbase << "doh_responses{type=\"valid\"," << addrlabel << "} " << doh->d_validresponses << "\n";

    output << frontsbase << "doh_version_status_responses{httpversion=\"1\",status=\"200\"," << addrlabel << "} " << doh->d_http1Stats.d_nb200Responses << "\n";
    output << frontsbase << "doh_version_status_responses{httpversion=\"1\",status=\"400\"," << addrlabel << "} " << doh->d_http1Stats.d_nb400Responses << "\n";
    output << frontsbase << "doh_version_status_responses{httpversion=\"1\",status=\"403\"," << addrlabel << "} " << doh->d_http1Stats.d_nb403Responses << "\n";
    output << frontsbase << "doh_version_status_responses{httpversion=\"1\",status=\"500\"," << addrlabel << "} " << doh->d_http1Stats.d_nb500Responses << "\n";
    output << frontsbase << "doh_version_status_responses{httpversion=\"1\",status=\"502\"," << addrlabel << "} " << doh->d_http1Stats.d_nb502Responses << "\n";
    output << frontsbase << "doh_version_status_responses{httpversion=\"1\",status=\"other\"," << addrlabel << "} " << doh->d_http1Stats.d_nbOtherResponses << "\n";
    output << frontsbase << "doh_version_status_responses{httpversion=\"2\",status=\"200\"," << addrlabel << "} " << doh->d_http2Stats.d_nb200Responses << "\n";
    output << frontsbase << "doh_version_status_responses{httpversion=\"2\",status=\"400\"," << addrlabel << "} " << doh->d_http2Stats.d_nb400Responses << "\n";
    output << frontsbase << "doh_version_status_responses{httpversion=\"2\",status=\"403\"," << addrlabel << "} " << doh->d_http2Stats.d_nb403Responses << "\n";
    output << frontsbase << "doh_version_status_responses{httpversion=\"2\",status=\"500\"," << addrlabel << "} " << doh->d_http2Stats.d_nb500Responses << "\n";
    output << frontsbase << "doh_version_status_responses{httpversion=\"2\",status=\"502\"," << addrlabel << "} " << doh->d_http2Stats.d_nb502Responses << "\n";
    output << frontsbase << "doh_version_status_responses{httpversion=\"2\",status=\"other\"," << addrlabel << "} " << doh->d_http2Stats.d_nbOtherResponses << "\n";
  }
#endif /* HAVE_DNS_OVER_HTTPS */

  auto localPools = g_pools.getLocal();
  const string cachebase = "dnsdist_pool_";
  output << "# HELP dnsdist_pool_servers " << "Number of servers in that pool" << "\n";
  output << "# TYPE dnsdist_pool_servers " << "gauge" << "\n";
  output << "# HELP dnsdist_pool_active_servers " << "Number of available servers in that pool" << "\n";
  output << "# TYPE dnsdist_pool_active_servers " << "gauge" << "\n";

  output << "# HELP dnsdist_pool_cache_size " << "Maximum number of entries that this cache can hold" << "\n";
  output << "# TYPE dnsdist_pool_cache_size " << "gauge" << "\n";
  output << "# HELP dnsdist_pool_cache_entries " << "Number of entries currently present in that cache" << "\n";
  output << "# TYPE dnsdist_pool_cache_entries " << "gauge" << "\n";
  output << "# HELP dnsdist_pool_cache_hits " << "Number of hits from that cache" << "\n";
  output << "# TYPE dnsdist_pool_cache_hits " << "counter" << "\n";
  output << "# HELP dnsdist_pool_cache_misses " << "Number of misses from that cache" << "\n";
  output << "# TYPE dnsdist_pool_cache_misses " << "counter" << "\n";
  output << "# HELP dnsdist_pool_cache_deferred_inserts " << "Number of insertions into that cache skipped because it was already locked" << "\n";
  output << "# TYPE dnsdist_pool_cache_deferred_inserts " << "counter" << "\n";
  output << "# HELP dnsdist_pool_cache_deferred_lookups " << "Number of lookups into that cache skipped because it was already locked" << "\n";
  output << "# TYPE dnsdist_pool_cache_deferred_lookups " << "counter" << "\n";
  output << "# HELP dnsdist_pool_cache_lookup_collisions " << "Number of lookups into that cache that triggered a collision (same hash but different entry)" << "\n";
  output << "# TYPE dnsdist_pool_cache_lookup_collisions " << "counter" << "\n";
  output << "# HELP dnsdist_pool_cache_insert_collisions " << "Number of insertions into that cache that triggered a collision (same hash but different entry)" << "\n";
  output << "# TYPE dnsdist_pool_cache_insert_collisions " << "counter" << "\n";
  output << "# HELP dnsdist_pool_cache_ttl_too_shorts " << "Number of insertions into that cache skipped because the TTL of the answer was not long enough" << "\n";
  output << "# TYPE dnsdist_pool_cache_ttl_too_shorts " << "counter" << "\n";
  output << "# HELP dnsdist_pool_cache_cleanup_count_total " << "Number of times the cache has been scanned to remove expired entries, if any" << "\n";
  output << "# TYPE dnsdist_pool_cache_cleanup_count_total " << "counter" << "\n";

  for (const auto& entry : *localPools) {
    string poolName = entry.first;

    if (poolName.empty()) {
      poolName = "_default_";
    }
    const string label = "{pool=\"" + poolName + "\"}";
    const std::shared_ptr<ServerPool> pool = entry.second;
    output << "dnsdist_pool_servers" << label << " " << pool->countServers(false) << "\n";
    output << "dnsdist_pool_active_servers" << label << " " << pool->countServers(true) << "\n";

    if (pool->packetCache != nullptr) {
      const auto& cache = pool->packetCache;

      output << cachebase << "cache_size"              <<label << " " << cache->getMaxEntries()       << "\n";
      output << cachebase << "cache_entries"           <<label << " " << cache->getEntriesCount()     << "\n";
      output << cachebase << "cache_hits"              <<label << " " << cache->getHits()             << "\n";
      output << cachebase << "cache_misses"            <<label << " " << cache->getMisses()           << "\n";
      output << cachebase << "cache_deferred_inserts"  <<label << " " << cache->getDeferredInserts()  << "\n";
      output << cachebase << "cache_deferred_lookups"  <<label << " " << cache->getDeferredLookups()  << "\n";
      output << cachebase << "cache_lookup_collisions" <<label << " " << cache->getLookupCollisions() << "\n";
      output << cachebase << "cache_insert_collisions" <<label << " " << cache->getInsertCollisions() << "\n";
      output << cachebase << "cache_ttl_too_shorts"    <<label << " " << cache->getTTLTooShorts()     << "\n";
      output << cachebase << "cache_cleanup_count_total"     <<label << " " << cache->getCleanupCount()     << "\n";
    }
  }

  output << "# HELP dnsdist_rule_hits " << "Number of hits of that rule" << "\n";
  output << "# TYPE dnsdist_rule_hits " << "counter" << "\n";
  addRulesToPrometheusOutput(output, g_ruleactions);
  addRulesToPrometheusOutput(output, g_respruleactions);
  addRulesToPrometheusOutput(output, g_cachehitrespruleactions);
  addRulesToPrometheusOutput(output, g_cacheInsertedRespRuleActions);
  addRulesToPrometheusOutput(output, g_selfansweredrespruleactions);

#ifndef DISABLE_DYNBLOCKS
  output << "# HELP dnsdist_dynblocks_nmg_top_offenders_hits_per_second " << "Number of hits per second blocked by Dynamic Blocks (netmasks) for the top offenders, averaged over the last 60s" << "\n";
  output << "# TYPE dnsdist_dynblocks_nmg_top_offenders_hits_per_second " << "gauge" << "\n";
  auto topNetmasksByReason = DynBlockMaintenance::getHitsForTopNetmasks();
  for (const auto& entry : topNetmasksByReason) {
    for (const auto& netmask : entry.second) {
      output << "dnsdist_dynblocks_nmg_top_offenders_hits_per_second{reason=\"" << entry.first << "\",netmask=\"" << netmask.first.toString() << "\"} " << netmask.second << "\n";
    }
  }

  output << "# HELP dnsdist_dynblocks_smt_top_offenders_hits_per_second " << "Number of this per second blocked by Dynamic Blocks (suffixes) for the top offenders, averaged over the last 60s" << "\n";
  output << "# TYPE dnsdist_dynblocks_smt_top_offenders_hits_per_second " << "gauge" << "\n";
  auto topSuffixesByReason = DynBlockMaintenance::getHitsForTopSuffixes();
  for (const auto& entry : topSuffixesByReason) {
    for (const auto& suffix : entry.second) {
      output << "dnsdist_dynblocks_smt_top_offenders_hits_per_second{reason=\"" << entry.first << "\",suffix=\"" << suffix.first.toString() << "\"} " << suffix.second << "\n";
    }
  }
#endif /* DISABLE_DYNBLOCKS */

  output << "# HELP dnsdist_info " << "Info from dnsdist, value is always 1" << "\n";
  output << "# TYPE dnsdist_info " << "gauge" << "\n";
  output << "dnsdist_info{version=\"" << VERSION << "\"} " << "1" << "\n";

  resp.body = output.str();
  resp.headers["Content-Type"] = "text/plain";
}
#endif /* DISABLE_PROMETHEUS */

using namespace json11;

static void addStatsToJSONObject(Json::object& obj)
{
  auto entries = g_stats.entries.read_lock();
  for (const auto& entry : *entries) {
    if (entry.d_name == "special-memory-usage") {
      continue; // Too expensive for get-all
    }
    if (const auto& val = boost::get<pdns::stat_t*>(&entry.d_value)) {
      obj.emplace(entry.d_name, (double)(*val)->load());
    } else if (const auto& adval = boost::get<pdns::stat_t_trait<double>*>(&entry.d_value)) {
      obj.emplace(entry.d_name, (*adval)->load());
    } else if (const auto& dval = boost::get<double*>(&entry.d_value)) {
      obj.emplace(entry.d_name, (**dval));
    } else if (const auto& func = boost::get<DNSDistStats::statfunction_t>(&entry.d_value)) {
      obj.emplace(entry.d_name, (double)(*func)(entry.d_name));
    }
  }
}

#ifndef DISABLE_BUILTIN_HTML
static void handleJSONStats(const YaHTTP::Request& req, YaHTTP::Response& resp)
{
  handleCORS(req, resp);
  resp.status = 200;

  if (req.getvars.count("command") == 0) {
    resp.status = 404;
    return;
  }

  const string& command = req.getvars.at("command");

  if (command == "stats") {
    auto obj=Json::object {
      { "packetcache-hits", 0},
      { "packetcache-misses", 0},
      { "over-capacity-drops", 0 },
      { "too-old-drops", 0 },
      { "server-policy", g_policy.getLocal()->getName()}
    };

    addStatsToJSONObject(obj);

    Json my_json = obj;
    resp.body = my_json.dump();
    resp.headers["Content-Type"] = "application/json";
  }
  else if (command == "dynblocklist") {
    Json::object obj;
#ifndef DISABLE_DYNBLOCKS
    auto nmg = g_dynblockNMG.getLocal();
    struct timespec now;
    gettime(&now);
    for (const auto& entry: *nmg) {
      if (!(now < entry.second.until)) {
        continue;
      }
      uint64_t counter = entry.second.blocks;
      if (entry.second.bpf && g_defaultBPFFilter) {
        counter += g_defaultBPFFilter->getHits(entry.first.getNetwork());
      }
      Json::object thing{
        {"reason", entry.second.reason},
        {"seconds", static_cast<double>(entry.second.until.tv_sec - now.tv_sec)},
        {"blocks", static_cast<double>(counter)},
        {"action", DNSAction::typeToString(entry.second.action != DNSAction::Action::None ? entry.second.action : g_dynBlockAction)},
        {"warning", entry.second.warning},
        {"ebpf", entry.second.bpf}
      };
      obj.emplace(entry.first.toString(), thing);
    }

    auto smt = g_dynblockSMT.getLocal();
    smt->visit([&now,&obj](const SuffixMatchTree<DynBlock>& node) {
      if (!(now < node.d_value.until)) {
        return;
      }
      string dom("empty");
      if (!node.d_value.domain.empty()) {
        dom = node.d_value.domain.toString();
      }
      Json::object thing{
        {"reason", node.d_value.reason},
        {"seconds", static_cast<double>(node.d_value.until.tv_sec - now.tv_sec)},
        {"blocks", static_cast<double>(node.d_value.blocks)},
        {"action", DNSAction::typeToString(node.d_value.action != DNSAction::Action::None ? node.d_value.action : g_dynBlockAction)},
        {"ebpf", node.d_value.bpf}
      };
      obj.emplace(dom, thing);
    });
#endif /* DISABLE_DYNBLOCKS */
    Json my_json = obj;
    resp.body = my_json.dump();
    resp.headers["Content-Type"] = "application/json";
  }
  else if (command == "ebpfblocklist") {
    Json::object obj;
#ifdef HAVE_EBPF
    struct timespec now;
    gettime(&now);
    for (const auto& dynbpf : g_dynBPFFilters) {
      std::vector<std::tuple<ComboAddress, uint64_t, struct timespec> > addrStats = dynbpf->getAddrStats();
      for (const auto& entry : addrStats) {
        Json::object thing
          {
            {"seconds", (double)(std::get<2>(entry).tv_sec - now.tv_sec)},
            {"blocks", (double)(std::get<1>(entry))}
          };
        obj.emplace(std::get<0>(entry).toString(), thing );
      }
    }
    if (g_defaultBPFFilter) {
      auto nmg = g_dynblockNMG.getLocal();
      for (const auto& entry: *nmg) {
        if (!(now < entry.second.until) || !entry.second.bpf) {
          continue;
        }
        uint64_t counter = entry.second.blocks + g_defaultBPFFilter->getHits(entry.first.getNetwork());
        Json::object thing{
          {"reason", entry.second.reason},
          {"seconds", static_cast<double>(entry.second.until.tv_sec - now.tv_sec)},
          {"blocks", static_cast<double>(counter)},
          {"action", DNSAction::typeToString(entry.second.action != DNSAction::Action::None ? entry.second.action : g_dynBlockAction)},
          {"warning", entry.second.warning},
        };
        obj.emplace(entry.first.toString(), thing);
      }
    }
#endif /* HAVE_EBPF */
    Json my_json = obj;
    resp.body = my_json.dump();
    resp.headers["Content-Type"] = "application/json";
  }
  else {
    resp.status = 404;
  }
}
#endif /* DISABLE_BUILTIN_HTML */

static void addServerToJSON(Json::array& servers, int id, const std::shared_ptr<DownstreamState>& a)
{
  string status;
  if (a->d_config.availability == DownstreamState::Availability::Up) {
    status = "UP";
  }
  else if (a->d_config.availability == DownstreamState::Availability::Down) {
    status = "DOWN";
  }
  else {
    status = (a->upStatus ? "up" : "down");
  }

  Json::array pools;
  pools.reserve(a->d_config.pools.size());
  for (const auto& p: a->d_config.pools) {
    pools.push_back(p);
  }

  Json::object server {
    {"id", id},
    {"name", a->getName()},
    {"address", a->d_config.remote.toStringWithPort()},
    {"state", status},
    {"protocol", a->getProtocol().toPrettyString()},
    {"qps", (double)a->queryLoad},
    {"qpsLimit", (double)a->qps.getRate()},
    {"outstanding", (double)a->outstanding},
    {"reuseds", (double)a->reuseds},
    {"weight", (double)a->d_config.d_weight},
    {"order", (double)a->d_config.order},
    {"pools", std::move(pools)},
    {"latency", (double)(a->latencyUsec/1000.0)},
    {"queries", (double)a->queries},
    {"responses", (double)a->responses},
    {"nonCompliantResponses", (double)a->nonCompliantResponses},
    {"sendErrors", (double)a->sendErrors},
    {"tcpDiedSendingQuery", (double)a->tcpDiedSendingQuery},
    {"tcpDiedReadingResponse", (double)a->tcpDiedReadingResponse},
    {"tcpGaveUp", (double)a->tcpGaveUp},
    {"tcpConnectTimeouts", (double)a->tcpConnectTimeouts},
    {"tcpReadTimeouts", (double)a->tcpReadTimeouts},
    {"tcpWriteTimeouts", (double)a->tcpWriteTimeouts},
    {"tcpCurrentConnections", (double)a->tcpCurrentConnections},
    {"tcpMaxConcurrentConnections", (double)a->tcpMaxConcurrentConnections},
    {"tcpTooManyConcurrentConnections", (double)a->tcpTooManyConcurrentConnections},
    {"tcpNewConnections", (double)a->tcpNewConnections},
    {"tcpReusedConnections", (double)a->tcpReusedConnections},
    {"tcpAvgQueriesPerConnection", (double)a->tcpAvgQueriesPerConnection},
    {"tcpAvgConnectionDuration", (double)a->tcpAvgConnectionDuration},
    {"tlsResumptions", (double)a->tlsResumptions},
    {"tcpLatency", (double)(a->latencyUsecTCP/1000.0)},
    {"healthCheckFailures", (double)(a->d_healthCheckMetrics.d_failures)},
    {"healthCheckFailuresParsing", (double)(a->d_healthCheckMetrics.d_parseErrors)},
    {"healthCheckFailuresTimeout", (double)(a->d_healthCheckMetrics.d_timeOuts)},
    {"healthCheckFailuresNetwork", (double)(a->d_healthCheckMetrics.d_networkErrors)},
    {"healthCheckFailuresMismatch", (double)(a->d_healthCheckMetrics.d_mismatchErrors)},
    {"healthCheckFailuresInvalid", (double)(a->d_healthCheckMetrics.d_invalidResponseErrors)},
    {"dropRate", (double)a->dropRate}
  };

  /* sending a latency for a DOWN server doesn't make sense */
  if (a->d_config.availability == DownstreamState::Availability::Down) {
    server["latency"] = nullptr;
    server["tcpLatency"] = nullptr;
  }

  servers.push_back(std::move(server));
}

static void handleStats(const YaHTTP::Request& req, YaHTTP::Response& resp)
{
  handleCORS(req, resp);
  resp.status = 200;

  int num = 0;

  Json::array servers;
  {
    auto localServers = g_dstates.getLocal();
    servers.reserve(localServers->size());
    for (const auto& a : *localServers) {
      addServerToJSON(servers, num++, a);
    }
  }

  Json::array frontends;
  num = 0;
  frontends.reserve(g_frontends.size());
  for (const auto& front : g_frontends) {
    if (front->udpFD == -1 && front->tcpFD == -1)
      continue;
    Json::object frontend {
      { "id", num++ },
      { "address", front->local.toStringWithPort() },
      { "udp", front->udpFD >= 0 },
      { "tcp", front->tcpFD >= 0 },
      { "type", front->getType() },
      { "queries", (double) front->queries.load() },
      { "nonCompliantQueries", (double) front->nonCompliantQueries.load() },
      { "responses", (double) front->responses.load() },
      { "tcpDiedReadingQuery", (double) front->tcpDiedReadingQuery.load() },
      { "tcpDiedSendingResponse", (double) front->tcpDiedSendingResponse.load() },
      { "tcpGaveUp", (double) front->tcpGaveUp.load() },
      { "tcpClientTimeouts", (double) front->tcpClientTimeouts },
      { "tcpDownstreamTimeouts", (double) front->tcpDownstreamTimeouts },
      { "tcpCurrentConnections", (double) front->tcpCurrentConnections },
      { "tcpMaxConcurrentConnections", (double) front->tcpMaxConcurrentConnections },
      { "tcpAvgQueriesPerConnection", (double) front->tcpAvgQueriesPerConnection },
      { "tcpAvgConnectionDuration", (double) front->tcpAvgConnectionDuration },
      { "tlsNewSessions", (double) front->tlsNewSessions },
      { "tlsResumptions", (double) front->tlsResumptions },
      { "tlsUnknownTicketKey", (double) front->tlsUnknownTicketKey },
      { "tlsInactiveTicketKey", (double) front->tlsInactiveTicketKey },
      { "tls10Queries", (double) front->tls10queries },
      { "tls11Queries", (double) front->tls11queries },
      { "tls12Queries", (double) front->tls12queries },
      { "tls13Queries", (double) front->tls13queries },
      { "tlsUnknownQueries", (double) front->tlsUnknownqueries },
    };
    const TLSErrorCounters* errorCounters = nullptr;
    if (front->tlsFrontend != nullptr) {
      errorCounters = &front->tlsFrontend->d_tlsCounters;
    }
    else if (front->dohFrontend != nullptr) {
      errorCounters = &front->dohFrontend->d_tlsCounters;
    }
    if (errorCounters != nullptr) {
      frontend["tlsHandshakeFailuresDHKeyTooSmall"] = (double)errorCounters->d_dhKeyTooSmall;
      frontend["tlsHandshakeFailuresInappropriateFallBack"] = (double)errorCounters->d_inappropriateFallBack;
      frontend["tlsHandshakeFailuresNoSharedCipher"] = (double)errorCounters->d_noSharedCipher;
      frontend["tlsHandshakeFailuresUnknownCipher"] = (double)errorCounters->d_unknownCipherType;
      frontend["tlsHandshakeFailuresUnknownKeyExchangeType"] = (double)errorCounters->d_unknownKeyExchangeType;
      frontend["tlsHandshakeFailuresUnknownProtocol"] = (double)errorCounters->d_unknownProtocol;
      frontend["tlsHandshakeFailuresUnsupportedEC"] = (double)errorCounters->d_unsupportedEC;
      frontend["tlsHandshakeFailuresUnsupportedProtocol"] = (double)errorCounters->d_unsupportedProtocol;
    }
    frontends.push_back(std::move(frontend));
  }

  Json::array dohs;
#ifdef HAVE_DNS_OVER_HTTPS
  {
    dohs.reserve(g_dohlocals.size());
    num = 0;
    for (const auto& doh : g_dohlocals) {
      dohs.emplace_back(Json::object{
        { "id", num++ },
        { "address", doh->d_local.toStringWithPort() },
        { "http-connects", (double) doh->d_httpconnects },
        { "http1-queries", (double) doh->d_http1Stats.d_nbQueries },
        { "http2-queries", (double) doh->d_http2Stats.d_nbQueries },
        { "http1-200-responses", (double) doh->d_http1Stats.d_nb200Responses },
        { "http2-200-responses", (double) doh->d_http2Stats.d_nb200Responses },
        { "http1-400-responses", (double) doh->d_http1Stats.d_nb400Responses },
        { "http2-400-responses", (double) doh->d_http2Stats.d_nb400Responses },
        { "http1-403-responses", (double) doh->d_http1Stats.d_nb403Responses },
        { "http2-403-responses", (double) doh->d_http2Stats.d_nb403Responses },
        { "http1-500-responses", (double) doh->d_http1Stats.d_nb500Responses },
        { "http2-500-responses", (double) doh->d_http2Stats.d_nb500Responses },
        { "http1-502-responses", (double) doh->d_http1Stats.d_nb502Responses },
        { "http2-502-responses", (double) doh->d_http2Stats.d_nb502Responses },
        { "http1-other-responses", (double) doh->d_http1Stats.d_nbOtherResponses },
        { "http2-other-responses", (double) doh->d_http2Stats.d_nbOtherResponses },
        { "get-queries", (double) doh->d_getqueries },
        { "post-queries", (double) doh->d_postqueries },
        { "bad-requests", (double) doh->d_badrequests },
        { "error-responses", (double) doh->d_errorresponses },
        { "redirect-responses", (double) doh->d_redirectresponses },
        { "valid-responses", (double) doh->d_validresponses }
      });
    }
  }
#endif /* HAVE_DNS_OVER_HTTPS */

  Json::array pools;
  {
    auto localPools = g_pools.getLocal();
    num = 0;
    pools.reserve(localPools->size());
    for (const auto& pool : *localPools) {
      const auto& cache = pool.second->packetCache;
      Json::object entry {
        { "id", num++ },
        { "name", pool.first },
        { "serversCount", (double) pool.second->countServers(false) },
        { "cacheSize", (double) (cache ? cache->getMaxEntries() : 0) },
        { "cacheEntries", (double) (cache ? cache->getEntriesCount() : 0) },
        { "cacheHits", (double) (cache ? cache->getHits() : 0) },
        { "cacheMisses", (double) (cache ? cache->getMisses() : 0) },
        { "cacheDeferredInserts", (double) (cache ? cache->getDeferredInserts() : 0) },
        { "cacheDeferredLookups", (double) (cache ? cache->getDeferredLookups() : 0) },
        { "cacheLookupCollisions", (double) (cache ? cache->getLookupCollisions() : 0) },
        { "cacheInsertCollisions", (double) (cache ? cache->getInsertCollisions() : 0) },
        { "cacheTTLTooShorts", (double) (cache ? cache->getTTLTooShorts() : 0) },
        { "cacheCleanupCount", (double) (cache ? cache->getCleanupCount() : 0) }
      };
      pools.push_back(std::move(entry));
    }
  }

  Json::array rules;
  /* unfortunately DNSActions have getStats(),
     and DNSResponseActions do not. */
  {
    auto localRules = g_ruleactions.getLocal();
    num = 0;
    rules.reserve(localRules->size());
    for (const auto& a : *localRules) {
      Json::object rule{
        {"id", num++},
        {"creationOrder", (double)a.d_creationOrder},
        {"uuid", boost::uuids::to_string(a.d_id)},
        {"matches", (double)a.d_rule->d_matches},
        {"rule", a.d_rule->toString()},
        {"action", a.d_action->toString()},
        {"action-stats", a.d_action->getStats()}
      };
      rules.push_back(std::move(rule));
    }
  }
  auto responseRules = someResponseRulesToJson(&g_respruleactions);
  auto cacheHitResponseRules = someResponseRulesToJson(&g_cachehitrespruleactions);
  auto cacheInsertedResponseRules = someResponseRulesToJson(&g_cacheInsertedRespRuleActions);
  auto selfAnsweredResponseRules = someResponseRulesToJson(&g_selfansweredrespruleactions);

  string acl;
  {
    vector<string> vec;
    g_ACL.getLocal()->toStringVector(&vec);

    for (const auto& s : vec) {
      if (!acl.empty()) {
        acl += ", ";
      }
      acl += s;
    }
  }

  string localaddressesStr;
  {
    std::set<std::string> localaddresses;
    for (const auto& front : g_frontends) {
      localaddresses.insert(front->local.toStringWithPort());
    }
    for (const auto& addr : localaddresses) {
      if (!localaddressesStr.empty()) {
        localaddressesStr += ", ";
      }
      localaddressesStr += addr;
    }
  }

  Json::object stats;
  addStatsToJSONObject(stats);

  Json responseObject(Json::object({
    { "daemon_type", "dnsdist" },
    { "version", VERSION },
    { "servers", std::move(servers) },
    { "frontends", std::move(frontends) },
    { "pools", std::move(pools) },
    { "rules", std::move(rules) },
    { "response-rules", std::move(responseRules) },
    { "cache-hit-response-rules", std::move(cacheHitResponseRules) },
    { "cache-inserted-response-rules", std::move(cacheInsertedResponseRules) },
    { "self-answered-response-rules", std::move(selfAnsweredResponseRules) },
    { "acl", std::move(acl) },
    { "local", std::move(localaddressesStr) },
    { "dohFrontends", std::move(dohs) },
    { "statistics", std::move(stats) }
        }));

  resp.headers["Content-Type"] = "application/json";
  resp.body = responseObject.dump();
}

static void handlePoolStats(const YaHTTP::Request& req, YaHTTP::Response& resp)
{
  handleCORS(req, resp);
  const auto poolName = req.getvars.find("name");
  if (poolName == req.getvars.end()) {
    resp.status = 400;
    return;
  }

  resp.status = 200;
  Json::array doc;

  auto localPools = g_pools.getLocal();
  const auto poolIt = localPools->find(poolName->second);
  if (poolIt == localPools->end()) {
    resp.status = 404;
    return;
  }

  const auto& pool = poolIt->second;
  const auto& cache = pool->packetCache;
  Json::object entry {
    { "name", poolName->second },
    { "serversCount", (double) pool->countServers(false) },
    { "cacheSize", (double) (cache ? cache->getMaxEntries() : 0) },
    { "cacheEntries", (double) (cache ? cache->getEntriesCount() : 0) },
    { "cacheHits", (double) (cache ? cache->getHits() : 0) },
    { "cacheMisses", (double) (cache ? cache->getMisses() : 0) },
    { "cacheDeferredInserts", (double) (cache ? cache->getDeferredInserts() : 0) },
    { "cacheDeferredLookups", (double) (cache ? cache->getDeferredLookups() : 0) },
    { "cacheLookupCollisions", (double) (cache ? cache->getLookupCollisions() : 0) },
    { "cacheInsertCollisions", (double) (cache ? cache->getInsertCollisions() : 0) },
    { "cacheTTLTooShorts", (double) (cache ? cache->getTTLTooShorts() : 0) },
    { "cacheCleanupCount", (double) (cache ? cache->getCleanupCount() : 0) }
  };

  Json::array servers;
  int num = 0;
  for (const auto& a : *pool->getServers()) {
    addServerToJSON(servers, num, a.second);
    num++;
  }

  resp.headers["Content-Type"] = "application/json";
  Json my_json = Json::object {
    { "stats", entry },
    { "servers", servers }
  };

  resp.body = my_json.dump();
}

static void handleStatsOnly(const YaHTTP::Request& req, YaHTTP::Response& resp)
{
  handleCORS(req, resp);
  resp.status = 200;

  Json::array doc;
  {
    auto entries = g_stats.entries.read_lock();
    for (const auto& item : *entries) {
      if (item.d_name == "special-memory-usage") {
        continue; // Too expensive for get-all
      }

      if (const auto& val = boost::get<pdns::stat_t*>(&item.d_value)) {
        doc.push_back(Json::object {
            { "type", "StatisticItem" },
            { "name", item.d_name },
            { "value", (double)(*val)->load() }
          });
      }
      else if (const auto& adval = boost::get<pdns::stat_t_trait<double>*>(&item.d_value)) {
        doc.push_back(Json::object {
            { "type", "StatisticItem" },
            { "name", item.d_name },
            { "value", (*adval)->load() }
          });
      }
      else if (const auto& dval = boost::get<double*>(&item.d_value)) {
        doc.push_back(Json::object {
            { "type", "StatisticItem" },
            { "name", item.d_name },
            { "value", (**dval) }
          });
      }
      else if (const auto& func = boost::get<DNSDistStats::statfunction_t>(&item.d_value)) {
        doc.push_back(Json::object {
            { "type", "StatisticItem" },
            { "name", item.d_name },
            { "value", (double)(*func)(item.d_name) }
          });
      }
    }
  }
  Json my_json = doc;
  resp.body = my_json.dump();
  resp.headers["Content-Type"] = "application/json";
}

#ifndef DISABLE_WEB_CONFIG
static void handleConfigDump(const YaHTTP::Request& req, YaHTTP::Response& resp)
{
  handleCORS(req, resp);
  resp.status = 200;

  Json::array doc;
  typedef boost::variant<bool, double, std::string> configentry_t;
  std::vector<std::pair<std::string, configentry_t> > configEntries {
    { "acl", g_ACL.getLocal()->toString() },
    { "allow-empty-response", g_allowEmptyResponse },
    { "control-socket", g_serverControl.toStringWithPort() },
    { "ecs-override", g_ECSOverride },
    { "ecs-source-prefix-v4", (double) g_ECSSourcePrefixV4 },
    { "ecs-source-prefix-v6", (double)  g_ECSSourcePrefixV6 },
    { "fixup-case", g_fixupCase },
    { "max-outstanding", (double) g_maxOutstanding },
    { "server-policy", g_policy.getLocal()->getName() },
    { "stale-cache-entries-ttl", (double) g_staleCacheEntriesTTL },
    { "tcp-recv-timeout", (double) g_tcpRecvTimeout },
    { "tcp-send-timeout", (double) g_tcpSendTimeout },
    { "truncate-tc", g_truncateTC },
    { "verbose", g_verbose },
    { "verbose-health-checks", g_verboseHealthChecks }
  };
  for(const auto& item : configEntries) {
    if (const auto& bval = boost::get<bool>(&item.second)) {
      doc.push_back(Json::object {
          { "type", "ConfigSetting" },
          { "name", item.first },
          { "value", *bval }
        });
    }
    else if (const auto& sval = boost::get<string>(&item.second)) {
      doc.push_back(Json::object {
          { "type", "ConfigSetting" },
          { "name", item.first },
          { "value", *sval }
        });
    }
    else if (const auto& dval = boost::get<double>(&item.second)) {
      doc.push_back(Json::object {
          { "type", "ConfigSetting" },
          { "name", item.first },
          { "value", *dval }
        });
    }
  }
  Json my_json = doc;
  resp.body = my_json.dump();
  resp.headers["Content-Type"] = "application/json";
}

static void handleAllowFrom(const YaHTTP::Request& req, YaHTTP::Response& resp)
{
  handleCORS(req, resp);

  resp.headers["Content-Type"] = "application/json";
  resp.status = 200;

  if (req.method == "PUT") {
    std::string err;
    Json doc = Json::parse(req.body, err);

    if (!doc.is_null()) {
      NetmaskGroup nmg;
      auto aclList = doc["value"];
      if (aclList.is_array()) {

        for (const auto& value : aclList.array_items()) {
          try {
            nmg.addMask(value.string_value());
          } catch (NetmaskException &e) {
            resp.status = 400;
            break;
          }
        }

        if (resp.status == 200) {
          infolog("Updating the ACL via the API to %s", nmg.toString());
          g_ACL.setState(nmg);
          apiSaveACL(nmg);
        }
      }
      else {
        resp.status = 400;
      }
    }
    else {
      resp.status = 400;
    }
  }
  if (resp.status == 200) {
    Json::array acl;
    vector<string> vec;
    g_ACL.getLocal()->toStringVector(&vec);

    for(const auto& s : vec) {
      acl.push_back(s);
    }

    Json::object obj{
      { "type", "ConfigSetting" },
      { "name", "allow-from" },
      { "value", acl }
    };
    Json my_json = obj;
    resp.body = my_json.dump();
  }
}
#endif /* DISABLE_WEB_CONFIG */

#ifndef DISABLE_WEB_CACHE_MANAGEMENT
static void handleCacheManagement(const YaHTTP::Request& req, YaHTTP::Response& resp)
{
  handleCORS(req, resp);

  resp.headers["Content-Type"] = "application/json";
  resp.status = 200;

  if (req.method != "DELETE") {
    resp.status = 400;
    Json::object obj{
      { "status", "denied" },
      { "error", "invalid method" }
    };
    resp.body = Json(obj).dump();
    return;
  }

  const auto poolName = req.getvars.find("pool");
  const auto expungeName = req.getvars.find("name");
  const auto expungeType = req.getvars.find("type");
  const auto suffix = req.getvars.find("suffix");
  if (poolName == req.getvars.end() || expungeName == req.getvars.end()) {
    resp.status = 400;
    Json::object obj{
      { "status", "denied" },
      { "error", "missing 'pool' or 'name' parameter" },
    };
    resp.body = Json(obj).dump();
    return;
  }

  DNSName name;
  QType type(QType::ANY);
  try {
    name = DNSName(expungeName->second);
  }
  catch (const std::exception& e) {
    resp.status = 400;
    Json::object obj{
      { "status", "error" },
      { "error", "unable to parse the requested name" },
    };
    resp.body = Json(obj).dump();
    return;
  }
  if (expungeType != req.getvars.end()) {
    type = QType::chartocode(expungeType->second.c_str());
  }

  std::shared_ptr<ServerPool> pool;
  try {
    pool = getPool(g_pools.getCopy(), poolName->second);
  }
  catch (const std::exception& e) {
    resp.status = 404;
    Json::object obj{
      { "status", "not found" },
      { "error", "the requested pool does not exist" },
    };
    resp.body = Json(obj).dump();
    return;
  }

  auto cache = pool->getCache();
  if (cache == nullptr) {
    resp.status = 404;
    Json::object obj{
      { "status", "not found" },
      { "error", "there is no cache associated with the requested pool" },
    };
    resp.body = Json(obj).dump();
    return;
  }

  auto removed = cache->expungeByName(name, type.getCode(), suffix != req.getvars.end());

  Json::object obj{
      { "status", "purged" },
      { "count", std::to_string(removed) }
    };
  resp.body = Json(obj).dump();
}
#endif /* DISABLE_WEB_CACHE_MANAGEMENT */

static std::unordered_map<std::string, std::function<void(const YaHTTP::Request&, YaHTTP::Response&)>> s_webHandlers;

void registerWebHandler(const std::string& endpoint, std::function<void(const YaHTTP::Request&, YaHTTP::Response&)> handler);

void registerWebHandler(const std::string& endpoint, std::function<void(const YaHTTP::Request&, YaHTTP::Response&)> handler)
{
  s_webHandlers[endpoint] = handler;
}

void clearWebHandlers()
{
  s_webHandlers.clear();
}

#ifndef DISABLE_BUILTIN_HTML
#include "htmlfiles.h"

static void redirectToIndex(const YaHTTP::Request& req, YaHTTP::Response& resp)
{
  const string charset = "; charset=utf-8";
  resp.body.assign(s_urlmap.at("index.html"));
  resp.headers["Content-Type"] = "text/html" + charset;
  resp.status = 200;
}

static void handleBuiltInFiles(const YaHTTP::Request& req, YaHTTP::Response& resp)
{
  if (req.url.path.empty() || !s_urlmap.count(req.url.path.c_str()+1)) {
    resp.status = 404;
    return;
  }

  resp.body.assign(s_urlmap.at(req.url.path.c_str()+1));

  vector<string> parts;
  stringtok(parts, req.url.path, ".");
  static const std::unordered_map<std::string, std::string> contentTypeMap = {
    { "html", "text/html" },
    { "css", "text/css" },
    { "js", "application/javascript" },
    { "png", "image/png" },
  };

  const auto& it = contentTypeMap.find(parts.back());
  if (it != contentTypeMap.end()) {
    const string charset = "; charset=utf-8";
    resp.headers["Content-Type"] = it->second + charset;
  }

  resp.status = 200;
}
#endif /* DISABLE_BUILTIN_HTML */

void registerBuiltInWebHandlers()
{
#ifndef DISABLE_BUILTIN_HTML
  registerWebHandler("/jsonstat", handleJSONStats);
#endif /* DISABLE_BUILTIN_HTML */
#ifndef DISABLE_PROMETHEUS
  registerWebHandler("/metrics", handlePrometheus);
#endif /* DISABLE_PROMETHEUS */
  registerWebHandler("/api/v1/servers/localhost", handleStats);
  registerWebHandler("/api/v1/servers/localhost/pool", handlePoolStats);
  registerWebHandler("/api/v1/servers/localhost/statistics", handleStatsOnly);
#ifndef DISABLE_WEB_CONFIG
  registerWebHandler("/api/v1/servers/localhost/config", handleConfigDump);
  registerWebHandler("/api/v1/servers/localhost/config/allow-from", handleAllowFrom);
#endif /* DISABLE_WEB_CONFIG */
#ifndef DISABLE_WEB_CACHE_MANAGEMENT
  registerWebHandler("/api/v1/cache", handleCacheManagement);
#endif /* DISABLE_WEB_CACHE_MANAGEMENT */
#ifndef DISABLE_BUILTIN_HTML
  registerWebHandler("/", redirectToIndex);

  for (const auto& path : s_urlmap) {
    registerWebHandler("/" + path.first, handleBuiltInFiles);
  }
#endif /* DISABLE_BUILTIN_HTML */
}

static void connectionThread(WebClientConnection&& conn)
{
  setThreadName("dnsdist/webConn");

  vinfolog("Webserver handling connection from %s", conn.getClient().toStringWithPort());

  try {
    YaHTTP::AsyncRequestLoader yarl;
    YaHTTP::Request req;
    bool finished = false;

    yarl.initialize(&req);
    while (!finished) {
      int bytes;
      char buf[1024];
      bytes = read(conn.getSocket().getHandle(), buf, sizeof(buf));
      if (bytes > 0) {
        string data = string(buf, bytes);
        finished = yarl.feed(data);
      } else {
        // read error OR EOF
        break;
      }
    }
    yarl.finalize();

    req.getvars.erase("_"); // jQuery cache buster

    YaHTTP::Response resp;
    resp.version = req.version;

    {
      auto config = g_webserverConfig.lock();

      addCustomHeaders(resp, config->customHeaders);
      addSecurityHeaders(resp, config->customHeaders);
    }
    /* indicate that the connection will be closed after completion of the response */
    resp.headers["Connection"] = "close";

    /* no need to send back the API key if any */
    resp.headers.erase("X-API-Key");

    if (req.method == "OPTIONS") {
      /* the OPTIONS method should not require auth, otherwise it breaks CORS */
      handleCORS(req, resp);
      resp.status = 200;
    }
    else if (!handleAuthorization(req)) {
      YaHTTP::strstr_map_t::iterator header = req.headers.find("authorization");
      if (header != req.headers.end()) {
        vinfolog("HTTP Request \"%s\" from %s: Web Authentication failed", req.url.path, conn.getClient().toStringWithPort());
      }
      resp.status = 401;
      resp.body = "<h1>Unauthorized</h1>";
      resp.headers["WWW-Authenticate"] = "basic realm=\"PowerDNS\"";
    }
    else if (!isMethodAllowed(req)) {
      resp.status = 405;
    }
    else {
      const auto it = s_webHandlers.find(req.url.path);
      if (it != s_webHandlers.end()) {
        it->second(req, resp);
      }
      else {
        resp.status = 404;
      }
    }

    std::ostringstream ofs;
    ofs << resp;
    string done = ofs.str();
    writen2(conn.getSocket().getHandle(), done.c_str(), done.size());
  }
  catch (const YaHTTP::ParseError& e) {
    vinfolog("Webserver thread died with parse error exception while processing a request from %s: %s", conn.getClient().toStringWithPort(), e.what());
  }
  catch (const std::exception& e) {
    errlog("Webserver thread died with exception while processing a request from %s: %s", conn.getClient().toStringWithPort(), e.what());
  }
  catch (...) {
    errlog("Webserver thread died with exception while processing a request from %s", conn.getClient().toStringWithPort());
  }
}

void setWebserverAPIKey(std::unique_ptr<CredentialsHolder>&& apiKey)
{
  auto config = g_webserverConfig.lock();

  if (apiKey) {
    config->apiKey = std::move(apiKey);
  } else {
    config->apiKey.reset();
  }
}

void setWebserverPassword(std::unique_ptr<CredentialsHolder>&& password)
{
  g_webserverConfig.lock()->password = std::move(password);
}

void setWebserverACL(const std::string& acl)
{
  NetmaskGroup newACL;
  newACL.toMasks(acl);

  g_webserverConfig.lock()->acl = std::move(newACL);
}

void setWebserverCustomHeaders(const boost::optional<std::unordered_map<std::string, std::string> > customHeaders)
{
  g_webserverConfig.lock()->customHeaders = customHeaders;
}

void setWebserverStatsRequireAuthentication(bool require)
{
  g_webserverConfig.lock()->statsRequireAuthentication = require;
}

void setWebserverAPIRequiresAuthentication(bool require)
{
  g_webserverConfig.lock()->apiRequiresAuthentication = require;
}

void setWebserverDashboardRequiresAuthentication(bool require)
{
  g_webserverConfig.lock()->dashboardRequiresAuthentication = require;
}

void setWebserverMaxConcurrentConnections(size_t max)
{
  s_connManager.setMaxConcurrentConnections(max);
}

void dnsdistWebserverThread(int sock, const ComboAddress& local)
{
  setThreadName("dnsdist/webserv");
  infolog("Webserver launched on %s", local.toStringWithPort());

  {
    auto config = g_webserverConfig.lock();
    if (!config->password && config->dashboardRequiresAuthentication) {
      warnlog("Webserver launched on %s without a password set!", local.toStringWithPort());
    }
  }

  for (;;) {
    try {
      ComboAddress remote(local);
      int fd = SAccept(sock, remote);

      if (!isClientAllowedByACL(remote)) {
        vinfolog("Connection to webserver from client %s is not allowed, closing", remote.toStringWithPort());
        close(fd);
        continue;
      }

      WebClientConnection conn(remote, fd);
      vinfolog("Got a connection to the webserver from %s", remote.toStringWithPort());

      std::thread t(connectionThread, std::move(conn));
      t.detach();
    }
    catch (const std::exception& e) {
      errlog("Had an error accepting new webserver connection: %s", e.what());
    }
  }
}
