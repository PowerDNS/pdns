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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <cstdio>
#include <csignal>
#include <cstring>
#include <cstdlib>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <cerrno>
#include <pthread.h>
#include <thread>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <fstream>
#include <boost/algorithm/string.hpp>
#ifdef HAVE_LIBSODIUM
#include <sodium.h>
#endif
#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif

#include "auth-main.hh"
#include "coverage.hh"
#include "secpoll-auth.hh"
#include "dynhandler.hh"
#include "dnsseckeeper.hh"
#include "threadname.hh"
#include "misc.hh"
#include "query-local-address.hh"
#include "trusted-notification-proxy.hh"
#include "packetcache.hh"
#include "packethandler.hh"
#include "opensslsigners.hh"
#include "dns.hh"
#include "dnsbackend.hh"
#include "ueberbackend.hh"
#include "dnspacket.hh"
#include "nameserver.hh"
#include "distributor.hh"
#include "logger.hh"
#include "arguments.hh"
#include "packethandler.hh"
#include "statbag.hh"
#include "tcpreceiver.hh"
#include "misc.hh"
#include "dynlistener.hh"
#include "dynhandler.hh"
#include "communicator.hh"
#include "dnsproxy.hh"
#include "utility.hh"
#include "dnsrecords.hh"
#include "version.hh"
#include "ws-auth.hh"

#ifdef HAVE_LUA_RECORDS
#include "minicurl.hh"
#endif /* HAVE_LUA_RECORDS */

time_t g_starttime;

string g_programname = "pdns"; // used in packethandler.cc

const char* funnytext = "*****************************************************************************\n"
                        "Ok, you just ran pdns-auth through 'strings' hoping to find funny messages.  \n"
                        "Well, you found one.                                                         \n"
                        "Two ions are flying through their particle accelerator, says the one to the  \n"
                        "other 'I think I've lost an electron!'                                       \n"
                        "So the other one says, 'Are you sure?'. 'YEAH! I'M POSITIVE!'                \n"
                        "                                                                             \n"
                        "                                            the pdns crew - pdns@powerdns.com\n"
                        "*****************************************************************************\n";

bool g_anyToTcp;
bool g_8bitDNS;
#ifdef HAVE_LUA_RECORDS
bool g_doLuaRecord;
int g_luaRecordExecLimit;
time_t g_luaHealthChecksInterval{5};
time_t g_luaHealthChecksExpireDelay{3600};
time_t g_luaConsistentHashesExpireDelay{86400};
time_t g_luaConsistentHashesCleanupInterval{3600};
#endif
#ifdef ENABLE_GSS_TSIG
bool g_doGssTSIG;
#endif
bool g_views;
typedef Distributor<DNSPacket, DNSPacket, PacketHandler> DNSDistributor;

ArgvMap theArg;
StatBag S; //!< Statistics are gathered across PDNS via the StatBag class S
AuthPacketCache PC; //!< This is the main PacketCache, shared across all threads
AuthQueryCache QC;
AuthZoneCache g_zoneCache;
std::vector<std::unique_ptr<RemoteLogger>> g_remote_loggers;

std::unique_ptr<DNSProxy> DP{nullptr};
static std::unique_ptr<DynListener> s_dynListener{nullptr};
CommunicatorClass Communicator;
static std::atomic<double> avg_latency{0.0}, receive_latency{0.0}, cache_latency{0.0}, backend_latency{0.0}, send_latency{0.0};
static unique_ptr<TCPNameserver> s_tcpNameserver{nullptr};
static vector<DNSDistributor*> s_distributors;
static shared_ptr<UDPNameserver> s_udpNameserver{nullptr};
static vector<std::shared_ptr<UDPNameserver>> s_udpReceivers;
NetmaskGroup g_proxyProtocolACL;
size_t g_proxyProtocolMaximumSize;

ArgvMap& arg()
{
  return theArg;
}

static void declareArguments()
{
  ::arg().set("config-dir", "Location of configuration directory (pdns.conf)") = SYSCONFDIR;
  ::arg().set("config-name", "Name of this virtual configuration - will rename the binary image") = "";
  ::arg().set("socket-dir", string("Where the controlsocket will live, ") + LOCALSTATEDIR + "/pdns when unset and not chrooted"
#ifdef HAVE_SYSTEMD
                + ". Set to the RUNTIME_DIRECTORY environment variable when that variable has a value (e.g. under systemd).")
    = "";
  auto runtimeDir = getenv("RUNTIME_DIRECTORY");
  if (runtimeDir != nullptr) {
    ::arg().set("socket-dir") = runtimeDir;
  }
#else
              )
    = "";
#endif
  ::arg().set("module-dir", "Default directory for modules") = PKGLIBDIR;
  ::arg().set("chroot", "If set, chroot to this directory for more security") = "";
  ::arg().set("logging-facility", "Log under a specific facility") = "";
  ::arg().set("daemon", "Operate as a daemon") = "no";

  ::arg().set("local-port", "The port on which we listen") = "53";
  ::arg().setSwitch("dnsupdate", "Enable/Disable DNS update (RFC2136) support. Default is no.") = "no";
  ::arg().setSwitch("write-pid", "Write a PID file") = "yes";
  ::arg().set("allow-dnsupdate-from", "A global setting to allow DNS updates from these IP ranges.") = "127.0.0.0/8,::1";
  ::arg().setSwitch("dnsupdate-require-tsig", "Require TSIG secured DNS updates. Default is no.") = "no";
  ::arg().set("proxy-protocol-from", "A Proxy Protocol header is only allowed from these subnets, and is mandatory then too.") = "";
  ::arg().set("proxy-protocol-maximum-size", "The maximum size of a proxy protocol payload, including the TLV values") = "512";
  ::arg().setSwitch("send-signed-notify", "Send TSIG secured NOTIFY if TSIG key is configured for a zone") = "yes";
  ::arg().set("allow-unsigned-notify", "Allow unsigned notifications for TSIG secured zones") = "yes"; // FIXME: change to 'no' later
  ::arg().set("allow-unsigned-autoprimary", "Allow autoprimaries to create zones without TSIG signed NOTIFY") = "yes";
  ::arg().setSwitch("forward-dnsupdate", "A global setting to allow DNS update packages that are for a Secondary zone, to be forwarded to the primary.") = "yes";
  ::arg().setSwitch("log-dns-details", "If PDNS should log DNS non-erroneous details") = "no";
  ::arg().setSwitch("log-dns-queries", "If PDNS should log all incoming DNS queries") = "no";
  ::arg().set("local-address", "Local IP addresses to which we bind") = "0.0.0.0, ::";
  ::arg().setSwitch("local-address-nonexist-fail", "Fail to start if one or more of the local-address's do not exist on this server") = "yes";
  ::arg().setSwitch("non-local-bind", "Enable binding to non-local addresses by using FREEBIND / BINDANY socket options") = "no";
  ::arg().setSwitch("reuseport", "Enable higher performance on compliant kernels by using SO_REUSEPORT allowing each receiver thread to open its own socket") = "no";
  ::arg().set("query-local-address", "Source IP addresses for sending queries") = "0.0.0.0 ::";
  ::arg().set("overload-queue-length", "Maximum queuelength moving to packetcache only") = "0";
  ::arg().set("max-queue-length", "Maximum queuelength before considering situation lost") = "5000";

  ::arg().set("retrieval-threads", "Number of AXFR-retrieval threads for secondary operation") = "2";
  ::arg().setSwitch("api", "Enable/disable the REST API (including HTTP listener)") = "no";
  ::arg().set("api-key", "Static pre-shared authentication key for access to the REST API") = "";
  ::arg().setSwitch("default-api-rectify", "Default API-RECTIFY value for zones") = "yes";
  ::arg().setSwitch("dname-processing", "If we should support DNAME records") = "no";

  ::arg().setCmd("help", "Provide a helpful message");
  ::arg().setCmd("version", "Output version and compilation date");
  ::arg().setCmd("config", "Provide configuration file on standard output");
  ::arg().setCmd("list-modules", "Lists all modules available");
  ::arg().setCmd("no-config", "Don't parse configuration file");

  ::arg().set("version-string", "PowerDNS version in packets - full, anonymous, powerdns or custom") = "full";
  ::arg().set("control-console", "Debugging switch - don't use") = "no"; // but I know you will!
  ::arg().set("loglevel", "Amount of logging. Higher is more. Do not set below 3") = "4";
  ::arg().setSwitch("loglevel-show", "Include log level indicator in log output") = "no";
  ::arg().set("disable-syslog", "Disable logging to syslog, useful when running inside a supervisor that logs stderr") = "no";
  ::arg().set("log-timestamp", "Print timestamps in log lines") = "yes";
  ::arg().set("distributor-threads", "Default number of Distributor (backend) threads to start") = "3";
  ::arg().set("signing-threads", "Default number of signer threads to start") = "3";
  ::arg().setSwitch("workaround-11804", "Workaround for issue 11804: send single RR per AXFR chunk") = "no";
  ::arg().set("receiver-threads", "Default number of receiver threads to start") = "1";
  ::arg().set("queue-limit", "Maximum number of milliseconds to queue a query") = "1500";
  ::arg().set("resolver", "Use this resolver for ALIAS and the internal stub resolver") = "no";
  ::arg().set("dnsproxy-udp-port-range", "Select DNS Proxy outgoing UDP port from given range (lower upper)") = "10000 60000";
  ::arg().set("udp-truncation-threshold", "Maximum UDP response size before we truncate") = "1232";

  ::arg().set("config-name", "Name of this virtual configuration - will rename the binary image") = "";

  ::arg().set("load-modules", "Load this module - supply absolute or relative path") = "";
  ::arg().set("launch", "Which backends to launch and order to query them in") = "";
  ::arg().setSwitch("disable-axfr", "Disable zonetransfers but do allow TCP queries") = "no";
  ::arg().set("allow-axfr-ips", "Allow zonetransfers only to these subnets") = "127.0.0.0/8,::1";
  ::arg().set("only-notify", "Only send AXFR NOTIFY to these IP addresses or netmasks") = "0.0.0.0/0,::/0";
  ::arg().set("also-notify", "When notifying a zone, also notify these nameservers") = "";
  ::arg().set("allow-notify-from", "Allow AXFR NOTIFY from these IP ranges. If empty, drop all incoming notifies.") = "0.0.0.0/0,::/0";
  ::arg().set("xfr-cycle-interval", "Schedule primary/secondary SOA freshness checks once every .. seconds") = "60";
  ::arg().set("secondary-check-signature-freshness", "Check signatures in SOA freshness check. Sets DO flag on SOA queries. Outside some very problematic scenarios, say yes here.") = "yes";

  ::arg().set("tcp-control-address", "If set, PowerDNS can be controlled over TCP on this address") = "";
  ::arg().set("tcp-control-port", "If set, PowerDNS can be controlled over TCP on this port") = "53000";
  ::arg().set("tcp-control-secret", "If set, PowerDNS can be controlled over TCP after passing this secret") = "";
  ::arg().set("tcp-control-range", "If set, remote control of PowerDNS is possible over these networks only") = "127.0.0.0/8, 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12, ::1/128, fe80::/10";

  ::arg().setSwitch("secondary", "Act as a secondary") = "no";
  ::arg().setSwitch("primary", "Act as a primary") = "no";
  ::arg().setSwitch("autosecondary", "Act as an autosecondary") = "no";
  ::arg().setSwitch("disable-axfr-rectify", "Disable the rectify step during an outgoing AXFR. Only required for regression testing.") = "no";
  ::arg().setSwitch("guardian", "Run within a guardian process") = "no";
  ::arg().setSwitch("prevent-self-notification", "Don't send notifications to what we think is ourself") = "yes";
  ::arg().setSwitch("any-to-tcp", "Answer ANY queries with tc=1, shunting to TCP") = "yes";
  ::arg().setSwitch("edns-subnet-processing", "If we should act on EDNS Subnet options") = "no";
  ::arg().set("delay-notifications", "Configure a delay to send out notifications, no delay by default") = "0";

  ::arg().set("edns-cookie-secret", "When set, set a server cookie when responding to a query with a Client cookie (in hex)") = "";

  ::arg().setSwitch("webserver", "Start a webserver for monitoring (api=yes also enables the HTTP listener)") = "no";
  ::arg().setSwitch("webserver-print-arguments", "If the webserver should print arguments") = "no";
  ::arg().set("webserver-address", "IP Address or path to UNIX domain socket for webserver/API to listen on") = "127.0.0.1";
  ::arg().set("webserver-port", "Port of webserver/API to listen on") = "8081";
  ::arg().set("webserver-password", "Password required for accessing the webserver") = "";
  ::arg().set("webserver-allow-from", "Webserver/API access is only allowed from these subnets") = "127.0.0.1,::1";
  ::arg().set("webserver-loglevel", "Amount of logging in the webserver (none, normal, detailed)") = "normal";
  ::arg().set("webserver-max-bodysize", "Webserver/API maximum request/response body size in megabytes") = "2";
  ::arg().set("webserver-connection-timeout", "Webserver/API request/response timeout in seconds") = "5";
  ::arg().setSwitch("webserver-hash-plaintext-credentials", "Whether to hash passwords and api keys supplied in plaintext, to prevent keeping the plaintext version in memory at runtime") = "no";

  ::arg().setSwitch("query-logging", "Hint backends that queries should be logged") = "no";

  ::arg().set("carbon-namespace", "If set overwrites the first part of the carbon string") = "pdns";
  ::arg().set("carbon-ourname", "If set, overrides our reported hostname for carbon stats") = "";
  ::arg().set("carbon-instance", "If set overwrites the instance name default") = "auth";
  ::arg().set("carbon-server", "If set, send metrics in carbon (graphite) format to this server IP address") = "";
  ::arg().set("carbon-interval", "Number of seconds between carbon (graphite) updates") = "30";

  ::arg().set("cache-ttl", "Seconds to store packets in the PacketCache") = "20";
  ::arg().set("negquery-cache-ttl", "Seconds to store negative query results in the QueryCache") = "60";
  ::arg().set("query-cache-ttl", "Seconds to store query results in the QueryCache") = "20";
  ::arg().set("zone-cache-refresh-interval", "Seconds to cache list of known zones") = "300";
  ::arg().set("server-id", "Returned when queried for 'id.server' TXT or NSID, defaults to hostname - disabled or custom") = "";
  ::arg().set("default-soa-content", "Default SOA content") = "a.misconfigured.dns.server.invalid hostmaster.@ 0 10800 3600 604800 3600";
  ::arg().set("default-soa-edit", "Default SOA-EDIT value") = "";
  ::arg().set("default-soa-edit-signed", "Default SOA-EDIT value for signed zones") = "";
  ::arg().set("dnssec-key-cache-ttl", "Seconds to cache DNSSEC keys from the database") = "30";
  ::arg().set("domain-metadata-cache-ttl", "Seconds to cache zone metadata from the database") = "";
  ::arg().set("zone-metadata-cache-ttl", "Seconds to cache zone metadata from the database") = "60";

  ::arg().set("trusted-notification-proxy", "IP address of incoming notification proxy") = "";
  ::arg().set("secondary-do-renotify", "If this secondary should send out notifications after receiving zone transfers from a primary") = "no";
  ::arg().set("forward-notify", "IP addresses to forward received notifications to regardless of primary or secondary settings") = "";

  ::arg().set("default-ttl", "Seconds a result is valid if not set otherwise") = "3600";
  ::arg().set("max-tcp-connections", "Maximum number of TCP connections") = "20";
  ::arg().set("max-tcp-connections-per-client", "Maximum number of simultaneous TCP connections per client") = "0";
  ::arg().set("max-tcp-transactions-per-conn", "Maximum number of subsequent queries per TCP connection") = "0";
  ::arg().set("max-tcp-connection-duration", "Maximum time in seconds that a TCP DNS connection is allowed to stay open.") = "0";
  ::arg().set("tcp-idle-timeout", "Maximum time in seconds that a TCP DNS connection is allowed to stay open while being idle") = "5";

  ::arg().setSwitch("no-shuffle", "Set this to prevent random shuffling of answers - for regression testing") = "off";

  ::arg().set("setuid", "If set, change user id to this uid for more security") = "";
  ::arg().set("setgid", "If set, change group id to this gid for more security") = "";

  ::arg().set("max-cache-entries", "Maximum number of entries in the query cache") = "1000000";
  ::arg().set("max-packet-cache-entries", "Maximum number of entries in the packet cache") = "1000000";
  ::arg().set("max-signature-cache-entries", "Maximum number of signatures cache entries") = "";
  ::arg().set("max-ent-entries", "Maximum number of empty non-terminals in a zone") = "100000";

  ::arg().set("lua-prequery-script", "Lua script with prequery handler (DO NOT USE)") = "";
  ::arg().set("lua-dnsupdate-policy-script", "Lua script with DNS update policy handler") = "";
  ::arg().set("lua-global-include-dir", "Include *.lua files from this directory into Lua contexts") = "";

  ::arg().setSwitch("traceback-handler", "Enable the traceback handler (Linux only)") = "yes";
  ::arg().setSwitch("direct-dnskey", "Fetch DNSKEY, CDS and CDNSKEY RRs from backend during DNSKEY or CDS/CDNSKEY synthesis") = "no";
  ::arg().setSwitch("direct-dnskey-signature", "Fetch signature of DNSKEY RRs from backend directly") = "no";
  ::arg().set("default-ksk-algorithm", "Default KSK algorithm") = "ecdsa256";
  ::arg().set("default-ksk-size", "Default KSK size (0 means default)") = "0";
  ::arg().set("default-zsk-algorithm", "Default ZSK algorithm") = "";
  ::arg().set("default-zsk-size", "Default ZSK size (0 means default)") = "0";
  ::arg().set("max-nsec3-iterations", "Limit the number of NSEC3 hash iterations") = "100";
  ::arg().set("default-publish-cdnskey", "Default value for PUBLISH-CDNSKEY") = "";
  ::arg().set("default-publish-cds", "Default value for PUBLISH-CDS") = "";

  ::arg().set("include-dir", "Include *.conf files from this directory");
  ::arg().set("security-poll-suffix", "Zone name from which to query security update notifications") = "secpoll.powerdns.com.";

  ::arg().setSwitch("expand-alias", "Expand ALIAS records") = "no";
  ::arg().set("outgoing-axfr-expand-alias", "Expand ALIAS records during outgoing AXFR") = "no";
  ::arg().setSwitch("resolve-across-zones", "Resolve CNAME targets and other referrals across local zones") = "yes";
  ::arg().setSwitch("8bit-dns", "Allow 8bit dns queries") = "no";
#ifdef HAVE_LUA_RECORDS
  ::arg().setSwitch("enable-lua-records", "Process Lua records for all zones (metadata overrides this)") = "no";
  ::arg().setSwitch("lua-records-insert-whitespace", "Insert whitespace when combining Lua chunks") = "no";
  ::arg().set("lua-records-exec-limit", "Lua records scripts execution limit (instructions count). Values <= 0 mean no limit") = "1000";
  ::arg().set("lua-health-checks-expire-delay", "Stops doing health checks after the record hasn't been used for that delay (in seconds)") = "3600";
  ::arg().set("lua-health-checks-interval", "Lua records health checks monitoring interval in seconds") = "5";
  ::arg().set("lua-consistent-hashes-cleanup-interval", "Pre-computed hashes cleanup interval (in seconds)") = "3600";
  ::arg().set("lua-consistent-hashes-expire-delay", "Cleanup pre-computed hashes that haven't been used for the given delay (in seconds). See pickchashed() Lua function") = "86400";
#endif
  ::arg().setSwitch("axfr-lower-serial", "Also AXFR a zone from a primary with a lower serial") = "no";

  ::arg().set("lua-axfr-script", "Script to be used to edit incoming AXFRs") = "";
  ::arg().set("xfr-max-received-mbytes", "Maximum number of megabytes received from an incoming XFR") = "100";
  ::arg().set("axfr-fetch-timeout", "Maximum time in seconds for inbound AXFR to start or be idle after starting") = "10";

  ::arg().set("tcp-fast-open", "Enable TCP Fast Open support on the listening sockets, using the supplied numerical value as the queue size") = "0";

  ::arg().set("max-generate-steps", "Maximum number of $GENERATE steps when loading a zone from a file") = "0";
  ::arg().set("max-include-depth", "Maximum number of nested $INCLUDE directives while processing a zone file") = "20";
  ::arg().setSwitch("upgrade-unknown-types", "Transparently upgrade known TYPExxx records. Recommended to keep off, except for PowerDNS upgrades until data sources are cleaned up") = "no";
  ::arg().setSwitch("svc-autohints", "Transparently fill ipv6hint=auto ipv4hint=auto SVC params with AAAA/A records for the target name of the record (if within the same zone)") = "no";

  ::arg().setSwitch("consistent-backends", "Assume individual zones are not divided over backends. Send only ANY lookup operations to the backend to reduce the number of lookups") = "yes";

  ::arg().set("default-catalog-zone", "Catalog zone to assign newly created primary zones (via the API) to") = "";

  ::arg().set("protobuf-servers", "Servers to send protobuf logging to");

#ifdef ENABLE_GSS_TSIG
  ::arg().setSwitch("enable-gss-tsig", "Enable GSS TSIG processing") = "no";
#endif

  ::arg().setSwitch("views", "Enable views (variants) of zones, for backends which support them") = "no";

  // FIXME520: remove when branching 5.2
  ::arg().set("entropy-source", "") = "";
  ::arg().set("rng", "") = "";

  ::arg().setDefaults();
}

static time_t s_start = time(nullptr);
static uint64_t uptimeOfProcess(const std::string& /* str */)
{
  return time(nullptr) - s_start;
}

static uint64_t getSysUserTimeMsec(const std::string& str)
{
  struct rusage ru;
  getrusage(RUSAGE_SELF, &ru);

  if (str == "sys-msec") {
    return (ru.ru_stime.tv_sec * 1000ULL + ru.ru_stime.tv_usec / 1000);
  }
  else
    return (ru.ru_utime.tv_sec * 1000ULL + ru.ru_utime.tv_usec / 1000);
}

static uint64_t getTCPConnectionCount(const std::string& /* str */)
{
  return s_tcpNameserver->numTCPConnections();
}

static uint64_t getQCount(const std::string& /* str */)
try {
  int totcount = 0;
  for (const auto& d : s_distributors) {
    if (!d)
      continue;
    totcount += d->getQueueSize(); // this does locking and other things, so don't get smart
  }
  return totcount;
}
catch (std::exception& e) {
  g_log << Logger::Error << "Had error retrieving queue sizes: " << e.what() << endl;
  return 0;
}
catch (PDNSException& e) {
  g_log << Logger::Error << "Had error retrieving queue sizes: " << e.reason << endl;
  return 0;
}

static uint64_t getLatency(const std::string& /* str */)
{
  return round(avg_latency);
}

static uint64_t getReceiveLatency(const std::string& /* str */)
{
  return round(receive_latency);
}

static uint64_t getCacheLatency(const std::string& /* str */)
{
  return round(cache_latency);
}

static uint64_t getBackendLatency(const std::string& /* str */)
{
  return round(backend_latency);
}

static uint64_t getSendLatency(const std::string& /* str */)
{
  return round(send_latency);
}

static void declareStats()
{
  S.declare("udp-queries", "Number of UDP queries received");
  S.declare("udp-do-queries", "Number of UDP queries received with DO bit");
  S.declare("udp-cookie-queries", "Number of UDP queries received with the COOKIE EDNS option");
  S.declare("udp-answers", "Number of answers sent out over UDP");
  S.declare("udp-answers-bytes", "Total size of answers sent out over UDP");
  S.declare("udp4-answers-bytes", "Total size of answers sent out over UDPv4");
  S.declare("udp6-answers-bytes", "Total size of answers sent out over UDPv6");

  S.declare("udp4-answers", "Number of IPv4 answers sent out over UDP");
  S.declare("udp4-queries", "Number of IPv4 UDP queries received");
  S.declare("udp6-answers", "Number of IPv6 answers sent out over UDP");
  S.declare("udp6-queries", "Number of IPv6 UDP queries received");
  S.declare("overload-drops", "Queries dropped because backends overloaded");

  S.declare("rd-queries", "Number of recursion desired questions");
  S.declare("recursion-unanswered", "Number of packets unanswered by configured recursor");
  S.declare("recursing-answers", "Number of recursive answers sent out");
  S.declare("recursing-questions", "Number of questions sent to recursor");
  S.declare("corrupt-packets", "Number of corrupt packets received");
  S.declare("signatures", "Number of DNSSEC signatures made");
  S.declare("tcp-queries", "Number of TCP queries received");
  S.declare("tcp-cookie-queries", "Number of TCP queries received with the COOKIE option");
  S.declare("tcp-answers", "Number of answers sent out over TCP");
  S.declare("tcp-answers-bytes", "Total size of answers sent out over TCP");
  S.declare("tcp4-answers-bytes", "Total size of answers sent out over TCPv4");
  S.declare("tcp6-answers-bytes", "Total size of answers sent out over TCPv6");

  S.declare("tcp4-queries", "Number of IPv4 TCP queries received");
  S.declare("tcp4-answers", "Number of IPv4 answers sent out over TCP");

  S.declare("tcp6-queries", "Number of IPv6 TCP queries received");
  S.declare("tcp6-answers", "Number of IPv6 answers sent out over TCP");

  S.declare("open-tcp-connections", "Number of currently open TCP connections", getTCPConnectionCount, StatType::gauge);

  S.declare("qsize-q", "Number of questions waiting for database attention", getQCount, StatType::gauge);

  S.declare("dnsupdate-queries", "DNS update packets received.");
  S.declare("dnsupdate-answers", "DNS update packets successfully answered.");
  S.declare("dnsupdate-refused", "DNS update packets that are refused.");
  S.declare("dnsupdate-changes", "DNS update changes to records in total.");

  S.declare("incoming-notifications", "NOTIFY packets received.");

  S.declare("uptime", "Uptime of process in seconds", uptimeOfProcess, StatType::counter);
  S.declare("real-memory-usage", "Actual unique use of memory in bytes (approx)", getRealMemoryUsage, StatType::gauge);
  S.declare("special-memory-usage", "Actual unique use of memory in bytes (approx)", getSpecialMemoryUsage, StatType::gauge);
  S.declare("fd-usage", "Number of open filedescriptors", getOpenFileDescriptors, StatType::gauge);
#ifdef __linux__
  S.declare("udp-recvbuf-errors", "UDP 'recvbuf' errors", udpErrorStats, StatType::counter);
  S.declare("udp-sndbuf-errors", "UDP 'sndbuf' errors", udpErrorStats, StatType::counter);
  S.declare("udp-noport-errors", "UDP 'noport' errors", udpErrorStats, StatType::counter);
  S.declare("udp-in-errors", "UDP 'in' errors", udpErrorStats, StatType::counter);
  S.declare("udp-in-csum-errors", "UDP 'in checksum' errors", udpErrorStats, StatType::counter);
  S.declare("udp6-in-errors", "UDP 'in' errors over IPv6", udp6ErrorStats, StatType::counter);
  S.declare("udp6-recvbuf-errors", "UDP 'recvbuf' errors over IPv6", udp6ErrorStats, StatType::counter);
  S.declare("udp6-sndbuf-errors", "UDP 'sndbuf' errors over IPv6", udp6ErrorStats, StatType::counter);
  S.declare("udp6-noport-errors", "UDP 'noport' errors over IPv6", udp6ErrorStats, StatType::counter);
  S.declare("udp6-in-csum-errors", "UDP 'in checksum' errors over IPv6", udp6ErrorStats, StatType::counter);
#endif

  S.declare("sys-msec", "Number of msec spent in system time", getSysUserTimeMsec, StatType::counter);
  S.declare("user-msec", "Number of msec spent in user time", getSysUserTimeMsec, StatType::counter);

#ifdef __linux__
  S.declare("cpu-iowait", "Time spent waiting for I/O to complete by the whole system, in units of USER_HZ", getCPUIOWait, StatType::counter);
  S.declare("cpu-steal", "Stolen time, which is the time spent by the whole system in other operating systems when running in a virtualized environment, in units of USER_HZ", getCPUSteal, StatType::counter);
#endif

  S.declare("meta-cache-size", "Number of entries in the metadata cache", DNSSECKeeper::dbdnssecCacheSizes, StatType::gauge);
  S.declare("key-cache-size", "Number of entries in the key cache", DNSSECKeeper::dbdnssecCacheSizes, StatType::gauge);
  S.declare("signature-cache-size", "Number of entries in the signature cache", signatureCacheSize, StatType::gauge);

  S.declare("nxdomain-packets", "Number of times an NXDOMAIN packet was sent out");
  S.declare("noerror-packets", "Number of times a NOERROR packet was sent out");
  S.declare("servfail-packets", "Number of times a server-failed packet was sent out");
  S.declare("unauth-packets", "Number of times a zone we are not auth for was queried");
  S.declare("latency", "Average number of microseconds needed to answer a question", getLatency, StatType::gauge);
  S.declare("receive-latency", "Average number of microseconds needed to receive a query", getReceiveLatency, StatType::gauge);
  S.declare("cache-latency", "Average number of microseconds needed for a packet cache lookup", getCacheLatency, StatType::gauge);
  S.declare("backend-latency", "Average number of microseconds needed for a backend lookup", getBackendLatency, StatType::gauge);
  S.declare("send-latency", "Average number of microseconds needed to send the answer", getSendLatency, StatType::gauge);
  S.declare("timedout-packets", "Number of packets which weren't answered within timeout set");
  S.declare("security-status", "Security status based on regular polling", StatType::gauge);
  S.declare(
    "xfr-queue", "Size of the queue of zones to be XFRd", [](const string&) { return Communicator.getSuckRequestsWaiting(); }, StatType::gauge);
  S.declareDNSNameQTypeRing("queries", "UDP Queries Received");
  S.declareDNSNameQTypeRing("nxdomain-queries", "Queries for nonexistent records within existent zones");
  S.declareDNSNameQTypeRing("noerror-queries", "Queries for existing records, but for type we don't have");
  S.declareDNSNameQTypeRing("servfail-queries", "Queries that could not be answered due to backend errors");
  S.declareDNSNameQTypeRing("unauth-queries", "Queries for zones that we are not authoritative for");
  S.declareRing("logmessages", "Log Messages");
  S.declareComboRing("remotes", "Remote server IP addresses");
  S.declareComboRing("remotes-unauth", "Remote hosts querying zones for which we are not auth");
  S.declareComboRing("remotes-corrupt", "Remote hosts sending corrupt packets");
}

static int isGuarded(char** argv)
{
  char* p = strstr(argv[0], "-instance");

  return !!p;
}

static void update_latencies(int start, int diff)
{
  send_latency = 0.999 * send_latency + 0.001 * std::max(diff - start, 0);
  avg_latency = 0.999 * avg_latency + 0.001 * std::max(diff, 0); // 'EWMA'
}

static void sendout(std::unique_ptr<DNSPacket>& a, int start)
{
  if (!a)
    return;

  try {
    int diff = a->d_dt.udiffNoReset();
    backend_latency = 0.999 * backend_latency + 0.001 * std::max(diff - start, 0);
    start = diff;

    s_udpNameserver->send(*a);

    diff = a->d_dt.udiff();
    update_latencies(start, diff);
  }
  catch (const std::exception& e) {
    g_log << Logger::Error << "Caught unhandled exception while sending a response: " << e.what() << endl;
  }
}

//! The qthread receives questions over the internet via the Nameserver class, and hands them to the Distributor for further processing
static void qthread(unsigned int num)
{
  try {
    setThreadName("pdns/receiver");

    s_distributors[num] = DNSDistributor::Create(::arg().asNum("distributor-threads", 1));
    DNSDistributor* distributor = s_distributors[num]; // the big dispatcher!
    DNSPacket question(true);
    DNSPacket cached(false);

    AtomicCounter& numreceived = *S.getPointer("udp-queries");
    AtomicCounter& numreceiveddo = *S.getPointer("udp-do-queries");
    AtomicCounter& numreceivedcookie = *S.getPointer("udp-cookie-queries");

    AtomicCounter& numreceived4 = *S.getPointer("udp4-queries");

    AtomicCounter& numreceived6 = *S.getPointer("udp6-queries");
    AtomicCounter& overloadDrops = *S.getPointer("overload-drops");

    int diff{};
    int start{};
    bool logDNSQueries = ::arg().mustDo("log-dns-queries");
    shared_ptr<UDPNameserver> NS; // NOLINT(readability-identifier-length)
    std::string buffer;
    ComboAddress accountremote;

    // If we have SO_REUSEPORT then create a new port for all receiver threads
    // other than the first one.
    if (s_udpNameserver->canReusePort()) {
      NS = s_udpReceivers[num];
      if (NS == nullptr) {
        NS = s_udpNameserver;
      }
    }
    else {
      NS = s_udpNameserver;
    }

    for (;;) {
      try {
        if (g_proxyProtocolACL.empty()) {
          buffer.resize(DNSPacket::s_udpTruncationThreshold);
        }
        else {
          buffer.resize(DNSPacket::s_udpTruncationThreshold + g_proxyProtocolMaximumSize);
        }

        if (!NS->receive(question, buffer)) { // receive a packet         inline
          continue; // packet was broken, try again
        }

        diff = question.d_dt.udiffNoReset();
        receive_latency = 0.999 * receive_latency + 0.001 * std::max(diff, 0);

        numreceived++;

        accountremote = question.d_remote;
        if (question.d_inner_remote) {
          accountremote = *question.d_inner_remote;
        }

        if (accountremote.sin4.sin_family == AF_INET) {
          numreceived4++;
        }
        else {
          numreceived6++;
        }

        if (question.d_dnssecOk) {
          numreceiveddo++;
        }

        if (question.hasEDNSCookie()) {
          numreceivedcookie++;
        }

        if (question.d.qr) {
          continue;
        }

        S.ringAccount("queries", question.qdomain, question.qtype);
        S.ringAccount("remotes", question.getInnerRemote());
        if (logDNSQueries) {
          g_log << Logger::Notice << "Remote " << question.getRemoteString() << " wants '" << question.qdomain << "|" << question.qtype << "', do = " << question.d_dnssecOk << ", bufsize = " << question.getMaxReplyLen();
          if (question.d_ednsRawPacketSizeLimit > 0 && question.getMaxReplyLen() != (unsigned int)question.d_ednsRawPacketSizeLimit) {
            g_log << " (" << question.d_ednsRawPacketSizeLimit << ")";
          }
        }

        if (PC.enabled() && (question.d.opcode != Opcode::Notify && question.d.opcode != Opcode::Update) && question.couldBeCached()) {
          start = diff;
          std::string view{};
          if (g_views) {
            Netmask netmask(accountremote);
            view = g_zoneCache.getViewFromNetwork(&netmask);
          }
          bool haveSomething = PC.get(question, cached, view); // does the PacketCache recognize this question?
          if (haveSomething) {
            if (logDNSQueries) {
              g_log << ": packetcache HIT" << endl;
            }
            cached.setRemote(&question.d_remote); // inlined
            cached.d_inner_remote = question.d_inner_remote;
            cached.setSocket(question.getSocket()); // inlined
            cached.d_anyLocal = question.d_anyLocal;
            cached.setMaxReplyLen(question.getMaxReplyLen()); // NOLINT(bugprone-narrowing-conversions,cppcoreguidelines-narrowing-conversions) get returns unsigned, set takes signed...
            cached.d.rd = question.d.rd; // copy in recursion desired bit
            cached.d.id = question.d.id;
            cached.commitD(); // commit d to the packet                        inlined

            diff = question.d_dt.udiffNoReset();
            cache_latency = 0.999 * cache_latency + 0.001 * std::max(diff - start, 0);
            start = diff;

            NS->send(cached); // answer it then                              inlined

            diff = question.d_dt.udiff();
            update_latencies(start, diff);
            continue;
          }
          diff = question.d_dt.udiffNoReset();
          cache_latency = 0.999 * cache_latency + 0.001 * std::max(diff - start, 0);
        }

        if (distributor->isOverloaded()) {
          if (logDNSQueries) {
            g_log << ": Dropped query, backends are overloaded" << endl;
          }
          overloadDrops++;
          continue;
        }

        if (logDNSQueries) {
          if (PC.enabled()) {
            g_log << ": packetcache MISS" << endl;
          }
          else {
            g_log << endl;
          }
        }

        try {
          distributor->question(question, &sendout); // otherwise, give to the distributor
        }
        catch (DistributorFatal& df) { // when this happens, we have leaked loads of memory. Bailing out time.
          _exit(1);
        }
      }
      catch (const std::exception& e) {
        g_log << Logger::Error << "Caught unhandled exception in question thread: " << e.what() << endl;
      }
    }
  }
  catch (PDNSException& pe) {
    g_log << Logger::Error << "Fatal error in question thread: " << pe.reason << endl;
    _exit(1);
  }
}

static void dummyThread()
{
}

static void triggerLoadOfLibraries()
{
  std::thread dummy(dummyThread);
  dummy.join();
}

static void mainthread()
{
  gid_t newgid = 0;
  if (!::arg()["setgid"].empty())
    newgid = strToGID(::arg()["setgid"]);
  uid_t newuid = 0;
  if (!::arg()["setuid"].empty())
    newuid = strToUID(::arg()["setuid"]);

  g_anyToTcp = ::arg().mustDo("any-to-tcp");
  g_8bitDNS = ::arg().mustDo("8bit-dns");
#ifdef HAVE_LUA_RECORDS
  g_doLuaRecord = ::arg().mustDo("enable-lua-records");
  g_LuaRecordSharedState = (::arg()["enable-lua-records"] == "shared");
  g_luaRecordExecLimit = ::arg().asNum("lua-records-exec-limit");
  g_luaRecordInsertWhitespace = ::arg().mustDo("lua-records-insert-whitespace");
  g_luaHealthChecksInterval = ::arg().asNum("lua-health-checks-interval");
  g_luaConsistentHashesExpireDelay = ::arg().asNum("lua-consistent-hashes-expire-delay");
  g_luaConsistentHashesCleanupInterval = ::arg().asNum("lua-consistent-hashes-cleanup-interval");
  g_luaHealthChecksExpireDelay = ::arg().asNum("lua-health-checks-expire-delay");
#endif
#ifdef ENABLE_GSS_TSIG
  g_doGssTSIG = ::arg().mustDo("enable-gss-tsig");
#endif
  g_views = ::arg().mustDo("views");

  DNSPacket::s_udpTruncationThreshold = std::max(512, ::arg().asNum("udp-truncation-threshold"));
  DNSPacket::s_doEDNSSubnetProcessing = ::arg().mustDo("edns-subnet-processing");
  PacketHandler::s_SVCAutohints = ::arg().mustDo("svc-autohints");

  g_proxyProtocolACL.toMasks(::arg()["proxy-protocol-from"]);
  g_proxyProtocolMaximumSize = ::arg().asNum("proxy-protocol-maximum-size");

  if (::arg()["edns-cookie-secret"].size() != 0) {
    // User wants cookie processing
#ifdef HAVE_CRYPTO_SHORTHASH // we can do siphash-based cookies
    DNSPacket::s_doEDNSCookieProcessing = true;
    const std::string& secret = ::arg()["edns-cookie-secret"];
    if (secret == "random") {
      std::array<char, EDNSCookiesOpt::EDNSCookieSecretSize / 2> key{};
      dns_random(key.data(), key.size());
      DNSPacket::s_EDNSCookieKey = std::string(key.data(), key.size());
    }
    else {
      try {
        if (secret.size() != EDNSCookiesOpt::EDNSCookieSecretSize) {
          throw std::range_error("wrong size (" + std::to_string(secret.size()) + "), must be " + std::to_string(EDNSCookiesOpt::EDNSCookieSecretSize));
        }
        DNSPacket::s_EDNSCookieKey = makeBytesFromHex(secret);
      }
      catch (const std::range_error& e) {
        g_log << Logger::Error << "edns-cookie-secret invalid: " << e.what() << endl;
        exit(1); // NOLINT(concurrency-mt-unsafe) we're single threaded at this point
      }
    }
#else
    g_log << Logger::Error << "Support for EDNS Cookies is not available because of missing cryptographic functions (libsodium support should be enabled, with the crypto_shorthash() function available)" << endl;
    exit(1);
#endif
  }

  // Check for mutually incompatible settings:
  // - enabling views currently requires the zone cache to be active
  if (g_views) {
    if (::arg().asNum("zone-cache-refresh-interval") == 0) {
      g_log << Logger::Error << R"(Error: use of views requires the zone cache to be enabled, please set "zone-cache-refresh-interval" to a nonzero value.)" << endl;
      exit(1); // NOLINT(concurrency-mt-unsafe) we're single threaded at this point
    }
  }
  // - configurations involving communicator threads need at least one
  //   such thread configured
  if (::arg().mustDo("primary") || ::arg().mustDo("secondary") || !::arg()["forward-notify"].empty()) {
    if (::arg().asNum("retrieval-threads", 1) <= 0) {
      g_log << Logger::Error << R"(Error: primary or secondary operation requires "retrieval-threads" to be set to a nonzero value.)" << endl;
      exit(1); // NOLINT(concurrency-mt-unsafe) we're single threaded at this point
    }
  }
  // (no more checks yet)

  PC.setTTL(::arg().asNum("cache-ttl"));
  PC.setMaxEntries(::arg().asNum("max-packet-cache-entries"));
  QC.setMaxEntries(::arg().asNum("max-cache-entries"));
  DNSSECKeeper::setMaxEntries(::arg().asNum("max-cache-entries"));

  if (!PC.enabled() && ::arg().mustDo("log-dns-queries")) {
    g_log << Logger::Warning << "Packet cache disabled, logging queries without HIT/MISS" << endl;
  }
  if (::arg()["outgoing-axfr-expand-alias"] == "ignore-errors") {
    g_log << Logger::Error << "Ignoring ALIAS resolve failures on outgoing AXFR transfers, see option \"outgoing-axfr-expand-alias\"" << endl;
  }

  stubParseResolveConf();

  if (!::arg()["chroot"].empty()) {
#ifdef HAVE_SYSTEMD
    char* ns;
    ns = getenv("NOTIFY_SOCKET");
    if (ns != nullptr) {
      g_log << Logger::Error << "Unable to chroot when running from systemd. Please disable chroot= or set the 'Type' for this service to 'simple'" << endl;
      exit(1);
    }
#endif
    triggerLoadOfLibraries();
    if (::arg().mustDo("primary") || ::arg().mustDo("secondary"))
      gethostbyname("a.root-servers.net"); // this forces all lookup libraries to be loaded
    Utility::dropGroupPrivs(newuid, newgid);
    if (chroot(::arg()["chroot"].c_str()) < 0 || chdir("/") < 0) {
      g_log << Logger::Error << "Unable to chroot to '" + ::arg()["chroot"] + "': " << stringerror() << ", exiting" << endl;
      exit(1);
    }
    else
      g_log << Logger::Error << "Chrooted to '" << ::arg()["chroot"] << "'" << endl;
  }
  else {
    Utility::dropGroupPrivs(newuid, newgid);
  }

  AuthWebServer webserver;
  Utility::dropUserPrivs(newuid);

  if (::arg().mustDo("resolver")) {
    DP = std::make_unique<DNSProxy>(::arg()["resolver"], ::arg()["dnsproxy-udp-port-range"]);
    DP->go();
  }

  try {
    doSecPoll(true);
  }
  catch (...) {
  }

  {
    // Some sanity checking on default key settings
    bool hadKeyError = false;
    int kskAlgo{0}, zskAlgo{0};
    for (const string algotype : {"ksk", "zsk"}) {
      int algo, size;
      if (::arg()["default-" + algotype + "-algorithm"].empty())
        continue;
      algo = DNSSECKeeper::shorthand2algorithm(::arg()["default-" + algotype + "-algorithm"]);
      size = ::arg().asNum("default-" + algotype + "-size");
      if (algo == -1) {
        g_log << Logger::Error << "Error: default-" << algotype << "-algorithm set to unknown algorithm: " << ::arg()["default-" + algotype + "-algorithm"] << endl;
        hadKeyError = true;
      }
      else if (algo <= 10 && size == 0) {
        g_log << Logger::Error << "Error: default-" << algotype << "-algorithm is set to an algorithm (" << ::arg()["default-" + algotype + "-algorithm"] << ") that requires a non-zero default-" << algotype << "-size!" << endl;
        hadKeyError = true;
      }
      if (algotype == "ksk") {
        kskAlgo = algo;
      }
      else {
        zskAlgo = algo;
      }
    }
    if (hadKeyError) {
      exit(1);
    }
    if (kskAlgo == 0 && zskAlgo != 0) {
      g_log << Logger::Error << "Error: default-zsk-algorithm is set, but default-ksk-algorithm is not set." << endl;
      exit(1);
    }
    if (zskAlgo != 0 && zskAlgo != kskAlgo) {
      g_log << Logger::Error << "Error: default-zsk-algorithm (" << ::arg()["default-zsk-algorithm"] << "), when set, can not be different from default-ksk-algorithm (" << ::arg()["default-ksk-algorithm"] << ")." << endl;
      exit(1);
    }
  }

  pdns::parseQueryLocalAddress(::arg()["query-local-address"]);

  pdns::parseTrustedNotificationProxy(::arg()["trusted-notification-proxy"]);

  {
    vector<string> addrs;
    stringtok(addrs, ::arg()["protobuf-servers"], ", ;");

    for (const string& addr : addrs) {
      g_remote_loggers.emplace_back(make_unique<RemoteLogger>(ComboAddress(addr)));
    }
  }

  UeberBackend::go();

  // Setup the zone cache
  g_zoneCache.setRefreshInterval(::arg().asNum("zone-cache-refresh-interval"));
  try {
    UeberBackend B;
    B.updateZoneCache();
  }
  catch (PDNSException& e) {
    g_log << Logger::Error << "PDNSException while filling the zone cache: " << e.reason << endl;
    exit(1);
  }
  catch (std::exception& e) {
    g_log << Logger::Error << "STL Exception while filling the zone cache: " << e.what() << endl;
    exit(1);
  }

  // NOW SAFE TO CREATE THREADS!
  s_dynListener->go();

  if (::arg().mustDo("webserver") || ::arg().mustDo("api")) {
    webserver.go(S);
  }

  if (::arg().mustDo("primary") || ::arg().mustDo("secondary") || !::arg()["forward-notify"].empty())
    Communicator.go();

  s_tcpNameserver->go(); // tcp nameserver launch

  unsigned int max_rthreads = ::arg().asNum("receiver-threads", 1);
  s_distributors.resize(max_rthreads);
  for (unsigned int n = 0; n < max_rthreads; ++n) {
    std::thread t(qthread, n);
    t.detach();
  }

  std::thread carbonThread(carbonDumpThread); // runs even w/o carbon, might change @ runtime

#ifdef HAVE_SYSTEMD
  /* If we are here, notify systemd that we are ay-ok! This might have some
   * timing issues with the backend-threads. e.g. if the initial MySQL connection
   * is slow and times out (leading to process termination through the backend)
   * We probably have told systemd already that we have started correctly.
   */
  sd_notify(0, "READY=1");
#endif

  const uint32_t secpollInterval = 1800;
  uint32_t secpollSince = 0;
  uint32_t zoneCacheUpdateSince = 0;
  for (;;) {
    const uint32_t sleeptime = g_zoneCache.getRefreshInterval() == 0 ? secpollInterval : std::min(secpollInterval, g_zoneCache.getRefreshInterval());
    sleep(sleeptime); // if any signals arrive, we might run more often than expected.

    zoneCacheUpdateSince += sleeptime;
    if (zoneCacheUpdateSince >= g_zoneCache.getRefreshInterval()) {
      try {
        UeberBackend B;
        B.updateZoneCache();
        zoneCacheUpdateSince = 0;
      }
      catch (PDNSException& e) {
        g_log << Logger::Error << "PDNSException while updating zone cache: " << e.reason << endl;
      }
      catch (std::exception& e) {
        g_log << Logger::Error << "STL Exception while updating zone cache: " << e.what() << endl;
      }
    }

    secpollSince += sleeptime;
    if (secpollSince >= secpollInterval) {
      secpollSince = 0;
      try {
        doSecPoll(false);
      }
      catch (...) {
      }
    }
  }

  g_log << Logger::Error << "Mainthread exiting - should never happen" << endl;
}

static void daemonize()
{
  if (fork())
    exit(0); // bye bye

  setsid();

  int i = open("/dev/null", O_RDWR); /* open stdin */
  if (i < 0)
    g_log << Logger::Critical << "Unable to open /dev/null: " << stringerror() << endl;
  else {
    dup2(i, 0); /* stdin */
    dup2(i, 1); /* stderr */
    dup2(i, 2); /* stderr */
    close(i);
  }
}

static int cpid;
static void takedown(int /* i */)
{
  if (cpid) {
    g_log << Logger::Error << "Guardian is killed, taking down children with us" << endl;
    kill(cpid, SIGKILL);
    exit(0);
  }
}

static void writePid()
{
  if (!::arg().mustDo("write-pid"))
    return;

  string fname = ::arg()["socket-dir"];
  if (::arg()["socket-dir"].empty()) {
    if (::arg()["chroot"].empty())
      fname = std::string(LOCALSTATEDIR) + "/pdns";
    else
      fname = ::arg()["chroot"] + "/";
  }
  else if (!::arg()["socket-dir"].empty() && !::arg()["chroot"].empty()) {
    fname = ::arg()["chroot"] + ::arg()["socket-dir"];
  }

  fname += +"/" + g_programname + ".pid";
  ofstream of(fname.c_str());
  if (of)
    of << getpid() << endl;
  else
    g_log << Logger::Error << "Writing pid for " << getpid() << " to " << fname << " failed: " << stringerror() << endl;
}

static int g_fd1[2], g_fd2[2];
static FILE* g_fp;
static std::mutex g_guardian_lock;

// The next two methods are not in dynhandler.cc because they use a few items declared in this file.
static string DLCycleHandler(const vector<string>& /* parts */, pid_t /* ppid */)
{
  kill(cpid, SIGKILL); // why?
  kill(cpid, SIGKILL); // why?
  sleep(1);
  return "ok";
}

static string DLRestHandler(const vector<string>& parts, pid_t /* ppid */)
{
  string line;

  for (vector<string>::const_iterator i = parts.begin(); i != parts.end(); ++i) {
    if (i != parts.begin())
      line.append(1, ' ');
    line.append(*i);
  }
  line.append(1, '\n');

  auto lock = std::scoped_lock(g_guardian_lock);

  try {
    writen2(g_fd1[1], line.c_str(), line.size() + 1);
  }
  catch (PDNSException& ae) {
    return "Error communicating with instance: " + ae.reason;
  }
  char mesg[512];
  string response;
  while (fgets(mesg, sizeof(mesg), g_fp)) {
    if (*mesg == '\0')
      break;
    response += mesg;
  }
  boost::trim_right(response);
  return response;
}

static int guardian(int argc, char** argv)
{
  if (isGuarded(argv))
    return 0;

  int infd = 0, outfd = 1;

  DynListener dlg(g_programname);
  DynListener::registerExitFunc("QUIT", &DLQuitHandler);
  DynListener::registerFunc("CYCLE", &DLCycleHandler, "restart instance");
  DynListener::registerFunc("PING", &DLPingHandler, "ping guardian");
  DynListener::registerFunc("STATUS", &DLStatusHandler, "get instance status from guardian");
  DynListener::registerRestFunc(&DLRestHandler);
  dlg.go();
  string progname = argv[0];

  bool first = true;
  cpid = 0;

  g_guardian_lock.lock();

  for (;;) {
    int pid;
    setStatus("Launching child");

    if (pipe(g_fd1) < 0 || pipe(g_fd2) < 0) {
      g_log << Logger::Critical << "Unable to open pipe for coprocess: " << stringerror() << endl;
      exit(1);
    }

    if (!(g_fp = fdopen(g_fd2[0], "r"))) {
      g_log << Logger::Critical << "Unable to associate a file pointer with pipe: " << stringerror() << endl;
      exit(1);
    }
    setbuf(g_fp, nullptr); // no buffering please, confuses select

    if (!(pid = fork())) { // child
      signal(SIGTERM, SIG_DFL);

      signal(SIGHUP, SIG_DFL);
      signal(SIGUSR1, SIG_DFL);
      signal(SIGUSR2, SIG_DFL);

      char** const newargv = new char*[argc + 2];
      int n;

      if (::arg()["config-name"] != "") {
        progname += "-" + ::arg()["config-name"];
        g_log << Logger::Error << "Virtual configuration name: " << ::arg()["config-name"] << endl;
      }

      newargv[0] = strdup(const_cast<char*>((progname + "-instance").c_str()));
      for (n = 1; n < argc; n++) {
        newargv[n] = argv[n];
      }
      newargv[n] = nullptr;

      g_log << Logger::Error << "Guardian is launching an instance" << endl;
      close(g_fd1[1]);
      fclose(g_fp); // this closes g_fd2[0] for us

      if (g_fd1[0] != infd) {
        dup2(g_fd1[0], infd);
        close(g_fd1[0]);
      }

      if (g_fd2[1] != outfd) {
        dup2(g_fd2[1], outfd);
        close(g_fd2[1]);
      }
      if (execvp(argv[0], newargv) < 0) {
        g_log << Logger::Error << "Unable to execvp '" << argv[0] << "': " << stringerror() << endl;
        char** p = newargv;
        while (*p)
          g_log << Logger::Error << *p++ << endl;

        exit(1);
      }
      g_log << Logger::Error << "execvp returned!!" << endl;
      // never reached
    }
    else if (pid > 0) { // parent
      close(g_fd1[0]);
      close(g_fd2[1]);

      if (first) {
        first = false;
        signal(SIGTERM, takedown);

        signal(SIGHUP, SIG_IGN);
        signal(SIGUSR1, SIG_IGN);
        signal(SIGUSR2, SIG_IGN);

        writePid();
      }
      g_guardian_lock.unlock();
      int status;
      cpid = pid;
      for (;;) {
        int ret = waitpid(pid, &status, WNOHANG);

        if (ret < 0) {
          g_log << Logger::Error << "In guardian loop, waitpid returned error: " << stringerror() << endl;
          g_log << Logger::Error << "Dying" << endl;
          exit(1);
        }
        else if (ret) // something exited
          break;
        else { // child is alive
          // execute some kind of ping here
          if (DLQuitPlease())
            takedown(1); // needs a parameter..
          setStatus("Child running on pid " + std::to_string(pid));
          sleep(1);
        }
      }

      g_guardian_lock.lock();
      close(g_fd1[1]);
      fclose(g_fp);
      g_fp = nullptr;

      if (WIFEXITED(status)) {
        int ret = WEXITSTATUS(status);

        if (ret == 99) {
          g_log << Logger::Error << "Child requested a stop, exiting" << endl;
          exit(1);
        }
        setStatus("Child died with code " + std::to_string(ret));
        g_log << Logger::Error << "Our pdns instance exited with code " << ret << ", respawning" << endl;

        sleep(1);
        continue;
      }
      if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        setStatus("Child died because of signal " + std::to_string(sig));
        g_log << Logger::Error << "Our pdns instance (" << pid << ") exited after signal " << sig << endl;
#ifdef WCOREDUMP
        if (WCOREDUMP(status))
          g_log << Logger::Error << "Dumped core" << endl;
#endif

        g_log << Logger::Error << "Respawning" << endl;
        sleep(1);
        continue;
      }
      g_log << Logger::Error << "No clue what happened! Respawning" << endl;
    }
    else {
      g_log << Logger::Error << "Unable to fork: " << stringerror() << endl;
      exit(1);
    }
  }
}

#if defined(__GLIBC__) && !defined(__UCLIBC__)
#include <execinfo.h>
static void tbhandler(int num)
{
  g_log << Logger::Critical << "Got a signal " << num << ", attempting to print trace: " << endl;
  void* array[20]; // only care about last 17 functions (3 taken with tracing support)
  size_t size;
  char** strings;
  size_t i;

  size = backtrace(array, 20);
  strings = backtrace_symbols(array, size); // Need -rdynamic gcc (linker) flag for this to work

  for (i = 0; i < size; i++) // skip useless functions
    g_log << Logger::Error << strings[i] << endl;

  signal(SIGABRT, SIG_DFL);
  abort(); // hopefully will give core
}
#endif

#ifdef COVERAGE
static void sigTermHandler([[maybe_unused]] int signal)
{
  pdns::coverage::dumpCoverageData();
  _exit(EXIT_SUCCESS);
}
#endif /* COVERAGE */

//! The main function of pdns, the pdns process
// NOLINTNEXTLINE(readability-function-cognitive-complexity)
int main(int argc, char** argv)
{
  versionSetProduct(ProductAuthoritative);
  reportAllTypes(); // init MOADNSParser

  g_programname = "pdns";
  g_starttime = time(nullptr);

#if defined(__GLIBC__) && !defined(__UCLIBC__)
  signal(SIGSEGV, tbhandler);
  signal(SIGFPE, tbhandler);
  signal(SIGABRT, tbhandler);
  signal(SIGILL, tbhandler);
#endif

  std::ios_base::sync_with_stdio(false);

  g_log.toConsole(Logger::Warning);
  try {
    declareArguments();

    ::arg().laxParse(argc, argv); // do a lax parse

    if (::arg().mustDo("version")) {
      cout << getProductVersion();
      cout << getBuildConfiguration();
      return 0;
    }

    if (::arg()["config-name"] != "")
      g_programname += "-" + ::arg()["config-name"];

    g_log.setName(g_programname);

    string configname = ::arg()["config-dir"] + "/" + g_programname + ".conf";
    cleanSlashes(configname);

    if (::arg()["config"] != "default" && !::arg().mustDo("no-config")) // "config" == print a configuration file
      ::arg().laxFile(configname.c_str());

    ::arg().laxParse(argc, argv); // reparse so the commandline still wins

    // FIXME520: remove when branching 5.2
    if (!::arg()["entropy-source"].empty()) {
      std::cerr << "WARNING: `entropy-source' setting is deprecated" << std::endl
                << "and will be removed in a future version" << std::endl;
    }
    if (!::arg()["rng"].empty()) {
      std::cerr << "WARNING: `rng' setting is deprecated" << std::endl
                << "and will be removed in a future version" << std::endl;
    }

    if (!::arg()["logging-facility"].empty()) {
      int val = logFacilityToLOG(::arg().asNum("logging-facility"));
      if (val >= 0)
        g_log.setFacility(val);
      else
        g_log << Logger::Error << "Unknown logging facility " << ::arg().asNum("logging-facility") << endl;
    }

    if (!::arg().isEmpty("domain-metadata-cache-ttl"))
      ::arg().set("zone-metadata-cache-ttl") = ::arg()["domain-metadata-cache-ttl"];

    // this mirroring back is on purpose, so that config dumps reflect the actual setting on both names
    ::arg().set("domain-metadata-cache-ttl") = ::arg()["zone-metadata-cache-ttl"];

    g_log.setLoglevel((Logger::Urgency)(::arg().asNum("loglevel")));
    g_log.setPrefixed(::arg().mustDo("loglevel-show"));
    g_log.disableSyslog(::arg().mustDo("disable-syslog"));
    g_log.setTimestamps(::arg().mustDo("log-timestamp"));
    g_log.toConsole((Logger::Urgency)(::arg().asNum("loglevel")));

    if (::arg().mustDo("help") || ::arg().mustDo("config")) {
      ::arg().set("daemon") = "no";
      ::arg().set("guardian") = "no";
    }

    if (::arg().mustDo("guardian") && !isGuarded(argv)) {
      if (::arg().mustDo("daemon")) {
        g_log.toConsole(Logger::Critical);
        daemonize();
      }
      guardian(argc, argv);
      // never get here, guardian will reinvoke process
      cerr << "Um, we did get here!" << endl;
    }

#ifdef COVERAGE
    if (!::arg().mustDo("guardian") && !::arg().mustDo("daemon")) {
      signal(SIGTERM, sigTermHandler);
    }
#endif

    // we really need to do work - either standalone or as an instance

#if defined(__GLIBC__) && !defined(__UCLIBC__)
    if (!::arg().mustDo("traceback-handler")) {
      g_log << Logger::Warning << "Disabling traceback handler" << endl;
      signal(SIGSEGV, SIG_DFL);
      signal(SIGFPE, SIG_DFL);
      signal(SIGABRT, SIG_DFL);
      signal(SIGILL, SIG_DFL);
    }
#endif

#ifdef HAVE_LIBSODIUM
    if (sodium_init() == -1) {
      cerr << "Unable to initialize sodium crypto library" << endl;
      exit(99);
    }
#endif

    openssl_thread_setup();
    openssl_seed();

#ifdef HAVE_LUA_RECORDS
    MiniCurl::init();
#endif /* HAVE_LUA_RECORDS */

    if (!::arg()["load-modules"].empty()) {
      vector<string> modules;

      stringtok(modules, ::arg()["load-modules"], ", ");
      if (!UeberBackend::loadModules(modules, ::arg()["module-dir"])) {
        exit(1);
      }
    }

    BackendMakers().launch(::arg()["launch"]); // vrooooom!

    if (!::arg().getCommands().empty()) {
      cerr << "Fatal: non-option";
      if (::arg().getCommands().size() > 1) {
        cerr << "s";
      }
      cerr << " (";
      bool first = true;
      for (const auto& c : ::arg().getCommands()) {
        if (!first) {
          cerr << ", ";
        }
        first = false;
        cerr << c;
      }
      cerr << ") on the command line, perhaps a '--setting=123' statement missed the '='?" << endl;
      exit(99);
    }

    if (::arg().mustDo("help")) {
      cout << "syntax:" << endl
           << endl;
      cout << ::arg().helpstring(::arg()["help"]) << endl;
      exit(0);
    }

    if (::arg().mustDo("config")) {
      string config = ::arg()["config"];
      if (config == "default") {
        cout << ::arg().configstring(false, true);
      }
      else if (config == "diff") {
        cout << ::arg().configstring(true, false);
      }
      else if (config == "check") {
        try {
          if (!::arg().mustDo("no-config"))
            ::arg().file(configname.c_str());
          ::arg().parse(argc, argv);
          exit(0);
        }
        catch (const ArgException& A) {
          cerr << "Fatal error: " << A.reason << endl;
          exit(1);
        }
      }
      else {
        cout << ::arg().configstring(true, true);
      }
      exit(0);
    }

    if (::arg().mustDo("list-modules")) {
      auto modules = BackendMakers().getModules();
      cout << "Modules available:" << endl;
      for (const auto& m : modules)
        cout << m << endl;

      _exit(99);
    }

    if (!::arg().asNum("local-port")) {
      g_log << Logger::Error << "Unable to launch, binding to no port or port 0 makes no sense" << endl;
      exit(99); // this isn't going to fix itself either
    }
    if (!BackendMakers().numLauncheable()) {
      g_log << Logger::Error << "Unable to launch, no backends configured for querying" << endl;
      exit(99); // this isn't going to fix itself either
    }
    if (::arg().mustDo("daemon")) {
      g_log.toConsole(Logger::None);
      if (!isGuarded(argv))
        daemonize();
    }

    if (isGuarded(argv)) {
      g_log << Logger::Warning << "This is a guarded instance of pdns" << endl;
      s_dynListener = std::make_unique<DynListener>(); // listens on stdin
    }
    else {
      g_log << Logger::Warning << "This is a standalone pdns" << endl;

      if (::arg().mustDo("control-console"))
        s_dynListener = std::make_unique<DynListener>();
      else
        s_dynListener = std::make_unique<DynListener>(g_programname);

      writePid();
    }
    DynListener::registerExitFunc("QUIT", &DLRQuitHandler);
    DynListener::registerFunc("CCOUNTS", &DLCCHandler, "get cache statistics");
    DynListener::registerFunc("CURRENT-CONFIG", &DLCurrentConfigHandler, "retrieve the current configuration", "[diff]");
    DynListener::registerFunc("FLUSH", &DLFlushHandler, "flush backend data");
    DynListener::registerFunc("LIST-ZONES", &DLListZones, "show list of zones", "[primary|secondary|native|consumer|producer]");
    DynListener::registerFunc("NOTIFY", &DLNotifyHandler, "queue a notification", "<zone>");
    DynListener::registerFunc("NOTIFY-HOST", &DLNotifyHostHandler, "notify host for specific zone", "<zone> <host>");
    DynListener::registerFunc("PURGE", &DLPurgeHandler, "purge entries from packet cache", "[<record>]");
    DynListener::registerFunc("QTYPES", &DLQTypesHandler, "get QType statistics");
    DynListener::registerFunc("REDISCOVER", &DLRediscoverHandler, "discover any new zones");
    DynListener::registerFunc("RELOAD", &DLReloadHandler, "reload all zones");
    DynListener::registerFunc("REMOTES", &DLRemotesHandler, "get top remotes");
    DynListener::registerFunc("RESPSIZES", &DLRSizesHandler, "get histogram of response sizes");
    DynListener::registerFunc("RETRIEVE", &DLNotifyRetrieveHandler, "retrieve secondary zone", "<zone> [<ip>]");
    DynListener::registerFunc("RPING", &DLPingHandler, "ping instance");
    DynListener::registerFunc("SET", &DLSettingsHandler, "set config variables", "<var> <value>");
    DynListener::registerFunc("SHOW", &DLShowHandler, "show a specific statistic or * to get a list", "<statistic>");
    DynListener::registerFunc("TOKEN-LOGIN", &DLTokenLogin, "Login to a PKCS#11 token", "<module> <slot> <pin>");
    DynListener::registerFunc("UPTIME", &DLUptimeHandler, "get instance uptime");
    DynListener::registerFunc("VERSION", &DLVersionHandler, "get instance version");
    DynListener::registerFunc("XFR-QUEUE", &DLSuckRequests, "Get all requests for XFR in queue");

    if (!::arg()["tcp-control-address"].empty()) {
      DynListener* dlTCP = new DynListener(ComboAddress(::arg()["tcp-control-address"], ::arg().asNum("tcp-control-port")));
      dlTCP->go();
    }

    // reparse, with error checking
    if (!::arg().mustDo("no-config"))
      ::arg().file(configname.c_str());
    ::arg().parse(argc, argv);

    if (::arg()["server-id"].empty()) {
      char tmp[128];
      if (gethostname(tmp, sizeof(tmp) - 1) == 0) {
        ::arg().set("server-id") = tmp;
      }
      else {
        g_log << Logger::Warning << "Unable to get the hostname, NSID and id.server values will be empty: " << stringerror() << endl;
      }
    }

    s_udpNameserver = std::make_shared<UDPNameserver>(); // this fails when we are not root, throws exception
    s_udpReceivers.push_back(s_udpNameserver);

    size_t rthreads = ::arg().asNum("receiver-threads", 1);
    if (rthreads > 1 && s_udpNameserver->canReusePort()) {
      s_udpReceivers.resize(rthreads);

      for (size_t idx = 1; idx < rthreads; idx++) {
        try {
          s_udpReceivers[idx] = std::make_shared<UDPNameserver>(true);
        }
        catch (const PDNSException& e) {
          g_log << Logger::Error << "Unable to reuse port, falling back to original bind" << endl;
          break;
        }
      }
    }

    s_tcpNameserver = make_unique<TCPNameserver>();
  }
  catch (const ArgException& A) {
    g_log << Logger::Error << "Fatal error: " << A.reason << endl;
    exit(1);
  }
  catch (const std::exception& e) {
    g_log << Logger::Error << "Fatal error: " << e.what() << endl;
    exit(1);
  }

  try {
    declareStats();
  }
  catch (const PDNSException& PE) {
    g_log << Logger::Error << "Exiting because: " << PE.reason << endl;
    exit(1);
  }

  try {
    auto defaultCatalog = ::arg()["default-catalog-zone"];
    if (!defaultCatalog.empty()) {
      auto defCatalog = DNSName(defaultCatalog);
    }
  }
  catch (const std::exception& e) {
    g_log << Logger::Error << "Invalid value '" << ::arg()["default-catalog-zone"] << "' for default-catalog-zone: " << e.what() << endl;
    exit(1);
  }
  S.blacklist("special-memory-usage");

  DLOG(g_log << Logger::Warning << "Verbose logging in effect" << endl);

  for (const string& line : getProductVersionLines()) {
    g_log << Logger::Warning << line << endl;
  }

  try {
    mainthread();
  }
  catch (const PDNSException& e) {
    try {
      if (!::arg().mustDo("daemon")) {
        cerr << "Exiting because: " << e.reason << endl;
      }
    }
    catch (const ArgException& A) {
    }
    g_log << Logger::Error << "Exiting because: " << e.reason << endl;
  }
  catch (const std::exception& e) {
    try {
      if (!::arg().mustDo("daemon")) {
        cerr << "Exiting because of STL error: " << e.what() << endl;
      }
    }
    catch (const ArgException& A) {
    }
    g_log << Logger::Error << "Exiting because of STL error: " << e.what() << endl;
  }
  catch (...) {
    cerr << "Uncaught exception of unknown type - sorry" << endl;
  }

  exit(1);
}
