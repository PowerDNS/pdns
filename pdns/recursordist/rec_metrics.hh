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

#pragma once

#include <string>
#include <unordered_map>
#include <vector>
#include <inttypes.h>
#include <unistd.h>
#include <atomic>

// Metric types for Prometheus
enum class PrometheusMetricType: int {
    counter = 1,
    gauge = 2
};

// Keeps additional information about metrics
struct MetricDefinition {
    MetricDefinition(const PrometheusMetricType& prometheusType_, const std::string& description_) {
      prometheusType = prometheusType_;
      description = description_;
    }

    MetricDefinition() = default;

    // Metric description
    std::string description;
    // Metric type for Prometheus
    PrometheusMetricType prometheusType;
};

class MetricDefinitionStorage {
public:
    // Return metric definition by name
    bool getMetricDetails(const std::string& metricName, MetricDefinition& metric) {
      auto metricDetailsIter = metrics.find(metricName);

      if (metricDetailsIter == metrics.end()) {
        return false;
      }

      metric = metricDetailsIter->second;
      return true;
    };

    // Return string representation of Prometheus metric type
    std::string getPrometheusStringMetricType(const PrometheusMetricType& metricType) {
      switch (metricType) {
        case PrometheusMetricType::counter:
          return "counter";
              break;
        case PrometheusMetricType::gauge:
          return "gauge";
              break;
        default:
          return "";
              break;
      }
    };

private:
    // Description and types for prometheus output of stats
    std::map<std::string, MetricDefinition> metrics = {
            { "all-outqueries",              MetricDefinition(PrometheusMetricType::counter, "Number of outgoing UDP queries since starting") },

            { "answers-slow",              MetricDefinition(PrometheusMetricType::counter, "Number of queries answered after 1 second") },
            { "answers0-1",              MetricDefinition(PrometheusMetricType::counter, "Number of queries answered within 1 millisecond") },
            { "answers1-10",              MetricDefinition(PrometheusMetricType::counter, "Number of queries answered within 10 milliseconds") },
            { "answers10-100",              MetricDefinition(PrometheusMetricType::counter, "Number of queries answered within 100 milliseconds") },
            { "answers100-1000",              MetricDefinition(PrometheusMetricType::counter, "Number of queries answered within 1 second") },

            { "auth4-answers-slow",              MetricDefinition(PrometheusMetricType::counter, "Number of queries answered by authoritatives over IPv4 after 1 second") },
            { "auth4-answers0-1",              MetricDefinition(PrometheusMetricType::counter, "Number of queries answered by authoritatives over IPv4within 1 millisecond") },
            { "auth4-answers1-10",              MetricDefinition(PrometheusMetricType::counter, "Number of queries answered by authoritatives over IPv4 within 10 milliseconds") },
            { "auth4-answers10-100",              MetricDefinition(PrometheusMetricType::counter, "Number of queries answered by authoritatives over IPv4 within 100 milliseconds") },
            { "auth4-answers100-1000",              MetricDefinition(PrometheusMetricType::counter, "Number of queries answered by authoritatives over IPv4 within 1 second") },

            { "auth6-answers-slow",              MetricDefinition(PrometheusMetricType::counter, "Number of queries answered by authoritatives over IPv6 after 1 second") },
            { "auth6-answers0-1",              MetricDefinition(PrometheusMetricType::counter, "Number of queries answered by authoritatives over IPv6 within 1 millisecond") },
            { "auth6-answers1-10",              MetricDefinition(PrometheusMetricType::counter, "Number of queries answered by authoritatives over IPv6 within 10 milliseconds") },
            { "auth6-answers10-100",              MetricDefinition(PrometheusMetricType::counter, "Number of queries answered by authoritatives over IPv6 within 100 milliseconds") },
            { "auth6-answers100-1000",              MetricDefinition(PrometheusMetricType::counter, "Number of queries answered by authoritatives over IPv6 within 1 second") },



            { "auth-zone-queries",              MetricDefinition(PrometheusMetricType::counter, "Number of queries to locally hosted authoritative zones (`setting-auth-zones`) since starting") },
            { "cache-bytes",              MetricDefinition(PrometheusMetricType::gauge, "Size of the cache in bytes") },
            { "cache-entries",              MetricDefinition(PrometheusMetricType::gauge, "Number of entries in the cache") },
            { "cache-hits",              MetricDefinition(PrometheusMetricType::counter, "Number of of cache hits since starting, this does **not** include hits that got answered from the packet-cache") },
            { "cache-misses",              MetricDefinition(PrometheusMetricType::counter, "Number of cache misses since starting") },
            { "case-mismatches",              MetricDefinition(PrometheusMetricType::counter, "Number of mismatches in character case since starting") },
            { "chain-resends",              MetricDefinition(PrometheusMetricType::counter, "Number of queries chained to existing outstanding") },
            { "client-parse-errors",              MetricDefinition(PrometheusMetricType::counter, "Number of client packets that could not be parsed") },
            { "concurrent-queries",              MetricDefinition(PrometheusMetricType::gauge, "Number of MThreads currently running") },
            { "cpu-msec-thread-0",              MetricDefinition(PrometheusMetricType::counter, "Number of milliseconds spent in thread n") },
            { "dlg-only-drops",              MetricDefinition(PrometheusMetricType::counter, "Number of records dropped because of `setting-delegation-only` setting") },

            { "dnssec-authentic-data-queries",              MetricDefinition(PrometheusMetricType::counter, "Number of queries received with the AD bit set") },
            { "dnssec-check-disabled-queries",              MetricDefinition(PrometheusMetricType::counter, "Number of queries received with the CD bit set") },
            { "dnssec-queries",              MetricDefinition(PrometheusMetricType::counter, "Number of queries received with the DO bit set") },
            { "dnssec-result-bogus",              MetricDefinition(PrometheusMetricType::counter, "Number of DNSSEC validations that had the Bogus state") },
            { "dnssec-result-indeterminate",              MetricDefinition(PrometheusMetricType::counter, "Number of DNSSEC validations that had the Indeterminate state") },
            { "dnssec-result-insecure",              MetricDefinition(PrometheusMetricType::counter, "Number of DNSSEC validations that had the Insecure state") },
            { "dnssec-result-nta",              MetricDefinition(PrometheusMetricType::counter, "Number of DNSSEC validations that had the (negative trust anchor) state") },
            { "dnssec-result-secure",              MetricDefinition(PrometheusMetricType::counter, "Number of DNSSEC validations that had the Secure state") },

            { "dnssec-validations",              MetricDefinition(PrometheusMetricType::counter, "Number of DNSSEC validations performed") },
            { "dont-outqueries",              MetricDefinition(PrometheusMetricType::counter, "Number of outgoing queries dropped because of `setting-dont-query` setting") },
            { "ecs-queries",              MetricDefinition(PrometheusMetricType::counter, "Number of outgoing queries adorned with an EDNS Client Subnet option") },
            { "ecs-responses",              MetricDefinition(PrometheusMetricType::counter, "Number of responses received from authoritative servers with an EDNS Client Subnet option we used") },
            { "edns-ping-matches",              MetricDefinition(PrometheusMetricType::counter, "Number of servers that sent a valid EDNS PING response") },
            { "edns-ping-mismatches",              MetricDefinition(PrometheusMetricType::counter, "Number of servers that sent an invalid EDN PING response") },
            { "failed-host-entries",              MetricDefinition(PrometheusMetricType::counter, "Number of servers that failed to resolve") },
            { "ignored-packets",              MetricDefinition(PrometheusMetricType::counter, "Number of non-query packets received on server sockets that should only get query packets") },
            { "ipv6-outqueries",              MetricDefinition(PrometheusMetricType::counter, "Number of outgoing queries over IPv6") },
            { "ipv6-questions",              MetricDefinition(PrometheusMetricType::counter, "Number of end-user initiated queries with the RD bit set, received over IPv6 UDP") },
            { "malloc-bytes",              MetricDefinition(PrometheusMetricType::counter, "Number of bytes allocated by the process (broken, always returns 0)") },
            { "max-cache-entries",              MetricDefinition(PrometheusMetricType::gauge, "Currently configured maximum number of cache entries") },
            { "max-packetcache-entries",              MetricDefinition(PrometheusMetricType::gauge, "Currently configured maximum number of packet cache entries") },
            { "max-mthread-stack",              MetricDefinition(PrometheusMetricType::gauge, "Maximum amount of thread stack ever used") },


            { "negcache-entries",              MetricDefinition(PrometheusMetricType::gauge, "Number of entries in the negative answer cache") },
            { "no-packet-error",              MetricDefinition(PrometheusMetricType::counter, "Number of erroneous received packets") },
            { "noedns-outqueries",              MetricDefinition(PrometheusMetricType::counter, "Number of queries sent out without EDNS") },
            { "noerror-answers",              MetricDefinition(PrometheusMetricType::counter, "Number of NOERROR answers since starting") },
            { "noping-outqueries",              MetricDefinition(PrometheusMetricType::counter, "Number of queries sent out without ENDS PING") },
            { "nsset-invalidations",              MetricDefinition(PrometheusMetricType::counter, "Number of times an nsset was dropped because it no longer worked") },
            { "nsspeeds-entries",              MetricDefinition(PrometheusMetricType::gauge, "Number of entries in the NS speeds map") },
            { "nxdomain-answers",              MetricDefinition(PrometheusMetricType::counter, "Number of NXDOMAIN answers since starting") },
            { "outgoing-timeouts",              MetricDefinition(PrometheusMetricType::counter, "Number of timeouts on outgoing UDP queries since starting") },
            { "outgoing4-timeouts",              MetricDefinition(PrometheusMetricType::counter, "Number of timeouts on outgoing UDP IPv4 queries since starting") },
            { "outgoing6-timeouts",              MetricDefinition(PrometheusMetricType::counter, "Number of timeouts on outgoing UDP IPv6 queries since starting") },
            { "over-capacity-drops",              MetricDefinition(PrometheusMetricType::counter, "Number of questions dropped because over maximum concurrent query limit") },
            { "packetcache-bytes",              MetricDefinition(PrometheusMetricType::gauge, "Size of the packet cache in bytes") },
            { "packetcache-entries",              MetricDefinition(PrometheusMetricType::gauge, "Number of packet cache entries") },
            { "packetcache-hits",              MetricDefinition(PrometheusMetricType::counter, "Number of packet cache hits") },
            { "packetcache-misses",              MetricDefinition(PrometheusMetricType::counter, "Number of packet cache misses") },

            { "policy-drops",              MetricDefinition(PrometheusMetricType::counter, "Number of packets dropped because of (Lua) policy decision") },
            { "policy-result-noaction",              MetricDefinition(PrometheusMetricType::counter, "Number of packets that were not actioned upon by the RPZ/filter engine") },
            { "policy-result-drop",              MetricDefinition(PrometheusMetricType::counter, "Number of packets that were dropped by the RPZ/filter engine") },
            { "policy-result-nxdomain",              MetricDefinition(PrometheusMetricType::counter, "Number of packets that were replied to with NXDOMAIN by the RPZ/filter engine") },
            { "policy-result-nodata",              MetricDefinition(PrometheusMetricType::counter, "Number of packets that were replied to with no data by the RPZ/filter engine") },
            { "policy-result-truncate",              MetricDefinition(PrometheusMetricType::counter, "Number of packets that were were forced to TCP by the RPZ/filter engine") },
            { "policy-result-custom",              MetricDefinition(PrometheusMetricType::counter, "Number of packets that were sent a custom answer by the RPZ/filter engine") },

            { "qa-latency",              MetricDefinition(PrometheusMetricType::gauge, "Shows the current latency average, in microseconds, exponentially weighted over past 'latency-statistic-size' packets") },
            { "query-pipe-full-drops",              MetricDefinition(PrometheusMetricType::counter, "Number of questions dropped because the query distribution pipe was full") },
            { "questions",              MetricDefinition(PrometheusMetricType::counter, "Counts all end-user initiated queries with the RD bit set") },
            { "rebalanced-queries",              MetricDefinition(PrometheusMetricType::counter, "Number of queries balanced to a different worker thread because the first selected one was above the target load configured with 'distribution-load-factor'") },
            { "resource-limits",              MetricDefinition(PrometheusMetricType::counter, "Number of queries that could not be performed because of resource limits") },
            { "security-status",              MetricDefinition(PrometheusMetricType::gauge, "security status based on `securitypolling`") },
            { "server-parse-errors",              MetricDefinition(PrometheusMetricType::counter, "Number of server replied packets that could not be parsed") },
            { "servfail-answers",              MetricDefinition(PrometheusMetricType::counter, "Number of SERVFAIL answers since starting") },
            { "spoof-prevents",              MetricDefinition(PrometheusMetricType::counter, "Number of times PowerDNS considered itself spoofed, and dropped the data") },
            { "sys-msec",              MetricDefinition(PrometheusMetricType::counter, "Number of CPU milliseconds spent in 'system' mode") },
            { "tcp-client-overflow",              MetricDefinition(PrometheusMetricType::counter, "Number of times an IP address was denied TCP access because it already had too many connections") },
            { "tcp-clients",              MetricDefinition(PrometheusMetricType::gauge, "Number of currently active TCP/IP clients") },
            { "tcp-outqueries",              MetricDefinition(PrometheusMetricType::counter, "Number of outgoing TCP queries since starting") },
            { "tcp-questions",              MetricDefinition(PrometheusMetricType::counter, "Number of all incoming TCP queries since starting") },
            { "throttle-entries",              MetricDefinition(PrometheusMetricType::gauge, "Number of of entries in the throttle map") },
            { "throttled-out",              MetricDefinition(PrometheusMetricType::counter, "Number of throttled outgoing UDP queries since starting") },
            { "throttled-outqueries",              MetricDefinition(PrometheusMetricType::counter, "Number of throttled outgoing UDP queries since starting") },
            { "too-old-drops",              MetricDefinition(PrometheusMetricType::counter, "Number of questions dropped that were too old") },
            { "truncated-drops",              MetricDefinition(PrometheusMetricType::counter, "Number of questions dropped because they were larger than 512 bytes") },
            { "empty-queries",              MetricDefinition(PrometheusMetricType::counter, "Questions dropped because they had a QD count of 0") },
            { "unauthorized-tcp",              MetricDefinition(PrometheusMetricType::counter, "Number of TCP questions denied because of allow-from restrictions") },
            { "unauthorized-udp",              MetricDefinition(PrometheusMetricType::counter, "Number of UDP questions denied because of allow-from restrictions") },
            { "unexpected-packets",              MetricDefinition(PrometheusMetricType::counter, "Number of answers from remote servers that were unexpected (might point to spoofing)") },
            { "unreachables",              MetricDefinition(PrometheusMetricType::counter, "Number of times nameservers were unreachable since starting") },
            { "uptime",              MetricDefinition(PrometheusMetricType::counter, "Number of seconds process has been running") },
            { "user-msec",              MetricDefinition(PrometheusMetricType::counter, "Number of CPU milliseconds spent in 'user' mode") },
            { "variable-responses",              MetricDefinition(PrometheusMetricType::counter, "Number of responses that were marked as 'variable'") },

            { "x-our-latency",              MetricDefinition(PrometheusMetricType::counter, "How much time was spent within PowerDNS in microseconds") },
            { "x-ourtime0-1",              MetricDefinition(PrometheusMetricType::counter, "Counts responses where between 0 and 1 milliseconds was spent within the Recursor") },
            { "x-ourtime1-2",              MetricDefinition(PrometheusMetricType::counter, "Counts responses where between 1 and 2 milliseconds was spent within the Recursor") },
            { "x-ourtime2-4",              MetricDefinition(PrometheusMetricType::counter, "Counts responses where between 2 and 4 milliseconds was spent within the Recursor") },
            { "x-ourtime4-8",              MetricDefinition(PrometheusMetricType::counter, "Counts responses where between 4 and 8 milliseconds was spent within the Recursor") },
            { "x-ourtime8-16",              MetricDefinition(PrometheusMetricType::counter, "Counts responses where between 8 and 16 milliseconds was spent within the Recursor") },
            { "x-ourtime16-32",              MetricDefinition(PrometheusMetricType::counter, "Counts responses where between 16 and 32 milliseconds was spent within the Recursor") },
            { "x-ourtime-slow",              MetricDefinition(PrometheusMetricType::counter, "Counts responses where more than 32 milliseconds was spent within the Recursor") },

            { "fd-usage",              MetricDefinition(PrometheusMetricType::gauge, "Number of open file descriptors") },
            { "real-memory-usage",              MetricDefinition(PrometheusMetricType::gauge, "Number of bytes real process memory usage") },
            { "udp-in-errors",              MetricDefinition(PrometheusMetricType::counter, "From /proc/net/snmp InErrors") },
            { "udp-noport-errors",              MetricDefinition(PrometheusMetricType::counter, "From /proc/net/snmp NoPorts") },
            { "udp-recvbuf-errors",              MetricDefinition(PrometheusMetricType::counter, "From /proc/net/snmp RcvbufErrors") },
            { "udp-sndbuf-errors",              MetricDefinition(PrometheusMetricType::counter, "From /proc/net/snmp SndbufErrors") },
    };
};

extern MetricDefinitionStorage g_metricDefinitions;
