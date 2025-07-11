#pragma once

#include "credentials.hh"
#include "dnsdist-prometheus.hh"
#include "sstuff.hh"

namespace dnsdist::webserver
{
void WebserverThread(ComboAddress listeningAddress, Socket sock);
void setMaxConcurrentConnections(size_t max);
void registerBuiltInWebHandlers();
void clearWebHandlers();
std::string getConfig();
bool addMetricDefinition(const dnsdist::prometheus::PrometheusMetricDefinition& def);
}
