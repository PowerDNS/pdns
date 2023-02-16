#pragma once

#include "credentials.hh"

void setWebserverAPIKey(std::unique_ptr<CredentialsHolder>&& apiKey);
void setWebserverPassword(std::unique_ptr<CredentialsHolder>&& password);
void setWebserverACL(const std::string& acl);
void setWebserverCustomHeaders(const boost::optional<std::unordered_map<std::string, std::string> > customHeaders);
void setWebserverAPIRequiresAuthentication(bool);
void setWebserverDashboardRequiresAuthentication(bool);
void setWebserverStatsRequireAuthentication(bool);
void setWebserverMaxConcurrentConnections(size_t);

void dnsdistWebserverThread(int sock, const ComboAddress& local);

void registerBuiltInWebHandlers();
void clearWebHandlers();

bool addMetricDefinition(const std::string& name, const std::string& type, const std::string& description, const std::string& customPrometheusName);

std::string getWebserverConfig();
