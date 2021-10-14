#pragma once

#include "credentials.hh"

void setWebserverAPIKey(std::unique_ptr<CredentialsHolder>&& apiKey);
void setWebserverPassword(std::unique_ptr<CredentialsHolder>&& password);
void setWebserverACL(const std::string& acl);
void setWebserverCustomHeaders(const boost::optional<std::map<std::string, std::string> > customHeaders);
void setWebserverStatsRequireAuthentication(bool);
void setWebserverMaxConcurrentConnections(size_t);

void dnsdistWebserverThread(int sock, const ComboAddress& local);

void registerBuiltInWebHandlers();
void clearWebHandlers();
