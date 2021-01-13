#pragma once

void setWebserverAPIKey(const boost::optional<std::string> apiKey);
void setWebserverPassword(const std::string& password);
void setWebserverACL(const std::string& acl);
void setWebserverCustomHeaders(const boost::optional<std::map<std::string, std::string> > customHeaders);
void setWebserverStatsRequireAuthentication(bool);

void dnsdistWebserverThread(int sock, const ComboAddress& local);

void registerBuiltInWebHandlers();
