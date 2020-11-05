#pragma once

struct WebserverConfig
{
  WebserverConfig()
  {
    acl.toMasks("127.0.0.1, ::1");
  }

  NetmaskGroup acl;
  std::string password;
  std::string apiKey;
  boost::optional<std::map<std::string, std::string> > customHeaders;
  std::mutex lock;
};

void setWebserverAPIKey(const boost::optional<std::string> apiKey);
void setWebserverPassword(const std::string& password);
void setWebserverACL(const std::string& acl);
void setWebserverCustomHeaders(const boost::optional<std::map<std::string, std::string> > customHeaders);

void dnsdistWebserverThread(int sock, const ComboAddress& local);

void registerBuiltInWebHandlers();
