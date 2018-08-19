#pragma once
#include "iputils.hh"

struct DOHFrontend
{
  std::string d_certFile;
  std::string d_keyFile;
  ComboAddress d_local;
  std::vector<std::string> d_urls;
};

int dohThread(const ComboAddress ca, std::vector<std::string> urls, string certfile, string keyfile);
