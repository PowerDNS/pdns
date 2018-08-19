#pragma once
#include "iputils.hh"

struct DOHFrontend
{
  std::string d_certFile;
  std::string d_keyFile;
  ComboAddress d_local;
};

int dohThread(const ComboAddress ca, const std::string& certfile, const std::string& keyfile);
