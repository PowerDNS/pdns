#pragma once
#include "iputils.hh"
#include <string>

ComboAddress encryptCA(const ComboAddress& ca, const std::string& key);
ComboAddress decryptCA(const ComboAddress& ca, const std::string& key);
