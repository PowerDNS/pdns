#pragma once
#include "iputils.hh"
#include <string>

// see https://powerdns.org/ipcipher

ComboAddress encryptCA(const ComboAddress& ca, const std::string& key);
ComboAddress decryptCA(const ComboAddress& ca, const std::string& key);
std::string makeIPCipherKey(const std::string& password);
