#pragma once
#include "config.h"

#include "iputils.hh"
#include <string>

// see https://powerdns.org/ipcipher

#ifdef HAVE_IPCIPHER
ComboAddress encryptCA(const ComboAddress& address, const std::string& key);
ComboAddress decryptCA(const ComboAddress& address, const std::string& key);
std::string makeIPCipherKey(const std::string& password);
#endif /* HAVE_IPCIPHER */
