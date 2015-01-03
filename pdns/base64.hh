#ifndef PDNS_BASE64_HH
#define PDNS_BASE64_HH

#include <string>

int B64Decode(const std::string& src, std::string& dst);
std::string Base64Encode (const std::string& src);

#endif
