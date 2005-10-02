#ifndef PDNS_BASE64_HH
#define PDNS_BASE64_HH
#include <string>
#include <vector>

int B64Decode(const std::string& strInput, std::string& strOutput);
std::string Base64Encode (const std::string& vby);
#endif
