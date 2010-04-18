#ifndef PDNS_BASE32_HH
#define PDNS_BASE32_HH
#include <string>

std::string toBase32Hex(const std::string& input);
std::string fromBase32Hex(const std::string& input);

#endif
