#pragma once
#include "filterpo.hh"
#include <string>

int loadRPZFromFile(const std::string& fname, DNSFilterEngine& target, int place);
