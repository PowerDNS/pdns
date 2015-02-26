#pragma once
#include <string>

void sodTest();
std::string newKeypair();

std::string sodEncrypt(const std::string& msg, const std::string& secretSource,
		       const std::string& publicDest);


std::string sodDecrypt(const std::string& msg, const std::string& publicSource,
		       const std::string& secretDest);


