#pragma once
#include <string>
#include <stdint.h>
#include <sodium.h>
void sodTest();
std::string newKeypair();

std::string sodEncryptAsym(const std::string& msg, const std::string& secretSource,
		       const std::string& publicDest);


std::string sodDecryptAsym(const std::string& msg, const std::string& publicSource,
		       const std::string& secretDest);



struct SodiumNonce
{
  void init()
  {
    randombytes_buf(value, sizeof value);
  }
  
  void increment()
  {
    uint64_t* p = (uint64_t*)value;
    (*p)++;
  }

  string toString() const
  {
    return string((const char*)value, crypto_secretbox_NONCEBYTES);
  }

  unsigned char value[crypto_secretbox_NONCEBYTES];
};

std::string sodEncryptSym(const std::string& msg, const std::string& key, SodiumNonce&);
std::string sodDecryptSym(const std::string& msg, const std::string& key, SodiumNonce&);
std::string newKey();
