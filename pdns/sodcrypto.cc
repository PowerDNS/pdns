#include <sodium.h>
#include <iostream>
#include "namespaces.hh"
#include "misc.hh"
#include "base64.hh"

string newKeypair()
{
  unsigned char alice_publickey[crypto_box_PUBLICKEYBYTES];
  unsigned char alice_secretkey[crypto_box_SECRETKEYBYTES];
  crypto_box_keypair(alice_publickey, alice_secretkey);
  
  string ret("{\"");
  ret+=Base64Encode(string((char*)alice_publickey, crypto_box_PUBLICKEYBYTES));
  ret+="\",\"";
  ret+=Base64Encode(string((char*)alice_secretkey, crypto_box_SECRETKEYBYTES));
  ret+="\"}";
  return ret;
}

// return: nonce + ciphertext

std::string sodEncrypt(const std::string& msg, const std::string& secretSource,
		  const std::string& publicDest)
{
  unsigned char nonce[crypto_box_NONCEBYTES];
  unsigned char ciphertext[msg.length() + crypto_box_MACBYTES];
  randombytes_buf(nonce, sizeof nonce);
  /*
  cerr<<"Encrypt plen: "<<msg.length()<<endl;
  cerr<<"Encrypt nonce: "<<makeHexDump(string((const char*)nonce, sizeof nonce))<<endl;
  cerr<<"keylen: "<<secretSource.length()<<", "<<publicDest.length()<<endl;
  */
  crypto_box_easy(ciphertext, (const unsigned char*)msg.c_str(), msg.length(), 
		  nonce,  (const unsigned char*)publicDest.c_str(),   // bob_pub
		  (const unsigned char*) secretSource.c_str());       // alice_sec
  //  cerr<<"MAC: "<<makeHexDump(string((const char*)ciphertext, crypto_box_MACBYTES))<<endl;
  string ret((const char*)nonce, crypto_box_NONCEBYTES);
  ret.append((const char*)ciphertext, sizeof(ciphertext));
  return ret;
}

std::string sodDecrypt(const std::string& msg, const std::string& publicSource,
		  const std::string& secretDest)
{
  auto plen = msg.size() - crypto_box_NONCEBYTES - crypto_box_MACBYTES;
  /*
  cerr<<"Payload len: "<<plen<<endl;
  cerr<<"Nonce: "<<makeHexDump(msg.substr(0, crypto_box_NONCEBYTES))<<endl;
  cerr<<"MAC: "<<makeHexDump(msg.substr(crypto_box_NONCEBYTES, crypto_box_MACBYTES))<<endl;
  cerr<<"keylen: "<<publicSource.length()<<", "<<secretDest.length()<<endl;
  */
  unsigned char decrypted[plen];
  if (crypto_box_open_easy(decrypted, (const unsigned char*)msg.c_str() + crypto_box_NONCEBYTES, plen + crypto_box_MACBYTES, (const unsigned char*)msg.c_str(),
			   (const unsigned char*)publicSource.c_str(),   // alice_pub
			   (const unsigned char*)secretDest.c_str()) != 0) {  // bob_sec
    /* message for Bob pretending to be from Alice has been forged! */
    throw runtime_error("Could not decrypt!");
  }

  return string((char*)decrypted, plen);
}


void sodTest()
{
#define MESSAGE (const unsigned char *) "test"
#define MESSAGE_LEN 4
#define CIPHERTEXT_LEN (crypto_box_MACBYTES + MESSAGE_LEN)

  unsigned char alice_publickey[crypto_box_PUBLICKEYBYTES];
  unsigned char alice_secretkey[crypto_box_SECRETKEYBYTES];
  crypto_box_keypair(alice_publickey, alice_secretkey);
  
 
  unsigned char bob_publickey[crypto_box_PUBLICKEYBYTES];
  unsigned char bob_secretkey[crypto_box_SECRETKEYBYTES];
  crypto_box_keypair(bob_publickey, bob_secretkey);
  
  unsigned char nonce[crypto_box_NONCEBYTES];
  unsigned char ciphertext[CIPHERTEXT_LEN];
  randombytes_buf(nonce, sizeof nonce);
  crypto_box_easy(ciphertext, MESSAGE, MESSAGE_LEN, nonce,
		  bob_publickey, alice_secretkey);
  
  unsigned char decrypted[MESSAGE_LEN];
  if (crypto_box_open_easy(decrypted, ciphertext, CIPHERTEXT_LEN, nonce,
			   alice_publickey, bob_secretkey) != 0) {
    /* message for Bob pretending to be from Alice has been forged! */
    cerr<<"BAD!"<<endl;
  }
  else 
    cerr<<"Decrypted: "<<string((char*)decrypted, MESSAGE_LEN)<<endl;
}
