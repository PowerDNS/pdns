
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "config.h"
#include "credentials.hh"

BOOST_AUTO_TEST_SUITE(credentials_cc)

#ifdef HAVE_EVP_PKEY_CTX_SET1_SCRYPT_SALT
BOOST_AUTO_TEST_CASE(test_CredentialsUtils)
{
  const std::string plaintext("test");
  /* generated with hashPassword("test") */
  const std::string sampleHash("$scrypt$ln=10,p=1,r=8$1GZ10YdmSGtTmKK9jTH85Q==$JHeICW1mUCnTC+nnULDr7QFQ3kRrZ7u12djruJdrPhI=");

  auto hashed = hashPassword(plaintext);
  BOOST_CHECK(!hashed.empty());

  BOOST_CHECK(verifyPassword(hashed, plaintext));
  BOOST_CHECK(verifyPassword(sampleHash, plaintext));

  BOOST_CHECK(!verifyPassword(hashed, "not test"));
  BOOST_CHECK(!verifyPassword(sampleHash, "not test"));

  BOOST_CHECK(isPasswordHashed(hashed));
  BOOST_CHECK(isPasswordHashed(sampleHash));
  BOOST_CHECK(!isPasswordHashed(plaintext));
}
#endif

BOOST_AUTO_TEST_CASE(test_CredentialsHolder)
{
  const std::string plaintext("test");

  auto holder = CredentialsHolder(std::string(plaintext), false);

  BOOST_CHECK(holder.matches(plaintext));
  BOOST_CHECK(!holder.matches("not test"));
  BOOST_CHECK(!holder.wasHashed());
  BOOST_CHECK(!holder.isHashed());

#ifdef HAVE_EVP_PKEY_CTX_SET1_SCRYPT_SALT
  BOOST_CHECK(CredentialsHolder::isHashingAvailable());
  const std::string sampleHash("$scrypt$ln=10,p=1,r=8$1GZ10YdmSGtTmKK9jTH85Q==$JHeICW1mUCnTC+nnULDr7QFQ3kRrZ7u12djruJdrPhI=");

  auto fromHashedHolder = CredentialsHolder(std::string(sampleHash), true);
  BOOST_CHECK(fromHashedHolder.wasHashed());
  BOOST_CHECK(fromHashedHolder.isHashed());
  BOOST_CHECK(fromHashedHolder.matches(plaintext));
  BOOST_CHECK(!fromHashedHolder.matches("not test"));

  auto fromPlaintextHolder = CredentialsHolder(std::string(plaintext), true);
  BOOST_CHECK(!fromPlaintextHolder.wasHashed());
  BOOST_CHECK(fromPlaintextHolder.isHashed());
  BOOST_CHECK(fromPlaintextHolder.matches(plaintext));
  BOOST_CHECK(!fromPlaintextHolder.matches("not test"));
#else
  BOOST_CHECK(!CredentialsHolder::isHashingAvailable());
#endif
}

BOOST_AUTO_TEST_SUITE_END()
