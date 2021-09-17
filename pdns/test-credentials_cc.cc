
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#include <boost/algorithm/string.hpp>
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

  {
    // hash password with custom parameters
    auto customParams = hashPassword(plaintext, 512, 2, 16);
    // check that the output is OK
    BOOST_CHECK(boost::starts_with(customParams, "$scrypt$ln=9,p=2,r=16$"));
    // check that we can verify the password
    BOOST_CHECK(verifyPassword(customParams, plaintext));
  }

  // empty
  BOOST_CHECK(!isPasswordHashed(""));
  // missing leading $
  BOOST_CHECK(!isPasswordHashed("scrypt$ln=10,p=1,r=8$1GZ10YdmSGtTmKK9jTH85Q==$JHeICW1mUCnTC+nnULDr7QFQ3kRrZ7u12djruJdrPhI="));
  // unknown algo
  BOOST_CHECK(!isPasswordHashed("$tcrypt$ln=10,p=1,r=8$1GZ10YdmSGtTmKK9jTH85Q==$JHeICW1mUCnTC+nnULDr7QFQ3kRrZ7u12djruJdrPhI="));
  // missing parameters
  BOOST_CHECK(!isPasswordHashed("$scrypt$1GZ10YdmSGtTmKK9jTH85Q==$JHeICW1mUCnTC+nnULDr7QFQ3kRrZ7u12djruJdrPhI="));
  // empty parameters
  BOOST_CHECK(!isPasswordHashed("$scrypt$$1GZ10YdmSGtTmKK9jTH85Q==$JHeICW1mUCnTC+nnULDr7QFQ3kRrZ7u12djruJdrPhI="));
  // missing r
  BOOST_CHECK(!isPasswordHashed("$scrypt$ln=10,p=1$1GZ10YdmSGtTmKK9jTH85Q==$JHeICW1mUCnTC+nnULDr7QFQ3kRrZ7u12djruJdrPhI="));
  // salt is too short
  BOOST_CHECK(!isPasswordHashed("$scrypt$ln=10,p=1,r=8$dGVzdA==$JHeICW1mUCnTC+nnULDr7QFQ3kRrZ7u12djruJdrPhI="));
  // hash is too short
  BOOST_CHECK(!isPasswordHashed("$scrypt$ln=10,p=1,r=8$1GZ10YdmSGtTmKK9jTH85Q==$c2hvcnQ="));
  // missing salt
  BOOST_CHECK(!isPasswordHashed("$scrypt$ln=10,p=1,r=8$JHeICW1mUCnTC+nnULDr7QFQ3kRrZ7u12djruJdrPhI="));
  // missing $ between the salt and hash
  BOOST_CHECK(!isPasswordHashed("$scrypt$ln=10,p=1,r=8$1GZ10YdmSGtTmKK9jTH85Q==JHeICW1mUCnTC+nnULDr7QFQ3kRrZ7u12djruJdrPhI="));
  // no hash
  BOOST_CHECK(!isPasswordHashed("$scrypt$ln=10,p=1,r=8$1GZ10YdmSGtTmKK9jTH85Q==$"));
  // hash is too long
  BOOST_CHECK(!isPasswordHashed("$scrypt$ln=10,p=1,r=8$1GZ10YdmSGtTmKK9jTH85Q==$dGhpcyBpcyBhIHZlcnkgbG9uZyBoYXNoLCBtdWNoIG11Y2ggbG9uZ2VyIHRoYW4gdGhlIG9uZXMgd2UgYXJlIGdlbmVyYXRpbmc="));

  // empty r
  BOOST_CHECK_THROW(verifyPassword("$scrypt$ln=10,p=1,r=$1GZ10YdmSGtTmKK9jTH85Q==$JHeICW1mUCnTC+nnULDr7QFQ3kRrZ7u12djruJdrPhI=", plaintext), std::runtime_error);
  // too many parameters
  BOOST_CHECK_THROW(verifyPassword("$scrypt$ln=10,p=1,r=8,t=1$1GZ10YdmSGtTmKK9jTH85Q==$JHeICW1mUCnTC+nnULDr7QFQ3kRrZ7u12djruJdrPhI=", plaintext), std::runtime_error);
  // invalid ln
  BOOST_CHECK_THROW(verifyPassword("$scrypt$ln=A,p=1,r=8$1GZ10YdmSGtTmKK9jTH85Q==$JHeICW1mUCnTC+nnULDr7QFQ3kRrZ7u12djruJdrPhI=", plaintext), std::runtime_error);
  // invalid p
  BOOST_CHECK_THROW(verifyPassword("$scrypt$ln=10,p=p,r=8$1GZ10YdmSGtTmKK9jTH85Q==$JHeICW1mUCnTC+nnULDr7QFQ3kRrZ7u12djruJdrPhI=", plaintext), std::runtime_error);
  // work factor is too large
  BOOST_CHECK_THROW(verifyPassword("$scrypt$ln=16,p=1,r=8$1GZ10YdmSGtTmKK9jTH85Q==$JHeICW1mUCnTC+nnULDr7QFQ3kRrZ7u12djruJdrPhI=", plaintext), std::runtime_error);
  // salt is too long
  BOOST_CHECK_THROW(verifyPassword("$scrypt$ln=10,p=1,r=8$dGhpcyBpcyBhIHZlcnkgbG9uZyBzYWx0$JHeICW1mUCnTC+nnULDr7QFQ3kRrZ7u12djruJdrPhI=", plaintext), std::runtime_error);
  // invalid b64 salt
  BOOST_CHECK_THROW(verifyPassword("$scrypt$ln=10,p=1,r=8$1GZ10YdmSGtTmKK9jTH85$JHeICW1mUCnTC+nnULDr7QFQ3kRrZ7u12djruJdrPhI=", plaintext), std::runtime_error);
  // invalid b64 hash
  BOOST_CHECK_THROW(verifyPassword("$scrypt$ln=10,p=1,r=8$1GZ10YdmSGtTmKK9jTH85Q==$JHeICW1mUCnTC+nnULDr7QFQ3kRrZ7u12djruJd", plaintext), std::runtime_error);
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
