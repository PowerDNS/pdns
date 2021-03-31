
#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "config.h"
#include "credentials.hh"

BOOST_AUTO_TEST_SUITE(credentials_cc)

#ifdef HAVE_LIBSODIUM
BOOST_AUTO_TEST_CASE(test_CredentialsUtils) {
  const std::string plaintext("test");
  /* generated with hashPassword("test") */
  const std::string sampleHash("$argon2id$v=19$m=65536,t=2,p=1$ndQKu3+ZsWedqRrlNFUaNw$tnb0MJVe5C2hlqkDt0Ln3R6VKCYkfMYdxDy+puXes3s");

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

BOOST_AUTO_TEST_CASE(test_CredentialsHolder) {
  const std::string plaintext("test");

  auto holder = CredentialsHolder(std::string(plaintext));

  BOOST_CHECK(holder.matches(plaintext));
  BOOST_CHECK(!holder.matches("not test"));
  BOOST_CHECK(!holder.wasHashed());

#ifdef HAVE_LIBSODIUM
  BOOST_CHECK(CredentialsHolder::isHashingAvailable());
  const std::string sampleHash("$argon2id$v=19$m=65536,t=2,p=1$ndQKu3+ZsWedqRrlNFUaNw$tnb0MJVe5C2hlqkDt0Ln3R6VKCYkfMYdxDy+puXes3s");

  auto fromHashedHolder= CredentialsHolder(std::string(sampleHash));
  BOOST_CHECK(fromHashedHolder.wasHashed());
  BOOST_CHECK(fromHashedHolder.matches(plaintext));
  BOOST_CHECK(!fromHashedHolder.matches("not test"));
#else
  BOOST_CHECK(!CredentialsHolder::isHashingAvailable());
#endif
}

BOOST_AUTO_TEST_SUITE_END()
