
#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "dnsdist.hh"

BOOST_AUTO_TEST_SUITE(dnsdistbackend_cc)

BOOST_AUTO_TEST_CASE(test_Basic)
{
  DownstreamState::Config config;
  DownstreamState ds(std::move(config), nullptr, false);
  BOOST_CHECK(ds.d_config.d_availability == DownstreamState::Availability::Auto);
  BOOST_CHECK(ds.d_config.d_healthCheckMode == DownstreamState::HealthCheckMode::Active);
  BOOST_CHECK_EQUAL(ds.isUp(), false);
  BOOST_CHECK_EQUAL(ds.getStatus(), "down");
  BOOST_CHECK_EQUAL(ds.healthCheckRequired(), true);

  ds.setUp();
  BOOST_CHECK(ds.d_config.d_availability == DownstreamState::Availability::Up);
  BOOST_CHECK_EQUAL(ds.isUp(), true);
  BOOST_CHECK_EQUAL(ds.getStatus(), "UP");
  BOOST_CHECK_EQUAL(ds.healthCheckRequired(), false);

  ds.setDown();
  BOOST_CHECK(ds.d_config.d_availability == DownstreamState::Availability::Down);
  BOOST_CHECK_EQUAL(ds.isUp(), false);
  BOOST_CHECK_EQUAL(ds.getStatus(), "DOWN");
  BOOST_CHECK_EQUAL(ds.healthCheckRequired(), false);

  ds.setAuto();
  BOOST_CHECK(ds.d_config.d_availability == DownstreamState::Availability::Auto);
  BOOST_CHECK_EQUAL(ds.isUp(), false);
  BOOST_CHECK_EQUAL(ds.getStatus(), "down");
  BOOST_CHECK_EQUAL(ds.healthCheckRequired(), true);

  ds.submitHealthCheckResult(true, true);
  BOOST_CHECK(ds.d_config.d_availability == DownstreamState::Availability::Auto);
  BOOST_CHECK_EQUAL(ds.isUp(), true);
  BOOST_CHECK_EQUAL(ds.getStatus(), "up");
  BOOST_CHECK_EQUAL(ds.healthCheckRequired(), true);
}

BOOST_AUTO_TEST_CASE(test_MaxCheckFailures)
{
  const size_t maxCheckFailures = 5;
  DownstreamState::Config config;
  config.maxCheckFailures = maxCheckFailures;
  /* prevents a re-connection */
  config.remote = ComboAddress("0.0.0.0");

  DownstreamState ds(std::move(config), nullptr, false);
  BOOST_CHECK(ds.d_config.d_availability == DownstreamState::Availability::Auto);
  BOOST_CHECK(ds.d_config.d_healthCheckMode == DownstreamState::HealthCheckMode::Active);
  ds.setUpStatus(true);
  BOOST_CHECK_EQUAL(ds.isUp(), true);
  BOOST_CHECK_EQUAL(ds.getStatus(), "up");

  for (size_t idx = 0; idx < maxCheckFailures - 1; idx++) {
    ds.submitHealthCheckResult(false, false);
  }

  /* four failed checks is not enough */
  BOOST_CHECK(ds.d_config.d_availability == DownstreamState::Availability::Auto);
  BOOST_CHECK_EQUAL(ds.isUp(), true);
  BOOST_CHECK_EQUAL(ds.getStatus(), "up");

  /* but five is */
  ds.submitHealthCheckResult(false, false);
  BOOST_CHECK(ds.d_config.d_availability == DownstreamState::Availability::Auto);
  BOOST_CHECK_EQUAL(ds.isUp(), false);
  BOOST_CHECK_EQUAL(ds.getStatus(), "down");

  /* only one successful check is needed to go back up */
  ds.submitHealthCheckResult(false, true);
  BOOST_CHECK(ds.d_config.d_availability == DownstreamState::Availability::Auto);
  BOOST_CHECK_EQUAL(ds.isUp(), true);
  BOOST_CHECK_EQUAL(ds.getStatus(), "up");
}

BOOST_AUTO_TEST_CASE(test_Rise)
{
  const size_t minRise = 5;
  DownstreamState::Config config;
  config.minRiseSuccesses = minRise;
  /* prevents a re-connection */
  config.remote = ComboAddress("0.0.0.0");

  DownstreamState ds(std::move(config), nullptr, false);
  BOOST_CHECK(ds.d_config.d_availability == DownstreamState::Availability::Auto);
  BOOST_CHECK(ds.d_config.d_healthCheckMode == DownstreamState::HealthCheckMode::Active);
  BOOST_CHECK_EQUAL(ds.isUp(), false);
  BOOST_CHECK_EQUAL(ds.getStatus(), "down");

  for (size_t idx = 0; idx < minRise - 1; idx++) {
    ds.submitHealthCheckResult(false, true);
  }

  /* four successful checks is not enough */
  BOOST_CHECK(ds.d_config.d_availability == DownstreamState::Availability::Auto);
  BOOST_CHECK_EQUAL(ds.isUp(), false);
  BOOST_CHECK_EQUAL(ds.getStatus(), "down");

  /* but five is */
  ds.submitHealthCheckResult(false, true);
  BOOST_CHECK(ds.d_config.d_availability == DownstreamState::Availability::Auto);
  BOOST_CHECK_EQUAL(ds.isUp(), true);
  BOOST_CHECK_EQUAL(ds.getStatus(), "up");

  /* only one failed check is needed to go back down */
  ds.submitHealthCheckResult(false, false);
  BOOST_CHECK(ds.d_config.d_availability == DownstreamState::Availability::Auto);
  BOOST_CHECK_EQUAL(ds.isUp(), false);
  BOOST_CHECK_EQUAL(ds.getStatus(), "down");
}

BOOST_AUTO_TEST_CASE(test_Lazy)
{
  DownstreamState::Config config;
  config.minRiseSuccesses = 5;
  config.maxCheckFailures = 3;
  config.d_lazyHealthCheckMinSampleCount = 11;
  config.d_lazyHealthCheckThreshold = 20;
  config.d_lazyHealthCheckUseExponentialBackOff = false;
  config.d_availability = DownstreamState::Availability::Auto;
  config.d_healthCheckMode = DownstreamState::HealthCheckMode::Lazy;
  /* prevents a re-connection */
  config.remote = ComboAddress("0.0.0.0");

  DownstreamState ds(std::move(config), nullptr, false);
  BOOST_CHECK(ds.d_config.d_availability == DownstreamState::Availability::Auto);
  BOOST_CHECK(ds.d_config.d_availability == DownstreamState::Availability::Auto);
  BOOST_CHECK_EQUAL(ds.isUp(), true);
  BOOST_CHECK_EQUAL(ds.getStatus(), "up");
  BOOST_CHECK_EQUAL(ds.healthCheckRequired(), false);

  /* submit a few results, first successful ones */
  for (size_t idx = 0; idx < 5; idx++) {
    ds.reportResponse(RCode::NoError);
  }
  BOOST_CHECK_EQUAL(ds.healthCheckRequired(), false);
  /* then failed ones */
  for (size_t idx = 0; idx < 5; idx++) {
    ds.reportTimeoutOrError();
  }

  /* the threshold should be reached (50% > 20%) but we do not have enough sample yet
     (10 < config.d_lazyHealthCheckMinSampleCount) */
  BOOST_CHECK_EQUAL(ds.isUp(), true);
  BOOST_CHECK_EQUAL(ds.getStatus(), "up");
  BOOST_CHECK_EQUAL(ds.healthCheckRequired(), false);

  /* reporting one valid answer put us above the minimum number of samples,
     and we are still above the threshold */
  ds.reportResponse(RCode::NoError);
  BOOST_CHECK_EQUAL(ds.isUp(), true);
  BOOST_CHECK_EQUAL(ds.getStatus(), "up");
  BOOST_CHECK_EQUAL(ds.healthCheckRequired(), true);

  /* we should be in Potential Failure mode now, and thus always returning true */
  BOOST_CHECK_EQUAL(ds.healthCheckRequired(), true);

  /* even if we fill the whole circular buffer with valid answers */
  for (size_t idx = 0; idx < config.d_lazyHealthCheckSampleSize; idx++) {
    ds.reportResponse(RCode::NoError);
  }
  BOOST_CHECK_EQUAL(ds.isUp(), true);
  BOOST_CHECK_EQUAL(ds.getStatus(), "up");
  BOOST_CHECK_EQUAL(ds.healthCheckRequired(), true);

  /* if we submit at least one valid health-check, we go back to Healthy */
  ds.submitHealthCheckResult(false, true);
  BOOST_CHECK_EQUAL(ds.isUp(), true);
  BOOST_CHECK_EQUAL(ds.getStatus(), "up");
  BOOST_CHECK_EQUAL(ds.healthCheckRequired(), false);

  /* now let's reach the threshold again, this time just barely */
  for (size_t idx = 0; idx < config.d_lazyHealthCheckThreshold; idx++) {
    ds.reportTimeoutOrError();
  }
  BOOST_CHECK_EQUAL(ds.isUp(), true);
  BOOST_CHECK_EQUAL(ds.getStatus(), "up");
  BOOST_CHECK_EQUAL(ds.healthCheckRequired(), true);

  /* we need maxCheckFailures failed health-checks to go down */
  BOOST_REQUIRE(config.maxCheckFailures >= 1);
  for (size_t idx = 0; idx < static_cast<size_t>(config.maxCheckFailures - 1); idx++) {
    ds.submitHealthCheckResult(false, false);
  }
  BOOST_CHECK_EQUAL(ds.isUp(), true);
  BOOST_CHECK_EQUAL(ds.getStatus(), "up");
  BOOST_CHECK_EQUAL(ds.healthCheckRequired(), true);
  time_t failedCheckTime = time(nullptr);
  ds.submitHealthCheckResult(false, false);

  /* now we are in Failed state */
  BOOST_CHECK_EQUAL(ds.isUp(), false);
  BOOST_CHECK_EQUAL(ds.getStatus(), "down");
  BOOST_CHECK(ds.getNextLazyHealthCheck() == (failedCheckTime + config.d_lazyHealthCheckFailedInterval));

  /* let fill the buffer with successes, it does not matter */
  for (size_t idx = 0; idx < config.d_lazyHealthCheckSampleSize; idx++) {
    ds.reportResponse(RCode::NoError);
  }

  /* we need minRiseSuccesses successful health-checks to go up */
  BOOST_REQUIRE(config.minRiseSuccesses >= 1);
  for (size_t idx = 0; idx < static_cast<size_t>(config.minRiseSuccesses - 1); idx++) {
    ds.submitHealthCheckResult(false, true);
  }
  BOOST_CHECK_EQUAL(ds.isUp(), false);
  BOOST_CHECK_EQUAL(ds.getStatus(), "down");

  ds.submitHealthCheckResult(false, true);
  BOOST_CHECK_EQUAL(ds.isUp(), true);
  BOOST_CHECK_EQUAL(ds.getStatus(), "up");
  BOOST_CHECK_EQUAL(ds.healthCheckRequired(), false);
}

BOOST_AUTO_TEST_CASE(test_LazyExponentialBackOff)
{
  DownstreamState::Config config;
  config.minRiseSuccesses = 5;
  config.maxCheckFailures = 3;
  config.d_lazyHealthCheckMinSampleCount = 11;
  config.d_lazyHealthCheckThreshold = 20;
  config.d_lazyHealthCheckUseExponentialBackOff = true;
  config.d_lazyHealthCheckMaxBackOff = 600;
  config.d_lazyHealthCheckFailedInterval = 15;
  DownstreamState::parseAvailabilityConfigFromStr(config, "lazy");

  /* prevents a re-connection */
  config.remote = ComboAddress("0.0.0.0");

  DownstreamState ds(std::move(config), nullptr, false);
  BOOST_CHECK(ds.d_config.d_availability == DownstreamState::Availability::Auto);
  BOOST_CHECK(ds.d_config.d_healthCheckMode == DownstreamState::HealthCheckMode::Lazy);
  BOOST_CHECK_EQUAL(ds.isUp(), true);
  BOOST_CHECK_EQUAL(ds.getStatus(), "up");
  BOOST_CHECK_EQUAL(ds.healthCheckRequired(), false);

  /* submit a few failed results */
  for (size_t idx = 0; idx < config.d_lazyHealthCheckMinSampleCount; idx++) {
    ds.reportTimeoutOrError();
  }
  BOOST_CHECK_EQUAL(ds.isUp(), true);
  BOOST_CHECK_EQUAL(ds.getStatus(), "up");
  BOOST_CHECK_EQUAL(ds.healthCheckRequired(), true);

  /* we should be in Potential Failure mode now, and thus always returning true */
  BOOST_CHECK_EQUAL(ds.healthCheckRequired(), true);

  /* we need maxCheckFailures failed health-checks to go down */
  BOOST_REQUIRE(config.maxCheckFailures >= 1);
  for (size_t idx = 0; idx < static_cast<size_t>(config.maxCheckFailures - 1); idx++) {
    ds.submitHealthCheckResult(false, false);
  }
  BOOST_CHECK_EQUAL(ds.isUp(), true);
  BOOST_CHECK_EQUAL(ds.getStatus(), "up");
  BOOST_CHECK_EQUAL(ds.healthCheckRequired(), true);
  time_t currentTime = time(nullptr);
  ds.submitHealthCheckResult(false, false);

  /* now we are in Failed state */
  BOOST_CHECK_EQUAL(ds.isUp(), false);
  BOOST_CHECK_EQUAL(ds.getStatus(), "down");
  BOOST_CHECK_EQUAL(ds.healthCheckRequired(currentTime), false);
  /* and the wait time between two checks will double every time a failure occurs */
  BOOST_CHECK_EQUAL(ds.getNextLazyHealthCheck(), (currentTime + (config.d_lazyHealthCheckFailedInterval * std::pow(2U, ds.currentCheckFailures - 1))));
  BOOST_CHECK_EQUAL(ds.currentCheckFailures, 1U);

  /* so after 5 failures */
  const size_t nbFailures = 5;
  for (size_t idx = 0; idx < nbFailures; idx++) {
    currentTime = ds.getNextLazyHealthCheck();
    BOOST_CHECK(ds.healthCheckRequired(currentTime));
    ds.submitHealthCheckResult(false, false);
  }
  BOOST_CHECK_EQUAL(ds.currentCheckFailures, nbFailures + 1);
  BOOST_CHECK_EQUAL(ds.getNextLazyHealthCheck(), (currentTime + (config.d_lazyHealthCheckFailedInterval * std::pow(2U, ds.currentCheckFailures - 1))));

  /* we need minRiseSuccesses successful health-checks to go up */
  BOOST_REQUIRE(config.minRiseSuccesses >= 1);
  for (size_t idx = 0; idx < static_cast<size_t>(config.minRiseSuccesses - 1); idx++) {
    ds.submitHealthCheckResult(false, true);
  }
  BOOST_CHECK_EQUAL(ds.isUp(), false);
  BOOST_CHECK_EQUAL(ds.getStatus(), "down");

  ds.submitHealthCheckResult(false, true);
  BOOST_CHECK_EQUAL(ds.isUp(), true);
  BOOST_CHECK_EQUAL(ds.getStatus(), "up");
  BOOST_CHECK_EQUAL(ds.healthCheckRequired(), false);
}

BOOST_AUTO_TEST_CASE(test_CheckAutoRestorePreviousHealthCheckMode)
{
  DownstreamState::Config config;
  DownstreamState::parseAvailabilityConfigFromStr(config, "lazy");
  /* prevents a re-connection */
  config.remote = ComboAddress("0.0.0.0");

  DownstreamState ds(std::move(config), nullptr, false);
  BOOST_CHECK(ds.d_config.d_availability == DownstreamState::Availability::Auto);
  BOOST_CHECK(ds.d_config.d_healthCheckMode == DownstreamState::HealthCheckMode::Lazy);
  ds.setUp();
  BOOST_CHECK(ds.d_config.d_availability == DownstreamState::Availability::Up);
  ds.setAuto();
  BOOST_CHECK(ds.d_config.d_availability == DownstreamState::Availability::Auto);
  BOOST_CHECK(ds.d_config.d_healthCheckMode == DownstreamState::HealthCheckMode::Lazy);
  ds.setActiveAuto();
  BOOST_CHECK(ds.d_config.d_availability == DownstreamState::Availability::Auto);
  BOOST_CHECK(ds.d_config.d_healthCheckMode == DownstreamState::HealthCheckMode::Active);
  ds.setUp();
  BOOST_CHECK(ds.d_config.d_availability == DownstreamState::Availability::Up);
  ds.setAuto();
  BOOST_CHECK(ds.d_config.d_availability == DownstreamState::Availability::Auto);
  BOOST_CHECK(ds.d_config.d_healthCheckMode == DownstreamState::HealthCheckMode::Active);
}

BOOST_AUTO_TEST_SUITE_END()
