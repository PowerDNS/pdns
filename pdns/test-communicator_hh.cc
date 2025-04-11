#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdlib.h>
#include <unistd.h>
#include <boost/test/unit_test.hpp>
#include "communicator.hh"

BOOST_AUTO_TEST_SUITE(test_communicator_hh)

BOOST_AUTO_TEST_CASE(test_axfr_queue_priority_order)
{
  SuckRequest sr[5] = {
    {ZoneName("test1.com"), ComboAddress("0.0.0.0"), false, {SuckRequest::SignaturesRefresh, 0}},
    {ZoneName("test2.com"), ComboAddress("0.0.0.0"), false, {SuckRequest::SerialRefresh, 1}},
    {ZoneName("test3.com"), ComboAddress("0.0.0.0"), false, {SuckRequest::Notify, 2}},
    {ZoneName("test4.com"), ComboAddress("0.0.0.0"), false, {SuckRequest::Api, 3}},
    {ZoneName("test5.com"), ComboAddress("0.0.0.0"), false, {SuckRequest::PdnsControl, 4}},
  };

  UniQueue suckDomains;

  suckDomains.insert(sr[0]);
  suckDomains.insert(sr[1]);
  suckDomains.insert(sr[2]);
  suckDomains.insert(sr[3]);
  suckDomains.insert(sr[4]);

  for (int i = 4; i >= 0; i--) {
    auto iter = suckDomains.begin();
    BOOST_CHECK_EQUAL(iter->domain, sr[i].domain);
    suckDomains.erase(iter);
  }
  BOOST_CHECK(suckDomains.empty());
}

BOOST_AUTO_TEST_CASE(test_axfr_queue_insert_and_priority_order)
{
  SuckRequest sr[5] = {
    {ZoneName("test1.com"), ComboAddress("0.0.0.0"), false, {SuckRequest::Api, 2}},
    {ZoneName("test2.com"), ComboAddress("0.0.0.0"), false, {SuckRequest::Api, 1}},
    {ZoneName("test3.com"), ComboAddress("0.0.0.0"), false, {SuckRequest::Api, 0}},
    {ZoneName("test4.com"), ComboAddress("0.0.0.0"), false, {SuckRequest::PdnsControl, 4}},
    {ZoneName("test5.com"), ComboAddress("0.0.0.0"), false, {SuckRequest::PdnsControl, 3}},
  };

  UniQueue suckDomains;

  suckDomains.insert(sr[0]);
  suckDomains.insert(sr[1]);
  suckDomains.insert(sr[2]);
  suckDomains.insert(sr[3]);
  suckDomains.insert(sr[4]);

  for (int i = 4; i >= 0; i--) {
    auto iter = suckDomains.begin();
    BOOST_CHECK_EQUAL(iter->domain, sr[i].domain);
    suckDomains.erase(iter);
  }
  BOOST_CHECK(suckDomains.empty());
}

BOOST_AUTO_TEST_CASE(test_axfr_queue_insert_and_priority_order_after_modify)
{
  SuckRequest sr[5] = {
    {ZoneName("test1.com"), ComboAddress("0.0.0.0"), false, {SuckRequest::Api, 1}},
    {ZoneName("test2.com"), ComboAddress("0.0.0.0"), false, {SuckRequest::Api, 0}},
    {ZoneName("test3.com"), ComboAddress("0.0.0.0"), false, {SuckRequest::Api, 2}},
    {ZoneName("test4.com"), ComboAddress("0.0.0.0"), false, {SuckRequest::PdnsControl, 4}},
    {ZoneName("test5.com"), ComboAddress("0.0.0.0"), false, {SuckRequest::PdnsControl, 3}},
  };
  SuckRequest rr1 = {ZoneName("test3.com"), ComboAddress("0.0.0.0"), false, {SuckRequest::PdnsControl, 5}};
  SuckRequest rr2 = {ZoneName("test4.com"), ComboAddress("0.0.0.0"), false, {SuckRequest::Api, 6}};

  UniQueue suckDomains;

  suckDomains.insert(sr[0]);
  suckDomains.insert(sr[1]);
  suckDomains.insert(sr[2]);
  suckDomains.insert(sr[3]);
  suckDomains.insert(sr[4]);

  auto res = suckDomains.insert(rr1);
  BOOST_CHECK(!res.second);
  suckDomains.modify(res.first, [priorityAndOrder = rr1.priorityAndOrder](SuckRequest& so) {
    if (priorityAndOrder.first < so.priorityAndOrder.first) {
      so.priorityAndOrder = priorityAndOrder;
    }
  });

  res = suckDomains.insert(rr2);
  BOOST_CHECK(!res.second);
  suckDomains.modify(res.first, [priorityAndOrder = rr2.priorityAndOrder](SuckRequest& so) {
    if (priorityAndOrder.first < so.priorityAndOrder.first) {
      so.priorityAndOrder = priorityAndOrder;
    }
  });

  for (int i = 4; i >= 0; i--) {
    auto iter = suckDomains.begin();
    BOOST_CHECK_EQUAL(iter->domain, sr[i].domain);
    suckDomains.erase(iter);
  }
  BOOST_CHECK(suckDomains.empty());
}

BOOST_AUTO_TEST_SUITE_END()
