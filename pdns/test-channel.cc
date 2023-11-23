#ifndef BOOST_TEST_DYN_LINK
#define BOOST_TEST_DYN_LINK
#endif

#define BOOST_TEST_NO_MAIN

#include <boost/test/unit_test.hpp>

#include "channel.hh"

struct MyObject
{
  uint64_t a{0};
};

BOOST_AUTO_TEST_SUITE(test_channel)

BOOST_AUTO_TEST_CASE(test_object_queue)
{
  auto [sender, receiver] = pdns::channel::createObjectQueue<MyObject>();

  BOOST_CHECK(receiver.getDescriptor() != -1);
  BOOST_CHECK_EQUAL(receiver.isClosed(), false);

  auto got = receiver.receive();
  BOOST_CHECK(!got);

  auto obj = std::make_unique<MyObject>();
  obj->a = 42U;
  BOOST_CHECK_EQUAL(sender.send(std::move(obj)), true);
  BOOST_CHECK(!obj);
  got = receiver.receive();
  BOOST_CHECK(got != std::nullopt && *got);
  BOOST_CHECK_EQUAL((*got)->a, 42U);
}

BOOST_AUTO_TEST_CASE(test_object_queue_full)
{
  auto [sender, receiver] = pdns::channel::createObjectQueue<MyObject>();

  {
    auto got = receiver.receive();
    BOOST_CHECK(!got);
  }

  /* add objects to the queue until it becomes full */
  bool blocked = false;
  size_t queued = 0;
  while (!blocked) {
    auto obj = std::make_unique<MyObject>();
    obj->a = 42U;
    blocked = !sender.send(std::move(obj));
    if (blocked) {
      BOOST_CHECK(obj);
    }
    else {
      BOOST_CHECK(!obj);
      ++queued;
    }
  }

  BOOST_CHECK_GT(queued, 1U);

  /* clear the queue */
  blocked = false;
  size_t received = 0;
  while (!blocked) {
    auto got = receiver.receive();
    if (got) {
      ++received;
    }
    else {
      blocked = true;
    }
  }

  BOOST_CHECK_EQUAL(queued, received);

  /* we should be able to write again */
  auto obj = std::make_unique<MyObject>();
  obj->a = 42U;
  BOOST_CHECK(sender.send(std::move(obj)));
  /* and to get it */
  {
    auto got = receiver.receive();
    BOOST_CHECK(got);
  }
}

BOOST_AUTO_TEST_CASE(test_object_queue_throw_on_eof)
{
  auto [sender, receiver] = pdns::channel::createObjectQueue<MyObject>();
  sender.close();
  BOOST_CHECK_THROW(receiver.receive(), std::runtime_error);
  BOOST_CHECK_EQUAL(receiver.isClosed(), true);
}

BOOST_AUTO_TEST_CASE(test_object_queue_do_not_throw_on_eof)
{
  auto [sender, receiver] = pdns::channel::createObjectQueue<MyObject>(pdns::channel::SenderBlockingMode::SenderNonBlocking, pdns::channel::ReceiverBlockingMode::ReceiverNonBlocking, 0U, false);
  sender.close();
  auto got = receiver.receive();
  BOOST_CHECK(got == std::nullopt);
  BOOST_CHECK_EQUAL(receiver.isClosed(), true);
}

BOOST_AUTO_TEST_CASE(test_notification_queue_full)
{
  auto [notifier, waiter] = pdns::channel::createNotificationQueue();

  BOOST_CHECK(waiter.getDescriptor() != -1);
  BOOST_CHECK_EQUAL(waiter.isClosed(), false);
  waiter.clear();

  /* add notifications until the queue becomes full */
  bool blocked = false;
  while (!blocked) {
    blocked = notifier.notify();
  }

  /* clear the queue */
  waiter.clear();

  /* we should be able to write again */
  BOOST_CHECK(notifier.notify());
}

BOOST_AUTO_TEST_CASE(test_notification_queue_throw_on_eof)
{
  auto [notifier, waiter] = pdns::channel::createNotificationQueue();

  BOOST_CHECK(waiter.getDescriptor() != -1);
  BOOST_CHECK_EQUAL(waiter.isClosed(), false);

  BOOST_CHECK_EQUAL(notifier.notify(), true);
  waiter.clear();

  notifier = pdns::channel::Notifier();
  BOOST_CHECK_THROW(waiter.clear(), std::runtime_error);
}

BOOST_AUTO_TEST_CASE(test_notification_queue_do_not_throw_on_eof)
{
  auto [notifier, waiter] = pdns::channel::createNotificationQueue(true, 0, false);

  BOOST_CHECK(waiter.getDescriptor() != -1);
  BOOST_CHECK_EQUAL(waiter.isClosed(), false);

  BOOST_CHECK_EQUAL(notifier.notify(), true);
  waiter.clear();

  notifier = pdns::channel::Notifier();
  waiter.clear();
  BOOST_CHECK_EQUAL(waiter.isClosed(), true);
}

BOOST_AUTO_TEST_SUITE_END()
