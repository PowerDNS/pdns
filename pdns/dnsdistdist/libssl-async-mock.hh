/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#pragma once

#if defined(SSL_MODE_ASYNC) && defined(MOCK_SSL_ASYNC)
#include "channel.hh"

// This class implements a mock OpenSSL Asynchronous Engine to exercize our
// async-aware code in our CI, where we lack proper QAT-like hardware.
// The gist of it is that the first handshake attempt results in the Async
// IOState to be returned to the caller. It should then call the correct method
// to get a file descriptor to poll, expecting the file descriptor to become
// readable when the asynchronous operation has completed.
// We emulate that via a notification queue, marking the file descriptor readable
// as soon as the caller retrieves it.
//
class MockAsyncEngine
{
public:
  [[nodiscard]] std::vector<int> getAsyncFDs()
  {
    std::vector<int> results;
    if (d_asyncChannel) {
      d_asyncPolled = true;
      results.emplace_back(d_asyncChannel->second.getDescriptor());
    }
    return results;
  }

  [[nodiscard]] bool isInAsyncOperation()
  {
    if (d_firstHandshakeAttempt) {
      d_firstHandshakeAttempt = false;
      d_asyncChannel = pdns::channel::createNotificationQueue();
      d_asyncChannel->first.notify();
      return true;
    }
    if (!d_asyncPolled) {
      return true;
    }
    d_asyncChannel.reset();
    return false;
  }

private:
  std::optional<std::pair<pdns::channel::Notifier, pdns::channel::Waiter>> d_asyncChannel{std::nullopt};
  bool d_asyncPolled{false};
  bool d_firstHandshakeAttempt{true};
};

#endif /* defined(SSL_MODE_ASYNC) && defined(MOCK_SSL_ASYNC) */
