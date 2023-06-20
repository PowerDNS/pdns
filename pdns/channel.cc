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

#include "channel.hh"

namespace pdns::channel
{

Notifier::Notifier(FDWrapper&& descriptor) :
  d_fd(std::move(descriptor))
{
}

bool Notifier::notify() const
{
  char data = 'a';
  while (true) {
    auto sent = write(d_fd.getHandle(), &data, sizeof(data));
    if (sent == 0) {
      throw std::runtime_error("Unable to write to channel notifier pipe: remote end has been closed");
    }
    if (sent != sizeof(data)) {
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return false;
      }
      throw std::runtime_error("Unable to write to channel notifier pipe: " + stringerror());
    }
    return true;
  }
}

Waiter::Waiter(FDWrapper&& descriptor, bool throwOnEOF) :
  d_fd(std::move(descriptor)), d_throwOnEOF(throwOnEOF)
{
}

void Waiter::clear()
{
  ssize_t got{0};
  do {
    char data{0};
    got = read(d_fd.getHandle(), &data, sizeof(data));
    if (got == 0) {
      d_closed = true;
      if (!d_throwOnEOF) {
        return;
      }
      throw std::runtime_error("EOF while clearing channel notifier pipe");
    }
    if (got == -1) {
      if (errno == EINTR) {
        continue;
      }
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        break;
      }
      throw std::runtime_error("Error while clearing channel notifier pipe: " + stringerror());
    }
  } while (got > 0);
}

int Waiter::getDescriptor() const
{
  return d_fd.getHandle();
}

std::pair<Notifier, Waiter> createNotificationQueue(bool nonBlocking, size_t pipeBufferSize, bool throwOnEOF)
{
  std::array<int, 2> fds = {-1, -1};
  if (pipe(fds.data()) < 0) {
    throw std::runtime_error("Error creating notification channel pipe: " + stringerror());
  }

  FDWrapper sender(fds[1]);
  FDWrapper receiver(fds[0]);

  if (nonBlocking && !setNonBlocking(receiver.getHandle())) {
    int err = errno;
    throw std::runtime_error("Error making notification channel pipe non-blocking: " + stringerror(err));
  }

  if (nonBlocking && !setNonBlocking(sender.getHandle())) {
    int err = errno;
    throw std::runtime_error("Error making notification channel pipe non-blocking: " + stringerror(err));
  }

  if (pipeBufferSize > 0 && getPipeBufferSize(receiver.getHandle()) < pipeBufferSize) {
    setPipeBufferSize(receiver.getHandle(), pipeBufferSize);
  }

  return {Notifier(std::move(sender)), Waiter(std::move(receiver), throwOnEOF)};
}
}
