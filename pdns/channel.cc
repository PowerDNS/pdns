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

namespace pdns
{
namespace channel
{

  Notifier::Notifier(FDWrapper&& fd) :
    d_fd(std::move(fd))
  {
  }

  bool Notifier::notify() const
  {
    char data = 'a';
    auto sent = write(d_fd.getHandle(), &data, sizeof(data));
    if (sent != sizeof(data)) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return false;
      }
      else {
        throw std::runtime_error("Unable to write to channel notifier pipe: " + stringerror());
      }
    }
    return true;
  }

  Waiter::Waiter(FDWrapper&& fd) :
    d_fd(std::move(fd))
  {
  }

  void Waiter::clear() const
  {
    ssize_t got;
    do {
      char data;
      got = read(d_fd.getHandle(), &data, sizeof(data));
      if (got == 0) {
        throw std::runtime_error("EOF while clearing channel notifier pipe");
      }
      else if (got == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          break;
        }
        throw std::runtime_error("Error while clearing channel notifier pipe: " + stringerror());
      }
    } while (got);
  }

  int Waiter::getDescriptor() const
  {
    return d_fd.getHandle();
  }

  std::pair<Notifier, Waiter> createNotificationQueue(bool nonBlocking, size_t pipeBufferSize)
  {
    int fds[2] = {-1, -1};
    if (pipe(fds) < 0) {
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

    return std::pair(Notifier(std::move(sender)), Waiter(std::move(receiver)));
  }
}
}
