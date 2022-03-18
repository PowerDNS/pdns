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
#include <memory>
#include <optional>

#include "misc.hh"

namespace pdns
{
namespace channel
{
  /**
   * The sender's end of a channel used to pass objects between threads.
   *
   * A sender can be used by several threads in a safe way.
   */
  template <typename T>
  class Sender
  {
  public:
    Sender()
    {
    }
    Sender(FDWrapper&& fd) :
      d_fd(std::move(fd))
    {
    }
    Sender(const Sender&) = delete;
    Sender& operator=(const Sender&) = delete;
    Sender(Sender&&) = default;
    Sender& operator=(Sender&&) = default;
    /**
     * \brief Try to send the supplied object to the other end of that channel. Might block if the channel was created in blocking mode.
     *
     * \return True if the object was properly sent, False if the channel is full.
     *
     * \throw runtime_error if the channel is broken, for example if the other end has been closed.
     */
    bool send(std::unique_ptr<T>&&) const;

  private:
    FDWrapper d_fd;
  };

  /**
   * The receiver's end of a channel used to pass objects between threads.
   *
   * A receiver can be used by several threads in a safe way, but in that case spurious wake up might happen.
   */
  template <typename T>
  class Receiver
  {
  public:
    Receiver()
    {
    }
    Receiver(FDWrapper&& fd) :
      d_fd(std::move(fd))
    {
    }
    Receiver(const Receiver&) = delete;
    Receiver& operator=(const Receiver&) = delete;
    Receiver(Receiver&&) = default;
    Receiver& operator=(Receiver&&) = default;
    /**
     * \brief Try to read an object sent by the other end of that channel. Might block if the channel was created in blocking mode.
     *
     * \return An object if one was available, and std::nullopt otherwise.
     *
     * \throw runtime_error if the channel is broken, for example if the other end has been closed.
     */
    std::optional<std::unique_ptr<T>> receive() const;

    /**
     * \brief Get a descriptor that can be used with an I/O multiplexer to wait for an object to become available.
     *
     * \return A valid descriptor or -1 if the Receiver was not properly initialized.
     */
    int getDescriptor() const
    {
      return d_fd.getHandle();
    }

  private:
    FDWrapper d_fd;
  };

  /**
   * \brief Create a channel to pass objects between threads, accepting multiple senders and receivers.
   *
   * \return A pair of Sender and Receiver objects.
   *
   * \throw runtime_error if the channel creation failed.
   */
  template <typename T>
  std::pair<Sender<T>, Receiver<T>> createObjectQueue(bool nonBlocking = true, size_t pipeBufferSize = 0);

  /**
   * The notifier's end of a channel used to communicate between threads.
   *
   * A notifier can be used by several threads in a safe way.
   */
  class Notifier
  {
  public:
    Notifier()
    {
    }
    Notifier(FDWrapper&&);
    Notifier(const Notifier&) = delete;
    Notifier& operator=(const Notifier&) = delete;
    Notifier(Notifier&&) = default;
    Notifier& operator=(Notifier&&) = default;

    /**
     * \brief Queue a notification to wake up the other end of the channel.
     *
     * \return True if the notification was properly sent, False if the channel is full.
     *
     * \throw runtime_error if the channel is broken, for example if the other end has been closed.
     */
    bool notify() const;

  private:
    FDWrapper d_fd;
  };

  /**
   * The waiter's end of a channel used to communicate between threads.
   *
   * A waiter can be used by several threads in a safe way, but in that case spurious wake up might happen.
   */
  class Waiter
  {
  public:
    Waiter(FDWrapper&&);
    Waiter(const Waiter&) = delete;
    Waiter& operator=(const Waiter&) = delete;
    Waiter(Waiter&&) = default;
    Waiter& operator=(Waiter&&) = default;

    /**
     * \brief Clear all notifications queued on that channel, if any.
     */
    void clear() const;
    /**
     * \brief Get a descriptor that can be used with an I/O multiplexer to wait for a notification to arrive.
     *
     * \return A valid descriptor or -1 if the Waiter was not properly initialized.
     */
    int getDescriptor() const;

  private:
    FDWrapper d_fd;
  };

  /**
   * \brief Create a channel to notify one thread from another one, accepting multiple senders and receivers.
   *
   * \return A pair of Notifier and Sender objects.
   *
   * \throw runtime_error if the channel creation failed.
   */
  std::pair<Notifier, Waiter> createNotificationQueue(bool nonBlocking = true, size_t pipeBufferSize = 0);

  template <typename T>
  bool Sender<T>::send(std::unique_ptr<T>&& object) const
  {
    auto ptr = object.release();
    static_assert(sizeof(ptr) <= PIPE_BUF, "Writes up to PIPE_BUF are guaranted not to interleaved and to either fully succeed or fail");
    ssize_t sent = write(d_fd.getHandle(), &ptr, sizeof(ptr));

    if (sent != sizeof(ptr)) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        return false;
      }
      else {
        throw std::runtime_error("Unable to write to channel:" + stringerror());
      }
      delete ptr;
    }

    return true;
  }

  template <typename T>
  std::optional<std::unique_ptr<T>> Receiver<T>::receive() const
  {
    std::optional<std::unique_ptr<T>> result;
    T* obj{nullptr};
    ssize_t got = read(d_fd.getHandle(), &obj, sizeof(obj));
    if (got == sizeof(obj)) {
      return std::unique_ptr<T>(obj);
    }
    else if (got == 0) {
      throw std::runtime_error("EOF while reading from Channel receiver");
    }
    else if (got == -1) {
      if (errno == EAGAIN || errno == EINTR) {
        return result;
      }
      throw std::runtime_error("Error while reading from Channel receiver: " + stringerror());
    }
    else {
      throw std::runtime_error("Partial read from Channel receiver");
    }
  }

  template <typename T>
  std::pair<Sender<T>, Receiver<T>> createObjectQueue(bool nonBlocking, size_t pipeBufferSize)
  {
    int fds[2] = {-1, -1};
    if (pipe(fds) < 0) {
      throw std::runtime_error("Error creating channel pipe: " + stringerror());
    }

    if (nonBlocking && !setNonBlocking(fds[0])) {
      int err = errno;
      close(fds[0]);
      close(fds[1]);
      throw std::runtime_error("Error making channel pipe non-blocking: " + stringerror(err));
    }

    if (nonBlocking && !setNonBlocking(fds[1])) {
      int err = errno;
      close(fds[0]);
      close(fds[1]);
      throw std::runtime_error("Error making channel pipe non-blocking: " + stringerror(err));
    }

    if (pipeBufferSize > 0 && getPipeBufferSize(fds[0]) < pipeBufferSize) {
      setPipeBufferSize(fds[0], pipeBufferSize);
    }

    FDWrapper sender(fds[1]);
    FDWrapper receiver(fds[0]);

    return std::pair(Sender<T>(std::move(sender)), Receiver<T>(std::move(receiver)));
  }
}
}
