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

/* g++ defines __SANITIZE_THREAD__
   clang++ supports the nice __has_feature(thread_sanitizer),
   let's merge them */
#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define __SANITIZE_THREAD__ 1
#endif
#endif

#if __SANITIZE_THREAD__
#if defined __has_include
#if __has_include(<sanitizer/tsan_interface.h>)
#include <sanitizer/tsan_interface.h>
#else /* __has_include(<sanitizer/tsan_interface.h>) */
extern "C" void __tsan_acquire(void* addr);
extern "C" void __tsan_release(void* addr);
#endif /* __has_include(<sanitizer/tsan_interface.h>) */
#else /* defined __has_include */
extern "C" void __tsan_acquire(void* addr);
extern "C" void __tsan_release(void* addr);
#endif /* defined __has_include */
#endif /* __SANITIZE_THREAD__ */

namespace pdns
{
namespace channel
{
  enum class SenderBlockingMode
  {
    SenderNonBlocking,
    SenderBlocking
  };
  enum class ReceiverBlockingMode
  {
    ReceiverNonBlocking,
    ReceiverBlocking
  };

  /**
   * The sender's end of a channel used to pass objects between threads.
   *
   * A sender can be used by several threads in a safe way.
   */
  template <typename T, typename D = std::default_delete<T>>
  class Sender
  {
  public:
    Sender() = default;
    Sender(FDWrapper&& descriptor) :
      d_fd(std::move(descriptor))
    {
    }
    Sender(const Sender&) = delete;
    Sender& operator=(const Sender&) = delete;
    Sender(Sender&&) = default;
    Sender& operator=(Sender&&) = default;
    ~Sender() = default;
    /**
     * \brief Try to send the supplied object to the other end of that channel. Might block if the channel was created in blocking mode.
     *
     * \return True if the object was properly sent, False if the channel is full.
     *
     * \throw runtime_error if the channel is broken, for example if the other end has been closed.
     */
    bool send(std::unique_ptr<T, D>&&) const;
    void close();

  private:
    FDWrapper d_fd;
  };

  /**
   * The receiver's end of a channel used to pass objects between threads.
   *
   * A receiver can be used by several threads in a safe way, but in that case spurious wake up might happen.
   */
  template <typename T, typename D = std::default_delete<T>>
  class Receiver
  {
  public:
    Receiver() = default;
    Receiver(FDWrapper&& descriptor, bool throwOnEOF = true) :
      d_fd(std::move(descriptor)), d_throwOnEOF(throwOnEOF)
    {
    }
    Receiver(const Receiver&) = delete;
    Receiver& operator=(const Receiver&) = delete;
    Receiver(Receiver&&) = default;
    Receiver& operator=(Receiver&&) = default;
    ~Receiver() = default;
    /**
     * \brief Try to read an object sent by the other end of that channel. Might block if the channel was created in blocking mode.
     *
     * \return An object if one was available, and std::nullopt otherwise.
     *
     * \throw runtime_error if the channel is broken, for example if the other end has been closed.
     */
    std::optional<std::unique_ptr<T, D>> receive();
    std::optional<std::unique_ptr<T, D>> receive(D deleter);

    /**
     * \brief Get a descriptor that can be used with an I/O multiplexer to wait for an object to become available.
     *
     * \return A valid descriptor or -1 if the Receiver was not properly initialized.
     */
    int getDescriptor() const
    {
      return d_fd.getHandle();
    }
    /**
     * \brief Whether the remote end has closed the channel.
     */
    bool isClosed() const
    {
      return d_closed;
    }

  private:
    FDWrapper d_fd;
    bool d_closed{false};
    bool d_throwOnEOF{true};
  };

  /**
   * \brief Create a channel to pass objects between threads, accepting multiple senders and receivers.
   *
   * \return A pair of Sender and Receiver objects.
   *
   * \throw runtime_error if the channel creation failed.
   */
  template <typename T, typename D = std::default_delete<T>>
  std::pair<Sender<T, D>, Receiver<T, D>> createObjectQueue(SenderBlockingMode senderBlockingMode = SenderBlockingMode::SenderNonBlocking, ReceiverBlockingMode receiverBlockingMode = ReceiverBlockingMode::ReceiverNonBlocking, size_t pipeBufferSize = 0, bool throwOnEOF = true);

  /**
   * The notifier's end of a channel used to communicate between threads.
   *
   * A notifier can be used by several threads in a safe way.
   */
  class Notifier
  {
  public:
    Notifier() = default;
    Notifier(FDWrapper&&);
    Notifier(const Notifier&) = delete;
    Notifier& operator=(const Notifier&) = delete;
    Notifier(Notifier&&) = default;
    Notifier& operator=(Notifier&&) = default;
    ~Notifier() = default;

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
    Waiter() = default;
    Waiter(FDWrapper&&, bool throwOnEOF = true);
    Waiter(const Waiter&) = delete;
    Waiter& operator=(const Waiter&) = delete;
    Waiter(Waiter&&) = default;
    Waiter& operator=(Waiter&&) = default;
    ~Waiter() = default;

    /**
     * \brief Clear all notifications queued on that channel, if any.
     */
    void clear();
    /**
     * \brief Get a descriptor that can be used with an I/O multiplexer to wait for a notification to arrive.
     *
     * \return A valid descriptor or -1 if the Waiter was not properly initialized.
     */
    int getDescriptor() const;
    /**
     * \brief Whether the remote end has closed the channel.
     */
    bool isClosed() const
    {
      return d_closed;
    }

  private:
    FDWrapper d_fd;
    bool d_closed{false};
    bool d_throwOnEOF{true};
  };

  /**
   * \brief Create a channel to notify one thread from another one, accepting multiple senders and receivers.
   *
   * \return A pair of Notifier and Sender objects.
   *
   * \throw runtime_error if the channel creation failed.
   */
  std::pair<Notifier, Waiter> createNotificationQueue(bool nonBlocking = true, size_t pipeBufferSize = 0, bool throwOnEOF = true);

  template <typename T, typename D>
  bool Sender<T, D>::send(std::unique_ptr<T, D>&& object) const
  {
    /* we cannot touch the initial unique pointer after writing to the pipe,
       not even to release it, so let's transfer it to a local object */
    auto localObj = std::move(object);
    auto ptr = localObj.get();
    static_assert(sizeof(ptr) <= PIPE_BUF, "Writes up to PIPE_BUF are guaranteed not to interleaved and to either fully succeed or fail");
    while (true) {
#if __SANITIZE_THREAD__
      __tsan_release(ptr);
#endif /* __SANITIZE_THREAD__ */
      ssize_t sent = write(d_fd.getHandle(), &ptr, sizeof(ptr));

      if (sent == sizeof(ptr)) {
        // coverity[leaked_storage]
        localObj.release();
        return true;
      }
      else if (sent == 0) {
#if __SANITIZE_THREAD__
        __tsan_acquire(ptr);
#endif /* __SANITIZE_THREAD__ */
        throw std::runtime_error("Unable to write to channel: remote end has been closed");
      }
      else {
#if __SANITIZE_THREAD__
        __tsan_acquire(ptr);
#endif /* __SANITIZE_THREAD__ */
        if (errno == EINTR) {
          continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          object = std::move(localObj);
          return false;
        }
        else {
          throw std::runtime_error("Unable to write to channel:" + stringerror());
        }
      }
    }
  }

  template <typename T, typename D>
  void Sender<T, D>::close()
  {
    d_fd.reset();
  }

  template <typename T, typename D>
  std::optional<std::unique_ptr<T, D>> Receiver<T, D>::receive()
  {
    return receive(D());
  }

  template <typename T, typename D>
  std::optional<std::unique_ptr<T, D>> Receiver<T, D>::receive(D deleter)
  {
    while (true) {
      std::optional<std::unique_ptr<T, D>> result;
      T* objPtr{nullptr};
      ssize_t got = read(d_fd.getHandle(), &objPtr, sizeof(objPtr));
      if (got == sizeof(objPtr)) {
#if __SANITIZE_THREAD__
        __tsan_acquire(objPtr);
#endif /* __SANITIZE_THREAD__ */
        return std::unique_ptr<T, D>(objPtr, deleter);
      }
      else if (got == 0) {
        d_closed = true;
        if (!d_throwOnEOF) {
          return result;
        }
        throw std::runtime_error("EOF while reading from Channel receiver");
      }
      else if (got == -1) {
        if (errno == EINTR) {
          continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          return result;
        }
        throw std::runtime_error("Error while reading from Channel receiver: " + stringerror());
      }
      else {
        throw std::runtime_error("Partial read from Channel receiver");
      }
    }
  }

  template <typename T, typename D>
  std::pair<Sender<T, D>, Receiver<T, D>> createObjectQueue(SenderBlockingMode senderBlockingMode, ReceiverBlockingMode receiverBlockingMode, size_t pipeBufferSize, bool throwOnEOF)
  {
    int fds[2] = {-1, -1};
    if (pipe(fds) < 0) {
      throw std::runtime_error("Error creating channel pipe: " + stringerror());
    }

    FDWrapper sender(fds[1]);
    FDWrapper receiver(fds[0]);
    if (receiverBlockingMode == ReceiverBlockingMode::ReceiverNonBlocking && !setNonBlocking(receiver.getHandle())) {
      int err = errno;
      throw std::runtime_error("Error making channel pipe non-blocking: " + stringerror(err));
    }

    if (senderBlockingMode == SenderBlockingMode::SenderNonBlocking && !setNonBlocking(sender.getHandle())) {
      int err = errno;
      throw std::runtime_error("Error making channel pipe non-blocking: " + stringerror(err));
    }

    if (pipeBufferSize > 0 && getPipeBufferSize(receiver.getHandle()) < pipeBufferSize) {
      setPipeBufferSize(receiver.getHandle(), pipeBufferSize);
    }

    return {Sender<T, D>(std::move(sender)), Receiver<T, D>(std::move(receiver), throwOnEOF)};
  }
}
}
