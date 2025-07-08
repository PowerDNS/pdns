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
#include <mutex>
#include <shared_mutex>
#include <stdexcept>

/*
  This file provides several features around locks:

  - LockGuarded and SharedLockGuarded provide a way to wrap any data structure as
  protected by a lock (mutex or shared mutex), while making it immediately clear
  which data is protected by that lock, and preventing any access to the data without
  holding the lock.

  For example, to protect a set of integers with a simple mutex:

  LockGuarded<std::set<int>> d_data;

  or with a shared mutex instead:

  SharedLockGuarded<std::set<int>> d_data;

  Then the only ways to access the data is to call the lock(), read_only_lock() or try_lock() methods
  for the simple case, or the read_lock(), write_lock(), try_read_lock() or try_write_lock() for the
  shared one.
  Doing so will return a "holder" object, which provides access to the protected data, checking that
  the lock has really been acquired if needed (try_ cases). The data might be read-only if read_lock(),
  try_read_lock() or read_only_lock() was called. Access is provided by dereferencing the holder object
  via '*' or '->', allowing a quick-access syntax:

  return d_data.lock()->size();

  Or when the lock needs to be kept for a bit longer:

  {
    auto data = d_data.lock();
    data->clear();
    data->insert(42);
  }

  - ReadWriteLock is a very light wrapper around a std::shared_mutex.
  It used to be useful as a RAII wrapper around pthread_rwlock, but since
  C++17 we don't actually that, so it's mostly there for historical
  reasons.

  - ReadLock, WriteLock, TryReadLock and TryWriteLock are there as RAII
  objects allowing to take a lock and be sure that it will always be unlocked
  when we exit the block, even with a unforeseen exception.
  They are light wrappers around std::unique_lock and std::shared_lock
  since C++17.

  Note that while the use of a shared mutex might be very efficient when the data
  is predominantly concurrently accessed for reading by multiple threads and not
  often written to (although if it is almost never updated our StateHolder in
  sholder.hh might be a better fit), it is significantly more expensive than
  a regular mutex, so that one might be a better choice if the contention is
  low. It is wise to start with a regular mutex and actually measure the contention
  under load before switching to a shared mutex.
 */

class ReadWriteLock
{
public:
  ReadWriteLock() = default;
  ~ReadWriteLock() = default;

  ReadWriteLock(const ReadWriteLock& rhs) = delete;
  ReadWriteLock(ReadWriteLock&& rhs) = delete;
  ReadWriteLock& operator=(ReadWriteLock&&) = delete;
  ReadWriteLock& operator=(const ReadWriteLock& rhs) = delete;

  std::shared_mutex& getLock()
  {
    return d_lock;
  }

private:
  std::shared_mutex d_lock;
};

class ReadLock
{
public:
  ReadLock(ReadWriteLock& lock) :
    ReadLock(lock.getLock())
  {
  }

  ReadLock(ReadWriteLock* lock) :
    ReadLock(lock->getLock())
  {
  }

  ~ReadLock() = default;
  ReadLock(const ReadLock& rhs) = delete;
  ReadLock& operator=(const ReadLock& rhs) = delete;
  ReadLock& operator=(ReadLock&&) = delete;

  ReadLock(ReadLock&& rhs) noexcept :
    d_lock(std::move(rhs.d_lock))
  {
  }

private:
  ReadLock(std::shared_mutex& lock) :
    d_lock(lock)
  {
  }

  std::shared_lock<std::shared_mutex> d_lock;
};

class WriteLock
{
public:
  WriteLock(ReadWriteLock& lock) :
    WriteLock(lock.getLock())
  {
  }

  WriteLock(ReadWriteLock* lock) :
    WriteLock(lock->getLock())
  {
  }

  ~WriteLock() = default;
  WriteLock(const WriteLock& rhs) = delete;
  WriteLock& operator=(const WriteLock& rhs) = delete;
  WriteLock& operator=(WriteLock&&) = delete;

  WriteLock(WriteLock&& rhs) noexcept :
    d_lock(std::move(rhs.d_lock))
  {
  }

private:
  WriteLock(std::shared_mutex& lock) :
    d_lock(lock)
  {
  }

  std::unique_lock<std::shared_mutex> d_lock;
};

class TryReadLock
{
public:
  TryReadLock(ReadWriteLock& lock) :
    TryReadLock(lock.getLock())
  {
  }

  TryReadLock(ReadWriteLock* lock) :
    TryReadLock(lock->getLock())
  {
  }

  ~TryReadLock() = default;
  TryReadLock(const TryReadLock& rhs) = delete;
  TryReadLock(TryReadLock&&) = delete;
  TryReadLock& operator=(const TryReadLock& rhs) = delete;
  TryReadLock& operator=(TryReadLock&&) = delete;

  [[nodiscard]] bool gotIt() const
  {
    return d_lock.owns_lock();
  }

private:
  TryReadLock(std::shared_mutex& lock) :
    d_lock(lock, std::try_to_lock)
  {
  }

  std::shared_lock<std::shared_mutex> d_lock;
};

class TryWriteLock
{
public:
  TryWriteLock(ReadWriteLock& lock) :
    TryWriteLock(lock.getLock())
  {
  }

  TryWriteLock(ReadWriteLock* lock) :
    TryWriteLock(lock->getLock())
  {
  }

  ~TryWriteLock() = default;
  TryWriteLock(const TryWriteLock& rhs) = delete;
  TryWriteLock(TryWriteLock&&) = delete;
  TryWriteLock& operator=(const TryWriteLock& rhs) = delete;
  TryWriteLock& operator=(TryWriteLock&&) = delete;

  [[nodiscard]] bool gotIt() const
  {
    return d_lock.owns_lock();
  }

private:
  TryWriteLock(std::shared_mutex& lock) :
    d_lock(lock, std::try_to_lock)
  {
  }

  std::unique_lock<std::shared_mutex> d_lock;
};

template <typename T>
class LockGuardedHolder
{
public:
  explicit LockGuardedHolder(T& value, std::mutex& mutex) :
    d_lock(mutex), d_value(value)
  {
  }

  T& operator*() const noexcept
  {
    return d_value;
  }

  T* operator->() const noexcept
  {
    return &d_value;
  }

private:
  std::scoped_lock<std::mutex> d_lock;
  T& d_value;
};

template <typename T>
class LockGuardedTryHolder
{
public:
  explicit LockGuardedTryHolder(T& value, std::mutex& mutex) :
    d_lock(mutex, std::try_to_lock), d_value(value)
  {
  }

  T& operator*() const
  {
    if (!owns_lock()) {
      throw std::runtime_error("Trying to access data protected by a mutex while the lock has not been acquired");
    }
    return d_value;
  }

  T* operator->() const
  {
    if (!owns_lock()) {
      throw std::runtime_error("Trying to access data protected by a mutex while the lock has not been acquired");
    }
    return &d_value;
  }

  operator bool() const noexcept
  {
    return d_lock.owns_lock();
  }

  [[nodiscard]] bool owns_lock() const noexcept
  {
    return d_lock.owns_lock();
  }

  void lock()
  {
    d_lock.lock();
  }

private:
  std::unique_lock<std::mutex> d_lock;
  T& d_value;
};

template <typename T>
class LockGuarded
{
public:
  explicit LockGuarded(const T& value) :
    d_value(value)
  {
  }

  explicit LockGuarded(T&& value) :
    d_value(std::move(value))
  {
  }

  explicit LockGuarded() = default;

  LockGuardedTryHolder<T> try_lock()
  {
    return LockGuardedTryHolder<T>(d_value, d_mutex);
  }

  LockGuardedHolder<T> lock()
  {
    return LockGuardedHolder<T>(d_value, d_mutex);
  }

  LockGuardedHolder<const T> read_only_lock()
  {
    return LockGuardedHolder<const T>(d_value, d_mutex);
  }

private:
  std::mutex d_mutex;
  T d_value;
};

template <typename T>
class RecursiveLockGuardedHolder
{
public:
  explicit RecursiveLockGuardedHolder(T& value, std::recursive_mutex& mutex) :
    d_lock(mutex), d_value(value)
  {
  }

  T& operator*() const noexcept
  {
    return d_value;
  }

  T* operator->() const noexcept
  {
    return &d_value;
  }

private:
  std::scoped_lock<std::recursive_mutex> d_lock;
  T& d_value;
};

template <typename T>
class RecursiveLockGuardedTryHolder
{
public:
  explicit RecursiveLockGuardedTryHolder(T& value, std::recursive_mutex& mutex) :
    d_lock(mutex, std::try_to_lock), d_value(value)
  {
  }

  T& operator*() const
  {
    if (!owns_lock()) {
      throw std::runtime_error("Trying to access data protected by a mutex while the lock has not been acquired");
    }
    return d_value;
  }

  T* operator->() const
  {
    if (!owns_lock()) {
      throw std::runtime_error("Trying to access data protected by a mutex while the lock has not been acquired");
    }
    return &d_value;
  }

  operator bool() const noexcept
  {
    return d_lock.owns_lock();
  }

  [[nodiscard]] bool owns_lock() const noexcept
  {
    return d_lock.owns_lock();
  }

  void lock()
  {
    d_lock.lock();
  }

private:
  std::unique_lock<std::recursive_mutex> d_lock;
  T& d_value;
};

template <typename T>
class RecursiveLockGuarded
{
public:
  explicit RecursiveLockGuarded(const T& value) :
    d_value(value)
  {
  }

  explicit RecursiveLockGuarded(T&& value) :
    d_value(std::move(value))
  {
  }

  explicit RecursiveLockGuarded() = default;

  RecursiveLockGuardedTryHolder<T> try_lock()
  {
    return RecursiveLockGuardedTryHolder<T>(d_value, d_mutex);
  }

  RecursiveLockGuardedHolder<T> lock()
  {
    return RecursiveLockGuardedHolder<T>(d_value, d_mutex);
  }

  RecursiveLockGuardedHolder<const T> read_only_lock()
  {
    return RecursiveLockGuardedHolder<const T>(d_value, d_mutex);
  }

private:
  std::recursive_mutex d_mutex;
  T d_value;
};

template <typename T>
class SharedLockGuardedHolder
{
public:
  explicit SharedLockGuardedHolder(T& value, std::shared_mutex& mutex) :
    d_lock(mutex), d_value(value)
  {
  }

  T& operator*() const noexcept
  {
    return d_value;
  }

  T* operator->() const noexcept
  {
    return &d_value;
  }

private:
  std::scoped_lock<std::shared_mutex> d_lock;
  T& d_value;
};

template <typename T>
class SharedLockGuardedTryHolder
{
public:
  explicit SharedLockGuardedTryHolder(T& value, std::shared_mutex& mutex) :
    d_lock(mutex, std::try_to_lock), d_value(value)
  {
  }

  T& operator*() const
  {
    if (!owns_lock()) {
      throw std::runtime_error("Trying to access data protected by a mutex while the lock has not been acquired");
    }
    return d_value;
  }

  T* operator->() const
  {
    if (!owns_lock()) {
      throw std::runtime_error("Trying to access data protected by a mutex while the lock has not been acquired");
    }
    return &d_value;
  }

  operator bool() const noexcept
  {
    return d_lock.owns_lock();
  }

  [[nodiscard]] bool owns_lock() const noexcept
  {
    return d_lock.owns_lock();
  }

private:
  std::unique_lock<std::shared_mutex> d_lock;
  T& d_value;
};

template <typename T>
class SharedLockGuardedNonExclusiveHolder
{
public:
  explicit SharedLockGuardedNonExclusiveHolder(const T& value, std::shared_mutex& mutex) :
    d_lock(mutex), d_value(value)
  {
  }

  const T& operator*() const noexcept
  {
    return d_value;
  }

  const T* operator->() const noexcept
  {
    return &d_value;
  }

private:
  std::shared_lock<std::shared_mutex> d_lock;
  const T& d_value;
};

template <typename T>
class SharedLockGuardedNonExclusiveTryHolder
{
public:
  explicit SharedLockGuardedNonExclusiveTryHolder(const T& value, std::shared_mutex& mutex) :
    d_lock(mutex, std::try_to_lock), d_value(value)
  {
  }

  const T& operator*() const
  {
    if (!owns_lock()) {
      throw std::runtime_error("Trying to access data protected by a mutex while the lock has not been acquired");
    }
    return d_value;
  }

  const T* operator->() const
  {
    if (!owns_lock()) {
      throw std::runtime_error("Trying to access data protected by a mutex while the lock has not been acquired");
    }
    return &d_value;
  }

  operator bool() const noexcept
  {
    return d_lock.owns_lock();
  }

  [[nodiscard]] bool owns_lock() const noexcept
  {
    return d_lock.owns_lock();
  }

private:
  std::shared_lock<std::shared_mutex> d_lock;
  const T& d_value;
};

template <typename T>
class SharedLockGuarded
{
public:
  explicit SharedLockGuarded(const T& value) :
    d_value(value)
  {
  }

  explicit SharedLockGuarded(T&& value) :
    d_value(std::move(value))
  {
  }

  explicit SharedLockGuarded() = default;

  SharedLockGuardedTryHolder<T> try_write_lock()
  {
    return SharedLockGuardedTryHolder<T>(d_value, d_mutex);
  }

  SharedLockGuardedHolder<T> write_lock()
  {
    return SharedLockGuardedHolder<T>(d_value, d_mutex);
  }

  SharedLockGuardedNonExclusiveTryHolder<T> try_read_lock()
  {
    return SharedLockGuardedNonExclusiveTryHolder<T>(d_value, d_mutex);
  }

  SharedLockGuardedNonExclusiveHolder<T> read_lock()
  {
    return SharedLockGuardedNonExclusiveHolder<T>(d_value, d_mutex);
  }

private:
  std::shared_mutex d_mutex;
  T d_value;
};
