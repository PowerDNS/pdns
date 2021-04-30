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

class ReadWriteLock
{
public:
  ReadWriteLock()
  {
  }

  ReadWriteLock(const ReadWriteLock& rhs) = delete;
  ReadWriteLock(ReadWriteLock&& rhs) = delete;
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
  ReadLock(ReadWriteLock& lock): ReadLock(lock.getLock())
  {
  }

  ReadLock(ReadWriteLock* lock): ReadLock(lock->getLock())
  {
  }

  ReadLock(const ReadLock& rhs) = delete;
  ReadLock& operator=(const ReadLock& rhs) = delete;
  ReadLock(ReadLock&& rhs)
  {
    d_lock = std::move(rhs.d_lock);
  }

private:
  ReadLock(std::shared_mutex& lock) : d_lock(lock)
  {
  }

  std::shared_lock<std::shared_mutex> d_lock;
};

class WriteLock
{
public:
  WriteLock(ReadWriteLock& lock): WriteLock(lock.getLock())
  {
  }

  WriteLock(ReadWriteLock* lock): WriteLock(lock->getLock())
  {
  }

  WriteLock(const WriteLock& rhs) = delete;
  WriteLock& operator=(const WriteLock& rhs) = delete;
  WriteLock(WriteLock&& rhs)
  {
    d_lock = std::move(rhs.d_lock);
  }

private:
  WriteLock(std::shared_mutex& lock) : d_lock(lock)
  {
  }

  std::unique_lock<std::shared_mutex> d_lock;
};

class TryReadLock
{
public:
  TryReadLock(ReadWriteLock& lock): TryReadLock(lock.getLock())
  {
  }

  TryReadLock(ReadWriteLock* lock): TryReadLock(lock->getLock())
  {
  }

  TryReadLock(const TryReadLock& rhs) = delete;
  TryReadLock& operator=(const TryReadLock& rhs) = delete;

  bool gotIt() const
  {
    return d_lock.owns_lock();
  }

private:
  TryReadLock(std::shared_mutex& lock) : d_lock(lock, std::try_to_lock)
  {
  }

  std::shared_lock<std::shared_mutex> d_lock;
};

class TryWriteLock
{
public:
  TryWriteLock(ReadWriteLock& lock): TryWriteLock(lock.getLock())
  {
  }

  TryWriteLock(ReadWriteLock* lock): TryWriteLock(lock->getLock())
  {
  }

  TryWriteLock(const TryWriteLock& rhs) = delete;
  TryWriteLock& operator=(const TryWriteLock& rhs) = delete;

  bool gotIt() const
  {
    return d_lock.owns_lock();
  }

private:
  TryWriteLock(std::shared_mutex& lock) : d_lock(lock, std::try_to_lock)
  {
  }

  std::unique_lock<std::shared_mutex> d_lock;
};

template <typename T>
class LockGuardedHolder
{
public:
  explicit LockGuardedHolder(T& value, std::mutex& mutex): d_lock(mutex), d_value(value)
  {
  }

  T& operator*() const noexcept {
    return d_value;
  }

  T* operator->() const noexcept {
    return &d_value;
  }

private:
  std::lock_guard<std::mutex> d_lock;
  T& d_value;
};

template <typename T>
class LockGuardedTryHolder
{
public:
  explicit LockGuardedTryHolder(T& value, std::mutex& mutex): d_lock(mutex, std::try_to_lock), d_value(value)
  {
  }

  T& operator*() const {
    if (!owns_lock()) {
      throw std::runtime_error("Trying to access data protected by a mutex while the lock has not been acquired");
    }
    return d_value;
  }

  T* operator->() const {
    if (!owns_lock()) {
      throw std::runtime_error("Trying to access data protected by a mutex while the lock has not been acquired");
    }
    return &d_value;
  }

  operator bool() const noexcept {
    return d_lock.owns_lock();
  }

  bool owns_lock() const noexcept {
    return d_lock.owns_lock();
  }

private:
  std::unique_lock<std::mutex> d_lock;
  T& d_value;
};

template <typename T>
class LockGuarded
{
public:
  explicit LockGuarded(T value): d_value(std::move(value))
  {
  }

  explicit LockGuarded()
  {
  }

  LockGuardedTryHolder<T> try_lock()
  {
    return LockGuardedTryHolder<T>(d_value, d_mutex);
  }

  LockGuardedHolder<T> lock()
  {
    return LockGuardedHolder<T>(d_value, d_mutex);
  }

private:
  std::mutex d_mutex;
  T d_value;
};

template <typename T>
class SharedLockGuardedHolder
{
public:
  explicit SharedLockGuardedHolder(T& value, std::shared_mutex& mutex): d_lock(mutex), d_value(value)
  {
  }

  T& operator*() const noexcept {
    return d_value;
  }

  T* operator->() const noexcept {
    return &d_value;
  }

private:
  std::lock_guard<std::shared_mutex> d_lock;
  T& d_value;
};

template <typename T>
class SharedLockGuardedTryHolder
{
public:
  explicit SharedLockGuardedTryHolder(T& value, std::shared_mutex& mutex): d_lock(mutex, std::try_to_lock), d_value(value)
  {
  }

  T& operator*() const {
    if (!owns_lock()) {
      throw std::runtime_error("Trying to access data protected by a mutex while the lock has not been acquired");
    }
    return d_value;
  }

  T* operator->() const {
    if (!owns_lock()) {
      throw std::runtime_error("Trying to access data protected by a mutex while the lock has not been acquired");
    }
    return &d_value;
  }

  operator bool() const noexcept {
    return d_lock.owns_lock();
  }

  bool owns_lock() const noexcept {
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
  explicit SharedLockGuardedNonExclusiveHolder(const T& value, std::shared_mutex& mutex): d_lock(mutex), d_value(value)
  {
  }

  const T& operator*() const noexcept {
    return d_value;
  }

  const T* operator->() const noexcept {
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
  explicit SharedLockGuardedNonExclusiveTryHolder(const T& value, std::shared_mutex& mutex): d_lock(mutex, std::try_to_lock), d_value(value)
  {
  }

  const T& operator*() const {
    if (!owns_lock()) {
      throw std::runtime_error("Trying to access data protected by a mutex while the lock has not been acquired");
    }
    return d_value;
  }

  const T* operator->() const {
    if (!owns_lock()) {
      throw std::runtime_error("Trying to access data protected by a mutex while the lock has not been acquired");
    }
    return &d_value;
  }

  operator bool() const noexcept {
    return d_lock.owns_lock();
  }

  bool owns_lock() const noexcept {
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
  explicit SharedLockGuarded(T value): d_value(std::move(value))
  {
  }

  explicit SharedLockGuarded()
  {
  }

  SharedLockGuardedTryHolder<T> try_lock()
  {
    return SharedLockGuardedTryHolder<T>(d_value, d_mutex);
  }

  SharedLockGuardedHolder<T> lock()
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
