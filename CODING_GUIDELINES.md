Coding Guidelines for Contributing to PowerDNS
----------------------------------------------

Thank you for you interest in contributing to the PowerDNS project.
This document describes the general coding guidelines to keep in mind when contributing code to our code base.
It does assume that you have already read the contributing document at [CONTRIBUTING.md](https://github.com/PowerDNS/pdns/blob/master/CONTRIBUTING.md).

# High-level Guidelines

* Although the codebase does not consistently have them, [docblocks](https://www.doxygen.nl/manual/docblocks.html) on functions and classes are appreciated.
* Never hesitate to write comments on anything that might not be immediately clear just from reading the code.
* When adding whole new things, consider putting them in a `pdns::X` namespace.
  Look for `namespace pdns` in the codebase for examples.

# Memory Handling

The memory model in C++, inherited from the C era, is very powerful but also very error-prone.
Several features are available in modern C++ (11 and up) to make it possible to avoid most of the pitfalls, while conserving the same level of performance.

Most of the issues related to memory allocation (memory leaks, use-after-free) can be solved by using standard containers, or taking advantage of RAII and smart pointers, which take care of destroying objects when it is not used anymore.

## Stack-based Memory Allocation

Default allocations, when declaring a variable local to a function for example, are done on the stack instead of doing a dynamic allocation on the heap.
Allocating objects on the stack is faster, especially in threaded programs, and provides the benefit that objects are automatically destroyed when the function exits.

One caveat that the programmer needs to be aware of is the size of the object in order to not exceed the space available on the stack, which would corrupt other objects in memory and could lead to a crash, or even execution of arbitrary code.
This is especially true in the Recursor which uses a custom mechanism for stack-switching in user-space and thus has a reduced stack size.

### Variable-Length Arrays (VLAs)

In order to avoid smashing the stack, special care should be taken to limit the depth of function calls that, for example, can grow quickly with recursion.
A second common source of stack smashing is the use of Variable-Length Arrays (VLAs), whose size is determined at runtime and is therefore very hard to predict.
The C++ language does not support VLAs but a lot of compilers inherit such support from C99, so it is possible to use them by accident.
PowerDNS strictly forbids the use of VLAs, as does the Linux kernel, and enforces that with the `-Werror=vla` compiler flag.

### C-style Arrays

While you might still find some uses of C-style arrays in the existing code base, we are actively trying to get rid of them. One example is as follows:

```C++
somestruct buffer[12];
auto bufferSize = sizeof(buffer) / sizeof(*buffer);
auto& firstElement = buffer[0];
```

It is immediately obvious that computing the actual number of elements is error-prone, because `sizeof()` does not return the number of elements but the total memory space used by the array.
Another obvious issue is that accesses to the array are not bound-checked.
These are not the only drawbacks of C-style arrays, but are bad enough already to justify getting rid of them.

The modern C++ way is to use `std::array`s:

```C++
std::array<somestruct, 12> buffer;
auto bufferSize = buffer.size();
auto& firstElement = buffer.at(0);
```

### `alloca`

The use of `alloca()` is forbidden in the code base because it is too easy to smash the stack.

## Resource Acquisition Is Initialization (RAII)

Resource acquisition is initialization ([RAII](https://en.cppreference.com/w/cpp/language/raii)) is one of the fundamental concepts in C++.
Resources are allocated during the construction of an object and destroyed when the object is itself destructed.
It means that if an object is correctly designed, the resources associated with it cannot survive its lifetime. In other words, the resources associated with a correctly designed object are owned by the object and cannot outlive it.
Since stack-allocated objects, like local variables in a function, are automatically destroyed when a function exits, be it by reaching the last line, calling return or throwing an exception, it makes it possible to ensure that resources are always properly destroyed by wrapping them in an object.

We describe the use of smart pointers, containers and other wrappers for that purpose below, but first a few words of caution.
Resources stored in an object are only tied to this object if the constructor executes fully and completes properly.
If an exception is raised in the constructor's body, the object is not created and therefore the destructor will not be called.
This means that if the object has non-object members holding resources, like raw file descriptors or raw C-style pointers, they need to be explicitly released before raising the exception; otherwise, they are lost or leaked.

```C++
class BadFileDescriptorWrapper
{
  BadFileDescriptorWrapper()
  {
    d_fd = open(...);
    if (something) {
      throw std::runtime_error(...); // WRONG, DO NOT DO THIS!
    }
    ...
  }

  ~BadFileDescriptorWrapper()
  {
    if (d_fd > 0) {
      close(d_fd);
      d_fd = -1;
    }
  }

  int getHandle() const
  {
    return d_fd;
  }

private:
  int d_fd{-1};
};
```

The use of smart pointers can be a solution to most resource leakage problems, but otherwise the only way is to be careful about exceptions in constructors:

```C++
GoodFileDescriptorWrapper()
{
  d_fd = open(...);
  if (something) {
    close(d_fd);
    d_fd = -1;
    throw std::runtime_error(...);
  }
  ...
}
```

## Smart Pointers

There is almost no good reason to not use a smart pointer when doing dynamic memory allocation.
Smart pointers will keep track of whether the dynamically allocated object is still used, and destroy it when the last user goes away.

Using raw pointers quickly results in security issues, ranging from memory leaks to arbitrary code execution.
Examples of such issues can be found in the following PowerDNS security advisories:

* [2017-07: Memory leak in DNSSEC parsing](https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2017-07.html)
* [2018-04: Crafted answer can cause a denial of service](https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2018-04.html)

Most allocations should be wrapped in a `std::unique_ptr`, using `make_unique`.
There can only be one owner at any given time, as opposed to shared pointers, but the ownership can be passed along using `std::move()` if needed.

If the dynamically allocated object needs to be referenced in several places, the use of a `std::shared_ptr` is advised instead, via `std::make_shared`.

The use of `make_*` methods has three advantages:

* They result in a single allocation for `shared_ptr`s, instead of two otherwise ;
* They avoid duplicating the type name ;
* They prevent a possible issue if an exception is raised with temporaries.

They also make is easier to spot raw pointers by searching or `grep`ping for "new" and "delete" throughout the code :)

Please note, however, that while unique pointers are as cheap as raw pointers, shared pointers are much more expensive.
That is because they need to use atomic operations to update their internal counters, so making a copy of a shared pointer is expensive.
Passing one by reference is cheap, however.

### Shared Pointers

An important thing to be aware of with shared pointers is that making a new copy or releasing a shared pointer, thus updating its internal reference counter, is atomic and therefore thread-safe.
Altering the content of the object pointed to is not, though, and is subject to the usual locking methods.
The often misunderstood part is that updating the target of the shared pointer is not thread-safe.
Basically, you can copy the shared pointer from multiple threads at once, and then each thread can assign a new target to its own copy safely, like this:

```C++
auto ptr = std::make_shared<int>(4);
for (auto idx = 0; idx < 10 ; idx++){
  std::thread([ptr]{ auto copy = ptr; }).detach();   // ok, only mutates the control block
}
```

But there is a race if one thread updates the exact same smart pointer that another thread is trying to read:

```c++
auto ptr = std::make_shared<int>(4);

std::thread threadA([&ptr]{
  ptr = std::make_shared<int>(10);
});

std::thread threadB([&ptr]{
  ptr = std::make_shared<int>(20);
});
```

That unfortunately means that we still need some locking with shared pointers.
C++11 defines atomic compare/exchange operations for `std::shared_ptr`, but they are implemented in `libstdc++` by global mutexes and are therefore not lock-free.

### Wrapping C Pointers

Smart pointers can also be used to wrap C-pointers, such as `FILE*` pointers:

```c++
auto fp = std::unique_ptr<FILE, decltype(&std::fclose)>(fopen(certificateFile.c_str(), "r"), std::fclose);
```

It also works with types from external C libraries, like OpenSSL:

```c++
auto cert = std::unique_ptr<X509, decltype(&X509_free)>(PEM_read_X509_AUX(fp.get(), nullptr, nullptr, nullptr), X509_free);
```

Unfortunately there are a few cases where smart pointers cannot be used.
In the PowerDNS products, these cases have been mostly reduced to a few select classes, like the `pdns::channel` ones, that are used to pass pointers to a different thread by writing them to a pipe, as is done for example by the query distributors of the auth and the rec.

When smart pointers cannot be used, special care should be taken to:

* Make sure that every exit point frees the allocated memory (early return, goto, exceptions..) ;
* Set the pointer to `nullptr` right after the deallocation, so we can avoid use-after-free vulnerabilities and crash the program instead ;
* Do not mix `malloc` with `delete`, or `new` with `free` (destructors are, at the very least, not run in such cases) ;
* Do not mix array allocations (`new[]`) with a non-array `delete` (vs `delete[]`).

## Pointer Arithmetic

It is very common to use pointer arithmetic to calculate a position in a buffer, or to test whether a given offset is outside of a given buffer.
Unfortunately it is quite easy to trigger undefined behaviour when doing so because the C++ standard does not allow pointer arithmetic pointing inside an object, except for arrays where it is also permitted to point one element past the end.
Still, that undefined behaviour is mostly harmless, but it might lead to real issue on some platforms.

One such example occurred in dnsdist: [2017-01: Crafted backend responses can cause a denial of service](https://dnsdist.org/security-advisories/powerdns-advisory-for-dnsdist-2017-01.html)

In that case, a pointer was set to the start of a buffer plus a given length, to see whether the result would go past another pointer that was set to the end of the buffer.
Unfortunately, if the start of the buffer is at a very high virtual address, the result of the addition might overflow and wrap around, causing the check to become true and leading to either a crash or the reading of unrelated memory.
While very unlikely on a 64 bits platform, it could happen on 32 bits platform.

This kind of issue is best avoided by the use of containers to avoid the need for pointer arithmetic, or by being very careful to only add checked offsets to a pointer.

### Containers

The use of containers like `vector`, `map` or `set` has several advantages in terms of security:

* Memory allocations are handled by the container itself ;
* It prevents a disconnect between the actual size and the variable tracking that size ;
* It provides safe (and fast) operations like comparisons, iterators, etc..

One issue that could have been prevented by the use of a container can be found in the following advisory: [2018-09: Crafted query can cause a denial of service](https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2018-09.html)

The use of a container and its corresponding `at()` operator would have prevented an out-of-bounds read since calling `at()` on an invalid offset results in an exception being raised.
The cost of using `at()` is negligible for most use cases, and can be avoided by using the `[]` operator in the rare case when the cost cannot be afforded.
Note that several Linux distributions now build with `-Wp,-D_GLIBCXX_ASSERTIONS` enabled by default, which turns on cheap range checks for C++ arrays, vectors, and strings.

Regarding performance, it is advised to [`reserve()`](https://en.cppreference.com/w/cpp/container/vector/reserve) the needed size in advance when a rough estimate is known to avoid reallocations and copies. It usually triggers the allocation of enough memory to hold the requested number of items but does not increase the size of the container as reported by `size()`.
Calling [`resize()`](https://en.cppreference.com/w/cpp/container/vector/resize) in advance is not advised, though, as it makes it harder to exactly know what is in the container in case of early returns or exceptions.

In C++11, move operators make it possible to cheaply get the contents of a container into a different variable if needed.

The need to pass a subset of a container without copying it often leads to passing a pointer to an array of chars along with a size.
Introduced in C++14, `views` provide a nice way to borrow the content of a container to pass it to a function, without any copying or dynamic memory allocation. The basic `string_view` class provides that feature for a container of chars.

# Threads and Concurrency

All of our products use threading to be able to take advantage of the increasing number of cores on modern CPUs.
This inevitably leads to the question of how to synchronise data accesses between threads.
Most objects, like containers, cannot be accessed from more than one thread at once.
Even `const` methods on containers might not be thread-safe.
For example getting the `size()` of a container might not be thread-safe if a different thread might be writing to the container.
Some functions might also not be thread-safe, for example if they have a static non-const variable.

We currently use three solutions, depending on the use-case.
The first one is used when we only need to share some kind of counter or gauge, and involves the use of `std::atomic` which allows atomic operations to be performed from different threads without locking. More on that later.
The second one is the "share nothing" approach, where each thread has its own data (using `thread_local`, for example), avoiding the need for data synchronization.
When a thread needs to communicate with another one, it might use a `pdns::channel` to pass a pointer to that second thread.
That works quite well but sometimes sharing data is much more efficient than the alternative.

For cases where sharing the data between threads is needed, we use the classic locking approach, using either a simple mutex or read-write lock, depending on the use case.

## Locks

Locks allow a thread of execution to ensure that no other thread will try to access the code path or data they protect at the same time.

There are a few pitfalls to avoid when using locks:

* Failing to release a lock, which can be avoided by using wrappers like `std::lock_guard`, `std::unique_lock` and our own wrappers: `LockGuarded` and `SharedLockGuarded` in `lock.hh` ;
* High contention, where threads are blocked for a long time while waiting to acquire a lock.
  This can be solved by carefully examining the portion of code that really needs to hold the lock, making the critical path shorter or faster, or by using sharding which basically divides the data protected by the lock into several pieces, each of them protected by its own lock ;
* Dead-locks, which occur for example when thread 1 acquires lock 1 and wants to acquire lock 2, which is already acquired by thread 2, itself currently waiting to acquire lock 1.
  This can be avoided by a better design of the locking mechanism, and assuring that locks are always acquired in the same order if more than one lock is required. Abstracting multiple locks away into a class with a small state machine that locks and unlocks both in the correct sequence and checks that they are always in a valid in-tandem state may prove to be a less error-prone approach while also improving readability and ergonomics.

There are several types of locks:

* Spinlocks are very fast but are busy-waiting, meaning that they do not pause, but instead repetitively try to get hold of the lock, using 100% of one core, doing so unless preempted by the OS ;
  So they are only suited for locks that are almost never contented ;
* A mutex is a very simple lock.
  In most implementations it is a very fast lock, implemented in user-space on recent Linux kernels and glibc ;
* A read-write lock (RW-lock) allows several threads to acquire it in read mode, but only one thread can acquire it in write mode.
  This is suited when most accesses are read-only and writes are rare and do not take too long.
  Otherwise, a mutex might actually be faster.

One quick word about condition variables, that allow a thread to notify one or more threads waiting for a condition to happen.
A thread should acquire a mutex using a `std::unique_lock` and call the `wait()` method of the condition variable.
This is a very useful mechanism but one must be careful about two things:

* The producer thread can either wake only one thread or all threads waiting on the condition variable.
  Waking up several threads if only one has something to do (known as a "thundering herd") is bad practice, but there are some cases where it makes sense ;
* A consumer thread might be waken up spuriously, which can be avoided by passing a predicate (which can be as simple as a small lambda function) to `wait()`.

Our wrappers, `LockGuarded`, `SharedLockGuarded` in `lock.hh`, should always be preferred over other solutions.
They provide a way to wrap any data structure as protected by a lock (mutex or shared mutex), while making it immediately clear which data is protected by that lock, and preventing any access to the data without holding the lock.

For example, to protect a set of integers with a simple mutex:

```c++
LockGuarded<std::set<int>> d_data;
```

or with a shared mutex instead:

```c+++
SharedLockGuarded<std::set<int>> d_data;
```

Then the only way to access the data is to call the `lock()`, `read_only_lock()` or `try_lock()` methods for the simple case, or the `read_lock()`, `write_lock()`, `try_read_lock()` or `try_write_lock()` for the shared one.
Doing so will return a "holder" object, which provides access to the protected data, checking that the lock has really been acquired if needed (`try_` cases).
The data might be read-only if `read_lock()`, `try_read_lock()` or `read_only_lock()` was called.
Access is provided by dereferencing the holder object via `*` or `->`, allowing a quick-access syntax:

```c+++
return d_data.lock()->size();
```

Or when the lock needs to be kept for a bit longer:

```c++
{
  auto data = d_data.lock();
  data->clear();
  data->insert(42);
}
```

## Atomics

`std::atomic` provides a nice way to share a counter or gauge between threads without the need for locking.
This is done by implementing operations like reading, increasing, decreasing or writing a value in an atomic way, using memory barriers, making sure that the value cannot be updated from a different core during the operation.
The default mode uses a sequentially consistent ordering memory model, which is quite expensive since it requires a full memory fence on all multi-core systems.
A relaxed model can be used for specific operations, but the default model has the advantage of being safe in all situations.

## Per-Thread Counters

For generic per-thread counters, we have a class in `tcounters.hh` that should provide better performance by allowing each thread to independently update its own counter, the costly operation only happens when the counter needs to be read by one thread gathering metrics from all threads.

# Dealing with Untrusted Data

As a rule of thumb, any data received from outside the process should be considered untrusted.
This includes data received on a socket, loaded from a file, retrieved from a database, etc.
Data received from an internal pipe might be excluded from that rule.

Untrusted data should never be trusted to adhere to the expected format or specifications, and a strict checking of boundaries should be performed.
It means for example that, after reading the length for a field inside the data, whether that length does not exceed the total length of the data should be checked.
In the same way, if we expect a numerical type we should check whether it matches what we expect and understand.

Anything unexpected should stop the processing and lead to the discarding of the complete data set.
If a smaller data set can be safely discarded, and it is more important to load an incomplete set than to assure the integrity of the complete data set, only the faulty data can be discarded instead.

## Alignment Issues

When structured, binary data is received from the network or read from a file, it might be tempting to map it to an existing structure directly to make the parsing easier.
But one must be careful about alignment issues on some architectures:

```c++
struct my_struct {
  uint32_t foo;
  uint32_t bar;
};
```

It might be tempting to directly cast the received data:

```c++
void func(char* data, size_t offset, size_t length) {
  // bounds check left out!
  const struct my_struct* tmp = reinterpret_cast<const struct my_struct*>(data + offset);
  ...
}
```

Unfortunately this leads to undefined behaviour because the offset might not be aligned with the alignment requirement of the struct.
One solution is to do a copy:

```c++
void func(char* data, size_t offset, size_t length) {
  // bounds check left out!
  struct my_struct tmp;
  memcpy(&tmp, data + offset, sizeof(tmp));
  /* ... */
}
```

## Signed vs. Unsigned

Signed integers might overflow, and the resulting value is unpredictable, as this overflow is undefined behaviour.
That means that this code results in an unpredictable value:

```c++
int8_t a = std::numeric_limits<int8_t>::max();
a++;
```

One such example led to [2006-01: Malformed TCP queries can lead to a buffer overflow which might be exploitable](https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2006-01.html).

It would be necessary to check that the value cannot overflow first.
Another possibility would be to instruct the compiler to treat signed overflow as it does for unsigned values, by wrapping.
This can be done with `-fwrapv` with g++.

An operation on an unsigned integer will never result in an overflow, because the value will simply wrap around.
This might still result in an unexpected value, possibly bypassing a critical check:

```c++
void parse_untrusted_data(uint8_t* data, uint16_t length)
{
  /* parse a record, first two bytes are the size of the record data, second two bytes are the type of the record */
  if (length < 4) {
    return;
  }

  /* read the first two bytes which hold the length of the next record */
  uint16_t recordLen = data[0] * 256 + data[1];

  /* let's assume that recordLen is equal to 65535 */
  uint16_t totalRecordLen = /* size of the type */ sizeof(uint16_t) + recordLen; // <-- this results in a wrapped value of 65535 + 2 = 65537 = 1
  if (totalRecordLen > length) {
    return;
  }

  /* ... */
}
```

A valid version to prevent the overflow:

```c++
void parse_untrusted_data(uint8_t* data, uint16_t length)
{
  /* parse a record, first two bytes are the size of the record data, second two bytes are the type of the record */
  if (length < 4) {
    return;
  }

  /* read the first two bytes which hold the length of the next record */
  uint16_t recordLen = data[0] * 256 + data[1];
  if (recordLen > length || (length - recordLen) < sizeof(uint16_t)) {
    return;
  }

  /* ... */
}
```

Converting from unsigned to signed will lose the high order bytes, and should be avoided, or the value should be checked beforehand:

```c++
uint64_t u = std::numeric_limits<uint64_t>::max();
int64_t s = static_cast<int64_t>(u); /* Wrong, and the cast eliminates any warning */
if (u <= std::numeric_limit<int64_t>::max()) {
  int64_t s = static_cast<int64_t>(u); /* OK */
}
```

The `pdns::checked_conv()` function can be used, ensuring that the conversion can safely be done and raising an exception otherwise.

`-Wsign-conversion` can be used to warn about dangerous conversions (disabled by default in g++, and note that a cast disables the warning).

## Fuzzing

Fuzzing is a very useful way to test a piece of code that parses untrusted data.
Efficient fuzzers are often doing coverage-based fuzzing, where the code that they test has been compiled in a special way to allow the fuzzer to detect which branches are executed and which are not, so that the fuzzer can see the effect of mutating specific bytes of the input on the code path.

PowerDNS has a few fuzzing targets that can be used with libFuzzer or AFL in the `pdns/` directory, and are built when `--enable-fuzzing-target` is passed to `configure`.
More information can be found in the [fuzzing/README.md](https://github.com/PowerDNS/pdns/blob/master/fuzzing/README.md) file.
The existing fuzzing targets are run on the OSS-Fuzz infrastructure for a short time every time a pull request is opened, and for a longer time on the HEAD of the repository.

# Other Potential Issues

## Time-Of-Check to Time-Of-Use (TOCTOU)

The time-of-check to time-of-use vulnerability is a very easy mistake to make when dealing with files or directories.
The gist of it is that there is a small race condition between the time where a program might check the ownership, permissions or even existence of a file and the time it will actually do something with it.
This time might be enough to allow an attacker to create a symbolic link to a critical file at the place of that exact file, for example.
Since the program has enough rights to edit this file, this might allow an attacker to trick the program into writing into a completely different file.

This is hard to avoid in all cases, but some mitigations do help:

* Opening a file first (handling errors if that fails) then getting the needed metadata via the file descriptor instead of the path (`fstat`, `fchmod`, `fchown`) ;
* Opening with the `O_NOFOLLOW` flag set, so that the operation will fail if the target exists and is a symbolic link ;
* Always creating temporary files via the `mkstemp()` function, which guarantees that the file did not exist before and has been created with the right permissions ;
* Using operations that are guaranteed to be atomic, like renaming a file on the same filesystem (for example in the same directory).

## `errno`

`errno` is only guaranteed to be set on failing system calls and not set on succeeding system calls.
A library call may clobber `errno`, even when it succeeds.
Safe practice is:

* Only look at `errno` on failing system calls or when a library function is documented to set `errno` ;
* Immediately save the value of `errno` in a local variable after a system call for later decision making.

## Secrets

Try very hard not to load sensitive information into memory.
And of course do not write this information to logs or to disk!

If you have to:

* Use an object that can't be copied, by deleting the copy constructors and assignments operators,
* Try to lock the memory so it cannot be swapped out to disk, or included in a core dump, via `sodium_malloc()` or `sodium_mlock()`, for example ;
* Wipe the content before releasing the memory, so it will not linger around.
  Do note that `memset()` is very often optimized out by the compiler, so function like `sodium_munlock()`, `explicit_bzero()` or `explicit_memset()` should be used instead.

### Constant-Time Comparison

Don't compare secret against data using a naive string comparison, as the timing of the operation will leak information about the content of the secret.
Ideally, a constant-time comparison should be used instead (see `constantTimeStringEquals()` in the PowerDNS code base) but it is not always easy to achieve.
One option might be to compute an HMAC of the secret using a key that was randomly generated at startup, and compare it against a HMAC of the supplied data computed with the same key.

## Virtual Destructors

Any class that is expected to be sub-classed should provide a virtual destructor.
Not doing so will prevent the destructor of any derived class from being called if the object is held as the base type:

```c++
class Parent
{
  virtual void doVirtualCall();
};

class Child: public Parent
{
  Child()
  {
    d_fd = fopen(..);
  }

  ~Child()
  {
    if (d_fd) {
      fclose(d_fd);
      f_fd = nullptr;
    }
  }

  void doVirtualCall() override;
};

std::vector<Parent> myObjects;
myObjects.push_back(Child());
```

Note that defining a destructor will prevent the automatic creation of move operators for that class, since they are generated only if these conditions are met:

* No copy operators are declared ;
* No move operators are declared ;
* No destructor is declared.

If the parent class holds data that is costly to copy, it might make sense to declare the move operators explicitly:

```c++
class Parent
{
  Parent(Parent&&) = default;
  Parent& operator=(Parent&&) = default;

  virtual ~Parent()
  {
  }

  virtual void doVirtualCall();

private:
  FILE* d_fd{nullptr};
};
```

Note that declaring the move operators disables the copy operators, so if they are still needed:

```c++
class Parent
{
  Parent(Parent&&) = default;
  Parent& operator=(Parent&&) = default;

  Parent(const Parent&) = default;
  Parent& operator=(const Parent&) = default;

  virtual ~Parent()
  {
  }

  virtual void doVirtualCall();
};
```

On a related topic, virtual methods should not be called from constructors or destructors.
While this is allowed under certain restrictions, it is very hard to know exactly which method (base or derived) will be called, and whether all sub-objects contained in the class would have been correctly constructed at that point.

## Hash Collisions

Hashes are a very useful tool, used in `unordered_map` and `unordered_set` among others.
They are also used in our caches.
An important caveat that developers need to be aware of regarding hashes are that the probability of a collision is often a lot higher than expected.
This is well-known as the birthday paradox, the fact that the probability of having two entries colliding is a lot higher than the probability of finding a collision for a specific entry.
This means that it is important to verify that the entries are actually identical, and just not that they hash to the same value.

This is especially important when hashing attacker-controlled values, as they can be specially crafted to trigger collisions to cause:

* Cache pollution (see [2018-06: Packet cache pollution via crafted query](https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2018-06.html)) ;
* Denial of service via hash table flooding (in a map, all entries that hash to the same value are often placed into a linked-list, making it possible to cause a linear scan of entries by making all of them hash to that same value).

The first issue can be prevented by comparing the entries and not just the value they hash to.
The second one can be avoided by using some sort of secret when computing the hash so that the result cannot be guessed by the attacker.
That can be achieved by using an unpredictable seed for certain hash algorithms, or a secret for some other like [`SipHash`](https://en.wikipedia.org/wiki/SipHash).

# Readability Tips

Some of these tips are actually enforced by `clang-tidy` nowadays, but it is still useful to keep them in mind.

## `auto`

C++11 introduced automatic type deduction, using the `auto` keyword.
Using automatic type deduction prevents nasty surprises if the variable is initialized from another one, or from a function, and the other type is changed to a different one.
Without `auto`, code might still compile but trigger a copy or worse.

## Explicit Comparisons

* Compare numerical values with `== 0` or `!= 0` explicitly ;
* Compare to `nullptr`, which is easier to read.

## Initialization

Use braced initialization for members as often as possible:

* It does forbid narrowing conversions :
* It avoids C++'s "[most vexing parse](https://en.wikipedia.org/wiki/Most_vexing_parse)" which is to declare a function instead of calling the default constructor:

```c++
Object a(); // declares a function named a that returns an object
```

## `nullptr`

When representing a pointer, using `nullptr` makes it immediately obvious that we are dealing with a pointer, as opposed to the use of `0`.
It also cannot be silently taken as an integer, which can happens with `0` but also with `NULL`.

## `const`-ness

* Mark parameters and variables that should not be modified as `const`.
  This is especially important for references and pointers that come from outside the function, but it also makes sense to do it for local variables or parameters passed by value because it might help detect a logic error later ;
* Mark `const` methods as such (and make them thread-safe) ;
* Prefer using `at()` on containers so that no insertion can take place by mistake, and to get bounds checking.

## Unnamed Namespace

Functions that are only used inside a single file should be put into an unnamed namespace, so that:

* The compiler knows that these functions will not be called from a different compilation unit and thus that no symbol needs to be generated, making it more likely for the function to be inlined ;
* The reader knows that this function is only used there and can be altered without causing an issue somewhere else.

```c++
namespace {

bool thisFunctionIsOnlyUsableFromThisTranslationUnit()
{
}

}
```

These functions used to be marked `static` in the past, so you might still encounter this form in the code base instead: 

```c++
static bool thisOneAsWell()
{
}
```

but the unnamed namespace form is now preferred.

For the same reason, global variables that are only accessed from a single file should be put into an unnamed namespace, or marked static as well.

## Variables

Try to declare variables in the innermost scope possible and avoid uninitialized variables as much as possible.
Declare and initialize variables when the values needed to initialize them are available.

## Exceptions

Exceptions should be reserved for events that interrupt the normal processing flow (corrupted data, timeouts, ...), and should not be triggered in the general case.

For example, it would be better for a function checking a password or an API key to return a boolean or a `enum` indicating whether the check was successful than to throw an exception if the credentials are not valid, because the return value makes it clear that the check can and will fail, while otherwise the caller might not be aware that an exception can be raised.

This does not mean that we should be afraid of using exceptions, though, but we need to keep in mind that they involve hidden complexity for the programmer that needs to keep a mental map of all the possible exceptions that can be raised.

As far as performance goes the cost of an exception that is not thrown is usually very small, thanks to the zero-cost exception model. It might still force the compiler to refrain from some optimizations, so it might make sense to avoid them in some very performance-sensitive, narrow code paths, and to mark these paths as `noexcept` whenever possible.

### Custom Exceptions

When exceptions are used, the ones defined by the standards should be used whenever possible, as they already cover a lot of use cases.

If custom exceptions are necessary, to be able to catch them explicitly, they should derive from `std::exception`, directly or indirectly, so that they can be caught in a more generic way to prevent the program from terminating.

For example, the main connection handling function of a server can catch `std::exception` and terminate the current connection if an uncaught exception bubbles up, without having to worry about all the possible cases.

### Catching Exceptions

Catching exceptions should always be done by `const`-reference:

```c+++
try {
}
catch (const std::exception& e) {
  std::cerr << e.what() <<endl;
}
```

Not using a reference would result in the exception object being sliced, meaning that a custom exception derived from `std::exception` would not see its overriding `what()` method called but the one from the base class instead.

## Casts

C-style casts should be avoided, as the compiler does almost no checking on the validity of the operation.
They are also very hard to spot in a code.
C++-style casts can easily be spotted in a code, which makes it easy to review them.

* `const_cast` can be used to remove the `const` qualifier on a variable.
  It's usually a bad sign, but is sometimes needed to call a function that will not modify the variable but lacks the `const` qualifier ;
* `dynamic_cast` can be used to cast a pointer to a derived class or to a base class, while checking that the operation is valid.
  If the cast object is not valid for the intended type, a `nullptr` value will be returned (or a `bad_cast` exception for references) so the result of the operation should be checked!
  Note that the Run-Time Type Information (RTTI) check needed to verify that the cast object is valid has a non-negligible CPU cost.
  Not checking the return value might lead to remote denial of service by `nullptr`-dereference, as happened with the issue described in this advisory: [2017-08: Crafted CNAME answer can cause a denial of service](https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2017-08.html) ;
* `static_cast` can perform downcast in place of `dynamic_cast`, with none of the cost associated to the check, but can only be done if the cast is known to be valid.
  It can also do implicit conversion between types (from `ssize_t` to `size_t`, **after** checking that the value is greater or equal to zero) ;
* `reinterpret_cast` is quite dangerous, since it can be used to turn a type into a different one.
  It cannot be be used to remove a `const` qualifier.
  When used to reinterpret the content of a buffer it can quickly lead to alignment issues, as described in the [Alignment Issues] section.
