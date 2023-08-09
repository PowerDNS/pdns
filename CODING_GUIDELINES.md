Coding guidelines for contributing to PowerDNS
----------------------------------------------

Thank you for you interest to contribute to the PowerDNS project.
This document describes the general coding guidelines to keep in mind when contributing code to our code base.
It does assume that you have already read the contributing document at [CONTRIBUTING.md](https://github.com/PowerDNS/pdns/blob/master/CONTRIBUTING.md).

# High-level guidelines

* Although the codebase does not consistently have them, [docblock](https://www.doxygen.nl/manual/docblocks.html)s on functions and classes are appreciated.
* Never hesitate to write comments on anything that might not be immediately clear just from reading the code.
* When adding whole new things, consider putting them in a `pdns::X` namespace.
  Look for `namespace pdns` in the codebase for examples.

# Memory handling

The memory model in C++, inherited from the C era, is very powerful but also very error-prone.
Several features are available in modern (C++11) C++ to make it possible to avoid most of the pitfalls, while conserving the same level of performance.

Most of the issues related to memory allocation (memory leaks, use-after-free) can be solved by using it via standard containers, or taking advantage of RAII and smart pointers, which take care of destructing the object when it's not used anymore.

## Stack-based memory allocation

Default allocations, when declaring a variable local to a function for example, is done on the stack instead of doing a dynamic allocation on the heap.
Allocating objects on the stack is faster, especially in threaded programs, and provides the benefit that objects are automatically destroyed when the function is exited.

One caveat is that the programmer needs to be wary about the size of the object in order not to exceed the space available on the stack, which would corrupt other objects in memory and could lead to a crash, or even execution of arbitrary code.
This is especially true in the recursor which uses a custom stack-switching in user-space mechanism and thus has a reduced stack size.

### Variable-Length Arrays

In order to avoid smashing the stack, a special care should be taken to limit the depth of function calls that can grow quickly with recursion, for example.
A second common source of smash stacking is the use of Variable-Length Arrays, whose size is determined at runtime and is therefore very hard to predict.
The C++ language doesn't support VLAs but a lot of compilers inherit such a support from C99, so it's possible to use them by mistake.
PowerDNS strictly forbids the use of VLAs, as does the Linux kernel, and enforce that with the `-Werror=vla` compiler flag.

### C-style arrays

While you might still find some in the existing code base, we are actively trying to get rid of C-style arrays like this one:

```C++
somestruct buffer[12];
auto bufferSize = sizeof(buffer) / sizeof(*buffer);
auto& firstElement = buffer[0];
```

It is immediately obvious that computing the actual number of elements is error-prone, as `sizeof()` does not return the number of elements but the total memory space used by the array.
An other obvious issue is that accesses to the array are not bound-checked.
These are not the only drawbacks of these arrays, but are bad enough already to justify getting rid of them.

The modern C++ way is to use `std::array`s:

```C++
std::array<somestruct, 12> buffer;
auto bufferSize = buffer.size();
auto& firstElement = buffer.at(0);
```

### Alloca

The use of `alloca()` is forbidden in the code base as it is much too easy to smash the stack.

## RAII

Resource acquisition is initialization (RAII) is one of the fundamental concept in C++.
Resources are allocated during the construction of an object and destroyed when the object is itself destructed.
It means that if an object is correctly designed, the resource associated to it can not survive its lifetime.
Since objects that are allocated on the stack (local variables in a function, for example) are automatically destroyed when a function is exited, be it by reaching the last line, calling return or throwing an exception, it makes it possible to ensure that resources are always properly destroyed by wrapping them into an object.

We describe the use of smart pointers, containers and other wrappers to that mean below, but first a few words of caution.
Resources stored in a object are only tied to this object if the constructor finished properly.
If an exception is raised in the constructor body, the object is not created and therefore the destructor will not get called.
This means that if the object has non-object members holding resources, like naked file descriptors or naked pointers, they need to be explicitly released before raising the exception, otherwise they are lost.

```C++
class BadFileDescriptionWrapper
{
  BadFileDescriptionWrapper()
  {
    d_fd = open(...);
    if (something) {
      throw std::runtime_error(...);
    }
    ...
  }
  ~BadFileDescriptionWrapper()
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

The use of smart pointers can be a solution to most resources leakage, but otherwise the only way is to be careful about exceptions in constructors:

```C++
BadFileDescriptionWrapper()
{
  d_fd = open(...);
  if (something) {
    close(d_fd);
    throw std::runtime_error(...);
  }
  ...
}
```

## Smart pointers

There is almost no good reason not to use a smart pointer when doing dynamic memory allocation.
Smart pointers will keep track of whether the dynamically allocated object is still used, and destroy when the last user goes away.

Using naked pointers quickly results in security issues, going from memory leaks to arbitrary code execution.
Examples of such issues can be found in the following PowerDNS security advisories:

* https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2017-07.html
* https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2018-04.html

Most allocations should be wrapped in a `std::unique_pointer`, using `make_unique`.
There can only be one owner at a given time, as opposed to shared pointers, but the ownership can be passed along using `std::move()` if needed.

If the dynamically allocated object needs to be referenced in several places, the use of a `std::shared_pointer` is advised instead, via `std::make_shared`.

The use of the `make_*` methods have three advantages:

* they result in a single allocation for `shared_pointer`s, instead of two otherwise ;
* they avoid duplicating the type name twice ;
* they prevent a possible issue if an exception is raised with temporaries.

They also make is easier to spot naked pointers by looking for "new" and "delete" throughout the code :)

Please note however that while unique pointers are as cheap as naked pointers, shared pointers are much more expensive.
That's because they need to use atomic operations to update their internal counters, so making a copy of a shared pointer is expensive.
Passing one by reference is cheap, however.

### Shared pointers

An important thing to be aware of with shared pointers is that taking a new copy of a shared pointer or releasing, thus updating its internal reference counter, is atomic and therefore thread-safe.
Altering the content of the object pointed to is not, though, and is subject to the usual locking methods.
The often misunderstood part is that updating the target of the shared pointer is not thread-safe.
Basically, you can copy the shared pointer from multiple threads at once, and then each thread can assign a new target to its own copy safely, like that:

```C++
auto ptr = std::make_shared<int>(4);
for (auto idx = 0; idx < 10 ; idx++){
  std::thread([ptr]{ auto copy = ptr; }).detach(); //ok, only mutates the control block 
}
```

But there is a race if one thread update the exact same smart pointer that another thread is trying to read:

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

### Wrapping C pointers

Smart pointers can also be used to wrap C-pointers, such as `FILE*` pointers:

```c++
auto fp = std::unique_ptr<FILE, int(*)(FILE*)>(fopen(certificateFile.c_str(), "r"), fclose);
```

It also works with types from external C libraries, like OpenSSL:

```c++
auto cert = std::unique_ptr<X509, decltype(&X509_free)>(PEM_read_X509_AUX(fp.get(), nullptr, nullptr, nullptr), X509_free);
```

Unfortunately there are a few cases where smart pointers cannot be used.
In the PowerDNS products, these cases have been mostly reduced to a few select classes, like the `pdns::channel` ones, that are used to pass pointers to a different thread by writing them to a pipe, as is done for example by the queries distributors of the auth and the rec.

When it happens, special care should be taken to:

* make sure that every exit point frees the allocated memory (early return, goto, exceptions..) ;
* set the pointer to `nullptr` right after the deallocation, so we can't use it again (use-after-free) ;
* do not mix `malloc` with `delete`, `new` with `free` (destructors are not run, at the very least) ;
* do not mix array allocations (`new[]`) with a non-array `delete` (vs `delete[]`).

## Pointer arithmetic

It is very common to use pointer arithmetic to calculate a position in a buffer, or to test whether a given offset is outside of a given buffer.
Unfortunately it is quite easy to trigger undefined behaviour when doing so, as the C++ standard does not allow pointer arithmetic pointing inside an object, except for arrays where it is also permitted to point one element past the end.
Still that undefined behaviour is mostly harmless, but it might lead to real issue on some platforms.

One such example occurred in dnsdist: https://dnsdist.org/security-advisories/powerdns-advisory-for-dnsdist-2017-01.html

In that case, a pointer was set to the start of a buffer plus a given length, to see whether the result go past another pointer that was set to the end of the buffer.
Unfortunately, if the start of the buffer is at a very high virtual address, the result of the addition might overflow and wrap around, causing the check to become true and leading to either a crash or the reading of unrelated memory.
While very unlikely on a 64 bits platform, it could happen on 16 or 32 bits platform.

This kind of issue is best avoided by the use of container to prevent the need of pointer arithmetic, or by very careful to only add checked offsets to a pointer.

### Containers

The use of containers like `vector`, `map` or `set` has several advantages in term of security:

* memory allocations are handled by the container itself ;
* it prevents a disconnect between the actual size and the variable tracking that size ;
* it provides safe (and fast) operations like comparisons, iterators, etc..

One issue that could have been prevented by the use of a container can be found in the following advisory: https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2018-09.html

The use of a container and its corresponding `at()` operator would have prevented an out-of-bounds read since calling `at()` on an invalid offset results in an exception being raised.
The cost of using `at()` is negligible for most use cases, and can be avoided by using the `[]` operator in the rate case when the cost can't be afforded.
Note that several Linux distributions now build with `-Wp,-D_GLIBCXX_ASSERTIONS` enabled by default, which turns on cheap range checks for C++ arrays, vectors, and strings anyway.

Regarding performance, it is advised to `reserve()` the needed size in advance when a rough estimate is known to avoid reallocations and copies.
Resizing in advance is not advised, though, as it makes it harder to know what is exactly in the container in case of early returns or exceptions.

In C++11, move operations make it possible to cheaply get the content of a container into a different variable if needed.

The need to pass a subset of a container without copying it often leads to passing a pointer to an array of chars along with a size.
Introduced in C++14 but already available in PowerDNS via boost (see views.hh), views provides a nice way to borrow the content of a container to pass it to a function, without any copy or dynamic memory allocation.

The basic `string_view` class provides that feature for a container of chars, but the same feature exists for other types, like `uint8_t`.

# Threads and concurrency

All of our products use threading to be able to take advantage of the increasing number of cores on modern CPUs.
That inevitably leads to the question of how to synchronise data accesses between threads.
Most objects, like containers, cannot be accessed from more than one thread at once.
Even `const` methods on containers might not be thread-safe.
For example getting the `size()` of a container might not be thread-safe if a different thread might be writing to the container.
Some functions might also not be thread-safe, for example if they have a static non-const variable.

We currently use three solutions, depending on the use-case.
The first one is used when we only need to share some kind of counters or gauges, and involves the use of `std::atomic` which allows atomic operations to be performed from different threads without locking.
More on that later.
The second one is the "share nothing" approach, where each thread has its own data (using `thread_local`, for example), avoiding the need to data synchronization.
When a thread needs to communicate with another one, it might use an pdns::channel to pass a pointer to that second thread.
That works quite well but sometimes sharing data is much more efficient than the alternative.

For these cases, we use the classic locking approach, using either a simple mutex or read-write lock, depending on the use case.

## locks

Locks allow a thread of execution to ensure that no other will try to access the code path or data they protect at the same time.

There are a few pitfalls to avoid then using locks:

* avoiding to release the lock, which can be avoided by wrappers like `std::lock_guard`, `std::unique_lock` and our own wrappers: look for `LockGuarded`, `SharedLockGuarded` in lock.hh ;
* high contention, where threads are blocked for a long time while waiting to acquire a lock.
  This can be solved by carefully examining the portion of code that really needs to hold the lock, making the critical path faster, or by using sharding which basically divide the data protected by the lock in several blocks, each one of them protected by its own lock ;
* starvation, which occurs for example when thread 1 acquires lock 1 and wants to acquire lock 2, which is already owned by thread 2, itself currently waiting to acquire lock 1.
  This can be avoided by a better design of the locking mechanism, and assuring that locks are always acquired in the same order if more than one lock is needed.

There are more than one type of locks:

* spinlock are very fast but are busy-waiting, meaning that they don't pause but repetitively try to get hold of the lock, using 100% of one core doing so unless preempted by the OS.
  So they are only suited for locks that are almost never contented ;
* a mutex is a very simple lock.
  In most implementations it's a very fast lock, implemented in user-space on recent Linux kernels and glibc ;
* a read-write lock allows several threads to acquire it in read mode, but only one thread can acquire it in write mode.
  This is suited when most accesses are read-only and writes are rare and don't take too long.
  Otherwise a mutex might actually be faster ;

One quick word about condition variables, that allows a thread to notify one or more threads waiting for a condition to happen.
A thread should acquire a mutex using a `std::unique_lock` and call the `wait()` method of the condition variable.
This is a very useful mechanism but one must be careful about two things:

* the producer thread can either wake only one thread or all threads waiting on the condition variable.
  Waking up several threads if only one has something to do (known as a "thundering herd") is bad practice, but there are some cases where it makes sense ;
* a consumer might be waken up spuriously, which can be avoided by passing a predicate (which can be as simple as a small lambda function) to `wait()`.

Our wrappers, `LockGuarded`, `SharedLockGuarded` in lock.hh, should always be preferred over other solutions.
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

## atomic

`std::atomic` provides a nice way to share a counter or gauge between threads without the need for locking.
This is done by implementing operations like reading, increasing, decreasing or writing a value in an atomic way, using memory barriers, making sure that the value can't be updated from a different core during the operation.
The default mode uses a sequentially consistent ordering memory model, which is quite expensive since it requires a full memory fence on all multi-core systems.
A relaxed model can be used for certain very specific operations, but the default model has the advantage of being safe in all situations.

## per-thread counters

For generic per-thread counters, we have a class in tcounters.hh that should provide better performances by allowing each thread to independently update its own counter, the costly operation only happening when the counter needs to be read by one thread gathering metrics from all threads.

# Dealing with untrusted data

As a rule of thumb, any data received from outside the process should be considered as untrusted.
That means data received on a socket, loaded from a file, retrieved from a database, etc..
Data received from an internal pipe might be excluded from that rule.

Untrusted data should never be trusted to adhere to the expected format or specifications, and a strict checking of boundaries should be performed.
It means for example that, after reading the length for a field inside the data, whether that length does not exceed the total length of the data should be checked.
In the same way, if we expect a numerical type we should check whether it matches one we expect and understand.

Anything unexpected should stop the processing and lead to the discarding of the complete data set.
If a smaller data set can be safely discarded, and it is more important to load an incomplete set than to assure the integrity of the complete data set, only the faulty data set can be discarded instead.

## alignment issues

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

## unsigned vs signed

Signed integer might overflow, and the resulting value is unpredictable, as this is an undefined behaviour.
That means that this code result in an unpredictable value:

```c++
int8_t a = std::numeric_limits<int8_t>::max();
a++;
```

One such example led to https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2006-01.html

It would be necessary to check that the value can't overflow first.
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

Converting from unsigned to signed will lose the high order bytes, and should be avoided, or the value should be checked before-hand:

```c++
uint64_t u = std::numeric_limits<uint64_t>::max();
int64_t s = static_cast<int64_t>(u); /* Wrong, and the cast eliminates any warning */
if (u <= std::numeric_limit<int64_t>::max()) {
  int64_t s = static_cast<int64_t>(u); /* OK */
}
```

The `pdns::checked_conv()` function can be used, ensuring that the conversion can safely be done and raising an exception otherwise.

`-Wsign-conversion` can be used to warn about dangerous conversions (disabled by default in g++, and note that a cast disables the warning).

## fuzzing

Fuzzing is a very useful way to test a piece of code that parses untrusted data.
Efficient fuzzers are often doing coverage-based fuzzing, where the code that they test have been compiled in a special way to allow the fuzzer to detect which branches are executed and which are not, so that the fuzzer can see the effect of mutating specific byte of the input on the code path.

PowerDNS has a few fuzzing targets that can be used with libFuzzer or AFL in the pdns/ directory, and are built when `--enable-fuzzing-target` is passed to the configure.
More information can be found in the [fuzzing/README.md](https://github.com/PowerDNS/pdns/blob/master/fuzzing/README.md) file.
The existing fuzzing targets are run on the OSS-Fuzz infrastructure for a short time every time a pull request is opened, and for a longer time on the HEAD of the repository.

# Others potential issues

## TOCTOU

The time-of-check time-of-use vulnerability is a very easy mistake to make when dealing with files or directory.
The gist of it is that there is a small race condition between the time where a program might check the ownership, permissions or even existence of a file and the time it will actually do something with it.
This time might be enough to allow an attacker to create a symbolic link to a critical file at the place of that exact file, for example.
Since the program has enough rights to edit this file, this might allow an attacker to trick the program into writing into a completely different file.

This is hard to avoid in all cases, but some mitigations do help:

* opening a file first (handling errors if that fails) then getting the needed metadata via the file descriptor instead of the path (`fstat`, `fchmod`, `fchown`) ;
* opening with the `O_NOFOLLOW` flag set, so that the operation will fail if the target exists and is a symbolic link ;
* always creating temporary files via the `mkstemp()` function, which guarantees that the file did not exist before and has been created with the right permissions ;
* using operations that are guaranteed to be atomic, like renaming a file on the same filesystem (for example in the same directory).

## Secrets

Try very hard not to load sensitive information in memory.
And of course don't write to disk!

If you have to:

* use an object that can't be copied by deleting the copy constructors and assignments operators,
* try to lock the memory so it can't be swapped out to disk, or included in a core dump, via `sodium_malloc()` or `sodium_mlock()`, for example ;
* wipe the content before releasing the memory, so it won't linger around.
  Be careful that memset() is very often optimized out by the compiler, so function like `sodium_munlock()`, `explicit_bzero()` or `explicit_memset()` should be used instead.

### Constant-time comparison

Don't compare secret against data using a naive string comparison, as the timing of the operation will leak information against the content of the secret.
Ideally, a constant-time comparison should be used instead (see `constantTimeStringEquals()` in the PowerDNS code base) but it's not easy to achieve.
One option might be to compute a HMAC of the secret using a key randomly generated at startup, and compare it against a HMAC of the supplied data computed with the same key.

## Virtual destructors

Any class that is expected to be sub-classed should provide a virtual destructor.
Not doing so will prevent the destructor of a derived class from being called if the object is held as the base type:

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

Be careful that defining a destructor will prevent the automatic creation of move operations for that class, since they are generated only if these conditions are met:

* no copy operations are declared ;
* no move operations are declared ;
* no destructor is declared.

If the Parent class holds data that is costly to copy, it might make sense to declare the move operations explicitly:

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

Note that declaring the move operations disables the copy operations, so if they are still needed:

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
While this is allowed under certain restrictions, it's very hard to know exactly which method (base or derived) will be called, and whether all sub-objects contained in the class would have been correctly constructed at that point.

## Hash collisions

Hashes are a very useful tool, used in `unordered_map` and `unordered_set` among others.
They are also used in our caches.
An important caveat that developers need to be aware about regarding hashes are that the probability of a collision is often a lot higher than expected.
This is well-known as the birthday paradox, the fact that the probability of having to entries colliding is a lot higher than the probability of finding a collision for a specific entry.
This means that it is important to verify that the entries are actually identical, and just not that they hash to the same value.

This is especially important when hashing attacker-controlled values, as they can be specially crafted to trigger collisions to cause:

* cache pollution (see https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2018-06.html) ;
* denial of service via hash table flooding (in a map, all entries that hash to the same value are often placed into a linked-list, making it possible to cause a linear scanning of entries by making all of them hash to the value).

The first issue can be prevented by comparing the entries and not just the value they hash to.
The second one can be used by using some sort of secret when computing the hash so that the result cannot be guessed by the attacker.
That can be achieved by using an unpredictable seed for certain hash algorithms, or a secret for some other like `SipHash`.

# Readability tips

Some of these tips are actually enforced by `clang-tidy` nowadays, but it is still useful to keep them in mind.

## Auto

C++11 introduced automatic type deduction, using the auto keyword.
In addition to saving the typing of a few more letters, using automatic type deduction prevents nasty surprises if the variable is initialized from another one, or from a function, and the other type is changed to a different one.
The code might still compile while now involving a copy or worse.

## Boolean expressions

## Explicit comparisons

* compare numerical values to `0` or `!= 0` explicitly ;
* compare to `false` explicitly, which is easier to read ;
* compare to `nullptr` for the same reason.

## Initialization

Use braced initialization for members as often as possible:

* it does forbid narrowing conversions
* and avoids C++'s "move vexing parse" which is to declare a function instead of calling the default constructor:

```c++
Object a(); // declares a function named a that returns an object
```

## nullptr

When representing a pointer, using `nullptr` makes it immediately obvious that we are dealing with a pointer, as opposed to the use of `0`.
It also can't be silently taken as an integer, which can happens with `0` but also with `NULL`.

## const-ness

* Mark parameters and variables that should not be modified as `const`.
  This is especially true for references and pointers that comes from outside the function, but it also makes sense to do it for local variables or parameters passed by value because it might help detect a logic error later.
* Mark const methods as such (and make them thread-safe)
* Prefer using `at()` on containers so that no insertion can take place by mistake, and to get bounds checking.

## static

Functions that are only used inside a single file should be marked as `static`, so that:

* the compiler knows that these functions will not be called from a different compilation unit and thus that no symbol needs to be generated, making it more likely for the function to be inlined ;
* the reader knows that this function is only used there and can be altered without causing an issue somewhere else.

For the same reason, global variables that are only accessed from a single file should be marked static as well.

## Variables

Try to declare variables in the innermost scope possible and avoid uninitialized variables as much as possible.
Declare and initialize them when the values needed to initialize them are available.

## Exceptions

Should be reserved to unexpected events (corrupted data, timeouts, ...) and should not be triggered in normal processing.

Don't be afraid of using them, though, as the cost of an exception that is not thrown is usually very small, thanks to the zero-cost exception model.
It might still force the compiler to refrain from some optimizations, so it might make sense to avoid them in some very performance-sensitive, narrow code paths.

### Custom exceptions

Exceptions defined by the standards should be used whenever possible, as they already cover a lot of use cases.

If custom exceptions are necessary, to be able to catch them explicitly, they should still derive from `std::exception`, directly or indirectly, so that they can still be caught in a more generic way to prevent the program from terminating.
For example, the main connection handling function of a server can catch `std::exception` and just terminate the current connection if an uncaught exception bubbles up.

### Catching exceptions

Catching exceptions should always be done by const reference:

```c+++
try {
}
catch (const std::exception& e) {
  std::cerr << e.what() <<endl;
}
```

Not using a reference would result in the exception object being sliced, meaning that a custom exception derived from `std::exception` would not see its overriding `what()` method called but the one from the base class instead.

## Casts

C-style casts should be avoided, as the compiler does almost no check on the validity of the operation.
They are also very hard to spot in a code.
C++-style casts can easily be spotted in a code, which makes it easy to review them.

* `const_cast` can be used to remove the const qualifier on a variable.
  It's usually a bad sign, but sometimes it is needed to call a function that will not modify the variable but lacks the const qualifier, for example.
* `dynamic_cast` can be used to cast a pointer to a derived class or to a base class, while checking that the operation is valid.
  If the casted object is not valid for the intended type, a nullptr value will be returned (or a bad_cast exception for references) so the result of the operation should be checked! Note that the RTTI check needed to verify that the casted object is valid has a non-negligible CPU cost.
  Not checking the return value might lead to remote denial of service by nullptr dereference, as happened with the issue described in this advisory: https://docs.powerdns.com/recursor/security-advisories/powerdns-advisory-2017-08.html
* `static_cast` can perform downcast in place of `dynamic_cast`, with none of the cost associated to the check, but can only be done if the cast is known to be valid.
  It can also do implicit conversion between types (from `ssize_t` to `size_t`, AFTER checking that the value is greater or equal to zero).
* `reinterpret_cast` is quite dangerous, since it can be used to turn a type into a different one.
  It can't be be used to remove a const qualifier.
  When used to reinterpret the content of a buffer it can quickly lead to alignment issues, as described in the [alignment issues] section.

## errno

`errno` is only guaranteed to be set on failing system calls and not set on succeeding system calls.
A library call may clobber `errno`, even when it succeeds.
Safe practise is:

* Only look at `errno` on failing systems calls or when a library function is documented to set `errno`.
* Immediately save the value of `errno` after a system call for later decision making in a local variable.
