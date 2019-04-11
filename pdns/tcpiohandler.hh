
#pragma once
#include <memory>

#include "misc.hh"

enum class IOState { Done, NeedRead, NeedWrite };

class TLSConnection
{
public:
  virtual ~TLSConnection() { }
  virtual void doHandshake() = 0;
  virtual IOState tryHandshake() = 0;
  virtual size_t read(void* buffer, size_t bufferSize, unsigned int readTimeout, unsigned int totalTimeout=0) = 0;
  virtual size_t write(const void* buffer, size_t bufferSize, unsigned int writeTimeout) = 0;
  virtual IOState tryWrite(std::vector<uint8_t>& buffer, size_t& pos, size_t toWrite) = 0;
  virtual IOState tryRead(std::vector<uint8_t>& buffer, size_t& pos, size_t toRead) = 0;
  virtual void close() = 0;

protected:
  int d_socket{-1};
};

class TLSCtx
{
public:
  TLSCtx()
  {
    d_rotatingTicketsKey.clear();
  }
  virtual ~TLSCtx() {}
  virtual std::unique_ptr<TLSConnection> getConnection(int socket, unsigned int timeout, time_t now) = 0;
  virtual void rotateTicketsKey(time_t now) = 0;
  virtual void loadTicketsKeys(const std::string& file)
  {
    throw std::runtime_error("This TLS backend does not have the capability to load a tickets key from a file");
  }

  void handleTicketsKeyRotation(time_t now)
  {
    if (d_ticketsKeyRotationDelay != 0 && now > d_ticketsKeyNextRotation) {
      if (d_rotatingTicketsKey.test_and_set()) {
        /* someone is already rotating */
        return;
      }
      try {
        rotateTicketsKey(now);
        d_rotatingTicketsKey.clear();
      }
      catch(const std::runtime_error& e) {
        d_rotatingTicketsKey.clear();
        throw std::runtime_error(std::string("Error generating a new tickets key for TLS context:") + e.what());
      }
      catch(...) {
        d_rotatingTicketsKey.clear();
        throw;
      }
    }
  }

  time_t getNextTicketsKeyRotation() const
  {
    return d_ticketsKeyNextRotation;
  }

  virtual size_t getTicketsKeysCount() = 0;

protected:
  std::atomic_flag d_rotatingTicketsKey;
  time_t d_ticketsKeyRotationDelay{0};
  time_t d_ticketsKeyNextRotation{0};
};

class TLSFrontend
{
public:
  bool setupTLS();

  void rotateTicketsKey(time_t now)
  {
    if (d_ctx != nullptr) {
      d_ctx->rotateTicketsKey(now);
    }
  }

  void loadTicketsKeys(const std::string& file)
  {
    if (d_ctx != nullptr) {
      d_ctx->loadTicketsKeys(file);
    }
  }

  std::shared_ptr<TLSCtx> getContext()
  {
    return d_ctx;
  }

  void cleanup()
  {
    d_ctx.reset();
  }

  size_t getTicketsKeysCount()
  {
    if (d_ctx != nullptr) {
      return d_ctx->getTicketsKeysCount();
    }

    return 0;
  }

  static std::string timeToString(time_t rotationTime)
  {
    char buf[20];
    struct tm date_tm;

    localtime_r(&rotationTime, &date_tm);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &date_tm);

    return std::string(buf);
  }

  time_t getTicketsKeyRotationDelay() const
  {
    return d_ticketsKeyRotationDelay;
  }

  std::string getNextTicketsKeyRotation() const
  {
    std::string res;

    if (d_ctx != nullptr) {
      res = timeToString(d_ctx->getNextTicketsKeyRotation());
    }

    return res;
  }

  std::vector<std::pair<std::string, std::string>> d_certKeyPairs;
  ComboAddress d_addr;
  std::string d_ciphers;
  std::string d_provider;
  std::string d_ticketKeyFile;

  size_t d_maxStoredSessions{20480};
  time_t d_ticketsKeyRotationDelay{43200};
  uint8_t d_numberOfTicketsKeys{5};
  bool d_enableTickets{true};

private:
  std::shared_ptr<TLSCtx> d_ctx{nullptr};
};

class TCPIOHandler
{
public:

  TCPIOHandler(int socket, unsigned int timeout, std::shared_ptr<TLSCtx> ctx, time_t now): d_socket(socket)
  {
    if (ctx) {
      d_conn = ctx->getConnection(d_socket, timeout, now);
    }
  }

  ~TCPIOHandler()
  {
    if (d_conn) {
      d_conn->close();
    }
    else if (d_socket != -1) {
      shutdown(d_socket, SHUT_RDWR);
    }
  }

  IOState tryHandshake()
  {
    if (d_conn) {
      return d_conn->tryHandshake();
    }
    return IOState::Done;
  }

  size_t read(void* buffer, size_t bufferSize, unsigned int readTimeout, unsigned int totalTimeout=0)
  {
    if (d_conn) {
      return d_conn->read(buffer, bufferSize, readTimeout, totalTimeout);
    } else {
      return readn2WithTimeout(d_socket, buffer, bufferSize, readTimeout, totalTimeout);
    }
  }

  /* Tries to read exactly toRead bytes into the buffer, starting at position pos.
     Updates pos everytime a successful read occurs,
     throws an std::runtime_error in case of IO error,
     return Done when toRead bytes have been read, needRead or needWrite if the IO operation
     would block.
  */
  IOState tryRead(std::vector<uint8_t>& buffer, size_t& pos, size_t toRead)
  {
    if (buffer.size() < (pos + toRead)) {
      throw std::out_of_range("Calling tryRead() with a too small buffer (" + std::to_string(buffer.size()) + ") for a read of " + std::to_string(toRead) + " bytes starting at " + std::to_string(pos));
    }

    if (d_conn) {
      return d_conn->tryRead(buffer, pos, toRead);
    }

    size_t got = 0;
    do {
      ssize_t res = ::read(d_socket, reinterpret_cast<char*>(&buffer.at(pos)), toRead - got);
      if (res == 0) {
        throw runtime_error("EOF while reading message");
      }
      if (res < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          return IOState::NeedRead;
        }
        else {
          throw std::runtime_error(std::string("Error while reading message: ") + strerror(errno));
        }
      }

      pos += static_cast<size_t>(res);
      got += static_cast<size_t>(res);
    }
    while (got < toRead);

    return IOState::Done;
  }

  /* Tries to write exactly toWrite bytes from the buffer, starting at position pos.
     Updates pos everytime a successful write occurs,
     throws an std::runtime_error in case of IO error,
     return Done when toWrite bytes have been written, needRead or needWrite if the IO operation
     would block.
  */
  IOState tryWrite(std::vector<uint8_t>& buffer, size_t& pos, size_t toWrite)
  {
    if (d_conn) {
      return d_conn->tryWrite(buffer, pos, toWrite);
    }

    size_t sent = 0;
    do {
      ssize_t res = ::write(d_socket, reinterpret_cast<char*>(&buffer.at(pos)), toWrite - sent);
      if (res == 0) {
        throw runtime_error("EOF while sending message");
      }
      if (res < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          return IOState::NeedWrite;
        }
        else {
          throw std::runtime_error(std::string("Error while writing message: ") + strerror(errno));
        }
      }

      pos += static_cast<size_t>(res);
      sent += static_cast<size_t>(res);
    }
    while (sent < toWrite);

    return IOState::Done;
  }

  size_t write(const void* buffer, size_t bufferSize, unsigned int writeTimeout)
  {
    if (d_conn) {
      return d_conn->write(buffer, bufferSize, writeTimeout);
    }
    else {
      return writen2WithTimeout(d_socket, buffer, bufferSize, writeTimeout);
    }
  }

  bool writeSizeAndMsg(const void* buffer, size_t bufferSize, unsigned int writeTimeout)
  {
    if (d_conn) {
      uint16_t size = htons(bufferSize);
      if (d_conn->write(&size, sizeof(size), writeTimeout) != sizeof(size)) {
        return false;
      }
      return (d_conn->write(buffer, bufferSize, writeTimeout) == bufferSize);
    }
    else {
      return sendSizeAndMsgWithTimeout(d_socket, bufferSize, static_cast<const char*>(buffer), writeTimeout, nullptr, nullptr, 0, 0, 0);
    }
  }

private:
  std::unique_ptr<TLSConnection> d_conn{nullptr};
  int d_socket{-1};
};
