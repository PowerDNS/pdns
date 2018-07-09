
#pragma once
#include <memory>

#include "misc.hh"

class TLSConnection
{
public:
  virtual ~TLSConnection() { }
  virtual size_t read(void* buffer, size_t bufferSize, unsigned int readTimeout, unsigned int totalTimeout=0) = 0;
  virtual size_t write(const void* buffer, size_t bufferSize, unsigned int writeTimeout) = 0;
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
        throw std::runtime_error("Error generating a new tickets key for TLS context");
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

  std::set<int> d_cpus;
  std::vector<std::pair<std::string, std::string>> d_certKeyPairs;
  ComboAddress d_addr;
  std::string d_ciphers;
  std::string d_provider;
  std::string d_interface;
  std::string d_ticketKeyFile;

  time_t d_ticketsKeyRotationDelay{43200};
  int d_tcpFastOpenQueueSize{0};
  uint8_t d_numberOfTicketsKeys{5};
  bool d_reusePort{false};
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
  size_t read(void* buffer, size_t bufferSize, unsigned int readTimeout, unsigned int totalTimeout=0)
  {
    if (d_conn) {
      return d_conn->read(buffer, bufferSize, readTimeout, totalTimeout);
    } else {
      return readn2WithTimeout(d_socket, buffer, bufferSize, readTimeout, totalTimeout);
    }
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
