
#pragma once
#include <memory>
/* needed for proper TCP_FASTOPEN_CONNECT detection */
#include <netinet/tcp.h>

#include "iputils.hh"
#include "libssl.hh"
#include "misc.hh"
#include "noinitvector.hh"

enum class IOState : uint8_t { Done, NeedRead, NeedWrite };

class TLSSession
{
public:
  virtual ~TLSSession()
  {
  }
};

class TLSConnection
{
public:
  virtual ~TLSConnection() { }
  virtual void doHandshake() = 0;
  virtual IOState tryConnect(bool fastOpen, const ComboAddress& remote) = 0;
  virtual void connect(bool fastOpen, const ComboAddress& remote, const struct timeval& timeout) = 0;
  virtual IOState tryHandshake() = 0;
  virtual size_t read(void* buffer, size_t bufferSize, const struct timeval& readTimeout, const struct timeval& totalTimeout={0,0}, bool allowIncomplete=false) = 0;
  virtual size_t write(const void* buffer, size_t bufferSize, const struct timeval& writeTimeout) = 0;
  virtual IOState tryWrite(const PacketBuffer& buffer, size_t& pos, size_t toWrite) = 0;
  virtual IOState tryRead(PacketBuffer& buffer, size_t& pos, size_t toRead, bool allowIncomplete=false) = 0;
  virtual bool hasBufferedData() const = 0;
  virtual std::string getServerNameIndication() const = 0;
  virtual std::vector<uint8_t> getNextProtocol() const = 0;
  virtual LibsslTLSVersion getTLSVersion() const = 0;
  virtual bool hasSessionBeenResumed() const = 0;
  virtual std::vector<std::unique_ptr<TLSSession>> getSessions() = 0;
  virtual void setSession(std::unique_ptr<TLSSession>& session) = 0;
  virtual bool isUsable() const = 0;
  virtual void close() = 0;

  void setUnknownTicketKey()
  {
    d_unknownTicketKey = true;
  }

  bool getUnknownTicketKey() const
  {
    return d_unknownTicketKey;
  }

  void setResumedFromInactiveTicketKey()
  {
    d_resumedFromInactiveTicketKey = true;
  }

  bool getResumedFromInactiveTicketKey() const
  {
    return d_resumedFromInactiveTicketKey;
  }

protected:
  int d_socket{-1};
  bool d_unknownTicketKey{false};
  bool d_resumedFromInactiveTicketKey{false};
};

class TLSCtx
{
public:
  TLSCtx()
  {
    d_rotatingTicketsKey.clear();
  }
  virtual ~TLSCtx() {}
  virtual std::unique_ptr<TLSConnection> getConnection(int socket, const struct timeval& timeout, time_t now) = 0;
  virtual std::unique_ptr<TLSConnection> getClientConnection(const std::string& host, int socket, const struct timeval& timeout) = 0;
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
  virtual std::string getName() const = 0;

  /* set the advertised ALPN protocols, in client or server context */
  virtual bool setALPNProtos(const std::vector<std::vector<uint8_t>>& protos)
  {
    return false;
  }

  /* called in a client context, if the client advertised more than one ALPN values and the server returned more than one as well, to select the one to use. */
  virtual bool setNextProtocolSelectCallback(bool(*)(unsigned char** out, unsigned char* outlen, const unsigned char* in, unsigned int inlen))
  {
    return false;
  }

protected:
  std::atomic_flag d_rotatingTicketsKey;
  std::atomic<time_t> d_ticketsKeyNextRotation{0};
  time_t d_ticketsKeyRotationDelay{0};
};

class TLSFrontend
{
public:
  TLSFrontend()
  {
  }

  TLSFrontend(std::shared_ptr<TLSCtx> ctx): d_ctx(std::move(ctx))
  {
  }

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
    return std::atomic_load_explicit(&d_ctx, std::memory_order_acquire);
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
    return d_tlsConfig.d_ticketsKeyRotationDelay;
  }

  std::string getNextTicketsKeyRotation() const
  {
    std::string res;

    if (d_ctx != nullptr) {
      res = timeToString(d_ctx->getNextTicketsKeyRotation());
    }

    return res;
  }

  std::string getRequestedProvider() const
  {
    return d_provider;
  }

  std::string getEffectiveProvider() const
  {
    if (d_ctx) {
      return d_ctx->getName();
    }
    return "";
  }

  TLSConfig d_tlsConfig;
  TLSErrorCounters d_tlsCounters;
  ComboAddress d_addr;
  std::string d_provider;

protected:
  std::shared_ptr<TLSCtx> d_ctx{nullptr};
};

class TCPIOHandler
{
public:
  enum class Type : uint8_t { Client, Server };

  TCPIOHandler(const std::string& host, int socket, const struct timeval& timeout, std::shared_ptr<TLSCtx> ctx, time_t now): d_socket(socket)
  {
    if (ctx) {
      d_conn = ctx->getClientConnection(host, d_socket, timeout);
    }
  }

  TCPIOHandler(int socket, const struct timeval& timeout, std::shared_ptr<TLSCtx> ctx, time_t now): d_socket(socket)
  {
    if (ctx) {
      d_conn = ctx->getConnection(d_socket, timeout, now);
    }
  }

  ~TCPIOHandler()
  {
    close();
  }

  void close()
  {
    if (d_conn) {
      d_conn->close();
      d_conn.reset();
    }

    if (d_socket != -1) {
      shutdown(d_socket, SHUT_RDWR);
      ::close(d_socket);
      d_socket = -1;
    }
  }

  int getDescriptor() const
  {
    return d_socket;
  }

  IOState tryConnect(bool fastOpen, const ComboAddress& remote)
  {
    d_remote = remote;

#ifdef TCP_FASTOPEN_CONNECT /* Linux >= 4.11 */
    if (fastOpen) {
      int value = 1;
      int res = setsockopt(d_socket, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &value, sizeof(value));
      if (res == 0) {
        fastOpen = false;
      }
    }
#endif /* TCP_FASTOPEN_CONNECT */

#ifdef MSG_FASTOPEN
    if (!d_conn && fastOpen) {
      d_fastOpen = true;
    }
    else {
      if (!s_disableConnectForUnitTests) {
        SConnectWithTimeout(d_socket, remote, /* no timeout, we will handle it ourselves */ timeval{0,0});
      }
    }
#else
    if (!s_disableConnectForUnitTests) {
      SConnectWithTimeout(d_socket, remote, /* no timeout, we will handle it ourselves */ timeval{0,0});
    }
#endif /* MSG_FASTOPEN */

    if (d_conn) {
      return d_conn->tryConnect(fastOpen, remote);
    }

    return IOState::Done;
  }

  void connect(bool fastOpen, const ComboAddress& remote, const struct timeval& timeout)
  {
    d_remote = remote;

#ifdef TCP_FASTOPEN_CONNECT /* Linux >= 4.11 */
    if (fastOpen) {
      int value = 1;
      int res = setsockopt(d_socket, IPPROTO_TCP, TCP_FASTOPEN_CONNECT, &value, sizeof(value));
      if (res == 0) {
        fastOpen = false;
      }
    }
#endif /* TCP_FASTOPEN_CONNECT */

#ifdef MSG_FASTOPEN
    if (!d_conn && fastOpen) {
      d_fastOpen = true;
    }
    else {
      if (!s_disableConnectForUnitTests) {
        SConnectWithTimeout(d_socket, remote, timeout);
      }
    }
#else
    if (!s_disableConnectForUnitTests) {
      SConnectWithTimeout(d_socket, remote, timeout);
    }
#endif /* MSG_FASTOPEN */

    if (d_conn) {
      d_conn->connect(fastOpen, remote, timeout);
    }
  }

  IOState tryHandshake()
  {
    if (d_conn) {
      return d_conn->tryHandshake();
    }
    return IOState::Done;
  }

  size_t read(void* buffer, size_t bufferSize, const struct timeval& readTimeout, const struct timeval& totalTimeout = {0,0}, bool allowIncomplete=false)
  {
    if (d_conn) {
      return d_conn->read(buffer, bufferSize, readTimeout, totalTimeout, allowIncomplete);
    } else {
      return readn2WithTimeout(d_socket, buffer, bufferSize, readTimeout, totalTimeout, allowIncomplete);
    }
  }

  /* Tries to read exactly toRead - pos bytes into the buffer, starting at position pos.
     Updates pos everytime a successful read occurs,
     throws an std::runtime_error in case of IO error,
     return Done when toRead bytes have been read, needRead or needWrite if the IO operation
     would block.
  */
  IOState tryRead(PacketBuffer& buffer, size_t& pos, size_t toRead, bool allowIncomplete=false)
  {
    if (buffer.size() < toRead || pos >= toRead) {
      throw std::out_of_range("Calling tryRead() with a too small buffer (" + std::to_string(buffer.size()) + ") for a read of " + std::to_string(toRead - pos) + " bytes starting at " + std::to_string(pos));
    }

    if (d_conn) {
      return d_conn->tryRead(buffer, pos, toRead, allowIncomplete);
    }

    do {
      ssize_t res = ::read(d_socket, reinterpret_cast<char*>(&buffer.at(pos)), toRead - pos);
      if (res == 0) {
        throw runtime_error("EOF while reading message");
      }
      if (res < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOTCONN) {
          return IOState::NeedRead;
        }
        else {
          throw std::runtime_error("Error while reading message: " + stringerror());
        }
      }

      pos += static_cast<size_t>(res);
      if (allowIncomplete) {
        break;
      }
    }
    while (pos < toRead);

    return IOState::Done;
  }

  /* Tries to write exactly toWrite - pos bytes from the buffer, starting at position pos.
     Updates pos everytime a successful write occurs,
     throws an std::runtime_error in case of IO error,
     return Done when toWrite bytes have been written, needRead or needWrite if the IO operation
     would block.
  */
  IOState tryWrite(const PacketBuffer& buffer, size_t& pos, size_t toWrite)
  {
    if (buffer.size() < toWrite || pos >= toWrite) {
      throw std::out_of_range("Calling tryWrite() with a too small buffer (" + std::to_string(buffer.size()) + ") for a write of " + std::to_string(toWrite - pos) + " bytes starting at " + std::to_string(pos));
    }
    if (d_conn) {
      return d_conn->tryWrite(buffer, pos, toWrite);
    }

#ifdef MSG_FASTOPEN
    if (d_fastOpen) {
      int socketFlags = MSG_FASTOPEN;
      size_t sent = sendMsgWithOptions(d_socket, reinterpret_cast<const char *>(&buffer.at(pos)), toWrite - pos, &d_remote, nullptr, 0, socketFlags);
      if (sent > 0) {
        d_fastOpen = false;
        pos += sent;
      }

      if (pos < toWrite) {
        return IOState::NeedWrite;
      }

      return IOState::Done;
    }
#endif /* MSG_FASTOPEN */

    do {
      ssize_t res = ::write(d_socket, reinterpret_cast<const char*>(&buffer.at(pos)), toWrite - pos);

      if (res == 0) {
        throw runtime_error("EOF while sending message");
      }
      if (res < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOTCONN) {
          return IOState::NeedWrite;
        }
        else {
          throw std::runtime_error("Error while writing message: " + stringerror());
        }
      }

      pos += static_cast<size_t>(res);
    }
    while (pos < toWrite);

    return IOState::Done;
  }

  size_t write(const void* buffer, size_t bufferSize, const struct timeval& writeTimeout)
  {
    if (d_conn) {
      return d_conn->write(buffer, bufferSize, writeTimeout);
    }

#ifdef MSG_FASTOPEN
    if (d_fastOpen) {
      int socketFlags = MSG_FASTOPEN;
      size_t sent = sendMsgWithOptions(d_socket, reinterpret_cast<const char *>(buffer), bufferSize, &d_remote, nullptr, 0, socketFlags);
      if (sent > 0) {
        d_fastOpen = false;
      }

      return sent;
    }
#endif /* MSG_FASTOPEN */

    return writen2WithTimeout(d_socket, buffer, bufferSize, writeTimeout);
  }

  bool hasBufferedData() const
  {
    if (d_conn) {
      return d_conn->hasBufferedData();
    }
    return false;
  }

  std::string getServerNameIndication() const
  {
    if (d_conn) {
      return d_conn->getServerNameIndication();
    }
    return std::string();
  }

  std::vector<uint8_t> getNextProtocol() const
  {
    if (d_conn) {
      return d_conn->getNextProtocol();
    }
    return std::vector<uint8_t>();
  }

  LibsslTLSVersion getTLSVersion() const
  {
    if (d_conn) {
      return d_conn->getTLSVersion();
    }
    return LibsslTLSVersion::Unknown;
  }

  bool isTLS() const
  {
    return d_conn != nullptr;
  }

  bool hasTLSSessionBeenResumed() const
  {
    return d_conn && d_conn->hasSessionBeenResumed();
  }

  bool getResumedFromInactiveTicketKey() const
  {
    return d_conn && d_conn->getResumedFromInactiveTicketKey();
  }

  bool getUnknownTicketKey() const
  {
    return d_conn && d_conn->getUnknownTicketKey();
  }

  void setTLSSession(std::unique_ptr<TLSSession>& session)
  {
    if (d_conn != nullptr) {
      d_conn->setSession(session);
    }
  }

  std::vector<std::unique_ptr<TLSSession>> getTLSSessions()
  {
    if (!d_conn) {
      throw std::runtime_error("Trying to get TLS sessions from a non-TLS handler");
    }

    return d_conn->getSessions();
  }

  bool isUsable() const
  {
    if (!d_conn) {
      return isTCPSocketUsable(d_socket);
    }
    return d_conn->isUsable();
  }

  const static bool s_disableConnectForUnitTests;

private:
  std::unique_ptr<TLSConnection> d_conn{nullptr};
  ComboAddress d_remote;
  int d_socket{-1};
#ifdef MSG_FASTOPEN
  bool d_fastOpen{false};
#endif
};

struct TLSContextParameters
{
  std::string d_provider;
  std::string d_ciphers;
  std::string d_ciphers13;
  std::string d_caStore;
  bool d_validateCertificates{true};
  bool d_releaseBuffers{true};
  bool d_enableRenegotiation{false};
};

std::shared_ptr<TLSCtx> getTLSContext(const TLSContextParameters& params);
bool setupDoTProtocolNegotiation(std::shared_ptr<TLSCtx>& ctx);
