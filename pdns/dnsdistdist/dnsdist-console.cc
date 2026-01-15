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
#include "config.h"

#include <fstream>
// we need this to get the home directory of the current user
#include <pwd.h>
#include <thread>

#ifdef HAVE_LIBEDIT
#if defined(__OpenBSD__) || defined(__NetBSD__)
// If this is not undeffed, __attribute__ will be redefined by /usr/include/readline/rlstdc.h
#undef __STRICT_ANSI__
#include <readline/readline.h>
#include <readline/history.h>
#else
#include <editline/readline.h>
#endif
#endif /* HAVE_LIBEDIT */

#include "ext/json11/json11.hpp"

#include "connection-management.hh"
#include "dolog.hh"
#include "dnsdist.hh"
#include "dnsdist-console.hh"
#include "dnsdist-console-completion.hh"
#include "dnsdist-crypto.hh"
#include "dnsdist-lua.hh"
#include "threadname.hh"

static LockGuarded<std::vector<pair<timeval, string>>> s_confDelta;

static ConcurrentConnectionManager s_connManager(100);

class ConsoleConnection
{
public:
  ConsoleConnection(const ComboAddress& client, FDWrapper&& fileDesc) :
    d_client(client), d_fileDesc(std::move(fileDesc))
  {
    if (!s_connManager.registerConnection()) {
      throw std::runtime_error("Too many concurrent console connections");
    }
  }
  ConsoleConnection(ConsoleConnection&& rhs) noexcept :
    d_client(rhs.d_client), d_fileDesc(std::move(rhs.d_fileDesc))
  {
  }

  ConsoleConnection(const ConsoleConnection&) = delete;
  ConsoleConnection& operator=(const ConsoleConnection&) = delete;
  ConsoleConnection& operator=(ConsoleConnection&&) = delete;

  ~ConsoleConnection()
  {
    if (d_fileDesc.getHandle() != -1) {
      s_connManager.releaseConnection();
    }
  }

  [[nodiscard]] int getFD() const
  {
    return d_fileDesc.getHandle();
  }

  [[nodiscard]] const ComboAddress& getClient() const
  {
    return d_client;
  }

private:
  ComboAddress d_client;
  FDWrapper d_fileDesc;
};

static void feedConfigDelta(const std::string& line)
{
  if (line.empty()) {
    return;
  }
  timeval now{};
  gettimeofday(&now, nullptr);
  s_confDelta.lock()->emplace_back(now, line);
}

namespace dnsdist::console
{
const std::vector<std::pair<timeval, std::string>>& getConfigurationDelta()
{
  return *(s_confDelta.lock());
}
}

#ifdef HAVE_LIBEDIT
static string historyFile(const bool& ignoreHOME = false)
{
  string ret;

  passwd pwd{};
  passwd* result{nullptr};
  std::array<char, 16384> buf{};
  getpwuid_r(geteuid(), &pwd, buf.data(), buf.size(), &result);

  // NOLINTNEXTLINE(concurrency-mt-unsafe): we are not modifying the environment
  const char* homedir = getenv("HOME");
  if (result != nullptr) {
    ret = string(pwd.pw_dir);
  }
  if (homedir != nullptr && !ignoreHOME) { // $HOME overrides what the OS tells us
    ret = string(homedir);
  }
  if (ret.empty()) {
    ret = "."; // CWD if nothing works..
  }
  ret.append("/.dnsdist_history");
  return ret;
}
#endif /* HAVE_LIBEDIT */

enum class ConsoleCommandResult : uint8_t
{
  Valid = 0,
  ConnectionClosed,
  TooLarge
};

static ConsoleCommandResult getMsgLen32(int fileDesc, uint32_t* len)
{
  try {
    uint32_t raw{0};
    size_t ret = readn2(fileDesc, &raw, sizeof(raw));

    if (ret != sizeof raw) {
      return ConsoleCommandResult::ConnectionClosed;
    }

    *len = ntohl(raw);
    if (*len > dnsdist::configuration::getCurrentRuntimeConfiguration().d_consoleOutputMsgMaxSize) {
      return ConsoleCommandResult::TooLarge;
    }

    return ConsoleCommandResult::Valid;
  }
  catch (...) {
    return ConsoleCommandResult::ConnectionClosed;
  }
}

static bool putMsgLen32(int fileDesc, uint32_t len)
{
  try {
    uint32_t raw = htonl(len);
    size_t ret = writen2(fileDesc, &raw, sizeof raw);
    return ret == sizeof raw;
  }
  catch (...) {
    return false;
  }
}

static ConsoleCommandResult sendMessageToServer(int fileDesc, const std::string& line, dnsdist::crypto::authenticated::Nonce& readingNonce, dnsdist::crypto::authenticated::Nonce& writingNonce, const bool outputEmptyLine)
{
  const auto& consoleKey = dnsdist::configuration::getCurrentRuntimeConfiguration().d_consoleKey;
  string msg = dnsdist::crypto::authenticated::encryptSym(line, consoleKey, writingNonce);
  const auto msgLen = msg.length();
  if (msgLen > std::numeric_limits<uint32_t>::max()) {
    cerr << "Encrypted message is too long to be sent to the server, " << std::to_string(msgLen) << " > " << std::numeric_limits<uint32_t>::max() << endl;
    return ConsoleCommandResult::TooLarge;
  }

  putMsgLen32(fileDesc, static_cast<uint32_t>(msgLen));

  if (!msg.empty()) {
    writen2(fileDesc, msg);
  }

  uint32_t len{0};
  auto commandResult = getMsgLen32(fileDesc, &len);
  if (commandResult == ConsoleCommandResult::ConnectionClosed) {
    cout << "Connection closed by the server." << endl;
    return commandResult;
  }
  if (commandResult == ConsoleCommandResult::TooLarge) {
    cerr << "Received a console message whose length (" << len << ") is exceeding the allowed one (" << dnsdist::configuration::getCurrentRuntimeConfiguration().d_consoleOutputMsgMaxSize << "), closing that connection" << endl;
    return commandResult;
  }

  if (len == 0) {
    if (outputEmptyLine) {
      cout << endl;
    }

    return ConsoleCommandResult::Valid;
  }

  msg.clear();
  msg.resize(len);
  readn2(fileDesc, msg.data(), len);
  msg = dnsdist::crypto::authenticated::decryptSym(msg, consoleKey, readingNonce);
  cout << msg;
  cout.flush();

  return ConsoleCommandResult::Valid;
}

namespace dnsdist::console
{
void doClient(const std::string& command)
{
  //coverity[auto_causes_copy]
  const auto consoleKey = dnsdist::configuration::getCurrentRuntimeConfiguration().d_consoleKey;
  //coverity[auto_causes_copy]
  const auto server = dnsdist::configuration::getCurrentRuntimeConfiguration().d_consoleServerAddress;
  if (!dnsdist::crypto::authenticated::isValidKey(consoleKey)) {
    cerr << "The currently configured console key is not valid, please configure a valid key using the setKey() directive" << endl;
    return;
  }

  if (dnsdist::configuration::getCurrentRuntimeConfiguration().d_verbose) {
    cout << "Connecting to " << server.toStringWithPort() << endl;
  }

  auto fileDesc = FDWrapper(socket(server.sin4.sin_family, SOCK_STREAM, 0));
  if (fileDesc.getHandle() < 0) {
    cerr << "Unable to connect to " << server.toStringWithPort() << endl;
    return;
  }
  SConnect(fileDesc.getHandle(), false, server);
  setTCPNoDelay(fileDesc.getHandle());
  dnsdist::crypto::authenticated::Nonce theirs;
  dnsdist::crypto::authenticated::Nonce ours;
  dnsdist::crypto::authenticated::Nonce readingNonce;
  dnsdist::crypto::authenticated::Nonce writingNonce;
  ours.init();

  writen2(fileDesc.getHandle(), ours.value.data(), ours.value.size());
  readn2(fileDesc.getHandle(), theirs.value.data(), theirs.value.size());
  readingNonce.merge(ours, theirs);
  writingNonce.merge(theirs, ours);

  /* try sending an empty message, the server should send an empty
     one back. If it closes the connection instead, we are probably
     having a key mismatch issue. */
  auto commandResult = sendMessageToServer(fileDesc.getHandle(), "", readingNonce, writingNonce, false);
  if (commandResult == ConsoleCommandResult::ConnectionClosed) {
    cerr << "The server closed the connection right away, likely indicating a key mismatch. Please check your setKey() directive." << endl;
    return;
  }
  if (commandResult == ConsoleCommandResult::TooLarge) {
    return;
  }

  if (!command.empty()) {
    sendMessageToServer(fileDesc.getHandle(), command, readingNonce, writingNonce, false);
    return;
  }

#ifdef HAVE_LIBEDIT
  string histfile = historyFile();
  {
    ifstream history(histfile);
    string line;
    while (getline(history, line)) {
      add_history(line.c_str());
    }
  }
  ofstream history(histfile, std::ios_base::app);
  string lastline;
  for (;;) {
    char* sline = readline("> ");
    rl_bind_key('\t', rl_complete);
    if (sline == nullptr) {
      break;
    }

    string line(sline);
    if (!line.empty() && line != lastline) {
      add_history(sline);
      history << sline << endl;
      history.flush();
    }
    lastline = line;
    // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,cppcoreguidelines-owning-memory): readline
    free(sline);

    if (line == "quit") {
      break;
    }
    if (line == "help" || line == "?") {
      line = "help()";
    }

    /* no need to send an empty line to the server */
    if (line.empty()) {
      continue;
    }

    commandResult = sendMessageToServer(fileDesc.getHandle(), line, readingNonce, writingNonce, true);
    if (commandResult != ConsoleCommandResult::Valid) {
      break;
    }
  }
#else
  SLOG(errlog("Client mode requested but libedit support is not available"),
       dnsdist::logging::getTopLogger("console-client")->info(Logr::Error, "Client mode requested but libedit support is not available"));
#endif /* HAVE_LIBEDIT */
}

#ifdef HAVE_LIBEDIT
static std::optional<std::string> getNextConsoleLine(ofstream& history, std::string& lastline)
{
  char* sline = readline("> ");
  rl_bind_key('\t', rl_complete);
  if (sline == nullptr) {
    return std::nullopt;
  }

  string line(sline);
  if (!line.empty() && line != lastline) {
    add_history(sline);
    history << sline << endl;
    history.flush();
  }

  lastline = line;
  // NOLINTNEXTLINE(cppcoreguidelines-no-malloc,cppcoreguidelines-owning-memory): readline
  free(sline);

  return line;
}
#else /* HAVE_LIBEDIT */
static std::optional<std::string> getNextConsoleLine()
{
  std::string line;
  if (!std::getline(std::cin, line)) {
    return std::nullopt;
  }
  return line;
}
#endif /* HAVE_LIBEDIT */

void doConsole()
{
#ifdef HAVE_LIBEDIT
  string histfile = historyFile(true);
  {
    ifstream history(histfile);
    string line;
    while (getline(history, line)) {
      add_history(line.c_str());
    }
  }
  ofstream history(histfile, std::ios_base::app);
  string lastline;
#endif /* HAVE_LIBEDIT */

  for (;;) {
#ifdef HAVE_LIBEDIT
    auto line = getNextConsoleLine(history, lastline);
#else /* HAVE_LIBEDIT */
    auto line = getNextConsoleLine();
#endif /* HAVE_LIBEDIT */
    if (!line) {
      break;
    }

    if (*line == "quit") {
      break;
    }
    if (*line == "help" || *line == "?") {
      line = "help()";
    }

    string response;
    try {
      bool withReturn = true;
    retry:;
      try {
        auto lua = g_lua.lock();
        g_outputBuffer.clear();
        resetLuaSideEffect();
        auto ret = lua->executeCode<
          std::optional<
            boost::variant<
              string,
              shared_ptr<DownstreamState>,
              ClientState*,
              std::unordered_map<string, double>>>>(withReturn ? ("return " + *line) : *line);
        if (ret) {
          if (const auto* dsValue = boost::get<shared_ptr<DownstreamState>>(&*ret)) {
            if (*dsValue) {
              cout << (*dsValue)->getName() << endl;
            }
          }
          else if (const auto* csValue = boost::get<ClientState*>(&*ret)) {
            if (*csValue != nullptr) {
              cout << (*csValue)->local.toStringWithPort() << endl;
            }
          }
          else if (const auto* strValue = boost::get<string>(&*ret)) {
            cout << *strValue << endl;
          }
          else if (const auto* mapValue = boost::get<std::unordered_map<string, double>>(&*ret)) {
            using namespace json11;
            Json::object obj;
            for (const auto& value : *mapValue) {
              obj[value.first] = value.second;
            }
            Json out = obj;
            cout << out.dump() << endl;
          }
        }
        else {
          cout << g_outputBuffer << std::flush;
        }

        if (!getLuaNoSideEffect()) {
          feedConfigDelta(*line);
        }
      }
      catch (const LuaContext::SyntaxErrorException&) {
        if (withReturn) {
          withReturn = false;
          // NOLINTNEXTLINE(cppcoreguidelines-avoid-goto)
          goto retry;
        }
        throw;
      }
    }
    catch (const LuaContext::WrongTypeException& e) {
      std::cerr << "Command returned an object we can't print: " << std::string(e.what()) << std::endl;
      // tried to return something we don't understand
    }
    catch (const LuaContext::ExecutionErrorException& e) {
      if (strcmp(e.what(), "invalid key to 'next'") == 0) {
        std::cerr << "Error parsing parameters, did you forget parameter name?";
      }
      else {
        std::cerr << e.what();
      }

      try {
        std::rethrow_if_nested(e);

        std::cerr << std::endl;
      }
      catch (const std::exception& ne) {
        // ne is the exception that was thrown from inside the lambda
        std::cerr << ": " << ne.what() << std::endl;
      }
      catch (const PDNSException& ne) {
        // ne is the exception that was thrown from inside the lambda
        std::cerr << ": " << ne.reason << std::endl;
      }
    }
    catch (const std::exception& e) {
      std::cerr << e.what() << std::endl;
    }
  }
}
}

namespace dnsdist::console
{
void clearHistory()
{
#ifdef HAVE_LIBEDIT
  clear_history();
#endif /* HAVE_LIBEDIT */
  s_confDelta.lock()->clear();
}

static void controlClientThread(ConsoleConnection&& conn, std::shared_ptr<Logr::Logger> logger)
{
  try {
    setThreadName("dnsdist/conscli");

    setTCPNoDelay(conn.getFD());

    //coverity[auto_causes_copy]
    const auto consoleKey = dnsdist::configuration::getCurrentRuntimeConfiguration().d_consoleKey;
    dnsdist::crypto::authenticated::Nonce theirs;
    dnsdist::crypto::authenticated::Nonce ours;
    dnsdist::crypto::authenticated::Nonce readingNonce;
    dnsdist::crypto::authenticated::Nonce writingNonce;
    ours.init();
    readn2(conn.getFD(), theirs.value.data(), theirs.value.size());
    writen2(conn.getFD(), ours.value.data(), ours.value.size());
    readingNonce.merge(ours, theirs);
    writingNonce.merge(theirs, ours);

    for (;;) {
      uint32_t len{0};
      if (getMsgLen32(conn.getFD(), &len) != ConsoleCommandResult::Valid) {
        break;
      }

      if (len == 0) {
        /* just ACK an empty message
           with an empty response */
        putMsgLen32(conn.getFD(), 0);
        continue;
      }

      std::string line;
      //coverity[tainted_data]
      line.resize(len);
      readn2(conn.getFD(), line.data(), len);

      line = dnsdist::crypto::authenticated::decryptSym(line, consoleKey, readingNonce);

      dnsdist::configuration::refreshLocalRuntimeConfiguration();

      string response;
      try {
        bool withReturn = true;
      retry:;
        try {
          auto lua = g_lua.lock();

          g_outputBuffer.clear();
          resetLuaSideEffect();
          auto ret = lua->executeCode<
            std::optional<
              boost::variant<
                string,
                shared_ptr<DownstreamState>,
                ClientState*,
                std::unordered_map<string, double>>>>(withReturn ? ("return " + line) : line);

          if (ret) {
            if (const auto* dsValue = boost::get<shared_ptr<DownstreamState>>(&*ret)) {
              if (*dsValue) {
                response = (*dsValue)->getName() + "\n";
              }
              else {
                response = "";
              }
            }
            else if (const auto* csValue = boost::get<ClientState*>(&*ret)) {
              if (*csValue != nullptr) {
                response = (*csValue)->local.toStringWithPort() + "\n";
              }
              else {
                response = "";
              }
            }
            else if (const auto* strValue = boost::get<string>(&*ret)) {
              response = *strValue + "\n";
            }
            else if (const auto* mapValue = boost::get<std::unordered_map<string, double>>(&*ret)) {
              using namespace json11;
              Json::object obj;
              for (const auto& value : *mapValue) {
                obj[value.first] = value.second;
              }
              Json out = obj;
              response = out.dump() + "\n";
            }
          }
          else {
            response = g_outputBuffer;
          }
          if (!getLuaNoSideEffect()) {
            feedConfigDelta(line);
          }
        }
        catch (const LuaContext::SyntaxErrorException&) {
          if (withReturn) {
            withReturn = false;
            // NOLINTNEXTLINE(cppcoreguidelines-avoid-goto)
            goto retry;
          }
          throw;
        }
      }
      catch (const LuaContext::WrongTypeException& e) {
        response = "Command returned an object we can't print: " + std::string(e.what()) + "\n";
        // tried to return something we don't understand
      }
      catch (const LuaContext::ExecutionErrorException& e) {
        if (strcmp(e.what(), "invalid key to 'next'") == 0) {
          response = "Error: Parsing function parameters, did you forget parameter name?";
        }
        else {
          response = "Error: " + string(e.what());
        }

        try {
          std::rethrow_if_nested(e);
        }
        catch (const std::exception& ne) {
          // ne is the exception that was thrown from inside the lambda
          response += ": " + string(ne.what());
        }
        catch (const PDNSException& ne) {
          // ne is the exception that was thrown from inside the lambda
          response += ": " + string(ne.reason);
        }
      }
      catch (const LuaContext::SyntaxErrorException& e) {
        response = "Error: " + string(e.what()) + ": ";
      }
      response = dnsdist::crypto::authenticated::encryptSym(response, consoleKey, writingNonce);
      putMsgLen32(conn.getFD(), response.length());
      writen2(conn.getFD(), response.c_str(), response.length());
    }
    if (dnsdist::configuration::getCurrentRuntimeConfiguration().d_logConsoleConnections) {
      SLOG(infolog("Closed control connection from %s", conn.getClient().toStringWithPort()),
           logger->info(Logr::Info, "Closed control connection"));
    }
  }
  catch (const std::exception& e) {
    SLOG(infolog("Got an exception in client connection from %s: %s", conn.getClient().toStringWithPort(), e.what()),
         logger->error(Logr::Info, e.what(), "Got an exception in control connection"));
  }
}

void controlThread(Socket&& acceptFD)
{
  setThreadName("dnsdist/control");
  const ComboAddress local = dnsdist::configuration::getCurrentRuntimeConfiguration().d_consoleServerAddress;
  auto logger = dnsdist::logging::getTopLogger("console-server")->withValues("network.local.address", Logging::Loggable(local));
  try {
    s_connManager.setMaxConcurrentConnections(dnsdist::configuration::getImmutableConfiguration().d_consoleMaxConcurrentConnections);

    ComboAddress client;
    // make sure that the family matches the one from the listening IP,
    // so that getSocklen() returns the correct size later, otherwise
    // the first IPv6 console connection might get refused
    client.sin4.sin_family = local.sin4.sin_family;

    int sock{-1};
    SLOG(infolog("Accepting control connections on %s", local.toStringWithPort()),
         logger->info(Logr::Info, "Accepting control connections"));

    while ((sock = SAccept(acceptFD.getHandle(), client)) >= 0) {
      dnsdist::configuration::refreshLocalRuntimeConfiguration();
      const auto& consoleKey = dnsdist::configuration::getCurrentRuntimeConfiguration().d_consoleKey;
      FDWrapper socket(sock);
      if (!dnsdist::crypto::authenticated::isValidKey(consoleKey)) {
        VERBOSESLOG(infolog("Control connection from %s dropped because we don't have a valid key configured, please configure one using setKey()", client.toStringWithPort()),
                    logger->info(Logr::Info, "Control connection dropped because we don't have a valid key configured, please configure one using setKey()", "client.address", Logging::Loggable(client)));
        continue;
      }

      const auto& runtimeConfig = dnsdist::configuration::getCurrentRuntimeConfiguration();
      if (!runtimeConfig.d_consoleACL.match(client)) {
        VERBOSESLOG(infolog("Control connection from %s dropped because of ACL", client.toStringWithPort()),
                    logger->info(Logr::Info, "Control connection dropped because of ACL", "client.address", Logging::Loggable(client)));
        continue;
      }

      try {
        ConsoleConnection conn(client, std::move(socket));
        auto connLogger = dnsdist::logging::getTopLogger("console-connection")->withValues("client.address", Logging::Loggable(client));
        if (runtimeConfig.d_logConsoleConnections) {
          SLOG(warnlog("Got control connection from %s", client.toStringWithPort()),
               connLogger->info(Logr::Info, "Control connection opened"));
        }

        std::thread clientThread(controlClientThread, std::move(conn), std::move(connLogger));
        clientThread.detach();
      }
      catch (const std::exception& e) {
        SLOG(infolog("Control connection died: %s", e.what()),
             logger->error(Logr::Info, e.what(), "Control connection died", "client.address", Logging::Loggable(client)));
      }
    }
  }
  catch (const std::exception& e) {
    SLOG(errlog("Control thread died: %s", e.what()),
         logger->error(Logr::Error, e.what(), "Control thread died"));
  }
}
}
