#include "dnsdist.hh"
#include "sodcrypto.hh"
#include <readline/readline.h>
#include <readline/history.h>
#include <fstream>
#include "dolog.hh"

vector<pair<struct timeval, string> > g_confDelta;

// MUST BE CALLED UNDER A LOCK - right now the LuaLock
void feedConfigDelta(const std::string& line)
{
  struct timeval now;
  gettimeofday(&now, 0);
  g_confDelta.push_back({now,line});
}

void doClient(ComboAddress server, const std::string& command)
{
  cout<<"Connecting to "<<server.toStringWithPort()<<endl;
  int fd=socket(server.sin4.sin_family, SOCK_STREAM, 0);
  SConnect(fd, server);

  SodiumNonce theirs, ours;
  ours.init();

  writen2(fd, (const char*)ours.value, sizeof(ours.value));
  readn2(fd, (char*)theirs.value, sizeof(theirs.value));

  if(!command.empty()) {
    string response;
    string msg=sodEncryptSym(command, g_key, ours);
    putMsgLen32(fd, msg.length());
    if(!msg.empty())
      writen2(fd, msg);
    uint32_t len;
    getMsgLen32(fd, &len);
    boost::scoped_array<char> resp(new char[len]);
    readn2(fd, resp.get(), len);
    msg.assign(resp.get(), len);
    msg=sodDecryptSym(msg, g_key, theirs);
    cout<<msg<<endl;
    return; 
  }

  set<string> dupper;
  {
    ifstream history(".dnsdist_history");
    string line;
    while(getline(history, line))
      add_history(line.c_str());
  }
  ofstream history(".dnsdist_history", std::ios_base::app);
  string lastline;
  for(;;) {
    char* sline = readline("> ");
    rl_bind_key('\t',rl_complete);
    if(!sline)
      break;

    string line(sline);
    if(!line.empty() && line != lastline) {
      add_history(sline);
      history << sline <<endl;
      history.flush();
    }
    lastline=line;
    free(sline);
    
    if(line=="quit")
      break;

    /* no need to send an empty line to the server */
    if(line.empty())
      continue;

    string response;
    string msg=sodEncryptSym(line, g_key, ours);
    putMsgLen32(fd, msg.length());
    writen2(fd, msg);
    uint32_t len;
    if(!getMsgLen32(fd, &len)) {
      cout << "Connection closed by the server." << endl;
      break;
    }

    if (len > 0) {
      boost::scoped_array<char> resp(new char[len]);
      readn2(fd, resp.get(), len);
      msg.assign(resp.get(), len);
      msg=sodDecryptSym(msg, g_key, theirs);
      cout<<msg<<endl;
    }
    else {
      cout<<endl;
    }
  }
}

void doConsole()
{
  set<string> dupper;
  {
    ifstream history(".dnsdist_history");
    string line;
    while(getline(history, line))
      add_history(line.c_str());
  }
  ofstream history(".dnsdist_history", std::ios_base::app);
  string lastline;
  for(;;) {
    char* sline = readline("> ");
    rl_bind_key('\t',rl_complete);
    if(!sline)
      break;

    string line(sline);
    if(!line.empty() && line != lastline) {
      add_history(sline);
      history << sline <<endl;
      history.flush();
    }
    lastline=line;
    free(sline);
    
    if(line=="quit")
      break;

    string response;
    try {
      std::lock_guard<std::mutex> lock(g_luamutex);
      g_outputBuffer.clear();
      resetLuaSideEffect();
      auto ret=g_lua.executeCode<
	boost::optional<
	  boost::variant<
	    string, 
	    shared_ptr<DownstreamState>
	    >
	  >
	>(line);

      if(ret) {
	if (const auto strValue = boost::get<shared_ptr<DownstreamState>>(&*ret)) {
	  cout<<(*strValue)->getName()<<endl;
	}
	else if (const auto strValue = boost::get<string>(&*ret)) {
	  cout<<*strValue<<endl;
	}
      }
      else 
	cout << g_outputBuffer;
      if(!getLuaNoSideEffect())
        feedConfigDelta(line);
    }
    catch(const LuaContext::ExecutionErrorException& e) {
      std::cerr << e.what() << ": ";
      try {
        std::rethrow_if_nested(e);
      } catch(const std::exception& e) {
        // e is the exception that was thrown from inside the lambda
        std::cerr << e.what() << std::endl;      
      }
      catch(const PDNSException& e) {
        // e is the exception that was thrown from inside the lambda
        std::cerr << e.reason << std::endl;      
      }
    }
    catch(const std::exception& e) {
      // e is the exception that was thrown from inside the lambda
      std::cerr << e.what() << std::endl;      
    }
  }
}
/**** CARGO CULT CODE AHEAD ****/
extern "C" {
char* my_generator(const char* text, int state)
{
  string t(text);
  vector<string> words{"showRules()", "shutdown()", "rmRule(", "mvRule(", "addACL(", "addLocal(", "setServerPolicy(", "setServerPolicyLua(",
      "newServer(", "rmServer(", "showServers()", "show(", "newDNSName(", "newSuffixMatchNode(", "controlSocket(", "topClients(", "showResponseLatency()", 
      "newQPSLimiter(", "makeKey()", "setKey(", "testCrypto()", "addAnyTCRule()", "showServerPolicy()", "setACL(", "showACL()", "addDomainBlock(", 
      "addPoolRule(", "addQPSLimit(", "topResponses(", "topQueries(", "topRule()", "setDNSSECPool(", "setECSOverride(", "setECSSourcePrefixV4(",
      "setECSSourcePrefixV6(", "addDelay(", "setTCPRecvTimeout(", "setTCPSendTimeout(", "setMaxTCPClientThreads(", "setMaxUDPOutstanding(" };
  static int s_counter=0;
  int counter=0;
  if(!state)
    s_counter=0;

  for(auto w : words) {
    if(boost::starts_with(w, t) && counter++ == s_counter)  {
      s_counter++;
      return strdup(w.c_str());
    }
  }
  return 0;
}

char** my_completion( const char * text , int start,  int end)
{
  char **matches=0;
  if (start == 0)
    matches = rl_completion_matches ((char*)text, &my_generator);
  else
    rl_bind_key('\t',rl_abort);
 
  if(!matches)
    rl_bind_key('\t', rl_abort);
  return matches;
}
}

void controlClientThread(int fd, ComboAddress client)
try
{
  SodiumNonce theirs;
  readn2(fd, (char*)theirs.value, sizeof(theirs.value));
  SodiumNonce ours;
  ours.init();
  writen2(fd, (char*)ours.value, sizeof(ours.value));

  for(;;) {
    uint32_t len;
    if(!getMsgLen32(fd, &len))
      break;

    if (len == 0) {
      /* just ACK an empty message
         with an empty response */
      putMsgLen32(fd, 0);
      continue;
    }

    boost::scoped_array<char> msg(new char[len]);
    readn2(fd, msg.get(), len);
    
    string line(msg.get(), len);
    line = sodDecryptSym(line, g_key, theirs);
    //    cerr<<"Have decrypted line: "<<line<<endl;
    string response;
    try {
      std::lock_guard<std::mutex> lock(g_luamutex);
      g_outputBuffer.clear();
      resetLuaSideEffect();
      auto ret=g_lua.executeCode<
	boost::optional<
	  boost::variant<
	    string, 
	    shared_ptr<DownstreamState>
	    >
	  >
	>(line);

      if(ret) {
	if (const auto strValue = boost::get<shared_ptr<DownstreamState>>(&*ret)) {
	  response=(*strValue)->getName();
	}
	else if (const auto strValue = boost::get<string>(&*ret)) {
	  response=*strValue;
	}
      }
      else
	response=g_outputBuffer;
      if(!getLuaNoSideEffect())
        feedConfigDelta(line);
    }
    catch(const LuaContext::ExecutionErrorException& e) {
      response = "Error: " + string(e.what()) + ": ";
      try {
        std::rethrow_if_nested(e);
      } catch(const std::exception& e) {
        // e is the exception that was thrown from inside the lambda
        response+= string(e.what());
      }
      catch(const PDNSException& e) {
        // e is the exception that was thrown from inside the lambda
        response += string(e.reason);
      }
    }
    catch(const LuaContext::SyntaxErrorException& e) {
      response = "Error: " + string(e.what()) + ": ";
    }
    response = sodEncryptSym(response, g_key, ours);
    putMsgLen32(fd, response.length());
    writen2(fd, response.c_str(), response.length());
  }
  infolog("Closed control connection from %s", client.toStringWithPort());
  close(fd);
  fd=-1;
}
catch(std::exception& e)
{
  errlog("Got an exception in client connection from %s: %s", client.toStringWithPort(), e.what());
  if(fd >= 0)
    close(fd);
}

