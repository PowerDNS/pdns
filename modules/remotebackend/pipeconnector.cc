#include "remotebackend.hh"

PipeConnector::PipeConnector(std::map<std::string,std::string> options) {
  if (options.count("command") == 0) {
    L<<Logger::Error<<"Cannot find 'command' option in connection string"<<endl;
    throw new AhuException();
  }
  this->command = options.find("command")->second;
  this->options = options;
  this->coproc = NULL;
  launch();
}

PipeConnector::~PipeConnector(){
  if (this->coproc != NULL) 
    delete coproc; 
}

void PipeConnector::launch() {
  if (coproc != NULL) return;
  rapidjson::Value val;
  rapidjson::Document init,res;
  int timeout=2000;
  if (options.find("timeout") != options.end()) { 
     timeout = boost::lexical_cast<int>(options.find("timeout")->second);
  }
  coproc = new CoProcess(this->command, timeout);
  init.SetObject();
  val = "initialize";
  init.AddMember("method",val, init.GetAllocator());
  val.SetObject();
  init.AddMember("parameters", val, init.GetAllocator());

  for(std::map<std::string,std::string>::iterator i = options.begin(); i != options.end(); i++) {
    val = i->second.c_str();
    init["parameters"].AddMember(i->first.c_str(), val, init.GetAllocator());
  }

  this->send(init);
  if (this->recv(res)==false) {
    L<<Logger::Error<<"Failed to initialize coprocess"<<std::endl;
  }
}

int PipeConnector::send_message(const rapidjson::Document &input)
{
   std::string data;

   data = makeStringFromDocument(input);

   launch();
   try {
      coproc->send(data);
      return 1;
   }
   catch(AhuException &ae) {
      delete coproc;
      coproc=NULL;
      throw;
   } 
}

int PipeConnector::recv_message(rapidjson::Document &output) 
{
   rapidjson::GenericReader<rapidjson::UTF8<> , rapidjson::MemoryPoolAllocator<> > r;
   std::string tmp;
   std::string s_output;

   launch();
   try {
      while(1) {
        coproc->receive(tmp);
        s_output.append(tmp);
        rapidjson::StringStream ss(s_output.c_str());
        output.ParseStream<0>(ss); 
        if (output.HasParseError() == false)
          return s_output.size();
      }
   } catch(AhuException &ae) {
      L<<Logger::Warning<<"[pipeconnector] "<<" unable to receive data from coprocess. "<<ae.reason<<endl;
      delete coproc;
      coproc = NULL;
      throw;
   }
}
