#!/usr/bin/ruby

require 'json'
require 'thread'
require "rubygems"
require "webrick"
require "./unittest"

class DNSBackendHandler < WEBrick::HTTPServlet::AbstractServlet
   def initialize(server, dnsbackend)
     @dnsbackend = dnsbackend
     @semaphore = Mutex.new
     @f = File.open("/tmp/tmp.txt","a")
   end

   def do_POST(req,res)
     req.continue

     return 400, "Bad request" unless req.path == "/dns/endpoint.json"

     tmp = JSON::parse(req.body)
     method = tmp["method"].downcase
     method = "do_#{method}"
     args = tmp["parameters"]
    
     @f.puts method
     @f.puts args

     @semaphore.synchronize do
       if @dnsbackend.respond_to?(method.to_sym)
          result, log = @dnsbackend.send(method.to_sym, args)
          body = {:result => result, :log => log}
          res.status = 200
          res["Content-Type"] = "application/javascript; charset=utf-8"
          res.body = body.to_json
        else
          res.status = 404
          res["Content-Type"] = "application/javascript; charset=utf-8"
          res.body = ({:result => false, :log => ["Method not found"]}).to_json
        end
     end
   end
end

server = WEBrick::HTTPServer.new(
	:Port=>62434,
	:BindAddress=>"localhost",
#	Logger: WEBrick::Log.new("remotebackend-server.log"),
	:AccessLog=>[ [ File.open("remotebackend-access.log", "w"), WEBrick::AccessLog::COMBINED_LOG_FORMAT ] ] 
)

be = Handler.new 
server.mount "/dns", DNSBackendHandler, be

trap('INT') { server.stop }
trap('TERM') { server.stop }

server.start
