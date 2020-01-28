#!/usr/bin/env ruby

require 'rubygems'
require 'bundler/setup'
require 'json'
require 'thread'
require 'webrick'
require './unittest'

class DNSBackendHandler < WEBrick::HTTPServlet::AbstractServlet
   def initialize(server, dnsbackend)
     @dnsbackend = dnsbackend
     @semaphore = Mutex.new
     @f = File.open("/tmp/remotebackend.txt.#{$$}","ab")
     @f.set_encoding 'UTF-8'
   end

   def parse_arrays(params)
     newparams = {}
     params.each do |key,val|
         if key=~/^(.*)\[(.*)\]\[(.*)\]/
             newparams[$1] = {} unless newparams.has_key? $1
             newparams[$1][$2] = {} unless newparams[$1].has_key? $2
             newparams[$1][$2][$3] = val
             params.delete key
         elsif key=~/^(.*)\[(.*)\]/ 
           if $2 == "" 
             newparams[$1] = [] unless newparams.has_key? $1
             newparams[$1] << val
           else 
             newparams[$1] = {} unless newparams.has_key? $1
             newparams[$1][$2] = val
           end
           params.delete key
         end
     end
     params.merge newparams
   end

   def parse_url(url)
     url = url.split('/')
     method = url.shift.downcase

     # do some determining based on method names
     args = case method
     when "lookup"
         {
          "qname" => url.shift,
          "qtype" => url.shift
         }
     when "list"
        {
	  "id" => url.shift,
          "zonename" => url.shift
        }
     when "getbeforeandafternamesabsolute", "getbeforeandafternames"
        {
           "id" => url.shift.to_i,
           "qname" => url.shift 
        }
     when "getdomainmetadata", "setdomainmetadata", "getdomainkeys"
        {
            "name" => url.shift,
            "kind" => url.shift
        }
     when "removedomainkey", "activatedomainkey", "deactivatedomainkey"
        {
             "id" => url.shift.to_i,
             "name" => url.shift
        } 
     when "adddomainkey", "gettsigkey", "getdomaininfo", "settsigkey", "deletetsigkey", "getalldomainmetadata"
        {
             "name" => url.shift
        }
     when "setnotified", "feedents"
        {
             "id" => url.shift.to_i
        }
     when "ismaster"
        {
             "name" => url.shift,
             "ip" => url.shift
        }
     when "supermasterbackend", "createslavedomain"
        {
             "ip" => url.shift,
             "domain" => url.shift
        }
     when "feedents3"
        {
             "id" => url.shift.to_i,
             "domain" => url.shift
        }
     when "starttransaction"
        {
             "id" => url.shift.to_i,
             "domain" => url.shift,
	     "trxid" => url.shift.to_i
	}
     when "committransaction", "aborttransaction"
        {
             "trxid" => url.shift.to_i
        }
     when "replacerrset"
        {
          "id" => url.shift.to_i,
          "qname" => url.shift,
          "qtype" => url.shift
        }
     else
        {}
     end

     [method, args]
   end

   def do_GET(req,res)
     req.continue

     tmp = req.path[/dns\/(.*)/,1]
     return 400, "Bad request" if (tmp.nil?)

     method, args = parse_url(tmp)

     method = "do_#{method}"
    
     # get more arguments
     req.each do |k,v|
        attr = k[/X-RemoteBackend-(.*)/,1]
        if attr 
          args[attr] = v
        end
     end

     args = args.merge req.query

     if method == "do_adddomainkey"
        args["key"] = {
           "flags" => args.delete("flags").to_i,
           "active" => args.delete("active").to_i,
           "published" => args.delete("published").to_i,
           "content" => args.delete("content")
        }
     end

     args = parse_arrays args
     begin
        @f.puts "#{Time.now.to_f} [http]: #{({:method=>method,:parameters=>args}).to_json}"
     rescue Encoding::UndefinedConversionError
        # this fails with encoding error for feedEnts3
     end

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

        @f.puts "#{Time.now.to_f} [http]: #{res.body}"
     end
   end

   def do_DELETE(req,res)
     do_GET(req,res)
   end
   
   def do_POST(req,res)
     do_GET(req,res)
   end 

   def do_PATCH(req,res)
     do_GET(req,res)
   end
  
   def do_PUT(req,res)
     do_GET(req,res)
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
server.mount_proc("/ping"){ |req,resp| resp.body = "pong" }

trap('INT') { server.stop }
trap('TERM') { server.stop }

server.start
