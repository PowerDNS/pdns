require 'json'
require 'thread'

class DNSBackendHandler < WEBrick::HTTPServlet::AbstractServlet
   def initialize(server, dnsbackend)
     @dnsbackend = dnsbackend
     @semaphore = Mutex.new
     @f = File.open("/tmp/tmp.txt","a")
   end

   def parse_url(url)
     url = url.split('/')
     method = url.shift.downcase

     # do some determining based on method names
     args = case method
     when "lookup"
         {
          "qname" => url.shift,
          "qtype" => url.shift,
         }
     when "list"
        {
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
             "id" => url.shift,
             "name" => url.shift
        } 
     when "adddomainkey", "gettsigkey", "getdomaininfo"
        {
             "name" => url.shift
        }
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
           "content" => args.delete("content")
        }
     end

     if method == "do_setdomainmetadata"
        args["value"] = []
        args.each do |k,a|
            args["value"] << a if k[/^value/]
        end
     end

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

   def do_DELETE(req,res)
     do_GET(req,res)
   end
   
   def do_POST(req,res)
     do_GET(req,res)
   end 
end
