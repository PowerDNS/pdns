require 'json'

class DNSBackendHandler < WEBrick::HTTPServlet::AbstractServlet
   def initialize(server, dnsbackend)
     @dnsbackend = dnsbackend
   end

   def do_GET(req,res)
     tmp = req.path[/dns\/(.*)/,1]
     return 400, "Bad request" if (tmp.nil?)
     tmp = tmp.split("/")
     method = "do_#{tmp.shift}".downcase
     args = {}

     if tmp.size > 0 
       args["qname"] = tmp[0]
       args["name"] = tmp[0]
       args["target"] = tmp.shift
     end
     if tmp.size > 0
       args["kind"] = tmp[0]
       args["qtype"] = tmp[0]
       args["id"] = tmp.shift
     end

     # get more arguments
     req.each do |k,v|
        attr = k[/X-RemoteBackend-(.*)/,1]
        if attr 
          args[attr] = v
        end
     end

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

   def do_DELETE(req,res)
   end
   
   def do_POST(req,res)
     req.continue

     # get method name and args
   end 
end
