require 'json'
require 'thread'

class DNSBackendHandler < WEBrick::HTTPServlet::AbstractServlet
   def initialize(server, dnsbackend)
     @dnsbackend = dnsbackend
     @semaphore = Mutex.new
     unless defined? @@f
       @@f = File.open("/tmp/remotebackend.txt.#{$$}","a")
       @@f.sync
     end
     @dnsbackend.do_initialize({})
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
          "qtype" => url.shift,
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
             "id" => url.shift,
             "name" => url.shift
        } 
     when "adddomainkey", "gettsigkey", "getdomaininfo"
        {
             "name" => url.shift
        }
     else 
        {
        }
     end

     [method, args]
   end

   def do_GET(req,res)
     req.continue

     tmp = req.path[/dns\/(.*)/,1]
     return 400, "Bad request" if (tmp.nil?)

     method, args = parse_url(tmp.force_encoding("UTF-8"))

     method = "do_#{method}"
    
     # get more arguments
     req.each do |k,v|
        attr = k[/x-remotebackend-(.*)/i,1]
        if attr 
          args[attr.downcase] = v.force_encoding("UTF-8")
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
 
     @@f.puts "#{Time.now.to_f} [http]: #{({:method=>method,:parameters=>args}).to_json}"

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
       @@f.puts "#{Time.now.to_f} [http]: #{res.body}" 
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
