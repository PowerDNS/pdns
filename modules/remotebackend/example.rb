#!/usr/bin/ruby

require 'rubygems'
require 'bundler/setup'
require 'json'

## this is an example stub for remote backend
## to add more methods, just write
## def do_<methodname>(args)
## end
## look at the existing methods to find out 
## how to customize this. 

## WARNING: this contains some code that 
## should never be used in production, but 
## is provided to give a more comprehensive
## example code. 

## Code provided only as example, not suitable
## for production. 

## Usage: 
##  launch=remote
##  remote-dnssec=yes
##  remote-connection-string=pipe:command=/path/to/example.rb,timeout=2000

class RequestHandler

public
  def initialize
    @_log = []
    @initialized = false
    @default_ttl = 3600
  end

protected

  ## YOUR METHODS GO AFTER THIS LINE

  def do_initialize(args)
     if @initialized
       raise "Cannot reinitialize"
     end 
     log "Example backend v1.0 starting"
     @initialized = true
     true
  end

  ## used to tell that we do NSEC3 NARROW
  def do_getdomainmetadata(args)
     if args["name"] == "example.com"
       if args["kind"] == "NSEC3NARROW"
           return "1"
       elsif args["kind"] == "NSEC3PARAM"
           return "1 1 1 fe"
       end
     end
     false
  end

  ## returns keys, do not use in production
  def do_getdomainkeys(args)
     if args["name"] == "example.com"
        return [ 
          {
             "id" => 1,
             "flags" => 257,
             "active" => true,
             "content" => "Private-key-format: v1.2
Algorithm: 8 (RSASHA256)
Modulus: ovvzf1fHdptdXsBrBLSqmGqdEKwR2B9st/KBgh8xQKoQzTGUG00CsPjF/J59IBU+EU/IIInMn0MxLLTyUKa2DJUkR6i7UKif5jKX1c7yvWzrFKLGOHjugUX2++r+o789biUte1qpWp3Kc2RYL18oPco4zpo6JcsPmhOK3aUCDJXmuWgHl1KudCQIiPkISArXVn4oOp+skQq+mUBl1Pysc4D+6sl77ERR2fW6xJ4ZRPOIKr445RJJmKgoMG8yRrR3it1RmV49hZlvMosQjBUoNcqhqOI0n4l8HOLyna7KIzoNKG62GtUCZh8uy8IjdUiWPYGEtkZ9zE0bnnF+R7HGvQ==
PublicExponent: AQAB
PrivateExponent: Lp/c3IUD7o4re7uX4dS9KLT3EZnn0OfMdiLNoafCszjzbX/NWrIBHxdLrCS6rr7k7pbgLU6+VqEmJB/vYdsPITJZGpbOXxieBYBbpzJ4hm/uIA0gn28Y66pUKWTkS3ud2zCPfkZFREL3c2M1Rvf1zxdWgOPl1oHsiKsmgpl9qJOSKHMWFC+m/pUMJ7iOMgyDRV+PNeb/8P1jVOAYyQMEnu+enw2ro2NiWXNikbnaWrIv3IxVZAyZG4/H8+1vfQFPDWztosOy7OhV3WyMJkfwcXrlGoyLlxyAgkh/jeCnmPllxlJZGTgCtoVYd/n8osMXCDKxpAhsfdfCPeNOcjocgQ==
Prime1: +T+s7wv+zVqONJqkAKw4OCVzxBc5FWrmDPcjPCUeKIK/K/3+XjmIqTlbvBKf+7rm+AGVnXAbqk90+jzE3mKI8HMG/rM2cx01986xNQsIqwi2VAt25huPhEyrtNzos6lmrCYaioaQnNpMvMLun3DvcaygkDUXxH7Dg+6BTHeUfnk=
Prime2: p2YbBveBK3XyGMuVrDH9CvvpgKEoko+mPwLoKNpBoHrGxeOdCQmlPbnr0GrtZpy4sBNc5+shz2c6c1J3GlgPndT7zi2+MFGfWIGV48SAknVLfOU4iUpaGllnxcbjZeytG6WHdy2RaR3ReeGvdWxmxeuv084c2zC/7/vkcmgOqWU=
Exponent1: EdVFeUEBdQ3imM7rpwSrbRD47HHA6tBgL1NLWRVKyBk6tloQ5gr1xS3Oa3FlsuwXdG0gmEgaIqBWvUS1zTd9lr6UJIsL/UZ8wwMt2J62ew4/hVngouwb45pcuq8HkzsulmiPg5PHKwHPdb34tr2s1BRG1KqHzc5IDNt2stLnc/k=
Exponent2: oT+Iv1BAu7WUa/AHj+RjJGZ+iaozo+H9uOq66Uc8OjKqMErNpLwG0Qu7rHqjjdlfSjSMpNXpLpj4Q8fm9JhpCpbzq6qCbpbhUGcbFFjfpLSZ74f5yr21R3ZhsLChsTenlF8Bu3pIfKH9e1M7KXgvE22xY+xB/Z3a9XeFmfLEVMU=
Coefficient: vG8tLZBE4s3bftN5INv2/o3knEcaoUAPfakSsjM2uLwQCGiUbBOOlp3QSdTU4MiLjDsza3fKIptdwYP9PvSkhGhtLPjBpKjRk1J1+sct3dfT66JPClJc1A8bLQPj4ZpO/BkJe6ji4HYfOp7Rjn9z8rTqwEfbP64CZV3/frUzIkQ="
          },
          {
             "id" => 2,
             "flags" => 256,
             "active" => true,
             "content" => "Private-key-format: v1.2
Algorithm: 8 (RSASHA256)
Modulus: wKPNcDwkCd2DKxfdkMqTFOV2ITdgxIDaOd4vQ2QtphMBY9yYwmEkNsVdVFz7VVuQHdls20JUe+brFUhs1zEMMbokulFP/qVAItAeEWcqtkPULT+mmX5HsexpFVAZ5+UXuerObk/HMiIMt1CvkIWhmjSIkAI6dFRlf/93zTjy0+vwrNWZPXSzLccK5TfJmxdYdGPcsHkg6UmqEFPQuyZpmlmpg3IwjL5YddTDobAoABz/BrH7WsW0q/PyVubITo8JuFiBI5Fmw+3ef3PVUt1jtUCGASvtqNXW4wtWrgqvQKg/odthpceQ4QagV9XSlOdml527thnf9cMpm0Gh4Ox5HQ==
PublicExponent: AQAB
PrivateExponent: f+M+26fRdQstrUomuZ0Cj/jVt69/+nRga9JpJiA3fe1YGue0MjczR3k3QG6KHFyxDF/vuJAMbkUbBAIU37ecFNcy0s5wgOlL7tCjZYJMBLx6+58qBvSivCfqi0+mIyEf4zlS2kD0SP/52SkjpJpScoE1uAUCsX/l8lezPPb1nmH3RDwJwX1NVhsErHCAmxGDoj4nPCEhKgHkdbR0i8geXGdWR4slyq1EhuGJal4p5sNvzDQTYRy6r49rpbNHw9F7ojomIhTUCUjOXAX0X1HB5UTXRMpgpCNEjRG1a+aqxp/ZSMHSEGCv67fua5Qrd/qX1Ppns/oqZfCfTpTD3v/sMQ==
Prime1: +0zQuFi7rZDTMGMIKiF6UOG5+pKwGxHmgKPOGF6fk3tIuSomgiVD3DLz5Y6kYk0kKls6IiA6X2esYwNXAaLe0dyMzpAnU4URXhFW7fUnHP0zA7NmaFRYPHstPeU59/JS+zmVlj4Ok1oeGocSGAFYGxXa+Sot0fyCXpAjZboDWg8=
Prime2: xD4hprQmcn5gmLqYO9+nEEJTNyNccbAciiKjRJxIE7w6muuKESx0uUn5XdnzSxhbVkK16kkEqW3s+Y+VoLxwRj2fuvoPfx8nTQXY1esgcIZCG8ubvHW5T0bzee5gyX3cMvaxkoeM7euYgvh0UwR/FG910SwAlmMZjSwXay2YlhM=
Exponent1: 6vcWzNcCnDWmkT53WtU0hb2Y4+YVzSm+iRcf039d20rRY3g6y0NGoPPvQftOTi9smkH0KAZULfJEp8tupbQAfN6ntVfpvVjVNUwnKJUo/hzsfxBVt0Ttv5c4ZQAYZHHqDsX3zKO3gyUmso0KaPGQzLpxpLlAYG+mAf7paeszyRc=
Exponent2: ouvWMjk0Bi/ncETRqDuYzkXSIl+oGvaT6xawp4B70m6d1QohWPqoeT/x2Dne44R4J9hAgR5X0XXinJnZJlXrfFUi7C84eFhb33UwPQD0sJa2Aa97Pu4Zh7im4J7IGd/01Ra7+6Ovm8LRnkI5CMcd3dBfZuX6IuBpUSu+0YtMN6M=
Coefficient: 5lP9IFknvFgaXKCs8MproehHSFhFTWac4557HIn03KrnlGOKDcY6DC/vgu1e42bEZ4J0RU0EELp5u4tAEYcumIaIVhfzRsajYRGln2mHe6o6nTO+FbANKuhyVmBEvTVczPOcYLrFXKVTglKAs+8W96dYIMDhiAwxi9zijLKKQ1k="
          }
        ]
     end
     false
  end

  ## Example lookup
  ## Returns SOA, MX, NS and A records for example.com
  ## also static A record for test.example.com
  ## and dynamic A record for anything else in example.com domain 
  def do_lookup(args)
     if args["qname"] == "example.com" and args["qtype"].downcase == "soa"
       return [
          record("SOA","example.com", "sns.dns.icann.org noc.dns.icann.org 2013012485 7200 3600 1209600 3600"),
              ]
     elsif args["qname"] == "example.com" and args["qtype"].downcase == "any"
       return [ 
          record("SOA","example.com", "sns.dns.icann.org noc.dns.icann.org 2013012485 7200 3600 1209600 3600"),
          record("NS","example.com","sns.dns.icann.org"),
          record("MX","example.com","10 test.example.com")
              ]
     elsif args["qname"] == "test.example.com" and args["qtype"].downcase == "any"
       return [
          record("A","test.example.com","127.0.0.1")
       ]
     elsif args["qname"] =~ /(.*)\.example\.com$/ and args["qtype"].downcase == "any"
       ip = 0
       $1.downcase.each_byte do |b| ip = ip + b end
       ip_2 = ip/256
       ip = ip%256
       return [
          record("A",args["qname"], "127.0.#{ip_2}.#{ip}")
       ]
     end
     false
  end

  ## AXFR support
  ## Do note that having AXFR here is somewhat stupid since
  ## we generate records above. But it is still included
  ## for sake of having an example. Do not do this in production.
  def do_list(args)
     if args["zonename"] == "example.com"
       return [
          record("SOA","example.com", "sns.dns.icann.org noc.dns.icann.org 2013012485 7200 3600 1209600 3600"),
          record("NS","example.com","sns.dns.icann.org"),
          record("MX","example.com","10 test.example.com"),
          record("A","test.example.com","127.0.0.1")
       ]
     end
     false          
  end

  ## Please see https://doc.powerdns.com/authoritative/backends/remote.html for methods to add here
  ## Just remember to prefix them with do_

  ## Some helpers after this 

  def record_ttl(qtype,qname,content,ttl)
    {:qtype => qtype, :qname => qname, :content => content, :ttl => ttl, :auth => 1}
  end

  def record(qtype,qname,content)
    record_ttl(qtype,qname,content,@default_ttl,)
  end

  def log(message)
    @_log << message
  end

  ## Flushes log array and returns it.
  def consume_log
    ret = @_log
    @_log = []
    ret
  end

public
  def run
     STDOUT.sync=true
     STDIN.each_line do |line|
        # So far rapidjson has managed to follow RFC4627
        # and hasn't done formatted json so there should be
        # no newlines. 
        msg = JSON.parse(line)
       
        # it's a good idea to prefix methods with do_ to prevent
        # clashes with initialize et al, and downcase it for simplicity
        method = "do_#{msg["method"].downcase}".to_sym
        if self.respond_to? method
          result = self.send method, msg["parameters"]
        else
          log "Method #{msg["method"]} not implemented"
          result = false
        end
        # build and emit result
        reply = { :result => result, :log => consume_log }
        puts reply.to_json
     end
  end
end

begin 
  RequestHandler.new.run
rescue Interrupt
  # ignore this exception, caused by ctrl+c in foreground mode
end
