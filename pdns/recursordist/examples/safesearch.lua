--[[
    Both Google and Bing offer ways to enforce the use of their 'safesearch' or 'strict' functionality
    for some or all of your users. This script provides a 'handleSafeSearch' function that
    implements enforced safe search for Google and Bing.

    First, get the google supported domain lists, and format it for Lua:
    
    $ (echo 'return{' ; for a in $(curl https://www.google.com/supported_domains) ; do echo \"$a\",; done ; echo '}') > googledomains.lua

    and then load this script with 'pdns-lua-script=safesearch.lua' in recursor.conf

    For Bing, only 'www.bing.com' is relevant.

    There is a comment below in preresolve where you could insert code to determine if a particular user should be filtered or not
]]--

googledomains={}
for k,v in pairs(dofile("googledomains.lua"))
do
    googledomains["www"..v]=1
    googledomains["encrypted"..v]=1  -- plug a loophole
    googledomains["ipv6"..v]=2       -- this too - change to 1 to get v4 instead of NXDOMAIN
end

    
function handleSafeSearch(dq)
         local name = dq.qname:toStringNoDot():lower();
         local status = googledomains[name]
         if( status == 1) then
                 dq:addAnswer(pdns.CNAME, "forcesafesearch.google.com")
                 dq.rcode=0
                 dq.followupFunction="followCNAMERecords"
                 return true
         elseif( status == 2) then
                 dq.rcode=pdns.NXDOMAIN 
                 -- inserting actual SOA record is a nice touch but requires figuring out country code
                 return true
         elseif(name=="www.bing.com") then
                 dq:addAnswer(pdns.CNAME, "strict.bing.com")
                 dq.rcode=0
                 dq.followupFunction="followCNAMERecords"
                 return true
         end

         return false
end

function preresolve(dq) 
        -- this is where you would test if the requesting IP address should be filtered or not
        -- if you do that, add: dq.variable=true to prevent packetcaching
        if(handleSafeSearch(dq)) then
            return true;
        end 
        return false;
end
