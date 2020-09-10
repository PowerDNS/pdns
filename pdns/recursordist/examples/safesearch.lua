--[[
    Google, Youtube, Bing and DuckDuckGo offer ways to enforce the use of their 'safesearch' or 'strict' functionality
    for some or all of your users. This script provides a 'handleSafeSearch' function that
    implements enforced safe search for Google and Bing.

    First, get the google supported domain lists, and format it for Lua:
    
    $ (echo 'return{' ; for a in $(curl https://www.google.com/supported_domains) ; do echo \"$a\",; done ; echo '}') > googledomains.lua

    and then load this script with 'pdns-lua-script=safesearch.lua' in recursor.conf

    For Bing, only 'www.bing.com' is relevant.

    For Youtube: https://support.google.com/a/answer/6214622?hl=en - option 1. Note that they offer both a very strict search, and a moderate. Usually, moderate is a good balance. If you want really strict, change the youtubedomains values to 11 instead of 1.

    For DuckDuckGo: https://help.duckduckgo.com/duckduckgo-help-pages/features/safe-search/ (bottom)

    There is a comment below in preresolve where you could insert code to determine if a particular user should be filtered or not
]]--

googledomains={}
for k,v in pairs(dofile("googledomains.lua"))
do
    googledomains["www"..v]=1
    googledomains["encrypted"..v]=1  -- plug a loophole
    googledomains["ipv6"..v]=2       -- this too - change to 1 to get v4 instead of NXDOMAIN
end

youtubedomains={}
youtubedomains['www.youtube.com'] = 1
youtubedomains['m.youtube.com'] = 1
youtubedomains['youtubei.googleapis.com'] = 1
youtubedomains['youtube.googleapis.com'] = 1
youtubedomains['www.youtube-nocookie.com'] = 1
    
function handleSafeSearch(dq)
         local name = dq.qname:toStringNoDot():lower();
         local statusg = googledomains[name]
         local statusyt = youtubedomains[name]

         if( statusg == 1) then
                 dq:addAnswer(pdns.CNAME, "forcesafesearch.google.com")
                 dq.rcode=0
                 dq.followupFunction="followCNAMERecords"
                 return true

         elseif( statusyt == 1) then
                 dq:addAnswer(pdns.CNAME, "restrictmoderate.youtube.com")
                 dq.rcode=0
                 dq.followupFunction="followCNAMERecords"
                 return true

         elseif( statusyt == 11) then
                 dq:addAnswer(pdns.CNAME, "restrict.youtube.com")
                 dq.rcode=0
                 dq.followupFunction="followCNAMERecords"
                 return true

         elseif( statusg == 2) then
                 dq.rcode=pdns.NXDOMAIN 
                 -- inserting actual SOA record is a nice touch but requires figuring out country code
                 return true

         elseif(name=="www.bing.com") then
                 dq:addAnswer(pdns.CNAME, "strict.bing.com")
                 dq.rcode=0
                 dq.followupFunction="followCNAMERecords"
                 return true

         elseif(name=="duckduckgo.com" or name=="www.duckduckgo.com") then
                 dq:addAnswer(pdns.CNAME, "safe.duckduckgo.com")
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
