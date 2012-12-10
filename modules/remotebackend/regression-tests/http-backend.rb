#!/usr/bin/ruby
require "rubygems"
#require "bundler/setup"
require "webrick"
require "../modules/remotebackend/regression-tests/dnsbackend"
require "../modules/remotebackend/regression-tests/backend"

server = WEBrick::HTTPServer.new(
	:Port=>62434,
	:BindAddress=>"localhost",
#	Logger: WEBrick::Log.new("remotebackend-server.log"),
	:AccessLog=>[ [ File.open("remotebackend-access.log", "w"), WEBrick::AccessLog::COMBINED_LOG_FORMAT ] ] 
)

be = Handler.new("../modules/remotebackend/regression-tests/remote.sqlite3") 
server.mount "/dns", DNSBackendHandler, be

trap('INT') { server.stop }
trap('TERM') { server.stop }

server.start
