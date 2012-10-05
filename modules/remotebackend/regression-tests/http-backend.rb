#!/usr/bin/ruby1.9.1
require "rubygems"
#require "bundler/setup"
require "webrick"
require "../modules/remotebackend/regression-tests/dnsbackend"
require "../modules/remotebackend/regression-tests/backend"

server = WEBrick::HTTPServer.new :Port => 62434

be = Handler.new("../modules/remotebackend/regression-tests/remote.sqlite3") 

server.mount "/dns", DNSBackendHandler, be
trap('INT') { server.stop }
server.start
