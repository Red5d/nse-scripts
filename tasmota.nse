local shortport = require "shortport"
local http = require("http")
local stringaux = require("stringaux")

description = [[Tasmota device name and version scanner]]

author = "Red5d"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery"}

portrule = shortport.http

action = function(host, port)


	res = http.get(host.ip, 80, "/")
    if http.response_contains(res, "Tasmota") then
	  local title = stringaux.strsplit("<title>", res.body)[2]
	  local name = stringaux.strsplit(" - ", title)[1]

	  local versionline = stringaux.strsplit(">Tasmota ", res.body)[2]
	  local version = stringaux.strsplit(" by ", versionline)[1]

	  output = {}
	  table.insert(output, "Name: " .. name)
      table.insert(output, "Version: " .. version)
	  return output
    end

end
