local shortport = require "shortport"
local http = require("http")
local string = require("string")

description = [[ifconfig.me External IP Lookup]]

author = "Red5d"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"external"}

-- No host/port/etc requirements for running this script
prerule = function()
  return true
end

action = function(host, port)
  -- HTTP GET request to https://ifconfig.me/
	res = http.get("ifconfig.me", 443, "/")

  -- Regex to find the IP address
  local ipaddr = res.body:match("ip_address\">([^<]+)")

  -- Return a string with the IP address
  return "External IP Address: " .. ipaddr
end
