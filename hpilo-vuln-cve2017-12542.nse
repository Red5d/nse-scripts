local shortport = require "shortport"
http = require "http"
stdnse = require "stdnse"

description = [[CVE-2017-12542 HP iLO firmware vuln scanner]]

author = "Red5d"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery"}


portrule = shortport.http

action = function(host, port)


	res = http.get(host.ip, 443, "/xmldata?item=ALL")
	local version = stdnse.strsplit("<FWRI>", res.body)[2]
	local version = stdnse.strsplit("</FWRI>", version)[1]
	output = {}
	table.insert(output, "HP iLO Firmware Version: " .. version)
	if 2.3 <= tonumber(version) and tonumber(version) <= 2.5 then
		table.insert(output, "Vulnerable: yes")
	else
		table.insert(output, "Vulnerable: no")
	end
	return output

end
