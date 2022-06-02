local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[Southeast LinuxFest Example]]

-- Usage: nmap --script selinuxfest southeastlinuxfest.org -p 443

author = "Red5d"

license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

categories = {"discovery", "safe"}

-- Only run when http-related ports are included
portrule = shortport.http

action = function(host, port)
  -- Perform HTTP GET request
  resp = http.get( host, port, "/")

  -- Regex on the response body to find info
  local latest_post = resp.body:match("bookmark\">([^<]+)")
  local last_updated = resp.body:match("timestamp updated\">([^<]+)")
  local author = resp.body:match('posts by ([^"]+)')

  -- Create an output table and load the info into it
  local output_tab = stdnse.output_table()
  output_tab.latest_post = latest_post
  output_tab.last_updated = last_updated
  output_tab.author = author

  -- Return the output table
  return output_tab
end