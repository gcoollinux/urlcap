module("luci.controller.urlcap", package.seeall)


function index()
	local fs = require "nixio.fs"
	if fs.access("/usr/bin/urlcap") then
		entry({"admin", "services", "urlcap"}, cbi("urlcap"), _("捕包设置"),48)
	end
	
end

