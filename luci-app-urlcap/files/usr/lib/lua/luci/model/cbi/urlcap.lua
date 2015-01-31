local sys = require "luci.sys"
local fs = require "nixio.fs"
local uci = require "luci.model.uci".cursor()

m = Map("urlcap", "urlcap配置",
	translate("配置抓包软件"))


if fs.access("/usr/bin/urlcap") then
	s = m:section(TypedSection, "urlcap", "urlcap配置")
	s.anonymous = true
	s.addremove = false
	ftp_host = s:option(Value,"ftp_host","FTP服务器地址","此处设置FTP服务器地址")
	ftp_pwd = s:option(Value,"ftp_pwd","FTP目录","默认地址是:/")
	ftp_user = s:option(Value,"ftp_user","FTP用户名","此处设置FTP用户名")
	ftp_password = s:option(Value,"ftp_password","FTP密码","此处设置FTP密码")
	hosts = s:option(Value,"hosts","hosts","此处设置捕捉的host,以逗号分隔")
	interface = s:option(Value,"interface","网卡","此处设置网卡名称")
	city = s:option(Value,"city","省市","此处设置省市名称")
	company = s:option(Value,"company","单位","此处设置单位名称")
	userdefine = s:option(Value,"userdefine","用户自定义","此处设置用户自定义字段")
	enable = s:option(Flag,"enable","启用抓包","重启后生效")
else
	m.pageaction = false
end


return m

