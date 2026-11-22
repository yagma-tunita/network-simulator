local os_ok = pcall(function() return os.execute("echo hacked") end)
local req_ok = pcall(function() return require("x") end)
if os_ok or req_ok then
  log("UNSAFE: sandbox escape")
else
  log("sandbox ok")
end
