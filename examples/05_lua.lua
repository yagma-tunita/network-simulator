-- Script a loop: three pings on a direct link, using the bundled Lua sandbox.
exec("add-device PC1 end")
exec("add-device PC2 end")
exec("add-port PC1 aa:aa:aa:aa:aa:01 10.0.0.1/24")
exec("add-port PC2 aa:aa:aa:aa:aa:02 10.0.0.2/24")
exec("connect PC1:0 PC2:0")

for i = 1, 3 do
  exec("ping PC1 10.0.0.2")
  run()
end

log("lua example done")
