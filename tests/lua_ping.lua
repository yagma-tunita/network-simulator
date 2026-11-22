exec("add-device PC1 end")
exec("add-device PC2 end")
exec("add-port PC1 aa:aa:aa:aa:aa:01 192.168.1.1/24")
exec("add-port PC2 aa:aa:aa:aa:aa:02 192.168.1.2/24")
exec("connect PC1:0 PC2:0")

for i = 1, 2 do
    exec("ping PC1 192.168.1.2")
    run()
end

log("lua scenario done")
