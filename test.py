from app.recon.host import Scanner

scn = Scanner("D8:BB:C1:23:9D:8F" , "192.168.100.9")

# scn = Scanner("E0:2B:E9:DD:D0:7E" , "192.168.100.4")
scn.tcp_syn_scan( "192.168.100.71" , fragmentation = True , port = 61)
