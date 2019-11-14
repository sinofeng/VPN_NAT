from scapy.all import *
import pyshark

# pcaps = rdpcap('./Traffic/Shadowsocks2.pcapng')
# <pre name="code" class="python">packet=pcaps[0]
# a = packet[Raw].load

cap = pyshark.FileCapture('./Traffic/Shadowsocks2.pcapng')
dic = {}
for pkt in cap:
    layer = pkt.highest_layer
    if layer in dic.keys():
        dic[layer] += 1
    else:
        dic[layer] = 0
debug = 1