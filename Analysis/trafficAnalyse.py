from scapy.all import *
import pyshark
import pickle
import matplotlib.pyplot as plt
import json

# pcaps = rdpcap('./TrafficData/Shadowsocks2.pcapng')
# <pre name="code" class="python">packet=pcaps[0]
# a = packet[Raw].loa
with open('./protocolDic.pkl', 'rb+') as f:
    protocol_dic = pickle.load(f)
with open('./timeStamps.pkl', 'rb+') as f:
    time_stamps = pickle.load(f)


def protocol(pac):
    dic = {}
    for pkt in pac:
        layer = pkt.highest_layer
        if layer in dic.keys():
            dic[layer] += 1
        else:
            dic[layer] = 1
    with open('./protocolDic.pkl', 'wb+') as f:
        pickle.dump(dic, f)
    return dic


def draw(dic_pro):
    keys = dic_pro.keys()
    values = dic_pro.values()
    plt.figure(figsize=(15, 20), dpi=100)
    plt.bar(keys, values)
    plt.xticks(rotation=45, fontsize=10)
    plt.yticks(fontsize=12)
    plt.xlabel('protocol', fontsize=14)
    plt.ylabel('amount', fontsize=14)
    plt.title('Protocol Number of Statistical', fontsize=16)
    plt.show()
    # plt.savefig('../Picture/protocolPlot.png')


def graph_size():
    # time_stamps = []
    # for packet in packets:
    #     # print(int(float(packet.sniff_timestamp)))
    #     time_stamps.append(int(float(packet.sniff_timestamp)))
    # with open('./timeStamps.pkl', 'wb+') as f:
    #     pickle.dump(time_stamps, f)
    d = int(float(2) * 60)
    num_bins = (max(time_stamps) - min(time_stamps)) // d
    step = len(time_stamps) // num_bins
    time_labels = [time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(i)) for i in time_stamps[::step]]
    plt.figure(figsize=(20, 8), dpi=100)
    plt.hist(time_stamps, num_bins, histtype='bar', rwidth=0.8)
    plt.xticks(range(min(time_stamps), max(time_stamps) + d, d), time_labels, rotation=30, fontsize=14)
    plt.yticks(fontsize=14)
    plt.xlabel("timestamp", fontsize=20)
    plt.ylabel("amount", fontsize=20)
    plt.title("amount of per " + str(d) + " s", fontsize=20)
    plt.show()
    # plt.savefig('../Picture/timeStamp.png')


if __name__ == '__main__':
    packets = pyshark.FileCapture('../TrafficData/Shadowsocks2.pcapng', display_filter='tcp')
    amount = 0
    # with open('./packet.pkl', 'wb+') as f:
    #     json.dump(packets, f)
    for pac in packets:
        for layer in pac.layers:
            if 'tcp' in layer._layer_name:
                print(pac.highest_layer)
                amount += 1

    print(amount)

    # protocol_dic = protocol(packets)
    # draw(protocol_dic)
    # graph_size()
