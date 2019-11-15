"""
If Protocol, src ip, dst ip, src port, dst port -> Same Flow

Features: tcp.time_delta, tcp.time_relative

pk_feature_dic:
length: packet length
time_delta: time delta with last packet for the same flow
time_relative: time used with the first packet
forward: True if forward, False if backward
mark: Five value to mark if the same flow

flow_info_dic:
keys: The mark value including five value
{key:[[forward traffic],[backward traffic]]...}
forward(backward) traffic:[length],[time_delta],[time_relative]
"""

import pyshark
import pickle

flow_info_dic = {}
pk_feature = ['length', 'time_delta', 'time_relative', 'forward', 'mark']
pk_feature_dic = {key: [] for key in pk_feature}
send_ip = ''


def load_traffic(path_, filter_='tls'):
    packets_ = pyshark.FileCapture(path, display_filter=filter_)
    return packets_


def get_send_ip(pks):
    ip_dic = {}
    for i in range(100):
        pk = pks.next()
        addr = pk.ip.addr
        if addr in ip_dic.keys():
            ip_dic[addr] += 1
        else:
            ip_dic[addr] = 1
    return sorted(ip_dic.items(), key=lambda x: x[1], reverse=True)[0][0]


def get_five_element(packet):
    flag = False
    layer_name = str(packet.highest_layer)
    src_ip = str(packet.ip.addr)
    dst_ip = str(packet.ip.dst)
    if src_ip == send_ip:
        flag = True
    src_port = str(packet.tcp.srcport)
    dst_port = str(packet.tcp.dstport)
    ip = src_ip + dst_ip if src_ip > dst_ip else dst_ip + src_ip
    port = src_port + dst_port if src_port > dst_port else dst_port + src_port
    return layer_name + ip + port, flag


def update_feature_dic(pk_, mark_, flag_):
    pk_feature_dic['length'].append(pk_.length)
    pk_feature_dic['time_delta'].append(pk_.tcp.time_delta)
    pk_feature_dic['time_relative'].append(pk_.tcp.time_relative)
    pk_feature_dic['forward'].append(flag_)
    pk_feature_dic['mark'].append(mark_)


def get_flow_info(packets_):
    for pk in packets_:
        n = 1
        mark_info, flag = get_five_element(pk)  # Mark for different flow
        update_feature_dic(pk, mark_info, flag)
        if mark_info in flow_info_dic.keys():
            if flag:
                n = 0
            flow_info_dic[mark_info][n][0] += [pk.tcp.time_delta]
            flow_info_dic[mark_info][n][1] += [pk.length]
            flow_info_dic[mark_info][n][2] += [pk.tcp.time_relative]
        else:
            flow_info_dic[mark_info] = [[[], [], []], [[], [], []]]
            if flag:
                flow_info_dic[mark_info][0] = [[pk.tcp.time_delta], [pk.length], [pk.tcp.time_relative]]
            else:
                flow_info_dic[mark_info][1] = [[pk.tcp.time_delta], [pk.length], [pk.tcp.time_relative]]


def save_packet_feature_dic(path_):
    with open(path_, 'wb+') as f:
        pickle.dump(pk_feature_dic, f)


def save_flow_info_dic(path_):
    with open(path_, 'wb+') as f:
        pickle.dump(flow_info_dic, f)


if __name__ == '__main__':
    path = '../TrafficData/Shadowsocks2.pcapng'
    packets = load_traffic(path, 'tls')  # Packet data using filter tls
    send_ip = get_send_ip(packets)  # Our ip addr, which help us to recognize forward or backward traffic
    get_flow_info(packets)
    save_packet_feature_dic('./packet.pkl')
    save_flow_info_dic('./flow.pkl')
    debug = 1
