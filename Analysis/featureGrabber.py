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
import copy

import pyshark
import pickle
import pandas as pd
import numpy as np
import datetime

pk_feature = ['length', 'time_delta', 'time_relative', 'forward', 'mark', 'timestamp']
pk_feature_dic = {key: [] for key in pk_feature}
send_ip = ''


def load_traffic(path_, filter_='tls'):
    packets_ = pyshark.FileCapture(path_, display_filter=filter_, keep_packets=False)
    return packets_


def get_send_ip(pks):
    ip_dic = {}
    end = 0
    for pk in pks:
        try:
            addr = pk.ip.addr
            if addr in ip_dic.keys():
                ip_dic[addr] += 1
            else:
                ip_dic[addr] = 1

            dst_addr = pk.ip.dst
            if dst_addr in ip_dic.keys():
                ip_dic[dst_addr] += 1
            else:
                ip_dic[dst_addr] = 1
        except Exception as e:
            pass
        end += 1
        if end >= 10000:
            break
    ip = sorted(ip_dic.items(), key=lambda x: x[1], reverse=True)[0][0]
    print('Send ip:', ip)
    return ip


def get_five_tuple(packet):
    """
    Get layer+ip+port
    :param packet:
    :return:
    """
    flag = False
    proto_name = str(packet.ip.proto)
    src_ip = str(packet.ip.addr)
    dst_ip = str(packet.ip.dst)
    if src_ip == send_ip:
        flag = True
    src_port = str(packet.tcp.srcport)
    dst_port = str(packet.tcp.dstport)
    #
    ip = src_ip + dst_ip if src_ip > dst_ip else dst_ip + src_ip
    port = src_port + dst_port if src_port > dst_port else dst_port + src_port
    return proto_name + ip + port, flag


def update_feature_dic(pk_, mark_, flag_):
    pk_feature_dic['length'].append(pk_.length)
    pk_feature_dic['time_delta'].append(pk_.tcp.time_delta)
    pk_feature_dic['time_relative'].append(pk_.tcp.time_relative)
    pk_feature_dic['forward'].append(flag_)
    pk_feature_dic['mark'].append(mark_)
    pk_feature_dic['timestamp'].append(pk_.sniff_timestamp)


def get_flow_info(packets_, name):
    flow_info_dic = {}
    print('Updating dictionary...\nIt need some time...')
    count = 0
    for pk in packets_:
        try:
            n = 1
            count += 1
            if count % 1000 == 0:
                print(name, count)
            mark_info, flag = get_five_tuple(pk)  # Mark for different flow
            update_feature_dic(pk, mark_info, flag)
            if mark_info in flow_info_dic.keys():
                if flag:
                    n = 0
                #
                flow_info_dic[mark_info][n][0] += [pk.length]
                flow_info_dic[mark_info][n][1] += [pk.tcp.time_delta]
                flow_info_dic[mark_info][n][2] += [pk.tcp.time_relative]
                flow_info_dic[mark_info][n][3] += [pk.sniff_timestamp]
            else:
                # dict{forward_list[length,time_delta,time_relative,sniff_timestamp],backward_list}
                flow_info_dic[mark_info] = [[[], [], [], []], [[], [], [], []]]
                if flag:
                    flow_info_dic[mark_info][0] = [[pk.length], [pk.tcp.time_delta], [pk.tcp.time_relative],
                                                   [pk.sniff_timestamp]]
                else:
                    flow_info_dic[mark_info][1] = [[pk.length], [pk.tcp.time_delta], [pk.tcp.time_relative],
                                                   [pk.sniff_timestamp]]
        except Exception as e:
            print('Exception:{}, Count number:{}, Caused by ipv6'.format(e, count))
    return flow_info_dic
    print('Finish update')


def save_packet_feature_dic(path_):
    with open(path_, 'wb+') as f:
        pickle.dump(pk_feature_dic, f)
    print('Finish write', path_)


def save_flow_info_dic(path_, flow_dic):
    with open(path_, 'wb+') as f:
        pickle.dump(flow_dic, f)
    print('Finish write', path_)


def write_csv(store_data_, path_, vpn_name):
    print('Writing csv')
    column = []
    for feature in ['ForwardLength', 'ForwardTime', 'BackwardLength', 'BackwardTime']:
        for sig in ['max', 'min', 'sd', 'avg']:
            column.append(feature + '_' + sig)
    column.append('VPN')
    fd = pd.DataFrame(store_data_, columns=column)
    fd.to_csv(path_, index=False)
    print('Finish write')


def write_csv_helper(flow_dic, vpn_name):
    w_data = []
    for mark in flow_dic.keys():
        # The data of one flow
        time_stamp = list(map(float, flow_info_dic[mark][0][3]))
        time_stamp1 = list(map(float, flow_info_dic[mark][1][3]))
        break_points = get_interval_index(time_stamp, time_stamp1, interval=0.01)

        res = []
        for i in range(2):
            break_len = len(break_points[i]) if len(break_points[i]) > 0 else 1
            for k in range(break_len):
                begin = break_points[i][k][0] if break_points[i] else 0
                end = break_points[i][k][1] if break_points[i] else -1
                for j in range(2):
                    if end == -1:
                        data_list = list(map(float, flow_info_dic[mark][i][j]))
                    else:
                        if k == break_len - 1:
                            end += 1
                        data_list = list(map(float, flow_info_dic[mark][i][j][begin:end]))
                    if not data_list:
                        data_list = [0]
                    max_ = max(data_list)
                    min_ = min(data_list)
                    sd_ = np.std(data_list)
                    avg_ = np.average(data_list)
                    res += [max_, min_, sd_, avg_]
        res.append(vpn_symbol[vpn_name])
        w_data.append(res)
    return w_data


def get_from_pkl(path1, path2):
    # global flow_info_dic, pk_feature_dic
    with open(path2, 'rb+') as f:
        flow_dic = pickle.load(f)
    return flow_dic


def get_interval_index(time_stamp1, time_stamp2, interval=15):
    """
    Get the index of the split point with given interval and timestamp
    :param time_stamp1:
    :param time_stamp2:
    :param interval
    :return:
    """
    res1 = list()
    res2 = list()
    begin_index1 = 0
    current_index1 = 0
    begin_index2 = 0
    current_index2 = 0
    while current_index1 < len(time_stamp1):
        while current_index1 < len(time_stamp1) and time_stamp1[current_index1] - time_stamp1[begin_index1] < interval:
            current_index1 += 1

        while current_index2 < len(time_stamp2) and current_index1 < len(time_stamp1) and time_stamp2[current_index2] < \
                time_stamp1[current_index1]:
            current_index2 += 1
        if current_index2 >= len(time_stamp2):
            break
        if current_index1 >= len(time_stamp1):
            break
        res2.append((begin_index2, current_index2))
        res1.append((begin_index1, current_index1))
        begin_index1 = current_index1
        begin_index2 = current_index2
    return res1, res2


if __name__ == '__main__':
    vpn_names = ['white', 'lantern', 'psiphon', 'wujie']
    vpn_symbol = {key: i for i, key in enumerate(vpn_names)}
    data_dir = '../TrafficData/'
    data_path = ['WhiteTraffic.pcapng', 'LanternTraffic.pcapng', 'psiphon_11times.pcap', 'wujie_27times.pcap']
    store_data = []
    for i in range(0, 1):
        # load_flag = input('{}: Load data from pickle directly?(y or n)\n'.format(vpn_names[i]))
        load_flag = 'y'
        if 'y' in load_flag:
            flow_info_dic = get_from_pkl('packet_{}.pkl'.format(vpn_names[i]),
                                         'flow_{}.pkl'.format(vpn_names[i]))  # Load pickle directly
            sum_ = 0
            for key in flow_info_dic.keys():
                flow = flow_info_dic[key]
                for i in range(2):
                    sum_ += len(flow[i][0])
            print(sum_)
            debug = 1
        else:
            packets = load_traffic(data_dir + data_path[i], 'tls')  # Packet data using filter tls
            send_ip = get_send_ip(packets)  # Our ip addr, which help us to recognize forward or backward traffic
            flow_info_dic = get_flow_info(packets, vpn_names[i])
            save_packet_feature_dic('packet_{}.pkl'.format(vpn_names[i]))
            save_flow_info_dic('flow_{}.pkl'.format(vpn_names[i]), flow_info_dic)
        write_data = write_csv_helper(flow_info_dic, vpn_names[i])
        store_data += write_data
    write_csv(store_data, '../Result/Feature.csv', 'white')  # Write csv file
    debug = 1