"""
If Protocol, src ip, dst ip, src port, dst port same flow

tcp.time_delta, tcp.time_relative
"""
import pyshark

info_dic = {}


def load_traffic(path_):
    packets_ = pyshark.FileCapture(path, display_filter='tls')
    return packets_


def get_five_element(packet):
    flag = 0
    layer_name = str(packet.highest_layer)
    src_ip = str(packet.ip.addr)
    dst_ip = str(packet.ip.dst)
    src_port = str(packet.tcp.srcport)
    dst_port = str(packet.tcp.dstport)
    ip = src_ip + dst_ip if src_ip > dst_ip else dst_ip + src_ip
    port = src_port + dst_port if src_port > dst_port else dst_port + src_port
    return layer_name + ip + port


if __name__ == '__main__':
    path = '../TrafficData/Shadowsocks2.pcapng'
    packets = load_traffic(path)
    packets_sum = pyshark.FileCapture(path, display_filter='tls', only_summaries=True)
    while True:
        pkg = packets.next()
        pkg_sum = packets_sum.next()
        check_info = get_five_element(pkg)
        if check_info in info_dic.keys():
            info_dic[check_info][0] += [pkg.tcp.time_delta]
            info_dic[check_info][1] += [pkg.length]
            info_dic[check_info][2] += [pkg.tcp.time_relative]
        else:
            info_dic[check_info] = [[pkg.tcp.time_delta], [pkg.length], [pkg.tcp.time_relative]]
    debug = 1
