import pyshark
import pickle

SEPERATOR = "+"


class flow():
    def __init__(self,packet):
        self.packets = []
        self.packets.append(packet)
        self.forward_ip_addr = packet.src_ip

        self.features = {}
        self.timeout = -1
    def flow_split_feature_extract(self,timeout):
        self.timeout = timeout
        pass

    def feature_extract(self):
        pass

class flow_packet():
    def __init__(self,src_ip,src_port,dest_ip,dest_port,protocol_name,timestamp_delta, timestamp_relative, original_pkt):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.protocl_name = protocol_name
        self.timestamp_delta = timestamp_delta
        self.timestamp_relative = timestamp_relative
        self.original_pkt = original_pkt

    def sort_ip(self):
        # need to be tested
        # sort the src ip and dest ip as the ascending order
        return sorted([self.src_ip,self.dest_ip])
    def sort_port(self):
        return sorted([self.src_port,self.dest_port])
    def sort_quintuple(self):
        ret = ""
        for i in self.sort_ip():
            ret += i + SEPERATOR
        for i in self.sort_port():
            ret += i + SEPERATOR
        ret += self.protocl_name
        return ret

def store_obj2pickle(data,path):
    with open(path,'bw') as f:
        pickle.dump(data,f)
    print("Store data into "+path)

def load_pickle2obj(path):
    with open(path,'br') as f:
        data = pickle.load(f)
    print("Load data from "+path)
    return data

def loadpcap_from_file(file_path,filter):
    return pyshark.FileCapture(file_path,display_filter=filter)

def get_five_element(packet):
    return str(packet.ip.src),str(packet.tcp.srcport),str(packet.ip.dst),str(packet.tcp.dstport),str(packet.ip.proto)
def get_time_element(packet):
    return str(packet.tcp.time_delta),str(packet.tcp.time_relative)

if __name__ == '__main__':
    file_path = 'C:\\Users\\\haoruikwok\\\Desktop\\result_google\\psiphon_11times.pcap'
    pcap_data = loadpcap_from_file(file_path,'tcp')

    multiple_flows = {}
    pkt_counter = 1
    for packet in pcap_data:
        src_ip,src_port,dst_ip,dst_port,protocol_name = get_five_element(packet)

        if src_port == '3389' or dst_port == '3389':
            pkt_counter += 1
            continue
        else:
            timestamp_delta, timestamp_relative = get_time_element(packet)
            pkt = flow_packet(src_ip,src_port,dst_ip,dst_port,protocol_name,timestamp_delta,timestamp_relative,packet)
            pkt_quintuple = pkt.sort_quintuple()
            if pkt_quintuple in multiple_flows.keys():
                multiple_flows[pkt_quintuple].packets.append(pkt)
            else:
                multiple_flows[pkt_quintuple] = flow(pkt)
        pkt_counter += 1
        if pkt_counter % 1000 == 0:
            print("Processing pkt count: ",pkt_counter)
    debug = 1
    store_obj2pickle(multiple_flows,'./flows.pickle')
