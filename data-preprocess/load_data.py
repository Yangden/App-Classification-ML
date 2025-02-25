import kagglehub
import pyshark
from collections import defaultdict
import pandas as pd 


# download data from kaggle 
def load_from_kaggle(kaggle_url):
    path = kagglehub.dataset_download(kaggle_url)
    print(path)


# group packets into flow 
def group_flows(file_path, num_packets):
    '''
    file_path: path of the pcap file
    '''
    cap = pyshark.FileCapture(file_path, display_filter = 'quic or tls', )
    flows = defaultdict(list)

    for packet in cap:
        src_ip = packet.ip.src
        dest_ip = packet.ip.dst
        src_port = packet[packet.transport_layer].srcport
        dst_port = packet[packet.transport_layer].dstport
        protocol = packet.transport_layer
        
        flow_key = (src_ip, dest_ip, src_port, dst_port, protocol)
        tcp_packet_length = packet.tcp.len
        if (flow_key not in flows or len(flows[flow_key]) < num_packets):
            flows[flow_key].append(tcp_packet_length)
        print("process one packet\n")
        
    
    print("the number of flows: ", len(flows))
    print(flows.values())
    return flows



# target: pandas dataframe including selected features + label

def transform_to_dataframe(flows, num_packets):
    '''
    extract values of the flow dictionary
    stored it in pandas dataframe
    the format of the dataframe: p-1 .. p-10
    in the future, considering add statistical information 
    '''
    features_list = []
    columns = ['pk-1', 'pk-2', 'pk-3', 'pk-4', 'pk-5', 'pk-6', 'pk-7', 'pk-8', 'pk-9', 'pk-10']

    for key in flows:
        curr_len = len(flows[key])
        for i in range(0, num_packets - curr_len): # padding zeros for flows less than 10 packets
            flows[key].append(0)
        features_list.append(flows[key])

    df = pd.DataFrame(data=features_list, columns=columns)    
    print(df.tail())

    # store df on disk
    df.to_hdf("mit-processed-data.h5", key="df", mode="w")
    
    
        
        