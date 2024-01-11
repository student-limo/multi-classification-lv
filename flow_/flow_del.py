from scapy.all import *
import os

# 删除分流产生的空白错误数据包
def truncate_pcap(input_file, output_file, max_size):
    packets = rdpcap(input_file)
    # for packet in packets:
        # 截断每个数据包，只保留前max_size字节
    # filtered_packets = [packet for packet in packets if len(packet) > 0]
    filtered_packets = [packet for packet in packets if packet.haslayer("IP")]
    # for packet in packets:
    #     if len(packet) == 0:
    #         print(input_file)
    wrpcap(output_file, filtered_packets)


if __name__ == "__main__":
    data_path = "./data_flow/all_1/benign/test/"
    for filename in os.listdir(data_path):
        file = "./data_flow/all_1/benign/test/" + filename
        # input_pcap = 'your_input_file.pcap'
        # output_pcap = 'output_truncated.pcap'
        max_size = 262144
        print(file)
        truncate_pcap(file, file, max_size)
