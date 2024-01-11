import os

from scapy.all import rdpcap, wrpcap

# 本脚本适用于将pcap文件中的数据包按照时间戳重新排列
# 输出文件将带有“sorted_前缀”
def sorted_pcap_by_feature(file_name):
    '''
    按照时间戳顺序，从新将pcap文件中的数据包进行排序
    '''
    for file in os.listdir(file_name):
        print(file)
        pcap = rdpcap(file_name + file)
        sorted_pcap = sorted(pcap, key=lambda x: x.time)
        wrpcap(file_name + "sorted_" + file, sorted_pcap)
        print("--end--")


if __name__ == "__main__":
    print("start")
    sorted_pcap_by_feature("./data_flow/all_1/benign/tcp_2/")  # 待处理文件夹路径
    print("over")
