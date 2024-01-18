import os
import numpy as np
import pandas as pd

# 本脚本用于将生成的npy格式数据转换为csv数据，并在最后一列添加数据标签
file_path = "./1222test_data_2.npy"  # 待处理npy文件路径
data = np.load(file_path, allow_pickle=True)
feature_names = ['pack_num', 'time_all', 'pkt_len_all', 'dport', 'sport', 'max_time', 'min_time', 'mean_time',
                 'std_time', 'max_time_src', 'min_time_src', 'mean_time_src', 'std_time_src', 'tot_time_src',
                 'max_time_dst', 'min_time_dst', 'mean_time_dst', 'std_time_dst', 'tot_time_dst', 'max_pktsz_pkt',
                 'mean_pktsz_pkt', 'std_pktsz_pkt', 'min_pktsz_pkt', 'max_pktsz_src', 'mean_pktsz_src', 'std_pktsz_src',
                 'min_pktsz_src', 'max_pktsz_dst', 'mean_pktsz_dst', 'std_pktsz_dst', 'min_pktsz_dst', 'tp_hdr_max',
                 'tp_hdr_min', 'tp_hdr_avg', 'tp_hdr_std', 'src_tp_hdr_max', 'src_tp_hdr_min', 'src_tp_hdr_avg',
                 'src_tp_hdr_std', 'dst_tp_hdr_max', 'dst_tp_hdr_min', 'dst_tp_hdr_avg', 'dst_tp_hdr_std',
                 'src_tcp_win_sz', 'dst_tcp_win_sz', 'protocol', 'fin', 'syn', 'rst', 'ack', 'urg', 'psh', 'ece', 'cwe',
                 'num_src', 'num_dst', 'num_ratio', 'size_src', 'size_dst', 'size_ratio', 'by_s',
                 'pk_s', 'Label']
print("start")
feature_stats = []
for item in data:
    feature_data = item['feature']  # 所需添加的类别
    feature_data.append('benign')  # 所需添加的标签名
    feature_stats.append(feature_data)
df = pd.DataFrame(feature_stats)
df.columns = feature_names
df.to_csv('./data/all/benign_flow_feature_new_udp_1222_udp_new.csv', index=False)  # 输出文件路径
# 不执行任何增删改查任务，仅执行格式转换使用下两行代码即可
# df = pd.DataFrame(data)
# df.to_csv('./1222test_data_2_ori.csv', index=False)
print("over")

