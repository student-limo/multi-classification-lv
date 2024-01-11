import os
import numpy as np
import pandas as pd

# 本脚本用于将生成的npy格式数据转换为csv数据，并在最后一列添加数据标签
file_path = "./1222test_data_2.npy"  # 待处理npy文件路径
data = np.load(file_path, allow_pickle=True)
print("start")
feature_stats = []
for item in data:
    feature_data = item['feature']  # 所需添加的类别
    feature_data.append('benign')  # 所需添加的标签名
    feature_stats.append(feature_data)
df = pd.DataFrame(feature_stats)
df.to_csv('./data/all/benign_flow_feature_new_udp_1222_udp_new.csv', index=False)  # 输出文件路径
# 不执行任何增删改查任务，仅执行格式转换使用下两行代码即可
# df = pd.DataFrame(data)
# df.to_csv('./1222test_data_2_ori.csv', index=False)
print("over")

