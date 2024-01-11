import os

# 本脚本用于将同一文件夹中所有切分好的pcap文件，在文件名后段加入标签字段
f_path = "./data_flow/all_1/benign/udp_2/"  # 待处理的文件夹路径

file_list = os.listdir(f_path)

for filename in file_list:
    if filename.endswith(".pcap"):
        new_filename = filename.replace(".pcap", "#benign.pcap")  # “#”后为预计打的标签名
        o_f_path = os.path.join(f_path, filename)
        n_f_path = os.path.join(f_path, new_filename)

        os.rename(o_f_path, n_f_path)
print("over")
