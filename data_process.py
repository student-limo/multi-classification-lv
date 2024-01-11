from numpy.random import seed

seed(1)
import sys
import tensorflow as tf
import os
import numpy as np
import pandas as pd
import glob
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
import argparse


def combin_file(source_path, des_path):  # 输出合并后的csv文件
    csv_list = glob.glob(source_path + '*.csv')
    print(u'共发现%s个CSV文件' % len(csv_list))
    csv_files_list = []
    for file in csv_list:  # 循环读取同文件夹下的csv文件
        fd = pd.read_csv(file, index_col=None, encoding='unicode_escape')
        csv_files_list.append(fd)
    results = pd.concat(csv_files_list)
    results.to_csv(des_path, index=False)


def del_feas_flow(csv_file):  # 删除csv流中无关特征列
    fd = pd.read_csv(csv_file, index_col=None)
    fd = fd.drop(columns=['Flow ID', 'Timestamp'])  # 删除无关列
    fd = fd[~fd.isin([np.nan, np.inf, -np.inf]).any(1)].dropna()  # 删除异常记录
    print(fd.shape)
    # fd['Tot pkts']=fd['Tot Fwd Pkts']+fd['Tot Bwd Pkts']
    # incomplete_flow=fd[fd['Tot pkts']<=3]
    fd.to_csv(csv_file, index=False)


def norm_num(data_file, dataset_path):
    # 正则化处理数据
    unnorm_cols = ['Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Label']

    rawdata = pd.read_csv(data_file, index_col=None)
    print(rawdata.shape)
    rawdoh_data = pd.read_csv("./com_doh_data_1017.csv", index_col=None)
    n_doh_data = pd.get_dummies(data=rawdoh_data, columns=['Protocol'])
    data = pd.get_dummies(data=rawdata, columns=['Protocol'])
    print(data.shape)
    # 流量分类
    ben_data = data[rawdata['Label'] == 'BENIGN']

    scf_data = data[rawdata['Label'] == 'SCF']
    vps_data = data[rawdata['Label'] == 'VPS']
    dns_data = data[rawdata['Label'] == 'DNS']
    doh_data = data[rawdata['Label'] == 'DoH']
    df_data = data[rawdata['Label'] == 'DF']

    scf_cc_data = data[rawdata['Label'] == 'SCF_CC']
    vps_cc_data = data[rawdata['Label'] == 'VPS_CC']
    dns_cc_data = data[rawdata['Label'] == 'DNS_CC']
    doh_cc_data = data[rawdata['Label'] == 'DoH_CC']
    df_cc_data = data[rawdata['Label'] == 'DF_CC']

    # mal_data = data[rawdata['Label'] == 'Malware']
    ##############
    # 供未来添加新的分类
    #######

    # 流量划分 多分类
    # print(scf_data.shape[0] + vps_data.shape[0])
    # 将恶意流量按流数最少的类的流数进行划分，是恶意数据各类别数量均衡
    minNum = min(scf_data.shape[0], vps_data.shape[0], dns_data.shape[0], df_data.shape[0], dns_cc_data.shape[0]
                 , scf_cc_data.shape[0], vps_cc_data.shape[0], df_cc_data.shape[0])
    minNumDoH = min(doh_data.shape[0], doh_cc_data.shape[0])
    vps_data = vps_data.sample(minNum)
    scf_data = scf_data.sample(minNum)
    dns_data = dns_data.sample(minNum)
    df_data = df_data.sample(minNum)

    scf_cc_data = scf_cc_data.sample(minNum)
    vps_cc_data = vps_cc_data.sample(minNum)
    dns_cc_data = dns_cc_data.sample(minNum)
    df_cc_data = df_cc_data.sample(minNum)

    doh_data = doh_data.sample(minNumDoH)
    doh_cc_data = doh_cc_data.sample(minNumDoH)

    n_doh_data = n_doh_data.sample(min(2 * minNumDoH, len(n_doh_data)))

    ben_data = ben_data.sample(8 * minNum + 2 * minNumDoH - len(n_doh_data))
    ben_data = pd.concat([ben_data, n_doh_data])
    # ben_data = ben_data.sample(8 * minNum + 2 * minNumDoH)
    # # 流量划分 二分类
    # minNum = min(ben_data.shape[0], mal_data.shape[0])
    # ben_data = ben_data.sample(minNum)
    # mal_data = mal_data.sample(minNum)
    # print(ben_data.shape)

    # 训练集和测试集划分 多分类
    ben_train_data, ben_test_data = train_test_split(ben_data, test_size=0.3)
    scf_train_data, scf_test_data = train_test_split(scf_data, test_size=0.3)
    vps_train_data, vps_test_data = train_test_split(vps_data, test_size=0.3)
    dns_train_data, dns_test_data = train_test_split(dns_data, test_size=0.3)
    df_train_data, df_test_data = train_test_split(df_data, test_size=0.3)

    doh_train_data, doh_test_data = train_test_split(doh_data, test_size=0.3)
    doh_cc_train_data, doh_cc_test_data = train_test_split(doh_cc_data, test_size=0.3)
    scf_cc_train_data, scf_cc_test_data = train_test_split(scf_cc_data, test_size=0.3)
    vps_cc_train_data, vps_cc_test_data = train_test_split(vps_cc_data, test_size=0.3)
    dns_cc_train_data, dns_cc_test_data = train_test_split(dns_cc_data, test_size=0.3)
    df_cc_train_data, df_cc_test_data = train_test_split(df_cc_data, test_size=0.3)

    # # 训练集和测试集划分 二分类
    # ben_train_data, ben_test_data = train_test_split(ben_data, test_size=0.3)
    # mal_train_data, mal_test_data = train_test_split(mal_data, test_size=0.3)

    # 数据合并
    train_data = pd.concat([ben_train_data, scf_train_data, vps_train_data, dns_train_data, df_train_data, doh_train_data,
                            scf_cc_train_data, vps_cc_train_data, dns_cc_train_data, df_cc_train_data, doh_cc_train_data])
    test_data = pd.concat([ben_test_data, scf_test_data, vps_test_data, dns_test_data, df_test_data, doh_test_data,
                           scf_cc_test_data, vps_cc_test_data, dns_cc_test_data, df_cc_test_data, doh_cc_test_data])
    # 二分类的
    # train_data = pd.concat([ben_train_data, mal_train_data])
    # test_data = pd.concat([ben_test_data, mal_test_data])
    print("合并后test_data.shape is ", test_data.shape)

    # 保存原始数据方便预实验结果进行对比
    # np.save(dataset_path + 'train_data_tfc_mul_ori', train_data)

    # train_ids = pd.DataFrame(train_data, columns=['Label'])
    # test_ids = pd.DataFrame(test_data, columns=['Label'])

    # 删除五元组加标签，避免其对分类的影响
    test_data = test_data.drop(columns=unnorm_cols)
    train_data = train_data.drop(columns=unnorm_cols)
    print("删除五元组后test_data.shape is ", test_data.shape)

    # 添加标签 多分类
    # test_data = pd.concat([ben_test_data, scf_test_data, vps_test_data, dns_test_data, df_test_data, doh_test_data,
    # scf_cc_test_data, vps_cc_test_data, dns_cc_test_data, df_cc_test_data, doh_cc_test_data])
    y_train = np.array([0] * len(ben_train_data) + [1] * len(scf_train_data) + [2] * len(vps_train_data)
                       + [3] * len(dns_train_data) + [4] * len(df_train_data) + [5] * len(doh_train_data)
                       + [6] * len(scf_cc_train_data) + [7] * len(vps_cc_train_data) + [8] * len(dns_cc_train_data)
                       + [9] * len(df_cc_train_data) + [10] * len(doh_cc_train_data))
    y_test = np.array([0] * len(ben_test_data) + [1] * len(scf_test_data) + [2] * len(vps_test_data)
                      + [3] * len(dns_test_data) + [4] * len(df_test_data) + [5] * len(doh_test_data)
                      + [6] * len(scf_cc_test_data) + [7] * len(vps_cc_test_data) + [8] * len(dns_cc_test_data)
                      + [9] * len(df_cc_test_data) + [10] * len(doh_cc_test_data))

    # # 添加标签 二分类
    # y_train = np.array([0] * len(ben_train_data) + [1] * len(mal_train_data))
    # y_test = np.array([0] * len(ben_test_data) + [1] * len(mal_test_data))

    print("y_test.shape is ", y_test.shape)
    norm = MinMaxScaler()  # 归一化
    train_data = norm.fit_transform(train_data)
    test_data = norm.transform(test_data)
    print("正则化后test_data.shape is ", test_data.shape)
    # test_data = np.c_[test_data, test_ids, y_test]
    # train_data = np.c_[train_data, train_ids, y_train]
    test_data = np.c_[test_data, y_test]
    train_data = np.c_[train_data, y_train]
    print("归一化后")
    print(train_data.shape)
    print(test_data.shape)
    print("--------------------")
    # print(test_data)
    np.save(dataset_path + '1127train_data_1', train_data)
    np.save(dataset_path + '1127test_data_1', test_data)


if __name__ == '__main__':
    print("hello")
    # # 命令行模式
    # parser = argparse.ArgumentParser()
    # parser.add_argument('input_arg', help='输入文件(.csv)文件夹地址')
    # parser.add_argument('output_arg', nargs='?', default=None,
    #                     help='输出文件(.npy)文件夹地址')
    # parser.add_argument('--mode2', nargs='?', const=True, default=False,
    #                     help='将输入的文件进行训练集和测试集划分')
    # args = parser.parse_args()
    # csv_data_file = args.input_arg  # 原始特征文件路径
    # dataset_path = args.output_arg  # 预处理生成的文件路径
    # data_file = dataset_path + 'com_data1.csv'  # 原始特征文件合并的文件
    #
    # combin_file(csv_data_file, data_file)
    # print('合并完毕')
    #
    # del_feas_flow(data_file)
    # print('数据清洗完成')
    #
    # if args.mode2:
    #     print("将输入进行训练集和测试集划分后在进行归一化")
    #     norm_num(data_file, dataset_path)
    #     print("训练测试归一化完成, 生成train_data.npy和test_data.npy两个文件")
    # else:
    #     print("仅将输入作为测试集进行归一化")
    #     norm_test(data_file, dataset_path)
    #     print("测试集归一化完成, 生成test_data1.npy一个文件")
    # 测试模式

    csv_data_file = "./dataset/tls_new/"  # 待合并处理csv文件夹
    data_file = "./dataset/all_11/com_data_all_11.csv"  # 合并后输出文件路径
    dataset_path = "./"  # 输出文件处理结果路径

    # 按照需求调用以下函数即可
    combin_file(csv_data_file, data_file)
    print('合并完毕')

    del_feas_flow(data_file)
    print('数据清洗完成')

    norm_num(data_file, dataset_path)
    print('特征归一化完毕')
