import os
import tqdm
from feature_extract.flow import Flow
import dpkt
import numpy as np
from tqdm import tqdm
import sys
import argparse


def pre_flow(args):
    dataset_name = args.d
    feature_type = args.f
    print("dataset:{} feature_type:{}".format(dataset_name, feature_type))
    # data_path = "./data_flow/all_1/{}/http/test/".format(dataset_name)
    data_path = "./data_flow/all_1/{}/udp_new/".format(dataset_name)
    ip_flag = "" if args.ip else "no"
    print(ip_flag, args.ip, args.s, args.app)
    if args.ip:
        # save_path = "data/all/{}_{}.npy".format(dataset_name, feature_type)
        save_path = "data/all/{}_{}_1222_udp_new.npy".format(dataset_name, feature_type)
    else:
        save_path = "data/all/{}_{}_noip.npy".format(dataset_name, feature_type)

    ip_flag = "" if args.ip else "no"
    print(ip_flag, args.ip, args.s, args.app)
    # data_path = "../../data_flow/{}/tls/".format("datacon/train_white")
    # save_path = "../../data/{}_{}.npy".format("datacon_white", feature_type)

    dataset = []
    for filename in tqdm(os.listdir(data_path)):
        if ".pcap" in filename:
            try:
                with open(data_path + filename, 'rb') as f:
                    capture = dpkt.pcap.Reader(f)
                    print(filename)
                    type = filename.replace('.pcap', '').split("#")[1]
                    flow_sample = Flow(capture, type, args)
                    flow_sample.name = filename.replace('.pcap', '')
                    # flow_sample.analyse()
                    flow_sample.analyse_udp()
                    if feature_type == "flow_feature_new":
                        feature = flow_sample.tolist_new()
                    elif feature_type == "flow_feature_new_udp":
                        feature = flow_sample.tolist_new_udp()
                    dataset.append(feature)
                f.close()
            except IOError:
                print('could not parse {0}'.format(filename))

    dataset_np = np.array(dataset)
    if args.s:
        np.save(save_path, dataset_np)


if __name__ == "__main__":
    print("begin")
    parse = argparse.ArgumentParser()
    parse.add_argument("--d", type=str, default="normal", help="dataset")
    parse.add_argument("--f", type=str, default="flow_feature_new_udp", help="feature_type")
    parse.add_argument("--s", type=bool, default=True, help="save or not")
    parse.add_argument("--m", type=str, default="datacon", help="dataset model")
    parse.add_argument("--l", type=int, default=95, help="word_num")
    parse.add_argument("--ip", type=bool, default=True)
    parse.add_argument("--tcp", type=bool, default=True)
    parse.add_argument("--app", type=bool, default=False)

    args = parse.parse_args()

    pre_flow(args)

    print("end")
