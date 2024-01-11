import dpkt
import socket
import os

def flow_cut(pcap_path, save_path):
    """
    @ pacp_path: pcap文件的路径
    @ save_path: 流存储目录
    """
    pcap_ana(pcap_path, save_path)


def pcap_ana(pcap_path, save_path):
    """
    read pcap file and record flow
    in order to open once and write many times a flow.pcap file
    """
    with open(pcap_path, 'rb') as f:
        f.seek(0)
        # capture = dpkt.pcapng.Reader(f)
        capture = dpkt.pcap.Reader(f)
        flow_record = {}
        cnt = 0
        for ts, pkt in capture:
            # 划分五元组
            eth = dpkt.ethernet.Ethernet(pkt)

            # 符合IP规范才往下解析
            if isinstance(eth.data, dpkt.ip.IP):  # 缺少IPv6的包
                # if isinstance(eth.data, dpkt.ip6.IP6):
                ip = eth.data
                # print("cnt is " + str(cnt))
                # 只考虑TCP和UDP，否则下一个pkt
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tproto = "TCP"
                elif isinstance(ip.data, dpkt.udp.UDP):
                    tproto = "UDP"
                else:
                    continue
                trsm = ip.data
                sport = trsm.sport
                dport = trsm.dport
                flow = socket.inet_ntoa(ip.src) + '_' + str(sport) + '_' + socket.inet_ntoa(ip.dst) + '_' + str(
                    dport) + '_' + tproto
                flow_rvs = socket.inet_ntoa(ip.dst) + '_' + str(dport) + '_' + socket.inet_ntoa(ip.src) + '_' + str(
                    sport) + '_' + tproto
                # if isinstance(trsm.data, dpkt.ssl.TLS):
                #     tls1 = trsm.data
                # else:
                #     continue
                # flow_record = {flow: [[pky, ts], ...], ...}
                if flow in flow_record.keys():
                    # print("f1: " + flow)
                    flow_record[flow].append([pkt, ts])
                elif flow_rvs in flow_record.keys():
                    # print("f2: " + flow_rvs)
                    flow_record[flow_rvs].append([pkt, ts])
                else:
                    flow_record[flow] = []
                    flow_record[flow].append([pkt, ts])
            cnt += 1
        # 正常流量输出每类数量
        # print(len(flow_record))
        # fk = next(iter(flow_record))
        # print(len(flow_record[fk]))

    flow_ana(flow_record, save_path)


def pcap_ana_new(pcap_path, save_path):
    """
    read pcap file and record flow
    in order to open once and write many times a flow.pcap file
    """
    with open(pcap_path, 'rb') as f:
        f.seek(0)
        capture = dpkt.pcap.Reader(f)
        flow_record = {}
        flow_ip_rec = {}
        cnt = 0
        start_num = 0
        for ts, pkt in capture:
            # 划分五元组
            eth = dpkt.ethernet.Ethernet(pkt)
            # 符合IP规范才往下解析
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                if isinstance(ip.data, dpkt.tcp.TCP):
                    tproto = "TCP"
                elif isinstance(ip.data, dpkt.udp.UDP):
                    tproto = "UDP"
                else:
                    continue
                # print("cnt is " + str(cnt))
                trsm = ip.data
                sport = trsm.sport
                dport = trsm.dport
                ip_id = ip.id
                # print(ip_id)
                str_num = str(start_num)
                flow = socket.inet_ntoa(ip.src) + '_' + str(sport) + '_' + socket.inet_ntoa(ip.dst) + '_' + str(
                    dport) + '_' + tproto + '_'
                flow_rvs = socket.inet_ntoa(ip.dst) + '_' + str(dport) + '_' + socket.inet_ntoa(ip.src) + '_' + str(
                    sport) + '_' + tproto + '_'

                if cnt == 0:
                    # print("f0: " + str(start_num) + " : " + flow)
                    flow_ip_rec[start_num] = []
                    flow_ip_rec[start_num].append(ip_id)
                    flow_record[flow + str(start_num)] = []
                    flow_record[flow + str(start_num)].append([pkt, ts])
                    start_num += 1
                    print(flow_ip_rec)
                else:
                    is_over = False
                    for key_num in flow_ip_rec:
                        ip_rec_set = flow_ip_rec[key_num]
                        if flow + str(key_num) in flow_record.keys() and ip_id == ip_rec_set[-1] or \
                                ip_id == ip_rec_set[-1] + 1:
                            flow_record[flow + str(key_num)].append([pkt, ts])
                            flow_ip_rec[key_num].append(ip_id)
                            is_over = True
                    if not is_over:
                        flow_ip_rec[start_num] = []
                        flow_ip_rec[start_num].append(ip_id)
                        flow_record[flow + str(start_num)] = []
                        flow_record[flow + str(start_num)].append([pkt, ts])
                        start_num += 1
            cnt += 1
        # 正常流量输出每类数量
        flow_rec_new = {}
        keys = list(flow_record.keys())
        timestamp_threshhold = 5.0
        ip_rec_set_new = {}
        ip_keys = list(flow_ip_rec)
        seen = []
        for i in range(len(keys)):
            if i in seen:
                continue
            ki = keys[i]
            fri = flow_record[ki]
            fti_s = fri[0][1]
            fti_e = fri[-1][1]
            seen.append(i)
            flow_rec_new[ki] = []
            flow_rec_new[ki].append(fri)
            ip_rec_set_new[ki] = []
            ip_rec_set_new[ki].append(flow_ip_rec[ip_keys[i]])
            for j in range(i+1, len(keys)):
                if j in seen:
                    continue
                kj = keys[j]
                frj = flow_record[kj]
                ftj_s = frj[0][1]
                ftj_e = frj[-1][1]
                if abs(ftj_s - fti_s) < timestamp_threshhold:
                    flow_rec_new[ki].append(frj)
                    ip_rec_set_new[ki].append(flow_ip_rec[ip_keys[j]])
                    seen.append(j)
                elif abs(ftj_s - fti_e) < timestamp_threshhold:
                    flow_rec_new[ki].append(frj)
                    ip_rec_set_new[ki].append(flow_ip_rec[ip_keys[j]])
                    seen.append(j)

        merged_flow_rec_new = {}
        merged_ip_rec_new = {}
        for key, value in flow_rec_new.items():
            mv = [item for sublist in value for item in sublist]
            merged_flow_rec_new[key] = mv
        for key, value in ip_rec_set_new.items():
            mv = [item for sublist in value for item in sublist]
            merged_ip_rec_new[key] = mv
    flow_ana(merged_flow_rec_new, save_path)


def flow_ana(flow_record, save_path):
    """
    write pcap file according to flow_record dict
    """
    print('切分得到的五元组流数量：%d' % len(flow_record.keys()))
    for key in flow_record:
        flow_path = save_path + key + '.pcap'
        file = open(flow_path, 'ab')
        writer = dpkt.pcap.Writer(file)
        ################
        # if len(flow_record[key]) <= 1:
        #     print(len(flow_record[key]))
        #     break
        for record in flow_record[key]:
            eth = record[0]
            tist = record[1]
            writer.writepkt(eth, ts=tist)

        file.flush()
        file.close()


if __name__ == "__main__":
    print("--start--")
    # 开始切分流
    # pcapngs_dir = "../data/pcapngs/"
    pcapngs_dir = "./data_flow/all_1/vps_cc/https/"
    # test_dir = "./flow_cut_testdataset/t1/"
    test_dir = "./data_flow/all_1/vps_cc/http/need_to_be/"
    # 正常流量处理
    # for f in os.listdir(test_dir):
    for f in os.listdir(pcapngs_dir):
        # if
        folder_name = f.split('.')[0]
        # pcaps_dir = "./data_flow/all_1/dns/test" + folder_name + "/"
        # if not os.path.exists(pcaps_dir):
        #     os.makedirs(pcaps_dir)
        pcaps_dir = "./data_flow/all_1/vps_cc/https/tmp/"
        # test_dir_end = "./flow_cut_testdataset/t1/res/"
        test_dir_end = "./data_flow/all_1/vps_cc/http/res/"
        # print(f)
        # if f.endswith(".pcapng"):
        if f.endswith(".pcap"):
            print(f)
            flow_cut(pcapngs_dir + f, pcaps_dir)
            # flow_cut(test_dir + f, test_dir_end)
            # pcap_ana_new(test_dir + f, test_dir_end)

