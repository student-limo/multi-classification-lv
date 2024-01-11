from distutils import extension
from functools import singledispatch
from pydoc import tempfilepager
from OpenSSL.crypto import sign
import numpy as np
import math
from cal import *
import dpkt
import OpenSSL
import sys
import socket
import time
from datetime import datetime
from .constants import PRETTY_NAMES
# from .feature_cipher import cipher_to_feature


class Flow(object):
    def __init__(self, capture, label, args):

        self.capture = capture  # 待处理数据
        self.flow = {}

        self.ip_src = ''  # 目的ip地址
        self.ip_dst = ''  # 源ip地址
        self.ip_list = []  # ip地址
        self.dport = 0  # 源端口号
        self.sport = 0  # 目的端口号
        self.port_list = []  # 端口列表

        self.tran_protocol = None  # 传输层协议

        self.pack_num = 0  # 包数量

        self.num_src = 0  # 源包数目
        self.num_dst = 0  # 目的包数目
        self.num_ratio = 0  # 上下行流量比
        self.size_src = 0  # 源总包大小
        self.size_dst = 0  # 目的总包大小
        self.size_ratio = 0  # 上下行包大小比
        self.by_s = 0  # 每秒字节传输速度
        self.pk_s = 0  # 每秒包传输速度

        self.time = 0  # 整体持续时间
        self.time_seq = []  # 时间序列
        self.max_time = 0  # 最大间隔时间
        self.min_time = 0  # 最小间隔时间
        self.mean_time = 0  # 平均间隔时间
        self.std_time = 0  # 均差间隔时间
        self.time_last = 0

        self.time_src_seq = []  # 源时间间隔序列
        self.max_time_src = 0  # 最大源时间间隔
        self.min_time_src = 0  # 最小源时间间隔
        self.mean_time_src = 0  # 平均源时间间隔
        self.std_time_src = 0  # 均差源时间间隔
        self.tot_time_src = 0  # 正向流总时间

        self.time_dst_seq = []  # 目的时间间隔序列
        self.max_time_dst = 0  # 最大目的时间间隔
        self.min_time_dst = 0  # 最小目的时间间隔
        self.mean_time_dst = 0  # 平均目的时间间隔
        self.std_time_dst = 0  # 均差目的时间间隔
        self.tot_time_dst = 0  # 反向流总时间

        self.packetsize_src_seq = []  # 源包大小序列
        self.max_packetsize_src = 0  # 最大源包大小
        self.min_packetsize_src = 0  # 最小源包大小
        self.mean_packetsize_src = 0  # 平均源包大小
        self.std_packetsize_src = 0  # 均差源包大小

        self.packetsize_dst_seq = []  # 目的包大小序列
        self.max_packetsize_dst = 0  # 最大目的包大小
        self.min_packetsize_dst = 0  # 最小目的包大小
        self.mean_packetsize_dst = 0  # 均值目的包大小
        self.std_packetsize_dst = 0  # 均差目的包大小

        self.packetsize_all = 0  # # #--平均包大小--# 总大小,指的是数据帧的有效长度，包括以太层的头长度
        self.packet_len_all = 0  # 数据包总长度，即ip数据包的total length，以太网层的载荷长度
        self.packetsize_avg = 0  # 平均包大小
        self.packetsize_packet_seq = []  # 包大小序列
        self.max_packetsize_packet = 0  # 最大包大小
        self.min_packetsize_packet = 0  # 最小包大小
        self.mean_packetsize_packet = 0  # 平均包大小
        self.std_packetsize_packet = 0  # 均差包大小

        self.tp_hdr_seq = []  # 包传输层头长度序列
        self.tp_hdr_sum = 0  # 包传输层头长度总长度
        self.tp_hdr_avg = 0  # 包传输层头长度平均值
        self.tp_hdr_min = 0  # 包传输层头长度最小值
        self.tp_hdr_max = 0  # 包传输层头长度最大值
        self.tp_hdr_std = 0  # 包传输层头长度标准差

        self.src_tp_hdr_seq = []  # 正向流包传输层头长度序列
        self.src_tp_hdr_sum = 0  # 正向流包传输层头长度总长度
        self.src_tp_hdr_avg = 0  # 正向流包传输层头长度平均值
        self.src_tp_hdr_min = 0  # 正向流包传输层头长度最小值
        self.src_tp_hdr_max = 0  # 正向流包传输层头长度最大值
        self.src_tp_hdr_std = 0  # 正向流包传输层头长度标准差

        self.dst_tp_hdr_seq = []  # 反向流包传输层头长度序列
        self.dst_tp_hdr_sum = 0  # 反向流包传输层头长度总长度
        self.dst_tp_hdr_avg = 0  # 反向流包传输层头长度平均值
        self.dst_tp_hdr_min = 0  # 反向流包传输层头长度最小值
        self.dst_tp_hdr_max = 0  # 反向流包传输层头长度最大值
        self.dst_tp_hdr_std = 0  # 反向流包传输层头长度标准差

        self.src_tcp_win_seq = []  # 正向TCP窗口大小序列
        self.dst_tcp_win_seq = []  # 反向TCP窗口大小序列
        self.src_tcp_win_sz = -1  # 正向TCP窗口大小初始值
        self.dst_tcp_win_sz = -1  # 反向TCP窗口大小初始值

        self.num = 0  # 数据流数量

        self.flag = False  # 只取第一个certificate

        self.fin = 0  # 标志位Fin的数量
        self.syn = 0  # 标志位Syn的数量
        self.rst = 0  # 标志位RST的数量
        self.ack = 0  # 标志位ACK的数量
        self.urg = 0  # 标志位URG的数量
        self.psh = 0  # 标志位PSH的数量
        self.ece = 0  # 标志位ECE的数量
        self.cwe = 0  # 标志位CWE的数量

        self.need_ip = args.ip
        self.need_tcp = args.tcp
        self.need_app = args.app

        self.transition_matrix = np.zeros((15, 15), dtype=int)  # 马尔可夫转移矩阵
        self.label = label  # 若有，则为具体攻击类型
        self.name = ''  # pcap包名称

        self.content = bytes(0)  # 包负载内容
        self.content_seq = []  # 包负载内容序列（前三个）
        self.content_payload = []  # 包负载大小序列（前三个）
        self.content_seq_2 = []  # 包负载内容序列（前两个）
        self.nth_seq = []

        self.need_flow_all = True
        self.flow_num = 0  # 流数目
        self.needbitFre = False

        self.need_experiment_1 = True
        if self.need_experiment_1:
            self.packet_seq_experiment_1 = []
        self.need_experiment_2 = True
        if self.need_experiment_2:
            self.packet_seq_experiment_2 = []

        self.packet_content_seq = []

        self.need_experiment_3 = True
        if self.need_experiment_3:
            self.mix_1 = bytes(0)  # 前784字节
            self.mix_2 = []  # 前32个包的大小、时间、tcp窗口大小
            self.mix_3 = []  # 前32个包的时间和空间按照方向，是否是握手划分的最小、最大、平均值、标准偏差、偏斜度，字节的总数目，包的总数目，bytes/s，paket/s
            self.is_hand = []  # 是否是加密握手包

        self.need_experiment_4 = True
        if self.need_experiment_4:
            self.tlsWord = []
            self.tlsWord_2 = []
            self.capp = ""
            self.sapp = ""

    def tolist_new(self):
        """change to list that is the model input"""
        # print(self.cipher_application_data)
        # 存在application data

        time_all = round(self.time)
        ip_src = int(self.ip_src.replace('.', ''))
        self.packetsize_avg = round(self.packetsize_all / self.pack_num)
        self.time_seq = self.time_seq
        self.max_time, self.min_time, self.mean_time, self.std_time = cal(self.time_seq)
        self.tp_hdr_max, self.tp_hdr_min, self.tp_hdr_avg, self.tp_hdr_std = cal(self.tp_hdr_seq)
        self.src_tp_hdr_max, self.src_tp_hdr_min, self.src_tp_hdr_avg, self.src_tp_hdr_std = cal(self.src_tp_hdr_seq)
        self.dst_tp_hdr_max, self.dst_tp_hdr_min, self.dst_tp_hdr_avg, self.dst_tp_hdr_std = cal(self.dst_tp_hdr_seq)

        self.max_time_src, self.min_time_src, self.mean_time_src, self.std_time_src = cal(self.time_src_seq)
        self.max_time_dst, self.min_time_dst, self.mean_time_dst, self.std_time_dst = cal(self.time_dst_seq)

        self.max_packetsize_src, self.min_packetsize_src, self.mean_packetsize_src, self.std_packetsize_src = cal(
            self.packetsize_src_seq)
        self.max_packetsize_dst, self.min_packetsize_dst, self.mean_packetsize_dst, self.std_packetsize_dst = cal(
            self.packetsize_dst_seq)
        self.max_packetsize_packet, self.min_packetsize_packet, self.mean_packetsize_packet, self.std_packetsize_packet = cal(
            self.packetsize_packet_seq)

        self.transition_matrix = cal_matrix(self.packetsize_packet_seq)

        self.num_ratio = cal_div(self.num_src, self.num_dst)
        self.size_ratio = cal_div(self.size_src, self.size_dst)
        self.by_s = cal_div(self.packetsize_all, self.time)
        self.pk_s = cal_div(self.pack_num, self.time)

        data = {}

        data["feature"] = [self.pack_num, self.time, self.packet_len_all/self.pack_num, self.dport, self.sport,
                           # 5
                           self.max_time, self.min_time, self.mean_time, self.std_time,
                           self.max_time_src, self.min_time_src, self.mean_time_src, self.std_time_src,
                           self.tot_time_src,
                           self.max_time_dst, self.min_time_dst, self.mean_time_dst, self.std_time_dst,
                           self.tot_time_dst,
                           # 23
                           self.max_packetsize_packet, self.mean_packetsize_packet, self.std_packetsize_packet,
                           self.min_packetsize_packet,
                           self.max_packetsize_src, self.mean_packetsize_src, self.std_packetsize_src,
                           self.min_packetsize_src,
                           self.max_packetsize_dst, self.mean_packetsize_dst, self.std_packetsize_dst,
                           self.min_packetsize_dst,
                           self.tp_hdr_max, self.tp_hdr_min, self.tp_hdr_avg, self.tp_hdr_std,
                           self.src_tp_hdr_max, self.src_tp_hdr_min, self.src_tp_hdr_avg, self.src_tp_hdr_std,
                           self.dst_tp_hdr_max, self.dst_tp_hdr_min, self.dst_tp_hdr_avg, self.dst_tp_hdr_std,
                           # 47
                           self.src_tcp_win_sz, self.dst_tcp_win_sz,
                           self.tran_protocol,
                           self.fin, self.syn, self.rst, self.ack, self.urg, self.psh, self.ece, self.cwe,

                           self.num_src, self.num_dst, self.num_ratio,
                           self.size_src, self.size_dst, self.size_ratio,
                           self.by_s, self.pk_s,
                           ]
        data["ip_src"] = self.ip_src
        data["ip_dst"] = self.ip_dst
        data["label"] = self.label
        data["name"] = self.name
        return data


    def tolist_new_udp(self):
        """change to list that is the model input"""

        time_all = round(self.time)
        ip_src = int(self.ip_src.replace('.', ''))
        self.packetsize_avg = round(self.packetsize_all / self.pack_num)
        self.time_seq = self.time_seq
        self.max_time, self.min_time, self.mean_time, self.std_time = cal(self.time_seq)
        self.tp_hdr_max, self.tp_hdr_min, self.tp_hdr_avg, self.tp_hdr_std = cal(self.tp_hdr_seq)
        self.src_tp_hdr_max, self.src_tp_hdr_min, self.src_tp_hdr_avg, self.src_tp_hdr_std = cal(self.src_tp_hdr_seq)
        self.dst_tp_hdr_max, self.dst_tp_hdr_min, self.dst_tp_hdr_avg, self.dst_tp_hdr_std = cal(self.dst_tp_hdr_seq)

        self.max_time_src, self.min_time_src, self.mean_time_src, self.std_time_src = cal(self.time_src_seq)
        self.max_time_dst, self.min_time_dst, self.mean_time_dst, self.std_time_dst = cal(self.time_dst_seq)

        self.max_packetsize_src, self.min_packetsize_src, self.mean_packetsize_src, self.std_packetsize_src = cal(
            self.packetsize_src_seq)
        self.max_packetsize_dst, self.min_packetsize_dst, self.mean_packetsize_dst, self.std_packetsize_dst = cal(
            self.packetsize_dst_seq)
        self.max_packetsize_packet, self.min_packetsize_packet, self.mean_packetsize_packet, self.std_packetsize_packet = cal(
            self.packetsize_packet_seq)

        self.transition_matrix = cal_matrix(self.packetsize_packet_seq)

        self.num_ratio = cal_div(self.num_src, self.num_dst)
        self.size_ratio = cal_div(self.size_src, self.size_dst)
        self.by_s = cal_div(self.packetsize_all, self.time)
        self.pk_s = cal_div(self.pack_num, self.time)

        self.fin = -1
        self.syn = -1
        self.rst = -1
        self.ack = -1
        self.urg = -1
        self.psh = -1
        self.ece = -1
        self.cwe = -1
        data = {}

        data["feature"] = [self.pack_num, self.time, self.packet_len_all/self.pack_num, self.dport, self.sport,
                           # 5
                           self.max_time, self.min_time, self.mean_time, self.std_time,
                           self.max_time_src, self.min_time_src, self.mean_time_src, self.std_time_src,
                           self.tot_time_src,
                           self.max_time_dst, self.min_time_dst, self.mean_time_dst, self.std_time_dst,
                           self.tot_time_dst,
                           # 23
                           self.max_packetsize_packet, self.mean_packetsize_packet, self.std_packetsize_packet,
                           self.min_packetsize_packet,
                           self.max_packetsize_src, self.mean_packetsize_src, self.std_packetsize_src,
                           self.min_packetsize_src,
                           self.max_packetsize_dst, self.mean_packetsize_dst, self.std_packetsize_dst,
                           self.min_packetsize_dst,
                           self.tp_hdr_max, self.tp_hdr_min, self.tp_hdr_avg, self.tp_hdr_std,
                           self.src_tp_hdr_max, self.src_tp_hdr_min, self.src_tp_hdr_avg, self.src_tp_hdr_std,
                           self.dst_tp_hdr_max, self.dst_tp_hdr_min, self.dst_tp_hdr_avg, self.dst_tp_hdr_std,
                           # 47
                           self.src_tcp_win_sz, self.dst_tcp_win_sz,
                           self.tran_protocol,
                           self.fin, self.syn, self.rst, self.ack, self.urg, self.psh, self.ece, self.cwe,

                           self.num_src, self.num_dst, self.num_ratio,
                           self.size_src, self.size_dst, self.size_ratio,
                           self.by_s, self.pk_s,
                           ]
        data["ip_src"] = self.ip_src
        data["ip_dst"] = self.ip_dst
        data["label"] = self.label
        data["name"] = self.name
        return data


    def cal_max_min_mean_div(self, seq):
        if not seq:
            return 0, 0, 0, 0, 0, 0
        seq_np = np.array(seq)
        max = np.max(seq_np)
        min = np.min(seq_np)
        mean = np.mean(seq_np)
        std = np.std(seq_np)
        sc = np.mean((seq_np - mean) ** 3)
        tot = np.sum(seq_np)
        return max, min, mean, std, sc, tot

    def cal_entropy(self, content):
        result = 0
        for key in content:
            if key != 0:
                result += (-key) * math.log(key, 2)
        return result


    def analyse(self):
        nth = 1
        flows = {}
        ip_src = None
        src_tp = []
        dst_tp = []

        for timestamp, packet in self.capture:

            if nth == 1:
                time_last = timestamp
                ip_src = dpkt.utils.inet_to_str(dpkt.ethernet.Ethernet(packet).data.src)
                self.tran_protocol = dpkt.ethernet.Ethernet(packet).data.p

            time = timestamp - time_last
            time_last = timestamp
            eth = dpkt.ethernet.Ethernet(packet)
            ip = eth.data
            self.tp_hdr_seq.append(len(ip.data) - len(ip.data.data))  # 计算传输层头长度序列
            if isinstance(ip, dpkt.ip.IP):
                src_ip = dpkt.utils.inet_to_str(ip.src)
                dst_ip = dpkt.utils.inet_to_str(ip.dst)
                src_port = ip.data.sport
                dst_port = ip.data.dport
                flow_key = (src_ip, src_port, dst_ip, dst_port)

                # 正反向tcp窗口大小序列
                if isinstance(ip.data, dpkt.tcp.TCP):
                    if src_ip == ip_src:
                        self.src_tcp_win_seq.append(ip.data.win)
                    else:
                        self.dst_tcp_win_seq.append(ip.data.win)
                # 计算正反向时间序列和传输层头大小
                if src_ip == ip_src:
                    src_tp.append(timestamp)
                    self.src_tp_hdr_seq.append(len(ip.data) - len(ip.data.data))
                else:
                    dst_tp.append(timestamp)
                    self.dst_tp_hdr_seq.append(len(ip.data) - len(ip.data.data))
                if flow_key not in flows:
                    flows[flow_key] = {'start_time': timestamp, 'end_time': timestamp}
                else:
                    flows[flow_key]['end_time'] = timestamp

            self.parse_packet(packet, time, nth)
            self.time_seq.append(time)
            nth += 1

        # 计算正反向间隔时间序列
        for i in range(len(src_tp)-1):
            self.time_src_seq.append(src_tp[i+1]-src_tp[i])
        for i in range(len(dst_tp)-1):
            self.time_dst_seq.append(dst_tp[i+1] - dst_tp[i])

        # TCP窗口大小
        if len(self.src_tcp_win_seq) != 0:
            self.src_tcp_win_sz = self.src_tcp_win_seq[0]
        if len(self.dst_tcp_win_seq) != 0:
            self.dst_tcp_win_sz = self.dst_tcp_win_seq[0]

        # 计算正反向总时间
        min_start_time = datetime.max
        max_end_time = datetime.min
        for flow_key, flow_info in flows.items():
            # print(flow_key[0], ip_src)
            if flow_key[0] == ip_src:
                start_time = datetime.utcfromtimestamp(flow_info['start_time'])
                end_time = datetime.utcfromtimestamp(flow_info['end_time'])
                # self.tot_time_src = end_time - start_time
                min_start_time = min(min_start_time, start_time)
                max_end_time = max(max_end_time, end_time)
            else:
                start_time = datetime.utcfromtimestamp(flow_info['start_time'])
                end_time = datetime.utcfromtimestamp(flow_info['end_time'])
                # self.tot_time_dst = end_time - start_time
                min_start_time = min(min_start_time, start_time)
                max_end_time = max(max_end_time, end_time)
        # 重新计算流持续总时间
        time_total = max_end_time - min_start_time

        for key in self.flow:
            if len(self.flow[key].data) != 0:

                tem = self.flow[key].data
                nth_flag = self.flow[key].nth_seq
                ip_tem = self.flow[key].ip
                data_seq = self.flow[key].sequence
                if tem[0] in {20, 21, 22, 23}:
                    rest_load, flag = self.parse_tls_records(ip_tem, tem, nth_flag[-1])
        self.tot_time_src = src_tp[-1] - src_tp[0]
        self.tot_time_dst = dst_tp[-1] - dst_tp[0]
        # 测试专用地

        self.time_seq = [item for item in self.time_seq if item != 0.0]
        self.pack_num = nth-1
        self.time = time_total.total_seconds()

    def analyse_udp(self):
        nth = 1
        flows = {}
        ip_src = None
        src_tp = []
        dst_tp = []

        for timestamp, packet in self.capture:

            if nth == 1:
                time_last = timestamp
                ip_src = dpkt.utils.inet_to_str(dpkt.ethernet.Ethernet(packet).data.src)
                self.tran_protocol = dpkt.ethernet.Ethernet(packet).data.p

            time = timestamp - time_last
            time_last = timestamp
            eth = dpkt.ethernet.Ethernet(packet)
            ip = eth.data
            self.tp_hdr_seq.append(len(ip.data) - len(ip.data.data))  # 计算传输层头长度序列
            if isinstance(ip, dpkt.ip.IP):
                src_ip = dpkt.utils.inet_to_str(ip.src)
                dst_ip = dpkt.utils.inet_to_str(ip.dst)
                src_port = ip.data.sport
                dst_port = ip.data.dport
                flow_key = (src_ip, src_port, dst_ip, dst_port)
                if src_ip == ip_src:
                    src_tp.append(timestamp)
                    self.src_tp_hdr_seq.append(len(ip.data) - len(ip.data.data))
                else:
                    dst_tp.append(timestamp)
                    self.dst_tp_hdr_seq.append(len(ip.data) - len(ip.data.data))
                if flow_key not in flows:
                    flows[flow_key] = {'start_time': timestamp, 'end_time': timestamp}
                else:
                    flows[flow_key]['end_time'] = timestamp

            self.parse_packet(packet, time, nth)
            self.time_seq.append(time)
            nth += 1

        # 计算正反向间隔时间序列
        for i in range(len(src_tp)-1):
            self.time_src_seq.append(src_tp[i+1]-src_tp[i])
        for i in range(len(dst_tp)-1):
            self.time_dst_seq.append(dst_tp[i+1] - dst_tp[i])

        # 计算正反向总时间
        min_start_time = datetime.max
        max_end_time = datetime.min
        for flow_key, flow_info in flows.items():
            if flow_key[0] == ip_src:
                start_time = datetime.utcfromtimestamp(flow_info['start_time'])
                end_time = datetime.utcfromtimestamp(flow_info['end_time'])
                min_start_time = min(min_start_time, start_time)
                max_end_time = max(max_end_time, end_time)
            else:
                start_time = datetime.utcfromtimestamp(flow_info['start_time'])
                end_time = datetime.utcfromtimestamp(flow_info['end_time'])
                min_start_time = min(min_start_time, start_time)
                max_end_time = max(max_end_time, end_time)
        # 重新计算流持续总时间
        time_total = max_end_time - min_start_time
        for key in self.flow:
            if len(self.flow[key].data) != 0:

                tem = self.flow[key].data
                nth_flag = self.flow[key].nth_seq
                ip_tem = self.flow[key].ip
                data_seq = self.flow[key].sequence
                if tem[0] in {20, 21, 22, 23}:
                    rest_load, flag = self.parse_tls_records(ip_tem, tem, nth_flag[-1])
        self.tot_time_src = src_tp[-1] - src_tp[0]
        self.tot_time_dst = dst_tp[-1] - dst_tp[0]
        # 测试专用地

        self.time_seq = [item for item in self.time_seq if item != 0.0]
        self.pack_num = nth-1
        self.time = time_total.total_seconds()

    def parse_packet(self, packet, timestamp, nth):
        """
        Main analysis loop for pcap.
        """
        eth = dpkt.ethernet.Ethernet(packet)

        if isinstance(eth.data, dpkt.ip.IP):
            self.parse_ip_packet_udp(eth, nth, timestamp)
        if isinstance(eth.data.data, dpkt.tcp.TCP):
            if (len(eth.data.data.data)) and len(self.content_seq) < 2:
                # 有效包
                self.content_seq_2.append(packet[14:])
        if self.need_experiment_3 and len(self.mix_1) < 784:
            if isinstance(eth.data.data, dpkt.tcp.TCP):
                if self.need_ip:
                    if len(self.content) < 784:
                        self.mix_1 += packet[14:]
                else:
                    tem = packet[12:]
                    self.mix_1 += (tem[:-8] + bytes(8))
                if len(self.content) < 784:
                    if self.need_ip:
                        self.content += packet[14:]
                    else:
                        tem = packet[14:]
                        self.content += tem[:12] + bytes(8) + tem[20:]

        if isinstance(eth.data.data, dpkt.tcp.TCP):
            if (len(eth.data.data.data)) and len(self.content_seq) < 3:
                # 有效包
                self.content_seq.append(packet[14:])
                self.content_payload.append(len(eth))
                self.nth_seq.append(nth)
        if isinstance(eth.data.data, dpkt.tcp.TCP):
            if self.need_ip:
                self.packet_content_seq.append(packet[14:])
            else:
                tem = packet[14:]
                self.packet_content_seq.append(tem[:12] + bytes(8) + tem[20:])
        if self.needbitFre:
            for bit in packet:
                self.bitFre[bit] += 1

    def parse_ip_packet(self, eth, nth, timestamp):
        """
        Parses IP packet.
        """

        ip = eth.data
        tcp = ip.data
        sys.stdout.flush()
        size = len(eth)  # 包大小
        self.packet_len_all += len(eth.data)
        self.packetsize_packet_seq.append(size)
        self.packetsize_all += size
        payload = len(ip.data.data)  # 有效负载大小
        self.pay_seq.append(payload)
        rest_load = None
        if isinstance(ip.data, dpkt.tcp.TCP):
            if (len(ip.data.data) != 0):
                self.parse_tcp_packet(ip, nth, timestamp)
        # 提取 ip地址、端口号
        if nth == 1:
            self.ip_src = socket.inet_ntoa(ip.src)
            self.ip_dst = socket.inet_ntoa(ip.dst)
            self.sport = int(ip.data.sport)
            self.dport = int(ip.data.dport)
        if nth == 1 or nth == 2 or nth == 3:
            if self.need_ip:
                self.word_seq.append(ip.src)
                self.word_seq.append(ip.dst)
            if self.need_tcp:
                self.word_seq.append(ip.data.sport.to_bytes(length=4, byteorder='big', signed=False))
                self.word_seq.append(ip.data.dport.to_bytes(length=4, byteorder='big', signed=False))
        if socket.inet_ntoa(ip.src) == self.ip_src:
            self.packetsize_src_seq.append(size)
            self.num_src += 1
            self.size_src += size
            self.dir_seq.append(1)
            self.ack_src_seq.append(1 if cal_ack(tcp.flags) else 0)
            self.psh_src_seq.append(1 if cal_psh(tcp.flags) else 0)
            self.pay_src_seq.append(len(tcp.data))
        else:
            self.packetsize_dst_seq.append(size)
            self.num_dst += 1
            self.size_dst += size
            self.dir_seq.append(-1)
            self.ack_dst_seq.append(1 if cal_ack(tcp.flags) else 0)
            self.psh_dst_seq.append(1 if cal_psh(tcp.flags) else 0)
            self.pay_dst_seq.append(len(tcp.data))
        self.fin += 1 if cal_fin(tcp.flags) else 0
        self.syn += 1 if cal_syn(tcp.flags) else 0
        self.rst += 1 if cal_rst(tcp.flags) else 0
        if cal_ack(tcp.flags):
            self.ack += 1
            self.ack_seq.append(1)
        else:
            self.ack_seq.append(0)
        self.urg += 1 if cal_urg(tcp.flags) else 0
        if cal_psh(tcp.flags):
            self.psh += 1
            self.psh_seq.append(0)
        else:
            self.psh_seq.append(0)
        self.ece += 1 if cal_ece(tcp.flags) else 0
        self.cwe += 1 if cal_cwe(tcp.flags) else 0
        if self.need_experiment_3 and nth <= 32:
            self.mix_2.append([len(eth), timestamp, tcp.win])
        if isinstance(ip.data, dpkt.tcp.TCP) and payload:
            if socket.inet_ntoa(ip.src) == self.ip_dst:
                direction = 1
            else:
                direction = -1
            dirpath = direction * payload
            if len(self.seq) < 20:
                self.seq.append(dirpath)
        if self.need_more_certificate:
            class FlowFlag:
                def __init__(self, seq, data):
                    self.seq = seq
                    self.seq_exp = seq + len(data)
                    self.data = data
                    self.sequence = []
                    self.nth_seq = []
                    self.ip = dpkt.ip.IP()
                    self.timestamp = 0
            # 设置flow记录流的各条记录，以解决tcp resseambeld segment
            flow_flag = socket.inet_ntoa(ip.src) + '-' + str(ip.data.sport) + '->' + socket.inet_ntoa(
                ip.dst) + '-' + str(ip.data.dport)
            flow_flag1 = socket.inet_ntoa(ip.dst) + '-' + str(ip.data.dport) + '->' + socket.inet_ntoa(
                ip.src) + '-' + str(ip.data.sport)
            # 存在udp 没有seq和ack
            try:
                seq = ip.data.seq
                ack = ip.data.ack
            except AttributeError as exception:
                seq = 0
                ack = 0
            data = ip.data.data
            data_flag = data
            try:
                if data[0] in {20, 21, 22, 23}:
                    # 直接可以解压一部分，且返回剩余负载部分
                    data_tem, flag = self.parse_tls_records(ip, data, nth)
                    if self.need_experiment_3:
                        if flag and nth not in self.is_hand:
                            self.is_hand.append(nth)
                    if flag:
                        if len(data_tem) == 0:
                            data_tem = bytes(0)
                        data = data_tem
            except:
                pass
            # 接收到反向的包
            if flow_flag1 in self.flow.keys():
                if ack >= self.flow[flow_flag1].seq:
                    if len(self.flow[flow_flag1].data) != 0:
                        tem = self.flow[flow_flag1].data
                        nth_flag = self.flow[flow_flag1].nth_seq
                        ip_tem = self.flow[flow_flag1].ip
                        data_seq = self.flow[flow_flag1].sequence
                        if tem[0] in {20, 21, 22, 23}:
                            rest_load, flag = self.parse_tls_records(ip_tem, tem, nth_flag[-1])
                            if self.need_experiment_3 and nth < 32:
                                if flag:
                                    for nth_i in nth_flag:
                                        if nth_i not in self.is_hand:
                                            self.is_hand.append(nth_i)
                    try:
                        if rest_load != None and not len(data_flag):
                            if rest_load == bytes(0):
                                self.flow.pop(flow_flag1)
                            elif rest_load[0] in {20, 21, 22, 23}:
                                self.flow[flow_flag1].data = rest_load
                                # 中间插入一条ack较大值
                                self.flow[flow_flag1].sequence = [rest_load]
                                self.flow[flow_flag1].ip = ip
                                self.flow[flow_flag1].timestamp = timestamp
                        else:
                            self.flow.pop(flow_flag1)
                    except:
                        if flow_flag1 in self.flow.keys():
                            self.flow.pop(flow_flag1)
            if len(data):
                if flow_flag not in self.flow.keys():
                    if data != bytes(0):
                        if data[0] in {20, 21, 22, 23}:
                            self.flow[flow_flag] = FlowFlag(seq, data)
                            self.flow[flow_flag].sequence.append(data)
                            self.flow[flow_flag].nth_seq.append(nth)
                            self.flow[flow_flag].seq_exp = seq + len(data_flag)
                            self.flow[flow_flag].ip = ip
                            self.flow[flow_flag].timestamp = timestamp
                else:
                    if self.flow[flow_flag].seq_exp == seq:
                        self.flow[flow_flag].seq = seq
                        self.flow[flow_flag].seq_exp += len(data_flag)
                        if data not in self.flow[flow_flag].sequence:
                            self.flow[flow_flag].data += data
                            self.flow[flow_flag].sequence.append(data)
                            self.flow[flow_flag].nth_seq.append(nth)
                            self.flow[flow_flag].ip = ip
                            self.flow[flow_flag].timestamp = timestamp
                    else:
                        pass

    def parse_ip_packet_udp(self, eth, nth, timestamp):
        """
        Parses IP packet for UDP.
        """
        ip = eth.data
        udp = ip.data
        sys.stdout.flush()
        size = len(eth)  # 包大小
        self.packet_len_all += len(eth.data)
        self.packetsize_packet_seq.append(size)
        self.packetsize_all += size
        payload = len(ip.data.data)  # 有效负载大小
        self.pay_seq.append(payload)
        rest_load = None
        # 提取 ip地址、端口号
        if nth == 1:
            self.ip_src = socket.inet_ntoa(ip.src)
            self.ip_dst = socket.inet_ntoa(ip.dst)
            self.sport = int(ip.data.sport)
            self.dport = int(ip.data.dport)
        if socket.inet_ntoa(ip.src) == self.ip_src:
            self.packetsize_src_seq.append(size)
            self.num_src += 1
            self.size_src += size
            self.dir_seq.append(1)
        else:
            self.packetsize_dst_seq.append(size)
            self.num_dst += 1
            self.size_dst += size
            self.dir_seq.append(-1)

    def parse_tcp_packet(self, ip, nth, timestamp):
        """
        Parses TCP packet.
        """
        rest_load = None
        tcp_data = ip.data
        stream = ip.data.data
        #  提取标志位
        if (stream[0]) in {20, 21, 22, 23, 128, 25}:
            if (stream[0]) in {20, 21, 22}:
                pass
            if (stream[0]) == 128:  # sslv2 client hello
                # feature.flag = True
                try:
                    cipher_length = stream[6] + stream[5] * 256
                except:
                    cipher_length = 0
                if len(stream) > 6:
                    if stream[2] == 1:  # sslv2 client hello
                        self.is_hand.append(nth)
                        self.client_hello_num += 1
                        packet = []
                        pos_flag = False
                        record_type_bytes = (22).to_bytes(length=1, byteorder='big', signed=False)
                        prefix = record_type_bytes + stream[2:3]
                        self.word_seq.append(prefix + bytes(3) + stream[1:2])  # 长度
                        self.word_seq.append(prefix + (2).to_bytes(length=4, byteorder='big', signed=False))  # 版本
                        self.word_seq.append(prefix + cipher_length.to_bytes(length=4, byteorder='big',
                                                                             signed=False))  # cipher_spec_length
                        if not self.cipher_num:
                            self.cipher_num = cipher_length
                        tem = stream[7] * 256 + stream[8] + 11  # 加密组件开始的stream的index
                        i = 0
                        if self.need_experiment_4:
                            self.tlsWord.append(str(stream[0]))
                            self.tlsWord_2.append(str(stream[0]))
                        while i < cipher_length:
                            cipher = 0
                            if tem + i + 2 < len(stream):
                                cipher = stream[tem + i + 2] + stream[tem + i + 1] * 256 + stream[tem + i] * 256 * 256
                                packet.append(bytes(1) + stream[tem + i: tem + i + 3])
                                self.word_seq.append(prefix + bytes(1) + stream[tem + i: tem + i + 3])
                                if self.need_experiment_4:
                                    self.tlsWord.append("C" + str(cipher))
                                    self.tlsWord_2.append(cipher)
                            if cipher not in self.cipher_support:
                                self.cipher_support.append(cipher)
                            i += 3
                        self.tls_seq.append("client_hello")
                        if not self.packet["client_hello"]:
                            self.packet["client_hello"] = packet
        return rest_load

    def multiple_handshake(self, nth, buf, ip):
        i, n = 0, len(buf)
        msgs = []
        while i + 5 < n:
            tot = 0
            v = buf[i + 1:i + 3]
            if v in dpkt.ssl.SSL3_VERSION_BYTES:
                head = buf[i:i + 5]
                tot_len = int.from_bytes(buf[i + 3:i + 5], byteorder='big')
                j = i + 5
                while j < tot_len + 5:
                    try:
                        Record_len = int.from_bytes(buf[j + 1:j + 4], byteorder='big', signed=False)
                        len_tem_b = (Record_len + 4).to_bytes(length=2, byteorder='big', signed=False)
                        head_tem = head[0:3] + len_tem_b
                        tem = head_tem + buf[j:j + Record_len + 4]
                    except:
                        # Record_len = 0
                        pass
                    try:
                        msg = dpkt.ssl.TLSRecord(tem)
                        msgs.append(msg)
                        record_type = self.pretty_name('tls_record', msg.type)

                    except dpkt.NeedData:
                        i = n
                        break
                    try:
                        j += Record_len + 4
                        i += Record_len + 4
                    except:
                        pass
            else:
                raise dpkt.ssl.SSL3Exception('Bad TLS version in buf: %r' % buf[i:i + 5])
            # i += tot
        return msgs, i + 5

    def parse_tls_records(self, ip, stream, nth):
        packet = []
        flag = False
        is_multiple_handshake_message = False
        record_nth = 0
        try:
            record_len = int.from_bytes(stream[3: 5], byteorder='big', signed=False)
            if record_len + 5 > len(stream):
                return stream, False
        except:
            return stream, False
        try:
            records, bytes_used = dpkt.ssl.tls_multi_factory(stream)
        except dpkt.ssl.SSL3Exception as exception:
            return stream, False
        # mutliple
        try:
            record = records[0]
            # length = record.length
            if record.type == 22 and record.data[0] in {1, 2, 11, 16}:
                length = int.from_bytes(record.data[1:4], byteorder='big', signed=False) + 4
            else:
                length = record.length
        except:
            length = record.length
            pass
        if bytes_used == 0 or length != record_len:
            try:
                records, bytes_used = self.multiple_handshake(nth, stream, ip)
                is_multiple_handshake_message = True
                multiple_handshake_length = stream[3:5]
            except:
                return stream, False
            if bytes_used > len(stream):
                return stream, False
        flag = True
        for record_nth, record in enumerate(records):
            record_type = self.pretty_name('tls_record', record.type)
            packet = []
            record_type_bytes = record.type.to_bytes(length=1, byteorder='big', signed=False)
            prefix = record_type_bytes + bytes(1)
            packet_len = (len(ip) + 14).to_bytes(length=4, byteorder='big', signed=False)
            # self.word_seq.extend([nth_bytes, packet_len, ip.src, ip.dst, ip.data.sport.to_bytes(length=4, byteorder='big', signed=False), ip.data.dport.to_bytes(length=4, byteorder='big', signed=False)])
            if record_type == 'change_cipher':  # change_cipher
                self.tls_seq.append('change_cipher')
                try:
                    version = prefix + record.version.to_bytes(length=4, byteorder='big', signed=False)
                    record_length = prefix + record.length.to_bytes(length=4, byteorder='big', signed=False)
                    change_cipher_spec_message = prefix + bytes(3) + record.data[0:1]
                    self.word_seq.extend([version, record_length, change_cipher_spec_message])
                except:
                    print('change_cipher error')
            elif record_type == 'application_data':  # app_data
                self.tls_seq.append('app_data')
                version = prefix + record.version.to_bytes(length=4, byteorder='big', signed=False)
                record_length = prefix + record.length.to_bytes(length=4, byteorder='big', signed=False)
                if self.need_app:
                    self.word_seq.extend([version, record_length])
                if self.need_experiment_4:
                    if socket.inet_ntoa(ip.src) == self.ip_src:
                        if not self.capp:
                            self.capp = "CAPP" + str(record.length)
                            self.tlsWord.append(self.capp)
                            self.tlsWord_2.append(record.length)
                    else:
                        if not self.sapp:
                            self.sapp = "SAPP" + str(record.length)
                            self.tlsWord.append(self.sapp)
                            self.tlsWord_2.append(record.length)
            elif record_type == 'alert':  # alert
                self.tls_seq.append('alert')
                version = prefix + record.version.to_bytes(length=4, byteorder='big', signed=False)
                record_length = prefix + record.length.to_bytes(length=4, byteorder='big', signed=False)
                if record.length == 2:
                    level = prefix + bytes(3) + record.data[0:1]
                    description = prefix + bytes(3) + record.data[1:2]
                    self.word_seq.extend([version, record_length, level, description])
                else:
                    # encypted alert 修改
                    self.word_seq.extend([version, record_length, prefix + bytes(4)])
            elif record_type == 'handshake':
                # handshake_data = dpkt.ssl.TLSHandshake(record.data)
                handshake_type = ord(record.data[:1])
                length = int.from_bytes(record.data[1:4], byteorder='big', signed=False)
                if length + 4 != len(record.data) or self.last_record == 'change_cipher':  # encrypted handshake
                    prefix = record_type_bytes + bytes(1)
                    version = prefix + record.version.to_bytes(length=4, byteorder='big', signed=False)
                    record_length = prefix + record.length.to_bytes(length=4, byteorder='big', signed=False)
                    self.word_seq.extend([version, record_length])
                    self.tls_seq.append('encrypted_shake')
                else:
                    # handshake_data = dpkt.ssl.TLSHandshake(record.data)
                    prefix = record_type_bytes + record.data[0:1]  # record_type + handshake_type
                    if not is_multiple_handshake_message:
                        version = prefix + record.version.to_bytes(length=4, byteorder='big', signed=False)
                        record_length = prefix + record.length.to_bytes(length=4, byteorder='big', signed=False)
                        handshake_length = prefix + bytes(1) + record.data[1:4]
                        self.word_seq.extend([version, record_length, handshake_length])
                    else:
                        if record_nth == 0:
                            version = prefix + record.version.to_bytes(length=4, byteorder='big', signed=False)
                            record_length = prefix + bytes(2) + multiple_handshake_length
                            self.word_seq.extend([version, record_length])
                        handshake_length = prefix + bytes(1) + record.data[1:4]
                        self.word_seq.append(handshake_length)
                    if handshake_type == 2:  # server hello
                        self.server_hello_num += 1
                        try:
                            length = int.from_bytes(record.data[1:4], byteorder='big')
                            if length + 4 != record.length:
                                break
                        except:
                            break
                        # self.cipher = (record.data[-2] + record.data[-3] * 256)
                        try:
                            cipher = int.from_bytes(record.data[record.data[38] + 39: record.data[38] + 41],
                                                    byteorder='big', signed=False)
                            if not self.cipher:
                                self.cipher = cipher
                        except:
                            print(self.name, nth, "server_hello error")

                        if self.need_experiment_4:
                            handshake_data = dpkt.ssl.TLSHandshake(record.data).data
                            self.tlsWord.append(str(handshake_data.version))
                            self.tlsWord_2.append(handshake_data.version)
                            self.tlsWord.append("C" + str(handshake_data.ciphersuite.code))
                            self.tlsWord_2.append(handshake_data.ciphersuite.code)
                            try:
                                extension = handshake_data.extensions
                                for (extension_type, extension_data) in extension:
                                    self.tlsWord.append("ET" + str(len(extension_data)))
                                    self.tlsWord_2.append(len(extension_data))
                            except:
                                pass

                        self.cipher_list.append(self.cipher)
                        self.tls_seq.append("server_hello")
                        self.word_seq.append(
                            prefix + bytes(2) + record.data[record.data[38] + 39: record.data[38] + 41])  # 组件
                    elif handshake_type == 11:  # certificate
                        a = self.parse_tls_certs(nth, record.data, packet, prefix)
                    elif handshake_type == 1:  # sslv3 tlsv1 client hello
                        # self.flag = True
                        self.client_hello_num += 1
                        try:
                            length = int.from_bytes(record.data[1:4], byteorder='big')
                            if length + 4 != record.length:
                                break
                        except:
                            break
                        try:
                            cipher_len = int.from_bytes(record.data[record.data[38] + 39:record.data[38] + 41],
                                                        byteorder='big')
                        except IndexError as exception:
                            cipher_len = 0
                            print(self.name, nth, "client_hello length error")
                            break
                        try:
                            cipher_len_bytes = prefix + bytes(2) + record.data[
                                                                   record.data[38] + 39:record.data[38] + 41]
                            self.word_seq.append(cipher_len_bytes)
                        except:
                            print("client_hello error")

                        self.tls_seq.append("client_hello")

                        if self.need_experiment_4:
                            handshake_data = dpkt.ssl.TLSHandshake(record.data).data
                            self.tlsWord.append(str(handshake_data.version))
                            self.tlsWord_2.append(handshake_data.version)
                            ciphersuites = handshake_data.ciphersuites
                            for i in range(len(ciphersuites)):
                                self.tlsWord.append("C" + str(ciphersuites[i].code))
                                self.tlsWord_2.append(ciphersuites[i].code)
                            try:
                                extension = handshake_data.extensions
                                for (extension_type, extension_data) in extension:
                                    self.tlsWord.append("ET" + str(len(extension_data)))
                                    self.tlsWord_2.append(len(extension_data))

                                for (extension_type, extension_data) in extension:
                                    if extension_type == 11:
                                        length = extension_data[0]
                                        for i in range(length):
                                            self.tlsWord.append("ECP" + str(extension_data[1 + i]))
                                            self.tlsWord_2.append(extension_data[1 + i])
                            except:
                                pass
                        if not self.cipher_num:
                            self.cipher_num = cipher_len
                        tem = 40 + record.data[38] + 1
                        i = 0
                        try:
                            while i < cipher_len:
                                cipher = record.data[tem + i] * 256 + record.data[tem + i + 1]
                                cipher_bytes = prefix + bytes(2) + record.data[tem + i:tem + i + 2]
                                self.word_seq.append(cipher_bytes)
                                if cipher not in self.cipher_support:
                                    self.cipher_support.append(cipher)
                                i += 2
                        except:
                            print("client_hello error")
                            packet = []
                        if not self.packet["client_hello"]:
                            self.packet["client_hello"] = packet

                    elif handshake_type == 14:
                        self.word_seq.append(prefix + bytes(4))
                        self.tls_seq.append("server_hello_done")
                    elif handshake_type == 16:
                        self.tls_seq.append('client_key_exchange')
                        encypte_preMaster_length = prefix + bytes(2) + record.data[4:6]
                        self.word_seq.append(encypte_preMaster_length)
                    elif handshake_type == 22:
                        # 192.168.27.243_1302&23.43.62.11_443_tcp#black handshake 
                        self.tls_seq.append('certificate_status')
                        certificate_status_type = prefix + bytes(3) + record.data[4:5]
                        self.word_seq.append(certificate_status_type)
                    elif handshake_type == 12:
                        # 192.168.27.243_1302&23.43.62.11_443_tcp#black handshake 
                        self.word_seq.append(prefix + bytes(4))  # 第二次更改
                        self.tls_seq.append('server_key_exchange')
                    elif handshake_type == 4:
                        # 192.168.225.157_1364&184.28.203.74_443_tcp#black handshake 4
                        self.tls_seq.append('new_session_ticket')
                        session_ticket_lifetimeHint = prefix + record.data[4:8]
                        session_ticket_length = prefix + bytes(2) + record.data[8:10]
                        self.word_seq.extend([session_ticket_lifetimeHint, session_ticket_length])
                    elif handshake_type == 13:
                        # 192.168.225.157_1364&184.28.203.74_443_tcp#black handshake 4
                        self.tls_seq.append('certificate_request')
                        certificate_type_count = prefix + bytes(3) + record.data[4:5]
                        self.word_seq.append(certificate_type_count)
                    elif handshake_type == 15:
                        # 192.168.225.157_1364&184.28.203.74_443_tcp#black handshake 4
                        self.tls_seq.append('certificate_verify')
                        signature_algorithm = prefix + bytes(2) + record.data[4:6]
                        self.word_seq.append(signature_algorithm)
                    else:
                        print(self.name, nth, "handshake", handshake_type, "last:", self.last_record)
                        self.tls_seq.append("handshake_{}".format(handshake_type))
            else:
                print(self.name, nth, "record_type", record.type)
                self.tls_seq.append(record.type)
            sys.stdout.flush()
        # ressembled tcp segments
        load = stream[bytes_used:]
        if load == None:
            load = bytes(0)
        return load, flag

    def parse_tls_certs(self, nth, data, packet, prefix):
        """
        Parses TLS Handshake message contained in data according to their type.
        """
        ans = []
        handshake_type = ord(data[:1])  # 握手类型
        if handshake_type == 4:
            print('[#] New Session Ticket is not implemented yet')
            return ans

        buffers = data[0:]
        try:
            handshake = dpkt.ssl.TLSHandshake(buffers)
        except dpkt.ssl.SSL3Exception as exception:
            pass
        except dpkt.dpkt.NeedData as exception:
            pass

        try:
            ch = handshake.data
        except UnboundLocalError as exception:
            pass
        else:
            if handshake.type == 11:  # TLS Certificate
                # ssl_servers_with_handshake.add(client)
                hd_data = handshake.data
                assert isinstance(hd_data, dpkt.ssl.TLSCertificate)
                certs = []
                for cert_num, cert_raw in enumerate(hd_data.certificates):

                    cert_1 = cert_raw
                    try:
                        cert_1 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_1)
                        self.tls_seq.append("certificate")
                        self.certificate_num += 1

                        # nth_bytes = nth.to_bytes(signed=False, byteorder='big', length=2)
                        # self.cipher_certificate_time.append(cert_1.get_notAfter()-cert_1.get_notBefore())

                        signature = cert_1.get_signature_algorithm()
                        # cut_bytes(signature, packet)
                        try:
                            issue = bytes(cert_1.get_issuer().CN.replace(" ", ""), encoding='utf-8')
                        except:
                            issue = bytes(0)
                        self.cut_bytes(issue, packet, nth, prefix)

                        time_before = cert_1.get_notBefore()[:8]
                        time_after = cert_1.get_notAfter()[:8]

                        self.word_seq.append(prefix + len(cert_raw).to_bytes(length=4, byteorder='big', signed=False))
                        self.word_seq.extend(
                            [prefix + time_before[:4], prefix + time_before[4:], prefix + time_after[:4],
                             prefix + time_after[4:]])
                        try:
                            subject = bytes(cert_1.get_subject().CN.replace(" ", ""), encoding='utf-8')
                        except:
                            subject = bytes(0)
                        self.cut_bytes(subject, packet, nth, prefix)

                        # self.word_seq.append(nth_bytes + cert_1.get_extension_count().to_bytes(length=4, byteorder='big', signed=False))

                        before = datetime.strptime(cert_1.get_notBefore().decode()[:-7], '%Y%m%d')
                        after = datetime.strptime(cert_1.get_notAfter().decode()[:-7], '%Y%m%d')
                        if not self.certificate:
                            self.cipher_subject = cert_1.get_subject().CN
                            self.cipher_issue = cert_1.get_issuer().CN
                            self.cipher_certificate_time = (after - before).days

                            self.cipher_extension_count = cert_1.get_extension_count()
                            self.cipher_sigature_alo = cert_1.get_signature_algorithm()
                            self.cipher_version = cert_1.get_version()
                            self.cipher_pubkey = cert_1.get_pubkey()
                            self.cipher_serial_number = cert_1.get_serial_number()
                            if cert_1.get_subject() == cert_1.get_issuer():
                                # 自签名
                                self.cipher_self_signature = 1
                                if cert_num == 0:
                                    print(self.name)
                        if not self.packet["certificate"]:
                            self.packet["certificate"] = packet
                        ans += certs
                    except:
                        print("certificate证书解析错误")
                        pass
        return ans

    def cut_bytes(self, tem, packet, nth, prefix):
        i = 0
        # nth_bytes = nth.to_bytes(length=2, signed=False, byteorder='big')
        while (i < len(tem)):
            if (i + 4) <= len(tem):
                packet.append(tem[i:i + 4])
                self.word_seq.append(prefix + tem[i:i + 4])
            else:
                packet.append(bytes(4 - len(tem) + i) + tem[i:])
                self.word_seq.append(prefix + bytes(4 - len(tem) + i) + tem[i:])
            i += 4

    def pretty_name(self, name_type, name_value):
        """Returns the pretty name for type name_type."""
        if name_type in PRETTY_NAMES:
            if name_value in PRETTY_NAMES[name_type]:
                name_value = PRETTY_NAMES[name_type][name_value]
            else:
                name_value = '{0}: unknown value {1}'.format(name_value, name_type)
        else:
            name_value = 'unknown type: {0}'.format(name_type)
        return name_value
