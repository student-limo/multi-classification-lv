# 高隐匿恶意流量识别
本项目提供从流量五元组划分、流量特征提取到模型训练全过程

## 流量五元组划分
### sortByTime.py
用于将pcap文件中的数据包按照时间顺序重新排序
于代码中的 ```sorted_pcap_by_feature()``` 方法中填入待处理的文件夹路径后运行代码即可

### flow_cut.py
用于将pcap文件中的数据包按照五元组分流，生成一批只包含一个五元组的pcap文件
其中请于```pcapngs_dir```中输入待处理的文件夹路径，于```pcaps_dir```输入输出结果的路径
方法```flow_cut()```和```pcap_ana_new()```均可完成分流，后者能够将五元组按照ip序号和时间戳间隔进行更细致的划分

### flow_del.py
用于将pcap文件中的异常包删除
请于```data_path```和```file```中填入待处理的数据文件夹路径

### nameChange.py
用于将待提取特征的pcap文件的文件名加一个标签后缀
请于`f_path`中填入待处理pcap文件文件夹路径，并于`filename.replace(".pcap", "#(标签名).pcap")`方法中第二个参数中填入预计标记的标签名即可

## 流量特征提取
### f_e.py
请以`./.../{xxx}/...`存放想要处理的xxx数据集, 因为特征提取区分传输层协议，所以请将TCP协议和UDP协议的数据分开文件夹存放
处理TCP协议相关数据时请注释掉代码中```flow_sample.analyse_udp()```方法，
处理UDP协议相关数据时请注释掉代码中```flow_sample.analyse()```方法。
* 使用方式：
` python f_e.py --d dateset_paht --f feature_type `其中`dataset_path`为上文存放数据集地址的`xxx`，`feature_type`为`flow_feature_new 或 flow_feature_new_udp`分别对应处理TCP数据和UDP数据
### npyReader.py
用于将提取的特征文件格式从npy转化到csv，并添加分类类别标签，便于后续文件合并
请于 `file_path`处填入待处理的npy文件路径，`df.to_csv()`方法中填入输出csv文件的路径
`feature_data.append()`中填入待标记的标记名即可
### data_process.py
*`csv_date_file`中填入待合并的数据文件夹路径，
*`data_file`中填入合并输出文件路径(以`.csv`结尾)，
*`dataset_path`中填入特征归一化处理后输出文件路径

## 模型训练
### model.py
* `train_path`中填入训练集路径
* `test_path`填入测试集路径
将输出混淆矩阵及其示意图以及各个训练指标值
结果示意图如下图所示

![cc](https://github.com/student-limo/multi-classification-lv/blob/master/e1ccc72f86e4fc200fda2cd4fab1cd1.png)

