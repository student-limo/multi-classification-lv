from numpy.random import seed

seed(1)
import tensorflow as tf

tf.random.set_seed(2)
import os
import numpy as np
import argparse
import xgboost as xgb
from matplotlib import pyplot as plt
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from matplotlib.ticker import MultipleLocator
from sklearn.linear_model import SGDClassifier
from sklearn.ensemble import RandomForestClassifier

os.environ["CUDA_VISIBLE_DEVICES"] = "-1"


# saved_model_path = "./save_model/"


def read_dataset(train_path, test_path):
    train_data = np.load(train_path, allow_pickle=True)
    test_data = np.load(test_path, allow_pickle=True)
    print(train_data.shape)

    train_ids = train_data[:, -1:]
    test_ids = test_data[:, -1:]

    train_data = train_data[:, :-1]
    test_data = test_data[:, :-1]

    return train_data.astype(np.float32), train_ids, test_data.astype(np.float32), test_ids


def plotCM(classes, matrix):
    """classes: a list of class names"""
    # Normalize by row
    matrix = matrix.astype(np.float)
    linesum = matrix.sum(1)
    linesum = np.dot(linesum.reshape(-1, 1), np.ones((1, matrix.shape[1])))
    matrix /= linesum
    # plot
    # plt.switch_backend('agg')
    fig = plt.figure()
    ax = fig.add_subplot(111)
    cax = ax.matshow(matrix)
    fig.colorbar(cax)
    ax.xaxis.set_major_locator(MultipleLocator(1))
    ax.yaxis.set_major_locator(MultipleLocator(1))
    for i in range(matrix.shape[0]):
        ax.text(i, i, str('%.2f' % (matrix[i, i] * 100)), va='center', ha='center')
    ax.set_xticklabels([''] + classes, rotation=45)
    ax.set_yticklabels([''] + classes)

    plt.show()


def xgboost():
    model = xgb.XGBClassifier(random_state=66, use_label_encoder=False, n_estimators=100, max_depth=13,
                              learning_rate=0.01)
    # train_data, train_ids, test_data, test_ids = read_dataset_tls(train_path, test_path)
    train_data, train_ids, test_data, test_ids = read_dataset(train_path, test_path)
    model.fit(train_data, train_ids)
    fi = model.feature_importances_
    for i, importance_score in enumerate(fi):
        print(f"Feature {i + 1}: {importance_score}")
    y_pred = model.predict(test_data)

    np.savetxt("1222pred_4_test_data_d.csv", test_data, delimiter=',')
    np.savetxt("1222pred_4_test_data_i.csv", test_ids, delimiter=',')

    np.savetxt("1222pred_4_test_data.csv", y_pred, delimiter=',')
    result = confusion_matrix(test_ids, y_pred)

    print(result)
    acc = accuracy_score(test_ids, y_pred)
    print(acc)
    result1 = classification_report(test_ids, y_pred)
    print(result1)
    #
    feature_score = model.get_booster().get_score(importance_type='weight')
    print(feature_score)
    print(model.feature_importances_)
    plotCM(['benign', 'SCF', 'VPS', 'DNS', 'DF', 'DoH', 'SCF_CC', 'VPS_CC', 'DNS_CC', 'DF_CC', 'DoH_CC'], result)


if __name__ == '__main__':
    print("hello world")
    # 训练模型并测试
    # parser = argparse.ArgumentParser()
    #
    # parser.add_argument('test_arg',
    #                     help='测试集数据(.npy)')
    # parser.add_argument('--mode2', action='store_true',
    #                     help='进行训练再测试(会覆盖原来保存的模型)')
    # parser.add_argument('train_arg', nargs='?', default=None,
    #                     help='训练集数据(.npy)')
    # 读取已完成训练的模型单独进行测试
    # args = parser.parse_args()
    # test_path = args.test_arg
    # train_path = args.train_arg
    # if args.mode2:
    #     print("重新进行训练，并进行测试，会覆盖旧的模型数据")
    #     print("--------------------------------------")
    #     xgboost()
    # else:
    #     print("--------------------------------------")
    #     print("直接进行测试")
    #     xgb_test()
    train_path = "./1222train_data_2.npy"
    test_path = "./1222test_data_2.npy"
    xgboost()
