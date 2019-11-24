import pandas as pd
import lightgbm
from sklearn.model_selection import train_test_split
import matplotlib.pyplot as plt
import numpy as np

data_dir = '../Result/'
data_name = 'DataSet.csv'


def get_r_square():
    avg_train = np.average(y_train)
    sum_train = 0
    sum_pred = 0
    for i in range(len(y_pred)):
        sum_train += abs(sum_train - y_pred[i])
        sum_pred += abs(y_pred[i] - y_test[i])
    return 1 - sum_pred / sum_train


if __name__ == '__main__':
    data_set = pd.read_csv(data_dir + data_name)
    variables = data_set.columns.values
    X = data_set[variables[:-1]]
    y = data_set[variables[-1]]
    X_train, X_leave, y_train, y_leave = train_test_split(X, y, test_size=0.2)
    X_eval, X_test, y_eval, y_test = train_test_split(X_leave, y_leave, test_size=0.5)
    model = lightgbm.LGBMClassifier(n_jobs=2, learning_rate=0.1, n_estimators=10000)
    model.fit(X_train, y_train, eval_set=[(X_eval, y_eval)], early_stopping_rounds=100, )
    print(pd.DataFrame({
        'Factor': variables[:-1],
        'Importance': model.feature_importances_
    }))
    y_pred = model.predict(X_test)
    x_ = [_ for _ in range(len(y_pred))]

    correct_num = 0
    y_test = list(y_test)
    for i in range(len(y_pred)):
        if y_test[i] == y_pred[i]:
            correct_num += 1
    total_num = len(y_pred)
    print('Accuracy:', correct_num / total_num)
    # plt.scatter(x_, y_pred)
    # plt.scatter(x_, y_test)
    # plt.show()
