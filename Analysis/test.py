import pickle
import numpy as np


class test:
    def __init__(self):
        pass


def calc_entropy(x):
    x_set = set(x)
    ent = 0
    n = len(x)
    for x_value in x_set:
        p = x.count(x_value) / n
        logp = np.log2(p)
        ent -= p * logp
    return ent


def calc_condition_entropy(x, y):
    # calc ent(y|x)
    x_value_list = set(x)
    ent = 0.0
    for x_value in x_value_list:
        sub_y = y[x == x_value]
        parent_ent = calc_entropy(sub_y)
        ent += (float(sub_y.shape[0]) / y.shape[0]) * parent_ent
    return ent


calc_condition_entropy(np.array([1, 2, 2, 0, 0.4]), np.array([1, 1, 0, 0, 1, 1]))
