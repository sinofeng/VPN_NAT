from sklearn import tree
from sklearn.datasets import load_iris
import pandas as pd
import graphviz


def read_csv(path_):
    data = []
    target = []
    with open(path_, 'r') as f:
        title = f.readline()
        while True:
            line = f.readline()
            if not line:
                break
            line = list(map(float, line.strip().split(',')))
            data.append(line[:-1])
            target.append(line[-1])
    return data, target


def check_result():
    test_l = '583,97,213.6872065,255.6666667,0.000425,9.60E-05,0.000126682,0.000257667,1454,97,521.0675964,521.6,0.251911,4.00E-06,0.100052319,0.051853'.split(
        ',')
    test_c = '94,94,0,94,0.000167,9.20E-05,2.56E-05,0.000132571,90,90,0,90,8.192663,7.680265,0.168753767,8.065557857'.split(
        ',')
    tests = [test_l, test_c]
    print(clf.predict_proba(tests))


if __name__ == '__main__':
    X, Y = read_csv('../Result/lanternAnalysis.csv')
    feature_name, target_name = [], ['White', 'Lantern']
    for feature in ['ForwardLength', 'ForwardTime', 'BackwardLength', 'BackwardTime']:
        for sig in ['max', 'min', 'sd', 'avg']:
            feature_name.append(feature + '_' + sig)
    clf = tree.DecisionTreeClassifier()
    clf = clf.fit(X, Y)
    dot_data = tree.export_graphviz(clf, out_file=None, feature_names=feature_name, class_names=target_name)
    graph = graphviz.Source(dot_data)
    graph.render("../Result/DecisionTree")
    check_result()
    # X = [[0.5, 11], [2, 4], [4, 4], [1, 10], [2, 14], [10, 10]]
    # Y = [0, 1, 1, 0, 0, 2]
    # clf = tree.DecisionTreeClassifier()
    # clf = clf.fit(X, Y)
    # print(clf.predict_prob([[1, 9]]))
