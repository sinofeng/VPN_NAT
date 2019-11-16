import pickle


with open('./flow_lantern.pkl', 'rb+') as f:
    a = pickle.load(f)
    debug  = 1