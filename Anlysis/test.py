import pickle


with open('./flow.pkl', 'rb+') as f:
    a = pickle.load(f)
    debug  = 1