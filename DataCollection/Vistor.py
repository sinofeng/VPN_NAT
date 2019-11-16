# -*_-coding: utf-8 -*-
# Author : Kaiqiang
# TIME : 11/8/19
import threading
import requests
import time


def visit(website):
    dic = {
        "User-Agent": 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.70 Safari/537.36'}
    while True:
        try:
            r = requests.get(website, headers=dic)
        except:
            print('Can not connect to:', website)
        print('Visit:', website)
        time.sleep(10)


if __name__ == '__main__':
    websites = ['https://www.baidu.com/', 'https://www.bilibili.com/', 'https://www.hao123.com/']
    for site in websites:
        t = threading.Thread(target=visit, args=(site,))
        t.start()
