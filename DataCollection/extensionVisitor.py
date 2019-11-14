import requests
from selenium import webdriver
import datetime
import time
from pymouse import PyMouse
from pykeyboard import PyKeyboard

extension_path = '/Users/wubohao/Library/Application Support/Google/Chrome/Default/Extensions/'
vpn = ['Shawdowsocks']
crx = ['omghfjlpggmjjaagoclmmobgdodcjboh/3.25.3_0.crx', 'mjnbclmflcpookeapghfhapeffmpodij/1.5.4_0.crx']
# urls = ['https://www.google.com', 'https://www.baidu.com/', 'https://www.bilibili.com/', 'https://cn.bing.com/',
#         'https://www.taobao.com/', 'https://tieba.baidu.com/', 'https://www.huya.com/', 'https://www.ifeng.com/',
#         'https://flights.ctrip.com/', 'https://mail.qq.com/', 'https://map.baidu.com/', 'https://music.163.com/']
urls = ['http://www.google.com/', 'https://www.baidu.com/', 'https://www.bilibili.com/']
open = [True]
is_ex = [False]
start_flag = False
crx_dic = dict(zip(vpn, crx))
m = PyMouse()


def init_option(index):
    options = webdriver.ChromeOptions()
    options.add_extension(extension_path + crx[index])
    return options


def open_extention(index):
    if open[index]:
        m = PyMouse()
        m.click(1188, 87)
        time.sleep(1)
        if vpn[index] == 'browsec':
            m.click(1154.5, 496)


def open_app(index):
    if vpn[index] == 'Shawdowsocks':
        m.click(832.8, 11.2)
        time.sleep(0.5)
        m.click(853.08203125, 58.7578125)


def close_app(index):
    if vpn[index] == 'Shawdowsocks':
        m.click(832.8, 11.2)
        time.sleep(1)
        m.click(853.08203125, 58.7578125)


if __name__ == "__main__":
    for i in range(len(vpn)):
        for j in range(10):
            time.sleep(5)
            if is_ex[i]:
                browser = webdriver.Chrome(options=init_option(i))
                browser.maximize_window()
                open_extention(i)
            else:
                browser = webdriver.Chrome()
                browser.maximize_window()
                open_app(i)

            time.sleep(10)
            m.click(593.6875, 44.3125)
            start_time = time.time()
            flag = False
            while True:
                for url in urls:
                    browser.get(url)
                    browser.implicitly_wait(0.5)
                    if time.time() - start_time > 300:
                        print(j + 1, time.time() - start_time)
                        browser.quit()
                        time.sleep(5)
                        flag = True
                        break
                if flag:
                    break
            if not is_ex[i]:
                close_app(i)
            else:
                start_flag = False

# 2019-10-01 10:00:00.000000
