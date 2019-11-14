# VPN_NAT
VPN traffic identification based on machine learning algorithm

This File will only give the summary of every weeks, more specifically, look for the relevant files

## 第一周





## 第二周





## 第三周





## 第四周11.11 -- 11.17

### 待做事项

+ [x] 配置谷歌云服务器以便后续工作开展

+ [ ] 分析ssr流量的具体行为，具体ssr有不同混淆参数如http，tls等，可以用wireshark抓包后进行wireshark观察以及python有对应的pyshark库对pcap文件进行整理流量中的一些参数比如auth套件，扩展参数等等




### 已做事项
#### 谷歌云rdp连接

+ 问题： rdp连接 --> 校园网把远程连接给墙了，可能是墙3389端口 --> 导致无法连接谷歌云的windows rdp

+ 解决措施：搭建ssh隧道翻过校园网的防火墙

  

#### 谷歌云ssh连接

+ 问题：ssh连接不上
+ 解决措施：利用谷歌自带ssh配置相关文件

#### 谷歌云ssr连接

+ 目的：为了测试不同ssr设置情况下的流量，需要自己搭建ssr服务器来采集流量观察 | 自己也能有vpn使用
+ 问题：安装了ssr无法使用
+ 解决措施：配置防火墙规则