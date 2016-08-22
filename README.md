# packetCaptureSystem
基于libpcap的数据包捕获系统，将数据包的基本信息存入mysql数据库
本系统分为三个模块：主控制模块、数据包采集模块和存储模块。
数据包基本信息：{源MAC地址，目的MAC地址，源IP地址，目的MAC地址，协议类型，包的长度，源端口号，目的端口号}

主控制模块：
系统向用户提供命令，如下所示:
run capture：开启采集
stop capture：关闭采集
run write：开启存储
stop write：关闭存储
capture status：采集状态查询
write status：存储状态查询
db status：数据库查看
exit：退出
help：帮助

用法：./dpcs
然后在主控制模块输入以上命令
