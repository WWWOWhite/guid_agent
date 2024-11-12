# Guid方案Agent代码 

## 文件结构

**init.sh:** 用于加载agent所有组件的脚本  

**app.py:** agent通信对外接口，使用flask轻量级Web框架

**get_map.sh:** 查询map内容的接口，供app.py调用
  
**xdp_rtps.c:** xdp内核态程序

**map_manager.c:** 用来操作map的函数

**xdp_load.sh:** 加载xdp程序脚本

**xdp_off.sh:** 卸载xdp程序脚本

## 环境安装
* python
    * flask 
* xdp 

```shell
apt install clang llvm libelf-dev libpcap-dev build-essential libc6-dev-i386
sudo apt install linux-tools-$(uname -r)
sudo apt install linux-headers-$(uname -r)
apt install libbpf-dev
sudo apt install linux-tools-common linux-tools-generic
sudo apt install tcpdump
apt install iproute2
```

## 启动方式

```shell
./init.sh
```