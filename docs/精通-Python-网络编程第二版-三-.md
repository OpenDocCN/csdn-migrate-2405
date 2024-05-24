# 精通 Python 网络编程第二版（三）

> 原文：[`zh.annas-archive.org/md5/dda7e4d1dd78bc5577547014ce9b53d1`](https://zh.annas-archive.org/md5/dda7e4d1dd78bc5577547014ce9b53d1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：使用 Python 进行网络安全

在我看来，网络安全是一个难以撰写的话题。原因不是技术上的，而是与设定正确的范围有关。网络安全的边界如此之广，以至于它们触及 OSI 模型的所有七层。从窃听的第 1 层到传输协议漏洞的第 4 层，再到中间人欺骗的第 7 层，网络安全无处不在。问题加剧了所有新发现的漏洞，有时似乎以每日的速度出现。这甚至没有包括网络安全的人为社会工程方面。

因此，在本章中，我想设定我们将讨论的范围。与迄今为止一样，我们将主要专注于使用 Python 来处理 OSI 第 3 和第 4 层的网络设备安全。我们将研究可以用于管理个别网络设备以实现安全目的的 Python 工具，以及使用 Python 作为连接不同组件的粘合剂。希望我们可以通过在不同的 OSI 层中使用 Python 来全面地处理网络安全。

在本章中，我们将研究以下主题：

+   实验室设置

+   Python Scapy 用于安全测试

+   访问列表

+   使用 Python 进行 Syslog 和 UFW 的取证分析

+   其他工具，如 MAC 地址过滤列表、私有 VLAN 和 Python IP 表绑定。

# 实验室设置

本章中使用的设备与之前的章节有些不同。在之前的章节中，我们通过专注于手头的主题来隔离特定的设备。对于本章，我们将在我们的实验室中使用更多的设备，以便说明我们将使用的工具的功能。连接和操作系统信息很重要，因为它们对我们稍后将展示的安全工具产生影响。例如，如果我们想应用访问列表来保护服务器，我们需要知道拓扑图是什么样的，客户端的连接方向是什么。Ubuntu 主机的连接与我们迄今为止看到的有些不同，因此如果需要，当您稍后看到示例时，请参考本实验室部分。

我们将使用相同的 Cisco VIRL 工具，其中包括四个节点：两个主机和两个网络设备。如果您需要关于 Cisco VIRL 的复习，请随时返回到第二章，*低级网络设备交互*，我们在那里首次介绍了这个工具：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/620c32a2-6ce0-471f-a165-264f14e09454.png)实验拓扑图列出的 IP 地址在您自己的实验室中将是不同的。它们在这里列出，以便在本章的其余部分中进行简单参考。

如图所示，我们将把顶部的主机重命名为客户端，底部的主机重命名为服务器。这类似于互联网客户端试图在我们的网络中访问公司服务器。我们将再次使用共享平面网络选项来访问设备进行带外管理：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/2365022c-82e9-4928-ab1e-620b2e95b72c.png)

对于两个交换机，我将选择**开放最短路径优先**（**OSPF**）作为`IGP`，并将两个设备放入区域`0`。默认情况下，`BGP`已打开，并且两个设备都使用 AS 1。从配置自动生成中，连接到 Ubuntu 主机的接口被放入 OSPF 区域`1`，因此它们将显示为区间路由。NX-OSv 的配置如下所示，IOSv 的配置和输出类似：

```py
 interface Ethernet2/1
 description to iosv-1
 no switchport
 mac-address fa16.3e00.0001
 ip address 10.0.0.6/30
 ip router ospf 1 area 0.0.0.0
 no shutdown

 interface Ethernet2/2
 description to Client
 no switchport
 mac-address fa16.3e00.0002
 ip address 10.0.0.9/30
 ip router ospf 1 area 0.0.0.0
 no shutdown

 nx-osv-1# sh ip route
 <skip>
 10.0.0.12/30, ubest/mbest: 1/0
 *via 10.0.0.5, Eth2/1, [110/41], 04:53:02, ospf-1, intra
 192.168.0.2/32, ubest/mbest: 1/0
 *via 10.0.0.5, Eth2/1, [110/41], 04:53:02, ospf-1, intra
 <skip>
```

OSPF 邻居和 NX-OSv 的 BGP 输出如下所示，IOSv 的输出类似：

```py
nx-osv-1# sh ip ospf neighbors
 OSPF Process ID 1 VRF default
 Total number of neighbors: 1
 Neighbor ID Pri State Up Time Address Interface
 192.168.0.2 1 FULL/DR 04:53:00 10.0.0.5 Eth2/1

nx-osv-1# sh ip bgp summary
BGP summary information for VRF default, address family IPv4 Unicast
BGP router identifier 192.168.0.1, local AS number 1
BGP table version is 5, IPv4 Unicast config peers 1, capable peers 1
2 network entries and 2 paths using 288 bytes of memory
BGP attribute entries [2/288], BGP AS path entries [0/0]
BGP community entries [0/0], BGP clusterlist entries [0/0]

Neighbor V AS MsgRcvd MsgSent TblVer InQ OutQ Up/Down State/PfxRcd
192.168.0.2 4 1 321 297 5 0 0 04:52:56 1
```

我们网络中的主机正在运行 Ubuntu 14.04，与迄今为止我们一直在使用的 Ubuntu VM 16.04 类似：

```py
cisco@Server:~$ lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description: Ubuntu 14.04.2 LTS
Release: 14.04
Codename: trusty
```

在两台 Ubuntu 主机上，有两个网络接口，`eth0`和`eth1`。`eth0`连接到管理网络（`172.16.1.0/24`），而`eth1`连接到网络设备（`10.0.0.x/30`）。设备环回的路由直接连接到网络块，远程主机网络通过默认路由静态路由到`eth1`：

```py
cisco@Client:~$ route -n
Kernel IP routing table
Destination Gateway Genmask Flags Metric Ref Use Iface
0.0.0.0 172.16.1.2 0.0.0.0 UG 0 0 0 eth0
10.0.0.4 10.0.0.9 255.255.255.252 UG 0 0 0 eth1
10.0.0.8 0.0.0.0 255.255.255.252 U 0 0 0 eth1
10.0.0.8 10.0.0.9 255.255.255.248 UG 0 0 0 eth1
172.16.1.0 0.0.0.0 255.255.255.0 U 0 0 0 eth0
192.168.0.1 10.0.0.9 255.255.255.255 UGH 0 0 0 eth1
192.168.0.2 10.0.0.9 255.255.255.255 UGH 0 0 0 eth1
```

为了验证客户端到服务器的路径，让我们 ping 和跟踪路由，确保我们的主机之间的流量通过网络设备而不是默认路由：

```py
## Our server IP is 10.0.0.14 cisco@Server:~$ ifconfig
<skip>
eth1 Link encap:Ethernet HWaddr fa:16:3e:d6:83:02
 inet addr:10.0.0.14 Bcast:10.0.0.15 Mask:255.255.255.252

## From the client ping toward server
cisco@Client:~$ ping -c 1 10.0.0.14
PING 10.0.0.14 (10.0.0.14) 56(84) bytes of data.
64 bytes from 10.0.0.14: icmp_seq=1 ttl=62 time=6.22 ms

--- 10.0.0.14 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 6.223/6.223/6.223/0.000 ms

## Traceroute from client to server
cisco@Client:~$ traceroute 10.0.0.14
traceroute to 10.0.0.14 (10.0.0.14), 30 hops max, 60 byte packets
 1 10.0.0.9 (10.0.0.9) 11.335 ms 11.745 ms 12.113 ms
 2 10.0.0.5 (10.0.0.5) 24.221 ms 41.635 ms 41.638 ms
 3 10.0.0.14 (10.0.0.14) 37.916 ms 38.275 ms 38.588 ms
cisco@Client:~$
```

太好了！我们有了实验室，现在准备使用 Python 来查看一些安全工具和措施。

# Python Scapy

Scapy（[`scapy.net`](https://scapy.net/)）是一个功能强大的基于 Python 的交互式数据包构建程序。除了一些昂贵的商业程序外，据我所知，很少有工具可以做到 Scapy 所能做的。这是我在 Python 中最喜欢的工具之一。

Scapy 的主要优势在于它允许您从非常基本的级别构建自己的数据包。用 Scapy 的创作者的话来说：

“Scapy 是一个功能强大的交互式数据包操作程序。它能够伪造或解码大量协议的数据包，将它们发送到网络上，捕获它们，匹配请求和响应，等等……与大多数其他工具不同，您不会构建作者没有想象到的东西。这些工具是为了特定的目标而构建的，不能偏离太多。”

让我们来看看这个工具。

# 安装 Scapy

在撰写本文时，Scapy 2.3.1 支持 Python 2.7。不幸的是，关于 Scapy 对 Python 3 的支持出现了一些问题，对于 Scapy 2.3.3 来说，这仍然是相对较新的。对于您的环境，请随时尝试使用版本 2.3.3 及更高版本的 Python 3。在本章中，我们将使用 Python 2.7 的 Scapy 2.3.1。如果您想了解选择背后的原因，请参阅信息侧栏。

关于 Scapy 在 Python 3 中的支持的长篇故事是，2015 年有一个独立的 Scapy 分支，旨在仅支持 Python 3。该项目被命名为`Scapy3k`。该分支与主要的 Scapy 代码库分道扬镳。如果您阅读本书的第一版，那是写作时提供的信息。关于 PyPI 上的`python3-scapy`和 Scapy 代码库的官方支持存在混淆。我们的主要目的是在本章中了解 Scapy，因此我选择使用较旧的基于 Python 2 的 Scapy 版本。

在我们的实验室中，由于我们正在从客户端向目标服务器构建数据包源，因此需要在客户端上安装 Scapy：

```py
cisco@Client:~$ sudo apt-get update
cisco@Client:~$ sudo apt-get install git
cisco@Client:~$ git clone https://github.com/secdev/scapy
cisco@Client:~$ cd scapy/
cisco@Client:~/scapy$ sudo python setup.py install
```

这是一个快速测试，以确保软件包已正确安装：

```py
cisco@Client:~/scapy$ python
Python 2.7.6 (default, Mar 22 2014, 22:59:56)
[GCC 4.8.2] on linux2
Type "help", "copyright", "credits" or "license" for more information.
>>> from scapy.all import *
```

# 交互式示例

在我们的第一个示例中，我们将在客户端上构建一个**Internet 控制消息协议**（**ICMP**）数据包，并将其发送到服务器。在服务器端，我们将使用`tcpdump`和主机过滤器来查看传入的数据包：

```py
## Client Side
cisco@Client:~/scapy$ sudo scapy
<skip>
Welcome to Scapy (2.3.3.dev274)
>>> send(IP(dst="10.0.0.14")/ICMP())
.
Sent 1 packets.
>>>

## Server Side
cisco@Server:~$ sudo tcpdump -i eth1 host 10.0.0.10
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth1, link-type EN10MB (Ethernet), capture size 65535 bytes
02:45:16.400162 IP 10.0.0.10 > 10.0.0.14: ICMP echo request, id 0, seq 0, length 8
02:45:16.400192 IP 10.0.0.14 > 10.0.0.10: ICMP echo reply, id 0, seq 0, length 8
```

正如您所看到的，使用 Scapy 构建数据包非常简单。Scapy 允许您使用斜杠（`/`）作为分隔符逐层构建数据包。`send`函数在第 3 层级别操作，负责路由和第 2 层级别。还有一个`sendp()`替代方案，它在第 2 层级别操作，这意味着您需要指定接口和链路层协议。

让我们通过使用发送请求（`sr`）函数来捕获返回的数据包。我们使用`sr`的特殊变体，称为`sr1`，它只返回一个回答发送的数据包：

```py
>>> p = sr1(IP(dst="10.0.0.14")/ICMP())
>>> p
<IP version=4L ihl=5L tos=0x0 len=28 id=26713 flags= frag=0L ttl=62 proto=icmp chksum=0x71 src=10.0.0.14 dst=10.0.0.10 options=[] |<ICMP type=echo-reply code=0 chksum=0xffff id=0x0 seq=0x0 |>>
```

需要注意的一点是，`sr()`函数本身返回一个包含已回答和未回答列表的元组：

```py
>>> p = sr(IP(dst="10.0.0.14")/ICMP()) 
>>> type(p)
<type 'tuple'>

## unpacking
>>> ans,unans = sr(IP(dst="10.0.0.14")/ICMP())
>>> type(ans)
<class 'scapy.plist.SndRcvList'>
>>> type(unans)
<class 'scapy.plist.PacketList'>
```

如果我们只看已回答的数据包列表，我们可以看到它是另一个包含我们发送的数据包以及返回的数据包的元组：

```py
>>> for i in ans:
...     print(type(i))
...
<type 'tuple'>
>>> for i in ans:
...     print i
...
(<IP frag=0 proto=icmp dst=10.0.0.14 |<ICMP |>>, <IP version=4L ihl=5L tos=0x0 len=28 id=27062 flags= frag=0L ttl=62 proto=icmp chksum=0xff13 src=10.0.0.14 dst=10.0.0.10 options=[] |<ICMP type=echo-reply code=0 chksum=0xffff id=0x0 seq=0x0 |>>)
```

Scapy 还提供了一个第 7 层的构造，比如`DNS`查询。在下面的例子中，我们正在查询一个开放的 DNS 服务器来解析`www.google.com`：

```py
>>> p = sr1(IP(dst="8.8.8.8")/UDP()/DNS(rd=1,qd=DNSQR(qname="www.google.com")))
>>> p
<IP version=4L ihl=5L tos=0x0 len=76 id=21743 flags= frag=0L ttl=128 proto=udp chksum=0x27fa src=8.8.8.8 dst=172.16.1.152 options=[] |<UDP sport=domain dport=domain len=56 chksum=0xc077 |<DNS id=0 qr=1L opcode=QUERY aa=0L tc=0L rd=1L ra=1L z=0L ad=0L cd=0L rcode=ok qdcount=1 ancount=1 nscount=0 arcount=0 qd=<DNSQR qname='www.google.com.' qtype=A qclass=IN |> an=<DNSRR rrname='www.google.com.' type=A rclass=IN ttl=299 rdata='172.217.3.164' |> ns=None ar=None |>>>
>>>
```

# 嗅探

Scapy 还可以用于轻松捕获网络上的数据包：

```py
>>> a = sniff(filter="icmp and host 172.217.3.164", count=5)
>>> a.show()
0000 Ether / IP / TCP 192.168.225.146:ssh > 192.168.225.1:50862 PA / Raw
0001 Ether / IP / ICMP 192.168.225.146 > 172.217.3.164 echo-request 0 / Raw
0002 Ether / IP / ICMP 172.217.3.164 > 192.168.225.146 echo-reply 0 / Raw
0003 Ether / IP / ICMP 192.168.225.146 > 172.217.3.164 echo-request 0 / Raw
0004 Ether / IP / ICMP 172.217.3.164 > 192.168.225.146 echo-reply 0 / Raw
>>>
```

我们可以更详细地查看数据包，包括原始格式：

```py
>>> for i in a:
...     print i.show()
...
<skip>
###[ Ethernet ]###
 dst= <>
 src= <>
 type= 0x800
###[ IP ]###
 version= 4L
 ihl= 5L
 tos= 0x0
 len= 84
 id= 15714
 flags= DF
 frag= 0L
 ttl= 64
 proto= icmp
 chksum= 0xaa8e
 src= 192.168.225.146
 dst= 172.217.3.164
 options
###[ ICMP ]###
 type= echo-request
 code= 0
 chksum= 0xe1cf
 id= 0xaa67
 seq= 0x1
###[ Raw ]###
 load= 'xd6xbfxb1Xx00x00x00x00x1axdcnx00x00x00x00x00x10x11x12x13x14x15x16x17x18x19x1ax1bx1cx1dx1ex1f !"#$%&'()*+,-./01234567'
None
```

我们已经看到了 Scapy 的基本工作原理。让我们继续看看如何使用 Scapy 进行一些常见的安全测试。

# TCP 端口扫描

任何潜在黑客的第一步几乎总是尝试了解网络上开放的服务，这样他们就可以集中精力进行攻击。当然，我们需要打开某些端口以为客户提供服务；这是我们需要接受的风险的一部分。但我们还应该关闭任何不必要暴露更大攻击面的其他开放端口。我们可以使用 Scapy 对我们自己的主机进行简单的 TCP 开放端口扫描。

我们可以发送一个`SYN`数据包，看服务器是否会返回`SYN-ACK`：

```py
>>> p = sr1(IP(dst="10.0.0.14")/TCP(sport=666,dport=23,flags="S"))
>>> p.show()
###[ IP ]###
 version= 4L
 ihl= 5L
 tos= 0x0
 len= 40
 id= 25373
 flags= DF
 frag= 0L
 ttl= 62
 proto= tcp
 chksum= 0xc59b
 src= 10.0.0.14
 dst= 10.0.0.10
 options
###[ TCP ]###
 sport= telnet
 dport= 666
 seq= 0
 ack= 1
 dataofs= 5L
 reserved= 0L
 flags= RA
 window= 0
 chksum= 0x9907
 urgptr= 0
 options= {}
```

请注意，在这里的输出中，服务器对 TCP 端口`23`响应了`RESET+ACK`。然而，TCP 端口`22`（SSH）是开放的；因此返回了`SYN-ACK`：

```py
>>> p = sr1(IP(dst="10.0.0.14")/TCP(sport=666,dport=22,flags="S"))
>>> p.show()
###[ IP ]###
 version= 4L
<skip>
 proto= tcp
 chksum= 0x28b5
 src= 10.0.0.14
 dst= 10.0.0.10
 options
###[ TCP ]###
 sport= ssh
 dport= 666
<skip>
 flags= SA
<skip>
```

我们还可以扫描从`20`到`22`的一系列目标端口；请注意，我们使用`sr()`进行发送-接收，而不是`sr1()`发送-接收一个数据包的变体：

```py
>>> ans,unans = sr(IP(dst="10.0.0.14")/TCP(sport=666,dport=(20,22),flags="S"))
>>> for i in ans:
...     print i
...
(<IP frag=0 proto=tcp dst=10.0.0.14 |<TCP sport=666 dport=ftp_data flags=S |>>, <IP version=4L ihl=5L tos=0x0 len=40 id=4126 flags=DF frag=0L ttl=62 proto=tcp chksum=0x189b src=10.0.0.14 dst=10.0.0.10 options=[] |<TCP sport=ftp_data dport=666 seq=0 ack=1 dataofs=5L reserved=0L flags=RA window=0 chksum=0x990a urgptr=0 |>>)
(<IP frag=0 proto=tcp dst=10.0.0.14 |<TCP sport=666 dport=ftp flags=S |>>, <IP version=4L ihl=5L tos=0x0 len=40 id=4127 flags=DF frag=0L ttl=62 proto=tcp chksum=0x189a src=10.0.0.14 dst=10.0.0.10 options=[] |<TCP sport=ftp dport=666 seq=0 ack=1 dataofs=5L reserved=0L flags=RA window=0 chksum=0x9909 urgptr=0 |>>)
(<IP frag=0 proto=tcp dst=10.0.0.14 |<TCP sport=666 dport=ssh flags=S |>>, <IP version=4L ihl=5L tos=0x0 len=44 id=0 flags=DF frag=0L ttl=62 proto=tcp chksum=0x28b5 src=10.0.0.14 dst=10.0.0.10 options=[] |<TCP sport=ssh dport=666 seq=4187384571 ack=1 dataofs=6L reserved=0L flags=SA window=29200 chksum=0xaaab urgptr=0 options=[('MSS', 1460)] |>>)
>>>
```

我们还可以指定目标网络而不是单个主机。从`10.0.0.8/29`块中可以看到，主机`10.0.0.9`、`10.0.0.13`和`10.0.0.14`返回了`SA`，这对应于两个网络设备和主机：

```py
>>> ans,unans = sr(IP(dst="10.0.0.8/29")/TCP(sport=666,dport=(22),flags="S"))
>>> for i in ans:
...     print(i)
...
(<IP frag=0 proto=tcp dst=10.0.0.9 |<TCP sport=666 dport=ssh flags=S |>>, <IP version=4L ihl=5L tos=0x0 len=44 id=7304 flags= frag=0L ttl=64 proto=tcp chksum=0x4a32 src=10.0.0.9 dst=10.0.0.10 options=[] |<TCP sport=ssh dport=666 seq=541401209 ack=1 dataofs=6L reserved=0L flags=SA window=17292 chksum=0xfd18 urgptr=0 options=[('MSS', 1444)] |>>)
(<IP frag=0 proto=tcp dst=10.0.0.14 |<TCP sport=666 dport=ssh flags=S |>>, <IP version=4L ihl=5L tos=0x0 len=44 id=0 flags=DF frag=0L ttl=62 proto=tcp chksum=0x28b5 src=10.0.0.14 dst=10.0.0.10 options=[] |<TCP sport=ssh dport=666 seq=4222593330 ack=1 dataofs=6L reserved=0L flags=SA window=29200 chksum=0x6a5b urgptr=0 options=[('MSS', 1460)] |>>)
(<IP frag=0 proto=tcp dst=10.0.0.13 |<TCP sport=666 dport=ssh flags=S |>>, <IP version=4L ihl=5L tos=0x0 len=44 id=41992 flags= frag=0L ttl=254 proto=tcp chksum=0x4ad src=10.0.0.13 dst=10.0.0.10 options=[] |<TCP sport=ssh dport=666 seq=2167267659 ack=1 dataofs=6L reserved=0L flags=SA window=4128 chksum=0x1252 urgptr=0 options=[('MSS', 536)] |>>)
```

根据我们迄今为止学到的知识，我们可以编写一个简单的可重用脚本`scapy_tcp_scan_1.py`。我们从建议的导入`scapy`和`sys`模块开始，用于接收参数：

```py
  #!/usr/bin/env python2

  from scapy.all import *
  import sys
```

`tcp_scan()`函数与我们到目前为止看到的类似：

```py
  def tcp_scan(destination, dport):
      ans, unans = sr(IP(dst=destination)/TCP(sport=666,dport=dport,flags="S"))
      for sending, returned in ans:
          if 'SA' in str(returned[TCP].flags):
              return destination + " port " + str(sending[TCP].dport) + " is open"
          else:
              return destination + " port " + str(sending[TCP].dport) + " is not open"
```

然后我们可以从参数中获取输入，然后在`main()`中调用`tcp_scan()`函数：

```py
  def main():
      destination = sys.argv[1]
      port = int(sys.argv[2])
      scan_result = tcp_scan(destination, port)
      print(scan_result)

  if __name__ == "__main__":
      main()
```

请记住，访问低级网络需要 root 访问权限；因此，我们的脚本需要以`sudo`执行：

```py
cisco@Client:~$ sudo python scapy_tcp_scan_1.py "10.0.0.14" 23
<skip>
10.0.0.14 port 23 is not open
cisco@Client:~$ sudo python scapy_tcp_scan_1.py "10.0.0.14" 22
<skip>
10.0.0.14 port 22 is open
```

这是一个相对较长的 TCP 扫描脚本示例，演示了使用 Scapy 构建自己的数据包的能力。我们在交互式 shell 中测试了这些步骤，并用一个简单的脚本完成了使用。让我们看看 Scapy 在安全测试中的一些更多用法。

# Ping 集合

假设我们的网络包含 Windows、Unix 和 Linux 机器的混合，用户添加了自己的**自带设备**（**BYOD**）；他们可能支持也可能不支持 ICMP ping。我们现在可以构建一个文件，其中包含我们网络中三种常见 ping 的 ICMP、TCP 和 UDP ping，在`scapy_ping_collection.py`中*：*

```py
#!/usr/bin/env python2

from scapy.all import *

def icmp_ping(destination):
    # regular ICMP ping
    ans, unans = sr(IP(dst=destination)/ICMP())
    return ans

def tcp_ping(destination, dport):
    # TCP SYN Scan
    ans, unans = sr(IP(dst=destination)/TCP(dport=dport,flags="S"))
    return ans

def udp_ping(destination):
    # ICMP Port unreachable error from closed port
    ans, unans = sr(IP(dst=destination)/UDP(dport=0))
    return ans
```

在这个例子中，我们还将使用`summary()`和`sprintf()`进行输出：

```py
def answer_summary(answer_list):
 # example of lambda with pretty print
    answer_list.summary(lambda(s, r): r.sprintf("%IP.src% is alive"))
```

如果你想知道为什么在前面的`answer_summary()`函数中有一个 lambda，那是一种创建小型匿名函数的方法。基本上，它是一个没有名字的函数。关于它的更多信息可以在[`docs.python.org/3.5/tutorial/controlflow.html#lambda-expressions`](https://docs.python.org/3.5/tutorial/controlflow.html#lambda-expressions)找到。

然后我们可以在一个脚本中执行网络上的三种 ping 类型：

```py
def main():
    print("** ICMP Ping **")
    ans = icmp_ping("10.0.0.13-14")
    answer_summary(ans)
    print("** TCP Ping **")
    ans = tcp_ping("10.0.0.13", 22)
    answer_summary(ans)
    print("** UDP Ping **")
    ans = udp_ping("10.0.0.13-14")
    answer_summary(ans)

if __name__ == "__main__":
    main()
```

到目前为止，希望你会同意我的观点，通过拥有构建自己的数据包的能力，你可以控制你想要运行的操作和测试的类型。

# 常见攻击

在这个例子中，让我们看看如何构造我们的数据包来进行一些经典攻击，比如*Ping of Death* ([`en.wikipedia.org/wiki/Ping_of_death`](https://en.wikipedia.org/wiki/Ping_of_death)) 和 *Land Attack* ([`en.wikipedia.org/wiki/Denial-of-service_attack`](https://en.wikipedia.org/wiki/Denial-of-service_attack))。这可能是您以前必须使用类似的商业软件付费的网络渗透测试。使用 Scapy，您可以在保持完全控制的同时进行测试，并在将来添加更多测试。

第一次攻击基本上发送了一个带有虚假 IP 头的目标主机，例如长度为 2 和 IP 版本 3：

```py
def malformed_packet_attack(host):
    send(IP(dst=host, ihl=2, version=3)/ICMP()) 
```

`ping_of_death_attack`由常规的 ICMP 数据包组成，其负载大于 65,535 字节：

```py
def ping_of_death_attack(host):
    # https://en.wikipedia.org/wiki/Ping_of_death
    send(fragment(IP(dst=host)/ICMP()/("X"*60000)))
```

`land_attack`想要将客户端响应重定向回客户端本身，并耗尽主机的资源：

```py
  def land_attack(host):
      # https://en.wikipedia.org/wiki/Denial-of-service_attack
      send(IP(src=host, dst=host)/TCP(sport=135,dport=135))
```

这些都是相当古老的漏洞或经典攻击，现代操作系统不再容易受到攻击。对于我们的 Ubuntu 14.04 主机，前面提到的攻击都不会使其崩溃。然而，随着发现更多安全问题，Scapy 是一个很好的工具，可以开始对我们自己的网络和主机进行测试，而不必等待受影响的供应商提供验证工具。这对于零日（未经事先通知发布的）攻击似乎在互联网上变得越来越常见尤其如此。 

# Scapy 资源

我们在本章中花了相当多的精力来使用 Scapy。这在一定程度上是因为我个人对这个工具的高度评价。我希望你同意 Scapy 是网络工程师工具箱中必备的伟大工具。Scapy 最好的部分是它在一个积极参与的用户社区的不断发展。

我强烈建议至少阅读 Scapy 教程 [`scapy.readthedocs.io/en/latest/usage.html#interactive-tutorial`](http://scapy.readthedocs.io/en/latest/usage.html#interactive-tutorial)，以及您感兴趣的任何文档。

# 访问列表

网络访问列表通常是防范外部入侵和攻击的第一道防线。一般来说，路由器和交换机的数据包处理速度要比服务器快得多，因为它们利用硬件，如**三态内容可寻址存储器**（**TCAM**）。它们不需要查看应用层信息，而只需检查第 3 层和第 4 层信息，并决定是否可以转发数据包。因此，我们通常将网络设备访问列表用作保护网络资源的第一步。

作为一个经验法则，我们希望将访问列表尽可能靠近源（客户端）。因此，我们也相信内部主机，不信任我们网络边界之外的客户端。因此，访问列表通常放置在外部网络接口的入站方向上。在我们的实验场景中，这意味着我们将在直接连接到客户端主机的 Ethernet2/2 上放置一个入站访问列表。

如果您不确定访问列表的方向和位置，以下几点可能会有所帮助：

+   从网络设备的角度考虑访问列表

+   简化数据包，只涉及源和目的地 IP，并以一个主机为例：

+   在我们的实验室中，来自我们服务器的流量将具有源 IP`10.0.0.14`和目的 IP`10.0.0.10`

+   来自客户端的流量将具有源 IP`10.10.10.10`和目的 IP`10.0.0.14`

显然，每个网络都是不同的，访问列表的构建方式取决于服务器提供的服务。但作为入站边界访问列表，您应该执行以下操作：

+   拒绝 RFC 3030 特殊使用地址源，如`127.0.0.0/8`

+   拒绝 RFC 1918 空间，如`10.0.0.0/8`

+   拒绝我们自己的空间作为源 IP；在这种情况下，`10.0.0.12/30`

+   允许入站 TCP 端口`22`（SSH）和`80`（HTTP）到主机`10.0.0.14`

+   拒绝其他所有内容

# 使用 Ansible 实现访问列表

实现此访问列表的最简单方法是使用 Ansible。我们在过去的两章中已经看过 Ansible，但值得重申在这种情况下使用 Ansible 的优势：

+   **更容易管理**：对于长访问列表，我们可以利用`include`语句将其分解为更易管理的部分。然后其他团队或服务所有者可以管理这些较小的部分。

+   **幂等性**：我们可以定期安排 playbook，并且只会进行必要的更改。

+   **每个任务都是明确的**：我们可以分开构造条目以及将访问列表应用到正确的接口。

+   **可重用性**：将来，如果我们添加额外的面向外部的接口，我们只需要将设备添加到访问列表的设备列表中。

+   **可扩展性**：您会注意到我们可以使用相同的 playbook 来构建访问列表并将其应用到正确的接口。我们可以从小处开始，根据需要在将来扩展到单独的 playbook。

主机文件非常标准。为简单起见，我们直接将主机变量放在清单文件中：

```py
[nxosv-devices]
nx-osv-1 ansible_host=172.16.1.155 ansible_username=cisco ansible_password=cisco
```

我们暂时将在 playbook 中声明变量：

```py
---
- name: Configure Access List
  hosts: "nxosv-devices"
  gather_facts: false
  connection: local

  vars:
    cli:
      host: "{{ ansible_host }}"
      username: "{{ ansible_username }}"
      password: "{{ ansible_password }}"
      transport: cli
```

为了节省空间，我们将仅说明拒绝 RFC 1918 空间。实施拒绝 RFC 3030 和我们自己的空间将与用于 RFC 1918 空间的步骤相同。请注意，我们在 playbook 中没有拒绝`10.0.0.0/8`，因为我们当前的配置使用了`10.0.0.0`网络进行寻址。当然，我们可以首先执行单个主机许可，然后在以后的条目中拒绝`10.0.0.0/8`，但在这个例子中，我们选择忽略它：

```py
tasks:
  - nxos_acl:
      name: border_inbound
      seq: 20
      action: deny
      proto: tcp
      src: 172.16.0.0/12
      dest: any
      log: enable
      state: present
      provider: "{{ cli }}"
  - nxos_acl:
      name: border_inbound
      seq: 40
      action: permit
      proto: tcp
      src: any
      dest: 10.0.0.14/32
      dest_port_op: eq
      dest_port1: 22
      state: present
      log: enable
      provider: "{{ cli }}"
  - nxos_acl:
      name: border_inbound
      seq: 50
      action: permit
      proto: tcp
      src: any
      dest: 10.0.0.14/32
      dest_port_op: eq
      dest_port1: 80
      state: present
      log: enable
      provider: "{{ cli }}"
  - nxos_acl:
      name: border_inbound
      seq: 60
      action: permit
      proto: tcp
      src: any
      dest: any
      state: present
      log: enable
      established: enable
      provider: "{{ cli }}"
  - nxos_acl:
      name: border_inbound
      seq: 1000
      action: deny
      proto: ip
      src: any
      dest: any
      state: present
      log: enable
      provider: "{{ cli }}"
```

请注意，我们允许来自内部服务器的已建立连接返回。我们使用最终的显式`deny ip any any`语句作为高序号（`1000`），因此我们可以随后插入任何新条目。

然后我们可以将访问列表应用到正确的接口上：

```py
- name: apply ingress acl to Ethernet 2/2
  nxos_acl_interface:
    name: border_inbound
    interface: Ethernet2/2
    direction: ingress
    state: present
    provider: "{{ cli }}"
```

VIRL NX-OSv 上的访问列表仅支持管理接口。您将看到此警告：警告：ACL 可能不会按预期行为，因为只支持管理接口，如果您通过 CLI 配置此`ACL`。这个警告没问题，因为我们的目的只是演示访问列表的配置自动化。

对于单个访问列表来说，这可能看起来是很多工作。对于有经验的工程师来说，使用 Ansible 执行此任务将比只是登录设备并配置访问列表需要更长的时间。但是，请记住，这个 playbook 可以在将来多次重复使用，因此从长远来看可以节省时间。

根据我的经验，通常情况下，长访问列表中的一些条目将用于一个服务，另一些条目将用于另一个服务，依此类推。访问列表往往会随着时间的推移而有机地增长，很难跟踪每个条目的来源和目的。我们可以将它们分开，从而使长访问列表的管理变得更简单。

# MAC 访问列表

在 L2 环境或在以太网接口上使用非 IP 协议的情况下，您仍然可以使用 MAC 地址访问列表来允许或拒绝基于 MAC 地址的主机。步骤与 IP 访问列表类似，但匹配将基于 MAC 地址。请记住，对于 MAC 地址或物理地址，前六个十六进制符号属于**组织唯一标识符**（**OUI**）。因此，我们可以使用相同的访问列表匹配模式来拒绝某个主机组。

我们正在使用`ios_config`模块在 IOSv 上进行测试。对于较旧的 Ansible 版本，更改将在每次执行 playbook 时推送出去。对于较新的 Ansible 版本，控制节点将首先检查更改，并且只在需要时进行更改。

主机文件和 playbook 的顶部部分与 IP 访问列表类似；`tasks`部分是使用不同模块和参数的地方：

```py
<skip>
  tasks:
    - name: Deny Hosts with vendor id fa16.3e00.0000
      ios_config:
        lines:
          - access-list 700 deny fa16.3e00.0000 0000.00FF.FFFF
          - access-list 700 permit 0000.0000.0000 FFFF.FFFF.FFFF
        provider: "{{ cli }}"
    - name: Apply filter on bridge group 1
      ios_config:
        lines:
          - bridge-group 1
          - bridge-group 1 input-address-list 700
        parents:
          - interface GigabitEthernet0/1
        provider: "{{ cli }}"   
```

随着越来越多的虚拟网络变得流行，L3 信息有时对底层虚拟链接变得透明。在这些情况下，如果您需要限制对这些链接的访问，MAC 访问列表成为一个很好的选择。

# Syslog 搜索

有大量记录的网络安全漏洞发生在较长的时间内。在这些缓慢的漏洞中，我们经常看到日志中有可疑活动的迹象。这些迹象可以在服务器和网络设备的日志中找到。这些活动之所以没有被检测到，不是因为信息不足，而是因为信息太多。我们正在寻找的关键信息通常深藏在难以整理的大量信息中。

除了 Syslog，**Uncomplicated Firewall**（**UFW**）是服务器日志信息的另一个很好的来源。它是 iptables 的前端，是一个服务器防火墙。UFW 使管理防火墙规则变得非常简单，并记录了大量信息。有关 UFW 的更多信息，请参阅*其他工具*部分。

在这一部分，我们将尝试使用 Python 搜索 Syslog 文本，以便检测我们正在寻找的活动。当然，我们将搜索的确切术语取决于我们使用的设备。例如，思科提供了一个在 Syslog 中查找任何访问列表违规日志的消息列表。它可以在[`www.cisco.com/c/en/us/about/security-center/identify-incidents-via-syslog.html`](http://www.cisco.com/c/en/us/about/security-center/identify-incidents-via-syslog.html)上找到。

要更好地理解访问控制列表日志记录，请访问[`www.cisco.com/c/en/us/about/security-center/access-control-list-logging.html`](http://www.cisco.com/c/en/us/about/security-center/access-control-list-logging.html)。

对于我们的练习，我们将使用一个包含大约 65,000 行日志消息的 Nexus 交换机匿名 Syslog 文件，该文件已包含在适应书籍 GitHub 存储库中供您使用：

```py
$ wc -l sample_log_anonymized.log
65102 sample_log_anonymized.log
```

我们已经插入了一些来自思科文档（[`www.cisco.com/c/en/us/support/docs/switches/nexus-7000-series-switches/118907-configure-nx7k-00.html`](http://www.cisco.com/c/en/us/support/docs/switches/nexus-7000-series-switches/118907-configure-nx7k-00.html) ）的 Syslog 消息作为我们应该寻找的日志消息：

```py
2014 Jun 29 19:20:57 Nexus-7000 %VSHD-5-VSHD_SYSLOG_CONFIG_I: Configured from vty by admin on console0
2014 Jun 29 19:21:18 Nexus-7000 %ACLLOG-5-ACLLOG_FLOW_INTERVAL: Src IP: 10.1 0.10.1,
 Dst IP: 172.16.10.10, Src Port: 0, Dst Port: 0, Src Intf: Ethernet4/1, Pro tocol: "ICMP"(1), Hit-count = 2589
2014 Jun 29 19:26:18 Nexus-7000 %ACLLOG-5-ACLLOG_FLOW_INTERVAL: Src IP: 10.1 0.10.1, Dst IP: 172.16.10.10, Src Port: 0, Dst Port: 0, Src Intf: Ethernet4/1, Pro tocol: "ICMP"(1), Hit-count = 4561
```

我们将使用简单的正则表达式示例。如果您已经熟悉 Python 中的正则表达式，请随时跳过本节的其余部分。

# 使用 RE 模块进行搜索

对于我们的第一个搜索，我们将简单地使用正则表达式模块来查找我们正在寻找的术语。我们将使用一个简单的循环来进行以下操作：

```py
#!/usr/bin/env python3

import re, datetime

startTime = datetime.datetime.now()

with open('sample_log_anonymized.log', 'r') as f:
   for line in f.readlines():
       if re.search('ACLLOG-5-ACLLOG_FLOW_INTERVAL', line):
           print(line)

endTime = datetime.datetime.now()
elapsedTime = endTime - startTime
print("Time Elapsed: " + str(elapsedTime))
```

搜索日志文件大约花了 6/100 秒的时间：

```py
$ python3 python_re_search_1.py
2014 Jun 29 19:21:18 Nexus-7000 %ACLLOG-5-ACLLOG_FLOW_INTERVAL: Src IP: 10.1 0.10.1,

2014 Jun 29 19:26:18 Nexus-7000 %ACLLOG-5-ACLLOG_FLOW_INTERVAL: Src IP: 10.1 0.10.1,

Time Elapsed: 0:00:00.065436
```

建议编译搜索术语以进行更有效的搜索。这不会对我们产生太大影响，因为脚本已经非常快速。实际上，Python 的解释性特性可能会使其变慢。但是，当我们搜索更大的文本主体时，这将产生影响，所以让我们做出改变：

```py
searchTerm = re.compile('ACLLOG-5-ACLLOG_FLOW_INTERVAL')

with open('sample_log_anonymized.log', 'r') as f:
   for line in f.readlines():
       if re.search(searchTerm, line):
           print(line)
```

时间结果实际上更慢：

```py
Time Elapsed: 0:00:00.081541
```

让我们扩展一下这个例子。假设我们有几个文件和多个要搜索的术语，我们将把原始文件复制到一个新文件中：

```py
$ cp sample_log_anonymized.log sample_log_anonymized_1.log
```

我们还将包括搜索`PAM: Authentication failure`术语。我们将添加另一个循环来搜索这两个文件：

```py
term1 = re.compile('ACLLOG-5-ACLLOG_FLOW_INTERVAL')
term2 = re.compile('PAM: Authentication failure')

fileList = ['sample_log_anonymized.log', 'sample_log_anonymized_1.log']

for log in fileList:
    with open(log, 'r') as f:
       for line in f.readlines():
           if re.search(term1, line) or re.search(term2, line):
               print(line) 
```

通过扩展我们的搜索术语和消息数量，我们现在可以看到性能上的差异：

```py
$ python3 python_re_search_2.py
2016 Jun 5 16:49:33 NEXUS-A %DAEMON-3-SYSTEM_MSG: error: PAM: Authentication failure for illegal user AAA from 172.16.20.170 - sshd[4425]

2016 Sep 14 22:52:26.210 NEXUS-A %DAEMON-3-SYSTEM_MSG: error: PAM: Authentication failure for illegal user AAA from 172.16.20.170 - sshd[2811]

<skip>

2014 Jun 29 19:21:18 Nexus-7000 %ACLLOG-5-ACLLOG_FLOW_INTERVAL: Src IP: 10.1 0.10.1,

2014 Jun 29 19:26:18 Nexus-7000 %ACLLOG-5-ACLLOG_FLOW_INTERVAL: Src IP: 10.1 0.10.1,

<skip>

Time Elapsed: 0:00:00.330697
```

当涉及性能调优时，这是一个永无止境的、不可能达到零的竞赛，性能有时取决于您使用的硬件。但重要的是定期使用 Python 对日志文件进行审计，这样您就可以捕捉到任何潜在违规的早期信号。

# 其他工具

还有其他网络安全工具可以使用 Python 进行自动化。让我们看看其中一些。

# 私有 VLAN

**虚拟局域网**（**VLANs**）已经存在很长时间了。它们本质上是一个广播域，所有主机都可以连接到一个交换机，但被划分到不同的域，所以我们可以根据哪个主机可以通过广播看到其他主机来分隔主机。让我们看一个基于 IP 子网的映射。例如，在企业大楼中，我可能会看到每个物理楼层一个 IP 子网：第一层的`192.168.1.0/24`，第二层的`192.168.2.0/24`，依此类推。在这种模式下，我们为每个楼层使用 1/24 块。这清晰地划分了我的物理网络和逻辑网络。想要与自己的子网之外通信的主机将需要通过其第 3 层网关，我可以使用访问列表来强制执行安全性。

当不同部门位于同一楼层时会发生什么？也许财务和销售团队都在二楼，我不希望销售团队的主机与财务团队的主机在同一个广播域中。我可以进一步分割子网，但这可能变得乏味，并且会破坏先前设置的标准子网方案。这就是私有 VLAN 可以帮助的地方。

私有 VLAN 本质上将现有的 VLAN 分成子 VLAN。私有 VLAN 中有三个类别：

+   **混杂（P）端口**：此端口允许从 VLAN 上的任何其他端口发送和接收第 2 层帧；这通常属于连接到第 3 层路由器的端口

+   **隔离（I）端口**：此端口只允许与 P 端口通信，并且它们通常连接到主机，当您不希望它与同一 VLAN 中的其他主机通信时

+   **社区（C）端口**：此端口允许与同一社区中的其他 C 端口和 P 端口通信

我们可以再次使用 Ansible 或迄今为止介绍的任何其他 Python 脚本来完成这项任务。到目前为止，我们应该有足够的练习和信心通过自动化来实现这个功能，所以我不会在这里重复步骤。在需要进一步隔离 L2 VLAN 中的端口时，了解私有 VLAN 功能将会很有用。

# 使用 Python 的 UFW

我们简要提到了 UFW 作为 Ubuntu 主机上 iptables 的前端。以下是一个快速概述：

```py
$ sudo apt-get install ufw
$ sudo ufw status
$ sudo ufw default outgoing
$ sudo ufw allow 22/tcp
$ sudo ufw allow www
$ sudo ufw default deny incoming
```

我们可以查看 UFW 的状态：

```py
$ sudo ufw status verbose
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To Action From
-- ------ ----
22/tcp ALLOW IN Anywhere
80/tcp ALLOW IN Anywhere
22/tcp (v6) ALLOW IN Anywhere (v6)
80/tcp (v6) ALLOW IN Anywhere (v6)
```

正如您所看到的，UFW 的优势在于提供一个简单的界面来构建否则复杂的 IP 表规则。有几个与 UFW 相关的 Python 工具可以使事情变得更简单：

+   我们可以使用 Ansible UFW 模块来简化我们的操作。更多信息请访问[`docs.ansible.com/ansible/ufw_module.html`](http://docs.ansible.com/ansible/ufw_module.html)。因为 Ansible 是用 Python 编写的，我们可以进一步检查 Python 模块源代码中的内容。更多信息请访问[`github.com/ansible/ansible/blob/devel/lib/ansible/modules/system/ufw.py.`](https://github.com/ansible/ansible/blob/devel/lib/ansible/modules/system/ufw.py)

+   有 Python 包装器模块围绕 UFW 作为 API（访问[`gitlab.com/dhj/easyufw`](https://gitlab.com/dhj/easyufw)）。如果您需要根据某些事件动态修改 UFW 规则，这可以使集成变得更容易。

+   UFW 本身是用 Python 编写的。因此，如果您需要扩展当前的命令集，可以使用现有的 Python 知识。更多信息请访问[`launchpad.net/ufw`](https://launchpad.net/ufw)。

UFW 被证明是保护您的网络服务器的好工具。

# 进一步阅读

Python 是许多安全相关领域中常用的语言。我推荐的一些书籍如下：

+   **暴力 Python**：T.J. O'Connor 编写的黑客、取证分析师、渗透测试人员和安全工程师的食谱（ISBN-10：1597499579）

+   **黑帽 Python**：Justin Seitz 编写的黑客和渗透测试人员的 Python 编程（ISBN-10：1593275900）

我个人在 A10 Networks 的**分布式拒绝服务**（**DDoS**）研究工作中广泛使用 Python。如果您有兴趣了解更多信息，可以免费下载指南：[`www.a10networks.com/resources/ebooks/distributed-denial-service-ddos`](https://www.a10networks.com/resources/ebooks/distributed-denial-service-ddos)。

# 总结

在本章中，我们使用 Python 进行了网络安全研究。我们使用 Cisco VIRL 工具在实验室中设置了主机和网络设备，包括 NX-OSv 和 IOSv 类型。我们对 Scapy 进行了介绍，它允许我们从头开始构建数据包。Scapy 可以在交互模式下进行快速测试。在交互模式完成后，我们可以将步骤放入文件进行更可扩展的测试。它可以用于执行已知漏洞的各种网络渗透测试。

我们还研究了如何使用 IP 访问列表和 MAC 访问列表来保护我们的网络。它们通常是我们网络保护的第一道防线。使用 Ansible，我们能够一致快速地部署访问列表到多个设备。

Syslog 和其他日志文件包含有用的信息，我们应该定期查看以检测任何早期入侵的迹象。使用 Python 正则表达式，我们可以系统地搜索已知的日志条目，这些条目可以指引我们注意的安全事件。除了我们讨论过的工具之外，私有 VLAN 和 UFW 是我们可以用于更多安全保护的其他一些有用工具。

在第七章中，*使用 Python 进行网络监控-第 1 部分*，我们将看看如何使用 Python 进行网络监控。监控可以让我们了解网络中正在发生的事情以及网络的状态。


# 第七章：使用 Python 进行网络监控-第 1 部分

想象一下，你在凌晨 2 点接到一个电话。电话那头的人说：“嗨，我们遇到了一个影响生产服务的困难问题。我们怀疑可能与网络有关。你能帮我们检查一下吗？”对于这种紧急的、开放式的问题，你会做什么？大多数情况下，脑海中浮现的第一件事是：在网络正常运行到出现问题之间发生了什么变化？很可能你会检查你的监控工具，看看最近几个小时内是否有任何关键指标发生了变化。更好的是，如果你收到了任何与指标基线偏差相关的监控警报。

在本书中，我们一直在讨论系统地对网络进行可预测的更改的各种方法，目标是尽可能使网络运行顺畅。然而，网络并不是静态的-远非如此-它们可能是整个基础设施中最流动的部分之一。根据定义，网络连接了基础设施的不同部分，不断地来回传递流量。有很多移动的部分可能导致您的网络停止按预期工作：硬件故障、软件错误、尽管有最好的意图，人为错误，等等。问题不在于事情是否会出错，而在于当它发生时，出了什么问题。我们需要监控我们的网络，以确保它按预期工作，并希望在它不按预期工作时得到通知。

在接下来的两章中，我们将看一些执行网络监控任务的各种方法。到目前为止，我们看到的许多工具可以通过 Python 进行绑定或直接管理。和我们看到的许多工具一样，网络监控涉及两个部分。首先，我们需要知道设备能够传输什么信息。其次，我们需要确定我们可以从中解释出什么有用的信息。

我们将看一些工具，让我们能够有效地监控网络：

+   **简单网络管理协议**（**SNMP**）

+   Matplotlib 和 Pygal 可视化

+   MRTG 和 Cacti

这个列表并不详尽，网络监控领域显然没有缺乏商业供应商。然而，我们将要看的网络监控基础知识对于开源和商业工具都适用。

# 实验室设置

本章的实验室与第六章中的实验室类似，*使用 Python 进行网络安全*，但有一个区别：网络设备都是 IOSv 设备。以下是这一点的说明：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/5e51171c-d3e7-46ad-b1bc-1d0afade785a.png)

两台 Ubuntu 主机将用于在网络中生成流量，以便我们可以查看一些非零计数器。

# SNMP

SNMP 是一种标准化的协议，用于收集和管理设备。尽管该标准允许你使用 SNMP 进行设备管理，但根据我的经验，大多数网络管理员更喜欢将 SNMP 仅作为信息收集机制。由于 SNMP 在 UDP 上运行，UDP 是无连接的，并且考虑到版本 1 和 2 中相对较弱的安全机制，通过 SNMP 进行设备更改往往会让网络运营商感到有些不安。SNMP 版本 3 增加了加密安全性和协议的新概念和术语，但技术的适应方式在网络设备供应商之间存在差异。

SNMP 在网络监控中被广泛使用，自 1988 年作为 RFC 1065 的一部分以来一直存在。操作很简单，网络管理器向设备发送`GET`和`SET`请求，设备与 SNMP 代理响应每个请求的信息。最广泛采用的标准是 SNMPv2c，定义在 RFC 1901 - RFC 1908 中。它使用简单的基于社区的安全方案进行安全。它还引入了新功能，例如获取批量信息的能力。以下图显示了 SNMP 的高级操作：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/c3503470-34a9-43fc-8986-07ffaa47eb09.png)SNMP 操作

设备中的信息存储在**管理信息库**（**MIB**）中。MIB 使用包含**对象标识符**（**OID**）的分层命名空间，表示可以读取并反馈给请求者的信息。当我们谈论使用 SNMP 查询设备信息时，我们实际上是在谈论使用管理站点查询代表我们所需信息的特定 OID。有一个常见的 OID 结构，例如系统和接口 OID，这在供应商之间是共享的。除了常见的 OID，每个供应商还可以提供特定于他们的企业级 OID。

作为操作员，您需要努力将信息整合到环境中的 OID 结构中，以检索有用的信息。有时这可能是一个繁琐的过程，一次找到一个 OID。例如，您可能会向设备 OID 发出请求，并收到一个值为 10,000。那个值是什么？那是接口流量吗？是字节还是位？或者可能是数据包的数量？我们怎么知道？我们需要查阅标准或供应商文档才能找到答案。有一些工具可以帮助这个过程，比如 MIB 浏览器可以为值提供更多的元数据。但至少在我的经验中，为您的网络构建基于 SNMP 的监控工具有时会感觉像是一场猫鼠游戏，试图找到那个缺失的值。

从操作中可以得出一些要点：

+   实施严重依赖设备代理提供的信息量。这又取决于供应商如何对待 SNMP：作为核心功能还是附加功能。

+   SNMP 代理通常需要来自控制平面的 CPU 周期来返回一个值。这不仅对于具有大型 BGP 表的设备效率低下，而且在小间隔内使用 SNMP 查询数据也是不可行的。

+   用户需要知道 OID 才能查询数据。

由于 SNMP 已经存在一段时间，我假设您已经有了一些经验。让我们直接跳到软件包安装和我们的第一个 SNMP 示例。

# 设置

首先，让我们确保我们的设置中有 SNMP 管理设备和代理工作。SNMP 捆绑包可以安装在我们实验室中的主机（客户端或服务器）或管理网络上的管理设备上。只要 SNMP 管理器可以通过 IP 与设备通信，并且受管设备允许入站连接，SNMP 就可以工作。在生产中，您应该只在管理主机上安装软件，并且只允许控制平面中的 SNMP 流量。

在这个实验中，我们在管理网络上的 Ubuntu 主机和实验室中的客户端主机上都安装了 SNMP 以测试安全性：

```py
$ sudo apt-get install snmp
```

下一步将是在网络设备`iosv-1`和`iosv-2`上打开和配置 SNMP 选项。您可以在网络设备上配置许多可选参数，例如联系人、位置、机箱 ID 和 SNMP 数据包大小。这些选项是特定于设备的，您应该查看设备的文档。对于 IOSv 设备，我们将配置一个访问列表，以限制只有所需的主机可以查询设备，并将访问列表与 SNMP 社区字符串绑定。在我们的情况下，我们将使用`secret`作为只读社区字符串，`permit_snmp`作为访问列表名称。

```py
!
ip access-list standard permit_snmp
 permit 172.16.1.173 log
 deny any log
!
!
snmp-server community secret RO permit_snmp
!
```

SNMP 社区字符串充当管理器和代理之间的共享密码；因此，每次要查询设备时都需要包含它。

正如本章前面提到的，与 SNMP 一起工作时找到正确的 OID 往往是战斗的一半。我们可以使用诸如思科 IOS MIB 定位器（[`tools.cisco.com/ITDIT/MIBS/servlet/index`](http://tools.cisco.com/ITDIT/MIBS/servlet/index)）这样的工具来查找要查询的特定 OID。或者，我们可以从 Cisco 企业树的顶部`.1.3.6.1.4.1.9`开始遍历 SNMP 树。我们将执行遍历以确保 SNMP 代理和访问列表正在工作：

```py
$ snmpwalk -v2c -c secret 172.16.1.189 .1.3.6.1.4.1.9
iso.3.6.1.4.1.9.2.1.1.0 = STRING: "
Bootstrap program is IOSv
"
iso.3.6.1.4.1.9.2.1.2.0 = STRING: "reload" iso.3.6.1.4.1.9.2.1.3.0 = STRING: "iosv-1"
iso.3.6.1.4.1.9.2.1.4.0 = STRING: "virl.info"
...
```

我们还可以更具体地说明我们需要查询的 OID：

```py
$ snmpwalk -v2c -c secret 172.16.1.189 .1.3.6.1.4.1.9.2.1.61.0
iso.3.6.1.4.1.9.2.1.61.0 = STRING: "cisco Systems, Inc.
170 West Tasman Dr.
San Jose, CA 95134-1706
U.S.A.
Ph +1-408-526-4000
Customer service 1-800-553-6387 or +1-408-526-7208
24HR Emergency 1-800-553-2447 or +1-408-526-7209
Email Address tac@cisco.com
World Wide Web http://www.cisco.com"
```

作为演示，如果我们在最后一个 OID 的末尾输入错误的值，例如从`0`到`1`的`1`位数，我们会看到这样的情况：

```py
$ snmpwalk -v2c -c secret 172.16.1.189 .1.3.6.1.4.1.9.2.1.61.1
iso.3.6.1.4.1.9.2.1.61.1 = No Such Instance currently exists at this OID
```

与 API 调用不同，没有有用的错误代码或消息；它只是简单地说明 OID 不存在。有时这可能非常令人沮丧。

最后要检查的是我们配置的访问列表将拒绝不需要的 SNMP 查询。因为我们在访问列表的允许和拒绝条目中都使用了`log`关键字，所以只有`172.16.1.173`被允许查询设备：

```py
*Mar 3 20:30:32.179: %SEC-6-IPACCESSLOGNP: list permit_snmp permitted 0 172.16.1.173 -> 0.0.0.0, 1 packet
*Mar 3 20:30:33.991: %SEC-6-IPACCESSLOGNP: list permit_snmp denied 0 172.16.1.187 -> 0.0.0.0, 1 packet
```

正如您所看到的，设置 SNMP 的最大挑战是找到正确的 OID。一些 OID 在标准化的 MIB-2 中定义；其他的在树的企业部分下。尽管如此，供应商文档是最好的选择。有许多工具可以帮助，例如 MIB 浏览器；您可以将 MIBs（同样由供应商提供）添加到浏览器中，并查看基于企业的 OID 的描述。当您需要找到您正在寻找的对象的正确 OID 时，像思科的 SNMP 对象导航器（[`snmp.cloudapps.cisco.com/Support/SNMP/do/BrowseOID.do?local=en`](http://snmp.cloudapps.cisco.com/Support/SNMP/do/BrowseOID.do?local=en)）这样的工具就变得非常有价值。

# PySNMP

PySNMP 是由 Ilya Etingof 开发的跨平台、纯 Python SNMP 引擎实现（[`github.com/etingof`](https://github.com/etingof)）。它为您抽象了许多 SNMP 细节，正如优秀的库所做的那样，并支持 Python 2 和 Python 3。

PySNMP 需要 PyASN1 包。以下内容摘自维基百科：

<q>"ASN.1 是一种标准和符号，描述了在电信和计算机网络中表示、编码、传输和解码数据的规则和结构。"</q>

PyASN1 方便地提供了一个 Python 封装器，用于 ASN.1。让我们首先安装这个包：

```py
cd /tmp
git clone https://github.com/etingof/pyasn1.git
cd pyasn1/
git checkout 0.2.3
sudo python3 setup.py install
```

接下来，安装 PySNMP 包：

```py
git clone https://github.com/etingof/pysnmp
cd pysnmp/
git checkout v4.3.10
sudo python3 setup.py install
```

由于`pysnmp.entity.rfc3413.oneliner`从版本 5.0.0 开始被移除（[`github.com/etingof/pysnmp/blob/a93241007b970c458a0233c16ae2ef82dc107290/CHANGES.txt`](https://github.com/etingof/pysnmp/blob/a93241007b970c458a0233c16ae2ef82dc107290/CHANGES.txt)），我们使用了较旧版本的 PySNMP。如果您使用`pip`来安装包，示例可能会出现问题。

让我们看看如何使用 PySNMP 来查询与上一个示例中使用的相同的 Cisco 联系信息。我们将采取的步骤是从[`pysnmp.sourceforge.net/faq/response-values-mib-resolution.html`](http://pysnmp.sourceforge.net/faq/response-values-mib-resolution.html)中的 PySNMP 示例中略微修改的版本。我们将首先导入必要的模块并创建一个`CommandGenerator`对象：

```py
>>> from pysnmp.entity.rfc3413.oneliner import cmdgen
>>> cmdGen = cmdgen.CommandGenerator()
>>> cisco_contact_info_oid = "1.3.6.1.4.1.9.2.1.61.0"
```

我们可以使用`getCmd`方法执行 SNMP。结果将被解包为各种变量；其中，我们最关心`varBinds`，其中包含查询结果：

```py
>>> errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
...     cmdgen.CommunityData('secret'),
...     cmdgen.UdpTransportTarget(('172.16.1.189', 161)),
...     cisco_contact_info_oid
... )
>>> for name, val in varBinds:
...     print('%s = %s' % (name.prettyPrint(), str(val)))
...
SNMPv2-SMI::enterprises.9.2.1.61.0 = cisco Systems, Inc.
170 West Tasman Dr.
San Jose, CA 95134-1706
U.S.A.
Ph +1-408-526-4000
Customer service 1-800-553-6387 or +1-408-526-7208
24HR Emergency 1-800-553-2447 or +1-408-526-7209
Email Address tac@cisco.com
World Wide Web http://www.cisco.com
>>>
```

请注意，响应值是 PyASN1 对象。`prettyPrint()`方法将一些这些值转换为人类可读的格式，但由于我们的结果没有被转换，我们将手动将其转换为字符串。

我们可以基于前面的交互式示例编写一个脚本。我们将其命名为`pysnmp_1.py`并进行错误检查。我们还可以在`getCmd()`方法中包含多个 OID：

```py
#!/usr/bin/env/python3

from pysnmp.entity.rfc3413.oneliner import cmdgen

cmdGen = cmdgen.CommandGenerator()

system_up_time_oid = "1.3.6.1.2.1.1.3.0"
cisco_contact_info_oid = "1.3.6.1.4.1.9.2.1.61.0"

errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
    cmdgen.CommunityData('secret'),
    cmdgen.UdpTransportTarget(('172.16.1.189', 161)),
    system_up_time_oid,
    cisco_contact_info_oid
)

# Check for errors and print out results
if errorIndication:
    print(errorIndication)
else:
    if errorStatus:
        print('%s at %s' % (
            errorStatus.prettyPrint(),
            errorIndex and varBinds[int(errorIndex)-1] or '?'
            )
        )
    else:
        for name, val in varBinds:
            print('%s = %s' % (name.prettyPrint(), str(val)))

```

结果将被解包并列出两个 OID 的值：

```py
$ python3 pysnmp_1.py
SNMPv2-MIB::sysUpTime.0 = 660959
SNMPv2-SMI::enterprises.9.2.1.61.0 = cisco Systems, Inc.
170 West Tasman Dr.
San Jose, CA 95134-1706
U.S.A.
Ph +1-408-526-4000
Customer service 1-800-553-6387 or +1-408-526-7208
24HR Emergency 1-800-553-2447 or +1-408-526-7209
Email Address tac@cisco.com
World Wide Web http://www.cisco.com 
```

在接下来的示例中，我们将持久化我们从查询中收到的值，以便我们可以执行其他功能，比如使用数据进行可视化。在我们的示例中，我们将使用 MIB-2 树中的`ifEntry`来绘制与接口相关的值。您可以找到许多资源来映射`ifEntry`树；这里是我们之前访问过`ifEntry`的 Cisco SNMP 对象导航器网站的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/dc9b8d4c-afc3-4aa7-8865-02b7faa9572d.png)SNMP ifEntry OID tree

一个快速测试将说明设备上接口的 OID 映射：

```py
$ snmpwalk -v2c -c secret 172.16.1.189 .1.3.6.1.2.1.2.2.1.2
iso.3.6.1.2.1.2.2.1.2.1 = STRING: "GigabitEthernet0/0"
iso.3.6.1.2.1.2.2.1.2.2 = STRING: "GigabitEthernet0/1"
iso.3.6.1.2.1.2.2.1.2.3 = STRING: "GigabitEthernet0/2"
iso.3.6.1.2.1.2.2.1.2.4 = STRING: "Null0"
iso.3.6.1.2.1.2.2.1.2.5 = STRING: "Loopback0"
```

从文档中，我们可以将`ifInOctets(10)`、`ifInUcastPkts(11)`、`ifOutOctets(16)`和`ifOutUcastPkts(17)`的值映射到它们各自的 OID 值。通过快速检查 CLI 和 MIB 文档，我们可以看到`GigabitEthernet0/0`数据包输出的值映射到 OID`1.3.6.1.2.1.2.2.1.17.1`。我们将按照相同的过程来映射接口统计的其余 OID。在 CLI 和 SNMP 之间进行检查时，请记住，值应该接近但不完全相同，因为在 CLI 输出和 SNMP 查询时间之间可能有一些流量：

```py
# Command Line Output
iosv-1#sh int gig 0/0 | i packets
 5 minute input rate 0 bits/sec, 0 packets/sec
 5 minute output rate 0 bits/sec, 0 packets/sec
 38532 packets input, 3635282 bytes, 0 no buffer
 53965 packets output, 4723884 bytes, 0 underruns

# SNMP Output
$ snmpwalk -v2c -c secret 172.16.1.189 .1.3.6.1.2.1.2.2.1.17.1
iso.3.6.1.2.1.2.2.1.17.1 = Counter32: 54070
```

如果我们处于生产环境中，我们可能会将结果写入数据库。但由于这只是一个例子，我们将把查询值写入一个平面文件。我们将编写`pysnmp_3.py`脚本来进行信息查询并将结果写入文件。在脚本中，我们已经定义了需要查询的各种 OID：

```py
  # Hostname OID
  system_name = '1.3.6.1.2.1.1.5.0'

  # Interface OID
  gig0_0_in_oct = '1.3.6.1.2.1.2.2.1.10.1'
  gig0_0_in_uPackets = '1.3.6.1.2.1.2.2.1.11.1'
  gig0_0_out_oct = '1.3.6.1.2.1.2.2.1.16.1'
  gig0_0_out_uPackets = '1.3.6.1.2.1.2.2.1.17.1'
```

这些值在`snmp_query()`函数中被使用，输入为`host`、`community`和`oid`：

```py
  def snmp_query(host, community, oid):
      errorIndication, errorStatus, errorIndex, varBinds = cmdGen.getCmd(
      cmdgen.CommunityData(community),
      cmdgen.UdpTransportTarget((host, 161)),
      oid
      )
```

所有的值都被放在一个带有各种键的字典中，并写入一个名为`results.txt`的文件：

```py
  result = {}
  result['Time'] = datetime.datetime.utcnow().isoformat()
  result['hostname'] = snmp_query(host, community, system_name)
  result['Gig0-0_In_Octet'] = snmp_query(host, community, gig0_0_in_oct)
  result['Gig0-0_In_uPackets'] = snmp_query(host, community, gig0_0_in_uPackets)
  result['Gig0-0_Out_Octet'] = snmp_query(host, community, gig0_0_out_oct)
  result['Gig0-0_Out_uPackets'] = snmp_query(host, community, gig0_0_out_uPackets)

  with open('/home/echou/Master_Python_Networking/Chapter7/results.txt', 'a') as f:
      f.write(str(result))
      f.write('n')
```

结果将是一个显示查询时接口数据包的文件：

```py
# Sample output
$ cat results.txt
{'Gig0-0_In_Octet': '3990616', 'Gig0-0_Out_uPackets': '60077', 'Gig0-0_In_uPackets': '42229', 'Gig0-0_Out_Octet': '5228254', 'Time': '2017-03-06T02:34:02.146245', 'hostname': 'iosv-1.virl.info'}
{'Gig0-0_Out_uPackets': '60095', 'hostname': 'iosv-1.virl.info', 'Gig0-0_Out_Octet': '5229721', 'Time': '2017-03-06T02:35:02.072340', 'Gig0-0_In_Octet': '3991754', 'Gig0-0_In_uPackets': '42242'}
{'hostname': 'iosv-1.virl.info', 'Gig0-0_Out_Octet': '5231484', 'Gig0-0_In_Octet': '3993129', 'Time': '2017-03-06T02:36:02.753134', 'Gig0-0_In_uPackets': '42257', 'Gig0-0_Out_uPackets': '60116'}
{'Gig0-0_In_Octet': '3994504', 'Time': '2017-03-06T02:37:02.146894', 'Gig0-0_In_uPackets': '42272', 'Gig0-0_Out_uPackets': '60136', 'Gig0-0_Out_Octet': '5233187', 'hostname': 'iosv-1.virl.info'}
{'Gig0-0_In_uPackets': '42284', 'Time': '2017-03-06T02:38:01.915432', 'Gig0-0_In_Octet': '3995585', 'Gig0-0_Out_Octet': '5234656', 'Gig0-0_Out_uPackets': '60154', 'hostname': 'iosv-1.virl.info'}
...
```

我们可以使这个脚本可执行，并安排一个`cron`作业每五分钟执行一次：

```py
$ chmod +x pysnmp_3.py

# Crontab configuration
*/5 * * * * /home/echou/Master_Python_Networking/Chapter7/pysnmp_3.py
```

如前所述，在生产环境中，我们会将信息放入数据库。对于 SQL 数据库，您可以使用唯一 ID 作为主键。在 NoSQL 数据库中，我们可能会使用时间作为主索引（或键），因为它总是唯一的，然后是各种键值对。

我们将等待脚本执行几次，以便值被填充。如果您是不耐烦的类型，可以将`cron`作业间隔缩短为一分钟。在`results.txt`文件中看到足够多的值以制作有趣的图表后，我们可以继续下一节，看看如何使用 Python 来可视化数据。

# 用于数据可视化的 Python

我们收集网络数据是为了深入了解我们的网络。了解数据含义的最佳方法之一是使用图形对其进行可视化。这对于几乎所有数据都是正确的，但特别适用于网络监控的时间序列数据。在过去一周内网络传输了多少数据？TCP 协议在所有流量中的百分比是多少？这些都是我们可以通过使用数据收集机制（如 SNMP）获得的值，我们可以使用一些流行的 Python 库生成可视化图形。

在本节中，我们将使用上一节从 SNMP 收集的数据，并使用两个流行的 Python 库 Matplotlib 和 Pygal 来对其进行图形化。

# Matplotlib

**Matplotlib** ([`matplotlib.org/`](http://matplotlib.org/))是 Python 语言及其 NumPy 数学扩展的 2D 绘图库。它可以用几行代码生成出版质量的图形，如绘图、直方图和条形图。

NumPy 是 Python 编程语言的扩展。它是开源的，并广泛用于各种数据科学项目。您可以在[`en.wikipedia.org/wiki/NumPy`](https://en.wikipedia.org/wiki/NumPy)了解更多信息。

# 安装

安装可以使用 Linux 软件包管理系统完成，具体取决于您的发行版：

```py
$ sudo apt-get install python-matplotlib # for Python2
$ sudo apt-get install python3-matplotlib
```

# Matplotlib – 第一个示例

在以下示例中，默认情况下，输出图形会显示为标准输出。在开发过程中，最好先尝试最初的代码，并首先在标准输出上生成图形，然后再用脚本完成代码。如果您一直通过虚拟机跟随本书，建议您使用虚拟机窗口而不是 SSH，这样您就可以看到图形。如果您无法访问标准输出，可以保存图形，然后在下载后查看（很快您将看到）。请注意，您需要在本节中的某些图形中设置`$DISPLAY`变量。

以下是本章可视化示例中使用的 Ubuntu 桌面的屏幕截图。在终端窗口中发出`plt.show()`命令后，`Figure 1`将出现在屏幕上。关闭图形后，您将返回到 Python shell：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/6e2ca222-f974-43d2-aa0c-5cbbe61e2165.png)使用 Ubuntu 桌面的 Matplotlib 可视化

让我们先看看折线图。折线图只是给出了两个与*x*轴和*y*轴值对应的数字列表：

```py
>>> import matplotlib.pyplot as plt
>>> plt.plot([0,1,2,3,4], [0,10,20,30,40])
[<matplotlib.lines.Line2D object at 0x7f932510df98>]
>>> plt.ylabel('Something on Y')
<matplotlib.text.Text object at 0x7f93251546a0>
>>> plt.xlabel('Something on X')
<matplotlib.text.Text object at 0x7f9325fdb9e8>
>>> plt.show()
```

图形将显示为折线图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/a829928b-284f-4292-ab0b-62b334bcba6f.png)Matplotlib 折线图

或者，如果您无法访问标准输出或者首先保存了图形，可以使用`savefig()`方法：

```py
>>> plt.savefig('figure1.png')
or
>>> plt.savefig('figure1.pdf')
```

有了这些基本的图形绘制知识，我们现在可以绘制从 SNMP 查询中收到的结果了。

# 用于 SNMP 结果的 Matplotlib

在我们的第一个 Matplotlib 示例中，即`matplotlib_1.py`，我们将除了`pyplot`之外还导入*dates*模块。我们将使用`matplotlib.dates`模块而不是 Python 标准库`dates`模块。与 Python`dates`模块不同，`mapplotlib.dates`库将在内部将日期值转换为 Matplotlib 所需的浮点类型：

```py
  import matplotlib.pyplot as plt
  import matplotlib.dates as dates
```

Matplotlib 提供了复杂的日期绘图功能；您可以在[`matplotlib.org/api/dates_api.html`](http://matplotlib.org/api/dates_api.html)找到更多信息。

在脚本中，我们将创建两个空列表，分别表示*x-*轴和*y-*轴的值。请注意，在第 12 行，我们使用内置的`eval()` Python 函数将输入读取为字典，而不是默认的字符串：

```py
   x_time = []
   y_value = []

   with open('results.txt', 'r') as f:
       for line in f.readlines():
           line = eval(line)
           x_time.append(dates.datestr2num(line['Time']))
           y_value.append(line['Gig0-0_Out_uPackets'])
```

为了以人类可读的日期格式读取*x-*轴的值，我们需要使用`plot_date()`函数而不是`plot()`。我们还将微调图形的大小，并旋转*x-*轴上的值，以便我们可以完整地读取该值：

```py
  plt.subplots_adjust(bottom=0.3)
  plt.xticks(rotation=80)

  plt.plot_date(x_time, y_value)
  plt.title('Router1 G0/0')
  plt.xlabel('Time in UTC')
  plt.ylabel('Output Unicast Packets')
  plt.savefig('matplotlib_1_result.png')
  plt.show()
```

最终结果将显示 Router1 Gig0/0 和输出单播数据包，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/ece57d54-836d-4b3e-86ef-ec605416081c.png)Router1 Matplotlib 图

请注意，如果您喜欢直线而不是点，您可以在`plot_date()`函数中使用第三个可选参数：

```py
     plt.plot_date(x_time, y_value, "-")
```

我们可以重复输出八进制、输入单播数据包和输入的步骤作为单独的图形。然而，在我们接下来的例子中，也就是`matplotlib_2.py`中，我们将向您展示如何在相同的时间范围内绘制多个值，以及其他 Matplotlib 选项。

在这种情况下，我们将创建额外的列表，并相应地填充值：

```py
   x_time = []
   out_octets = []
   out_packets = []
   in_octets = []
   in_packets = []

   with open('results.txt', 'r') as f:
       for line in f.readlines():
   ...
           out_packets.append(line['Gig0-0_Out_uPackets'])
           out_octets.append(line['Gig0-0_Out_Octet'])
           in_packets.append(line['Gig0-0_In_uPackets'])
           in_octets.append(line['Gig0-0_In_Octet'])
```

由于我们有相同的*x-*轴值，我们可以将不同的*y-*轴值添加到同一图中：

```py
  # Use plot_date to display x-axis back in date format
  plt.plot_date(x_time, out_packets, '-', label='Out Packets')
  plt.plot_date(x_time, out_octets, '-', label='Out Octets')
  plt.plot_date(x_time, in_packets, '-', label='In Packets')
  plt.plot_date(x_time, in_octets, '-', label='In Octets')
```

还要在图中添加网格和图例：

```py
  plt.legend(loc='upper left')
  plt.grid(True)
```

最终结果将把所有值合并到一个图中。请注意，左上角的一些值被图例挡住了。您可以调整图形的大小和/或使用平移/缩放选项来在图形周围移动，以查看值：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/5c6c3d57-899b-402b-b554-c85e94fe3b24.png)Router 1 – Matplotlib 多线图

Matplotlib 中有许多其他绘图选项；我们当然不仅限于绘制图形。例如，我们可以使用以下模拟数据来绘制我们在线上看到的不同流量类型的百分比：

```py
#!/usr/bin/env python3
# Example from http://matplotlib.org/2.0.0/examples/pie_and_polar_charts/pie_demo_features.html
import matplotlib.pyplot as plt

# Pie chart, where the slices will be ordered and plotted counter-clockwise:
labels = 'TCP', 'UDP', 'ICMP', 'Others'
sizes = [15, 30, 45, 10]
explode = (0, 0.1, 0, 0) # Make UDP stand out

fig1, ax1 = plt.subplots()
ax1.pie(sizes, explode=explode, labels=labels, autopct='%1.1f%%',
 shadow=True, startangle=90)
ax1.axis('equal') # Equal aspect ratio ensures that pie is drawn as a circle.

plt.show()
```

上述代码导致了从`plt.show()`生成的饼图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/6a9328fe-b860-4287-98e2-a56c469da3aa.png)Matplotlib 饼图

# 附加的 Matplotlib 资源

Matplotlib 是最好的 Python 绘图库之一，能够生成出版质量的图形。与 Python 一样，它的目标是使复杂的任务变得简单。在 GitHub 上有超过 7550 颗星（还在增加），它也是最受欢迎的开源项目之一。它的受欢迎程度直接转化为更快的错误修复、友好的用户社区和通用的可用性。学习这个包需要一点时间，但是非常值得努力。

在本节中，我们只是浅尝了 Matplotlib 的表面。您可以在[`matplotlib.org/2.0.0/index.html`](http://matplotlib.org/2.0.0/index.html)（Matplotlib 项目页面）和[`github.com/matplotlib/matplotlib`](https://github.com/matplotlib/matplotlib)（Matplotlib GitHub 存储库）找到更多资源。

在接下来的部分中，我们将看一下另一个流行的 Python 图形库：**Pygal**。

# Pygal

Pygal（[`www.pygal.org/`](http://www.pygal.org/)）是一个用 Python 编写的动态 SVG 图表库。在我看来，Pygal 的最大优势是它能够轻松本地生成**可伸缩矢量图形**（**SVG**）格式的图形。SVG 相对于其他图形格式有许多优势，但其中两个主要优势是它对 Web 浏览器友好，并且提供了可伸缩性而不会损失图像质量。换句话说，您可以在任何现代 Web 浏览器中显示生成的图像，并且可以放大和缩小图像，而不会丢失图形的细节。我提到了我们可以在几行 Python 代码中做到这一点吗？这有多酷？

# 安装

安装是通过`pip`完成的：

```py
$ sudo pip install pygal #Python 2
$ sudo pip3 install pygal
```

# Pygal - 第一个例子

让我们看一下 Pygal 文档中演示的线图示例，网址为[`pygal.org/en/stable/documentation/types/line.html`](http://pygal.org/en/stable/documentation/types/line.html)：

```py
>>> import pygal
>>> line_chart = pygal.Line()
>>> line_chart.title = 'Browser usage evolution (in %)'
>>> line_chart.x_labels = map(str, range(2002, 2013))
>>> line_chart.add('Firefox', [None, None, 0, 16.6, 25, 31, 36.4, 45.5, 46.3, 42.8, 37.1])
<pygal.graph.line.Line object at 0x7fa0bb009c50>
>>> line_chart.add('Chrome', [None, None, None, None, None, None, 0, 3.9, 10.8, 23.8, 35.3])
<pygal.graph.line.Line object at 0x7fa0bb009c50>
>>> line_chart.add('IE', [85.8, 84.6, 84.7, 74.5, 66, 58.6, 54.7, 44.8, 36.2, 26.6, 20.1])
<pygal.graph.line.Line object at 0x7fa0bb009c50>
>>> line_chart.add('Others', [14.2, 15.4, 15.3, 8.9, 9, 10.4, 8.9, 5.8, 6.7, 6.8, 7.5])
<pygal.graph.line.Line object at 0x7fa0bb009c50>
>>> line_chart.render_to_file('pygal_example_1.svg')
```

在这个例子中，我们创建了一个带有`x_labels`的线对象，自动呈现为 11 个单位的字符串。每个对象都可以以列表格式添加标签和值，例如 Firefox、Chrome 和 IE。

这是在 Firefox 中查看的结果图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/29abfeb0-b81b-4751-b7d3-ba3dc6bd8cb5.png)Pygal 示例图

现在我们可以看到 Pygal 的一般用法，我们可以使用相同的方法来绘制我们手头上的 SNMP 结果。我们将在接下来的部分中进行这样做。

# Pygal 用于 SNMP 结果

对于 Pygal 线图，我们可以大致按照 Matplotlib 示例的相同模式进行操作，其中我们通过读取文件创建值列表。我们不再需要将*x-*轴值转换为内部浮点数，就像我们为 Matplotlib 所做的那样；但是，我们确实需要将我们将在浮点数中收到的每个值中的数字转换为浮点数：

```py
  #!/usr/bin/env python3

  import pygal

  x_time = []
  out_octets = []
  out_packets = []
  in_octets = []
  in_packets = []

  with open('results.txt', 'r') as f:
      for line in f.readlines():
          line = eval(line)
          x_time.append(line['Time'])
          out_packets.append(float(line['Gig0-0_Out_uPackets']))
          out_octets.append(float(line['Gig0-0_Out_Octet']))
          in_packets.append(float(line['Gig0-0_In_uPackets']))
          in_octets.append(float(line['Gig0-0_In_Octet']))
```

我们可以使用我们看到的相同机制来构建线图：

```py
  line_chart = pygal.Line()
  line_chart.title = "Router 1 Gig0/0"
  line_chart.x_labels = x_time
  line_chart.add('out_octets', out_octets)
  line_chart.add('out_packets', out_packets)
  line_chart.add('in_octets', in_octets)
  line_chart.add('in_packets', in_packets)
  line_chart.render_to_file('pygal_example_2.svg')
```

结果与我们已经看到的类似，但是图表现在以 SVG 格式呈现，可以轻松地显示在网页上。它可以在现代 Web 浏览器中查看：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/6e383a39-e3b8-48c9-a6be-6fc05fcf4cb1.png)路由器 1—Pygal 多线图

就像 Matplotlib 一样，Pygal 为图表提供了更多的选项。例如，要在 Pygal 中绘制我们之前看到的饼图，我们可以使用`pygal.Pie()`对象：

```py
#!/usr/bin/env python3

import pygal

line_chart = pygal.Pie()
line_chart.title = "Protocol Breakdown"
line_chart.add('TCP', 15)
line_chart.add('UDP', 30)
line_chart.add('ICMP', 45)
line_chart.add('Others', 10)
line_chart.render_to_file('pygal_example_3.svg')
```

生成的 SVG 文件将类似于 Matplotlib 生成的 PNG：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/dd33b69f-99ec-45bb-bc0a-386ee0c65bcf.png)Pygal 饼图

# 其他 Pygal 资源

Pygal 为您从基本网络监控工具（如 SNMP）收集的数据提供了更多可定制的功能和图形能力。在本节中，我们演示了简单的线图和饼图。您可以在此处找到有关项目的更多信息：

+   **Pygal 文档**：[`www.pygal.org/en/stable/index.html`](http://www.pygal.org/en/stable/index.html)

+   **Pygal GitHub 项目页面**：[`github.com/Kozea/pygal`](https://github.com/Kozea/pygal)

在接下来的部分中，我们将继续使用 SNMP 主题进行网络监控，但使用一个名为**Cacti**的功能齐全的网络监控系统。

# Cacti 的 Python

在我作为地区 ISP 的初级网络工程师工作的早期，我们使用开源跨平台**多路由器流量图**（**MRTG**）（[`en.wikipedia.org/wiki/Multi_Router_Traffic_Grapher`](https://en.wikipedia.org/wiki/Multi_Router_Traffic_Grapher)）工具来检查网络链路上的流量负载。我们几乎完全依赖于该工具进行流量监控。我真的很惊讶开源项目可以有多好和有用。这是第一个将 SNMP、数据库和 HTML 的细节抽象化为网络工程师的开源高级网络监控系统之一。然后出现了**循环数据库工具**（**RRDtool**）（[`en.wikipedia.org/wiki/RRDtool`](https://en.wikipedia.org/wiki/RRDtool)）。在 1999 年的首次发布中，它被称为“正确的 MRTG”。它极大地改进了后端的数据库和轮询器性能。

Cacti（[`en.wikipedia.org/wiki/Cacti_(software)`](https://en.wikipedia.org/wiki/Cacti_(software)）于 2001 年发布，是一个开源的基于 Web 的网络监控和图形工具，旨在作为 RRDtool 的改进前端。由于 MRTG 和 RRDtool 的传承，您会注意到熟悉的图表布局、模板和 SNMP 轮询器。作为一个打包工具，安装和使用将需要保持在工具本身的范围内。但是，Cacti 提供了我们可以使用 Python 的自定义数据查询功能。在本节中，我们将看到如何将 Python 用作 Cacti 的输入方法。

# 安装

在 Ubuntu 上使用 APT 进行安装非常简单：

```py
$ sudo apt-get install cacti
```

这将触发一系列安装和设置步骤，包括 MySQL 数据库、Web 服务器（Apache 或 lighttpd）和各种配置任务。安装完成后，导航到`http://<ip>/cacti`开始使用。最后一步是使用默认用户名和密码（`admin`/`admin`）登录；您将被提示更改密码。

一旦你登录，你可以按照文档添加设备并将其与模板关联。有一个预制的 Cisco 路由器模板可以使用。Cacti 在[`docs.cacti.net/`](http://docs.cacti.net/)上有关于添加设备和创建第一个图形的良好文档，所以我们将快速查看一些你可以期望看到的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/30d73b73-895c-472d-8723-22a9be73d6f3.png)

当你能看到设备的正常运行时间时，这是 SNMP 通信正在工作的一个标志：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/fdf75bec-2cb7-4e51-a6c8-87e9cf54ca4d.png)

你可以为设备添加接口流量和其他统计信息的图形：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/d02f3ac0-6883-4358-a3ae-deeebff30af9.png)

一段时间后，你会开始看到流量，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/4e894e42-b8ca-4140-bf0c-e19f83ebef34.png)

我们现在准备看一下如何使用 Python 脚本来扩展 Cacti 的数据收集功能。

# Python 脚本作为输入源

在我们尝试将 Python 脚本作为输入源之前，有两份文档我们应该阅读：

+   数据输入方法：[`www.cacti.net/downloads/docs/html/data_input_methods.html`](http://www.cacti.net/downloads/docs/html/data_input_methods.html)

+   使你的脚本与 Cacti 一起工作：[`www.cacti.net/downloads/docs/html/making_scripts_work_with_cacti.html`](http://www.cacti.net/downloads/docs/html/making_scripts_work_with_cacti.html)

有人可能会想知道使用 Python 脚本作为数据输入扩展的用例是什么。其中一个用例是为那些没有相应 OID 的资源提供监控，例如，如果我们想知道访问列表`permit_snmp`允许主机`172.16.1.173`进行 SNMP 查询的次数。我们知道我们可以通过 CLI 看到匹配的次数：

```py
iosv-1#sh ip access-lists permit_snmp | i 172.16.1.173
 10 permit 172.16.1.173 log (6362 matches)
```

然而，很可能与这个值没有关联的 OID（或者我们可以假装没有）。这就是我们可以使用外部脚本生成一个可以被 Cacti 主机消耗的输出的地方。

我们可以重用我们在第二章中讨论的 Pexpect 脚本，`chapter1_1.py`。我们将其重命名为`cacti_1.py`。除了执行 CLI 命令并保存输出之外，一切都应该与原始脚本一样熟悉：

```py
for device in devices.keys():
...
    child.sendline('sh ip access-lists permit_snmp | i 172.16.1.173')
    child.expect(device_prompt)
    output = child.before
...
```

原始形式的输出如下：

```py
b'sh ip access-lists permit_snmp | i 172.16.1.173rn 10 permit 172.16.1.173 log (6428 matches)rn'
```

我们将使用`split()`函数对字符串进行处理，只留下匹配的次数并在脚本中将其打印到标准输出：

```py
print(str(output).split('(')[1].split()[0])
```

为了测试这一点，我们可以执行脚本多次来查看增量的数量：

```py
$ ./cacti_1.py
6428
$ ./cacti_1.py
6560
$ ./cacti_1.py
6758
```

我们可以将脚本设置为可执行，并将其放入默认的 Cacti 脚本位置：

```py
$ chmod a+x cacti_1.py
$ sudo cp cacti_1.py /usr/share/cacti/site/scripts/
```

Cacti 文档，可在[`www.cacti.net/downloads/docs/html/how_to.html`](http://www.cacti.net/downloads/docs/html/how_to.html)上找到，提供了如何将脚本结果添加到输出图形的详细步骤。这些步骤包括将脚本添加为数据输入方法，将输入方法添加到数据源，然后创建一个图形进行查看：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/76e0529b-8252-41c3-b8c3-ab9f9cd550f3.png)

SNMP 是提供网络监控服务给设备的常见方式。RRDtool 与 Cacti 作为前端提供了一个良好的平台，可以通过 SNMP 用于所有的网络设备。

# 总结

在本章中，我们探讨了通过 SNMP 执行网络监控的方法。我们在网络设备上配置了与 SNMP 相关的命令，并使用了我们的网络管理 VM 与 SNMP 轮询程序来查询设备。我们使用了 PySNMP 模块来简化和自动化我们的 SNMP 查询。我们还学习了如何将查询结果保存在一个平面文件或数据库中，以便用于将来的示例。

在本章的后面，我们使用了两种不同的 Python 可视化包，即 Matplotlib 和 Pygal，来绘制 SNMP 结果的图表。每个包都有其独特的优势。Matplotlib 是一个成熟、功能丰富的库，在数据科学项目中被广泛使用。Pygal 可以原生生成灵活且适合网络的 SVG 格式图表。我们看到了如何生成对网络监控相关的折线图和饼图。

在本章的末尾，我们看了一个名为 Cacti 的全面网络监控工具。它主要使用 SNMP 进行网络监控，但我们看到当远程主机上没有 SNMP OID 时，我们可以使用 Python 脚本作为输入源来扩展平台的监控能力。

在第八章中，《使用 Python 进行网络监控-第 2 部分》，我们将继续讨论我们可以使用的工具来监控我们的网络，并了解网络是否表现如预期。我们将研究使用 NetFlow、sFlow 和 IPFIX 进行基于流的监控。我们还将使用诸如 Graphviz 之类的工具来可视化我们的网络拓扑，并检测任何拓扑变化。最后，我们将使用 Elasticsearch、Logstash 和 Kibana，通常被称为 ELK 堆栈，来监控网络日志数据以及其他与网络相关的输入。


# 第八章：使用 Python 进行网络监控-第 2 部分

在第七章中，*使用 Python 进行网络监控-第 1 部分*，我们使用 SNMP 从网络设备查询信息。我们通过使用 SNMP 管理器查询驻留在网络设备上的 SNMP 代理来实现这一点。SNMP 信息以层次结构格式化，具有特定的对象 ID 来表示对象的值。大多数时候，我们关心的值是一个数字，比如 CPU 负载、内存使用率或接口流量。这是我们可以根据时间绘制图表，以便让我们了解值随时间的变化。

我们通常可以将 SNMP 方法归类为“拉”方法，因为我们不断地向设备请求特定的答案。这种方法会给设备增加负担，因为它需要在控制平面上花费 CPU 周期从子系统中找到答案，将答案打包成一个 SNMP 数据包，并将答案传输回轮询器。如果你曾经参加过家庭聚会，有一个家庭成员一遍又一遍地问你同样的问题，那就相当于 SNMP 管理器不断轮询受管节点。

随着时间的推移，如果我们有多个 SNMP 轮询器每 30 秒查询同一个设备（你会惊讶地发现这种情况经常发生），管理开销将变得相当大。在我们给出的家庭聚会的例子中，想象一下不是一个家庭成员，而是许多其他人每 30 秒打断你问你一个问题。我不知道你怎么想，但我知道即使是一个简单的问题（或者更糟糕的是，如果所有人都问同样的问题），我也会感到非常恼火。

我们可以提供更有效的网络监控的另一种方法是将管理站与设备之间的关系从拉模型转变为推模型。换句话说，信息可以以约定的格式从设备推送到管理站。这个概念是基于基于流的监控。在基于流的模型中，网络设备将流量信息流向管理站。格式可以是思科专有的 NetFlow（版本 5 或版本 9），行业标准 IPFIX，或开源 sFlow 格式。在本章中，我们将花一些时间用 Python 来研究 NetFlow、IPFIX 和 sFlow。

并非所有的监控都以时间序列数据的形式出现。如果你真的愿意，你可以将网络拓扑和 Syslog 等信息表示为时间序列格式，但这并不理想。我们可以使用 Python 来检查网络拓扑信息，并查看拓扑是否随时间发生了变化。我们可以使用 Graphviz 等工具与 Python 包装器来说明拓扑。正如在第六章中已经看到的，*使用 Python 进行网络安全*，Syslog 包含安全信息。在本章中，我们将研究使用 ELK 堆栈（Elasticsearch、Logstash、Kibana）作为收集和索引网络日志信息的有效方法。

具体来说，在本章中，我们将涵盖以下主题：

+   Graphviz，这是一个开源的图形可视化软件，可以帮助我们快速高效地绘制网络图

+   基于流的监控，如 NetFlow、IPFIX 和 sFlow

+   使用 ntop 来可视化流量信息

+   使用 Elasticsearch 来索引和分析我们收集的数据

让我们首先看看如何使用 Graphviz 作为监控网络拓扑变化的工具。

# Graphviz

Graphviz 是一种开源的图形可视化软件。想象一下，如果我们不用图片的好处来描述我们的网络拓扑给同事。我们可能会说，我们的网络由三层组成：核心、分发和接入。核心层包括两台路由器用于冗余，并且这两台路由器都对四台分发路由器进行全网状连接；分发路由器也对接入路由器进行全网状连接。内部路由协议是 OSPF，外部使用 BGP 与服务提供商进行对等连接。虽然这个描述缺少一些细节，但对于您的同事来说，这可能足够绘制出您网络的一个相当不错的高层图像。

Graphviz 的工作方式类似于通过描述 Graphviz 可以理解的文本格式来描述图形，然后我们可以将文件提供给 Graphviz 程序来为我们构建图形。在这里，图形是用一种称为 DOT 的文本格式描述的（[`en.wikipedia.org/wiki/DOT_(graph_description_language)`](https://en.wikipedia.org/wiki/DOT_(graph_description_language)）），Graphviz 根据描述渲染图形。当然，因为计算机缺乏人类的想象力，语言必须非常精确和详细。

对于 Graphviz 特定的 DOT 语法定义，请查看[`www.graphviz.org/doc/info/lang.html`](http://www.graphviz.org/doc/info/lang.html)。

在本节中，我们将使用**链路层发现协议**（**LLDP**）来查询设备邻居，并通过 Graphviz 创建网络拓扑图。完成这个广泛的示例后，我们将看到如何将新的东西，比如 Graphviz，与我们已经学到的东西结合起来解决有趣的问题。

让我们开始构建我们将要使用的实验室。

# 实验室设置

我们将使用 VIRL 来构建我们的实验室。与前几章一样，我们将组建一个包括多个路由器、一个服务器和一个客户端的实验室。我们将使用五个 IOSv 网络节点以及两个服务器主机：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/3166a522-47db-4a53-bd7f-0e15ad415b04.png)

如果您想知道我们选择 IOSv 而不是 NX-OS 或 IOS-XR 以及设备数量的原因，在构建自己的实验室时，请考虑以下几点：

+   由 NX-OS 和 IOS-XR 虚拟化的节点比 IOS 更占用内存

+   我使用的 VIRL 虚拟管理器有 8GB 的 RAM，似乎足够支持九个节点，但可能会有点不稳定（节点随机从可达到不可达）

+   如果您希望使用 NX-OS，请考虑使用 NX-API 或其他 API 调用来返回结构化数据

对于我们的示例，我们将使用 LLDP 作为链路层邻居发现的协议，因为它是与厂商无关的。请注意，VIRL 提供了自动启用 CDP 的选项，这可以节省一些时间，并且在功能上类似于 LLDP；但是，它是一种思科专有技术，因此我们将在我们的实验室中禁用它：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/7ffca5b5-9a64-4fdd-b214-e5af0d08b772.png)

实验室建立完成后，继续安装必要的软件包。

# 安装

可以通过`apt`获取 Graphviz：

```py
$ sudo apt-get -y install graphviz
```

安装完成后，请注意使用`dot`命令进行验证：

```py
$ dot -V
dot - graphviz version 2.38.0 (20140413.2041)~
```

我们将使用 Graphviz 的 Python 包装器，所以让我们现在安装它：

```py
$ sudo pip install graphviz #Python 2
$ sudo pip3 install graphviz

$ python3
Python 3.5.2 (default, Nov 23 2017, 16:37:01)
[GCC 5.4.0 20160609] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import graphviz
>>> graphviz.__version__
'0.8.4'
>>> exit() 
```

让我们看看如何使用这个软件。

# Graphviz 示例

像大多数流行的开源项目一样，Graphviz 的文档（[`www.graphviz.org/Documentation.php`](http://www.graphviz.org/Documentation.php)）是非常广泛的。对于新手来说，挑战通常在于从何处开始。对于我们的目的，我们将专注于绘制有向图的 dot 图，这是一种层次结构（不要与 DOT 语言混淆，DOT 语言是一种图描述语言）。

让我们从一些基本概念开始：

+   节点代表我们的网络实体，如路由器、交换机和服务器

+   边缘代表网络实体之间的链接

+   图表、节点和边都有可以调整的属性([`www.graphviz.org/doc/info/attrs.html`](https://www.graphviz.org/doc/info/attrs.html))

+   描述网络后，我们可以将网络图([`www.graphviz.org/doc/info/output.html`](https://www.graphviz.org/doc/info/output.html))输出为 PNG、JPEG 或 PDF 格式

我们的第一个例子是一个无向点图，由四个节点(`core`、`distribution`、`access1`和`access2`)组成。边由破折号`-`符号表示，将核心节点连接到分布节点，以及将分布节点连接到两个访问节点：

```py
$ cat chapter8_gv_1.gv
graph my_network {
 core -- distribution;
 distribution -- access1;
 distribution -- access2;
}
```

图表可以在命令行中输出为`dot -T<format> source -o <output file>`：

```py
$ dot -Tpng chapter8_gv_1.gv -o output/chapter8_gv_1.png
```

生成的图表可以从以下输出文件夹中查看：

就像第七章中的*使用 Python 进行网络监控-第 1 部分*一样，当处理这些图表时，可能更容易在 Linux 桌面窗口中工作，这样你就可以立即看到图表。

请注意，我们可以通过将图表指定为有向图，并使用箭头(`->`)符号来表示边来使用有向图。在节点和边的情况下，有几个属性可以修改，例如节点形状、边标签等。同一个图表可以修改如下：

```py
$ cat chapter8_gv_2.gv
digraph my_network {
 node [shape=box];
 size = "50 30";
 core -> distribution [label="2x10G"];
 distribution -> access1 [label="1G"];
 distribution -> access2 [label="1G"];
}
```

这次我们将文件输出为 PDF：

```py
$ dot -Tpdf chapter8_gv_2.gv -o output/chapter8_gv_2.pdf
```

看一下新图表中的方向箭头：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/9856fec1-2710-4661-8be9-99f9a65151de.png)

现在让我们看一下围绕 Graphviz 的 Python 包装器。

# Python 与 Graphviz 示例

我们可以使用我们安装的 Python Graphviz 包再次生成与之前相同的拓扑图：

```py
$ python3
Python 3.5.2 (default, Nov 17 2016, 17:05:23)
>>> from graphviz import Digraph
>>> my_graph = Digraph(comment="My Network")
>>> my_graph.node("core")
>>> my_graph.node("distribution")
>>> my_graph.node("access1")
>>> my_graph.node("access2")
>>> my_graph.edge("core", "distribution")
>>> my_graph.edge("distribution", "access1")
>>> my_graph.edge("distribution", "access2")
```

该代码基本上产生了您通常会用 DOT 语言编写的内容，但以更 Pythonic 的方式。您可以在生成图表之前查看图表的源代码：

```py
>>> print(my_graph.source)
// My Network
digraph {
 core
 distribution
 access1
 access2
 core -> distribution
 distribution -> access1
 distribution -> access2
} 
```

图表可以通过`render()`方法呈现；默认情况下，输出格式为 PDF：

```py
>>> my_graph.render("output/chapter8_gv_3.gv")
'output/chapter8_gv_3.gv.pdf'
```

Python 包装器紧密模仿了 Graphviz 的所有 API 选项。您可以在 Graphviz Read the Docs 网站([`graphviz.readthedocs.io/en/latest/index.html`](http://graphviz.readthedocs.io/en/latest/index.html))上找到有关选项的文档。您还可以在 GitHub 上查看源代码以获取更多信息([`github.com/xflr6/graphviz`](https://github.com/xflr6/graphviz))。我们现在准备使用这个工具来绘制我们的网络。

# LLDP 邻居图

在本节中，我们将使用映射 LLDP 邻居的示例来说明多年来帮助我的问题解决模式：

1.  如果可能的话，将每个任务模块化为更小的部分。在我们的例子中，我们可以合并几个步骤，但如果我们将它们分解成更小的部分，我们将能够更容易地重用和改进它们。

1.  使用自动化工具与网络设备交互，但将更复杂的逻辑保留在管理站。例如，路由器提供了一个有点混乱的 LLDP 邻居输出。在这种情况下，我们将坚持使用可行的命令和输出，并在管理站使用 Python 脚本来解析我们需要的输出。

1.  在面对相同任务的选择时，选择可以重复使用的选项。在我们的例子中，我们可以使用低级别的 Pexpect、Paramiko 或 Ansible playbooks 来查询路由器。在我看来，Ansible 是一个更可重用的选项，所以我选择了它。

要开始，因为路由器默认情况下未启用 LLDP，我们需要首先在设备上配置它们。到目前为止，我们知道我们有许多选择；在这种情况下，我选择了使用`ios_config`模块的 Ansible playbook 来完成任务。`hosts`文件包括五台路由器：

```py
$ cat hosts
[devices]
r1 ansible_hostname=172.16.1.218
r2 ansible_hostname=172.16.1.219
r3 ansible_hostname=172.16.1.220
r5-tor ansible_hostname=172.16.1.221
r6-edge ansible_hostname=172.16.1.222
```

`cisco_config_lldp.yml` playbook 包括一个 play，其中嵌入了用于配置 LLDP 的变量：

```py
<skip>
 vars:
   cli:
     host: "{{ ansible_hostname }}"
     username: cisco
     password: cisco
     transport: cli tasks:
  - name: enable LLDP run
       ios_config:
         lines: lldp run
         provider: "{{ cli }}"
<skip>
```

几秒钟后，为了允许 LLDP 交换，我们可以验证 LLDP 确实在路由器上处于活动状态：

```py
$ ansible-playbook -i hosts cisco_config_lldp.yml

PLAY [Enable LLDP] ***********************************************************
...
PLAY RECAP *********************************************************************
r1 : ok=2 changed=1 unreachable=0 failed=0
r2 : ok=2 changed=1 unreachable=0 failed=0
r3 : ok=2 changed=1 unreachable=0 failed=0
r5-tor : ok=2 changed=1 unreachable=0 failed=0
r6-edge : ok=2 changed=1 unreachable=0 failed=0

## SSH to R1 for verification
r1#show lldp neighbors

Capability codes: (R) Router, (B) Bridge, (T) Telephone, (C) DOCSIS Cable Device (W) WLAN Access Point, (P) Repeater, (S) Station, (O) Other

Device ID Local Intf Hold-time Capability Port ID
r2.virl.info Gi0/0 120 R Gi0/0
r3.virl.info Gi0/0 120 R Gi0/0
r5-tor.virl.info Gi0/0 120 R Gi0/0
r5-tor.virl.info Gi0/1 120 R Gi0/1
r6-edge.virl.info Gi0/2 120 R Gi0/1
r6-edge.virl.info Gi0/0 120 R Gi0/0

Total entries displayed: 6
```

在输出中，您将看到`G0/0`配置为 MGMT 接口；因此，您将看到 LLDP 对等方，就好像它们在一个平坦的管理网络上一样。我们真正关心的是连接到其他对等方的`G0/1`和`G0/2`接口。当我们准备解析输出并构建我们的拓扑图时，这些知识将派上用场。

# 信息检索

我们现在可以使用另一个 Ansible playbook，即`cisco_discover_lldp.yml`，在设备上执行 LLDP 命令，并将每个设备的输出复制到`tmp`目录中：

```py
<skip>
 tasks:
   - name: Query for LLDP Neighbors
     ios_command:
       commands: show lldp neighbors
       provider: "{{ cli }}"
<skip>
```

./tmp 目录现在包含所有路由器的输出（显示 LLDP 邻居）的文件：

```py
$ ls -l tmp/
total 20
-rw-rw-r-- 1 echou echou 630 Mar 13 17:12 r1_lldp_output.txt
-rw-rw-r-- 1 echou echou 630 Mar 13 17:12 r2_lldp_output.txt
-rw-rw-r-- 1 echou echou 701 Mar 12 12:28 r3_lldp_output.txt
-rw-rw-r-- 1 echou echou 772 Mar 12 12:28 r5-tor_lldp_output.txt
-rw-rw-r-- 1 echou echou 630 Mar 13 17:12 r6-edge_lldp_output.txt
```

`r1_lldp_output.txt`的内容是我们 Ansible playbook 中的`output.stdout_lines`变量：

```py
$ cat tmp/r1_lldp_output.txt

[["Capability codes:", " (R) Router, (B) Bridge, (T) Telephone, (C) DOCSIS Cable Device", " (W) WLAN Access Point, (P) Repeater, (S) Station, (O) Other", "", "Device ID Local Intf Hold-time Capability Port ID", "r2.virl.info Gi0/0 120 R Gi0/0", "r3.virl.info Gi0/0 120 R Gi0/0", "r5-tor.virl.info Gi0/0 120 R Gi0/0", "r5-tor.virl.info Gi0/1 120 R Gi0/1", "r6-edge.virl.info Gi0/0 120 R Gi0/0", "", "Total entries displayed: 5", ""]]
```

# Python 解析脚本

我们现在可以使用 Python 脚本解析每个设备的 LLDP 邻居输出，并从结果构建网络拓扑图。目的是自动检查设备，看看 LLDP 邻居是否由于链路故障或其他问题而消失。让我们看看`cisco_graph_lldp.py`文件，看看是如何做到的。

我们从包的必要导入开始：一个空列表，我们将用节点关系的元组填充它。我们也知道设备上的`Gi0/0`连接到管理网络；因此，我们只在`show LLDP neighbors`输出中搜索`Gi0/[1234]`作为我们的正则表达式模式：

```py
import glob, re
from graphviz import Digraph, Source
pattern = re.compile('Gi0/[1234]')
device_lldp_neighbors = []
```

我们将使用`glob.glob()`方法遍历`./tmp`目录中的所有文件，解析出设备名称，并找到设备连接的邻居。脚本中有一些嵌入的打印语句，我们可以在最终版本中注释掉；如果取消注释，我们可以看到解析的结果：

```py
device: r1
 neighbors: r5-tor
 neighbors: r6-edge
device: r5-tor
 neighbors: r2
 neighbors: r3
 neighbors: r1
device: r2
 neighbors: r5-tor
 neighbors: r6-edge
device: r3
 neighbors: r5-tor
 neighbors: r6-edge
device: r6-edge
 neighbors: r2
 neighbors: r3
 neighbors: r1
```

完全填充的边列表包含了由设备及其邻居组成的元组：

```py
Edges: [('r1', 'r5-tor'), ('r1', 'r6-edge'), ('r5-tor', 'r2'), ('r5-tor', 'r3'), ('r5-tor', 'r1'), ('r2', 'r5-tor'), ('r2', 'r6-edge'), ('r3', 'r5-tor'), ('r3', 'r6-edge'), ('r6-edge', 'r2'), ('r6-edge', 'r3'), ('r6-edge', 'r1')]
```

我们现在可以使用 Graphviz 包构建网络拓扑图。最重要的部分是解压代表边关系的元组：

```py
my_graph = Digraph("My_Network")
<skip>
# construct the edge relationships
for neighbors in device_lldp_neighbors:
    node1, node2 = neighbors
    my_graph.edge(node1, node2)
```

如果我们打印出结果的源 dot 文件，它将是我们网络的准确表示：

```py
digraph My_Network {
   r1 -> "r5-tor"
   r1 -> "r6-edge"
   "r5-tor" -> r2
   "r5-tor" -> r3
   "r5-tor" -> r1
   r2 -> "r5-tor"
   r2 -> "r6-edge"
   r3 -> "r5-tor"
   r3 -> "r6-edge"
   "r6-edge" -> r2
   "r6-edge" -> r3
   "r6-edge" -> r1
}
```

有时，看到相同的链接两次会让人困惑；例如，`r2`到`r5-tor`的链接在上一个图表中每个方向都出现了两次。作为网络工程师，我们知道有时物理链接故障会导致单向链接，我们希望看到这种情况。

如果我们按原样绘制图表，节点的放置会有点奇怪。节点的放置是自动渲染的。以下图表说明了默认布局以及`neato`布局的渲染，即有向图（`My_Network`，`engine='neato'`）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/dde9bc1b-9f98-4da2-ac4e-4bea01181aa1.png)

`neato`布局表示尝试绘制更少层次结构的无向图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/54d47a85-be7a-4294-acf5-056fae7ad784.png)

有时，工具提供的默认布局就很好，特别是如果你的目标是检测故障而不是使其视觉上吸引人。然而，在这种情况下，让我们看看如何将原始 DOT 语言旋钮插入源文件。通过研究，我们知道可以使用`rank`命令指定一些节点可以保持在同一级别。然而，在 Graphviz Python API 中没有提供这个选项。幸运的是，dot 源文件只是一个字符串，我们可以使用`replace()`方法插入原始 dot 注释，如下所示：

```py
source = my_graph.source
original_text = "digraph My_Network {"
new_text = 'digraph My_Network {n{rank=same Client "r6-edge"}n{rank=same r1 r2 r3}n'
new_source = source.replace(original_text, new_text)
new_graph = Source(new_source)new_graph.render("output/chapter8_lldp_graph.gv")
```

最终结果是一个新的源文件，我们可以从中渲染最终的拓扑图：

```py
digraph My_Network {
{rank=same Client "r6-edge"}
{rank=same r1 r2 r3}
                Client -> "r6-edge"
                "r5-tor" -> Server
                r1 -> "r5-tor"
                r1 -> "r6-edge"
                "r5-tor" -> r2
                "r5-tor" -> r3
                "r5-tor" -> r1
                r2 -> "r5-tor"
                r2 -> "r6-edge"
                r3 -> "r5-tor"
                r3 -> "r6-edge"
               "r6-edge" -> r2
               "r6-edge" -> r3
               "r6-edge" -> r1
}
```

图现在可以使用了：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/b0444bef-47f9-44c4-a33c-e9b8aca1caee.png)

# 最终 playbook

我们现在准备将这个新的解析脚本重新整合到我们的 playbook 中。我们现在可以添加渲染输出和图形生成的额外任务到`cisco_discover_lldp.yml`中：

```py
  tasks:
    - name: Query for LLDP Neighbors
      ios_command:
        commands: show lldp neighbors
        provider: "{{ cli }}"

      register: output

    - name: show output
      debug:
        var: output

    - name: copy output to file
      copy: content="{{ output.stdout_lines }}" dest="./tmp/{{ inventory_hostname }}_lldp_output.txt"

    - name: Execute Python script to render output
      command: ./cisco_graph_lldp.py
```

这本 playbook 现在将包括四个任务，涵盖了在 Cisco 设备上执行`show lldp`命令的端到端过程，将输出显示在屏幕上，将输出复制到单独的文件，然后通过 Python 脚本呈现输出。

playbook 现在可以通过`cron`或其他方式定期运行。它将自动查询设备的 LLDP 邻居并构建图表，该图表将代表路由器所知的当前拓扑结构。

我们可以通过关闭`r6-edge`上的`Gi0/1`和`Go0/2`接口来测试这一点。当 LLDP 邻居超时时，它们将从`r6-edge`的 LLDP 表中消失。

```py
r6-edge#sh lldp neighbors
...
Device ID Local Intf Hold-time Capability Port ID
r2.virl.info Gi0/0 120 R Gi0/0
r3.virl.info Gi0/3 120 R Gi0/2
r3.virl.info Gi0/0 120 R Gi0/0
r5-tor.virl.info Gi0/0 120 R Gi0/0
r1.virl.info Gi0/0 120 R Gi0/0

Total entries displayed: 5
```

如果我们执行这个 playbook，图表将自动显示`r6-edge`只连接到`r3`，我们可以开始排查为什么会这样。

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/061f359c-1354-4204-a779-51bf15a11c9c.png)

这是一个相对较长的例子。我们使用了书中学到的工具——Ansible 和 Python——来模块化和将任务分解为可重用的部分。然后我们使用了一个新工具，即 Graphviz，来帮助监视网络的非时间序列数据，如网络拓扑关系。

# 基于流的监控

正如章节介绍中提到的，除了轮询技术（如 SNMP）之外，我们还可以使用推送策略，允许设备将网络信息推送到管理站点。NetFlow 及其密切相关的 IPFIX 和 sFlow 就是从网络设备向管理站点推送的信息的例子。我们可以认为`推送`方法更具可持续性，因为网络设备本身负责分配必要的资源来推送信息。例如，如果设备的 CPU 繁忙，它可以选择跳过流导出过程，而优先路由数据包，这正是我们想要的。

根据 IETF 的定义，流是从发送应用程序到接收应用程序的一系列数据包。如果我们回顾 OSI 模型，流就是构成两个应用程序之间通信的单个单位。每个流包括多个数据包；有些流有更多的数据包（如视频流），而有些只有几个（如 HTTP 请求）。如果你思考一下流，你会注意到路由器和交换机可能关心数据包和帧，但应用程序和用户通常更关心网络流。

基于流的监控通常指的是 NetFlow、IPFIX 和 sFlow：

+   **NetFlow**：NetFlow v5 是一种技术，网络设备会缓存流条目，并通过匹配元组集（源接口、源 IP/端口、目的 IP/端口等）来聚合数据包。一旦流完成，网络设备会导出流特征，包括流中的总字节数和数据包计数，到管理站点。

+   **IPFIX**：IPFIX 是结构化流的提议标准，类似于 NetFlow v9，也被称为灵活 NetFlow。基本上，它是一个可定义的流导出，允许用户导出网络设备了解的几乎任何内容。灵活性往往是以简单性为代价的，与 NetFlow v5 相比，IPFIX 的配置更加复杂。额外的复杂性使其不太适合初学者学习。但是，一旦你熟悉了 NetFlow v5，你就能够解析 IPFIX，只要你匹配模板定义。

+   sFlow：sFlow 实际上没有流或数据包聚合的概念。它对数据包进行两种类型的抽样。它随机抽样*n*个数据包/应用程序，并具有基于时间的抽样计数器。它将信息发送到管理站，管理站通过参考接收到的数据包样本类型和计数器来推导网络流信息。由于它不在网络设备上执行任何聚合，可以说 sFlow 比 NetFlow 和 IPFIX 更具可扩展性。

了解每个模块的最佳方法可能是直接进入示例。

# 使用 Python 解析 NetFlow

我们可以使用 Python 解析在线上传输的 NetFlow 数据报。这为我们提供了一种详细查看 NetFlow 数据包以及在其工作不如预期时排除任何 NetFlow 问题的方法。

首先，让我们在 VIRL 网络的客户端和服务器之间生成一些流量。我们可以使用 Python 的内置 HTTP 服务器模块快速在充当服务器的 VIRL 主机上启动一个简单的 HTTP 服务器：

```py
cisco@Server:~$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 ...
```

对于 Python 2，该模块的名称为`SimpleHTTPServer`；例如，`python2 -m SimpleHTTPServer`。

我们可以在 Python 脚本中创建一个简短的`while`循环，不断向客户端的 Web 服务器发送`HTTP GET`：

```py
sudo apt-get install python-pip python3-pip
sudo pip install requests
sudo pip3 install requests

$ cat http_get.py
import requests, time
while True:
 r = requests.get('http://10.0.0.5:8000')
 print(r.text)
 time.sleep(5)
```

客户端应该得到一个非常简单的 HTML 页面：

```py
cisco@Client:~$ python3 http_get.py
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN"><html>
<title>Directory listing for /</title>
<body>
...
</body>
</html>
```

我们还应该看到客户端每五秒不断发出请求：

```py
cisco@Server:~$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 ...
10.0.0.9 - - [15/Mar/2017 08:28:29] "GET / HTTP/1.1" 200 -
10.0.0.9 - - [15/Mar/2017 08:28:34] "GET / HTTP/1.1" 200 -
```

我们可以从任何设备导出 NetFlow，但由于`r6-edge`是客户端主机的第一跳，我们将使此路由器将 NetFlow 导出到端口`9995`的管理主机。

在此示例中，我们仅使用一个设备进行演示；因此，我们手动配置它所需的命令。在下一节中，当我们在所有设备上启用 NetFlow 时，我们将使用 Ansible playbook 一次性配置所有路由器。

在 Cisco IOS 设备上导出 NetFlow 需要以下配置：

```py
!
ip flow-export version 5
ip flow-export destination 172.16.1.173 9995 vrf Mgmt-intf
!
interface GigabitEthernet0/4
 description to Client
 ip address 10.0.0.10 255.255.255.252
 ip flow ingress
 ip flow egress
...
!
```

接下来，让我们看一下 Python 解析器脚本。

# Python socket 和 struct

脚本`netFlow_v5_parser.py`是从 Brian Rak 的博客文章[`blog.devicenull.org/2013/09/04/python-netflow-v5-parser.html`](http://blog.devicenull.org/2013/09/04/python-netflow-v5-parser.html)修改而来。修改主要是为了 Python 3 兼容性以及解析额外的 NetFlow 版本 5 字段。我们选择 NetFlow v5 而不是 NetFlow v9 的原因是 v9 更复杂，使用模板来映射字段，使得在入门会话中更难学习。但是，由于 NetFlow 版本 9 是原始 NetFlow 版本 5 的扩展格式，本节介绍的所有概念都适用于它。

因为 NetFlow 数据包在线上传输时以字节表示，我们将使用标准库中包含的 Python struct 模块将字节转换为本机 Python 数据类型。

您可以在[`docs.python.org/3.5/library/socket.html`](https://docs.python.org/3.5/library/socket.html)和[`docs.python.org/3.5/library/struct.html`](https://docs.python.org/3.5/library/struct.html)找到有关这两个模块的更多信息。

我们将首先使用 socket 模块绑定和监听 UDP 数据报。使用`socket.AF_INET`，我们打算监听 IPv4 地址套接字；使用`socket.SOCK_DGRAM`，我们指定将查看 UDP 数据报：

```py
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 9995))
```

我们将启动一个循环，并每次从线上检索 1,500 字节的信息：

```py
while True:
        buf, addr = sock.recvfrom(1500)
```

以下行是我们开始解构或解包数据包的地方。`!HH`的第一个参数指定了网络的大端字节顺序，感叹号表示大端字节顺序，以及 C 类型的格式（`H = 2`字节无符号短整数）：

```py
(version, count) = struct.unpack('!HH',buf[0:4])
```

前四个字节包括版本和此数据包中导出的流数。如果您没有记住 NetFlow 版本 5 标头（顺便说一句，这是一个玩笑；我只是在想要快速入睡时才会读标头），这里有一个快速浏览：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/1cb08f1a-95f9-4402-a1b2-ee4753fc54b8.png)NetFlow v5 标头（来源：http://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html#wp1006108）

其余的标头可以根据字节位置和数据类型进行相应的解析：

```py
 (sys_uptime, unix_secs, unix_nsecs, flow_sequence) = struct.unpack('!IIII', buf[4:20])
 (engine_type, engine_id, sampling_interval) = struct.unpack('!BBH', buf[20:24])
```

接下来的`while`循环将使用流记录填充`nfdata`字典，解包源地址和端口、目的地址和端口、数据包计数和字节计数，并在屏幕上打印出信息：

```py
for i in range(0, count):
    try:
        base = SIZE_OF_HEADER+(i*SIZE_OF_RECORD)
        data = struct.unpack('!IIIIHH',buf[base+16:base+36])
        input_int, output_int = struct.unpack('!HH', buf[base+12:base+16])
        nfdata[i] = {}
        nfdata[i]['saddr'] = inet_ntoa(buf[base+0:base+4])
        nfdata[i]['daddr'] = inet_ntoa(buf[base+4:base+8])
        nfdata[i]['pcount'] = data[0]
        nfdata[i]['bcount'] = data[1]
...
```

脚本的输出允许您一目了然地查看标头以及流内容：

```py
Headers:
NetFlow Version: 5
Flow Count: 9
System Uptime: 290826756
Epoch Time in seconds: 1489636168
Epoch Time in nanoseconds: 401224368
Sequence counter of total flow: 77616
0 192.168.0.1:26828 -> 192.168.0.5:179 1 packts 40 bytes
1 10.0.0.9:52912 -> 10.0.0.5:8000 6 packts 487 bytes
2 10.0.0.9:52912 -> 10.0.0.5:8000 6 packts 487 bytes
3 10.0.0.5:8000 -> 10.0.0.9:52912 5 packts 973 bytes
4 10.0.0.5:8000 -> 10.0.0.9:52912 5 packts 973 bytes
5 10.0.0.9:52913 -> 10.0.0.5:8000 6 packts 487 bytes
6 10.0.0.9:52913 -> 10.0.0.5:8000 6 packts 487 bytes
7 10.0.0.5:8000 -> 10.0.0.9:52913 5 packts 973 bytes
8 10.0.0.5:8000 -> 10.0.0.9:52913 5 packts 973 bytes
```

请注意，在 NetFlow 版本 5 中，记录的大小固定为 48 字节；因此，循环和脚本相对简单。但是，在 NetFlow 版本 9 或 IPFIX 的情况下，在标头之后，有一个模板 FlowSet（[`www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html`](http://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html)），它指定了字段计数、字段类型和字段长度。这使得收集器可以在不事先知道数据格式的情况下解析数据。

通过在脚本中解析 NetFlow 数据，我们对字段有了很好的理解，但这非常繁琐且难以扩展。正如您可能已经猜到的那样，还有其他工具可以帮助我们避免逐个解析 NetFlow 记录的问题。让我们在接下来的部分看看这样的一个工具，名为**ntop**。

# ntop 流量监控

就像第七章中的 PySNMP 脚本，以及本章中的 NetFlow 解析器脚本一样，我们可以使用 Python 脚本来处理线路上的低级任务。但是，也有一些工具，比如 Cacti，它是一个包含数据收集（轮询器）、数据存储（RRD）和用于可视化的 web 前端的一体化开源软件包。这些工具可以通过将经常使用的功能和软件打包到一个软件包中来节省大量工作。

在 NetFlow 的情况下，有许多开源和商业 NetFlow 收集器可供选择。如果您快速搜索前 N 个开源 NetFlow 分析器，您将看到许多不同工具的比较研究。它们每个都有自己的优势和劣势；使用哪一个实际上是一种偏好、平台和您对定制的兴趣。我建议选择一个既支持 v5 又支持 v9，可能还支持 sFlow 的工具。其次要考虑的是工具是否是用您能理解的语言编写的；我想拥有 Python 可扩展性会是一件好事。

我喜欢并以前使用过的两个开源 NetFlow 工具是 NfSen（后端收集器为 NFDUMP）和`ntop`（或`ntopng`）。在这两者中，`ntop`是更为知名的流量分析器；它可以在 Windows 和 Linux 平台上运行，并且与 Python 集成良好。因此，在本节中，让我们以`ntop`为例。

我们的 Ubuntu 主机的安装很简单：

```py
$ sudo apt-get install ntop
```

安装过程将提示输入必要的接口以进行监听，并设置管理员密码。默认情况下，`ntop` web 界面监听端口为`3000`，而探针监听 UDP 端口为`5556`。在网络设备上，我们需要指定 NetFlow 导出器的位置：

```py
!
ip flow-export version 5
ip flow-export destination 172.16.1.173 5556 vrf Mgmt-intf
!
```

默认情况下，IOSv 创建一个名为`Mgmt-intf`的 VRF，并将`Gi0/0`放在 VRF 下。

我们还需要在接口配置下指定流量导出的方向，比如入口或出口：

```py
!
interface GigabitEthernet0/0
...
 ip flow ingress
 ip flow egress
...
```

供您参考，我已经包含了 Ansible playbook，`cisco_config_netflow.yml`，用于配置实验设备进行 NetFlow 导出。

`r5-tor`和`r6-edge`比`r1`、`r2`和`r3`多两个接口。

执行 playbook 并确保设备上的更改已正确应用：

```py
$ ansible-playbook -i hosts cisco_config_netflow.yml

TASK [configure netflow export station] ****************************************
changed: [r1]
changed: [r3]
changed: [r2]
changed: [r5-tor]
changed: [r6-edge]

TASK [configure flow export on Gi0/0] ******************************************
changed: [r2]
changed: [r1]
changed: [r6-edge]
changed: [r5-tor]
changed: [r3]
...
PLAY RECAP *********************************************************************
r1 : ok=4 changed=4 unreachable=0 failed=0
r2 : ok=4 changed=4 unreachable=0 failed=0
r3 : ok=4 changed=4 unreachable=0 failed=0
r5-tor : ok=6 changed=6 unreachable=0 failed=0
r6-edge : ok=6 changed=6 unreachable=0 failed=0

##Checking r2 for NetFlow configuration
r2#sh run | i flow
 ip flow ingress
 ip flow egress
 ip flow ingress
 ip flow egress
 ip flow ingress
 ip flow egress
ip flow-export version 5
ip flow-export destination 172.16.1.173 5556 vrf Mgmt-intf 
```

一切都设置好后，您可以检查 ntop web 界面以查看本地 IP 流量：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/e414a37d-aacc-43ef-a619-d95d026509cf.png)

ntop 最常用的功能之一是使用它来查看最活跃的对话者图表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/b5516589-b8af-4feb-b605-e603552db5bd.png)

ntop 报告引擎是用 C 编写的；它快速高效，但是需要对 C 有足够的了解才能做一些像改变 web 前端这样简单的事情，这并不符合现代敏捷开发的思维方式。

在 2000 年代中期，ntop 的人们在 Perl 上尝试了几次，最终决定将 Python 嵌入为可扩展的脚本引擎。让我们来看看。

# ntop 的 Python 扩展

我们可以使用 Python 通过 ntop web 服务器来扩展 ntop。ntop web 服务器可以执行 Python 脚本。在高层次上，脚本将执行以下操作：

+   访问 ntop 状态的方法

+   Python CGI 模块处理表单和 URL 参数

+   制作生成动态 HTML 页面的模板

+   每个 Python 脚本都可以从`stdin`读取并打印出`stdout/stderr`

+   `stdout`脚本是返回的 HTTP 页面

有几个资源对于 Python 集成非常有用。在 Web 界面下，您可以单击关于|显示配置，以查看 Python 解释器版本以及 Python 脚本的目录：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/df42b61f-c658-4b7b-b622-3d0a1e38244d.png)Python 版本

您还可以检查 Python 脚本应该驻留的各个目录：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/f76bf24a-6008-4e58-90a9-cd40ddd4b3e4.png)

插件目录

在关于|在线文档|Python ntop 引擎下，有 Python API 和教程的链接：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/bb5f4a60-be4f-443f-b572-5b0cab30ba76.png)Python ntop 文档

如前所述，ntop web 服务器直接执行放置在指定目录下的 Python 脚本：

```py
$ pwd
/usr/share/ntop/python
```

我们将把我们的第一个脚本，即`chapter8_ntop_1.py`，放在目录中。Python `CGI`模块处理表单并解析 URL 参数：

```py
# Import modules for CGI handling
import cgi, cgitb
import ntop

# Parse URL
cgitb.enable();
```

`ntop`实现了三个 Python 模块；每个模块都有特定的目的：

+   `ntop`：此模块与`ntop`引擎交互

+   **主机**：此模块用于深入了解特定主机的信息

+   **接口**：此模块表示有关本地主机接口的信息

在我们的脚本中，我们将使用`ntop`模块来检索`ntop`引擎信息，并使用`sendString()`方法发送 HTML 正文文本：

```py
form = cgi.FieldStorage();
name = form.getvalue('Name', default="Eric")

version = ntop.version()
os = ntop.os()
uptime = ntop.uptime()

ntop.printHTMLHeader('Mastering Python Networking', 1, 0)
ntop.sendString("Hello, "+ name +"<br>")
ntop.sendString("Ntop Information: %s %s %s" % (version, os, uptime))
ntop.printHTMLFooter()
```

我们将使用`http://<ip>:3000/python/<script name>`来执行 Python 脚本。这是我们的`chapter8_ntop_1.py`脚本的结果：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/869976ca-1508-4a7b-a9ba-4bdd8c66b83e.png)

我们可以看另一个与接口模块交互的示例，`chapter8_ntop_2.py`。我们将使用 API 来遍历接口：

```py
import ntop, interface, json

ifnames = []
try:
    for i in range(interface.numInterfaces()):
        ifnames.append(interface.name(i))

except Exception as inst:
    print type(inst) # the exception instance
    print inst.args # arguments stored in .args
    print inst # __str__ allows args to printed directly
...
```

生成的页面将显示 ntop 接口：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/6140fbbb-7e30-4897-ad3f-fabcd4ce6fa6.png)

除了社区版本外，ntop 还提供了一些商业产品供您选择。凭借活跃的开源社区、商业支持和 Python 可扩展性，ntop 是您 NetFlow 监控需求的不错选择。

接下来，让我们来看看 NetFlow 的表兄弟：sFlow。

# sFlow

sFlow 最初由 InMon（[`www.inmon.com`](http://www.inmon.com)）开发，后来通过 RFC 进行了标准化。当前版本是 v5。行业内许多人认为 sFlow 的主要优势是其可扩展性。sFlow 使用随机的一种`n`数据包流样本以及计数器样本的轮询间隔来推导出流量的估计；这比网络设备的 NetFlow 更节省 CPU。sFlow 的统计采样与硬件集成，并提供实时的原始导出。

出于可扩展性和竞争原因，sFlow 通常比 NetFlow 更受新供应商的青睐，例如 Arista Networks、Vyatta 和 A10 Networks。虽然思科在其 Nexus 产品线上支持 sFlow，但通常*不*支持在思科平台上使用 sFlow。

# SFlowtool 和 sFlow-RT 与 Python

很遗憾，到目前为止，sFlow 是我们的 VIRL 实验室设备不支持的东西（即使是 NX-OSv 虚拟交换机也不支持）。您可以使用思科 Nexus 3000 交换机或其他支持 sFlow 的供应商交换机，例如 Arista。实验室的另一个好选择是使用 Arista vEOS 虚拟实例。我碰巧可以访问运行 7.0（3）的思科 Nexus 3048 交换机，我将在本节中使用它作为 sFlow 导出器。

思科 Nexus 3000 的 sFlow 配置非常简单：

```py
Nexus-2# sh run | i sflow
feature sflow
sflow max-sampled-size 256
sflow counter-poll-interval 10
sflow collector-ip 192.168.199.185 vrf management
sflow agent-ip 192.168.199.148
sflow data-source interface Ethernet1/48
```

摄取 sFlow 的最简单方法是使用`sflowtool`。有关安装说明，请参阅[`blog.sflow.com/2011/12/sflowtool.html`](http://blog.sflow.com/2011/12/sflowtool.html)上的文档：

```py
$ wget http://www.inmon.com/bin/sflowtool-3.22.tar.gz
$ tar -xvzf sflowtool-3.22.tar.gz
$ cd sflowtool-3.22/
$ ./configure
$ make
$ sudo make install
```

安装完成后，您可以启动`sflowtool`并查看 Nexus 3048 发送到标准输出的数据报：

```py
$ sflowtool
startDatagram =================================
datagramSourceIP 192.168.199.148
datagramSize 88
unixSecondsUTC 1489727283
datagramVersion 5
agentSubId 100
agent 192.168.199.148
packetSequenceNo 5250248
sysUpTime 4017060520
samplesInPacket 1
startSample ----------------------
sampleType_tag 0:4
sampleType COUNTERSSAMPLE
sampleSequenceNo 2503508
sourceId 2:1
counterBlock_tag 0:1001
5s_cpu 0.00
1m_cpu 21.00
5m_cpu 20.80
total_memory_bytes 3997478912
free_memory_bytes 1083838464
endSample ----------------------
endDatagram =================================
```

`sflowtool` GitHub 存储库（[`github.com/sflow/sflowtool`](https://github.com/sflow/sflowtool)）上有许多很好的用法示例；其中之一是使用脚本接收`sflowtool`输入并解析输出。我们可以使用 Python 脚本来实现这个目的。在`chapter8_sflowtool_1.py`示例中，我们将使用`sys.stdin.readline`接收输入，并使用正则表达式搜索仅打印包含单词`agent`的行当我们看到 sFlow 数据包时：

```py
import sys, re
for line in iter(sys.stdin.readline, ''):
    if re.search('agent ', line):
        print(line.strip())
```

该脚本可以通过管道传输到`sflowtool`：

```py
$ sflowtool | python3 chapter8_sflowtool_1.py
agent 192.168.199.148
agent 192.168.199.148
```

还有许多其他有用的输出示例，例如`tcpdump`，以 NetFlow 版本 5 记录输出，以及紧凑的逐行输出。这使得`sflowtool`非常灵活，以适应您的监控环境。

ntop 支持 sFlow，这意味着您可以直接将您的 sFlow 导出到 ntop 收集器。如果您的收集器只支持 NetFlow，您可以在 NetFlow 版本 5 格式中使用`sflowtool`输出的`-c`选项：

```py
$ sflowtool --help
...
tcpdump output:
   -t - (output in binary tcpdump(1) format)
   -r file - (read binary tcpdump(1) format)
   -x - (remove all IPV4 content)
   -z pad - (extend tcpdump pkthdr with this many zeros
                          e.g. try -z 8 for tcpdump on Red Hat Linux 6.2)

NetFlow output:
 -c hostname_or_IP - (netflow collector host)
 -d port - (netflow collector UDP port)
 -e - (netflow collector peer_as (default = origin_as))
 -s - (disable scaling of netflow output by sampling rate)
 -S - spoof source of netflow packets to input agent IP
```

或者，您也可以使用 InMon 的 sFlow-RT（[`www.sflow-rt.com/index.php`](http://www.sflow-rt.com/index.php)）作为您的 sFlow 分析引擎。sFlow-RT 从操作员的角度来看，其主要优势在于其庞大的 REST API，可以定制以支持您的用例。您还可以轻松地从 API 中检索指标。您可以在[`www.sflow-rt.com/reference.php`](http://www.sflow-rt.com/reference.php)上查看其广泛的 API 参考。

请注意，sFlow-RT 需要 Java 才能运行以下内容：

```py
$ sudo apt-get install default-jre
$ java -version
openjdk version "1.8.0_121"
OpenJDK Runtime Environment (build 1.8.0_121-8u121-b13-0ubuntu1.16.04.2-b13)
OpenJDK 64-Bit Server VM (build 25.121-b13, mixed mode)
```

安装完成后，下载和运行 sFlow-RT 非常简单（[`sflow-rt.com/download.php`](https://sflow-rt.com/download.php)）：

```py
$ wget http://www.inmon.com/products/sFlow-RT/sflow-rt.tar.gz
$ tar -xvzf sflow-rt.tar.gz
$ cd sflow-rt/
$ ./start.sh
2017-03-17T09:35:01-0700 INFO: Listening, sFlow port 6343
2017-03-17T09:35:02-0700 INFO: Listening, HTTP port 8008
```

我们可以将 Web 浏览器指向 HTTP 端口`8008`并验证安装：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/ac593583-04c5-4b0b-8ade-4a925b583726.png)sFlow-RT about

一旦 sFlow-RT 接收到任何 sFlow 数据包，代理和其他指标将出现：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/1a438b4c-45c7-459a-953f-54991e570b6e.png)sFlow-RT agents

以下是使用 Python 请求从 sFlow-RT 的 REST API 中检索信息的两个示例：

```py
>>> import requests
>>> r = requests.get("http://192.168.199.185:8008/version")
>>> r.text
'2.0-r1180'
>>> r = requests.get("http://192.168.199.185:8008/agents/json")
>>> r.text
'{"192.168.199.148": {n "sFlowDatagramsLost": 0,n "sFlowDatagramSource": ["192.168.199.148"],n "firstSeen": 2195541,n "sFlowFlowDuplicateSamples": 0,n "sFlowDatagramsReceived": 441,n "sFlowCounterDatasources": 2,n "sFlowFlowOutOfOrderSamples": 0,n "sFlowFlowSamples": 0,n "sFlowDatagramsOutOfOrder": 0,n "uptime": 4060470520,n "sFlowCounterDuplicateSamples": 0,n "lastSeen": 3631,n "sFlowDatagramsDuplicates": 0,n "sFlowFlowDrops": 0,n "sFlowFlowLostSamples": 0,n "sFlowCounterSamples": 438,n "sFlowCounterLostSamples": 0,n "sFlowFlowDatasources": 0,n "sFlowCounterOutOfOrderSamples": 0n}}'
```

咨询参考文档，了解可用于您需求的其他 REST 端点。接下来，我们将看看另一个工具，称为**Elasticsearch**，它正在成为 Syslog 索引和一般网络监控的相当流行的工具。

# Elasticsearch（ELK 堆栈）

正如我们在本章中所看到的，仅使用我们已经使用的 Python 工具就足以监控您的网络，并具有足够的可扩展性，适用于各种规模的网络，无论大小。然而，我想介绍一个名为**Elasticsearch**（[`www.elastic.co/`](https://www.elastic.co/)）的额外的开源、通用分布式搜索和分析引擎。它通常被称为**Elastic**或**ELK 堆栈**，用于将**Elastic**与前端和输入包**Logstash**和**Kibana**结合在一起。

如果您总体上看网络监控，实际上是分析网络数据并理解其中的意义。ELK 堆栈包含 Elasticsearch、Logstash 和 Kibana 作为完整的堆栈，使用 Logstash 摄取信息，使用 Elasticsearch 索引和分析数据，并通过 Kibana 呈现图形输出。它实际上是三个项目合而为一。它还具有灵活性，可以用其他输入替换 Logstash，比如**Beats**。或者，您可以使用其他工具，比如**Grafana**，而不是 Kibana 进行可视化。Elastic Co*.*的 ELK 堆栈还提供许多附加工具，称为**X-Pack**，用于额外的安全性、警报、监控等。

正如您可能从描述中可以看出，ELK（甚至仅是 Elasticsearch）是一个深入的主题，有许多关于这个主题的书籍。即使只涵盖基本用法，也会占用比我们在这本书中可以空出的更多空间。我曾考虑过将这个主题从书中删除，仅仅是因为它的深度。然而，ELK 已经成为我正在进行的许多项目中非常重要的工具，包括网络监控。我觉得不把它放在书中会对你造成很大的伤害。

因此，我将花几页时间简要介绍这个工具以及一些用例，以及一些信息，让您有兴趣深入了解。我们将讨论以下主题：

+   建立托管的 ELK 服务

+   Logstash 格式

+   Logstash 格式的 Python 辅助脚本

# 建立托管的 ELK 服务

整个 ELK 堆栈可以安装为独立服务器或分布在多台服务器上。安装步骤可在[`www.elastic.co/guide/en/elastic-stack/current/installing-elastic-stack.html`](https://www.elastic.co/guide/en/elastic-stack/current/installing-elastic-stack.html)上找到。根据我的经验，即使只有少量数据，运行 ELK 堆栈的单个虚拟机通常也会耗尽资源。我第一次尝试将 ELK 作为单个虚拟机运行，仅持续了几天，几乎只有两三个网络设备向其发送日志信息。在作为初学者运行自己的集群的几次不成功尝试之后，我最终决定将 ELK 堆栈作为托管服务运行，这也是我建议您开始使用的方式。

作为托管服务，有两个提供商可以考虑：

+   **Amazon Elasticsearch Service**（[`aws.amazon.com/elasticsearch-service/`](https://aws.amazon.com/elasticsearch-service/)）

+   **Elastic Cloud**（[`cloud.elastic.co/`](https://cloud.elastic.co/)）

目前，AWS 提供了一个免费的套餐，很容易开始使用，并且与当前的 AWS 工具套件紧密集成，例如身份服务（[`aws.amazon.com/iam/`](https://aws.amazon.com/iam/)）和 lambda 函数（[`aws.amazon.com/lambda/`](https://aws.amazon.com/lambda/)）。然而，与 Elastic Cloud 相比，AWS 的 Elasticsearch 服务没有最新的功能，也没有扩展的 x-pack 集成。然而，由于 AWS 提供了免费套餐，我的建议是您从 AWS Elasticsearch 服务开始。如果您后来发现需要比 AWS 提供的更多功能，您总是可以转移到 Elastic Cloud。

设置服务很简单；我们只需要选择我们的区域并为我们的第一个域名命名。设置完成后，我们可以使用访问策略来通过 IP 地址限制输入；确保这是 AWS 将看到的源 IP 地址（如果您的主机 IP 地址在 NAT 防火墙后面被转换，请指定您的公司公共 IP）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-py-net-2e/img/75b38547-2d30-40f8-a951-7af6777231e8.png)

# Logstash 格式

Logstash 可以安装在您习惯发送网络日志的服务器上。安装步骤可在[`www.elastic.co/guide/en/logstash/current/installing-logstash.html`](https://www.elastic.co/guide/en/logstash/current/installing-logstash.html)找到。默认情况下，您可以将 Logstash 配置文件放在`/etc/logstash/conf.d/`下。该文件采用`input-filter-output`格式（[`www.elastic.co/guide/en/logstash/current/advanced-pipeline.html`](https://www.elastic.co/guide/en/logstash/current/advanced-pipeline.html)）。在下面的示例中，我们将输入指定为`网络日志文件`，并使用占位符过滤输入，输出为将消息打印到控制台以及将输出导出到我们的 AWS Elasticsearch 服务实例：

```py
input {
  file {
    type => "network_log"
    path => "path to your network log file"
 }
}
filter {
  if [type] == "network_log" {
  }
}
output {
  stdout { codec => rubydebug }
  elasticsearch {
  index => "logstash_network_log-%{+YYYY.MM.dd}"
  hosts => ["http://<instance>.<region>.es.amazonaws.com"]
  }
}
```

现在让我们来看看我们可以用 Python 和 Logstash 做的其他事情。

# 用于 Logstash 格式的 Python 辅助脚本

前面的 Logstash 配置将允许我们摄取网络日志并在 Elasticsearch 上创建索引。如果我们打算放入 ELK 的文本格式不是标准的日志格式，会发生什么？这就是 Python 可以帮助的地方。在下一个示例中，我们将执行以下操作：

1.  使用 Python 脚本检索 Spamhaus 项目认为是拒收列表的 IP 地址列表（[`www.spamhaus.org/drop/drop.txt`](https://www.spamhaus.org/drop/drop.txt)）

1.  使用 Python 日志模块以 Logstash 可以摄取的方式格式化信息

1.  修改 Logstash 配置文件，以便任何新输入都可以发送到 AWS Elasticsearch 服务

`chapter8_logstash_1.py`脚本包含我们将使用的代码。除了模块导入之外，我们将定义基本的日志配置。该部分直接配置输出，并且应该与 Logstash 格式匹配：

```py
#!/usr/env/bin python

#https://www.spamhaus.org/drop/drop.txt

import logging, pprint, re
import requests, json, datetime
from collections import OrderedDict

#logging configuration
logging.basicConfig(filename='./tmp/spamhaus_drop_list.log', level=logging.INFO, format='%(asctime)s %(message)s', datefmt='%b %d %I:%M:%S')
```

我们将定义一些更多的变量，并将请求中的 IP 地址列表保存在一个变量中：

```py
host = 'python_networking'
process = 'spamhause_drop_list'

r = requests.get('https://www.spamhaus.org/drop/drop.txt')
result = r.text.strip()

timeInUTC = datetime.datetime.utcnow().isoformat()
Item = OrderedDict()
Item["Time"] = timeInUTC
```

脚本的最后一部分是一个循环，用于解析输出并将其写入新的日志文件：

```py
for line in result.split('n'):
    if re.match('^;', line) or line == 'r': # comments
        next
    else:
       ip, record_number = line.split(";")
       logging.warning(host + ' ' + process + ': ' + 'src_ip=' + ip.split("/")[0] + ' record_number=' + record_number.strip())
```

以下是日志文件条目的示例：

```py
$ cat tmp/spamhaus_drop_list.log
...
Jul 14 11:35:26 python_networking spamhause_drop_list: src_ip=212.92.127.0 record_number=SBL352250
Jul 14 11:35:26 python_networking spamhause_drop_list: src_ip=216.47.96.0 record_number=SBL125132
Jul 14 11:35:26 python_networking spamhause_drop_list: src_ip=223.0.0.0 record_number=SBL230805
Jul 14 11:35:26 python_networking spamhause_drop_list: src_ip=223.169.0.0 record_number=SBL208009
...
```

然后我们可以相应地修改 Logstash 配置文件以适应我们的新日志格式，首先是添加输入文件位置：

```py
input {
  file {
    type => "network_log"
    path => "path to your network log file"
 }
  file {
    type => "spamhaus_drop_list"
    path => "/home/echou/Master_Python_Networking/Chapter8/tmp/spamhaus_drop_list.log"
 }
}
```

我们可以使用`grok`添加更多的过滤配置：

```py
filter { 
  if [type] == "spamhaus_drop_list" {
     grok {
       match => [ "message", "%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} %{NOTSPACE:process} src_ip=%{IP:src_ip} %{NOTSPACE:record_number}.*"]
       add_tag => ["spamhaus_drop_list"]
     }
  }
}
```

我们可以将输出部分保持不变，因为额外的条目将存储在同一索引中。现在我们可以使用 ELK 堆栈来查询、存储和查看网络日志以及 Spamhaus IP 信息。

# 总结

在本章中，我们看了一些额外的方法，可以利用 Python 来增强我们的网络监控工作。我们首先使用 Python 的 Graphviz 包来创建实时 LLDP 信息报告的网络拓扑图。这使我们能够轻松地显示当前的网络拓扑，以及轻松地注意到任何链路故障。

接下来，我们使用 Python 来解析 NetFlow 版本 5 数据包，以增强我们对 NetFlow 的理解和故障排除能力。我们还研究了如何使用 ntop 和 Python 来扩展 ntop 以进行 NetFlow 监控。sFlow 是一种替代的数据包抽样技术，我们使用`sflowtool`和 sFlow-RT 来解释结果。我们在本章结束时介绍了一个通用的数据分析工具，即 Elasticsearch，或者 ELK 堆栈。

在第九章中，*使用 Python 构建网络 Web 服务*，我们将探讨如何使用 Python Web 框架 Flask 来构建网络 Web 服务。
