# Linux Shell 编程秘籍（五）

> 原文：[`zh.annas-archive.org/md5/ABA4B56CB4F69896DB2E9CFE0817AFEF`](https://zh.annas-archive.org/md5/ABA4B56CB4F69896DB2E9CFE0817AFEF)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：老男孩网络

在本章中，我们将涵盖：

+   基本网络入门

+   让我们 ping 一下！

+   列出网络上所有活动的机器

+   通过网络传输文件

+   使用脚本设置以太网和无线局域网

+   使用 SSH 进行无密码自动登录

+   使用 SSH 在远程主机上运行命令

+   在本地挂载点挂载远程驱动器

+   在网络上多播窗口消息

+   网络流量和端口分析

# 介绍

网络是通过网络互连机器并配置网络中的节点具有不同规格的行为。我们使用 TCP/IP 作为我们的网络堆栈，并且所有操作都基于它。网络是每个计算机系统的重要组成部分。网络中连接的每个节点都被分配一个唯一的 IP 地址以进行标识。网络中有许多参数，如子网掩码、路由、端口、DNS 等，需要基本的理解才能跟进。

许多使用网络的应用程序通过打开和连接到防火墙端口来运行。每个应用程序可能提供诸如数据传输、远程 shell 登录等服务。在由许多机器组成的网络上可以执行许多有趣的管理任务。Shell 脚本可用于配置网络中的节点、测试机器的可用性、自动执行远程主机上的命令等。本章重点介绍了介绍有趣的与网络相关的工具或命令的不同配方，以及它们如何用于解决不同的问题。

# 基本网络入门

在基于网络的配方之前，您有必要对设置网络、术语和命令进行基本了解，例如分配 IP 地址、添加路由等。本配方将概述 GNU/Linux 中用于网络的不同命令及其用法。

## 准备工作

网络中的每个节点都需要分配许多参数才能成功工作并与其他机器互连。一些不同的参数包括 IP 地址、子网掩码、网关、路由、DNS 等。

本配方将介绍`ifconfig`、`route`、`nslookup`和`host`命令。

## 如何做...

网络接口用于连接到网络。通常，在类 UNIX 操作系统的上下文中，网络接口遵循 eth0、eth1 的命名约定。此外，还有其他接口，如 usb0、wlan0 等，可用于 USB 网络接口、无线局域网等网络。

`ifconfig`是用于显示网络接口、子网掩码等详细信息的命令。

`ifconfig`位于`/sbin/ifconfig`。当键入`ifconfig`时，一些 GNU/Linux 发行版会显示错误“找不到命令”。这是因为用户的 PATH 环境变量中没有包含`/sbin`。当键入命令时，Bash 会在 PATH 变量中指定的目录中查找。

默认情况下，在 Debian 中，`ifconfig`不可用，因为`/sbin`不在 PATH 中。

`/sbin/ifconfig`是绝对路径，因此尝试使用绝对路径（即`/sbin/ifconfig`）运行 ifconfig。对于每个系统，默认情况下都会有一个名为'lo'的接口，称为环回，指向当前机器。例如：

```
$ ifconfig
lo        Link encap:Local Loopback
inet addr:127.0.0.1  Mask:255.0.0.0
inet6addr: ::1/128 Scope:Host
 UP LOOPBACK RUNNING  MTU:16436  Metric:1
 RX packets:6078 errors:0 dropped:0 overruns:0 frame:0
 TX packets:6078 errors:0 dropped:0 overruns:0 carrier:0
collisions:0 txqueuelen:0
 RX bytes:634520 (634.5 KB)  TX bytes:634520 (634.5 KB)

wlan0     Link encap:EthernetHWaddr 00:1c:bf:87:25:d2
inet addr:192.168.0.82  Bcast:192.168.3.255  Mask:255.255.252.0
inet6addr: fe80::21c:bfff:fe87:25d2/64 Scope:Link
 UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
 RX packets:420917 errors:0 dropped:0 overruns:0 frame:0
 TX packets:86820 errors:0 dropped:0 overruns:0 carrier:0
collisions:0 txqueuelen:1000
 RX bytes:98027420 (98.0 MB)  TX bytes:22602672 (22.6 MB)

```

`ifconfig`输出中最左边的列显示了网络接口的名称，右侧列显示了与相应网络接口相关的详细信息。

## 还有更多...

有几个附加命令经常用于查询和配置网络。让我们一起了解基本命令和用法。

### 打印网络接口列表

以下是一个一行命令序列，用于打印系统上可用的网络接口列表。

```
$ ifconfig | cut -c-10 | tr -d ' ' | tr -s '\n'
lo
wlan0

```

`ifconfig`输出的每行的前 10 个字符用于写入网络接口的名称。因此，我们使用`cut`提取每行的前 10 个字符。`tr -d ' '`删除每行中的每个空格字符。现在使用`tr -s '\n'`来压缩`\n`换行符，以产生一个接口名称列表。

### 分配和显示 IP 地址

`ifconfig`命令显示系统上可用的每个网络接口的详细信息。但是，我们可以通过使用以下命令将其限制为特定接口：

```
$ ifconfig iface_name

```

例如：

```
$ ifconfig wlan0
wlan0     Link encap:Ethernet HWaddr 00:1c:bf:87:25:d2
inet addr:192.168.0.82  Bcast:192.168.3.255
 Mask:255.255.252.0

```

从前面提到的命令的输出中，我们感兴趣的是 IP 地址、广播地址、硬件地址和子网掩码。它们如下：

+   `HWaddr 00:1c:bf:87:25:d2`是硬件地址（MAC 地址）

+   `inet addr:192.168.0.82`是 IP 地址

+   `Bcast:192.168.3.255`是广播地址

+   子网掩码：255.255.252.0

在几种脚本上下文中，我们可能需要从脚本中提取这些地址中的任何一个以进行进一步操作。

提取 IP 地址是一个常见的任务。为了从`ifconfig`输出中提取 IP 地址，请使用：

```
$ ifconfig wlan0 | egrep -o "inet addr:[^ ]*" | grep -o "[0-9.]*"
192.168.0.82

```

第一个命令`egrep -o "inet addr:[^ ]*"`将打印`inet addr:192.168.0.82`。

模式以`inet addr:`开头，以一些非空格字符序列（由`[^ ]*`指定）结尾。现在在下一个管道中，它打印数字和'.'的字符组合。

为了设置网络接口的 IP 地址，请使用：

```
# ifconfig wlan0 192.168.0.80

```

您需要以 root 身份运行上述命令。`192.168.0.80`是要设置的地址。

设置子网掩码以及 IP 地址如下：

```
# ifconfig wlan0 192.168.0.80  netmask 255.255.252.0

```

### 欺骗硬件地址（MAC 地址）

在某些情况下，通过使用硬件地址提供对网络上计算机的身份验证或过滤，我们可以使用硬件地址欺骗。硬件地址显示为`ifconfig`输出中的`HWaddr 00:1c:bf:87:25:d2`。

我们可以在软件级别欺骗硬件地址，如下所示：

```
# ifconfig eth0 hw ether 00:1c:bf:87:25:d5

```

在上述命令中，`00:1c:bf:87:25:d5`是要分配的新 MAC 地址。

当我们需要通过 MAC 认证的服务提供商访问互联网以为单个机器提供互联网访问时，这可能是有用的。

### 名称服务器和 DNS（域名服务）

互联网的基本寻址方案是 IP 地址（点分十进制形式，例如`202.11.32.75`）。但是，互联网上的资源（例如网站）是通过称为 URL 或域名的 ASCII 字符组合访问的。例如，[google.com](http://google.com)是一个域名。它实际上对应一个 IP 地址。在浏览器中输入 IP 地址也可以访问 URL`www.google.com`。

将 IP 地址与符号名称抽象化的技术称为**域名服务**（**DNS**）。当我们输入`google.com`时，配置了我们网络的 DNS 服务器将域名解析为相应的 IP 地址。而在本地网络上，我们可以使用本地 DNS 通过主机名对网络上的本地机器进行符号命名。

分配给当前系统的名称服务器可以通过读取`/etc/resolv.conf`来查看。例如：

```
$ cat /etc/resolv.conf
nameserver 8.8.8.8

```

我们可以手动添加名称服务器，如下所示：

```
# echo nameserver IP_ADDRESS >> /etc/resolv.conf

```

我们如何获取相应域名的 IP 地址？

获取 IP 地址的最简单方法是尝试 ping 给定的域名，并查看回显回复。例如：

```
$ ping google.com
PING google.com (64.233.181.106) 56(84) bytes of data.
Here 64.233.181.106 is the corresponding IP address.

```

一个域名可以分配多个 IP 地址。在这种情况下，DNS 服务器将从 IP 地址列表中返回一个地址。要获取分配给域名的所有地址，我们应该使用 DNS 查找实用程序。

### DNS 查找

命令行中有不同的 DNS 查找实用程序可用。这些将请求 DNS 服务器进行 IP 地址解析。`host`和`nslookup`是两个 DNS 查找实用程序。

当执行`host`时，它将列出附加到域名的所有 IP 地址。`nslookup`是另一个类似于`host`的命令，它可以用于查询与 DNS 和名称解析相关的详细信息。例如：

```
$ host google.com
google.com has address 64.233.181.105
google.com has address 64.233.181.99
google.com has address 64.233.181.147
google.com has address 64.233.181.106
google.com has address 64.233.181.103
google.com has address 64.233.181.104

```

它还可以列出 DNS 资源记录，如 MX（邮件交换器）如下：

```
$ nslookup google.com
Server:    8.8.8.8
Address:  8.8.8.8#53

Non-authoritative answer:
Name:  google.com
Address: 64.233.181.105
Name:  google.com
Address: 64.233.181.99
Name:  google.com
Address: 64.233.181.147
Name:  google.com
Address: 64.233.181.106
Name:  google.com
Address: 64.233.181.103
Name:  google.com
Address: 64.233.181.104

Server:    8.8.8.8

```

上面的最后一行对应于用于 DNS 解析的默认名称服务器。

在不使用 DNS 服务器的情况下，可以通过向文件`/etc/hosts`添加条目来将符号名称添加到 IP 地址解析中。

要添加一个条目，请使用以下语法：

```
# echo IP_ADDRESS symbolic_name >> /etc/hosts

```

例如：

```
# echo 192.168.0.9 backupserver.com  >> /etc/hosts

```

添加了这个条目后，每当解析到`backupserver.com`时，它将解析为`192.168.0.9`。

### 设置默认网关，显示路由表信息

当本地网络连接到另一个网络时，需要分配一些机器或网络节点，通过这些节点进行互连。因此，目的地在本地网络之外的 IP 数据包应该被转发到与外部网络相连的节点机器。这个特殊的节点机器，能够将数据包转发到外部网络，被称为网关。我们为每个节点设置网关，以便连接到外部网络。

操作系统维护一个称为路由表的表，其中包含有关数据包如何转发以及通过网络中的哪个机器节点的信息。路由表可以显示如下：

```
$ route
Kernel IP routing table
Destination      Gateway   Genmask      Flags  Metric  Ref  UseIface
192.168.0.0         *      255.255.252.0  U     2      0     0wlan0
link-local          *      255.255.0.0    U     1000   0     0wlan0
default          p4.local  0.0.0.0        UG    0      0     0wlan0

```

或者，您也可以使用：

```
$ route -n
Kernel IP routing table
Destination   Gateway      Genmask       Flags Metric Ref  Use   Iface
192.168.0.0   0.0.0.0      255.255.252.0   U     2     0     0   wlan0
169.254.0.0   0.0.0.0      255.255.0.0     U     1000  0     0   wlan0
0.0.0.0       192.168.0.4  0.0.0.0         UG    0     0     0   wlan0

```

使用`-n`指定显示数字地址。当使用`-n`时，它将显示每个带有数字 IP 地址的条目，否则它将显示 DNS 条目下的符号主机名而不是 IP 地址。

默认网关设置如下：

```
# route add default gw IP_ADDRESS INTERFACE_NAME

```

例如：

```
# route add default gw 192.168.0.1 wlan0

```

### Traceroute

当应用程序通过 Internet 请求服务时，服务器可能位于遥远的位置，并通过任意数量的网关或设备节点连接。数据包通过多个网关传输并到达目的地。有一个有趣的命令`traceroute`，它显示了数据包到达目的地所经过的所有中间网关的地址。`traceroute`信息帮助我们了解每个数据包需要经过多少跳才能到达目的地。中间网关或路由器的数量为连接在大型网络中的两个节点之间的距离提供了一个度量标准。`traceroute`的输出示例如下：

```
$ traceroute google.com
traceroute to google.com (74.125.77.104), 30 hops max, 60 byte packets
1  gw-c6509.lxb.as5577.net (195.26.4.1)  0.313 ms  0.371 ms  0.457 ms
2  40g.lxb-fra.as5577.net (83.243.12.2)  4.684 ms  4.754 ms  4.823 ms
3  de-cix10.net.google.com (80.81.192.108)  5.312 ms  5.348 ms  5.327 ms
4  209.85.255.170 (209.85.255.170)  5.816 ms  5.791 ms 209.85.255.172 (209.85.255.172)  5.678 ms
5  209.85.250.140 (209.85.250.140)  10.126 ms  9.867 ms  10.754 ms
6  64.233.175.246 (64.233.175.246)  12.940 ms 72.14.233.114 (72.14.233.114)  13.736 ms  13.803 ms
7  72.14.239.199 (72.14.239.199)  14.618 ms 209.85.255.166 (209.85.255.166)  12.755 ms 209.85.255.143 (209.85.255.143)  13.803 ms
8  209.85.255.98 (209.85.255.98)  22.625 ms 209.85.255.110 (209.85.255.110)  14.122 ms
* 
9  ew-in-f104.1e100.net (74.125.77.104)  13.061 ms  13.256 ms  13.484 ms

```

## 另请参阅

+   *使用变量和环境变量玩耍* 第一章 ，解释了 PATH 变量

+   *使用 grep 在文件中搜索和挖掘“文本”* 第四章 ，解释了 grep 命令

# 让我们 ping！

`ping`是最基本的网络命令，每个用户都应该首先了解。它是一个通用命令，在主要操作系统上都可以使用。它也是一个用于验证网络上两个主机之间连接性的诊断工具。它可以用来查找网络上哪些机器是活动的。让我们看看如何使用 ping。

## 如何做...

为了检查网络上两个主机的连接性，`ping`命令使用**Internet** **Control** **Message** **Protocol** (**ICMP**)回显数据包。当这些回显数据包发送到主机时，如果主机是可达或活动的，主机将以回复的方式响应。

检查主机是否可达如下：

```
$ ping ADDRESS

```

`ADDRESS`可以是主机名、域名或 IP 地址本身。

`ping`将持续发送数据包，并且回复信息将打印在终端上。通过按下*Ctrl* + *C*来停止 ping。

例如：

+   当主机是可达时，输出将类似于以下内容：

```
$ ping 192.168.0.1 
PING 192.168.0.1 (192.168.0.1) 56(84) bytes of data.
64 bytes from 192.168.0.1: icmp_seq=1 ttl=64 time=1.44 ms
^C 
--- 192.168.0.1 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1.440/1.440/1.440/0.000 ms

$ ping google.com
PING google.com (209.85.153.104) 56(84) bytes of data.
64 bytes from bom01s01-in-f104.1e100.net (209.85.153.104): icmp_seq=1 ttl=53 time=123 ms
^C 
--- google.com ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 123.388/123.388/123.388/0.000 ms

```

+   当主机不可达时，输出将类似于：

```
$ ping 192.168.0.99
PING 192.168.0.99 (192.168.0.99) 56(84) bytes of data.
From 192.168.0.82 icmp_seq=1 Destination Host Unreachable
From 192.168.0.82 icmp_seq=2 Destination Host Unreachable

```

一旦主机不可达，ping 将返回`Destination Host Unreachable`错误消息。

## 有更多

除了检查网络中两点之间的连接性外，`ping`命令还可以与其他选项一起使用以获得有用的信息。让我们看看`ping`的其他选项。

### 往返时间

`ping`命令可用于查找网络上两个主机之间的**往返时间**（**RTT**）。 RTT 是数据包到达目标主机并返回到源主机所需的时间。 RTT 以毫秒为单位可以从 ping 中获得。示例如下：

```
--- google.com ping statistics ---
5 packets transmitted, 5 received, 0% packet loss, time 4000ms
rtt min/avg/max/mdev = 118.012/206.630/347.186/77.713 ms

```

这里最小的 RTT 为 118.012ms，平均 RTT 为 206.630ms，最大 RTT 为 347.186ms。 `ping`输出中的`mdev`（77.713ms）参数代表平均偏差。

### 限制要发送的数据包数量

`ping`命令发送回显数据包，并无限期等待`echo`的回复，直到通过按下*Ctrl* + *C*停止。但是，我们可以使用`-c`标志来限制要发送的回显数据包的数量。

用法如下：

```
-c COUNT
```

例如：

```
$ ping 192.168.0.1 -c 2 
PING 192.168.0.1 (192.168.0.1) 56(84) bytes of data. 
64 bytes from 192.168.0.1: icmp_seq=1 ttl=64 time=4.02 ms 
64 bytes from 192.168.0.1: icmp_seq=2 ttl=64 time=1.03 ms 

--- 192.168.0.1 ping statistics --- 
2 packets transmitted, 2 received, 0% packet loss, time 1001ms 
rtt min/avg/max/mdev = 1.039/2.533/4.028/1.495 ms 

```

在上一个示例中，`ping`命令发送两个回显数据包并停止。

当我们需要通过脚本 ping 多台机器并检查其状态时，这是非常有用的。

### ping 命令的返回状态

`ping`命令在成功时返回退出状态 0，并在失败时返回非零。成功意味着目标主机是可达的，而失败意味着目标主机是不可达的。

返回状态可以轻松获得如下：

```
$ ping ADDRESS -c2
if [ $? -eq 0 ];
then
 echo Successful ;
else
 echo Failure
fi

```

# 列出网络上所有活动的机器

当我们处理大型局域网时，我们可能需要检查网络中其他机器的可用性，无论是存活还是不存活。机器可能不存活有两种情况：要么它没有通电，要么由于网络中的问题。通过使用 shell 脚本，我们可以轻松地找出并报告网络上哪些机器是活动的。让我们看看如何做到这一点。

## 准备就绪

在这个配方中，我们使用了两种方法。第一种方法使用`ping`，第二种方法使用`fping`。`fping`不会默认随 Linux 发行版一起提供。您可能需要使用软件包管理器手动安装`fping`。

## 如何做到...

让我们通过脚本找出网络上所有活动的机器以及查找相同的替代方法。

+   **方法 1：**

我们可以使用`ping`命令编写自己的脚本来查询 IP 地址列表，并检查它们是否存活，如下所示：

```
#!/bin/bash
#Filename: ping.sh
# Change base address 192.168.0 according to your network.

for ip in 192.168.0.{1..255} ;
do
  ping $ip -c 2 &> /dev/null ;

  if [ $? -eq 0 ];
  then
    echo $ip is alive
  fi

done
```

输出如下：

```
$ ./ping.sh
192.168.0.1 is alive
192.168.0.90 is alive

```

+   **方法 2：**

我们可以使用现有的命令行实用程序来查询网络上计算机的状态，如下所示：

```
$ fping -a 192.160.1/24 -g 2> /dev/null 
192.168.0.1 
192.168.0.90

```

或者，使用：

```
$ fping -a 192.168.0.1 192.168.0.255 -g

```

## 它是如何工作的...

在方法 1 中，我们使用`ping`命令来查找网络上存活的计算机。我们使用`for`循环来遍历 IP 地址列表。列表生成为`192.168.0.{1..255}`。`{start..end}`符号将扩展并生成 IP 地址列表，例如`192.168.0.1`，`192.168.0.2`，`192.168.0.3`直到`192.168.0.255`。

`ping $ip -c 2 &> /dev/null`将在每次循环执行时对相应的 IP 地址运行`ping`。`-c 2`用于限制要发送的回显数据包的数量为两个数据包。`&> /dev/null`用于将`stderr`和`stdout`重定向到`/dev/null`，以便它不会打印在终端上。使用`$?`我们评估退出状态。如果成功，退出状态为 0，否则为非零。因此，成功的 IP 地址将被打印。我们还可以打印不成功的 IP 地址列表，以提供不可达的 IP 地址列表。

### 注意

这里有一个练习给你。不要在脚本中使用硬编码的 IP 地址范围，而是修改脚本以从文件或`stdin`中读取 IP 地址列表。

在这个脚本中，每个 ping 都是依次执行的。尽管所有 IP 地址彼此独立，但由于是顺序程序，`ping`命令会由于发送两个回显数据包和接收它们的延迟或执行下一个`ping`命令的超时而执行。

当涉及到 255 个地址时，延迟很大。让我们并行运行所有`ping`命令，使其更快。脚本的核心部分是循环体。为了使`ping`命令并行运行，将循环体括在`( )&`中。`( )`括起一组命令以作为子 shell 运行，`&`通过离开当前线程将其发送到后台。例如：

```
(
 ping $ip -c2 &> /dev/null ;

 if [ $? -eq 0 ];
 then
 echo $ip is alive
 fi
)&

wait

```

`for`循环体执行许多后台进程，退出循环并终止脚本。为了使脚本在所有子进程结束之前终止，我们有一个称为`wait`的命令。在脚本的末尾放置一个`wait`，以便它等待直到所有子`( )`子 shell 进程完成。

### 注意

`wait`命令使脚本只有在所有子进程或后台进程终止或完成后才能终止。

查看书中提供的代码中的`fast_ping.sh`。

方法 2 使用了一个名为`fping`的不同命令。它可以同时 ping 一系列 IP 地址并非常快速地响应。`fping`可用的选项如下：

+   `fping`的`-a`选项指定打印所有活动机器的 IP 地址

+   `-u`选项与`fping`一起指定打印所有不可达的机器

+   `-g`选项指定从斜杠子网掩码表示法指定的 IP/mask 或起始和结束 IP 地址生成 IP 地址范围：

```
$ fping -a 192.160.1/24 -g

```

或

```
$ fping -a 192.160.1 192.168.0.255 -g

```

+   `2>/dev/null`用于将由于不可达主机而打印的错误消息转储到空设备

还可以手动指定 IP 地址列表作为命令行参数或通过`stdin`列表。例如：

```
$ fping -a 192.168.0.1 192.168.0.5 192.168.0.6
# Passes IP address as arguments
$ fping -a <ip.list
# Passes a list of IP addresses from a file

```

## 还有更多...

`fping`命令可用于从网络查询 DNS 数据。让我们看看如何做到这一点。

### 使用 fping 进行 DNS 查找

`fping`有一个`-d`选项，通过使用 DNS 查找返回主机名。它将在 ping 回复中打印主机名而不是 IP 地址。

```
$ cat ip.list
192.168.0.86
192.168.0.9
192.168.0.6

$ fping -a -d 2>/dev/null  <ip.list
www.local
dnss.local

```

## 另请参阅

+   *玩转文件描述符和重定向*第一章，解释了数据重定向

+   *比较和测试*第一章，解释数字比较

# 文件传输

计算机网络的主要目的是资源共享。在资源共享中，最突出的用途是文件共享。有多种方法可以在网络上的不同节点之间传输文件。本教程讨论了如何使用常用协议 FTP、SFTP、RSYNC 和 SCP 进行文件传输。

## 准备工作

执行网络文件传输的命令在 Linux 安装中通常是默认可用的。可以使用`lftp`命令通过 FTP 传输文件。可以使用`sftp`通过 SSH 连接传输文件，使用`rsync`命令和使用`scp`通过 SSH 进行传输。

## 如何做...

**文件传输协议**（**FTP**）是一种用于在网络上的机器之间传输文件的旧文件传输协议。我们可以使用`lftp`命令来访问启用 FTP 的服务器进行文件传输。它使用端口 21。只有在远程机器上安装了 FTP 服务器才能使用 FTP。许多公共网站使用 FTP 共享文件。

要连接到 FTP 服务器并在其间传输文件，请使用：

```
$ lftp username@ftphost

```

现在它将提示输入密码，然后显示如下的登录提示：

```
lftp username@ftphost:~> 

```

您可以在此提示中键入命令。例如：

+   要更改目录，请使用`cd directory`

+   要更改本地机器的目录，请使用`lcd`

+   要创建目录，请使用`mkdir`

+   要下载文件，请使用`get filename`如下：

```
lftp username@ftphost:~> get filename

```

+   要从当前目录上传文件，请使用`put filename`如下：

```
lftp username@ftphost:~> put filename

```

+   可以使用`quit`命令退出`lftp`会话

`lftp`提示中支持自动完成。

## 还有更多...

让我们来看一些用于通过网络传输文件的其他技术和命令。

### 自动 FTP 传输

`ftp`是另一个用于基于 FTP 的文件传输的命令。`lftp`更灵活。`lftp`和`ftp`命令打开一个与用户的交互会话（它通过显示消息提示用户输入）。如果我们想要自动化文件传输而不是使用交互模式怎么办？我们可以通过编写一个 shell 脚本来自动化 FTP 文件传输，如下所示：

```
#!/bin/bash
#Filename: ftp.sh
#Automated FTP transfer
HOST='domain.com'
USER='foo'
PASSWD='password'
ftp -i -n $HOST <<EOF
user ${USER} ${PASSWD}
binary
cd /home/slynux
puttestfile.jpg
getserverfile.jpg
quit
EOF
```

上述脚本具有以下结构：

```
<<EOF
DATA
EOF
```

这用于通过`stdin`发送数据到 FTP 命令。第一章中的*Playing with file descriptors and redirection*一节解释了各种重定向到`stdin`的方法。

`ftp`的`-i`选项关闭与用户的交互会话。`user ${USER} ${PASSWD}`设置用户名和密码。`binary`将文件模式设置为二进制。

### SFTP（安全 FTP）

SFTP 是一种类似 FTP 的文件传输系统，运行在 SSH 连接的顶部。它利用 SSH 连接来模拟 FTP 接口。它不需要远程端安装 FTP 服务器来执行文件传输，但需要安装和运行 OpenSSH 服务器。它是一个交互式命令，提供`sftp`提示符。

以下命令用于执行文件传输。对于具有特定 HOST、USER 和 PASSWD 的每个自动化 FTP 会话，所有其他命令保持不变：

```
cd /home/slynux
put testfile.jpg
get serverfile.jpg

```

要运行`sftp`，请使用：

```
$ sftp user@domainname

```

类似于`lftp`，`sftp`会话可以通过输入`quit`命令退出。

SSH 服务器有时不会在默认端口 22 上运行。如果它在不同的端口上运行，我们可以在`sftp`后面指定端口，如`-oPort=PORTNO`。

例如：

```
$ sftp -oPort=422 user@slynux.org

```

### 注意

`-oPort`应该是`sftp`命令的第一个参数。

### RSYNC

rsync 是一个重要的命令行实用程序，广泛用于在网络上复制文件和进行备份快照。这在单独的*使用 rsync 进行备份快照*一节中有更好的解释，解释了`rsync`的用法。

### SCP（安全复制）

SCP 是一种比传统的名为`rcp`的远程复制工具更安全的文件复制技术。文件通过加密通道传输。SSH 用作加密通道。我们可以通过以下方式轻松地将文件传输到远程计算机：

```
$ scp filename user@remotehost:/home/path

```

这将提示输入密码。可以通过使用自动登录 SSH 技术使其无需密码。*使用 SSH 进行无密码自动登录*一节解释了 SSH 自动登录。

因此，使用`scp`进行文件传输不需要特定的脚本。一旦 SSH 登录被自动化，`scp`命令可以在不需要交互式提示输入密码的情况下执行。

这里的`remotehost`可以是 IP 地址或域名。`scp`命令的格式是：

```
$ scp SOURCE DESTINATION

```

`SOURCE`或`DESTINATION`可以采用`username@localhost:/path`的格式，例如：

```
$ scp user@remotehost:/home/path/filename filename

```

上述命令将文件从远程主机复制到当前目录，并给出文件名。

如果 SSH 运行的端口与 22 不同，请使用与`sftp`相同语法的`-oPort`。

### 使用 SCP 进行递归复制

通过使用`scp`，我们可以通过以下方式在网络上的两台计算机之间递归复制目录，使用`-r`参数：

```
$ scp -r /home/slynux user@remotehost:/home/backups
# Copies the directory /home/slynux recursively to remote location

```

`scp`也可以通过使用`-p`参数保留权限和模式来复制文件。

## 另请参阅

+   第一章的*Playing with file descriptors and redirection*一节解释了使用 EOF 的标准输入

# 使用脚本设置以太网和无线局域网

以太网配置简单。由于它使用物理电缆，因此没有特殊要求，如身份验证。然而，无线局域网需要身份验证，例如 WEP 密钥以及要连接的无线网络的 ESSID。让我们看看如何通过编写一个 shell 脚本连接到无线网络和有线网络。

## 准备工作

连接有线网络时，我们需要使用`ifconfig`实用程序分配 IP 地址和子网掩码。但是对于无线网络连接，将需要额外的实用程序，如`iwconfig`和`iwlist`，以配置更多参数。

## 如何做...

为了从有线接口连接到网络，执行以下脚本：

```
#!/bin/bash
#Filename: etherconnect.sh
#Description: Connect Ethernet

#Modify the parameters below according to your settings
######### PARAMETERS ###########

IFACE=eth0
IP_ADDR=192.168.0.5
SUBNET_MASK=255.255.255.0
GW=192.168.0.1
HW_ADDR='00:1c:bf:87:25:d2'
# HW_ADDR is optional
#################################

if [ $UID -ne 0 ];
then
  echo "Run as root"
  exit 1
fi

# Turn the interface down before setting new config
/sbin/ifconfig $IFACE down

if [[ -n $HW_ADDR  ]];
then
  /sbin/ifconfig hw ether $HW_ADDR
 echo Spoofed MAC ADDRESS to $HW_ADDR

fi

/sbin/ifconfig $IFACE $IP_ADDR netmask $SUBNET_MASK

route add default gw $GW $IFACE

echo Successfully configured $IFACE
```

连接到带有 WEP 的无线局域网的脚本如下：

```
#!/bin/bash
#Filename: wlan_connect.sh
#Description: Connect to Wireless LAN

#Modify the parameters below according to your settings
######### PARAMETERS ###########
IFACE=wlan0
IP_ADDR=192.168.1.5
SUBNET_MASK=255.255.255.0
GW=192.168.1.1
HW_ADDR='00:1c:bf:87:25:d2' 
#Comment above line if you don't want to spoof mac address

ESSID="homenet"
WEP_KEY=8b140b20e7 
FREQ=2.462G
#################################

KEY_PART=""

if [[ -n $WEP_KEY ]];
then
  KEY_PART="key $WEP_KEY"
fi

# Turn the interface down before setting new config
/sbin/ifconfig $IFACE down

if [ $UID -ne 0 ];
then
  echo "Run as root"
  exit 1;
fi

if [[ -n $HW_ADDR  ]];
then
  /sbin/ifconfig $IFACE hw ether $HW_ADDR
  echo Spoofed MAC ADDRESS to $HW_ADDR
fi

/sbin/iwconfig $IFACE essid $ESSID $KEY_PART freq $FREQ

/sbin/ifconfig $IFACE $IP_ADDR netmask $SUBNET_MASK

route add default gw $GW $IFACE

echo Successfully configured $IFACE
```

## 它是如何工作的...

命令`ifconfig`、`iwconfig`和`route`需要以 root 用户身份运行。因此，在脚本开始时会检查 root 用户。

以太网连接脚本非常简单，并且使用了食谱中解释的概念，*基本网络入门*。让我们来看看用于连接到无线局域网的命令。

无线局域网需要一些参数，如`essid`、`key`和频率才能连接到网络。`essid`是我们需要连接的无线网络的名称。一些**有线** **等效** **协议**（**WEP**）网络使用 WEP 密钥进行身份验证，而有些网络则不使用。WEP 密钥通常是一个 10 位十六进制密码。接下来是分配给网络的频率。`iwconfig`是用于将无线网卡连接到适当的无线网络、WEP 密钥和频率的命令。

我们可以使用实用程序`iwlist`扫描和列出可用的无线网络。要进行扫描，请使用以下命令：

```
# iwlist scan 
wlan0     Scan completed : 
 Cell 01 - Address: 00:12:17:7B:1C:65
 Channel:11
 Frequency:2.462 GHz (Channel 11) 
 Quality=33/70  Signal level=-77 dBm
 Encryption key:on
 ESSID:"model-2" 

```

`频率`参数可以从扫描结果中提取，从`Frequency:2.462 GHz (Channel 11)`这一行中。

## 另请参阅

+   *比较和测试*第一章中，解释了字符串比较。

# 使用 SSH 进行无密码自动登录

SSH 在自动化脚本中被广泛使用。通过使用 SSH，可以在远程主机上远程执行命令并读取它们的输出。SSH 通过使用用户名和密码进行身份验证。在执行 SSH 命令时会提示输入密码。但是在自动化脚本中，SSH 命令可能会在循环中执行数百次，因此每次提供密码是不切实际的。因此我们需要自动化登录。SSH 具有一个内置功能，可以使用 SSH 密钥进行自动登录。本食谱描述了如何创建 SSH 密钥并实现自动登录。

## 如何做...

SSH 使用基于公钥和私钥的加密技术进行自动身份验证。身份验证密钥有两个元素：公钥和私钥对。我们可以使用`ssh-keygen`命令创建一个身份验证密钥。为了自动化身份验证，公钥必须放置在服务器上（通过将公钥附加到`~/.ssh/authorized_keys`文件），并且其配对的私钥文件应该存在于客户端机器的`~/.ssh`目录中，即您要从中登录的计算机。关于 SSH 的几个配置（例如`authorized_keys`文件的路径和名称）可以通过修改配置文件`/etc/ssh/sshd_config`来配置。

设置使用 SSH 进行自动身份验证有两个步骤。它们是：

1.  从需要登录到远程机器的机器上创建 SSH 密钥。

1.  将生成的公钥传输到远程主机，并将其附加到`~/.ssh/authorized_keys`文件中。

为了创建一个 SSH 密钥，输入以下指定 RSA 加密算法类型的`ssh-keygen`命令：

```
$ ssh-keygen -t rsa
Generating public/private rsa key pair. 
Enter file in which to save the key (/home/slynux/.ssh/id_rsa): 
Created directory '/home/slynux/.ssh'. 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/slynux/.ssh/id_rsa. 
Your public key has been saved in /home/slynux/.ssh/id_rsa.pub. 
The key fingerprint is: 
f7:17:c6:4d:c9:ee:17:00:af:0f:b3:27:a6:9c:0a:05slynux@slynux-laptop 
The key's randomart image is: 
+--[ RSA 2048]----+ 
|           .     | 
|            o . .|
|     E       o o.|
|      ...oo | 
|       .S .+  +o.| 
|      .  . .=....| 
|     .+.o...| 
|      . . + o.  .|
|       ..+       | 
+-----------------+ 

```

生成公私钥对需要输入一个密码。也可以在不输入密码的情况下生成密钥对，但这是不安全的。我们可以编写使用脚本从脚本到多台机器进行自动登录的监控脚本。在这种情况下，应该在运行`ssh-keygen`命令时将密码留空，以防止脚本在运行时要求输入密码。

现在`~/.ssh/id_rsa.pub`和`~/.ssh/id_rsa`已经生成。`id_dsa.pub`是生成的公钥，`id_dsa`是私钥。公钥必须附加到远程服务器上的`~/.ssh/authorized_keys`文件，我们需要从当前主机自动登录。

为了附加一个密钥文件，使用：

```
$ ssh USER@REMOTE_HOST "cat >> ~/.ssh/authorized_keys" < ~/.ssh/id_rsa.pub
Password:

```

在上一个命令中提供登录密码。

自动登录已设置。从现在开始，在执行过程中 SSH 不会提示输入密码。您可以使用以下命令进行测试：

```
$ ssh USER@REMOTE_HOST uname
Linux

```

您将不会被提示输入密码。

# 使用 SSH 在远程主机上运行命令

SSH 是一个有趣的系统管理工具，可以通过登录 shell 来控制远程主机。SSH 代表安全外壳。可以在通过登录到远程主机收到的 shell 上执行命令，就好像我们在本地主机上运行命令一样。它通过加密隧道运行网络数据传输。本教程将介绍在远程主机上执行命令的不同方法。

## 准备工作

SSH 不会默认随所有 GNU/Linux 发行版一起提供。因此，您可能需要使用软件包管理器安装`openssh-server`和`openssh-client`软件包。SSH 服务默认在端口号 22 上运行。

## 如何做...

要连接到运行 SSH 服务器的远程主机，请使用：

```
$ ssh username@remote_host

```

在这个命令中：

+   `username`是存在于远程主机上的用户。

+   `remote_host`可以是域名或 IP 地址。

例如：

```
$ ssh mec@192.168.0.1
The authenticity of host '192.168.0.1 (192.168.0.1)' can't be established.
RSA key fingerprint is 2b:b4:90:79:49:0a:f1:b3:8a:db:9f:73:2d:75:d6:f9.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '192.168.0.1' (RSA) to the list of known hosts.
Password:

Last login: Fri Sep  3 05:15:21 2010 from 192.168.0.82
mec@proxy-1:~$

```

它将交互式地要求用户密码，并在成功验证后将返回用户的 shell。

默认情况下，SSH 服务器在端口 22 上运行。但是某些服务器在不同端口上运行 SSH 服务。在这种情况下，使用`ssh`命令的`-p port_no`来指定端口。

为了连接到运行在端口 422 上的 SSH 服务器，请使用：

```
$ ssh user@locahost -p 422

```

您可以在对应于远程主机的 shell 中执行命令。Shell 是一个交互式工具，用户可以在其中输入和运行命令。但是，在 shell 脚本上下文中，我们不需要交互式 shell。我们需要自动化多个任务。我们需要在远程 shell 上执行多个命令，并在本地主机上显示或存储其输出。在自动化脚本中每次输入密码都不切实际，因此应配置 SSH 的自动登录。

*使用 SSH 实现无密码自动登录*中解释了 SSH 命令。

在运行使用 SSH 的自动化脚本之前，请确保已配置自动登录。

要在远程主机上运行命令并在本地主机 shell 上显示其输出，请使用以下语法：

```
$ ssh user@host 'COMMANDS'

```

例如：

```
$ ssh mec@192.168.0.1 'whoami'
Password: 
mec

```

可以通过在命令之间使用分号分隔符来给出多个命令，如下所示：

```
$ ssh user@host 'command1 ; command2 ; command3'

```

命令可以通过`stdin`发送，并且命令的输出将可用于`stdout`。

语法如下：

```
$ ssh user@remote_host  "COMMANDS" > stdout.txt 2> errors.txt

```

`COMMANDS`字符串应该用引号引起来，以防止分号字符在本地主机 shell 中充当分隔符。我们还可以通过`stdin`传递任何涉及管道语句的命令序列到 SSH 命令，如下所示：

```
$ echo  "COMMANDS" | sshuser@remote_host> stdout.txt 2> errors.txt

```

例如：

```
$ ssh mec@192.168.0.1  "echo user: $(whoami);echo OS: $(uname)"
Password: 
user: slynux 
OS: Linux 

```

在此示例中，在远程主机上执行的命令是：

```
echo user: $(whoami);
echo OS: $(uname)

```

它可以概括为：

```
COMMANDS="command1; command2; command3"
$ ssh user@hostname  "$COMMANDS"

```

我们还可以通过使用`( )`子 shell 运算符在命令序列中传递更复杂的子 shell。

让我们编写一个基于 SSH 的 shell 脚本，用于收集一组远程主机的正常运行时间。正常运行时间是系统已经运行的时间。`uptime`命令用于显示系统已经运行多长时间。

假设`IP_LIST`中的所有系统都有一个共同的用户`test`。

```
#!/bin/bash
#Filename: uptime.sh
#Description: Uptime monitor

IP_LIST="192.168.0.1 192.168.0.5 192.168.0.9"
USER="test"

for IP in $IP_LIST;
do
 utime=$(ssh $USER@$IP uptime  | awk '{ print $3 }' )
 echo $IP uptime:  $utime
done

```

预期输出是：

```
$ ./uptime.sh
192.168.0.1 uptime: 1:50,
192.168.0.5 uptime: 2:15,
192.168.0.9 uptime: 10:15,

```

## 还有更多...

`ssh`命令可以使用多个附加选项执行。让我们逐一介绍它们。

### 使用压缩的 SSH

SSH 协议还支持使用压缩进行数据传输，当带宽成为问题时非常有用。使用`ssh`命令的`-C`选项启用压缩，如下所示：

```
$ ssh -C user@hostname COMMANDS

```

### 将数据重定向到远程主机 shell 命令的 stdin

有时我们需要将一些数据重定向到远程 shell 命令的`stdin`中。让我们看看如何做到这一点。一个例子如下：

```
$ echo "text" | ssh user@remote_host 'cat >> list'

```

或：

```
# Redirect data from file as:
$ ssh user@remote_host 'cat >> list'  < file

```

`cat >> list`将通过`stdin`接收的数据附加到文件列表中。此命令在远程主机上执行。但是数据是从本地主机传递到`stdin`。

## 另请参阅

+   *使用 SSH 实现无密码自动登录*，解释了如何配置自动登录以执行命令而无需提示输入密码。

# 在本地挂载点挂载远程驱动器

在进行读写数据传输操作时，拥有一个本地挂载点以访问远程主机文件系统将非常有帮助。SSH 是网络中最常见的传输协议，因此我们可以利用它与`sshfs`一起使用。`sshfs`使您能够将远程文件系统挂载到本地挂载点。让我们看看如何做到这一点。

## 准备工作

`sshfs`在 GNU/Linux 发行版中默认未安装。使用软件包管理器安装`sshfs`。`sshfs`是 fuse 文件系统包的扩展，允许支持的操作系统将各种数据挂载为本地文件系统。

## 如何做...

为了将远程主机上的文件系统位置挂载到本地挂载点，使用：

```
# sshfs user@remotehost:/home/path /mnt/mountpoint
Password:

```

在提示时输入用户密码。

现在，远程主机上`/home/path`的数据可以通过本地挂载点`/mnt/mountpoint`访问。

在完成工作后卸载，使用：

```
# umount /mnt/mountpoint

```

## 参见

+   *使用 SSH 在远程主机上运行命令*，解释了 ssh 命令。

# 在网络上多播窗口消息

网络管理员经常需要向网络上的节点发送消息。在用户的桌面上显示弹出窗口将有助于提醒用户获得信息。使用 shell 脚本和 GUI 工具包可以实现此任务。本教程讨论了如何向远程主机发送自定义消息的弹出窗口。

## 准备工作

要实现 GUI 弹出窗口，可以使用 zenity。Zenity 是一个可脚本化的 GUI 工具包，用于创建包含文本框、输入框等的窗口。SSH 可用于连接到远程主机上的远程 shell。Zenity 在 GNU/Linux 发行版中默认未安装。使用软件包管理器安装 zenity。

## 如何做...

Zenity 是可脚本化的对话框创建工具包之一。还有其他工具包，如 gdialog、kdialog、xdialog 等。Zenity 似乎是一个灵活的工具包，符合 GNOME 桌面环境。

为了使用 zenity 创建信息框，使用：

```
$ zenity --info --text "This is a message"
# It will display a window with "This is a message" as text.

```

Zenity 可以用来创建带有输入框、组合输入、单选按钮、按钮等的窗口。这些不在本教程的范围内。查看 zenity 的 man 页面以获取更多信息。

现在，我们可以使用 SSH 在远程机器上运行这些 zenity 语句。为了在远程主机上通过 SSH 运行此语句，运行：

```
$ ssh user@remotehost 'zenity --info --text "This is a message"'

```

但是这将返回一个错误，如下：

```
(zenity:3641): Gtk-WARNING **: cannot open display: 

```

这是因为 zenity 依赖于 Xserver。Xsever 是一个负责在屏幕上绘制图形元素的守护进程，包括 GUI。裸的 GNU/Linux 系统只包含文本终端或 shell 提示符。

Xserver 使用一个特殊的环境变量`DISPLAY`来跟踪正在系统上运行的 Xserver 实例。

我们可以手动设置`DISPLAY=:0`来指示 Xserver 关于 Xserver 实例。

上一个 SSH 命令可以重写为：

```
$ ssh username@remotehost 'export DISPLAY=:0 ; zenity --info --text "This is a message"'

```

如果具有用户名的用户已登录到任何窗口管理器中，此语句将在`remotehost`上显示一个弹出窗口。

为了将弹出窗口多播到多个远程主机，编写一个 shell 脚本如下：

```
#!/bin/bash
#Filename: multi_cast_window.sh
# Description: Multi-cast window popups

IP_LIST="192.168.0.5 192.168.0.3 192.168.0.23"
USER="username"

COMMAND='export DISPLAY=:0 ;zenity --info --text "This is a message" '
for host in $IP_LIST;
do
  ssh $USER@$host  "$COMMAND" &
done
```

## 它是如何工作的...

在上面的脚本中，我们有一个 IP 地址列表，应该在这些 IP 地址上弹出窗口。使用循环来遍历 IP 地址并执行 SSH 命令。

在 SSH 语句中，最后我们使用了后缀`&`。`&`将 SSH 语句发送到后台。这样做是为了方便执行多个 SSH 语句的并行化。如果不使用`&`，它将启动 SSH 会话，执行 zenity 对话框，并等待用户关闭弹出窗口。除非远程主机上的用户关闭窗口，否则循环中的下一个 SSH 语句将不会被执行。为了避免循环被阻塞，等待 SSH 会话终止，使用了`&`技巧。

## 参见

+   *使用 SSH 在远程主机上运行命令*，解释了 ssh 命令。

# 网络流量和端口分析

网络端口是网络应用程序的基本参数。应用程序在主机上打开端口，并通过远程主机上打开的端口与远程主机通信。了解打开和关闭的端口对于安全上下文至关重要。恶意软件和 root 工具包可能在具有自定义端口和自定义服务的系统上运行，这允许攻击者捕获对数据和资源的未经授权访问。通过获取打开的端口和运行在端口上的服务列表，我们可以分析和保护系统免受 root 工具包的控制，并且该列表有助于有效地将它们移除。打开端口的列表不仅有助于恶意软件检测，还有助于收集有关系统上打开端口的信息，从而能够调试基于网络的应用程序。它有助于分析特定端口连接和端口监听功能是否正常工作。本教程讨论了用于端口分析的各种实用程序。

## 准备就绪

有多种命令可用于监听每个端口上运行的端口和服务（例如，`lsof`和`netstat`）。这些命令默认情况下在所有 GNU/Linux 发行版上都可用。

## 如何做...

要列出系统上所有打开的端口以及每个附加到它的服务的详细信息，请使用：

```
$ lsof -i
COMMAND    PID   USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
firefox-b 2261 slynux   78u  IPv4  63729      0t0  TCP localhost:47797->localhost:42486 (ESTABLISHED)
firefox-b 2261 slynux   80u  IPv4  68270      0t0  TCP slynux-laptop.local:41204->192.168.0.2:3128 (CLOSE_WAIT)
firefox-b 2261 slynux   82u  IPv4  68195      0t0  TCP slynux-laptop.local:41197->192.168.0.2:3128 (ESTABLISHED)
ssh       3570 slynux    3u  IPv6  30025      0t0  TCP localhost:39263->localhost:ssh (ESTABLISHED)
ssh       3836 slynux    3u  IPv4  43431      0t0  TCP slynux-laptop.local:40414->boneym.mtveurope.org:422 (ESTABLISHED)
GoogleTal 4022 slynux   12u  IPv4  55370      0t0  TCP localhost:42486 (LISTEN)
GoogleTal 4022 slynux   13u  IPv4  55379      0t0  TCP localhost:42486->localhost:32955 (ESTABLISHED)

```

`lsof`的输出中的每个条目对应于打开端口进行通信的每个服务。输出的最后一列包含类似于以下行：

```
slynux-laptop.local:34395->192.168.0.2:3128 (ESTABLISHED)
```

在此输出中，`slynux-laptop.local:34395`对应于本地主机部分，`192.168.0.2:3128`对应于远程主机。

`34395`是从当前机器打开的端口，`3128`是服务连接到远程主机的端口。

要列出当前机器上打开的端口，请使用：

```
$ lsof -i | grep ":[0-9]\+->" -o | grep "[0-9]\+" -o  | sort | uniq

```

`:[0-9]\+->`正则表达式用于从`lsof`输出中提取主机端口部分（`:34395->`）。接下来的`grep`用于提取端口号（即数字）。通过同一端口可能发生多个连接，因此同一端口的多个条目可能会发生。为了仅显示每个端口一次，它们被排序并打印唯一的端口。

## 还有更多...

让我们通过其他实用程序来查看打开的端口和与网络流量相关的信息。

### 使用 netstat 列出打开的端口和服务

`netstat` 是用于网络服务分析的另一个命令。解释`netstat`的所有功能不在本教程的范围内。我们现在将看看如何列出服务和端口号。

使用`netstat -tnp`列出打开的端口和服务如下：

```
$ netstat -tnp
(Not all processes could be identified, non-owned process info 
will not be shown, you would have to be root to see it all.) 
Active Internet connections (w/o servers) 
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name 
tcp        0      0 192.168.0.82:38163      192.168.0.2:3128        ESTABLISHED 2261/firefox-bin 
tcp        0      0 192.168.0.82:38164      192.168.0.2:3128        TIME_WAIT   - 
tcp        0      0 192.168.0.82:40414      193.107.206.24:422      ESTABLISHED 3836/ssh 
tcp        0      0 127.0.0.1:42486         127.0.0.1:32955         ESTABLISHED 4022/GoogleTalkPlug 
tcp        0      0 192.168.0.82:38152      192.168.0.2:3128        ESTABLISHED 2261/firefox-bin 
tcp6       0      0 ::1:22                  ::1:39263               ESTABLISHED - 
tcp6       0      0 ::1:39263               ::1:22                  ESTABLISHED 3570/ssh 

```


# 第八章：戴上监视器的帽子

在本章中，我们将涵盖：

+   磁盘使用技巧

+   计算命令的执行时间

+   有关已登录用户、启动日志、启动失败的信息

+   打印最常用的 10 个命令

+   列出 1 小时内 CPU 消耗最多的前 10 个进程

+   使用 watch 监视命令输出

+   记录对文件和目录的访问

+   使用 logrotate 管理日志文件

+   使用 syslog 记录

+   监视用户登录以查找入侵者

+   远程磁盘使用健康监控

+   查找系统上活跃用户的小时数

# 介绍

操作系统由一系列系统软件组成，设计用于不同的目的，为不同的任务集提供服务。这些程序中的每一个都需要被操作系统或系统管理员监视，以了解它是否正常工作。我们还将使用一种称为日志记录的技术，通过该技术在应用程序运行时将重要信息写入文件。通过阅读这个文件，我们可以了解正在进行的特定软件或守护进程的操作时间线。如果应用程序或服务崩溃，这些信息有助于调试问题，并使我们能够解决任何问题。日志记录和监视还有助于从数据池中收集信息。日志记录和监视是确保操作系统安全和调试的重要任务。

本章介绍了可以用于监视不同活动的不同命令。它还介绍了日志记录技术及其用途。

# 磁盘使用技巧

磁盘空间是有限的资源。我们经常对硬盘或任何存储介质进行磁盘使用计算，以找出磁盘上可用的空闲空间。当空闲空间变得稀缺时，我们需要找出需要删除或移动的大文件，以便创建空闲空间。磁盘使用操作通常在 shell 脚本环境中使用。本文将说明用于磁盘操作的各种命令，以及可以使用各种选项计算磁盘使用情况的问题。

## 准备工作

`df`和`du`是用于计算 Linux 磁盘使用的两个重要命令。命令`df`代表磁盘空闲，`du`代表磁盘使用。让我们看看如何使用它们执行涉及磁盘使用计算的各种任务。

## 如何做...

要查找文件（或文件）使用的磁盘空间，请使用：

```
$ du  FILENAME1 FILENAME2 ..

```

例如：

```
$ du file.txt
4

```

为了获取目录中所有文件的磁盘使用情况，以及在每行中显示每个文件的个别磁盘使用情况，请使用：

```
$ du -a DIRECTORY

```

-a 在指定的目录或递归目录中输出所有文件的结果。

### 提示

运行`du DIRECTORY`将输出类似的结果，但它只会显示子目录消耗的大小。然而，它们不显示每个文件的磁盘使用情况。要打印文件的磁盘使用情况，-a 是必需的。

例如：

```
$  du -a test
4  test/output.txt
4  test/process_log.sh
4  test/pcpu.sh
16  test

```

使用`du DIRECTORY`的示例如下：

```
$ du test
16  test

```

## 还有更多...

让我们看看`du`命令的其他用法。

### 以 KB、MB 或块显示磁盘使用情况

默认情况下，磁盘使用命令显示文件使用的总字节数。当以标准单位 KB、MB 或 GB 表示磁盘使用时，更易读的格式。为了以友好的格式打印磁盘使用情况，请使用`-h`如下：

```
du -h FILENAME

```

例如：

```
$ du -sh test/pcpu.sh
4.0K  test/pcpu.sh
# Multiple file arguments are accepted

```

或：

```
# du -h DIRECTORY
$ du -h hack/
16K  hack/

```

### 显示磁盘使用的总和

假设我们需要计算所有文件或目录占用的总大小，显示个别文件大小将不会有帮助。`du`有一个选项`-c`，它将输出作为参数给出的所有文件和目录的总磁盘使用情况。它附加了一行 SIZE 总和结果。语法如下：

```
$ du -c FILENAME1 FILENAME2..

```

例如：

```
du -c process_log.sh pcpu.sh
4  process_log.sh
4  pcpu.sh
8  total

```

或：

```
$ du  -c DIRECTORY

```

例如：

```
$ du -c test/
16  test/
16  total

```

或：

```
$ du -c *.txt
# Wildcards

```

-c 可以与其他选项一起使用，如-a 和-h。它提供与不使用-c 相同的输出。唯一的区别是它附加了一个包含总大小的额外行。

还有另一个选项`-s`（汇总），它将只打印总和作为输出。它将打印总和，并且可以与`-h`标志一起使用以以人类可读的格式打印。这个命令在实践中经常使用。语法如下：

```
$ du -s FILES(s)
$ du -sh DIRECTORY

```

例如：

```
$ du -sh slynux
680K  slynux

```

### 以指定单位打印文件

我们可以强制`du`以指定的单位打印磁盘使用量。例如：

+   通过使用以下方式以字节（默认）打印大小：

```
$ du -b FILE(s)

```

+   通过使用以下方式以千字节为单位打印大小：

```
$ du -k FILE(s)

```

+   通过使用以下方式打印以兆字节为单位的大小：

```
$ du -m FILE(s)

```

+   通过使用指定的 BLOCK 大小打印大小：

```
$ du -B BLOCK_SIZE FILE(s)

```

这里，`BLOCK_SIZE`以字节为单位指定。

一个包含所有命令的示例如下：

```
$ du pcpu.sh
4  pcpu.sh
$ du -b pcpu.sh
439	pcpu.sh
$ du -k pcpu.sh
4  pcpu.sh
$ du -m pcpu.sh
1  pcpu.sh
$ du -B 4  pcpu.sh
1024  pcpu.sh

```

### 排除磁盘使用量计算中的文件

有时我们需要从磁盘使用量计算中排除某些文件。这些被排除的文件可以通过两种方式指定：

1.  **通配符**

我们可以使用通配符指定如下：

```
$ du --exclude "WILDCARD" DIRECTORY

```

例如：

```
$ du --exclude "*.txt" FILES(s)
# Excludes all .txt files from calculation

```

1.  **排除列表**

我们可以指定要从文件中排除的文件列表如下：

```
$ du --exclude-from EXCLUDE.txt DIRECTORY
# EXCLUDE.txt is the file containing list

```

`du`还提供了一些其他方便的选项，以限制磁盘使用量的计算。我们可以通过使用`--max-depth`参数指定`du`应该遍历的层次结构的最大深度来计算整个磁盘使用量。指定深度为`1`计算当前目录中文件的大小。深度`2`将计算当前目录中的文件和下一个子目录的文件，并在第二个子目录处停止遍历。

例如：

```
$ du --max-depth 2 DIRECTORY

```

### 注意

`du`可以通过使用`-x`参数限制只遍历单个文件系统。假设运行`du DIRECTORY`，它将递归地遍历`DIRECTORY`的每个可能的子目录。目录层次结构中的一个子目录可能是一个挂载点（例如，`/mnt/sda1`是`/mnt`的子目录，它是设备`/dev/sda1`的挂载点）。`du`将遍历该挂载点，并计算该设备文件系统的磁盘使用总和。为了防止`du`遍历和计算其他挂载点或文件系统，可以在其他`du`选项中使用`-x`标志。`du -x /`将排除`/mnt/`中的所有挂载点进行磁盘使用量计算。

在使用`du`时，请确保它遍历的目录或文件具有适当的读取权限。

### 从给定目录中查找最大的 10 个文件大小

查找大尺寸文件是我们经常遇到的一个常规任务。我们经常需要删除这些巨大的文件或移动它们。我们可以使用`du`和`sort`命令轻松找到大尺寸文件。以下一行脚本可以完成这项任务：

```
$ du -ak SOURCE_DIR | sort -nrk 1 | head

```

这里的`-a`指定所有目录和文件。因此，`du`遍历`SOURCE_DIR`并计算所有文件的大小。输出的第一列包含以千字节为单位的大小，因为指定了`-k`，第二列包含文件或文件夹名称。

`sort`用于对第 1 列进行数字排序并将其反转。`head`用于从输出中解析前 10 行。

例如：

```
$ du -ak /home/slynux | sort -nrk 1 | head -n 4
50220 /home/slynux
43296 /home/slynux/.mozilla
43284 /home/slynux/.mozilla/firefox
43276 /home/slynux/.mozilla/firefox/8c22khxc.default

```

上述一行命令的一个缺点是它包括目录在结果中。然而，当我们只需要找到最大的文件而不是目录时，我们可以改进一行命令，只输出大尺寸的文件，如下所示：

```
$ find . -type f -exec du -k {} \; | sort -nrk 1 | head

```

我们使用`find`来过滤`du`而不是允许`du`自行递归遍历。

### 磁盘空闲信息

`du`命令提供有关使用情况的信息，而`df`提供有关可用磁盘空间的信息。它可以与`-h`一起使用，也可以不使用。当`df`与`-h`一起使用时，它以人类可读的格式打印磁盘空间。

例如：

```
$ df
Filesystem           1K-blocks      Used Available Use% Mounted on
/dev/sda1              9611492   2276840   6846412  25% /
none                    508828       240    508588   1% /dev
none                    513048       168    512880   1% /dev/shm
none                    513048        88    512960   1% /var/run
none                    513048         0    513048   0% /var/lock
none                    513048         0    513048   0% /lib/init/rw
none                   9611492   2276840   6846412  25% /var/lib/ureadahead/debugfs

$ df -h
FilesystemSize  Used Avail Use% Mounted on
/dev/sda1             9.2G  2.2G  6.6G  25% /
none                  497M  240K  497M   1% /dev
none                  502M  168K  501M   1% /dev/shm
none                  502M   88K  501M   1% /var/run
none                  502M     0  502M   0% /var/lock
none                  502M     0  502M   0% /lib/init/rw
none                  9.2G  2.2G  6.6G  25% /var/lib/ureadahead/debugfs

```

# 计算命令的执行时间

在测试应用程序或比较给定问题的不同算法时，程序所花费的执行时间非常关键。一个好的算法应该在最短的时间内执行。有几种情况下，我们需要监视程序执行所花费的时间。例如，在学习排序算法时，如何实际陈述哪个算法更快？答案是计算相同数据集的执行时间。让我们看看如何做到这一点。

## 如何做到...

`time`是任何类 UNIX 操作系统中都可用的命令。您可以在要计算执行时间的命令前加上`time`，例如：

```
$ time COMMAND

```

命令将被执行并显示其输出。除了输出之外，`time`命令还会在`stderr`中附加所用的时间。例如：

```
$ time ls
test.txt
next.txt
real    0m0.008s
user    0m0.001s
sys     0m0.003s

```

它将显示执行的实际、用户和系统时间。三种不同的时间可以定义如下：

+   **Real**是挂钟时间——从调用开始到结束的时间。这是包括其他进程使用的时间片和进程被阻塞时花费的时间（例如，如果它正在等待 I/O 完成）的所有经过的时间。

+   **User**是进程内用户模式代码（内核之外）中花费的 CPU 时间。这只是执行进程时实际使用的 CPU 时间。其他进程和进程被阻塞时花费的时间不计入这个数字。

+   **Sys**是进程内核中花费的 CPU 时间。这意味着内核中系统调用中执行的 CPU 时间，而不是仍在用户空间中运行的库代码。与“用户时间”一样，这只是进程使用的 CPU 时间。

### 注意

`time`命令的可执行二进制文件位于`/usr/bin/time`，还有一个名为`time`的 shell 内置命令。当我们运行`time`时，默认情况下会调用 shell 内置命令。shell 内置的 time 选项有限。因此，我们应该使用可执行文件（`/usr/bin/time`）的绝对路径来执行其他功能。

我们可以使用`-o filename`选项将时间统计信息写入文件，如下所示：

```
$ /usr/bin/time -o output.txt COMMAND

```

文件名应该始终出现在`-o`标志之后。

为了将时间统计信息附加到文件而不覆盖，使用`-a`标志以及`-o`选项如下：

```
$ /usr/bin/time –a -o output.txt COMMAND

```

我们还可以使用`-f`选项使用格式字符串格式化时间输出。格式字符串由与特定选项对应的参数组成，前缀为`%`。实际时间、用户时间和系统时间的格式字符串如下：

+   实际时间 - `%e`

+   用户 - `%U`

+   sys - `%S`

通过组合参数字符串，我们可以创建格式化的输出，如下所示：

```
$ /usr/bin/time -f "FORMAT STRING" COMMAND

```

例如：

```
$ /usr/bin/time -f "Time: %U" -a -o timing.log uname
Linux

```

这里`%U`是用户时间的参数。

生成格式化输出时，命令的格式化输出被写入标准输出，而被计时的`COMMAND`的输出被写入标准错误。我们可以使用重定向运算符（`>`）重定向格式化输出，并使用（`2>`）错误重定向运算符重定向时间信息输出。例如：

```
$ /usr/bin/time -f "Time: %U" uname> command_output.txt 2>time.log
$ cat time.log
Time: 0.00
$ cat command_output.txt
Linux

```

使用`time`命令可以收集有关进程的许多细节。重要的细节包括退出状态、接收的信号数、进行的上下文切换次数等。可以使用适当的格式字符串显示每个参数。

以下表格显示了一些有趣的参数：

| 参数 | 描述 |
| --- | --- |
| `%C` | 被计时命令的名称和命令行参数。 |
| `%D` | 进程的未共享数据区的平均大小，以千字节为单位。 |
| `%E` | 进程使用的实际经过的时间（挂钟时间）[小时:]分钟:秒。 |
| `%x` | 命令的退出状态。 |
| `%k` | 传递给进程的信号数。 |
| `%W` | 进程被交换出主内存的次数。 |
| `％Z` | 系统的页面大小（以字节为单位）。这是一个每系统常量，但在系统之间有所不同。 |
| `％P` | 此作业获得的 CPU 百分比。这只是用户+系统时间除以总运行时间。它还打印一个百分号。 |
| `％K` | 进程的平均总（数据+堆栈+文本）内存使用量，以千字节为单位。 |
| `％w` | 程序自愿上下文切换的次数，例如在等待 I/O 操作完成时。 |
| `％c` | 进程被非自愿上下文切换的次数（因为时间片到期）。 |

例如，可以使用`％Z`参数显示页面大小如下：

```
$ /usr/bin/time -f "Page size: %Z bytes" ls> /dev/null
Page size: 4096 bytes

```

这里不需要`timed`命令的输出，因此将标准输出重定向到`/dev/null`设备，以防止它写入终端。

还有更多的格式字符串参数可用。阅读`man time`以获取更多详细信息。

# 有关登录用户、引导日志和引导失败的信息

收集有关操作环境、登录用户、计算机已经运行的时间以及任何引导失败的信息非常有帮助。这个教程将介绍一些用于收集有关活动机器信息的命令。

## 准备工作

这个教程将介绍`who`、`w`、`users`、`uptime`、`last`和`lastb`命令。

## 如何做...

要获取有关当前登录到计算机的用户的信息，请使用：

```
$ who
slynux   pts/0   2010-09-29 05:24 (slynuxs-macbook-pro.local)
slynux   tty7    2010-09-29 07:08 (:0) 

```

或者：

```
$ w
 07:09:05 up  1:45,  2 users,  load average: 0.12, 0.06, 0.02
USER     TTY     FROM    LOGIN@   IDLE  JCPU PCPU WHAT
slynux   pts/0   slynuxs 05:24  0.00s  0.65s 0.11s sshd: slynux 
slynux   tty7    :0      07:08  1:45m  3.28s 0.26s gnome-session

```

它将提供有关登录用户、用户使用的伪 TTY、当前从伪终端执行的命令以及用户登录的 IP 地址的信息。如果是本地主机，它将显示主机名。`who`和`w`的格式输出略有不同。`w`命令提供的详细信息比`who`更多。

TTY 是与文本终端相关联的设备文件。当用户新生成终端时，将在`/dev/`中创建相应的设备（例如`/dev/pts/3`）。可以通过键入和执行`tty`命令来找出当前终端的设备路径。

要列出当前登录到计算机的用户，请使用：

```
$ users
Slynux slynux slynux hacker

```

如果用户已经打开了多个伪终端，将显示相同用户的多个条目。在上面的输出中，用户`slynux`已经打开了三个伪终端。打印唯一用户的最简单方法是使用`sort`和`uniq`进行过滤，如下所示：

```
$ users | tr ' ' '\n' | sort | uniq
slynux
hacker

```

我们使用`tr`将`' '`替换为`'\n'`。然后`sort`和`uniq`的组合将为每个用户生成唯一的条目。

为了查看系统已经运行了多长时间，请使用：

```
$ uptime
 21:44:33 up  3:17,  8 users,  load average: 0.09, 0.14, 0.09

```

跟在单词`up`后面的时间表示系统已经运行的时间。我们可以编写一个简单的一行代码来提取仅运行时间。

`uptime`输出中的平均负载是指系统负载的一个参数。这在章节*Administration Calls!*中有更详细的解释。为了获取有关以前的引导和用户登录会话的信息，请使用：

```
$ last
slynux   tty7         :0              Tue Sep 28 18:27   still logged in
reboot   system boot  2.6.32-21-generi Tue Sep 28 18:10 - 21:46  (03:35)
slynux   pts/0        :0.0            Tue Sep 28 05:31 - crash  (12:39)

```

`last`命令将提供有关登录会话的信息。实际上，它是一个系统登录的日志，其中包含`tty`从中登录的信息、登录时间、状态等。

`last`命令使用日志文件`/var/log/wtmp`作为输入日志数据。还可以使用`-f`选项明确指定`last`命令的日志文件。例如：

```
$ last –f /var/log/wtmp

```

为了获取单个用户的登录会话信息，请使用：

```
$ last USER

```

获取有关重新启动会话的信息如下：

```
$ last reboot
reboot   system boot  2.6.32-21-generi Tue Sep 28 18:10 - 21:48  (03:37)
reboot   system boot  2.6.32-21-generi Tue Sep 28 05:14 - 21:48  (16:33)

```

为了获取有关失败的用户登录会话的信息，请使用：

```
# lastb
test     tty8         :0               Wed Dec 15 03:56 - 03:56  (00:00) 
slynux   tty8         :0               Wed Dec 15 03:55 - 03:55  (00:00)

```

您应该以 root 用户身份运行`lastb`。

# 打印最常用的 10 个命令

终端是用于访问 shell 提示符的工具，在那里我们输入和执行命令。用户在 shell 中运行许多命令。其中许多是经常使用的。通过查看他经常使用的命令，可以很容易地识别用户的性质。这个教程是一个小练习，用于找出最常用的 10 个命令。

## 准备工作

Bash 通过用户之前输入的命令并存储在文件`~/.bash_history`中来跟踪先前输入的命令。但它只保留最近执行的一定数量（比如 500）的命令。可以使用`history`命令或`cat ~/.bash_history`命令查看命令的历史记录。我们将使用这个来查找经常使用的命令。

## 如何做...

我们可以从`~/.bash_history`获取命令列表，仅获取不包括参数的命令，计算每个命令的出现次数，并找出出现次数最高的 10 个命令。

以下脚本可用于查找经常使用的命令：

```
#!/bin/bash
#Filename: top10_commands.sh
#Description: Script to list top 10 used commands

printf "COMMAND\tCOUNT\n" ;

cat ~/.bash_history | awk '{ list[$1]++; } \
END{
for(i in list)
{
printf("%s\t%d\n",i,list[i]); }
}'| sort -nrk 2 | head
```

示例输出如下：

```
$ ./top10_commands.sh
COMMAND  COUNT
ping    80
ls      56
cat     35
ps      34
sudo    26
du      26
cd      26
ssh     22
sftp    22
clear   21

```

## 它是如何工作的...

在上述脚本中，历史文件`~/.bash_history`是使用的源文件。源输入通过管道传递给`awk`。在`awk`中，我们有一个关联数组列表。这个数组可以使用命令名称作为索引，并将命令的计数存储在数组位置中。因此，对于每个命令的到达或出现，它将递增一个（`list[$1]++`）。`$1`被用作索引。`$1`是输入行中文本的第一个单词。如果使用`$0`，它将包含命令的所有参数。例如，如果`ssh 192.168.0.4`是来自`.bash_history`的一行，`$0`等于`ssh 192.168.0.4`，`$1`等于`ssh`。

一旦历史文件的所有行都被遍历，我们将得到一个带有命令名称作为索引和它们计数作为值的数组。因此，具有最大计数值的命令名称将是最常用的命令。因此，在`awk`的`END{}`块中，我们遍历命令的索引并打印所有命令名称和它们的计数。`sort -nrk 2`将根据第二列（`COUNT`）执行数值排序并反转它。因此，我们使用`head`命令从列表中提取前 10 个命令。您可以使用参数`head -n NUMBER`将前 10 个自定义为前 5 个或任何其他数字。

# 列出一个小时内消耗前 10 个 CPU 的进程

CPU 时间是一个重要的资源，有时我们需要跟踪在一段时间内消耗最多 CPU 周期的进程。在常规的台式机或笔记本电脑上，CPU 被大量消耗可能不是一个问题。然而，对于处理大量请求的服务器来说，CPU 是一个关键资源。通过监视一定时间内的 CPU 使用情况，我们可以识别一直占用 CPU 的进程，并优化它们以有效地使用 CPU 或者由于其他问题对它们进行调试。这个配方是一个处理监视和记录进程的实践。

## 准备工作

`ps`是一个用于收集有关系统上运行的进程的详细信息的命令。它可以用于收集诸如 CPU 使用情况、正在执行的命令、内存使用情况、进程状态等的详细信息。可以记录一个小时内消耗 CPU 的进程，并通过适当使用`ps`和文本处理来确定前 10 个进程。有关`ps`命令的更多详细信息，请参阅章节：*管理调用*。

## 如何做...

让我们通过以下 shell 脚本来监视和计算一个小时内的 CPU 使用情况：

```
#!/bin/bash
#Name: pcpu_usage.sh
#Description: Script to calculate cpu usage by processes for 1 hour

SECS=3600
UNIT_TIME=60

#Change the SECS to total seconds for which monitoring is to be performed.
#UNIT_TIME is the interval in seconds between each sampling

STEPS=$(( $SECS / $UNIT_TIME ))

echo Watching CPU usage... ;

for((i=0;i<STEPS;i++))
do
  ps -eo comm,pcpu | tail -n +2 >> /tmp/cpu_usage.$$
  sleep $UNIT_TIME
done

echo
echo CPU eaters :

cat /tmp/cpu_usage.$$ | \
awk '
{ process[$1]+=$2; }
END{ 
  for(i in process)
  {
    printf("%-20s %s",i, process[i] ;
  }

   }' | sort -nrk 2 | head

rm /tmp/cpu_usage.$$
#Remove the temporary log file
```

示例输出如下：

```
$ ./pcpu_usage.sh
Watching CPU usage...
CPU eaters :
Xorg        20
firefox-bin   15
bash        3
evince      2
pulseaudio    1.0
pcpu.sh         0.3
wpa_supplicant  0
wnck-applet     0
watchdog/0      0
usb-storage     0

```

## 它是如何工作的...

在上述脚本中，主要的输入来源是`ps -eocomm, pcpu`。`comm`代表命令名称，`pcpu`代表 CPU 使用率百分比。它将输出所有进程名称和 CPU 使用率百分比。对于输出中的每个进程都存在一行。由于我们需要监视一个小时的 CPU 使用情况，我们会使用`ps -eo comm,pcpu` `| tail -n +2`重复地获取使用统计信息，并将其附加到一个文件`/tmp/cpu_usage.$$`中，该文件在`for`循环中运行，每次迭代都等待 60 秒。这个等待是由`sleep 60`提供的。它将每分钟执行一次`ps`。

`tail -n +2`用于剥离`ps`输出中的标题和`COMMAND %CPU`。

`$$`在`cpu_usage.$$`中表示它是当前脚本的进程 ID。假设 PID 为 1345，在执行期间它将被替换为`/tmp/cpu_usage.1345`。我们将这个文件放在`/tmp`中，因为它是一个临时文件。

统计文件将在一小时后准备好，并包含 60 个条目，对应于每分钟的进程状态。然后使用`awk`来对每个进程的总 CPU 使用情况进行求和。一个关联数组进程用于 CPU 使用情况的求和。它使用进程名称作为数组索引。最后，它根据总 CPU 使用情况进行数字逆排序，并通过 head 获取前 10 个使用情况条目。

## 另请参阅

+   *第四章的基本 awk 入门*，解释了 awk 命令

+   *head 和 tail - 打印第三章的最后或前十行*，解释了 tail 命令

# 使用 watch 监视命令输出

我们可能需要在相等的时间间隔内持续观察命令的输出一段时间。例如，对于大文件复制，我们需要观察文件大小的增长。为了做到这一点，新手们反复输入命令并按回车键多次。相反，我们可以使用 watch 命令重复查看输出。本教程解释了如何做到这一点。

## 如何做...

`watch`命令可用于定期监视终端上命令的输出。`watch`命令的语法如下：

```
$ watch COMMAND

```

例如：

```
$ watch ls

```

或者：

```
$ watch 'COMMANDS'

```

例如：

```
$ watch 'ls -l | grep "^d"'
# list only directories

```

此命令将以默认间隔两秒更新输出。

我们还可以通过使用`-n SECONDS`来指定输出需要更新的时间间隔。例如：

```
$ watch -n 5 'ls -l'
#Monitor the output of ls -l at regular intervals of 5 seconds

```

## 还有更多

让我们探索`watch`命令的一个附加功能。

### 突出显示 watch 输出中的差异

在`watch`中，有一个选项可以在执行命令期间更新的差异以突出显示，并使用颜色进行标记。可以通过使用`-d`选项启用差异突出显示，如下所示：

```
$ watch -d 'COMMANDS'

```

# 记录对文件和目录的访问

记录文件和目录访问对于跟踪文件和文件夹发生的变化非常有帮助。本教程将描述如何记录用户访问。

## 准备就绪

`inotifywait`命令可用于收集有关文件访问的信息。它不会默认随每个 Linux 发行版一起提供。您必须使用软件包管理器安装`inotify-tools`软件包。它还需要 Linux 内核编译时启用 inotify 支持。大多数新的 GNU/Linux 发行版都启用了内核中的 inotify。

## 如何做...

让我们走一遍监视目录访问的 shell 脚本：

```
#/bin/bash
#Filename: watchdir.sh
#Description: Watch directory access
path=$1
#Provide path of directory or file 
as argument to script

inotifywait -m -r -e create,move,delete $path  -q 

```

示例输出如下：

```
$ ./watchdir.sh .
./ CREATE new
./ MOVED_FROM new
./ MOVED_TO news
./ DELETE news

```

## 它是如何工作的...

先前的脚本将记录从给定路径创建、移动和删除文件和文件夹的事件。给出`-m`选项以持续监视更改，而不是在事件发生后退出。给出`-r`以启用递归监视目录。`-e`指定要监视的事件列表。`-q`是为了减少冗长的消息并只打印所需的消息。此输出可以重定向到日志文件。

我们可以添加或删除事件列表。可用的重要事件如下：

| 事件 | 描述 |
| --- | --- |
| `access` | 当文件发生读取时。 |
| `modify` | 当文件内容被修改时。 |
| `attrib` | 当元数据被更改时。 |
| `move` | 当文件进行移动操作时。 |
| `create` | 当创建新文件时。 |
| `open` | 当文件进行打开操作时。 |
| `close` | 当文件进行关闭操作时。 |
| `delete` | 当文件被删除时。 |

# 使用 logrotate 进行日志文件管理

日志文件是 Linux 系统维护的重要组成部分。日志文件有助于跟踪系统上不同服务发生的事件。这有助于系统管理员调试问题，还提供了有关实时机器上发生的事件的统计信息。需要管理日志文件，因为随着时间的推移，日志文件的大小会变得越来越大。因此，我们使用一种称为轮换的技术来限制日志文件的大小，如果日志文件达到了限制之外的大小，它将剥离日志文件并将日志文件的旧条目存储在归档中。因此，旧日志可以被存储和保留以供将来参考。让我们看看如何轮换日志并存储它们。

## 准备工作

`logrotate`是每个 Linux 系统管理员都应该了解的命令。它有助于限制日志文件的大小。在日志文件中，记录器将信息追加到日志文件中。因此，最近的信息出现在日志文件的底部。`logrotate`将根据配置文件扫描特定的日志文件。它将保留日志文件的最后 100 千字节（例如，指定 SIZE = 100k），并将其余数据（旧的日志数据）移动到一个新文件`logfile_name.1`中。当日志文件（`logfile_name.1`）中出现更多条目并且超过了 SIZE 时，它将使用最新的条目更新日志文件，并创建带有旧日志的`logfile_name.2`。这个过程可以很容易地通过`logrotate`进行配置。`logrotate`还可以将旧日志压缩为`logfile_name.1.gz`、`logfile_name2.gz`等。是否压缩旧日志文件的选项在`logrotate`配置中可用。

## 如何做...

`logrotate`的配置目录位于`/etc/logrotate.d`。如果列出该目录的内容，可以找到许多其他日志文件的配置。

我们可以为我们的日志文件编写自定义配置（比如`/var/log/program.log`）如下：

```
$ cat /etc/logrotate.d/program
/var/log/program.log {
missingok
notifempty
size 30k
 compress
weekly
 rotate 5
create 0600 root root
}

```

现在配置已经完成。配置中的`/var/log/program.log`指定了日志文件路径。它将在相同的目录路径中归档旧日志。让我们看看这些参数各是什么：

| 参数 | 描述 |
| --- | --- |
| `missingok` | 如果日志文件丢失，则忽略并返回而不进行日志轮换。 |
| `notifempty` | 只有在源日志文件不为空时才进行日志轮换。 |
| `size 30k` | 限制要进行轮换的日志文件的大小。可以是 1M 表示 1MB。 |
| `compress` | 启用 gzip 对较旧的日志进行压缩。 |
| `weekly` | 指定进行轮换的时间间隔。可以是每周、每年或每天。 |
| `rotate 5` | 要保留的旧日志文件归档副本的数量。由于指定了 5，将会有`program.log.1.gz`、`program.log.2.gz`，以此类推，直到`program.log.5.gz`。 |
| `create 0600 root root` | 指定要创建的日志文件归档的模式、用户和组。 |

表中指定的选项是可选的；我们可以在`logrotate`配置文件中只指定所需的选项。`logrotate`有许多可用的选项。请参考 man 页面（[`linux.die.net/man/8/logrotate`](http://linux.die.net/man/8/logrotate)）获取有关`logrotate`的更多信息。

# 使用 syslog 记录

日志文件是为向用户提供服务的应用程序的重要组成部分。应用程序在运行时将状态信息写入其日志文件。如果发生任何崩溃或者我们需要查询有关服务的一些信息，我们会查看日志文件。您可以在`/var/log`目录中找到与不同守护程序和应用程序相关的许多日志文件。这是存储日志文件的常见目录。如果您阅读日志文件的几行，您会发现日志中的行是以常见格式编写的。在 Linux 中，创建和将日志信息写入`/var/log`日志文件由一种称为 syslog 的协议处理。它由`syslogd`守护程序处理。每个标准应用程序都使用 syslog 来记录信息。在本教程中，我们将讨论如何使用`syslogd`从 shell 脚本记录信息。

## 准备就绪

日志文件对帮助您推断系统出现了什么问题非常有用。因此，在编写关键应用程序时，始终将应用程序的进度记录到日志文件中是一种良好的做法。我们将学习命令记录器以使用`syslogd`记录到日志文件。在了解如何写入日志文件之前，让我们先浏览一下 Linux 中使用的重要日志文件列表：

| 日志文件 | 描述 |
| --- | --- |
| `/var/log/boot.log` | 启动日志信息。 |
| `/var/log/httpd` | Apache Web 服务器日志。 |
| `/var/log/messages` | 启动后内核信息。 |
| `/var/log/auth.log` | 用户认证日志。 |
| `/var/log/dmesg` | 系统启动消息。 |
| `/var/log/mail.log` | 邮件服务器日志。 |
| `/var/log/Xorg.0.log` | X 服务器日志。 |

## 如何做…

为了记录到 syslog 文件`/var/log/messages`，请使用：

```
$ logger LOG_MESSAGE

```

例如：

```
$ logger This is a test log line

$ tail -n 1 /var/log/messages
Sep 29 07:47:44 slynux-laptop slynux: This is a test log line

```

日志文件`/var/log/messages`是一个通用目的的日志文件。当使用`logger`命令时，默认情况下会记录到`/var/log/messages`。为了记录到具有指定标记的 syslog 中，请使用：

```
$ logger -t TAG This is a message

$ tail -n 1 /var/log/messages
Sep 29 07:48:42 slynux-laptop TAG: This is a message

```

syslog 处理`/var/log`中的许多日志文件。但是，当记录器发送消息时，它使用标记字符串来确定需要记录到哪个日志文件中。`syslogd`通过使用与日志相关的`TAG`来决定应将日志记录到哪个文件中。您可以从位于`/etc/rsyslog.d/`目录中的配置文件中查看标记字符串和相关的日志文件。

为了将另一个日志文件的最后一行记录到系统日志中，请使用：

```
$ logger -f /var/log/source.log

```

## 另见

+   *head 和 tail - 打印最后或前 10 行* 第三章 ，解释 head 和 tail 命令

# 监视用户登录以查找入侵者

日志文件可用于收集有关系统状态的详细信息。以下是一个有趣的脚本编写问题陈述：

我们有一个连接到启用 SSH 的互联网的系统。许多攻击者试图登录系统。我们需要编写一个 shell 脚本来设计入侵检测系统。入侵者被定义为尝试在两分钟以上进行多次尝试并且所有尝试都失败的用户。应检测此类用户并生成报告，其中包括以下详细信息：

+   尝试登录的用户帐户

+   尝试次数

+   攻击者的 IP 地址

+   IP 地址的主机映射

+   尝试登录的时间范围。

## 入门

我们可以编写一个 shell 脚本，可以扫描日志文件并从中收集所需的信息。在这里，我们正在处理 SSH 登录失败。用户认证会话日志被写入日志文件`/var/log/auth.log`。脚本应扫描日志文件以检测失败的登录尝试，并对日志执行不同的检查以推断数据。我们可以使用`host`命令从 IP 地址找出主机映射。

## 如何做…

让我们编写一个入侵者检测脚本，该脚本可以使用认证日志文件生成入侵者报告，如下所示：

```
#!/bin/bash
#Filename: intruder_detect.sh
#Description: Intruder reporting tool with auth.log input
AUTHLOG=/var/log.auth.log

if [[ -n $1 ]];
then
  AUTHLOG=$1
  echo Using Log file : $AUTHLOG
fi

LOG=/tmp/valid.$$.log
grep -v "invalid" $AUTHLOG > $LOG
users=$(grep "Failed password" $LOG | awk '{ print $(NF-5) }' | sort | uniq)

printf "%-5s|%-10s|%-10s|%-13s|%-33s|%s\n" "Sr#" "User" "Attempts" "IP address" "Host_Mapping" "Time range"

ucount=0;

ip_list="$(egrep -o "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" $LOG | sort | uniq)"

for ip in $ip_list;
do
  grep $ip $LOG > /tmp/temp.$$.log

for user in $users;
do
  grep $user /tmp/temp.$$.log> /tmp/$$.log
  cut -c-16 /tmp/$$.log > $$.time
  tstart=$(head -1 $$.time);
  start=$(date -d "$tstart" "+%s");

  tend=$(tail -1 $$.time);
  end=$(date -d "$tend" "+%s")

  limit=$(( $end - $start ))

  if [ $limit -gt 120 ];
  then
    let ucount++;

    IP=$(egrep -o "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" /tmp/$$.log | head -1 );

    TIME_RANGE="$tstart-->$tend"

    ATTEMPTS=$(cat /tmp/$$.log|wc -l);

    HOST=$(host $IP | awk '{ print $NF }' )

  printf "%-5s|%-10s|%-10s|%-10s|%-33s|%-s\n" "$ucount" "$user" "$ATTEMPTS" "$IP" "$HOST" "$TIME_RANGE";
  fi
done
done

rm /tmp/valid.$$.log /tmp/$$.log $$.time /tmp/temp.$$.log 2> /dev/null
```

示例输出如下：

![如何做…](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-cb/img/3760_08_01.jpg)

## 它是如何工作的...

在`intruder_detect.sh`脚本中，我们使用`auth.log`文件作为输入。我们可以通过使用命令行参数将日志文件作为输入提供给脚本，或者默认情况下，它读取`/var/log/auth.log`文件。我们只需要记录关于有效用户名的登录尝试的详细信息。当发生无效用户的登录尝试时，类似于`Failed password for invalid user bob from 203.83.248.32 port 7016 ssh2`的日志将被记录到`auth.log`。因此，我们需要排除日志文件中所有包含“invalid”单词的行。使用带有反转选项（`-v`）的`grep`命令来删除所有与无效用户对应的日志。下一步是找出发生登录尝试并失败的用户列表。SSH 将记录类似于`sshd[21197]: Failed password for bob1 from 203.83.248.32 port 50035 ssh2`的日志行，表示密码错误。

因此，我们应该找到所有包含“failed password”单词的行。现在需要找出所有唯一的 IP 地址，以提取与每个 IP 地址对应的所有日志行。可以使用 IP 地址的正则表达式和`egrep`命令来提取 IP 地址的列表。使用`for`循环来迭代 IP 地址，并使用`grep`找到相应的日志行，并将其写入临时文件。日志行中倒数第六个单词是用户名（例如，bob1）。使用`awk`命令从最后一个单词中提取第六个单词。`NF`返回最后一个单词的列数。因此，`NF-5`给出了倒数第六个单词的列数。我们使用`sort`和`uniq`命令来生成一个不重复的用户列表。

现在我们应该收集包含每个用户名称的失败登录日志行。使用`for`循环来读取与每个用户对应的行，并将这些行写入临时文件。每个日志行中的前 16 个字符是时间戳。使用`cut`命令来提取时间戳。一旦我们获得了用户的所有失败登录尝试的时间戳，我们应该检查第一次尝试和最后一次尝试之间的时间差。第一条日志行对应于第一次尝试，最后一条日志行对应于最后一次尝试。我们使用`head -1`提取第一行和`tail -1`提取最后一行。现在我们有第一次（`tstart`）和最后一次尝试（`tends`）的时间戳的字符串格式。使用`date`命令，我们可以将字符串表示的日期转换为 UNIX Epoch 时间的总秒数（第一章的*获取、设置日期和延迟*中的配方解释了 Epoch 时间）。

变量 start 和 end 具有与日期字符串中的开始和结束时间戳对应的秒数。现在，取它们之间的差异，并检查是否超过两分钟（120 秒）。因此，特定用户被称为入侵者，并且相应的带有详细信息的条目将被生成为日志。可以使用 IP 地址的正则表达式和`egrep`命令从日志中提取 IP 地址。尝试次数是用户的日志行数。可以使用`wc`命令找出行数。主机名映射可以通过使用 IP 地址作为参数运行 host 命令的输出来提取。时间范围可以使用我们提取的时间戳来打印。最后，脚本中使用的临时文件将被删除。

上述脚本旨在说明从日志中扫描并生成报告的模型。它试图使脚本更小更简单，以排除复杂性。因此它有一些错误。您可以通过使用更好的逻辑来改进脚本。

# 远程磁盘使用健康监视器

一个网络由几台具有不同用户的机器组成。网络需要对远程机器的磁盘使用情况进行集中监控。网络的系统管理员需要每天记录网络中所有机器的磁盘使用情况。每条日志行应包含日期、机器的 IP 地址、设备、设备容量、已使用空间、剩余空间、使用百分比和健康状态等详细信息。如果任何远程机器中任何分区的磁盘使用率超过 80％，健康状态应设置为警报，否则应设置为安全。本示例将说明如何编写一个监控脚本，可以从网络中的远程机器收集详细信息。

## 准备工作

我们需要从网络中的每台机器单独收集磁盘使用统计信息，并在中央机器中编写日志文件。可以安排每天在特定时间运行收集详细信息并写入日志的脚本。可以使用 SSH 登录到远程系统来收集磁盘使用数据。

## 如何做…

首先，我们必须在网络中的所有远程机器上设置一个公共用户帐户。这是为了让 disklog 程序登录到系统中。我们应该为该特定用户配置 SSH 自动登录（在第七章的*使用 SSH 进行无密码自动登录*一节中，解释了自动登录的配置）。我们假设所有远程机器中都有一个名为 test 的用户，配置了自动登录。让我们来看一下 shell 脚本：

```
#!/bin/bash
#Filename: disklog.sh
#Description: Monitor disk usage health for remote systems

logfile="diskusage.log"

if [[ -n $1 ]]
then
  logfile=$1
fi

if [ ! -e $logfile ]
then

  printf "%-8s %-14s %-9s %-8s %-6s %-6s %-6s %s\n" "Date" "IP address" "Device" "Capacity" "Used" "Free" "Percent" "Status" > $logfile
fi

IP_LIST="127.0.0.1 0.0.0.0"
#provide the list of remote machine IP addresses 

(
for ip in $IP_LIST;
do

  ssh slynux@$ip 'df -H' | grep ^/dev/ > /tmp/$$.df

  while read line;
  do
    cur_date=$(date +%D)
    printf "%-8s %-14s " $cur_date $ip
    echo $line | awk '{ printf("%-9s %-8s %-6s %-6s %-8s",$1,$2,$3,$4,$5); }'

  pusg=$(echo $line | egrep -o "[0-9]+%")
  pusg=${pusg/\%/};
  if [ $pusg -lt 80 ];
  then
    echo SAFE
  else
    echo ALERT
  fi

  done< /tmp/$$.df	
done

) >> $logfile
```

我们可以使用 cron 实用程序安排定期运行脚本。例如，要在每天上午 10 点运行脚本，可以在`crontab`中写入以下条目：

```
00 10 * * * /home/path/disklog.sh /home/user/diskusg.log
```

运行命令`crontab -e`。添加上述行并保存文本编辑器。

您可以手动运行脚本，如下所示：

```
$ ./disklog.sh

```

上述脚本的示例输出日志如下：

![如何做…](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-sh-scp-cb/img/3760_08_02.jpg)

## 它是如何工作的…

在`disklog.sh`脚本中，我们可以将日志文件路径作为命令行参数提供，否则它将使用默认日志文件。如果日志文件不存在，它将把日志文件头文本写入新文件中。使用`-e $logfile`来检查文件是否存在。远程机器的 IP 地址列表存储在变量`IP_LIST`中，用空格分隔。必须确保`IP_LIST`中列出的所有远程系统都有一个名为`test`的公共用户，并配置了 SSH 自动登录。使用`for`循环来迭代每个 IP 地址。执行远程命令`df -H`来使用`ssh`命令获取磁盘空闲使用数据。它被存储在一个临时文件中。使用`while`循环逐行读取文件。使用`awk`提取数据并打印。还打印日期。使用`egrep`命令提取百分比使用率，并用`none`替换`%`以获得百分比的数值。检查百分比值是否超过 80。如果小于 80，则状态设置为安全，如果大于或等于 80，则状态设置为警报。整个打印数据应重定向到日志文件。因此，代码部分被封装在子 shell`()`中，并且标准输出被重定向到日志文件。

## 另请参阅

+   *使用 cron 进行调度*在第九章中，解释了 crontab 命令

# 查找系统上活跃用户的小时数

考虑一个具有共享托管的 Web 服务器。每天有许多用户登录和退出服务器。用户活动记录在服务器的系统日志中。这个示例是一个实践任务，利用系统日志，找出每个用户在服务器上花了多少小时，并根据总使用小时数对它们进行排名。应该生成一个报告，包括排名、用户、第一次登录日期、最后登录日期、登录次数和总使用小时数等详细信息。让我们看看如何解决这个问题。

## 准备工作

`last`命令用于列出系统中用户的登录会话的详细信息。日志数据存储在`/var/log/wtmp`文件中。通过为每个用户单独添加会话小时数，我们可以找出总使用小时数。

## 如何做到这一点...

让我们通过脚本找出活跃用户并生成报告。

```
#!/bin/bash
#Filename: active_users.sh
#Description: Reporting tool to find out active users

log=/var/log/wtmp

if [[ -n $1 ]];
then
  log=$1
fi

printf "%-4s %-10s %-10s %-6s %-8s\n" "Rank" "User" "Start" "Logins" "Usage hours"

last -f $log | head -n -2   > /tmp/ulog.$$

cat /tmp/ulog.$$ |  cut -d' ' -f1 | sort | uniq> /tmp/users.$$

(
while read user;
do
  grep ^$user /tmp/ulog.$$ > /tmp/user.$$
  seconds=0

while read t
  do
    s=$(date -d $t +%s 2> /dev/null) 
    let seconds=seconds+s
  done< <(cat /tmp/user.$$ | awk '{ print $NF }' | tr -d ')(')

  firstlog=$(tail -n 1 /tmp/user.$$ | awk '{ print $5,$6 }')
  nlogins=$(cat /tmp/user.$$ | wc -l) 
  hours=$(echo "$seconds / 60.0" | bc)

  printf "%-10s %-10s %-6s %-8s\n"  $user "$firstlog" $nlogins $hours
done< /tmp/users.$$ 

) | sort -nrk 4 | awk '{ printf("%-4s %s\n", NR, $0) }' 
rm /tmp/users.$$ /tmp/user.$$ /tmp/ulog.$$
```

一个示例输出如下：

```
$ ./active_users.sh
Rank User       Start      Logins Usage hours
1    easyibaa   Dec 11     531    11437311943
2    demoproj   Dec 10     350    7538718253
3    kjayaram   Dec 9      213    4587849555
4    cinenews   Dec 11     85     1830831769
5    thebenga   Dec 10     54     1163118745
6    gateway2   Dec 11     52     1120038550
7    soft132    Dec 12     49     1055420578
8    sarathla   Nov 1      45     969268728
9    gtsminis   Dec 11     41     883107030
10   agentcde   Dec 13     39     840029414

```

## 它是如何工作的...

在`active_users.sh`脚本中，我们可以将`wtmp`日志文件作为命令行参数提供，或者它将使用`defaulwtmp`日志文件。使用`last -f`命令来打印日志文件内容。日志文件中的第一列是用户名。通过使用`cut`命令，我们从日志文件中提取第一列。然后使用`sort`和`uniq`命令找出唯一的用户。现在对于每个用户，使用`grep`找出对应其登录会话的日志行，并将其写入临时文件。最后一条日志中的最后一列是用户登录会话的持续时间。因此，为了找出用户的总使用小时数，需要将会话持续时间相加。使用时间命令将使用持续时间转换为秒。

为了提取用户的会话小时数，我们使用了`awk`命令。为了去掉括号，使用了`tr -d`命令。使用`<( COMMANDS )`操作符将使用小时字符串列表传递给`while`循环的标准输入。它充当文件输入。通过使用`date`命令，将每个小时字符串转换为秒，并添加到变量`seconds`中。用户的第一次登录时间在最后一行，并且被提取出来。登录尝试次数是日志行数。为了根据总使用小时数计算每个用户的排名，数据记录需要按照使用小时作为关键字进行降序排序。为了指定反向排序的数量，使用`-nr`选项以及`sort`命令。`-k4`用于指定关键列（使用小时）。最后，排序的输出被传递给`awk`。`awk`命令为每行添加了行号，这成为每个用户的排名。
