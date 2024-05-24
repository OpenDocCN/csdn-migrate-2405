# Kali Linux 2019 学习手册（二）

> 原文：[`annas-archive.org/md5/29591BFA2DAF3F905BBECC2F6DAD8828`](https://annas-archive.org/md5/29591BFA2DAF3F905BBECC2F6DAD8828)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：主动信息收集

在渗透测试的侦察阶段，主动信息收集可以提供非常有用的结果。通过这种主动方法，渗透测试人员直接连接到实际目标，收集**开源情报**（**OSINT**）无法提供的具体细节。使用主动信息收集，渗透测试人员能够创建目标的非常详细的概要，收集操作系统类型和运行服务等信息。这些信息有助于研究和识别与目标相关的漏洞，从而缩小选择特定利用方式的范围。 

在整个本章中，我们将专注于直接与目标进行互动，以收集有关其特定细节的信息，以帮助我们对任何正在运行的服务进行概要。了解如何执行主动侦察将为我们在利用阶段提供重要的帮助。在信息收集阶段，您将能够识别漏洞并确定适当的利用方式来入侵系统和网络。您还将能够从网络设备和系统中检索敏感信息。

在本章的过程中，我们将涵盖以下主题：

+   了解主动信息收集

+   DNS 询问

+   扫描

+   Nmap

+   Hping3

+   SMB、LDAP 枚举和空会话

+   使用 EyeWitness 进行网络足迹和枚举

+   Metasploit 辅助模块

# 技术要求

以下是本章的技术要求：

+   Kali Linux: [www.kali.org](http://www.kali.org)

+   Wireshark: [www.wireshark.org](http://www.wireshark.org)

+   JXplorer: [`github.com/pegacat/jxplorer`](https://github.com/pegacat/jxplorer)

+   EyeWitness: [`github.com/FortyNorthSecurity/EyeWitness`](https://github.com/FortyNorthSecurity/EyeWitness)

# 了解主动信息收集

主动信息收集使用直接方法与我们的目标进行互动；它实际上涉及在我们的机器和目标网络和系统之间建立连接。通过执行主动信息收集，我们能够收集特定和详细的数据，如活动主机、运行的服务和应用程序版本、网络文件共享和用户帐户信息。

执行主动信息收集确实存在被检测的风险。

确定活动主机将让我们了解在线设备的数量。针对离线设备没有意义，因为它将无法响应。了解目标上的操作系统和运行的服务将帮助我们了解该设备在网络中的角色以及为其客户提供的资源。

例如，如果在主动信息收集过程中在目标系统上找到了大量文件共享，这可能意味着目标可能是一个具有大量重要数据的文件服务器。在执行主动信息收集时，攻击者的机器（在我们的案例中是基于 Kali Linux 的机器）向潜在受害者发送特殊查询，希望受害者机器会通过提供某种机密信息（如网络共享和服务版本）来回应。

现在您对主动信息收集有了更好的理解，让我们深入探讨以下各节中的实践。

# DNS 询问

作为未来的网络安全专业人士，理解各种应用程序和网络协议的目的非常重要。在本节中，我们将专注于一个特定的协议：**域名系统**（**DNS**）。

让我们首先进一步了解 DNS 的作用以及作为渗透测试人员如何获取信息。

# DNS 是什么，为什么我们需要在网络上使用它？

DNS 就像一个包含名称、地址和电话号码的电话目录。DNS 用于网络——组织的内部网络和互联网上的外部网络。DNS 协议用于将主机名（域名）解析为 IP 地址。

在 DNS 出现之前，每台计算机都包含一个位于`C:\Windows\System32\drivers\etc`目录中的`hosts`文件。为了确保用户能够通过指定其主机名或域名到达各种网站或服务器，需要经常更新此文件。如果没有`hosts`文件，用户需要指定他们想要访问的服务器的 IP 地址。

网络上的所有设备都有一个分配的 IP 地址。记住要访问的每个服务器或网站的所有 IP 地址将是非常具有挑战性的。如果`hosts`文件不包含新服务器和网站的最新记录，用户将难以到达他们的目的地。

以下屏幕截图显示了 Windows 操作系统的`hosts`文件中的当前条目：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/e917ba89-ee3a-46d0-87d6-56818b1b673e.png)

Windows 主机文件记录

DNS 帮助我们避免依赖`hosts`文件。许多知名的互联网公司，如思科、谷歌和 Cloudflare，都建立了包含几乎每个互联网域名记录的公共 DNS 服务器。为了进一步阐述，让我们用一个简单的例子来帮助您理解 DNS 的工作原理。

想象一下，您想访问一个网站，比如[www.example.com](http://www.example.com)：

1.  每当计算机或设备需要将主机名解析为 IP 地址时，它会向其 DNS 服务器发送 DNS 查询消息，如下图中的*步骤 1*所示。

1.  DNS 服务器将检查其记录，并在下图中的*步骤 2*中向客户端计算机提供域的 IP 地址。

1.  最后，客户端收到 IP 地址，并在下图中显示的*步骤 3*中与`www.example.com`域建立会话：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/b062ba1c-4040-4a76-a34f-bd46e6318028.png)

DNS 交易

互联网上有许多公共 DNS 服务器；其中一些具有恶意性质，捕获您的 DNS 信息并将您重定向到有害的网站和域。因此，我建议在所有网络设备和计算机上使用受信任的 DNS 提供商，以提高您的在线安全性。以下是互联网上一些知名的 DNS 服务器：

+   Cloudflare DNS：[`1.1.1.1/`](https://1.1.1.1/)

+   Google Public DNS：[`developers.google.com/speed/public-dns/`](https://developers.google.com/speed/public-dns/)

+   Cisco OpenDNS：[`www.opendns.com/`](https://www.opendns.com/)

此外，DNS 服务器不仅将主机名解析为 IP 地址，还包含用于各种类型解析的各种记录。

以下是不同的记录类型：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/6e4b82f0-90c5-48cb-9e0a-627241b01a4a.png)

DNS 记录类型

**A**记录类型的示例将是将`www.example.com`的主机名映射到 IPv4 地址`93.184.216.34`；相同主机名的**AAAA**记录将包含 IPv6 地址`2606:2800:220:1:248:1893:25c8:1946`，依此类推。

`nslookup`实用程序是验证 DNS 信息的非常有用的工具。 `nslookup`可以执行各种任务，例如解析给定域的每种类型的 DNS 记录，并且具有查询特定 DNS 服务器的能力。

**DNS 枚举**是探测特定组织域的特定 DNS 记录的技术。换句话说，我们询问 DNS 服务器有关目标组织的 IP 地址和服务器名称。此外，我们尝试执行 DNS 区域传输。**DNS 区域传输**将允许将区域文件从主 DNS 服务器复制到另一个 DNS 服务器，例如辅助 DNS 服务器。

然而，DNS 服务器管理员有时会忘记应用安全控制以防止将区域文件复制到未经授权的服务器。成功的 DNS 区域传输可能导致渗透测试人员获取企业网络布局。在最坏的情况下（对于被定向的组织来说），组织可能没有在其 DNS 服务器上分离内部和外部命名空间。这样的错误配置可能导致某人为恶意目的获取这样的信息。

在接下来的练习中，我们将尝试提取给定域的各种 DNS 记录：

+   DNS 枚举

+   DNS 区域传输

+   使用`host`实用程序进行 DNS 分析

+   使用**Fierce**进行 DNS 询问

让我们深入研究并在 Kali Linux 上享受一些与 DNS 相关的乐趣！

# 执行 DNS 枚举和区域传输使用 dnsenum

dnsenum 是一个非常简单易用的工具，用于枚举和解析给定目标的 DNS 信息。此外，它具有使用**名称服务器**详细信息自动执行 DNS 区域传输的能力：

1.  打开一个新的终端窗口并执行`dnsenum`命令。帮助菜单将显示，提供各种操作符/参数及其用法的详细描述。

1.  使用`dnsenum zonetransfer.me`命令对`zonetransfer.me`域执行 DNS 枚举，如下面的屏幕截图所示：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/4195abba-027d-480e-97fd-800e33abba18.png)

dnsenum

dnsenum 将尝试获取给定域的所有服务器和主机名。我们能够获取找到的每个服务器和主机名的名称服务器、邮件服务器（用于电子邮件交换）和 IP 地址。

1.  dnsenum 将尝试通过查询枚举过程中找到的特定名称服务器来执行 DNS 区域传输，如下面的屏幕截图所示：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/f5f241fe-9328-4b4f-896e-082f394169bf.png)

DNS 区域传输

就像前面的片段一样，dnsenum 工具能够成功地从`nsztml.digi.ninja`名称服务器中提取/复制**主区记录**。使用找到的信息，渗透测试人员将更好地了解目标组织（`zonetransfer.me`）的内部和外部网络设备。

访问敏感信息，例如我们发现的信息，可能会导致成功地入侵目标组织的网络。

接下来，我们将尝试使用本机 Linux 工具进行 DNS 分析。

# 使用`host`实用程序进行 DNS 分析

`host`实用程序是 Linux 操作系统的本机工具，可以帮助我们获取有关目标域的各种 DNS 信息：

1.  在 Kali Linux 上打开一个新的终端并执行`host zonetransfer.me`命令；`host`工具将尝试获取域的 DNS 记录，如**A**和**MX**记录：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/bb8cb216-fd91-4deb-8354-669c799333d1.png)

使用`host`检索 DNS 记录

1.  使用`host -t ns zonetransfer.me`命令尝试通过获取域的名称服务器来进行枚举。`-t`操作符允许您指定 DNS 记录：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/8df4df6e-b71b-45c0-8215-4a0679b422ef.png)

名称服务器记录

1.  现在我们已经获取了域的名称服务器，让我们利用迄今为止收集的信息。让我们尝试通过使用`host -l zonetransfer.me nsztml.digi.ninja`命令查询域的名称服务器来执行 DNS 区域传输，如下面的屏幕截图所示：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/8bedac8b-859f-4508-9ae7-4b8f86edc438.png)

使用主机进行 DNS 区域传输

确保查询给定域的所有名称服务器 - 有时，一个服务器可能配置错误，即使其他服务器已经得到了保护。

现在您已经具备执行 DNS 枚举和区域传输的技能，让我们尝试使用 DNS 发现子域。

# 使用 dnsmap 查找子域

**dnsmap**与我们在前面的示例中看到的工具有些不同。dnsmap 尝试通过查询 Kali Linux 操作系统上的内置单词列表来枚举组织域名的子域。一旦找到子域，dnsmap 将尝试解析 IP 地址。

使用`dnsmap microsoft.com`命令，我们能够找到组织的子域和它们对应的 IP 地址：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/150a577c-3a18-46ee-be35-617dd1f91147.png)

dnsmap 结果

如前一节所述，发现组织的子域可以导致在域中找到隐藏的敏感门户和目录。

正如您可能已经注意到的，到目前为止我们使用的每个工具都为我们提供了更多的细节。在下一节中，我们将使用更具侵略性的工具来帮助我们提取有关目标域的更多细节。

# 使用 Fierce 进行 DNS 审讯

Fierce 被认为是一种半轻量级的 DNS 审讯工具。它对给定目标域的 IP 空间和主机名执行广泛的查找。要使用 Fierce，我们可以执行`fierce -dns example.com`命令，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/f5b43e27-e343-40e5-9fe8-a6f01fe70811.png)

Fierce DNS 审讯

Fierce 将尝试获取给定域的所有 DNS 记录，并发现任何子域及其相应的 IP 地址。该工具可能需要一些时间来完成其审讯，因为它对目标域实施了深入分析。

我们现在已经完成了本节的练习。接下来，我们将直接与目标进行接触，使用各种扫描技术收集更具体的细节。

# 扫描

让我们将信息收集阶段推进一步。在本节中，我们将对目标执行各种扫描类型。这些将包括以下内容：

+   Ping 扫描

+   操作系统和服务版本检测

+   扫描禁用 ICMP 的主机设备

+   执行隐蔽扫描

+   使用 Nmap 扫描 UDP 端口

+   使用 Nmap 执行规避扫描技术

扫描的目标是识别网络上的活动主机，确定系统上的开放和关闭端口，识别目标上运行的服务，并创建目标网络基础设施的网络图。在网络扫描阶段获取的信息对于创建目标组织的概况至关重要。

在许多国家，未经许可进行目标扫描是非法的。因此，我们将在我们的实验室内扫描设备。

在数据包中，有许多类型的 TCP 标志在网络上的两个或多个主机之间进行通信时使用。作为渗透测试人员，我们可以利用 TCP/IP 堆栈中的某些漏洞来执行网络扫描。换句话说，我们将向目标发送特制的标志，以确定其端口状态、操作系统、正在运行的服务及其版本；我们还将确定防火墙是否监视入站或出站流量等。

以下 TCP 标志位于数据包中：

+   `URG`：（**紧急**）指示应立即处理此数据包

+   `PSH`：（**推送**）立即发送缓冲数据

+   `FIN`：（**结束**）指示没有更多的传输需要发送

+   `ACK`：（**确认**）确认收到消息

+   `RST`：（**重置**）重置网络连接

+   `SYN`：（**同步**）用于初始化主机设备之间的连接

通过使用 Wireshark（[www.wireshark.org](http://www.wireshark.org)）等工具，您可以观察网络上数据包的每个细节。

以下片段是设置了`ACK`标志的网络数据包的捕获：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/c5cb2d83-88ca-4217-aa77-c2a4ba04b59c.png)

启用 ACK 标志的数据包

此外，通过观察数据包中的细节，您可以看到源和目的地 MAC 地址、IP 地址、端口和其他重要特征。Wireshark 被认为是网络和网络安全专业人员中最好的网络协议分析器和嗅探器之一。

既然我们了解了扫描的重要性，让我们了解一下行业中最流行的扫描工具之一，Nmap。

# Nmap

Nmap 是免费的，是 Windows 和 Linux 平台上最强大的网络扫描工具之一。Nmap 可以在许多方面帮助网络管理员和网络安全专业人员。

Nmap 的功能包括以下内容：

+   创建网络清单

+   检查活动主机

+   确定操作系统

+   确定运行的服务及其版本

+   识别主机上的漏洞

+   检测嗅探器

+   确定网络上是否存在防火墙

我们将首先介绍 Nmap 的基础知识，然后逐渐转向高级扫描技术。作为渗透测试人员，我们必须确保拥有一套工具，可以帮助我们高效地完成工作。然而，作为专业人士，我们还必须确保非常熟悉并知道如何使用我们可用的每个工具。

因此，我们将从对目标进行基本扫描开始：

1.  让我们从打开一个新的终端并使用以下语法开始：`nmap <目标 IP 或主机名>`。

1.  我们将扫描一个已经给予我们合法许可的网站。让我们使用`nmap scanme.nmap.org`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/73168080-b963-4a51-9621-5977998d41ce.png)

Nmap 扫描 1

通过定期扫描目标或网络，Nmap 会检查目标上使用最广泛的 1000 个 TCP/IP 端口。

1.  观察输出，Nmap 能够识别开放的端口，确定开放的端口是 TCP 还是 UDP，识别应用层协议，并找出目标的 IP 地址（IPv4 和 IPv6）。

确定目标上的开放端口就像发现系统中的开放门一样，确定服务可以帮助我们缩小搜索和利用漏洞的范围。

要对 IPv6 地址进行扫描，可以包括`-6`操作符，如：`nmap -6 2600:3c01::f03c:91ff:fel8:bb2f`。

Nmap 并不那么难，对吧？让我们在接下来的部分中更深入地了解 Nmap。

# 使用 Nmap 进行 ping 扫描

有时，在渗透测试期间，您可能需要识别网络上的所有活动主机。Nmap 能够在多个目标上执行 ping 扫描，无论是指定范围还是整个子网。使用`-sn`操作符将允许您仅对目标执行 ping 扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/3266d5e1-d6ed-4c09-9512-3859e5c59b7a.png)

使用 Nmap 进行 ping 扫描

在前面的片段中，Nmap 只呈现了它认为在网络段上是活动的主机，并且能够查找每个主机的 MAC 地址以确定供应商。

+   如果您想要执行范围扫描，可以使用以下语法：`nmap start ip addr - end ip addr`。

+   如果您想要扫描网络上的特定 IP 设备，请使用以下语法：`nmap host1 host2 host3`。

+   Nmap 还支持使用以下语法扫描列在文本文件中的主机：`nmap –iL file.txt`。

现在让我们提升一下，学习更多关于如何在接下来的部分中使用 Nmap 的知识。

# 使用 Nmap 获取操作系统和服务版本

到目前为止，我们已经能够收集有关目标的基本信息。我们可以使用 Nmap 帮助用户确定操作系统、操作系统版本以及目标上运行的应用程序的服务版本。

使用`-A`操作符将启动一个侵略性扫描，`-O`将对操作系统进行概要分析，`-sV`将识别服务版本。

执行一种侵入式扫描可能会被**侵入检测系统**/**侵入预防系统**（**IDS**/**IPS**）或防火墙设备标记。要小心，因为渗透测试的一个重要部分是尽可能保持安静，以避免被发现。

在我们的目标系统 Metasploitable VM 上使用`nmap -A -O -sV target`命令，我们将能够获得关于目标的更有意义的信息。

正如您在以下片段中所看到的，对于每个开放的端口，Nmap 已经确定了在该端口上运行的特定服务，并且我们还能够检索应用服务版本的详细信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/7ef78224-85f8-43ca-a260-b12cb5d06f53.png)

操作系统和服务版本

在输出中再向下滚动一点，我们可以看到，通过使用`-O`参数，Nmap 能够确定操作系统的类型：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/adc54871-b19e-4032-9e42-a7ded6b2f17a.png)

检测内核版本

到目前为止，我们对我们的目标 Metasploitable VM 有了更好的了解。我们知道所有开放的端口、服务和当前正在运行的服务版本，以及操作系统。

Nmap 很棒，不是吗？让我们学习如何使用 Nmap 扫描禁用了 ICMP 的设备。

# 扫描禁用 ICMP 的主机设备

当 Nmap 要对主机执行扫描时，它会向主机发送一个 ping 数据包来确定目标是否存活。如果目标不响应，Nmap 将不会尝试执行扫描。然而，系统管理和网络安全专业人员通常会在服务器上禁用**Internet 控制消息协议**（**ICMP**）响应。从目标那里收不到 ICMP 回显回复将表明目标设备已关闭/离线；然而，这种技术旨在基本上欺骗一个新手黑客，让他认为主机根本不可用。在 Nmap 扫描期间使用`-Pn`操作符将跳过主机发现阶段，并将目标视为在线。

以下是一个例子：

```
nmap -Pn 10.10.10.100
```

在渗透测试期间，如果您无法在网络上发现活动主机，不要过分担心，因为网络安全专业人员倾向于在其终端设备和网络上应用安全控制。Nmap 可以检测隐藏的系统，绕过防火墙和网络嗅探器，以检测主机上的安全漏洞。

在执行扫描时，目标很可能会知道正在进行端口扫描的是攻击者还是渗透测试人员。在接下来的部分中，我们将描述如何使用 Nmap 执行隐秘扫描。

# 使用 Nmap 执行隐秘扫描

默认情况下，Nmap 会在找到的任何开放的 TCP 端口上建立**TCP 三次握手**。握手建立后，消息被交换。以下片段显示了握手过程，其中**主机 A**想要与**主机 B**通信：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/c7b26f71-e515-4559-9794-452593e8cb45.png)

TCP 三次握手

在渗透测试期间，我们需要尽可能保持在网络上隐秘。这会产生一个实际黑客试图在不被组织的安全控制和系统发现的情况下入侵系统/网络的效果。通过与我们的目标设备建立 TCP 三次握手，我们让自己对目标设备有所了解。

因此，我们将使用 Nmap 执行隐秘扫描（半开放）。隐秘扫描不会与目标建立完整的 TCP 握手。

1.  攻击者机器通过向目标发送 TCP SYN 数据包来欺骗目标，如果目标上的特定端口是开放的。

1.  一个 TCP SYN/ACK 数据包被返回给攻击者机器。

1.  最后，攻击者发送一个 TCP RST 数据包来重置目标上的连接状态：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/d9da960d-f408-47cd-89c3-9b88b7b14e47.png)

隐秘扫描

在我们的练习中，我们将使用 Nmap 对我们的 Metasploitable VM 上的端口`80`进行隐蔽扫描。使用`-sS`操作符表示隐蔽扫描，并使用`-p`操作符扫描（探测）特定端口，我们可以在我们的 Kali Linux 机器上执行`nmap -sS -p 80 10.10.10.100`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/aac02726-20c1-4e0a-8390-41e3079f4d34.png)

使用 Nmap 进行隐蔽扫描

使用 Wireshark，我们能够看到我们的 Kali Linux 机器和目标之间的数据包流动。数据包编号 18 表明一个[SYN]数据包被发送到 Metasploitable VM，数据包编号 19 表明一个[SYN, ACK]数据包被返回到 Kali Linux 机器，最后，数据包编号 20 表明我们的 Kali Linux 机器发送了一个[RST]数据包来重置连接：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/be8c86d0-df1a-4b30-bd7d-42f5b4699fee.png)

在 Wireshark 中检测到隐蔽扫描

最终结果是我们成功地探测了目标系统上的一个端口，并没有在我们的机器和目标之间建立网络会话。

有许多服务和协议使用 UDP 作为首选的传输方法。UDP 应用默认不会响应典型的端口扫描。每当使用 Nmap 执行网络/端口扫描时，默认情况下扫描引擎会搜索开放的 TCP 端口；这意味着 UDP 端口通常在结果中被忽略。在下一节中，我们将看一下如何执行 UDP 端口扫描。

# 使用 Nmap 扫描 UDP 端口

有许多应用层协议使用**用户数据报协议**（**UDP**）作为其首选传输协议。使用`-sU`操作符将指示需要对给定目标执行 UDP 端口扫描。使用以下命令，我们可以完成这个任务：

```
nmap -sU target
```

我们现在已经掌握了在目标设备或网络上执行 UDP 扫描的技能。在下一节中，我们将看一下如何使用 Nmap 规避安全设备和检测。

# 使用 Nmap 规避检测

每当一个数据包从一个设备发送到另一个设备时，源 IP 地址都包含在数据包的头部。这是 TCP/IP 协议栈的默认行为；所有地址细节必须包含在需要穿越网络的所有数据包中。在对目标进行网络扫描时，我们的源 IP 地址包含在我们的机器 Kali Linux 发送到目标的所有数据包中。

Nmap 有能力使用伪装来欺骗目标，使其相信网络扫描是来自多个源而不是单个源 IP 地址。`-D`操作符后面跟着随机 IP 地址，这些是伪装。假设我们想要扫描一个 IP 地址`10.10.10.100`，并设置三个伪装：`10.10.10.14`、`10.10.10.15`和`10.10.10.19`。我们可以使用以下命令：

```
nmap -sS 10.10.10.100 –D 10.10.10.14, 10.10.10.15, 10.10.10.19
```

观察以下 Wireshark 捕获，我们可以看到在目标上进行端口扫描时，包含我们源 IP 地址和伪装 IP 地址的数据包被使用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/80c22611-9926-4be5-9550-9ec75d43947f.png)

在 Wireshark 中检测伪装

然而，一个 RST 数据包是从实际的源地址发送的。此外，我们还可以使用其他操作符，如`--spoof-mac`来伪装源 MAC 地址。

在下一节中，我们将学习如何在使用 Nmap 执行网络扫描时规避防火墙检测。

# 使用 Nmap 规避防火墙

在您作为网络安全专业人士、渗透测试人员或道德黑客的职业生涯中，您经常会遇到一些组织——无论是小型、中型还是大型企业——在其网络基础设施上都有某种防火墙设备或软件。

防火墙可以阻止网络扫描并给我们作为渗透测试人员带来挑战。以下是可以在 Nmap 中使用的各种操作符来规避防火墙：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/ac7a1430-aad4-41b8-a51e-d0d5d19dc849.png)

Nmap 的防火墙规避操作符

此外，我们可以发送带有特定标志的自定义探测到目标并分析响应。

在接下来的部分中，我们将看看如何确定网络上是否存在有状态防火墙。

# 检查有状态防火墙

在检查有状态防火墙时，我们可以向目标发送一个启用了 ACK 标志的探测。 如果目标没有提供响应，这将表明存在防火墙：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/9746582b-7a7c-493b-9bc2-b12d74b70367.png)

有状态防火墙存在

但是，如果返回的数据包设置了 RST 标志，这将表明目标系统上没有防火墙：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/85436ee2-05c1-4737-b0aa-d379b7824871.png)

防火墙状态不明

我们可以使用 Nmap 上的`–sA`运算符对目标执行 ACK 扫描。 让我们对我们的 Metasploitable VM 执行扫描，以确定端口`80`是否打开，以及系统是否存在防火墙：

1.  使用`nmap -sA -p 80 <target>`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/f8b7d739-aa20-4443-a031-71981f137e48.png)

使用 Nmap 进行 ACK 扫描

1.  我们能够确定端口`80`在目标上是打开且未经过滤（没有防火墙）。 此外，通过观察数据包，我们看到 RST 数据包返回到我们的 Kali Linux（攻击者）机器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/1f287ce9-f845-48ec-9d42-8381cc64e60f.png)

Wireshark 中显示的端口扫描

每当您对目标进行扫描并且结果表明`filtered`时，这意味着存在防火墙，并且它正在积极监视端口，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/8fa76c5f-be8b-4b82-af3a-a2d2b3287f13.png)

使用 Nmap 检测过滤端口

此外，以下运算符可用于确定系统上是否存在防火墙：

| **运算符** | **描述** |
| --- | --- |
| `-sX` | 执行 XMAS 扫描。 URG，FIN 和 PSH 标志都已设置。 |
| `-sF` | 执行 FIN 扫描。 仅设置 FIN 标志。 |
| `-sN` | 执行 Null 扫描。 没有设置标志。 |

额外的 Nmap 运算符

Nmap 将解释响应并确定目标上的端口是否经过过滤或未经过过滤。

完成了本节后，您现在可以使用 Nmap 对目标进行分析。 在下一节中，我们将学习**Nmap 脚本引擎**（**NSE**）。

# NSE 脚本

NSE 是 Nmap 中最强大的功能之一。 它允许用户创建和自动化脚本，以执行针对目标设备的定制扫描。 通过使用各种 Nmap 脚本执行扫描，您可以快速检测目标是否容易受到已知漏洞，恶意软件，开放后门等的攻击。

以下是 NSE 脚本的主要类别：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/72161386-df94-4f48-8eb8-e2179bd803a6.png)

NSE 类别

要执行整个脚本类别，我们可以使用`--script category`命令。 以下代码片段是在 Nmap 扫描期间使用`vuln`脚本类别的示例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/9175a49e-9f88-4e4c-a09d-e07e9163b187.png)

使用 NSE 找到的漏洞

运行整个脚本类别可能并不总是适用于各种情况。 如果您正在执行扫描以搜索包含特定漏洞的系统，例如**vsFTPd 2.3.4 后门（CVE-2011-2523）**，您可以使用以下命令：

```
nmap --script ftp-proftpd-backdoor target
```

每个 NSE 脚本都存储在 Kali Linux 的`/usr/share/nmap/scripts`目录中。 但是，您应该熟悉使用 NSE 脚本，因为这将帮助您节省时间，并更快地找到有关目标的特定信息。 为了帮助您进一步了解 NSE 脚本，请访问官方 NSE 文档网站[`nmap.org/nsedoc/`](https://nmap.org/nsedoc/)。 该存储库包含每个 NSE 脚本的详细描述。

完成了关于 Nmap 和 NSE 的本节，现在让我们学习 Nmap 的 GUI 版本 Zenmap。

# Zenmap

Zenmap 是 Nmap 的图形用户界面（GUI）版本，并支持多个平台，如 Windows、Linux 和 macOS。Zenmap 的创建是面向初学者的，因为它比 Nmap 的传统命令行界面更容易使用。要在您的系统上下载 Zenmap，请访问[`nmap.org/zenmap/`](https://nmap.org/zenmap/)。

以下显示了 Zenmap 界面。它非常简单易用：只需输入目标并选择要执行的扫描类型。根据您选择的扫描类型，将在命令字段中设置必要的 Nmap 操作符。

为了演示，让我们通过观察以下步骤在我们的 Metasploitable VM 上进行快速扫描：

1.  输入我们目标的 IP 地址。

1.  从配置文件菜单中选择快速扫描选项。

1.  单击扫描开始，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/19b1db05-aac6-41c9-bc1b-3ce37048de50.png)

Zenmap 界面

扫描完成后，单击每个选项卡以获取有关目标的更多详细信息。如果您正在对整个网络进行扫描，拓扑选项卡将帮助您创建目标网络的网络图。

可以通过以下步骤在 Zenmap 上创建自定义扫描配置文件：

1.  要创建新的扫描配置文件，请单击配置文件|新配置文件或命令。

1.  配置文件编辑器将打开，为您提供 Nmap 扫描的所有选项，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/dacd1ddd-3956-44d8-8600-8e0b1f36d278.png)

Zenmap 配置文件编辑器

一定要访问每个选项卡，并熟悉各种可用的选项，因为它们将在将来有用。

正如您所看到的，Zenmap 非常易于使用和用户友好。在下一节中，我们将学习另一个工具 Hping3，用它来执行扫描。

# Hping3

Hping3 是一个命令行工具，允许用户分析网络上的 TCP/IP 消息。此外，Hping3 允许我们组装网络数据包，这对于渗透测试人员在执行设备和服务发现以及攻击性行动（如拒绝服务攻击）时可能有益。

Hping3 是一个可以执行以下任务的工具：

+   在网络上进行主机发现

+   指纹识别主机设备以确定服务

+   嗅探网络流量

+   洪水包（DoS）

+   文件传输

如前一节所述，有许多服务器和设备禁用了 ICMP 响应作为安全预防措施。我们可以使用 Hping3 来探测目标系统上的一个端口，以强制 ICMP 响应返回到我们的攻击者机器。

要开始使用 Hping3，让我们使用以下步骤在端口`80`上执行端口扫描：

1.  我们使用`ping`实用程序向我们的 Windows 服务器机器（启用防火墙并禁用 ICMP）发送四个 ICMP 回显请求消息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/91d4a945-3d52-4322-a7c9-09c74daa1b52.png)

对目标进行 ping

1.  我们的攻击者机器（Kali Linux）没有从目标那里收到任何响应。一个新手黑客可能会认为目标已离线，并可能会离开。但是，使用 Hping3 来探测特定端口，发送 SYN 数据包将迫使目标显露自己。使用`hping3 -S 目标 ip 地址 -p 端口 -c 2`语法，我们得到以下响应：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/9f70b9a5-1094-4f99-af14-7b38b8b7904a.png)

使用 Hping3 进行端口扫描

通过查看我们的结果，我们可以看到我们已经从目标那里收到了成功的响应。这意味着`10.10.10.14`设备在线，并且端口`80`是开放的。

`-S`操作符表示发送 SYN 数据包，`-p`允许您指定目标端口号，`-c`指定要发送的数据包数量。

1.  此外，我们可以进一步采取一步行动，通过在目标设备上的一系列网络端口上执行端口扫描。使用`hping3 -8 20-1000 -S 10.10.10.14`命令，我们能够在目标上的端口范围`20`-`1000`上执行 SYN 扫描。以下片段表明我们的目标上的端口`80`、`135`、`139`、`445`、`902`和`912`是开放的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/d0a189ae-a036-46ba-b258-c401f5ecb998.png)

使用 Hping3 进行隐形扫描

在使用 Hping3 时，还有许多可以组合的操作符；请务必使用终端上的`hping3 -h`命令查看帮助菜单。

现在您已经熟悉了使用 Hping3 作为扫描器，让我们深入研究在目标设备上执行枚举。

# SMB、LDAP 枚举和空会话

在本节中，我们将研究使用各种应用程序协议来帮助我们从目标系统中提取敏感数据和记录。

# SMBmap 和 SMBclient

**SMBmap**是一个流行且易于使用的工具，用于帮助我们发现设备上的任何 SMB 共享并检测任何发现的共享的权限：

1.  使用`smbmap -H target`语法，我们可以尝试执行端口扫描，寻找 SMB 服务使用的端口；在我们的目标上，它是`445`，并且是开放的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/481ba446-50dd-486d-bbbf-d484989bb080.png)

SMB 共享

1.  SMBmap 将尝试在攻击者机器和目标端口`445`之间建立会话，以枚举任何共享驱动器和文件夹。在我们的目标（Metasploitable）上，有一个`tmp`文件夹，它给予我们读写权限。

1.  使用`smbmap -H 10.10.10.100 -r tmp`命令，我们将能够列出指定目录的内容。在我们的示例中，我们正在列出`tmp`文件夹的内容，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/1a809591-326b-4b25-be51-cbe066e69961.png)

SMBmap 枚举

SMBmap 是一个枚举目标设备上 SMB 共享的绝佳工具；然而，始终最好在您的工具库中有另一个工具可用。其他工具包括 SMBlookup、SMBclient 和 Nmap。

有关 SMBmap 的更多信息，请访问：[`tools.kali.org/information-gathering/smbmap`](https://tools.kali.org/information-gathering/smbmap)。

**SMBclient**是另一个方便的工具，工作方式类似于 SMBmap。要在目标上枚举 SMB 服务，我们可以使用`smbclient -L //target`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/2a63d131-89cd-4585-adac-f67b2512e8fe.png)

SMBclient 枚举

SMBclient 将尝试提取目标设备上的任何共享，如前面的截图所示。有关 SMBclient 的更多信息，请访问：[`www.samba.org/samba/docs/current/man-html/smbclient.1.html`](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)。

完成了本节后，您已经掌握了使用 SMBmap 和 SMBclient 在目标上执行 SMB 枚举的技能。在下一节中，我们将简要讨论另一个流行的 SMB 枚举工具 Enum4linux。

# Enum4linux

**Enum4linux**是一种枚举工具，能够检测和提取 Windows 和 Linux 操作系统上的数据，包括网络上的**Samba**（**SMB**）主机。Enum4linux 能够发现以下内容：

+   目标上的密码策略

+   远程目标的操作系统

+   设备上的共享（驱动器和文件夹）

+   域和组成员资格

+   用户列表

要扫描目标，请使用以下命令：`enum4linux target`。该工具将执行所有可能的检查和枚举。一开始输出可能有点压倒性：一定要仔细检查细节，因为它们将包含有关目标的有意义信息。

Enum4linux 有时会派上用场，用于在网络上执行扫描以发现任何共享资源。在下一节中，我们将深入探讨 Windows 网络上的 LDAP 枚举。

# LDAP 枚举

**轻量级目录访问协议**（**LDAP**）用于查询数据库或目录类型的服务。一个常见的例子是一个拥有**Active Directory**（**AD**）服务器的企业环境，该服务器管理整个组织的用户账户。诸如台式电脑之类的终端设备需要在每次用户尝试登录到该台式电脑时查询 AD 服务器。

LDAP 默认使用端口`389`；然而，数据包以明文形式在网络上传输。另外，使用**LDAPS**（**LDAP 安全**）确保了在客户端和 LDAP 服务器之间发送的信息默认是加密的；LDAPS 默认使用端口`636`。我们可以使用 Nmap 扫描在网络上具有端口`389`和`636`开放的设备。

我们可以使用一个名为 JXplorer（[`jxplorer.org`](http://jxplorer.org)）的工具来执行 LDAP 枚举。这个工具不是在 Kali Linux 中原生安装的，因此，我们需要从它的 GitHub 存储库中下载并运行它。

要开始 LDAP 枚举，让我们使用以下步骤： 

1.  使用以下命令来下载和执行这个工具：

```
git clone https://github.com/pegacat/jxplorer.git cd jxplorer chmod +x jxplorer.sh ./jxplorer.sh
```

1.  一旦成功执行`./jxplorer.sh`脚本，用户界面将会打开。点击连接图标（位于文件下方）来插入你的目标的详细信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/207f67b3-e9fd-4e47-a5a7-b0f7f5b23047.png)

JXplorer 界面

在我们的实验室中，我们有一台 Windows Server 机器，配置如下：

+   已安装 Active Directory 域服务

+   已安装 Active Directory 轻量级目录服务

+   域：`pentestlab.local`

+   创建的用户账户：`bob`（属于域管理员用户组）

假设，在渗透测试期间，通过使用数据包嗅探工具如 Wireshark，你能够在用户尝试对 AD 服务器进行身份验证时捕获用户凭据，你可以在前面的截图中的安全字段中使用这些用户账户。

使用管理员用户账户将提供在 JXplorer 中提取信息所需的权限；你将能够从 Active Directory 服务器中枚举敏感信息，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/e7b8c7b8-0bf1-4981-bd94-70102e37d663.png)

使用 JXplorer 进行 LDAP 枚举

你将能够从你的攻击者机器上查看整个目录并提取敏感信息。如果服务只使用 LDAPS，这将是一个挑战，因为用户凭据将被隐藏。

完成了这个练习之后，让我们在下一节中使用**rpcclient**工具执行一个空会话攻击。

# 空会话

在一个空会话中，攻击者能够使用一个空账户登录到目标。空账户是一个实际上并不存在的账户。这是怎么可能的呢？一些系统容易受到允许匿名登录的漏洞。一旦用户能够匿名登录，空用户就能够检索存储在目标上的敏感信息。

我们可以尝试从我们的 Kali Linux 机器（攻击者）到目标 Metasploitable 上进行一个空会话枚举，使用`rpcclient -U "" 10.10.10.100`命令，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/39cd647e-81c9-4cca-bbe8-f78fa963c091.png)

空会话攻击

使用`srvinfo`命令，目标将会向我们返回它的操作系统类型。要获取查询命令的完整列表，你可以使用`rpcclient --help`命令。另外，你可以访问[`www.samba.org/samba/docs/current/man-html/rpcclient.1.html`](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html)。

请记住，并非所有的机器都容易受到这种类型的攻击，但在渗透测试中执行这种攻击仍然是值得的。在下一节中，我们将讨论通过嘈杂的身份验证控制进行用户枚举。

# 通过嘈杂的身份验证控制进行用户枚举

枚举是黑客或渗透测试人员尝试对目标系统执行暴力攻击以猜测或确认有效用户的技术。一个简单的例子是，恶意用户或渗透测试人员在电子邮件门户上执行密码猜测或暴力攻击。

以下是一个典型登录门户的示例。以下截图中显示的凭据是一个示例，不是真实的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/5860f2b0-7691-426d-b5f3-d7ee75d908af.png)

攻击者可以尝试各种可能的用户名和密码组合，直到找到一个有效的用户。然而，这种攻击被认为是喧闹的而不是隐秘的。作为比较，想象一下你在玩一个在线第一人称射击游戏，你的任务是入侵敌人的基地并偷走一个奖杯而不引起警卫的注意。如果你不够小心并发出任何大声的声音，警卫就会被警觉，任务就会失败。在这个类比中，警卫是安全控制，传感器是防火墙、IDS/IPS 和反恶意软件保护。因此，这种技术在网络上并不是安静的；然而，这种方法仍然可以让你访问系统，前提是安全控制在你获得访问权限之前不执行锁定操作。

很多时候，当用户在登录门户上输入错误的用户名时，通常会返回一个错误消息，通常说明已输入了错误的用户名。这清楚地告诉攻击者，提供的用户名在数据库中不存在。此外，如果输入了错误的密码，系统通常会返回一条消息，说明为该用户名输入了错误的密码。因此，从攻击者的角度来看，系统告诉我们，用户名存在于数据库中，但我们没有为它提供正确的密码。

现在，Web 开发人员和安全专业人员在用户名或密码不正确时都包含了通用响应，类似于这样的消息：*用户名/密码不正确*。这条消息并没有明确说明哪个值是正确的或不正确的。

现在您对喧闹的身份验证控件有了更好的理解，让我们尝试在下一节中执行 Web 枚举。

# 使用 EyeWitness 进行 Web 足迹和枚举

**EyeWitness**是一个允许渗透测试人员在不离开终端的情况下捕获网站截图的工具——该工具在后台完成所有工作。想象一下需要对多个网站进行视觉配置文件、打开**虚拟网络计算**（**VNC**）服务器和使用**远程桌面协议**（**RDPs**）的情况。这可能是一个耗时的任务。EyeWitness 拍摄截图，将它们存储在离线状态，并提供 HTML 报告：

1.  首先，您需要使用`git clone https://github.com/FortyNorthSecurity/EyeWitness.git`从其 GitHub 存储库下载 EyeWitness。

1.  下载完成后，访问`root/EyeWitness/setup`目录，并使用以下命令序列运行`setup.sh`脚本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/12d98d7c-a8ae-45c8-97b2-8eaf1f551d31.png)

EyeWitness 设置屏幕

1.  设置过程完成后，使用`cd ..`命令进入`root/EyeWitness`目录。要对单个网站进行截图，使用以下命令：

```
./EyeWitness.py --web --single example.com 
```

您可以在 Metasploitable 或 OWASP BWA 虚拟机上的一个 Web 应用程序上尝试这个工具。

EyeWitness 允许您使用`--web`、`--rdp`、`--vnc`和`--all-protocols`等操作符指定各种协议。

1.  任务完成后，EyeWitness 将指示是否成功捕获了目标的截图，并为您提供离线报告的位置，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/46f904e0-5e3b-4dd1-a605-0eea354e98d2.png)

EyeWitness 报告向导

1.  打开 HTML 报告后，左侧列包含有关 Web 请求的信息，而右侧列包含截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/7f541fd7-bdcc-45e5-a921-1bc05a3dd3e0.png)

EyeWitness 的报告

这个工具在同时对多个服务和网站进行概要分析时非常方便。

有关 EyeWitness 的更多信息，请访问[`tools.kali.org/information-gathering/eyewitness`](https://tools.kali.org/information-gathering/eyewitness)。

现在您已经完成了这一部分，可以使用 EyeWitness 工具执行 Web 枚举。

# Metasploit 辅助模块

Metasploit 是由 Rapid7 创建的开发利用框架（[www.rapid7.com](http://www.rapid7.com)）。Metasploit 包含许多用于渗透测试的功能和功能。有许多模块，如 exploits、payloads、encoders 和 auxiliary。辅助模块包含端口扫描器、网络嗅探器、模糊器等，以便于渗透测试的信息收集阶段：

1.  要访问 Metasploit 界面，请打开一个新的终端并执行以下命令：

```
service postgresql start msfconsole
```

1.  一旦用户界面加载，`show auxiliary`命令将提供 Metasploit 中所有辅助模块的列表。让我们用一个简单的例子来演示如何使用模块：假设您想对目标进行隐秘（SYN）扫描。您可以开始选择一个模块。

1.  使用`use auxiliary/scanner/portscan/syn`命令。

1.  使用`show options`命令检查描述和要求。

1.  此模块要求配置远程主机；使用`set RHOSTS target`命令。

1.  要执行模块，请使用`run`命令。

1.  以下截图演示了对我们的 Windows 服务器（`10.10.10.14`）进行隐秘扫描的结果底部显示了找到的各种开放端口：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/71c7c9fa-34f1-49f2-8355-67fdcef8df66.png)

1.  此外，在 Metasploit 中搜索模块时，使用`search keyword`语法非常有用，因为框架中有许多不同的模块，学习它们都可能非常具有挑战性和压倒性。

在本书的后续章节中，我们将深入探讨如何使用 Metasploit 在我们的实验室中对目标设备进行利用。

# 摘要

在本章中，我们使用了各种 DNS 询问技术，使用各种工具发现了重要的服务器、子域和 IP 地址，并成功地从 DNS 服务器（区域传输）中提取了区域文件，因为目标 DNS 服务器的配置错误。

然后，我们使用 Nmap 执行各种类型的端口扫描，以确定端口状态、运行服务及其版本以及目标操作系统；我们还得知了目标是否有防火墙。最后，为了结束本章，我们执行了 SMB 和 LDAP 枚举，以收集网络设备上的用户共享和目录记录。

现在您已经完成了本章，您将能够成功地在易受攻击的 DNS 服务器上执行 DNS 区域传输；对系统进行概要分析，发现其操作系统、运行服务和安全漏洞；在执行网络扫描时规避检测；并在目标上执行 LDAP 和系统枚举。您还获得了同时对多个网站进行视觉概要分析的技能。希望本章对您学习渗透测试的旅程有所帮助。

在第七章中，*使用漏洞扫描器*，我们将介绍使用漏洞扫描器查找目标上的安全漏洞和缺陷的重要性。

# 问题

以下是基于本章内容的一些问题：

1.  使用 DNS 的主要目的是什么？

1.  DNS 区域传输是什么意思？

1.  什么工具允许我们对目标系统进行扫描，并确定其运行的服务和操作系统？

1.  在扫描期间使用了什么方法来规避防火墙？

1.  可以用什么工具来枚举 Active Directory？

# 进一步阅读

+   信息收集和漏洞评估：[`hub.packtpub.com/information-gathering-and-vulnerability-assessment-0/`](https://hub.packtpub.com/information-gathering-and-vulnerability-assessment-0/)

+   开源情报：[`hub.packtpub.com/open-source-intelligence/`](https://hub.packtpub.com/open-source-intelligence/)

+   收集情报并制定攻击策略：[`hub.packtpub.com/gather-intel-and-plan-attack-strategies/`](https://hub.packtpub.com/gather-intel-and-plan-attack-strategies/)


# 第三部分：使用 Kali Linux 2019 进行漏洞评估和渗透测试

本节向读者介绍了各种漏洞扫描器及其目的和功能，以及渗透测试，并帮助识别系统或网络中的安全漏洞以及如何利用它们。

此外，读者将通过使用 Kali Linux 2019 中的各种工具获得实际的渗透测试技术和方法。读者将被带过所有相关阶段，从发现目标上的漏洞到利用各种操作系统和 Web 应用程序。

本节包括以下章节：

+   第七章，*使用漏洞扫描器*

+   第八章，*理解网络渗透测试*

+   第九章，*网络渗透测试-连接前攻击*

+   第十章，*网络渗透测试-获取访问权限*

+   第十一章，*网络渗透测试-连接后攻击*

+   第十二章，*网络渗透测试-检测和安全*

+   第十三章，*客户端攻击-社会工程*

+   第十四章，*执行网站渗透测试*

+   第十五章，*网站渗透测试-获取访问权限*

+   第十六章，*最佳实践*


# 第七章：使用漏洞扫描器

在渗透测试期间，发现和分析安全漏洞起着重要作用。在渗透测试人员或道德黑客成功启动攻击之前，他们必须能够识别攻击表面上的安全弱点。攻击表面是攻击者可以尝试进入或从系统中获取数据的区域。快速识别漏洞并获得严重性评级的战略方法是使用已知和知名的漏洞扫描器。

有许多知名的漏洞扫描器，如 Acunetix、OpenVAS、Qualys、Nexpose、Nikto、Retina Network Security Scanner 和 Nessus 等。了解所有这些工具是一个好主意，但您不希望运行每个工具，因为其中一些是商业和订阅服务。

选择漏洞扫描器作为首选选择非常重要，因为有很多时候产品供应商可能无法及时提供更新以检测系统中的威胁和弱点，这对于您作为渗透测试人员可能至关重要。想象一下运行扫描以确定系统是否容易受到特定攻击的影响，而您使用的工具不包含签名更新以检测此类漏洞；结果可能不会有成果。

在本章的过程中，我们将探讨使用 Nessus 作为我们首选的漏洞扫描器。

在本章中，我们将探讨以下漏洞评估工具和主题：

+   Nessus 及其策略

+   使用 Nessus 进行扫描

+   导出 Nessus 结果

+   分析 Nessus 结果

+   使用 Web 应用程序扫描器

# 技术要求

以下是本章的技术要求：

+   Kali Linux：[`www.kali.org/`](https://www.kali.org/)

+   Nessus（基本版）：[`www.tenable.com/products/nessus/nessus-essentials`](https://www.tenable.com/products/nessus/nessus-essentials)

+   WordPress 服务器：[`www.turnkeylinux.org/wordpress`](https://www.turnkeylinux.org/wordpress)

# Nessus 及其策略

Nessus 是业内最知名和知名的漏洞扫描器之一，被许多网络安全专业人士使用。它已成为网络安全专业人员进行漏洞评估的事实行业标准。使用 Nessus 的一些好处包括以下内容：

+   发现超过 45,000 个**通用漏洞和公开漏洞**（**CVE**）

+   包含超过 100,000 个插件（用于发现漏洞）

+   频繁更新新插件以发现新披露的漏洞

+   能够识别过去三年中超过 100 个零日漏洞

让我们登录到我们的 Kali Linux 机器上的 Nessus；首先，您需要在终端窗口中使用以下命令启用 Nessus 服务：

```
service nessusd start
```

一旦成功启用服务，在 Kali Linux 中打开 Web 浏览器，输入`https://localhost:8834`到地址栏中，然后点击*Enter*。您应该看到以下登录门户网站：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/fb77e4c8-5a1c-4d26-aec0-9468a0086906.png)

使用您在设置过程中创建的用户帐户登录。登录后，主要仪表板可用。在这里，您可以配置和访问策略和插件规则，创建新扫描并查看结果。Nessus 用户界面是一个非常简单易用的界面，您很快就会非常熟悉它。

# Nessus 策略

在 Nessus 应用程序中，有许多现有的策略用于各种目的，并且新策略经常添加到数据库中。Nessus 策略是控制对目标系统进行扫描的技术方面的参数。更进一步地说，扫描的技术方面可能包括要扫描的主机设备数量、端口号和服务、协议类型（TCP、UDP 和 ICMP）、端口扫描器的类型等。

Nessus 策略还允许在基于 Windows 的操作系统、Oracle 平台等数据库应用程序以及 FTP、POP 和 HTTP 等应用层协议上使用凭据（用户名和密码）进行本地扫描。

有预安装的策略，可帮助安全从业者对系统执行合规性审计。一个例子是检查处理付款卡交易的网络是否容易受攻击，使用**内部 PCI 网络扫描**。该策略将根据**PCI 数据安全标准**（**PCI DSS**）检查任何漏洞。

Nessus 策略允许通过将哈希校验和与目标系统上的良性和恶意文件进行比较，来扫描 Windows 操作系统上的恶意软件感染。当确定网络上感染某种恶意软件的主机数量时，该策略非常方便。

要开始使用 Nessus 上的策略，请确保您当前已登录 Nessus。在左侧窗格中，单击**策略**。以下屏幕截图显示了 Nessus 家庭版中当前可用的策略。但是，如果您想解锁其他插件和策略，您需要获取专业版：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/b135b42a-ed67-434d-89fa-f46683d73f04.png)

如前所述，策略包含了预定义的配置，用于扫描目标以寻找特定的漏洞，并确保系统符合合规标准。但是，作为安全专业人员，您需要自定义自己的扫描策略，以对各种类型的系统进行漏洞评估。

# 使用 Nessus 进行扫描

使用 Nessus 进行漏洞扫描非常简单。在本节中，我将指导您完成创建自定义扫描的过程。

要创建新的扫描，请使用以下过程：

1.  在右上角，单击新扫描按钮，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/01b05641-c312-4780-ace5-427ba051f846.png)

1.  您可以选择使用其中一个可用的预定义策略。如果要为目标创建自定义扫描，请选择高级扫描策略，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/d4501827-db6d-4afe-bc1b-e8b0e36e4181.png)

1.  策略/扫描向导将打开，为您提供许多选项来自定义新的扫描。在常规选项卡上，确保您输入名称和描述，因为它们将有助于识别此新扫描/策略的目的；一定要包括您的目标：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/a8b353cf-cded-45c8-b632-54d768fcd696.png)

1.  您将有选项来安排扫描/策略应该运行的频率：一次、每天、每周、每月或每年。此功能允许自动运行定期漏洞扫描目标系统。如果决定为扫描创建时间表，可以使用选项设置日期和时间、时区以及重复频率：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/e9d1e526-598e-4059-9728-4667a4b05a66.png)

1.  如果您想接收有关扫描状态的电子邮件通知，只需单击通知选项卡并输入收件人的电子邮件地址。但是，请确保您已配置了 SMTP 服务器设置，该设置将处理电子邮件通知的传递。

1.  要访问 SMTP 服务器设置，请转到`https://localhost:8834/#/settings/smtp-server`。

发现选项卡包含以下选项：

+   +   主机发现：提供了使用 ping 方法（ARP、TCP、UDP 和 ICMP）发现网络上的主机设备的可用选项，发现网络打印机、Novell NetWare 主机和运营技术设备。

+   端口扫描：提供了可自定义的选项，用于扫描一系列端口或单个端口，使用**netstat**工具和**简单网络管理协议**（**SNMP**）对**安全外壳**（**SSH**）、**Windows 管理工具**（**WMI**）进行枚举。对 TCP 和 UDP 端口进行网络扫描和隐蔽扫描。

+   服务发现：允许将每个发现的服务映射到端口号。

评估选项卡包含以下选项：

+   +   **暴力破解**：对 Oracle 数据库进行暴力破解测试，并尝试使用 Hydra 登录网站。

+   **Web 应用程序**：Web 应用程序漏洞测试。

+   **Windows**：尝试枚举域和本地用户帐户。

+   **恶意软件**：扫描恶意软件。

以下截图显示了前一节中概述的选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/0efc3502-4c3c-4384-ab0e-ca8979605f5e.png)

1.  完成自定义策略后，点击保存。新策略/扫描将在“我的扫描”文件夹（左侧面板）中可用。要启动新创建的策略/扫描，点击扫描，然后选择启动。

现在您已经了解了如何使用 Nessus 进行扫描，让我们深入了解 Nessus 在下一节中产生的结果。

# 导出 Nessus 结果

每当扫描完成后，我们可以简单地点击它以访问一个非常好的带有统计数据的仪表板。以 PDF、HTML、CSV 等各种格式导出结果非常简单。导出结果将允许您离线保存报告。这对于渗透测试人员来说非常有益，无论是在以后重新查看漏洞评估细节，还是向相关人员（客户或团队成员）提供报告。

要导出 Nessus 扫描的结果，请按照以下步骤进行：

1.  打开扫描，然后点击导出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/fbce6399-42d4-45f4-b0f4-d066c0feb706.png)

1.  您可以选择输出格式。然后，导出向导将提供另一个选项，生成最终输出作为执行摘要或根据个人偏好定制报告：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/289075d1-1ada-4d68-adb9-745c816fccfa.png)

1.  如果您选择创建自定义报告，以下选项可用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/c0eb3d9a-1d44-44a4-a972-453e8aa2a4d8.png)

执行报告更适合不关心漏洞评估的所有技术细节而更关心报告主要概述的高级管理人员。根据所需和读者的兴趣，可以使用自定义报告来包含或删除特定细节。

以下是在我们实验室的 Metasploitable VM 上进行漏洞扫描生成的执行报告的样本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/b9990e04-4c13-41bb-bb81-5ab899852b75.png)

如您所见，对于在目标上发现的每个漏洞，都会分配一个严重性评级和分数。**通用漏洞评分系统**（**CVSS**）是一个定量的漏洞评分系统，可帮助安全专业人员确定威胁、利用甚至安全弱点的严重性。

有关 CVSS 的更多信息可以在 FIRST 网站上找到[`www.first.org/cvss/`](https://www.first.org/cvss/)。

在本节中，您已经了解了导出 Nessus 结果的各种格式，离线导出报告的好处以及报告类型。在接下来的部分，我们将深入分析 Nessus 提供的输出/结果。

# 分析 Nessus 结果

使用 Nessus 创建和执行漏洞扫描非常容易；然而，在分析阶段最需要的是网络安全专业人员的思维方式。Nessus 使结果的分析变得容易。扫描完成后，您可以通过选择漏洞选项卡查看发现的漏洞列表，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/c7506863-7e0e-4645-9721-d8fe1e923d78.png)

现在，我们能够看到在目标上发现的漏洞列表。Nessus 为我们提供了严重性评级、漏洞名称和发现数量：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/764420b9-1569-4b13-9643-d2eb66c381cb.png)

要获取有关漏洞的更多详细信息，请单击特定漏洞，例如在前面的截图中突出显示的漏洞。Nessus 将为您提供所选漏洞的详细描述、风险信息、插件详细信息、补救措施和外部参考，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/123f1914-d3f3-4c6f-b040-f50d8e989031.png)

使用这些信息，渗透测试人员可以快速识别目标上的最薄弱点，并在选择有效载荷以利用目标时缩小范围。

现在您对 Nessus 及其功能有了牢固的理解。在下一节中，我们将使用各种 Web 应用程序扫描器来帮助我们检测目标服务器上的 Web 漏洞。

# 使用 Web 应用程序扫描器

Web 应用程序扫描器主要专注于检测和识别 Web 服务器、网站和 Web 应用程序上的漏洞。在您的网络安全职业生涯中，无论是作为渗透测试人员还是安全从业者，您可能会被要求对目标网站或 Web 服务器执行某种安全审计。

然而，作为一名渗透测试人员，我们需要能够发现目标网站和 Web 服务器上的安全配置错误和弱点。一个组织可能会与您签订合同，要求您对他们的网站进行渗透测试，而不是对他们的网络，甚至两者都要。请记住，对网站等对象进行渗透测试的目标是尽快识别漏洞并进行补救，以防止实际黑客能够 compromise 系统并窃取数据。

市场上有许多 Web 应用程序扫描器，从商业到免费和开源；以下是其中一些：

+   Acunetix 漏洞扫描器（商业）

+   w3af（免费）

+   Nikto（免费）

+   Burp Suite（商业和免费）

+   IBM AppScan（商业）

在本章的其余部分，我们将使用 Nikto、WPScan 和 Burp Suite 进行各种练习，以便在目标 Web 服务器上检测和识别安全漏洞。

让我们在下一节深入了解 Nikto。

# Nikto

Nikto 是一个流行的开源 Web 漏洞扫描器，并且预装在 Kali Linux 中。这个命令行工具能够识别目标网站上的安全漏洞，并为每个发现的问题提供详细的参考。Nikto 不是一个隐秘导向的工具，在执行扫描时可能会有些嘈杂。

它的一些特点如下：

+   检查 Web 服务器上是否有任何过时的组件

+   能够通过目标上的标头和文件识别已安装的应用程序

+   SSL 支持

+   执行子域猜测

+   Apache 用户名枚举

要开始使用 Nikto，在我们的 Metasploitable VM 上执行 Web 漏洞扫描。如果您还记得，在上一章中，我们对 Metasploitable 执行了端口扫描，并看到端口 `80` 是开放的。默认情况下，Web 服务器打开端口 `80`，以允许客户端和 Web 服务器之间的入站和出站通信。

使用 `nikto -h <target>` 语法在新的终端窗口中打开一个新的终端窗口，其中 `-h` 指定主机（主机名或 IP 地址）。我们使用 `nikto -h 10.10.10.100` 命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/024cb038-8c09-4d03-9861-e0e2667a56ed.png)

如果您提供主机名，Nikto 将能够通过**域名系统**（**DNS**）执行 IP 查找。在初始阶段，Nikto 试图执行操作系统和服务版本指纹识别；我们的目标使用 Ubuntu 作为其操作系统，Apache 2.2.8 作为 Web 服务器应用程序。

**Nikto** 可以在 Kali Linux 的应用程序 | 02 – 漏洞分析选项卡下找到。

输出中的每个点都是 Nikto 检测到的问题的指示，无论是缺少配置，找到对敏感目录或文件的访问，还是应用程序版本过时。对于找到的每个安全问题，都会关联一个**开放源漏洞数据库**（**OSVDB**）参考 ID。OSVBD 是一个独立的开源数据库，包含有关 Web 应用程序安全漏洞的信息。一旦 Nikto 能够在目标上识别出安全漏洞，它就会提供一个相关的 OSVDB 参考 ID。一旦获得了 OSVDB ID，您可以转到[`cve.mitre.org/data/refs/refmap/source-OSVDB.html`](http://cve.mitre.org/data/refs/refmap/source-OSVDB.html)来参考 OSVDB ID 与 CVE 条目。

有关 Nikto 的更多信息，请访问[`cirt.net/Nikto2`](https://cirt.net/Nikto2)和[`github.com/sullo/nikto`](https://github.com/sullo/nikto)。

现在您已经掌握了使用 Nikto 的基本技能，让我们在下一节中看看如何使用 WPScan。

# WPScan

为公司创建网站涉及大量的编程和工作。有许多**内容管理系统**（**CMSes**）可以让您轻松创建、管理和发布网站。想象一下，必须为网站的多个页面或多个网站静态编码 Web 语言；这将是一项艰巨的任务，需要对 Web 语言有很好的了解。CMS 允许 Web 管理员轻松地管理和更新网站的内容，同时能够集成额外的第三方 Web 插件，为用户提供更多功能。

有许多 CMS 可用；以下是其中一些：

+   WordPress

+   Joomla

+   Drupal

+   Plone

在互联网上，目前最流行的 CMS 之一是 WordPress。无论您是博主、自由职业者、初创公司还是大型组织，许多人都将 WordPress 作为首选 CMS。WordPress 是一个基于 MySQL 和 PHP 的开源 CMS。由于 WordPress 在互联网上非常流行，我们将使用 Kali Linux 中的**WPScan**工具来扫描 WordPress Web 服务器的 Web 漏洞。

首先，您需要在虚拟实验室环境中安装 WordPress 服务器。要做到这一点，请按照以下步骤：

1.  转到[`www.turnkeylinux.org/wordpress`](https://www.turnkeylinux.org/wordpress)并下载 ISO 映像或 VM 文件（使用虚拟机文件更容易设置 VM）。

1.  安装在 hypervisor 中后，确保网络配置已启用，与您的 Kali Linux 机器处于相同的网络中。

1.  打开 WordPress VM。它将从 hypervisor 中的**动态主机配置协议**（**DHCP**）服务自动接收 IP 地址。

1.  使用您的 Kali Linux 机器，执行网络和端口扫描以识别 WordPress 服务器 IP 地址。

1.  在 Kali Linux 网络浏览器中输入 IP 地址，您应该会看到 WordPress 默认网页。

1.  使用`http://<ip address>/wp-login.php` URL 将显示管理员登录页面，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/5e7602b3-6b19-4260-b895-6e09d532d20f.png)

这是 WordPress 服务器的默认登录页面。

可选地，WPScan 工具可以在 Kali Linux 菜单的应用程序| 03 - Web 应用程序分析| CMS 和框架识别选项卡下找到。

在您的 Kali Linux 机器上，我们将使用`wpscan --url <target IP or hostname>`命令对 WordPress Web 服务器执行漏洞扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/44bdc057-e991-4940-bd3c-6e36c70f55c5.png)

WPScan 将提供服务器平台；在我们的案例中，它是 Apache。

接下来，它将尝试发现并列出所有已知的漏洞，并为每个漏洞提供修复和参考，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/7855b5f3-2c95-4704-8dc1-aecc728251d2.png)

WPScan 不仅是 WordPress 的漏洞扫描器，还具有执行用户账户枚举的能力。让我们尝试在我们的 WordPress 服务器上提取用户账户；使用`wpscan --url 10.10.10.100 -e u vp`命令执行用户枚举：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/0f41445e-763d-4692-914c-894b97f9dd18.png)

在我们的结果中，发现了`admin`用户。接下来，我们可以尝试使用暴力破解技术对`admin`账户进行密码破解。

要创建用于密码破解的自定义单词列表，您可以使用 Kali Linux 中的**crunch**工具。此外，您还可以从互联网上下载单词列表。一个很好的来源是[`github.com/danielmiessler/SecLists`](https://github.com/danielmiessler/SecLists)。

使用 WPScan 和离线单词列表（我们的称为`custom_list.txt`）执行密码破解，我们使用`wpscan --url 10.10.10.100 -e u --passwords custom_list.txt`命令。

在下面的片段中，我们能够破解用户账户的密码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/e4a68ffe-793e-4bfa-8410-a2a312030523.png)

作为渗透测试人员已经获得了用户名和密码，该账户已被破解。现在我们可以登录到 WordPress 服务器的控制面板，执行各种恶意操作。

密码破解可能是一个非常耗时的过程，可能需要几分钟或几个小时才能完成。

完成了这一部分后，您已经掌握了使用 WPScan 对 WordPress 服务器进行漏洞评估的技能。在下一部分中，我们将学习另一个 Web 漏洞评估工具 Burp Suite。

# Burp Suite

Burp Suite（[`portswigger.net/burp`](https://portswigger.net/burp)）是一个**图形用户界面**（**GUI**）Web 应用程序漏洞扫描器，具有识别 100 多种通用漏洞的能力，例如 OWASP 十大关键 Web 应用程序安全风险中发现的所有漏洞。

OWASP 十大漏洞列表可以在[`www.owasp.org/index.php/Category:OWASP_Top_Ten_2017_Project`](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_2017_Project)找到。

Burp Suite 应用程序允许渗透测试人员拦截 Web 服务器（Web 应用程序）和浏览器之间的所有 HTTP 和 HTTPS 请求和响应，通过其 HTTP 代理组件。通过拦截 Web 流量，Burp Suite 可以测试各种类型的漏洞和攻击，如模糊测试、暴力破解密码攻击、解码、通过蜘蛛获取隐藏的 URL 等。

在开始使用 Burp Suite 之前，请确保您的 OWASP **Broken Web Applications** (**BWA**)虚拟机（受害者机器）在线并已获得 IP 地址。

一旦 OWASP BWA VM 在线，您应该看到以下屏幕；但是，您的 IP 地址详细信息可能与所示的不同：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/9403a26f-82d1-4260-8803-b436ab1989fc.png)

在您的 Kali Linux 机器上，通过对 OWASP BWA 虚拟机进行 ping 测试，确保端到端的连接。一旦您验证了连接，就可以打开 Burp Suite 应用程序了。

要完成此任务，请使用以下说明：

1.  转到应用程序 | 03 – Web Application Analysis | Web Application Proxies | Burp Suite。

1.  现在应用程序已经打开，向导将询问您是否要创建临时项目、在磁盘上创建新项目或打开现有项目。

1.  选择临时项目并单击“下一步”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/6a2b5a49-a6e2-49be-9934-9c62ec217318.png)

1.  下一个窗口将询问 Burp Suite 是否应该使用默认设置或从文件加载配置。选择使用 Burp 默认选项，并单击“启动 Burp”以启动用户仪表板：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/cf70a015-1a2e-4bff-9032-b9e56e6a287c.png)

Web 浏览器和目标 Web 服务器之间发送的流量不会被 Burp Suite 监视或拦截。Burp Suite 包含一个 HTTP 代理，允许应用程序在 Web 浏览器和目标 Web 服务器之间拦截 HTTP 流量。Web 浏览器不直接与 Web 服务器交互；流量从 Web 浏览器发送到 Burp Suite HTTP 代理，然后 HTTP 代理将流量转发到目标 Web 服务器，反之亦然。以下是显示 Web 浏览器和 Web 服务器之间流量流动的图表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/3847ad67-9b44-4801-b88e-24cb6c6837fe.png)

Burp Suite 作为一个拦截代理应用程序。默认情况下，Burp Suite 无法拦截我们的 Kali Linux 机器和 OWASP BWA 虚拟机之间的任何流量。要配置我们的网络浏览器与 Burp Suite 一起工作，请使用以下说明：

1.  打开 Firefox，点击菜单图标|首选项（选项）。

1.  在默认选项卡上，向下滚动直到看到网络代理设置（网络设置），然后点击“设置”。

1.  选择手动代理配置，并使用下一个截图中显示的配置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/03c0f462-1a21-48cb-8d59-51ca68a87b87.png)

确保“不使用代理”字段为空。

1.  点击“确定”以保存 Firefox 中的设置。

现在我们已经配置了我们的网络浏览器与 Burp Suite HTTP 代理服务一起工作，让我们回到 Burp Suite 应用程序，以允许拦截流量。为此，请按照以下步骤操作：

1.  点击代理|拦截，并点击拦截打开图标以切换启用/禁用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/c4764ba2-2bf4-42e6-8366-067609b9e4e9.png)

确保您的配置设置正确，否则练习将无法按预期进行。

如果拦截图标显示为打开状态，则 Burp Suite 能够拦截 Web 浏览器和 Web 服务器之间的流量。此外，请确保转发请求；否则，它们将留在拦截器中不会被转发，最终请求将超时。

1.  接下来，在您的 Kali Linux 机器上的 Firefox 地址栏中输入 OWASP BWA 虚拟机的 IP 地址。默认网页应该完美加载。在 Burp Suite 中，点击目标|站点地图以查看 HTTP 请求和响应：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/736a5bde-14b8-4b2d-b56c-e74c676dc7e0.png)

1.  在网络浏览器中，输入 OWASP BWA 虚拟机的 URL（或 IP 地址）。 HTTP 请求和响应将显示在 Burp Suite 的目标|站点地图选项卡上。

现在我们已经概述了如何使用 Burp Suite 拦截 Web 流量，让我们进一步进行攻击我们的 Metasploitable 机器。在下一节中，我们将使用 Burp Suite 执行暴力破解攻击。

# 使用入侵者进行暴力破解

Burp Suite 中的入侵者组件/模块允许渗透测试人员使用暴力破解方法执行在线密码攻击。让我们尝试获取登录到`http://<target ip addr>/mutillidae` URL 的密码：

1.  使用 Firefox 网络浏览器点击 Mutillidae II。在 Burp Suite 中，您应该在站点地图选项卡的左窗格下看到`mutillidae`文件夹出现。

1.  接下来，右键单击`mutillidae`文件夹，并选择如下截图所示的添加到范围。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/e2dbfa59-b1db-44e6-a420-6c3836564f61.png)

1.  以下代理历史记录窗口将出现；只需点击“是”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/f165eed0-2ab3-4771-ae0f-ddf66c92f9bf.png)

1.  要验证我们的范围是否已成功添加，请转到目标|范围选项卡：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/17d87000-4f8f-4137-b053-4c480b58ef6b.png)

1.  现在您的范围已添加，请返回到您的网络浏览器。在 Mutillidae 网页的顶部，您将看到一个链接，允许用户进行登录尝试。使用`admin`作为用户名，`password`作为密码。登录尝试应该失败；但是，我们需要 Burp Suite 捕获有关网页上登录字段的特定细节。

让我们回到 Burp Suite 继续我们的练习。

1.  在 Burp Suite 上，单击代理|HTTP 历史选项卡，然后选择 HTTP **POST**消息，其中包含来自我们浏览器的登录尝试（您的`#`消息可能与以下片段中显示的内容不同）。选择后，右键单击并选择发送到入侵者：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/23946f1b-1912-4561-98a7-b7229c9c005d.png)

1.  接下来，点击入侵者|目标选项卡，查看已设置的目标 IP 地址：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/cf9e8bf2-7bfe-42d6-ae39-fde58aed0f26.png)

在入侵者选项卡中，有一些子选项卡，包括以下内容：

+   +   目标：允许您设置特定的目标和端口号。

+   位置：允许您选择负载将被插入到 HTTP 请求的位置。

+   有效负载：提供配置有效负载类型的能力。

+   选项：可以在此选项卡上设置其他选项。

1.  选择位置选项卡，然后单击清除按钮以清除所有选择。默认情况下，Burp Suite 已选择 HTTP 请求消息的某些区域以插入其有效负载。但是，对于我们的练习，有效负载应插入到密码字段中。

1.  突出显示单词“密码”，然后单击添加。这将允许 Burp Suite 在所选字段上插入其有效负载：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/f282e168-49c6-4ae2-b4ed-e0c9f449c64e.png)

红色文本是从浏览器发送到 Web 服务器的数据。正如您所看到的，单词“密码”是我们在登录尝试中使用的值。

1.  单击有效负载选项卡。在文本字段中输入`admin`，然后单击添加；这将是我们的自定义有效负载：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/bc6bbd45-7c9b-40dc-a217-61378a647bcc.png)

确保在有效负载和选项选项卡的其余部分中保持默认设置。

1.  当您准备好启动有效负载时，请单击开始攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/66ea3971-6dd5-46e1-afd5-d180966f55e1.png)

攻击完成后，入侵者将打开一个新窗口以提供摘要。在结果选项卡上，注意我们有一个带有 302 状态代码的 HTTP 请求消息；这意味着发生了 HTTP 重定向。换句话说，入侵者成功登录到了 Mutillidae。详细信息可以在以下截图中看到，其中包括`用户名`和`密码`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/50073b97-1646-4ee5-ad04-3644a5253edf.png)

选择具有**302**状态代码的 HTTP 请求消息，您可以在请求选项卡上看到从 Web 浏览器发送的“用户名”和“密码”。

1.  要查看来自 Web 服务器的响应，请单击响应|渲染选项卡。在这里，您将能够看到 Web 应用程序对有效负载的响应：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/02be4c19-8d9f-4fce-adb7-6abd14412ef1.png)

仔细观察，您会看到`admin`用户帐户已成功登录。请注意，前面截图中显示的用户帐户是有意易受攻击的 Metasploitable 虚拟机的默认管理帐户。此外，请不要在未获得合法许可的设备或网络上尝试任何形式的攻击。此练习是在实验室环境中进行的。

*Sunny Wear*的*Burp Suite Cookbook*包含了执行基于 Web 的评估的许多配方。此标题可在[`www.packtpub.com/networking-and-servers/burp-suite-cookbook`](https://www.packtpub.com/networking-and-servers/burp-suite-cookbook)找到。

正如您所看到的，Burp Suite 是进行 Web 渗透测试和漏洞评估的非常强大的应用程序。每当您被要求对 Web 服务器和网站进行安全审计时，这个工具肯定应该是您的工具清单的一部分。

# 摘要

在本章中，我们讨论了发现系统甚至 Web 服务器上的安全漏洞的必要性。我们研究了使用 Nessus 执行漏洞扫描、自定义策略和报告。此外，我们了解了 Nikto，一个开源的 Web 漏洞扫描程序，以及使用 WPScan 来检测 WordPress 中的安全配置错误和缺陷。最后，我们通过介绍了使用 Burp Suite 应用程序的基础知识，并尝试使用暴力破解来进入网站，结束了本章。

完成本章后，您现在可以成功地对目标网络和系统使用 Nessus 执行漏洞评估，并使用 Burp Suite、Nikto 和 WPScan 执行网站渗透测试。

我希望本章内容对您有所帮助，并在您的网络安全领域之旅中有所帮助。在下一章中，我们将探讨无线渗透测试的基本概念。

# 问题

以下是一些基于本章内容的问题：

1.  在 Kali Linux 中安装 Nessus 后，使用什么命令来启用 Nessus 服务？

1.  许多金融机构为其客户提供卡支付功能。为了确保机构符合行业标准，应该使用什么框架？

1.  Nessus 可以导出哪些类型的报告？

1.  您能否说出 Kali Linux 中预安装的两三个 Web 漏洞扫描程序？

1.  可以用什么工具来扫描 WordPress 网站的安全漏洞？

# 进一步阅读

+   有关 Nessus 的更多信息，请访问[`www.tenable.com/products/nessus/nessus-professional.`](https://www.tenable.com/products/nessus/nessus-professional)

+   PCI DSS 的更多信息可以在安全标准理事会网站上找到[`www.pcisecuritystandards.org/`](https://www.pcisecuritystandards.org/)。


# 第八章：了解网络渗透测试

在网络渗透测试的准备阶段，了解对目标系统和/或网络基础设施进行安全测试的目标至关重要。在发起任何攻击模拟之前，通过欺骗您设备的 MAC 地址并配置无线网络适配器来监视和捕获 IEEE 802.11 无线网络上的无线流量，成为网络上的匿名用户（或假装成合法用户）非常重要。

网络渗透测试侧重于进入网络并对目标组织的内部网络中的网络安全设备、设备和系统进行安全审计（渗透测试）。在本章中，您将了解 Kali Linux 上可以配置的各种模式，如何欺骗 MAC 地址以及如何在无线网络上捕获数据包。

在本章中，我们将涵盖以下主题：

+   网络渗透测试简介

+   了解 MAC 地址

+   将无线适配器连接到 Kali Linux

+   管理和监控无线模式

# 技术要求

以下是本章的技术要求：

+   Kali Linux ([`www.kali.org/`](https://www.kali.org/))

+   VMware Workstation 或 Oracle VM VirtualBox

+   支持数据包注入的无线网络接口卡（NIC）

并非所有无线网卡都支持监视模式和数据包注入。但是，芯片组的微小修订可能导致卡无法在监视模式下工作，有些卡可能需要编译驱动程序，可能无法直接使用。

以下是 Kali Linux 支持的外部无线 NIC 的列表：

+   Atheros：ATH9KHTC（AR9271，AR7010）

+   雷凌：RT3070

+   Realtek：RTL8192CU

+   TP-Link TL-WN722N

+   TP-Link TL-WN822N v1 - v3

+   Alfa Networks AWUS036NEH

+   Alfa Networks AWUS036NHA

+   Alfa Networks AWUSO36NH

我个人建议使用 Alfa Networks AWUS036NHA 卡。

# 网络渗透测试简介

网络渗透测试的目标是发现目标网络基础设施上的任何安全漏洞。这种类型的渗透测试可以从组织外部（外部测试）或从内部（内部测试）进行。作为一名渗透测试人员，我绝对建议在目标网络上进行内部和外部安全测试。

以下是网络渗透测试的一些目标：

+   绕过外围防火墙

+   规避入侵检测系统/预防系统（IDS/IPS）

+   测试路由和交换错误配置

+   检测不必要的开放网络端口和服务

+   查找敏感目录和信息

进行网络渗透测试有助于 IT 专业人员关闭不必要的网络端口，禁用服务，解决问题，并更好地配置安全设备以减轻威胁。

在外部网络渗透测试期间，渗透测试人员试图通过攻破防火墙和任何 IDS/IPS 来访问目标组织的网络。然而，内部网络渗透测试涉及从组织内部网络进行安全测试，该网络已经位于外围防火墙设备之后。

以下是网络渗透测试过程中需要遵循的六个步骤：

1.  信息收集

1.  端口扫描

1.  操作系统和服务指纹识别

1.  漏洞研究

1.  利用验证

1.  报告

在接下来的部分，我们将简要介绍渗透测试的不同方法。

# 渗透测试类型

以下是渗透测试人员通常进行的三种安全测试类型：

+   **白盒测试**：白盒测试涉及在进行网络渗透测试之前对网络和系统拥有完整的知识，包括网络图、IP 地址方案和其他信息。这种类型的测试比灰盒和黑盒测试要容易得多，因为渗透测试人员不需要对目标网络和系统进行任何信息收集。

+   **灰盒测试**：在灰盒测试中，渗透测试人员在进行网络渗透测试之前对组织的网络基础设施和系统有限的了解。

+   **黑盒测试**：在黑盒测试中，渗透测试人员对目标组织或其网络和系统信息没有任何先验知识。关于目标提供的信息通常只是组织的名称。

现在我们已经完成了这个网络渗透测试入门部分，让我们深入了解 MAC 地址的基本知识。

# 了解 MAC 地址

在网络领域中，网络专业人员在故障排除过程中经常提到两种模型。这些模型被称为**开放系统互连**（**OSI**）参考模型和**传输控制协议/互联网协议**（**TCP/IP**）堆栈。

以下表格概述了每个模型的层次，并显示了 OSI 模型、**协议数据单元**（**PDU**）和 TCP/IP 协议套件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/d1793b6a-4bc2-4fdf-ad81-d1b212fbceee.png)

通常，术语**数据包**和**帧**会被交替使用，但它们之间是有区别的。让我们更加关注帧的特性和构成。

在本节中，我们将重点关注 OSI 模型的数据链路层（第 2 层）。数据链路层负责在设备上的软件应用程序和网络的物理层之间传输数据。这是由网卡完成的。此外，在数据放置在物理层之前，数据层将网卡的物理地址，即**媒体访问控制**（**MAC**）地址，插入到帧中。这个地址有时被称为**固定地址**（**BIA**）。

设备的 MAC 地址长度为 48 位，以十六进制格式编写；因此，每个字符的范围在 0-9 和 A-F 之间。前 24 位被称为**组织唯一标识符**（**OUI**），由**电气和电子工程师协会**（**IEEE**）分配给供应商和制造商。通过了解任何有效 MAC 地址的前 24 位，您可以确定网卡和/或设备的供应商/制造商。最后的 24 位是唯一的，并由供应商分配，从而为每个设备创建一个唯一的 MAC 地址。

以下是 MAC 地址的分解：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/830d2dae-d13a-4824-ab1b-665ddea26bc5.png)

要在 Windows 上查看 MAC 地址，请使用`ipconfig /all`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/e1f4db91-6c2d-445e-8016-6866c724f316.png)

然而，在基于 Linux 的操作系统上，您需要使用`ifconfig`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/2a78f60b-4e5b-429d-8c30-c7969904d9ba.png)

现在我们对设备和网络上 MAC 地址的目的有了更好的了解。现在，让我们深入学习如何在 Kali Linux 中更改（欺骗）我们的 MAC 地址。

# 如何欺骗 MAC 地址

**欺骗**是网络上的一种冒充形式；它隐藏了您作为渗透测试人员的身份。离开您的 Kali Linux 机器的所有流量将包含源的新配置的 MAC 地址。

在这个练习中，我们将改变 Kali Linux 机器上 LAN 接口的 MAC 地址。按照以下简单的步骤来做：

1.  使用以下命令关闭网络接口：

```
ifconfig eth0 down
```

1.  一旦接口关闭，我们可以使用`macchanger`工具在接口上修改我们的 MAC 地址。`macchanger`工具允许您自定义您的新（伪造的）地址。要查看所有可用选项，请使用`macchanger --help`命令。

1.  要更改我们以太网（网络）接口的 MAC 地址，我们将使用`macchanger --random eth0`命令，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/59eca6ef-05c0-4630-bd0f-312998035508.png)

1.  一旦成功更改了 MAC 地址，就可以使用以下命令打开以太网接口：

```
ifconfig eth0 up
```

1.  最后，我们现在可以使用`ifconfig`命令来验证新的 MAC 地址是否在接口上注册，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/434bdeba-5deb-4b21-8198-9bdee471b60f.png)

完成了这个练习后，您现在可以在 Kali Linux 的每个网络接口上伪造 MAC 地址。在下一节中，我们将学习如何将无线适配器连接到 Kali Linux 机器。

# 将无线适配器连接到 Kali Linux

在无线网络渗透测试期间，您将需要将外部无线网卡连接到 Kali Linux 机器上。如果您直接在磁盘驱动器上安装了 Kali Linux，则只需通过 USB 连接即可连接无线网卡。适配器将自动出现在网络设置中。

然而，在使用虚拟机时可能会有些棘手。在本节中，我将演示如何将无线网络适配器连接到**VMware Workstation**和**Oracle VM VirtualBox**。

如果您使用的是 VMware Workstation，请按照以下步骤操作：

1.  首先，选择 Kali Linux 虚拟机，然后点击编辑虚拟机设置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/f6c1bea1-3d90-476d-8199-64f9994cdf04.png)

1.  然后，虚拟机设置将打开，为您提供一些选项来添加、删除和修改模拟的硬件资源。选择**USB 控制器**；选项将出现在窗口的右侧。根据计算机上的物理 USB 控制器选择适当的 USB 版本，并确保**显示所有 USB 输入设备**的复选框中有一个勾选：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/7d0d5833-8872-4ff4-a65f-b00c975af90e.png)

1.  完成后，点击**确定**保存设置。启动 Kali Linux 虚拟机，并将无线适配器插入计算机上的可用 USB 端口。

在 VMware Workstation 的右下角，您会看到一些图标。这些图标代表物理硬件组件或设备。变暗的图标表示硬件或设备未连接到虚拟机，而明亮的图标表示组件或设备已连接。

1.  点击下面屏幕截图中突出显示的 USB 图标。将会出现一个菜单，提供从主机机器连接到虚拟机的 USB 设备的选项。选择无线适配器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/6074d91e-b060-4ffe-8ae2-0211cb1dbc6d.png)

1.  一旦 USB 无线适配器成功连接，图标应该会亮起。现在，是时候验证 Kali Linux 是否能够看到无线适配器了。打开终端并执行`ifconfig`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/b981e52f-c4ec-4506-abe5-2f40b98cd540.png)

所有无线适配器都表示为`wlan`，后面跟着一个数字。我们的无线适配器是`wlan0`。

对于那些使用**Oracle VM VirtualBox**的人来说，这个过程与之前提到的 VMware 有些相似。使用以下步骤来完成通过 hypervisor 将无线适配器连接到 Kali Linux 的练习：

1.  要开始，请在仪表板中选择 Kali Linux 虚拟机，然后点击**设置**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/d1de9fe5-196a-462f-8c8a-f09b001602d4.png)

1.  一旦打开了设置菜单，请在左侧列中选择**USB**类别。确保无线适配器插入计算机的 USB 端口，并且与我们在 VMware Workstation 中所做的类似，选择**USB 2.0（EHCI）控制器**版本。

1.  接下来，点击旁边带有+符号的**USB**图标，将 USB 设备连接到虚拟机。选择 USB 无线适配器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/0a88858e-30e1-4213-a7b2-0fb376b51fe9.png)

无线适配器将被插入**USB 设备过滤器**字段中，如下截屏所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/1a93b8b9-2ddc-41d9-b8f7-8f6beb1f8b6b.png)

1.  点击**OK**保存虚拟机的设置。启动 Kali Linux 虚拟机，并使用`ifconfig`命令验证无线适配器的状态。

完成本节后，您将具备成功连接无线适配器到 Kali Linux 虚拟机所需的技能。在下一节中，我们将看看如何在 Kali Linux 中管理和监控无线模式。

# 管理和监控无线模式

Linux 操作系统允许用户手动配置无线适配器的操作模式。

以下是不同模式和它们的解释：

+   **Ad hoc**模式用于连接多个终端设备，如笔记本电脑，而无需使用无线路由器或接入点。

+   默认的操作模式是**managed**。这种模式允许设备（即主机）连接到无线路由器和接入点。但是，有时您可能需要对组织的 Wi-Fi 网络进行无线渗透测试。在 managed 模式下的无线适配器不适合这样的任务。

+   **Master**模式允许 Linux 设备作为访问点运行，以允许其他设备同步数据。

+   **Repeater**模式允许节点设备将数据包转发到网络上的其他节点；中继通常用于扩展无线信号的范围。

+   **Secondary**模式允许设备作为主设备或中继的备份。

+   **Monitor**模式允许设备在 IEEE 802.11 的频率上传递监控数据包和帧。这种模式不仅允许渗透测试人员监视流量，还可以使用兼容的无线适配器进行**数据包注入**来捕获数据。

操作模式取决于网络拓扑和 Linux 操作系统在网络中的角色。

有两种方法可以用来配置无线适配器为监控模式：手动和使用`airmon-ng`工具。

在接下来的部分，我们将看看如何做以下事情：

+   手动启用监控模式

+   使用 airmon-ng 启用监控模式

让我们更详细地看看这些方法。

# 手动启用监控模式

在本节中，我将指导您逐步手动启用 Kali Linux 机器上无线网卡的监控模式所需的步骤。

以下说明将指导您在 Kali Linux 机器上手动启用监控模式的过程。

要开始，请打开一个新的终端窗口并执行以下命令：

1.  执行`ifconfig`命令以确定无线适配器是否连接并被 Kali Linux 操作系统识别。此外，注意接口 ID。在下面的截图中，接口是`wlan0`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/472ec4e0-1656-4a7b-87b4-789ec06d2bba.png)

1.  现在我们有了接口 ID，使用`ifconfig wlan0 down`通过操作系统逻辑地关闭接口。在更改任何接口的模式之前，这是必要的。

1.  现在接口已关闭，是时候为我们的`wlan0`接口配置监控模式了。`iwconfig wlan0 mode monitor`命令将启用监控模式。完成后，我们需要验证接口上的模式是否已成功更改。执行`iwconfig`命令。您应该看到模式已更改为`Monitor`，如下截屏所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/a841801b-ee08-4009-b089-c780c012f591.png)

1.  最后，我们需要使用`ifconfig wlan0 up`命令将我们的`wlan0`接口启动起来。

通过完成此练习，您已经掌握了在 Kali Linux 中启用监控模式所需的技能。在下一节中，我们将看看如何使用 airmon-ng 来配置无线适配器。

# 使用 airmon-ng 启用监控模式

airmon-ng 是 aircrack-ng 套件中用于无线安全审计的工具之一。airmon-ng 是一个用于配置无线适配器为（和退出）监控模式的工具。

让我们看看如何启用和禁用监控模式：

1.  要开始，请打开一个新的终端窗口，并执行`ifconfig`或`iwconfig`命令来验证无线适配器的状态和 ID：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/19295055-7c6b-46b3-b8e8-337cdb555817.png)

1.  在启用监控模式之前，我们需要终止可能阻止适配器转换为监控模式的任何后台进程。通过使用`airmon-ng check kill`命令，工具将检查可能阻止适配器转换为监控模式的任何进程并将其终止：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/e2504050-4fe0-4549-928a-d67a41f15259.png)

1.  接下来，执行`airmon-ng start wlan0`以启用监控模式。此外，将创建一个新的逻辑接口，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/b9ef30b9-f922-45c7-8cbc-e010e1d97d2f.png)

1.  `wlan0mon`接口将用于监视 IEEE 802.11 网络。要禁用监控模式，只需使用`airmon-ng stop wlan0mon`命令。

通过完成此练习，您现在可以使用手动方法和 airmon-ng 工具在无线适配器上启用监控。

# 总结

在本章中，我们讨论了网络渗透测试的基本概念及其重要性。我们提供了关于将无线适配器连接到我们的 Kali Linux 机器的实用信息，讨论了 MAC 地址及其构成的目的，并讨论了如何通过修改来伪装我们的身份。此外，我们还看了如何通过手动配置和使用 airmon-ng 工具将无线适配器的默认模式更改为监控模式。

现在您已经完成了本章，您知道如何使用`airmon-ng`工具和通过 Kali Linux 操作系统手动启用监控模式。此外，您现在可以对无线网络进行监控。

希望本章内容能够为您提供信息，并在网络安全领域的旅程中为您提供帮助和指导。在下一章第九章中，“网络渗透测试-连接前攻击”，我们将深入研究网络渗透测试，并进行一些实际操作。

# 问题

以下是基于本章内容的一些问题：

1.  在 Kali Linux 中可以使用什么工具来更改 MAC 地址？

1.  您能否列举无线适配器可以配置为操作的不同模式？

1.  如何查看网络接口的 MAC 地址？

1.  如何终止可能阻止适配器转换为监控模式的任何后台进程？

# 进一步阅读

+   有关 OSI 模型和 TCP/IP 堆栈的更多详细信息，请参阅*CompTIA Network+ Certification Guide* [`www.packtpub.com/networking-and-servers/comptia-network-certification-guide`](https://www.packtpub.com/networking-and-servers/comptia-network-certification-guide)。

+   有关 aircrack-ng 和 airmon-ng 的更多信息，请参阅[`www.aircrack-ng.org/documentation.html`](https://www.aircrack-ng.org/documentation.html)。


# 第九章：网络渗透测试 - 连接前攻击

许多组织都有无线网络。想象一下获得对企业无线网络的访问权限，然后利用无线作为进入有线网络并破坏其他系统和设备的媒介或通道。了解无线渗透测试是至关重要的，以便能够识别可能导致此类安全漏洞的漏洞。这些技能将帮助您作为渗透测试人员，因为您将需要在目标网络上执行无线安全测试。

在本章中，我们将深入研究诸如 aircrack-ng 之类的无线黑客工具。此外，我们将介绍了解各种无线攻击工作的基本知识。这些攻击包括取消与无线访问点关联的用户、创建虚假访问点和执行密码破解。

在本章中，我们将涵盖以下主题：

+   使用 airodump-ng 开始数据包嗅探

+   使用 airodump-ng 进行有针对性的数据包嗅探

+   在无线网络上取消客户端的认证

+   创建一个伪装 AP/恶意双胞胎

+   执行密码喷洒攻击

+   设置诱饵攻击

+   利用弱加密进行凭证窃取

# 技术要求

以下是本章的技术要求：

+   **Kali Linux**：[`www.kali.org/`](https://www.kali.org/)

+   **Airgeddon**：[`github.com/v1s1t0r1sh3r3/airgeddon`](https://github.com/v1s1t0r1sh3r3/airgeddon)

+   **WordPress 服务器**：[`www.turnkeylinux.org/wordpress`](https://www.turnkeylinux.org/wordpress)

+   **Bee-Box**：[`sourceforge.net/projects/bwapp/files/bee-box/`](https://sourceforge.net/projects/bwapp/files/bee-box/)

# 使用 airodump-ng 开始数据包嗅探

要开始数据包嗅探，我们将使用`airodump-ng`工具。 `airodump-ng`具有许多功能，包括执行 IEEE 802.11 帧的原始捕获。此外，使用此工具，我们将能够查看无线 AP、关联和未关联的客户端设备（站点）、加密类型、SSID、AP 的制造商等。

在第八章中，*了解网络渗透测试*，我们概述了将无线网络适配器连接到 Kali Linux 机器并启用监视模式所涉及的程序。对于这个练习，您需要再次重复这个过程。

要启用监视模式，请执行以下步骤：

1.  将无线适配器连接到 Kali Linux。使用`ifconfig`命令验证适配器的状态。

1.  通过使用`airmon-ng check kill`命令终止可能妨碍启用监视模式的任何进程。

1.  使用`airmon-ng start wlan0`命令在无线适配器上启用监视模式。

现在您的无线适配器处于监视模式，让我们使用`airodump-ng`工具查看所有附近 AP 和站点的列表。要执行此操作，请使用以下命令：

```
airodump-ng wlan0mon
```

您的终端窗口现在将开始显示所有附近的 AP，显示以下信息：

+   `BSSID`：这是 AP 或无线路由器的 MAC 地址。

+   `PWR`：这是功率评级。功率评级越低，AP 距离无线适配器越远。

+   `Beacons`：信标是从 AP 发送的广告。信标通常包含有关 AP 的信息，例如网络名称和操作。

+   `#Data`：这是每个网络捕获的数据包数量。

+   `#/s`：此字段表示在 10 秒内每秒的数据包数量。

+   `CH`：这是 AP 的操作频道。

+   `MB`：此字段概述了 AP 支持的最大速度。

+   `ENC`：这确定了无线网络上使用的加密密码。

+   `AUTH`：这确定了无线网络上的认证协议类型。

+   `ESSID`：**扩展服务集标识符**（**ESSID**）和网络 SSID 的名称相同。

+   `STATION`：显示关联和未关联设备的 MAC 地址。

执行命令后，您的无线适配器将执行所有附近无线网络和设备的实时扫描和监视。您应该会收到类似以下的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/3c428bee-6610-477f-a6ef-30298fc6d69f.png)

根据您的地理位置，列出的设备和网络将会有所不同。

实时查看网络流量可能会让人不知所措，特别是在我们可以看到所有附近设备的情况下。`airodump-ng`工具允许我们使用`--bssid`参数来过滤特定 AP 的输出。此外，使用`-c`参数允许我们指定 AP 所在的信道。使用以下语法：

```
airodump-ng --bissid <bssid value> -c <channel number> wlan0mon
```

您将得到类似以下的输出，其中将显示有关目标无线网络的具体细节：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/e8f51204-2e0b-405a-9805-84ba4e2cc1f8.png)

现在您已经能够进行数据包嗅探，让我们在下一节尝试将我们的攻击定向到特定目标。

# 使用 airodump-ng 进行目标数据包嗅探

在这一部分，我们将学习 airodump-ng 中的附加功能。最重要的是，我们将使用 airodump-ng 来针对特定网络；这将允许我们将攻击重点放在**特定** **目标**上，而不会对其他附近的无线网络造成任何伤害。

即使您正在过滤您的视图，流量（数据包）并没有被离线保存以供后续分析。使用`-w`参数将允许您指定文件位置以保存内容。因此，以下命令将帮助您完成此任务：

```
airodump-ng --bissid <bssid value> -c <channel number> wlan0mon -w /root/capture
```

在您的终端上使用`ls -l`命令，您会看到数据已经离线写入`root`目录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/b4818f88-b7ad-4536-a52a-0a4192d0bfc6.png)

airodump-ng 通常将捕获的数据写入五种文件类型中；这些是`.cap`、`.csv`、`.kistmet.csv`、`.kismet.netxml`和`.log.csv`格式。

您让`airodump-ng`工具运行的时间越长，离线文件中将写入越多的数据包，并最终捕获到客户端和目标 AP 之间的 WPA/WPA2 握手。在使用 Airodump-ng 进行数据包嗅探时，您将看到右上角出现**WPA 握手**消息；这表明 WPA/WPA2 握手已被 airodump-ng 捕获。捕获 WPA/WPA2 握手将帮助我们破解目标无线网络的密码。

在下一节中，我们将尝试从无线网络中去认证用户。

# 在无线网络上去认证客户端

每当客户端设备，如笔记本电脑或智能手机，试图与受密码保护的无线网络建立关联时，用户将需要提供正确的密码。如果用户提供了正确的密码，设备将在网络上得到认证，并能够访问任何可用的资源。

在去认证攻击中，攻击者或渗透测试人员试图将每个关联设备从无线 AP 中踢出。这种攻击是在攻击者机器与目标无线 AP 或网络没有任何连接（关联）的情况下执行的。

对于攻击者机器来说，要向无线 AP 发送去认证帧，需要在帧的主体中插入一个原因代码。这些代码用于通知接入点或无线路由器网络上的变化。原因代码将指示以下之一：

+   **代码 2**：以前的认证不再有效

+   **代码 3**：去认证离开

这将导致每个客户端从目标 AP 中被去认证。以下是对网络攻击的示例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/107805e1-7dec-4732-8d0b-cc4effe154ea.png)

要发起去认证攻击，请执行以下步骤：

1.  在您的无线适配器上启用监视模式。

1.  使用`airodump-ng wlan0mon`命令来发现您目标的 BSSID 地址。BSSID 将被用来专门针对特定 AP 发动我们的攻击。

1.  一旦发现目标 AP，记下它的 BSSID 和操作频道，然后通过使用*Ctrl* + *C* 终止对附近 AP 的扫描。

1.  通过使用以下语法将无线监视范围缩小到特定目标 AP：`airodump-ng --bssid <bssid value> -c <channel #> wlan0mon`。这个当前的终端窗口将用于监视我们攻击的进展。

1.  打开一个新的终端窗口。这个窗口将用于使用`aireplay-ng`工具发动攻击。`aireplay-ng -0 0 -a <BSSID> wlan0mon`命令将向目标 AP 发送持续的去认证帧。

您的结果应该类似于以下截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/35b3ef5a-5251-4aa5-8c84-155bf31c6175.png)

在截图中，我们可以看到`aireplay-ng`正在向我们的目标接入点发送持续的去认证帧。

在攻击过程中，切换回到您监视目标网络的第一个终端窗口。很快，您会看到客户端（站点）被断开连接，最终，WPA/WPA2 握手将被捕获。您将在您的终端上注意到，使用 airodump-ng，WPA 握手值将出现在窗口的右上角。这表明 WPA/WPA2 握手已经被捕获。在下一章中，我们将对无线网络进行密码破解。

您可以使用诸如**Hashcat** ([`hashcat.net/hashcat/`](https://hashcat.net/hashcat/)) 和**John the Ripper** ([`www.openwall.com/john/`](https://www.openwall.com/john/)) 进行密码破解。

此外，如果您想要从 AP 中去认证特定的客户端（站点），以下命令将允许这个操作：

```
aireplay-ng -0 0 -a <target's bssid> -c <client's mac addr> wlan0mon
```

以下是我们使用的每个参数的描述：

+   `-0`：这表示这是一个去认证攻击。

+   `0`：这指定要注入的帧的数量。使用`0`将创建一个持续的攻击；如果您指定`2`，则只会注入两个去认证帧。

+   `-c`：这允许您指定客户端的 MAC 地址。

在下一节中，我们将使用 Kali Linux 和各种无线工具创建一个蜜罐。

# 创建一个伪装 AP/恶意双胞胎

作为未来的渗透测试人员或道德黑客，您可能被要求为您的公司或客户组织进行广泛的无线安全测试。创建一个具有吸引力的 SSID（无线网络名称）的伪装 AP，例如`VIP_WiFi`或`Company-name_VIP`，将诱使员工建立连接。

在创建一个伪装 AP 时，目标是捕获用户凭据和敏感信息，并检测组织中的任何易受攻击的无线客户端。在部署伪装 AP 时，请考虑以下一些提示：

+   选择一个合适的位置，以确保潜在受害者有最大的覆盖范围。

+   从真实 AP 中去认证客户端，导致他们与伪装 AP 建立关联。

+   创建一个捕获用户凭据的强制门户。

要开始，我们将使用**Airgeddon**。这个工具包含了很多功能和功能，将帮助我们，从收集关于目标无线网络及其客户端的信息到发动各种类型的攻击和诱使用户与我们的伪装 AP 关联。

要开始创建一个虚假的接入点，请按照以下步骤进行：

1.  从其 GitHub 存储库下载 Airgeddon，并在您的用户帐户上给予`airgeddon.sh`脚本可执行权限。使用以下命令：

```
git clone https://github.com/v1s1t0r1sh3r3/airgeddon.git 
cd airgeddon chmod +x airgeddon.sh
```

1.  在您的终端窗口中，使用`./airgeddon.sh`命令启动 Airgeddon 界面。一旦脚本被启动，Airgeddon 将开始检查您的 Kali Linux 机器上的基本硬件和软件要求。

1.  按*Enter*几次，直到您到达接口选择提示；请务必选择您的无线适配器，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/4e3359e2-4c52-413f-9e8e-0387a61cdfb1.png)

选择选项`2`，它具有 wlan0 接口，并按*Enter*。

如果 Airgeddon 指出您缺少任何工具，请务必在继续之前安装它们。

1.  现在，您将看到 Airgeddon 的主要仪表板。在这里，您可以选择在无线适配器上在监视模式或托管模式之间切换。您将能够发动各种类型的攻击，如**拒绝服务**（**DoS**）攻击，尝试破解无线密码，捕获和解密无线握手，执行恶意双子攻击，或创建一个恶意 AP：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/3f024bda-63f4-4225-bd93-d2aea1a01e8f.png)

对于我们的攻击，我们将创建一个蜜罐，诱使受害者连接到我们的假 AP，以拦截、重定向和捕获敏感信息。

1.  接下来，将您的无线适配器设置为监视模式。您可以在 Airgeddon 菜单中使用**将接口置于监视模式**选项来完成这个操作。完成后，您应该看到您的无线适配器的状态现在已更改为**监视**模式，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/3f992a7d-b09f-4789-a4b7-0e1daca2f62f.png)

1.  选择恶意双子攻击菜单选项并按*Enter*。您将看到以下选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/95928872-dd3a-4d7b-8bc4-173139007a85.png)

Airgeddon 不仅允许我们轻松设置一个恶意 AP 或恶意双子，而且还为我们提供了其他功能，如嗅探受害者的流量，执行任何 SSL/TLS 连接的 SSL 剥离，执行浏览器利用，甚至创建一个用于收集用户凭据的囚犯门户。

1.  让我们首先寻找一个目标。选择选项`4`并按*Enter*。一个弹出的终端窗口将打开，显示所有附近的 AP。当您准备好选择一个目标时，请选择扫描窗口：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/1027ca72-3fb5-498b-a0dc-8c5a8a2c69e2.png)

1.  选择您的目标 AP 并按*Enter*继续。此时，我们已经将无线适配器设置为监视模式并选择了我们的目标：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/b7d42a28-eb97-4387-a99a-e24e6dd6e76e.png)

1.  让我们进行一个带嗅探的恶意双子攻击。选择选项`6`并按*Enter*。接下来的菜单将变为可用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/3abb0448-2f1c-443e-9fe9-9e7fac27013c.png)

1.  选择选项`2`来对目标无线网络执行去认证攻击；这将迫使真实网络的客户端断开连接（去认证），他们将尝试连接到我们的恶意双子/恶意双子。Airgeddon 将要求您选择连接到互联网/物理网络的物理接口。目的是为受害者提供常规网络连接的假象。当他们连接并访问本地资源时，受害者会认为这是合法的网络：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/cb876ff2-a25b-48c4-af19-4e2182b37add.png)

1.  选择适当的接口并按*Enter*继续；再次按*Enter*以验证所选的接口。

选择欺骗你的 MAC 地址来改变你的身份。

1.  当你准备好时，发动攻击。Airgeddon 将打开几个较小的终端窗口，显示它正在执行的每次攻击的状态，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/923af4e8-36bf-4e34-b040-b39327950a33.png)

一旦客户端连接，适当的终端窗口将为您提供更新。只需几个步骤，你现在拥有了自己的恶意双子/恶意双子。

在下一部分，我们将讨论并演示对目标系统的密码喷洒。

# 执行密码喷洒攻击

密码喷洒（有时被称为反向暴力破解）是一种通过使用有效的用户名和包含密码各种可能性的单词列表进行多次登录尝试的技术。进行密码喷洒攻击的目标是获得一组有效的用户凭据。

要执行密码喷洒攻击，我们将使用我们现有的 WordPress 服务器作为我们的目标**Burp Suite**，以在网页上获取用户名和密码输入字段，并使用`hydra`执行我们的密码喷洒攻击以找到有效的用户凭据。

要开始，请使用以下说明：

1.  配置您的网络浏览器以使用 Burp Suite 代理设置。完成后，打开 Burp Suite 并打开其拦截模式。

1.  接下来，在您的网络浏览器上，转到 WordPress 登录门户。URL 应为`http://<服务器地址>/wp-login.php`。请注意，您不应该在未经适当权限的设备或网络上尝试任何攻击。本节中执行的任务仅在实验环境中进行，仅用于教育目的。

1.  在用户名和密码字段中输入以下用户凭据，然后按*Enter*发送登录请求：

+   `uname`

+   `pass`

1.  请返回到 Burp Suite。在代理|拦截选项卡上，点击几次前进按钮，直到在**原始**子选项卡中看到一个 HTTP `POST`消息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/de17e88f-1e19-4ba6-ab67-0ef157acedd2.png)

1.  在`POST`消息中，注意第一行中的目录(`/wp-login.php`)和用户名/密码字段。

1.  确保记录网页上的登录错误消息，因为它在后续步骤中是必需的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/7765a672-0c5b-485f-82ab-0985ab9d98eb.png)

在我们的练习中，已创建了两个自定义字词表：第一个字词表包含可能的用户名列表，第二个包含可能的密码列表。使用 Kali Linux 上的`hydra`工具，您将能够对目标 WordPress 服务器执行**密码喷洒**攻击。

1.  使用`hydra`，我们可以得到以下语法：

```
hydra -L <username list> -p <password list> <IP Address> <form parameters><failed login message>
```

1.  替换语法中的每个值，我们得到以下命令：

```
hydra -L usernames.txt -P custom_list.txt 10.10.10.22 http-form-post "/wp-login. php: log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.10.22%2Fwp-admin% 2F&testcookie=l: Invalid username" -V
```

1.  将`uname`替换为`^USER^`，将`pass`替换为`^PASS^`，我们可以告诉`hydra`这些是用户名和密码字段。另外，指定`-V`以在终端窗口上产生详细输出。

1.  执行命令后，以下是预期输出的示例。以`[80] [http-post-form]`开头的行提供了目标的可能有效的用户名和密码，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/b4691dc9-934c-40d6-b28b-e8bd218891f2.png)

确保检查每个用户名和密码以验证其在目标系统上的真实性。快速向目标系统发送用户名和密码可能会导致锁定并停止我们的攻击。为了在尝试之间创建 10 秒的等待时间，使用`-w 10`参数。这是可选的；但是，它可能会减少被目标锁定或阻止的机会。

在下一节中，我们将介绍饮水源攻击的基本知识。

# 设置饮水源攻击

在 IT 安全领域，了解各种类型的攻击和威胁非常重要。其中一些攻击有一些非常不寻常的名称，在本节中，我们将介绍**饮水源攻击**的基础知识。

假设您是一家公司的 IT 安全管理员或工程师。您已经在行业内实施了最佳的安全设备，以主动检测和防止任何内部或外部的威胁。您还实施了行业最佳实践，遵守了标准，并确保您的用户（组织的员工）经常接受用户安全实践培训。您已经在组织内建立了一个安全堡垒，并确保网络边界也对新兴威胁保持警惕。

攻击者会注意到他们无法渗透您的网络，甚至社会工程技术，如钓鱼邮件，也无法成功针对您的组织。这将对妥协组织（目标）造成很大挑战，因为它受到了很好的保护。其中一种方法是进行饮水源攻击。

想象一下，在午餐时间，一些员工去附近的咖啡店喝一杯热饮或冷饮。黑客可能正在监视组织员工的活动——比如说，他们在休息时间经常去到有公共 Wi-Fi 的地方，甚至下班后也是如此。假设有一群员工经常光顾当地的咖啡店。攻击者可以妥协咖啡店的 Wi-Fi 网络，并植入一个下载到连接到网络的任何设备并在后台运行的 payload。

通过 compromise 咖啡店的 Wi-Fi 网络，攻击者正在对饮水源进行污染，包括目标组织的员工在享用饮料时使用的饮水源。假设 Alice 的智能手机在咖啡店被攻击；她将其带回组织并连接到内部（Wi-Fi）网络。此时，攻击是从内部生成的，并且可以危害网络的其余部分，甚至尝试在目标组织中创建后门。

有许多其他方法可以创建饮水源攻击；这只是一个例子。另一个例子是妥协经常有许多用户访问的合法网站，并在潜在受害者的系统上种植恶意软件。当系统感染恶意软件时，payload 可以针对其他网站或网络。

在下一节中，我们将讨论并演示如何从使用弱加密系统的系统中窃取凭据。

# 利用弱加密窃取凭据

加密在我们的日常生活中扮演着关键角色；无论是在外出时检查电子邮件，浏览喜爱的网站，还是简单地给朋友发送消息，数据加密为我们提供了一定程度的隐私保护，使得我们免受窥探。很多时候，IT 专业人员并不总是跟踪他们在维护加密技术方面的合规水平。这导致恶意用户或黑客通过攻击易受攻击的系统来获取机密数据，因为加密实践不当。

在这个练习中，我们将尝试发现目标上加密中最常见的漏洞。一旦找到，我们将利用弱加密漏洞。

要开始，请执行以下步骤：

1.  下载并设置**bee-box**虚拟机。bee-box 文件可以在[`sourceforge.net/projects/bwapp/files/bee-box/`](https://sourceforge.net/projects/bwapp/files/bee-box/)找到。

1.  安装完成后，在您的 Kali Linux（攻击者机器）上打开 Web 浏览器，输入 bee-box 的 IP 地址，然后点击*Enter*。

1.  将出现以下屏幕。点击**bWAPP**链接，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/d729380b-f83c-4dd4-98b3-a89b991fb809.png)

1.  您将遇到一个登录门户。输入用户名`bee`和密码`bug`进行登录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/04aaae79-65aa-40ec-8be4-1e24f41f70b7.png)

1.  在屏幕的左上角，使用下拉菜单并选择 Heartbleed Vulnerability。然后，点击 Hack 以加载目标虚拟机上的漏洞：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/33bf6c86-3348-4ef5-9edc-30de33a9badd.png)

1.  接下来，您将看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/051381cd-5022-4d8c-9ec5-09821cdd673c.png)

1.  在您的 Kali Linux 机器上，在地址栏中输入带有端口号`8443`的新 URL，然后点击*Enter*。新的 URL 应该是`https://10.10.10.131:8443`。确保再次使用*步骤 4*中提供的凭据登录 bWAPP 应用程序。

1.  使用 Nmap，我们可以执行漏洞扫描，以确定目标上是否存在心脏出血漏洞。要执行此任务，请使用以下命令：

```
nmap -p 8443 -script ssl-heartbleed <target IP address>
```

如果目标上存在漏洞，Nmap 将向我们呈现以下屏幕：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/91322818-3fa2-4ccc-b625-00d965aedb99.png)

1.  现在我们确定了目标上存在心脏出血漏洞，是时候使用 Metasploit 进行一些利用了。在 Metasploit 中，让我们使用`search`命令来帮助我们找到一个合适的模块：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/9c7b20c7-6a47-4bd3-a594-b118cd85f6e4.png)

1.  搜索返回了两个可用的模块。我们将使用`auxiliary/scanner/ssl/openssl_heartbleed`模块。此外，我们将把`RHOSTS`设置为目标的 IP 地址，`RPORTS`设置为`8443`，如 bWAPP 界面的提示所指定的。以下片段显示了配置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/eec001a7-ae79-4aaa-9dc5-573e41130c78.png)

启动模块后，您会注意到数据正在以下屏幕中泄漏：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/991a6026-aa4c-4dfb-b472-bd4baf69f32c.png)

仔细检查输出，您会看到利用返回了`可打印信息泄漏`部分，随后是明文的 HTTP 会话信息；目标机器以数据泄漏做出了响应。如果没有发现泄漏，目标机器将不会向我们的 Metasploit 界面返回任何数据。默认情况下，数据的转储已被提取并存储在您的 Kali Linux 机器上的`/root/.msf4/loot/…`位置。

1.  使用`show info`命令，您将看到`openssl_heartbleed`模块下可执行的操作，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/cddebdb6-feb0-4e2b-aed5-a583104737b7.png)

可以使用以下命令更改这些操作：

+   `set action DUMP`

+   `set action KEYS`

+   `set action SCAN`

以下是在使用`set action DUMP`命令后`.bin`文件的内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/51804a0e-fc70-4b64-8dba-0c195f9a3ba3.png)

此外，越多的人当前访问易受攻击的应用程序，收集更多机密信息的可能性就越高，例如登录凭据。然而，在我们的练习中，我能够捕获 cookie 数据。

# 总结

在本章中，您学习了如何执行无线数据包嗅探，熟悉了数据包嗅探的基础知识，并使用`aircrack-ng`进行了有针对性的数据包嗅探。此外，您还学会了在*在无线网络上去认证客户端*部分对目标无线访问点执行去认证攻击所需的基本技能。

在*创建一个恶意 AP/恶意孪生*部分，您学习了如何使用 Airgeddon 将多个攻击链接在一起，并创建一个恶意孪生/恶意访问点。此外，密码喷洒部分提供了获取远程系统访问权限所需的技能，同时还提供了利用使用弱加密的系统的技能。

在下一章，第十章，*网络渗透测试-获取访问权限*，我们将更详细地介绍网络渗透。

# 问题

1.  什么工具可以为您的无线网络适配器启用监视模式？

1.  SSID 的另一个名称是什么？

1.  在去认证攻击期间，用于断开客户端的代码是什么？

1.  用于执行去认证的工具是什么？

# 进一步阅读

以下是一些额外的阅读资源：

+   **去认证攻击**：[`www.aircrack-ng.org/doku.php?id=deauthentication`](https://www.aircrack-ng.org/doku.php?id=deauthentication)

+   **常见 WLAN 保护机制及其缺陷**：[`hub.packtpub.com/common-wlan-protection-mechanisms-and-their-flaws/`](https://hub.packtpub.com/common-wlan-protection-mechanisms-and-their-flaws/)

+   **高级无线嗅探**：[`hub.packtpub.com/advanced-wireless-sniffing/`](https://hub.packtpub.com/advanced-wireless-sniffing/)
