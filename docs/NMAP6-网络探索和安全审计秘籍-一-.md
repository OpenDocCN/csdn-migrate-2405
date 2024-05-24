# NMAP6 网络探索和安全审计秘籍（一）

> 原文：[`annas-archive.org/md5/0DC464DD8E91DC475CC40B74E4774B2B`](https://annas-archive.org/md5/0DC464DD8E91DC475CC40B74E4774B2B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

《Nmap 6：网络探索与安全审计食谱》是一本 100%实用的书，采用食谱风格。每个配方都专注于一个单独的任务，并包含命令行示例、样本输出、详细解释和其他有用的提示。

通过九章内容，探索了 Nmap 的广泛功能，涵盖了渗透测试人员和系统管理员的 100 个不同任务。与 Nmap 的官方书籍不同，本书侧重于使用 Nmap 脚本引擎可以完成的任务，同时也涵盖了 Nmap 的核心功能。

有许多优秀的 NSE 脚本，我希望有更多的空间可以包含在这本书中，也有许多脚本将在出版后创建。Luis Martin Garcia 最近发布了一个有趣的视频，展示了 Nmap 多年来的成长，网址为[`www.youtube.com/watch?v=7rlF1MSAbXk`](http://www.youtube.com/watch?v=7rlF1MSAbXk)。我邀请您注册开发邮件列表，了解 Nmap 的最新功能和 NSE 脚本。

我希望您不仅享受阅读这本食谱，而且在掌握 Nmap 脚本引擎的过程中，能够提出新的创意，并为这个令人惊叹的项目做出贡献。

最后，不要忘记您可以向我发送问题，我会尽力帮助您。

# 本书涵盖内容

第一章，Nmap 基础知识，涵盖了使用 Nmap 执行的最常见任务。此外，它还简要介绍了 Ndiff、Nping 和 Zenmap。

第二章，网络探索，涵盖了 Nmap 支持的主机发现技术，以及 Nmap 脚本引擎的其他有用技巧。

第三章，收集额外的主机信息，涵盖了使用 Nmap 及其脚本引擎进行有趣的信息收集任务。

第四章，审计 Web 服务器，涵盖了与 Web 安全审计相关的任务。

第五章，审计数据库，涵盖了对 MongoDB、MySQL、MS SQL 和 CouchDB 数据库进行安全审计的任务。

第六章，审计邮件服务器，涵盖了 IMAP、POP3 和 SMTP 服务器的任务。

第七章，扫描大型网络，涵盖了在扫描大型网络时有用的任务，从扫描优化到在多个客户端之间分发扫描。

第八章，生成扫描报告，涵盖了 Nmap 支持的输出选项。

第九章，编写自己的 NSE 脚本，涵盖了 NSE 开发的基础知识。其中包括处理套接字、输出、库和并行性的具体示例。

附录 A，参考资料，涵盖了本书中使用的参考资料和官方文档。

# 本书所需内容

您需要最新版本的 Nmap（可从[`nmap.org`](http://nmap.org)获取）来按照本书中的配方进行操作。

# 本书的受众

本书适用于任何希望学习如何使用和掌握 Nmap 和 Nmap 脚本引擎的安全顾问、管理员或爱好者。

### 注意

本书包含了如何进行各种渗透测试的指南，例如对远程网络和设备进行暴力破解密码审计。在许多情况下，这些任务可能在您的司法管辖区属于非法行为，或者至少属于服务条款违规或职业不端行为。提供这些指南是为了让您能够测试系统对抗威胁，了解这些威胁的性质，并保护自己的系统免受类似攻击。在执行这些任务之前，请确保您站在法律和道德的正确一边...运用您的力量为善！

# 惯例

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是这些样式的一些示例，以及它们的含义解释。

文本中的代码词显示如下："标志`-PS`强制执行 TCP SYN ping 扫描。"

代码块设置如下：

```
table.insert(fingerprints, {
  category='cms',
  probes={
    {path='/changelog.txt'},
    {path='/tinymce/changelog.txt'},
  },
  matches={
    {match='Version (.-) ', output='Version \\1'},
    {output='Interesting, a changelog.'}
  }
})
```

任何命令行输入或输出都以以下方式编写：

```
$ nmap -sP -PS80,21,53 <target>
$ nmap -sP -PS1-1000 <target>
$ nmap -sP -PS80,100-1000 <target>

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中："单击**确定**开始下载您的新工作副本。"

### 注意

警告或重要提示会以这样的方式出现在框中。

### 提示

提示和技巧看起来像这样。


# 第一章：Nmap 基础知识

### 注意

本章向您展示了如何执行在许多情况下可能是非法、不道德、违反服务条款或只是不明智的一些操作。这里提供这些信息是为了让您了解如何保护自己免受威胁，并使自己的系统更加安全。在遵循这些说明之前，请确保您站在法律和道德的一边……运用您的力量为善！

在本章中，我们将涵盖：

+   从官方源代码仓库下载 Nmap

+   从源代码编译 Nmap

+   列出远程主机上的开放端口

+   对远程主机的指纹服务

+   在您的网络中查找活动主机

+   使用特定端口范围进行扫描

+   运行 NSE 脚本

+   使用指定的网络接口进行扫描

+   使用 Ndiff 比较扫描结果

+   使用 Zenmap 管理多个扫描配置文件

+   使用 Nping 检测 NAT

+   使用 Nmap 和 Ndiff 远程监控服务器

# 介绍

**Nmap**（网络映射器）是一款专门用于网络探索和安全审计的开源工具，最初由 Gordon "Fyodor" Lyon 发布。官方网站（[`nmap.org`](http://nmap.org)）对其进行了如下描述：

> Nmap（网络映射器）是一个用于网络发现和安全审计的免费开源（许可证）实用程序。许多系统和网络管理员也发现它在网络清单、管理服务升级计划和监控主机或服务的正常运行时间等任务中非常有用。Nmap 以新颖的方式使用原始 IP 数据包来确定网络上有哪些主机可用，这些主机提供了哪些服务（应用程序名称和版本），它们正在运行哪种操作系统（和操作系统版本），正在使用哪种类型的数据包过滤器/防火墙，以及其他几十种特征。它旨在快速扫描大型网络，但也可以对单个主机进行扫描。Nmap 可在所有主要计算机操作系统上运行，并提供 Linux、Windows 和 Mac OS X 的官方二进制软件包。

市面上有许多其他端口扫描工具，但没有一个能够提供 Nmap 的灵活性和高级选项。

**Nmap 脚本引擎（NSE）**通过允许用户编写使用 Nmap 收集的主机信息执行自定义任务的脚本，彻底改变了端口扫描仪的可能性。

此外，Nmap 项目还包括其他出色的工具：

+   **Zenmap**：Nmap 的图形界面

+   **Ndiff**：用于比较扫描结果的工具

+   **Nping**：用于生成数据包和流量分析的优秀工具

+   **Ncrack**：用于暴力破解网络登录的与 Nmap 兼容的工具

+   **Ncat**：用于在网络上读写数据的调试工具

不用说，每个安全专业人员和网络管理员都必须掌握这个工具，以便进行安全评估、高效地监控和管理网络。

Nmap 的社区非常活跃，每周都会添加新功能。我鼓励您始终在您的工具库中保持最新版本，如果您还没有这样做；更好的是，订阅开发邮件列表，网址为[`cgi.insecure.org/mailman/listinfo/nmap-dev`](http://cgi.insecure.org/mailman/listinfo/nmap-dev)。

本章描述了如何使用 Nmap 执行一些最常见的任务，包括端口扫描和目标枚举。它还包括一些示例，说明了 Zenmap 的配置文件有多方便，如何使用 Nping 进行 NAT 检测，以及 Ndiff 的不同应用，包括如何借助 bash 脚本和 cron 设置远程监控系统。我尽可能添加了许多参考链接，建议您访问它们以了解更多有关 Nmap 执行的高级扫描技术内部工作的信息。

我还创建了网站[`nmap-cookbook.com`](http://nmap-cookbook.com)来发布新的相关材料和额外的示例，所以请确保您不时地过来逛逛。

# 从官方源代码存储库下载 Nmap

本节描述了如何从官方子版本存储库下载 Nmap 的源代码。通过这样做，用户可以编译 Nmap 的最新版本，并跟上提交到子版本存储库的每日更新。

## 准备

在继续之前，您需要有一个工作的互联网连接和访问子版本客户端。基于 Unix 的平台配备了一个名为**subversion**（**svn**）的命令行客户端。要检查它是否已安装在您的系统中，只需打开终端并键入：

```
$ svn

```

如果它告诉您找不到该命令，请使用您喜欢的软件包管理器安装`svn`或从源代码构建它。从源代码构建 svn 的说明超出了本书的范围，但在网上有广泛的文档记录。使用您喜欢的搜索引擎找到您系统的具体说明。

如果您更喜欢使用图形用户界面，RapidSVN 是一个非常受欢迎的跨平台替代品。您可以从[`rapidsvn.tigris.org/`](http://rapidsvn.tigris.org/)下载并安装 RapidSVN。

## 如何做...

打开您的终端并输入以下命令：

```
$ svn co --username guest https://svn.nmap.org/nmap/

```

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册以直接通过电子邮件接收文件。

等到 svn 下载存储库中的所有文件。当它完成时，您应该看到添加的文件列表，如下面的屏幕截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/nmap6-net-exp-sec-adt-cb/img/7485_01_01.jpg)

当程序返回/退出时，您将在当前目录中拥有 Nmap 的源代码。

## 它是如何工作的...

```
$ svn checkout https://svn.nmap.org/nmap/ 

```

此命令将下载位于[`svn.nmap.org/nmap/`](https://svn.nmap.org/nmap/)的远程存储库的副本。该存储库具有对最新稳定构建的全球读取访问权限，允许 svn 下载您的本地工作副本。

## 还有更多...

如果您使用 RapidSVN，则按照以下步骤操作：

1.  右键单击**书签**。

1.  单击**检出新的工作副本**。

1.  在 URL 字段中键入`https://svn.nmap.org/nmap/`。

1.  选择您的本地工作目录。

1.  单击**确定**开始下载您的新工作副本。![还有更多...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/nmap6-net-exp-sec-adt-cb/img/7485_01_02_new.jpg)

### 尝试开发分支

如果您想尝试开发团队的最新创作，那么有一个名为`nmap-exp`的文件夹，其中包含项目的不同实验分支。存储在那里的代码不能保证始终有效，因为开发人员将其用作沙盒，直到准备合并到稳定分支为止。该文件夹的完整子版本 URL 是[`svn.nmap.org/nmap-exp/`](https://svn.nmap.org/nmap-exp/)。

### 保持您的源代码最新

要更新先前下载的 Nmap 副本，请在工作目录中使用以下命令：

```
$ svn update

```

您应该看到已更新的文件列表，以及一些修订信息。

## 另请参阅

+   *从源代码编译 Nmap*配方

+   *列出远程主机上的开放端口*配方

+   *对远程主机的服务进行指纹识别*配方

+   *运行 NSE 脚本*配方

+   *使用 Ndiff 比较扫描结果*配方

+   *使用 Zenmap 管理多个扫描配置文件*配方

+   第八章中的*使用 Zenmap 生成网络拓扑图*配方，生成*扫描报告*

+   第八章中的*以正常格式保存扫描结果*配方，生成*扫描报告*

# 从源代码编译 Nmap

预编译的软件包总是需要时间来准备和测试，导致发布之间的延迟。如果您想要保持与最新添加的内容同步，强烈建议编译 Nmap 的源代码。

该食谱描述了如何在 Unix 环境中编译 Nmap 的源代码。

## 准备工作

确保您的系统中安装了以下软件包：

+   `gcc`

+   `openssl`

+   `make`

使用您喜欢的软件包管理器安装缺少的软件，或者从源代码构建。从源代码构建这些软件包的说明超出了本书的范围，但可以在线获得。

## 操作步骤...

1.  打开您的终端并进入 Nmap 源代码存储的目录。

1.  根据您的系统进行配置：

```
$ ./configure

```

如果成功，将显示一个 ASCII 龙警告您 Nmap 的强大（如下图所示），否则将显示指定错误的行。

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/nmap6-net-exp-sec-adt-cb/img/7485_01_03.jpg)

1.  使用以下命令构建 Nmap：

```
$ make 

```

如果您没有看到任何错误，那么您已成功构建了最新版本的 Nmap。您可以通过查找当前目录中编译的二进制文件`Nmap`来验证这一点。

如果要使 Nmap 对系统中的所有用户可用，请输入以下命令：

```
# make install 

```

## 工作原理...

我们使用脚本`configure`来设置不同的参数和影响您的系统和所需配置的环境变量。然后，GNU 的`make`通过编译源代码生成了二进制文件。

## 还有更多...

如果您只需要 Nmap 二进制文件，可以使用以下配置指令来避免安装 Ndiff、Nping 和 Zenmap：

+   通过使用`--without-ndiff`跳过 Ndiff 的安装

+   通过使用`--without-zenmap`跳过 Zenmap 的安装

+   通过使用`--without-nping`跳过 Nping 的安装

### OpenSSL 开发库

在构建 Nmap 时，OpenSSL 是可选的。启用它允许 Nmap 访问与多精度整数、哈希和编码/解码相关的此库的功能，用于服务检测和 Nmap NSE 脚本。

在 Debian 系统中，OpenSSL 开发包的名称是`libssl-dev`。

### 配置指令

在构建 Nmap 时可以使用几个配置指令。要获取完整的指令列表，请使用以下命令：

```
$ ./configure --help

```

### 预编译软件包

在线上有几个预编译的软件包（[`nmap.org/download.html`](http://nmap.org/download.html)）可供使用，适用于那些无法访问编译器的人，但不幸的是，除非是最近的版本，否则很可能会缺少功能。Nmap 在不断发展。如果您真的想利用 Nmap 的功能，就要保持本地副本与官方仓库同步。

### 另请参阅

+   *从官方源代码仓库下载 Nmap*食谱

+   *列出远程主机上的开放端口*食谱

+   *对远程主机的服务进行指纹识别*食谱

+   *使用 Ndiff 比较扫描结果*食谱

+   *使用 Zenmap 管理多个扫描配置文件*食谱

+   *运行 NSE 脚本*食谱

+   *使用指定的网络接口进行扫描*食谱

+   在第八章中的*保存正常格式的扫描结果*食谱，生成*扫描报告*

+   在第八章中的*使用 Zenmap 生成网络拓扑图*食谱，生成*扫描报告*

# 列出远程主机上的开放端口

该食谱描述了使用 Nmap 确定远程主机上端口状态的最简单方法，这是用于识别常用服务的运行过程，通常称为**端口扫描**。

## 操作步骤...

1.  打开终端。

1.  输入以下命令：

```
$ nmap scanme.nmap.org

```

扫描结果应该显示在屏幕上，显示有趣的端口及其状态。标记为打开的端口特别重要，因为它们代表目标主机上运行的服务。

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/nmap6-net-exp-sec-adt-cb/img/7485_01_04.jpg)

## 工作原理...

通过启动 TCP 端口扫描，以下命令检查主机`scanme.nmap.org`上最受欢迎的端口的状态：

```
$ nmap scanme.nmap.org

```

结果包含主机信息，如 IPv4 地址和 PTR 记录，以及端口信息，如服务名称和端口状态。

## 还有更多...

即使对于这种最简单的端口扫描，Nmap 在后台也做了很多事情，这些也可以进行配置。

Nmap 首先通过 DNS 将主机名转换为 IPv4 地址。如果您希望使用不同的 DNS 服务器，请使用`--dns-servers <serv1[,serv2],...>`，或者如果您希望跳过此步骤，请使用`-n`如下：

```
$ nmap --dns-servers 8.8.8.8,8.8.4.4 scanme.nmap.org

```

然后，它会 ping 目标地址，以检查主机是否存活。要跳过此步骤，请使用`–PN`如下：

```
$ nmap -PN scanme.nmap.org

```

然后，Nmap 通过反向 DNS 调用将 IPv4 地址转换回主机名。如下使用`-n`跳过此步骤：

```
$ nmap -n scanme.nmap.org

```

最后，它启动了 TCP 端口扫描。要指定不同的端口范围，请使用`-p[1-65535]`，或使用`-p-`表示所有可能的 TCP 端口，如下所示：

```
$ nmap -p1-30 scanme.nmap.org

```

### 特权与非特权

以特权用户身份运行`nmap <TARGET>`将启动**SYN Stealth 扫描**。对于无法创建原始数据包的非特权帐户，将使用**TCP Connect 扫描**。

这两者之间的区别在于 TCP Connect 扫描使用高级系统调用**connect**来获取有关端口状态的信息。这意味着每个 TCP 连接都完全完成，因此速度较慢，更容易被检测并记录在系统日志中。SYN Stealth 扫描使用原始数据包发送特制的 TCP 数据包，更可靠地检测端口状态。

### 端口状态

Nmap 将端口分类为以下状态：

### 注意

发送的数据包类型取决于使用的扫描技术。

+   **开放**：这表示应用程序正在此端口上监听连接。

+   **关闭**：这表示探测已收到，但在此端口上没有应用程序监听。

+   **过滤**：这表示探测未收到，无法确定状态。还表示探测正在被某种过滤器丢弃。

+   **未过滤**：这表示探测已收到，但无法确定状态。

+   **开放/过滤**：这表示端口被过滤或打开，但 Nmap 无法确定状态。

+   **关闭/过滤**：这表示端口被过滤或关闭，但 Nmap 无法确定状态。

### Nmap 支持的端口扫描技术

我们展示了执行端口扫描的最简单方法，但 Nmap 提供了大量先进的扫描技术。使用`nmap -h`或访问[`nmap.org/book/man-port-scanning-techniques.html`](http://nmap.org/book/man-port-scanning-techniques.html)了解更多信息。

## 另请参阅

+   *指纹识别远程主机的服务*食谱

+   *在您的网络中查找活动主机*食谱

+   *使用特定端口范围进行扫描*食谱

+   *使用指定网络接口进行扫描*食谱

+   *使用 Zenmap 管理不同的扫描配置文件*食谱

+   *使用 Nmap 和 Ndiff 远程监视服务器*食谱

+   *从扫描中排除主机*食谱在第二章中，*网络探索*

+   *扫描 IPv6 地址*食谱在第二章中，*网络探索*

+   *指纹识别主机操作系统*食谱在第三章中，*收集额外的主机信息*

+   *发现 UDP 服务*食谱在第三章中，*收集额外的主机信息*

+   *列出远程主机支持的协议*食谱在第三章中，*收集额外的主机信息*

# 指纹识别远程主机的服务

**版本检测**是 Nmap 最受欢迎的功能之一。知道服务的确切版本对于使用该服务寻找安全漏洞的渗透测试人员以及希望监视网络是否有未经授权更改的系统管理员非常有价值。对服务进行指纹识别还可能揭示有关目标的其他信息，例如可用模块和特定协议信息。

本食谱描述了如何使用 Nmap 对远程主机的服务进行指纹识别。

## 如何做...

打开终端并输入以下命令：

```
$ nmap -sV scanme.nmap.org

```

此命令的结果是一个包含名为**版本**的额外列的表，显示特定的服务版本，如果被识别。其他信息将被括号括起来。请参考以下截图：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/nmap6-net-exp-sec-adt-cb/img/7485_01_05.jpg)

## 它是如何工作的...

标志`-sV`启用服务检测，返回额外的服务和版本信息。

**服务检测**是 Nmap 最受欢迎的功能之一，因为它在许多情况下非常有用，比如识别安全漏洞或确保服务在给定端口上运行。

这个功能基本上是通过从`nmap-service-probes`发送不同的探测到疑似开放端口的列表。探测是根据它们可能被用来识别服务的可能性选择的。

关于服务检测模式的工作原理和使用的文件格式有非常详细的文档，网址为[`nmap.org/book/vscan.html`](http://nmap.org/book/vscan.html)。

## 还有更多...

您可以通过更改扫描的强度级别来设置要使用的探测数量，使用参数`--version-intensity [0-9]`，如下所示：

```
# nmap -sV –-version-intensity 9 

```

### 侵略性检测

Nmap 有一个特殊的标志来激活侵略性检测，即`-A`。**侵略模式**启用了 OS 检测(`-O`)、版本检测(`-sV`)、脚本扫描(`-sC`)和跟踪路由(`--traceroute`)。不用说，这种模式发送了更多的探测，更容易被检测到，但提供了大量有价值的主机信息。您可以通过以下命令之一来查看：

```
# nmap -A <target>

```

或

```
# nmap -sC -sV -O <target>

```

![侵略性检测](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/nmap6-net-exp-sec-adt-cb/img/7485_01_06.jpg)

### 提交服务指纹

Nmap 的准确性来自多年来通过用户提交收集的数据库。非常重要的是，我们帮助保持这个数据库的最新。如果 Nmap 没有正确识别服务，请将您的新服务指纹或更正提交到[`insecure.org/cgi-bin/submit.cgi?`](http://insecure.org/cgi-bin/submit.cgi?)。

## 另请参阅

+   *列出远程主机上的开放端口*食谱

+   *在您的网络中查找活动主机*食谱

+   *使用特定端口范围进行扫描*食谱

+   *使用指定网络接口进行扫描*食谱

+   *使用 Zenmap 管理多个扫描配置文件*食谱

+   *使用 Nmap 和 Ndiff 远程监视服务器*食谱

+   在第二章的*使用额外的随机数据隐藏我们的流量*食谱中，*网络探索*

+   在第二章的*扫描 IPv6 地址*食谱中，*网络探索*

+   在第三章的*从 WHOIS 记录中获取信息*食谱中，*收集额外的主机信息*

+   在第三章的*暴力破解 DNS 记录*食谱中，*收集额外的主机信息*

+   在第三章的*对主机的操作系统进行指纹识别*食谱中，*收集额外的主机信息*

# 在您的网络中查找活动主机

在网络中查找活动主机通常被渗透测试人员用来枚举活动目标，也被系统管理员用来计算或监视活动主机的数量。

此配方描述了如何执行 ping 扫描，以通过 Nmap 找到网络中的活动主机。

## 如何做...

打开您的终端并输入以下命令：

```
$ nmap -sP 192.168.1.1/24

```

结果显示了在线并响应 ping 扫描的主机。

```
Nmap scan report for 192.168.1.102 
Host is up. 
Nmap scan report for 192.168.1.254 
Host is up (0.0027s latency). 
MAC Address: 5C:4C:A9:F2:DC:7C (Huawei Device Co.) 
Nmap done: 256 IP addresses (2 hosts up) scanned in 10.18 seconds 

```

在这种情况下，我们在网络中找到了两个活动主机。Nmap 还找到了 MAC 地址，并识别了家用路由器的供应商。

## 它是如何工作的...

Nmap 使用`-sP`标志进行 ping 扫描。这种类型的扫描对于枚举网络中的主机非常有用。它使用 TCP ACK 数据包和 ICMP 回显请求（如果以特权用户身份执行），或者使用`connect()` `syscall`发送的 SYN 数据包（如果由不能发送原始数据包的用户运行）。

在`192.168.1.1/24`中使用 CIDR`/24`表示我们要扫描网络中的所有 256 个 IP。

## 还有更多...

在以特权用户身份扫描本地以太网网络时使用 ARP 请求，但您可以通过包括标志`--send-ip`来覆盖此行为。

```
# nmap -sP --send-ip 192.168.1.1/24

```

### Traceroute

使用`--traceroute`来包括您的机器和每个找到的主机之间的路径。

```
Nmap scan report for 192.168.1.101 
Host is up (0.062s latency). 
MAC Address: 00:23:76:CD:C5:BE (HTC) 

TRACEROUTE 
HOP RTT      ADDRESS 
1   61.70 ms 192.168.1.101 

Nmap scan report for 192.168.1.102 
Host is up. 

Nmap scan report for 192.168.1.254 
Host is up (0.0044s latency). 
MAC Address: 5C:4C:A9:F2:DC:7C (Huawei Device Co.) 

TRACEROUTE 
HOP RTT     ADDRESS 
1   4.40 ms 192.168.1.254 

Nmap done: 256 IP addresses (3 hosts up) scanned in 10.03 seconds 

```

### NSE 脚本

Ping 扫描不执行端口扫描或服务检测，但可以根据主机规则启用 Nmap 脚本引擎，例如`sniffer-detect`和`dns-brute`的情况。

```
# nmap -sP --script discovery 192.168.1.1/24 

Pre-scan script results: 
| broadcast-ping: 
|_  Use the newtargets script-arg to add the results as targets 
Nmap scan report for 192.168.1.102 
Host is up. 

Host script results: 
|_dns-brute: Can't guess domain of "192.168.1.102"; use dns-brute.domain script argument. 

Nmap scan report for 192.168.1.254 
Host is up (0.0023s latency). 
MAC Address: 5C:4C:A9:F2:DC:7C (Huawei Device Co.) 

Host script results: 
|_dns-brute: Can't guess domain of "192.168.1.254"; use dns-brute.domain script argument. 
|_sniffer-detect: Likely in promiscuous mode (tests: "11111111") 

Nmap done: 256 IP addresses (2 hosts up) scanned in 14.11 seconds 

```

## 另请参阅

+   *运行 NSE 脚本*配方

+   第二章中的*使用广播 ping 发现主机*配方，*网络探索*

+   第二章中的*使用 TCP SYN ping 扫描发现主机*配方，*网络探索*

+   第二章中的*使用 TCP ACK ping 扫描发现主机*配方，*网络探索*

+   第二章中的*使用 ICMP ping 扫描发现主机*配方，*网络探索*

+   第二章中的*使用广播脚本收集网络信息*配方，*网络探索*

+   第三章中的*发现指向相同 IP 的主机名*配方，*收集额外主机信息*

+   第三章中的*强制 DNS 记录*配方，*收集额外主机信息*

+   第三章中的*欺骗端口扫描的源 IP*配方，*收集额外主机信息*

# 使用特定端口范围进行扫描

有时系统管理员正在寻找使用特定端口进行通信的感染机器，或者用户只是寻找特定服务或开放端口，而不太关心其他内容。缩小使用的端口范围也可以优化性能，在扫描多个目标时非常重要。

此配方描述了在执行 Nmap 扫描时如何使用端口范围。

## 如何做...

打开您的终端并输入以下命令：

```
# nmap -p80 192.168.1.1/24 

```

将显示带有端口`80`状态的主机列表。

```
Nmap scan report for 192.168.1.102 
Host is up (0.000079s latency). 
PORT   STATE SERVICE 
80/tcp closed  http 

Nmap scan report for 192.168.1.103 
Host is up (0.016s latency). 
PORT   STATE SERVICE 
80/tcp open  http 
MAC Address: 00:16:6F:7E:E0:B6 (Intel) 

Nmap scan report for 192.168.1.254 
Host is up (0.0065s latency). 
PORT   STATE SERVICE 
80/tcp open  http 
MAC Address: 5C:4C:A9:F2:DC:7C (Huawei Device Co.) 

Nmap done: 256 IP addresses (3 hosts up) scanned in 8.93 seconds 

```

## 它是如何工作的...

Nmap 使用标志`-p`来设置要扫描的端口范围。此标志可以与任何扫描方法结合使用。在前面的示例中，我们使用参数`-p80`来告诉 Nmap 我们只对端口 80 感兴趣。

在`192.168.1.1/24`中使用 CIDR`/24`表示我们要扫描网络中的所有 256 个 IP。

## 还有更多...

对于参数`-p`，有几种被接受的格式：

+   端口列表：

```
# nmap -p80,443 localhost

```

+   端口范围：

```
# nmap -p1-100 localhost

```

+   所有端口：

```
# nmap -p- localhost

```

+   协议的特定端口：

```
# nmap -pT:25,U:53 <target>

```

+   服务名称：

```
# nmap -p smtp <target>

```

+   服务名称通配符：

```
# nmap -p smtp* <target>

```

+   仅在 Nmap 服务中注册的端口：

```
# nmap -p[1-65535] <target>

```

## 另请参阅

+   *在您的网络中查找活动主机*配方

+   *列出远程主机上的开放端口*配方

+   *使用指定的网络接口进行扫描*配方

+   *运行 NSE 脚本*配方

+   第二章中的*使用额外的随机数据隐藏我们的流量*配方，*网络探索*

+   第二章中的*强制 DNS 解析*配方，*网络探索*

+   第二章中的*从扫描中排除主机*配方，*网络探索*

+   第二章中的*扫描 IPv6 地址*配方，*网络探索*

+   第三章中的*列出远程主机支持的协议*配方，*收集额外的主机信息*

# 运行 NSE 脚本

NSE 脚本非常强大，已经成为 Nmap 的主要优势之一，可以执行从高级版本检测到漏洞利用的任务。

以下配方描述了如何运行 NSE 脚本以及此引擎的不同选项。

## 如何做到...

要在扫描结果中包含 Web 服务器索引文档的标题，请打开终端并输入以下命令：

```
$ nmap -sV --script http-title scanme.nmap.org 

```

![如何做到...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/nmap6-net-exp-sec-adt-cb/img/7485_01_07.jpg)

## 它是如何工作的...

参数**--script**设置应该在扫描中运行的 NSE 脚本。在这种情况下，当服务扫描检测到 Web 服务器时，将为所选的 NSE 脚本初始化一个并行线程。

有超过 230 个可用的脚本，执行各种各样的任务。NSE 脚本**http-title**如果检测到 Web 服务器，则返回根文档的标题。

## 还有更多...

您可以一次运行多个脚本：

```
$ nmap --script http-headers,http-title scanme.nmap.org
Nmap scan report for scanme.nmap.org (74.207.244.221) 
Host is up (0.096s latency). 
Not shown: 995 closed ports 
PORT     STATE    SERVICE 
22/tcp   open     ssh 
25/tcp   filtered smtp 
80/tcp   open     http 
| http-headers: 
|   Date: Mon, 24 Oct 2011 07:12:09 GMT 
|   Server: Apache/2.2.14 (Ubuntu) 
|   Accept-Ranges: bytes 
|   Vary: Accept-Encoding 
|   Connection: close 
|   Content-Type: text/html 
| 
|_  (Request type: HEAD) 
|_http-title: Go ahead and ScanMe! 
646/tcp  filtered ldp 
9929/tcp open     nping-echo 

```

此外，NSE 脚本可以按类别、表达式或文件夹进行选择：

+   运行`vuln`类别中的所有脚本：

```
$ nmap -sV --script vuln <target>

```

+   运行`version`或`discovery`类别中的脚本：

```
$ nmap -sV --script="version,discovery" <target>

```

+   运行除`exploit`类别中的脚本之外的所有脚本：

```
$ nmap -sV --script "not exploit" <target>

```

+   运行除`http-brute`和`http-slowloris`之外的所有 HTTP 脚本：

```
$ nmap -sV --script "(http-*) and not(http-slowloris or http-brute)" <target>

```

要调试脚本，请使用`--script-trace`。这将启用执行脚本的堆栈跟踪，以帮助您调试会话。请记住，有时您可能需要增加调试级别，使用标志`-d[1-9]`来解决问题的根源：

```
$ nmap -sV –-script exploit -d3 --script-trace 192.168.1.1 

```

### NSE 脚本参数

标志`--script-args`用于设置 NSE 脚本的参数。例如，如果您想设置 HTTP 库参数`useragent`，您将使用：

```
$ nmap -sV --script http-title --script-args http.useragent="Mozilla 999" <target>

```

在设置 NSE 脚本的参数时，您还可以使用别名。例如，您可以使用

```
$ nmap -p80 --script http-trace --script-args path <target>

```

而不是：

```
$ nmap -p80 --script http-trace --script-args http-trace.path <target> 

```

### 添加新脚本

要测试新脚本，您只需将它们复制到您的`/scripts`目录，并运行以下命令来更新脚本数据库：

```
# nmap --script-update-db

```

### NSE 脚本类别

+   `auth`：此类别用于与用户身份验证相关的脚本。

+   `broadcast`：这是一个非常有趣的脚本类别，它使用广播请求收集信息。

+   `brute`：此类别用于帮助进行暴力密码审计的脚本。

+   `default`：此类别用于在执行脚本扫描（`-sC`）时执行的脚本。

+   `discovery`：此类别用于与主机和服务发现相关的脚本。

+   `dos`：此类别用于与拒绝服务攻击相关的脚本。

+   `exploit`：此类别用于利用安全漏洞的脚本。

+   `external`：此类别用于依赖于第三方服务的脚本。

+   `fuzzer`：此类别用于专注于模糊测试的 NSE 脚本。

+   `intrusive`：此类别用于可能会导致崩溃或产生大量网络噪音的脚本。系统管理员可能认为具有侵入性的脚本属于此类别。

+   `malware`：此类别用于与恶意软件检测相关的脚本。

+   `safe`：此类别用于在所有情况下都被认为是安全的脚本。

+   `version`：此类别用于高级版本控制的脚本。

+   `vuln`：此类别用于与安全漏洞相关的脚本。

## 另请参阅

+   *使用 Zenmap 管理不同的扫描配置文件*配方

+   *使用 Nmap 和 Ndiff 远程监视服务器*食谱

+   *远程主机的服务指纹识别*食谱

+   *在你的网络中查找活动主机*食谱

+   在第二章的*网络探索*中的*使用广播脚本收集网络信息*食谱

+   在第三章的*收集额外主机信息*中的*收集有效的电子邮件帐户*食谱

+   在第三章的*收集额外主机信息*中的*发现指向相同 IP 的主机名*食谱

+   在第三章的*收集额外主机信息*中的*暴力破解 DNS 记录*食谱

# 使用指定的网络接口进行扫描

Nmap 以其灵活性而闻名，并允许用户在扫描时指定使用的网络接口。当运行一些嗅探器 NSE 脚本、发现你的接口是否支持混杂模式，或者测试具有路由问题的网络连接时，这非常方便。

以下食谱描述了如何强制 Nmap 使用指定的网络接口进行扫描。

## 如何操作...

打开你的终端并输入以下命令：

```
$ nmap -e <INTERFACE> scanme.nmap.org

```

这将强制 Nmap 使用接口`<INTERFACE>`对`scanme.nmap.org`执行 TCP 扫描。

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/nmap6-net-exp-sec-adt-cb/img/7485_01_08.jpg)

## 它是如何工作的...

当 Nmap 无法自动选择一个网络接口时，使用标志**-e**来设置特定的网络接口。该标志的存在允许 Nmap 通过备用接口发送和接收数据包。

## 还有更多...

如果你需要手动选择你的接口，你会看到以下消息：

```
WARNING: Unable to find appropriate interface for system route to ...

```

### 检查 TCP 连接

要检查网络接口是否能与你的网络通信，你可以尝试强制 Nmap 使用指定的接口进行 ping 扫描：

```
$ nmap -sP -e INTERFACE 192.168.1.254 
--------------- Timing report --------------- 
 hostgroups: min 1, max 100000 
 rtt-timeouts: init 1000, min 100, max 10000 
 max-scan-delay: TCP 1000, UDP 1000, SCTP 1000 
 parallelism: min 0, max 0 
 max-retries: 10, host-timeout: 0 
 min-rate: 0, max-rate: 0 
--------------------------------------------- 
Initiating ARP Ping Scan at 02:46 
Scanning 192.168.1.254 [1 port] 
Packet capture filter (device wlan2): arp and arp[18:4] = 0x00C0CA50 and arp[22:2] = 0xE567 
Completed ARP Ping Scan at 02:46, 0.06s elapsed (1 total hosts) 
Overall sending rates: 16.76 packets / s, 704.05 bytes / s. 
mass_rdns: Using DNS server 192.168.1.254 
Initiating Parallel DNS resolution of 1 host. at 02:46 
mass_rdns: 0.03s 0/1 [#: 1, OK: 0, NX: 0, DR: 0, SF: 0, TR: 1] 
Completed Parallel DNS resolution of 1 host. at 02:46, 0.03s elapsed 
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0] 
Nmap scan report for 192.168.1.254 
Host is up, received arp-response (0.0017s latency). 
MAC Address: 5C:4C:A9:F2:DC:7C (Huawei Device Co.) 
Final times for host: srtt: 1731 rttvar: 5000  to: 100000 
Read from /usr/local/bin/../share/nmap: nmap-mac-prefixes nmap-payloads. 
Nmap done: 1 IP address (1 host up) scanned in 0.17 seconds 
 Raw packets sent: 1 (28B) | Rcvd: 1 (28B) 

```

## 另请参阅

+   *运行 NSE 脚本*食谱

+   *使用特定端口范围进行扫描*食谱

+   在第二章的*网络探索*中的*使用额外随机数据隐藏我们的流量*食谱

+   在第二章的*网络探索*中的*强制 DNS 解析*食谱

+   在第二章的*网络探索*中的*排除扫描主机*食谱

+   在第三章的*收集额外主机信息*中的*暴力破解 DNS 记录*食谱

+   在第三章的*收集额外主机信息*中的*识别主机操作系统的指纹识别*食谱

+   在第三章的*收集额外主机信息*中的*发现 UDP 服务*食谱

+   在第三章的*收集额外主机信息*中的*列出远程主机支持的协议*食谱

# 使用 Ndiff 比较扫描结果

Ndiff 旨在解决使用两个 XML 扫描结果进行差异比较的问题。它通过删除误报并生成更易读的输出来比较文件，非常适合需要跟踪扫描结果的人。

这个食谱描述了如何比较两个 Nmap 扫描以检测主机中的变化。

## 准备工作

Ndiff 需要两个 Nmap XML 文件才能工作，所以确保你之前已经保存了同一主机的扫描结果。如果没有，你可以随时扫描你自己的网络，停用一个服务，然后再次扫描以获得这两个测试文件。要将 Nmap 扫描结果保存到 XML 文件中，请使用`-oX <filename>`。

## 如何操作...

1.  打开你的终端。

1.  输入以下命令：

```
$ ndiff FILE1 FILE2

```

1.  输出返回`FILE1`和`FILE2`之间的所有差异。新行显示在加号后。在`FILE2`上删除的行显示在减号后。![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/nmap6-net-exp-sec-adt-cb/img/7485_01_09.jpg)

## 它是如何工作的...

Ndiff 使用第一个文件作为基础来与第二个文件进行比较。它显示主机、端口、服务和操作系统检测的状态差异。

## 还有更多...

如果您喜欢 Zenmap，您可以使用以下步骤：

1.  启动 Zenmap。

1.  单击主工具栏上的**工具**。

1.  单击**比较结果**（*Ctrl* + *D*）。

1.  通过单击**打开**在名为**扫描**的部分中选择第一个文件。

1.  通过单击**打开**在名为**B 扫描**的部分中选择第二个文件。![还有更多...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/nmap6-net-exp-sec-adt-cb/img/7485_01_10.jpg)

### 输出格式

默认情况下返回人类可读的格式。但是，如果需要，Ndiff 可以使用`--xml`标志以 XML 格式返回差异。

### 详细模式

**详细模式**包括所有信息，包括未更改的主机和端口。要使用它，请输入以下命令：

```
$ ndiff -v FILE1 FILE2
$ ndiff –verbose FILE1 FILE2 

```

## 另请参阅

+   *使用 Nmap 和 Ndiff 远程监视服务器*配方

+   *使用 Zenmap 管理多个扫描配置文件*配方

+   *IP 地址地理定位*配方在第三章中，*获取额外的主机信息*

+   *从 WHOIS 记录获取信息*配方在第三章中，*获取额外的主机信息*

+   *指纹识别主机操作系统*配方在第三章中，*获取额外的主机信息*

+   *发现 UDP 服务*配方在第三章中，*获取额外的主机信息*

+   *检测可能的 XST 漏洞*配方在第四章中，*审计 Web 服务器*

# 使用 Zenmap 管理多个扫描配置文件

扫描配置文件是 Nmap 参数的组合，可用于节省时间，并且在启动 Nmap 扫描时无需记住参数名称。

这个配方是关于在 Zenmap 中添加、编辑和删除扫描配置文件。

## 如何操作...

让我们为扫描 Web 服务器添加一个新的配置文件：

1.  启动 Zenmap。

1.  单击主工具栏上的**配置文件**。

1.  单击**新配置文件**或**命令**（*Ctrl* + *P*）。将启动**配置文件编辑器**。

1.  在**配置文件**选项卡上输入配置文件名称和描述。

1.  在**扫描**选项卡上启用**版本检测**，并禁用**反向 DNS 解析**。

1.  在**脚本**选项卡上启用以下脚本：

+   **hostmap**

+   **http-default-accounts**

+   **http-enum**

+   **http-favicon**

+   **http-headers**

+   **http-methods**

+   **http-trace**

+   **http-php-version**

+   **http-robots.txt**

+   **http-title**

1.  接下来，转到**目标**选项卡，单击**端口**以扫描，并输入`80`，`443`。

1.  单击**保存更改**以保存更改。![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/nmap6-net-exp-sec-adt-cb/img/7485_01_11.jpg)

## 它是如何工作的...

在使用编辑器创建配置文件后，我们得到了以下 Nmap 命令：

```
$ nmap -sV -p 80,443 -T4 -n --script http-default-accounts,http-methods,http-php-version,http-robots.txt,http-title,http-trace,http-userdir-enum <target>

```

使用**配置文件**向导，我们已启用服务扫描（`-sV`），将扫描端口设置为`80`和`443`，将**定时**模板设置为`4`，并选择了一堆 HTTP 相关的脚本，以尽可能多地从这个 Web 服务器中收集信息。现在我们已经保存了这个配置文件，可以快速扫描而无需再次输入所有这些标志和选项。

## 还有更多...

Zenmap 包括 10 个预定义的扫描配置文件，以帮助新手熟悉 Nmap。我建议您分析它们，以了解 Nmap 可用的附加扫描技术，以及一些更有用的选项组合。

+   强烈扫描：`nmap -T4 -A -v`

+   强烈扫描加 UDP：`nmap -sS -sU -T4 -A -v`

+   强烈扫描，所有 TCP 端口：`nmap -p 1-65535 -T4 -A -v`

+   强烈扫描，无 ping：`nmap -T4 -A -v -Pn`

+   Ping 扫描：`nmap -sn`

+   快速扫描：`nmap -T4 -F`

+   快速扫描加：`nmap -sV -T4 -O -F –version-light`

+   快速 traceroute：`nmap -sn –traceroute`

+   常规扫描：`nmap`

+   慢速综合扫描：`nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script`默认或发现和安全

### 编辑和删除扫描配置文件

要编辑或删除扫描配置文件，您需要从**配置文件**下拉菜单中选择要修改的条目。单击主工具栏上的**配置文件**，然后选择**编辑所选配置文件**（*Ctrl* + *E*）。

将启动编辑器，允许您编辑或删除所选配置文件。

## 另请参阅

+   列出远程主机上的开放端口的配方

+   远程主机的指纹服务器的配方

+   在您的网络中查找活动主机的配方

+   使用特定端口范围进行扫描的配方

+   运行 NSE 脚本的配方

+   在[第二章]（ch02.html“第二章。网络探索”）中扫描 IPv6 地址的配方，网络探索

+   在[第二章]（ch02.html“第二章。网络探索”）中使用广播脚本收集网络信息的配方，网络探索

+   在[第三章]（ch03.html“第三章。收集其他主机信息”）中查找 UDP 服务的配方，收集其他主机信息

# 使用 Nping 检测 NAT

Nping 旨在用于数据包制作和流量分析，并且非常适用于各种网络任务。

以下配方将介绍 Nping，演示如何借助 Nping Echo 协议执行 NAT 检测。

## 如何做...

打开终端并输入以下命令：

```
# nping --ec "public" -c 1 echo.nmap.org

```

这将导致类似于以下示例的输出流：

Nping 将返回客户端和 Nping 回显服务器`echo.nmap.org`之间的数据包流量：

```
Starting Nping 0.5.59BETA1 ( http://nmap.org/nping ) at 2011-10-27 16:59 PDT 
SENT (1.1453s) ICMP 192.168.1.102 > 74.207.244.221 Echo request (type=8/code=0) ttl=64 id=47754 iplen=28 
CAPT (1.1929s) ICMP 187.136.56.27 > 74.207.244.221 Echo request (type=8/code=0) ttl=57 id=47754 iplen=28 
RCVD (1.2361s) ICMP 74.207.244.221 > 192.168.1.102 Echo reply (type=0/code=0) ttl=53 id=37482 iplen=28 

Max rtt: 90.751ms | Min rtt: 90.751ms | Avg rtt: 90.751ms 
Raw packets sent: 1 (28B) | Rcvd: 1 (46B) | Lost: 0 (0.00%)| Echoed: 1 (28B) 
Tx time: 0.00120s | Tx bytes/s: 23236.51 | Tx pkts/s: 829.88 
Rx time: 1.00130s | Rx bytes/s: 45.94 | Rx pkts/s: 1.00 
Nping done: 1 IP address pinged in 2.23 seconds 

```

注意第一个标记为`SENT`的数据包中的源地址`192.168.1.102`。

```
 SENT (1.1453s) ICMP 192.168.1.102 > 74.207.244.221 Echo request (type=8/code=0) ttl=64 id=47754 iplen=28 

```

将此地址与标记为`CAPT`的第二个数据包中的源地址进行比较。

```
CAPT (1.1929s) ICMP 187.136.56.27 > 74.207.244.221 Echo request (type=8/code=0) ttl=57 id=47754 iplen=28 

```

这些地址不同，表明存在 NAT。

## 它是如何工作的...

Nping 的**回显模式**旨在帮助排除防火墙和路由问题。基本上，它会将接收到的数据包的副本返回给客户端。

命令是：

```
# nping --ec "public" -c 1 echo.nmap.org

```

它使用 Nping 的回显模式（`--ec`或`--echo-client`）来帮助我们分析 Nmap 的 Nping 回显服务器之间的流量，以确定网络中是否存在 NAT 设备。 `–ec`后面的参数对应于服务器知道的秘密密码短语，用于加密和验证会话。

标志`-c`用于指定必须发送多少次数据包的迭代。

## 还有更多...

使用 Nping 生成自定义 TCP 数据包非常简单。例如，要向端口 80 发送 TCP SYN 数据包，请使用以下命令：

```
# nping --tcp -flags syn -p80 -c 1 192.168.1.254

```

这将导致以下输出：

```
SENT (0.0615s) TCP 192.168.1.102:33599 > 192.168.1.254:80 S ttl=64 id=21546 iplen=40  seq=2463610684 win=1480 
RCVD (0.0638s) TCP 192.168.1.254:80 > 192.168.1.102:33599 SA ttl=254 id=30048 iplen=44  seq=457728000 win=1536 <mss 768> 

Max rtt: 2.342ms | Min rtt: 2.342ms | Avg rtt: 2.342ms 
Raw packets sent: 1 (40B) | Rcvd: 1 (46B) | Lost: 0 (0.00%) 
Tx time: 0.00122s | Tx bytes/s: 32894.74 | Tx pkts/s: 822.37 
Rx time: 1.00169s | Rx bytes/s: 45.92 | Rx pkts/s: 1.00 
Nping done: 1 IP address pinged in 1.14 seconds 

```

Nping 是用于流量分析和数据包制作的非常强大的工具。通过使用以下命令，花点时间查看其所有选项：

```
$ nping -h 

```

### Nping Echo 协议

要了解有关 Nping Echo 协议的更多信息，请访问[`nmap.org/svn/nping/docs/EchoProtoRFC.txt`](http://nmap.org/svn/nping/docs/EchoProtoRFC.txt)。

## 另请参阅

+   在您的网络中查找活动主机的配方

+   使用 Ndiff 比较扫描结果的配方

+   使用 Zenmap 管理多个扫描配置文件的配方

+   使用 Nmap 和 Ndiff 远程监视服务器的配方

+   使用广播脚本收集网络信息的配方[第二章]（ch02.html“第二章。网络探索”），网络探索

+   暴力破解 DNS 记录的配方[第三章]（ch03.html“第三章。收集其他主机信息”），收集其他主机信息

+   欺骗端口扫描的源 IP 的配方[第三章]（ch03.html“第三章。收集其他主机信息”），收集其他主机信息

+   使用 Zenmap 生成网络拓扑图的配方[第八章]（ch08.html“第八章。生成扫描报告”），生成扫描报告

# 使用 Nmap 和 Ndiff 远程监视服务器

通过结合 Nmap 项目中的工具，我们可以建立一个简单但强大的监控系统。这可以被系统管理员用来监视 Web 服务器，也可以被渗透测试人员用来监视远程系统。

本配方描述了如何使用 bash 脚本、cron、Nmap 和 Ndiff 设置一个监控系统，如果在网络中检测到变化，系统将通过电子邮件向用户发出警报。

## 如何做...

创建目录`/usr/local/share/nmap-mon/`以存储所有必要的文件。

扫描您的目标主机并将结果保存在您刚刚创建的目录中。

```
# nmap -oX base_results.xml -sV -PN <target>

```

生成的文件`base_results.xml`将被用作您的基本文件，这意味着它应该反映已知的“良好”版本和端口。

将文件`nmap-mon.sh`复制到您的工作目录中。

扫描的输出将如下所示。

```
#!/bin/bash 
#Bash script to email admin when changes are detected in a network using Nmap and Ndiff. 
# 
#Don't forget to adjust the CONFIGURATION variables. 
#Paulino Calderon <calderon@websec.mx> 

# 
#CONFIGURATION 
# 
NETWORK="YOURDOMAIN.COM" 
ADMIN=YOUR@EMAIL.COM 
NMAP_FLAGS="-sV -Pn -p- -T4" 
BASE_PATH=/usr/local/share/nmap-mon/ 
BIN_PATH=/usr/local/bin/ 
BASE_FILE=base.xml 
NDIFF_FILE=ndiff.log 
NEW_RESULTS_FILE=newscanresults.xml 

BASE_RESULTS="$BASE_PATH$BASE_FILE" 
NEW_RESULTS="$BASE_PATH$NEW_RESULTS_FILE" 
NDIFF_RESULTS="$BASE_PATH$NDIFF_FILE" 

if [ -f $BASE_RESULTS ] 
then 
 echo "Checking host $NETWORK" 
 ${BIN_PATH}nmap -oX $NEW_RESULTS $NMAP_FLAGS $NETWORK 
 ${BIN_PATH}ndiff $BASE_RESULTS $NEW_RESULTS > $NDIFF_RESULTS 
 if [ $(cat $NDIFF_RESULTS | wc -l) -gt 0 ] 
 then 
 echo "Network changes detected in $NETWORK" 
 cat $NDIFF_RESULTS 
 echo "Alerting admin $ADMIN" 
 mail -s "Network changes detected in $NETWORK" $ADMIN < $NDIFF_RESULTS 
 fi 
fi 

```

根据您的系统更新配置值。

```
NETWORK="YOURDOMAIN.COM" 
ADMIN=YOUR@EMAIL.COM 
NMAP_FLAGS="-sV -Pn -p- -T4" 
BASE_PATH=/usr/local/share/nmap-mon/ 
BIN_PATH=/usr/local/bin/ 
BASE_FILE=base.xml 
NDIFF_FILE=ndiff.log 
NEW_RESULTS_FILE=newscanresults.xml 

```

通过输入以下命令使`nmap-mon.sh`可执行：

```
# chmod +x /usr/local/share/nmap-mon/nmap-mon.sh 

```

现在，您可以运行脚本`nmap-mon.sh`，以确保它正常工作。

```
# /usr/local/share/nmap-mon/nmap-mon.sh

```

启动您的`crontab`编辑器：

```
# crontab -e 

```

添加以下命令：

```
0 * * * * /usr/local/share/nmap-mon/nmap-mon.sh

```

当 Ndiff 检测到网络中的变化时，您现在应该收到电子邮件警报。

## 它是如何工作的...

Ndiff 是用于比较两次 Nmap 扫描的工具。借助 bash 和 cron 的帮助，我们设置了一个定期执行的任务，以扫描我们的网络并将当前状态与旧状态进行比较，以识别它们之间的差异。

## 还有更多...

您可以通过修改 cron 行来调整扫描之间的间隔：

```
0 * * * * /usr/local/share/nmap-mon/nmap-mon.sh

```

要更新您的基本文件，您只需覆盖位于`/usr/local/share/nmap-mon/`的基本文件。请记住，当我们更改扫描参数以创建基本文件时，我们也需要在`nmap-mon.sh`中更新它们。

### 监视特定服务

要监视某些特定服务，您需要更新`nmap-mon.sh`中的扫描参数。

```
NMAP_FLAGS="-sV -Pn"

```

例如，如果您想监视 Web 服务器，可以使用以下参数：

```
NMAP_FLAGS="-sV --script http-google-safe -Pn -p80,443" 

```

这些参数仅将端口扫描设置为端口`80`和`443`，此外，这些参数还包括脚本`http-google-safe`，以检查您的 Web 服务器是否被 Google 安全浏览服务标记为恶意。

## 另请参阅

+   *列出远程主机上的开放端口*配方

+   *对远程主机的指纹服务进行识别*配方

+   *在您的网络中查找活动主机*配方

+   *运行 NSE 脚本*配方

+   *使用 Ndiff 比较扫描结果*配方

+   第二章中的*使用 ICMP ping 扫描发现主机*配方，*网络探索*

+   第二章中的*扫描 IPv6 地址*配方，*网络探索*

+   第二章中的*使用广播脚本收集网络信息*配方，*网络探索*

+   第三章中的*检查主机是否已知存在恶意活动*配方，*收集额外的主机信息*

+   第三章中的*发现 UDP 服务*配方，*收集额外的主机信息*


# 第二章：网络探测

### 注意

本章将向您展示如何做一些在许多情况下可能是非法、不道德、违反服务条款或不明智的事情。这里提供这些信息是为了让您了解如何保护自己免受威胁，并使自己的系统更加安全。在遵循这些说明之前，请确保您站在法律和道德的一边...善用您的力量！

在本章中，我们将介绍：

+   使用 TCP SYN ping 扫描发现主机

+   使用 TCP ACK ping 扫描发现主机

+   使用 UDP ping 扫描发现主机

+   使用 ICMP ping 扫描发现主机

+   使用 IP 协议 ping 扫描发现主机

+   使用 ARP ping 扫描发现主机

+   使用广播 ping 发现主机

+   使用额外的随机数据隐藏我们的流量

+   强制 DNS 解析

+   从扫描中排除主机

+   扫描 IPv6 地址

+   使用广播脚本收集网络信息

# 介绍

近年来，Nmap 已成为**网络探测**的事实标准工具，远远超越其他扫描器。它之所以受欢迎，是因为具有大量对渗透测试人员和系统管理员有用的功能。它支持应用于主机和服务发现的几种 ping 和端口扫描技术。

受数据包过滤系统（如防火墙或入侵防范系统）保护的主机有时会因为用于阻止某些类型流量的规则而导致错误结果。在这些情况下，Nmap 提供的灵活性是非常宝贵的，因为我们可以轻松尝试替代的主机发现技术（或它们的组合）来克服这些限制。Nmap 还包括一些非常有趣的功能，使我们的流量更不容易引起怀疑。因此，如果您想进行真正全面的扫描，学习如何结合这些功能是必不可少的。

系统管理员将了解不同扫描技术的内部工作原理，并希望激励他们加强流量过滤规则，使其主机更安全。

本章介绍了支持的**ping 扫描技术**—TCP SYN、TCP ACK、UDP、IP、ICMP 和广播。还描述了其他有用的技巧，包括如何强制 DNS 解析、随机化主机顺序、附加随机数据和扫描 IPv6 地址。

不要忘记访问主机发现的参考指南，托管在[`nmap.org/book/man-host-discovery.html`](http://nmap.org/book/man-host-discovery.html)。

# 使用 TCP SYN ping 扫描发现主机

**Ping 扫描**用于检测网络中的活动主机。Nmap 的默认 ping 扫描（`-sP`）使用 TCP ACK 和 ICMP 回显请求来确定主机是否响应，但如果防火墙阻止这些请求，我们将错过这个主机。幸运的是，Nmap 支持一种称为 TCP SYN ping 扫描的扫描技术，在这些情况下非常方便，系统管理员可以对其他防火墙规则更加灵活。

本教程将介绍 TCP SYN ping 扫描及其相关选项。

## 如何做...

打开终端并输入以下命令：

```
$ nmap -sP -PS 192.168.1.1/24

```

您应该看到使用 TCP SYN ping 扫描找到的主机列表：

```
$ nmap -sP -PS 192.168.1.1/24 
Nmap scan report for 192.168.1.101 
Host is up (0.088s latency). 
Nmap scan report for 192.168.1.102 
Host is up (0.000085s latency). 
Nmap scan report for 192.168.1.254 
Host is up (0.0042s latency). 
Nmap done: 256 IP addresses (3 hosts up) scanned in 18.69 seconds 

```

## 工作原理...

参数`-sP`告诉 Nmap 执行 ping 扫描，仅包括发现在线主机。

标志`-PS`强制进行 TCP SYN ping 扫描。这种 ping 扫描的工作方式如下：

+   Nmap 向端口 80 发送 TCP SYN 数据包。

+   如果端口关闭，主机将用 RST 数据包响应。

+   如果端口是开放的，主机将用 TCP SYN/ACK 数据包响应，表示可以建立连接。之后，发送 RST 数据包以重置此连接。

在`192.168.1.1/24`中的 CIDR `/24`用于表示我们要扫描私有网络中的所有 256 个 IP。

## 还有更多...

让我们对一个不响应 ICMP 请求的主机进行 ping 扫描。

```
# nmap -sP 0xdeadbeefcafe.com 

Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn 
Nmap done: 1 IP address (0 hosts up) scanned in 3.14 seconds 

```

主机被标记为离线，但让我们尝试强制进行 TCP SYN ping 扫描：

```
# nmap -sP -PS 0xdeadbeefcafe.com 

Nmap scan report for 0xdeadbeefcafe.com (50.116.1.121) 
Host is up (0.090s latency). 
Nmap done: 1 IP address (1 host up) scanned in 13.24 seconds 

```

这次我们发现这个特定的主机确实在线，但在一个过滤 TCP ACK 或 ICMP 回显请求的系统后面。

### 特权与非特权 TCP SYN ping 扫描

作为无特权用户运行 TCP SYN ping 扫描，无法发送原始数据包，使 Nmap 使用系统调用`connect()`发送 TCP SYN 数据包。在这种情况下，当函数成功返回时，Nmap 区分 SYN/ACK 数据包，当它收到 ECONNREFUSED 错误消息时，它区分 RST 数据包。

### 防火墙和流量过滤器

在 TCP SYN ping 扫描期间，Nmap 使用 SYN/ACK 和 RST 响应来确定主机是否响应。重要的是要注意，有防火墙配置为丢弃 RST 数据包。在这种情况下，除非我们指定一个开放的端口，否则 TCP SYN ping 扫描将失败：

```
$ nmap -sP -PS80 <target>

```

您可以使用`-PS`（端口列表或范围）设置要使用的端口列表如下：

```
$ nmap -sP -PS80,21,53 <target>
$ nmap -sP -PS1-1000 <target>
$ nmap -sP -PS80,100-1000 <target>

```

## 另请参阅

+   在第一章中的* Nmap 基础知识*中的*在您的网络中查找活动主机*方法

+   使用 TCP ACK ping 扫描发现主机的方法

+   使用 UDP ping 扫描发现主机的方法

+   使用 ICMP ping 扫描发现主机的方法

+   使用 IP 协议 ping 扫描发现主机的方法

+   使用 ARP ping 扫描发现主机的方法

+   使用广播 ping 发现主机的方法

+   在第三章中的*使用 TCP ACK 扫描发现有状态防火墙*方法，*收集其他主机信息*

# 使用 TCP ACK ping 扫描发现主机

与 TCP SYN ping 扫描类似，TCP ACK ping 扫描用于确定主机是否响应。它可以用于检测阻止 SYN 数据包或 ICMP 回显请求的主机，但是现代防火墙跟踪连接状态，因此很可能会被阻止。

以下方法显示了如何执行 TCP ACK ping 扫描及其相关选项。

## 如何做到...

在终端中输入以下命令：

```
# nmap -sP -PA <target>

```

## 它是如何工作的...

TCP ACK ping 扫描的工作方式如下：

+   Nmap 发送一个带有 ACK 标志设置为端口 80 的空 TCP 数据包

+   如果主机离线，它不应该对此请求做出响应

+   如果主机在线，它会返回一个 RST 数据包，因为连接不存在

## 还有更多...

重要的是要理解，有时这种技术不起作用。让我们对其中一个主机进行 TCP ACK ping 扫描。

```
# nmap -sP -PA 0xdeadbeefcafe.com 

Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn 
Nmap done: 1 IP address (0 hosts up) scanned in 3.14 seconds 

```

主机显示为离线，但让我们尝试使用相同的主机进行 TCP SYN ping 扫描。

```
# nmap -sP -PS 0xdeadbeefcafe.com 

Nmap scan report for 0xdeadbeefcafe.com (50.116.1.121) 
Host is up (0.090s latency). 
Nmap done: 1 IP address (1 host up) scanned in 13.24 seconds 

```

我们发现主机在线，但阻止了 ACK 数据包。

### 特权与非特权 TCP ACK ping 扫描

TCP ACK ping 扫描需要以特权用户身份运行，否则将使用系统调用`connect()`发送一个空的 TCP SYN 数据包。因此，TCP ACK ping 扫描将不使用先前讨论的 TCP ACK 技术作为非特权用户，并且将执行 TCP SYN ping 扫描。

### 在 TCP ACK ping 扫描中选择端口

此外，您可以通过在标志`-PA`后列出它们来选择要使用此技术进行探测的端口：

```
# nmap -sP -PA21,22,80 <target>
# nmap -sP -PA80-150 <target>
# nmap -sP -PA22,1000-65535 <target>

```

## 另请参阅

+   在第一章中的* Nmap 基础知识*中的*在您的网络中查找活动主机*方法

+   使用 TCP SYN ping 扫描发现主机的方法

+   使用 UDP ping 扫描发现主机的方法

+   使用 ICMP ping 扫描发现主机的方法

+   使用 ARP ping 扫描发现主机的方法

+   使用 ARP ping 扫描发现主机的方法

+   使用广播 ping 发现主机的方法

+   在第三章中的*使用 TCP ACK 扫描发现有状态防火墙*方法，*收集其他主机信息*

# 使用 UDP ping 扫描发现主机

Ping 扫描用于确定主机是否响应并且可以被视为在线。UDP ping 扫描具有检测严格 TCP 过滤防火墙后面的系统的优势，使 UDP 流量被遗忘。

下一个配方描述了如何使用 Nmap 执行 UDP ping 扫描以及其相关选项。

## 如何做到...

打开终端并输入以下命令：

```
# nmap -sP -PU <target>

```

Nmap 将使用这种技术确定`<target>`是否可达。

```
# nmap -sP -PU scanme.nmap.org 

Nmap scan report for scanme.nmap.org (74.207.244.221) 
Host is up (0.089s latency). 
Nmap done: 1 IP address (1 host up) scanned in 13.25 seconds 

```

## 工作原理...

UDP ping 扫描使用的技术如下：

+   Nmap 向端口 31 和 338 发送一个空的 UDP 数据包

+   如果主机响应，应返回 ICMP 端口不可达错误

+   如果主机离线，可能会返回各种 ICMP 错误消息

## 还有更多...

不响应空 UDP 数据包的服务在探测时会产生误报。这些服务将简单地忽略 UDP 数据包，并且主机将被错误地标记为离线。因此，重要的是我们选择可能关闭的端口。

### 在 UDP ping 扫描中选择端口

要指定要探测的端口，请在标志`-PU`后添加它们，`如下`：

```
# nmap -sP -PU1337,11111 scanme.nmap.org

```

## 另请参阅

+   第一章中的*在您的网络中查找活动主机*配方，*Nmap 基础*

+   *使用 TCP SYN ping 扫描发现主机*配方

+   *使用 TCP ACK ping 扫描发现主机*配方

+   *使用 ICMP ping 扫描发现主机*配方

+   *使用 IP 协议 ping 扫描发现主机*配方

+   *使用 ARP ping 扫描发现主机*配方

+   *使用广播 ping 发现主机*配方

+   第三章中的*使用 TCP ACK 扫描发现有状态防火墙*配方，*收集额外主机信息*

# 使用 ICMP ping 扫描发现主机

Ping 扫描用于确定主机是否在线和响应。ICMP 消息用于此目的，因此 ICMP ping 扫描使用这些类型的数据包来完成此操作。

以下配方描述了如何使用 Nmap 执行 ICMP ping 扫描，以及不同类型的 ICMP 消息的标志。

## 如何做到...

要发出 ICMP 回显请求，请打开终端并输入以下命令：

```
# nmap -sP -PE scanme.nmap.org

```

如果主机响应，您应该看到类似于这样的内容：

```
# nmap -sP -PE scanme.nmap.org 

Nmap scan report for scanme.nmap.org (74.207.244.221) 
Host is up (0.089s latency). 
Nmap done: 1 IP address (1 host up) scanned in 13.25 seconds 

```

## 工作原理...

参数`-sP -PE scanme.nmap.org`告诉 Nmap 向主机`scanme.nmap.org`发送 ICMP 回显请求数据包。如果我们收到对此探测的 ICMP 回显回复，我们可以确定主机是在线的。

```
SENT (0.0775s) ICMP 192.168.1.102 > 74.207.244.221 Echo request (type=8/code=0) ttl=56 id=58419 iplen=28 
RCVD (0.1671s) ICMP 74.207.244.221 > 192.168.1.102 Echo reply (type=0/code=0) ttl=53 id=24879 iplen=28 
Nmap scan report for scanme.nmap.org (74.207.244.221) 
Host is up (0.090s latency). 
Nmap done: 1 IP address (1 host up) scanned in 0.23 seconds 

```

## 还有更多...

不幸的是，ICMP 已经存在了相当长的时间，远程 ICMP 数据包现在通常被系统管理员阻止。但是，对于监视本地网络来说，它仍然是一种有用的 ping 技术。

### ICMP 类型

还有其他可以用于主机发现的 ICMP 消息，Nmap 支持 ICMP 时间戳回复（`-PP`）和地址标记回复（`-PM`）。这些变体可以绕过错误配置的仅阻止 ICMP 回显请求的防火墙。

```
$ nmap -sP -PP <target>
$ nmap -sP -PM <target>

```

## 另请参阅

+   第一章中的*在您的网络中查找活动主机*配方，*Nmap 基础*

+   *使用 TCP SYN ping 扫描发现主机*配方

+   *使用 TCP ACK ping 扫描发现主机*配方

+   *使用 UDP ping 扫描发现主机*配方

+   *使用 IP 协议 ping 扫描发现主机*配方

+   *使用 ARP ping 扫描发现主机*配方

+   *使用广播 ping 发现主机*配方

+   第三章中的*使用 TCP ACK 扫描发现有状态防火墙*配方，*收集额外主机信息*

# 使用 IP 协议 ping 扫描发现主机

Ping 扫描对主机发现非常重要。系统管理员和渗透测试人员使用它们来确定哪些主机是在线的并且做出了响应。Nmap 实现了几种 ping 扫描技术，包括一种称为 IP 协议 ping 扫描的技术。这种技术尝试使用不同的 IP 协议发送不同的数据包，希望得到一个表明主机在线的响应。

这个方法描述了如何执行 IP 协议 ping 扫描。

## 如何操作...

打开你喜欢的终端并输入以下命令：

```
# nmap -sP -PO scanme.nmap.org

```

如果主机对任何请求做出了响应，你应该会看到类似下面的内容：

```
# nmap -sP -PO scanme.nmap.org 
Nmap scan report for scanme.nmap.org (74.207.244.221) 
Host is up (0.091s latency). 
Nmap done: 1 IP address (1 host up) scanned in 13.25 seconds 

```

## 工作原理...

参数`-sP -PO scanme.nmap.org`告诉 Nmap 对主机`scanme.nmap.org`执行 IP 协议 ping 扫描。

默认情况下，这种 ping 扫描将使用 IGMP、IP-in-IP 和 ICMP 协议来尝试获得表明主机在线的响应。使用`--packet-trace`将显示更多发生在幕后的细节：

```
# nmap -sP -PO --packet-trace scanme.nmap.org 

SENT (0.0775s) ICMP 192.168.1.102 > 74.207.244.221 Echo request (type=8/code=0) ttl=52 id=8846 iplen=28 
SENT (0.0776s) IGMP (2) 192.168.1.102 > 74.207.244.221: ttl=38 id=55049 iplen=28 
SENT (0.0776s) IP (4) 192.168.1.102 > 74.207.244.221: ttl=38 id=49338 iplen=20 
RCVD (0.1679s) ICMP 74.207.244.221 > 192.168.1.102 Echo reply (type=0/code=0) ttl=53 id=63986 iplen=28 
NSOCK (0.2290s) UDP connection requested to 192.168.1.254:53 (IOD #1) EID 8 
NSOCK (0.2290s) Read request from IOD #1 [192.168.1.254:53] (timeout: -1ms) EID 18 
NSOCK (0.2290s) Write request for 45 bytes to IOD #1 EID 27 [192.168.1.254:53]: .............221.244.207.74.in-addr.arpa..... 
NSOCK (0.2290s) Callback: CONNECT SUCCESS for EID 8 [192.168.1.254:53] 
NSOCK (0.2290s) Callback: WRITE SUCCESS for EID 27 [192.168.1.254:53] 
NSOCK (4.2300s) Write request for 45 bytes to IOD #1 EID 35 [192.168.1.254:53]: .............221.244.207.74.in-addr.arpa..... 
NSOCK (4.2300s) Callback: WRITE SUCCESS for EID 35 [192.168.1.254:53] 
NSOCK (8.2310s) Write request for 45 bytes to IOD #1 EID 43 [192.168.1.254:53]: .............221.244.207.74.in-addr.arpa..... 
NSOCK (8.2310s) Callback: WRITE SUCCESS for EID 43 [192.168.1.254:53] 
Nmap scan report for scanme.nmap.org (74.207.244.221) 
Host is up (0.090s latency). 
Nmap done: 1 IP address (1 host up) scanned in 13.23 seconds 

```

标记为`SENT`的三行显示了 ICMP、IGMP 和 IP-in-IP 数据包：

```
SENT (0.0775s) ICMP 192.168.1.102 > 74.207.244.221 Echo request (type=8/code=0) ttl=52 id=8846 iplen=28 
SENT (0.0776s) IGMP (2) 192.168.1.102 > 74.207.244.221: ttl=38 id=55049 iplen=28 
SENT (0.0776s) IP (4) 192.168.1.102 > 74.207.244.221: ttl=38 id=49338 iplen=20 

```

在这三个中，只有 ICMP 做出了响应：

```
RCVD (0.1679s) ICMP 74.207.244.221 > 192.168.1.102 Echo reply (type=0/code=0) ttl=53 id=63986 iplen=28 

```

然而，这足以表明这个主机是在线的。

## 更多内容...

你也可以通过在选项`-PO`后列出它们来设置要使用的 IP 协议。例如，要使用 ICMP（协议编号 1）、IGMP（协议编号 2）和 UDP（协议编号 17）协议，可以使用以下命令：

```
# nmap -sP -PO1,2,4 scanme.nmap.org

```

使用这种技术发送的所有数据包都是空的。请记住，你可以生成随机数据来与这些数据包一起使用，使用选项`--data-length`：

```
# nmap -sP -PO --data-length 100 scanme.nmap.org

```

### 支持的 IP 协议及其有效负载

当使用时，设置所有协议头的协议是：

+   TCP：协议编号 6

+   UDP：协议编号 17

+   ICMP：协议编号 1

+   IGMP：协议编号 2

对于其他 IP 协议中的任何一个，将发送一个只有 IP 头的数据包。

## 另请参阅

+   在第一章的*在你的网络中找到活动主机*的方法，*Nmap 基础知识*

+   *使用 TCP SYN ping 扫描发现主机*的方法

+   *使用 TCP ACK ping 扫描发现主机*的方法

+   *使用 UDP ping 扫描发现主机*的方法

+   *使用 ICMP ping 扫描发现主机*的方法

+   *使用 ARP ping 扫描发现主机*的方法

+   *使用广播 ping 发现主机*的方法

+   在第三章的*使用 TCP ACK 扫描发现有状态防火墙*的方法，*收集额外的主机信息*

# 使用 ARP ping 扫描发现主机

渗透测试人员和系统管理员使用 ping 扫描来确定主机是否在线。ARP ping 扫描是在局域网中检测主机的最有效方法。

Nmap 通过使用自己的算法来优化这种扫描技术而真正发光。以下方法将介绍启动 ARP ping 扫描及其可用选项的过程。

## 如何操作...

打开你喜欢的终端并输入以下命令：

```
# nmap -sP -PR 192.168.1.1/24 

```

你应该看到对 ARP 请求做出响应的主机列表：

```
# nmap -sP -PR 192.168.1.1/24 

Nmap scan report for 192.168.1.102 
Host is up. 
Nmap scan report for 192.168.1.103 
Host is up (0.0066s latency). 
MAC Address: 00:16:6F:7E:E0:B6 (Intel) 
Nmap scan report for 192.168.1.254 
Host is up (0.0039s latency). 
MAC Address: 5C:4C:A9:F2:DC:7C (Huawei Device Co.) 
Nmap done: 256 IP addresses (3 hosts up) scanned in 14.94 seconds 

```

## 工作原理...

参数`-sP -PR 192.168.1.1/24`使 Nmap 对这个私有网络中的所有 256 个 IP（CIDR /24）进行 ARP ping 扫描。

**ARP ping 扫描**的工作方式非常简单：

+   ARP 请求被发送到目标

+   如果主机以 ARP 回复做出响应，那么很明显它是在线的

要发送 ARP 请求，使用以下命令：

```
# nmap -sP -PR --packet-trace 192.168.1.254 

```

这个命令的结果将如下所示：

```
SENT (0.0734s) ARP who-has 192.168.1.254 tell 192.168.1.102 
RCVD (0.0842s) ARP reply 192.168.1.254 is-at 5C:4C:A9:F2:DC:7C 
NSOCK (0.1120s) UDP connection requested to 192.168.1.254:53 (IOD #1) EID 8 
NSOCK (0.1120s) Read request from IOD #1 [192.168.1.254:53] (timeout: -1ms) EID 18 
NSOCK (0.1120s) Write request for 44 bytes to IOD #1 EID 27 [192.168.1.254:53]: .............254.1.168.192.in-addr.arpa..... 
NSOCK (0.1120s) Callback: CONNECT SUCCESS for EID 8 [192.168.1.254:53] 
NSOCK (0.1120s) Callback: WRITE SUCCESS for EID 27 [192.168.1.254:53] 
NSOCK (0.2030s) Callback: READ SUCCESS for EID 18 [192.168.1.254:53] (44 bytes): .............254.1.168.192.in-addr.arpa..... 
NSOCK (0.2030s) Read request from IOD #1 [192.168.1.254:53] (timeout: -1ms) EID 34 
Nmap scan report for 192.168.1.254 
Host is up (0.011s latency). 
MAC Address: 5C:4C:A9:F2:DC:7C (Huawei Device Co.) 
Nmap done: 1 IP address (1 host up) scanned in 0.22 seconds 

```

注意扫描输出开头的 ARP 请求：

```
SENT (0.0734s) ARP who-has 192.168.1.254 tell 192.168.1.102 
RCVD (0.0842s) ARP reply 192.168.1.254 is-at 5C:4C:A9:F2:DC:7C 

```

ARP 回复显示主机`192.168.1.254`在线，并且具有 MAC 地址`5C:4C:A9:F2:DC:7C`。

## 更多内容...

每次 Nmap 扫描私有地址时，都必须不可避免地进行 ARP 请求，因为在发送任何探测之前，我们需要目标的目的地。由于 ARP 回复显示主机在线，因此在此步骤之后实际上不需要进行进一步的测试。这就是为什么 Nmap 在私有 LAN 网络中执行 ping 扫描时每次都会自动使用这种技术的原因，无论传递了什么参数：

```
# nmap -sP -PS --packet-trace 192.168.1.254 

SENT (0.0609s) ARP who-has 192.168.1.254 tell 192.168.1.102 
RCVD (0.0628s) ARP reply 192.168.1.254 is-at 5C:4C:A9:F2:DC:7C 
NSOCK (0.1370s) UDP connection requested to 192.168.1.254:53 (IOD #1) EID 8 
NSOCK (0.1370s) Read request from IOD #1 [192.168.1.254:53] (timeout: -1ms) EID 18 
NSOCK (0.1370s) Write request for 44 bytes to IOD #1 EID 27 [192.168.1.254:53]: 1............254.1.168.192.in-addr.arpa..... 
NSOCK (0.1370s) Callback: CONNECT SUCCESS for EID 8 [192.168.1.254:53] 
NSOCK (0.1370s) Callback: WRITE SUCCESS for EID 27 [192.168.1.254:53] 
NSOCK (0.1630s) Callback: READ SUCCESS for EID 18 [192.168.1.254:53] (44 bytes): 1............254.1.168.192.in-addr.arpa..... 
NSOCK (0.1630s) Read request from IOD #1 [192.168.1.254:53] (timeout: -1ms) EID 34 
Nmap scan report for 192.168.1.254 
Host is up (0.0019s latency). 
MAC Address: 5C:4C:A9:F2:DC:7C (Huawei Device Co.) 
Nmap done: 1 IP address (1 host up) scanned in 0.18 seconds 

```

要强制 Nmap 在扫描私有地址时不执行 ARP ping 扫描，请使用选项`--send-ip`。这将产生类似以下的输出：

```
# nmap -sP -PS --packet-trace --send-ip 192.168.1.254 

SENT (0.0574s) TCP 192.168.1.102:63897 > 192.168.1.254:80 S ttl=53 id=435 iplen=44  seq=128225976 win=1024 <mss 1460> 
RCVD (0.0592s) TCP 192.168.1.254:80 > 192.168.1.102:63897 SA ttl=254 id=3229 iplen=44  seq=4067819520 win=1536 <mss 768> 
NSOCK (0.1360s) UDP connection requested to 192.168.1.254:53 (IOD #1) EID 8 
NSOCK (0.1360s) Read request from IOD #1 [192.168.1.254:53] (timeout: -1ms) EID 18 
NSOCK (0.1360s) Write request for 44 bytes to IOD #1 EID 27 [192.168.1.254:53]: d~...........254.1.168.192.in-addr.arpa..... 
NSOCK (0.1360s) Callback: CONNECT SUCCESS for EID 8 [192.168.1.254:53] 
NSOCK (0.1360s) Callback: WRITE SUCCESS for EID 27 [192.168.1.254:53] 
NSOCK (0.1610s) Callback: READ SUCCESS for EID 18 [192.168.1.254:53] (44 bytes): d~...........254.1.168.192.in-addr.arpa..... 
NSOCK (0.1610s) Read request from IOD #1 [192.168.1.254:53] (timeout: -1ms) EID 34 
Nmap scan report for 192.168.1.254 
Host is up (0.0019s latency). 
MAC Address: 5C:4C:A9:F2:DC:7C (Huawei Device Co.) 
Nmap done: 1 IP address (1 host up) scanned in 0.17 seconds 

```

### MAC 地址欺骗

在执行 ARP ping 扫描时可以伪造 MAC 地址。使用`--spoof-mac`设置新的 MAC 地址：

```
# nmap -sP -PR --spoof-mac 5C:4C:A9:F2:DC:7C

```

## 另请参阅

+   第一章中的*在您的网络中查找活动主机*的方法，*Nmap 基础*

+   *使用 TCP SYN ping 扫描发现主机*的方法

+   *使用 TCP ACK ping 扫描发现主机*的方法

+   *使用 UDP ping 扫描发现主机*的方法

+   *使用 ICMP ping 扫描发现主机*的方法

+   *使用 IP 协议 ping 扫描发现主机*的方法

+   *使用广播 ping 发现主机*的方法

+   第三章中的*使用 TCP ACK 扫描发现有状态防火墙*的方法，*收集额外的主机信息*

# 使用广播 ping 发现主机

**广播 ping**将 ICMP 回显请求发送到本地广播地址，即使它们并非始终有效，它们也是在网络中发现主机的一种不错的方式，而无需向其他主机发送探测。

本方法描述了如何使用 Nmap NSE 通过广播 ping 发现新主机。

## 如何做...

打开您的终端并输入以下命令：

```
# nmap --script broadcast-ping 

```

您应该看到响应广播 ping 的主机列表：

```
Pre-scan script results: 
| broadcast-ping: 
|   IP: 192.168.1.105  MAC: 08:00:27:16:4f:71 
|   IP: 192.168.1.106  MAC: 40:25:c2:3f:c7:24 
|_  Use --script-args=newtargets to add the results as targets 
WARNING: No targets were specified, so 0 hosts scanned. 
Nmap done: 0 IP addresses (0 hosts up) scanned in 3.25 seconds 

```

## 它是如何工作的...

广播 ping 通过向本地广播地址`255.255.255.255`发送 ICMP 回显请求，然后等待主机以 ICMP 回显回复进行回复。它产生类似以下的输出：。

```
# nmap --script broadcast-ping --packet-trace 

NSOCK (0.1000s) PCAP requested on device 'wlan2' with berkeley filter 'dst host 192.168.1.102 and icmp[icmptype]==icmp-echoreply' (promisc=0 snaplen=104 to_ms=200) (IOD #1) 
NSOCK (0.1000s) PCAP created successfully on device 'wlan2' (pcap_desc=4 bsd_hack=0 to_valid=1 l3_offset=14) (IOD #1) 
NSOCK (0.1000s) Pcap read request from IOD #1  EID 13 
NSOCK (0.1820s) Callback: READ-PCAP SUCCESS for EID 13 
NSOCK (0.1820s) Pcap read request from IOD #1  EID 21 
NSOCK (0.1850s) Callback: READ-PCAP SUCCESS for EID 21 
NSOCK (0.1850s) Pcap read request from IOD #1  EID 29 
NSOCK (3.1850s) Callback: READ-PCAP TIMEOUT for EID 29 
NSE: > | CLOSE 
Pre-scan script results: 
| broadcast-ping: 
|   IP: 192.168.1.105  MAC: 08:00:27:16:4f:71 
|   IP: 192.168.1.106  MAC: 40:25:c2:3f:c7:24 
|_  Use --script-args=newtargets to add the results as targets 
WARNING: No targets were specified, so 0 hosts scanned. 
Nmap done: 0 IP addresses (0 hosts up) scanned in 3.27 seconds 

```

## 还有更多...

要增加 ICMP 回显请求的数量，请使用脚本参数`broadcast-ping.num_probes`：

```
# nmap --script broadcast-ping --script-args broadcast-ping.num_probes=5

```

在扫描大型网络时，通过使用`--script-args broadcast-ping.timeout=<time in ms>`来增加超时限制可能是有用的，以避免错过具有较差延迟的主机。

```
# nmap --script broadcast-ping --script-args broadcast-ping.timeout=10000

```

您可以使用`broadcast-ping.interface`指定网络接口。如果不指定接口，`broadcast-ping`将使用所有具有 IPv4 地址的接口发送探测。

```
# nmap --script broadcast-ping --script-args broadcast-ping.interface=wlan3

```

### 目标库

参数`--script-args=newtargets`强制 Nmap 将这些新发现的主机用作目标：

```
# nmap --script broadcast-ping --script-args newtargets 
Pre-scan script results: 
| broadcast-ping: 
|   IP: 192.168.1.105  MAC: 08:00:27:16:4f:71 
|_  IP: 192.168.1.106  MAC: 40:25:c2:3f:c7:24 
Nmap scan report for 192.168.1.105 
Host is up (0.00022s latency). 
Not shown: 997 closed ports 
PORT    STATE SERVICE 
22/tcp  open  ssh 
80/tcp  open  http 
111/tcp open  rpcbind 
MAC Address: 08:00:27:16:4F:71 (Cadmus Computer Systems) 

Nmap scan report for 192.168.1.106 
Host is up (0.49s latency). 
Not shown: 999 closed ports 
PORT   STATE SERVICE 
80/tcp open  http 
MAC Address: 40:25:C2:3F:C7:24 (Intel Corporate) 

Nmap done: 2 IP addresses (2 hosts up) scanned in 7.25 seconds 

```

请注意，我们没有指定目标，但`newtargets`参数仍然将 IP `192.168.1.106`和`192.168.1.105`添加到扫描队列中。

参数`max-newtargets`设置要添加到扫描队列中的主机的最大数量：

```
# nmap --script broadcast-ping --script-args max-newtargets=3

```

## 另请参阅

+   第一章中的*在您的网络中查找活动主机*的方法，*Nmap 基础*

+   *使用 TCP SYN ping 扫描发现主机*的方法

+   *使用 TCP ACK ping 扫描发现主机*的方法

+   *使用 UDP ping 扫描发现主机*的方法

+   *使用 ICMP ping 扫描发现主机*的方法

+   *使用 IP 协议 ping 扫描发现主机*的方法

+   *使用 ARP ping 扫描发现主机*的方法

+   第三章中的*使用 TCP ACK 扫描发现有状态防火墙*的方法，*收集额外的主机信息*

# 使用额外的随机数据隐藏我们的流量

Nmap 扫描生成的数据包通常只设置协议头，并且只在某些情况下包含特定的有效负载。Nmap 实现了一个功能，通过使用随机数据作为有效负载来减少检测这些已知探测的可能性。

本方法描述了如何在扫描期间由 Nmap 发送的数据包中发送额外的随机数据。

## 如何做...

要附加 300 字节的随机数据，请打开终端并输入以下命令：

```
# nmap -sS -PS --data-length 300 scanme.nmap.org

```

## 它是如何工作的...

参数`--data-length <# of bytes>`告诉 Nmap 生成随机字节并将其附加为请求中的数据。

大多数扫描技术都支持这种方法，但重要的是要注意，使用此参数会减慢扫描速度，因为我们需要在每个请求中传输更多的数据。

在以下屏幕截图中，显示了由默认 Nmap 扫描生成的数据包，以及我们使用参数`--data-length`的数据包：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/nmap6-net-exp-sec-adt-cb/img/7485_02_01.jpg)

## 还有更多...

将参数`--data-length`设置为`0`将强制 Nmap 在请求中不使用任何有效负载：

```
# nmap --data-length 0 scanme.nmap.org

```

## 另请参阅

+   第一章的*使用特定端口范围进行扫描*配方，*Nmap 基础*

+   在第三章的*欺骗端口扫描源 IP*配方中，*收集额外的主机信息*

+   *强制 DNS 解析*配方

+   *从扫描中排除主机*配方

+   *扫描 IPv6 地址*配方

+   第七章的*跳过测试以加快长时间扫描*配方，*扫描大型网络*

+   第七章的*调整时间参数*配方，*扫描大型网络*

+   第七章的*选择正确的时间模板*配方，*扫描大型网络*

# 强制 DNS 解析

DNS 名称经常透露有价值的信息，因为系统管理员根据其功能为主机命名，例如`firewall`或`mail.domain.com`。默认情况下，如果主机离线，Nmap 不执行 DNS 解析。通过强制 DNS 解析，即使主机似乎处于离线状态，我们也可以收集有关网络的额外信息。

该配方描述了如何在 Nmap 扫描期间强制对离线主机进行 DNS 解析。

## 如何做到...

打开终端并输入以下命令：

```
# nmap -sS -PS -F -R XX.XXX.XXX.220-230

```

此命令将强制对范围`XX.XXX.XXX.220-230`中的离线主机进行 DNS 解析。

考虑使用列表扫描，它也将执行 DNS 解析，分别为`-sL`。

是的，列表扫描会这样做。我在这里要传达的是，您可以在端口扫描期间或运行 NSE 脚本时包含主机的 DNS 信息。

## 它是如何工作的...

参数`-sS -PS -F -R`告诉 Nmap 执行 TCP SYN Stealth (`-sS`)、SYN ping (`-PS`)、快速端口扫描 (`-F`)，并始终执行 DNS 解析 (`-R`)。

假设我们想要扫描围绕域`0xdeadbeefcafe.com`的两个 IP，IP 为`XX.XXX.XXX.223`，可以使用以下命令：

```
# nmap -sS -PS -F -R XX.XXX.XXX.222-224
Nmap scan report for liXX-XXX.members.linode.com (XX.XXX.XXX.222) 
Host is up (0.11s latency). 
All 100 scanned ports on liXX-XXX.members.linode.com (XX.XXX.XXX.222) are filtered 

Nmap scan report for 0xdeadbeefcafe.com (XX.XXX.XXX.223) 
Host is up (0.11s latency). 
Not shown: 96 closed ports 
PORT    STATE    SERVICE 
22/tcp  open     ssh 
25/tcp  open smtp 

Nmap scan report for mail.0xdeadbeefcafe.com (XX.XXX.XXX.224) 
Host is up (0.11s latency). 
Not shown: 96 closed ports 
PORT    STATE    SERVICE 
25/tcp  filtered     smtp

```

在这种情况下，快速扫描告诉我们，这可能是 Linode 托管的 VPS，并且也是他们邮件服务器的位置。

## 还有更多...

您还可以使用参数`-n`完全禁用 DNS 解析。这会加快扫描速度，如果您不需要对主机进行 DNS 解析，则非常推荐使用。

```
# nmap -sS -PS -F -n scanme.nmap.org

```

### 指定不同的 DNS 名称服务器

默认情况下，Nmap 会查询系统的 DNS 服务器进行 DNS 解析。可以使用参数`--dns-servers`设置替代 DNS 名称服务器。例如，要使用 Google 的开放 DNS 服务器：

```
# nmap -sS -PS -R --dns-servers 8.8.8.8,8.8.4.4 <target>

```

## 另请参阅

+   *使用额外的随机数据隐藏我们的流量*配方

+   第一章的*使用特定端口范围进行扫描*配方，*Nmap 基础*

+   第三章的*欺骗端口扫描源 IP*配方，*收集额外的主机信息*

+   *从扫描中排除主机*配方

+   *扫描 IPv6 地址*配方

+   第七章的*跳过测试以加快长时间扫描*配方，*扫描大型网络*

+   第七章中的*调整时间参数*食谱，*扫描大型网络*

+   第七章中的*选择正确的时间模板*食谱，*扫描大型网络*

# 从扫描中排除主机

将出现需要**排除主机**的情况，以避免扫描某些机器。例如，您可能缺乏授权，或者可能主机已经被扫描，您想节省一些时间。Nmap 实现了一个选项来排除一个主机或主机列表，以帮助您在这些情况下。

本食谱描述了如何从 Nmap 扫描中排除主机。

## 如何做...

打开您的终端并输入以下命令：

```
# nmap -sV -O --exclude 192.168.1.102,192.168.1.254 192.168.1.1/24

```

您应该看到私人网络`192.168.1.1-255`中所有可用主机的扫描结果，排除了 IP`192.168.1.254`和`192.168.1.102`，如下例所示：

```
# nmap -sV -O --exclude 192.168.1.102,192.168.1.254 192.168.1.1/24 

Nmap scan report for 192.168.1.101 
Host is up (0.019s latency). 
Not shown: 996 closed ports 
PORT     STATE    SERVICE VERSION 
21/tcp   filtered ftp 
53/tcp   filtered domain 
554/tcp  filtered rtsp 
3306/tcp filtered mysql 
MAC Address: 00:23:76:CD:C5:BE (HTC) 
Too many fingerprints match this host to give specific OS details 
Network Distance: 1 hop 

OS and Service detection performed. Please report any incorrect results at http://nmap.org/submit/ . 
Nmap done: 254 IP addresses (1 host up) scanned in 18.19 seconds 

```

## 它是如何工作的...

参数`-sV -O --exclude 192.168.1.102,192.168.1.254 192.168.1.1/1`告诉 Nmap 执行服务检测扫描(`-sV`)和所有 256 个 IP 的 OS 指纹识别(`-O`)在这个私人网络中的(`192.168.1.1/24`)，分别排除了 IP 为`192.168.102`和`192.168.1.254`的机器(`--exclude 192.168.1.102,192.168.1.254`)。

## 还有更多...

参数`--exclude`也支持 IP 范围，如下例所示：

```
# nmap -sV -O --exclude 192.168.1-100 192.168.1.1/24 
# nmap -sV -O --exclude 192.168.1.1,192.168.1.10-20 192.168.1.1/24

```

### 从您的扫描中排除主机列表

Nmap 还支持参数`--exclude-file <filename>`，以排除列在`<filename>`中的目标：

```
# nmap -sV -O --exclude-file dontscan.txt 192.168.1.1/24

```

## 另请参阅

+   *使用额外的随机数据隐藏我们的流量*食谱

+   *强制 DNS 解析*食谱

+   *扫描 IPv6 地址*食谱

+   *使用广播脚本收集网络信息*食谱

+   第一章中的*使用特定端口范围进行扫描*食谱，*Nmap 基础*

+   第三章中的*欺骗端口扫描的源 IP*食谱，*收集额外的主机信息*

+   *从您的扫描中排除主机*食谱

+   第七章中的*跳过测试以加快长时间扫描*食谱，*扫描大型网络*

+   第七章中的*调整时间参数*食谱，*扫描大型网络*

+   第七章中的*选择正确的时间模板*食谱，*扫描大型网络*

# 扫描 IPv6 地址

尽管我们并没有像一些人预测的那样耗尽所有 IPv4 地址，但 IPv6 地址正在变得更加普遍，Nmap 开发团队一直在努力改进其 IPv6 支持。所有端口扫描和主机发现技术已经实现，这使得 Nmap 在处理 IPv6 网络时至关重要。

本食谱描述了如何使用 Nmap 扫描 IPv6 地址。

## 如何做...

让我们扫描代表本地主机的 IPv6 地址(`::1`)：

```
# nmap -6 ::1

```

结果看起来像正常的 Nmap 扫描：

```
Nmap scan report for ip6-localhost (::1) 
Host is up (0.000018s latency). 
Not shown: 996 closed ports 
PORT     STATE SERVICE VERSION 
25/tcp   open  smtp    Exim smtpd 
80/tcp   open  http    Apache httpd 2.2.16 ((Debian)) 
631/tcp  open  ipp     CUPS 1.4 
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1 

```

## 它是如何工作的...

参数`-6`告诉 Nmap 执行 IPv6 扫描。您基本上可以与`-6`结合使用任何其他标志。它支持使用原始数据包的扫描技术，服务检测，TCP 端口和 ping 扫描以及 Nmap 脚本引擎。

```
# nmap -6 -sT --traceroute ::1 

Nmap scan report for ip6-localhost (::1) 
Host is up (0.00033s latency). 
Not shown: 996 closed ports 
PORT     STATE SERVICE 
25/tcp   open  smtp 
80/tcp   open  http 
631/tcp  open  ipp 
8080/tcp open  http-proxy 

```

## 还有更多...

在执行 IPv6 扫描时，请记住您可以使用主机名和 IPv6 地址作为目标：

```
# nmap -6 scanmev6.nmap.org
# nmap -6 2600:3c01::f03c:91ff:fe93:cd19

```

### IPv6 扫描中的 OS 检测

IPv6 地址的 OS 检测方式与 IPv4 的方式类似；探针被发送并与指纹数据库进行匹配。发送的探针列在[`nmap.org/book/osdetect-ipv6-methods.html`](http://nmap.org/book/osdetect-ipv6-methods.html)。您可以使用选项`-O`在 IPv6 扫描中启用 OS 检测：

```
#nmap -6 -O <target>

```

最近添加了操作系统检测，您可以通过发送 Nmap 用于检测算法的指纹来提供帮助。提交新的 IPv6 指纹的过程由 Luis Martin Garcia 在[`seclists.org/nmap-dev/2011/q3/21`](http://seclists.org/nmap-dev/2011/q3/21)中描述。我知道 Nmap 团队的工作速度，我知道它很快就会准备好。

## 另请参阅

+   *使用额外的随机数据隐藏我们的流量*食谱

+   *强制 DNS 解析*食谱

+   *排除主机扫描*食谱

+   *使用广播脚本收集网络信息*食谱

+   第一章《Nmap 基础知识》中的*使用特定端口范围进行扫描*食谱

+   第三章《收集额外主机信息》中的*欺骗端口扫描的源 IP*食谱

+   *扫描 IPv6 地址*食谱

+   第七章《扫描大型网络》中的*跳过测试以加快长时间扫描*食谱

+   第七章《扫描大型网络》中的*调整定时参数*食谱

+   第七章《扫描大型网络》中的*选择正确的定时模板*食谱

# 使用广播脚本收集网络信息

广播请求通常会显示协议和主机详细信息，并且在 NSE 广播脚本的帮助下，我们可以从网络中收集有价值的信息。**NSE 广播脚本**执行诸如检测 dropbox 监听器、嗅探以检测主机以及发现 MS SQL 和 NCP 服务器等任务。

这个食谱描述了如何使用 NSE 广播脚本从网络中收集有趣的信息。

## 如何做...

打开终端并输入以下命令：

```
# nmap --script broadcast

```

请注意，广播脚本可以在不设置特定目标的情况下运行。所有找到信息的 NSE 脚本都将包含在您的扫描结果中：

```
Pre-scan script results: 
| targets-ipv6-multicast-invalid-dst: 
|   IP: fe80::a00:27ff:fe16:4f71  MAC: 08:00:27:16:4f:71  IFACE: wlan2 
|_  Use --script-args=newtargets to add the results as targets 
| targets-ipv6-multicast-echo: 
|   IP: fe80::a00:27ff:fe16:4f71   MAC: 08:00:27:16:4f:71  IFACE: wlan2 
|   IP: fe80::4225:c2ff:fe3f:c724  MAC: 40:25:c2:3f:c7:24  IFACE: wlan2 
|_  Use --script-args=newtargets to add the results as targets 
| targets-ipv6-multicast-slaac: 
|   IP: fe80::a00:27ff:fe16:4f71   MAC: 08:00:27:16:4f:71  IFACE: wlan2 
|   IP: fe80::4225:c2ff:fe3f:c724  MAC: 40:25:c2:3f:c7:24  IFACE: wlan2 
|_  Use --script-args=newtargets to add the results as targets 
| broadcast-ping: 
|   IP: 192.168.1.105  MAC: 08:00:27:16:4f:71 
|   IP: 192.168.1.106  MAC: 40:25:c2:3f:c7:24 
|_  Use --script-args=newtargets to add the results as targets 
| broadcast-dns-service-discovery: 
|   192.168.1.102 
|     9/tcp workstation 
|_      Address=192.168.1.102 fe80:0:0:0:2c0:caff:fe50:e567 
| broadcast-avahi-dos: 
|   Discovered hosts: 
|     192.168.1.102 
|   After NULL UDP avahi packet DoS (CVE-2011-1002). 
|_  Hosts are all up (not vulnerable). 
WARNING: No targets were specified, so 0 hosts scanned. 
Nmap done: 0 IP addresses (0 hosts up) scanned in 35.06 seconds 

```

## 它是如何工作的...

参数`--script broadcast`告诉 Nmap 初始化广播类别中的所有 NSE 脚本。该类别包含使用广播请求的脚本，这意味着不会直接向目标发送探测。

在撰写本文时，有 18 个广播脚本可用。让我们看看脚本描述，摘自 Nmap 的官方文档：

+   `broadcast-avahi-dos`：此脚本尝试使用 DNS 服务发现协议在本地网络中发现主机，并向每个主机发送一个空的 UDP 数据包，以测试它是否容易受到 Avahi 空 UDP 数据包拒绝服务攻击（CVE-2011-1002）。

+   `broadcast-db2-discover`：此脚本尝试通过向端口`523/udp`发送广播请求来发现网络上的 DB2 服务器。

+   `broadcast-dhcp-discover`：此脚本向广播地址（255.255.255.255）发送 DHCP 请求并报告结果。在这样做时，它使用静态 MAC 地址（DE:AD:CO:DE:CA:FE）以防止范围耗尽。

+   `broadcast-dns-service-discovery`：此脚本尝试使用 DNS 服务发现协议来发现主机的服务。它发送多播 DNS-SD 查询并收集所有响应。

+   `broadcast-dropbox-listener`：此脚本监听每 20 秒[Dropbox.com](http://Dropbox.com)客户端广播的 LAN 同步信息广播，然后打印出所有发现的客户端 IP 地址、端口号、版本号、显示名称等。

+   `broadcast-listener`：此脚本嗅探传入的广播通信并尝试解码接收到的数据包。它支持诸如 CDP、HSRP、Spotify、DropBox、DHCP、ARP 等协议。有关更多信息，请参见`packetdecoders.lua`。

+   `broadcast-ms-sql-discover`：此脚本在相同的广播域中发现 Microsoft SQL 服务器。

+   `broadcast-netbios-master-browser`：此脚本尝试发现主浏览器及其管理的域。

+   `broadcast-novell-locate`：此脚本尝试使用服务位置协议来发现**Novell NetWare Core Protocol** **(NCP)**服务器。

+   `broadcast-ping`：此脚本通过使用原始以太网数据包向选定的接口发送广播 ping，并输出响应主机的 IP 和 MAC 地址，或者（如果请求）将它们添加为目标。在 Unix 上运行此脚本需要 root 权限，因为它使用原始套接字。大多数操作系统不会响应广播 ping 探测，但可以配置为这样做。

+   `broadcast-rip-discover`：此脚本发现在局域网上运行 RIPv2 的设备和路由信息。它通过发送 RIPv2 请求命令并收集所有响应来实现这一点。

+   `broadcast-upnp-info`：此脚本尝试通过发送多播查询来从 UPnP 服务中提取系统信息，然后收集、解析和显示所有响应。

+   `broadcast-wsdd-discover`：此脚本使用多播查询来发现支持 Web Services Dynamic Discovery (WS-Discovery)协议的设备。它还尝试定位任何发布的**Windows Communication Framework (WCF)** web 服务（.NET 4.0 或更高版本）。

+   `lltd-discovery`：此脚本使用 Microsoft LLTD 协议来发现本地网络上的主机。

+   `targets-ipv6-multicast-echo`：此脚本向所有节点的链路本地多播地址（`ff02::1`）发送 ICMPv6 回显请求数据包，以发现局域网上的响应主机，而无需逐个 ping 每个 IPv6 地址。

+   `targets-ipv6-multicast-invalid-dst`：此脚本向所有节点的链路本地多播地址（`ff02::1`）发送带有无效扩展标头的 ICMPv6 数据包，以发现局域网上的（一些）可用主机。这是因为一些主机将用 ICMPv6 参数问题数据包响应此探测。

+   `targets-ipv6-multicast-slaac`：此脚本通过触发**无状态地址自动配置（SLAAC）**执行 IPv6 主机发现。

+   `targets-sniffer`：此脚本在本地网络上嗅探相当长的时间（默认为 10 秒），并打印发现的地址。如果设置了`newtargets`脚本参数，则发现的地址将添加到扫描队列中。

请考虑每个脚本都有一组可用的参数，有时需要进行调整。例如，`targets-sniffer`只会在网络上嗅探 10 秒，这对于大型网络可能不够。

```
# nmap --script broadcast --script-args targets-sniffer.timeout 30 

```

正如您所看到的，广播类别有一些非常巧妙的 NSE 脚本，值得一看。您可以在[`nmap.org/nsedoc/categories/broadcast.html`](http://nmap.org/nsedoc/categories/broadcast.html)了解有关广播脚本的特定参数的更多信息。

## 还有更多...

记住，NSE 脚本可以按类别、表达式或文件夹进行选择。因此，我们可以调用所有广播脚本，但不包括名为`targets-*`的脚本，如下所示：

```
# nmap --script "broadcast and not targets*" 

Pre-scan script results: 
| broadcast-netbios-master-browser: 
| ip             server    domain 
|_192.168.1.103  CLDRN-PC  WORKGROUP 
| broadcast-upnp-info: 
|   192.168.1.103 
|       Server: Microsoft-Windows-NT/5.1 UPnP/1.0 UPnP-Device-Host/1.0 
|_      Location: http://192.168.1.103:2869/upnphost/udhisapi.dll?content=uuid:69d208b4-2133-48d4-a387-3a19d7a733de 
| broadcast-dns-service-discovery: 
|   192.168.1.101 
|     9/tcp workstation 
|_      Address=192.168.1.101 fe80:0:0:0:2c0:caff:fe50:e567 
| broadcast-wsdd-discover: 
|   Devices 
|     192.168.1.103 
|         Message id: b9dcf2ab-2afd-4791-aaae-9a2091783e90 
|         Address: http://192.168.1.103:5357/53de64a8-b69c-428f-a3ec-35c4fc1c16fe/ 
|_        Type: Device pub:Computer 
| broadcast-listener: 
|   udp 
|       DropBox 
|         displayname  ip             port   version  host_int   namespaces 
|_        104784739    192.168.1.103  17500  1.8      104784739  14192704, 71393219, 68308486, 24752966, 69985642, 20936718, 78567110, 76740792, 20866524 
| broadcast-avahi-dos: 
|   Discovered hosts: 
|     192.168.1.101 
|   After NULL UDP avahi packet DoS (CVE-2011-1002). 
|_  Hosts are all up (not vulnerable). 
WARNING: No targets were specified, so 0 hosts scanned. 
Nmap done: 0 IP addresses (0 hosts up) scanned in 34.86 seconds 

```

### 目标库

参数`--script-args=newtargets`强制 Nmap 使用这些新发现的主机作为目标：

```
# nmap --script broadcast-ping --script-args newtargets
Pre-scan script results: 
| broadcast-ping: 
|   IP: 192.168.1.105  MAC: 08:00:27:16:4f:71 
|_  IP: 192.168.1.106  MAC: 40:25:c2:3f:c7:24 
Nmap scan report for 192.168.1.105 
Host is up (0.00022s latency). 
Not shown: 997 closed ports 
PORT    STATE SERVICE 
22/tcp  open  ssh 
80/tcp  open  http 
111/tcp open  rpcbind 
MAC Address: 08:00:27:16:4F:71 (Cadmus Computer Systems) 

Nmap scan report for 192.168.1.106 
Host is up (0.49s latency). 
Not shown: 999 closed ports 
PORT   STATE SERVICE 
80/tcp open  http 
MAC Address: 40:25:C2:3F:C7:24 (Intel Corporate) 

Nmap done: 2 IP addresses (2 hosts up) scanned in 7.25 seconds 

```

请注意，我们没有指定目标，但`newtargets`参数仍将 IP`192.168.1.106`和`192.168.1.105`添加到扫描队列中。

参数`max-newtargets`设置要添加到扫描队列中的主机的最大数量：

```
# nmap --script broadcast-ping --script-args max-newtargets=3

```

## 另请参阅

+   *使用广播 ping 发现主机*配方

+   *强制 DNS 解析*配方

+   *扫描 IPv6 地址*配方

+   在第三章的*收集额外的主机信息*中的*发现指向相同 IP 地址的主机名*配方

+   在第三章的*收集额外的主机信息*中的*IP 地址地理定位*配方

+   在第一章的*发现网络中的活动主机*配方

+   《Nmap 基础》第一章中的*对远程主机进行指纹识别服务*配方

+   《Nmap 基础》第一章中的*运行 NSE 脚本*配方
