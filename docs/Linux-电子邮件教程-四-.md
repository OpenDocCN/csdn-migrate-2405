# Linux 电子邮件教程（四）

> 原文：[`zh.annas-archive.org/md5/7BD6129F97DE898479F1548456826B76`](https://zh.annas-archive.org/md5/7BD6129F97DE898479F1548456826B76)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：防病毒保护

一种普遍的观点是 Linux 不容易受到病毒攻击，那么为什么要安装防病毒解决方案？虽然 Linux 确实很少受到病毒攻击，但主要目标不是保护邮件服务器免受感染，而是减少或消除对接收者的任何风险。您的组织可能有运行 Windows 的客户端 PC，容易受到病毒攻击，或者您可能收到带有病毒的电子邮件，您可能会将其转发给客户或商业伙伴。

使用 Procmail 进行过滤的众多选项之一是删除电子邮件中的可执行附件，以保护系统免受可能的病毒攻击。这将是一个粗糙的操作，最坏的情况下，它将删除不包含病毒的文件，并可能留下其他受感染的文档，如不是可执行文件的脚本。

也可以在客户端扫描电子邮件。但在公司环境中，不一定能够依赖每个人的机器都是最新的，并且正确安装了适当的病毒检测软件。明显的解决方案是在服务器上运行一个高效的进程，以确保组织发送或接收的所有电子邮件都经过正确的病毒扫描。

针对基于 Linux 的系统有许多防病毒解决方案可用。我们选择专注于 Clam AntiVirus，通常称为 ClamAV。这是一个开源软件，并定期更新病毒数据库，以便在下载之前进行检查。

在本章中，我们将学习：

+   ClamAV 可以检测到可能包含病毒的文档类型

+   安装和配置 ClamAV 组件以检测病毒

+   建立程序以维护最新的防病毒数据库

+   将 ClamAV 与 Postfix 集成，以扫描所有传入的电子邮件消息和附件

+   通过使用包含测试病毒签名的样本文件和测试电子邮件伯恩病毒来广泛测试我们的安装

+   将每个 ClamAV 组件添加到我们的系统启动和关闭程序中

# ClamAV 简介

Clam AntiVirus 是一个面向 Linux、Windows 和 Mac OS X 的开源防病毒工具包。ClamAV 的主要设计特点是将其与邮件服务器集成，以执行附件扫描并帮助过滤已知病毒。该软件包提供了一个灵活和可扩展的多线程守护程序（`clamd`）、一个命令行扫描程序（`clamscan`）和一个通过互联网进行自动更新的工具（`freshclam`）。这些程序基于一个共享库`libclamav`，与 Clam AntiVirus 软件包一起分发，您也可以将其与自己的软件一起使用。

我们将在本章中使用的 ClamAV 版本是最新的稳定版本 0.95.2，具有最新的病毒数据库和签名，可以检测超过 580,000 种病毒、蠕虫和特洛伊木马，包括 Microsoft Office 宏病毒、移动恶意软件和其他威胁。虽然本书未涉及，但它也能够在 Linux 下进行适当安装并进行实时扫描。

# 支持的文档类型

ClamAV 可以提供对大多数文档类型的保护，这些文档类型可能包含或传播病毒：

+   UNIX 和类 UNIX 操作系统（如 Linux、Solaris 和 OpenBSD）使用的**ELF**（**可执行和链接格式**）文件。

+   **可移植可执行文件**（**PE**）文件（32/64 位）使用 UPX、FSG、Petite、WWPack32 压缩，并使用 SUE、Yoda's Cryptor 等进行混淆。这是 Microsoft Windows 可执行文件的标准格式，也是病毒最常见的传输方式之一。

+   许多形式的 Microsoft 文档可能包含脚本或可执行文件。ClamAV 可以处理以下文档和存档类型：

+   MS OLE2

+   MS Cabinet 文件

+   MS CHM（压缩 HTML）

+   MS SZDD

+   MS Office Word 和 Excel 文档

+   支持其他特殊文件和格式，包括：

+   HTML

+   RTF

+   PDF

+   使用 CryptFF 和 ScrEnc 加密的文件

+   uuencode

+   TNEF（winmail.dat）

+   ClamAV 可以处理的其他常见存档格式包括任何形式的文档：

+   RAR（2.0）

+   ZIP

+   gzip

+   bzip2

+   tar

+   BinHex

+   SIS（SymbianOS 软件包）

+   AutoIt

扫描存档还包括扫描存档中保存的支持的文档格式。

# 下载和安装 ClamAV

由于几乎每天都会发现病毒，因此安装最新稳定版本的 ClamAV 软件非常值得。如果您的系统已经安装了 ClamAV，则可能是基于过时的安装包进行安装。强烈建议您从 ClamAV 网站下载并安装最新版本，以确保系统对病毒具有最高级别的安全性。

## 添加新的系统用户和组

您将不得不为 ClamAV 系统添加一个新用户和组。

```
# groupadd clamav
# useradd -g clamav -s /bin/false -c "Clam AntiVirus" clamav

```

## 从软件包安装

ClamAV 有许多安装包可供选择，详细信息可以在 ClamAV 网站上找到（[`www.clamav.net/download/packages/packages-linux.`](http://www.clamav.net/download/packages/packages-linux.)）

### 注意

由于许可限制，大多数二进制软件包没有内置的 RAR 支持。因此，我们建议您在任何许可问题得到解决之前从源代码安装 ClamAV。

如果您使用的是基于 Red Hat 的系统，则可以使用以下选项之一执行安装，具体取决于您安装了哪个发行版：

```
# yum update clamav

```

或者

```
# up2date -u clamav

```

如果您使用的是基于 Debian 的系统，则可以使用以下命令执行安装：

```
# apt-get install clamav clamav-daemon clamav-freshclam

```

### 注意

确保安装的版本是 0.95.2 或更高版本，因为与以前的版本相比有重大改进。一般来说，您应该始终安装最新的稳定版本。

## 从源代码安装

从原始源代码安装 ClamAV 并不是很困难，可以让您运行任何您想要的版本，而不仅仅是您的 Linux 发行版的软件包维护者选择的版本。ClamAV 源代码可以从主 ClamAV 网站的多个镜像下载（[`www.clamav.net/download/sources`](http://www.clamav.net/download/sources)）。

### 要求

编译 ClamAV 需要以下元素：

+   zlib 和 zlib-devel 软件包

+   gcc 编译器套件

以下软件包是可选的，但强烈推荐：

+   bzip2 和 bzip2-devel 库

+   解压包

### 构建和安装

下载并解压缩存档后，`cd`到目录，例如`clamav-0.95.2`。在开始构建和安装软件之前，值得阅读`INSTALL`和`README`文档。

对于大多数 Linux 系统，最简单的安装方法可以通过按照这里列出的步骤来简化：

1.  运行`configure`实用程序通过运行`configure`命令来创建正确的构建环境：

```
$ ./configure --sysconfdir=/etc

```

1.  配置脚本完成后，可以运行`make`命令来构建软件可执行文件。

```
$ make

```

1.  最后一步是以`root`身份将可执行文件复制到系统上的正确位置以进行操作。

```
# make install

```

在最后一步，软件安装到`/usr/local`目录，配置文件安装到`/etc`，如`—sysconfdir`选项所示。

在所有阶段，您都应该检查进程输出是否有任何重大错误或警告。

与所有从源代码构建的软件包一样，在完成本章的构建、安装和测试步骤后，您可能希望删除解压的存档。

### 快速测试

我们可以通过尝试扫描源目录中的示例测试病毒文件来验证软件是否正确安装：

### 注意

提供的测试病毒文件不包含真正的病毒，是无害的。它们包含专门设计用于测试目的的行业认可的病毒签名。

```
$ clamscan -r -l scan.txt clamav-x.yz/test

```

它应该在`clamav-x.yz/test`目录中找到一些测试文件。扫描结果将保存在`scan.txt`日志文件中。检查日志文件，特别注意任何警告，指示对特定文件或存档格式的支持未被编译进去。日志文件的末尾应该包含类似以下的摘要：

![快速测试](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-eml/img/8648_09_01.jpg)

# 编辑配置文件

安装软件后，需要编辑两个配置文件。第一个文件`/etc/clamd.conf`是用于实际病毒扫描软件的。这个文件的大部分重要配置选项在接下来的章节中讨论。第二个配置文件`/etc/freshclam.conf`将在本章后面讨论。这是我们添加自动病毒数据库更新的配置选项的地方。

## clamd

您必须编辑配置文件才能使用守护进程，否则`clamd`将无法运行。

```
$ clamd

```

```
ERROR: Please edit the example config file /etc/clamd.conf.

```

这显示了默认配置文件的位置。该文件的格式和选项在`clamd.conf(5)`手册中有详细描述。`config`文件有很好的注释，配置应该是直观的。

### 检查示例配置文件

提供的示例`config`文件在每个重要配置值处都有注释，非常详细。以下是一些您可能希望修改的关键值：

```
##
## Example config file for the Clam AV daemon
## Please read the clamd.conf(5) manual before editing this file.
##
# Comment or remove the line below.
#Example

```

`Example`行将导致程序因配置错误而停止运行，并且是故意包含的，以强制您在软件正确运行之前编辑文件。在编辑完文件后，在该行的开头加上`#`就足以解决这个问题。

```
# Uncomment this option to enable logging.
# LogFile must be writable for the user running daemon.
# A full path is required.
# Default: disabled
LogFile /var/log/clamav/clamd.log

```

建立一个日志文件非常值得，以便您可以在运行的最初几周内检查错误并监视正确的操作。之后，您可以决定是否停止记录或保持其运行。

```
# Log time with each message.
# Default: disabled
LogTime yes

```

在日志文件中启用时间戳可以确保您可以追踪事件被记录的时间，以帮助调试问题并将事件与其他日志文件中的条目匹配。

```
# Path to the database directory.
# Default: hardcoded (depends on installation options)
#DatabaseDirectory /var/lib/clamav
DatabaseDirectory /usr/local/share/clamav

```

确保数据库目录正确配置，以确切地知道病毒签名信息存储在哪里。安装过程将创建文件`main.cvd`，可能还有`daily.cld`，作为包含病毒签名的数据库文件。

```
# The daemon works in a local OR a network mode. Due to security # reasons we recommend the local mode.
# Path to a local socket file the daemon will listen on.
# Default: disabled
LocalSocket /var/run/clamav/clamd.sock

```

使用本地模式是一个重要的配置更改，也是确保安装了 ClamAV 的系统的安全所必需的。

```
# This option allows you to save a process identifier of the listening
# daemon (main thread).
# Default: disabled
PidFile /var/run/clamav/clamd.pid

```

这对于启动和停止脚本非常有用。如前面的示例所示，ClamAV 目录必须是可写的。

```
# TCP address.
# By default we bind to INADDR_ANY, probably not wise.
# Enable the following to provide some degree of protection
# from the outside world.
# Default: disabled
TCPAddr 127.0.0.1

```

这是另一个与安全相关的配置项，以确保只有本地进程可以访问该服务。

```
# Execute a command when virus is found. In the command string %v # will
# be replaced by a virus name.
# Default: disabled
#VirusEvent /usr/local/bin/send_sms 123456789 "VIRUS ALERT: %v"

```

在某些情况下，这可能是一个有用的功能。然而，由于病毒传递的广泛范围和频率，这可能会成为一个显著的烦恼，因为消息可能会在整个夜晚或白天到达。

```
# Run as a selected user (clamd must be started by root).
# Default: disabled
User clamav

```

通过为 ClamAV 创建一个专门的用户，我们可以将文件和进程的所有权分配给这个用户 ID，并通过限制对只有这个用户 ID 的访问来提高文件的安全性。此外，当在系统上列出运行的进程时，很容易识别出 ClamAV 系统拥有的进程。

## freshclam

您必须编辑配置文件，否则`freshclam`将无法运行。

```
$ freshclam

```

```
ERROR: Please edit the example config file /etc/freshclam.conf

```

源分发中还包括了一个`freshclam`配置文件的示例。如果您需要更多关于配置选项和格式的信息，您应该参考*freshclam.conf(5)*手册页。

### 最近的镜像

互联网上有许多镜像服务器可供下载最新的防病毒数据库。为了避免过载任何一个服务器，配置文件应设置为确保下载来自最近可用的服务器。包含的`update`实用程序利用 DNS 系统来定位基于您请求的国家代码的合适服务器。

需要修改的配置文件条目是`DatabaseMirror`。您还可以指定参数`MaxAttempts`——从服务器下载数据库的次数。

默认的数据库镜像是`clamav.database.net`，但您可以在配置文件中应用多个条目。配置条目应使用格式`db.xx.clamav.net`，其中`xx`代表您的正常两字母 ISO 国家代码。例如，如果您的服务器在美国，您应该将以下行添加到`freshclam.conf`。两字母国家代码的完整列表可在[`www.iana.org/cctld/cctld-whois.htm`](http://www.iana.org/cctld/cctld-whois.htm)上找到。

```
DatabaseMirror db.us.clamav.net
DatabaseMirror db.local.clamav.net

```

如果由于任何原因与第一个条目的连接失败，将尝试从第二个镜像条目下载。您不应该只使用默认条目，因为这可能导致您的服务器或 IP 地址被 ClamAV 数据库管理员列入黑名单，因为过载，您可能无法获取任何更新。

### 检查示例配置文件

提供的示例`config`文件在每个重要配置值处都有注释，非常详细。以下是一些您可能希望修改的关键值：

```
##
## Example config file for freshclam
## Please read the freshclam.conf(5) manual before editing this file.
## This file may be optionally merged with clamd.conf.
##
# Comment or remove the line below.
#Example

```

确保此行已注释以允许守护程序运行。

```
# Path to the log file (make sure it has proper permissions)
# Default: disabled
UpdateLogFile /var/log/clamav/freshclam.log

```

启用日志文件对于跟踪正在应用的持续更新以及在早期测试阶段监视系统的正确操作非常有用。

```
# Enable verbose logging.
# Default: disabled
LogVerbose

```

前面的选项使得更详细的错误消息能够包含在更新日志文件中。

```
# Use DNS to verify virus database version. Freshclam uses DNS TXT # records to verify database and software versions. We highly # recommend enabling this option.
# Default: disabled
DNSDatabaseInfo current.cvd.clamav.net
# Uncomment the following line and replace XY with your country
# code. See http://www.iana.org/cctld/cctld-whois.htm for the full # list.
# Default: There is no default, which results in an error when running freshclam
DatabaseMirror db.us.clamav.net

```

这是一个重要的配置，可以减少网络流量开销，并确保您从地理位置接近的服务器获取更新。

```
# database.clamav.net is a round-robin record which points to our # most
# reliable mirrors. It's used as a fall back in case db.XY.clamav.net
# is not working. DO NOT TOUCH the following line unless you know
# what you are doing.
DatabaseMirror database.clamav.net

```

正如说明所说——不要动这一行。

```
# Number of database checks per day.
# Default: 12 (every two hours)
Checks 24

```

对于忙碌的服务器和大量流量的服务器，值得以更频繁的间隔更新病毒数据库。但是，这仅建议适用于运行 ClamAV 软件版本 0.8 或更高版本的系统。

```
# Run command after successful database update.
# Default: disabled
#OnUpdateExecute command
# Run command when database update process fails..
# Default: disabled
#OnErrorExecute command

```

为了帮助监控对配置文件的更新，您刚刚看到的选项可用于在更新正确或不正确时应用适当的操作。

## 文件权限

根据先前的建议，`clamd`将作为`clamav`用户运行，并且默认情况下，当启动时，`freshclam`会放弃权限并切换到`clamav`用户。因此，应使用以下命令设置在前面示例中看到的配置文件中指定的套接字、PID 和日志文件的所有权，以允许正确访问：

```
# mkdir /var/log/clamav /var/run/clamav
# chown clamav:clamav /var/log/clamav /var/run/clamav

```

`freshclam`和`clamd`运行的用户可以在`freshclam.conf`和`clamd.conf`中更改。但是，如果更改这些参数，您应验证 ClamAV 进程是否可以访问病毒定义数据库。

# 安装后测试

现在我们已经安装了 ClamAV 的主要组件，我们可以验证每个组件的正确操作。

+   `clamscan`——命令行扫描程序

+   `clamd`——ClamAV 守护程序

+   `freshclam`——病毒定义更新程序

对于这些测试，我们需要一个病毒，或者至少一个看起来像病毒的非破坏性文件。

## EICAR 测试病毒

许多防病毒研究人员已经共同努力制作了一个文件，他们（以及许多其他产品）检测到它像是病毒。就此类目的，达成一致意见简化了用户的事务。

这个测试文件被称为**EICAR**（**欧洲计算机防病毒研究所）标准防病毒测试文件**。该文件本身不是病毒，它根本不包含任何程序代码，因此可以安全地传递给其他人。但是，大多数防病毒产品会对该文件做出反应，就好像它真的是一个病毒，这可能会使它成为一个相当棘手的文件，如果您或接收者已经有良好的病毒防护系统，可能会很难操作或通过电子邮件发送。

该文件是一个完全由可打印的 ASCII 字符组成的文本文件，因此可以很容易地使用常规文本编辑器创建。任何支持 EICAR 测试文件的防病毒产品都应该能够在任何以以下 68 个字符开头的文件中检测到它：

```
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*

```

在创建此文件时，您应该注意以下事实。该文件仅使用大写字母、数字和标点符号，并且不包括空格。在重新创建此文件时可能会出现一些常见错误。这些错误包括确保第三个字符是大写字母`O`，而不是数字零（0），并且所有的 68 个字符都在一行上，这必须是文件中的第一行。

有关 EICAR 防病毒测试文件的更多信息，请访问[`www.eicar.org/anti_virus_test_file.htm`](http://www.eicar.org/anti_virus_test_file.htm)。

## 测试 clamscan

我们需要运行的第一个测试是确保病毒扫描程序已安装，并且病毒定义数据库已正确配置和包含。病毒数据库是安装过程的一部分。

这样做的最简单方法是在服务器上创建 EICAR 测试文件的副本，然后运行`clamscan`程序。我们使用`—i`标志，以便只显示感染的文件。您应该得到以下输出：

![测试 clamscan](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-eml/img/8648_09_02.jpg)

请注意关于过时病毒数据库的警告。这是正常的，在进行`freshclam`测试期间将会得到纠正。

## 测试 clamd

通过使用`clamdscan`程序，我们可以再次扫描测试文件，但是通过指示`clamd`进程进行扫描。这是一个很好的测试，以确保`clamd`守护程序进程正在运行。

预期的输出应该看起来像以下内容：

```
$ clamdscan testvirus.txt

```

```
/home/ian/testvirus.txt: Eicar-Test-Signature FOUND
----------- SCAN SUMMARY -----------
Infected files: 1
Time: 0.000 sec (0 m 0 s)

```

如果 clamd 守护程序没有运行，可以使用`# clamd`命令启动它。

在运行此测试后，您还应检查`clamd`日志文件（在`clamd.conf`中配置）是否包含任何意外的错误或警告。

## 测试 freshclam

使用`freshclam`程序进行交互式操作，我们可以使用最新的定义更新病毒数据库。此测试将仅更新数据库一次。稍后我们将看到如何执行自动更新。使用以下命令（作为超级用户），我们期望得到类似以下的输出：

![测试 freshclam](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-eml/img/8648_09_03.jpg)

从输出中，我们可以看到更新过程成功下载了两个差异更新，并在第三次出现网络问题时失败。下载最新数据库与当前数据库之间的差异有助于减少网络流量和服务器负载。在这种情况下，`freshclam`检测到了失败，并下载了最新的每日更新，以使病毒数据库更新到具有增加病毒签名数量的状态。

现在如果再次运行`clamscan`测试，您会注意到不再显示过时警告。

在运行此测试后，您还应检查`freshclam`日志文件是否包含类似于先前代码的输出。

# ClamSMTP 介绍

为了扫描通过服务器的所有电子邮件，需要在 Postfix 和 ClamAV 之间使用软件接口。我们将使用的接口是**ClamSMTP**。来自 ClamSMTP 网站（[`memberwebs.com/stef/software/clamsmtp/`](http://memberwebs.com/stef/software/clamsmtp/)）的以下介绍描述了 SMTP 病毒过滤器：

> ClamSMTP 是一个 SMTP 过滤器，允许您使用 ClamAV 防病毒软件检查病毒。它接受 SMTP 连接并将 SMTP 命令和响应转发到另一个 SMTP 服务器。在转发之前拦截并扫描“DATA”电子邮件正文。ClamSMTP 旨在轻量、可靠和简单，而不是拥有大量选项。它是用 C 编写的，没有主要依赖关系。

Postfix 旨在允许调用外部过滤器来处理邮件消息，并将处理后的数据返回给 Postfix 以进行进一步交付。ClamSMTP 已经被设计为直接在 Postfix 和 ClamAV 之间工作，以确保高效运行。

一些 Linux 发行版可能会维护 ClamSMTP 的软件包，可以通过相关软件包管理器安装。但是，您仍然应该完成后续的配置和集成 ClamSMTP 到 Postfix 的指示。

最新的源代码可以从[`memberwebs.com/stef/software/clamsmtp/`](http://memberwebs.com/stef/software/clamsmtp/)下载，直接使用`wget`命令下载到您的 Linux 系统上。切换到适当的位置以下载和构建软件。当前版本（1.10）的命令选项将是`wget <url>`。

```
$ wget http://memberwebs.com/stef/software/clamsmtp/clamsmtp-1.10.tar.gz

```

您应该检查网站以获取可以下载的最新版本。下载文件后，使用`tar`命令解压文件的内容。

```
$ tar xvfz clamsmtp-1.10.tar.gz

```

这将创建一个目录结构，其中包含当前目录下的所有相关文件。

## 构建和安装

在构建和安装软件之前，值得阅读`INSTALL`和`README`文档。

对于大多数 Linux 系统，最简单的安装方法如下：

1.  运行`configure`实用程序通过运行`configure`命令创建正确的构建环境。

```
$ ./configure --sysconfdir=/etc

```

1.  配置脚本完成后，您可以运行`make`命令来构建软件可执行文件：

```
$ make

```

1.  最后一步，作为`root`，是将可执行文件复制到系统上的正确位置以进行操作：

```
# make install

```

在最后一步，软件安装到`/usr/local`目录，配置文件安装到`/etc`目录。

在所有阶段，您应该检查进程输出以查找任何重要的错误或警告。

## 配置到 Postfix

Postfix 通过将邮件项目通过外部进程来支持邮件过滤。此操作可以在邮件排队之前或之后执行。Postfix 与`clamsmtp`之间的通信方式是假装`clamsmtp`本身是一个 SMTP 服务器。这种简单的方法提供了一种简单的方式来创建分布式架构，不同的进程可以在不同的机器上工作，以在非常繁忙的网络中分散负载。对于我们的用途，我们将假设我们只使用一台机器，所有软件都在该机器上运行。

`clamsmtp`过滤器接口是专门设计为在 ClamAV 和 Postfix 邮件系统之间提供接口。该过滤器被实现为用于邮件防病毒扫描的后队列过滤器。

第一个配置选项需要向 Postfix 的`main.cf`文件添加行：

```
content_filter = scan:127.0.0.1:10025
receive_override_options = no_address_mappings

```

`content_filter`指令强制 Postfix 通过名为`scan`的服务在端口`10025`上发送所有邮件。扫描服务将是我们使用`clamsmtpd`设置的服务。`receive_override_options`的指令配置 Postfix 执行`no_address_mappings`。这可以防止 Postfix 扩展任何电子邮件别名或组，否则将导致接收到重复的电子邮件。

第二个配置更改需要在 Postfix 的`master.cf`文件中进行。

```
# AV scan filter (used by content_filter)
scan unix - - n - 16 smtp
-o smtp_send_xforward_command=yes
-o smtp_enforce_tls=no
# For injecting mail back into postfix from the filter
127.0.0.1:10026 inet n - n - 16 smtpd
-o content_filter=
-o receive_override_options=no_unknown_recipient_checks,no_header_body_checks
-o smtpd_helo_restrictions=
-o smtpd_client_restrictions=
-o smtpd_sender_restrictions=
-o smtpd_recipient_restrictions=permit_mynetworks,reject
-o mynetworks_style=host
-o smtpd_authorized_xforward_hosts=127.0.0.0/8

```

### 注意

文件的格式非常重要。您应该确保在您添加的文本中，`=`（等号）周围没有空格或`,（逗号）`。

“前两行实际上创建了`scan`服务。其余的行设置了一个服务，用于接受邮件返回到 Postfix 以进行投递。其他选项是为了防止邮件循环发生并放宽地址检查。当这些更改完成后，您需要使用以下命令让 Postfix 重新读取修改后的配置文件：”

```
**# postfix reload** 
```

## “配置 clamSMTP”

“您必须创建配置文件`/etc/clamsmtpd.conf`，否则`clamsmtpd`将无法运行：”

```
**$ clamsmtpd
clamsmtpd: configuration file not found: /etc/clamsmtpd.conf** 
```

“源分发`doc`目录中包含了一个示例`clamsmtp.conf`配置文件。在`clamsmtp`软件正常运行之前，需要将其复制到正确的位置并进行编辑。”

```
**# cp clamsmtpd.conf /etc/clamsmtpd.conf** 
```

“该文件的格式和选项在`clamsmtpd.conf(5)`手册中有详细描述。”

### “检查样本配置文件”

“提供的示例**config**文件非常详细地记录了每个重要配置值的注释。以下是您可能希望修改的一些关键值。”

```
# The address to send scanned mail to.
# This option is required unless TransparentProxy is enabled
**OutAddress: 127.0.0.1:10026** 
```

“由于我们在此配置中只使用一台机器，因此我们应该将`OutAddress`选项指定为`127.0.0.1:10026`，以匹配`master.cf`中指定的选项。”

```
# The maximum number of connection allowed at once.
# Be sure that clamd can also handle this many connections
#MaxConnections: 64
# Amount of time (in seconds) to wait on network IO
#TimeOut: 180
# Keep Alives (ie: NOOP's to server)
#KeepAlives: 0
# Send XCLIENT commands to receiving server
#XClient: off
# Address to listen on (defaults to all local addresses on port 10025)
#Listen: 0.0.0.0:10025 
```

“此地址与`main.cf`中指定的选项匹配。”

```
# The address clamd is listening on
**ClamAddress: /var/run/clamav/clamd.sock** 
```

“这应该与`clamd.conf`文件中的`LocalSocket`选项匹配。”

```
# A header to add to all scanned email
#Header: X-Virus-Scanned: ClamAV using ClamSMTP
# Directory for temporary files
#TempDirectory: /tmp
# What to do when we see a virus (use 'bounce' or 'pass' or 'drop'
**Action: drop** 
```

“丢弃消息。”

```
# Whether or not to keep virus files
#Quarantine: off
# Enable transparent proxy support
#TransparentProxy: off
# User to switch to
**User: clamav** 
```

“重要的是要确保进程以与您用于运行`clamd`相同的用户身份运行，否则您可能会发现每个进程在访问其他临时文件时出现问题。”

```
# Virus actions: There's an option to run a script every time a virus is found.
# !IMPORTANT! This can open a hole in your server's security big enough to drive
# farm vehicles through. Be sure you know what you're doing. !IMPORTANT!
#VirusAction: /path/to/some/script.sh 
```

“现在我们准备启动`clamsmtpd`进程。您应该以`root`身份启动此进程，并验证该进程是否存在并以`clamav`用户 ID 运行。”

```
**# clamsmtpd** 
```

“如果启动服务时遇到问题，请确保`clamd`（ClamAV 守护程序）正在运行，并且它正在监听您指定的套接字。您可以在`clamd.conf`中使用`LocalSocket`或`TCPSocket`指令进行设置（确保只取消注释其中一行）。您还应确保`ScanMail`指令设置为`on`。”

“# 测试电子邮件过滤”

病毒，根据定义，是我们希望尽量避免接触的东西。但为了确保我们的过滤和检测过程正常运行，并且我们得到充分的保护，我们需要访问病毒进行测试。在现实世界的生产环境中使用真正的病毒进行测试，就像在办公室的垃圾桶里点火来测试烟雾探测器是否正常工作一样。这样的测试会产生有意义的结果，但伴随着令人不愉快的风险和不可接受的副作用。因此，我们需要 EICAR 测试文件，可以安全地发送邮件，并且显然不是病毒，但您的防病毒软件会对其做出反应，就像它是病毒一样。

## 测试邮件传播的病毒过滤

第一个测试是检查您是否仍然可以收到邮件。

```
$ echo "Clean mail" | sendmail $USER

```

您应该收到您的邮件，并在标题中添加以下行：

```
X-virus-scanned: ClamAV using ClamSMTP

```

如果您没有收到邮件，请检查系统、postfix 和 clamd 日志文件。如果需要，您还可以使用`-d 4`选项停止和重新启动`clamsmtpd`守护进程以获得额外的调试输出。

通过简单地将 EICAR 病毒作为电子邮件附件发送给自己，可以执行第二个简单的测试，以检测邮件传播的病毒。

必须将示例 EICAR 病毒文件创建为电子邮件的附件。从 Linux 命令提示符中执行以下命令链将发送一个非常简单的 uuencoded 附件副本的感染病毒文件。

```
$ uuencode testvirus.txt test_virus | sendmail $USER

```

如果一切正常并且配置正确，您不应该收到邮件，因为`clamsmtp`被指示丢弃该消息。消息的缺失并不意味着一切都正常，因此请检查系统或 postfix 日志文件，查看类似以下条目的内容：

```
Jul 8 19:38:57 ian postfix/smtp[6873]: 26E66F42CB: to=<ian@example.com>, orig_to=<ian>, relay=127.0.0.1[127.0.0.1]:10025, delay=0.1, delays=0.06/0/0.04/0, dsn=2.0.0, status=sent (250 Virus Detected; Discarded Email)

```

这证明了检测包含病毒的简单附件的简单情况。

当然，在现实世界中，病毒比你平均的电子邮件附件要聪明一些。需要进行彻底的测试，以确保过滤设置正确。幸运的是，有一个网站（[`www.gfi.com/emailsecuritytest/`](http://www.gfi.com/emailsecuritytest/)）可以向您发送包含 EICAR 病毒的电子邮件，以多种方式编码。目前它支持 17 个单独的测试。

## 彻底的电子邮件测试

该网站[`www.gfi.com/emailsecuritytest/`](http://www.gfi.com/emailsecuritytest/)要求您注册要测试的电子邮件地址，并向该地址发送确认电子邮件。在这封电子邮件中有一个链接，确认您是控制该电子邮件地址的有效用户。然后，您可以将这些 17 个病毒和电子邮件客户端利用测试中的任何一个或全部发送到这个电子邮件地址。如果任何携带病毒的电子邮件最终未被过滤到您的收件箱中，那么安装就失败了。

### 注意

然而，该网站上有一些测试消息并不严格是病毒，因此不会被 ClamAV 进程检测到。这是因为这些消息本身并不包含病毒，因此没有东西可以找到，因此也没有东西可以停止。

根据定义，ClamAV 只捕获恶意代码。gfi（[`www.gfi.com/emailsecuritytest/`](http://www.gfi.com/emailsecuritytest/)）网站发送这种类型的测试消息。这些消息的性质是它们有一些格式错误的 MIME 标记，可以欺骗 Outlook 客户端。杀毒软件的工作不是检测这样的消息。

# 自动更新病毒数据

ClamAV 由志愿者提供，用于分发软件和病毒数据库的服务器和带宽是自愿资助的。因此，重要的是要确保在维护最新数据库的更新频率和过载各种服务器之间保持平衡。

### 注意

ClamAV 组建议以下操作：如果您运行的是 ClamAV 0.8x 或更高版本，可以每小时检查四次数据库更新，只要您在`freshclam.conf`中有以下选项：DNSDatabaseInfo current.cvd.clamav.net。

如果您没有这个选项，您必须坚持每小时检查一次。

## 设置自动更新

ClamAV 的病毒数据库文件可以以多种方式从 ClamAV 服务器下载。这包括使用自动化或手动工具，如`wget`。但这不是更新的首选方式。

我们之前使用 ClamAV 安装的`freshclam`实用程序是执行更新的首选方法。它将定期自动下载最新的杀毒软件数据库。它可以设置为自动从`cron`条目或命令行工作，也可以作为守护进程运行并处理自己的调度。当`freshclam`由具有 root 权限的用户启动时，它会放弃特权并切换用户 ID 为`clamav`用户。

`freshclam`使用 DNS 系统的功能来获取准备下载的最新病毒数据库的详细信息以及可以从哪里获取。这可以显著减少您自己以及远程系统的负载，因为在大多数情况下，执行的唯一操作是与 DNS 服务器的检查。只有在有更新版本可用时，它才会尝试执行下载。

我们现在准备启动`freshclam`进程。如果您决定将其作为守护进程运行，只需执行以下命令：

```
# freshclam –d

```

然后检查进程是否正在运行，并且日志文件是否被正确更新。

另一种可用的方法是使用`cron`守护程序安排`freshclam`进程定期运行。为此，您需要为`root`或`clamav`用户的`crontab`文件添加以下条目：

```
N * * * *       /usr/local/bin/freshclam –quiet

```

### 注意

`N`可以是您选择的`1`到`59`之间的任意数字。请不要选择任何 10 的倍数，因为已经有太多服务器在使用这些时间段。

代理设置仅可通过配置文件进行配置，并且在启用`HTTPProxyPassword`时，`freshclam`将要求配置文件的所有者具有严格的只读权限。例如，

```
# chmod 0600 /etc/freshclam.conf

```

以下是代理设置的示例：

```
HTTPProxyServer myproxyserver.com
HTTPProxyPort 1234
HTTPProxyUsername myusername
HTTPProxyPassword mypass

```

# 自动化启动和关闭

如果您通过软件包管理器而不是从源代码安装了 ClamAV 和 ClamSMTP 组件中的任何一个或全部组件，则可能已提供必要的启动脚本。请检查是否已将必要的脚本包含在引导启动顺序中。

如果您从源代码安装了 ClamAV，则以下脚本是用于在引导时启动和停止必要守护程序的示例。根据您的发行版，文件位置可能会有所不同，您可能需要执行其他命令来为每个脚本设置运行级别。请参阅您的发行版文档。

## ClamSMTP

ClamSMTP 源中提供的一个贡献脚本是用于在系统引导时自动启动和停止操作守护程序的脚本。检查脚本中的路径名是否与配置文件和安装目录中的路径名匹配，然后从 ClamSMTP 源树的根目录执行以下命令：

```
# cp scripts/clamsmtpd.sh /etc/init.d/clamsmtpd

```

复制文件后，请确保脚本具有执行权限，并且除系统根用户外，其他人无法修改它。

```
# ls -al /etc/init.d/clamsmtpd
-rwxr-xr-x 1 root root 756 2009-07-09 15:51 /etc/init.d/clamsmtpd

```

将脚本添加到系统启动中。

```
# update-rc.d clamsmtpd defaults

```

## ClamAV

以下是一个示例脚本，用于在引导时启动和停止`clamd`和`freshclamd`守护程序。与以前一样，验证路径名，根据需要调整脚本，并在将其添加到系统启动之前将脚本复制到系统初始化目录。

如果`freshclam`作为`cron`作业运行，而不是作为守护程序运行，则从脚本中删除启动和停止`freshclam`进程的行。

```
#!/bin/sh
#
# Startup script for the Clam AntiVirus Daemons
#
[ -x /usr/local/sbin/clamd ] || [ -x /usr/local/bin/freshclam ] || exit 0
# See how we were called.
case "$1" in
start)
echo -n "Starting Clam AntiVirus Daemon: "
/usr/local/sbin/clamd
echo -n "Starting FreshClam Daemon: "
/usr/local/bin/freshclam -d -p /var/run/clamav/freshclam.pid
;;
stop)
echo -n "Stopping Clam AntiVirus Daemon: "
[ -f /var/run/clamav/clamd.pid ] && kill `cat /var/run/clamav/clamd.pid`
rm -f /var/run/clamav/clamd.socket
rm -f /var/run/clamav/clamd.pid
echo -n "Stopping FreshClam Daemon: "
[ -f /var/run/clamav/freshclam.pid ] && kill `cat /var/run/clamav/freshclam.pid`
rm -f /var/run/clamav/freshclam.pid
;;
*)
echo "Usage: clamav {start|stop}"
;;
esac

```

# 监视日志文件

定期监视日志文件非常重要。在这里，您将能够跟踪病毒数据库的定期更新，并确保您的系统受到尽可能多的保护。

定期更新消息应该类似于以下内容：

![监视日志文件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-eml/img/8648_09_04.jpg)

偶尔会发布新软件并需要更新。在这种情况下，您将在日志文件中收到警告消息，例如以下内容：

![监视日志文件](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-eml/img/8648_09_05.jpg)

在出现互联网连接问题或远程文件在更新时不可用的情况下，该过程可能会记录瞬态错误消息。只要这些错误不持续存在，就无需采取任何行动。

# 文件消毒

常见的请求是在转发给最终接收者之前自动对文件进行消毒。在当前版本（0.95）中，ClamAV 无法对文件进行消毒。以下信息可从 ClamAV 文档中获取。

> 我们将在接下来的一个稳定版本中添加对 OLE2 文件的消毒支持。没有计划对其他类型的文件进行消毒。原因有很多：清除文件中的病毒在今天几乎是毫无意义的。清理后很少有任何有用的东西留下，即使有，你会相信它吗？

# 总结

我们现在已经安装并配置了一个非常高效的防病毒系统，用于检查所有传入电子邮件中的感染附件，并且已经显着加强了我们的系统——服务器和工作站——以防止攻击。

我们的邮件传输代理 Postfix 现在可以通过 ClamSMTP 内容过滤接口，使用 ClamAV 守护程序来过滤所有消息，以扫描和检测针对病毒签名数据库的各种威胁。通过使用`freshclam`，我们已经确保我们的检测数据库始终保持最新，以防范最新的威胁和任何新发布的病毒。在这场持续的战斗中，仍然需要保持不懈的警惕，以确保软件和文件始终保持完全最新。


# 第十章：备份您的系统

为了从重大硬件或软件故障中的灾难性服务丢失中恢复，绝对必须有备份。备份应该让您恢复软件（或者软件的配置）和其他需要重新建立服务的数据。这包括用户的邮件，系统的邮件队列以及它们的认证数据等。

本章将指导您完成必要的步骤，以防止系统故障，并在发生故障时如何从中恢复。阅读完本章后，您将了解：

+   可用的备份选项

+   我们需要备份哪些数据

+   我们备份介质的存储考虑

+   如何为邮箱执行增量和完整备份

+   完成文件系统恢复所需的步骤

+   如何恢复单个电子邮件

+   如何备份我们的服务器配置

+   设置自动备份计划

# 备份选项

选择最合适的备份选项总是一个权衡。您必须权衡业务停机成本，备份媒体和硬件的价格和可用性，用户数据的价值（在我们的情况下，用户的电子邮件），以及管理备份操作的人员成本。

对于我们的小型办公室电子邮件服务器，我们将提出一个简单但可靠的解决方案，使用多年来许多管理员采用的经过验证的技术和工具。

我们采取的任何备份都需要存储在备份介质上。最方便的解决方案是拥有一个备用的 Linux 机器，配备多个硬盘，与我们的电子邮件服务器相连，最好位于另一栋建筑物中。如果我们想要保护自己免受火灾等灾难性事件的影响，将备份存储在离站位置是必不可少的。

如果远程服务器不可用，另一种选择可能是连接到服务器的一些热插拔外部硬盘，甚至在紧急情况下使用 DVD 刻录机。磁带驱动器也是一个选择，但通常磁带驱动器和介质的成本大于服务器。如果可移动介质是唯一的选择，那么不要把备份堆叠在服务器顶部或桌子抽屉里，将它们移动到一个安全的离站位置。保留最新备份介质的本地副本以更快地应对紧急恢复情况可能更方便。

## RAID

RAID 是“冗余磁盘阵列”的缩写。通过在 RAID 设置中使用多个磁盘，数据分布在磁盘上，但操作系统将该阵列视为单个设备。通过在整个阵列中复制和分割数据，可以显著减少磁盘故障的容忍度，提高数据可靠性，可能提高 I/O 性能。如果阵列中的硬盘故障，旧硬盘可以被更换为新硬盘。然后，RAID 控制器（无论是硬件控制器还是软件控制器）会重建数据。有关 RAID 和可用的各种配置选项的更多信息，请访问[`en.wikipedia.org/wiki/RAID`](http://en.wikipedia.org/wiki/RAID)。

然而，单独使用 RAID 并不是一个备份解决方案。已删除的文件或电子邮件，无论是意外还是恶意删除，都无法恢复。RAID 无法保护用户错误或严重的硬件故障，例如使服务器烧毁的电涌甚至火灾。

使用 RAID 增加数据可用性是一件好事，但并不是适当备份和恢复策略的替代品。

## 镜像备份

磁盘镜像备份程序将从硬盘逐扇区地复制数据，而不考虑硬盘上的任何文件或结构。备份是硬盘的精确镜像——主引导记录，分区表和所有数据。

在发生重大硬件故障的情况下，恢复系统的步骤如下：

1.  更换或修复故障的硬件。

1.  引导 Linux 光盘，其中包含磁盘镜像恢复程序。

1.  将每个磁盘的映像写入备份。

1.  重新启动。

表面上看，这似乎是一种快速恢复服务的吸引人且快速的方法。然而，使用磁盘映像进行备份存在一些问题。

+   通常无法将磁盘映像恢复到大小或几何不同的新磁盘上。

+   新硬件几乎肯定会有不同的配置（主板、网络卡、磁盘控制器等），并且恢复的 Linux 内核可能没有必要的驱动程序来成功引导。

+   磁盘映像很大。映像是磁盘的总大小，而不仅仅是存储在其中的数据大小。多个磁盘映像的空间需求很快就会累积起来。

+   恢复单个用户文件非常麻烦。需要将磁盘映像恢复到备用磁盘上，挂载到运行中的系统上，然后找到后，复制到所需的位置。

总体系统故障很少发生，映像恢复的感觉上便利和快速通常被文件系统备份的灵活性所抵消。

## 文件系统备份

与映像备份不同，文件系统备份了解文件系统的结构，因此也了解硬盘上的数据。因此，只复制分配的磁盘部分，而不复制空闲空间。备份是针对文件系统中的所有文件而不是按扇区复制。

因为文件系统备份是这样完成的，这意味着可以仅复制自上次备份以来发生更改的文件，从而产生较小的后续备份文件。

在发生重大硬件故障时，恢复系统的步骤如下：

1.  更换或修复故障的硬件。

1.  安装 Linux 发行版。

1.  安装本书中的邮件服务器应用程序。

1.  应用任何补丁。

1.  恢复应用程序配置数据备份。

1.  恢复用户数据备份。

1.  重新启动

与映像备份相比，这种方法需要的时间略长，涉及的步骤更多，但确实具有许多优点。

+   替换磁盘不需要与原来的大小或几何相同。

+   只要您的 Linux 发行版支持新硬件，就不会出现兼容性问题。

+   备份文件大小要小得多。

+   恢复单个文件要简单得多。

如前所述，主要系统故障并不常见。尽管完成完全恢复的步骤比映像备份更繁琐，但较小且更快的备份以及用户数据选择性恢复的优势是显著的。

为了减少意外磁盘故障的可能性，系统工具可用于监视磁盘驱动器的健康状况。有关更多信息，请访问[`en.wikipedia.org/wiki/S.M.A.R.T.`](http://en.wikipedia.org/wiki/S.M.A.R.T)。

## 临时备份

文件系统备份仅备份整个文件系统，而不是单个文件或目录。偶尔，我们可能希望在我们的应用程序的重大配置更改后复制几个文件的副本。

使用标准的 Linux 工具，如`tar`或`cp`，可以将重要的更改文件复制到正常备份计划的文件系统中的目录。

# 备份什么

备份始终伴随着一个大问题：“我们应该备份什么？”

有许多因素影响我们最终的决定。当然，我们希望备份服务器的配置，因为这对服务器的功能至关重要。但我们也希望备份用户的数据，因为这是我们业务的宝贵资产。公司是否有政策允许人们使用电子邮件进行私人通信？如果有，我们是否也应该备份这些消息？

我们应该只备份我们需要将系统恢复到正常状态所需的内容。这可以节省备份介质上的空间，并缩短执行备份和必要时恢复所需的时间。

毕竟，备份介质上的空间是有限的，因此宝贵的。备份所有用户的邮件比完全备份`/tmp`目录更重要。此外，我们备份的数据越少，执行备份所需的时间就越少，因此更快地将系统资源（CPU 周期、I/O 带宽）返回到它们的主要用途——处理用户的邮件。

以下是我们需要备份以获得可用系统的项目列表：

+   系统清单

+   服务所需的已安装软件

+   软件配置文件

+   用户的凭据

+   用户的邮箱

+   日志文件（用于计费目的和最终用户请求）

+   Postfix 邮件队列

以下各节描述了讨论的每个项目。

## 系统清单

在部分或完全硬件故障的情况下，记录当前系统布局是有用的。在大多数情况下，替换硬件通常会和甚至更好地满足我们当前的设置。为了恢复我们的系统，我们需要知道磁盘如何分区以及挂载点的组织方式。将我们的用户数据恢复到一个太小的磁盘上将会很困难。

使用以下命令的输出，我们将有足够的信息来重新创建我们的磁盘布局：

```
# fdisk -l > disk_layout.txt

```

该命令打印出每个磁盘的分区表，并将输出保存到文件中。

```
# df -h >> disk_layout.txt

```

该命令将每个挂载点的容量和使用情况追加到我们的文件中。

```
# mount >> disk_layout.txt

```

`mount`命令列出当前的挂载点，我们将其追加到文件中。

可能还有其他信息在文件`/etc/fstab`中，我们稍后会备份。

## 获取已安装软件的列表

为了恢复我们安装的软件，我们需要有当前安装的软件列表。

在 Debian 中，可以使用以下命令。文件`installed_software.txt`包含系统上已安装/未安装的软件的当前状态。

```
# dpkg --get-selections > installed_software.txt

```

在基于 RPM 的发行版中，这将是：

```
# rpm -qa > installed_software.txt

```

在基于 Debian 的系统中，稍后可以使用此文件安装相同的软件集。

```
# dpkg --set-selections < installed_software.txt
# dselect

```

在`dselect`实用程序中，选择`i`进行“安装”，然后确认安装。

在基于 RPM 的发行版中，这将是：

```
# yum -y install $(cat installed_software.txt)

```

### 注意

刚才讨论的命令仅列出通过软件包管理器安装的软件。如果您从源代码安装了软件，请记下您安装的应用程序和版本。

## 系统配置文件

如果没有这些，服务器将无法执行预期的职责。至少需要备份的配置文件包括：

+   `/etc/courier:`该目录保存了 Courier-IMAP 的配置数据。

+   `/etc/postfix:`该目录保存了 Postfix 的配置数据。

目录树`/etc`包括诸如网络设置、路由等项目，我们否则需要记住。建议备份整个`/etc`树。

### 注意

如果您从非标准位置安装了带有配置文件的软件，请确保将这些配置文件包含在备份候选列表中。

## 认证数据

用户如果没有这些，将无法使用他们的用户名和密码组合进行身份验证。需要备份的数据取决于认证的方式，并且可能包括三个文件“/etc/passwd，/etc/shadow”和`/etc/group`，以及一个 MySQL 数据库（如果用户的凭据存储在该数据库中）。

## 用户的邮箱

这是用户的邮件存储位置。这包括整个`/home`及其子目录树。这是我们备份的主要内容——大量的数据。

## 日志文件

我们至少应该存储由 Postfix 和 Courier 生成的日志。这些将需要用于处理用户请求，比如“我的邮件去哪了？”。如果用户根据发送和/或接收的邮件量计费，我们肯定需要备份 Postfix 的日志。

由于 Postfix 和 Courier 的日志通常是由系统的`syslogd`守护程序写入的，我们需要检查`/etc/syslog.conf`文件，看看这些日志去哪里。这两个程序都使用`syslog`邮件设施记录它们的消息。

为了确保完全覆盖，最好备份`/var/log`的整个目录树。

## 邮件队列

根据情况，备份工作系统的 Postfix 队列可能有意义，也可能没有意义。

使用 Postfix，电子邮件消息至少会两次进入磁盘。

+   电子邮件消息第一次到达您的驱动器是在被 Postfix 接受时；它们被写入 Postfix 的`queue_directory`，然后交付继续进行。

### 注意

病毒扫描程序或检测垃圾邮件的程序（例如`clamav`和`spamassassin`）可能会产生更多的磁盘 I/O。

+   如果是本地域的邮件，我们的服务器是这些邮件的最终目的地，在`queue_directory`中的寿命极短。它们进入队列，然后立即传递到用户的邮箱。这是它们第二次进入磁盘。

+   如果是发往其他域的邮件（因为服务器充当中继），那么 Postfix 将立即联系收件人的邮件服务器，并尝试在那里传递消息。只有在出现问题的情况下，队列中才会包含大量尚未传递的电子邮件。这些问题包括：

+   `content_filter`很慢或者无法运行：例如`clamsmtp`或其他产品。

+   **远程站点存在问题：**大型免费电子邮件提供商经常出现问题，因此可能无法立即接受我们的电子邮件。

在这两种情况下，延迟队列将填满尚未传递的邮件，显然在发生故障时应该备份。如果服务器非常忙，队列中可能会有相当多的延迟邮件。

Postfix 邮件队列包括目录树`/var/spool/postfix`及其子目录。

# 不需要备份的内容

我们不需要备份所有已安装的二进制文件，因为这些可以通过前面提到的“已安装软件列表”简单地重新安装。当我们需要重建系统时，这当然假定安装介质是可用的。作为注重安全的管理员，我们通过安装供应商的补丁来保持系统的最新状态。随着时间的推移，已安装和随后打补丁的软件版本将与安装介质上的版本有很大不同。如果这些更新可以通过互联网安装（例如使用 Red Hat 的 up2date 或 Debian 的 apt-get），我们就不必将它们保存在现场。

# 备份用户的电子邮件

我们将使用 dump 来备份包含我们邮箱的整个分区。dump 命令将文件系统上的文件复制到指定的磁盘、磁带或其他媒体。

使用它的一些原因是：

+   它非常快（在我的测试中，网络是瓶颈）

+   它很简单（一个命令就足够了）

+   它可以无人值守运行（例如，作为`cron`作业）

+   它不需要安装任何额外的软件

+   它不需要图形用户界面

+   自 1975 年左右的 AT&T UNIX 版本 6 以来，它已经非常成熟了

`restore`命令执行与`dump`相反的操作。使用`dump`备份的文件系统可以作为完整的文件系统进行恢复，或者可以选择性地恢复某些文件或目录。

## 邮件存储

我们建议将邮箱（`/home`）放在单独的分区上，有很多原因。

+   文件系统维护可以独立于系统的其他部分进行（简单地卸载`/home`，执行`fsck`，然后再次挂载）。

+   可以将该分区放在单独的磁盘或 RAID 上，从而将用户的 I/O（在该分区上）与系统的 I/O（日志、邮件队列、病毒扫描程序）分开。

最重要的是：

+   使用`dump/restore`，我们可以转储整个分区。（好吧，这并不完全正确，但是只有整个分区才能轻松进行`dump/restore`。）

+   包含邮箱的超额分区不会对系统写入日志文件或其他重要系统信息产生负面影响。如果所有数据（日志、邮箱、系统文件）都在一个分区上，填满这个分区将导致日志记录停止。

Courier 和 Postfix 都使用 Maildir 格式存储用户邮箱。它们将每封邮件存储为单独的文件，即使对于单个邮件，也可以轻松进行恢复操作。

使用 Maildir 格式非常容易进行备份操作。

+   “备份电子邮件”对应于“将文件备份到备份介质”。

+   “恢复电子邮件”对应于“从备份介质中恢复文件”。

+   “备份邮箱”对应于“将 Maildir 及其所有子目录备份到备份介质”。

+   “恢复邮箱”对应于“从备份介质中恢复 Maildir 及其所有子目录”。

## 使用 dump

基本上有两种备份数据的方法。简单的方法是在每次备份时存储所有数据。这称为完整备份。它的优点是简单性，主要缺点是需要存储在备份介质上的大量数据。这个问题通过增量备份的概念得到解决。增量备份仅保存自上次增量（或完整）备份以来的更改。

如果备份介质上的空间允许每天进行完整备份，我们可以为了简单起见这样做。这样我们只需要查看最后一个完整备份来恢复所有数据。

增量备份很简单。备份软件只需要备份自上次备份以来最近创建或更改的文件和目录。

如果空间不允许使用这种简单的解决方案，我们可以使用以下方案：

+   每周执行一次完整备份

+   每天进行六次增量备份

如果我们需要从头开始恢复，首先恢复最后一个完整备份，然后恢复最多六个增量备份。这样我们最多会丢失一天的邮件，这是我们在每日备份间隔下能够做到的。稍后我们将看到更复杂的增量备份策略，以减少恢复完整转储后需要的增量恢复次数。

有关`dump(8)`和`restore(8)`的详细信息，请参阅系统手册页。

现在我们将看一下使用`dump`命令备份邮箱的实际任务。

### 完整转储

我们现在将执行包含用户 Maildirs 的分区的完整备份。在这个例子中，这个分区将是`/dev/sdb1`（我们的 SATA 磁盘的第一个分区）。因此，我们将要备份`/dev/sdb1`。

要找出我们需要在系统上备份的分区，我们需要检查`mount`命令的输出：

```
# mount

```

```
/dev/sda1 on / type ext3 (rw,relatime,errors=remount-ro)
tmpfs on /lib/init/rw type tmpfs (rw,nosuid,mode=0755)
/proc on /proc type proc (rw,noexec,nosuid,nodev)
sysfs on /sys type sysfs (rw,noexec,nosuid,nodev)
varrun on /var/run type tmpfs (rw,nosuid,mode=0755)
varlock on /var/lock type tmpfs (rw,noexec,nosuid,nodev,mode=1777)
udev on /dev type tmpfs (rw,mode=0755)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)
devpts on /dev/pts type devpts (rw,noexec,nosuid,gid=5,mode=620)
fusectl on /sys/fs/fuse/connections type fusectl (rw)
lrm on /lib/modules/2.6.27-14-generic/volatile type tmpfs (rw,mode=755)
/dev/sdb1 on /home type ext3 (rw,relatime)

```

我们可以看到，`/home`是`/dev/sdb1`的分区。

我们的计划是使用`dump`工具为这个分区创建备份。这些备份数据需要传输到我们的备份介质，可以是另一块磁盘、磁带，或者在我们的情况下是远程备份服务器上的磁盘。

有各种方法可以在网络上传输数据，其中之一是`ssh`。这是一种网络协议，可以促进两个设备之间的安全通信。

为了将我们的备份数据通过网络传输到备份服务器中的另一块磁盘，我们利用 Linux 的强大功能来结合`dump`程序和`ssh`协议。

`dump`程序的输出将被输入到`gzip`中以压缩转储，然后传输到`ssh`，然后在备份服务器上生成另一个`dd`程序，最终将数据写入其磁盘。

以下代码行将分区中的邮箱完全转储到远程系统上的文件。我们假设邮箱位于挂载为`/home`的分区`/dev/sdb1`上。

以 root 用户身份运行以下命令：

```
# dump -0 -u -b 1024 -f - /dev/sdb1 | \
gzip -c | \
ssh user@backup-host.domain.com \
dd of=/backupdirectory/$(date +%Y%m%d%H%M%S).home.dump.0.gz

```

该命令看起来很复杂，所以让我们逐步分解每个步骤：

+   `dump -0 -u -b 1024 -f -`执行分区`/dev/sdb1`（在我们的示例中包含`/home`）的级别`0`（`full`）转储，使用块大小`1024`（以获得最佳性能），并在成功转储后更新（`-u`）文件`/var/lib/dumpdates`。`-u`选项很重要，因为它记录了此转储的日期和时间，因此随后的增量转储可以确定自上次转储以来已更改或创建的文件。转储的输出进入指定为（`-`）的文件（`-f`），该文件表示`stdout`，标准输出。

+   由于`dump`数据进入标准输出（`stdout`），我们可以将该输出管道传输到`gzip`以压缩转储的大小。`-c`选项告诉`gzip`将压缩输出写入`stdout`。

+   然后，压缩级别 0 的转储输出被传送到`ssh`命令，该命令与系统`backup-host.domain.com`建立远程连接，以`user`身份登录。一旦登录，远程系统执行`dd`命令。我们建议使用`ssh`提供的基于密钥的身份验证方案。这样，备份可以无人值守运行，因为没有人需要输入登录`backup-host.domain.com`上的`user`所需的密码。

+   在远程服务器上，最后一步是使用`dd`命令写入输出。输出文件名由`dd`的`of`选项指定。输出文件名已经构造成易于识别文件系统、转储日期和时间、转储级别以及后缀`.gz`以指示此转储文件已被压缩。文件名部分`$(date +%Y%m%d%H%M%S`)是在本地系统上执行的 shell 扩展（而不是远程系统），以输出当前日期和时间以`YYYYMMDDHHMMSS`格式。最终的输出文件名将类似于`20090727115323.dump.0.gz`。

有关每个命令的更多信息，请参阅`dump、gzip、ssh、dd`和`date`的系统手册页面。

输出将类似于以下内容：

![完整转储](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-eml/img/8648_10_01.jpg)

下一个示例将简单地将备份数据写入一个目录，这次没有`stdout`的巫术！

以下代码行将完整转储包含邮箱的分区写入一个单独的磁盘上的文件以保存备份：

```
# dump -0 -u -f /backupdirectory/fulldump /dev/sdb1

```

当然，这比通过`ssh`将所有数据加密并在传输过程中进行解密（这需要大量时间和 CPU 功率）快得多简单得多，但如果我们的服务器被烧毁，内置硬盘上的备份将毫无帮助。

请记住，`/backupdirectory/fulldump`也可以是 NFS 挂载或 SMB 挂载。这将为您提供简单命令行和远程备份的优势。因此，请确保您有远程备份。无论哪种方式都很容易。

### 增量转储

增量转储的执行方式与完整转储完全相同，只是我们将级别选项从 0 更改为 1、2 或 3，等等，具体取决于我们希望备份多少更改。请记住，级别数字大于 0 告诉转储复制自上次较低级别转储以来新建或修改的所有文件。这最好通过一些示例来说明。为了清晰起见，我们将简单地转储到一个文件中，但在实践中，我们通常会使用与使用`gzip、ssh、dd`等相同的命令序列。

假设我们的级别 0 转储是在星期日晚上进行的。第一个增量转储（级别 1，由`-1`选项指示）然后在星期一晚上进行，如下所示：

```
# dump -1 -u -f mon.dump.1 /dev/sdb1

```

这将保存自上次完整转储以来新建或更改的所有内容到`mon.dump.1`。这个转储文件将比之前的完整转储小得多，只包含星期一的更改。假设在第二天我们重复这个级别 1 转储

```
# dump -1 -u -f tue.dump.1 /dev/sdb1

```

第二个增量转储`tue.dump.1`将包含周一和周二所做的所有更改，因为 1 级转储将备份自 0 级转储以来发生的所有更改。为了将系统恢复到最新的备份，我们只需要恢复周二的备份。因此，有人可能认为周一的转储现在已经过时；然而，如果用户希望恢复在周一创建并在周二意外删除的文件，我们仍然需要第一次备份。

反复执行 1 级转储允许非常快速的恢复，因为只需要恢复两个转储文件，即 0 级转储和最新的 1 级转储。缺点是每个后续转储文件的大小都会增加，并且完成时间会越来越长。这种方案有时被称为差异备份。

另一种选择是使用额外的转储级别来减少每个备份文件的大小。

例如，以下一系列命令在我们的初始 0 级转储后执行了许多增量备份：

```
# dump -1 -u -f mon.dump.1 /dev/sdb1
# dump -2 -u -f tue.dump.2 /dev/sdb1
# dump -3 -u -f wed.dump.3 /dev/sdb1
# dump -4 -u -f thu.dump.4 /dev/sdb1

```

在这个例子中，每天的转储文件只包含自上一个转储以来的新文件和更改文件。从周二开始的每个转储操作将更快地完成，并且生成的文件大小比我们之前的例子要小。然而，恢复将需要更长时间。要恢复到最新的备份，我们需要恢复完整的转储，然后按顺序恢复从周一到周四的每个增量转储。

在一个小的临时文件系统上尝试这些示例可能是一个有用的练习，以便了解不同级别的转储之间的交互。可以使用以下命令检查每个转储文件：

```
# restore -t -f filename

```

对于好奇的人，文件`/var/lib/dumpdates`也可以在每次转储后进行检查，以验证每次转储的日期和级别。

正如本章开头所述，一切都是一种权衡，因此选择适当的备份策略涉及平衡媒体成本、人员成本和恢复时间。

到目前为止，我们所有的备份都是在挂载的磁盘上执行的，这使得验证备份是不可能的。原因是我们刚刚备份的数据不断变化。请记住，每个文件代表一封电子邮件。每当用户收到新邮件或删除旧邮件时，文件系统的状态都会发生变化。用户不断地收邮件、阅读邮件和删除邮件，即使在进行备份之前也是如此。

`restore`命令确实有`-C`选项，用于将转储与原始磁盘内容进行比较，但只有在我们转储的文件系统未挂载时才是明智的。在大多数情况下，卸载每个文件系统是不切实际的，并且会显著中断服务。

## 使用 restore

所有已备份的数据在使用之前都需要被恢复。

这可以通过两种方式完成，交互式或非交互式。

### 交互式恢复

要交互地从转储中恢复数据，我们需要将转储从备份介质复制到我们的系统上，或者在存储转储的计算机上执行文件选择以进行恢复。如果我们只提取几个文件，可以在临时目录中执行此操作，并在恢复完成后将生成的文件移动到正确的位置。对于更多的文件，例如整个用户帐户，我们可以在开始恢复之前`cd`到最终目的地。

对于交互式恢复，请运行以下命令：

```
# restore -i -f /backupdirectory/subdir/dumpfile
>

```

`>`是交互式接口的提示符，用于恢复。这是一个简陋的界面，可用的命令有限。它允许通过转储进行导航，就好像我们在实时文件系统上一样。使用`ls`和`cd`来显示目录内容或更改目录。输入`?`以获取支持的命令列表。

一旦找到要恢复的数据，输入以下命令之一：

+   `> add directoryname`

+   `> add filename`

这将把特定的“目录名”和其下所有数据，或者只是“文件名”添加到需要还原的文件集中。对于其他文件或目录重复此操作。

一旦我们添加了所有需要恢复的数据，我们发出`extract`命令。

![交互式还原](https://github.com/OpenDocCN/freelearn-linux-zh/raw/master/docs/linux-eml/img/8648_10_02.jpg)

前一个屏幕截图中显示的输出与磁带上的卷号有关。一个转储文件可能已经分割成多卷磁带集，但在处理硬盘上的转储文件时，选择卷`1`。通常我们会选择`n`以保留工作目录的当前所有权和权限。

一旦必要的文件被提取出来，执行以下命令：

```
> quit

```

对于最后一个完整转储和每个增量转储，按顺序进行，直到可用的最后一个增量转储。这样可以确保我们还原自上次完整备份以来的所有更改。

### 注意

如果我们要还原的数据在两次转储之间没有发生变化，我们在第二个增量转储中将找不到它。

### 网络上的非交互式还原

如果我们只想还原几个邮箱，手动方法是有意义的。如果我们需要完全恢复所有邮箱，我们需要使用非交互式方案。这不需要目标系统上的额外存储空间，因为转储数据正在通过网络传输。

在我们新安装的、新分区的硬盘上重新创建文件系统并挂载它：

```
# mke2fs -j /dev/sdb1
# mount /dev/sdb1 /home

```

`-j`选项对`mke2fs`在`/dev/sdb1`上创建一个 ext3 日志文件系统，并将其挂载为`/home`。

请注意，我们需要使用创建备份时使用的相同文件系统来重新创建数据！

让还原开始。

```
# cd /home
# ssh user@backup-host.domain.com \
dd if=/backupdirectory/20090601030034.home.dump.0.gz | \
gunzip -c | restore -r -f -

```

就像我们在网络上执行备份时一样，现在我们也要用还原来做同样的操作。

```
ssh user@backup-host.domain.com

```

前一行将以下命令作为`backup-host.domain.com`主机上的`user`执行，尽管这次使用`dd`命令使用`if`选项读取压缩的转储文件并将输出发送到`stdout`。

```
dd if=/backupdirectory/20090601030034.home.dump.0.gz

```

输出通过网络传输并输入到`gunzip`中解压文件，最终传输到`restore -r -f -`。`-r`选项指示还原从转储文件的内容到原始位置使用原始权限和所有权重新构建整个文件系统。如果需要，可以使用`restore`的`-v`选项进行详细输出。

### 注意

在发出`restore`命令之前，必须确保我们位于正确的目录中，否则可能会对现有文件系统造成严重损坏。

还原的输出看起来会像这样：

```
# ssh backup@nas1 dd if=backups/20090727153909.home.dump.0.gz \ | gunzip -c | restore -r -f -
restore: ./lost+found: File exists
1629153+1 records in
1629153+1 records out
834126574 bytes (834 MB) copied, 71.4752 s, 11.7 MB/s
#

```

关于`lost+found`存在的警告是正常的，可以安全地忽略。

然后，这个操作应该对每个需要将系统恢复到所需状态的增量转储文件重复进行。如果我们以错误的顺序还原增量转储，将会出现错误“增量磁带太低”或“增量磁带太高”。一旦我们收到这些错误中的一个，就无法完成完整的还原，必须从级别 0 的转储重新开始还原。

当使用`-r`选项执行还原命令时，它将创建文件`restoresymtable`。这是一个检查点文件，还原命令在还原多个转储时使用它来帮助下一个`restore`命令确定哪些目录或文件需要更新、创建或删除。

一旦文件系统完全还原并验证，我们应该删除`restoresymtable`文件。如果这个文件包含在下一个转储中，旧的`restoresymtable`文件可能会覆盖正在创建的文件，并阻止其他转储的还原。

作为最后一步，对新还原的文件系统执行级别 0 的`dump`。

# 备份配置和日志

备份配置数据和重要日志文件有两种方法。

+   **将数据存储在我们的备份介质上：**使用这种方法，我们将直接备份到我们的备份服务器。

+   **将数据添加到我们的备份计划中：**这种方法将包括必要的文件作为我们用户数据备份的一部分。

任何一种情况都是同样有效的，实际上是个人偏好的问题。

作为提醒，之前我们列出了需要备份的系统重要部分。这些是：

| 系统的重要部分 | 示例命令 |
| --- | --- |
| --- | --- |
| 系统清单 | `disk_layout.txt` |
| 已安装软件列表 | `installed_software.txt` |
| 系统配置文件 | `/etc` |
| 认证数据 | `/etc/password /etc/groups /etc/shadow` |
| 日志文件 | `/var/log` |
| 邮件队列 | `/var/spool/postfix` |

由于每个系统都不同，您应该确保下面给出的示例命令涵盖了所有必要的文件。

## 将配置和日志传输到备份介质

为了简化操作，我们只需使用`tar`工具创建文件和目录的存档，并将其存储在备份服务器上完整或增量转储的相同目录中：

```
# tar cz disk_layout.txt installed_software.txt \
/etc /var/log /var/spool/postfix | \
ssh user@backup-host.domain.com \
dd of=/backupdirectory/$(date +%Y%m%d%H%M%S).config.tar.gz

```

或者，我们可以在`/home`文件系统上创建`tar`存档，并将其作为我们正常备份计划的一部分进行备份。

```
# mkdir -p /home/config
# chmod 600 /home/config
# tar czf /home/config/$(date +%Y%m%d%H%M%S).config.tar.gz \
disk_layout.txt installed_software.txt \
/etc /var/log /var/spool/postfix

```

在这两种情况下，我们使用`tar`命令，选项为`c`创建存档，`z`压缩，`f`作为输出存档名称。还要注意，我们已经限制了对`/home/config`目录的访问，因为它包含了应该受到保护的敏感信息的存档。

有关`tar`的更多信息，请参阅系统手册页。

## 恢复配置

根据之前使用的方法，恢复我们的配置和日志文件相对简单。我们可以从备份服务器复制所需的存档，或者直接使用`/home/config`中的存档。在任何情况下，解压存档都是使用以下命令执行的：

```
# mkdir tmpdir
# cd tmpdir
# tar xzf xxxxx.config.tar.gz

```

请注意，在扩展存档之前，我们已经创建并移动到了一个临时目录。如果我们执行`tar`命令时当前目录是`/`，我们将覆盖`/etc、/var/log`和`/var/spool/postfix`中的所有文件，可能会产生不良后果。

现在我们已经解压了存档，我们可以比较并复制我们需要恢复的文件。

# 自动化备份

现在我们已经看到如何备份我们的系统，我们需要建立一个自动化的程序来消除手动调用`dump`的繁琐。

转储的手册页确实提供了一些关于多久进行备份以及在哪个级别减少恢复时间的指导。

> *在发生灾难性的磁盘事件时，通过错开增量转储的时间，可以将将所有必要的备份磁带或文件恢复到磁盘所需的时间最小化。错开增量转储的有效方法以最小化磁带数量如下：*
> 
> *始终从 0 级备份开始。这应该在固定的时间间隔内进行，比如每个月或每两个月一次，并且使用一组永久保存的新磁带*。
> 
> *在进行 0 级备份后，每天对活动文件系统进行转储，使用修改后的汉诺塔算法，转储级别的顺序为：3 2 5 4 7 6 9 8 9 9 . . . 对于每天的转储，应该可以使用固定数量的磁带，每周使用一次。每周进行 1 级转储，并且每天的汉诺塔序列从 3 开始重复。对于每周转储，每个转储的文件系统也使用一组固定的磁带，也是循环使用的*。
> 
> *几个月后，每天和每周的磁带应该被从转储周期中移出，并带入新的磁带*。

这一系列转储看起来相当奇怪，需要更多的解释。通过这个过程，我们将说明如何最小化转储的大小并减少恢复所需的数量。

一旦进行了级别 3 的转储，恢复只是恢复转储 0 和 3。第二天后，级别 2 的转储将备份自上次较低级别的转储以来发生的所有更改，即级别 0。这使级别 3 的转储无效。然后，级别 5 的转储将备份自级别 2 转储以来的更改。随着序列的进行，使用更高级别和更低级别来跳过天数，以前的转储变得无效，不再需要完成完全恢复。每个转储仍应保留，以防我们需要在以后的某个时间恢复意外删除的单个文件。

到了周末，执行级别 1 的转储，使之前几周的转储级别都变得过时，然后在月底重新开始，进行新的级别 0 的转储。

以下表格说明了每天采取的转储级别以及恢复数据到最新版本所需的次数：

| 日期 | 转储级别 | 需要的恢复级别 |
| --- | --- | --- |
| 1 | 0 | 0 |
| 2, 9, 16, 23, 30 | 3 | 0, 1*, 3 |
| 3, 10, 17, 24, 31 | 2 | 0, 1*, 2 |
| 4, 11, 18, 25 | 5 | 0, 1*, 2, 5 |
| 5, 12, 19, 26 | 4 | 0, 1*, 2, 4 |
| 6, 13, 20, 27 | 7 | 0, 1*, 2, 4, 7 |
| 7, 14, 21, 28 | 6 | 0, 1*, 2, 4, 6 |
| 8, 15, 22, 29 | 1 | 0,1 |

### 注意

在第一周，级别 1 的转储（标有*）在恢复过程中不是必需的。从第八天开始，级别 1 的转储总是必需的。

从表中我们可以看到，即使在月底，只需要几次转储就可以恢复我们的数据，而不是每天创建增量转储时需要的几十次。

通过我们的月度备份计划，一个简单的脚本和添加一些条目到`cron`，将完成自动备份过程。

## 备份脚本

以下示例 bash 脚本将存档我们的系统配置和日志文件，并将请求的文件系统转储到远程备份服务器。这只是一个示例脚本，应根据您的需求进行修改。为了清晰起见，任何错误检查和日志记录都已省略。

```
#!/bin/sh
# The name of the dump, e.g. home or users
NAME=$1
# The partition to dump, e.g. /dev/sdb1
DEVICE=$2
# The dump level, e.g. 0 or 3 etc.
LEVEL=$3
# ssh login name and host
#
USERNAME=user
BACKUPHOST=backuphost
# Take a system inventory.
#
/sbin/fdisk -l > /tmp/disk_layout.txt
/bin/df -h >> /tmp/disk_layout.txt
/bin/mount >> /tmp/disk_layout.txt
# Installed software (Debian)
#
/usr/bin/dpkg --get-selections > /tmp/installed_software.txt
# Archive our system configuration and logs
#
/bin/tar cz /tmp/disk_layout.txt /tmp/installed_software.txt \
/etc /var/log /var/spool/postfix | \
/usr/bin/ssh $USERNAME@$BACKUPHOST \
/bin/dd of=$(date +%Y%m%d%H%M%S).config.tar.gz
# Perform the dump to the remote backup server.
#
/usr/sbin/dump -u -$LEVEL -f - $DEVICE | \
/bin/gzip -c | ssh $USERNAME@$BACKUPHOST \
/bin/dd $(date +%Y%m%d%H%M%S).$NAME.dump.$LEVEL.gz"
# Remove temporary files.
#
rm -f /tmp/disk_layout.txt /tmp/installed_software.txt
exit 0

```

该脚本需要 3 个参数，转储的名称，要转储的分区和转储级别。

典型的用法如下：

```
# remote-dump.sh home /home 0

```

上一个脚本每次运行都会存档`/etc`。您可能希望将这些命令移到一个单独的脚本中，每周或每月执行此任务。如果脚本将用于转储其他文件系统，则这一点尤为重要。

脚本不会删除以前几个月的旧转储文件，这可能会填满我们的备份服务器，从而阻止未来的备份。最好制定程序，根据组织的数据保留政策，删除或存档旧的转储文件。

## 添加 crontab 条目

每晚自动运行我们的备份脚本只是使用备份计划表中的条目并执行脚本来转储正确的分区。以下示例`crontab`条目每晚在 02:10 执行我们的脚本来转储`/home`。每个月的第一天，执行级别 0 的转储，然后每隔七天执行一次每周级别 1 的转储。其他条目实现了修改后的“汉诺塔”算法。

```
10 02 1 * * /bin/remote-dump.sh home /home 0
10 02 2,9,16,23,30 * * /bin/remote-dump.sh home /home 3
10 02 3,10,17,24,31 * * /bin/remote-dump.sh home /home 2
10 02 4,11,18,25 * * /bin/remote-dump.sh home /home 5
10 02 5,12,19,26 * * /bin/remote-dump.sh home /home 4
10 02 6,13,20,27 * * /bin/remote-dump.sh home /home 7
10 02 7,14,21,28 * * /bin/remote-dump.sh home /home 6
10 02 8,15,22,29 * * /bin/remote-dump.sh home /home 1

```

一旦我们的自动备份程序就位，我们需要密切关注任何错误，并验证远程服务器上转储文件的完整性。

# 验证恢复程序

即使做了最好的计划，事情也会出错，而且总是在最不方便的时候。

采取积极的灾难恢复方法，进行良好的规划和实践，将在太迟之前就能发现任何问题。验证系统备份的完整性只有通过恢复它们并检查恢复的系统是否完全可操作才是真正可能的。

您应该问自己一些问题，比如，“如果远程服务器出现故障，需要采取哪些措施？”您是先修复备份服务器还是切换到另一台服务器以减小没有备份的时间窗口？如果邮件服务器出现故障，您是否熟悉恢复程序？例如，是否可以在短时间内获得替换硬件，比如在星期天？

有许多管理员勤奋地进行备份，却发现在需要时备份无用，因为磁带驱动器错误或备份脚本中的轻微语法错误覆盖了有效的转储文件，导致数据损坏。

为自己构想情景，并在备用硬件上练习完全裸金属恢复，或者恢复单个用户的电子邮件。

验证恢复程序是否有效将使您相信您可以从数据丢失中恢复过来。

# 总结

在本章中，我们描述了如何备份电子邮件和邮件服务器配置。我们从介绍应该考虑备份的内容开始，最后使用自动完全和增量备份的复杂解决方案结束。

特别是，我们描述了使用`dump`命令的过程，以及如何复制我们的数据。我们使用`restore`命令来恢复完整的文件系统和选择性文件。

本章指导您备份和恢复服务器宝贵数据的过程。它展示了为什么要备份，备份哪些数据，不同的备份和恢复方法，以及进行自动每日备份的程序。

在实施本章中向您展示的所有程序之后，您将睡得更香甜，而且无论如何，您的用户都会喜欢系统所能提供的范围和功能。
