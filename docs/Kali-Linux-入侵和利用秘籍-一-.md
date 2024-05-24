# Kali Linux 入侵和利用秘籍（一）

> 原文：[`annas-archive.org/md5/38D0D8F444F88ADA9AC2256055C3F399`](https://annas-archive.org/md5/38D0D8F444F88ADA9AC2256055C3F399)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书揭示了使用 Kali Linux 进行渗透测试过程的最佳方法和技术。这对网络系统管理员是一个增值，帮助他们了解整个安全测试方法。这将帮助他们在日常攻击中保护自己，使他们能够提前找到并修补漏洞。由于企业环境中的渗透测试通常是每年进行一次，这将帮助管理员定期主动保护他们的网络。

本书涵盖了开始进行安全测试和在企业网络或正在测试的服务器上执行自己的安全评估的方法。通过本书，您将开发出更广泛的技能和完整的渗透测试场景的知识，您将能够对任何网络执行成功的渗透测试。

Kali Linux 是一个带有先进工具的先进操作系统，将帮助识别、检测和利用漏洞。它被认为是成功的安全测试的一站式操作系统。

# 本书涵盖的内容

第一章，“入门-设置环境”，教你如何在系统、亚马逊云、移动设备和 Docker 上安装 Kali Linux 和 Kali 产品。本章帮助您熟悉在多种便利的媒介上安装 Kali Linux，以及安装多个第三方工具。

第二章，“网络信息收集”，涵盖了在网络上发现服务器和开放端口。您还将学习探测服务和抓取横幅，以及扫描网络的不同方式，包括 IDS/IPS/防火墙绕过。

第三章，“网络漏洞评估”，向您展示了如何使用某些 Kali 工具进行漏洞评估。您将通过测试一个脆弱的机器来学习漏洞评估。您还将学习使用高级工具进行评估。

第四章，“网络利用”，涵盖了多种技术，用于入侵网络服务，如 FTP、HTTP、SSH、SQL。此外，您还将学习如何利用 Linux 和 Windows 机器上的脆弱服务。

第五章，“Web 应用信息收集”，展示了如何进行 Web 应用程序侦察，通过 DNS 协议进行收集，并检测 WAF 防火墙/负载均衡器。您还将学习如何进行暴力破解以发现隐藏的文件/文件夹和 CMS/插件检测，以及发现 SSL 密码协议漏洞。

第六章，“Web 应用漏洞评估”，演示了如何使用各种 Web 应用测试工具在应用程序中查找漏洞，并设置代理和通过代理进行各种攻击。

第七章，“Web 应用利用”，教你如何利用基于 Web 的漏洞。您将学习如何进行 RFI/LFI 攻击，WebDAV 利用，利用文件上传漏洞，SQL 注入漏洞等。

第八章，“系统和密码利用”，展示了如何破解 Windows/Linux OS 上的密码哈希。您还将学习如何使用社会工程工具包和 BEef-xxs 进行利用，并访问目标系统。

第九章 *权限提升和利用*，为您提供了一个实际的方法来提升系统/根权限。您将学习各种技术，帮助您在 Windows 机器上提升权限。

第十章 *无线利用*，教你如何设置无线网络进行渗透测试和了解基础知识。您还将学习如何破解 WEP、WPA2 和 WPS。除此之外，您还将学习拒绝服务攻击。

附录，*渗透测试 101 基础*，这将帮助读者了解不同类型的测试方法，为什么要进行测试以及企业级测试的工作原理。它还使人了解整个安全测试的目标。

# 本书需要什么

要按照本书中的步骤，您将需要最新版本的 Kali Linux；可以在[`www.kali.org/downloads/`](https://www.kali.org/downloads/)找到。详细的安装步骤在 Kali 的 readme 部分中介绍，可以在[`docs.kali.org/category/installation`](http://docs.kali.org/category/installation)找到。对于无线测试，将需要一个无线设备；我们演示了使用 alfa awus036h 卡进行测试。具有类似功能的芯片组可以在[`www.aircrack-ng.org/doku.php?id=compatibility_drivers`](https://www.aircrack-ng.org/doku.php?id=compatibility_drivers)找到。

在某些情况下，有必要安装 Docker，读者可以从中拉取易受攻击的镜像并开始测试。Docker 可以从[`www.docker.com/get-docker`](https://www.docker.com/get-docker)安装。我们还展示了如何在 OnePlus One 移动设备上安装 NetHunter；为此，将需要 OnePlus One 或 Kali NetHunter 支持的设备。NetHunter 支持的设备包括：Nexus 5、Nexus 6、Nexus 7、Nexus 9、Nexus 10 和 OnePlus One。

# 这本书是为谁写的

本书致力于所有系统网络管理员，以及希望了解企业网络安全测试方法的个人。即使是初学者也可以找到合适的内容来了解测试 Linux、Windows 服务器和无线网络。

# 章节

在本书中，您会发现一些经常出现的标题（准备工作、如何做、它是如何工作的、还有更多、另请参阅）。

为了清晰地说明如何完成一个配方，我们使用以下部分：

## 准备工作

本节告诉您在配方中可以期待什么，并描述如何设置任何软件或配方所需的任何预备设置。

## 如何做…

本节包含了遵循配方所需的步骤。

## 它是如何工作的…

本节通常包括对前一节发生的事情的详细解释。

## 还有更多…

本节包含有关配方的其他信息，以使读者更加了解配方。

## 另请参阅

本节提供了有关配方的其他有用信息的链接。

# 约定

在本书中，您会发现一些区分不同类型信息的文本样式。以下是这些样式的一些示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："在您的终端窗口中，用您喜欢的编辑器打开`/etc/apt/sources.list.d/backports.list`文件。"

任何命令行输入或输出都以以下方式编写：

```
docker pull kalilinux/kali-linux-docker

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这样的方式出现在文本中："选择您喜欢的语言，然后点击**继续**。"

### 注意

警告或重要说明会以这样的方式出现在一个框中。

### 提示

提示和技巧会显示在这里。


# 第一章： 入门-设置环境

在本章中，我们将介绍与首次使用 Kali Linux 设置相关的基本任务。 配方包括：

+   在云上安装 Kali Linux-Amazon AWS

+   在 Docker 上安装 Kali Linux

+   在 OnePlus One 上安装 NetHunter

+   在虚拟机上安装 Kali Linux

+   定制 Kali Linux 以实现更快的软件包更新

+   定制 Kali Linux 以实现更快的操作

+   配置远程连接服务-HTTP，TFTP 和 SSH

+   配置 Nessus 和 Metasploit

+   配置第三方工具

+   在 Kali Linux 上安装 Docker

# 介绍

Kali Linux 是最受欢迎的 Linux 渗透测试发行版 Backtrack 的全面改版。 Kali Linux 2.0 于 2015 年 8 月 11 日推出，是 Kali Linux 的改进版本，具有全新的内核 4.0，并基于 Debian 的 Jessie 版本，具有改进的硬件和无线驱动程序覆盖范围，支持各种桌面环境（GNOME，KDE，XFCE，MATE，e17，LXDE 和 i3wm）和工具等等。

如果您要从 Kali Linux 升级到 Kali Linux 2.0，那么有一个好消息。 好消息是现在我们有了一个滚动的发行版。 例如，Kali Linux 核心不断更新。

Kali Linux 具有您进行渗透测试和安全评估所需的一切，而无需考虑下载，安装和为您的工具库中的每个工具设置环境。 Kali Linux 2.0 包括 300 多种安全工具。 您现在可以在一个地方安装，配置和准备使用全球专业人士最喜欢的安全工具。

所有安全工具都已经被逻辑地分类并映射到执行一系列步骤的测试人员，例如，侦察，扫描，利用，权限提升，保持访问权限和覆盖轨迹。

安全工具通常很昂贵，但 Kali Linux 是免费的。 使用 Kali 的最大优势是它包含各种商业安全产品的开源或社区版本。

Kali Linux 2.0 现在支持比以往更多的硬件设备。 由于基于 ARM 的系统变得更便宜和更易获得，现在可以使用 ARMEL 和 ARMHF 支持在这些设备上运行 Kali Linux。 目前，Kali Linux 可用于以下 ARM 设备：

+   树莓派（树莓派 2，树莓派 A/B+和树莓派 A/B+ TFT）

+   CompuLab-Utilite 和 Trim-Slice

+   BeagleBone Black

+   ODROID U2/X2

+   Chromebook-HP，Acer 和 Samsung

+   Cubieboard 2

+   CuBox（CuBox 和 CuBox-i）

+   Nexus 5（Kali Nethunter）

+   Odroid（U2，XU 和 XU3）

+   USBArmory

+   RioTboard

+   FriendlyARM

+   BananaPi

# 在云上安装 Kali Linux-Amazon AWS

将 Kali Linux 列入 Amazon EC2 Marketplace 已经将近 2 年了。 这对于渗透测试人员来说是一个非常好的消息，因为他们可以在 Amazon AWS 基础架构中设置自己的 Kali Linux 并用于渗透测试，而且甚至符合免费套餐的条件，只要您在指定的限制范围内使用它，这是相当公平的。

本配方中提供的步骤将帮助您在 Amazon AWS EC2 控制台上安全地设置运行 Kali Linux 的实例，仅需几分钟。

## 准备好

对于这个配方，您需要：

+   一个 Amazon AWS 帐户

+   至少 2GB RAM，如果要运行 Metasploit

## 如何做...

按照本配方执行以下步骤：

1.  创建了 Amazon AWS 帐户后，登录到[`aws.amazon.com`](https://aws.amazon.com)，并转到**Amazon Web Services**仪表板，如下面的屏幕截图所示。 转到**EC2** | **Launch Instance**：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_001.jpg)

1.  您需要选择**Amazon Machine Image (AMI)**，如下面的屏幕截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_002.jpg)

1.  单击**AWS Marketplace**选项，并在**AWS Marketplace**上搜索 Kali Linux，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_003.jpg)

1.  单击**Select**，然后单击**Continue**，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_004-1.jpg)

1.  现在您已经在第 2 步显示的屏幕上。在这里，您可以选择实例类型；请注意，只有**t1.micro**和**t2.micro**才符合免费套餐的条件。但是，运行 Metasploit 需要至少 2GB 的 RAM。为此，您可以根据预算选择**t2.small**或**t2.medium**，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_005-1.jpg)

1.  单击**Review and Launch**。您将看到一个弹出窗口，询问您是否要将 SSD 用作启动卷。选择**Make general purpose (SSH)...(recommended)**，然后单击**Next**，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_006-1.jpg)

1.  您将直接进入第 7 步进行审查，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_007.jpg)

1.  首先会看到一个警告，提示您改善实例安全性；单击**6.配置安全组**，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_008-1.jpg)

1.  单击**Source**下拉列表，选择**My IP**，它将自动检测您的公共 IP 范围。单击**Review and Launch**。请注意，这仅在您拥有专用公共 IP 时才有效。如果您有动态 IP，您需要重新登录到 AWS 控制台，并允许您的更新 IP 地址：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_009-1.jpg)

1.  正如您所看到的，有一个警告说您不符合免费使用套餐的条件，因为我们选择了**m2.medium**，需要至少 2GB 的 RAM：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_010-1.jpg)

1.  单击**Launch**；在这里，您需要在继续之前创建并下载一个新的密钥对，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_011-1.jpg)

1.  下载了密钥对后，继续单击**Launch Instances**，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_012-1.jpg)

## 操作步骤...

EC2 中的 EC 代表弹性计算，简而言之就是在云中启动虚拟服务器。亚马逊 AWS 已经有了所有流行的操作系统镜像，并且您只需要选择您的需求，然后选择硬件需求。根据您选择的操作系统和硬件配置，AWS 将配置该硬件并安装该操作系统。您可以选择您想要的存储类型，传统或 SSD，然后根据您的需求附加/分离硬盘。最重要的是，您只需支付您想要使用的时间，当您停止 EC2 机器时，AWS 将释放这些资源并将它们添加回其库存，这就是 AWS 的灵活性。现在，是时候快速回顾一下我们在这个配方中所做的事情了。作为先决条件，您需要首先创建一个亚马逊 AWS 帐户，这非常容易创建。然后，步骤 1 向您展示如何选择 EC2。步骤 2 和 3 展示了如何搜索和选择 Kali Linux 的最小镜像。在第 4 步中，您可以阅读 Kali Linux AMI 提供的所有内容，基本要求和用户登录信息。第 5 步向您展示如何根据您的需求和预算选择实例类型。在第 6 到 7 步中，您将通过简单的向导选择默认推荐的 SSD 进行引导。第 8 步向您展示了最终页面，其中包含您应该注意或了解的警告和要点。在第 9 步中，您选择在 SSH 协议端口`22`上设置安全组，只允许您从属于您的特定 IP 范围访问。在第 10 步中，您将看到审查页面，根据您的实例类型选择，它会告诉您是否有资格获得免费套餐。在第 11 步中，您创建一个新的 SSH 密钥对并将其下载到本地计算机。在第 12 步中，您最终点击启动实例。

## 还有更多...

在亚马逊 AWS 基础设施中安装了 Kali Linux，并具有公共 IP 地址，只需点击几下，就可以在外部渗透测试期间非常有帮助。正如您所知，我们已经选择并安装了 Kali Linux 的最小镜像，用于在 AWS 基础设施中使用，因此我们的安装默认没有安装任何工具。

在我们的下一个配方中，我们将介绍如何使用 SSH 并在亚马逊 AWS 盒子上设置 Kali Linux 以供使用。在这个配方中，我们还将解决您在更新存储库和安装 Kali Linux 工具以及设置 GUI 和安装我们将需要使用的所有必需工具时可能遇到的一些问题。

# 在 Docker 上安装 Kali Linux

我认为在这里对 Docker 进行一点介绍是合理的。Docker 是一种新的开源容器技术，于 2013 年 3 月发布，它自动化了在自包含软件容器内部部署应用程序。Docker（建立在 Linux 容器之上）提供了一种更简单的方式来管理单台机器上的多个容器。将其视为虚拟机，但它更轻量级和高效。

这样做的美妙之处在于您几乎可以在任何可以运行 Docker 的系统上安装 Kali Linux。比如，例如，您想在 Digital Ocean droplet 上运行 Kali，但它不允许您直接像 Ubuntu 那样快速启动 Kali Linux。但现在，您可以在数字海洋上简单地快速启动 Ubuntu 或 Centos，并在其上安装 Docker，然后拉取 Kali Linux Docker 镜像，您就可以开始了。

由于 Docker 提供了另一层抽象，从安全的角度来看也是有益的。比如，如果您运行的是托管应用程序的 apache 服务器，您可以简单地为其创建一个 Docker 容器并运行它。即使您的应用程序受到攻击，攻击者也只能被限制在 Docker 镜像中，无法伤害您的主机操作系统。

说了这么多，现在在您的机器上安装 Docker，为了演示的目的，我们将在 Mac 操作系统上安装 Docker。

## 准备就绪

对于这个操作，你需要以下东西：

+   连接到互联网

+   已安装的 Virtualbox

## 如何操作...

按照以下步骤进行此操作：

1.  要在 Mac 操作系统上安装 Docker，你需要从[`www.docker.com/docker-toolbox`](https://www.docker.com/docker-toolbox)下载并安装 Docker 工具箱。在你的 Mac 上运行此安装程序后，你将设置 Docker 环境；工具箱将安装 Docker 客户端、Machine、Compose（仅限 Mac）、Kitematic 和 VirtualBox。

1.  安装完成后，转到**应用程序** | **Docker** | **Docker 快速启动终端.app**，或者直接打开启动台并点击 Docker 快速启动。当你双击该应用程序时，你将看到终端窗口，如下面的屏幕截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_013-1.jpg)

1.  要检查你的安装是否成功，你可以运行以下命令：

```
 docker run hello-world

```

如果你的安装成功，你将看到以下输出：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_014-1.jpg)

1.  现在，让我们去 Docker hub（[`hub.docker.com`](https://hub.docker.com)）搜索`Kali Linux`镜像，如下面的屏幕截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_015-1.jpg)

1.  正如你所看到的，官方的 Kali 镜像是可用的；我们将使用以下命令在我们的 Docker 中拉取并运行它：

```
 docker pull kalilinux/kali-linux-docker
 docker run -t -i kalilinux/kali-linux-docker

```

1.  现在，你在 Docker 中运行了 Kali Linux 的最小基础版本；这个镜像中没有添加任何工具，你可以根据需要安装它们，或者你可以参考[`www.kali.org/news/kali-linux-metapackages/`](https://www.kali.org/news/kali-linux-metapackages/)。

1.  假设你只想运行 Metasploit；为此，你可以在 hub 上搜索`kali Metasploit`镜像，并安装到目前为止拉取次数最多的镜像，如下面的屏幕截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_016-1.jpg)

1.  使用以下命令拉取镜像；但在这之前，请注意这不是官方镜像。因此，你可以自行决定是否信任这个镜像：

```
 docker pull linuxkonsult/kali-metasploit

```

1.  然后，使用`docker run`命令运行 Docker 镜像，如下所示：

```
docker run -t -i linuxkonsult/kali-metasploit

```

输出将如下所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_017-1.jpg)

框架准备好后，解压并执行，应该如下所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_018-1.jpg)

正如你所看到的，你已经更新并运行了 Metasploit。但这还不是全部；你所做的所有更改都不是永久的，直到你提交这些更改。一旦你提交了更改，下次可以从你离开的地方继续。要提交更改，打开另一个控制台窗口并输入以下命令：

```
      docker ps

```

1.  运行此命令后，你将看到以下输出，如下面的屏幕截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_019.jpg)

1.  要提交更改，你需要按照以下格式输入命令：

```
      docker commit <docker-id> <docker-name>
docker commit bd590456f320 admiring_pike

```

成功提交后，你将看到以下输出：

```
b4a7745de59f9e106029c49a508c2f55b36be0e9487dbd32f6b5c58b24fcb57

```

## 工作原理...

在这个操作中，我们需要先安装 Virtualbox 作为先决条件，然后下载并安装 Docker 工具箱。一旦 Docker 工具箱安装完成，只需打开**Docker 快速启动终端.app**并拉取你想要运行的镜像，你可以从[`hub.docker.com`](https://hub.docker.com)搜索所需的镜像，并使用`docker run`命令来运行它。完成操作后，只需使用`docker commit`命令提交更改。

在这里，我们使用了`-i`和`-t`开关。对于交互式进程（如 shell），你必须同时使用`-i` `-t`来为容器进程分配**电传打字机**（**TTY**）。`-i` `-t`开关通常写作`-it`。

## 还有更多...

您可以在[`www.docker.com`](https://www.docker.com)了解有关 Docker 的更多信息。要搜索公共映像，您可以访问[`hub.docker.com`](https://hub.docker.com)。要安装 Kali Linux 元软件包，您可以访问[`www.kali.org/news/kali-linux-metapackages/`](https://www.kali.org/news/kali-linux-metapackages/)。

# 在 OnePlus One 上安装 NetHunter

Kali Linux NetHunter 是 Nexus 和 One Plus 设备的第一个开源网络渗透测试平台。在本章中，我们将看到如何在 One Plus One 上安装 Kali Linux NetHunter。

在开始之前，请确保在进行以下任何操作之前备份设备数据。

## 准备工作

为了开始，您将需要以下内容：

+   一部 OnePlus One 设备，64GB

+   一根 USB 电缆

+   任何 Windows 操作系统

+   NetHunter Windows 安装程序

+   活动的互联网连接

## 如何做...

执行以下步骤进行此操作：

1.  在[`www.nethunter.com/download/`](http://www.nethunter.com/download/)下载 Kali NetHunter Windows 安装程序，您将看到以下页面：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_020.jpg)

1.  安装下载的设置，如下截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_021.jpg)

1.  安装完成后，在桌面上创建的快捷方式上运行：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_022.jpg)

1.  应用程序加载后，请确保检查是否有更新。如果没有，请单击**下一步**按钮：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_023.jpg)

1.  现在我们将选择设备进行 root。我们的教程坚持选择 OnePlus，因此让我们选择**ONEPLUSONE-BACON (A0001) - 64GB**选项，然后单击**下一步**：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_024.jpg)

1.  现在我们将提示安装驱动程序，这些是用于笔记本电脑/PC 通过 USB 连接与移动设备通信的驱动程序。单击**安装**驱动程序...**开始安装过程。安装完成后，单击**测试驱动程序...**以确保驱动程序正常工作，如下截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_025.jpg)

1.  一旦驱动程序正确安装，点击**下一步**，现在我们将进入安装程序配置。在这里，建议继续进行**安装官方 Kali Linux NetHunter**。如果您有自定义的 NetHunter，请选择第二个选项，但要注意兼容性问题：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_026.jpg)

1.  点击**下一步**，我们将进入**下载文件**选项，应用程序将确定可用的软件包和缺少的文件可以通过**下载+更新所有文件依赖项**选项获取。如果卡住或任何文件无法下载，您可以简单地谷歌文件名并下载它并将其放入应用程序安装的文件夹中：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_027.jpg)

1.  一旦所有依赖项都可用，请确保执行以下操作：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_028.jpg)

1.  完成后，我们可以继续解锁启动加载程序。单击**解锁设备启动加载程序**。在从这一点开始之前，请务必备份设备的所有重要数据：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_029.jpg)

1.  手机将进入**Fastboot**模式并进行解锁。完成后，继续下一步，刷入原始 ROM。这是一个新的 ROM，将安装在您的设备上，以保持与 Kali Linux NetHunter 的兼容性。如下截图所示，单击**刷入原始...**：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_030.jpg)

1.  完成刷入原始后，继续下一步，单击**刷入 Kali Linux + Root!**，如下截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_031.jpg)

上述步骤将在您的设备中获取 Kali Linux NetHunter。一旦成功，设备将进入 TWRP 恢复模式。

1.  在恢复模式中，点击**重新启动**，它会要求安装超级用户，滑动一次安装完成后，Kali Linux 将启动。现在，点击**SuperSU**，看看它是否工作：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_032.jpg)

1.  下载 Stephen（Stericson）的**BusyBox**并安装，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_033.jpg)

1.  点击名为**NetHunter**的图标，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_034.jpg)

1.  一旦应用程序运行，您将被要求授予 root 权限。点击**授予**，然后转到 Kali 启动器，然后转到终端，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_035.jpg)

1.  选择 Kali 终端并启动**Metasploit**，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_036.jpg)

1.  在设备上启动**msfconsole**：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_037.jpg)

## 它是如何工作的...

在这个教程中，我们展示了如何安装 Kali Linux，也称为 NetHunter。NetHunter 是 ARM，已被移植到非英特尔处理器上运行，构建在您信任的 Kali Linux 和工具集上。Kali Linux NetHunter 项目是一个面向 ARM 设备的开源 Android 渗透测试平台，由 Kali 社区成员**BinkyBear**和 Offensive Security 共同努力创建。

## 还有更多...

我们在设备上安装了 Kali NetHunter，现在我们可以从 OnePlus One 进行渗透测试，这在红队演习、社会工程或在进行物理安全评估时非常有效。

有关更多信息，请访问[`www.nethunter.com`](http://www.nethunter.com)。

# 在虚拟机上安装 Kali Linux

在硬盘上安装 Kali Linux 是第一步。在物理硬盘或虚拟硬盘上安装 Kali Linux 的过程是完全相似的。因此，可以放心地使用相同的步骤在物理机上安装 Kali Linux。毋庸置疑，只有使用这种方法才能将 Kali Linux 2.0 安装在您的硬盘上作为主要操作系统。

## 准备就绪

在安装 Kali Linux 之前，您将需要 Kali Linux 最新的 ISO 映像，可以从[`www.kali.org/downloads/`](https://www.kali.org/downloads/)下载。

## 如何操作...

执行以下步骤进行此教程：

1.  在您的 macOS 上打开 VMware，按*command* + *N*，一旦完成，我们将看到如下的屏幕截图：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_038-1.jpg)

1.  选择**从光盘或映像安装**，然后点击**继续**：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_039-1.jpg)

1.  拖放刚刚下载的 Kali Linux 2.0 ISO，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_040-1.jpg)

1.  选择**Debian 5 64 位**，然后点击**继续**，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_041-1.jpg)

1.  点击**自定义设置**，选择要保存虚拟机的位置：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_042-1.jpg)

1.  保存后，VMware 打开**Debian 设置**。打开**处理器和内存**，将 RAM 大小增加到 4GB（或根据笔记本电脑上可用的内存）。请记住，作为先决条件，Metasploit 需要最少 2GB 的 RAM 来运行：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_043-1.jpg)

1.  关闭窗口，点击**启动**，然后点击窗口内部。光标控制将转到**Guest VM**。向下滚动并选择**图形安装**，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_044-1.jpg)

1.  选择您喜欢的语言，然后点击**继续**（我们选择了**英语**）：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_045-1.jpg)

1.  选择您的国家（我们选择了**美国**）：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_046-1.jpg)

1.  选择您的键盘配置（我们选择了**美式英语**）：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_047-1.jpg)

1.  接下来，我们需要配置基本的网络服务。输入您喜欢的主机名（我们将其命名为`Intrusion-Exploitation`）：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_048-1.jpg)

1.  接下来，输入您选择的域名（我们输入了`kali.example.com`）：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_049-1.jpg)

1.  最重要的一步是输入您的 root 密码，并确保您有一个强密码，并且不要忘记它（使用 A-Z、a-z、0-9 和特殊字符的组合）：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_050-1.jpg)

1.  在下一个屏幕上，选择您的时区（我们选择了**东部**）：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_051-1.jpg)

1.  接下来，您将看到四个选项可供选择；如果您有首选的磁盘分区方式，可以选择**手动**。但是，为了简化分区，我们将使用**引导-使用整个磁盘**：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_052-1.jpg)

1.  在屏幕上，您将收到提示，整个磁盘空间将被格式化，单击**继续**：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_053-1.jpg)

1.  接下来，您将看到三个选项。由于我们只打算将其用于渗透测试，而不是作为服务器或主要桌面操作系统，所以选择**一个分区中的所有文件**是安全的：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_054-1.jpg)

1.  您将看到对磁盘进行的更改摘要。选择**完成分区并将更改写入磁盘**，然后单击**继续**：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_055-1.jpg)

1.  选择**是**，然后单击**继续**：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_056-1.jpg)

1.  接下来，您将被要求使用网络镜像配置您的软件包管理器。它允许您在 Kali 工具集可用时更新您的 Kali 工具集，而在我们的情况下，我们选择了**是**：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_057-1.jpg)

1.  接下来，您可以输入您的网络中是否有代理服务器。如果没有，您可以简单地跳过并单击**继续**：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_058-1.jpg)

1.  最后，您将被要求将 GRUB 引导加载程序安装到/Dev/SDA-主引导记录；选择**是**，然后单击**继续**：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_059-1.jpg)

1.  最后，您将被要求手动输入设备或`/dev/sda`; 选择`/dev/sda`并单击**继续**：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_060-1.jpg)

1.  如果您看到前面的屏幕，这意味着您已经完成了 Kali 的安装。恭喜！单击**继续**，您的系统将重新启动，带您进入全新安装的 Kali Linux。

## 它是如何工作的...

在这个步骤中，我们插入了 Kali Linux ISO 并启动了图形安装。在图形安装过程中，我们开始配置我们喜欢的语言、键盘语言、国家和时区。从第 5 步开始，我们输入了我们的 Kali Linux 主机名，在第 6 步，我们输入了我们的 Kali Linux 域名。

从第 9 步到第 13 步，我们配置了硬盘分区，将整个磁盘用于安装，并为所有文件夹创建了一个分区，因为我们只打算用它进行渗透测试。安装完成后，从第 14 步开始，我们配置了 Kali 以使用网络镜像进行更快的更新，配置了任何网络代理（如果需要），最后安装了 GRUB 引导加载程序。

# 为了更快地更新软件包，定制 Kali Linux

Kali 包含了 300 多个安全工具和系统二进制文件。安装 Kali Linux 后，您需要做的第一件事就是更新 Kali Linux，以获取最新的安全工具和功能集。由于 Kali 基于 Debian Linux，您可以使用`apt-get update`命令来更新二进制文件和工具的存储库。

然而，有时在更新 Kali Linux 时，您会注意到无论您的互联网速度和带宽如何，更新都可能会很慢。在这个步骤中，我们将向您展示如何更新您的源文件，以便您的软件包管理器可以更快地更新软件包：

## 准备工作

对于这个食谱，您需要连接到具有有效 IP 地址的互联网。

## 如何操作...

执行以下步骤来制作这个食谱：

1.  打开终端并使用编辑器打开`sources.list`文件：

```
 vim /etc/apt/sources.list

```

1.  默认的`sources.list`文件如下所示：

```
 #deb cdrom:[Debian GNU/Linux 7.0 _Kali_ - Official Snapshot i386       LIVE/INSTALL Binary 20140721-23:20]/ kali contrib main non-free
 deb http://http.kali.org/kali kali main non-free contrib
 deb-src http://http.kali.org/kali kali main non-free contrib
 ## Security updates
 deb http://security.kali.org/kali-security kali/updates main       contrib non-free

```

您只需要按照以下代码所示将`http`更改为`repo`：

```
      #deb cdrom:[Debian GNU/Linux 7.0 _Kali_ - Official Snapshot i386       LIVE/INSTALL Binary 20140721-23:20]/ kali contrib main non-free
      deb http://repo.kali.org/kali kali main non-free contrib
      deb-src http://repo.kali.org/kali kali main non-free contrib
      ## Security updates
      deb http://security.kali.org/kali-security kali/updates main       contrib non-free

```

1.  进行以下更改，保存文件，并通过按*Esc*键然后输入`wq!`并按*Enter*退出编辑器。

1.  现在，使用以下命令更新和升级您的 Kali；您将注意到速度上的差异：

```
      apt-get update && apt-get upgrade

```

## 它是如何工作的...

Kali Linux 在世界各地有多个不同的镜像。根据您的 IP 地址位置，它会自动选择距离您最近的镜像。由于各种原因，这些镜像可能会随着时间的推移变得缓慢。您可以在[`http.kali.org/README.mirrorlist`](http://http.kali.org/README.mirrorlist)找到距离您最近的镜像列表。`apt-get`命令从`/etc/apt/sources.list`获取更新服务器列表。对`sources.list`文件的更改确保我们的 Kali 连接到正确的服务器并获得更快的更新。

# 定制 Kali Linux 以获得更快的操作

在审核和渗透测试期间，您将使用 Kali Linux。您需要配置和定制您的 Kali Linux，以便在这些关键测试过程中获得最高速度。在这个食谱中，我们将向您展示几种工具，可以用来优化您的 Kali Linux 体验。

## 准备工作

对于这个食谱，您需要连接到互联网。

## 如何操作...

执行以下步骤来制作这个食谱：

1.  Preload 是由 Behdad Esfahbod 编写的一个作为守护进程运行的程序。该应用程序密切观察经常使用的应用程序和二进制文件的使用情况，并在系统空闲时加载到内存中。这样可以加快启动时间，因为从磁盘获取的数据更少。您可以在[`wiki.archlinux.org/index.php/Preload`](https://wiki.archlinux.org/index.php/Preload)了解更多关于这个应用程序的信息。要安装该应用程序，请在终端窗口上发出以下命令：

```
      apt-get install preload

```

BleachBit 快速释放磁盘空间，并不知疲倦地保护您的隐私。释放缓存，删除 cookie，清除互联网历史记录，销毁临时文件，删除日志，并丢弃您不知道存在的垃圾。您可以在[`bleachbit.sourceforge.net/`](http://bleachbit.sourceforge.net/)了解更多关于这个应用程序的信息。

1.  要安装该应用程序，请在终端窗口上发出以下命令：

```
      apt-get install bleachbit

```

1.  默认情况下，Kali 不显示启动菜单中的所有应用程序和脚本。您安装的每个应用程序最终都会通过启动，即使不需要也会减慢启动过程。您可以安装 Boot-Up 管理器，并密切关注在启动过程中允许哪些服务和应用程序。您可以随时禁用不必要的服务和应用程序，以增加 Kali 的启动速度。

要安装该应用程序，请在终端窗口上发出以下命令：

```
      apt-get install bum

```

## 它是如何工作的...

在这个食谱中，我们使用了`apt-get`命令来安装基本系统实用程序，这些实用程序可以帮助我们在渗透测试期间有效地管理我们的 Kali Linux 资源，使我们的 Kali Linux 进程和启动文件夹优化以获得最佳性能。

# 配置远程连接服务-HTTP、TFTP 和 SSH

在渗透测试和审核期间，我们将需要从我们的 Kali Linux 向目标机器交付有效载荷。为此，我们将利用基本的网络服务，如 HTTP、FTP 和 SSH。HTTP 和 SSH 等服务默认安装在 Kali Linux 中，但 Kali 不启用任何网络服务以最小化检测。

在这个食谱中，我们将向您展示如何配置和开始安全运行服务：

## 准备工作

对于这个食谱，您需要连接到具有有效 IP 地址的互联网。

## 如何操作...

执行本教程的以下步骤：

1.  让我们开始启动 Apache web 服务器。要启动 Apache 服务，请使用以下命令：

```
      service apache2 start

```

您可以通过浏览器浏览本地主机来验证服务是否正在运行，如下面的屏幕截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_061.jpg)

1.  要启动 SSH 服务，需要生成 SSH 密钥。在 Backtrack r5 中，您曾经使用`sshd-generate`命令生成 SSH 密钥，但在 Kali Linux 中不可用。使用默认的 SSH 密钥存在安全风险，因此应生成新的 SSH 密钥。要生成 SSH 密钥，您可以删除或备份 Kali Linux 生成的默认密钥：

```
      # cd /etc/ssh
      # mkdir default_kali_keys
      # mv ssh_host_* default_kali_keys/
      # cd /root/

```

1.  首先，我们需要通过以下命令删除 SSH 的运行级别：

```
      # update-rc.d -f ssh remove

```

1.  现在，我们需要通过以下命令加载默认的 SSH 运行级别：

```
      # update-rc.d -f ssh defaults

```

1.  重新生成密钥：

```
# dpkg-reconfigure openssh-server 
      Creating SSH2 RSA key; this may take some time ...
      Creating SSH2 DSA key; this may take some time ...
      Creating SSH2 ECDSA key; this may take some time ...
      insserv: warning: current start runlevel(s) (empty) of script       `ssh' overrides LSB defaults (2 3 4 5).
      insserv: warning: current stop runlevel(s) (2 3 4 5) of script       `ssh' overrides LSB defaults (empty).

```

1.  您可以检查 SSH 密钥散列是否已更改：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_062.jpg)

1.  使用以下命令启动 SSH 服务：

```
      service ssh start

```

1.  您可以使用`netstat`命令验证服务是否正在运行：

```
      netstat - antp | grep ssh

```

1.  使用以下命令启动 FTP 服务器：

```
      service pure-ftpd start

```

1.  要验证服务是否正在运行，请使用以下命令：

```
      netstat -ant | grep ftp

```

1.  要停止任何服务，可以使用以下命令：

```
      service <servicename> stop

```

这里，`<servicename>`是要终止的服务的名称：

```
      service ssh stop

```

## 工作原理...

在本教程中，我们已配置并启动了基本网络服务，这些服务将根据情况用于向受害机交付有效载荷。我们已启动了 HTTP 服务、FTP 服务，并备份了默认的 SSH 密钥并生成了新的 SSH 密钥，并启动了 SSH 服务。

# 配置 Nessus 和 Metasploit

在本教程中，我们将向您展示如何安装、配置和启动 Nessus 和 Metasploit。

## 准备工作

对于本教程，我们将下载 Nessus 家庭版并注册有效许可证。

## 操作步骤...

执行本教程的以下步骤：

1.  打开 Firefox 并转到[`www.tenable.com/products/nessus/select-your-operating-system`](http://www.tenable.com/products/nessus/select-your-operating-system)，然后选择家庭版。在下一页上，选择操作系统为**Debian 6 and 7**（因为 Kali 基于 Debian Jessie），如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_063.jpg)

1.  要安装 Nessus，请在终端中打开以下命令并输入：

```
      dpkg -i Nessus-6.2.0-debian6_amd64.deb

```

1.  现在，您的 Nessus 已安装，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_064.jpg)

1.  安装完成后，使用以下命令启动 Nessus 服务：

```
      /etc/init.d/nessusd start

```

1.  打开链接`https://kali:8834`，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_065.jpg)

1.  默认情况下，在安装期间，Nessus 配置为使用自签名证书来加密浏览器和 Nessus 服务器之间的流量；因此，您看到了前面屏幕截图中显示的页面。如果您从可信任的网站下载了 Nessus，可以安全地单击**我了解风险并接受证书**继续，然后您将看到以下页面：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_066.jpg)

1.  单击**继续**，将显示初始帐户设置页面，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_067.jpg)

1.  输入要创建的用户名和密码组合，然后单击**继续**。在下一页上，您将需要输入激活代码，如下面的屏幕截图所示：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_068.jpg)

1.  要获取激活码，请转到[`www.tenable.com/products/nessus-home`](http://www.tenable.com/products/nessus-home)，并在页面右侧填写表格以接收激活码。您将在电子邮件帐户中收到激活码。复制激活码并输入到此屏幕上并继续：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_069.jpg)

现在，激活已经完成，Nessus 将更新插件，工具将准备好供您使用。

1.  现在我们已经安装了 Nessus。所以，让我们设置 Metasploit。Metasploit 在操作系统安装期间默认安装。要调用，您需要启动以下服务：

```
      # service postgresql start
      [ ok ] Starting PostgreSQL 9.1 database server: main.
      root@Intrusion-Exploitation:~#
      root@Intrusion-Exploitation:~# msfconsole
      [ ok ] Starting Metasploit rpc server: prosvc.
      [ ok ] Starting Metasploit web server: thin.
      [ ok ] Starting Metasploit worker: worker.

```

1.  Metasploit 将如下所示启动：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_070.jpg)

## 工作原理...

在这个食谱中，我们已经下载了 Nessus 家庭订阅并启动了服务。我们完成了基本的初始帐户设置，并输入了帐户激活密钥以激活我们的 Nessus 家庭订阅版本，并最终更新了插件。

后来，我们打开了 PostgreSQL 和 Metasploit 服务，最后，使用`msfconsole`我们启动了一个 Metasploit 实例。

## 还有更多...

Nessus 是一个漏洞扫描器，Metasploit 是来自 Rapid7 的利用框架。然而，大多数网络环境只需要漏洞评估，而不需要深入的利用。但是，在某些情况下，如果需要，Metasploit 是最好的框架之一。与 Nessus 类似，Rapid7 还推出了他们自己的漏洞扫描器**Nexpose**。Nexpose 可以配置为与 Metasploit 集成，这允许 Metasploit 使用 NexPose 进行漏洞扫描，并根据 Nexpose 收集的信息选择利用，因此与使用 Nessus 与 Metasploit 相比，它提供了更好的体验。有关更多信息，请访问[`www.rapid7.in/products/nexpose/`](http://www.rapid7.in/products/nexpose/)。

# 配置第三方工具

在这个食谱中，我们将安装一些基本的第三方工具，这些工具作为 Backtrack 5 的一部分，或者可以作为渗透测试工具箱的良好补充。

## 准备工作

对于这个食谱，您需要连接到互联网。

## 如何操作...

执行此食谱的以下步骤：

1.  Lazy Kali 是一个 Bash 脚本，旨在自动化 Kali 更新并安装所有其他您可能需要使 Kali 成为默认操作系统的第三方工具。您可以在[`code.google.com/p/lazykali/`](https://code.google.com/p/lazykali/)了解更多关于此脚本的信息。

要下载并安装此脚本，请在终端窗口上发出以下命令：

```
      Wget https://www.lazykaligooglecode.com/files/lazykali.sh
      Give it executable permission and execute:
      chmod +x lazykali.sh
      sh lazykali

```

1.  当你运行`lazykali.sh`脚本时，它会显示脚本是否已经安装，如果没有，你可以按照下面的截图进行安装：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_071.jpg)

1.  自更新脚本后，继续，您将看到以下屏幕：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_01_072.jpg)

1.  接下来，输入`6`来安装额外的工具：

1.  然后，选择“选择全部”。然后它将安装所有在后续食谱中所需的工具。

## 工作原理...

在这个食谱中，我们已经下载了`lazykali.sh`脚本，我们将用它来下载进一步的第三方工具，这些工具将在我们的后续食谱中使用。

# 在 Kali Linux 上安装 Docker

在这个食谱中，我们将在 Kali Linux 上安装和设置 Docker。

## 准备工作

要完成此食谱的步骤，您需要在 Oracle Virtualbox 或 VMware 中运行 Kali Linux，并连接到互联网。不需要其他先决条件。

## 如何操作...

对于这个食谱，您需要执行以下步骤：

1.  在撰写本书时，Kali Linux 2.0 Rolling 基于 Debian Wheezy，因此这些步骤只适用于基于 Debian Wheezy 的 Kali Linux。将来，如果 Kali 有更新，那么请检查 Docker 文档中的最新安装步骤。

1.  在终端窗口中打开`/etc/apt/sources.list.d/backports.list`文件，并在您喜欢的编辑器中打开。如果文件不存在，请创建它。

1.  删除任何现有条目，并在 Debian wheezy 上添加一个 backports 条目：

```
      deb http://http.debian.net/debian wheezy-backports main

```

1.  更新软件包信息，并确保 APT 使用 HTTPS 方法工作，并安装 CA 证书：

```
 $ apt-get update
 $ apt-get install apt-transport-https ca-certificates

```

1.  添加 GPG 密钥：

```
      $ apt-key adv --keyserver hkp://p80.pool.sks-keyservers.net:80        --recv-keys 58118E89F3A912897C070ADBF76221572C52609D

```

1.  在您喜欢的编辑器中打开`/etc/apt/sources.list.d/docker.list`。如果文件不存在，请创建它。

1.  删除任何现有条目，并在 Debian wheezy 上添加后备条目：

```
      $ deb https://apt.dockerproject.org/repo debian-wheezy main

```

1.  更新软件包信息并验证 APT 是否从正确的存储库中拉取：

```
      $ apt-get update && apt-cache policy docker-engine

```

1.  安装 Docker：

```
      $ apt-get install docker-engine

```

1.  启动 Docker 守护程序：

```
      $ service docker start

```

1.  验证 Docker 是否安装正确：

```
      $ docker run hello-world

```

由于您已经以`root`用户登录到 Kali Linux 安装中，因此无需使用`sudo`。但重要的是要注意，`docker`守护程序始终以`root`用户身份运行，并且`docker`守护程序绑定到 Unix 套接字而不是 TCP 端口。默认情况下，该 Unix 套接字归`root`用户所有，因此，如果您未以 root 用户身份登录，则需要使用前面的命令与`sudo`一起使用。

## 工作原理...

在这个教程中，我们添加了`docker`源列表，这样每次在系统上使用`apt-get update`命令时，我们就可以获取 Docker 的更新。然后，更新`apt-get`源并安装安装 Docker 所需的先决条件。我们添加了`GPG`密钥，以确保我们安装的任何更新都是有效的官方未更改的软件包。在完成所有这些基本配置之后，我们运行了基本的`apt-cache`来确保 APT 正在从正确的存储库中获取 docker-engine。最后，我们使用`apt-get`安装了`docker-engine`。


# 第二章：网络信息收集

在本章中，我们将介绍以下教程：

+   发现网络上的活动服务器

+   绕过 IDS/IPS/防火墙

+   发现网络上的端口

+   使用 unicornscan 进行更快的端口扫描

+   服务指纹识别

+   使用 nmap 和 xprobe2 确定操作系统

+   服务枚举

+   开源信息收集

# 介绍

在本章中，我们将学习如何在网络上检测活动服务器和网络设备，并执行服务指纹识别和枚举以进行信息收集。收集信息对于成功的漏洞评估和渗透测试至关重要。接下来，我们将运行扫描程序来查找检测到的服务中的漏洞。除此之外，我们还将编写 bash 脚本，以便加快发现-枚举-扫描的过程。

# 发现网络上的活动服务器

在这个教程中，我们将学习如何使用两种方法进行网络设备/机器的发现：**被动信息收集**和**主动信息收集**。

作为被动信息收集的一部分，我们将检查环境的网络流量，然后进行主动信息收集，我们将向网络发送数据包以检测活动的机器和正在运行的服务。

## 准备工作

为了开始这个教程，我们将使用一个名为**netdiscover**的简单 ARP 嗅探/扫描工具。这是一个可以用于主动/被动 ARP 侦察的网络发现工具。

## 操作步骤...

让我们从被动侦察开始：

1.  要启动 netdiscover，请确保您通过 Wi-Fi 连接并具有有效的 IP 地址。打开终端并输入以下命令进行被动侦察：

```
netdiscover - p

```

输出将如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_001.jpg)

1.  要执行对网络的主动扫描以发现活动 IP，请在终端中输入以下命令：

```
netdiscover -i eth0

```

输出将如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_002.jpg)

1.  如果您想保存 netdiscover 的输出，可以使用以下命令：

```
netdiscover -i eth0 > localIPS.txt

```

1.  几秒钟后（例如，10 秒），使用*Ctrl* + *C*终止程序，文件的输出将看起来像以下内容：![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_003.jpg)

1.  另一种执行快速有效扫描的方法是使用`nmap`命令。要通过简单的 ping 扫描检测网络范围内的活动系统，请在终端中使用以下命令：

```
nmap -sP 192.168.1.0/24

```

输出将如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_004.jpg)

1.  您还可以将 nmap 工具的输出保存到文件中。我们所要做的就是添加一些 bash 脚本，并在终端中输入以下命令：

```
nmap -sP <IP address range>/<class subnet> | grep "report for" |        cut -d " " -f5 > nmapliveIPs.txt

```

让我们了解这个命令：第一个`nmap`命令的输出作为管道符后面的第二个命令的输入。在第二个命令中，grep 命令搜索包含"report for"的行，因为这将是指定 IP 正在响应的语句。找到包含"report for "的行的输出被转发到管道符后面的第三个命令。在第三个命令中，我们执行一个 cut 操作，我们说比较分隔符是"空格"在行中，并获取第 5 个字段，即在基于"空格"分隔的情况下的第五个单词。

文件的输出将只包含我们可以继续用于进一步评估的 IP 地址：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_005.jpg)

这个文件将用于进一步的引用，以自动化一系列扫描请求，因为所有 IP 都已经提取到一个文件中。

## 工作原理...

因此，我们使用的少数工具的工作原理如下：

+   `netdiscover`：此命令使用以下开关：

+   `-p`：此开关用于以被动模式运行；它确保不会自己发送任何数据包，只是作为我们网络接口卡上的监听器

+   `-i`：此开关用于指定用于检测活动 IP 的接口

我们还看到输出可以存储在文件中以供以后参考。

+   `nmap`：此命令使用以下开关：

+   `-sP`：此开关也被视为`-sn`开关，用于 ping 扫描

我们还使用了 bash 脚本将 ping 扫描的输出保存在文件中，调用了基本逻辑。

在本教程中，我们已经学会了如何检测网络中所有活动的 IP，并在下一个教程中对其进行了开放端口分析。

## 还有更多...

netdiscover 工具中提供了更多功能，可帮助加快流程。它们如下：

+   `-h`：此功能加载 netdiscover 使用的帮助内容

+   `-r`：此功能允许您执行范围扫描，而不是自动扫描

+   `-s`：此功能为您提供在每个请求之间休眠的选项

+   `-l`：此功能允许您提供一个包含要扫描的 IP 范围列表的文件

+   `-f`：此功能启用快速模式扫描；与正常检测技术相比，它节省了大量时间

nmap 工具还支持许多用于检测活动 IP 的选项：

+   `-sL`：这是一个简单的列表扫描，用于指定要检查的 IP 地址文件

+   `-sn`：这是一个简单的 ping 扫描程序，用于确定活动 IP。

+   `-PS`/`PA`/`PU`/`PY TCP SYN`/`ACK`：用于 UDP 或 SCTP 端口检测

+   `--traceroute`：此选项允许对每个主机进行跟踪跳径

## 另请参阅

有关主动和被动扫描以及更多相同工具的信息，请参阅以下链接：

+   [`tools.kali.org/tools-listing`](http://tools.kali.org/tools-listing)获取工具集

+   [`nmap.org/docs.html`](https://nmap.org/docs.html)

# 绕过 IDS/IPS/防火墙

在本教程中，我们将看一下 nmap 支持的一些开关，这些开关可用于绕过 IDS/IPS/防火墙。许多时候，当我们执行扫描时，我们会遇到防火墙。如果防火墙配置不正确，我们将能够执行 nmap 的以下防火墙规避命令。

## 准备就绪

我们将使用 nmap 进行此活动。让我们从我们已检测到的机器开始运行一些规避开关。

## 如何做...

对于本教程，我们将执行以下步骤：

1.  我们将使用分段数据包开关执行发现：

分段数据包开关将 TCP 标头分成几个数据包，以使数据包过滤器、入侵检测系统和其他麻烦更难检测到正在进行的活动扫描。可能会发生失败的情况，因为一些程序可能无法处理微小的数据包。要了解更详细的信息，请访问[`nmap.org/book/man-bypass-firewalls-ids.html`](https://nmap.org/book/man-bypass-firewalls-ids.html)。

我们将输入以下命令：

```
nmap -f <ip address>

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_006.jpg)

1.  另一个开关是 nmap 中可用的`mtu`开关，当我们执行分段扫描时，nmap 将数据包分成 8 字节或更少，因此要理解一个 30 字节的数据包将被分成 4 个数据包，重新指定`-f`后，数据包将被分成 16 字节，从而减少了片段，mtu 允许我们指定我们想要用于扫描目的的自己的偏移大小。

要在此处通过 MTU 执行规避，请在终端中输入以下命令：

```
nmap -mtu 24 <ip address>

```

### 注意

有关 MTU 开关的更多信息，请参阅[`nmap.org/book/man-bypass-firewalls-ids.html`](https://nmap.org/book/man-bypass-firewalls-ids.html)。

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_007.jpg)

1.  在这里，我们将使用欺骗攻击。在终端中输入以下命令：

```
nmap -D <Fake IP>,<Fake IP>,<Fake IP> <Real IP>

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_008.jpg)

1.  在这里，我们将进行自定义端口攻击。在终端中输入以下命令：

```
nmap -source-port 53 <IP address>

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_009.jpg)

以下是一个示例，以帮助您更好地理解情景：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_010.jpg)

注意端口如何响应正常扫描与分段扫描。这表明我们能够绕过防火墙并检测到开放端口。

## 工作原理...

让我们了解这些开关是如何工作的：

+   `-f`：这种技术已经在配置错误的防火墙上使用了相当长的时间。它的作用是发送较小的数据包，以规避防火墙。

+   `-mtu <8,16,24,32>`：**MTU**代表**最大传输单元**。在这里，我们可以手动指定数据包的大小；一旦我们指定大小，nmap 将发送指定大小的数据包来执行扫描活动。

+   `-D`：这用于欺骗数据包，提及我们选择的源 IP，以便在日志中创建垃圾条目，并且很难定位扫描是从哪个系统发起的。

+   `--source-port`：大多数情况下，防火墙为网络中的各种设备设置了允许传入规则的特定端口。这可以通过使用可能在系统上允许传入访问的自定义源端口来利用，以执行扫描活动。

## 还有更多...

在规避标准中还有一些其他技术；例如，附加随机数据、MAC 欺骗和错误校验扫描。这可以作为自学内容。

# 发现网络上的端口

在这个示例中，我们将使用我们扫描并保存在文件中的活动 IP 列表来执行信息收集，目的是扫描这些 IP 上的开放端口。我们将使用 nmap 及其功能来发现开放端口。

## 准备就绪

我们将使用 nmap 工具来检测 IP 上的开放端口。让我们从检测特定 IP 上的开放端口的过程开始。

## 如何做...

对于这个示例，您需要执行以下步骤：

1.  我们将在终端中输入以下命令来运行 nmap：

```
nmap <ip address>

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_011.jpg)

1.  我们甚至可以通过使用详细开关来检查工具的操作，通过在终端中输入以下命令：

```
nmap -v <IP address>

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_012.jpg)

1.  默认情况下，它只扫描 1,000 个知名端口集。如果我们有兴趣将扫描偏好设置为前 100 个端口，我们可以在终端中运行以下命令：

```
nmap --top-ports <number> <ip address>

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_013.jpg)

1.  我们甚至可以将端口扫描限制为特定端口或 IP 的一系列端口。我们可以运行以下命令来查看相同的内容：

```
nmap -p <port range> <IP address>

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_014.jpg)

1.  可能存在这样的情况，我们想知道整个网络范围内有哪些 IP 运行了特定服务。我们在终端中运行以下命令：

```
nmap -p <port number> <IP address>

```

输出如下所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_015.jpg)

1.  假设我们想要检查特定系统上有哪些 UDP 端口是开放的。我们可以通过在终端中输入以下命令来检查：

```
nmap -sU <IP Address>

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_016.jpg)

1.  在上一个示例中，我们看到我们已经将活动 IP 的输出保存在一个文件中；现在让我们看看如何从文件中导入 IP 并执行简单的 TCP 扫描。

打开终端并输入以下命令，确保正确输入 IP 文件的路径：

```
nmap -sT -iL /root/nmapliveIPs.txt

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/B01606_02.jpg)

1.  可以使用以下命令将实时 IP 扫描结果保存在文件中：

```
nmap -sT -iL /root/nmapliveIPs.txt > openports.txt

```

1.  Nmap 还有一个图形化版本；它被命名为 zenmap，看起来如下：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_018.jpg)

## 它是如何工作的...

让我们了解一下这些开关是如何工作的：

+   `Nmap <IP 地址>`：仅对著名端口执行 SYN 扫描，并得出基本信息

+   `-v`：切换到详细模式，从而提供有关扫描类型的更多信息

+   `--top-ports <number>`：这个开关告诉 nmap 从著名的端口库中扫描给定数量的端口

+   `-p`：这个开关告诉 nmap 它应该只扫描开关后面提到的端口号

+   `-sU`：这是 nmap 中的一个 UDP 开关，告诉它通过发送 UDP 数据包并检测相应的响应来扫描开放端口

+   `-sT`：这是一个 TCP 开关，告诉 nmap 与目标网络建立连接，以确保端口确实是打开的

+   `-iL`：这个开关告诉 nmap 输入可以从`-iL`开关后面提到的文件中获取

在这个配方中，我们已经看到了如何检测开放端口；这将帮助我们进行接下来的配方。

## 还有更多...

nmap 中还有许多其他选项，可以用来扫描基于协议的开放端口，以及其他有效扫描技术，尝试保持对网络中运行的扫描器的低级别检测。工具中有用的命令如下：

+   `-sS`：这个命令执行一个 SYN 扫描（最快和最准确的扫描-推荐）

+   `-sX`：这个命令执行一个 Xmas 扫描

+   `-sF`：这个命令执行一个 FIN 扫描

+   `-sN`：这个命令执行一个 Null 扫描

+   `-sU`：这个命令执行一个 UDP 扫描。然而，它并不是很准确，因为 UDP 是无状态的

## 另请参阅

+   对于 Zenmap（nmap 的图形化版本），我们建议您访问[`nmap.org/book/man-port-scanning-techniques.html`](http://nmap.org/book/man-port-scanning-techniques.html) 作为参考。它可以在**Kali Linux** | **信息收集** | **网络扫描仪** | **Zenmap**下找到

# 使用 unicornscan 进行更快的端口扫描

Unicornscan 是另一个工作非常快的扫描器，其核心原因是工具实现的方法。它使用异步无状态 TCP 扫描的技术，在其中对 TCP 标志和 UDP 进行所有可能的变化。在这个配方中，我们将看看如何利用 unicornscan 及其高级功能。

## 准备工作

为了开始使用 unicornscan，我们将从我们的 IP 范围中取一个 IP，并深入了解工具的功能。

## 如何操作...

让我们按照以下步骤进行：

1.  打开终端并输入以下命令进行简单的 unicornscan：

```
unicornscan <IP address>

```

输出将如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_019.jpg)

1.  如果您想在执行命令时看到它正在做什么的细节，我们可以使用以下命令使用详细脚本：

```
unicornscan -v <IP address>

```

输出将如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_020.jpg)

我们可以看到它在执行扫描时考虑的端口。

1.  假设我们也想对 UDP 进行相同的操作。在终端中输入以下命令：

```
unicornscan -v -m U <IP address>

```

输出将如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_021.jpg)

1.  还有更多选项可用。要检查它们，请在终端中输入以下命令：

```
Unicornscan -h

```

输出将如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_022.jpg)

## 它是如何工作的...

配方中提到的命令的工作如下：

+   `Unicornscan <IP 地址>`：在这种情况下，unicornscan 运行默认的`TCP SYN`扫描（unicornscan 中的参数将是`-mTS`在 IP 上）并扫描`unicornscan.conf`文件中的快速端口，该文件位于`/etc/Unicornscan/unicornscan.conf`。

+   `-v`：这个开关告诉扫描器进入详细模式，并提供更多关于它在执行扫描时正在做什么的信息。

+   -m U：`-m`开关代表要使用的扫描模式。在这种情况下，我们使用了`U`，这意味着扫描类型应该是 UDP。

在这个示例中，我们已经看到了如何有效地使用 unicornscan 获取有关开放端口的信息，并且我们可以在不同的开关之间切换。

## 还有更多...

unicornscan 中还有许多其他可用于改进扫描偏好的开关。建议尝试并熟悉它们：

```
Unicornscan -h

```

# 服务指纹识别

在这个示例中，我们将看看如何分析开放端口，以确定开放端口上运行的是什么样的服务。这将帮助我们了解目标 IP 是否运行了任何易受攻击的软件。这就是为什么服务指纹识别是一个必要且非常重要的步骤。

## 准备工作

我们将使用 nmap 对目标 IP 的服务进行指纹识别。Nmap 是一个多功能工具，可以从主机发现到漏洞评估；服务指纹识别也是其中的一部分。

## 操作步骤...

步骤如下：

1.  使用 nmap，在终端中运行以下命令以获得服务枚举结果：

```
nmap -sV <IP address>

```

输出将如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_023.jpg)

1.  我们甚至可以使用 UDP 扫描开关以及服务检测开关来枚举目标 IP 上运行的 UDP 服务：

```
Nmap -sU -sV <IP address>

```

输出将如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_024.jpg)

1.  我们可以使用以下命令加快扫描速度：

```
nmap -T4 -F -sV  <IP address>

```

有关使用的开关的详细信息在*工作原理*部分提供。要获取更多详细信息，请访问[`nmap.org/book/man-port-specification.html`](https://nmap.org/book/man-port-specification.html)和[`nmap.org/book/man-version-detection.html`](https://nmap.org/book/man-version-detection.html)。

输出将如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_025.jpg)

在这里我们可以看到正常扫描和定时扫描之间的差异几乎是 60 秒以上。

## 工作原理...

以下是我们使用的开关列表及其解释，以便更好地理解：

+   `-sV`：这代表版本检测；它探测所有开放端口，并尝试解析抓取的横幅信息以确定服务版本。

+   `-T4`：`T`代表精细的时间控制，`4`代表执行扫描的速度级别。时间范围从 0 到 5：(0)患妄想症，(1)鬼鬼祟祟，(2)礼貌，(3)正常，(4)侵略性，(5)疯狂。(0)和(1)通常有助于 IDS 逃避，而(4)告诉 nmap 假设我们在一个快速可靠的网络上，从而加快扫描速度。

+   `-F`：这是快速模式；它扫描的端口比默认扫描少。

在这个示例中，我们已经学会了如何使用 nmap 对开放端口进行指纹识别，以检测运行的服务及其相应的版本。这将在以后帮助我们检测操作系统。

## 还有更多...

我们甚至可以查看 Kali 发行版中提供的其他工具，这些工具处理服务枚举。我们可以检查一些列在**Kali Linux** | **信息收集** | **<services>**下的工具。

在 nmap `-sV`检测中还有详细的开关可用：

+   `--all-ports`：这告诉 nmap 确保对所有开放端口上运行的服务版本进行指纹识别。

+   `--version-intensity`：这告诉 nmap 使用强度值从 0 到 9 进行扫描，9 是最有效的指纹识别。

端口枚举后，攻击者可以通过一些谷歌搜索或查看[exploit-db.com](http://exploit-db.com)、[securityfocus.com](http://securityfocus.com)等网站，找出端口上运行的软件版本是否容易受到攻击向量的影响。

# 使用 nmap 和 xprobe2 确定操作系统

在这个配方中，我们将使用工具来确定目标 IP 正在运行的操作系统类型。将目标 IP 与相应的操作系统进行映射是必要的，以帮助筛选和验证漏洞。

## 准备工作

在这个配方中，我们将使用 nmap 工具来确定操作系统。我们只需要一个 IP 地址，针对该地址我们将运行 OS 枚举扫描。其他可以使用的工具包括 hping 和 xprobe2。

## 如何做...

让我们开始确定操作系统：

1.  打开终端并输入以下内容：

```
nmap -O <IP address>

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_026.jpg)

我们可以使用高级运算符以更积极的方式找出操作系统。在终端中输入以下命令：

```
nmap O --osscan-guess <IP address>

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_027.jpg)

这表明使用 nmap 中操作系统检测的其他参数，我们可以得到最佳匹配的可能想法。

1.  Xprobe2 使用了与 nmap 不同的方法。它使用模糊签名匹配来提供可能的操作系统。打开终端并输入以下命令：

```
xprobe2 <IP Address>

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_028.jpg)

我们无法确定哪种扫描器是最好的，因为每个扫描器都有其自己的实现方法。为了证明我们所说的，让我们看看以下情景。我们设置了一个用于枚举操作系统的常见目标。目标是[www.google.com](http://www.google.com)。

以下截图显示了 nmap 的结果：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_029.jpg)

以下截图显示了 Xprobe 的结果：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_030.jpg)

## 它是如何工作的...

Nmap 执行基于 TCP/IP 堆栈指纹识别的操作系统确定活动。它发送一系列数据包，包括 TCP 和 UDP 数据包，并分析所有响应。然后将它们与 nmap 引擎中可用的签名进行比较，以确定最佳匹配的操作系统，并告诉我们目标机器的操作系统可能是什么。在前面的情景中，有一个目标 IP 没有提供任何操作系统详细信息；这是因为 nmap 工具无法将任何响应与工具中可用的签名匹配。

让我们看一下上面使用的开关的一些细节：

+   `-O`参数使 nmap 引擎开始根据从横幅检索到的信息来确定可能的操作系统。它提到，如果在目标 IP 上找到一个开放和一个关闭的 TCP 端口，那么它会更有效。 

+   `--osscan-guess`参数使 nmap 引擎在无法找到完美匹配时显示检测到的签名的最佳可能匹配项。

Xprobe2 有大约 14 个模块，可用于扫描远程目标上运行的操作系统的检测。

在这个配方中，我们学习了如何有效地使用不同的扫描器确定操作系统。我们现在将使用这些信息来继续下一个配方。

## 还有更多...

nmap 操作系统发现模块中还有其他选项，如下所示：

+   `--osscan-limit`：此参数将仅限于有希望的目标进行检测；如果它没有找到任何端口打开，它将跳过目标。这在扫描多个目标时节省了大量时间。

+   `--max-os-tries`：这用于设置 nmap 应尝试检测的次数。默认情况下，它尝试五次；这可以设置为较低的值以避免耗时。

# 服务枚举

一旦服务被指纹识别，我们就可以执行枚举。可以使用许多不同的来源来实现这个配方的目标。在这个配方中，我们将看看如何使用各种工具执行服务发现扫描，包括以下内容：

+   SMB 扫描

+   SNMP 扫描

+   使用**NSE**（**nmap 脚本引擎**）引擎

**Nbtscan**是 Kali 中的一个脚本，用于枚举目标 IP 的 NetBIOS 名称。它可以用作 SMB 枚举的早期部分。它基本上请求以人类可读格式的 NetBIOS 名称的状态查询。

## 准备工作

在本教程中，我们将使用工具枚举上述所有服务。

## 如何做...

对于本教程，步骤如下：

1.  为了枚举 NetBIOS 名称，我们将在终端中运行以下命令：

```
nbtscan <IP address>

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_031.jpg)

1.  您还可以在终端中使用以下命令对类范围进行 NetBIOS 枚举：

```
nbtscan -r <IP address>/<class range>

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_032.jpg)

1.  要执行 SMB 扫描，我们可以使用命令如`enum4linux`。在终端中输入以下命令开始 SMB 扫描：

```
enum4linux <IP address>

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_033.jpg)

此外，它甚至提供共享枚举信息以检查系统上可用的共享：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_034.jpg)

它甚至显示了目标上的密码策略（如果有的话）：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_035.jpg)

正如您所看到的，enum4 Linux 是一个强大的工具，特别是在启用空会话的情况下。

### 注意

从维基百科了解空会话的参考：空会话是对基于 Windows 的计算机上的进程间通信网络服务的匿名连接。该服务旨在允许命名管道连接。但是，它可以被利用来检索信息。要了解空会话的基本知识，请访问[`www.softheap.com/security/session-access.html`](http://www.softheap.com/security/session-access.html)。可以在[`pen-testing.sans.org/blog/2013/07/24/plundering-windows-account-info-via-authenticated-smb-sessions`](https://pen-testing.sans.org/blog/2013/07/24/plundering-windows-account-info-via-authenticated-smb-sessions)上了解详细的渗透测试场景。

1.  让我们继续进行 SNMP 扫描。为此，我们将使用一个名为 SnmpWalk 的扫描工具，并开始浏览**MIB**（**管理信息库**）树。

首先在终端中输入以下命令：

```
snmpwalk -c public -v1 <IP address>

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_036.jpg)

1.  当我们尝试访问 SNMP 服务时，我们可以看到获取了大量信息，默认字符串为 public，如果未更改。为了确保我们不会获取太多信息，并且有序地请求信息，我们可以利用 MIB 树。

例如，如果我们希望仅提取系统用户，则可以使用此值`1.3.6.1.4.1.77.1.2.25`，在终端中输入以下命令：

```
snmpwalk -c public -v1 <IP address> <MIB value>

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_037.jpg)

1.  我们将使用 nmap 查找开放端口的漏洞。Nmap 有一个用于评估目的的脚本的大列表，可以在`/usr/share/nmap/scripts/`中找到。输出将如下截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_038.jpg)

这些脚本需要不时更新。

选择目标后，我们将对其运行 nmap 脚本。

1.  打开终端并输入以下命令以执行脚本扫描：

```
nmap -sC <IP address >

```

### 注意

这将运行与开放端口匹配的所有可能的脚本。

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_039.jpg)

1.  我们甚至可以将扫描范围缩小到特定服务。在终端中键入以下命令，仅运行与 SMB 服务相关的所有枚举脚本：

```
nmap -sT --script *smb-enum* <IP address>

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_040.jpg)

1.  但是，我们应该意识到有一些脚本可能会在尝试分析目标是否容易受攻击时使服务停滞或崩溃。这些可以通过使用不安全的参数来调用，例如在终端中输入以下命令：

```
nmap -sT -p 139,443 --script smb-check-vulns --script-      args=unsafe=1 <IP address>

```

输出如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_041.jpg)

这告诉我们端口是否容易受到任何攻击。

## 它是如何工作的...

让我们了解一下本教程中使用的一些开关：

在 Nbtscan 中，我们使用了`-r`开关，告诉 nbtscan 扫描给定的整个类网络/子网；它查询 UDP 端口`137`上的所有系统。此端口有一个服务引用为“网络邻居”，也称为 netbios。当此端口接收到查询时，它会响应该系统上所有正在运行的服务。

`enum4linux`是一个枚举几乎所有可能信息的脚本，包括 RID 循环、用户列表、共享枚举、识别远程操作系统的类型、正在运行的服务是什么、密码策略等等，如果目标 IP 容易受到空会话认证的攻击。

以下是 SnmpWalk 中使用的开关：

+   `-c`：此开关告诉 SnmpWalk 它是什么类型的社区字符串。默认情况下，SNMP 社区字符串是 public。

+   `-v1`：此开关指定 SNMP 版本为 1。我们甚至可以使用 2c 或 3，这取决于它正在运行的 SNMP 服务版本的类型。

+   `dnsenum`：这是一个 DNS 枚举工具。它基本上从 DNS 服务器中枚举所有与 DNS 相关的信息，并检查是否可能进行区域传输。

+   `-sC`：此开关使 nmap 能够运行默认 NSE 脚本，用于检测目标 IP 上检测到的所有开放端口，从存储库中。

+   `--script`：此开关使我们能够指定要执行的脚本。我们可以使用正则表达式，如前面的示例所示。

+   `--script-args=unsafe=1`：此开关使 nmap 能够运行危险的脚本，以评估端口是否容易受到某种攻击。之所以不是默认脚本分析的一部分，是因为有时这些脚本可能导致远程服务崩溃并变得不可用，导致 DOS 情况。

在这个教程中，我们学习了如何在 nmap 检测到的服务上运行不同的脚本，以及如何运行危险的枚举脚本。

## 还有更多...

建议为了更好地运行脚本，我们应该使用 Zenmap。我们可以创建一个配置文件并选择要执行的脚本。

在 Zenmap 中，转到**配置文件** | **新配置文件**或**命令** | **脚本**，并选择要测试的脚本。

# 开源信息收集

在这个教程中，我们将看看如何使用专为在线信息收集而设计的工具。我们将介绍用于收集有关 Whois、域工具和 MX 邮件服务器信息的工具。Shodan 是一个强大的搜索引擎，可以在互联网上为我们定位驱动器。借助各种过滤器，我们可以找到有关我们目标的信息。在黑客中，它也被称为世界上最危险的搜索引擎。

## 准备工作

我们将利用诸如 DNsenum 之类的工具进行 Whois 枚举，找出与域相关的所有 IP 地址，以及 Shodan 如何为我们提供所搜索目标的开放端口信息。

## 如何操作...

步骤如下：

1.  对于 DNS 扫描，我们将使用一个名为 DNsenum 的工具。让我们从在终端中输入以下命令开始：

```
dnsenum <domainname>

```

输出如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_042.jpg)

1.  我们还可以使用可用于通过谷歌抓取搜索更多子域的功能。输入以下命令：

```
dnsenum -p 5 -s 20 facebook.com

```

输出如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_043-2.jpg)

正如我们所看到的，`p`和`s`开关告诉 dnsenum 在 4 页谷歌搜索中搜索，并从谷歌中拉取最大数量的抓取条目。

1.  dnsenum 的另一个特性是提供一个子域字典文件列表，以查找有效的子域和它们的地址。可以通过发出以下命令来完成相同的操作：

```
 dnsenum -f subdomains.txt facebook.com

```

在这里，子域是可能的子域的自定义列表，我们得到以下输出：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_044.jpg)

回到简单的 DNS 枚举，我们执行了上面的操作，观察到输出包含大量信息，因此最好将输出保存在文件中。一种选择是使用以下命令将输出推送到文件中：

```
dnsenum <domain name> > dnsenum_info.txt

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_045.jpg)

然而，如果我们需要将输出枚举用于另一个工具，我们必须使用 dnsenum 提供的开关以 XML 格式输出，因为大多数工具支持 XML 导入功能。使用以下命令：

```
dnsenum -o dnsenum_info <domain name>

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_046.jpg)

1.  当我们使用 head 命令输出文件时，我们得到以下内容：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_047.jpg)

1.  `dnsenum`命令为您提供了有关目标的大量信息：

+   名称服务器：名称服务器是处理有关域名各种服务位置的查询的服务器

+   MX 记录：这指定了与给定主机的邮件服务器对应的 IP。

+   主机地址：这指定了服务器托管的 IP 地址

+   子域：主站点的一个子集；例如，[mail.google.com](http://mail.google.com)和[drive.google.com](http://drive.google.com)是[google.com](http://google.com)的子域。

+   反向查找：查询 DNS 服务器以查找域名的 IP 地址

1.  在[`www.shodan.io`](http://www.shodan.io)上注册 Shodan，并单击“探索”以浏览可见的功能列表。

1.  现在转到网络摄像头部分，您将看到所有具有网络摄像头服务器运行在其系统上的 IP 列表。

1.  假设您设法获取了目标 IP 或 Web URL；只需在搜索过滤器中输入 IP，就可以检索大量信息，如下截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_048.jpg)

1.  假设您想要检查属于某个国家的所有服务器；在搜索过滤器中，输入`Country:IN`。

您可以看到它获取了大量的输出：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_049.jpg)

1.  这是特定 IP 地址的输出方式：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_050.jpg)

1.  在左上角，当您单击**查看全部...**选项卡时，您将获得 Shodan 所有可用功能的列表：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_02_051.jpg)

正如我们所看到的，提供的功能数量是庞大的。我们应该花时间逐一探索所有选项。

## 工作原理...

`dnsenum <domain name>`语法查询所述域名的 DNS 服务器，然后是名称服务器和邮件服务器。它还执行检查是否可以进行区域传输。

使用的命令如下：

+   `-o`：当与文件名一起指定时，这将提供所做的 DNS 枚举的基于 XML 的输出

+   `-p = pages <value>`：在抓取名称时要处理的谷歌搜索页面数；默认为 20 页；必须指定`-s`开关

+   `-s = scrap <value>`：从谷歌中抓取的子域的最大数量

+   `-f, = file <file>`：从此文件中读取子域以执行暴力破解

Shodan 有一个庞大的过滤器列表；上面使用的过滤器如下：

+   **国家**：这指定了搜索给定目标的国家；通常由国家代码标识

## 还有更多...

可以通过使用 Shodan 搜索引擎进行更多的信息收集。

Shodan 搜索引擎允许用户通过不同的过滤器组合在互联网上找到特定类型的计算机或设备。这可以是一个收集有关目标信息的重要资源。我们可以通过访问[`www.shodanhq.com/help/filters`](http://www.shodanhq.com/help/filters)了解更多关于 Shodan 过滤器的信息。


# 第三章：网络漏洞评估

在本章中，我们将涵盖以下内容：

+   使用 nmap 进行手动漏洞评估

+   将 nmap 与 Metasploit 集成

+   使用 Metasploit 进行 Metasploitable 评估的详细步骤

+   使用 OpenVAS 框架进行漏洞评估

# 介绍

之前，我们已经涵盖了在网络上发现活动服务器以及服务枚举。在这里，我们将讨论什么是漏洞评估。漏洞评估是一个过程，测试人员旨在确定端口上运行的服务，并检查它们是否存在漏洞。当利用漏洞时，可能会导致我们获得未经身份验证的访问、拒绝服务或信息泄露。漏洞评估是必不可少的，因为它给我们提供了被测试网络安全的全面图景。

在本章中，我们将检查运行在开放端口上的服务是否存在漏洞。了解服务运行的操作系统非常重要，因为这是在涉及远程代码执行的漏洞发现中的关键因素之一。原因是不同操作系统上的相同服务由于架构差异将具有不同的漏洞利用。让我们谈谈一个漏洞：SMB 服务，根据 MS08-067 netapi 漏洞是易受攻击的。这个漏洞存在于旧的 Windows 系统上，但在新系统上不存在。例如，Windows XP 容易受到这种攻击的影响；然而，Windows Vista 不会，因为它已经修补了。因此，了解系统正在运行的操作系统和服务包版本，以及开放端口上的服务，如果要发现任何漏洞，这是非常重要的。在本章中，我们将学习在目标 IP 上检测漏洞的不同方法。

# 使用 nmap 进行手动漏洞评估

到目前为止，很明显 nmap 从 IP 发现开始就扮演着非常重要的角色。nmap 还具有漏洞评估功能，通过**Nmap 脚本引擎**（**NSE**）实现。它允许用户运行漏洞检测脚本。NSE 包含一组非常庞大的脚本，涵盖了从发现到利用的各种脚本。这些脚本位于`nmap`文件夹中，并按其类别进行了分离。可以通过阅读位于`nmap`文件夹中的`scripts.db`文件更好地理解这些类别。然而，在本章中，我们将限制自己只进行漏洞检测。

## 准备工作

为了开始本章，我们将使用 nmap 来检查位于`scripts`文件夹下的 nmap 中的 NSE 脚本。为了演示目的，我们将使用 Metasploitable 2 和 Windows XP SP1。

## 如何做...

此食谱的步骤如下：

1.  我们应该首先看看 NSE 脚本的位置。输入以下命令：

```
ls /usr/share/nmap/scripts/

```

输出将如下截屏所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_001.jpg)

1.  为了了解这些脚本属于的所有不同类别，输入：

```
cat /usr/share/nmap/scripts/script.db | grep "vuln"

```

输出将如下截屏所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_002.jpg)

1.  您可能会注意到前面的截图中有一个名为`vuln`的类别。我们将主要使用这个类别。要运行简单的`vuln`类别扫描，请在终端窗口上使用以下命令：

```
nmap -sT --script vuln <IP Address> 

```

1.  假设我们只想快速评估几组端口。我们可以运行基于端口的`vuln`评估扫描：

```
nmap -sT -p <ports> --script vuln <IP Address>

```

输出将如下截屏所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_003.jpg)

我们可以看到它揭示了很多信息，并向我们展示了许多可能的攻击向量；它甚至检测到了 SQL 注入以进行潜在攻击：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_004.jpg)

1.  假设我们想知道脚本类别`vuln`的详细信息。我们可以通过在终端中输入以下命令来简单检查：

```
nmap --script-help vuln

```

输出将如下截屏所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_005.jpg)

1.  让我们检查远程运行的机器是否容易受到 SMB 的攻击。我们首先找出 SMB 端口是否开放：

```
nmap -sT -p 139,445 <IP address>

```

输出将如下截屏所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_006.jpg)

1.  一旦我们检测到端口是开放的，我们运行一个`smb`漏洞检测脚本，如下所示：

```
nmap -sT -p 139,445 --script smb-vuln-ms08-067 <IP address>

```

输出将如下截屏所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_007.jpg)

因此，可以使用 nmap 中可用的各种带有`vuln`类别的脚本对目标 IP 进行评估，并根据端口和服务运行情况找出漏洞。

## 工作原理...

理解所有参数相当容易；我们一直在玩 NSE 引擎中可用的脚本。让我们了解一下这种方法中使用的一些命令：

+   `scripts.db`文件包含了所有 NSE 分类信息，用于指定哪些脚本可以被视为特定类型的漏洞。有不同的类别，如`auth`、`broadcast`、`brute`、`default`、`dos`、`discovery`、`exploit`、`external`、`fuzzer`、`intrusive`、`malware`、`safe`、`version`和`vuln`。

+   在前面的示例中，我们使用了带有`vuln`参数的`nmap`命令。我们只是指示 nmap 使用`vuln`类别并运行所有类别为`vuln`的脚本。

### 注意

这个扫描需要很长时间，因为它将在许多检测到的开放端口上运行许多漏洞评估。

+   在某个时候，我们为`vuln`类别扫描指定了一个额外的端口参数。这只是确保脚本仅在指定的端口上运行，而不是其他端口，从而节省了我们大量的时间。

+   `--script-help <filename>|<category>|<directory>|<expression>|all[,...]`命令是 NSE 引擎的帮助功能。`help`命令应始终与 NSE 脚本的类别或特定文件名或表达式一起使用。例如，要检查所有与 SMB 相关的帮助，可以简单地使用表达式`*smb*`。

+   在`--script-args=unsafe=1`命令中，`script-args`语法类似于要传递给我们刚选择的脚本的附加参数；在这种情况下，我们正在传递一个额外的`unsafe`参数，值为`1`，表示脚本有权限运行可能导致服务崩溃的危险脚本。

## 还有更多...

我们已经学会了如何使用 NSE 进行漏洞评估。`script-args`参数用于许多目的，例如提供用户名和密码的文件，指定给定服务的凭据，以便 NSE 可以在认证后提取信息等。这是建议的，以便您更深入地了解`script-args`功能。

## 另请参阅...

+   更多信息可以在 NSE 文档中找到，网址为[`nmap.org/book/nse-usage.html`](https://nmap.org/book/nse-usage.html)。

# 将 nmap 与 Metasploit 集成

仅使用 nmap 进行漏洞评估是不够的，因为漏洞数量日益增加。一个月内报告了许多漏洞，因此建议您使用多个漏洞扫描工具。在上一章中，我们看到了如何将 nmap 扫描的输出导出到 XML 文件；在这里，我们将学习如何将 nmap 输出与 Metasploit 集成，用于漏洞评估。

## 准备工作

我们首先需要在 Kali Linux 机器上设置和更新 Metasploit。

需要注意的一点是，为了演示目的，我们已经向 Windows 操作系统添加了更多服务，以更好地了解活动，因为默认情况下只有少数端口是开放的。为了准备这项活动，我们对 Windows 机器进行了扫描，并保存了相同的 XML 输出。

## 操作步骤...

1.  首先，我们将使用以下命令将 nmap XML 文件保存为 Metasploitable 2 服务器：

```
nmap -sT -oX Windows.xml <IP Address>

```

文件将保存在您终端的当前工作目录中。

1.  为了启动 Metasploit，我们将启动 Metasploit 程序中涉及的服务。我们将启动 Postgres SQL 服务和 Metasploit 服务。要做到这一点，请使用以下命令：

```
      service postgresql start
      service metasploit start

```

输出将如下截屏所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_008.jpg)

1.  一旦服务启动，我们将通过在命令行中输入以下内容来启动 Metasploit：

```
msfconsole

```

输出将如下截屏所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_009.jpg)

1.  首先，我们将把 nmap 扫描导入 Metasploit。为此，请输入以下命令：

```
      db_import /root/Windows.xml
      db_import <path to the file>

```

该命令从指定路径导入文件。请确保记下从读者存储文件的路径导入。

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_010.jpg)

1.  一旦导入成功，我们将在 Metasploit 中使用以下命令搜索运行 SMB 服务的 IP：

```
Services -p 445 -R

```

这将产生以下输出：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_011.jpg)

1.  现在我们已经发现有一个感兴趣的端口，我们将尝试深入挖掘。让我们尝试显示 SMB 共享。在 Metasploit 控制台中输入以下内容：

```
use auxiliary/scanner/smb/smb_enumshares

```

输出将如下截屏所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_012.jpg)

1.  为了列出可用的共享，我们将运行扫描器辅助模块。只需在 Metasploit 控制台中输入`run`或`exploit`，这两个命令都可以完成工作。

输出将如下截屏所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_013.jpg)

1.  正如我们所看到的，我们能够收到一个 IP 地址的详细信息。让我们更仔细地查看一下活动主机。我们将尝试枚举此主机可用的管道审计员类型。在 Metasploit 控制台中输入以下内容：

```
use auxiliary/scanner/smb/pipe_auditor

```

命名管道用作通信的端点；它是客户端和服务器之间的逻辑连接；`smb`命名管道与与 Server Message Block 相关的连接有关。如果我们幸运的话，我们可能能够检索到像可用的公共共享这样的信息。

完成后，您可以检查所有参数是否正确输入。由于在检查攻击之前必须输入一些选项卡，您可以使用以下命令：

```
      show options
      run

```

它应该是这样的：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_014.jpg)

1.  在检查给定端口的漏洞时，发现 SMB 共享对于早于 Windows XP Service Pack 2 的所有 Windows 版本都容易受到`ms08_067_netapi`攻击。让我们尝试找出我们的活动主机是否容易受到这种攻击。在 Metasploit 窗口中输入以下内容以加载`ms08_067_netapi`模块：

```
use exploit/windows/smb/ms08_067_netapi

```

要检查 IP 是否存在漏洞，请使用`check`命令，您将得到输出，说明它是否可能是一个成功的攻击向量：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_015.jpg)

正如您所看到的，目标是有漏洞的。

## 工作原理...

正如你所看到的，我们首先将 nmap 结果导入到 Metasploit 中。当我们在 nmap 中有大量 IP 输出时，这非常方便，因为我们可以导入所有这些 IP，并在方便的时候执行漏洞评估阶段。让我们来看看我们使用的所有命令的理解：

+   `service postgresql start`：这将启动 Postgres SQL 服务。

+   `service metasploit start`：这将启动 Metasploit 客户端服务

+   `msfconsole`：这将启动 Metasploit 控制台

+   `db_import`：此命令允许 Metasploit 从 XML 文件中导入 nmap 结果，并将其添加到包含通过 nmap 获得的所有信息的主机列表的数据库中

+   `services -p（端口号）-R`：此命令显示在指定端口上运行的服务，如果存在满足条件的 IP，则会通过`-R`命令将其添加到 Metasploit 主机列表中

+   `use <扫描模块>`：`use`命令选择要从 Metasploit 中选择的模块类型

+   `check`：在某些情况下，Metasploit 允许用户运行检查命令，该命令会对服务进行指纹识别，并告诉我们它是否存在漏洞。但在 DDOS 模块的情况下不起作用。

## 还有更多...

+   Metasploit 中还有更多可帮助您操作不同辅助模块的选项

# 使用 Metasploit 进行 Metasploitable 评估的演练

在本节中，我们将学习如何对一个名为 Metasploitable 2 的易受攻击的服务器进行评估。本节将为您介绍在漏洞评估环境中进行的一些评估测试。漏洞评估是一个非常广泛的阶段。我们需要执行许多任务，比如找出服务器上开放的端口，运行在这些端口上的服务，以及这些服务是否存在漏洞。同样的，也可以通过在线搜索已知的服务漏洞来完成。所有的信息收集和漏洞兼容性检查都可以在漏洞评估结束时完成。我们开始利用系统进行 root 或 shell 攻击的地方可以称为渗透测试。

## 准备工作...

对于这个练习，我们需要 Metasploitable 2，这是一个故意创建的虚拟机，其中包含许多含有漏洞的服务。可以在（[`www.vulnhub.com/entry/metasploitable-2,29/`](https://www.vulnhub.com/entry/metasploitable-2,29/)）下载这个虚拟机，以及我们已经拥有的 Kali Linux 虚拟机。我们将首先看看如何安装和设置 Metasploitable 2 实验室，以便开始漏洞评估。

## 如何操作...

1.  一旦图像被下载，将其加载到虚拟机中。可以使用 Virtual box 或 VMplayer；安装如下：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_016.jpg)

1.  加载后，它将加载到虚拟机中。它将显示在**虚拟**选项卡中，如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_017.jpg)

1.  将**网络适配器**设备配置为**桥接**模式，以便获得 LAN IP。对于 VMware 用户，右键单击图像，单击**设置**，选择网络适配器选项并选择桥接模式。对于 VirtualBox 用户，右键单击 Metasploitable 图像，选择**设置**，转到网络并将**连接到**选项设置为**桥接**。

用户也可以选择将其设置为**NAT**或**仅主机**模式；确保两台机器都处于相同的网络设置；然而，在**仅主机**模式下，用户将无法访问互联网。由于此活动是在受控环境中进行的，设置已被允许为**桥接**网络。然而，作为读者，建议您将这些虚拟机保持在**NAT**环境或**仅主机**环境中：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_018.jpg)

1.  一旦完成，启动机器。由于我们已将连接设置为桥接，我们将自动分配 IP。可以使用`ifconfig`命令检查。但是，如果我们没有分配一个，以超级用户身份运行`dhclient`。用户名为`msfadmin`，密码为`msfadmin`。

1.  我们现在将在我们的 Kali 机器上开始漏洞评估。首先，我们将执行一个`nmap`扫描，以查看 Metasploitable 2 机器上的开放端口。在 Kali 终端中输入以下命令：

```
nmap -sT <IP address>

```

输出将如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_019.jpg)

1.  一旦找到端口号，我们将运行信息收集模块或 NSE 脚本以获取更多信息。在终端中输入以下命令：

```
nmap -sT -T4 -A -sC <IP Address>

```

输出为我们提供了大量信息。让我们来看一下：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_020.jpg)

前面的截图显示了服务器正在运行`ftp`、`openssh`、`telnet`、`smtp`、`domain`等。已检索到更多信息。让我们看看以下截图：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_021.jpg)

我们还可以看到系统上运行着`mysql`服务、`postgresql`服务、`vnc`服务、`x11`和`IRC`。现在让我们开始对 Metasploitable 2 服务器进行漏洞评估。

1.  在整个过程中，我们将使用 Metasploit。让我们分析`ftp`服务，看看它是否容易受到已知组件的攻击。如果`Rhosts`选项没有显示我们的目标 IP 地址，我们可以手动填写。在 Metasploit 控制台中输入以下命令：

```
      use auxiliary/scanner/ftp/anonymous
      show options
      set Rhosts <IP Address>
      exploit

```

输出如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_022.jpg)

1.  我们将尝试使用`mysql`的身份验证绕过，看看我们是否成功。在`msf`终端上运行以下命令：

```
      use auxiliary/scanner/mysql/mysql_authbypass_hashdump
      exploit

```

输出如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_023.jpg)

1.  我们还知道有一个运行中的`nfs`服务。让我们运行信息收集模块`nfsmount`。输入以下命令：

```
      use auxiliary/scanner/nfs/nfsmount
      show options
      exploit

```

输出如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_024.jpg)

1.  我们甚至可以通过`metasploit`模块对`postgresql`服务进行暴力破解攻击。要做到这一点，在`mfs`终端中输入以下命令：

```
      use auxiliary/scanner/postgres/postgres_login
      exploit

```

输出如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_025.jpg)

1.  还有一个`smtp`服务正在运行。我们可以运行 Metasploit 的`smtp enumuser`脚本来列出可用的用户名。在`msf`终端中输入以下命令：

```
      use auxiliary/scanner/smtp/smtp_enum
      exploit

```

输出如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_026.jpg)

1.  我们还对 VNC 服务进行了评估。要做到这一点，在`msf`终端中输入以下命令：

```
      use auxiliary/scanner/vnc/vnc_logins
      Show options
      exploit

```

输出如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_027.jpg)

1.  有一个`x11`插件用于检查开放的`x11`连接。让我们测试系统上是否运行了`x11`服务。在`msf`终端中输入以下内容：

```
      use auxiliary/scanner/x11/open_x11
      show options
exploit 

```

输出如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_028.jpg)

1.  服务器还在端口`6667`上运行一个 IRC 频道。IRC 的名称是`unreal IRC`。为了验证，您可以使用 nmap 在给定端口上运行版本检测扫描。如果我们搜索该服务的可能漏洞，我们会看到以下内容：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_029.jpg)

点击[`www.exploit-db.com/exploits/16922/`](https://www.exploit-db.com/exploits/16922/)链接，我们看到以下内容：

![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_030.jpg)

这证实了 IRC 服务可能容易受到后门命令执行的攻击。

## 工作原理...

我们已成功评估了 Metasploitable 2 服务器。我们没有完成所有测试，但我们已经涵盖了其中的一些。

我们使用了以下命令：

+   `use auxiliary/scanner/ftp/anonymous`：该命令加载匿名`ftp`评估脚本，这将帮助我们了解指定的 IP 是否容易受到匿名 ftp 的攻击。

+   `use auxiliary/scanner/mysql/mysql_authbypass_hashdump`：该命令加载`mysql`身份验证绕过`hashdump`检查（如果可用）。

+   `use auxiliary/scanner/nfs/nfsmount`：该命令加载`nfs`检查，并显示服务器共享了哪些内容。

+   `use auxiliary/scanner/postgres/postgres_login`：该模块使用可用的凭据列表进行暴力破解。

+   `use auxiliary/scanner/smtp/smtp_enum`：该命令加载模块，帮助列出 SMTP 服务上可用的用户名。

+   `use auxiliary/scanner/vnc/vnc_login`：该命令加载`vnc`凭据`bruteforce`脚本。

+   `use auxiliary/scanner/x11/open_x11`：该命令在 Metasploit 上加载`x11`开放终端枚举脚本。

+   `show options`：此命令显示执行脚本所需的参数。这里提到的所有脚本都符合此描述。

+   `exploit/run`：此命令执行脚本并提供相应脚本运行的输出。

## 还有更多...

更多的扫描脚本可以在`/usr/share/metasploit-framework/modules/auxiliary/scanner`目录下找到。

它应该看起来像这样：

![还有更多...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_031.jpg)

这些都是漏洞评估的所有可用脚本，只要我们找到在目标机器上运行的相应脚本。

## 另请参阅...

+   有关更多信息，请访问[`www.offensive-security.com/metasploit-unleashed/auxiliary-module-reference/`](https://www.offensive-security.com/metasploit-unleashed/auxiliary-module-reference/)。

# 使用 OpenVAS 框架进行漏洞评估

我们已经看到了如何使用`metasploit`，`nmap`脚本进行手动漏洞评估测试。现在我们将看看如何使用自动化扫描程序。OpenVAS 是一个框架，包括几个具有全面和强大的漏洞扫描能力的服务和工具。OpenVAS 是 Kali Linux 操作系统的一部分。它可以在[`www.openvas.org/`](http://www.openvas.org/)下载，并且是开源软件。在这个教程中，我们将学习如何设置 OpenVAS。我们将安装、更新并开始使用这些服务。以下是了解扫描程序如何运行的架构：

![使用 OpenVAS 框架进行漏洞评估](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_032.jpg)

### 注意

在[`www.openvas.org/`](http://www.openvas.org/)找到更多关于 OpenVAS 的信息。

## 准备工作

首先，我们必须更新所有软件包和库。安装 OpenVAS 完成后，我们将更新插件并在 Metasploitable 2 机器上使用扫描程序。

## 如何做...

1.  首先，我们将更新和升级我们的操作系统，以确保我们的软件包和库是最新的。为此，请在命令行中输入以下内容：

```
apt-get update && apt-get upgrade

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_033.jpg)

1.  更新和升级所有软件包需要一些时间。完成后，浏览到以下位置并启动 OpenVAS 设置：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_034.jpg)

1.  设置是自解释的，您将看到以下屏幕。它更新了 OpenVAS NVT Feed，如下截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_035.jpg)

1.  随着安装的进行，它会更新 CVE feeds。**CVE**代表**通用漏洞和暴露**。

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_036.jpg)

1.  下载完成后，将创建一个用户并向我们提供服务，如下截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_037.jpg)

1.  现在，我们将使用终端中的以下命令检查安装是否已正确完成：

```
openvas-check-setup

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_038.jpg)

安装成功后，将显示以下内容：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_039.jpg)

1.  这表明我们的安装已经成功。我们将立即重新启动服务：

```
      openvas-stop
      openvas-start

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_040.jpg)

1.  让我们也为用户创建一个新密码，以及一个新用户：

```
      openvasmd --user=admin --new-password=<Your password>
      openvasmd --create-user <Your Username>

```

输出将如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_041.jpg)

1.  既然我们知道安装已经成功完成，我们将访问 Greenbone Security Assistant。在 Iceweasel 浏览器中输入`https://127.0.0.1:9392/login/login.html` URL 并输入我们的凭据：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_042.jpg)

1.  登录后，屏幕将如下所示。我们将输入目标 IP 地址，如下截图所示：![如何做...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_043.jpg)

1.  一旦我们点击**开始扫描**选项，扫描器将利用其对所有插件的知识，并检查应用程序上是否存在已知漏洞。这是一个耗时的过程，完全取决于服务器上开放的端口数量。扫描完成后，将显示检测到的漏洞总数：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_044.jpg)

1.  如前面的截图所示，要查看报告，我们将点击**扫描管理**选项卡，然后点击**报告**选项，这将带我们到报告页面。然后，我们将选择我们扫描的 IP 地址，这将显示所有的漏洞：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_045.jpg)

1.  我们可以导出包含这些细节的 PDF 报告。在报告上方，就像鼠标指针在下面的截图中所示的那样，会有一个下载选项，我们可以从那里保存：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_046.jpg)

1.  保存的 PDF 文件将如下截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_047.jpg)

然后可以使用此文件来枚举不同类型的漏洞，然后我们可以检查漏洞列表中是否存在任何误报。

## 工作原理...

正如您所看到的，设置和操作 OpenVAS 漏洞扫描器非常简单。让我们看看后端实际发生了什么，以及我们使用的一些前面的命令的含义。

让我们先看看命令：

+   `openvas-check-setup`：此命令验证我们的 OpenVAS 设置是否正确安装，并警告我们任何文件安装不完整。它还建议任何必要的修复以使软件正常运行。

+   `openvas-stop`：此命令停止 OpenVAS 中涉及的所有服务，如 OpenVAS 扫描仪、管理器和 Greenbone 安全助理。

+   `openvas-start`：此命令启动 OpenVAS 中涉及的所有服务，如 OpenVAS 扫描仪、管理器和 Greenbone 安全助理。

+   `openvasmd --user=<您的用户名> --new-password=<您的密码>`：此命令帮助设置创建的用户的新密码。

+   `openvasmd --create-user <用户名>`：此命令创建一个指定用户名的用户。

当我们启动扫描时，扫描器会加载所有模块和插件，对所有可用的端口进行评估。该过程如下：

+   扫描开放端口

+   运行所有开放端口及其服务的插件

+   运行来自 CVE 数据库和 OpenVAS NVT feeds 的已知漏洞

+   基于插件评估，我们得到了我们正在评估的目标的可能漏洞的输出

## 还有更多...

我们甚至可以通过 Greenbone 安全助理中的**配置**选项卡根据自己的需要配置扫描。我们还可以设置系统的凭据进行系统配置审查，并自定义警报、过滤器和要扫描的端口。

仅通过查看一些示例，很难理解“漏洞评估”这个术语。需要有一个可以遵循的标准，以便基本了解评估的实际发生情况。在本节中，我们将学习漏洞评估的含义。

漏洞评估有时会与渗透测试混淆。整个漏洞评估过程的核心目的是识别系统、环境或组织的威胁。在漏洞评估过程中，主要目标是找到系统的入口点，并查明它们是否使用了易受攻击的服务或易受攻击的组件。然后进行严格的测试，以确定系统上是否存在各种已知威胁。

然而，渗透测试是一种超越简单识别的东西。当您开始攻击系统以获得 shell 或崩溃服务时，您就参与了渗透测试。为了对漏洞评估有组织的方法，可以参考开源。有一篇非常好的文章，可以帮助理解 Daniel Meissler 撰写的漏洞评估和渗透测试之间的微妙差别。以下是文章的链接：[`danielmiessler.com/study/vulnerability-assessment-penetration-test/`](https://danielmiessler.com/study/vulnerability-assessment-penetration-test/)。

一些测试方法的例子如下：

+   **渗透测试执行标准**（**PTES**）

+   **开放网络应用安全项目**（**OWASP**）：Web 应用程序测试指南

+   **开放源安全测试方法手册**（**OSSTMM**）

+   Web 应用程序黑客方法论（Web 应用程序黑客手册）

### PTES

渗透测试执行标准可在[`www.pentest-standard.org/index.php/Main_Page`](http://www.pentest-standard.org/index.php/Main_Page)找到，包括七个主要部分：

+   *前期互动*

+   *情报收集*

+   *威胁建模*

+   *漏洞分析*

+   *利用*

+   *后期利用*

+   *报告*

正如 PTES 所总结的：“*漏洞测试是发现系统和应用程序中可以被攻击者利用的缺陷的过程。这些缺陷可以是主机和服务配置错误，或不安全的应用程序设计。尽管用于查找缺陷的过程因特定组件的测试而异，并且高度依赖于特定组件的测试，但是一些关键原则适用于该过程。*”

PTES 是一系列非常详细的技术指南，可以在[`www.pentest-standard.org/index.php/PTES_Technical_Guidelines`](http://www.pentest-standard.org/index.php/PTES_Technical_Guidelines)找到。

### OWASP

开放网络应用安全项目主要处理基于 Web 应用程序的安全评估。OWASP 是一个旨在提高软件安全性的非营利性慈善组织。它是一个广泛使用的基于 Web 的安全组织。OWASP 可以在[`www.owasp.org/`](https://www.owasp.org/)找到。

OWASP 的目标最好由组织本身总结：“*每个人都可以自由参与 OWASP，我们所有的材料都在自由和开放的软件许可下可用。您可以在我们的维基或链接到我们的维基上找到关于 OWASP 的一切信息，以及我们的 OWASP 博客上的最新信息。OWASP 不认可或推荐商业产品或服务，这使我们的社区能够保持与全球软件安全最优秀的头脑的集体智慧保持供应商中立。*

*我们要求社区注意 OWASP 品牌的不当使用，包括我们的名称、标志、项目名称和其他商标问题。*

OWASP 测试指南可以在[`www.owasp.org/index.php/Web_Application_Penetration_Testing`](https://www.owasp.org/index.php/Web_Application_Penetration_Testing)找到。

### Web 应用程序黑客方法论

这种方法已经在书中得到很好的定义，《Web 应用程序黑客手册：发现和利用安全漏洞，第 2 版》。同样可以在[`www.amazon.in/Web-Application-Hackers-Handbook-Exploiting/dp/8126533404/&keywords=web+application+hackers+handbook`](http://www.amazon.in/Web-Application-Hackers-Handbook-Exploiting/dp/8126533404/&keywords=web+application+hackers+handbook)上找到。

总结该方法，请查看以下图表：

![Web 应用程序黑客方法论](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali-itrs-exp-cb/img/image_03_048.jpg)

## 另请参阅...

+   有关 OpenVAS 工作原理的更多信息，请参考 NetSecNow 的视频教程[`www.youtube.com/watch?v=0b4SVyP0IqI`](https://www.youtube.com/watch?v=0b4SVyP0IqI)。
