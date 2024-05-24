# Kali NetHunter 渗透测试实用指南（三）

> 原文：[`annas-archive.org/md5/459BF96CB0C4FE5AC683E666C385CC38`](https://annas-archive.org/md5/459BF96CB0C4FE5AC683E666C385CC38)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：建立实验室

在网络安全领域学习利用和渗透测试对学生和专业人士来说既令人兴奋又迷人。黑客的想法很酷，但是在学习网络安全，比如渗透测试时，一个学术机构，比如技术学院或大学，通常会建立一个物理实验室环境来进行培训。学习道德黑客和渗透测试应该只使用为此类培训设计和构建的系统来教授；换句话说，渗透测试绝对不应该使用互联网上可用的系统或者不提供此类测试许可的系统来教授。

要开始渗透测试，您应该建立一个实验室。拥有自己的实验室将消除某些限制，比如必须在培训机构内部才能访问他们的实验室。此外，实验室的可用性和可移植性将不受限制。

在本章中，我们将涵盖以下主题：

+   建立渗透测试实验室的要求

+   虚拟化简介

+   建立易受攻击的系统

让我们开始吧！

# 技术要求

在建立任何东西时，最重要的考虑之一是完成所需的成本。然而，在 IT 领域，有许多合法的方法可以建立渗透测试实验室，而无需花费任何金钱。我们不是在谈论盗版，因为那是非法的，但是有许多企业标准的免费应用程序可用。我们将使用各种应用程序来组装我们自己的便携式渗透测试实验室。

要开始，您需要从互联网上下载一些项目来实现所有这些：

+   虚拟化程序

+   易受攻击的系统

+   渗透测试分发

# 虚拟化程序

在 IT 领域，我们中的一些人喜欢使用服务器，无论是 Windows 还是 Linux。服务器和 IT 中的其他所有东西一样令人兴奋。今天最重要的技术之一是虚拟化。虚拟化允许您在任何类型的硬件上安装几乎任何类型的操作系统。这意味着什么？一些操作系统，如 Android、Windows Server、Linux Server 和 macOS，需要专门的硬件，如特定类型的处理器，如果系统没有所需的硬件资源，操作系统将无法安装。虚拟化通过使用一个称为虚拟机管理器的虚拟机来拯救一天。

虚拟化程序创建和模拟一个虚拟环境以满足操作系统的需求。虚拟化程序允许管理员（比如您）配置处理器的核心和线程数量，内存和硬盘分配，以及输入/输出（I/O）如 USB 控制器和串行控制器。因此，在安装过程中，客户操作系统认为自己是在物理硬件上安装，但实际上是在虚拟环境中安装。这些被称为虚拟机。

主机操作系统是当前笔记本电脑或台式电脑上的操作系统，客户操作系统是虚拟机或虚拟化程序内的操作系统。

有两种类型的虚拟化程序。让我们在接下来的部分中讨论每种类型。

# Type 1

Type 1 虚拟化程序被称为裸金属虚拟化程序。这种类型的虚拟化程序直接安装到硬件上，并成为主机操作系统：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/e70d0e08-f857-4119-8433-12b540467fc5.png)

# Type 2

Type 2 虚拟化程序安装在主机操作系统之上。这种类型的虚拟化程序使用主机操作系统提供的 CPU、内存和存储资源：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/896a001f-f95b-416d-a5dc-a6d6531a724c.png)

我们将使用 Type 2 虚拟化程序来建立我们的渗透测试实验室。使用虚拟机进行技术培训的好处是，如果在客户操作系统中发生任何事情，都不会影响主机操作系统。

以下是 Type 2 虚拟化程序：

+   Oracle VM VirtualBox（免费）

+   VMware Workstation Player（免费和商业）

+   VMware Workstation Pro（商业）

+   Microsoft Virtual PC（免费）

# 易受攻击的系统

建立渗透实验室中最重要的组成部分之一是易受攻击的系统。我们不能随意尝试在没有事先同意的系统上进行实践，因为那是非法和侵入性的。

用于渗透测试培训和实践的流行易受攻击的机器包括 Metasploitable 2 和 Metasploitable 3。这些是由 Rapid 7 的开发团队（[www.rapid7.com](http://www.rapid7.com)）为学生和专业人士开发他们的渗透测试技能而创建的，使用 Rapid 7 自己的开发框架 Metasploit（[www.rapid7.com/products/metasploit](http://www.rapid7.com/products/metasploit)）。

用于练习和添加到实验室中的易受攻击系统的其他来源包括 VulnHub ([www.vulnhub.com](http://www.vulnhub.com))和 Pentesterlab ([www.pentesterlab.com](http://www.pentesterlab.com))。

# 建立实验室

在这一部分，我们将组装所有的部件，建立一个完全操作的渗透测试实验室。

# 第 1 步 - 安装 hypervisor

首先，从其官方网站下载 Oracle VM VirtualBox：[www.virtualbox.org](http://www.virtualbox.org)。

一旦你下载了 Oracle VM VirtualBox，完成安装过程，并保持所有选项默认。安装成功后，你将看到以下窗口：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/eb1b2e87-e151-4770-bfcc-9a153deea759.png)

另一个非常受欢迎的 hypervisor 是 VMware Workstation。但是，这个产品是商业的（付费），不像 Oracle VM VirtualBox（免费）。

# 第 2 步 - 获取易受攻击的系统

正如前面提到的，互联网上有许多可用的易受攻击系统。我们将部署*Metasploitable*和*OWASP 破碎的 Web 应用项目* - 这两个都是为了给学生和专业人士提供真实的实践经验而设计的虚拟机。

Metasploitable 2 目前可以在其官方存储库[`information.rapid7.com/download-metasploitable-2017.html`](https://information.rapid7.com/download-metasploitable-2017.html)上找到，也可以在[`sourceforge.net/projects/metasploitable/`](https://sourceforge.net/projects/metasploitable/)上找到。

OWASP 破碎的 Web 应用项目可以在[`sourceforge.net/projects/owaspbwa/files/`](https://sourceforge.net/projects/owaspbwa/files/)找到。确保你已经下载了`.ova`文件，因为它将使设置过程更加顺畅。

# 第 3 步 - 设置 Metasploitable

从 Metasploitable 2 开始，转到包含文件`metasploitable-linux-2.0.0.zip`的文件夹。确保解压缩文件夹的内容。这些文件组成了一个虚拟硬盘，稍后可以添加到 hypervisor 上：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/8b35d837-9fc6-4c3b-bfe8-3ea497f4b370.png)

打开 VirtualBox，点击新建。向导以引导模式打开，但是我们将使用专家模式：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/576c619c-1ae0-4d21-adaf-20902836060b.png)

对于硬盘选项，我们将使用 Metasploitable 2 虚拟硬盘；这些是从上一步中提取的文件。选择“使用现有的虚拟硬盘文件”选项，然后点击文件夹图标

点击“添加”以附加虚拟硬盘。一旦它在窗口中，点击“选择”来选择它：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/6f14d7e2-db5d-46f8-a86a-7d72712f10dc.png)

点击“选择”将你带回到主窗口 - 我们可以看到文件已经被附加上了：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/a5831fe5-a31b-4caa-bdea-7a6dfe55c7fd.png)

点击“创建”完成过程：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/906697f3-a614-4f69-85e6-8f9452c5f563.png)

让我们在这个新创建的虚拟机上配置网络适配器。选择虚拟机，然后点击“设置”。

接下来，选择网络类别，应用以下配置，完成后点击“确定”：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/02ff8f76-573e-48f5-ae5e-56961f740732.png)

**仅主机适配器**设置将允许虚拟机和主机操作系统之间在私有虚拟网络上进行通信。不建议将易受攻击的系统连接到互联网。

**桥接模式**将允许虚拟机直接连接到您的物理或真实网络。

现在，是时候使用 VirtualBox 设置虚拟网络了。要在主机系统上配置虚拟适配器，请确保 VirtualBox 已打开 - 在顶部，点击工具|创建：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/5b7c3a41-4f40-46fb-b535-c35975828765.png)

如果适配器已经存在，请选择它并点击属性。我们将在我们的虚拟实验室网络中使用`10.10.10.0/24`网络。这个 IP 方案将提供一个可用范围从`10.10.10.1`到`10.10.10.254`，但是这些 IP 地址将由内置在 VirtualBox 中的 DHCP 服务器分配：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/12b7bea2-93a1-46a7-8ba3-52d71b434c0e.png)

完成这些配置后，点击应用。

现在是时候启动*Metasploitable*了。用户名是`msfadmin`，密码是`msfadmin`：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/f99a5991-3d64-48f2-9f28-97d41ea8ae59.png)

一旦您登录，使用`ifconfig`命令检查**虚拟机**（**VM**）的 IP 地址：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/7aeff7fa-a177-4cd0-bb89-bb55dc73e08f.jpg)

# 第 4 步 - 设置 OWASP 破碎的 Web 应用项目

打开 VirtualBox 并点击导入：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/d170de4f-cd4d-4c72-9b27-2637fbd8a157.png)

导入虚拟设备窗口将打开 - 点击右侧的文件夹图标。选择`OWASP_Broken_Web_Apps_VM_1.2.ova`文件：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/0633d9a3-6eec-4b15-b3ff-4e5636c5c55b.png)

现在窗口中应该填充了设备配置，所以点击导入：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/d739ad5d-7a1c-42bc-8e69-ffaaf7e651da.png)

导入后，是时候启动新的虚拟机并获取其 IP 地址了。用户名是`root`，密码是`owaspbwa`：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/86e7db50-1f97-4e29-b90e-a87ff8671baf.png)

OWASP Broken Web Applications Project 的资源，这是一个通过 Web 界面访问的 VM。

现在我们在我们的虚拟化渗透测试实验室中有一些易受攻击的系统，并且可以随时使用。请记住：可以随时向您的实验室添加其他易受攻击的系统，以进一步练习并提高您的技能。

# 摘要

在本章中，我们介绍了组装虚拟实验室进行渗透测试的要求，选择每个组件的原因，并最终在组装阶段将这些组件组合在一起。我希望本章内容能够提供信息，并且您能够添加更多的虚拟机，以增加实验室的规模，并在渗透测试中变得更加优秀。现在，您可以在家里建立自己的实验室。 

在下一章中，我们将看看如何为 Kali 设备和硬件选择各种选项。


# 第十二章：选择 Kali 设备和硬件

当您几乎完成了这本书，仍有一些重要的细节和组件需要讨论，以确保您已经准备好进行渗透测试之旅。

在本章中，我们将涵盖以下主题：

+   适用于 Kali Linux 的移动硬件

+   外部组件

+   额外的硬件

在本书的过程中，您已经了解了渗透测试领域，特别是使用移动设备对目标系统或网络执行真实世界的模拟攻击和分析。但是，选择适合 Kali Linux 的设备有时可能会有些麻烦。作为学生、安全专业人员、渗透测试人员或者在网络安全领域开始探索道路的人，尤其是在渗透测试方面，您可能会有以下问题：

+   Kali NetHunter 可以在任何移动设备上运行吗？

+   如果我没有兼容的设备，还有其他可以尝试的吗？

+   是否可以创建自己的 Kali NetHunter 的自定义版本？

让我们开始吧！

# 小型计算机

最初，Kali Linux 渗透测试平台是一种操作系统，可以安装在计算机的本地硬盘驱动器（HDD）上，或者从光盘（如数字多用途光盘（DVD））上进行现场引导。多年来，Kali Linux 的开发扩展到了更新和更现代的设备，如智能手机和平板电脑，甚至其他具有高级 RISC 机器（ARM）处理器的设备，如树莓派。

# Gem PDA

与基于安卓的智能手机等现代移动设备相比，Gem PDA 看起来有点“老派”。这款设备结合了智能手机和个人数字助理（PDA）的概念：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/76b74365-19c9-480e-ae94-eaa8bd1c71fd.png)

您可能想知道这款设备适合 Kali Linux 的原因。Gem PDA 支持多重引导功能，可安装最多三个操作系统。

以下是支持的操作系统列表：

+   安卓

+   Debian

+   Kali Linux

+   旗鱼

Gem PDA 的 Kali Linux 镜像可以在[`www.offensive-security.com/kali-linux-arm-images/`](https://www.offensive-security.com/kali-linux-arm-images/)找到。

# 树莓派 2 和 3

树莓派是一款信用卡大小的单板计算机。可以将其视为没有外围设备（如键盘、鼠标和驱动程序）的计算机。但是，CPU、RAM、输入/输出（I/O）模块和网络适配器都集成在一个单板上，使其成为微型计算机：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/0065f430-82d1-4736-bf84-4b1eaa4eb395.jpg)

树莓派 3 型 B+目前是市场上最新的型号，具有以下整体规格：

+   Cortex-A53（ARMv8）64 位 SoC，主频 1.4GHz

+   1GB SDRAM

+   2.4GHz 和 5GHz IEEE 802.11.b/g/n/ac WLAN

+   蓝牙 v4.2

+   通过 USB 2.0 的千兆以太网

+   5V 2.5A 直流电源输入

+   通过以太网供电（PoE）

+   Micro SD 端口（用于操作系统）

# ODROID U2

ODROID U2 是一款超小型微型计算机，比信用卡还小。该设备配备了 Cortex-A9 四核 1.7 GHz 处理器，2 GB RAM，支持通过 Micro HDMI 进行视频输出，用于网络连接的 10/100 Mbps 以太网，使用 MicroSD 进行存储，并需要 5V 2A 电源适配器：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/b0f82b9f-1ab3-4f07-a45c-0e70dc29404a.png)

支持 ARM 的设备列表可以在官方 Kali ARM 文档网站上找到：[`docs.kali.org/category/kali-on-arm`](https://docs.kali.org/category/kali-on-arm)。此外，Kali NetHunter 镜像可以在[`github.com/offensive-security/kali-nethunter/wiki`](https://github.com/offensive-security/kali-nethunter/wiki)找到。

# 移动硬件

选择适合 Kali NetHunter 平台的移动设备并不像看起来那么困难。Offensive Security 团队（[www.offensive-security.com](http://www.offensive-security.com)）为我们创建了自定义镜像，但是也有一个支持设备的列表。最初，Kali NetHunter 是为 Google Nexus 系列设备和 OnePlus 设计的：

+   Nexus 5

+   Nexus 6

+   Nexus 7

+   Nexus 9

+   Nexus 10

+   OnePlus One

Offensive Security 推荐 OnePlus One 作为 Kali NetHunter 平台的首选移动设备。要下载 Nexus 系列和 OnePlus One 设备的官方镜像，请访问[`www.offensive-security.com/kali-linux-nethunter-download/`](https://www.offensive-security.com/kali-linux-nethunter-download/)。

你可能会认为首选设备的数量有很大的限制；幸运的是，还有一个额外的支持设备列表：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/8a411ebf-6b64-46ab-8f3e-6e6e829fa84f.png)

如果你使用的设备在上表中列出，你需要为你的设备构建一个自定义版本的 Kali NetHunter。要做到这一点，请参考第一章中的*构建 Kali NetHunter*部分，即《Kali NetHunter 简介》。如果需要更多信息，请参考官方文档：[`github.com/offensive-security/kali-nethunter/wiki/Building-Nethunter`](https://github.com/offensive-security/kali-nethunter/wiki/Building-Nethunter)。

以下是根据它们的代号和 Android 版本给出的支持的 Android 设备列表：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/2da2bef5-9803-460a-9e88-b67380566a58.png)

# 外部组件

在本节中，我们将讨论对使用 Kali NetHunter 模拟对目标的攻击的渗透测试人员有用的外部组件。

# 无线适配器

作为渗透测试人员，一个必不可少的硬件是一个外部无线适配器，用于对目标网络执行各种无线攻击。以下是与 Kali NetHunter 内核兼容的支持的无线适配器列表：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/b80c23de-3ec5-40ac-a70c-3d229d0e29eb.png)

一些适配器可能由于各种原因无法工作，比如不兼容的内核和驱动程序 - 适配器可能无法从 Android 设备获得足够的电源；在这种情况下，建议使用带有外部电源的 Y 型电缆。

# OTG 电缆

此外，在使用 Kali NetHunter 时，**on-the-go**（**OTG**）电缆应该是你的组件清单的一部分。OTG 电缆将允许 USB 设备，如外部无线适配器，与 NetHunter 接口。

以下是带有 RT5370 迷你 USB WiFi 适配器的 OTG 电缆的图像：

![image](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/hsn-pentest-kali-nthtr/img/bb46fd9a-b1da-4751-83cd-26cfebab94e6.jpg)

# 总结

在本章中，我们看了一些支持 Kali Linux 操作系统的微型计算机。这些设备可以让渗透测试人员为目标网络创建自己的网络植入物。在审查编译特定设备的自定义 Kali NetHunter 镜像的方法时，我们涵盖了支持的移动设备列表。最后，渗透测试离不开无线网络适配器，因此提供了已知支持的移动设备的无线适配器列表。

希望本章和本书对你的学习有所帮助，并将在你的网络安全之路上受益。谢谢你的关注！
