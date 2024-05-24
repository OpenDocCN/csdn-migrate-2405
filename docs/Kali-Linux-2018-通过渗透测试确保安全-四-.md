# Kali Linux 2018：通过渗透测试确保安全（四）

> 原文：[`annas-archive.org/md5/9DD5BABA897F5FE8AD4CCDC0C9A2594A`](https://annas-archive.org/md5/9DD5BABA897F5FE8AD4CCDC0C9A2594A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：使用 Kali NetHunter 进行移动渗透测试

Kali NetHunter 专门设计用于在 Android 移动平台上运行，为渗透测试人员提供了更大的灵活性和移动性。

Kali NetHunter 具有我们讨论过的许多工具，以及一些额外的工具，可以进行更多的移动渗透测试。在本章中，我们将讨论安装 Kali NetHunter 以及如何使用关键工具。最后，将讨论 NetHunter 平台在某些用例中相比尝试使用更传统的 Kali Linux 方法具有显著优势的情况。

在本章中，我们将讨论以下内容：

+   Kali Linux NetHunter 概述

+   部署 NetHunter

+   安装 NetHunter 的一般概述

+   工具和技术

+   无线攻击

+   人机界面设备攻击

# 技术要求

在本章中，OnePlus One 和 Nexus 4 设备都用于运行 NetHunter。兼容设备的完整列表可在[`github.com/offensive-security/kali-nethunter/wiki`](https://github.com/offensive-security/kali-nethunter/wiki)上找到。

# Kali NetHunter

NetHunter 是建立在开源 Android 平台上的第一个移动渗透测试操作系统。这是 Offensive Security 和 Kali 社区成员 Binky Bear 之间的合作开发。NetHunter 可以安装在以下 Google Nexus 设备上：Nexus 5、Nexus 6、Nexus 7、Nexus 9、Nexus 10 和 OnePlus One。兼容设备的完整列表可在[`github.com/offensive-security/kali-nethunter/wiki`](https://github.com/offensive-security/kali-nethunter/wiki)上找到。Offensive Security 提供了基于设备和制造年份的多个 NetHunter 镜像。

# 部署

由于其大小，NetHunter 可以以三种一般方式部署。这些部署策略利用了 NetHunter 平台内的工具以及可以轻松获取的额外硬件。这些部署策略允许渗透测试人员测试各种环境中发现的广泛的安全措施。

# 网络部署

前面大部分章节都致力于介绍渗透测试人员用于测试远程或本地网络的工具和技术。这些工具需要通过物理连接访问这些网络。NetHunter 也具有相同的能力。利用 USB Android 适配器和 USB 以太网适配器的组合，渗透测试人员可以直接连接到墙壁插座，或者如果他们能够获得网络硬件的访问权限，可以直接连接到交换机。

这种部署策略适用于那些希望秘密进入区域而不想携带笔记本电脑的测试人员。使用 Nexus 智能手机甚至小型平板电脑，渗透测试人员可以连接到物理网络，入侵本地系统并在那里设置持久性，然后继续前进。在测试公共可用网络插孔周围的安全性时，这种方法也很有用。

# 无线部署

NetHunter 在一个便携包中包含了许多相同的工具。在某些渗透测试中，使用平板电脑或智能手机测试平台而不是笔记本电脑，可以更轻松地在大型校园周围移动，识别网络并捕获无线流量以供以后破解。

要以这种方式部署 NetHunter，需要使用外部天线和 USB 到 Android 适配器。一旦连接，这些硬件工具允许充分使用 NetHunter 的无线工具。

# 主机部署

NetHunter 平台相对于 Kali Linux 平台的一个优势是在 Android OS 中找到的本机 USB 支持。这使得渗透测试人员能够将 NetHunter 平台直接连接到诸如笔记本电脑和台式机之类的主机。这种能力允许渗透测试人员利用执行人机界面设备攻击的工具。在这些攻击中，渗透测试人员能够利用允许连接到主机设备并模拟所谓的**人机界面设备**（**HID**）的工具。HID 是诸如键盘和鼠标之类的设备，通过 USB 连接到主机。

HID 攻击利用这一特性，强制主机系统执行命令或直接下载有效负载脚本到系统。这种攻击更难阻止的原因在于，即使数据丢失预防控制不允许连接 USB 存储设备，HID 设备也是允许的。

# 安装 Kali NetHunter

一般来说，安装 NetHunter 的过程包括对设备进行 root、将其恢复到出厂镜像，然后将 Kali NetHunter 镜像刷入设备。您应该给自己一个小时来完成整个过程。这里提供的是一个概述，让您有一个很好的起点来收集必要的工具和镜像。

以下是您 root 设备、放置恢复镜像和最后安装 NetHunter 镜像所需的一些资源：

+   在本地系统上安装 Android SDK 工具集。可在[`developer.android.com/studio/index.html`](https://developer.android.com/studio/index.html)上找到。

+   TWRP 恢复镜像将在这个过程中使用；您可以在[`twrp.me`](https://twrp.me)上找到它。 [](https://twrp.me)

+   要从 Windows 对设备进行 root，您将需要特定的 root 工具包。Nexus root 信息可在[`www.wugfresh.com/nrt/`](http://www.wugfresh.com/nrt/)上找到，Oneplus Bacon Root Toolkit 可在[`www.wugfresh.com/brt/`](http://www.wugfresh.com/brt/)上找到。有关使用 Windows 机器安装 NetHunter 的指南可在[`github.com/offensive-security/kali-nethunter/wiki/Windows-install`](https://github.com/offensive-security/kali-nethunter/wiki/Windows-install)上找到。

+   NetHunter 镜像可在[`www.offensive-security.com/kali-linux-nethunter-download/`](https://www.offensive-security.com/kali-linux-nethunter-download/)上找到。

确保您按照正确的顺序仔细遵循说明。在这个过程中不要着急。

# NetHunter 图标

一旦 NetHunter 安装在您的设备上，作为镜像的一部分安装了两个图标。您将在应用程序菜单中找到它们。您将会广泛使用这些图标，所以我建议您将它们移动到顶层屏幕。第一个图标是 Kali NetHunter 菜单。该菜单包括在渗透测试中常用的配置设置和工具。首先，点击 NetHunter 图标：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/96471e97-baa3-4583-b79b-14c15394907f.png)

您将被带到一个主屏幕，上面有一系列工具，以及一些配置设置菜单。我们现在要检查的菜单是 Kali Services 菜单。该菜单允许您配置 NetHunter 上可用的不同服务，而无需使用命令行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/5b49e14e-0a6b-4170-bbc1-ef049bc3d94f.png)

在这个菜单中，您可以配置许多服务在启动时启动，或根据您的具体要求切换开关。我们在其他章节中介绍过的两个特定服务包括 Apache Web 服务器和 Metasploit 服务。这两个服务都可以从这个菜单中启动：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/94852bbb-ed2d-47e4-8a68-483157ece7cc.png)

除了菜单选项之外，NetHunter 还有一个用于访问命令行的图标。要访问终端，请点击 NetHunter 终端：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/f8c748fe-b808-4537-ad1e-961ff0156751.png)

然后将打开命令提示符，看起来与我们在之前章节中看到的标准界面相同：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/de7cfd46-6aba-451b-bd93-e35d1c2baf60.png)

右上角的三个垂直点将允许您访问选项，这些选项允许您使用特殊键，访问帮助菜单，并设置您的首选项，以及其他选项。此外，Kali NetHunter 预先配置了 Hacker's Keyboard。导航到平板菜单中的应用程序页面。您将找到 Hacker's Keyboard 的图标。这个键盘更加用户友好，在使用命令行时非常有用。

# NetHunter 工具

由于它基于 Kali Linux 操作系统，我们在之前章节中探讨过的许多工具都是 NetHunter 平台的一部分。因此，在渗透测试期间可以使用相同的命令和技术。在接下来的部分中，我们将讨论两个在渗透测试中最常用的工具，并检查一些可以成为个人 NetHunter 平台一部分的其他工具。

# Nmap

其中一个最常用的工具是 Nmap，我们已经详细介绍过。虽然您可以在 NetHunter 中使用与 Kali Linux 相同功能的命令行运行 Nmap，但 NetHunter Nmap 界面减少了输入这些命令所需的工作量。要进入 NMAP，点击 NetHunter 图标，然后导航到 Nmap。在这里，我们有一个界面，允许我们输入单个 IP 地址、范围或 CIDR 表示法。在这种情况下，我们将使用一个路由器的单个 IP 地址：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/abb9cbb2-cf70-482a-b210-44be392d74d5.png)

NetHunter 界面允许您设置 NMAP 扫描类型、操作系统检测、服务检测和 IPv6 支持。还可以设置特定的端口扫描选项。渗透测试人员可以根据自己的规格设置扫描，或选择 NMAP 应用程序选项来限制他们的端口扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/f2854514-91e3-436b-bf56-5ce172d92e83.png)

通过点击选择时间模板，可以设置扫描时间。与 NMAP 的命令行版本一样，扫描的时间可以根据情况进行调整。最后，还可以设置扫描类型。点击选择扫描技术将显示可用的扫描类型选项。这包括 SYN 或 TCP 扫描等选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/9e74cead-3a83-480d-9e71-409c152a9268.png)

配置好扫描后，点击扫描按钮。NetHunter 将打开一个命令窗口并运行扫描：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/92bc430b-3e5d-4dad-8964-9eca6bd52a65.png)

NetHunter 附带的 GUI 非常适合运行简单的扫描。对于更详细的扫描或使用脚本，您将需要切换到 NMAP 的命令行版本。

# Metasploit

在之前的章节中，我们讨论过许多强大的渗透测试工具之一是 Metasploit。Metasploit 框架包含在 NetHunter 中，并且与 Kali Linux 的功能完全相同。例如，让我们使用 NetHunter 平台尝试利用运行 Metasploitable 的目标系统中的后门漏洞。

首先，我们点击 NetHunter 终端图标，然后输入以下内容：

```
    # msfconsole
```

我们将利用 Metasploitable 中 IRC 守护程序的后门漏洞。因此，我们将使用`unreal_ircd_3281_backdoor`漏洞。我们在命令行中输入以下内容：

```
    msf > use exploit/unix/irc/unreal_ircd_3281_backdoor
```

接下来，我们将远程主机设置为我们的 Metasploitable 机器：

```
    msf >exploit(unreal_ircd_3281_backdoor) >set RHOST 192.168.0.182  
```

最后，我们运行漏洞利用。以下截图显示了前面命令的输出：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/218e5ae8-bd57-4579-871d-fec195655ffc.png)

一旦触发了漏洞利用，我们可以运行`whoami`命令，并将其标识为根命令 shell。正如我们通过这个例子看到的那样，NetHunter 在 Metasploit 框架方面具有与 Kali Linux OS 相同的功能。这使得渗透测试人员可以利用 NetHunter 平台在更小更便携的平台上进行攻击。利用 Metasploit 框架的一个缺点是在平板电脑或手机上输入命令。

就像在 Kali Linux 中一样，NetHunter 还包括用于 Metasploit 的 Msfvenom 有效负载创建器。此 GUI 可用于生成用于 Metasploit 框架的自定义有效负载。要访问此工具，请单击 NetHunter 图标，然后导航到 Metasploit 有效负载生成器。您将被带到以下菜单：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/6f51441f-0ee6-4908-aada-81fb869f5291.png)

从此菜单中，我们拥有与 Kali Linux 版本的 Msfvenom 相同的选项。此外，此 GUI 允许我们创建特定的有效负载并将其保存到 SD 卡以供进一步使用。

NetHunter 中与 Metasploit 一起使用的另一个工具是 Searchsploit。此工具查询[`www.exploit-db.com/`](https://www.exploit-db.com/)上的 Exploit 数据库，并允许用户搜索可与 Metasploit 中的漏洞一起使用的其他漏洞。

# MAC 更改器

在对目标无线网络进行攻击或连接到物理网络的情况下，可能需要更改 NetHunter 平台的 MAC 地址。为了方便起见，NetHunter 预装了 MAC Changer。要访问 MAC Changer，请单击 NetHunter 图标，然后单击 MAC Changer。您将被带到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/fb883575-5a08-496c-a8a2-5e3eb487a422.png)

MAC 更改器允许您将主机名设置为您选择的主机名。将主机名设置为模仿目标组织的命名约定，可以在网络上记录活动的系统存在的情况下掩盖您的活动。此外，MAC 更改器允许您设置 MAC 地址或允许工具为每个接口随机分配 MAC 地址。

# 第三方 Android 应用程序

除了您的 NetHunter 安装外，通过浏览主菜单，您还应该注意到其他六个已安装的 Android 应用程序。

已安装的应用程序是**NetHunter 终端应用程序，DriveDroid，USB 键盘，Shodan，Router Keygen**和**cSploit**。尽管这些第三方应用程序在 NetHunter 文档中被列为正在进行的工作，但我发现它们都可以使用。根据您的移动设备及其硬件，某些应用程序或应用程序中的功能可能无法正常工作。

# NetHunter 终端应用程序

就像 Kali 和 NetHunter 中的终端一样，NetHunter 终端应用程序允许用户在各种类型的终端之间进行选择，包括 Kali 终端、Android 终端和 AndroidSU（root Android）终端：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/609e26bf-a5c5-450f-b3c9-1e18eeee1e32.png)

# DriveDroid

DriveDroid 允许您的 Android 设备模拟可引导的闪存驱动器或 DVD。然后，设备本身可以在从 PC 引导时用作可引导媒体（例如可引导的闪存驱动器）。

DriveDroid 应用程序允许用户在创建可引导的 Android 驱动器时从本地存储或下载的 OS 映像（.iso）中进行选择。DriveDroid 也可以直接从 Google Play 商店下载：[`play.google.com/store/apps/details?id=com.softwarebakery.drivedroid&hl=en`](https://play.google.com/store/apps/details?id=com.softwarebakery.drivedroid&hl=en)。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/d25822b1-6412-4075-9cb4-8ed1d9f1cee5.png)

# USB 键盘

这个功能，正如其名称所示，允许使用 USB 键盘。使用此功能的能力可能取决于所使用的 Android 设备的型号。

# Shodan

Shodan 工具，通常被称为黑客的搜索引擎，也有一个适用于 NetHunter 用户的移动版本。使用 Shodan 应用程序还需要一个 API 密钥，如果您在第四章注册了帐户，您已经被分配了一个 API 密钥，*足迹和信息收集*。访问[`www.shodan.io`](http://www.shodan.io)并登录（或注册）以查看浏览器右上角的 API 密钥。在移动设备上提示时，将 API 密钥输入 Shodan 应用程序中。

一旦您获得并输入了您的代码，您可以像在浏览器中一样使用 Shodan 应用程序：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/4402a6c4-f89c-43ee-9330-d8f6d721f105.png)

# Router Keygen

Router Keygen 是一个为支持 WEP 和 WPA 加密的路由器生成密钥的应用程序。该应用程序首先扫描 Wi-Fi 网络，以确定攻击是否受支持。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/f97fe1c5-cc49-4754-ae0f-8c04dd94a620.png)

点击支持的网络会生成可能用于连接路由器和网络的密钥：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/89d5c1eb-cd0b-4c06-9be6-7c664d60f76a.png)

Router Keygen 也可以直接从 Google Play 商店下载，网址为[`play.google.com/store/apps/details?id=io.github.routerkeygen&hl=en_US`](https://play.google.com/store/apps/details?id=io.github.routerkeygen&hl=en_US)。

# cSploit

cSploit 应用程序允许轻松进行信息收集、会话劫持和**拒绝服务**（**DoS**）和**中间人**（**MitM**）攻击，只需轻按按钮。启动时，cSploit 首先提示用户选择目标网络。然后用户将看到几个模块，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/4fe39d02-f51e-412e-8c9b-889e3c0ab99f.png)

考虑到所有模块都可以从移动设备运行，并且可以在渗透测试人员的身上隐藏或在攻击进行时轻松隐藏，这个工具相当令人印象深刻，只要电池还能用。

# 无线攻击

使用 NetHunter 平台的一个明显优势是其体积和隐蔽性。如果您被要求测试一个站点的无线安全性，同时又想保持一定的隐蔽性，这是一个有用的优势。坐在目标位置的大厅里，打开笔记本电脑并连接外部天线可能会引起一些不必要的注意。相反，将 NetHunter 部署在 Nexus 5 手机上，并将离散的外部天线隐藏在报纸或日程安排后面，是保持低调的更好方式。NetHunter 平台在进行无线渗透测试时的另一个关键优势是能够覆盖更广泛的区域，比如校园环境，而无需携带大型笔记本电脑。

# 无线扫描

正如在上一章中讨论的那样，识别无线目标网络是无线渗透测试中的关键步骤。NetHunter 平台中包含了可以执行无线扫描和目标识别的工具。还有第三方应用程序，具有用户友好的界面，通常可以收集与可能的目标网络相同或更详细的信息。

NetHunter 包括在第十一章*,* *无线渗透测试*中讨论的 Aircrack-ng 工具套件，并且可以通过命令行以相同的方式工作。在这里，我们将打开一个命令 shell 并输入`airoddump-ng`来识别潜在的目标网络：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/54dada2f-d77f-4130-84f2-14201ba8156a.png)

就像在 Kali Linux 操作系统中一样，我们能够确定 BSSID、信道和正在广播的 SSID。

# WPA/WPA2 破解

正如我们之前讨论的，Aircrack-ng 套件工具在 NetHunter 中也包含了我们在第十一章中讨论过的工具。这使我们能够执行相同的攻击，而无需修改命令或技术。此外，我们可以利用在[第十一章](https://cdp.packtpub.com/kali_linux_assuring_security_by_penetration_testing__fourth_edition/wp-admin/post.php?post=377&action=edit#post_343)中使用的相同天线，以及外部适配器。以下破解是针对我们在[第十一章](https://cdp.packtpub.com/kali_linux_assuring_security_by_penetration_testing__fourth_edition/wp-admin/post.php?post=377&action=edit#post_343)中讨论过的相同访问点和相同的 BSSID 进行的。所有这些都是通过 NetHunter 命令行完成的。

在下面的截图中，我们看到了`#airodump-ng -c 6 --bssid -w NetHunter`命令的输出：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/8f84ff58-f389-4ecd-8e81-9a8f0e11a99b.png)

Aircrack-ng 能够像 Kali Linux 版本一样抓取四路握手。正如我们在[第十一章](https://cdp.packtpub.com/kali_linux_assuring_security_by_penetration_testing__fourth_edition/wp-admin/post.php?post=377&action=edit#post_343)中讨论的那样，我们可以使用预配置的列表来反向获取密码。为了演示目的，预配置的列表很短。

`#aircrack-ng -w wifipasscode.txt -b 44:94:FC:37:10:6E NetHunter-01.cap`命令产生了以下输出：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/f8059557-81b7-471e-a80f-c069606a7198.png)

使用 NetHunter 键盘可能会在破解目标网络的密码方面有点乏味，但是可以做到。此外，这种攻击在需要坐在笔记本电脑和外部天线旁引起不必要注意的情况下是有用的。另一个有用的技术是使用 NetHunter 平台来扫描和捕获握手，然后将捕获文件传输到您的 Kali Linux 平台并在那里运行破解程序。这产生了相同的结果，同时给渗透测试人员保持隐身的能力。

# WPS 破解

在 NetHunter 键盘上输入命令可能会有点令人沮丧，NetHunter 还使用了我们在[第十一章](https://cdp.packtpub.com/kali_linux_assuring_security_by_penetration_testing__fourth_edition/wp-admin/post.php?post=377&action=edit#post_343)中讨论过的 Wifite 工具。这个工具允许我们通过简单输入一个数字来进行攻击。打开 Kali 命令 shell，输入`wifite`命令，然后按 Enter。这将产生以下输出：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/c782b594-b89e-405c-ba41-3846062f427f.png)

正如我们所看到的，NetHunter 的输出有一些细微的差异。有两个 WLAN 接口：内部无线接口和我们自己的外部天线。还有`P2P0`接口。这是 Android 操作系统的对等无线接口。然后我们通过输入数字`3`将我们的 WLAN1 接口设置为监视模式。

这产生了以下输出：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/8e9afa46-c059-4ce7-925d-0170f144a74c.png)

就像我们在[第十一章](https://cdp.packtpub.com/kali_linux_assuring_security_by_penetration_testing__fourth_edition/wp-admin/post.php?post=377&action=edit#post_343)中看到的那样，我们看到了我们之前测试过的相同网络。在我们停止扫描并输入数字`15`然后*Enter*之后，Wifite 运行了与之前相同的攻击：

！[](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/4f6ff15d-e07e-4383-afbf-dee9a1126c71.png)

从前面的截图中，我们可以看到我们已经为无线网络 Brenner 找到了相同的 WPA 和 PIN。

# 恶意 AP 攻击

**邪恶接入点**（evil AP）攻击是一种无线 MitM 攻击。在这种攻击中，我们试图让目标设备连接到我们设置的伪装成合法接入点的无线接入点。我们的目标认为这是一个合法的网络，因此连接到它。客户端的流量在转发到下游的合法接入点时被嗅探。来自合法接入点的任何流量也会通过我们设置的 AP 路由，再次我们有能力嗅探该流量。

以下图表说明了这种攻击。左边是我们目标的笔记本电脑。中间是我们的 NetHunter 平台。右边是一个连接到互联网的合法接入点。当目标连接到我们的 NetHunter 平台时，我们能够在转发到合法接入点之前嗅探流量。来自接入点的任何流量也会被嗅探，然后转发到客户端：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/38679e0c-2c1b-4109-9135-2c43e17adefa.png)

这只是我们过去讨论过的 MitM 攻击的一个变体。与以往不同的是，我们不需要了解客户端或他们所在网络的任何信息，因为我们将控制他们使用的网络。这是一种经常发生在使用免费无线互联网的公共区域的攻击，例如机场、咖啡店和酒店。

# Mana 邪恶 AP

在 NetHunter 平台中我们将使用的工具是**Mana Wireless Toolkit**。从 NetHunter 图标导航到 Mana Wireless Toolkit。您将被带到的第一页是`hostapd-karma.conf`屏幕。

这使我们能够配置我们的邪恶 AP 无线接入点：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/1f94fd6f-5ad2-4c6c-acb6-f1f5e97607aa.png)

首先要考虑的是您需要确保有两个可用的无线接口。Android 的无线接口，很可能是 WLAN0，需要连接到具有互联网连接的接入点。这可以由您控制，或者只是我们位置上可用的免费无线互联网。WLAN1 接口将是我们的外部天线，它将提供虚假接入点。接下来，您可以将 BSSID 配置为模仿实际接入点的 MAC 地址。此外，我们还可以配置 SSID 来广播任何接入点的标识。其他设置涉及使用 Karma 漏洞进行攻击。这是对邪恶 AP 的变体。（有关更多信息，请参见[`insights.sei.cmu.edu/cert/2015/08/instant-karma-might-still-get-you.html.`](https://insights.sei.cmu.edu/cert/2015/08/instant-karma-might-still-get-you.html.)）我们可以将这些设置保持为默认值。在这种情况下，我们将保持默认设置，导航到三个垂直点并点击开始 mana。

这将启动虚假接入点：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/73419b43-828c-4e42-84c6-e3e6fb420aed.png)

在上一张截图中，我们可以看到 Mana 邪恶 AP 清除缓存信息并设置新的接入点。如果我们切换到设备，我们可以看到无线接入点 Free_Internet。此外，我们能够无需任何身份验证即可连接：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/f54dee87-5e00-4c40-b369-79fd1a3f6c85.png)

现在，在 NetHunter 平台上的另一个终端上，我们通过使用以下命令配置`tcpdump`捕获来配置我们的数据包捕获：

```
    # tcpdump -I wlan1
```

这产生了以下结果：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/fec682b0-1e06-4ab1-be6e-efba7626927e.png)

作为连接的设备接收和发送帧时，我们能够嗅探该流量。另一个可用的选项是以`.pcap`文件的形式捕获流量，然后将其卸载以在 Wireshark 中查看。

这是在目标组织的公共区域的有用攻击。这次攻击的另一个关键方面是，多个目标设备可以连接。但需要注意的是，如果有多个设备连接，可能会导致流量传输到目标的速度明显变慢。还有一种可以利用这个工具和一些移动设备中发现的漏洞的技术。许多移动设备会自动配置为连接到以前连接过的任何网络。这种自动连接不会查看无线接入点的 MAC 地址，而是正在广播的 SSID。在这种情况下，我们可以将我们的 Mana 邪恶 AP 称为常见的位置 SSID。当人们经过时，他们的移动设备将自动连接，并且只要它们在范围内，它们就会通过我们的设备路由其流量。

# HID 攻击

NetHunter 有几个内置工具，允许您配置 HID 攻击。在这些工具中，NetHunter 利用标准命令行来执行一系列命令。要访问 HID 攻击菜单，请单击 NetHunter，然后单击 HID Attacks。在 HID Attacks 屏幕上，我们将看到两个选项。一个是 PowerSploit 攻击，另一个是 Windows CMD 攻击。在本节中，我们将详细介绍 Windows CMD 攻击。

在这种情况下，我们将使用 NetHunter 平台并将其连接到目标机器。我们的攻击将利用 HID 漏洞来运行`ipconfig`命令，并使用`net user offsec NetHunter! / add`命令将用户`offsec`添加到系统中。

最后，我们将使用`net localgroup administrators offsec /add`命令将该用户帐户添加到本地管理员组中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/44760a39-a9dd-4d4a-a426-694eea22ef5a.png)

接下来，我们需要设置**用户帐户控制**（**UAC**）绕过。这允许 NetHunter 以管理员身份运行命令行。单击 UAC Bypass 以为适当的 Windows OS 进行配置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/eb68834f-70bb-4c59-855f-94ba7da8164b.png)

在这种情况下，我们正在尝试针对 Windows 10 OS 的 HID 攻击，因此我们将 UAC Bypass 设置为 Windows 10：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/96f649fb-69a7-49e2-8241-0f849241faaa.png)

在配置 UAC Bypass 后，将 USB 电缆插入目标机器。单击三个垂直点，然后单击执行攻击。

随着攻击的开始执行，您将看到目标机器正在打开命令提示符作为管理员的过程。然后执行在 NetHunter 中设置的命令。在这里，我们看到第一个命令`ipconfig`已经运行：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/fcccd6b5-5f8a-4243-892c-0046cc932ec3.png)

接下来，我们看到`offsec`用户已输入相关密码。用户帐户现已输入到目标计算机上的本地管理员组中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/fe042a8b-9736-4de0-8bd9-e23aa334cb47.png)

如果您身处某个位置并观察到开放的工作站，则此攻击非常有用。您可以配置多种不同的命令，然后简单地将您的 NetHunter 平台连接到系统并执行。这可能包括使用 PowerShell 或其他脚本攻击的更复杂的攻击。

# DuckHunter HID 攻击

DuckHunter HID 攻击将 USB Rubber Ducky 脚本转换为 NetHunter HID 攻击，如前所述。可以从 Hak5 的 Darren Kitchen 的 GitHub 页面[`github.com/hak5darren`](https://github.com/hak5darren)下载 USB Rubber Ducky 脚本，并加载到 Convert 选项卡中的 NetHunter HID 工具中。

有效载荷包括（但绝对不限于）以下内容：

+   WiFi 密钥抓取器

+   具有持久性的反向 Shell

+   从活动文件系统中检索 SAM 和 SYSYTEM

+   Netcat 反向 Shell

+   OSX 本地 DNS 中毒

+   批量擦除/驱动擦除

+   Wifi 后门

# 总结

Kali NetHunter 平台在其体积方面具有很多功能。对于渗透测试人员来说，最明显的优势是，工具和技术基本上与 Kali Linux 和 NetHunter 相同，这减少了学习新工具集所需的时间，同时使渗透测试人员能够从手机或平板电脑上运行渗透测试。这使测试人员能够更接近目标组织，同时也能够模糊其一些行动。添加 HID 等攻击进一步使渗透测试人员能够执行其他工具无法完成的攻击。NetHunter 是一个非常好的平台，可以加入到您的渗透测试工具包中。

在下一章中，我们将继续讨论**PCI DSS**（**Payment Card Industry Data Security Standard**）并讨论范围、调度、分割以及执行 PCI DSS 扫描的各种工具。

# 问题

+   哪些版本的 OnePlus 和 Nexus 手机支持 Kali NetHunter？

+   NetHunter 在移动设备上需要 root 访问权限吗？

+   NetHunter 包括哪些第三方安卓应用程序？

+   Router Keygen 支持哪些类型的无线加密？

+   cSploit 应用程序的一些特点是什么？

+   MitM 无线攻击工具的名称是什么？

+   DuckHunter HID 攻击是什么？

# 进一步阅读

+   NetHunter 文档：[`github.com/offensive-security/kali-nethunter/wiki`](https://github.com/offensive-security/kali-nethunter/wiki)

+   在安卓设备上安装 NetHunter：[`www.androidauthority.com/how-to-install-kali-nethunter-android-896887/`](https://www.androidauthority.com/how-to-install-kali-nethunter-android-896887/)

+   使用 NetHunter 进行 DNS 欺骗：[`cyberarms.wordpress.com/category/nethunter-tutorial/`](https://cyberarms.wordpress.com/category/nethunter-tutorial/)


# 第十三章：PCI DSS 扫描和渗透测试

支付卡行业数据安全标准（PCI DSS）成立于 2006 年，由包括万事达卡、Discover、Visa、美国运通和 JCB 国际在内的几家领先的信用卡公司联合创办。PCI DSS（当前版本为 3.2.1）适用于所有接受、处理、传输和存储信用卡信息及相关细节的机构、商家和企业。该标准的目的仍然是保护商家、服务提供商和消费者免受与信用卡和相关个人可识别信息（PII）的数据安全违规相关的财务和商誉损失。

根据 PCI DSS，持卡人数据包括：

+   持卡人的姓名

+   持卡人的帐号

+   持卡人的服务代码

+   卡的到期日期

敏感数据还包括个人识别号码（PIN）和磁条或芯片上的数据。

PCI DSS 包括 6 个目标和 12 个要求。所有 6 个目标和 12 个要求都可以通过深入评估来实现，以验证已采取措施积极确保持卡人信息的保护。尽管满足 6 个目标和 12 个成就听起来可能很简单，但实际上有 250 个 PCI 子要求。

根据万事达卡，PCI DSS 的六个目标如下：

+   建立和维护安全的网络和系统

+   持卡人数据的保护

+   维护漏洞管理计划

+   实施强大的访问控制措施

+   定期监控和测试网络

+   维护信息安全政策

处理的持卡人交易量决定了公司需要完成的评估类型。一些公司，如 Discover 卡的 Discover Global Network，要求所有使用 Discover 网络处理、传输或存储持卡人数据的商家都符合 PCI 标准。

信用卡机构有各种级别和类别，用于确定合规要求，如下一节所列。这些标准在不同机构之间有所不同，尽管要求对所有机构都是相同的。

+   **级别 1**：必须提交一份年度现场安全评估报告，详细说明处理、存储或传输信用卡信息的评估系统。还需要进行季度网络扫描，必须由批准的扫描供应商（ASV）进行，以远程扫描漏洞和潜在威胁。

+   美国运通年交易量：2.5 百万（或更多）

+   万事达卡年交易量：6 百万或更多

+   **级别 2**：50,000-2.5 百万。需要进行年度自我评估，以及季度网络扫描。商家也可以根据自己的意愿提供现场评估。

+   美国运通年交易量：少于 50,000

+   万事达卡年交易量：1 至 6 百万之间

+   **级别 3**：需要进行年度自我评估，以及季度网络扫描。商家也可以根据自己的意愿提供现场评估。

+   美国运通年交易量：少于 50,000

+   万事达卡年交易量：超过 20,000，但少于 100 万

额外级别：

+   **级别 EMV（美国运通）**：处理超过 50,000 笔芯片启用卡交易需要进行年度 EMV Attestation（AEA）自我检查。

+   **级别 4（万事达卡）**：需要进行年度自我评估，以及季度网络扫描。商家也可以根据自己的意愿提供现场评估。

# PCI DSS v3.2.1 要求 11.3

在本章的前面，我提到 PCI DSS 包括 6 个目标和 12 个要求。官方的 PCI DSS v3.2.1 快速参考指南提供了所有 12 个要求的摘要，可以在[`www.pcisecuritystandards.org/documents/PCI_DSS-QRG-v3_2_1.pdf?agreement=true&time=1535479943356`](https://www.pcisecuritystandards.org/documents/PCI_DSS-QRG-v3_2_1.pdf?agreement=true&time=1535479943356)下载。在本节中，我们关注 PCI DSS 评估的渗透测试元素，这属于*要求 11：定期测试安全系统和流程*，属于*目标 5：定期监控和测试网络*。

要求 11.3 基于实施渗透测试方法，如建议的*NIST SP800-115 信息安全测试和评估技术指南*。尽管 NIST SP800-115 是在 2008 年发布的，但它提供了经过验证的技术和最佳实践，用于范围界定和执行渗透测试，并且在考虑或创建渗透测试方法时应作为指南使用。

要求 11.3.1 侧重于进行外部渗透测试。这应该每年进行一次，或在组织内进行任何有影响力和重大的升级后进行，例如服务器升级、骨干应用程序、交换机、路由器、防火墙、云迁移，甚至环境中操作系统的升级。外部渗透测试应由合格和有经验的人员或第三方进行。

要求 11.3.2 侧重于内部渗透测试。与要求 11.3.1 一样，内部渗透测试应每年进行一次，并由合格和有经验的个人或第三方进行。

要求 11.3.3 更多地是作为分析性要求而不是技术要求，因为它涉及对内部和外部渗透测试的分析，以确保消除所揭示的漏洞和利用。

要求 11.4 定义了方法论范围内的分割。在确定评估范围时（我们将在下一节中看到），强烈建议采取措施来减少范围本身，因为并非网络或 CDE 中的每个系统都需要进行评估。可以使用防火墙和路由器中的访问控制列表配置来进行这种类型的网络隔离。

# PCI DSS 渗透测试的范围

在进行任何类型的渗透测试之前，渗透测试人员需要与客户合作，以确保获得所有适当的信息。在目标范围界定阶段，渗透测试人员将从客户那里收集信息，用于生成目标评估要求，定义测试的参数，以及客户的业务目标和时间表。这个过程在定义任何类型的安全评估的明确目标方面起着重要作用。通过确定这些关键目标，您可以轻松地绘制出将要测试的内容、如何测试、将分配哪些资源、将应用哪些限制、将实现哪些业务目标以及测试项目将如何计划和安排的实际路线图。所有这些信息最终都在一个测试计划中明确说明测试的范围。

我们可以将所有这些元素结合起来，并以正式的范围流程呈现，以实现所需的目标。以下是本章将讨论的关键概念：

+   **收集客户需求**：这涉及通过口头或书面沟通积累有关目标环境的信息。

+   **准备测试计划**：这取决于不同的变量集。这些变量可能包括将实际要求塑造成结构化的测试过程、法律协议、成本分析和资源分配。

+   **确定测试边界**：这确定了与渗透测试任务相关的限制。这些可能是技术、知识的限制，或者是客户 IT 环境的正式限制。

+   **定义业务目标**：这是一个将业务观点与渗透测试计划的技术目标对齐的过程。

+   **项目管理和安排**：这指导了渗透测试过程的每一步，为测试执行制定了适当的时间表。可以使用多种先进的项目管理工具来实现这一目标。

强烈建议您遵循范围界定过程，以确保测试的一致性和更大的成功概率。此外，该过程还可以根据特定情况和测试因素进行调整。如果没有这样的过程，失败的可能性会更大，因为收集到的要求没有适当的定义和程序可供遵循。这可能会使整个渗透测试项目面临风险，并可能导致意外的业务中断。在这个阶段，特别关注渗透测试过程将对测试的其他阶段和技术管理领域的观点有很好的贡献。关键是尽可能多地从客户那里获取信息，以制定反映渗透测试多个方面的战略路径。这些可能包括可协商的法律条款、合同协议、资源分配、测试限制、核心能力、基础设施信息、时间表和参与规则。作为最佳实践的一部分，范围界定过程解决了启动我们的渗透测试项目所必需的每个属性。

每个步骤都包含独特的信息，按照逻辑顺序进行，以成功进行测试执行。这也管理着在早期阶段需要解决的任何法律问题。因此，我们将在下一节更详细地解释每个步骤。请记住，如果所有收集到的信息都以有组织的方式进行管理，对于客户和渗透测试顾问来说，更容易进一步理解测试过程。

# 收集客户需求

这一步提供了一个通用的指南，可以以问卷的形式绘制，以便从客户那里获取有关目标基础设施的所有信息。客户可以是任何与目标组织有法律和商业约束关系的主体。因此，为了成功进行渗透测试项目，关键是在项目的早期阶段识别所有内部和外部利益相关者，并分析他们的利益水平、期望、重要性和影响力。然后可以制定策略，以满足每个利益相关者的需求和参与渗透测试项目，以最大化积极影响并减轻潜在的负面影响。

渗透测试人员有责任在进一步采取任何行动之前验证合同方的身份。

收集客户需求的基本目的是打开一个真实和真实的渠道，通过这个渠道，渗透测试人员可以获取可能对测试过程有必要的任何信息。一旦确定了测试需求，客户应验证这些需求，以消除任何误导性信息。这将确保未来的测试计划是一致和完整的。

# 创建客户需求表

我们列出了一些常见的问题和考虑因素，这些可以作为创建传统客户需求表的基础。需要注意的是，根据客户的目标，这个清单可以扩展或缩短：

+   收集基本信息，如公司名称、地址、网站、联系人详细信息、电子邮件地址和电话号码

+   确定渗透测试项目背后的关键目标

+   确定渗透测试类型（是否具有特定标准）：

+   黑盒测试

+   白盒测试

+   外部测试

+   内部测试

+   包括社会工程

+   排除社会工程

+   调查员工背景信息

+   采用员工的假身份（可能需要法律顾问）

+   包括拒绝服务

+   排除拒绝服务

+   渗透业务合作伙伴系统：

+   需要测试多少台服务器、工作站和网络设备？

+   您的基础设施支持哪些操作系统技术？

+   哪些网络设备需要进行测试？防火墙、路由器、交换机、负载均衡器、IDS、IPS 或其他设备？

+   是否有灾难恢复计划？如果有，我们应该联系谁？

+   目前是否有管理员管理您的网络？

+   是否有遵守行业标准的特定要求？如果有，请列出。

+   谁将成为这个项目的联系人？

+   为这个项目分配了多少时间？

+   您对这个项目的预算是多少？

+   列出任何其他必要的杂项要求。

# 准备测试计划

一旦客户收集并验证了要求，就是时候制定一个正式的测试计划，该计划应反映所有这些要求，以及关于测试过程的法律和商业基础的其他必要信息。准备测试计划涉及的关键变量包括结构化测试流程、资源分配、成本分析、保密协议、渗透测试合同和参与规则。每个领域都有简短的描述，如下所示：

+   **结构化测试流程**：在分析客户提供的细节后，重构测试方法可能很重要。例如，如果社会工程服务即将被排除，您需要将其从正式测试流程中删除。有时，这种做法被称为**测试流程验证**。这是一个需要反复访问的任务，每当客户需求发生变化时都需要重新访问。如果在测试执行过程中涉及任何不必要的步骤，可能会违反组织的政策并造成严重处罚。此外，根据测试类型，测试流程可能会有一些变化。例如，白盒测试可能不需要信息收集和目标发现阶段，因为测试人员已经了解内部基础设施。

无论测试类型如何，验证网络和环境数据可能都是有用的。毕竟，客户可能不知道他们的网络真正是什么样子！

+   **资源分配**：确定实现测试完整性所需的专业知识是最重要的领域之一。因此，将适当技能的渗透测试人员分配到特定任务可能会导致更好的安全评估。例如，对应用程序进行渗透测试需要具有专业知识的应用程序安全测试人员。这项活动在渗透测试任务的成功中起着重要作用。

+   **成本分析**：渗透测试的成本取决于几个因素。这可能涉及分配时间来完成项目范围的天数、额外的服务要求，如社会工程和物理安全评估，以及评估特定技术所需的专业知识。从行业的角度来看，这应该结合定性和定量价值。

+   **保密协议**（**NDA**）：在开始测试过程之前，有必要签署一份能够反映双方利益的保密协议：客户和渗透测试人员。使用这样一份相互保密协议应该明确测试应该遵循的条款和条件。渗透测试人员应该在整个测试过程中遵守这些条款。违反任何一项协议条款都可能导致严重处罚或永久性排除在工作之外。

+   **渗透测试合同**：总是需要一份法律合同来解决客户和渗透测试人员之间的技术和商业事项。这就是渗透测试合同的用武之地。这类合同中的基本信息集中在提供的测试服务、它们的主要目标、如何进行测试、支付声明以及保持整个项目的保密性。强烈建议您由律师或法律顾问创建此文件，因为它将用于大部分渗透测试活动。

+   **参与规则（ROE）**：渗透测试过程可能具有侵入性，并需要清楚了解评估的要求、客户提供的支持以及每种评估技术可能产生的潜在影响或效果类型。此外，渗透测试过程中使用的工具应明确说明其目的，以便测试人员可以相应地使用它们。ROE 以更详细的方式定义了所有这些陈述，以解决测试执行过程中应遵循的技术标准的必要性。您绝不能越过预先同意的 ROE 设定的界限。

通过准备测试计划的每个子部分，您可以确保对渗透测试过程有一致的视图。这将为渗透测试人员提供更具体的评估细节，这些细节是从客户的要求中得出的。始终建议您准备一份测试计划检查表，用于验证与承包方的评估标准及其基础条款。以下部分讨论了一种这样的示范性检查表。

# 测试计划检查表

在范围过程中采取任何进一步步骤之前，以下是一组问题的示例，应正确回答：

+   在 RFP 期间承诺的所有要求都得到满足了吗？

+   测试范围是否明确定义了？

+   所有测试实体都已经确定了吗？

+   所有非测试实体都已经单独列出了吗？

+   是否有任何特定的测试流程将被遵循？

+   测试过程是否被正确记录了？

+   测试过程完成后是否会产生可交付成果？

+   在测试之前是否已经对整个目标环境进行了研究和记录？

+   所有与测试活动相关的角色和责任都已经分配了吗？

+   是否有第三方承包商来完成特定技术评估？

+   是否已经采取任何步骤将项目优雅地结束？

+   灾难恢复计划已经确定了吗？

+   测试项目的成本已经最终确定了吗？

+   已经确定了谁将批准测试计划吗？

+   已经确定了谁将接受测试结果吗？

# 测试边界的分析

了解测试环境的限制和边界与客户需求息息相关，可以解释为有意或无意的利益。这些可以是技术、知识或客户对基础设施施加的任何其他正式限制的形式。每个施加的限制可能会对测试过程造成严重中断，并可以使用替代方法解决。但是，请注意，某些限制无法修改，因为它们由客户管理以控制渗透测试的过程。我们将讨论每种通用类型的限制及其相关示例如下：

+   **技术限制**：这种限制发生在项目范围得到了正确定义，但网络基础设施中存在新技术阻止审计员进行测试。这只有在审计员没有任何可以协助评估这种新技术的渗透测试工具时才会发生。例如，想象一家公司引入了一个强大的 GZ 网络防火墙设备，它位于边界并用于保护整个内部网络。然而，防火墙内部专有方法的实施阻止了任何防火墙评估工具的工作。因此，总是需要一个能够处理这种新技术评估的最新解决方案。

+   **知识限制**：如果渗透测试人员的技能水平有限，无法测试某些技术，那么渗透测试人员的知识限制可能会产生负面影响。例如，专门的数据库渗透测试人员将无法评估网络基础设施的物理安全。因此，根据渗透测试人员的技能和知识，划分角色和责任是有益的，以实现所需的目标。

+   **其他基础设施限制**：客户可以通过限制评估过程来控制某些测试限制。这可以通过限制 IT 基础设施的视图，仅包括需要评估的特定网络设备和技术来实现。通常，这种限制是在需求收集阶段引入的；例如，在测试给定网络段后面的所有设备，除了第一个路由器。客户施加的这种限制首先不能确保路由器的安全，这可能导致整个网络的妥协，即使所有其他网络设备都经过了加固和安全保证。因此，在对渗透测试施加任何此类限制之前，总是需要进行适当的思考。

对所有这些限制和限制进行概要是重要的，可以在收集客户需求的同时进行。一名优秀的渗透测试人员的职责是剖析每个需求，并与客户进行讨论，以撤销或更改可能导致测试过程中断或在不久的将来导致安全漏洞的任何模糊限制。引入高技能的渗透测试人员和先进的工具和技术也可以克服这些限制，尽管某些技术限制天生无法消除，可能需要额外时间来开发测试解决方案。

# 定义业务目标

根据评估要求和服务的认可，定义业务目标至关重要。这将确保测试输出以多种方式使业务受益。每个业务目标都是根据评估要求专注和结构化的，并且可以清晰地展示行业希望实现的目标。我们已经制定了一些通用的业务目标，可以用于任何渗透测试任务。但是，它们也可以根据需求的变化进行重新设计。这个过程很重要，可能需要渗透测试人员在测试完成之前、期间和之后观察和理解业务动机，同时保持标准的最低水平。业务目标是将管理和技术团队聚集在一起，以支持强有力的主张和保护信息系统的想法的主要方面。根据要进行的不同类型的安全评估，得出了以下常见目标列表：

+   通过定期进行安全检查，提供行业范围内的可见性和认可。

+   通过保证业务完整性，实现必要的标准和合规性。

+   保护持有关于客户、员工和其他业务实体的机密数据的信息系统。

+   列出在网络基础设施中发现的活动威胁和漏洞，并帮助制定应该阻止已知和未知风险的安全政策和程序。

+   提供一个平稳而强大的业务结构，将使其合作伙伴和客户受益。

+   保持维护 IT 基础设施安全的最低成本。安全评估衡量了业务系统的机密性、完整性和可用性。

+   通过消除可能由恶意对手利用而造成更多成本的潜在风险，实现更大的投资回报。

+   详细说明组织的技术团队可以遵循的补救程序，以关闭任何开放的漏洞，从而减少运营负担。

+   遵循行业最佳实践和最佳工具和技术，根据基础技术评估信息系统的安全性。

+   建议应该用于保护业务资产的任何可能的安全解决方案。

# 项目管理和排程

管理渗透测试项目需要对范围过程的所有个体部分有透彻的理解。一旦这些范围目标得到清晰，项目经理可以与渗透测试人员协调，制定一个定义项目计划和时间表的正式大纲。通常情况下，渗透测试人员可以独立完成这项任务，但客户的合作可能会给该时间表的这一部分带来积极的关注。这很重要，因为测试执行需要仔细分配不应超过声明的截止日期的时间范围。一旦确定了适当的资源并分配了执行评估期间某些任务的资源，就有必要绘制一个时间表，描述这些资源在渗透测试过程中的关键角色。

每个任务都被定义为渗透测试人员进行的工作。资源可以是参与安全评估的人员，也可以是实验室设备等普通资源，这些资源对渗透测试有帮助。为了有效和经济地管理这些项目，有许多项目管理工具可供选择，可用于实现我们的任务。我们在下表中列出了一些重要的项目管理工具。选择最佳工具取决于环境和测试标准的规定：

| **项目管理工具** | **网站** |
| --- | --- |
| 微软办公项目专业版 | [`www.microsoft.com/project/`](http://www.microsoft.com/project/) |
| TimeControl | [`www.timecontrol.com/`](http://www.timecontrol.com/) |
| TaskMerlin | [`www.taskmerlin.com/`](http://www.taskmerlin.com/) |
| Project KickStart Pro | [`www.projectkickstart.com/`](http://www.projectkickstart.com/) |
| FastTrack Schedule | [`www.aecsoftware.com/`](http://www.aecsoftware.com/) |
| ProjectLibre | [www.projectlibre.org](http://www.projectlibre.org) |
| TaskJuggler | [`www.taskjuggler.org/`](http://www.taskjuggler.org/) |

使用任何这些强大的工具，渗透测试人员的工作可以轻松地按照其定义的任务和时间段进行跟踪和管理。此外，这些工具还提供其他高级功能，例如在任务完成或截止日期超过时为项目经理生成警报。在渗透测试任务期间使用项目管理工具的许多其他积极因素。这些包括按时交付服务的效率，提高测试生产率和客户满意度，提高工作的质量和数量，以及灵活控制工作的进展。

# 执行 PCI DSS 渗透测试的工具

PCI DSS 规定 ASV 每年进行评估，而合格和有经验的专业人士可以每季度进行自我评估。合格的人员应具有多年的渗透测试经验，并持有以下一项或多项认证：

+   **Certified Ethical Hacker** (**CEH**)

+   **Offensive Security Certified Professional** (**OSCP**)

+   **CREST**渗透测试认证

+   **全球信息保障认证** (**GIAC**)，例如 GPEN，GWAPT 和 GXPN。

PCI DSS 评估专业人员使用的工具可以是商业工具或开源工具，只要它们能够产生高水平的准确性。在本书中，我们使用了许多工具，其中一些不仅执行多个功能，而且以自动化的方式执行，通常在指定了所有 IP 信息之后执行。

在第六章，*漏洞扫描*中，我们看了几种用于执行自动化漏洞评估的工具，包括 Tenable 的 Nessus 的试用版及其用于 PCI DSS 评估和合规性的可用选项。Tenable 也是许多公司之一，可以直接聘请作为独立第三方进行年度 PCI DSS 报告的 PCI ASV 漏洞扫描，具体取决于公司的合规水平和年度交易量。

尽管现在只能通过付费订阅获得，但 Nessus 也可以执行内部和外部 PCI DSS 评估。以下屏幕截图显示了 Nessus 内部 PCI DSS 评估的详细信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/1729167c-d925-4bc9-890c-9d3096417f09.jpg)

为了简化事情，我列出了前几章涵盖的工具列表，这些工具可以帮助您作为 PCI DSS 自我评估的一部分执行漏洞评估和渗透测试。同样，某些工具可能在列表中重复出现，因为它们可能执行多个功能：

+   信息收集（第四章，*足迹和信息收集*）：

1.  Devsploit

1.  Striker

1.  RedHawk

+   扫描（第五章，*扫描和规避技术*）：

1.  Nmap

1.  RedHawk

+   漏洞评估（第六章，*漏洞扫描*）：

1.  OpenVAS

1.  Nessus

1.  Lynis（Linux 系统审计）。

1.  Sparta

+   第七章，*社会工程*：

1.  社会工程工具包

+   利用（第 8-12 章）：

1.  Metasploit

1.  NetHunter

+   报告（第十四章，*渗透测试报告工具*）：

1.  Dradis 框架

当然，还有许多其他工具可用于评估，但这些工具应该足以让您开始。

# Summary

在本章中，我们介绍了**支付卡行业数据安全标准**（**PCI DSS**）及其对必须符合 PCI DSS 的组织的目标和要求。我们还了解了根据每年处理的支付卡交易量所需的不同合规级别。我们还了解了分割的重要性及其对 PCI DSS 评估的影响，然后详细了解了范围界定过程。

在本章的最后，我们了解到只有合格和有经验的专业人员才能被授权进行 PCI DSS 自我评估，还要雇佣 PCI DSS ASV 来执行年度外部 PCI DSS 评估。最后，我们回顾了本书中之前章节中使用的各种工具，这些工具可以用于执行评估。

在下一章中，我们将介绍创建报告并帮助我们整合渗透测试各个方面的工具。

# 问题

1.  哪些公司制定了 PCI DSS 标准？

1.  PCI DSS 的当前版本是什么？

1.  PCI DSS 中有多少个目标和要求？

1.  哪些要求涉及内部和外部 PCI DSS 评估？

1.  ASV 可以进行哪种类型的评估？

1.  ASV 必须多久进行一次外部评估？

1.  分割的目的是什么？

1.  在提到评估的范围方面时，结构化测试过程指的是什么？

1.  专业的渗透测试人员应具备哪些资格？

1.  哪些漏洞评估工具可用于执行 PCI DSS 自我评估？

# 进一步阅读

关于 PCI DSS、评估和与此相关的一般知识，还有更多内容可以了解，请访问以下链接。

+   要求和安全评估程序：[`www.pcisecuritystandards.org/documents/PCI_DSS_v3-2-1.pdf`](https://www.pcisecuritystandards.org/documents/PCI_DSS_v3-2-1.pdf)

+   PCI DSS 快速参考指南：[`www.pcisecuritystandards.org/documents/PCI_DSS-QRG-v3_2_1.pdf?agreement=true&time=1535905197919`](https://www.pcisecuritystandards.org/documents/PCI_DSS-QRG-v3_2_1.pdf?agreement=true&time=1535905197919)

+   PCI DSS 合规性报告模板：[`www.pcisecuritystandards.org/documents/PCI-DSS-v3_2_1-ROC-Reporting-Template.pdf?agreement=true&time=1535905197972`](https://www.pcisecuritystandards.org/documents/PCI-DSS-v3_2_1-ROC-Reporting-Template.pdf?agreement=true&time=1535905197972)

+   追求 PCI DSS 合规性的优先方法概述：[`www.pcisecuritystandards.org/documents/Prioritized-Approach-for-PCI-DSS-v3_2_1.pdf?agreement=true&time=1535905628536`](https://www.pcisecuritystandards.org/documents/Prioritized-Approach-for-PCI-DSS-v3_2_1.pdf?agreement=true&time=1535905628536)


# 第十四章：渗透测试报告工具

评估跟踪和文档是专业渗透测试的关键方面。应记录测试工具的每个输入和输出，以确保在需要时可以以准确和一致的方式再现发现。请记住，渗透测试过程的一部分包括向客户呈现发现结果。这些客户很可能希望减轻漏洞，然后尝试模仿您的步骤，以确保他们的减轻措施有效。根据范围的不同，您可能需要执行额外的测试，以验证客户所做的任何改进实际上是否消除了您发现的漏洞。准确记录您的步骤将有助于确保在后续过程中进行完全相同的测试。

适当的测试文档提供了执行操作的记录，因此允许您在客户在约定的测试时间窗口内遇到非测试相关事件时追踪您的步骤。详细记录您的操作可能非常繁琐，但作为专业的渗透测试人员，您不应忽视这一步骤。

文档编制、报告准备和演示是必须以系统化、结构化和一致的方式处理的核心领域。本章提供了详细的说明，将帮助您调整文档编制和报告策略。本章将涵盖以下主题：

+   结果验证，确保只报告经过验证的发现。

+   将从执行、管理和技术角度讨论报告类型及其报告结构，以最好地反映参与渗透测试项目的相关当局的利益。

+   演示部分提供了一般提示和指南，有助于了解您的观众及其对所提供信息的接受程度。

+   测试后程序；即作为报告的一部分应包括的纠正措施和建议，以及在相关组织中为建议团队提供支持的使用。这种练习非常具有挑战性，需要对安全考虑下的目标基础设施有深入的了解。

以下各节将为准备文档、报告和演示提供坚实的基础，特别是突出它们的作用。即使是一个小错误也可能导致法律问题。您创建的报告必须与您的发现保持一致，并且不仅仅指出目标环境中发现的潜在弱点。例如，它应该准备充分，并展示对客户可能要求的已知合规要求的支持证据。此外，它应清楚地说明攻击者的作案手法、应用工具和技术，并列出发现的漏洞和经过验证的利用方法。主要是关注弱点，而不是解释用于发现它们的事实或程序。

# 技术要求

需要一台至少配备 6GB RAM、四核 CPU 和 500GB 硬盘空间的笔记本电脑或台式机。对于操作系统，我们使用 Kali Linux 2018.2 或 2018.3 作为虚拟机，或安装在硬盘、SD 卡或 USB 闪存驱动器上。

# 文档和结果验证

在大多数情况下，需要进行大量的漏洞验证，以确保您的发现实际上是可以利用的。缓解工作可能会很昂贵，因此漏洞验证对于您的声誉和诚信而言是一项关键任务。根据我们的经验，我们注意到有几种情况，人们只是运行一个工具，获取结果，然后直接呈现给他们的客户。这种不负责任和对评估的控制不足可能会导致严重后果，并导致您的职业生涯的垮台。在存在错误的情况下，甚至可能通过出售虚假的安全感来使客户处于风险之中。因此，测试数据的完整性不应受到错误和不一致性的影响。

以下是一些可能在将测试结果记录和验证成最终报告之前帮助您的程序：

+   **详细记录**：在信息收集、发现、枚举、漏洞映射、社会工程、利用、权限提升和持久访问渗透测试过程的每个步骤中都要做详细记录。

+   **记录模板**：为您从 Kali 对目标执行的每个工具制作一个记录模板。模板应清楚地说明其目的、执行选项和为目标评估对齐的配置文件，并提供空间记录相应的测试结果。在从特定工具得出最终结论之前，重复练习至少两次是至关重要的。这样，您可以对任何意外情况对结果进行认证和测试。例如，当使用 Nmap 进行端口扫描时，我们应该制定我们的模板，包括任何必要的部分，如使用目的、目标主机、执行选项和配置文件（服务检测、操作系统类型、MAC 地址、开放端口、设备类型等），并相应地记录输出结果。

+   **可靠性**：不要依赖单一工具。依赖单一工具（例如，用于信息收集）是绝对不切实际的，可能会给您的渗透测试带来不一致性。因此，我们强烈建议您使用专为类似目的而制作的不同工具进行相同的练习。这将确保验证过程的透明度，提高生产力，并减少错误的阳性和阴性。换句话说，每个工具都有其处理特定情况的专长。在适用的情况下，手动测试某些条件也是值得的，并利用您的知识和经验来验证所有报告的发现。

# 报告类型

在收集到您验证的每个测试结果后，您必须将它们合并成一个系统化和结构化的报告，然后再提交给目标利益相关者。有三种不同类型的报告；每种都有其自己的模式和布局，与参与渗透测试项目的商业实体的利益相关。报告类型如下：

+   执行报告

+   管理报告

+   技术报告

这些报告是根据接收者理解和理解渗透测试人员传达的信息的能力水平而准备的。在接下来的部分中，我们将检查每种报告类型及其报告结构，以及可能需要完成您的目标的基本元素。

重要的是要注意，所有这些报告在交给利益相关者之前都应遵守保密政策、法律通知和渗透测试协议。

# 执行报告

执行报告，一种评估报告，更短，更简洁，从业务战略的角度指出了渗透测试输出的高层视图。该报告是为目标组织的 C 级高管（CEO、CTO、CIO 等）准备的。它必须包含一些基本元素，如下所示：

+   **项目目标**：本部分定义了您与客户之间渗透测试项目的相互同意的标准。

+   **漏洞风险分类**：本部分解释了报告中使用的风险级别（关键、高、中、低和信息性）。这些级别应该清晰区分，并应强调严重程度方面的技术安全风险。

+   **执行摘要**：本部分简要描述了在定义的方法论下渗透测试任务的目的和目标。它还强调了发现和成功利用的漏洞数量。

+   **统计数据**：本部分详细介绍了在目标网络基础设施中发现的漏洞。这些也可以以饼状图或其他直观的形式呈现。

+   **风险矩阵**：本部分量化和分类了所有已确定的漏洞，确定了潜在受影响的资源，并以简略格式列出了发现、参考和建议。

在准备执行报告时，始终是一种理想的方法是创造性和表达性，并牢记您不需要反映评估结果的技术基础，而是提供从这些结果中加工出的事实信息。报告的总体大小应为两到四页。请参考本章末尾的*进一步阅读*部分，了解示例报告。

# 管理报告

管理报告通常旨在涵盖问题，包括目标安全姿态的监管和合规性测量。实际上，它应该通过一些可能对**人力资源**（**HR**）和其他管理人员感兴趣的部分，以及协助他们的法律程序来扩展执行报告。以下是可能为您提供有价值的基础，用于创建这样一个报告的关键部分：

+   **合规性达成**：这包含已知标准的列表，并将其各个部分或子部分与当前的安全状况进行映射。它应该突出显示发生的任何监管违规行为，并可能无意中暴露目标基础设施并构成严重威胁。

+   **测试方法**：这应该简要描述，并包含足够的细节，以帮助管理人员了解渗透测试生命周期。

+   **假设和限制**：这突出了可能阻止渗透测试人员达到特定目标的已知因素。

+   **变更管理**：这有时被视为纠正过程的一部分；然而，它主要针对处理受控 IT 环境中的所有变化的战略方法和程序。从安全评估中产生的建议和推荐应该与程序中的任何变化保持一致，以最小化对服务的意外事件的影响。

+   **配置管理**：这关注系统的功能操作和性能的一致性。在系统安全的背景下，它遵循可能已经引入到目标环境中的任何变化（硬件、软件、物理属性等）。这些配置变化应该受到监控和控制，以维持系统配置状态。

作为一名负责任和知识渊博的渗透测试人员，您有责任在进行渗透测试生命周期之前澄清任何管理术语。这项工作肯定涉及一对一的对话和就目标特定评估标准达成协议，比如必须评估何种合规性或标准框架，是否在遵循特定测试路径时有任何限制，建议的变更是否在目标环境中可持续，以及如果引入任何配置变更是否会影响当前系统状态。这些因素共同建立了目标环境中当前安全状态的管理视图，并根据技术安全评估提供建议和建议。

# 技术报告

技术评估报告在解决渗透测试过程中提出的安全问题方面起着非常重要的作用。这种报告通常是为想要了解目标系统处理的核心安全功能的技术人员而制定的。报告将详细说明任何漏洞，它们如何被利用，可能带来的业务影响，以及如何开发抵御任何已知威胁的抗性解决方案。它必须与全面的安全指南进行沟通，以保护网络基础设施。到目前为止，我们已经讨论了执行和管理报告的基本要素。在技术报告中，我们扩展了这些要素，并包括一些可能引起目标组织技术团队极大兴趣的特殊主题。有时，项目目标、漏洞风险分类、风险矩阵、统计数据、测试方法和假设和限制等部分也是技术报告的一部分。技术报告包括以下部分：

+   **安全问题**：在渗透测试过程中提出的安全问题应该清楚地详细列出，对于每种应用的攻击方法，您必须提到受影响资源的列表、其影响、原始请求和响应数据、模拟攻击请求和响应数据，为修复团队提供外部来源的参考，并提供专业建议来修复目标 IT 环境中发现的漏洞。

+   **漏洞地图**：提供了在目标基础设施中发现的漏洞列表，每个漏洞都应该很容易与资源标识符（例如 IP 地址和目标名称）匹配。

+   **利用地图**：提供了成功检查和验证的针对目标的利用列表。还要提到利用是私有还是公开。详细说明利用代码的来源以及它已经可用多长时间可能是有益的。

+   **最佳实践**：这强调了目标可能缺乏的任何更好的设计、实施和运行安全程序。例如，在大型企业环境中，部署边缘级安全可能有利于减少威胁数量，使其无法进入企业网络。这些解决方案非常方便，不需要与生产系统或传统代码进行技术交流。

一般来说，技术报告向相关组织成员提出了现实情况。这份报告在风险管理过程中起着重要作用，并可能被用来制定可行的修复任务。

# 网络渗透测试报告

正如有不同类型的渗透测试一样，报告结构也有不同类型。我们提供了一个基于网络的渗透测试报告的通用版本，几乎可以扩展到几乎任何其他类型的渗透测试（例如，Web 应用程序、防火墙、无线和网络）。除了以下目录外，您还需要一个封面页面，上面列出了测试公司的名称、报告类型、扫描日期、作者姓名、文档修订号以及简短的版权和保密声明。

以下是基于网络的渗透测试报告的目录：

+   法律声明

+   渗透测试协议

+   介绍

+   项目目标

+   假设和限制

+   漏洞风险等级

+   执行摘要

+   风险矩阵

+   测试方法

+   安全威胁

+   建议

+   漏洞图

+   利用图

+   合规评估

+   变更管理

+   最佳实践

+   附件

正如您所看到的，我们已将所有类型的报告合并为一个具有明确定义结构的完整报告。每个部分都可以有自己相关的子部分，可以更好地对测试结果进行分类，更详细地进行分析。例如，附件部分可以用于列出测试过程的技术细节和分析、活动日志、来自各种安全工具的原始数据、研究细节、对任何互联网来源的引用以及术语表。根据客户要求的报告类型，您有责任在开始渗透测试之前了解您的职位的重要性和价值。

# 准备您的演示

为了成功进行演示，了解您的受众的技术能力和目标是有帮助的。您需要根据受众调整材料；否则，您将面临负面反应。您的主要任务是让客户了解您测试过的领域周围的潜在风险因素。例如，高管级别的经理可能没有时间担心社会工程攻击向量的细节，但他们会对当前的安全状态以及应采取哪些整改措施来改善他们的安全状况感兴趣。

虽然没有正式的程序来创建和呈现您的发现，但您应该保持专业的态度，以使您的技术和非技术受众受益。了解目标环境及其技术人员的技能水平，并帮助他们了解您以及对组织的任何关键资产，也是您的职责的一部分。

指出当前安全状况的不足之处，并在没有情感附着的情况下暴露弱点，可以导致成功和专业的展示。记住，您在那里是为了坚持事实和发现，从技术上证明它们，并相应地向整改团队提供建议。由于这是一种面对面的练习，强烈建议您提前准备好以支持事实和数据回答任何问题。

# 测试后程序

整改措施、纠正步骤和建议都是指测试后程序。在这些程序中，您将充当目标组织的整改团队的顾问。在这个角色中，您可能需要与不同背景的技术人员互动，因此请记住，您的社交形象和人际关系技能在这里可能非常有价值。

此外，除非您接受过培训，否则不可能拥有目标 IT 环境所需的所有知识。在这种情况下，处理和纠正每个脆弱资源的每个实例而不得到专家网络的支持是非常具有挑战性的。我们制定了几条通用指南，可以帮助您向客户推送关键建议：

+   重新审视网络设计，并检查报告中指出的脆弱资源的可利用条件。

+   集中精力在边缘级或数据中心保护方案上，以减少在后端服务器和工作站同时受到攻击之前发生的安全威胁的数量。

+   客户端或社会工程攻击几乎是不可能抵抗的，但可以通过培训员工使用最新的对策和意识来减少。 

+   根据渗透测试人员提供的建议，减轻系统安全问题可能需要进行额外的调查，以确保对系统的任何更改不会影响其功能特性。

+   在必要时部署经过验证和可信赖的第三方解决方案（IDS/IPS、防火墙、内容保护系统、防病毒软件、IAM 技术等），并调整引擎以安全高效地工作。

+   使用分而治之的方法，将安全网络区域与目标基础设施上的不安全或面向公众的实体分开。

+   加强开发人员编写目标 IT 环境中安全应用程序的技能。评估应用程序安全性并执行代码审计可以为组织带来有价值的回报。

+   采用物理安全对策。采用多层入口策略，包括安全的环境设计、机械和电子门禁、入侵警报、闭路电视监控和人员识别。

+   定期更新所有必要的安全系统，以确保其保密性、完整性和可用性。

+   检查和验证所有记录的解决方案，作为建议提供，以消除入侵或利用的可能性。

# 使用 Dradis 框架进行渗透测试报告

Dradis 框架是一个用户友好的报告框架，也支持协作。使用多种工具进行测试和评估可能非常令人兴奋；然而，当涉及组织文档时，这可能会变得有点令人不知所措，考虑到报告中需要包含输出文件以及输出文件的屏幕截图，以及评估期间使用的命令，这些也必须记录。 Dradis 框架通过提供易于使用的界面来协助这一领域，支持许多工具的插件，额外的合规性指南，并且可以轻松定制检查表。

可以通过单击应用程序，然后单击 12-Reporting Tools，然后单击 Dradis 框架，在 Kali 菜单中找到 Dradis 框架。

Dradis 也可以通过在终端中键入`dradis`来直接启动：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/d3f11cbb-b9d6-494b-9d61-06d4c2078fd2.jpg)

前面两种方法都会在浏览器中打开 Dradis Web 界面，URL 为`127.0.0.1:3000/setup`。输入将由所有访问服务器的人使用的密码，然后单击创建共享密码并继续。

接下来，输入用户名和密码，然后点击让我进来！这将带我们到 Dradis CE（社区版）仪表板。 Dradis CE 允许用户创建作为方法论的检查表。您可以通过单击 Methodologies（在左窗格上），或者在主窗口的 Methodology progress 部分下单击+Add a testing methodology 来执行此操作：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/a1f1d86b-bee7-4a70-ad81-de77d4f687cb.jpg)

Dradis 给用户提供了两种选择，要么创建一个新的方法论，要么在其他合规包之间进行选择（必须下载）。如果您希望为您的方法论使用特定模板，而不是创建一个新的模板，可以选择“下载更多”选项，该选项将引导用户转到合规包页面（[`dradisframework.com/academy/industry/compliance/`](https://dradisframework.com/academy/industry/compliance/)），其中包括以下内容：

+   HIPAA 合规审计工具

+   **Offensive Security Certified Professional** (**OSCP**) 报告

+   OWASP 测试指南 v4

+   PTES 技术指南

要为您的方法论创建一个检查表，请选择“新检查表”选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/d5d4756d-13d1-4818-aaa5-20d1fb24f285.jpg)

给新的检查表命名，然后单击“添加到项目”。这将创建一个未填充的检查表，其中包含两个部分标题，以便我们开始：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/9dc1402f-299e-4cf2-b17a-5fc72c380844.jpg)

要编辑部分和任务，请单击“编辑”按钮并编辑 XML 内容。例如，我在第 1 部分区域中添加了“扫描”。编辑完成后，滚动到 XML 文件底部，然后单击“更新方法论”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/5ab96ea2-798d-4c9a-8bca-38c6a525edab.jpg)

在左窗格中，单击“节点”以添加 Dradis CE 将创建报告的设备。如果使用多个节点，请输入节点的 IP（每行一个），然后单击“完成”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/d86e5b22-d272-4cc8-bd91-cb193781d008.jpg)

在左窗格的“注释”部分下单击各个 IP 后，将打开节点摘要仪表板。在这里，您可以添加证据、注释，甚至根据需要添加子节点，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/64b0fbb5-286c-42fb-97a4-9ec4f5e46f8d.jpg)

Dradis 还通过插件能够处理来自各种工具的输出，包括 Acunetix、Burp、Metasploit、Nessus、Nikto、OpenVas 等，用于报告。单击仪表板顶部的“从工具上传输出”。选择一个工具，然后选择要上传到 Dradis 的文件，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/29014cab-d5b5-4e27-99ec-254efcf936c6.jpg)

要完成报告，请单击仪表板顶部的“导出结果”。报告可以生成为 CSV 和 HTML 格式，以及自定义的 Word 和 Excel 报告。选择一个模板，然后单击“导出”以生成您的文件，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/d0b4367c-a32a-4338-84cc-b0eae3887ea7.jpg)

# 渗透测试报告工具

Dradis 并不是 Kali Linux 2018 中唯一可用的工具。单击“应用程序”，然后单击“报告工具”，我们可以看到其他可用的工具，例如 Faraday IDE，MagicTree 和 pipal：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/c41e1d8b-914c-4772-bf76-1dbd6ec2b554.jpg)

# Faraday IDE

Faraday IDE 是另一个旨在支持协作的工具，其中包含大约 40 个内置工具用于生成报告。支持的插件包括 Metasploit、Nmap 和 Nessus。Faraday IDE 提出了多用户渗透测试的概念，在这种环境中，它的功能与在终端中单独运行工具完全相同。

要启动 Faraday IDE，请单击“应用程序”，然后单击“Faraday”。加载界面后，为您的工作区命名以开始使用该应用程序，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/fd5b3da0-d91c-414f-867b-de3ef5538707.jpg)

有关安装和使用 Faraday IDE 的更多信息，请访问[`github.com/infobyte/faraday/wiki`](https://github.com/infobyte/faraday/wiki)。

# MagicTree

MagicTree 是 Kali Linux 中的另一个工具，用于生成和管理报告。Nmap 用户可能会发现这个工具特别有趣，因为它允许用户直接从应用程序中运行 Nmap 扫描。可以通过单击“应用程序”，然后单击“报告工具”来启动 MagicTree。该工具应该看起来像下面的屏幕截图：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-asr-sec-pentest/img/60b1d806-5f5e-45d2-b922-b3adc351b07b.jpg)

有关使用 MagicTree 的更多信息，请访问[`www.gremwell.com/using_magictree_quick_intro`](https://www.gremwell.com/using_magictree_quick_intro)。

# 总结

在本章中，我们探讨了创建渗透测试报告所需的一些基本步骤，并讨论了在客户面前进行演示的核心方面。起初，我们充分解释了如何记录来自各个工具的结果的方法，并建议您不要仅依赖单个工具来获得最终结果。因此，在记录结果之前，您的经验和知识在验证测试结果时至关重要。确保保持您的技能更新并足以在需要时手动验证发现。

然后，我们研究了报告工具，主要关注了 Dradis Framework，同时涉及了 Faraday IDE 和 MagicTree。我们鼓励您尝试它们，因为您可能希望将这些工具结合起来进行各种目的和合作。

最后，我们希望您喜欢这本书，并祝愿您在网络安全和渗透测试的冒险中一切顺利。

# 问题

1.  向客户呈现的渗透测试报告有哪三种主要类型？

1.  在执行报告中，风险矩阵量化了什么？

1.  漏洞地图的目的是什么？

1.  利用地图的目的是什么？

1.  测试方法论应包含什么？

1.  如何减少客户端或社会工程攻击？

# 进一步阅读

+   样本渗透测试报告：[`www.offensive-security.com/reports/sample-penetration-testing-report.pdf`](https://www.offensive-security.com/reports/sample-penetration-testing-report.pdf)

+   撰写渗透测试报告的提示：[`www.sans.org/reading-room/whitepapers/bestprac/writing-penetration-testing-report-33343`](https://www.sans.org/reading-room/whitepapers/bestprac/writing-penetration-testing-report-33343)

+   Nessus 样本报告：[`www.tenable.com/products/nessus/sample-reports`](https://www.tenable.com/products/nessus/sample-reports)

+   技术渗透测试报告样本：[`tbgsecurity.com/wordpress/wp-content/uploads/2016/11/Sample-Penetration-Test-Report.pdf`](https://tbgsecurity.com/wordpress/wp-content/uploads/2016/11/Sample-Penetration-Test-Report.pdf)


# 第十五章：评估

# 第一章：- 评估答案

1.  NetHunter

1.  MD5 和 SHA 校验和实用程序

1.  sha265sum

1.  Rufus

1.  实时（amd64），实时（取证模式），实时 USB

1.  apt-get update

1.  T2 微型

# 第二章：- 评估答案

1.  VMware 和 VirtualBox

1.  虚拟机磁盘

1.  用户名和密码都是*msfadmin*

1.  Packer 和 Vagrant

1.  apt-get install（package_name）

1.  service mysql start

1.  service ssh start

# 第四章：- 评估答案

1.  开源情报

1.  whois

1.  IPv4 地址

1.  Metagoofil

1.  Devlpoit 和 RedHawk

1.  Shodan

# 第五章：- 评估答案

1.  Nmap 7.7 中有 588 个脚本可用

1.  FIN 标志表示没有更多数据要发送，并且连接应该被终止

1.  过滤端口表示数据包阻止设备正在阻止探测到达目标

1.  -f Nmap 选项可用于在规避防火墙和 IDS 时使数据包更难被检测到

1.  Netdiscover -r

1.  -p 选项可以在 Netdiscover 中用于运行被动扫描

1.  www.dnsleak.com

# 第六章：- 评估答案

1.  漏洞是系统中发现的安全漏洞，攻击者可以利用该漏洞执行未经授权的操作，而利用则利用该漏洞或错误。

1.  设计漏洞使开发人员根据安全要求推导出规范，并安全地解决其实施。因此，与其他类别的漏洞相比，解决这个问题需要更多的时间和精力。

1.  远程漏洞是指攻击者没有先前访问权限，但漏洞仍然可以通过在网络上触发恶意代码来利用。

1.  Nessus。

1.  Lynis。

1.  Nikto。

# 第十二章：- 评估答案

1.  Nexus 4，Nexus 5 和 OnePlus One

1.  是的，NetHunter 需要移动设备上的 root 访问权限

1.  cSploit，Drive Droid，Router Keygen，Shodan

1.  WPA，WPA2

1.  会话劫持者，终止连接，重定向，脚本注入

1.  邪恶孪生

1.  DuckHunter HID 攻击将 USB Rubber Ducky 脚本转换为 NetHunter HID 攻击

# 第十三章：- 评估答案

1.  万事达卡，VISA，美国运通和 JCB 国际

1.  PCI DSS 版本 3

1.  6 个目标，12 个要求

1.  要求 11.3

1.  季度网络评估

1.  每年

1.  分段的目的是将持卡人数据环境（CDE）与其余环境隔离开来

1.  结构化测试过程是指根据客户端更改重构测试方法论

1.  CEH，OSCP，CREST，GIAC

1.  Nessus，Lynis

# 第十四章：- 评估答案

1.  三种类型的报告：

- 执行报告

- 管理报告

- 技术报告

1.  风险矩阵对所有发现的漏洞进行量化和分类，确定潜在受影响的资源，并以简略格式列出发现、参考和建议。

1.  漏洞地图提供了在目标基础设施中发现的漏洞列表，每个漏洞应该很容易与资源标识符（例如 IP 地址和目标名称）匹配。

1.  Exploits 地图提供了成功检查和验证的漏洞利用列表，这些漏洞利用针对目标起作用。

1.  测试方法应包含足够的细节，以帮助管理了解渗透测试生命周期。

1.  通过培训员工最新的对策，可以减少客户端或社会工程攻击。
