# Kali Linux 2018：Windows 渗透测试（一）

> 原文：[`annas-archive.org/md5/1C1B0B4E8D8902B879D8720071991E31`](https://annas-archive.org/md5/1C1B0B4E8D8902B879D8720071991E31)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Microsoft Windows 是两种最常见的操作系统之一，管理其安全性催生了 IT 安全学科。Kali Linux 是测试和维护 Windows 安全性的首选平台。Kali 是基于 Linux 的 Debian 发行版构建的，并且共享了该操作系统的传奇稳定性。这使您可以专注于使用网络渗透、密码破解、取证工具，而不是操作系统。

本书具有最先进的工具和技术，可以复制复杂黑客使用的方法，使您成为 Kali Linux 渗透测试的专家。您将首先了解现在随 Kali 一起提供的各种桌面环境。本书涵盖了网络嗅探器和分析工具，以揭示网络上使用的 Windows 协议。您将看到几种工具，以提高您在密码获取方面的平均水平，从哈希破解、在线攻击、离线攻击和彩虹表到社会工程学。它还演示了 Kali Linux 工具的几种用例，如社会工程工具包、Metasploit 等，以利用 Windows 漏洞。

最后，您将学习如何获得对受损系统的完全系统级访问权限，然后保持该访问权限。在本书结束时，您将能够使用易于遵循的说明和支持图像快速进行系统和网络渗透测试。

# 本书适合人群

如果您是一名希望通过对 Kali Linux 进行深入了解来扩展攻击技能的工作中的道德黑客，那么这本书就是为您而写的。对 Linux 操作系统、Bash 终端和 Windows 命令行的先前了解将非常有益。

# 充分利用本书

您需要以下内容来测试本书的代码：

+   路由器/防火墙

+   Linux 工作站 8 核 32 GB RAM 用于 VM 服务器。（运行 VirtualBox）

+   Windows 2008 服务器用于 DC（VM）

+   Windows 2008 服务器文件服务器（VM）

+   Win7 客户端（VM）

+   Win10 客户端（这是一台物理笔记本电脑）

+   笔记本电脑运行 Kali 4 核 8 GB RAM。用于攻击的平台。（我的个人笔记本电脑）

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：`www.packtpub.com/sites/default/files/downloads/9781788997461_ColorImages.pdf`。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这里有一个例子：“这将产生一个快速扫描-`T`代表时间（从 1 到 5），默认时间是`-T3`。”

一块代码设置如下：

```
html, body, #map {
 height: 100%; 
 margin: 0;
 padding: 0
}
```

任何命令行输入或输出都写成如下形式：

```
nmap -v -sn 192.168.0.0/16 10.0.0.0/8
nmap -v -iR 10000 -Pn -p 80
```

**粗体**：表示一个新术语、一个重要单词或您在屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这里有一个例子：“从顶部栏上的图标打开终端，或者点击菜单链接：

应用程序 | 配件 | 终端”。

警告或重要说明会显示为这样。

提示和技巧会显示为这样。


# 第一章：选择您的发行版

自我们的书的第一版以来，Kali Linux 发生了很多变化。除了 Kali 现在是一个滚动发行版之外，它现在还配备了几个桌面环境和几种不同的内核架构。这意味着你可以在小型树莓派上运行 Kali，也可以在专为速度和功率而建的完整工作站上运行 Kali。通过添加一个普通用户帐户和一些额外的配置和软件包，你可以将 Kali 作为你的日常驱动程序操作系统。在本章中，我们将讨论几种桌面环境以及各自的优缺点。这将帮助你决定在使用 Kali 进行黑客活动时应该下载哪个发行版。如果你对 Linux 不熟悉，本章将帮助你了解 Linux 及其设计的一些内部知识。

+   桌面环境

+   选择您的外观和感觉

+   为您的日常驱动程序进行配置

# 桌面环境

Unix/Linux 系统和 Windows 之间的一个重大区别是它们在设计上真正是模块化的。当然，我知道微软说“Windows 在设计上是模块化的”，但实际情况并非如此。在 Windows 中，桌面*无缝集成到操作系统中*。因此，在 Server 2012 之前，你必须运行带有运行 GUI 的 Windows 服务器。在 Server 2012 中，你可以选择无头运行机器，但在这种模式下服务器的使用非常有限。试图卸载 Internet Explorer；嗯，你不能。是的，Internet Explorer 是一个具有最大安全漏洞的常见应用程序之一。是的，Internet Explorer 具有系统级访问权限。是的，托托，这是一个问题，我们将在本书的后面利用它，但在本章中让我们专注于桌面环境。

Linux 的设计真的是模块化的。Linux 的父亲是 Unix，Unix 的整个设计理念是小型交互式程序，可以链接在一起执行更大的任务。Linux 也是这样设计的。实际上，Linux 只是由一个人，Linus Torvalds 发明的操作系统的内核。几乎所有其他东西都是一系列小应用程序组合在一起*让系统运行*。一个大而持续的组件集，帮助内核与硬件交互，被称为 GNU 工具集。这些工具大多是从 Unix 移植过来的，或者重新编写以避免版权问题，但仍然使用相同的输入和输出。

因此，根据这种设计结构，GUI 只是操作系统的另一个模块，可以在不影响底层工作部分的情况下进行更改或完全删除。这使得 Linux 能够做任何事情，从智能手表到运行强子对撞机，或者...成为一个黑客机器。

# 桌面环境与窗口管理器

一个重要的区别可能会帮助你理解桌面环境在 Kali 和其他 Linux 系统上是如何工作的，那就是窗口管理器。桌面环境，也称为图形用户界面（GUI），通常包括文件夹、壁纸、桌面小部件、图标、窗口、工具栏和应用程序界面。微软 Windows 桌面环境可能是你发现的第一个类似的构造。你的智能手机也有一个桌面环境，而 Windows 8 桌面环境的失败是试图将 Windows CE（手机 GUI）和 Windows 7/Server 2003 GUI 的开发合并在一起。微软犯的错误是假设有更多具有触摸屏功能的工作站。技术显然存在，但显示器昂贵且使用范围有限。Bo 和 Wolf 认为 Ubuntu Unity 桌面环境也是基于相同设计假设的失败。鼠标驱动的工作站界面还将继续存在一段时间。

在 Kali 中，桌面环境通常与 X Windows 系统或 Wayland 等窗口系统交互，后者直接在硬件之上运行，并且与用户看到和与之交互的窗口管理器应用程序交互。窗口管理器提供了 Kali Linux 体验的外观和感觉。在 Kali Linux 中几乎可以与任何桌面环境一起使用几种窗口管理器。其中之一是 Enlightenment 窗口管理器，它作为 E17 包含在 Kali ISO 下载中。E17 和完整的桌面环境（如 KDE 或 Gnome）之间的主要区别在于，E17 几乎没有专门为 E17 构建的应用程序，而 KDE 和 Gnome 有专门的应用程序，需要满足大量依赖关系才能在其他桌面环境中运行。Kate 和 gedit 分别是 KDE 和 Gnome 的专门文本编辑器。

# 启蒙（E17）

安装 E17 ISO 与安装任何其他桌面环境几乎相似，只要你使用默认安装选项。标准引导屏幕是运行级别 3，只有一个命令行界面，所以你必须使用`startx`命令来查看桌面界面。如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/c65a7a2e-dced-4f79-9476-89494f230a51.png)

E17 启动屏幕

在第一次登录到 E17 环境时，你将被问及一系列你在安装过程中已经回答过的问题：

+   语言：默认高亮显示的是美式英语。

+   键盘布局：默认高亮显示的是英语（美国）。

+   配置文件：这是硬件配置文件，选择是移动和计算机。默认高亮显示的是计算机。

+   大小：这是标题大小。选择从 0.8 到 2.0。默认高亮显示的是 1.0。

+   窗口焦点：选择是单击和鼠标悬停。默认高亮显示（以及一般的 Linux 默认）是鼠标悬停。

+   检查 Connman 是否存在：Connman 是 Enlightenment 网络连接管理器。点击安装/启用 Connman。

+   合成：这是 E17 中大部分视觉效果的来源。默认情况下启用合成，但如果你正在进行裸机安装，你可能想使用硬件加速（Open-GL）合成。如果 RAM 不足或者你使用的是较旧的处理器，你可能根本不想使用合成：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/3fc76446-7397-4ac2-9b61-ed71bc38011f.png)

首次启动合成选择

+   更新：你可以启用对 Enlightenment 更新的检查。默认情况下是勾选此更新的框。如果你在目标网络中运行，请清除此复选框。如果网络应该是仅限 Windows 的，那么随机出现的网络检查就不是特别隐秘了。

+   任务栏：启用任务栏可以让你在 Kali Linux E17 桌面上看到打开的应用程序和窗口。这是默认启用的。

一旦你完成了配置，E17 会显示桌面。下面的截图显示了默认桌面。你可能注意到的第一件事是背景是一个平坦的白色板。顶部的菜单行来自 Virtual Box。底部的菜单栏让人联想到苹果 Mac 的工具栏。中间的浮动菜单栏是通过右键单击桌面实现的：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/9915808e-1e8e-4780-ab3a-b7d8baa778b4.png)

E17 默认桌面

基本默认文件管理窗口如下截图所示。它是可读的，但几乎没有令人兴奋的地方。如果你点击桌面菜单，你可以添加小工具。我已经在任务栏中添加了一个系统小工具，但你也可以把它放在桌面的任何地方。下面的截图显示了来自背光小工具的右键菜单。如果你点击“开始移动小工具”，你可以移动所有的小工具，直到你点击“停止移动小工具”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/94db8146-64d3-4d0d-8cad-7d08bf3b40a7.png)

移动小工具

# E17 窗口管理器问题

1.  几乎所有的安全工具都被归类在“其他菜单”下的“应用程序菜单”下，这可能会有点拥挤。

1.  如果您在靠近右屏幕边框的地方打开单击菜单，子菜单将超出屏幕。其他菜单过度拥挤的效果如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/770f5e6b-02b5-4f45-b3a8-438edcf48bdb.png)

其他菜单过度拥挤的效果

1.  这个版本的 Enlightenment 已经有好几年了。当前的主要版本是 22。也许创建 Kali 的 Offensive Security 的人决定将 Enlightenment 冻结在主要版本 17，因为 Enlightenment 开发人员正在转向使用 Wayland 窗口系统，默认情况下 Kali-E17 正在使用**xorg**窗口系统。

要检查您的 Kali 版本是否正在运行 xorg 还是 Wayland，请在命令行上键入`xdpyinfo`。如果它正在运行纯 Wayland 环境，该命令将失败。如果它正在使用 xorg，它将产生有关您的视频配置的几行信息。以下屏幕截图显示了默认安装的结果的截断屏幕：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/1156c31b-062e-4010-96cf-d30414e156ce.png)

截断的 xpdyinfo 输出

1.  获取所有安全工具的最简单方法似乎是打开“应用程序”|“运行所有”对话框，如前面所示。我发现当我尝试打开 E17 中的默认终端仿真器**xterm**来安装我最喜欢的软件安装程序**Synaptic**时，会返回错误代码。我必须转到“应用程序”|“系统菜单”并从那里打开 xterm。似乎没有一个简单的解决方法来修复失败的“运行所有”小部件。也许升级到当前稳定版本的 Enlightenment（E22.x）会解决这个问题，但解决方案可能需要重新设计窗口系统，这是一个非常重要的工作。

要安装`synaptic`：

```
#> apt install synaptic
```

要在 E17 中更改壁纸，请单击“应用程序”|“设置”|“壁纸设置”。这将打开以下屏幕截图中显示的对话框。您可以选择自己的桌面图像或工厂图像之一：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/23be8e54-847c-4164-9474-2997a12a12a7.png)

更改桌面壁纸

# Gnome 桌面

在 Backtrack 时代，Backtrack 是 Kali Linux 的前身安全平台，默认桌面环境是一个非常简化的 KDE 版本。当 Backtrack 被废弃并且 Offensive Security 发布了 Kali 时，默认桌面被更改为 Gnome。Backtrack 只是一个活动光盘 CD，并且不打算安装在任何计算机上。Backtrack 版本的 KDE 被简化以便能够从标准 CD 加载。这种简化去除了许多桌面功能。当 Kali 发布时，它被设计为从活动 DVD 加载，并安装在 x386 和 amd_64 架构上。Gnome 略微让人联想到 Windows 3.11 的外观和感觉，并且使用更少的内存来绘制桌面比 KDE。

Gnome 桌面自 Linux 早期以来就存在。Kali Linux 默认桌面环境是 Gnome 3。进行标准安装时，桌面看起来像这样：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/5767ac08-f313-4433-9fb1-1d648d447ff1.png)

Gnome 3 默认桌面

左边框上的工具栏是收藏夹组。当您打开任何应用程序时，它的图标会出现在左侧的收藏夹组中，如下面的屏幕截图所示，我已经打开了 OWASP ZAP：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/42bbb60d-a4c3-4449-a5a7-fcc05d317c66.png)

将应用程序添加到收藏夹组

安全工具菜单位于桌面左上角的“应用程序”选项卡下。这是一个非常好的分类列表，使得更容易找到您想要使用的任何工具。列表如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/0e3b99ab-f9ae-4425-8915-7300acd0a121.png)

Kali 的 Gnome 应用菜单

在 Gnome 3 中更改桌面图像很容易，但设置菜单有点难找。它隐藏在右上角的图标下面。以下截图显示了系统菜单，其中包括声音音量控制、网络连接对话框和设置编辑器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/a196ba3f-684b-438e-955e-825031c6858a.png)

Gnome 系统菜单

大多数 Gnome 中的设置都可以在设置对话框中找到，如下一个截图所示。有关 Wi-Fi、背景、通知、搜索、区域和语言、通用访问、在线帐户、隐私、共享、声音、电源和网络的设置表。下一个截图显示了桌面编辑器，其中包含默认的桌面图像：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/b16554d6-fab9-46a4-98d1-19bb8b95b0bd.png)

Gnome 设置对话框

要更改图像，只需单击要更改的图像。这将打开一个对话框，您可以从图片目录中选择几个包含的图像，或者选择自己的图像：

# Gnome 3 桌面问题

+   似乎没有任何简单的方法将应用程序添加到收藏夹组

+   下拉菜单栏使用滑块将您带到通常的应用程序菜单，而不是完整长度的子菜单

# KDE 桌面

KDE 自 Linux 早期以来就存在，是 Bo Weaver 最喜欢的。随着年龄的增长，稳定性也增加了，KDE 是一个非常稳定的桌面。外观和感觉非常类似于 Windows，因此对于 Windows 用户来说很容易使用。 KDE 的一个优势是桌面高度可配置。如果你不喜欢它的外观，就改变它。这可能是一个很大的优势。 KDE 带有所有最新的 Jumping Monkeys 和功能。你可能喜欢你自己的桌面环境，就像我们一样。只要你能把桌面配置成多年来一直的样子，最新的东西就无所谓了。这有助于*肌肉记忆*。肌肉记忆起作用是因为一切都在预期的位置上，这降低了工作的开销，因为没有时间去寻找你每天使用的常见工具。不必考虑工具在机器上的隐藏位置或如何保存文件，因为开发人员决定该应用程序不再需要菜单栏。使用 KDE，你可以将你的桌面改回老式的简约桌面，一切都和多年前一样。如果你感到无聊，你可以定制桌面，超出默认的 Kali 外观。下一张截图显示了默认桌面，开始菜单打开在应用程序上。菜单组织与你已经看到的 Gnome 3 菜单类似：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/3de20378-92b8-4dfc-97e5-ff41d5c928b5.png)

默认 KDE Kali 桌面

KDE 的一个缺点是，由于它是如此高度可配置并且带有许多内置功能，它对机器的内存和显卡需求很高。KDE 确实需要在具有良好内存的现代机器上运行。此外，由于它是如此高度可配置，有时很容易搞乱你的设置。

KDE 的一个优势是桌面小部件。桌面小部件是在桌面上运行的小应用程序，可以做很多事情。在黑客时，你需要密切关注你的本地系统资源。有一些小部件可以让你一目了然地监视系统内存、CPU 和网络使用情况。在工作中突然启动一个工具，然后因为内存不足而导致系统崩溃是一件令人沮丧的事情。使用小部件，你可以监视内存使用、网络和 CPU 使用情况。

KDE 在使用多个监视器时也非常好用，并且可以完全配置分配哪个监视器是主监视器以及工具栏的位置。它还可以在不重新启动或调整配置的情况下恢复到单个监视器。当你的机器是一台经常移动的笔记本电脑时，这一点非常棒。

KDE 开发人员似乎明白，平板电脑的桌面界面在使用鼠标的工作站上不起作用。自从平板电脑出现以来，KDE 现在确实有两个界面，Plasma 和 Neon，它们在硬件更改时互换。它们都使用相同的后端工具集；只有在从平板模式切换到工作站模式时，外观和功能才会发生变化。这是 Windows 8 桌面的失败，也是 Gnome 桌面的失败。你不能设计一个既适用于手指又适用于鼠标的界面。你最终得到的将是一个既不适合手指也不适合鼠标的界面。

# KDE 问题

KDE 图形繁忙，使用了大量资源。这使得它不适合非常老旧的机器，或者图形内存较低的机器。

+   **SHOW STOPPER!**: 这是一个安装程序问题，你可能不会遇到这种情况。创建 Kali Linux 的人随着时间的推移向 ISO 磁盘文件添加更新，当 Wolf 进行此安装时，出现了这个问题。这很容易解决，重要的是不要惊慌。如果你的安装出现这种情况，你没有做错任何事。安装后，KDE 实例加载到 tty1 全屏 CLI，`startx`不会启动 GUI。`startx`是`xinit`软件包的一部分，所以你可以以 root（刚刚登录的帐户）的身份输入以下内容来安装`xinit`：

```
#> xinit 
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/c7653e4f-47ab-4a74-a885-f64a196a84d6.png)

安装 xinit 后的 KDE startx

# LXDE 桌面

LXDE，全称轻量级 X11 桌面环境，是由台湾程序员洪任中在 2006 年设计的，他写了 LXDE 的第一个模块。那是一个文件管理器。这让人想起 Linux 内核本身的创建，Linus Torvalds 从一个文件管理器模块开始。安装出现了问题，但是 Live 光盘似乎运行良好。我注意到 Kali-Linux 图形安装要求输入机器域，但常规安装不需要。下面的屏幕截图显示了默认的 LXDE 桌面。

这个桌面环境也让人想起 Windows XP，因为菜单启动按钮在左下角：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/14bb6071-f0d4-4403-8076-cb53d1d299e1.png)

LXDE 默认桌面视图

要更改桌面背景，请转到左下角的菜单，选择首选项|桌面首选项。菜单显示在下一个屏幕截图中。如果你想要更多的背景图片选择，可以查看[`pixabay.com/`](https://pixabay.com/)：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/5d6ed548-49ba-4595-af4d-692488c9dfe2.png)

LXDE 桌面图像首选项对话框

# LXDE 问题

+   **SHOW STOPPER**: 图形安装失败，因为**没有计划分区表，也没有计划创建文件系统**

+   **SHOW STOPPER**: 常规安装失败，因为**未安装操作系统**

# MATE 桌面

MATE 桌面是现在已经不再使用的 Gnome 2 桌面环境的一个分支。MATE 代表 MATE 高级传统环境。这类似于 GNU 首字母缩略词，*GNU 不是 Unix*。将分支重命名为 MATE 避免了与仍在使用的 Gnome 3 环境的命名约定问题。

MATE 包括许多 Gnome 应用程序的分支，并且开发人员编写了新的应用程序。这些名称都是西班牙语，以反映 MATE 的阿根廷起源。

MATE 应用程序包括以下内容：

+   **Caja**: 文件管理器（来自 Nautilus）

+   **Atril**: 文档查看器（来自 Evince）

+   **Engrampa**: 存档管理器（来自存档管理器）

+   **MATE 终端**: 终端模拟器（来自 GNOME 终端）

+   **Marco**: 窗口管理器（来自 Metacity）

+   **Mozo**: 菜单项编辑器（来自 Alacarte）

+   **Pluma**: 文本编辑器（来自 Gedit）

MATE 的第一次启动，以及所有后续的启动，都将我们带入运行级别 3，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/1a25df7d-5d89-4664-98e9-1821a0b78946.png)

MATE 首次启动

MATE 的默认 GUI 对大多数 Linux 用户来说是熟悉的，因为它几乎是 Gnome 2 的镜像。下一张截图显示了带有默认 Kali 标志的桌面。应用程序、位置和系统菜单结构一直是 Linux 桌面的标志，许多长期使用 Linux 的用户欢迎 MATE 团队维护这一传统的努力：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/772776fb-52ee-495e-8e65-dbf4c35ae34c.png)

MATE GUI

以下截图显示了 MATE 桌面的所有三个系统菜单，代表性的子菜单已打开。Places 菜单打开 Caja（文件管理）窗口：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/cd755805-1235-4083-9841-b3cef9eb3756.png)

MATE 系统菜单

外观和感觉菜单为您提供了 12 种预设的外观偏好，然后可以进一步定制。以下截图显示了其中一些预设的选择：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/4e2ad710-0c9e-49f1-a303-80876712fafe.png)

MATE 外观预设

# MATE 问题

进入运行级别 3 的行为是困难的，但并非不可克服，因为我们知道在面对这个屏幕时要尝试`startx`。根据您下载 MATE 的日期，您可能会遇到这个问题，也可能不会。这是服务器的标准运行级别，但您可能希望在 Kali Linux 中同时使用 GUI 和 CLI 工具。

# Xfce 桌面

Xfce 桌面是一个轻量级的桌面环境，是 Wolf Halton 的个人最爱。他在写本书第一版时使用 Xfce 来节省资源。他今天正在使用它作为高度定制和古怪的 Ubuntu Studio 操作系统的一部分，以便在本书的当前版本上工作。

这个桌面环境的缩写发音为**ex-eff-cee-ee**。它曾经是 X-Forms Common Environment 的首字母缩略词，但现在它使用的是 GTK 工具包而不是 X-Forms。Xfce 最初设计为 CDE 的替代品，CDE 是 1996 年的 Unix Common Desktop Environment，当时后者仍然是专有的。一些人可能认为 Xfce 在外观和感觉上有点过时。默认的 Xfce 桌面显示在以下截图中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/87c38c87-4043-4b7a-bef8-d6248d37044a.png)

Xfce 默认桌面

底部的工具栏是最小化但完全功能：

+   第一个按钮最小化所有窗口，显示桌面

+   第二个按钮打开命令行终端仿真器

+   第三个按钮打开 Thunar 文件管理器

+   第四个按钮打开 Firefox 网络浏览器

+   第五个按钮是应用程序查找器

+   第六个按钮是活动用户的家目录

以下截图显示了打开`root`家目录、终端仿真器、浏览器窗口和应用程序查找器的结果。`application`文件夹中有一个应用程序菜单，与左上角的应用程序按钮相同：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/8610fe9f-d1d2-4bff-a0f4-a2a5b64e92df.png)

Xfce 下部工具栏示例

改变个性化最明显的方法是将桌面更改为您选择的图像。有四个选项卡可以对桌面环境进行更深入、更微妙的更改，并使 Xfce 成为您自己的。以下截图显示了这四个选项卡中的三个：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/c340066f-fc18-49be-9cd9-a96d5e01569f.png)

Xfce 外观选项

# Xfce 问题

Xfce 桌面没有真正的显示停止器。也许这是因为 Xfce 是一个非常稳定的桌面环境；它从未带来任何问题。

# 选择外观和感觉

外观和感觉是主观的。没有人有完全平均的气质。用例将在您选择硬件和使您满意的自定义程度方面发挥重要作用：

+   如果您总是从 USB 存储设备或光盘运行，最好使用 Gnome 3 桌面，因为它经过开发人员最多的测试，或者使用 Xfce 桌面，因为它使用的资源最少

+   如果您要安装到虚拟机，您可能希望使用 Xfce 或 LXDE 桌面环境，因为虚拟机往往具有较低的资源级别

+   如果您要加载到专用服务器或笔记本电脑，您可能具有最高的资源级别，并且不太可能经常破坏操作系统，因此选择 E17 或 KDE 桌面，因为它们是最可定制的

+   如果您已经对任何桌面环境有深入的了解，您可能应该选择那个，因为它为您提供了舒适的使用体验

# 配置 Kali 成为您的日常驱动程序

Kali 自从首次开发以来已经走了很长的路。它最初是 Linux 的精简版本，旨在作为 VM 或从 USB 或 CD 运行。您的常规计算工具只是在那里。您会注意到 Kali 旨在在 root 帐户下运行。在安装过程中，与大多数其他发行版不同，安装中没有正常的设置用户帐户部分。当然，这通常是一个很大的安全禁忌。普通用户不应该具有系统的根级访问权限。今天，在大多数 Linux 发行版上，root 帐户基本上已禁用了交互式登录，并且系统管理的指令告诉您使用`sudo`来访问系统级文件。基于 GUI 的管理应用程序要求用户`sudo`并使用其凭据打开和保存对系统的配置更改。这对于正常使用的系统设置是一个很好的主意，但是在渗透测试中，您需要直接访问硬件和系统级别。在每个命令前使用`sudo`并不是一个有用的选项。

下一个截图是 Bo 编写本章时所用计算机的桌面。由于他正在撰写文档，查找互联网上的信息并检查电子邮件，因此他使用了基本的非特权用户帐户。请注意他的个人照片在桌面上。在系统上使用多个帐户（特别是其中一个帐户是 root 时），您可能希望为每个帐户设置不同的壁纸。这有助于提醒您登录方式，并防止您在 root 帐户中做一些愚蠢的事情。这也有助于保护您免受互联网上的恶意攻击：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/7d7fa317-65b1-403a-8605-6aaa4bedcf23.png)

Bo Weaver 的桌面

以下截图是此计算机的根桌面。当您使用此壁纸时，您会毫无疑问地知道自己在哪里：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/5bf214ec-524e-48c5-b7e8-105544e9f653.png)

Bo Weaver 的根桌面

# 用户帐户设置

在设置和运行 Kali 之后，您需要将普通用户帐户添加到系统中，使其成为您的日常驱动程序。大多数 Kali 发行版未加载用户管理器应用程序。它们可以安装，但最简单的方法，也适用于所有发行版的方法是使用终端中的老式`useradd`命令，如下一个截图所示。

此用户和所有其他用户进程的用户是 root：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/8bf502ef-63fa-441a-a4e0-b2f9bb82a804.png)

添加管理员用户

为了解释命令选项的含义，以下是一个示例，添加用户`fred`并设置密码为`Password`。请确保将用户名和密码更改为您的唯一帐户；我们不再允许`fred`进入我们的网络。

```
useradd -m -U -G sudo -p LamePassword fred  
```

我们在这个命令中使用的标志如下：

+   `-m`：在`/home`目录中为用户设置一个主目录。

+   `-U`：此标志为新用户设置了一个唯一的用户组，组名与用户名相同。

+   `-G sudo`：这将新用户添加到不止他自己的组。您希望您的普通用户帐户具有 sudo 访问权限，因此我们将用户添加到 sudo 组。

+   `-p LamePassword`：此标志为帐户设置了密码。请不要在这里使用愚蠢的东西。

+   `fred`：我们用新用户名结束命令。

+   接下来，只需按下*Enter*键，新用户帐户就设置好了。

有几个应用程序你需要加载才能使用桌面：要么是 LibreOffice 或 Apache OpenOffice，还有一个邮件客户端。Kali 的存储库中没有 OpenOffice，所以在这个演示中我们将使用 LibreOffice。Mozilla Thunderbird 是一个有用的邮件/日程安排工具。我们将在演示中使用它。Kali 默认没有安装邮件客户端，因为它是设计为在 root 下运行的。警告：永远不要在 root 账户下打开邮件。坏事可能会发生！

首先，确保你的软件包列表是最新的，所以运行这个命令：

```
apt-get update  
```

接下来，安装 OpenOffice 和 Thunderbird：

```
apt-get -y install libreoffice thunderbird  
```

或者，使用这个：

```
apt install libreoffice thunderbird  
```

`-y`标志将回答是安装软件包。在这一点上，喝杯咖啡或者出去走一小段路，因为这将需要一些时间来安装。第二个命令做同样的事情，但它让我们查看要安装和升级的软件包。第二个命令的结果的摘要显示在下一个截图中。这个截图显示了安装的主要部分之间的波浪线，以适应所有这些实际存在的三个屏幕详细信息的图像窗口。有数十个建议的软件包，你可以忽略这些，只需按下*Y*键。你也可以稍后返回，从终端窗口中复制所有建议的软件包名称，并运行这个命令：

```
apt install [all those names you just copied]  
```

将它们添加到你的安装中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/0066fc57-4c8d-48ba-9437-f95051cd4b1a.png)

安装邮件客户端和办公应用程序

所以，现在你准备好了。将你的 root 桌面更改为某种提醒你已经以 root 身份登录的东西。退出 root，在登录界面输入新用户的凭据。一旦你登录，你现在拥有一个具有正常用户账户完整安全性的运行账户。使用这个账户，你可以安全地浏览互联网，阅读邮件，以及进行其他你通常在系统上做的事情。当你需要进行一些小的渗透测试时，只需以 root 身份登录。

# 总结

在本章中，我们为你简要介绍了当前桌面环境的选项，并对使用它们进行了一些理由。大多数定制发生在笔记本电脑和台式机上的裸金属安装上。最少的定制将发生在活动光盘和 USB 存储器使用情况下，因为资源有限，更改不会被保留。


# 第二章：磨刀

一个工匠只有他的工具那么好，而工具需要设置和维护。由于您已经有了对您感兴趣的 Kali Linux 发行版的想法，本章将帮助您设置和配置平台的个人版本。Kali Linux 是多才多艺的，可以用于多种用途。

当您首次决定使用 Kali Linux 时，您可能还没有考虑到各种常见和不常见的用途。本章向您介绍了最适合您的 Windows 渗透测试要求的工具，我们用来确保测试结果准备和呈现正确的文档工具，以及您需要操作这些工具的 Linux 服务的详细信息。许多书籍，包括 Wolf Halton 撰写的有关渗透测试的第一本书，将其章节按照 Kali 安全桌面中的子菜单顺序排列。我们发现这不够直观。我们将所有设置放在开头，以减少第一次使用 Kali 用户的困惑，并且因为某些事情，例如文档工具，必须在您开始使用其他工具之前理解。本章标题为*磨刀*的原因是因为一个劣质的工匠，或者一个经验不足的黑客，总是责怪他的工具，而一个熟练的工匠会花更多时间准备工具，以便他们的工作更快进行。

在 Kali Gnome3 桌面菜单中，有一个名为**收藏夹**的子菜单，在您第一次运行时，这些工具将是 Kali Linux 的创建者认为对于工作中的安全分析师来说最不可或缺的武器。在本章中，安装和设置后，我们将向您展示我们最常使用的工具。这些可能成为您的收藏夹。以下屏幕截图显示了默认的收藏夹菜单。默认值如下：

+   **Firefox ESR**：Web 浏览器

+   **终端**：Bash 终端仿真器

+   **文件**：类似于 Windows 资源管理器的文件管理器.exe

+   **metasploit framework**：利用框架的黄金标准

+   **armitage**：Metasploit 的图形用户界面前端

+   **burpsuite**：Web 应用攻击代理

+   **beef xss framework**：跨站脚本工具

+   **faraday IDE**：支持 70 多种工具的多用户渗透测试环境，包括 Metasploit、Burpsuite、终端等

+   **Leafpad**：文本编辑应用程序

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/c4135a04-dc0a-4b22-a487-faccef6d50f3.png)

Kali Linux 上的许多系统服务与基于 Debian 平台的 Ubuntu 和其他 Linux 服务器上的服务相同，但由于有使用客户端/服务器模型的安全工具，因此需要提前启动一些服务才能成功运行测试。

在本章中，我们将学习以下主题

+   将 Kali Linux 安装到加密的 USB 驱动器上

+   从 Live DVD 上运行 Kali

+   安装和配置应用程序

+   设置和配置 OpenVAS

+   报告测试

+   在 Kali Linux 上运行服务

# 技术要求

+   您选择的 Kali 发行版（Gnome、KDE、LXDE 或 MATE）

+   一个至少 16GB 大小的空白 USB 驱动器。

+   具有手动引导选项的笔记本电脑或工作站

# 将 Kali Linux 安装到加密的 USB 驱动器上

像大多数有 IT 部门的组织中发现的那样安全的网络环境对安全工程师提出了一些挑战。公司可能有一个特定的批准应用程序列表。防病毒应用程序通常是从中央位置管理的。安全工具通常被错误地归类为邪恶的黑客工具或恶意软件包。许多公司对在公司计算硬件上安装任何不是 Microsoft Windows 的操作系统都有防御性规定。

为了增加挑战，他们禁止在公司网络上使用非公司资产。您将发现的主要问题是，针对 Windows 编写的经济实惠的渗透测试工具非常少，而少数有 Windows 版本的工具，如**Metasploit**，往往会与较低级别的操作系统功能发生冲突。由于大多数公司笔记本电脑必须在系统上运行反病毒软件，因此您必须在 Metasploit 的目录上进行一些严重的例外处理。反病毒软件将隔离所有病毒和随 Metasploit 一起提供的工具。此外，本地入侵保护软件和本地防火墙规则会引起问题。这些操作系统功能和安全附加组件旨在防止黑客攻击，而这正是您准备要做的事情。

支付卡行业数字安全标准（PCI DSS 3.2.1）要求处理付款数据的任何 Windows 机器或与处理付款数据的任何机器在同一网络上的机器都应该打补丁，运行防火墙，并在其上安装反病毒软件。此外，许多公司的 IT 安全政策规定，任何终端用户都不能在没有处罚的情况下禁用反病毒保护。

将 Windows 机器用作您的渗透测试机器的另一个问题是，您可能会不时地进行外部测试。为了进行适当的外部测试，测试机器必须连接到公共互联网。将 Windows 机器悬挂在公共网络上，并关闭所有安全应用程序是不明智的。这样的配置可能在将其连接到互联网后的 20 分钟内就会被感染蠕虫。

那么答案是什么呢？一个加密的可启动 USB 驱动器，加载了 Kali Linux。在 Kali 的安装屏幕上，有一个选项可以将 Kali 安装到一个带有所谓**持久性**的 USB 驱动器上。这使您能够将 Kali 安装到 USB 驱动器上，并且可以将文件保存到 USB 中，但该驱动器没有加密。通过在 Linux 机器上挂载 USB 驱动器，您的文件就可以被获取。这对于尝试 Kali 来说是可以的，但您不希望真正的测试数据漂浮在一个 USB 驱动器上。通过对 USB 驱动器进行正常的全面安装，可以在磁盘上使用全磁盘加密。如果 USB 被入侵或丢失，数据仍然是安全的。

在本章中，我们将把 Kali 安装到一个 64GB 的 U 盘上。您可以使用更小的 U 盘，但请记住您将从测试中收集数据，即使在一个小型网络上，这也可能会产生大量数据。我们几乎每天都在进行测试，所以我们使用了一个 1TB 的 USB 3.0 驱动器。64GB 的驱动器对于大多数测试来说是一个不错的大小。

# 安装的先决条件

在本章中，您将需要一个 64GB 的 U 盘，一个刻录了 Kali 的 DVD 和一台具有 DVD 播放器和 USB 启动功能的机器。您可以在[`www.kali.org/downloads/`](https://www.kali.org/downloads/)下载 Kali，并查找下载您想要的版本的链接。以下截图显示了下载页面的一部分：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/d54c751f-8152-4dbe-be12-320b1cf1fdc8.png)

由于我们在第一章中向您展示了几种 Kali 的发行版，*选择您的发行版*，以下截图显示了当您一次下载所有可用的 Kali Linux ISO 文件时会发生什么。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/3b8ead17-ade0-43c1-91a3-50122f010a8b.png)

# 启动

准备好后，将 DVD 和 U 盘插入您的机器。

确保在启动机器之前插入 U 盘。您希望机器在启动时看到 U 盘，这样安装程序在安装过程中就能看到它。

现在启动机器，您将看到以下屏幕。从菜单中选择图形安装。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/55759b88-f2bf-49cc-ae47-96d90bba7479.png)

如果选择第六行的安装命令，还可以使用文本安装程序进行安装。

# 配置安装

如果您曾经安装过任何 Linux 发行版，安装的第一部分应该看起来非常熟悉。您将看到一系列用于设置国家、语言和键盘的屏幕。为您的地区和选择的语言设置这些。通常安装程序会自动发现键盘，您可以单击所选的键盘。在美国，默认选择是标准英语和标准键盘映射。进行适当的更改，然后在每个页面上单击“继续”按钮。

在进行这些配置之后，您将获得以下窗口以提供**主机名**。给它一个独特的名称，而不是默认的名称。这在以后使用保存的数据和截图时会很有帮助。如果有几个人使用 Kali，而所有机器都被命名为 Kali，那么数据来自哪里可能会让人感到困惑。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/6503b69c-e4bb-42aa-89b8-6d73ba803c20.png)

下一个截图要求输入域名。使用您或您公司控制的真实域名。不要使用虚假的域名，如`.local`或`.localdomain`。如果您在互联网上做生意，或者是一名学生并希望成为一名安全专业人员，请使用一个合适的域名。这样可以更容易地跟踪路由和跟踪数据包。域名很便宜。如果域名属于您的雇主，而您不能只使用他们的域名，请请求一个子域，比如`testing.mycompany.com`。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/5cae43e1-438d-45a3-afd8-81704cef0cad.png)

在下一个窗口中，您将被要求提供 root 密码。给它一个*强大*的密码。密码越长越复杂，越好。请记住，经过几次测试，您的网络密钥将存储在这台设备上。与大多数计算机操作不同，在渗透测试期间，您将使用 root 帐户，而不是普通用户帐户。您需要能够打开和关闭端口，并完全控制网络堆栈。

标准的 Kali 安装不会给您添加标准用户的机会。如果您在笔记本电脑上安装 Kali，并且除了测试之外还使用这台笔记本电脑进行其他事情，请创建一个标准用户并赋予它`sudoer`权限。您永远不希望养成使用您的`root`帐户来浏览互联网和发送电子邮件的习惯。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/d5023e29-fc95-4d86-8af9-c093428f631b.png)

接下来，您将被要求选择您的时区。根据地图上的位置或下拉菜单设置，或选择您的 UTC 偏移。Kali Linux 上的许多工具会输出时间戳，这些时间戳是您所做的事情的法律证据，以及您所说的时间。 

# 设置驱动器

下一步是设置驱动器，对其进行加密，并对其进行分区。下一个对话框将要求您选择此安装的分区类型。

1.  选择引导-使用整个磁盘并设置加密的 LVM。这将完全加密整个驱动器，而不仅仅是加密`/home`目录。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/e37ff9d7-f685-479e-86d3-9099eb4c5c03.png)

在下一个窗口中，您将被要求选择要安装 Kali Linux 的磁盘。

警告。小心选择 USB 驱动器而不是本地驱动器。如果选择本地驱动器，将会擦除该驱动器上的操作系统。注意：在接下来的窗口中，您可以看到 USB 驱动器和 VMware 虚拟磁盘。虚拟磁盘是用于此演示的虚拟机的硬盘。

1.  选择 USB 驱动器并单击“继续”。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/5a3db1ce-5fdf-4700-9556-22c54e329e5c.png)

1.  在下一个窗口中，您将被要求如何对驱动器进行分区。选择默认选项并单击“继续”。

接下来，您将被要求保存分区信息，并开始分区过程。

当您单击“继续”时，磁盘上的所有数据都将丢失。单击“是”，然后单击“继续”。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/beb651e7-c44c-4a88-9e08-881ce49ef4ee.png)

这将启动磁盘加密和分区过程。首先，驱动器将被完全擦除和加密。这将需要一些时间。喝杯咖啡，或者更好的是，出去散散步。1TB 驱动器需要大约 30 小时才能加密。64GB 驱动器需要大约 30 分钟。

在下一个窗口中，您将被要求为驱动加密创建一个密码。您在启动 Kali 时将使用此密码。请注意术语**密码**。

使用一些长而易于记忆的东西：一首歌的一行歌词或一句诗或引用！越长越好！*玛丽有一只小羊，牵着它去了城里*。即使这个短语中没有数字，John the Ripper 也需要一个多月的时间才能破解。

接下来，您将被要求确认这些更改。选择**完成分区并将更改写入磁盘**，然后点击**继续**。

现在系统将开始分区过程。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/c7c7ab9a-6e7b-4b0c-8257-f230667c3369.png)

分区过程完成后，系统安装将开始。USB 是一个慢协议，甚至与 ATA 硬盘相比，所以现在是暖茶的时候了。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/f517e49b-6a7b-4766-863a-c2e80aa84fe3.png)

接下来，您将被问及是否要使用网络镜像。在这上点击**是**！这将选择靠近您位置的存储库镜像，并在以后更新系统时加快更新速度。

您的安装过程现在将完成，并且将要求您重新启动系统。在重新启动之前，请务必删除安装光盘。

# 启动您的新安装的 Kali

现在我们准备启动 Kali。将 Kali USB 驱动器插入计算机并启动。在启动过程开始时，您将有能力手动选择启动驱动器。具体的按键将取决于您的计算机类型和制造商。无论您的计算机使用什么过程，您将得到一个可用启动驱动器的菜单。选择 USB 驱动器并继续。系统启动时，将出现一个要求输入密码的屏幕。这是您在安装过程中选择的密码。这不是 root 登录密码。输入密码并按*Enter*键。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/6798339a-f6b8-492e-a3a2-47dfe6241bc1.png)

这将从现在未加密的驱动器启动系统的实际启动过程。一旦系统启动，您将看到以下登录屏幕。以下屏幕是您安装 Kali Linux 的 e17 版本后看到的。 

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/35d0a6e4-5ce5-478c-a393-7a069b88ec2d.png)

在 e17 版本中，您可以使用 root 凭据登录到终端模拟器屏幕，然后输入`startx`打开 GUI。

以下屏幕截图是您安装标准 Gnome3 版本后看到的。

在标准的 Gnome3 GUI 安装中，您将看到一个**GUI 桌面管理器**（**GDM**）登录截图如下：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/9cd78881-f576-4a7b-94a1-363dd130f288.png)

**黑客技巧**：

在我们继续之前，我们建议您只在您已经获得授权测试的系统上使用这些工具，或者您个人拥有的系统上使用这些工具。在未经授权测试的计算机上使用这些工具是违反各种联邦和州法律的。当您被抓到时，您将被监禁。黑客的判决往往是非常长的。

获取公司接收的测试豁免的个人副本，以允许他们测试客户的网络和系统。此文档应包含测试的日期和时间以及要测试的 IP 地址和/或网络。这是您测试的范围。这个文档是您的*免于监禁的牌*。没有这个文档不要进行测试。

现在说完了，让我们登录并继续设置。以下屏幕截图显示了 Gnome3 桌面。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/f4d62260-4603-4b55-af62-0aa0b199d702.png)

第一次登录时，请检查一切是否都是最新的。由于这是一个滚动发行版，几乎总会有一些更新。有几种方法可以进入终端仿真器：

1.  通过单击左上角的应用程序菜单栏中的终端窗口。转到应用程序|常用应用程序|系统工具|终端。

1.  在相同的应用程序菜单中，转到应用程序|收藏夹|终端。

1.  您可能会注意到收藏夹菜单也显示为桌面左侧的按钮栏。单击终端按钮。

1.  在裸机安装（而不是虚拟机安装）中，您可以按*Alt* + *F2*打开运行对话框，然后键入`gnome-terminal`。

任何一种方法都应该打开终端或命令行窗口。键入以下内容：

```
root@kalibook :~#  apt-get update  
```

这将刷新更新列表并检查新的更新。接下来，运行：

```
root@kalibook :~#  apt-get -y upgrade  
```

这将作为`-y`自动回答升级的升级过程。系统将升级所有应用程序。如有必要，重新启动。

# 从 Live DVD 运行 Kali

从 Live Disk 运行 Kali Linux 最适合进行取证或恢复任务。Live Disk 不会向计算机的硬盘写入任何内容。某些工具，例如**OpenVAS**，根本无法工作，因为它们必须进行配置并且文件更新必须保存。您无法从 DVD 上执行此操作。

要从 DVD 运行 Kali，只需将光盘放入您正在测试的机器中并从中启动。您将看到以下屏幕。这是您在本章的前一节中选择图形安装程序的屏幕。我们现在将讨论选项。请注意，从 DVD 启动现场有几个选项。

+   从第一个选项启动将加载具有工作网络堆栈的 Kali。您可以使用此选项通过网络运行许多工具。此模式的最佳用途之一是恢复死机的机器。在操作系统驱动器死机后，它可能允许您恢复崩溃的机器。无论您对 fsck 和其他磁盘实用程序做了什么，它都不会自行恢复。如果您从现场 DVD 启动，然后运行 fsck，很可能可以使驱动器恢复到足够的状态以从中复制数据。然后，您可以使用 Kali 将数据从驱动器复制到网络上的另一台机器。

+   从第二个选项启动将启动 Kali，没有运行的服务和没有网络堆栈。当系统真的出现问题时，这个选项很好。也许它被闪电击中，网络接口卡受损。您可以在此模式下执行上述操作并将数据复制到已挂载的 USB 驱动器中。

+   第三个选项是取证模式。使用此选项启动时，它会尽量不触及机器本身。不会启动任何驱动器，并且与正常启动不同，内存不会完全刷新。这允许您捕获上次启动的旧内存，并允许您对任何驱动器进行取证复制，而实际上不触及数据。您没有工作的网络堆栈或运行的服务。

+   从第四和第五个选项启动需要您将 Kali 安装到 USB 驱动器上并从 USB 驱动器运行它。当您从 USB 启动时，您将看到相同的屏幕，但您将选择其中一个选项。有关带持久性选项的 USB，请参阅列出的链接（[`kali.org/prst`](http://kali.org/prst)）以获取出色的教程。

+   如果您熟悉 Linux 命令行，您可能需要第六个选项。这是**Debian Ncurses**安装程序。它具有图形安装程序的所有功能，但缺少图形安装程序的现代外观。您还可以使用此安装程序以选项完全安装到加密的 USB。步骤都是一样的。

+   **图形安装**用于直接安装到硬盘，并且，如我们的演示所示，您还可以使用它来对 USB 或闪存驱动器进行完全安装。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/a1c3f81c-885b-4d53-bcc9-2c41f390b6d7.png)

# 安装和配置应用程序

大多数你需要的东西都预装在 Kali 上。如果您在特定领域使用 Kali，Kali 在[`tools.kali.org/kali-metapackages`](https://tools.kali.org/kali-metapackages)页面提供了特定类别工具的列表，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/4962e68e-2e35-47ba-996a-27e95db07114.png)

这是一个有用的数据源，但它可能会让你的生活变得有点复杂，因为它会迫使你做出选择。我们发现了一些有用的应用程序，这些应用程序在基本安装中没有加载。我们还将设置和配置 OpenVAS，用作我们的漏洞扫描器。

# Gedit- Gnome 文本编辑器

Kali 默认的文本编辑器是**Leafpad**。这是一个非常轻量级的文本编辑器。Kali 的桌面是基于 Gnome 的，Gnome 文本编辑器**Gedit**是一个更好的编辑器。安装：

```
root@kalibook :~#  apt -y install gedit  
```

安装完成后，您将在常用应用程序|附件下找到它。

# Geany-跨平台代码 IDE

Geany 是 Wolf 最喜欢的文本编辑器/集成开发环境。它具有很强的字符串编辑能力，以及自动代码标签闭合和高亮功能。最后，它可以在从 Kali 到 Windows 的任何平台上运行。拥有一个在您接触的所有平台上都能够运行的编辑器，可以节省时间。来自 Geany 项目网站（[`www.geany.org/Main/About`](https://www.geany.org/Main/About)）的一些其他功能如下：

+   构建系统来编译和执行您的代码

+   代码折叠

+   代码导航

+   构建完成/片段

+   符号名称自动完成

+   支持的文件类型包括 C、Java、PHP、HTML、Python、Perl 等

+   符号列表

+   简单的项目管理

+   插件接口

安装：

```
root@kalibook :~#  apt -y install geany  
```

安装完成后，您将在常用应用程序|编程下找到它。

以下截图显示了 Geany 在 Kali Linux 上的实现。请注意代码高亮和包含的终端以显示输出。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/db1b7e37-3b67-4f22-8059-ceece22f539b.png)

# Terminator-多任务终端仿真器

这是 Bo 最喜欢的终端应用程序。您可以将屏幕分成几个窗口。当同时运行多个 SSH 会话时，这将成为一个很大的帮助。它还具有广播功能，您可以同时在所有窗口中运行相同的字符串。以下是来自终结者网站（[`gnometerminator.blogspot.com/p/introduction.html`](https://gnometerminator.blogspot.com/p/introduction.html)）的一些主要功能：

+   将终端排列成网格

+   标签

+   拖放重新排序终端

+   键盘快捷键

+   GUI 首选项编辑器，可让您保存多个布局和配置文件

安装：

```
    root@kalibook :~#  apt -y install terminator

```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/6ace2493-4137-4685-a8a7-8a86dfcfe1a2.png)

# Etherape-图形协议分析工具

这是一个很棒的视觉被动/主动网络嗅探工具。它非常适用于嗅探 Wi-Fi 网络。它会显示服务运行的位置，还可以显示用户正在进行可疑的比特流下载等行为，这些行为在大多数公司网络上都是不被允许的。

安装：

```
root@kalibook :~#  apt -y install etherape 
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/ea29ab45-3dae-4af3-9d76-bcdf7e81e443.png)

# 设置和配置 OpenVAS

侦察就是一切，因此一个好的漏洞扫描器是必不可少的。Kali 以前是预装了 OpenVAS 的。现在你必须安装 OpenVAS。

安装：

```
root@kalibook :~#  apt -y install openvas  
```

在使用之前必须进行配置和更新。幸运的是，Kali 带有一个有用的脚本来设置这一点。这可以在应用程序|漏洞分析|openvas 初始设置下找到。单击这个将打开一个终端窗口并为您运行脚本。这将为 SSL 设置自签名证书并下载最新的漏洞文件和相关数据。它还将为系统上的管理员帐户生成一个密码。

确保保存此密码；您将需要它进行登录。您可以在第一次登录后更改它。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/e55b2b0a-cd7c-46d6-89c7-00e9aaa2ec9e.png)

Kali 还配备了一个设置脚本，用于检查服务和配置。如果出现问题，它将提供有关问题的帮助信息。此脚本可以在应用程序 | 系统服务 | openvas check setup 中找到。

单击此按钮，将打开一个终端窗口并运行脚本。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/c5f0608a-2e64-4709-97a2-4ba714e9effc.png)

脚本结果如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/e699f663-7946-450e-8a2e-ab6fa31b73dd.png)

请注意，此检查显示服务的运行端口。检查显示警告，表明这些服务仅在本地接口上运行。这对您的工作来说是可以接受的。在某些时候，您可能会发现将 OpenVAS 服务器运行在其他机器上以提高扫描速度是有用的。

接下来，我们将登录到 Greenbone web 界面，检查 Openvas。

1.  打开浏览器，转到`https://localhost:9392`。您将看到一个自签名证书的安全警告；接受它，您将看到一个登录屏幕，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/7ca0eabf-1bf7-4880-8dd7-132093d8a4ca.png)

1.  您将使用用户名`admin`和在设置期间生成的非常长且复杂的密码登录。别担心，一旦登录，我们就会更改密码。登录后，您将看到以下页面。

1.  现在转到 Administration | Users 选项卡，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/03024b05-fe18-42d1-b450-ec08560462db.png)

这将带您到用户管理页面。

1.  单击名称`admin`旁边的扳手链接；这将打开管理员用户的编辑页面。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/ba6d5c22-6d74-4507-98e5-d3375e82b71f.png)

1.  将使用现有值的单选按钮更改为空字段；添加新密码并单击保存按钮。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/499c9aa8-48e1-4367-91fa-b908be5c496a.png)

我们现在已经完成了 OpenVAS 的设置，并准备做一些真正的工作。

# 报告测试

清晰的文档有助于报告您的工作。我们使用两种文档工具来保持文档的组织：

+   KeepNote

+   Dradis

文档组织者不仅仅是一个被吹捧的文本编辑器或弱的文字处理器。正确的文档需要有组织的文件结构。当然，Windows 安全分析师可以创建一个让他们在 Kali Linux 中组织文档的文件夹结构，就像他们在 Windows 工作站上一样。文档组织应用程序内置了这些功能，并且使用它们可以减少丢失或意外递归文件夹的机会。更容易跟踪您的调查文档。您还可以为目录结构创建模板，以便您可以标准化结构，这也会让您的工作更容易。

# KeepNote - 独立文档组织者

**KeepNote**是一个更简单的工具，如果您是独自工作，它就足够了。要找到 KeepNote，打开应用程序菜单，然后点击应用程序 | 常用应用程序 | 办公 | KeepNote。下面的截图显示了一个类似于记录短测试的 KeepNote 设置。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/60e89dca-d3dd-447f-90c0-dd54ccbed480.png)

**黑客笔记**：

要编辑图像，如前面的截图所示，打开终端并键入：

`**root@kalibook: ~# apt install gimp**`

`**然后将图像从您的工作图像目录拖到 keepnote 目录中。**`

# Dradis - 基于 Web 的文档组织者

**Dradis**是一个 Web 应用程序，可用于与团队共享文档。Dradis 的默认 URL 是`https://127.0.0.1:3004`。该应用程序可以托管在远程安全服务器上，这是 Dradis 的最佳功能。以下截图来自[`dradisframework.org`](http://dradisframework.org)。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/0dade2b6-e6ba-45ea-8b9f-29d7e8028076.png)

# 在 Kali Linux 上运行的服务

当您需要时，您会希望启动几个服务。在 Windows 和 Linux 中，服务的一般用途是在计算机启动时启动它们。除非出现问题，大多数管理员很少花时间管理服务。在 Kali 系统中，您倾向于在实际进行安全分析任务时关闭工作站，并且您肯定不希望您在工作站上拥有的安全工具，如 OpenVAS 或 Metasploit，可以通过互联网访问。这意味着您会在需要时启动它们，并在不使用它们时关闭它们。

您可以从应用程序菜单—应用程序|系统服务中找到启动和停止 Kali 服务的命令

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/3da5ca96-3a79-40a0-b829-fece3b0daac0.png)

另一种处理服务的方法是在命令行上使用`systemctl`。例如，考虑 HTTP（Apache2）。有几个服务选项：

+   **开始**: 这将启动 Apache web 服务器并显示**进程 ID**（**PID**）*.*

+   **状态**: 显示服务器的状态。它是启动的吗？它是关闭的吗？它卡住了吗？

+   **重新启动**: 将服务器关闭并在不同的 PID 上重新启动。如果服务器卡住或者您已更改服务器依赖的网络进程，请使用此选项。

+   **重新加载**: 重新读取配置。当您对配置进行轻微更改时，请使用此选项。

+   **停止**: 关闭 web 服务器。

以下屏幕截图显示了对 apache2 web 服务器进行状态请求的`apache2ctl`和`systemctl`的比较。可能可以写一本关于强大的`systemctl`命令的整本书。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/0c869f80-c4d3-4377-9aa6-9ab958f99749.png)

# 总结

本章向您展示了两种设置 Kali Linux 的方法，以便您可以使用公司发放的 Windows 笔记本电脑或任何其他笔记本电脑，以便更好地发挥 Kali Linux 的性能，而不必为 Kali 专门购置新设备。大多数企业不允许您在计算机上进行双重启动，并且在虚拟机上运行 Kali 会限制 Kali 安装的资源。此外，本章向您展示了我们使用的两种报告工具，以及每种工具最合适的情况。我们向您展示了如何首次设置 OpenVAS。我们还向您展示了如何在 Kali Linux 上运行服务。


# 第三章：信息收集和漏洞评估

有一个误解，认为所有的 Windows 系统都很容易受到攻击。这并不完全正确。几乎任何 Windows 系统都可以加固到需要花费太长时间才能利用其漏洞的程度。在本章中，你将学习如何对你的 Windows 网络进行足迹识别，并在坏人之前发现漏洞。

你还将学习调查和映射你的 Windows 网络，找到易受攻击的 Windows 系统。在某些情况下，这将增加你对前 10 个安全工具的了解；在其他情况下，我们将向你展示全新的工具来处理这类调查。

我们将在本章中涵盖以下主题：

+   对网络进行足迹识别

+   Nmap 命令选项的注释列表

+   使用 OpenVAS

+   使用 Maltego

+   使用 KeepNote

# 技术要求

要跟着本章进行学习，你需要以下内容：

+   运行的 Kali Linux 版本

+   一些需要扫描的网络上的 Windows 主机

# 对网络进行足迹识别

没有一张好地图，你就无法找到路。在本章中，我们将学习如何收集网络信息并评估网络上的漏洞。在黑客世界中，这被称为**足迹识别**。这是任何正当的黑客行动的第一步。这是你将节省时间和大量头痛的地方。

没有对目标进行足迹识别，你只是在盲目射击。任何优秀的渗透测试人员工具箱中最重要的工具是你的**心态**。你必须有狙击手的心态。你要了解你的目标习惯和行为。你要了解目标所在网络的流量流向。你要找到目标的弱点，然后攻击这些弱点。搜索和摧毁！

为了进行良好的足迹识别，你必须使用 Kali 提供的几个工具。每个工具都有其优势，并从不同角度观察目标。对目标的多个视角，可以制定更好的攻击计划。

足迹识别将根据你的目标是外部公共网络上的还是内部局域网上的而有所不同。我们将涵盖这两个方面。

对公共网络上的机器进行扫描和使用这些工具，如果你没有书面许可访问，那就是一种联邦犯罪。

在这本书中，对于大多数 Kali Linux 实例，我们将使用专门为本书构建的在**VMware**和**Oracle VirtualBox**上运行的虚拟机。我们日常使用的 Kali 实例都经过了相当大的定制，涵盖这些定制需要整本书的篇幅。对于外部网络，我们将使用互联网上的几台实时服务器。

请尊重并不要攻击这些地址，其中两个是 Bo 的个人服务器，还有几个在亚特兰大云技术服务器集群中。

请再次阅读前面的说明，并记住你没有我们的许可攻击这些机器。*如果你做不到，就不要犯罪*。

# Nmap

谈论网络就不能不谈**Nmap**。Nmap 是网络管理员的瑞士军刀。它不仅是一个很好的足迹识别工具，也是任何系统管理员都可以拥有的最好和最便宜的网络分析工具。它真的是网络分析的瑞士军刀：

+   这是一个检查单个服务器端口是否正常运行的好工具

+   它可以心跳 ping 整个网络段或网络上的几台主机

+   它甚至可以在 ICMP（ping）被关闭时发现机器

+   它可以用来压力测试服务。如果机器在负载下冻结，就需要修理

Nmap 是由 Gordon Lyon 于 1997 年创建的，他在互联网上使用 Fyodor 这个名号。Fyodor 仍在维护 Nmap，并可以从[`insecure.org`](http://insecure.org/)下载。您还可以在该网站上订购他关于 Nmap 的书。这是一本很棒的书。物有所值！Fyodor 和 Nmap 黑客已经在该网站上收集了大量信息和安全电子邮件列表。由于您正在运行 Kali Linux，您已经安装了完整的 Nmap！

以下是针对 Kali Linux 实例运行 Nmap 的示例：

1.  从顶部栏的图标或单击菜单链接打开终端：应用程序 | 附件 | 终端。如果您愿意，也可以选择 Root 终端，但由于您已经以 Root 身份登录，您不会看到任何区别。

1.  在命令提示符中键入`nmap -A 10.0.0.4`。（您需要输入要测试的机器的 IP。）

1.  输出显示了 1,000 个常用端口中的开放端口。在这个例子中，没有开放端口，所以为了使其更有趣，可以执行以下操作。

1.  通过输入`/etc/init.d/apache2 start`来启动内置的 Web 服务器。

1.  启动 Web 服务器后，再次运行 Nmap 命令，如下：`nmap -A 10.0.0.4`。

1.  如您所见，Nmap 正在尝试发现操作系统并告诉 Web 服务器版本：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/bef77e3f-6617-41d5-85fc-ba47adb79259.png)

以下是在 Git Bash 应用程序中运行 Nmap 的示例，该应用程序允许您在 Windows 桌面上运行 Linux 命令。此视图显示了 Nmap 的一个很好的功能。如果您感到无聊或焦虑，并认为系统扫描时间太长，您可以按下箭头键，它将打印出一个状态行，告诉您扫描完成的百分比。这与告诉您扫描还剩多少时间不同，但它确实让您了解已经完成了多少工作：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/4ad09350-b0bb-4a78-b914-46d1be5e89a5.png)

Nmap 也作为 Windows 可安装应用程序提供给您的 Windows 机器。如果您是网络或系统管理员，您会发现这是一个很好的工具，不仅用于足迹识别，还用于系统和网络故障排除。对于其他系统，您可以在[`nmap.org/download.html`](https://nmap.org/download.html)找到 Nmap 安装程序。

# Zenmap

Nmap 附带一个名为**Zenmap**的图形用户界面。Zenmap 是 Nmap 应用程序的友好图形界面。您可以在 Kali Linux | 信息收集 | 网络扫描仪 | Zenmap 下找到 Zenmap。界面如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/f615fc31-0eb3-4922-92d3-3026c9ca0adb.png)

Zenmap 的一个很酷的功能是，当您使用按钮设置扫描时，应用程序还会写出命令行版本的命令，这将帮助您学习在命令行模式下使用 Nmap 的命令行标志。

黑客提示：

大多数黑客在 Linux **命令行界面**（**CLI**）上非常熟悉。您希望在命令行上学习 Nmap 命令，因为您可以在自动化的 bash 脚本中使用 Nmap，并创建 cron 作业以使常规扫描变得更简单。您可以设置一个 cron 作业在非高峰时段运行测试，当网络较为安静时，您的测试对网络的合法用户影响较小。

强烈扫描选项会生成一个命令行`nmap -T4 -A -v`：

+   这将产生一个快速扫描；`T`代表时间（从 1 到 5），默认时间是`-T3`。时间越快，测试越粗糙，如果网络正在运行**入侵检测系统**（**IDS**），则越有可能被检测到。

+   进行深度端口扫描，包括操作系统识别和尝试查找监听端口的应用程序以及这些应用程序的版本。`-A`代表全部。

+   最后，`-v`代表冗长。`-vv`表示非常冗长。

在下面，我们看到一个下拉框中列出了最常见的扫描方式：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/f121faf5-36e5-4aef-a775-5c5b00496fdf.png)

# 冗长性的差异

下面的三个截图展示了冗长在 OS 扫描中的差异。OS 扫描包括隐形扫描，因此`nmap -O hostname`和`nmap -sS -O hostname`是完全相同的。

通过点击拓扑标签，然后点击主机查看器按钮，您可以得到一个主机的好列表。通过点击地址，您可以看到每个主机的详细信息。请注意，地址是不同的颜色。Nmap 为您挑出了最容易的目标。绿色表示安全，而黄色和红色表示有漏洞或服务，可能会被利用。

这里的冗长版本已经稍作调整，以适应截图中的所有细节。当将`-v`或`-vv`选项添加到搜索字符串时，不同的扫描选项会有不同的增强内容。当您选择一些可能的目标时，使用`-v`或`-vv`是有意义的。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/de79df54-8481-4d03-b23b-d69be656b39a.png)

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/622a9b90-a2cf-4276-9f93-4b29907c9e03.png)

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/422cf39b-72d1-4c71-85d5-a241ee747c73.png)

# 扫描网络范围

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/767c78e7-da82-4ca1-be63-6f7089694dd5.png)

如果网络关闭了 ICMP，尝试对机器进行 ping 测试会花费很长时间。几乎和对目标机器的 UDP 端口进行 ping 测试一样长。对于任何一种情况，每台机器大约需要 75 秒每个端口。在第一种情况下，这意味着对六台机器进行 ping 测试需要 450 秒才能失败。UDP 搜索测试每台机器的端口要多得多。在标准 UDP 端口扫描中测试了 1,000 个端口，你将需要大约 21 小时才能测试 UDP。如果没有一个真正好的理由使用 Nmap 检查 UDP 端口，这不是一种具有成本效益的做法。

Zenmap 还具有一个用于比较扫描结果的很好的功能。您可以在菜单栏中找到它，路径是 Tools | Compare Results。在下面的截图中，您将看到我们对网络运行了两次扫描。当我们比较这两次扫描时，我们可以看到在第二次扫描中发现了一台新机器。在第一次扫描的结果中，它标记为红色，并显示`192.168.202.131`为关闭。当它是绿色时，它显示为开启，并显示了开放的端口和系统信息。

在下一个截图中，我们在冗长标志中添加了另一个`v`(`-vv`)并重新运行了扫描。正如我们所看到的，关于系统和扫描的更多信息被输出。

如果您有一个大型网络，只想找到 Windows 机器，以便专注于 Windows 漏洞，您可以使用以下命令运行快速扫描：`nmap -T4 -F 10.0.0.0/24`。或者，您可以选择快速扫描 Plus，输入`nmap -sV -T4 -O -F -version-light 10.0.0.0/24`。这将让您对哪些机器真正感兴趣有一个很好的了解。看起来`10.0.0.12`是一台 Windows 机器，因为五个开放端口中有四个是与 Windows 相关的。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/3a1c8e0d-5d04-483b-b796-4893f7e201bc.png)

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/3f15c054-d736-427d-ad69-23ae60371194.png)

以下截图是从命令行运行 Nmap 的结果。正如您之前看到的，Nmap 已经移植到了 Windows。如果您的公司允许，Nmap 可以通过命令行在 Windows 系统上运行，可以在命令窗口或通过 Windows PowerShell 运行。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/5a1160ad-087f-477e-acea-f7208b19eb02.png)

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/767c78e7-da82-4ca1-be63-6f7089694dd5.png)

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/ea241f4d-4774-4428-8750-495cd5bf9b55.png)

当您查看拓扑标签时，可以通过更改窗口底部控件的值来调整组的大小。通过增加**兴趣因素**来增加图形的大小。标准视图将本地主机放在组的中心，但如果单击其他主机中的一个，它将被带到中心，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/5fbcbb5e-8479-4966-9f66-a416ef504854.png)

# Nmap 命令选项的注释列表

即使 Zenmap 有一个简短，有力的下拉列表，列出了流行和有用的扫描，但您可以使用各种命令和选项来自定义扫描。

**您在哪里可以找到有关此事的说明？**

在 Linux 框中，有三个地方可以找到有关命令行应用程序的更多信息：

+   **帮助页面**：几乎所有的 Unix 和 Linux 应用程序都有一个帮助文件，您可以通过在命令行上输入应用程序名称和`-h`来访问。考虑以下示例：`root@kali-01: ~# nmap -h`。

+   **man 页面**：这是大多数现代命令行应用程序的完整手册，您可以通过在命令行上键入`man`和应用程序名称来访问。看以下示例：`root@kali-01: ~#-`。这会为您提供如何使用 Rsync 的相当好的解释，这是安全和记录的文件传输协议。man 页面的质量不一，其中许多实际上是由火箭科学家编写的，因此新手可能需要研究如何阅读手册页面才能对他们有用。Nmap 的 man 页面写得很清楚，有可理解的示例可供尝试。

+   **信息页面**：对于 Bash shell 内置命令，有一组信息页面，而不是 man 页面。要查看信息页面，请键入`info`和应用程序名称。例如，`root@kali-01: ~# info ls`将为您呈现 ls 命令的信息页面，这是 DOS 中 DIR 命令的 Linux 版本。

`-h`命令会在终端窗口中呈现内联文本，因此在信息滚动过去后，您会立即返回到命令提示符。`man`和`info`命令启动文本阅读器**Less**，因此您可以在文档上下滚动，即使您仍然在终端窗口中。要从**Less**中退出，只需按 Q 键。

Shift 键是 Linux 终端模拟器中的好朋友。

如果您想在终端窗口中上下滚动，例如，如果`-h`帮助文件比单个屏幕长，只需按住 Shift +上或下光标键。

复制和粘贴的热键序列分别是*Shift* + *Ctrl* + *C*和*Shift* + *Ctrl* + *V*。*Ctrl* + *C*意味着关闭 Bash Shell 中正在运行的应用程序，*Ctrl* + *V*则根本不起作用。

Nmap 6.47 帮助文件可以在[`nmap.org`](http://nmap.org)找到。

| **用法**：`nmap [扫描类型] [选项] {目标规范}` |
| --- |
| **目标规范**： |  |
| **例如**：`atlantacbudtech.com`，`aarrrggh.com/26`，`192.168.3.111`；`10.1-16.0-255.1-254` |
| - ` -L <inputfilename>`： | 从主机/网络列表输入。 |
| - ` -R <num hosts>`： | 选择随机目标。 |
| - ` -exclude <host1，[host2]，[host3]，...>`： | 排除主机/网络。 |
| - ` -exludefile <exclude_file>`： | 从文件中排除列表。 |
| **主机发现**： |  |
| - ` -sL`： | 列出扫描 - 只是列出要扫描的目标。 |
| - ` -sn`： | Ping 扫描 - 禁用端口扫描。 |
| - ` -Pn`： | 将所有主机视为在线 - 跳过主机发现的 ping。 |
| - ` -PS/PA/PU/PY [portlist]`： | TCP SYN/ACK，UDP 或 SCTP 发现到给定端口。 |
| - ` -PE/PP/PM`： | ICMP 回显，时间戳和子网掩码请求发现探测。 |
| - ` -PO [protocol list]`： | IP 协议 ping，而不是 ICMP ping。 |
| - ` -n/-R`： | 从不进行 DNS 解析/始终解析[默认：有时]。 |

解析 DNS 可以为您提供有关网络的更多信息，但它会产生 DNS 请求流量，这可能会提醒系统管理员有一些不太正常的事情正在发生，特别是如果他们在网络中没有使用 DNS。

这是 Nmap 带有我们的注释的帮助文件视图（您可以在[`nmap.org/book/man/`](http://nmap.org/book/man/)的手册页面找到更多信息）：

+   `--dns-servers <serv1[,serv2],...>`：指定自定义 DNS 服务器。

+   `--system-dns`：使用操作系统的 DNS 解析器。这是默认行为。

+   `--traceroute`：跟踪到每个主机的跳数路径。这只在大型，复杂，分段的网络中才有意义。

**扫描技术：**

+   `-sS/sT/sA/sW/sM`：TCP SYN/Connect()/ACK/Window/Maimon 扫描

+   `-sU`：UDP 扫描

+   `-sN/sF/sX`：TCP Null，FIN 和 Xmas 扫描

+   `--scanflags <flags>`：自定义 TCP 扫描标志

NS-ECN-nonce 隐瞒保护（这是实验性的：有关更多信息，请参阅 RFC 3540）。

+   `CWR`：拥塞窗口减小。用于指示正在减小数据包大小以在拥塞的网络条件下维持流量。

+   `ECE`：ECN-Echo 具有双重作用，取决于 SYN 标志的值：

+   如果 SYN 标志设置（1），则表示 TCP 对等方支持 ECN。

+   如果 SYN 标志清除（0），则表示在正常传输期间接收到 IP 标头中设置了拥塞经历标志的数据包（这是由 RFC 3168 添加到标头中的）。

+   `URG`：这表示紧急指针字段很重要。

+   `ACK`：这表示确认字段很重要。

+   `PSH`：推送功能。要求将缓冲数据推送到接收应用程序。

+   `RST`：重置连接。

+   `SYN`：同步序列号。

+   `FIN`：发送方不再有数据。

+   `-sI <zombie host[:probeport]>`：空闲扫描。

+   `-sY/sZ`：SCTP INIT/COOKIE-ECHO 扫描。

+   `-sO`：IP 协议扫描。

+   `-b <FTP relay host>`：FTP 反弹扫描。

端口规范和扫描顺序：

`-p <端口范围>`：仅扫描指定端口。

例如，考虑以下代码：`-p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080,S:9`

+   `-F`：快速模式-扫描比默认扫描更少的端口

+   `-r`：连续扫描端口-不随机化

+   `--top-ports <number>`：扫描<number>最常见的端口

+   `--port-ratio <ratio>`：扫描比给定的`<ratio>`更常见的端口

服务/版本检测：

+   `-sV`：探测开放端口以确定服务/版本信息

+   `--version-intensity <level>`：设置从 0（轻）到 9（尝试所有探测）的强度

+   `--version-light`：限制为最可能的探测（强度 2）

+   `--version-all`：尝试每个单独的探测（强度 9）

+   `--version-trace`：显示扫描活动的详细版本（用于调试）

脚本扫描：

+   `-sC`：等同于`-script=default`

+   `--script=<Lua scripts>`：`<Lua scripts>`是一个逗号分隔的目录，脚本文件或脚本类别列表

+   `--script-args=<n1=v1,[n2=v2,...]>`：为脚本提供参数

+   `--script-args-file=filename`：在文件中提供 NSE 脚本参数

+   `--script-trace`：显示发送和接收的所有数据

+   `--script-updatedb`：更新脚本数据库

+   `--script-help=<Lua scripts>`：显示有关脚本的帮助

+   `<Lua scripts>`是一个逗号分隔的脚本文件或脚本类别列表

操作系统检测：

+   `-O`：启用 OS 检测

+   `--osscan-limit`：将 OS 检测限制为有希望的目标

+   `--osscan-guess`：更积极地尝试猜测操作系统

时间和性能：

指定时间间隔的选项以秒为单位，或者我们可以在值后附加'ms'（毫秒），'s'（秒），'m'（分钟）或'h'（小时）。例如，`23ms`将被翻译为 23 毫秒。

+   `-T<0-5>`：设置时间模板（更高表示更快，也更吵）

+   `--min-hostgroup/max-hostgroup <size>`：并行主机扫描组大小

+   `--min-parallelism/max-parallelism <numprobes>`：探测并行化

+   `--min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <time>`：指定探测往返时间

+   `--max-retries <tries>`：限制端口扫描探测的重传次数

+   --host-timeout <time>：在此时间间隔后放弃目标

+   --scan-delay/--max-scan-delay <time>：调整探测之间的延迟

+   --min-rate <number>：每秒发送的数据包不慢于<number>

+   --max-rate <number>：每秒发送的数据包不超过<number>

防火墙/IDS 规避和欺骗：

+   -f; --mtu <val>：分段数据包（可选带有给定的 MTU）

+   -D <decoy1,decoy2[,ME],...>：用伪装物隐藏扫描

+   -S <IP_Address>：欺骗源地址

+   -e <iface>：使用指定的接口

+   -g/--source-port <portnum>：使用给定的端口号

+   --proxies <url1,[url2],...>：通过 HTTP/SOCKS4 代理中继连接

+   --data-length <num>：向发送的数据包附加随机数据

+   --ip-options <options>：发送带有指定 IP 选项的数据包

+   --ttl <val>：设置 IP 生存时间字段

+   --spoof-mac <mac address/prefix/vendor name>：欺骗您的 MAC 地址

+   --badsum：发送带有虚假 TCP/UDP/SCTP 校验和的数据包

输出：

+   -oN/-oX/-oS/-oG <file>：将扫描以正常、XML、s|<rIpt kIddi3 和 grepable 格式输出到给定的文件名

+   -oA <basename>：同时以三种主要格式输出

+   -v：增加详细级别（使用`-vv`或更高级别效果更好）

+   -d：增加调试级别（使用`-dd`或更高级别效果更好）

+   --reason：显示端口处于特定状态的原因

+   --open：仅显示打开（或可能打开）的端口

+   --packet-trace：显示发送和接收的所有数据包

+   --iflist：打印主机接口和路由（用于调试）

+   --log-errors：将错误/警告记录到正常格式的输出文件

+   --append-output：追加到指定的输出文件，而不是覆盖

+   --resume <filename>：恢复中止的扫描

+   --stylesheet <path/URL>：使用 XSL 样式表将 XML 输出转换为 HTML

+   --webxml：从 nmap.org 引用样式表以获得更便携的 XML

+   --no-stylesheet：防止将 XSL 样式表与 XML 输出关联

杂项：

+   -6：启用 IPv6 扫描。

+   -A：启用操作系统检测、版本检测、脚本扫描和跟踪路由。这是`-sS -sV --traceroute -O`的快捷方式。这是 Wolf 最喜欢的扫描选项。

+   --datadir <dirname>：指定自定义 Nmap 数据文件位置。

+   --send-eth/--send-ip：使用原始以太网帧或 IP 数据包发送。

+   --privileged：假设用户完全具有特权。

+   --unprivileged：假设用户缺少原始套接字权限。

+   -V：打印 Nmap 版本号。与其他选项一起使用无效。

+   -h：打印帮助摘要页面。

示例：

```
nmap -v -A boweaver.com
nmap -v -sn 192.168.0.0/16 10.0.0.0/8
nmap -v -iR 10000 -Pn -p 80  
```

您可以构建自定义的 Nmap 扫描字符串并将其复制到 Zenmap 中，以便享受 Zenmap 界面的好处。

# 使用 OpenVAS

在第二章中，我们为漏洞扫描设置了 OpenVAS。Nmap 在报告端口和服务方面做得很好，但缺乏扫描漏洞的能力。OpenVAS 将发现漏洞并对系统进行报告。OpenVAS 的人员每周更新他们的漏洞列表，因此最好在运行扫描之前更新 OpenVAS。要在 Kali 上执行此操作，请从终端窗口运行以下命令：

```
root@kalibook : ~ # OpenVAS-nvt-sync  
```

这将为 OpenVAS 运行漏洞更新。第一次运行时，您将看到以下截图中可见的信息，要求您迁移到使用 Rsync 来更新漏洞。键入`Y`并按*Enter*键。更新将开始。第一次运行此命令时，需要相当长的时间，因为它必须提供完整的插件和可用测试列表。在随后运行`update`命令时，它只会添加新的或更改的数据，并且速度要快得多：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/c4eb5d48-5264-41c1-ae7d-43ef2e7dcd41.png)

您还需要运行以下命令：

```
root@kalibook : ~ # OpenVAS-scapdata-sync  
```

更新完成后，我们已经准备就绪。现在让我们启动 OpenVAS 服务。转到应用程序 | Kali Linux | 系统服务 | OpenVAS | 启动 OpenVAS。一个终端窗口将打开，您将看到相关服务正在启动。一旦它们启动，您可以关闭此窗口并转到以下链接：`https://localhost:9392`。

何时不使用 OpenVAS？

在一些公司网络中，已经有了可以用来扫描漏洞的扫描服务。除非您怀疑官方公司扫描工具未正确配置以适应搜索范围，或者未更新以包括对最新漏洞的搜索，否则没有必要重复进行扫描。诸如 Qualys、Nexpose 和 Nessus 之类的扫描工具都是很好的扫描工具，可以完成与 OpenVAS 相同的任务。所有这些服务都以 XML 格式导出其数据，然后可以将其导入到诸如 Metasploit 之类的工具中。

现在，使用在设置步骤中生成的极长且复杂的密码登录 OpenVAS Web 界面。通常，用户是`admin`。

现在是一个很好的时机，去管理选项卡并将密码更改为仍然复杂但更容易记住的内容。

要运行您的第一次扫描，只需将要扫描的网络子网或单个 IP 地址输入到扫描文本框中，然后点击按钮开始扫描。这个小极客女巫会为您设置几个正常参数并运行扫描。您还可以设置自定义扫描，甚至安排在特定日期和时间运行作业：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/a85dc8e9-dd39-4af2-bc7e-ac0e5af2a129.png)

一旦扫描开始，您将看到以下屏幕。此时，您将看到它标记为“已请求”，大约一分钟后屏幕将刷新，您将看到进度条开始移动。根据您要扫描的网络大小，您可以去喝杯咖啡，吃顿饭，明天回来，或者周末离开。这将需要一些时间。值得注意的是，在整个过程中，您无需紧挨着点击“下一步”按钮。

现在扫描已经完成，您将看到一个类似以下的屏幕。转到扫描管理选项卡，然后在下拉菜单中选择报告。这将带您到报告页面，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/824c6c7d-53ac-4d9a-a059-57ad4366833b.png)

报告页面将向您提供扫描结果，将发现的漏洞从最严重到最低进行分类，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/acd7f2e3-954d-4282-b9d5-77be2875e630.png)

在这里，您可以以各种格式生成报告。选择所需的格式，然后点击绿色按钮，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/0c87d4a4-47c8-47bc-ae8c-3b0964fb981c.png)

然后您可以下载报告。您可以编辑报告以显示您公司的标志和任何未包含在文档中的必要公司信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/e2647312-ed08-4b74-b7f3-4b6be35cb0b1.png)

# 使用 Maltego

**Maltego**是一个信息收集工具，除了收集网络信息外，还有许多其他用途。您还可以从各种来源收集有关人员和公司的信息。现在，我们将使用它来收集有关公共网络的网络信息。

第一次启动 Maltego 时，您需要进行一些设置，并在其网站上注册，以便登录到转换服务器。这很容易，免费，没有垃圾邮件，因此提供您的电子邮件地址不会成为问题。首先，您需要选择要使用的版本。Maltego XL 和 Classic 是专业版本，您必须支付才能获得许可证。CE 版本是免费版本，而您正在学习如何使用此工具时，我们将在以下部分中使用的 CE 版本将完全正常工作。如果您是以渗透测试为生，那么 Classic 版本的许可证有点昂贵，但是非常值得。付费版本将在搜索中提取超过 10,000 个实体。CE 版本对每个实体的限制为 10 个。

1.  因此，选择 CE 版本，然后点击“运行”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/22950f50-6818-4b30-802d-62b6ed19d07a.png)

1.  接下来，填写您用于注册的信息，解决验证码，然后点击“下一步”：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/644d528b-8d22-44f9-9537-fec223335dfb.png)

1.  所以，我们都注册了，然后我们得到了以下窗口。点击“下一步”继续：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/8dd88348-0735-44b8-a380-39ed3a70a753.png)

1.  接下来，我们会得到一个询问如何开始的窗口。我们将选择一个空白图表，然后点击“完成”，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/b141eeb6-ed46-4003-abfd-481d6090ba1e.png)

1.  点击“完成”后，我们会得到一个空白图表页面，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/bdb499cb-6b04-4cc6-81d3-525d1245930d.png)

所以，让我们足迹一个域名。

1.  点击并将左侧工具栏中的域图标拖动到图表页面的中心。默认域显示为 paterva.com。这是 Maltego 的网站，现在只是一个占位符。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/e94cb9ee-8216-4540-bc87-2cc8b3cc14ab.png)

在右下角的工具栏中，在属性视图中，将 paterva.com 更改为您想要足迹的域。

记住：永远不要测试您不拥有或没有书面许可的任何东西！监狱不好玩，有关黑客行为的权力正在严厉打击，您不想被贴上*网络恐怖分子*的标签。不，您没有权限测试我的东西。请友好相处！

在接下来的部分中，我们将足迹作者的一个域：`boweaver.com`。由于我拥有该域，我允许自己测试该域：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/a3589676-7b53-4d67-b7c4-e771f8205e8b.png)

1.  接下来，右键单击域图标，您将会得到一个命令窗口。

1.  点击双箭头。这将在域上运行所有转换。这将花费一分钟来运行。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/f7cbdf0d-0580-42dc-b954-756f09be8afd.png)

一旦转换完成，您将在屏幕上看到输出信息。只需点击一下，应用程序就会出去，检查许多在线来源，并提取有关域的许多基本信息：所有者、IP 地址、该地址的物理位置等等。现在，您可以右键单击任何这些实体，以深入了解并收集更多信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/eb9725be-03cc-4c4e-989e-b7939eefab9b.png)

现在我们已经生成了一些数据，我们需要保存我们的结果。点击 Maltego 图标（窗口左上角的三个彩色圆圈组成的圆圈），然后点击“另存为”，将文件保存到项目工作区，如下所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/e589a3e4-5c96-4203-9019-9cade47268ff.png)

现在让我们看一下收集到的一些信息。从第一行，我们可以看出该域名在 GoDaddy 注册。DNS 列出的管理员电子邮件地址是`postmaster@boweaver.com`。在第二行，我们看到其他 DNS 记录条目，显示了邮件服务器（`bomail`）和 Web 服务器（`www`）。我们还看到与域`boweaver.net`有关系。在第三行，我们看到搜索从转换源找到的几个电子邮件地址。此外，该域的 MX 记录列表显示了`bomail.boweaver.com`和该域的邮件服务器。第四行显示了 NS 服务器和与该域连接的实体。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/5249a0ce-3532-4e59-8e67-dcc578b8e56b.png)

我们可以在以下截图中看到数据输出的左侧部分。通过查看列出的滥用电子邮件地址，我们可以知道该域名设置了隐私保护，因此电话号码和电子邮件地址指向了 GoDaddy。我们还看到了相关网站`www.boweaver.com`。因此，一个简单的一键搜索揭示了关于该域名、其结构和所有者的大量信息。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/c583ce95-9589-429f-b056-148536ca2c70.png)

通过右键单击网站，我们得到以下窗口。通过单击“解析为 IP”旁边的双箭头，我们可以获取该网站的 IP 地址和网络信息：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/95bcbbfb-3c44-44d7-b802-a510b6a407df.png)

因此，通过深入挖掘，我们已经找到了 IP 地址、分配的网络块和自治系统号（ASN）。我们还可以看到该网站托管在 Digital Oceans 的纽约数据中心：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/42daf813-3d32-48f4-86eb-9e7e05795852.png)

Maltego 允许您将此信息保存到表格（CSV 文件），生成报告，或将图表导出为图像：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/cf2d6c37-aec3-4237-b00e-1f841f1a0b14.png)

因此，通过这个应用程序的两次鼠标点击，而实际上并没有触及目标的任何资产，我们已经确定了大量关于目标的信息。

这只是这个工具的简单用法。这个工具可以挖掘的信息深度令人震惊，也有点可怕，特别是如果您使用专业版。这个工具的完整使用超出了本书的范围。关于这个工具的深入使用有很多在线资源。

# 使用 KeepNote

在这里要说一下笔记！渗透测试收集了大量数据，即使是在一个小网络上，我是说非常多！因此，在进行渗透测试时，您需要在进行测试时能够收集到来的数据。Kali 配备了几个应用程序来实现这一点。无论您选择哪一个，只需选择一个并使用它。测试运行后六周，当您需要回头验证某些内容时，您会为自己的选择感到高兴。此外，在进行高安全环境的测试时，比如必须符合 HIPPA 或 PCI 标准的网络，这些笔记在撰写报告时尤其有用。另外，请确保将所有项目文件放在一个目录中，并与此框架一起使用。做好笔记的另一个原因是，如果出现法律诉讼，您的笔记可能是您最好的辩护。

以下截图显示了 Bo 使用的框架。他为客户组织创建一个文件夹，然后为实际测试创建一个带有日期的文件夹名称。可以肯定的是，无论您在哪里从事业务，您都会反复看到相同的客户。如果您没有看到重复的业务，那么您自己的业务模式可能存在问题。Ext-20150315 表示在 20150315 进行的外部测试。20150315 是一个 Unix 风格的日期，可以分解为 YYYYMMDD。如果您看到看起来像 20150317213209 的 Unix 风格日期戳，那么这可以被分解到秒。在该文件夹内，Bo 设置了用于证据、笔记和扫描文档的目录。所有收集的证据，包括截图，都放入`evidence`文件夹。来自 KeepNote 的笔记保存在`notes`文件夹中，扫描和其他相关文档保存在`scans-docs`文件夹中。当我们在本书的后面开始进行测试时，您将看到这个框架被使用。

以下是文件夹布局的截图。在这种情况下，我们使用 LXDE 文件管理器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/6a1a71aa-96b4-4282-b0e9-63dfe17ed211.png)

即使您只为一家公司工作，也要保持每个测试的数据分开并标记日期；这将帮助您跟踪测试情况。

对于实际的笔记，Kali 配备了几个应用程序，如之前所示；Maltego 是其中之一，能够将所有数据保存在一个地方。

博最喜欢的是 KeepNote。您在第一章中看到了 KeepNote 的介绍，*选择您的发行版*。KeepNote 是一个简单的笔记应用程序。在 Bo 的测试中，他保存了手动利用的输出副本，单独的扫描数据和截图。好处在于您可以随时格式化数据，因此稍后将其导入模板只是复制/粘贴的问题。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/75220810-40c0-4906-ac1f-ecaa0e5bdf58.png)

# 摘要

在本章中，您已经了解了 Nmap 工具的许多用途，以及其 GUI 界面 Zenmap。我们了解了 OpenVAS 漏洞扫描器的详细用法，以及在攻击中使用这些数据。我们还了解了信息收集工具 Maltego 的用法。

# 进一步阅读

+   **Fydor 的 Nmap 网络扫描**: [`nmap.org/book/`](https://nmap.org/book/)

+   **OpenVAS 文档**: [`www.openvas.org/documentation.html`](http://www.openvas.org/documentation.html)

+   **Maltego 用户指南**: [`www.paterva.com/web7/docs/userguides/user_guide.php`](https://www.paterva.com/web7/docs/userguides/user_guide.php)


# 第四章：嗅探和欺骗

嗅探网络流量可以帮助你了解哪些用户正在使用你可以利用的服务，以及

IP 欺骗可以用来毒害系统的 DNS 或 ARP 缓存，以便将所有流量发送到中间人（例如你指定的主机）。嗅探和欺骗经常用于网络中的 Windows 端点，你需要了解坏人将要使用的技术。

+   **嗅探网络流量**：有许多工具可以嗅探网络流量，但它们都是基于同样的原理。捕获你的**网络接口卡**（**NIC**）可读的数据包。有数百种协议和数千个 TCP/IP 端口。可以肯定的是你不需要了解所有这些，但你可能会学习几十种。

+   **欺骗网络流量**：TCP/IP 系统是信任的。网络工作的一般假设是可信任的。当恶意者决定对网络数据包的组装方式玩一些把戏时会发生什么？这就是欺骗。例如，当一个 ICMP 数据包广播到大量主机时，但源 IP 地址已被伪造指向特定目标主机，所有发送广播数据包的主机都会向受害者发送意外的确认。这就是*Smurf 攻击*，它会占用受害者的机器。Smurf 攻击是许多拒绝服务攻击中的一种。

在本章中，我们将学习以下主题：

+   嗅探和欺骗网络流量

+   嗅探网络流量

+   欺骗网络流量

# 技术要求

在本章中，你至少需要两台运行 Windows 的机器，可以是实际机器也可以是虚拟机器，以及你的 Kali 机器。

# 嗅探和欺骗网络流量

你很可能已经注意到 Kali Linux 的座右铭：*你越安静，你就越能听到更多声音*。这是嗅探网络流量的核心。你悄悄地监听网络流量，复制每个数据包。每个数据包都很重要，否则它就不会存在。戴上你的安全帽，想一想这一点。你明白为什么明文发送密码是如此糟糕吗？例如，Telnet、FTP 和 HTTP 等协议会以明文发送密码，而不是加密哈希。任何数据包嗅探器都可以捕获这些密码，而不需要天才就可以搜索数据包捕获中的密码等术语。无需破解哈希；它就在那里。你可以通过从空气中提取他们的明文密码来给经理或客户留下深刻印象。坏人也使用相同的技术来侵入网络并窃取金钱和机密。

你复制的数据包中不仅包含密码。数据包嗅探器不仅用于这个目的。在寻找网络上的攻击者时，它们也很有用。你无法躲避数据包嗅探器。数据包嗅探器也非常适用于网络诊断。例如，网络运行缓慢可能是由于服务器上的一个网卡出现问题，正在向无人发送数据，或者一个运行失控的进程占用了其他进程的响应。

如果嗅探是监听网络，那么欺骗就是在网络上撒谎。你所做的是让攻击机器对网络撒谎，并假装成其他人。使用接下来描述的一些工具，并在攻击机器上的两个网络卡上，你甚至可以将流量传递到真实主机，并捕获两台机器之间的所有流量。这是一种**中间人**（**MitM**）攻击。在大多数渗透测试中，你实际上只需要获取密码哈希，而不需要进行完整的 MitM 攻击。只是欺骗而不传递流量将在 NetBIOS 的 ARP 广播中显示密码哈希。

黑客提示：

高级黑客实验室：如果您计划在您的网络上运行全面的 MitM 攻击，您将需要一个至少有两个网卡的主机，以及安装了 Kali Linux 的笔记本电脑。您的 MitM 主机可以是虚拟的或物理的服务器。

# 嗅探网络流量

在这里，我们将学习 Kali 标志的含义，*你变得越安静，你就能听到的越多*，以及可以从网络 passively 获得的信息。

# tcpdump

tcpdump 是一个简单的命令行嗅探工具，可以在大多数路由器、防火墙和 Linux/UNIX 系统上找到。也有一个由 micoOLAP 制作的可以在 Windows 上运行的版本，可以在[`www.microolap.com/products/network/tcpdump/`](http://www.microolap.com/products/network/tcpdump/)找到。它不是免费的，但有试用版本。这个版本的好处是它是一个简单的可执行文件，可以上传到系统并在不安装额外驱动程序的情况下使用。它可以在您有 shell 访问权限的破解系统上启动。您的 shell 必须具有系统或管理员级别的访问权限才能工作，因为没有管理员权限，网卡将无法以混杂模式运行。另一个数据包转储工具是**Windump.exe**，可以从[`www.winpcap.org/windump/install/`](http://www.winpcap.org/windump/install/)获取，您还将在那里找到**WinPcap.exe**，您需要在机器上安装 tcpdump 或 WinDump。

在 Linux/UNIX 系统和 Cisco 或 Juniper 等路由器上，它很可能是默认安装的。如果您在 Linux 系统上找不到它，它在每个发行版的软件库中都有。

tcpdump 最好不用于实时检查数据，而是用于捕获数据到文件中，以便以后使用诸如 Wireshark 之类的工具查看。由于其体积小、可移植性强，并且可以从命令行中使用，tcpdump 非常适合这项任务。

在下面的屏幕截图中，我们看到`tcpdump`在不保存到文件的情况下运行；请注意，我们可以看到数据包通过接口时的情况。

我们正在运行的命令是：

```
tcpdump -v -i vmnet1  
```

`-v` 将应用程序置于详细模式。`-i vmnet1` 告诉应用程序只捕获`vmnet1`接口上的数据包。按下 *Enter* 键，tcpdump 将开始捕获数据包并在屏幕上显示。要停止捕获，按下 *Ctrl* + *C*。

现在，在这种模式下，数据传输速度太快，无法进行实际使用，特别是在大型网络上，所以下一步我们将数据保存到文件中，这样我们就可以在闲暇时使用更好的查看工具查看数据：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/cac9609b-ae90-4011-8a4d-85982480895e.png)

现在我们将运行以下命令并将输出导向一个 `.pcap` 文件。请注意，屏幕上没有您之前看到的输出。数据现在正在写入文件而不是屏幕。运行以下命令：

```
tcpdump -v -i vmnet1 -w kalibook-cap-20150411.pcap  
```

请注意，我们在命令中添加了`-w kalibook-cap-20150411.pcap`。`-w`标志告诉应用程序将输出写入名为`kalibook-cap-20150411.pcap`的文件中。文件应该有一个描述性的名称，我还在文件名中包含了日期。如果您不从时间到时间进行测试并且不从系统中删除文件，同一系统上的几个这样的文件可能会令人困惑。`.pcap`是行业中用于数据包文件的标准文件扩展名，代表**Packet Capture File**。这个文件可以通过文件传输方法移动到另一台机器上：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/9e5f312e-c4b5-4fea-a161-c115c65ae1c0.png)

请注意，此捕获是在名为**Wander**的机器上完成的。Wander 是我们网络的防火墙，如果可能的话，这是捕获网络流量的最佳位置。现在我们将把它传输到我们的 Kali 盒子上检查数据包。

首先，在我们的 Kali 机器上，我们需要启动 SSH 服务。正如我们之前所说，Kali 包括您在任何 Linux 服务器上都会找到的所有网络服务，但出于安全原因，默认情况下所有服务都被关闭，必须手动启动才能使用。我们将使用以下命令启动 SSH：

```
service ssh start  
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/1cfccc6f-0052-4eed-9b5b-e6a83ac1413d.png)

我们可以看到 SSH 服务启动，并通过运行`netstat -tl`命令，我们可以看到 SSH 服务在所有接口上都在监听。现在我们将从防火墙传输文件到 Kali。

在 Kali 上，运行以下命令：

```
ifconfig 
```

这将显示你的 IP 地址：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/4d0aad11-a0f0-4870-850c-0bcd1a0ab738.png)

现在，从防火墙上运行以下命令将文件传输到 Kali：

```
scp kalibook-cap-20150411.pcap root@192.168.202.129:kalibook/kalibook-cap-20150411.pcap  
```

通过输入`yes`接受密钥警告，然后在提示时输入 root 密码。

我在演示中犯了一个错误，试图将其发送到错误的目录。没有`workspace`目录。如果你看到这种类型的错误，这很可能是原因。请注意，我已将此文件直接发送到 Kali 盒子上的项目目录：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/ea87e752-888c-41de-bde2-6c1bb69d5eb7.png)

完成后，不要忘记关闭 SSH：

```
service ssh stop  
```

这对于内置 SSH 的系统来说很好，但是 Windows 呢？大多数人似乎使用`putty.exe`，但是你的被入侵的服务器系统不太可能安装 putty。我们将退而使用老式的 FTP。大多数 Windows 系统都带有 FTP 命令行实用程序。有时，注重安全的系统管理员会从计算机中删除`ftp.exe`，这会阻止这种类型的文件传输。通常它是存在的供你使用。如果不存在，请访问[`www.coreftp.com/`](http://www.coreftp.com/)并下载 Core FTP。他们有一个免费版本适用于此应用程序，并且您还可以获得更多功能的付费许可证。

现在我们将把`tcpdump`实用程序传输到我们的被入侵的 Windows 机器上，以捕获一些数据包。

首先，我们需要在 Kali 上设置 FTP 服务来回传输。我们将使用我们的朋友 Metasploit 来实现这一点。Metasploit 为此提供了一个易于使用的 FTP 服务。我们需要一个工作文件夹：

1.  在 Kali 桌面上打开计算机。

1.  在左侧列表中点击主页链接。

1.  右键单击文件夹区域，选择创建新文件夹。

1.  将其命名为`public`，然后右键单击文件夹，转到属性。

1.  点击权限选项卡，为组和其他人提供读/写访问权限以及创建和删除文件的能力，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/3b2c8e51-0791-408b-b5ec-41daa21b5d34.png)

1.  如果使用命令行，则通过`mkdir public`创建一个目录。

1.  然后输入以下命令：

```
chmod 777 public
```

现在将`NDIS driver`和`tcpdump.exe`复制到`public`文件夹。您可能需要根据目标网络上可能使用的防病毒软件和/或 IDS/IPS 系统的情况来重命名 tcpdump 文件。我已将名称更改为`tdpdump.jpg`。`microolap_pssdk6_driver_for_ndis6_x86_v6.1.0.6363.msi`驱动文件通常可以通过。

现在在 Kali 盒子上启动 Metasploit，方法是转到应用程序| Kali Linux | 系统服务 | community/pro start 来启动服务。一旦服务启动，打开一个终端窗口，输入`msfpro`。

Metasploit 将启动。一旦 Metasploit 运行起来，进入你的项目工作空间。我的工作空间名为`kali-book-int-20150300`：

```
workspace kali-book-int-20150300  
```

现在我们将配置 FTP 服务器并启动它。要加载 FTP 服务器，请输入以下命令：

```
use auxiliary/server/ftp
 show options  
```

你会看到以下配置选项：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/a41ee932-fafe-4b0f-8553-a9d28aeeb3c8.png)

我们需要更改`FTPROOT`设置类型：

```
set FTPROOT /root/public
show options  
```

通过再次运行`show options`命令，我们可以检查我们的配置。我们已经准备好了。输入以下命令：

```
run  
```

你会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/8a0613b8-e4c0-4533-bbd2-2b89d5e74dd4.png)

你可以通过运行以下命令查看服务：

```
netstat-tl      
```

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/511078b3-7ce0-49b8-ac7d-bc6a25894bf8.png)

现在让我们将文件复制到我们的被入侵的 Windows 机器上，并捕获一些有用的数据包！我们将在 Windows 上使用 WinDump 进行此过程。

# WinDump（Windows tcpdump）

WinDump 是 Windows 的 tcpdump。它是开源的，属于 BSD 许可证。您可以在[`www.winpcap.org/windump/`](https://www.winpcap.org/windump/)下载。

您还需要 WinPcap 驱动程序，因此一定要从网站上获取它们。

WinDump 可以从命令行、PowerShell 或远程 shell 中工作。与 tcpdump 一样，它将写入一个文件，您可以下载以进行离线查看。

现在让我们将文件复制到我们的被入侵的 Windows 机器上。从命令行、Power Shell 或被入侵的远程 shell 中，登录到 Kali 上的 FTP 服务器。我的 Kali 盒子在`192.168.202.129`：

```
ftp 192.168.202.129  
```

系统将要求输入用户名。只需按*Enter*。它还会要求输入密码。再次只需按*Enter*，然后输入以下命令：

```
dir  
```

这将显示目录的内容：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/95206610-ff09-4deb-80a9-8d12bf068182.png)

如前面的截图所示，我们看到了我们的`WinPcap`驱动程序和我们的未伪装的`WinDump.exe`。要下载它们，只需输入以下命令：

```
get WinPcap_4_1_3.exe  
```

然后输入以下命令：

```
get WinDump.exe  
```

我们已经拿到了我们的文件。现在按照以下步骤退出：

```
quit  
```

如我们所见，现在我们通过输入以下命令在本地拥有了我们的文件：

```
dir  
```

我们还可以在 Metasploit 中的运行实例中看到文件正在传输到 Kali：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/731b1d91-65c1-4191-a7e9-2eebba26680c.png)

现在登录到您的被入侵的 Windows 机器，可以通过 RDP 或从 Metasploit 启动 VNC 会话。从桌面，转到您下载文件的文件夹，并双击`WinPcap.exe`文件，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/dcf8396d-06aa-4ce0-8402-1188324e7ea3.png)

接下来，您将获得许可证窗口。点击“我同意”并继续：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/61187d7d-fbd3-4bf0-a534-7a4cd74dab3a.png)

下一个屏幕开始实际安装驱动程序。一定要保持复选框选中以自动运行。如果以后需要返回，这将非常有帮助：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/7809c710-3f64-41af-a0de-60b73d1dc65a.png)

完成后，您就可以开始捕获一些数据包了。

启动命令行窗口或 Power Shell 并转到您拥有 WinDump 的目录。我们将其放在`Downloads`文件夹中。运行以下命令：

```
.\WinDump.exe  
```

很快您将开始看到数据包通过接口传输。您在屏幕上看到的数据量取决于您的系统与网络通信的频率。显然，这是远远超出实时理解的数据量。此外，在此模式下，您只能看到数据包的标头信息，而无法看到完整的数据包及其信息。在下面的截图中，黄色下划线显示了正在运行的命令，绿色下划线显示了它正在监听运行接口。之后，您将看到数据包进入。

现在让我们将我们的捕获转储到文件中，以便真正了解我们拥有什么：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/4d9373f2-ab0b-434f-874b-7b2a4924e366.png)

```
.\WinDump.exe -w Win7-dump-20150411.pcap  
```

-w 文件告诉 WinDump 将文件写入到`Win7-dump-20150411.pcap`文件中。如下截图所示，使用`-h`标志运行 WinDump 将有所帮助，如果您忘记了写标志。运行一段时间后，按*Ctrl* + *C*停止捕获。现在您可以看到我们有一个包含我们捕获数据包的文件：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/559064cc-e653-4f80-996b-563e91d0abb2.png)

捕获后，我们需要将文件发送回 Kali 以分析数据包。

Windows 文件共享适用于此。如果未启用打印机和文件共享，请启用它以共享文件并返回到您的 Kali 盒子。

黑客提示：

此过程可能会引发警报，如果网络管理员有类似 Tripwire 的东西来检查配置更改，或者设置了 ArcSight 来标记管理用户的记录操作。

Kali 在所有桌面环境的文件管理器中都内置了 SMB 文件共享和 NetBIOS 发现。您可以从文件管理器映射到 SMB 共享。在以下演示中，我们使用 MATE 桌面。从其文件管理器，您可以通过转到菜单栏中的 Go | Location...来映射 SMB 共享：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/cc294105-73e8-444c-8d16-8be22b754fa6.png)

这将给您一个转到：地址栏。由于我们将使用 SMB 协议，我们将使用前缀`smb://`。其他服务类型的共享也可以使用这种方法映射，例如 SSH、FTP 和 NFS 共享。要连接到受害者机器并复制文件，请键入`smb://10.0.2.101/C$`。

然后按下*Enter*键。这对应隐藏的`C$`共享：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/f4544778-8b21-4709-a899-bd1b1836d910.png)

按下*Enter*后，会出现一个登录框。要登录共享，只需添加您拥有的 Windows 凭据，然后点击连接按钮。现在您将看到系统上的共享目录。深入文件夹并转到数据包捕获所在的目录。对我们来说，它将是`Users\Administrator\Downloads`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/50b8ddf5-a002-4444-a242-adc6b6f29ede.png)

现在我们已经找到文件所在的位置，再次点击计算机图标，打开另一个文件管理器窗口，然后转到您项目的证据目录。然后只需将文件拖放到 Kali 的驱动器上：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/c037bc06-341d-4cb9-9c3d-1aaddae1b516.png)

现在我们准备好读取一些捕获的数据包了。

# Wireshark

Wireshark 是数据包嗅探和分析网络数据包的行业标准。它不仅适用于 TCP/IP，还适用于几乎所有其他已知的协议和标准。Wireshark 有适用于每个知名操作系统的版本。在 Windows 上运行 Wireshark 需要本章前面提到的 WinPcap 驱动程序。在 Linux/UNIX 和 OSX 上，驱动程序通常已经存在。Wireshark 预装在 Kali 上。

Wireshark 是一个非常复杂的应用程序。已经有很多关于它的使用方法的书籍。我建议您获取一本并深入学习这个工具的使用。我们这里只会涵盖基础知识。

如果你真的思考一下，互联网是什么？有些人指着他们的网络浏览器说那里就是互联网。系统管理员可能会给你一个关于服务器和设备在网络上传输数据的长篇回答。每个人的回答都是正确的，但仍然没有完全理解它到底是什么。互联网就是数据包。没有数据包，信息就无法传输。大多数人没有意识到 TCP/IP 是两个独立工作的协议套件。有 IP，然后有 TCP 和 UDP，它们运行在 IP 之上。然后所有这些都运行在互联网帧之上。

我们稍后会回到 Wireshark。首先我们需要了解什么是数据包。

# 数据包

让我们看一个数据包。以下只是从捕获的数据流中提取的一小部分信息。请记住：这只是一个数据包！

哦，这里有一点历史。如果你看一下数据包的结构，再看一下旧电报消息的结构，你会注意到它们的结构是一样的。是的，数据包基本上就是一封电报。另外，记住莫尔斯电码基本上是一种四位二进制语言。

请注意，首先我们有**帧**。帧包含有关数据包的基本信息，您可以看到。Wireshark 捕获了传输线上的字节。这也保留了数据包的时间，用于在接收时重新组装数据包：

```
Frame 9: 188 bytes on wire (1504 bits), 188 bytes captured (1504 bits) 
  Encapsulation type: Ethernet (1) 
  Arrival Time: Apr 12, 2015 01:43:27.374355000 EDT 
  [Time shift for this packet: 0.000000000 seconds] 
  Epoch Time: 1428817407.374355000 seconds 
  [Time delta from previous captured frame: 0.002915000 seconds] 
  [Time delta from previous displayed frame: 0.002915000 seconds] 
  [Time since reference or first frame: 9.430852000 seconds] 
  Frame Number: 9 
  Frame Length: 188 bytes (1504 bits) 
  Capture Length: 188 bytes (1504 bits) 
  [Frame is marked: False] 
  [Frame is ignored: False] 
  [Protocols in frame: eth:ip:tcp:nbss:smb] 
  [Coloring Rule Name: SMB] 
  [Coloring Rule String: smb || nbss || nbns || nbipx || ipxsap || 
       netbios]
```

接下来，我们有数据包的 IP 部分。我们看到这包含了源和目标接口的 MAC 地址。您的 MAC 地址是您真实的机器地址。堆栈的 IP 部分进行路由，以便这两个 MAC 地址可以找到彼此：

```
Ethernet II, Src: Vmware_07:7e:d8 (00:0c:29:07:7e:d8), Dst: Vmware_45:85:dc (00:0c:29:45:85:dc) 
  Destination: Vmware_45:85:dc (00:0c:29:45:85:dc) 
    Address: Vmware_45:85:dc (00:0c:29:45:85:dc) 
    .... ..0\. .... .... .... .... = LG bit: Globally unique address (factory default) 
    .... ...0 .... .... .... .... = IG bit: Individual address (unicast) 
  Source: Vmware_07:7e:d8 (00:0c:29:07:7e:d8) 
    Address: Vmware_07:7e:d8 (00:0c:29:07:7e:d8) 
    .... ..0\. .... .... .... .... = LG bit: Globally unique address (factory default) 
    .... ...0 .... .... .... .... = IG bit: Individual address (unicast) 
  Type: IP (0x0800) 
Internet Protocol Version 4, Src: 192.168.202.130 (192.168.202.130), Dst: 192.168.202.128 (192.168.202.128) 
  Version: 4 
  Header length: 20 bytes 
  Differentiated Services Field: 0x00 (DSCP 0x00: Default; ECN: 0x00: Not-ECT (Not ECN-Capable Transport)) 
  Total Length: 174 
  Identification: 0x033f (831) 
  Flags: 0x02 (Don't Fragment) 
  Fragment offset: 0 
  Time to live: 128 
  Protocol: TCP (6) 
  Header checksum: 0xe0b6 [correct] 
    [Good: True] 
    [Bad: False] 
  Source: 192.168.202.130 (192.168.202.130) 
  Destination: 192.168.202.128 (192.168.202.128) 
  [Source GeoIP: Unknown] 
  [Destination GeoIP: Unknown] 
```

数据包的下一部分是 TCP 介入的地方，设置要使用的 TCP 或 UDP 协议类型以及用于传输数据包的分配源和目的端口。这个数据包是从客户端机器（源）发送的。从前面的 IP 部分，我们看到客户端 IP 地址是`192.168.202.130`。我们看到客户端的端口是`49161`。这个数据包被发送到`192.168.202.128`（目的地）的端口`445`。由于这是 TCP，返回路由也包括返回的流量。仅通过“目的地端口”信息，我们就可以知道这是某种类型的 SMB 流量：

```
Transmission Control Protocol, Src Port: 49161 (49161), Dst Port: microsoft-ds (445), Seq: 101, Ack: 61, Len: 134 
  Source port: 49161 (49161) 
  Destination port: microsoft-ds (445) 
  [Stream index: 0] 
  Sequence number: 101  (relative sequence number) 
  [Next sequence number: 235  (relative sequence number)] 
  Acknowledgment number: 61  (relative ack number) 
  Header length: 20 bytes 
  Flags: 0x018 (PSH, ACK) 
    000\. .... .... = Reserved: Not set 
    ...0 .... .... = Nonce: Not set 
    .... 0... .... = Congestion Window Reduced (CWR): Not set 
    .... .0.. .... = ECN-Echo: Not set 
    .... ..0\. .... = Urgent: Not set 
    .... ...1 .... = Acknowledgment: Set 
    .... .... 1... = Push: Set 
    .... .... .0.. = Reset: Not set 
    .... .... ..0\. = Syn: Not set 
    .... .... ...0 = Fin: Not set 
```

在数据包信息中，0 表示否，1 表示是。

```
  Window size value: 63725 
  [Calculated window size: 63725] 
  [Window size scaling factor: -1 (unknown)] 
  Checksum: 0xf5d8 [validation disabled] 
  [SEQ/ACK analysis] 
    [This is an ACK to the segment in frame: 8] 
    [The RTT to ACK the segment was: 0.002915000 seconds] 
    [Bytes in flight: 134] 
```

我们看到这是使用 SMB 协议的 NetBIOS 会话：

```
NetBIOS Session Service 
  Message Type: Session message (0x00) 
  Length: 130 
SMB (Server Message Block Protocol) 
  SMB Header 
    Server Component: SMB 
    [Response in: 10] 
    SMB Command: NT Create AndX (0xa2) 
    NT Status: STATUS_SUCCESS (0x00000000) 
    Flags: 0x18 
    Flags2: 0xc807 
    Process ID High: 0 
    Signature: 0000000000000000 
    Reserved: 0000 
    Tree ID: 2049 
    Process ID: 2108 
    User ID: 2048 
    Multiplex ID: 689 
  NT Create AndX Request (0xa2) 
    [FID: 0x4007] 
    Word Count (WCT): 24 
    AndXCommand: No further commands (0xff) 
    Reserved: 00 
    AndXOffset: 57054 
    Reserved: 00 
    File Name Len: 44 
    Create Flags: 0x00000016 
    Root FID: 0x00000000 
```

接下来，我们已经被授予了我们正在请求的数据的访问权限。我们现在可以看到这个数据包涉及访问一个文件。发出此请求的用户具有查看所请求文件的以下权限。我们可以从前面的代码中看到，文件请求已经获得了成功的状态。

```
    Access Mask: 0x00020089 
      0... .... .... .... .... .... .... .... = Generic Read: Generic read is NOT set 
      .0.. .... .... .... .... .... .... .... = Generic Write: Generic write is NOT set 
      ..0\. .... .... .... .... .... .... .... = Generic Execute: Generic execute is NOT set 
      ...0 .... .... .... .... .... .... .... = Generic All: Generic all is NOT set 
      .... ..0\. .... .... .... .... .... .... = Maximum Allowed: Maximum allowed is NOT set 
      .... ...0 .... .... .... .... .... .... = System Security: System security is NOT set 
      .... .... ...0 .... .... .... .... .... = Synchronize: Can NOT wait on handle to synchronize on completion of I/O 
      .... .... .... 0... .... .... .... .... = Write Owner: Can NOT write owner (take ownership) 
      .... .... .... .0.. .... .... .... .... = Write DAC: Owner may NOT write to the DAC 
      .... .... .... ..1\. .... .... .... .... = Read Control: READ ACCESS to owner, group and ACL of the SID 
      .... .... .... ...0 .... .... .... .... = Delete: NO delete access 
      .... .... .... .... .... ...0 .... .... = Write Attributes: NO write attributes access 
      .... .... .... .... .... .... 1... .... = Read Attributes: READ ATTRIBUTES access 
      .... .... .... .... .... .... .0.. .... = Delete Child: NO delete child access 
      .... .... .... .... .... .... ..0\. .... = Execute: NO execute access 
      .... .... .... .... .... .... ...0 .... = Write EA: NO write extended attributes access 
      .... .... .... .... .... .... .... 1... = Read EA: READ EXTENDED ATTRIBUTES access 
      .... .... .... .... .... .... .... .0.. = Append: NO append access 
      .... .... .... .... .... .... .... ..0\. = Write: NO write access 
      .... .... .... .... .... .... .... ...1 = Read: READ access 
    Allocation Size: 0 
    File Attributes: 0x00000000 
    Share Access: 0x00000007 SHARE_DELETE SHARE_WRITE SHARE_READ 
    Disposition: Open (if file exists open it, else fail) (1) 
    Create Options: 0x00000044 
    Impersonation: Impersonation (2) 
    Security Flags: 0x03 
    Byte Count (BCC): 47 
    File Name: \My Videos\desktop.ini 
```

所有前面的代码都是为了让一台计算机知道另一台计算机上存在一个名为`\My Videos\desktop.ini`的文件。发送了 47 字节的信息。现在这不是实际的文件，而只是文件的列表。基本上，这将是使文件图标出现在你的窗口管理器中的数据包。发送这么少的数据确实需要很多工作：

```
No.   Time    Source        Destination      Protocol Length Info 
   10 9.431187  192.168.202.128    192.168.202.130    SMB   193  NT Create AndX Response, FID: 0x4007 
```

现在我们对数据包有了一些了解，让我们回到 Wireshark。

# 使用 Wireshark

让我们打开它并打开我们的捕获。首先，转到应用程序 | Kali Linux | 前 10 个安全工具 | wireshark。当它启动时，它会警告你以`root`身份运行。只需点击通过。如果愿意，可以勾选不再显示这些警告的复选框。当你使用 Kali 时，你将始终以`root`身份工作。

另一个警告：永远不要在生产 Linux 机器上这样做。除了 Kali 之外，永远不要以`root`身份登录和运行。Wolf 在他的 Kali Linux 测试盒中添加了一个标准用户和`sudo`，只有在实际运行测试时才以`root`身份运行。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/257d67e6-3cbf-4cd6-8c7e-289c9fcdb827.png)

警告后，窗口将打开。正如我们所看到的，我们有一个非常好的界面。你不仅可以阅读捕获的数据，还可以从列出的本地接口捕获数据包。在右侧，你会看到一个在线帮助的部分。如果你迷失了并且需要帮助，那就是你去的地方。你会在网上找到大量的帮助：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/345cb7f8-711a-4e6c-8f72-969cddde5837.png)

让我们打开我们的捕获。点击文件 | 打开，你会得到一个文件菜单。导航到你的文件所在的位置，然后点击打开：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/d999690c-f766-4d42-9c16-a5e7eaca7d83.png)

现在捕获已经打开，所有捕获的数据都列在顶部屏幕上。每个列表都是一个数据包。你所看到的是数据包的头信息，它的源，目的地和协议类型。

通过在顶部屏幕上点击一个数据包，该数据包的完整信息将显示在中间屏幕上。这将是我们之前在分解数据包时看到的信息。这就是你会看到这些信息的地方。实际上，这是以人类可读的形式呈现的数据包。在底部屏幕上，我们有实际的原始数据包以机器语言显示。通过在中间屏幕上的信息行上点击，Wireshark 将以蓝色突出显示机器语言字符串，显示该代码在数据包中的位置：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/757a53ba-47c2-4a94-9ca3-00d3738a1cdd.png)

从第一个屏幕上看，我们可以看到整体的流量。我们看到一台机器发出了 DHCPv6 Solicit 呼叫，但没有从任何地方得到响应。嗯，IPv6 在这个网络上必须被关闭了。接下来，我们看到`192.168.202.128`和`192.168.202.130`之间来回的 SMB 通信。仅从头部信息，我们就可以看到这个传输是用于在`192.168.202.128`上使用 SMB 的文件信息。仅仅通过查看头部信息，我们就可以知道`.130`上的用户可以访问`.128`：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/f5aec13f-ae5d-4b62-8195-966e52b62117.png)

那么好东西在哪里？在下面的截图中，我们有一个`SMB NTLMSSP`数据包，甚至可以看到这是用于账户`IVEBEENHAD\Administrator`的。通过选择数据包，我们可以深入到数据包中，找到密码的 NTLM 哈希值。这本身可以用于传递哈希的利用工具。您还可以将这个哈希值带入离线密码破解工具，比如 John the Ripper 或 Hydra。请注意，您还可以在底部屏幕的原始数据包信息中看到该值：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/90479b5c-6336-47a1-bfcb-c9891bac9ffc.png)

Wireshark 最好的功能之一是**搜索**功能。这个功能的细节足够写一本书。您可以使用过滤器字段右侧的 Expression...按钮构建表达式。从简单的过滤器，比如`ip != 10.0.0.232`（用于切出所有发送到您的 Kali 盒子的流量），或者通过在过滤器字段中输入 SMTP 来检查意外的 SMTP 流量，学习最需要的过滤器时会有无尽的乐趣。在线帮助会解释很多内容，就像所有良好的知识库一样，它也会引发新的问题：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/120a512c-5048-471d-8bac-12eaeaed4eba.png)

# 欺骗网络流量

互联网上有几种欺骗的定义：

+   电子邮件欺骗：最常见的定义是通过使用假电子邮件地址伪装成不同的人。在尝试**钓鱼攻击**时，这很有效，受害者会收到一封假装来自他们的银行或零售商的电子邮件。

+   域名欺骗：可以欺骗域名，在网络或个人工作站上毒害路由表。其工作原理是用户在浏览器地址栏中输入的域名被错误地指向错误的 IP 地址。当受害者访问[`bankarmenia.com/`](http://bankarmenia.com/)时，他们最终会进入一个看起来与亚美尼亚银行网站完全相同的钓鱼网站，但实际上并不是。这用于收集用户的凭证，以进行盗窃。

+   域名错误欺骗：黑客购买常见错误的域名，比如`https://www.yaahoo.com/`。他们建立一个看起来像[`www.yahoo.com/`](https://www.yahoo.com/)的网站，并从所有的拼写错误中获益。

+   IP 欺骗：制作精心制作的数据包，目的是伪装成不同的机器，或者为了隐藏数据包的来源。

# Ettercap

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/729ca8ba-aa0a-41d3-95e8-fe6d1005018f.png)

可爱的标志，非常具有启发性。是的，在蜘蛛背上有一个无线路由器。Ettercap 有一些用于无线网络的很棒的插件。我们现在不会涵盖无线网络，但这是需要知道的。Ettercap 可以嗅探和捕获数据，就像 tcpdump 和 Wireshark 一样，但它还可以欺骗网络流量，捕获有趣的信息，并将其传输到文件中。图形界面可以在应用程序 | Kali Linux | 嗅探/欺骗 | 网络嗅探器 | ettercap-graphical 中找到，这将启动 Ettercap：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/5bd16b7c-25f4-4ab3-81b0-86a4374ad099.png)

以下截图显示了 Ettercap 的图形界面。我们首先通过选择菜单栏中的 Sniff | Unified Sniffing...来启动统一嗅探：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/9ef36662-0c3b-4df2-8c47-d8952ea216dc.png)

现在我们被问到要使用哪个接口。通常情况下，如果需要的话，它将是默认的。通过下拉框，您可以选择系统上的任何接口。点击确定：

警告！

在使用 SSH 隧道时，如果从远程机器使用，Ettercap 将中断隧道连接。它们似乎无法很好地协同工作。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/3ab039c8-4325-44da-ae8e-50b6ee5049cd.png)

一旦配置了统一嗅探，您会注意到菜单栏已经发生了变化。

首先我们需要记录消息。在菜单栏中选择 Logging | Log user messages...：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/c22cdc99-d696-4502-b383-59a428cc47fd.png)

然后会弹出一个窗口，用于为消息输出命名文件。给它一个文件名，然后点击确定：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/312f377c-44ee-4726-9fae-cd686e0f9a32.png)

接下来，我们需要开始嗅探流量。转到开始 | 开始嗅探。这里发生的情况与 tcpdump 和 Wireshark 执行的功能相同。目前，Ettercap 只是被动地捕获数据包。在开始嗅探之前，您可以在日志菜单下设置 Ettercap，以便保存所有捕获的数据包以供以后检查。您只需将捕获保存到一个`.pcap`文件中，就像在 tcpdump 和 Wireshark 中一样。

通常，只保存用户消息的输出就足够进行渗透测试。在渗透测试中，您主要是在寻找密码和登录凭据。消息日志将捕获这些信息。有时，为了进行额外的侦察，您可以保存整个捕获：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/e7c68ac9-4a38-4ad1-8587-f16b88862f04.png)

一旦嗅探开始，我们需要扫描主机。在菜单栏中选择主机 | 扫描主机。这将扫描本地网络以查找可用的主机。请注意，还有一个选项是从文件加载....您可以选择此选项，并从文本文件中加载主机 IP 地址列表。当在大型网络上时，这是一个很好的选择，您只想欺骗文件服务器和域控制器的流量，而不是欺骗工作站。这将减少网络流量。ARP 欺骗可能会产生大量流量。如果是大型网络，这种流量可能会减慢网络。如果您在秘密测试，这种流量会让您被发现：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/15805e3d-d9fb-4904-ac12-1830a87c7275.png)

在下面的截图中，我们看到了我们从扫描中获得的主机列表。由于这是一个小型网络，我们将欺骗所有主机。我们看到有五个主机列出，包括 MAC 地址。请记住其中一个是测试机器：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/8b1606e9-3595-4085-8160-c8e56d0b4d09.png)

我们已经准备好对水进行投毒并查看浮出的东西。转到 Mitm | Arp poisoning...然后点击它：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/1c574c16-c748-4012-af9e-712b155c1dc7.png)

然后，您将获得一个窗口来设置要执行的投毒类型。选择嗅探远程连接。然后点击确定：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/ac22faca-660e-49bd-9641-88ba9b871bac.png)

以下屏幕显示了 DNS 投毒正在进行中：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/fe83501a-ced0-421b-87f2-ce83b2759e7b.png)

投毒完成后，数据将通过 Ettercap 界面发送，显示管理员用户及其 NTLM 密码哈希。这已经足够开始使用 John the Ripper 或 Hashcat 对密码哈希进行破解。

黑客提示：

即使管理员密码失败，您仍然应该破解它们。管理员用户可能已经忘记了他们登录的机器，而失败的密码可能在系统的其他地方起作用。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/c3de540b-7eec-41f7-9f28-49ae25b6611c.png)

在大多数安全策略中，Windows 系统设置为在用户尝试五次或六次连接后拒绝连接。这个策略保护用户帐户免受暴力破解密码或猜测密码的攻击。这将阻止暴力破解密码，但正如您所看到的，这个策略对这种漏洞没有影响。您已经有了管理员密码，所以您可以第一次登录。

Ettercap 的一个很棒的功能是它还可以在命令行下使用 Ncurses 界面。这在使用 SSH 从远程系统工作时非常方便。使用*Tab*键和箭头键在菜单中移动，使用*Enter*键进行选择。

# 命令行上的 Ettercap

在许多情况下，您将无法使用 Ettercap 的图形界面。当您从一个破解的 Linux 机器上发动攻击时，您可能会发现它根本没有图形桌面。在这种情况下，您可以使用 Ettercap 的 curses 版本或纯文本版本。这在使用 SSH 从远程系统工作时非常方便。使用*Tab*键和箭头键在菜单中移动，使用*Enter*键进行选择：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/11a8cd5d-c128-4404-90e6-5565951a933e.png)

要从命令行启动 Ettercap，您需要向命令添加一些标志；就像大多数 Linux 命令一样，您可以使用`ettercap -help`来获取标志及其含义的列表。对于基本用法，您可以使用以下命令：

```
root@kalibook :~# ettercap -C -m ettercap-msg.txt   
```

`-C`标志以 Ncurses 模式启动 Ettercap。我已经包含了`-m ettercap-mgs.txt`标志，将消息输出导出到`ettercap-msg.txt`文件。如果您想保存整个捕获，添加`-w ettercap-capture.pcap`。这将保存完整的捕获，以便以后在需要时将其导入 Wireshark。我发现使用命令行标志保存输出更容易。

下一张截图显示了基于 CLI 的 Curses 界面。

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/486c4172-9192-41ab-8259-55f39d2104f8.png)

下一张截图显示了基于 CLI 的纯文本界面：

![](https://github.com/OpenDocCN/freelearn-kali-zh/raw/master/docs/kali18-win-pentest/img/814b95f9-5c84-4a8b-bcad-94c3d820070a.png)

# 总结

在本章中，您将学习如何使用 tcpdump、WinDump 和 Wireshark 嗅探网络，以及如何过滤协议和 IP 地址。之后，您将使用 Ettercap 进行欺骗和 ARP 欺骗。

在我们的下一章中，我们将利用从 ARP 欺骗中获得的信息积极地攻击我们的目标，并学习如何在线和离线破解密码。

# 进一步阅读

+   有关 Wireshark 的更多信息，请访问其文档网站：[`www.wireshark.org/docs/`](https://www.wireshark.org/docs/)

+   有关 tcpdump 的更多信息，请访问其网站：[`www.tcpdump.org/#documentation`](http://www.tcpdump.org/#documentation)

+   有关 Ettercap 的更多信息，请访问其网站：[`www.ettercap-project.org/`](https://www.ettercap-project.org/)
