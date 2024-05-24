# Python 物联网项目（一）

> 原文：[`zh.annas-archive.org/md5/34135f16ce1c2c69e5f81139e996b460`](https://zh.annas-archive.org/md5/34135f16ce1c2c69e5f81139e996b460)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

物联网承诺解锁真实世界，就像互联网几十年前解锁了数百万台计算机一样。树莓派计算机于 2012 年首次发布，迅速风靡全球。最初设计的目的是给新一代带来与上世纪 80 年代个人计算机同样的编程激情，树莓派已经成为无数创客的标配。

1991 年，Guido van Rossum 向世界介绍了 Python 编程语言。Python 是一种简洁的语言，旨在提高代码可读性。Python 程序往往需要的代码行数比其他编程语言少。Python 是一种可扩展的语言，可用于从最简单的程序到大规模项目。

在本书中，我们将释放树莓派和 Python 的力量，创建令人兴奋的物联网项目。

本书的第一部分向读者介绍了令人惊叹的树莓派。我们将学习如何设置它，并立即开始 Python 编程。我们将通过为物理计算创建“Hello World”应用程序——闪烁 LED，开始我们的真实计算之旅。

我们的第一个项目将我们带回到模拟指针仪表统治数据显示领域的年代。回想一下那些旧的模拟万用表和无数的旧科幻电影，信息是通过按钮和大型闪烁灯控制和显示的。在我们的项目中，我们将从网络服务中检索天气数据，并在模拟指针仪表上显示它。我们将通过 GPIO 将舵机连接到我们的树莓派，实现这一目标。

家庭安全系统在现代生活中几乎无处不在。整个行业和职业都建立在安装和监控这些系统上。你知道吗，你可以轻松地创建自己的家庭安全系统吗？在我们的第二个项目中，我们就是这样做的，我们使用树莓派作为 Web 服务器来构建家庭安全系统。

自 1831 年以来，谦卑的门铃一直与我们同在。在我们的第三个项目中，我们将给它增加 21 世纪的变化，让我们的树莓派向网络服务发送信号，当有人来敲门时，网络服务将给我们发短信。

在我们的最后一个项目中，我们将从前两个项目中学到的知识创建一个名为 T.A.R.A.S（这个令人惊叹的树莓派自动安全代理）的物联网机器人车。

未来，无人驾驶汽车将成为规则而不是例外，需要一种控制这些汽车的方式。这个最后的项目为读者提供了洞察和知识，了解如何控制没有人类驾驶员的汽车。

# 这本书是为谁写的

本书面向那些对编程有一定了解并对物联网感兴趣的人。了解 Python 编程语言将是一个明显的优势。对面向对象编程的理解或浓厚的兴趣将有助于读者理解本书中使用的编码示例。

# 本书内容

第一章《在树莓派上安装 Raspbian》通过在树莓派上安装 Raspbian 操作系统开始了我们的树莓派物联网之旅。然后我们将看一些预装在 Raspbian 上的程序。

第二章《使用树莓派编写 Python 程序》介绍了 Windows、macOS 和 Linux 这些对开发人员来说很熟悉的操作系统。许多关于开发树莓派的书籍都涉及使用其中一个操作系统并远程访问树莓派。但本书将采用不同的方法，我们将把树莓派作为开发机器。在本章中，我们将初步了解如何将树莓派作为开发机器。

第三章，“使用 GPIO 连接外部世界”，解释了如果树莓派只是一台 35 美元的计算机，对我们许多人来说已经足够了。然而，树莓派背后真正的力量在于开发者通过**通用输入输出**（**GPIO**）引脚访问外部世界的能力。在本章中，我们将深入研究 GPIO，并开始将树莓派连接到现实世界。我们将使用外部 LED 创建一个莫尔斯电码生成器，然后使用这个生成器来闪烁模拟的天气信息。

第四章，“订阅 Web 服务”，探讨了一些世界上一些最大公司提供的一些网络服务。我们的项目将使用虚拟版本的树莓派 Sense HAT 作为滚动条，显示来自 Yahoo! Weather 网络服务的当前天气信息。

第五章，“使用 Python 控制舵机”，介绍了使用连接到树莓派的舵机电机创建模拟仪表针的概念。

第六章，“使用舵机控制代码控制模拟设备”，继续讨论使用舵机电机的主题，因为我们正在构建我们的第一个真正的物联网设备，一个天气仪表盘。这个天气仪表盘不仅会有一个模拟指针；它还将使用指针指向根据天气条件建议的衣柜图片。

第七章，“设置树莓派 Web 服务器”，介绍了如何安装和配置 Web 框架 CherryPy。我们将通过构建一个显示天气信息的本地网站来结束本章。

第八章，“使用 Python 读取树莓派 GPIO 传感器数据”，介绍了如何在转移到 PIR 传感器和距离传感器之前读取按钮的状态。我们将通过构建简单的报警系统来结束本章。

第九章，“构建家庭安全仪表盘”，解释了如何使用树莓派作为提供从 GPIO 收集的传感器数据的 HTML 内容的 Web 服务器来构建家庭安全仪表盘。

第十章，“发布到 Web 服务”，介绍了如何测量室温和湿度，并通过物联网仪表板将这些值发布到网络上。我们还将设置并运行使用 Twilio 服务的短信警报。

第十一章，“使用蓝牙创建门铃按钮”，将我们的重点转向本章中的蓝牙使用。蓝牙是一种无线技术，允许在短距离内传输数据。对于我们的项目，我们将探索 Android Play 商店中的 BlueDot 应用。我们将使用这个应用来构建一个简单的蓝牙连接门铃。

第十二章，“增强我们的物联网门铃”，将我们在“使用蓝牙创建门铃按钮”中创建的简单门铃转变为物联网门铃，使用我们在“发布到 Web 服务”中学到的知识。

第十三章，“介绍树莓派机器人车”，通过介绍这个令人惊叹的树莓派自动安全代理（T.A.R.A.S）开始了我们进入物联网机器人车的旅程。本章将首先概述我们构建 T.A.R.A.S 所需的组件，然后我们将继续将它们全部组装起来。

第十四章，*使用 Python 控制机器人车*，介绍了如何为我们的机器人车编写 Python 代码。我们将利用 GPIO Zero 库使车轮向前转动，移动携带摄像头的伺服电机，并点亮机器人车后面的 LED 灯。

第十五章，*将机器人车的感应输入连接到网络*，帮助我们理解，为了将我们的机器人车变成真正的物联网设备，我们必须将其连接到互联网。在本章中，我们将把机器人车的距离传感器连接到互联网。

第十六章，*通过 Web 服务调用控制机器人车*，继续将我们的机器人车变成物联网设备，深入研究了我们为机器人车创建的互联网仪表板。

第十七章，*构建 JavaScript 客户端*，将我们的注意力从 Python 转移到 JavaScript。我们将使用 JavaScript 构建一个基于 Web 的客户端，使用 MQTT 协议在互联网上进行通信。

第十八章，*将所有内容整合在一起*，介绍了我们将如何将我们的机器人车 T.A.R.A.S 连接到 JavaScript 客户端，并使用 MQTT 协议在互联网上进行控制。

# 为了充分利用本书

为了充分利用本书，我将假设以下情况：

+   您已经购买或将购买一台树莓派计算机，最好是 2015 年或更新的型号。

+   您对 Python 编程语言有一定了解，或者渴望学习它。

+   您对电子元件有基本的了解，并知道如何使用面包板。

+   您已经购买或愿意购买基本的电子元件。

在硬件需求方面，您至少需要以下设备：

+   一个树莓派 3 型号（2015 年或更新的型号）

+   一个 USB 电源适配器

+   一台计算机显示器

+   一个 USB 键盘

+   一个 USB 鼠标

+   一张 microSD RAM 卡

+   一个面包板和面包板跳线

每章节开始时会介绍额外的硬件部件。

在软件需求方面，您将需要树莓派 NOOBS 镜像（[`www.raspberrypi.org/downloads/noobs/`](https://www.raspberrypi.org/downloads/noobs/)）。额外的软件、账户和 Python 包将在途中介绍。本书中使用的任何软件、网络服务或 Python 包都是免费的。

# 下载示例代码文件

您可以从您在[www.packt.com](http://www.packt.com)的账户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，以便直接通过电子邮件接收文件。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)上登录或注册。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在“搜索”框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用以下最新版本解压或提取文件夹：

+   Windows 上的 WinRAR/7-Zip

+   Mac 上的 Zipeg/iZip/UnRarX

+   Linux 上的 7-Zip/PeaZip

本书的代码捆绑包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Internet-of-Things-Programming-Projects`](https://github.com/PacktPublishing/Internet-of-Things-Programming-Projects)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码捆绑包，来自我们丰富的图书和视频目录，可在**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**上找到。去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781789134803_ColorImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/9781789134803_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“为了访问 Python 3，我们在终端窗口中输入  `python3` 命令。”

代码块设置如下：

```py
wind_dir_str_len = 2
if currentWeather.getWindSpeed()[-2:-1] == ' ':
    wind_dir_str_len = 1
```

任何命令行输入或输出都以以下方式编写：

```py
pip3 install weather-api
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这是一个例子：“从 视图 菜单中，选择 对象检查器 和 变量。”

警告或重要说明会以这种方式出现。提示和技巧会以这种方式出现。


# 第一章：在树莓派上安装 Raspbian

树莓派被宣传为一台小巧实惠的计算机，您可以用来学习编程。至少这是它最初的目标。正如我们将在本书中看到的，它远不止于此。

本章将涵盖以下主题：

+   树莓派的简要历史

+   树莓派的操作系统

+   安装 Raspbian 操作系统

+   Raspbian 操作系统的快速概述

# 树莓派的简要历史

首次发布于 2012 年，第一代树莓派配备了 700 MHz 单核处理器和 256 MB 内存。树莓派 2 于 2015 年 2 月发布，配备了 900 MHz 四核处理器和 1 GB 内存。树莓派 3 于 2016 年 2 月发布，将处理器速度提高到 1.2 GHz。这款型号还是第一款包含无线局域网和蓝牙的型号。

以下是 2015 年树莓派 3 B 的图片：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/e63d1e50-e7ab-42e3-860f-f4e3bfaa5f2a.png)

这个版本的树莓派包括以下部分：

+   四个 USB 2 端口

+   一个 LAN 端口

+   一个 3.5 毫米复合视频和音频插孔

+   用于视频和音频的 HDMI 端口

+   一个 OTG USB 端口（我们将用它连接电源）

+   一个 microSD 插槽（用于放置我们的操作系统）

+   用于树莓派触摸屏的 DSI 显示端口

+   通用输入输出（GPIO）引脚

+   一个用于特殊树莓派摄像头的摄像头端口

树莓派 Zero 于 2015 年 11 月发布。以下是它的图片：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/96a78725-cada-4c3b-a2e6-cfd430518aa8.png)

尽管不如之前的树莓派强大，Zero 的尺寸更小（65 毫米 X 30 毫米），非常适合空间有限的项目（即可穿戴项目）。此外，树莓派 Zero 的价格为 5 美元，非常实惠。树莓派 Zero W 于 2017 年 2 月 28 日发布，价格翻倍（10 美元），内置 Wi-Fi 和蓝牙功能。

截至撰写本文时，最新型号是于 2018 年 3 月 14 日发布的树莓派 3 B+。处理器速度已升级至 1.4 GHz，无线局域网现在支持 2.4 GHz 和 5 GHz 频段。另一个升级是增加了低功耗蓝牙，这是一种为不需要大量数据交换但需要长电池寿命的应用程序而设计的技术。

树莓派的创造者最初认为他们最多只能卖出 1000 台。他们不知道他们的发明会爆炸式地受欢迎。截至 2018 年 3 月，树莓派计算机的销量已经超过了 1900 万台。

# 树莓派的操作系统

可以安装在树莓派上的各种操作系统（或系统镜像）从特定应用程序的操作系统，如音频播放器，到各种通用操作系统。树莓派的强大之处在于它可以用于各种应用和项目。

以下是一些适用于树莓派的操作系统（系统镜像）的列表：

+   Volumio：您是否想要建立一个网络音频系统，通过计算机或手机访问您的音乐列表？Volumio 可能是您正在寻找的东西。在树莓派上安装它可以创建一个无头音频播放器（不需要键盘和鼠标的系统），通过 USB 或网络连接到您的音频文件。可以添加一个特殊的音频 HAT（硬件附加在顶部）到您的 Pi 上，以提供纯净的音频连接到放大器和扬声器。甚至有一个插件可以添加 Spotify，这样您就可以设置您的树莓派访问这项服务，并在您的音响系统上播放音乐。

+   **PiFM 无线电发射器**：PiFM 无线电发射器将您的树莓派变成 FM 发射器，您可以使用它将音频文件通过空气发送到标准 FM 收音机。通过连接到 GPIO 引脚之一的简单导线（我们稍后将了解更多关于 GPIO 的知识），您可以为传输的 FM 信号创建天线，这个信号出奇地强。

+   **Stratux**：ADS-B 是航空领域的新标准，其中地理位置和天气信息与地面控制器和飞行员共享。 Stratux 镜像与附加硬件将树莓派变成这些信息的 ADS-B 接收器。

+   **RetroPie**：RetroPie 将您的树莓派变成一个复古游戏主机，通过模拟过去的游戏主机和计算机。一些模拟包括 Amiga，Apple II，Atari 2600 和 20 世纪 80 年代初的任天堂娱乐系统。

+   **OctoPi**：OctoPi 将您的树莓派变成 3D 打印机的服务器。通过 OctoPi，您可以通过网络控制您的 3D 打印机，包括使用网络摄像头查看您的 3D 打印机的状态。

+   **NOOBS**：这可能是在树莓派上安装操作系统的最简单方法。NOOBS 代表 New Out-Of-the Box Software，我们将使用 NOOBS 来安装 Raspbian。

# 项目概述

在这个项目中，我们将在我们的树莓派上安装 Raspbian 操作系统。安装完成后，我们将快速浏览操作系统以熟悉它。我们将首先格式化一个 microSD 卡来存储我们的安装文件。然后我们将从 microSD 卡运行安装。Raspbian 安装完成后，我们将快速浏览一下以熟悉它。

这个项目应该需要大约两个小时来完成，因为我们安装 Raspbian 操作系统并快速浏览一下。

# 入门

完成此项目需要以下内容：

+   一个树莓派 3 型（2015 年或更新型号）

+   USB 电源适配器

+   计算机显示器

+   USB 键盘

+   USB 鼠标

+   一个 microSD RAM 卡

+   树莓派 NOOBS 镜像（[`www.raspberrypi.org/downloads/noobs/`](https://www.raspberrypi.org/downloads/noobs/)）

# 安装 Raspbian 操作系统

Raspbian 操作系统被认为是树莓派的默认操作系统。在本节中，我们将使用 NOOBS 镜像安装 Raspbian。

# 为 Raspbian 格式化 microSD 卡

树莓派使用 microSD 卡存储操作系统。这使您可以轻松地在不同的操作系统（系统镜像）之间切换，用于您的树莓派。我们将使用 NOOBS 镜像为我们的项目安装默认的 Raspbian 操作系统。

首先将 microSD 卡插入 USB 适配器，然后插入计算机：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/8677f37c-23dd-4a1d-b823-1b3288e4b2b5.png)

您可能需要格式化 microSD 卡。如果需要，使用适合您计算机操作系统的工具将卡格式化为 FAT32。建议使用容量为 8GB 或更大的卡。对于 Windows 操作系统和容量为 64GB 或更大的卡，应使用第三方工具（如 FAT32 格式）进行格式化。

# 将 NOOBS 文件复制到 microSD RAM

解压您下载的 NOOBS 镜像。打开解压后的目录，将文件拖到 microSD 卡上。

文件应该与以下截图中的一样：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/139b6e01-51a0-477e-8c2c-89176b9fe7cd.png)

# 运行安装程序

现在我们将在树莓派上安装 Raspbian。这一步骤对于之前有安装 Windows 或 macOS 等操作系统经验的人来说应该很熟悉。Raspbian 操作系统将被安装并在我们的 microSD 卡上运行。

要在我们的 microSD 卡上安装 Raspbian，请执行以下操作：

1.  首先将 microSD 卡插入 Raspberry Pi 上的适当插槽。 请确保安装时标签面（暴露的接触面的对面）朝上。 将其与金属接触面朝向板子插入。 microSD 卡的标签面顶部应该有一个微小的凸起，方便用指甲轻松取出。

1.  将键盘和鼠标插入侧面的 USB 插槽，将显示器插入 HDMI 端口，最后将 USB 电源线插入电源端口。 Raspberry Pi 没有开关，只要连接电源线，它就会启动：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/4d90416c-f18d-42aa-b6b2-b731a8749950.png)

1.  在初始的黑屏上滚动白色文本后，您应该会看到以下对话框：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/49d9ea80-82e5-4404-b7aa-1c284550fb25.png)

1.  在上一个屏幕截图中，我们点击了语言选项。 对于我们的目的，我们将保持默认的英语（英国）。 我们还将保持标准的 gb 键盘。

1.  由于 Raspberry Pi 3 具有无线局域网，我们可以设置我们的 Wi-Fi（对于较旧的板，请将 Wi-Fi dongle 插入 USB 端口或使用有线 LAN 端口并跳过下一步）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/a9b9b607-7c5c-454f-b8f1-7f51d94eebf2.png)

1.  单击 Wifi 网络（w）按钮。 使用单选按钮选择认证方法。 一些路由器配备了 WPS 按钮，可让您直接连接到路由器。 要使用“密码”方法，请选择密码认证单选按钮，并输入网络的密码。 连接到网络后，您将注意到现在有更多的操作系统选项可供选择：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/543976c7-9dbb-4831-b1e5-a1b2a60ab932.png)

1.  我们将选择顶部选项 Raspbian。 在 Raspbian [RECOMMENDED]旁边勾选框，然后单击对话框左上角的安装（i）按钮。 Raspbian 将开始安装在您的 Raspberry Pi 上。 您将看到一个带有先前图形的进度条，描述 Raspbian 操作系统的各种功能：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/5a8f5fda-d42d-4e01-b9f2-a2f0f47c4665.png)

1.  进度条达到 100％后，计算机将重新启动，然后您将看到一个屏幕上的文本，然后默认桌面加载：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/520575fc-e358-435d-8301-f0941bdf1329.png)

# Raspbian OS 的快速概述

Raspbian 桌面与其他操作系统（如 Windows 和 macOS）的桌面类似。 点击左上角的按钮会弹出应用程序菜单，您可以在其中访问各种预安装的程序。 我们还可以从此菜单关闭 Raspberry Pi：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/609f7ed8-9e9c-46d2-807c-c2a36d837130.png)

# Chromium 网络浏览器

从左边数第二个按钮加载 Raspberry Pi 的 Google Chromium 网络浏览器：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/9a86f814-1356-4097-a788-1aa437189323.png)

Chromium 浏览器是一款轻量级浏览器，在 Raspberry Pi 上运行非常出色：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/28eac85f-e265-46de-a38d-272cf14bf715.png)

# home 文件夹

双文件夹按钮打开一个窗口，显示`home`文件夹：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/47bf1549-dad2-4768-91c8-9e8adf82c266.png)

`home`文件夹是在 Raspberry Pi 上查找文件的好地方。 实际上，当您使用`scrot`命令或 Print Screen 按钮进行截图时，文件会自动存储在此文件夹中：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/ca942e5e-401b-45e6-95ca-a3d9697a01cf.png)

# 终端

从左边数第三个按钮打开终端。 终端允许命令行访问 Raspberry Pi 的文件和程序：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/29e9805f-77d9-4601-af7b-0eaea2ce6f3c.png)

就是从命令行中，您可以使用`sudo apt-get update`和`sudo apt-get dist-upgrade`命令来更新 Raspberry Pi。

`apt-get`更新软件包列表，`apt-get dist-upgrade`更新软件包：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/0d520f34-4c38-4632-b63b-c065032bd906.png)

在安装 Raspbian 后，建议立即运行这两个命令，使用`sudo`命令。Raspberry Pi 上 Raspbian 的默认用户是`pi`，属于 Raspbian 中的超级用户组，因此必须使用`sudo`命令（`pi`用户的默认密码是`raspberry`）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/b43f2d57-82ae-4c84-86e9-7d7e86fa3f91.png)掌握命令行是许多程序员渴望掌握的一种技能。能够快速输入命令看起来很酷，甚至连电影制作人也注意到了（你上次看到电影中的电脑高手用鼠标在屏幕上点击是什么时候？）。为了帮助你成为这样一个超酷的电脑高手，这里有一些基本的 Raspbian 命令供你在终端中掌握：

`ls`：查看当前目录内容的命令

`cd`：切换目录的命令。例如，使用`cd`从当前目录上移一个目录

`pwd`：显示当前目录的命令

`sudo`：允许用户以超级用户的身份执行任务

`shutdown`：允许用户从终端命令行关闭计算机的命令

# Mathematica

第三和第四个按钮分别用于 Mathematica 和访问 Wolfram 语言的终端：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/72bbe447-1b96-4ceb-84ff-c88e1dcbd58f.png)

Mathematica 涵盖技术计算的各个领域，并使用 Wolfram 语言作为编程语言。Mathematica 的应用领域包括机器学习、图像处理、神经网络和数据科学：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/f0ee2eb4-9f29-4d9b-925b-c91d2388c712.png)

Mathematica 是一款专有软件，于 1988 年首次发布，通过 2013 年底宣布的合作伙伴关系，可以在 Raspberry Pi 上免费使用个人版。

现在让我们来看一些从主下拉菜单中访问的程序。

# Sonic Pi

Sonic Pi 是一个用于创建电子音乐的实时编码环境。可以从编程菜单选项中访问。Sonic Pi 是一种创造音乐的创新方式，用户可以通过实时剪切和粘贴代码来编写循环、琶音和音景。Sonic Pi 中的合成器可以进行深层配置，为音乐编码者提供定制体验：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/ba0d82e6-d8f5-48b9-8ee1-2c7b8eb3a3cc.png)

Sonic Pi 主要面向电子舞曲风格的音乐，也可以用来创作古典和爵士音乐风格。

# Scratch 和 Scratch 2.0

Scratch 和 Scratch 2.0 是为教授儿童编程而设计的可视化编程环境。使用 Scratch，程序员可以创建自己的动画，并使用循环和条件语句。

程序中可以创建游戏。Scratch 的第一个版本于 2003 年由麻省理工学院媒体实验室的终身幼儿园小组发布。Scratch 2.0 于 2013 年发布，目前正在开发 Scratch 3.0：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/9895522b-dd89-4968-9ece-cdd098b04418.png)

Scratch 和 Scratch 2.0 可以在编程菜单选项下访问。

# LibreOffice

LibreOffice 是一个免费开源的办公套件，于 2010 年从 OpenOffice 分支出来。LibreOffice 套件包括文字处理程序、电子表格程序、演示程序、矢量图形编辑器、用于创建和编辑数学公式的程序以及数据库管理程序。可以通过 LibreOffice 菜单选项访问 LibreOffice 程序套件：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/daf33d70-19fb-4037-b7e0-c61eb41817af.png)

# 总结

我们从 Raspberry Pi 的历史开始了本章。最初是为了推广编程教育给新一代人，现在已经发展成为一个全球现象。然后我们下载了 NOOBS 镜像并安装了 Raspbian 操作系统，这是 Raspberry Pi 的默认操作系统。这涉及格式化和准备 microSD 卡以安装 NOOBS 文件。

最容易认为像树莓派这样便宜小巧的计算机并不那么强大。我们证明了树莓派确实是一台非常有能力的计算机，因为我们看了一些预装在 Raspbian OS 上的应用程序。

在第二章中，*使用树莓派编写 Python 程序*，我们将开始使用树莓派和 Raspbian 中提供的一些开发工具进行 Python 编码。

# 问题

1.  第一款树莓派是在哪一年推出的？

1.  树莓派 3 Model B+相比上一个版本有哪些升级？

1.  NOOBS 代表什么？

1.  预装应用程序的名称是什么，它允许使用 Python 代码创建音乐？

1.  树莓派的操作系统存储在哪里？

1.  为儿童设计的可视化编程环境的名称是什么，它预装在 Raspbian 中？

1.  Mathematica 中使用的语言名称是什么？

1.  Raspbian 的默认用户名和密码是什么？

1.  GPIO 代表什么？

1.  RetroPie 是什么？

1.  真或假？单击主栏上的两个文件夹图标会加载“主目录”文件夹。

1.  真或假？microSD 卡槽位于树莓派的底部。

1.  真或假？要关闭树莓派，从应用程序菜单中选择关闭。

1.  真或假？只能使用 NOOBS 安装 Raspbian OS。

1.  真或假？蓝牙低功耗是指吃了太多蓝莓并且早上很难醒来的人。

# 进一步阅读

有关树莓派的更多信息，请参阅[www.raspberrypi.org](http://www.raspberrypi.org)上的主要树莓派网站。


# 第二章：使用树莓派编写 Python 程序

在本章中，我们将开始使用树莓派编写 Python 程序。Python 是树莓派的官方编程语言，并由 Pi 代表在名称中。

本章将涵盖以下主题：

+   树莓派的 Python 工具

+   使用 Python 命令行

+   编写一个简单的 Python 程序

Python 在 Raspbian 上预装了两个版本，分别是版本 2.7.14 和 3.6.5（截至目前为止），分别代表 Python 2 和 Python 3。这两个版本之间的区别超出了本书的范围。在本书中，我们将使用 Python 3，除非另有说明。

# 项目概述

在这个项目中，我们将熟悉树莓派上的 Python 开发。您可能已经习惯了在其他系统（如 Windows、macOS 和 Linux）上使用的开发工具或集成开发环境（IDE）。在本章中，我们将开始使用树莓派作为开发机器。随着我们开始使用 Python，我们将慢慢熟悉开发。

# 技术要求

完成此项目需要以下内容：

+   树莓派 3 型号（2015 年或更新型号）

+   USB 电源供应

+   计算机显示器

+   USB 键盘

+   USB 鼠标

# 树莓派的 Python 工具

以下是预装的工具，我们可以在树莓派上使用 Raspbian 进行 Python 开发。这个列表绝不是我们可以用于开发的唯一工具。

# 终端

由于 Python 预装在 Raspbian 上，启动它的简单方法是使用终端。如下面的屏幕截图所示，可以通过在终端窗口中输入`python`作为命令提示符来访问 Python 解释器：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/4b9ce0a3-278d-47ca-9aca-63a575d7e3e0.png)

我们可以通过运行最简单的程序来测试它：

```py
print 'hello'
```

注意命令后的 Python 版本，2.7.13。在 Raspbian 中，`python`命令与 Python 2 绑定。为了访问 Python 3，我们必须在终端窗口中输入`python3`命令：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/6dde2f30-1b0d-4210-8bff-83f5fbea886a.png)

# 集成开发和学习环境

自从版本 1.5.2 起，**集成开发和学习环境**（**IDLE**）一直是 Python 的默认 IDE。它本身是用 Python 编写的，使用 Tkinter GUI 工具包，并且旨在成为初学者的简单 IDE：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/93dcbe0c-8693-4603-9673-9117625b9595.png)

IDLE 具有多窗口文本编辑器，具有自动完成、语法高亮和智能缩进。对于使用过 Python 的任何人来说，IDLE 应该是很熟悉的。在 Raspbian 中有两个版本的 IDLE，一个用于 Python 2，另一个用于 Python 3。这两个程序都可以从应用程序菜单 | 编程中访问。

# Thonny

Thonny 是随 Raspbian 捆绑的 IDE。使用 Thonny，我们可以使用`debug`函数评估表达式。Thonny 也适用于 macOS 和 Windows。

要加载 Thonny，转到应用程序菜单 | 编程 | Thonny：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/787c8d31-e199-4c97-9f77-c2e83215cc25.png)

上面是 Thonny 的默认屏幕。可以从“视图”菜单中打开和关闭查看程序中的变量的面板，以及查看文件系统的面板。Thonny 的紧凑结构使其非常适合我们的项目。

随着我们继续阅读本书的其余部分，我们将更多地了解 Thonny。

# 使用 Python 命令行

让我们开始编写一些代码。每当我开始使用新的操作系统进行开发时，我都喜欢回顾一些基础知识，以便重新熟悉（我特别是在凌晨熬夜编码的时候）。

从终端最简单地访问 Python。我们将运行一个简单的程序来开始。从主工具栏加载终端，然后在提示符处输入`python3`。输入以下行并按*Enter*：

```py
from datetime import datetime
```

这行代码将`datetime`模块中的`datetime`对象加载到我们的 Python 实例中。接下来输入以下内容并按*Enter*：

```py
print(datetime.now())
```

你应该看到当前日期和时间被打印到屏幕上：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/dd45f391-4029-4246-a3f4-808a3d876518.png)

让我们再试一个例子。在 shell 中输入以下内容：

```py
import pyjokes
```

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/1a8ba55f-024a-41ef-a400-76b6e612d81c.png)

这是一个用来讲编程笑话的库。要打印一个笑话，输入以下内容并按*Enter*：

```py
pyjokes.get_joke()
```

你应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/59f16162-12c6-497a-8ccb-c9219b2aae76.png)

好的，也许这不是你的菜（对于 Java 程序员来说，也许是咖啡）。然而，这个例子展示了导入 Python 模块并利用它是多么容易。

如果你收到`ImportError`，那是因为`pyjokes`没有预先安装在你的操作系统版本中。类似以下例子，输入`sudo pip3 install pyjokes`将会在你的树莓派上安装`pyjokes`。

这些 Python 模块的共同之处在于它们可以供我们使用。我们只需要直接将它们导入到 shell 中以便使用，因为它们已经预先安装在我们的 Raspbian 操作系统中。但是，那些未安装的库呢？

让我们试一个例子。在 Python shell 中，输入以下内容并按*Enter*：

```py
import weather
```

你应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/0ef83036-57f0-4bf2-a46a-233b37f9ea3b.png)

由于`weather`包没有安装在我们的树莓派上，我们在尝试导入时会收到错误。为了安装这个包，我们使用 Python 命令行实用程序`pip`，或者在我们的情况下，使用`pip3`来进行 Python 3：

1.  打开一个新的终端（确保你在终端会话中，而不是 Python shell 中）。输入以下内容：

```py
pip3 install weather-api
```

1.  按*Enter*。你会看到以下内容：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/6f8c804a-290a-4a93-9d6d-37b67658a21e.png)

1.  进程完成后，我们将在树莓派上安装`weather-api`包。这个包将允许我们从 Yahoo! Weather 获取天气信息。

现在让我们试一些例子：

1.  输入`python3`并按*Enter*。现在你应该回到 Python shell 中了。

1.  输入以下内容并按*Enter*：

```py
from weather import Weather 
from weather import Unit
```

1.  我们已经从`weather`中导入了`Weather`和`Unit`。输入以下内容并按*Enter*：

```py
 weather = Weather(unit=Unit.CELSIUS)
```

1.  这实例化了一个名为`weather`的`weather`对象。现在，让我们使用这个对象。输入以下内容并按*Enter*：

```py
lookup = weather.lookup(4118)
```

1.  我们现在有一个名为`lookup`的变量，它是用代码`4118`创建的，对应于加拿大多伦多市。输入以下内容并按*Enter*：

```py
condition = lookup.condition
```

1.  我们现在有一个名为`condition`的变量，它包含了通过`lookup`变量获取的多伦多市的当前天气信息。要查看这些信息，输入以下内容并按*Enter*：

```py
print(condition.text)
```

1.  你应该得到多伦多市的天气状况描述。当我运行时，返回了以下内容：

```py
Partly Cloudy
```

现在我们已经看到，在树莓派上编写 Python 代码与在其他操作系统上编写一样简单，让我们再进一步编写一个简单的程序。我们将使用 Thonny 来完成这个任务。

Python 模块是一个包含可供导入使用的代码的单个 Python 文件。Python 包是一组 Python 模块。

# 编写一个简单的 Python 程序

我们将编写一个简单的 Python 程序，其中包含一个类。为此，我们将使用 Thonny，这是一个预先安装在 Raspbian 上并具有出色的调试和变量内省功能的 Python IDE。你会发现它的易用性使其成为我们项目开发的理想选择。

# 创建类

我们将从创建一个类开始我们的程序。类可以被看作是创建对象的模板。一个类包含方法和变量。要在 Thonny 中创建一个 Python 类，做如下操作：

1.  通过应用菜单 | 编程 | Thonny 加载 Thonny。从左上角选择新建并输入以下代码：

```py
class CurrentWeather:
    weather_data={'Toronto':['13','partly sunny','8 km/h NW'], 'Montreal':['16','mostly sunny','22 km/h W'],
                'Vancouver':['18','thunder showers','10 km/h NE'],
                'New York':['17','mostly cloudy','5 km/h SE'],
                'Los Angeles':['28','sunny','4 km/h SW'],
                'London':['12','mostly cloudy','8 km/h NW'],
                'Mumbai':['33','humid and foggy','2 km/h S']
                 }

     def __init__(self, city):
         self.city = city 

     def getTemperature(self):
         return self.weather_data[self.city][0]

     def getWeatherConditions(self):
         return self.weather_data[self.city][1]

     def getWindSpeed(self):
         return self.weather_data[self.city][2]
```

正如您所看到的，我们创建了一个名为`CurrentWeather`的类，它将保存我们为其实例化类的任何城市的天气条件。我们使用类是因为它将允许我们保持我们的代码清晰，并为以后使用外部类做好准备。

# 创建对象

我们现在将从我们的`CurrentWeather`类创建一个对象。我们将使用`London`作为我们的城市：

1.  单击顶部菜单中的“运行当前脚本”按钮（一个带有白色箭头的绿色圆圈）将我们的代码加载到 Python 解释器中。

1.  在 Thonny shell 的命令行上，输入以下内容并按*Enter*键：

```py
londonWeather = CurrentWeather('London')
```

我们刚刚在我们的代码中创建了一个名为`londonWeather`的对象，来自我们的`CurrentWeather`类。通过将`'London'`传递给构造函数（`init`），我们将我们的新对象设置为仅发送`London`城市的天气信息。这是通过类属性`city`（`self.city`）完成的。

1.  在 shell 命令行上输入以下内容：

```py
weatherLondon.getTemperature()
```

您应该在下一行得到答案`'12'`。

1.  要查看`London`的天气条件，请输入以下内容：

```py
weatherLondon.getWeatherConditions()
```

您应该在下一行看到“'大部分多云'”。

1.  要获取风速，请输入以下内容并按*Enter*键：

```py
weatherLondon.getWindSpeed()
```

您应该在下一行得到`8 km/h NW`。

我们的`CurrentWeather`类模拟了来自天气数据的网络服务的数据。我们类中的实际数据存储在`weather_data`变量中。

在以后的代码中，尽可能地将对网络服务的调用封装在类中，以便保持组织和使代码更易读。

# 使用对象检查器

让我们对我们的代码进行一些分析：

1.  从“视图”菜单中，选择“对象检查器”和“变量”。您应该看到以下内容：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/28a96595-39e3-41ba-bfec-573038792cfd.png)

1.  在“变量”选项卡下突出显示`londonWeather`变量。我们可以看到`londonWeather`是`CurrentWeather`类型的对象。在对象检查器中，我们还可以看到属性`city`设置为`'London'`。这种类型的变量检查在故障排除代码中非常宝贵。

# 测试您的类

在编写代码时测试代码非常重要，这样您就可以尽早地捕获错误：

1.  将以下函数添加到`CurrentWeather`类中：

```py
 def getCity(self):
     return self.city
```

1.  将以下内容添加到`CurrentWeather.py`的底部。第一行应该与类定义具有相同的缩进，因为此函数不是类的一部分：

```py
if __name__ == "__main__":
    currentWeather = CurrentWeather('Toronto')
    wind_dir_str_len = 2

    if currentWeather.getWindSpeed()[-2:-1] == ' ':
        wind_dir_str_len = 1

     print("The current temperature in",
            currentWeather.getCity(),"is",
            currentWeather.getTemperature(),
            "degrees Celsius,",
            "the weather conditions are",
            currentWeather.getWeatherConditions(),
            "and the wind is coming out of the",
            currentWeather.getWindSpeed()[-(wind_dir_str_len):],
            "direction with a speed of",
            currentWeather.getWindSpeed()
            [0:len(currentWeather.getWindSpeed())
            -(wind_dir_str_len)]
            )
```

1.  通过单击“运行当前脚本”按钮来运行代码。您应该看到以下内容：

```py
The current temperature in Toronto is 13 degrees Celsius, the weather conditions are partly sunny and the wind is coming out of the NW direction with a speed of 8 km/h 
```

`if __name__ == "__main__":`函数允许我们直接在文件中测试类，因为`if`语句只有在直接运行文件时才为真。换句话说，对`CurrentWeather.py`的导入不会执行`if`语句后面的代码。随着我们逐步阅读本书，我们将更多地探索这种方法。

# 使代码灵活

更通用的代码更灵活。以下是我们可以使代码更少具体的两个例子。

# 例一

`wind_dir_str_len`变量用于确定风向字符串的长度。例如，`S`方向只使用一个字符，而 NW 则使用两个。这样做是为了在方向仅由一个字符表示时，不包括额外的空格在我们的输出中：

```py
wind_dir_str_len = 2
if currentWeather.getWindSpeed()[-2:-1] == ' ':
    wind_dir_str_len = 1
```

通过使用`[-2:-1]`来寻找空格，我们可以确定这个字符串的长度，并在有空格时将其更改为`1`（因为我们从字符串的末尾返回两个字符）。

# 例二

通过向我们的类添加`getCity`方法，我们能够创建更通用名称的类，如`currentWeather`，而不是`torontoWeather`。这使得我们可以轻松地重用我们的代码。我们可以通过更改以下行来演示这一点：

```py
currentWeather = CurrentWeather('Toronto') 
```

我们将其更改为：

```py
currentWeather = CurrentWeather('Mumbai')
```

如果我们再次单击“运行”按钮运行代码，我们将得到句子中所有条件的不同值：

```py
The current temperature in Mumbai is 33 degrees Celsius, the weather conditions are humid and foggy and the wind is coming out of the S direction with a speed of 2 km/h 
```

# 总结

我们开始本章时讨论了 Raspbian 中可用的各种 Python 开发工具。在终端窗口中运行 Python 的最快最简单的方法。由于 Python 预先安装在 Raspbian 中，因此在终端提示符中使用`python`命令加载 Python（在本例中为 Python 2）。无需设置环境变量即可使命令找到程序。通过输入`python3`在终端中运行 Python 3。

我们还简要介绍了 IDLE，这是 Python 开发的默认 IDE。IDLE 代表集成开发和学习环境，是初学者学习 Python 时使用的绝佳工具。

Thonny 是另一个预先安装在 Raspbian 上的 Python IDE。Thonny 具有出色的调试和变量内省功能。它也是为初学者设计的 Python 开发工具，但是其易用性和对象检查器使其成为我们项目开发的理想选择。随着我们在书中的进展，我们将更多地使用 Thonny。

然后，我们立即开始编程，以激发我们的开发热情。我们从使用终端进行简单表达式开始，并以天气数据示例结束，该示例旨在模拟用于调用 Web 服务的对象。

在第三章中，*使用 GPIO 连接到外部世界*，我们将立即进入树莓派上编程最强大的功能，即 GPIO。 GPIO 允许我们通过连接到树莓派上的此端口的设备与现实世界进行交互。 GPIO 编程将使我们的 Python 技能提升到一个全新的水平。

# 问题

1.  Thonny 适用于哪些操作系统？

1.  我们如何从终端命令行进入 Python 2？

1.  Thonny 中的哪个工具用于查看对象内部的内容？

1.  给出两个原因，说明为什么我们在天气示例代码中使用对象。

1.  向`CurrentWeather`类添加一个名为`getCity`的方法的优点是什么？

1.  IDLE 是用哪种语言编写的？

1.  为了打印当前日期和时间，需要采取哪两个步骤？

1.  在我们的代码中，我们是如何补偿只用一个字母表示的风速方向的？

1.  `if __name__ =="__main__"`语句的作用是什么？

1.  IDLE 代表什么？

# 进一步阅读

*Dusty Phillips*的*Python 3 - 面向对象编程*，Packt Publishing。


# 第三章：使用 GPIO 连接到外部世界

在本章中，我们将开始解锁树莓派背后真正的力量——GPIO，或通用输入输出。 GPIO 允许您通过可以设置为输入或输出的引脚将树莓派连接到外部世界，并通过代码进行控制。

本章将涵盖以下主题：

+   树莓派的 Python 库

+   访问树莓派的 GPIO

+   设置电路

+   你好 LED

# 项目概述

在本章中，我们首先探索了 Python 的树莓派特定库。我们将使用树莓派相机模块和 Pibrella HAT 的几个示例来演示这些内容。在转到使用 Fritzing 程序设计物理电路之前，我们将尝试使用 Sense Hat 模拟器进行一些编码示例。使用面包板，我们将设置这个电路并将其连接到我们的树莓派。

我们将通过在第二章中创建的类中构建一个摩尔斯电码生成器，该生成器将以摩尔斯电码传输天气数据来结束本章，*使用树莓派编写 Python 程序*。完成本章应该需要一个下午的时间。

# 技术要求

完成此项目需要以下内容：

+   树莓派 3 型号（2015 年或更新型号）

+   USB 电源适配器

+   计算机显示器

+   USB 键盘

+   USB 鼠标

+   树莓派相机模块（可选）—[`www.raspberrypi.org/products/camera-module-v2/`](https://www.raspberrypi.org/products/camera-module-v2/)

+   Pribrella HAT（可选）—[www.pibrella.com](http://www.pibrella.com)

+   Sense HAT（可选，因为我们将在本章中使用模拟器）—[`www.raspberrypi.org/products/sense-hat/a`](https://www.raspberrypi.org/products/sense-hat/)

+   面包板

+   母对公跳线

+   LED

# 树莓派的 Python 库

我们将把注意力转向 Raspbian 预装的 Python 库或包。要从 Thonny 查看这些包，请单击工具|管理包。稍等片刻后，您应该会在对话框中看到许多列出的包：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/f8e2919c-6c5f-4f6b-b422-44c9bad7d1ed.png)

让我们来探索其中一些包。

# picamera

树莓派上的相机端口或 CSI 允许您将专门设计的树莓派相机模块连接到您的 Pi。该相机可以拍摄照片和视频，并具有进行延时摄影和慢动作视频录制的功能。`picamera`包通过 Python 使我们可以访问相机。以下是连接到树莓派 3 Model B 的树莓派相机模块的图片：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/60d9b712-4c92-452c-9930-4b35240bbf9f.png)

将树莓派相机模块连接到您的 Pi，打开 Thonny，并输入以下代码：

```py
import picamera
import time

picam = picamera.PiCamera()
picam.start_preview()
time.sleep(10)
picam.stop_preview()
picam.close()
```

此代码导入了`picamera`和`time`包，然后创建了一个名为`picam`的`picamera`对象。从那里，我们开始预览，然后睡眠`10`秒，然后停止预览并关闭相机。运行程序后，您应该在屏幕上看到来自相机的`10`秒预览。

# 枕头

Pillow 包用于 Python 图像处理。要测试这一点，请将图像下载到与项目文件相同的目录中。在 Thonny 中创建一个新文件，然后输入以下内容：

```py
from PIL import Image

img = Image.open('image.png')
print(img.format, img.size)
```

您应该在随后的命令行中看到图像的格式和大小（括号内）打印出来。

# sense-hat 和 sense-emu

Sense HAT 是树莓派的一个复杂的附加板。Sense HAT 是 Astro Pi 套件的主要组件，是一个让年轻学生为国际空间站编程树莓派的计划的一部分。

Astro Pi 比赛于 2015 年 1 月正式向英国所有小学和中学年龄的孩子开放。在对国际空间站的任务中，英国宇航员蒂姆·皮克在航天站上部署了 Astro Pi 计算机。

获胜的 Astro Pi 比赛代码被加载到太空中的 Astro Pi 上。生成的数据被收集并发送回地球。

Sense HAT 包含一组 LED，可用作显示器。Sense HAT 还具有以下传感器：

+   加速度计

+   温度传感器

+   磁力计

+   气压传感器

+   湿度传感器

+   陀螺仪

我们可以通过`sense-hat`包访问 Sense HAT 上的传感器和 LED。对于那些没有 Sense HAT 的人，可以使用 Raspbian 中的 Sense HAT 模拟器。我们使用`sense-emu`包来访问 Sense HAT 模拟器上模拟的传感器和 LED 显示。

为了演示这一点，请执行以下步骤：

1.  在 Thonny 中创建一个新文件，并将其命名为`sense-hat-test.py`，或类似的名称。

1.  键入以下代码：

```py
from sense_emu import SenseHat

sense_emulator = SenseHat()
sense_emulator.show_message('Hello World')
```

1.  从应用程序菜单|编程|Sense HAT 模拟器加载 Sense HAT 模拟器程序。

1.  调整屏幕，以便您可以看到 Sense HAT 模拟器的 LED 显示和 Thonny 的完整窗口（请参见下一张截图）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/366ddf47-8fe3-40c4-ae0a-3eadd23b99ff.png)

1.  单击**运行当前脚本**按钮。

1.  你应该看到“Hello World！”消息一次一个字母地滚动在 Sense HAT 模拟器的 LED 显示器上（请参见上一张截图）。

# 访问树莓派的 GPIO

通过 GPIO，我们能够连接到外部世界。以下是树莓派 GPIO 引脚的图示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/79dbd754-d3e8-462d-83c5-4eba89aed7ac.jpg)

以下是这些引脚的解释：

+   红色引脚代表 GPIO 输出的电源。GPIO 提供 3.3 伏特和 5 伏特。

+   黑色引脚代表用于电气接地的引脚。正如您所看到的，GPIO 上有 8 个接地引脚。

+   蓝色引脚用于树莓派的**硬件附加在顶部**（**HATs**）。它们允许树莓派和 HAT 的**电可擦可编程只读存储器**（**EEPROM**）之间的通信。

+   绿色引脚代表我们可以为其编程的输入和输出引脚。请注意，一些绿色 GPIO 引脚具有额外的功能。我们将不会涵盖这个项目的额外功能。

GPIO 是树莓派的核心。我们可以通过 GPIO 将 LED、按钮、蜂鸣器等连接到树莓派上。我们还可以通过为树莓派设计的 HAT 来访问 GPIO。其中之一叫做`Pibrella`，这是我们接下来将使用的，用来通过 Python 代码探索连接到 GPIO。

树莓派 1 型 A 和 B 型只有前 26 个引脚（如虚线所示）。从那时起的型号，包括树莓派 1 型 A+和 B+，树莓派 2，树莓派 Zero 和 Zero W，以及树莓派 3 型 B 和 B+，都有 40 个 GPIO 引脚。

# Pibrella

Pibrella 是一个相对便宜的树莓派 HAT，可以轻松连接到 GPIO。以下是 Pibrella 板上的组件：

+   1 个红色 LED

+   1 个黄色 LED

+   1 个绿色 LED

+   小音箱

+   按键

+   4 个输入

+   4 个输出

+   Micro USB 电源连接器，用于向输出提供更多电源

Pibrella 是为早期的树莓派型号设计的，因此只有 26 个引脚输入。但是，它可以通过前 26 个引脚连接到后来的型号。

要安装 Pibrella Hat，将 Pibrella 上的引脚连接器与树莓派上的前 26 个引脚对齐，并向下按。在下图中，我们正在将 Pibrella 安装在树莓派 3 型 B 上：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/e0cdda19-675f-4dd9-8be8-92b39e77bb6b.png)

安装 Pibrella 时应该很合适：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/4db07f13-e208-4307-9997-1d85ee2adc90.png)

连接到 Pibrella 所需的库在 Raspbian 中没有预先安装（截至撰写本文的时间），因此我们必须自己安装它们。为此，我们将使用终端中的`pip3`命令：

1.  通过单击顶部工具栏上的终端（从左起的第四个图标）加载终端。在命令提示符下，键入以下内容：

```py
sudo pip3 install pibrella
```

1.  您应该看到终端加载软件包：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/98d08ff7-12f1-4e83-8cad-e317d2db3e8d.png)

1.  使用`Pibrella`库，无需知道 GPIO 引脚编号即可访问 GPIO。该功能被包装在我们导入到代码中的`Pibrella`对象中。我们将进行一个简短的演示。

1.  在 Thonny 中创建一个名为`pibrella-test.py`的新文件，或者取一个类似的名字。键入以下代码：

```py
import pibrella
import time

pibrella.light.red.on()
time.sleep(5)
pibrella.light.red.off()
pibrella.buzzer.success()
```

1.  点击运行当前脚本按钮运行代码。如果您输入的一切都正确，您应该看到 Pibrella 板上的红灯在`5`秒钟内亮起，然后扬声器发出短暂的旋律。

恭喜，您现在已经跨越了物理计算的门槛。

# RPi.GPIO

用于访问 GPIO 的标准 Python 包称为`RPi.GPIO`。描述它的最佳方式是使用一些代码（这仅用于演示目的；我们将在接下来的部分中运行代码来访问 GPIO）：

```py
import RPi.GPIO as GPIO
import time

GPIO.setmode(GPIO.BCM)
GPIO.setup(18, GPIO.OUT)
GPIO.output(18, GPIO.HIGH)
time.sleep(5)
GPIO.output(18, GPIO.LOW)
```

正如您所看到的，这段代码似乎有点混乱。我们将逐步介绍它：

1.  首先，我们导入`RPi.GPIO`和`time`库：

```py
import RPi.GPIO as GPIO
import time
```

1.  然后，我们将模式设置为`BCM`：

```py
GPIO.setmode(GPIO.BCM)
```

1.  在 BCM 模式下，我们通过 GPIO 编号（显示在我们的树莓派 GPIO 图形中的编号）访问引脚。另一种方法是通过它们的物理位置（`GPIO.BOARD`）访问引脚。

1.  要将 GPIO 引脚`18`设置为输出，我们使用以下行：

```py
GPIO.setup(18, GPIO.OUT)
```

1.  然后我们将 GPIO `18`设置为`HIGH`，持续`5`秒，然后将其设置为`LOW`：

```py
GPIO.output(18, GPIO.HIGH)
time.sleep(5)
GPIO.output(18, GPIO.LOW)
```

如果我们设置了电路并运行了代码，我们会看到 LED 在`5`秒钟内亮起，然后关闭，类似于 Pibrella 示例。

# GPIO 零

`RPi.GPIO`的替代方案是 GPIO Zero 包。与`RPi.GPIO`一样，这个包已经预装在 Raspbian 中。名称中的零指的是零样板或设置代码（我们被迫每次输入的代码）。

为了完成打开和关闭 LED 灯 5 秒钟的相同任务，我们使用以下代码：

```py
from gipozero import LED
import time

led = LED(18)
led.on()
time.sleep(5)
led.off()
```

与我们的`RPi.GPIO`示例一样，这段代码仅用于演示目的，因为我们还没有设置电路。很明显，GPIO Zero 代码比`RPi.GPIO`示例简单得多。这段代码非常容易理解。

在接下来的几节中，我们将在面包板上构建一个物理电路，其中包括 LED，并使用我们的代码来打开和关闭它。

# 设置电路

Pibrella HAT 为我们提供了一种简单的编程 GPIO 的方法，然而，树莓派项目的最终目标是创建一个定制的工作电路。我们现在将采取步骤设计我们的电路，然后使用面包板创建电路。

第一步是在计算机上设计我们的电路。

# Fritzing

Fritzing 是一款免费的电路设计软件，适用于 Windows、macOS 和 Linux。树莓派商店中有一个版本，我们将在树莓派上安装它：

1.  从应用菜单中，选择首选项|添加/删除软件。在搜索框中，键入`Fritzing`：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/732813b5-525b-4bad-aac3-de11bd72da0a.png)

1.  选择所有三个框，然后单击应用，然后单击确定。安装后，您应该能够从应用菜单|编程|Fritzing 中加载 Fritzing。

1.  点击面包板选项卡以访问面包板设计屏幕。一个全尺寸的面包板占据了屏幕的中间。我们将它缩小，因为我们的电路很小而简单。

1.  点击面包板。在检查器框中，您会看到一个名为属性的标题。

1.  点击大小下拉菜单，选择 Mini。

1.  要将树莓派添加到我们的电路中，在搜索框中键入`Raspberry Pi`。将树莓派 3 拖到我们的面包板下方。

1.  从这里，我们可以将组件拖放到面包板上。

1.  将 LED 和 330 欧姆电阻器添加到我们的面包板上，如下图所示。我们使用电阻器来保护 LED 和树莓派免受可能造成损坏的过大电流：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/d26a7e02-67c4-48f9-9591-588675500457.png)

1.  当我们将鼠标悬停在树莓派组件的每个引脚上时，会弹出一个黄色提示，显示引脚的 BCM 名称。点击 GPIO 18，将线拖到 LED 的正极（较长的引脚）。

1.  同样，将 GND 连接拖到电阻的左侧。

这是我们将为树莓派构建的电路。

# 构建我们的电路

要构建我们的物理电路，首先要将组件插入我们的面包板。参考之前的图表，我们可以看到一些孔是绿色的。这表示电路中有连续性。例如，我们通过同一垂直列将 LED 的负极连接到 330 欧姆电阻。因此，两个组件的引脚通过面包板连接在一起。

在我们开始在面包板上放置组件时，我们要考虑这一点：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/f4d79016-46de-4fd7-9baa-94beaf95042d.png)

1.  将 LED 插入我们的面包板，如上图所示。我们遵循我们的 Fritzing 图表，并将正极插入下方的孔中。

1.  按照我们的 Fritzing 图表，连接 330 欧姆电阻。使用母对公跳线，将树莓派连接到面包板上。

1.  参考我们的树莓派 GPIO 图表，在树莓派主板上找到 GPIO 18 和 GND。

在连接跳线到 GPIO 时，最好将树莓派断电。

如下图所示，完整的电路类似于我们的 Fritzing 图表（只是我们的面包板和树莓派被转向）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/df8f25c1-4ead-4c0a-a641-2146ccb891ab.png)

1.  将树莓派重新连接到显示器、电源、键盘和鼠标。

我们现在准备好编程我们的第一个真正的 GPIO 电路。

# Hello LED

我们将直接进入代码：

1.  在 Thonny 中创建一个新文件，并将其命名为`Hello LED.py`或类似的名称。

1.  输入以下代码并运行：

```py
from gpiozero import LED

led = LED(18)
led.blink(1,1,10)
```

# 使用 gpiozero 闪烁 LED

如果我们正确连接了电路并输入了正确的代码，我们应该看到 LED 以 1 秒的间隔闪烁 10 秒。`gpiozero LED`对象中的`blink`函数允许我们设置`on_time`（LED 保持打开的时间长度，以秒为单位）、`off_time`（LED 关闭的时间长度，以秒为单位）、`n`或 LED 闪烁的次数，以及`background`（设置为`True`以允许 LED 闪烁时运行其他代码）。

带有默认参数的`blink`函数调用如下：

```py
blink(on_time=1, off_time=1, n=none, background=True)
```

在函数中不传递参数时，LED 将以 1 秒的间隔不停地闪烁。请注意，我们不需要像使用`RPi.GPIO`包访问 GPIO 时那样导入`time`库。我们只需将一个数字传递给`blink`函数，表示我们希望 LED 打开或关闭的时间（以秒为单位）。

# 摩尔斯码天气数据

在第二章中，*使用树莓派编写 Python 程序*，我们编写了模拟调用提供天气信息的网络服务的代码。根据本章学到的知识，让我们重新审视该代码，并对其进行物理计算升级。我们将使用 LED 来闪烁表示我们的天气数据的摩尔斯码。

我们中的许多人认为，世界直到 1990 年代才开始通过万维网变得连接起来。我们很少意识到，19 世纪引入电报和跨世界电报电缆时，我们已经有了这样一个世界。这个所谓的维多利亚时代互联网的语言是摩尔斯码，摩尔斯码操作员是它的门卫。

以下是闪烁摩尔斯码表示我们的天气数据的步骤：

1.  我们首先将创建一个`MorseCodeGenerator`类：

```py
from gpiozero import LED
from time import sleep

class MorseCodeGenerator:

    led = LED(18)
    dot_duration = 0.3
    dash_duration = dot_duration * 3
    word_spacing_duration = dot_duration * 7

    MORSE_CODE = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 
        'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..',
        'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---',
        'P': '.--.', 'Q': '--.-', 'R': '.-.',
       'S': '...', 'T': '-', 'U': '..-',
        'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..', '0': '-----',
        '1': '.----', '2': '..---', '3': '...--',
        '4': '....-', '5': '.....', '6': '-....',
        '7': '--...', '8': '---..', '9': '----.',
        ' ': ' '
        } 

    def transmit_message(self, message):
        for letter in message: 
            morse_code_letter = self.MORSE_CODE[letter.upper()]

            for dash_dot in morse_code_letter:

                if dash_dot == '.':
                    self.dot()

                elif dash_dot == '-':
                    self.dash()

                elif dash_dot == ' ':
                    self.word_spacing()

            self.letter_spacing()

    def dot(self):
        self.led.blink(self.dot_duration,self.dot_duration,1,False)

    def dash(self):
        self.led.blink(self.dash_duration,self.dot_duration,1,False)

    def letter_spacing(self):
        sleep(self.dot_duration)

    def word_spacing(self):
        sleep(self.word_spacing_duration-self.dot_duration)

if __name__ == "__main__":

    morse_code_generator = MorseCodeGenerator()
    morse_code_generator.transmit_message('SOS')    
```

1.  在我们的`MorseCodeGenerator`类中导入`gpiozero`和`time`库后，我们将 GPIO 18 定义为我们的 LED，代码为`led=LED(18)`

1.  我们使用`dot_duration = 0.3`来设置`dot`持续的时间。

1.  然后我们根据`dot_duration`定义破折号的持续时间和单词之间的间距。

1.  为了加快或减慢我们的莫尔斯码转换，我们可以相应地调整`dot_duration`。

1.  我们使用一个名为`MORSE_CODE`的 Python 字典。我们使用这个字典将字母转换为莫尔斯码。

1.  我们的`transmit_message`函数逐个遍历消息中的每个字母，然后遍历莫尔斯码中的每个字符，这相当于使用`dash_dot`变量。

1.  我们的类的魔力在`dot`和`dash`方法中发生，它们使用了`gpiozero`库中的`blink`函数：

```py
def dot(self):
       self.led.blink(self.dot_duration, self.dot_duration,1,False)
```

在`dot`方法中，我们可以看到我们将 LED 打开的持续时间设置为`dot_duration`，然后我们将其关闭相同的时间。我们只闪烁一次，因为在`blink`方法调用中将其设置为数字`1`。我们还将背景参数设置为`False`。

这个最后的参数非常重要，因为如果我们将其保留为默认值`True`，那么 LED 在有机会闪烁之前，代码将继续运行。基本上，除非将背景参数设置为`False`，否则代码将无法工作。

在我们的测试消息中，我们放弃了通常的`Hello World`，而是使用了标准的`SOS`，这对于大多数莫尔斯码爱好者来说是熟悉的。我们可以通过单击“运行”按钮来测试我们的类，如果一切设置正确，我们将看到 LED 以莫尔斯码闪烁 SOS。

现在，让我们重新审视一下第二章中的`CurrentWeather`类，即*使用树莓派编写 Python 程序*。我们将进行一些小的修改：

```py
from MorseCodeGenerator import MorseCodeGenerator

class CurrentWeather:

    weather_data={
        'Toronto':['13','partly sunny','8 NW'],
        'Montreal':['16','mostly sunny','22 W'],
        'Vancouver':['18','thunder showers','10 NE'],
        'New York':['17','mostly cloudy','5 SE'],
        'Los Angeles':['28','sunny','4 SW'],
        'London':['12','mostly cloudy','8 NW'],
        'Mumbai':['33','humid and foggy','2 S']
    }

    def __init__(self, city):
        self.city = city 

    def getTemperature(self):
        return self.weather_data[self.city][0]

    def getWeatherConditions(self):
        return self.weather_data[self.city][1]

    def getWindSpeed(self):
        return self.weather_data[self.city][2]

    def getCity(self):
        return self.city

if __name__ == "__main__":

    current_weather = CurrentWeather('Toronto')
    morse_code_generator = MorseCodeGenerator()
    morse_code_generator.transmit_message(current_weather.
    getWeatherConditions())

```

我们首先导入我们的`MorseCodeGenerator`类（确保两个文件在同一个目录中）。由于我们没有`/`的莫尔斯码等价物，我们从`weather_data`数据集中去掉了 km/h。类的其余部分与第二章中的内容保持一致，即*使用树莓派编写 Python 程序*。在我们的测试部分，我们实例化了`CurrentWeather`类和`MorseCodeGenerator`类。使用`CurrentWeather`类，我们将多伦多的天气条件传递给`MorseCodeGenerator`类。

如果在输入代码时没有出现任何错误，我们应该能够看到 LED 以莫尔斯码闪烁“部分晴天”。

# 摘要

本章涵盖了很多内容。到最后，您应该对在树莓派上开发应用程序感到非常满意。

`picamera`，`Pillow`和`sense-hat`库使得使用树莓派与外部世界进行通信变得很容易。使用树莓派摄像头模块和`picamera`，我们为树莓派打开了全新的可能性。我们只是触及了`picamera`的一小部分功能。此外，我们只是浅尝了`Pillow`库的图像处理功能。Sense HAT 模拟器使我们可以节省购买实际 HAT 的费用，并测试我们的代码。通过`sense-hat`和树莓派 Sense HAT，我们真正扩展了我们在物理世界中的影响力。

廉价的 Pibrella HAT 提供了一个简单的方式来进入物理计算世界。通过安装`pibrella`库，我们让我们的 Python 代码可以访问一系列 LED、扬声器和按钮，它们都被整齐地打包在一个树莓派 HAT 中。

然而，物理计算的真正终极目标是构建电子电路，以弥合我们的树莓派和外部世界之间的差距。我们开始使用树莓派商店提供的 Fritzing 电路构建器来构建电子电路。然后，我们在面包板上用 LED 和电阻器构建了我们的第一个电路。

我们通过使用树莓派和 LED 电路创建了一个莫尔斯码生成器来结束本章。在新旧结合的转折中，我们能够通过闪烁 LED 以莫尔斯码传输天气数据。

在[第四章]（626664bb-0130-46d1-b431-682994472fc1.xhtml）中，*订阅 Web 服务*，我们将把 Web 服务纳入我们的代码中，从而将互联网世界与现实世界连接起来，形成一个称为物联网的概念。

# 问题

1.  Python 包的名称是什么，可以让您访问树莓派相机模块？

1.  真或假？由学生编写的树莓派已部署在国际空间站上。

1.  Sense HAT 包含哪些传感器？

1.  真或假？我们不需要为开发购买树莓派 Sense HAT，因为 Raspbian 中存在这个 HAT 的模拟器。

1.  GPIO 上有多少个接地引脚？

1.  真或假？树莓派的 GPIO 引脚提供 5V 和 3.3V。

1.  Pibrella 是什么？

1.  真或假？只能在早期的树莓派计算机上使用 Pibrella。

1.  BCM 模式是什么意思？

1.  真或假？BOARD 是 BCM 的替代品。

1.  `gpiozero`中的 Zero 指的是什么？

1.  真或假？使用 Fritzing，我们可以为树莓派设计一个 GPIO 电路。

1.  `gpiozero` LED `blink`函数中的默认背景参数设置为什么？

1.  真或假？使用`gpiozero`库访问 GPIO 比使用`RPi.GPIO`库更容易。

1.  什么是维多利亚时代的互联网？

# 进一步阅读

本章涵盖了许多概念，假设所需的技能不超出普通开发人员和修补者的能力。为了进一步巩固对这些概念的理解，请谷歌以下内容：

+   如何安装树莓派相机模块

+   如何使用面包板？

+   Fritzing 电路设计软件简介

+   Python 字典

对于那些像我一样对过去的技术着迷的人，以下是一本关于维多利亚时代互联网的好书：*维多利亚时代的互联网*，作者汤姆·斯坦德奇。


# 第四章：订阅 Web 服务

我们许多人都认为互联网建立在其上的技术是理所当然的。当我们访问我们喜爱的网站时，我们很少关心我们正在查看的网页是为我们的眼睛而制作的。然而，在底层是通信协议的互联网协议套件。机器也可以利用这些协议，通过 Web 服务进行机器之间的通信。

在本章中，我们将继续我们的连接设备通过**物联网**（**IoT**）的旅程。我们将探索 Web 服务和它们背后的各种技术。我们将以一些 Python 代码结束我们的章节，其中我们调用一个实时天气服务并提取信息。

本章将涵盖以下主题：

+   物联网的云服务

+   编写 Python 程序提取实时天气数据

# 先决条件

读者应该具有 Python 编程语言的工作知识，以完成本章，以及对基本面向对象编程的理解。这将为读者服务良好，因为我们将把我们的代码分成对象。

# 项目概述

在这个项目中，我们将探索各种可用的 Web 服务，并涉及它们的核心优势。然后，我们将编写调用 Yahoo! Weather Web 服务的代码。最后，我们将使用树莓派 Sense HAT 模拟器显示实时天气数据的“滚动”显示。

本章应该需要一个上午或下午来完成。

# 入门

要完成这个项目，需要以下内容：

+   树莓派 3 型号（2015 年或更新型号）

+   USB 电源适配器

+   计算机显示器（支持 HDMI）

+   USB 键盘

+   USB 鼠标

+   互联网接入

# 物联网的云服务

有许多云服务可供我们用于物联网开发。一些科技界最大的公司已经全力支持物联网，特别是具有人工智能的物联网。

以下是一些这些服务的详细信息。

# 亚马逊网络服务 IoT

亚马逊网络服务 IoT 是一个云平台，允许连接设备与其他设备或云应用程序安全地交互。这些是按需付费的服务，无需服务器，从而简化了部署和可扩展性。

**亚马逊网络服务**（**AWS**）的服务，AWS IoT 核心可以使用如下：

+   AWS Lambda

+   亚马逊 Kinesis

+   亚马逊 S3

+   亚马逊机器学习

+   亚马逊 DynamoDB

+   亚马逊 CloudWatch

+   AWS CloudTrail

+   亚马逊 Elasticsearch 服务

AWS IoT 核心应用程序允许收集、处理和分析由连接设备生成的数据，无需管理基础设施。定价是按发送和接收的消息计费。

以下是 AWS IoT 的使用示意图。在这种情况下，汽车的道路状况数据被发送到云端并存储在 S3 云存储服务中。AWS 服务将这些数据广播给其他汽车，警告它们可能存在危险的道路状况：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/ec770430-be8c-48e1-b7d6-52bc9189240e.png)

# IBM Watson 平台

IBM Watson 是一个能够用自然语言回答问题的系统。最初设计用来参加电视游戏节目*Jeopardy!*，Watson 以 IBM 的第一任 CEO Thomas J. Watson 的名字命名。2011 年，Watson 挑战了*Jeopardy!*冠军 Brad Rutter 和 Ken Jennings 并获胜。

使用 IBM Watson 开发者云的应用程序可以通过 API 调用来创建。使用 Watson 处理物联网信息的潜力是巨大的。

直白地说，Watson 是 IBM 的一台超级计算机，可以通过 API 调用在网上访问。

Watson 与 IoT 的一个应用是 IBM Watson 助手汽车版，这是为汽车制造商提供的集成解决方案。通过这项技术，驾驶员和乘客可以与外界互动，例如预订餐厅和检查日历中的约会。车辆中的传感器可以集成，向 IBM Watson 助手提供车辆状态的信息，如轮胎压力。以下是一个图表，说明了 Watson 如何警告驾驶员轮胎压力过低，建议修理，并预约车库：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/aae158bc-7e55-4d14-af47-1db370364d77.png)

IBM Watson 助手汽车版作为白标服务出售，以便制造商可以将其标记为适合自己的需求。IBM Watson 助手汽车版的成功将取决于它与亚马逊的 Alexa 和谷歌的 AI 助手等其他 AI 助手服务的竞争情况。与 Spotify 音乐和亚马逊购物等热门服务的整合也将在未来的成功中发挥作用。

# 谷歌云平台

虽然谷歌的 IoT 并不像 AWS IoT 那样广泛和有文档记录，但谷歌对 IoT 的兴趣很大。开发人员可以通过使用谷歌云服务来利用谷歌的处理、分析和机器智能技术。

以下是谷歌云服务提供的一些服务列表：

+   App Engine：应用程序托管服务

+   BigQuery：大规模数据库分析服务

+   Bigtable：可扩展的数据库服务

+   Cloud AutoML：允许开发人员访问谷歌神经架构搜索技术的机器学习服务

+   云机器学习引擎：用于 TensorFlow 模型的机器学习服务

+   谷歌视频智能：分析视频并创建元数据的服务

+   云视觉 API：通过机器学习返回图像数据的服务

以下是谷歌云视觉 API 的使用图表。一张狗站在一个颠倒的花盆旁边的图片通过 API 传递给服务。图像被扫描，并且使用机器学习在照片中识别物体。返回的 JSON 文件包含结果的百分比：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/1699693d-94f5-49ec-91f7-180558df180d.png)

谷歌专注于使事情简单快捷，使开发人员可以访问谷歌自己的全球私人网络。谷歌云平台的定价低于 AWS IoT。

# 微软 Azure

微软 Azure（以前称为 Windows Azure）是微软的基于云的服务，允许开发人员使用微软庞大的数据中心构建、测试、部署和管理应用程序。它支持许多不同的编程语言，既是微软特有的，也来自外部第三方。

Azure Sphere 是微软 Azure 框架的一部分，于 2018 年 4 月推出，是 Azure 的 IoT 解决方案。以下是 Azure Sphere（或如图表所示的 Azure IoT）可能被使用的场景。在这种情况下，远程工厂中的机器人手臂通过手机应用程序进行监控和控制：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/71cf93b4-2b0e-46e1-a77b-190e426a4551.png)

您可能已经注意到，前面的例子可以使用任何竞争对手的云服务来设置，这确实是重点。通过相互竞争，服务变得更好、更便宜，因此更易获得。

随着 IBM、亚马逊、谷歌和微软等大公司参与 IoT 数据处理，IoT 的未来是无限的。

# Weather Underground

虽然不像谷歌和 IBM 那样重量级，Weather Underground 提供了一个天气信息的网络服务，开发人员可以将他们的应用程序与之联系起来。通过使用开发人员账户，可以构建利用当前天气条件的 IoT 应用程序。

在撰写本章时，Weather Underground 网络为开发人员提供了 API 以访问天气信息。自那时起，Weather Underground API 网站发布了服务终止通知。要了解此服务的状态，请访问[`www.wunderground.com/weather/api/`](https://www.wunderground.com/weather/api/)。

# 从云中提取数据的基本 Python 程序

在第二章中，*使用树莓派编写 Python 程序*，我们介绍了一个名为`weather-api`的包，它允许我们访问 Yahoo! Weather Web 服务。在本节中，我们将在我们自己的类中包装`weather-api`包中的`Weather`对象。我们将重用我们的类名称`CurrentWeather`。在测试我们的`CurrentWeather`类之后，我们将在 Raspbian 中利用 Sense Hat 模拟器并构建一个天气信息滚动条。

# 访问 Web 服务

我们将首先修改我们的`CurrentWeather`类，以通过`weather-api`包对 Yahoo! Weather 进行 Web 服务调用：

1.  从应用程序菜单|编程|Thonny Python IDE 打开 Thonny。

1.  单击新图标创建新文件。

1.  输入以下内容：

```py
from weather import Weather, Unit

class CurrentWeather:
     temperature = ''
     weather_conditions = ''
     wind_speed = ''
     city = ''

     def __init__(self, city):
         self.city = city
         weather = Weather(unit = Unit.CELSIUS)
         lookup = weather.lookup_by_location(self.city)
         self.temperature = lookup.condition.temp
         self.weather_conditions = lookup.condition.text
         self.wind_speed = lookup.wind.speed

     def getTemperature(self):
         return self.temperature

     def getWeatherConditions(self):
         return self.weather_conditions

     def getWindSpeed(self):
         return self.wind_speed

     def getCity(self):
         return self.city

if __name__=="__main__":
        current_weather = CurrentWeather('Montreal')
        print("%s %sC %s wind speed %s km/h"
        %(current_weather.getCity(),
        current_weather.getTemperature(),
        current_weather.getWeatherConditions(),
        current_weather.getWindSpeed()))
```

1.  将文件保存为`CurrentWeather.py`。

1.  运行代码。

1.  您应该在 Thonny 的 shell 中看到来自 Web 服务的天气信息打印出来。当我运行程序时，我看到了以下内容：

```py
Toronto 12.0C Clear wind speed 0 km/h
```

1.  现在，让我们仔细看看代码，看看发生了什么。我们首先从我们需要的程序包中导入资源：

```py
from weather import Weather, Unit
```

1.  然后我们定义我们的类名`CurrentWeather`，并将类变量（`temperature`、`weather_conditions`、`wind_speed`和`city`）设置为初始值：

```py
class CurrentWeather:
     temperature = ''
     weather_conditions = ''
     wind_speed = ''
     city = ''
```

1.  在`init`方法中，我们根据传入方法的`city`设置我们的类变量。我们通过将一个名为`weather`的变量实例化为`Weather`对象，并将`unit`设置为`CELSIUS`来实现这一点。`lookup`变量是基于我们传入的`city`名称创建的。从那里，简单地设置我们的类变量（`temperature`、`weather_conditions`和`wind_speed`）从我们从`lookup`中提取的值。`weather-api`为我们完成了所有繁重的工作，因为我们能够使用点表示法访问值。我们无需解析 XML 或 JSON 数据：

```py
def __init__(self, city):
    self.city = city
    weather = Weather(unit = Unit.CELSIUS)
    lookup = weather.lookup_by_location(self.city)
    self.temperature = lookup.condition.temp
    self.weather_conditions = lookup.condition.text
     self.wind_speed = lookup.wind.speed
```

1.  在`init`方法中设置类变量后，我们使用方法调用来返回这些类变量：

```py
def getTemperature(self):
    return self.temperature

def getWeatherConditions(self):
    return self.weather_conditions

def getWindSpeed(self):
    return self.wind_speed

def getCity(self):
    return self.city
```

1.  由于我们在 Thonny 中作为程序运行`CurrentWeather.py`，我们可以使用`if __name__=="__main__"`方法并利用`CurrentWeather`类。请注意，`if __name__=="__main__"`方法的缩进与类名相同。如果不是这样，它将无法工作。

在 Python 的每个模块中，都有一个名为`__name__`的属性。如果您要检查已导入到程序中的模块的此属性，您将得到返回的模块名称。例如，如果我们在前面的代码中放置行`print(Weather.__name__)`，我们将得到名称`Weather`。在运行文件时检查`__name__`返回`__main__`值。

1.  在`if __name__=="__main__"`方法中，我们创建一个名为`current_weather`的`CurrentWeather`类型的对象，传入城市名`Montreal`。然后，我们使用适当的方法调用打印出`city`、`temperature`、`weather conditions`和`wind speed`的值：

```py
if __name__=="__main__":
    current_weather = CurrentWeather('Montreal')
    print("%s %sC %s wind speed %s km/h"
    %(current_weather.getCity(),
    current_weather.getTemperature(),
    current_weather.getWeatherConditions(),
    current_weather.getWindSpeed()))
```

# 使用 Sense HAT 模拟器

现在，让我们使用树莓派 Sense HAT 模拟器来显示天气数据。我们将利用我们刚刚创建的`CurrentWeather`类。要在 Sense HAT 模拟器中看到显示的天气信息，请执行以下操作：

1.  从应用程序菜单|编程|Thonny Python IDE 打开 Thonny

1.  单击新图标创建新文件

1.  输入以下内容：

```py
from sense_emu import SenseHat
from CurrentWeather import CurrentWeather

class DisplayWeather:
    current_weather = ''

    def __init__(self, current_weather):
        self.current_weather = current_weather

    def display(self):
        sense_hat_emulator = SenseHat()

        message = ("%s %sC %s wind speed %s km/h"
           %(self.current_weather.getCity(),
           self.current_weather.getTemperature(),
           self.current_weather.getWeatherConditions(),
           self.current_weather.getWindSpeed()))

        sense_hat_emulator.show_message(message)

if __name__ == "__main__":
    current_weather = CurrentWeather('Toronto')
    display_weather = DisplayWeather(current_weather)
    display_weather.display()
```

1.  将文件保存为`DisplayWeather.py`

1.  从应用程序菜单|编程|Sense HAT 模拟器加载 Sense HAT 模拟器

1.  将 Sense HAT 模拟器定位到可以看到显示的位置

1.  运行代码

你应该在 Sense HAT 模拟器显示器上看到`多伦多`的天气信息滚动条，类似于以下截图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/9cfaaa47-606f-426e-a44c-1c86b418d7dd.png)

那么，我们是如何做到这一点的呢？`init`和`message`方法是这个程序的核心。我们通过设置类变量`current_weather`来初始化`DisplayWeather`类。一旦`current_weather`被设置，我们就在`display`方法中从中提取值，以便构建我们称之为`message`的消息。然后我们也在`display`方法中创建一个`SenseHat`模拟器对象，并将其命名为`sense_hat_emulator`。我们通过`sense_hat_emulator.show_message(message)`这一行将我们的消息传递给`SenseHat`模拟器的`show_message`方法：

```py
def __init__(self, current_weather):
    self.current_weather = current_weather

def display(self):
    sense_hat_emulator = SenseHat()

    message = ("%s %sC %s wind speed %s km/h"
           %(self.current_weather.getCity(),
           self.current_weather.getTemperature(),
           self.current_weather.getWeatherConditions(),
           self.current_weather.getWindSpeed()))

    sense_hat_emulator.show_message(message)
```

# 总结

我们从讨论一些可用的各种网络服务开始了本章。我们讨论了一些在人工智能和物联网领域中最大的信息技术公司的工作。

亚马逊和谷歌都致力于成为物联网设备连接的平台。亚马逊通过其亚马逊网络服务提供了大量的文档和支持。谷歌也在建立一个强大的物联网平台。哪个平台会胜出还有待观察。

IBM 在人工智能领域的涉足集中在 Watson 上，他们的*Jeopardy!*游戏冠军。当然，赢得游戏秀并不是 Watson 的最终目标。然而，从这些追求中建立的知识和技术将会进入我们今天只能想象的领域。Watson 可能会被证明是物联网世界的所谓杀手应用程序。

也许没有什么比天气更多人谈论的了。在本章中，我们使用`weather-api`包利用内置在 Raspbian 操作系统中的树莓派 Sense HAT 模拟器构建了一个天气信息滚动条。

在第五章中，*使用 Python 控制舵机*，我们将探索使用舵机以提供模拟显示的其他通信方式。

# 问题

1.  IBM Watson 是什么？

1.  真的还是假的？亚马逊的物联网网络服务允许访问亚马逊的其他基于云的服务。

1.  真的还是假的？Watson 是*Jeopardy!*游戏秀的冠军吗？

1.  真的还是假的？谷歌有他们自己的全球私人网络。

1.  真的还是假的？当我们引入网络服务数据时，我们需要更改函数的名称，比如`getTemperature`。

1.  真的还是假的？在你的类中使用测试代码以隔离该类的功能是一个好主意。

1.  在我们的代码中，`DisplayWeather`类的目的是什么？

1.  在我们的代码中，我们使用`SenseHat`对象的哪种方法来在 Sense HAT 模拟器中显示天气信息？

# 进一步阅读

在扩展你对网络服务的知识时，通过谷歌搜索可用的各种网络服务是一个很好的起点。


# 第五章：使用 Python 控制舵机

在数字技术兴起之前，模拟仪表和仪器是显示数据的唯一方式。一旦转向数字技术，模拟仪表就不再流行。在模拟时钟上学习报时的一代人可能会突然发现这项技能已经过时，因为数字显示时间已经成为常态。

在本章中，我们将通过根据数字值改变舵机的位置来弥合数字世界和模拟世界之间的差距。

本章将涵盖以下主题：

+   将舵机连接到树莓派

+   通过命令行控制舵机

+   编写一个 Python 程序来控制舵机

# 完成本章所需的知识

读者需要对 Python 编程语言有一定的了解才能完成本章。还必须了解使用简单的面包板连接组件。

# 项目概述

在这个项目中，我们将连接一个舵机和 LED，并使用`GPIO Zero`库来控制它。我们将首先在 Fritzing 中设计电路，然后进行组装。

我们将开始使用 Python shell 来控制舵机。

最后，我们将通过创建一个 Python 类来扩展这些知识，该类将根据传递给类的数字打开、关闭或闪烁 LED，并根据百分比量来转动舵机。

这个项目应该需要大约 2 个小时来完成。

# 入门

完成这个项目需要以下物品：

+   树莓派 3 型号（2015 年或更新型号）

+   USB 电源适配器

+   计算机显示器

+   USB 键盘

+   USB 鼠标

+   一个小型舵机

+   面包板

+   LED（任何颜色）

+   面包板的跳线

# 将舵机连接到树莓派

这个项目涉及将舵机连接到我们的树莓派。许多人将舵机与步进电机和直流电机混淆。让我们来看看这些类型的电机之间的区别。

# 步进电机

步进电机是无刷直流电动机，可以移动等步长的完整旋转。电机的位置是在没有使用反馈系统（开环系统）的情况下控制的。这使得步进电机相对廉价，并且在机器人、3D 打印机和数控机床等应用中很受欢迎。

以下是步进电机内部工作的粗略图示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/35ada15a-697a-46e7-9680-659725d49243.jpg)

通过按顺序打开和关闭线圈 A 和 B，可以旋转连接到电机轴的永磁体。使用精确的步骤，可以精确控制电机，因为步数可以轻松控制。

步进电机往往比其他类型的小型电机更重更笨重。

以下照片显示了 3D 打印机中使用的典型步进电机：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/29d7c3f6-9842-4328-aa1e-6d1fac677db1.png)

# 直流电机

直流电机与步进电机类似，但不会将运动分成相等的步骤。它们是最早被广泛使用的电动机，并且在电动汽车、电梯和任何不需要精确控制电机位置的应用中使用。直流电机可以是刷式或无刷的。

刷式电机操作起来更简单，但在每分钟转数（RPM）和使用寿命上有限制。无刷电机更复杂，需要电子控制，例如一些无人机上使用的电子调速器（ESC）。无刷电机可以以更高的转速运行，并且比刷式电机有更长的使用寿命。

直流电机的响应时间比步进电机短得多，并且比可比较的步进电机更轻。

以下是典型的小型刷式直流电机的照片：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/a1a836f9-1ba8-4389-a264-e9334868bcba.png)

# 舵机

舵机利用闭环反馈机制来提供对电机位置的极其精确的控制。它们被认为是步进电机的高性能替代品。范围可以根据舵机的不同而变化，有些舵机限制在 180 度运动，而其他舵机可以运动 360 度。

闭环控制系统与开环控制系统不同，它通过测量输出的实际条件并将其与期望的结果进行比较来维持输出。闭环控制系统通常被称为反馈控制系统，因为正是这种反馈被用来调整条件。

舵机的角度由传递到舵机控制引脚的脉冲决定。不同品牌的舵机具有不同的最大和最小值，以确定舵机指针的角度。

以下是一个图表，用于演示**脉冲宽度调制**（**PWM**）与 180 度舵机位置之间的关系：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/2f396a7b-6ff8-4927-b78c-9b6e8e46d669.jpg)

以下是我们将在电路中使用的小型舵机的照片。我们可以直接将这个舵机连接到我们的树莓派（较大的舵机可能无法实现）：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/f4c4ea4c-ac2d-443e-95c3-adeb4af4fd75.png)

以下是舵机颜色代码的图表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/d0ff3d63-d318-408e-aa5d-f8b7c7d0e08e.png)

# 将舵机连接到我们的树莓派

我们的电路将由一个简单的舵机和 LED 组成。

以下是电路的 Fritzing 图：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/51200b9c-1606-418a-b96b-dfc27c026afe.png)

我们连接：

+   舵机的正电源到 5V 直流电源，地到 GND

+   从舵机到 GPIO 17 的控制信号

+   LED 的正极连接到 GPIO 14，电阻连接到 GND

确保使用小型舵机，因为较大的舵机可能需要比树莓派能够提供的更多电力。电路应该类似于以下内容：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/02e23687-6fd6-40d8-9f3c-a9d313002c39.png)

# 通过命令行控制舵机

现在我们的舵机已连接到树莓派，让我们在命令行中编写一些代码来控制它。我们将使用树莓派 Python 库`GPIO Zero`来实现这一点。

加载 Thonny 并点击 Shell：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/iot-prog-pj/img/60473ee5-7d07-4f6d-a96d-697fe870bd5b.png)

在 Shell 中输入以下内容：

```py
from gpiozero import Servo
```

短暂延迟后，光标应该返回。我们在这里所做的是将`gpiozero`中的`servo`对象加载到内存中。我们将使用以下语句为引脚 GPIO `17`分配：

```py
servo = Servo(17)
```

现在，我们将舵机移动到最小（`min`）位置。在命令行中输入以下内容：

```py
servo.min()
```

你应该听到舵机在移动，指针将移动到最远的位置（如果它还没有在那里）。

使用以下命令将舵机移动到最大（`max`）位置：

```py
servo.max()
```

现在，使用以下命令将舵机移动到中间（`mid`）位置：

```py
servo.mid()
```

舵机应该移动到其中间位置。

当你把手放在舵机上时，你可能会感到轻微的抽搐运动。要暂时禁用对舵机的控制，请在命令行中输入以下内容并按 Enter 键：

```py
servo.detach()
```

抽搐运动应该停止，附在舵机上的指针指示器应该保持在当前位置。

正如我们所看到的，很容易将舵机移动到其最小、中间和最大值。但是如果我们想要更精确地控制舵机怎么办？在这种情况下，我们可以使用`servo`对象的 value 属性。可以使用介于`-1`（最小）和`1`（最大）之间的值来移动舵机。

在命令行中输入以下内容：

```py
servo.value=-1
```

`servo`应该移动到其最小位置。现在，输入以下内容：

```py
servo.value=1
```

`servo`现在应该移动到其最大位置。让我们使用 value 属性来指示天气条件。在命令行中输入以下内容：

```py
weather_conditions = {'cloudy':-1, 'partly cloudy':-0.5, 'partly sunny': 0.5, 'sunny':1}
```

在 Shell 中使用以下代码进行测试：

```py
weather_conditions['partly cloudy']
```

你应该在 Shell 中看到以下内容：

```py
-0.5
```

有了我们的`servo`对象和我们的`weather_conditions`字典，我们现在可以使用伺服电机来物理地指示天气条件。在 shell 中输入以下内容：

```py
servo.value = weather_conditions['cloudy']
```

伺服电机应该移动到最小位置，以指示天气条件为“多云”。现在，让我们尝试“晴朗”：

```py
servo.value = weather_conditions['sunny']
```

伺服应该移动到最大位置，以指示“晴朗”的天气条件。

对于“局部多云”和“局部晴朗”的条件，使用以下内容：

```py
servo.value = weather_conditions['partly cloudy']
```

```py
servo.value = weather_conditions['partly sunny']
```

# 编写一个 Python 程序来控制伺服

杰瑞·塞范菲尔德曾开玩笑说，我们需要知道天气的全部信息就是：我们是否需要带上外套？在本章和下一章的其余部分中，我们将建立一个模拟仪表针仪表板，以指示天气条件所需的服装。

我们还将添加一个 LED，用于指示需要雨伞，并闪烁以指示非常恶劣的风暴。

在我们可以在第六章中构建仪表板之前，我们需要代码来控制伺服和 LED。我们将首先创建一个类来实现这一点。

这个类将在我们的电路上设置伺服位置和 LED 状态：

1.  从应用程序菜单 | 编程 | Thonny Python IDE 打开 Thonny

1.  单击新图标创建一个新文件

1.  输入以下内容：

```py
from gpiozero import Servo
from gpiozero import LED

class WeatherDashboard:

    servo_pin = 17
    led_pin = 14

    def __init__(self, servo_position=0, led_status=0):      
        self.servo = Servo(self.servo_pin)
        self.led = LED(self.led_pin)      
        self.move_servo(servo_position)
        self.set_led_status(led_status)

    def move_servo(self, servo_position=0): 
        self.servo.value=self.convert_percentage_to_integer
        (servo_position)

    def set_led_status(self, led_status=0):       
        if(led_status==0):
            self.led.off()
        elif (led_status==1):
            self.led.on()
        else:
            self.led.blink()

    def convert_percentage_to_integer(self, percentage_amount):
        return (percentage_amount*0.02)-1

if __name__=="__main__":
    weather_dashboard = WeatherDashboard(50, 1)
```

1.  将文件保存为`WeatherDashboard.py`

1.  运行代码

1.  您应该看到伺服移动到中间位置，LED 应该打开

尝试其他值，看看是否可以将伺服移动到 75%并使 LED 闪烁。

让我们来看看代码。在定义类之后，我们使用以下内容为伺服和 LED 设置了 GPIO 引脚值：

```py
servo_pin = 17
led_pin = 14
```

正如您在我们建立的电路中看到的那样，我们将伺服和 LED 分别连接到 GPIO`17`和 GPIO`14`。GPIO Zero 允许我们轻松地分配 GPIO 值，而无需样板代码。

在我们的类初始化方法中，我们分别创建了名为`servo`和`led`的`Servo`和`LED`对象：

```py
self.servo = Servo(self.servo_pin)
self.led = LED(self.led_pin) 
```

从这里开始，我们调用我们类中移动伺服和设置 LED 的方法。让我们看看第一个方法：

```py
def move_servo(self, servo_position=0): 
        self.servo.value=self.convert_percentage_to_integer
        (servo_position)
```

在这个方法中，我们只需设置`servo`对象中的值属性。由于此属性仅接受从`-1`到`1`的值，而我们传递的值是从`0`到`100`，因此我们需要将我们的`servo_position`进行转换。我们使用以下方法来实现这一点：

```py
def convert_percentage_to_integer(self, percentage_amount):
    return (percentage_amount*0.02)-1
```

为了将百分比值转换为`-1`到`1`的比例值，我们将百分比值乘以`0.02`，然后减去`1`。通过使用百分比值为`50`来验证这个数学问题是很容易的。值为`50`代表了`0`到`100`比例中的中间值。将`50`乘以`0.02`得到了值为`1`。从这个值中减去`1`得到了`0`，这是`-1`到`1`比例中的中间值。

要设置 LED 的状态（关闭、打开或闪烁），我们从初始化方法中调用以下方法：

```py
def set_led_status(self, led_status=0):       
    if(led_status==0):
        self.led.off()
    elif (led_status==1):
        self.led.on()
    else:
        self.led.blink()
```

在`set_led_status`中，如果传入的值为`0`，我们将 LED 设置为“关闭”，如果值为`1`，我们将其设置为“打开”，如果是其他值，我们将其设置为“闪烁”。

我们用以下代码测试我们的类：

```py
if __name__=="__main__":
    weather_dashboard = WeatherDashboard(50, 1)
```

在第六章中，*使用伺服控制代码控制模拟设备*，我们将使用这个类来构建我们的模拟天气仪表板。

# 总结

正如我们所看到的，使用树莓派轻松地将数字世界和模拟世界之间的差距进行数据显示。其 GPIO 端口允许轻松连接各种输出设备，如电机和 LED。

在本章中，我们连接了一个伺服电机和 LED，并使用 Python 代码对它们进行了控制。我们将在第六章中扩展这一点，使用伺服控制代码来控制模拟设备，构建一个带有模拟仪表盘显示的物联网天气仪表板。

# 问题

1.  真还是假？步进电机是使用开环反馈系统控制的。

1.  如果您要建造一辆电动汽车，您会使用什么类型的电动机？

1.  真或假？舵机被认为是步进电机的高性能替代品。

1.  是什么控制了舵机的角度？

1.  真或假？直流电机的响应时间比步进电机短。

1.  我们使用哪个 Python 包来控制我们的舵机？

1.  真或假？我们能够在 Thonny 的 Python shell 中控制舵机。

1.  用什么命令将舵机移动到最大位置？

1.  真或假？我们只能将舵机移动到最小、最大和中间位置。

1.  我们如何将百分比值转换为代码中`servo`对象理解的相应值？

# 进一步阅读

`GPIO Zero`文档提供了对这个令人惊叹的树莓派 Python 库的完整概述。了解更多信息，请访问[`gpiozero.readthedocs.io/en/stable/`](https://gpiozero.readthedocs.io/en/stable/)。
