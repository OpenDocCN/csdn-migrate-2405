# JavaScript 物联网编程（一）

> 原文：[`zh.annas-archive.org/md5/98FAEC66467881BC21EC8531C753D4EC`](https://zh.annas-archive.org/md5/98FAEC66467881BC21EC8531C753D4EC)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

树莓派 Zero 是一款功能强大、价格低廉、信用卡大小的计算机，非常适合开始控制复杂的家庭自动化设备。使用可用的板载接口，树莓派 Zero 可以扩展，允许连接几乎无限数量的安全传感器和设备。

由于 Arduino 平台更加多功能和有用于制作项目，包括物联网的网络应用，这就是我们将在本书中看到的：连接到节点的设备的集成，使用令人惊叹和重要的 Arduino 板，以及如何集成树莓派 Zero 来控制和监控设备，从而形成一个作为中心界面工作的中心。通过软件编程，您将创建一个基于 JavaScript、HTML5 和 Node.js 等发展技术的物联网系统。

这正是我将在这本书中教给你的。您将学习如何在几个家庭自动化项目中使用树莓派 Zero 板，以便您自己建立。

这本书指导您，每一章的项目都从准备领域、硬件、传感器、通信和软件编程控制开始，以便拥有完整的控制和监控系统。

# 本书涵盖的内容

第一章，“开始使用树莓派 Zero”，描述了设置树莓派和 Arduino 板的过程，以及设备之间的通信。我们将安装和设置操作系统，将我们的 Pi 连接到网络，并远程访问它。我们还将保护我们的 Pi，并确保它能保持正确的时间。

第二章，“将东西连接到树莓派 Zero”，展示了如何将信号连接到树莓派 Zero 和 Arduino。它探讨了 GPIO 端口及其各种接口。我们将看看可以使用 GPIO 连接到树莓派的各种东西。

第三章，“连接传感器-测量真实的事物”，展示了如何实现用于检测不同类型信号的传感器，用于安全系统、能源消耗的流量电流、家庭中的一些风险检测、实现气体传感器、流量水传感器来测量水量，并且还将展示如何制作一个将使用指纹传感器控制家庭入口的安全系统。

第四章，“控制连接设备”，展示了如何使用通信模块在树莓派 Zero 的网络领域中控制您的 Arduino 板，以及如何在中央界面仪表板中显示。

第五章，“添加网络摄像头监控您的安全系统”，展示了如何配置连接到您的板的网络摄像头，以监控物联网安全系统。

第六章，“构建 Web 监视器并从仪表板控制设备”，展示了如何设置一个系统来监控您的安全系统使用网络服务。将树莓派 Zero 与 Arduino 集成，构建一个完整的系统连接设备和监控。

第七章，“使用物联网仪表板构建间谍警察”，展示了如何制作不同的迷你家庭自动化项目，以及如何使用物联网连接网络服务和监控您的安全系统。

Chapter 8, *Monitor and Control your devices from a Smart Phone*, explains how to develop an app for Smart Phone using Android Studio and APP inventor, and control your Arduino board and the Raspberry Pi Zero.

Chapter 9, *Putting It All Together*, shows how to put everything together, all the parts of the project, the electronics field, software configurations, and power supplies.

# What you need for this book

You’ll need the following software:

+   Win32 Disk Imager 0.9.5 PuTTY

+   i2C-tools

+   WiringPi2 for Python

+   Node.js 4.5 or later

+   Node.js for Windows V7.3.0 or later

+   Python 2.7.x or Python 3.x

+   PHP MyAdmin Database

+   MySQL module

+   Create and account in Gmail so that you can get in APP Inventor

+   Android Studio and SDK modules

+   Arduino software

In the first chapters, we explain all the basics so you will have everything configured and will be able to use the Raspberry Pi Zero without any problems, so you can use it for the projects in this book. We will use some basic components, such as sensors, and move to more complex components in the rest of the book.

On the software side, it is good if you actually have some existing programming skills, especially in JavaScript and in the Node.js framework. However, I will explain all the parts of each software piece of this book, so even if you don't have good programming skills in JavaScript you will be able to follow along.

# Who this book is for

This book is for all the people who want to automate their homes and make them smarter, while at the same time having complete control of what they are doing. If that's your case, you will learn everything there is to learn in this book about how to use the amazing Raspberry Pi Zero board to control your projects.

This book is also for makers who have played in the past with other development boards, such as Arduino. If that's the case, you will learn how to use the power of the Raspberry Pi platform to build smart homes. You will also learn how to create projects that can easily be done with other platforms, such as creating a wireless security camera with the Pi Zero.

# Conventions

In this book, you will find a number of text styles that distinguish between different kinds of information. Here are some examples of these styles and an explanation of their meaning.

Code words in text, database table names, folder names, filenames, file extensions, pathnames, dummy URLs, user input, and Twitter handles are shown as follows: "Extract `2015-09-24-raspbian-jessie.img` to your Home folder."

A block of code is set as follows:

```js
# passwd
root@raspberrypi:/home/pi# passwd
Enter new UNIX password:
Retype new UNIX password:
passwd: password updated successfully
        root@raspberrypi:/home/pi#
```

When we wish to draw your attention to a particular part of a code block, the relevant lines or items are set in bold:

```js
[default]
exten => s,1,Dial(Zap/1|30)
exten => s,2,Voicemail(u100)
**exten => s,102,Voicemail(b100)**
exten => i,1,Voicemail(s0)
```

Any command-line input or output is written as follows:

```js
**        sudo npm install express request**

```

**New terms** and **important words** are shown in bold. Words that you see on the screen, for example, in menus or dialog boxes, appear in the text like this:

"You can now just click on **Stream** to access the live stream from the camera."

### Note

Warnings or important notes appear in a box like this.

### Tip

Tips and tricks appear like this.


# 第一章：使用 Raspberry Pi Zero 入门

在为家庭安全系统和通过电子控制系统控制家用电器构建几个项目之前，在本章中，我们将进行初始配置并准备我们的 Raspberry Pi Zero 在网络中工作，以便您可以在本书中看到的所有项目中使用它。

在我们进行项目、构建网络与设备并将传感器连接到板子之前，了解 Raspberry Pi 的配置是很重要的。本章的主要目的是解释如何设置您的 Raspberry Pi Zero；我们将涵盖以下主题：

+   设置 Raspberry Pi Zero

+   准备 SD 卡

+   安装 Raspbian 操作系统

+   使用串行控制台电缆配置您的 Raspberry Pi Zero

+   远程访问网络

+   通过远程桌面访问

+   配置 Web 服务器

# 设置 Raspberry Pi Zero

Raspberry Pi 是一个专门用于项目的低成本板。在这里，我们将使用 Raspberry Pi Zero 板。查看以下链接：[`www.adafruit.com/products/2816`](https://www.adafruit.com/products/2816)。我用了这块板。

为了使 Raspberry Pi 工作，我们需要一个充当硬件和用户之间桥梁的操作系统。本书使用 Raspbian Jessy，可以从[`www.raspberrypi.org/downloads/`](https://www.raspberrypi.org/downloads/)下载。在此链接中，您将找到下载所有必要软件的信息，以便与您的 Raspberry Pi 一起使用部署 Raspbian。您需要至少 4GB 的微型 SD 卡。

我用来测试 Raspberry Pi Zero 的套件包括安装所有必要的东西和准备好板子所需的一切：

![设置 Raspberry Pi Zero](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/image_01_001-3.jpg)

## 准备 SD 卡

Raspberry Pi Zero 只能从 SD 卡启动，不能从外部驱动器或 USB 存储设备启动。对于本书，建议使用 4GB 的微型 SD 卡。

## 安装 Raspbian 操作系统

树莓派板上有许多可用的操作系统，其中大多数基于 Linux。然而，通常推荐的是 Raspbian，这是一个基于 Debian 的操作系统，专门为树莓派制作。

为了在您的 Pi 上安装 Raspbian 操作系统，请按照以下步骤：

1.  从官方 Raspberry Pi 网站下载最新的 Raspbian 镜像：[`www.raspberrypi.org/downloads/raspbian/`](https://www.raspberrypi.org/downloads/raspbian/)

1.  接下来，使用适配器将微型 SD 卡插入计算机。（适配器通常随 SD 卡一起提供。）

1.  然后从[`sourceforge.net/projects/win32diskimager/`](https://sourceforge.net/projects/win32diskimager/)下载 Win32DiskImager。

在下载文件夹后，您将看到以下文件，如截图所示：

![安装 Raspbian 操作系统](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/image_01_002-3.jpg)

1.  打开文件映像，选择您的微型 SD 卡路径，然后单击**写**按钮。

1.  几秒钟后，您的 SD 卡上安装了 Raspbian；将其插入 Raspberry Pi 并通过微型 USB 端口将 Raspberry Pi 板连接到电源源。

在下面的截图中，您可以看到安装的进度：

![安装 Raspbian 操作系统](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/image_01_003-3.jpg)

## 使用串行控制台电缆调试您的 Raspberry Pi Zero

在这一部分，我们将看看如何使用 TTL 串行转换器从计算机与 Raspberry Pi Zero 进行通信。我们可以通过连接到计算机的 USB 端口的串行控制电缆进行调试。我们使用串行电缆与板子通信，因为如果我们想要从计算机向板子发送命令，就必须使用这根电缆进行通信。您可以在[`www.adafruit.com/products/954`](https://www.adafruit.com/products/954)找到这根电缆：

![使用串行控制电缆调试您的 Raspberry Pi Zero](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_04.jpg)

重要的是要考虑到这根电缆使用 3.3 伏特，但我们不在乎，因为我们使用的是 Adafruit 的电缆。它经过测试可以在这个电压级别下工作。

您需要按照以下步骤安装和与您的 Raspberry Pi Zero 通信：

1.  您的计算机上需要有一个空闲的 USB 端口。

1.  我们需要安装串行控制电缆的驱动程序，以便系统可以识别硬件。我们建议您从[`www.adafruit.com/images/product-files/954/PL2303_Prolific_DriverInstaller_v1_12_0.zip`](https://www.adafruit.com/images/product-files/954/PL2303_Prolific_DriverInstaller_v1_12_0.zip)下载驱动程序。

1.  我们使用一个名为 PuTTY 的接口（控制台软件），在 Windows 计算机上运行；这样我们就可以与我们的 Raspberry Pi 板进行通信。这个软件可以从[`www.putty.org/`](http://www.putty.org/)下载和安装。

1.  对于连接，我们需要将红色电缆连接到**5**伏特，黑色电缆连接到地面，白色电缆连接到**TXD**引脚，绿色电缆连接到 Raspberry Pi Zero 的 RXD 引脚。

1.  电缆的另一端连接插头到 USB 端口。

这是连接的图像；这是硬件配置：

![使用串行控制电缆调试您的 Raspberry Pi Zero](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_05.jpg)

## 测试和访问串行 COM 接口

驱动程序安装完成后，我们已经安装了端口 COM：

### 提示

这个配置是为了 Windows 安装；如果你有不同的操作系统，你需要执行不同的步骤。

**如何获得设备管理器屏幕**：在您的 Windows PC 上，点击**开始**图标，转到控制面板，选择系统，然后点击**设备管理器**。

在下面的截图中，您可以看到 USB 串行端口的设备管理器：

![测试和访问串行 COM 接口](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_06.jpg)

1.  在 PuTTY 中打开终端，并选择串行通信为`COM3`，**速度**为`115200`，**奇偶校验**为**无**，**流控制**为**无**；点击**打开**：![测试和访问串行 COM 接口](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_07.jpg)

1.  当出现空白屏幕时，按下键盘上的*Enter*：![测试和访问串行 COM 接口](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_08.jpg)

1.  这将启动与您的 Pi 板的连接，并要求您输入用户名和密码；您将看到一个屏幕，类似于以下截图，带有认证登录：![测试和访问串行 COM 接口](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_09.jpg)

1.  Raspberry Pi Zero 的默认用户名是`pi`，密码是`raspberry`：![测试和访问串行 COM 接口](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_10.jpg)

# 连接到家庭网络并远程访问

我们的 Raspberry Pi 将在一个真实的网络中工作，因此它需要设置为与将一起使用的所有设备一起工作。因此，我们需要配置我们的家庭网络。我们将向您展示如何使用以太网适配器和可以用于 Raspberry Pi Zero 的 Wi-Fi 插头。

## 使用以太网适配器连接

如果您想将我们的树莓派 Zero 连接到本地网络，您需要使用来自 Adafruit 的 USB OTG 主机电缆-MicroB OTG 公对母。您可以在这里找到它：[`www.adafruit.com/products/1099`](https://www.adafruit.com/products/1099)。我们正在使用的板没有以太网连接器，因此有必要使用它与外部设备进行通信。

在下面的图像中，我们可以看到以太网适配器连接到树莓派 Zero：

![使用以太网适配器连接](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_11.jpg)

这是您可以使用的连接器，用于连接您的以太网适配器并与网络建立链接：

![使用以太网适配器连接](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_12.jpg)

现在我们需要按照以下步骤来配置以太网连接适配器：

1.  将适配器连接到转换器；我使用了**TRENDnet NETAdapter**，但您也可以使用来自 Adafruit 的以太网集线器和 Micro USB OTG 连接器的 USB 集线器。您可以在这里找到它：[`www.adafruit.com/products/2992m`](https://www.adafruit.com/products/2992m)。这是一个集线器，可以连接到以太网电缆或 USB 设备。

1.  验证路由器配置，两个 LED 都开始闪烁后，您可以在配置中看到 IP 地址。 DHCP 服务器将 IP 地址分配给树莓派。

这是您在主机名**raspberrypi**上看到的路由器配置：

![使用以太网适配器连接](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_13.jpg)

## 通过 SSH 访问树莓派 Zero

因为我们知道了树莓派的 IP 地址，我们将使用 PuTTY 终端访问它，如下面的屏幕截图所示。您需要输入 IP 地址，默认端口是`22`；点击**打开**按钮：

![通过 SSH 访问树莓派 Zero](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_14.jpg)

之后，我们将看到如下的登录屏幕：

![通过 SSH 访问树莓派 Zero](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_15.jpg)

使用以下命令：

```js
**sudo ifconfig -a**

```

现在我们可以看到以太网控制器适配器的配置信息。**Eth0**是以太网适配器：

![通过 SSH 访问树莓派 Zero](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_16.jpg)

## 连接到 Wi-Fi 网络

在本节中，我们将向您展示如何配置您的 Wi-Fi 网络连接，以便您的树莓派 Zero 可以与您的 Wi-Fi 网络进行交互。首先，我们需要使用 USB OTG 电缆将微型 Wi-Fi（802.11b/g/n）Wi-Fi dongle 连接到树莓派：

![连接到 Wi-Fi 网络](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_17.jpg)

# 如何安装无线工具

使用以下命令配置无线网络：

```js
**sudo apt-get install wireless-tools**

```

在下面的屏幕截图中，我们可以看到`ifconfig`命令的结果：

![如何安装无线工具](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_18.jpg)

执行命令后，我们将看到安装`wireless-tools`的结果：

![如何安装无线工具](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_19.jpg)

## 配置 IP 地址和无线网络

为了进行网络配置，我们需要为我们的设备分配一个 IP 地址，以便参与网络。

输入以下命令：

```js
**sudo nano etc/network/interfaces**

```

![配置 IP 地址和无线网络](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_20.jpg)

在名为`interface`的配置文件中，我们解释了需要向文件添加什么内容，以便我们可以将树莓派 Zero 连接到 Wi-Fi 网络进行**Wlan0**连接。

我们启动文件配置；这意味着文件的开始：

```js
auto lo 

```

我们为本地主机配置以太网设备`loopback`并启动 DHCP 服务器：

```js
iface lo inet loopback 
iface eth0 inet dhcp 

```

允许配置`wlan0`以进行 Wi-Fi 连接：

```js
allow-hotplug wlan0 
auto wlan0
```

我们启动 Wi-Fi 连接的 DHCP 服务器，并输入您的`ssid`和密码的名称。我们需要输入您的 Wi-Fi 网络的`ssid`和`password`参数：

```js
iface wlan0 inet dhcp 
        wpa-ssid "ssid" 
        wpa-psk "password" 

```

# 测试通信

我们需要测试设备是否响应其他主机。现在，如果一切配置正确，我们可以在 Wi-Fi 连接中看到以下 IP 地址：

![测试通信](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_21.jpg)

我们可以在路由器配置中看到分配给无线网络的当前 IP 地址：

![测试通信](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_22.jpg)

## 从计算机 ping

将计算机连接到与 Raspberry Pi 相同的网络：

![从计算机 ping](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_23.jpg)

您需要 ping Raspberry Pi 的 IP 地址。在我们对 Raspberry Pi 无线连接的 IP 地址进行 ping 后，我们看到结果：

![从计算机 ping](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_24.jpg)

# 更新软件包存储库

这将通过从官方 Raspberry Pi 存储库下载所有最新软件包来升级您的 Pi 板，因此这是确保您的板连接到互联网的绝佳方式。然后，从您的计算机上键入以下内容：

```js
**sudo apt-get update**

```

以下屏幕截图显示了 Raspberry Pi 收集软件包数据的过程：

![更新软件包存储库](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_25.jpg)

安装完成后，我们有以下结果：

![更新软件包存储库](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_26.jpg)

# 远程桌面

在这一部分，我们需要具有 Raspbian 操作系统的**RDP**软件包。为此，首先需要执行以下命令：

```js
**sudo apt-get install xrdp** 

```

此命令执行并安装 RDP 进程并更新软件包：

![使用 Windows 远程桌面](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_27.jpg)

## 使用 Windows 远程桌面

在本章结束时，您希望能够使用远程桌面从自己的计算机访问板；您需要输入您的 Raspberry Pi 的 IP 地址并单击**连接**按钮：

![使用 Windows 远程桌面](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_28.jpg)

在我们输入 Raspberry Pi Zero 的 IP 地址后，我们将看到以下屏幕；需要输入您的用户名和密码：

![使用 Windows 远程桌面](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_29.jpg)

您需要您的 Raspberry Pi 的登录信息，用户名和密码：

![使用 Windows 远程桌面](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_30.jpg)

这是操作系统的主窗口；您已经正确地通过远程桌面访问了您的 Raspberry Pi：

![使用 Windows 远程桌面](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_31.jpg)

# 配置 Web 服务器

有几个 Web 服务器可用，我们可以在 Raspberry Pi 上安装。我们将安装`lighttpd`网络服务器。此外，我们需要安装 PHP 支持，这将帮助我们在 Raspberry Pi 上运行网站并拥有动态网页。

要安装和配置，请通过 PuTTY 的终端控制台登录到 Raspberry Pi：

1.  更新软件包安装程序：

```js
 **sudo apt-get update**

```

1.  安装`lighttpd`网络服务器：

```js
 **sudo apt-get install lighttpd**

```

安装后，它将自动作为后台服务启动；每次 Raspberry Pi 启动时都会这样做：

1.  为了设置我们的 PHP 5 界面以使用 PHP 5 进行编程，我们需要使用以下命令安装`PHP5`模块支持；这对于拥有我们的服务器并且可以执行 PHP 文件的必要性是必要的，这样我们就可以制作我们的网站：

```js
 **sudo apt-get install php5-cgi**

```

1.  现在我们需要在我们的 Web 服务器上启用`PHP FastCGI`模块：

```js
 **sudo lighty-enable-mod fastcgi-php**

```

1.  最后一步，我们需要使用以下命令重新启动服务器：

```js
 **sudo /etc/init.d/lighttpd**

```

在下面的屏幕截图中，我们展示了配置 Web 服务器和 PHP 5 界面时将出现的页面内容。Web 服务器在位置`/var/www`安装了一个测试占位页面。在浏览器中输入您的 Raspberry Pi 的 IP 地址，例如`http://192.168.1.105/`，然后出现以下屏幕，打开配置服务器的活动页面：

![配置 Web 服务器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_32.jpg)

# 测试 PHP 安装

在这一点上，我们需要用 PHP 测试我们的网站。这可以通过编写一个简单的 PHP 脚本页面来完成。如果 PHP 安装正确，它将返回有关其环境和配置的信息。

1.  转到下一个文件夹，那里是根文档：

```js
 **cd /var/www/html** 

```

1.  创建一个名为`phpinfo.php`的文件。

我们使用`nano`这个词，这样我们就可以以特权进入系统文件并执行以下命令：

```js
 **sudo nano phpinfo.php**

```

1.  创建文件后，按照以下截图，按下*CTRL-X*，然后保存文件：![测试 PHP 安装](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_33.jpg)

1.  在浏览器中输入您的树莓派的 IP 地址，例如`http://192.168.1.105/phpinfo.php`，您应该会看到以下屏幕：![测试 PHP 安装](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_01_34.jpg)

# 总结

在本书的第一章中，我们看了如何配置树莓派 Zero 板，以便在后面的章节中使用。我们看了一下树莓派需要什么组件，以及如何安装 Raspbian，这样我们就可以在板上运行软件。

我们还安装了一个 Web 服务器，这将在本书的一些项目中使用。在下一章中，我们将深入探讨如何将设备连接到您的树莓派和 Arduino 板上。我们还将看看使用 GPIO 可以连接到树莓派的各种东西。


# 第二章：将东西连接到树莓派 Zero

您需要学习如何将东西连接到您的树莓派 Zero，并查看架构并区分我们可以用于我们定义目的的引脚。这就是我们有这一部分的原因-帮助您连接传感器并了解如何连接其他设备的基础知识。在本节中，我们将解释如何配置树莓派；现在您无法避免学习如何连接到您的树莓派传感器以读取连接到它的模拟输入。

我们将涵盖以下主题，以使我们的硬件与板通信：

+   连接数字输入：传感器 DS18B20

+   使用 MCP3008 ADC 转换器连接模拟输入

+   连接实时时钟（RTC）

# 连接数字输入-传感器 DS18B20

树莓派有数字引脚，因此在本节中，我们将看看如何将数字传感器连接到板上。我们将使用数字传感器 DS18B20，它具有数字输出，并且可以完美地连接到我们树莓派传感器的数字输入。主要思想是从传感器中获取温度读数并在屏幕上显示它们。

## 硬件要求

我们需要以下硬件来读取温度：

+   温度传感器 DS18B20（防水）

+   一个 4.7 千欧姆的电阻

+   一些跳线线

+   一个面包板

我们将使用防水传感器 DS18B20 和*4.7*千欧姆电阻：

![硬件要求](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_02_01.jpg)

这是我们在这个项目中使用的防水传感器。

## 硬件连接

以下图表显示了面包板上的电路，带有传感器和电阻：

![硬件连接](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_02_02.jpg)

在下图中，我们可以看到带有传感器的电路：

![硬件连接](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_02_03.jpg)

# 配置单线协议

在树莓派中打开一个终端，并输入以下内容：

```js
**sudo nano /boot/config.txt**

```

您应该在页面底部输入以下行以配置协议并定义单线协议将进行通信的引脚：

```js
**dtoverlay=w1-gpio**

```

下一步是重新启动树莓派。几分钟后，打开终端并输入以下行：

```js
**sudo modprobew1-gpio**
**sudo modprobe w1-therm**

```

进入文件夹并选择要配置的设备：

```js
**cd /sys/bus/w1/devices**
**ls**

```

选择要设置的设备。将`xxxx`更改为协议中将设置的设备的序列号：

```js
**cd 28-xxxx**
**cat w1_slave**

```

您将看到以下内容：

![配置单线协议](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_02_04.jpg)

之后，您将看到一行，上面写着*如果出现温度读数，则为 Yes，如下所示：t=29.562*。

## 软件配置

现在让我们看一下代码，每秒在屏幕上显示摄氏度和华氏度的温度。

在这里，我们导入了程序中使用的库：

```js
import os1 
import glob1 
import time1 

```

在这里，我们定义了协议中配置的设备：

```js
os1.system('modprobew1-gpio') 
os1.system('modprobew1-therm1') 

```

在这里，我们定义了设备配置的文件夹：

```js
directory = '/sys/bus/w1/devices/' 
device_folder1 = glob1.glob(directory + '28*')[0] 
device_file1 = device_folder1 + '/w1_slave' 

```

然后我们定义读取`温度`和配置传感器的函数：

```js
defread_temp(): 
f = open(device_file1, 'r') 
readings = f.readlines() 
f.close() 
return readings 

```

使用以下函数读取温度：

```js
defread_temp(): 
readings = read_temp() 

```

在这个函数中，我们比较了接收到消息`YES`时的时间，并获取了温度的值：

```js
while readings[0].strip()[-3:] != 'YES': 
time1.sleep(0.2) 
readings = read_temp() 
equals = lines[1].find('t=') 

```

然后我们计算温度，`temp`以`C`和`F`返回值：

```js
if equals != -1: 
temp = readings[1][equals pos+2:] 
tempc = float(temp) / 1000.0 
tempf = temp * 9.0 / 5.0 + 32.0 
returntempc, tempf 

```

它每秒重复一次循环：

```js
while True: 
print(temp()) 
time1.sleep(1) 

```

## 在屏幕上显示读数

现在我们需要执行`thermometer.py`。要显示 Python 中制作的脚本的结果，请打开您的 PuTTY 终端，并输入以下命令：

```js
**sudo python thermometer.py**

```

该命令的意思是，当我们运行温度计文件时，如果一切正常运行，我们将看到以下结果：

![在屏幕上显示读数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_02_05.jpg)

# 使用 MCP3008 ADC 转换器连接模拟输入

如果我们想要连接模拟传感器到树莓派，我们需要使用**模拟到数字转换器**（**ADC**）。该板没有模拟输入；我们使用**MCP3008**连接模拟传感器。这是一个 10 位 ADC，有八个通道。这意味着您可以连接多达八个传感器，可以从树莓派 Zero 读取。我们不需要特殊的组件来连接它们。它们可以通过 SPI 连接到树莓派的 GPIO。

第一步是启用 SPI 通信：

1.  访问树莓派终端并输入以下命令：

```js
**sudo raspi-config**

```

1.  如下截图所示选择**高级选项**：![使用 MCP3008 ADC 转换器连接模拟输入](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_02_06.jpg)

1.  通过选择**SPI**选项启用**SPI**通信：![使用 MCP3008 ADC 转换器连接模拟输入](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_02_07.jpg)

1.  选择**<Yes>**以启用 SPI 接口：![使用 MCP3008 ADC 转换器连接模拟输入](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_02_08.jpg)

1.  当我们启用 SPI 接口时，最终屏幕看起来像下面的截图。选择**<Ok>**：![使用 MCP3008 ADC 转换器连接模拟输入](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_02_09.jpg)

# 树莓派 GPIO 引脚

以下截图是树莓派 Zero 的 GPIO 引脚图表。在这种情况下，我们将使用 SPI 配置接口（`SPI_MOSI, SPI_MISO, SPI_CLK, SPI_CE0_N`）：

![树莓派 GPIO 引脚](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_02_10.jpg)

以下图表显示了 MCP3008 芯片的引脚名称，您将其连接到树莓派：

![树莓派 GPIO 引脚](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_02_11.jpg)

以下图片显示了温度传感器：

![树莓派 GPIO 引脚](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_02_12.jpg)

您需要根据以下描述连接以下引脚：

+   **VDD**连接到***3.3***伏特

+   **VREF**连接到树莓派 Zero 的**3.3**伏特

+   将**AGND**引脚连接到**GND**

+   将**CLK**（时钟）引脚连接到树莓派的**GPIO11**

+   **DOUT**连接到**GPIO9**

+   将**DIN**引脚连接到**GPIO10**

+   将**CS**引脚连接到**GPIO8**和引脚

+   将 MCP3008D 的**GND**引脚连接到地面

这个连接在下图中表示：

![树莓派 GPIO 引脚](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_02_13.jpg)

以下图片显示了传感器连接到 ADC MCP3008 和树莓派的连接：

![树莓派 GPIO 引脚](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_02_14.jpg)

## 使用 Python 脚本读取数据

在下一节中，您将创建`MCP3008.py`文件；您需要按照以下步骤进行：

1.  在您的树莓派 Zero 上打开终端。

1.  在您的树莓派终端中输入界面。

1.  在使用之前使用`nano`非常重要。

1.  输入`sudo nano MCP3008.py`。

它将出现在屏幕上，我们将描述以下行：

1.  导入库：

```js
        import spidev1 
        import os1 

```

1.  打开 SPI 总线：

```js
        spi1 = spidev1.SpiDev1() 
        spi1.open(0,0) 

```

1.  定义 ADC MCP2008 的通道：

```js
        def ReadChannel1(channel1): 
          adc1 = spi1.xfer2([1,(8+channel1)<<4,0]) 
          data1 = ((adc1[1]&3) << 8) + adc1[2] 
          return data1 

```

1.  转换电压的函数如下：

```js
        def volts(data1,places1): 
          volts1 = (data1 * 3.3) / float(1023) 
          volts1 = round(volts1,places1) 
          return volts1 

```

1.  转换温度的函数如下：

```js
        def Temp(data1,places1): 
          temp1 = (data1 * 0.0032)*100 
          temp1 = round(temp1,places1) 
          return temp1 

```

1.  定义 ADC 的通道：

```js
          channels = 0 

```

1.  定义读取时间：

```js
        delay = 10 

```

1.  读取温度的函数如下：

```js
        while True: 

          temp  = Channels(temp) 
          volts = Volts(temp1,2) 
          temp  = Temp(temp1,2) 

```

1.  打印结果：

```js
        print"**********************************************" 
        print("Temp : {} ({}V) {} degC".format(temp1,volts,temp)) 

```

1.  每 5 秒等待：

```js
        Time1.sleep(delay) 

```

1.  使用以下命令运行 Python 文件：

```js
**sudo python MCP3008.py**

```

1.  在下一个屏幕上，我们可以看到温度、ADC 测量值和根据温度的电压：![使用 Python 脚本读取数据](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_02_15.jpg)

# 连接 RTC

要控制系统，拥有一个可以读取时间的电路非常重要；它可以帮助控制树莓派的输出或在特定时间检测动作。我们将使用**RTC**模块*DS3231*与树莓派进行接口。

## I2C 设置

第一步是通过执行以下步骤启用**I2C**接口：

1.  选择**高级选项**：![I2C 设置](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_02_16.jpg)

1.  启用**I2C**选项，如下截图所示：![I2C 设置](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_02_17.jpg)

1.  在下一个屏幕上选择**<Yes>**：![I2C 设置](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_02_18.jpg)

1.  选择**<Ok>**：![I2C 设置](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_02_19.jpg)

1.  然后选择**<Yes>**：![I2C 设置](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_02_20.jpg)

1.  接下来，选择**<OK>**：![I2C 设置](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_02_21.jpg)

# DS3231 模块设置

DS3231 模块是一个实时时钟。它可以用于从集成电路获取时间和日期，因此可以与您的系统一起工作，以控制您想要从嵌入式芯片编程的特定事件。它可以与树莓派 Zero 完美配合，以实时获取时间和日期。

您需要确保您有最新的更新。为此，请在终端中输入以下命令：

```js
**sudo apt-get update**
**sudo apt-get -y upgrade**

```

使用以下命令修改系统文件：

```js
**sudo nano /etc/modules**

```

将以下行添加到`modules.txt`文件中：

```js
**snd-bcm2835 
i2c-bcm2835 
i2c-dev 
rtc-ds1307**

```

## 硬件设置

在本节中，我们将查看 RTC 模块的引脚：

```js
DS3231   Pi GPIO 
GNDP     1-06 
VCC      (3.3V) 
SDA      (I2CSDA) 
SCL      (I2CSCL)
```

这是 RTC 模块，我们可以看到芯片的引脚：

![硬件设置](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_02_22.jpg)

以下图表显示了电路连接：

![硬件设置](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_02_23.jpg)

以下图片显示了最终的连接：

![硬件设置](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_02_24.jpg)

# 测试 RTC

打开终端，输入以下内容：

```js
**sudo i2cdetect -y 1**

```

您应该看到类似于以下截图的内容：

![测试 RTC](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_02_25.jpg)

# I2C 设备设置

下一步是检查时间时钟是否与 RTC 时间同步。在这里我们定义 RTC 本地：

```js
**sudo nano /etc/rc.local**

```

将以下行添加到文件中，因为我们声明了新设备和我们配置的路径：

```js
echo ds1307 0x68 > /sys/class/i2c-adapter/i2c-1/new_device 

```

以下命令将启动 RTC：

```js
**hwclock -s**

```

执行此命令后，重新启动 Pi。您将看到以下屏幕，这意味着 RTC 已配置并准备好工作：

![I2C 设备设置](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_02_26.jpg)

# 将实时时钟进行最终测试

您可以使用以下命令读取 Pi 时间系统：

```js
**date**

```

![将实时时钟进行最终测试](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/image_02_027.jpg)

一旦 RTC 准备就绪，您可以使用以下命令进行测试；将时间写入 RTC：

```js
**sudo hwclock -w**

```

您可以使用此处给出的命令从 RTC 读取时间：

```js
**sudo hwclock -r**

```

现在进行最终命令。使用此命令，我们可以看到以下截图中显示的时间值：

![将实时时钟进行最终测试](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/image_02_028.jpg)

# 总结

在本章中，您学习了如何使用 MCP3008 ADC 转换器，以及如何使用树莓派 Zero 使用温度传感器。我们探索了 GPIO 端口及其各种接口。我们看了看可以使用 GPIO 连接到树莓派的各种东西。

在下一章中，我们将深入研究更多的硬件采集，连接不同类型的传感器到我们的树莓派 Zero 和 Arduino 板。这将帮助您在项目中进行真实的测量。非常有趣 - 继续努力！


# 第三章：连接传感器-测量真实的事物

本书的目标是建立一个家庭安全系统，通过电子控制系统和传感器控制家用电器，并从仪表板监控它们。首先，我们需要考虑我们的传感器连接到一个可以读取信号并将其传输到网络的终端设备。

对于终端设备，我们将使用 Arduino 板从传感器中获取读数。我们可以看到树莓派没有模拟输入。因此，我们使用 Arduino 板来读取这些信号。

在上一章中，我们讨论了如何将设备连接到树莓派；在本节中，我们将看到如何将传感器与 Arduino 板进行接口，以了解如何从不同应用程序中读取真实信号进行实际测量。本章将涵盖以下主题：

+   使用流量传感器计算水的体积

+   使用传感器测量气体浓度

+   使用传感器测量酒精浓度

+   使用传感器检测火灾

+   为植物测量湿度

+   测量容器中的水位

+   测量温度、湿度和光，并在 LCD 中显示数据

+   使用 PIR 传感器检测运动

+   使用铁磁开关检测门是否打开

+   使用指纹传感器检测谁可以进入房屋

重要的是要考虑到我们需要将我们的系统与现实世界进行通信。由于我们正在建立一个家庭安全系统，我们需要学习如何连接和与一些必要的传感器进行交互，以在我们的系统中使用它们。

在下一节中，我们将介绍您在家居自动化和安全系统中需要读取的数据的传感器。

# 测量流量传感器以计算水的体积

我们需要对家中使用的水进行自动测量。为此项目，我们将使用传感器进行此读数，并使测量自动化。

要完成这个项目，我们需要以下材料：

流水传感器和 Arduino UNO 板：

![测量流量传感器以计算水的体积](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/image_03_001.jpg)

## 硬件连接

现在我们有了流量传感器的连接。我们可以看到它有三个引脚--红色引脚连接到+VCC 5 伏特，黑色引脚连接到 GND，黄色引脚连接到 Arduino 板的引脚 2，如下图所示：

![硬件连接](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/image_03_002.jpg)

## 读取传感器信号

中断用于计算通过水流的脉冲，如下所示：

```js
attachInterrupt(0, count_pulse, RISING); 

```

中断类型为`RISING`，计算从低状态到高状态的脉冲：

```js
**Function for counting pulses:** 

voidcount_pulse() 
{ 
pulse++; 
} 

```

# 使用 Arduino 读取和计数脉冲

在代码的这一部分中，我们解释了它如何使用中断来计算传感器的信号，我们已将其配置为`RISING`，因此它会计算从数字信号零到数字信号一的脉冲：

```js
int pin = 2; 
volatile unsigned int pulse; 
constintpulses_per_litre = 450; 

void setup() 
{ 
Serial.begin(9600); 

pinMode(pin, INPUT); 
attachInterrupt(0, count_pulse, RISING); 
} 

void loop() 
{ 
pulse=0; 
interrupts(); 
delay(1000); 
noInterrupts(); 

Serial.print("Pulses per second: "); 
Serial.println(pulse); 
} 

voidcount_pulse() 
{ 
pulse++; 
} 

```

打开 Arduino 串行监视器，并用嘴对水流传感器吹气。每个循环中每秒脉冲的数量将打印在 Arduino 串行监视器上，如下截图所示：

![使用 Arduino 读取和计数脉冲](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_03-1.jpg)

# 根据计数的脉冲计算水流速

在这部分中，我们测量脉冲并将其转换为水流，步骤如下：

1.  打开新的 Arduino IDE，并复制以下草图。

1.  验证并上传 Arduino 板上的草图。

```js
        int pin = 2; 
        volatile unsigned int pulse; 
        constintpulses_per_litre = 450; 

        void setup() 
        { 
          Serial.begin(9600); 

          pinMode(pin, INPUT); 
          attachInterrupt(0, count_pulse, RISING); 
        } 

```

1.  以下代码将计算从传感器读取的脉冲；我们将每秒计数的脉冲数除以脉冲数：

```js
      void loop() 
      { 
        pulse = 0; 
        interrupts(); 
        delay(1000); 
        noInterrupts(); 

        Serial.print("Pulses per second: "); 
        Serial.println(pulse); 

        Serial.print("Water flow rate: "); 
        Serial.print(pulse * 1000/pulses_per_litre); 
        Serial.println(" milliliters per second"); 
        delay(1000); 
      } 
      void count_pulse() 
      { 
        pulse++; 
      } 

```

1.  打开 Arduino 串行监视器，并用嘴吹气通过水流传感器。每个循环中脉冲的数量和每秒的水流速将打印在 Arduino 串行监视器上，如下截图所示：![基于计数的水流速率计算](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_04-1.jpg)

# 计算水流和水的体积：

现在你可以将代码复制到一个名为`Flow_sensor_measure_volume.ino`的文件中，或者直接从这个项目的文件夹中获取完整的代码。

在这部分中，我们从传感器计算流量和体积：

```js
int pin = 2; 
volatile unsigned int pulse; 
float volume = 0; 
floatflow_rate =0; 
constintpulses_per_litre = 450; 

```

我们设置中断：

```js
void setup() 
{ 
Serial.begin(9600); 
pinMode(pin, INPUT); 
attachInterrupt(0, count_pulse, RISING); 
} 

```

启动中断：

```js
void loop() 
{ 
pulse=0; 
interrupts(); 
delay(1000); 
noInterrupts(); 

```

然后我们显示传感器的流速：

```js
Serial.print("Pulses per second: "); 
Serial.println(pulse); 

flow_rate = pulse * 1000/pulses_per_litre; 

```

我们计算传感器的体积：

```js
Serial.print("Water flow rate: "); 
Serial.print(flow_rate); 
Serial.println(" milliliters per second"); 

volume = volume + flow_rate * 0.1; 

```

我们显示毫升的体积：

```js
Serial.print("Volume: "); 
Serial.print(volume); 
Serial.println(" milliliters"); 
} 

```

计算脉冲的函数如下：

```js
Void count_pulse() 
{ 
  pulse++; 
} 

```

结果可以在下面的截图中看到：

![计算水流和水的体积：](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_05-1.jpg)

## 在 LCD 上显示测量参数

您可以在新建的水表上添加 LCD 屏幕，以显示读数，而不是在 Arduino 串行监视器上显示它们。然后，在将草图上传到 Arduino 后，您可以将水表从计算机上断开连接。

首先，我们定义 LCD 库：

```js
#include <LiquidCrystal.h> 

```

然后我们定义程序中将使用的变量：

```js
int pin = 2; 
volatile unsigned int pulse; 
float volume = 0; 
floatflow_rate = 0; 
constintpulses_per_litre = 450; 

```

我们定义 LCD 引脚：

```js
// initialize the library with the numbers of the interface pins 
LiquidCrystallcd(12, 11, 6, 5, 4, 3); 

```

我们定义传感的中断：

```js
void setup() 
{ 
  Serial.begin(9600); 
  pinMode(pin, INPUT); 
  attachInterrupt(0, count_pulse, RISING); 

```

现在我们在 LCD 上显示消息：

```js
  // set up the LCD's number of columns and rows:  
  lcd.begin(16, 2); 
  // Print a message to the LCD. 
  lcd.print("Welcome..."); 
  delay(1000); 
} 

```

我们现在在主循环中定义中断：

```js
void loop() 
{ 
  pulse = 0; 

  interrupts(); 
  delay(1000); 
  noInterrupts(); 

```

我们在 LCD 上显示数值：

```js
  lcd.setCursor(0, 0); 
  lcd.print("Pulses/s: "); 
  lcd.print(pulse); 

  flow_rate = pulse*1000/pulses_per_litre; 

```

然后我们显示传感器的流速：

```js
  lcd.setCursor(0, 1); 
  lcd.print(flow_rate,2);//display only 2 decimal places 
  lcd.print(" ml"); 

```

我们现在显示体积的值：

```js
  volume = volume + flow_rate * 0.1; 
  lcd.setCursor(8, 1); 
  lcd.print(volume, 2);//display only 2 decimal places 
  lcd.println(" ml "); 
} 

```

然后我们定义计算脉冲的函数：

```js
void count_pulse() 
{ 
 pulse++; 
} 

```

水流的连接如下图所示：

![在 LCD 上显示测量参数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/image_03_006.jpg)

以下图片显示了 LCD 上的测量结果：

![在 LCD 上显示测量参数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/image_03_007.jpg)

您可以在 LCD 屏幕上看到一些信息，例如每秒脉冲、水流速和从时间开始的总水量。

# 测量气体浓度

在我们的系统中有一个检测气体的传感器是很重要的，这样我们就可以将其应用在家里，以便检测气体泄漏。现在我们将描述如何连接到 Arduino 板并读取气体浓度。

在这一部分，我们将使用一个气体传感器和甲烷 CH4。在这种情况下，我们将使用一个可以检测 200 到 10000ppm 浓度的 MQ-4 传感器。

该传感器在输出中具有模拟电阻，并可以连接到 ADC；它需要 5 伏的线圈激励。传感器的图像如下所示：

![测量气体浓度](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_08-1.jpg)

我们可以在[`www.sparkfun.com/products/9404`](https://www.sparkfun.com/products/9404)找到 MQ-4 传感器的信息。

![测量气体浓度](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_09-1.jpg)

## 传感器和 Arduino 板的连接

根据前面的图表，我们现在将在下面的图像中看到所做的连接：

![传感器和 Arduino 板的连接](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_10-1.jpg)

打开 Arduino IDE，并复制以下草图：

```js
void setup(){ 
  Serial.begin(9600); 
} 

void loop() 
{ 
  float vol; 
  int sensorValue = analogRead(A0); 
  vol=(float)sensorValue/1024*5.0; 
  Serial.println(vol,1); 
  Serial.print("Concentration of gas= "); 
  Serial.println(sensorValue); 
  delay(2000); 
} 

```

我们在屏幕上看到以下结果：

![传感器和 Arduino 板的连接](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_11-1.jpg)

# 用传感器测量酒精的浓度

在这一部分，我们将构建一个非常酷的项目：您自己的**酒精** **呼吸分析仪**。为此，我们将使用一个简单的 Arduino Uno 板以及一个乙醇气体传感器：

![用传感器测量酒精的浓度](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_12-1.jpg)

以下图表显示了传感器与 Arduino 的连接：

![用传感器测量酒精的浓度](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_13-1.jpg)

现在我们将为项目编写代码。在这里，我们将简单地介绍代码的最重要部分。

现在你可以将代码复制到名为`Sensor_alcohol.ino`的文件中，或者直接从该项目的文件夹中获取完整的代码：

```js
int readings=0; 
void setup(){ 
Serial.begin(9600); 
} 

void loop(){ 
lectura=analogRead(A1); 
Serial.print("Level of alcohol= "); 
Serial.println(readings); 
delay(1000); 
} 

```

当它没有检测到酒精时，我们可以看到 Arduino 读取的数值：

![使用传感器测量酒精含量](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_14-1.jpg)

如果检测到酒精，我们可以看到 Arduino 从模拟读取的数值，如下截图所示：

![使用传感器测量酒精含量](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_15-1.jpg)

# 使用传感器检测火灾

如果我们家中有火灾，及时检测是至关重要的；因此，在下一节中，我们将创建一个使用传感器检测火灾的项目。

在下图中，我们看到了火灾传感器模块：

![使用传感器检测火灾](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_16-1.jpg)

现在你可以将代码复制到名为`Sensor_fire.ino`的文件中，或者直接从该项目的文件夹中获取完整的代码。

我们在程序开始时为程序定义变量：

```js
int ledPin = 13;             
int inputPin= 2; 
int val = 0;                    

```

我们定义输出信号和串行通信：

```js
void setup() { 
pinMode(ledPin, OUTPUT);       
pinMode(inputPin, INPUT);      
Serial.begin(9600); 
} 

```

现在我们显示数字信号的值：

```js
void loop(){ 
val = digitalRead(inputPin); 
Serial.print("val : ");   
Serial.println(val); 
digitalWrite(ledPin, HIGH);  // turn LED ON 

```

然后我们进行比较：如果数值检测到高逻辑状态，它会关闭输出；如果读取相反的数值，它会打开数字信号；这意味着它已经检测到火灾：

```js
if (val == HIGH) {             
  Serial.print("NO Fire detected "); 
  digitalWrite(ledPin, LOW); // turn LED OFF 
} 
else{ 
  Serial.print("Fire DETECTED "); 
  digitalWrite(ledPin, HIGH);   
  } 
} 

```

当 Arduino 板检测到火灾时，它将在数字输入中读取`*1*`，这意味着没有检测到火灾：

![使用传感器检测火灾](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_17-1.jpg)

如果检测到火灾，数字输入从数字输入读取`*0*`逻辑：

![使用传感器检测火灾](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_18-1.jpg)

# 测量植物的湿度

![测量植物的湿度](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_19-1.jpg)

在本节中，我们将看到使用传感器测试植物和土壤中的湿度：

![测量植物的湿度](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_20-1.jpg)

我现在将介绍这段代码的主要部分。然后我们设置串行通信：

```js
int value;   

void setup() { 
Serial.begin(9600); 
}  

```

在主循环中，我们将从传感器读取模拟信号：

```js
void loop(){   
Serial.print("Humidity sensor value:"); 
Value = analogRead(0);   
Serial.print(value);   

```

我们比较传感器的数值，并在串行接口上显示结果：

```js
if (Value<= 300)   
Serial.println(" Very wet");   
if ((Value > 300) and (Value<= 700))   
Serial.println(" Wet, do not water");    
if (Value> 700)   
Serial.println(" Dry, you need to water");  
delay(1000);  
} 

```

这里，截图显示了读数的结果：

![测量植物的湿度](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_21-1.jpg)

以下截图显示植物不需要水；因为土壤中已经有足够的湿度：

![测量植物的湿度](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_22-1.jpg)

# 测量容器中的水位

有时，我们需要测量容器中的水位，或者如果你想看到水箱中的水位，测量它所含水量是必要的；因此，在本节中，我们将解释如何做到这一点。

传感器通常是打开的。当水超过限制时，接点打开，并向 Arduino 板发送信号。我们使用数字输入的引脚号`2`：

![测量容器中的水位](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_23-1.jpg)

在程序中声明变量和`const`：

```js
const int buttonPin = 2;     // the number of the input sensor pin 
const int ledPin =  13;      // the number of the LED pin 

```

我们还定义数字信号的状态：

```js
// variables will change: 
intbuttonState = 0;         // variable for reading the pushbutton status 

```

我们配置程序的信号、输入和输出：

```js
void setup() { 
  // initialize the LED pin as an output: 
pinMode(ledPin, OUTPUT); 
  // initialize the pushbutton pin as an input: 
pinMode(buttonPin, INPUT); 
Serial.begin(9600); 
} 

```

读取数字输入的状态：

```js
void loop() { 
  // read the state of the pushbutton value: 
buttonState = digitalRead(buttonPin); 

```

我们对传感器进行比较：

```js
if (buttonState == HIGH) { 
Serial.println(buttonState); 
Serial.println("The recipient is fulled"); 
digitalWrite(ledPin, HIGH); 
delay(1000); 
  } 

```

如果传感器检测到**低**水平，容器是空的：

```js
else { 
digitalWrite(ledPin, LOW); 
Serial.println(buttonState); 
Serial.println("The recipient is empty"); 
delay(1000); 
  } 
} 

```

以下截图显示了容器为空时的结果：

![测量容器中的水位](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_24-1.jpg)

水超过限制：

![测量容器中的水位](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_25-1.jpg)

# 测量温度、湿度和光线，并在 LCD 上显示数据

在本节中，我将教你如何在 LCD 屏幕上监测温度、湿度和光线检测。

## 硬件和软件要求

在这个项目中，你将使用 Arduino UNO 板；但你也可以使用 Arduino MEGA，它也可以完美地工作。

对于温度读数，我们需要一个 DHT11 传感器、一个 4.7k 电阻、一个光敏电阻（光传感器）和一个 10k 电阻。

还需要一个 16 x 2 的 LCD 屏幕，您可以在其中进行测试；我使用了一个 I2C 通信模块，用于与 Arduino 板接口的屏幕。我建议使用这种通信，因为只需要 Arduino 的两个引脚来发送数据：

![硬件和软件要求](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_26-1.jpg)

最后，它需要一个面包板和公对公和母对公的电缆进行连接。

以下是项目的组件清单：

+   Arduino UNO

+   温湿度传感器 DHT11

+   LCD 屏幕 16 x 2

+   LCD 的 I2C 模块

+   一个面包板

+   电缆

我们连接不同的组件：

![硬件和软件要求](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_27-1.jpg)

在这里，我们可以看到温湿度 DHT11 传感器的图像：

![硬件和软件要求](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_40.jpg)

然后将**DHT11 传感器（VCC）**的引脚号**1**连接到面包板上的红线，引脚**4**（GND）连接到蓝线。还要将传感器的引脚号**2**连接到 Arduino 板的引脚号**7**。最后，将 4.7k 欧姆的电阻连接到传感器的引脚号**1**和**2**之间。

在面包板上串联一个 10k 欧姆的电阻。然后将光敏电阻的另一端连接到面包板上的红线，电阻的另一端连接到蓝线（地线）。最后，将光敏电阻和电阻之间的公共引脚连接到 Arduino 模拟引脚**A0**。

现在让我们连接 LCD 屏幕。由于我们使用的是带有 I2C 接口的 LCD 屏幕，因此只需要连接两根信号线和两根电源线。将 I2C 模块的引脚**VDC**连接到面包板上的红线，**GND**引脚连接到面包板上的蓝线。然后将**SDA**引脚模块连接到 Arduino 引脚**A4**，**A5 SCL**引脚连接到 Arduino 的引脚：

![硬件和软件要求](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_29-1.jpg)

这是项目的完全组装图像，这样您就可以对整个项目有一个概念：

![硬件和软件要求](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_30-1.jpg)

## 测试传感器

现在硬件项目已经完全组装好，我们将测试不同的传感器。为此，我们将在 Arduino 中编写一个简单的草图。我们只会读取传感器数据，并将这些数据打印在串行端口上。

您现在可以将代码复制到名为`Testing_sensors_Temp_Hum.ino`的文件中，或者只需从此项目的文件夹中获取完整的代码。

首先我们定义库：

```js
#include "DHT.h" 
#define DHTPIN 7  
#define DHTTYPE DHT11 

```

我们定义传感器的类型：

```js
DHT dht(DHTPIN, DHTTYPE); 

```

然后我们配置串行通信：

```js
void setup() 
{ 
Serial.begin(9600); 
dht.begin(); 
} 

```

我们读取传感器数值：

```js
void loop() 
{ 
  float temp = dht.readTemperature(); 
  float hum = dht.readHumidity(); 
  float sensor = analogRead(0); 
  float light = sensor / 1024 * 100; 

```

我们在串行接口上显示数值：

```js
  Serial.print("Temperature: "); 
  Serial.print(temp); 
  Serial.println(" C"); 
  Serial.print("Humidity: "); 
  Serial.print(hum); 
  Serial.println("%"); 
  Serial.print("Light: "); 
  Serial.print(light); 
  Serial.println("%"); 
  delay(700); 
} 

```

将代码下载到 Arduino 板上，并打开串行监视器以显示发送的数据。重要的是要检查串行端口的传输速度，必须为 9600。您应该看到以下内容：

![测试传感器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_31-1.jpg)

## 在 LCD 上显示数据

现在下一步是将我们的信息集成到 LCD 屏幕上显示。传感器读数部分将保持不变，只是在通信和在 LCD 上显示数据方面进行了详细说明。以下是这部分的完整代码，以及解释。

您现在可以将代码复制到名为`LCD_sensors_temp_hum.ino`的文件中，或者只需从此项目的文件夹中获取完整的代码。

我们为程序包括库：

```js
#include <Wire.h> 
#include <LiquidCrystal_I2C.h> 
#include "DHT.h" 
#define DHTPIN 7  
#define DHTTYPE DHT11 

```

我们为 LCD 定义 LCD 地址：

```js
LiquidCrystal_I2C lcd(0x3F,16,2); 
DHT dht(DHTPIN, DHTTYPE); 

```

我们启动 LCD 屏幕：

```js
void setup() 
{ 
lcd.init(); 
lcd.backlight(); 
lcd.setCursor(1,0); 
lcd.print("Hello !!!"); 
lcd.setCursor(1,1); 
lcd.print("Starting ..."); 

```

我们定义`dht`传感器的开始：

```js
dht.begin(); 
delay(2000); 
lcd.clear(); 
} 

```

我们读取传感器并将数值保存在变量中：

```js
void loop() 
{ 
  float temp = dht.readTemperature(); 
  float hum = dht.readHumidity(); 
  float sensor = analogRead(0); 
  float light = sensor / 1024 * 100; 

```

我们在 LCD 屏幕上显示数值：

```js
  lcd.setCursor(0,0); 
  lcd.print("Temp:"); 
  lcd.print(temp,1); 
  lcd.print((char)223); 
  lcd.print("C"); 
  lcd.setCursor(0,1); 
  lcd.print("Hum:"); 
  lcd.print(hum); 
  lcd.print("%"); 
  lcd.setCursor(11,1); 
  //lcd.print("L:"); 
  lcd.print(light); 
  lcd.print("%"); 
  delay(700); 
} 

```

下一步是在 Arduino 板上下载示例；稍等片刻，您将在 LCD 上看到显示读数。以下是项目运行的图像：

![在 LCD 上显示数据](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_32-1.jpg)

# 使用 PIR 传感器检测运动

我们将建立一个带有常见家庭自动化传感器的项目：运动传感器（PIR）。你是否注意到过那些安装在房屋某些房间顶角的小白色塑料模块，当有人走过时会变成红色的模块？这正是我们这个项目要做的事情。

运动传感器必须有三个引脚：两个用于电源供应，一个用于信号。你还应该使用 5V 电压级别以与 Arduino 卡兼容，Arduino 卡也是在 5V 下运行的。以下图片显示了一个简单的运动传感器：

![使用 PIR 传感器检测运动](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_33-1.jpg)

出于实际目的，我们将使用信号输入 8 来连接运动传感器，5 伏特的信号电压和地**GND**。

## PIR 传感器与 Arduino 接口

PIR 传感器检测体热（红外能量）。被动红外传感器是家庭安全系统中最常用的运动检测器。一旦传感器变热，它就可以检测周围区域的热量和运动，形成一个保护网格。如果移动物体阻挡了太多的网格区域，并且红外能量水平迅速变化，传感器就会被触发。

在这一点上，我们将测试 Arduino 和运动传感器之间的通信。

我们定义变量和串行通信，定义数字引脚 8，输入信号，读取信号状态，并显示传感器的状态信号：

```js
**int sensor = 8;**
**void setup() {**
**Serial.begin(9600);**
**pinMode(sensor,INPUT);**
**}**
**void loop(){**
**// Readind the sensor**
**int state = digitalRead(sensor);**
**Serial.print("Detecting sensor: ");**
**Serial.println(state);**
**delay(100);**
**}**

```

# 使用铁簧管检测门是否打开

已添加一个示例作为选项，以实现磁传感器来检测门或窗户何时打开或关闭。

使用铁簧管检测门是否打开

传感器在检测到磁场时输出`0`，当磁场远离时输出为`1`；因此你可以确定门是打开还是关闭。

Arduino 中的程序执行如下：

我们定义传感器的输入信号，并配置串行通信：

```js
void setup() { 
  pinMode(sensor, INPUT_PULLUP); 
  Serial.begin(9600); 
} 

```

我们读取传感器的状态：

```js
void loop() { 
state = digitalRead(sensor); 

```

它比较数字输入并在串行接口中显示门的状态：

```js
  if (state == LOW){ 
    Serial.println("Door Close"); 
  } 
  if (state == HIGH){ 
    Serial.println("Door Open"); 
  } 
} 

```

# 使用指纹传感器检测谁可以进入房屋

在本节中，我们将创建一个可以帮助我们建立完整安全系统的项目。在这个项目中，指纹访问将通过使用指纹传感器读取指纹来实现，如下图所示：

![使用指纹传感器检测谁可以进入房屋](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_35-1.jpg)

在这部分，我们将看到如何连接和配置我们的硬件，以便激活继电器。

## 硬件配置：

像往常一样，我们将使用 Arduino Uno 板作为项目的大脑。这个项目最重要的部分是指纹传感器。

首先，我们将看到如何组装这个项目的不同部分。让我们从连接电源开始。将 Arduino 板上的**5V**引脚连接到红色电源轨，将 Arduino 的**GND**连接到面包板上的蓝色电源轨。

现在，让我们连接指纹传感器。首先，通过将电缆连接到面包板上的相应颜色来连接电源。然后，将传感器的白色线连接到 Arduino 引脚 3，将绿色线连接到引脚 2。

之后，我们将连接继电器模块。将**VCC**引脚连接到红色电源轨，**GND**引脚连接到蓝色电源轨，将**EN**引脚连接到 Arduino 引脚 7：

![硬件配置：](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_36-1.jpg)

## 保存指纹：

以下示例用于直接从库`Adafruit_Fingerprint`注册 ID 的指纹。

首先，我们定义库：

```js
#include <Adafruit_Fingerprint.h> 
#include <SoftwareSerial.h> 

```

我们定义读取的 ID 和注册过程的功能：

```js
uint8_t id; 
uint8_tgetFingerprintEnroll(); 

```

我们定义与设备的串行通信：

```js
SoftwareSerialmySerial(2, 3); 
Adafruit_Fingerprint finger = Adafruit_Fingerprint(&mySerial); 

```

我们声明传感器的实例：

```js
//Adafruit_Fingerprint finger = Adafruit_Fingerprint(&Serial1); 

```

我们设置并显示传感器是否正在配置：

```js
void setup()   
{ 
  while (!Serial); 
  delay(500); 

```

我们显示传感器确认：

```js
  Serial.begin(9600); 
  Serial.println("Adafruit Fingerprint sensor enrollment"); 
  // set the data rate for the sensor serial port 
  finger.begin(57600); 

```

我们识别传感器是否检测到：

```js
  if (finger.verifyPassword()) { 
  Serial.println("Found fingerprint sensor!"); 
  } else { 
    Serial.println("Did not find fingerprint sensor :("); 
    while (1); 
    } 
  } 
  uint8_treadnumber(void) { 
  uint8_tnum = 0; 
  booleanvalidnum = false;  
  while (1) { 
    while (! Serial.available()); 
      char c = Serial.read(); 
      if (isdigit(c)) { 
        num *= 10; 
        num += c - '0'; 
        validnum = true; 
        } else if (validnum) { 
          returnnum; 
        } 
      } 
    } 

```

我们显示注册 ID：

```js
void loop()                     // run over and over again 
{ 
Serial.println("Ready to enroll a fingerprint! Please Type in the ID # you want to save this finger as..."); 
id = readnumber(); 
Serial.print("Enrolling ID #"); 
Serial.println(id); 

while (!  getFingerprintEnroll() ); 
} 

```

注册的功能如下：

```js
uint8_tgetFingerprintEnroll() { 
int p = -1; 
Serial.print("Waiting for valid finger to enroll as #"); Serial.println(id); 
while (p != FINGERPRINT_OK) { 
    p = finger.getImage(); 
switch (p) { 
case FINGERPRINT_OK: 
Serial.println("Image taken"); 
break; 
case FINGERPRINT_NOFINGER: 
Serial.println("."); 
break; 
case FINGERPRINT_PACKETRECIEVEERR: 
Serial.println("Communication error"); 
break; 
case FINGERPRINT_IMAGEFAIL: 
Serial.println("Imaging error"); 
break; 
default: 
Serial.println("Unknown error"); 
break; 
    } 
  } 

```

如果传感器成功读取图像，您将看到以下内容：

```js
  p = finger.image2Tz(1); 
switch (p) { 
case FINGERPRINT_OK: 
Serial.println("Image converted"); 
break; 
case FINGERPRINT_IMAGEMESS: 
Serial.println("Image too messy"); 
return p; 
case FINGERPRINT_PACKETRECIEVEERR: 
Serial.println("Communication error"); 
return p; 
case FINGERPRINT_FEATUREFAIL: 
Serial.println("Could not find fingerprint features"); 
return p; 
case FINGERPRINT_INVALIDIMAGE: 

```

如果无法找到指纹特征，您将看到以下内容：Serial.println("无法找到指纹特征");

```js
return p; 
default: 
Serial.println("Unknown error"); 
return p; 
  } 

```

移除指纹传感器：

```js
Serial.println("Remove finger"); 
delay(2000); 
  p = 0; 
while (p != FINGERPRINT_NOFINGER) { 
p = finger.getImage(); 
  } 
Serial.print("ID "); Serial.println(id); 
p = -1; 
Serial.println("Place same finger again"); 
while (p != FINGERPRINT_OK) { 
    p = finger.getImage(); 
switch (p) { 
case FINGERPRINT_OK: 
Serial.println("Image taken"); 
break; 
case FINGERPRINT_NOFINGER: 
Serial.print("."); 
break; 
case FINGERPRINT_PACKETRECIEVEERR: 
Serial.println("Communication error"); 
break; 
case FINGERPRINT_IMAGEFAIL: 
Serial.println("Imaging error"); 
break; 
default: 
Serial.println("Unknown error"); 
break; 
    } 
  } 

```

指纹传感器的图像：

```js
  p = finger.image2Tz(2); 
switch (p) { 
case FINGERPRINT_OK: 
Serial.println("Image converted"); 
break; 
case FINGERPRINT_IMAGEMESS: 
Serial.println("Image too messy"); 
return p; 
case FINGERPRINT_PACKETRECIEVEERR: 
Serial.println("Communication error"); 
return p; 
case FINGERPRINT_FEATUREFAIL: 
Serial.println("Could not find fingerprint features"); 
return p; 
case FINGERPRINT_INVALIDIMAGE: 
Serial.println("Could not find fingerprint features"); 
return p; 
default: 
Serial.println("Unknown error"); 
return p; 
  } 

```

如果正确，您将看到以下内容：

```js
Serial.print("Creating model for #");  Serial.println(id); 

  p = finger.createModel(); 
if (p == FINGERPRINT_OK) { 
Serial.println("Prints matched!"); 
  } else if (p == FINGERPRINT_PACKETRECIEVEERR) { 
Serial.println("Communication error"); 
return p; 
  } else if (p == FINGERPRINT_ENROLLMISMATCH) { 
Serial.println("Fingerprints did not match"); 
return p; 
  } else { 
Serial.println("Unknown error"); 
return p; 
  }    

```

显示传感器的结果：

```js
Serial.print("ID "); Serial.println(id); 
  p = finger.storeModel(id); 
if (p == FINGERPRINT_OK) { 
Serial.println("Stored!"); 
  } else if (p == FINGERPRINT_PACKETRECIEVEERR) { 
Serial.println("Communication error"); 
return p; 
  } else if (p == FINGERPRINT_BADLOCATION) { 
Serial.println("Could not store in that location"); 
return p; 
  } else if (p == FINGERPRINT_FLASHERR) { 
Serial.println("Error writing to flash"); 
return p; 
  } else { 
Serial.println("Unknown error"); 
return p; 
}    
} 

```

## 测试传感器

打开串行监视器，然后输入在上一步保存的 ID 号码：

![测试传感器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_37-1.jpg)

以下截图表明您应该再次将同一手指放在传感器上：

![测试传感器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_38-1.jpg)

以下截图显示传感器响应表明数字指纹已成功保存：

![测试传感器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/iot-prog-js/img/B05170_03_39-1.jpg)

# 摘要

在本章中，我们看到如何与连接到 Arduino 板的不同传感器进行交互，例如用于能源消耗的流量电流，检测家庭风险，实施气体传感器，实施流水传感器以测量水量，制作安全系统，并使用指纹传感器控制访问。所有这些传感器都可以集成到一个完整的系统中，用于监控和控制您在任何项目上工作的一切。

在下一章中，我们将看到如何集成所有内容，监控和控制一个完整的系统，并在仪表板上读取 Arduino 板和树莓派 Zero 作为中央接口的传感器和执行器。
