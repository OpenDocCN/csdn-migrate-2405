# C++ 机器人编程实用指南（一）

> 原文：[`zh.annas-archive.org/md5/E72C92D0A964D187E23464F49CAD88BE`](https://zh.annas-archive.org/md5/E72C92D0A964D187E23464F49CAD88BE)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

C++是最受欢迎的传统编程语言之一，用于机器人技术，许多领先的行业都使用 C++和机器人硬件的组合。本书将弥合树莓派和 C/C++编程之间的差距，并使您能够为树莓派开发应用程序。要跟随本书中涵盖的项目，您可以使用 wiringPi 库在树莓派上实现 C 程序。

通过本书，您将开发一个完全功能的小车机器人，并编写程序以不同的方向移动它。然后，您将使用超声波传感器创建一个避障机器人。此外，您将了解如何使用您的 PC/Mac 无线控制机器人。本书还将帮助您使用 OpenCV 处理对象检测和跟踪，并指导您探索人脸检测技术。最后，您将创建一个 Android 应用程序，并使用 Android 智能手机无线控制机器人。

通过本书，您将获得使用树莓派和 C/C++编程开发机器人的经验。

# 这本书适合谁

本书适用于希望利用 C++构建激动人心的机器人应用程序的开发人员、程序员和机器人爱好者。需要一些 C++的先验知识。

# 本书涵盖的内容

第一章，*树莓派简介*，介绍了树莓派的不同模式和 GPIO 引脚配置。然后，我们将设置树莓派 B+和树莓派 Zero，并在其上安装 Raspbian 操作系统。我们还将学习如何通过 Wi-Fi 网络将树莓派无线连接到笔记本电脑。

第二章，*使用 wiringPi 实现 Blink*，介绍了 wiringPi 库的安装。在本章中，我们将了解树莓派的 wiringPi 引脚连接。然后，我们将编写两个 C++程序，并将它们上传到我们的树莓派上。

第三章，*编程机器人*，介绍了选择机器人底盘的标准。之后，我们将构建我们的小车，将电机驱动器连接到树莓派，并了解 H 桥电路的工作原理。最后，我们将编写程序，使机器人向前、向后、向左和向右移动。

第四章，*构建避障机器人*，介绍了超声波传感器的工作原理，并编写了一个测量距离值的程序。接下来，我们将编程 16 x 2 LCD 以读取超声波距离值。我们还将研究 I2C LCD，它将 16 个 LCD 引脚作为输入，并提供四个引脚作为输出，从而简化了接线连接。最后，我们将在机器人上安装超声波传感器，创建我们的避障机器人。当附近没有障碍物时，这个机器人将自由移动，如果它接近障碍物，它将通过转弯来避开。

第五章，*使用笔记本电脑控制机器人*，介绍了使用笔记本电脑控制机器人的两种不同技术。在第一种技术中，我们将使用 ncurses 库从键盘接收输入，以相应地移动机器人。在第二种技术中，我们将使用 QT Creator IDE 创建 GUI 按钮，然后使用这些按钮以不同的方向移动机器人。

第六章，*使用 OpenCV 访问 Rpi 相机*，重点介绍了在树莓派上安装 OpenCV。您还将了解树莓派相机模块，并在设置 Pi 相机后，使用 Pi 相机拍照和录制短视频剪辑。

第七章，*使用 OpenCV 构建一个目标跟随机器人*，介绍了 OpenCV 库中的一些重要功能。之后，我们将对这些功能进行测试，并尝试从图像中识别对象。然后，我们将学习如何从 Pi 摄像头读取视频源，如何对彩色球进行阈值处理，以及如何在其上放置一个红点。最后，我们将使用 Pi 摄像头和超声波传感器来检测球并跟随它。

第八章，*使用 Haar 分类器进行面部检测和跟踪*，使用 Haar 面部分类器从视频源中检测面部并在其周围绘制一个矩形。接下来，我们将检测给定面部上的眼睛和微笑，并创建一个围绕眼睛和嘴的圆圈。在使用这些面部和眼睛检测知识后，我们将在检测到眼睛和微笑时首先打开/关闭 LED。接下来，通过在面部中心创建一个白点，我们将使机器人跟随面部。

第九章，*构建语音控制机器人*，从创建我们的第一个 Android 应用程序 Talking Pi 开始，其中文本框中的文本将显示在标签中，并由智能手机朗读出来。然后，我们将为机器人开发一个语音控制的 Android 应用程序，该应用程序将识别我们的声音并通过蓝牙将文本发送到 RPi。之后，我们将使用终端窗口将 Android 智能手机的蓝牙与 RPi 的蓝牙配对。最后，我们将研究套接字编程，并编写 VoiceBot 程序，以建立与 Android 智能手机蓝牙的连接，以控制机器人。

# 为了充分利用本书

要使用本书中的代码，需要 Raspberry Pi 3B+或 Raspberry Pi Zero 板。每章的*技术要求*部分中提到了额外的硬件和软件。

# 下载示例代码文件

您可以从您在[www.packt.com](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packt.com/support](http://www.packt.com/support)并注册，以便文件直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[www.packt.com](http://www.packt.com)登录或注册。

1.  选择 SUPPORT 选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的解压缩或提取文件夹：

+   WinRAR/7-Zip 适用于 Windows

+   Mac 上的 Zipeg/iZip/UnRarX

+   7-Zip/PeaZip 适用于 Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Robotics-Programming-with-Cpp`](https://github.com/PacktPublishing/Hands-On-Robotics-Programming-with-Cpp)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还提供了来自我们丰富书籍和视频目录的其他代码包，网址为**[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)**。请查看！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/9781789139006_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/9781789139006_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：指示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。这是一个例子：“将轴向和径向转向的代码添加到`RobotMovement.cpp`程序中。”

代码块设置如下：

```cpp
digitalWrite(0,HIGH);           //PIN O & 2 will STOP the Left Motor
digitalWrite(2,HIGH);
digitalWrite(3,HIGH);          //PIN 3 & 4 will STOP the Right Motor
digitalWrite(4,HIGH);
delay(3000);
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```cpp
digitalWrite(0,HIGH);           //PIN O & 2 will STOP the Left Motor
digitalWrite(2,HIGH);
digitalWrite(3,HIGH);          //PIN 3 & 4 will STOP the Right Motor
digitalWrite(4,HIGH);
delay(3000);
```

任何命令行输入或输出都将以以下方式书写：

```cpp
sudo nano /boot/config.txt
```

**粗体**: 表示一个新术语、一个重要词或者屏幕上看到的词。例如，菜单或对话框中的单词会以这种方式出现在文本中。这里有一个例子："选择 记住密码 选项 然后按 确定。"

警告或重要说明会显示在这样。

提示和技巧会显示在这样。


# 第一部分：在树莓派上使用 wiringPi 入门

在本节中，您将首先介绍树莓派的基础知识，并学习如何在树莓派上安装 Raspbian 操作系统。接下来，您将使用 wiringPi 库，在树莓派上执行您的第一个 C 程序。

本节包括以下章节：

+   第一章，树莓派简介

+   第二章，使用 wiringPi 实现闪烁


# 第一章：Raspberry Pi 简介

最初的想法是在英国各地的学校教授和推广基本的计算机编程，**Raspberry Pi**（**RPi**）立即成为了一大热门。最初发布时的价格仅为 25 美元，因此受到了开发人员、爱好者和工程师的欢迎，并且至今仍然被全世界广泛使用。

在本章中，您将探索 Raspberry Pi 的基本概念。然后，您将学习在设备上安装操作系统。最后，您将配置 Raspberry Pi 上的 Wi-Fi，并学习如何通过 Wi-Fi 将其连接到笔记本电脑并设置远程桌面。

通过以下主题，您将实现这些目标：

+   了解 Raspberry Pi

+   在 Raspberry Pi 3B+上安装 Raspbian OS

+   通过 Wi-Fi 将 Raspberry Pi 3B+连接到笔记本电脑

+   在 Raspberry Pi Zero W 上安装 Raspbian OS

+   通过 Wi-Fi 将 Raspberry Pi Zero W 连接到笔记本电脑

# 技术要求

对于本章，需要以下软件和硬件。

# 所需软件

如果您想按照本章的说明进行操作，请下载以下软件：

+   **Raspbian Stretch**：Raspbian Stretch 是我们将写入 microSD 卡的**操作系统**（**OS**）。Stretch 是将运行我们的 Raspberry Pi 的操作系统。可以从[`www.raspberrypi.org/downloads/raspbian/`](https://www.raspberrypi.org/downloads/raspbian/)下载。这个操作系统是专门为 Raspberry Pi 开发的。

+   **Balena Etcher**：此软件将格式化 microSD 卡并将 Raspbian Stretch 镜像写入 microSD 卡。可以从[`www.balena.io/etcher/`](https://www.balena.io/etcher/)下载。

+   **PuTTY**：我们将使用 PuTTY 将 Raspberry Pi 连接到 Wi-Fi 网络，并找到 Wi-Fi 网络分配给它的 IP 地址。可以从[`www.chiark.greenend.org.uk/~sgtatham/putty/latest.html`](https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html)下载。

+   **VNC Viewer**：使用 VNC Viewer，我们将能够在笔记本电脑上查看 Raspberry Pi 的显示。可以从[`www.realvnc.com/en/connect/download/viewer/`](https://www.realvnc.com/en/connect/download/viewer/)下载。

+   **Bonjour**：通常用于通过 Wi-Fi 将打印机连接到计算机。可以从[`support.apple.com/kb/DL999?viewlocale=en_MY&locale=en_MY`](https://support.apple.com/kb/DL999?viewlocale=en_MY&locale=en_MY)下载。

+   **Notepad++**：我们需要 Notepad++来编辑 Raspbian Stretch 镜像中的代码。可以从[`notepad-plus-plus.org/download/v7.5.9.html`](https://notepad-plus-plus.org/download/v7.5.9.html)下载。

+   **Brackets**：Brackets 允许使用 macOS 的用户编辑 Rapbian Stretch 镜像中的代码。要下载 Brackets，请访问[`www.brackets.io/`](http://www.brackets.io/)。

所有这些软件的安装都非常简单。保持默认设置选中，点击几次“下一步”按钮，然后在安装完成后点击“完成”按钮。

# 硬件要求

我们需要以下硬件来按照本章的说明进行操作。

# 适用于 Raspberry Pi 3B+和 Raspberry Pi Zero W

如果您使用 Raspberry Pi 3B+或 Raspberry Pi Zero W，您将需要以下硬件：

+   键盘

+   鼠标

+   SD 卡——应具有至少 8GB 的存储空间，但建议使用 32GB

+   MicroSD 卡读卡器

+   显示器——具有 HDMI 端口的计算机显示器或电视

+   HDMI 电缆

+   5V 移动充电器或移动电源。这将为 Raspberry Pi 供电

# Raspberry Pi 3B+的额外硬件

Raspberry Pi 3B+需要以下额外的硬件：

+   一根以太网电缆

# Raspberry Pi Zero W 的额外硬件要求

由于 Raspberry Pi Zero 具有微型 USB 端口和 Micro HDMI 端口，因此需要以下额外的硬件：

+   USB 集线器

+   一根微型 USB B 到 USB 连接器（也称为 OTG 连接器）

+   一个 HDMI 到迷你 HDMI 连接器

# 了解树莓派

树莓派是一款信用卡大小的基于 Linux 的微型计算机，由树莓派基金会于 2012 年发明。第一款树莓派型号被称为树莓派 1B，随后推出了 A 型。树莓派板最初是为了推广学校的计算机科学课程。然而，它们廉价的硬件和免费的开源软件，很快使树莓派在黑客和机器人开发者中流行起来。

树莓派可以用作完全功能的计算机。它可以用于浏览互联网，玩游戏，观看高清视频，以及创建 Excel 和 Word 文档等任务。但它与普通计算机的真正区别在于其可编程的 GPIO 引脚。树莓派由**40 个数字 I/O GPIO 引脚**组成，可以进行编程。

简单来说，树莓派可以被认为是**微型计算机**和**电子硬件板**的结合，因为它既可以用作完全功能的计算机，也可以用来创建电子和机器人项目。

有不同的树莓派型号。在本书中，我们将使用以下两个型号：

+   树莓派 3B+

+   树莓派 Zero W

# 树莓派 3B+

树莓派 3B+于 2018 年 2 月发布。其规格如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/d87e50ec-5758-46d0-81c4-401e7b15204c.png)

树莓派 3B+的规格如下：

+   Broadcom BCM2837 四核 1.4 GHz 处理器

+   1 GB RAM

+   Broadcom VideoCore GPU

+   蓝牙 4.2

+   双频 2.4 GHz 和 5 GHz Wi-Fi

+   一个以太网端口

+   通过 microSD 插槽使用 microSD 卡进行存储

+   40 个可编程的 GPIO 引脚

+   四个 USB 2.0 端口

+   一个 HDMI 端口

+   3.5 毫米音频插孔

+   **摄像头串行接口**（**CSI**），用于将树莓派摄像头直接连接到树莓派

# 树莓派 Zero W

如果我们正在寻找一个更小尺寸的树莓派版本，我们可以选择树莓派 Zero W。**W**代表**无线**，因为树莓派 Zero W 具有内置 Wi-Fi。以下是树莓派 Zero W 的规格：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/e31c570f-5732-4288-b40e-2795b7fa6ada.png)

树莓派 Zero W 型号的成本约为 10 美元。还有一个没有**W**的树莓派 Zero，成本约为 5 美元，但它没有内置 Wi-Fi，这使得它非常难以连接到互联网。2017 年发布的树莓派 Zero W 基本上是 2015 年发布的树莓派 Zero 的升级版本。

在本书的后面，当我们设计我们的机器人时，我们将学习如何通过 Wi-Fi 网络从笔记本电脑无线上传程序到我们的树莓派。如果你选择购买树莓派的较小版本，我建议你选择树莓派 Zero W，而不是树莓派 Zero，以便使用更加方便。

树莓派 Zero W 由于尺寸较小，有一些缺点。首先，它比树莓派 3B+慢一些。其次，如果我们想将其用作微型计算机，我们需要购买不同的扩展设备来连接外围设备，如键盘、鼠标或显示器。然而，如果我们打算将树莓派 Zero W 用于构建电子和机器人项目，我们就不需要担心这个缺点。在本书的后面，我们将学习如何通过 Wi-Fi 将树莓派 Zero W 连接到笔记本电脑，并如何使用笔记本电脑来控制它。

树莓派 Zero W 的规格如下：

+   Broadcom ARM11 1 GHz 处理器

+   512 MB RAM

+   Broadcom VideoCore GPU

+   蓝牙 4.0

+   双频 2.4 GHz 和 5 GHz Wi-Fi

+   通过 microSD 插槽使用 microSD 卡进行存储

+   40 个可编程的 GPIO 引脚

+   一个迷你 HDMI 端口

+   **摄像头串行接口**（**CSI**），用于将树莓派摄像头直接连接到树莓派

# 设置树莓派 3B+作为台式电脑

为了在树莓派 3B+上设置和安装 Raspbian OS，我们需要各种硬件和软件组件。硬件组件包括以下内容：

+   一台笔记本电脑，用于在 microSD 卡上安装 Raspbian OS。

+   一个键盘。

+   一只老鼠。

+   一个 SD 卡-至少 8GB 的存储卡就足够了，但是使用 8GB 卡，默认 OS 将占据存储卡空间的 50%。在本章后面，我们还将在树莓派上安装 OpenCV，由于 OpenCV 也会占用存储卡上的大量空间，因此您需要卸载一些默认软件。因此，我建议您使用 16GB 或 32GB 存储卡-使用 32GB 存储卡，默认 OS 仅占据卡空间的 15%。

+   一个 SD 卡读卡器。

+   显示单元-这可以是计算机显示器或电视，只要它具有 HDMI 端口。

+   一个 HDMI 电缆。

+   移动充电器或移动电源为树莓派供电。

所需的软件组件包括以下内容：

+   刻录机

+   带桌面的 Raspbian Stretch 操作系统

现在我们知道需要安装 OS，让我们开始安装。

# 在 SD 卡上安装 Raspbian OS

要在 microSD 卡上安装 Raspbian OS，我们首先将在计算机上安装**Etcher**。之后，我们将把 microSD 卡插入 microSD 卡读卡器，并将其连接到计算机上。

# 下载和安装 Etcher

Etcher 将首先格式化 microSD 卡，然后将 Raspbian Stretch 图像写入其中。让我们开始安装 Etcher：

1.  在浏览器中，转到[`www.etcher.io/`](http://www.etcher.io/)[.](https://etcher.io/)

1.  从下拉菜单中选择您的操作系统。Etcher 将开始下载，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/9ee22f37-8a33-436c-b7bf-069930dab9e3.png)

1.  下载完成后，打开安装文件并安装 Etcher。

现在 Etcher 已经设置好了，让我们继续进行 Raspbian 的安装。

# 下载 Raspbian Stretch 图像

现在我们必须下载一个 OS 来在树莓派上运行。虽然有许多第三方树莓派 OS 可用，但我们将安装 Raspbian OS。这个 OS 基于 Debian，专门为树莓派开发。最新版本称为**Raspbian Stretch**。

要下载 Raspbian Stretch 图像，请访问[`www.raspberrypi.org/downloads/raspbian/`](https://www.raspberrypi.org/downloads/raspbian/)，查找 RASPBIAN STRETCH WITH DESKTOP ZIP 文件，并单击“下载 ZIP”按钮，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/3d3c39bc-2306-43b9-9c27-460cc390a8a5.png)

现在我们在笔记本电脑上有了 Raspbian Stretch 的副本，让我们继续将其写入我们的 microSD 卡。

# 将 Raspbian Stretch 图像写入 microSD 卡

下载 Etcher 和 Raspbian Stretch 图像后，让我们将 Raspbian Stretch 写入我们的 microSD 卡：

1.  将 microSD 卡插入 microSD 卡读卡器，然后通过 USB 将读卡器连接到笔记本电脑：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/41609a9c-de1c-4d5d-9a88-cfc489ba3938.png)

1.  接下来，打开 Etcher 并单击“选择图像”按钮。然后，选择 Raspbian Stretch ZIP 文件并单击“打开”：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/0c8c9c38-7d73-400e-965b-7d22b9689088.png)

1.  之后，请确保选择了 microSD 卡读卡器驱动器，如下面的屏幕截图所示。如果错误地选择了其他驱动器，请单击“更改”按钮并选择 microSD 卡驱动器。单击“闪存！”按钮将 Raspbian OS 写入 microSD 卡：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/6ae14275-52e8-409b-bf48-1899fc75dc76.png)

将图像写入 SD 卡的过程也称为**启动**。

Etcher 将花大约 15-20 分钟来用 Raspbian OS 刷写您的 SD 卡：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/f9a8fc7c-04b0-456e-a112-8cf937443d4d.jpg)

一旦 OS 被写入 SD 卡，Etcher 将自动弹出 microSD 卡读卡器。

现在我们已经将 Raspbian Stretch 写入我们的 microSD 卡，让我们开始设置树莓派 3B+。

# 设置树莓派 3B+

从 microSD 卡引导 Raspbian 操作系统后，我们将通过连接不同的外围设备来设置树莓派，如下所示：

1.  将 microSD 卡插入位于树莓派 3B+背面的 SD 卡槽中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/c680b739-7f97-4d60-b10b-8a917c02b6b3.png)

1.  将键盘和鼠标连接到树莓派 3B+的 USB 端口。也可以使用无线键盘和鼠标：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/bb9ea818-6b29-4c02-904d-938160ce10ab.png)

1.  树莓派 3B+包含一个 HDMI 端口，我们可以用它连接 RPi 到显示单元，比如计算机显示器或电视。将 HDMI 电缆的一端连接到树莓派的 HDMI 端口，另一端连接到显示单元：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/62feef5f-4473-4d77-9cd1-e8e725d72fd7.png)

1.  最后，为了打开树莓派，我们需要提供电源。一个典型的树莓派需要 5V 的电压和理想情况下 2.5A 的电流。我们可以使用两种方法为树莓派提供电源：

+   +   **智能手机充电器**：大多数智能手机充电器提供 5V 的电压输出和 2.5A 的电流输出。如果你仔细看一下你的智能手机充电器，你会发现最大电压和电流输出值印在上面，如下图所示。在我的充电器上，3A 的电流输出表示最大电流输出。然而，充电器只会根据 RPi 的需求提供电流输出，而不是最大电流 3A。请注意，树莓派包含一个 micro **USB B**端口，因此，为了连接到树莓派的电源端口，我们需要用 micro **USB B**线连接到我们的充电器：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/b223517b-a0cd-42bc-bc52-48f6d9647336.png)

+   +   **移动电源或电池组**：另外，我们可以使用移动电源或电池组。如前所述，我们需要通过 micro USB B 端口将移动电源连接到树莓派，并且我们还需要确保它提供 5V 的电压输出和大约 2.5A 的电流输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/f0e0aa48-b5e6-4a07-aa48-cb4d1b0abd87.png)

1.  一切都插好后，打开显示单元，确保选择了正确的 HDMI 选项。

1.  接下来，打开电源。你会看到树莓派上的红色 LED 灯亮起。等待大约 10-20 秒，等待树莓派启动。一旦完成，你会看到以下屏幕：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/ca735791-3548-48e9-8dec-1f41dc681335.png)

现在我们的树莓派 3B+已经运行起来了，让我们把它连接到互联网。

# 连接树莓派 3B+到互联网

我们可以使用两种方法为树莓派提供互联网连接：

+   **以太网电缆**：树莓派 3B+包含一个以太网端口。要通过以太网端口提供互联网连接，只需将以太网电缆连接到它。

+   **Wi-Fi**：通过 Wi-Fi 连接树莓派也非常简单。点击任务栏中的 Wi-Fi 图标。选择你的 Wi-Fi 网络，输入正确的密码，树莓派将连接到所需的 Wi-Fi 网络：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/f8526e29-bec4-4d43-b892-dc8ba90389e7.png)

在将树莓派 3B+设置为桌面电脑后，我们可以简单地打开任何代码编辑器，开始编写程序来控制树莓派的电机或 LED。

由于我们将使用树莓派创建一个可移动的机器人，因此桌面电脑设置将无法使用。这是因为显示器、键盘和鼠标都直接连接到 Pi，将限制其移动。在下一节中，为了能够在没有这些外围设备的情况下使用它，我们将看看如何通过 Wi-Fi 将树莓派 3B+无线连接到笔记本电脑。

# 通过 Wi-Fi 将树莓派 3B+连接到笔记本电脑

要通过 Wi-Fi 将树莓派 3B+无线连接到笔记本电脑，我们首先需要使用一个名为 PuTTY 的软件将 RPi 连接到 Wi-Fi 网络。之后，我们可以找出树莓派的 IP 地址，并将其输入到一个名为**VNC Viewer**的软件中，以将树莓派连接到笔记本电脑。为了成功执行此任务，树莓派和笔记本电脑必须连接到同一个 Wi-Fi 网络。

所需的硬件包括以下内容：

+   **以太网电缆**：以太网电缆将直接连接到树莓派 3B+的以太网端口和笔记本电脑的以太网端口。如果您的笔记本电脑不包含以太网端口，则需要为您的笔记本电脑购买一个**USB 到以太网**连接器。

+   **Micro USB B 电缆**：这是连接树莓派 3B+和笔记本电脑的标准 Micro USB B 电缆。

所需的软件是**PuTTY**，VNC Viewer 和 Bonjour。

# 在 microSD 卡上创建一个 SSH 文件

安装了上述软件后，我们需要在 microSD 卡上创建一个 SSH 文件，以启用树莓派 3B+的 SSH。为此，请执行以下步骤：

1.  打开分配给 SD 卡的驱动器。在我们的案例中，这是`boot (F:)`驱动器。如下面的截图所示，microSD 卡上有一些文件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/d35a5892-4f40-4e3e-a93b-5e8db01c8170.png)

1.  要创建 SSH 文件，请在驱动器中右键单击，然后单击**新建**，选择**文本文档**，如此处所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/45601b8a-6404-4efb-a43d-4e3ad98d739d.png)

1.  给这个文本文件命名为`ssh`，但不要包括`.txt`扩展名。我们会收到一个警告，指出这个文件将变得不稳定，因为它没有扩展名。点击**是**按钮：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/8026d47a-17d1-40c1-9b6e-033eb80accae.png)

1.  接下来，右键单击`ssh`文件，然后选择**属性**选项。在属性中，点击**常规**选项卡。我们应该看到**文件类型**设置为文件。点击确定：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/f34cd446-e408-4474-9ae8-56f49c5e003e.png)

在 microSD 卡上创建一个 SSH 文件后，从笔记本电脑中取出读卡器，并将 microSD 卡插入树莓派 3B+。

在下一节中，我们将看看如何将 RPi 3B+连接到 Wi-Fi 网络。设置是在 Windows 系统上完成的。如果你有一台 Mac，那么你可以按照以下教程视频之一进行操作：

+   **在 Mac 上访问 Raspbian OS**：**[`www.youtube.com/watch?v=-v88m-HYeys`](https://www.youtube.com/watch?v=-v88m-HYeys)**

+   **在 VNC Viewer 上访问树莓派显示**：**[`www.youtube.com/watch?v=PYunvpwSwGY`](https://www.youtube.com/watch?v=PYunvpwSwGY)**

# 使用 PuTTY 将树莓派 3B+连接到 Wi-Fi 网络

将 microSD 卡插入 RPi 后，让我们看看如何使用 PuTTY 将树莓派连接到 Wi-Fi 网络：

1.  首先，将以太网电缆的一端连接到树莓派的以太网端口，另一端连接到笔记本电脑的以太网端口。

1.  接下来，通过使用 Micro USB B 电缆将树莓派 3B+连接到笔记本电脑来启动树莓派 3B+。我们会看到红色的电源 LED 灯亮起。我们还会看到以太网端口的黄色 LED 灯亮起并持续闪烁。

1.  之后，打开 PuTTY 软件。在主机名框中，输入`raspberrypi.local`，然后点击**打开**按钮：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/ba9cd502-99ba-4e1f-83ea-1b81e8a3d162.png)

1.  然后我们会看到一个 PuTTY 安全警告消息。点击**是**：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/fcf02cb1-69c2-41c1-9788-96bf1710f627.png)

1.  在 PuTTY 中，我们需要输入树莓派的凭据。默认登录名是`pi`，密码是`raspberry`。输入密码后，按*Enter*：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/721ff4d4-afe5-4325-ac9c-2093f56415ef.png)

1.  之后，要将树莓派 3B+连接到特定的 Wi-Fi 网络，请输入`sudo nano /etc/wpa_supplicant/wpa_supplicant.conf`命令，如此截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/fbfa565e-ac27-40a2-849b-d0248be43d2a.png)

1.  这个命令将打开 nano 编辑器，看起来如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/4bd64bc9-d1ff-45f7-add4-05971e06bbb6.png)

1.  在`update_config=1`行下，按照以下语法输入您的 Wi-Fi 名称和密码：

```cpp
network={
*ssid="*Wifi name*"* psk="Wifi password"
}
```

确保将前面的代码精确地添加到`update_config=1`行下方。Wi-Fi 名称和密码应该用双引号(`""`)括起来，如此处所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/825ccc45-2a16-41dc-9000-3f9d606139f5.png)

输入 Wi-Fi 名称和密码后，按下*Ctrl* + *O*键保存更改。然后按*Enter*。之后，按下*Ctrl* + *X*键退出 nano 编辑器。

1.  要重新配置并将树莓派连接到 Wi-Fi 网络，请输入以下命令：`sudo wpa_cli reconfigure`。如果连接成功，您将看到接口类型和`OK`消息：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/dbc7b302-9fff-4ee9-ad45-7d0f830d0c2f.png)

1.  然后我们需要重新启动树莓派。要做到这一点，输入`sudo shutdown now`。一旦树莓派关闭，关闭 PuTTY 软件。

1.  接下来，从笔记本电脑上拔下 USB 电缆。

1.  之后，拔下连接到树莓派和笔记本电脑的以太网电缆。

1.  重新连接 USB 电缆，以便树莓派开机。

1.  打开 PuTTY。在主机名字段中再次输入`raspberrypi.local`，然后按打开按钮：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/662db87f-3dc0-40bd-9148-f09eee3f41b2.png)

1.  输入我们之前使用的用户名和密码。

1.  一旦树莓派连接到 Wi-Fi 网络，Wi-Fi 网络将为其分配一个 IP 地址。要查找 IP 地址，请输入`ifconfig wlan0`命令并按*Enter*。您会注意到现在已经分配了一个 IP 地址：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/4888107f-9cca-4fe2-9268-960fe0cba6cd.png)

在我的情况下，IP 地址是`192.168.0.108`。请在某处记下您的 IP 地址，因为在使用 VNC Viewer 软件时需要输入它。

# 启用 VNC 服务器

要查看树莓派显示，我们需要从树莓派配置窗口启用 VNC 服务器：

1.  要打开配置窗口，我们需要在 PuTTY 终端中键入`sudo raspi-config`并按*Enter*。然后我们可以打开接口选项，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/d0d96370-7ea7-42df-af94-1f9408c9a25a.png)

1.  然后我们可以打开**VNC**选项：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/da06fd14-da0d-4265-8453-fcba398c6bdd.png)

1.  要启用 VNC 服务器，请导航到“Yes”选项并按*Enter*：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/5226edbd-ea63-4b21-b757-1ceb778988ed.png)

1.  启用 VNC 服务器后，按 OK：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/9c1bbec9-0545-4752-bebe-495150257fa0.png)

1.  按 Finish 退出树莓派配置窗口：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/d1d6425d-a0ea-4629-b882-6276a4df159d.png)

启用 VNC 服务器后，我们将打开 VNC Viewer 软件，以便可以看到树莓派显示屏。

# 在 VNC Viewer 上查看树莓派输出

要在 VNC Viewer 上查看树莓派输出，请按照以下说明操作：

1.  打开 VNC Viewer 软件后，在 VNC Viewer 中输入您的树莓派 IP 地址，然后按*Enter*：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/a3332d62-9305-4a35-9e37-8869a4453cb0.png)

1.  您将收到一个弹出消息，指出 VNC Viewer 没有此 VNC 服务器的记录。按继续：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/b5e12eed-984c-4ac6-8cfb-4a5a34be5870.png)

1.  输入用户名`pi`和密码`raspberry`**。** 选择记住密码选项，然后按 OK：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/1370ca89-f78d-435a-8938-a0e1db4dc753.png)

现在我们应该能够在 VNC Viewer 软件中查看树莓派显示输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/bfb0ab7e-fc5d-4da1-981b-987826b75bba.png)

现在我们已经通过 Wi-Fi 将树莓派连接到笔记本电脑，就不需要再通过 USB 电缆将树莓派连接到笔记本电脑了。下次，我们可以简单地使用移动电源或移动充电器为树莓派供电。当我们选择我们的树莓派的 IP 地址时，我们可以使用 VNC Viewer 软件查看树莓派显示输出。

如前所述，请确保在使用笔记本电脑进行远程桌面访问时，树莓派和笔记本电脑都连接到同一 Wi-Fi 网络。

# 增加 VNC 的屏幕分辨率

在 VNC Viewer 中查看 RPi 的显示输出后，你会注意到 VNC Viewer 的屏幕分辨率很小，没有覆盖整个屏幕。为了增加屏幕分辨率，我们需要编辑`config.txt`文件：

1.  在终端窗口中输入以下命令：

```cpp
sudo nano /boot/config.txt
```

1.  接下来，在`#hdmi_mode=1`代码下面，输入以下三行：

```cpp
hdmi_ignore_edid=0xa5000080
hdmi_group=2
hdmi_mode=85
```

1.  之后，按下*Ctrl* + *O*，然后按*Enter*保存文件。按下*Ctrl* + *X*退出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/7bc3020b-fc6a-4efc-bc8f-7c12a93f1970.png)

1.  接下来，重新启动你的 RPi 以应用这些更改：

```cpp
sudo reboot
```

重新启动后，你会注意到 VNC 的屏幕分辨率已经增加，现在覆盖了整个屏幕。

# 处理 VNC 和 PuTTY 错误

在 VNC Viewer 中，有时当你选择 RPi 的 IP 地址时，你可能会看到以下弹出错误消息，而不是 RPi 的显示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/a96b0a16-1fb5-4591-9114-419fb5c9a2cd.png)

你可能还会看到以下消息：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/ca417b88-0a59-4312-ba18-bd6b71ab5021.png)

如果你遇到以上任何错误，请点击笔记本电脑上的 Wi-Fi 图标，并确保你连接到与 RPi 连接的相同的 Wi-Fi 网络。如果是这种情况，你的 RPi 的 IP 地址在 Wi-Fi 网络中可能已经改变，这在新设备连接到 Wi-Fi 网络时有时会发生。

要找到新的 IP 地址，请按照以下步骤操作：

1.  打开 PuTTY，输入`raspberrypi.local`到主机名框中。

1.  在 PuTTY 的终端窗口中输入命令`ifconfig wlan0`。如果你的 IP 地址已经改变，你会在`inet`选项中看到新的 IP 地址。

1.  在 VNC Viewer 中输入新的 IP 地址以查看 RPi 的显示输出。

有时，你可能也无法连接到 Putty，并且会看到以下错误：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/2faf56c7-3679-4f18-af45-0f088a9d4e83.png)

要解决 PuTTY 中的前述错误，请按照以下步骤操作：

1.  将 LAN 电缆连接到 RPi 和笔记本电脑。

1.  打开你的 RPi 并尝试通过在主机名框中输入`raspberrypi.local`来连接 putty。通过 LAN 电缆连接到 RPi 和笔记本电脑，你应该能够访问 PuTTY 终端窗口。

1.  按照之前的步骤找到 RPi 的新 IP 地址。

1.  一旦你在 VNC Viewer 中看到 RPi 的显示，你可以拔掉 LAN 电缆。

# 设置树莓派 Zero W 为台式电脑

正如我们所说，树莓派 Zero W 是树莓派 3B+的简化版本。树莓派 Zero W 的连接非常有限，因此为了连接不同的外围设备，我们需要购买一些额外的组件。我们需要以下硬件组件：

+   一个键盘

+   一个鼠标

+   一个至少 8GB 的 microSD 卡（推荐 32GB）

+   一个 microSD 卡读卡器

+   一个 HDMI 电缆

+   一个显示单元，最好是带有 HDMI 端口的 LED 屏幕或电视

+   一个移动充电器或移动电源来为树莓派供电

+   一个 micro USB B 到 USB 连接器（也称为 OTG 连接器），看起来像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/a31de9cd-cb94-49d4-ba91-f1f812d1e223.png)

+   一个迷你 HDMI 到 HDMI 连接器，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/8053b151-a774-4033-8843-adf17be41506.png)

+   一个 USB 集线器，如图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/97dc9277-51cb-46a9-887e-1d754e1d5485.png)

现在我们知道需要哪些硬件，让我们设置我们的树莓派 Zero W。

# 设置树莓派 Zero W

将 Raspbian OS 安装到 microSD 卡上的步骤与在“在 SD 卡上安装 Raspbian OS”部分中已经列出的树莓派 3B+完全相同。一旦你的 SD 卡准备好了，按照以下步骤设置树莓派 Zero W：

1.  首先，将 microSD 卡插入树莓派 Zero W 的 SD 卡槽中。

1.  将**mini HDMI 到 HDMI 连接器**（H2HC）的一端插入树莓派 Zero W 的 HDMI 端口，将 H2HC 连接器的另一端插入 HDMI 电缆。

1.  将 OTG 连接器连接到 Micro USB 数据端口（而不是电源端口），并将 USB 集线器连接到 OTG 连接器。

1.  将键盘和鼠标连接到 USB 集线器。

1.  将移动充电器或电池组连接到电源单元的 Micro USB 端口。

1.  接下来，将 HDMI 电缆连接到电视或监视器的 HDMI 端口。

1.  将移动充电器连接到主电源以为树莓派 Zero W 供电。然后，当树莓派 Zero W 开机时，您将看到绿色 LED 闪烁一段时间。

1.  如果您已将 HDMI 电缆连接到电视，请选择正确的 HDMI 输入通道。以下有注释的照片显示了这里提到的连接：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/2c3b8857-7884-4530-b5dd-a63dce2bab07.png)

树莓派 Zero W 连接

1.  树莓派 Zero W 启动大约需要两到三分钟。一旦准备好，您将在电视或监视器屏幕上看到以下窗口：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/a7dc9eb4-3ec4-4dfc-aed6-5d5c4f4bcf65.png)

1.  要关闭树莓派，按树莓派图标，然后单击关闭。

现在设置好了，让我们将树莓派 Zero W 连接到笔记本电脑。

# 通过 Wi-Fi 将树莓派 Zero W 连接到笔记本电脑

当树莓派 Zero 于 2015 年首次推出时，它没有内置的 Wi-Fi 模块，这使得连接到互联网变得困难。一些树莓派开发人员想出了有用的黑客技巧，以连接树莓派到互联网，一些公司也为树莓派 Zero 创建了以太网和 Wi-Fi 模块。

然而，2017 年，树莓派 Zero W 推出。这款产品具有内置的 Wi-Fi 模块，这意味着树莓派开发人员不再需要执行任何 DIY 黑客或购买单独的组件来添加互联网连接。具有内置 Wi-Fi 还有助于我们将树莓派 Zero W 无线连接到笔记本电脑。让我们看看如何做到这一点。

将树莓派 Zero W 连接到笔记本电脑的 Wi-Fi 的过程与树莓派 3B+类似。但是，由于树莓派 Zero W 没有以太网端口，因此我们将不得不在`cmdline.txt`和`config.txt`文件中写入一些代码。

尽管`cmdline.txt`和`config.txt`是**文本**（**TXT**）文件，但这些文件中的代码在 Microsoft 的记事本软件中无法正确打开。要编辑这些文件，我们需要使用代码编辑器软件，例如 Notepad++（仅适用于 Windows）或 Brackets（适用于 Linux 和 macOS）。

安装其中一个后，让我们按以下方式自定义 microSD 卡：

1.  在树莓派 Zero W 中，我们还需要在 microSD 卡上创建一个 SSH 文件。有关如何在 microSD 卡上创建 SSH 文件的说明，请参阅*在 microSD 卡上创建 SSH 文件*部分。

1.  创建 SSH 文件后，右键单击`config.txt`文件，并在 Notepad++或 Brackets 中打开它。在这种情况下，我们将在 Notepad++中打开它：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/8426e584-8682-402a-bd99-0d0991e5066f.png)

向下滚动到此代码的底部，并在末尾添加行`dtoverlay=dwc2`。添加代码后，保存并关闭文件。

1.  接下来，打开 Notepad++中的`cmdline.txt`文件。`cmdline`文件中的整个代码将显示在一行上。接下来，请确保在`consoles`和`modules`之间只添加一个空格。

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/243eda4e-28b8-48d8-95d4-72dc49f8686a.png)

在`plymouth.ignore-serial-consoles`代码旁边输入行`modules-load=dwc2,g_ether`：

1.  接下来，使用**数据传输 USB 电缆**将树莓派 Zero W 连接到笔记本电脑。将 USB 电缆连接到树莓派 Zero W 的数据端口，而不是电源端口。

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/044f7037-35eb-4fa6-ad98-f7c31a263eb4.png)

1.  确保您连接到树莓派 Zero W 和笔记本电脑的 USB 电缆支持数据传输。例如，查看以下照片：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/e7b97117-7b28-4fff-8849-79f41d3bccf7.png)

在上面的照片中，有两根相似但重要不同的电缆：

+   +   左侧的小型 USB 电缆是随我的移动电源套件一起提供的。这个 USB 电缆提供电源，但不支持数据传输。

+   右侧的 USB 电缆是随新的安卓智能手机一起购买的。这些支持数据传输。

检查您的 USB 是否支持数据传输的一个简单方法是将其连接到智能手机和笔记本电脑上。如果您的智能手机被检测到，这意味着您的 USB 电缆支持数据传输。如果没有，您将需要购买一根支持数据传输的 USB 电缆。以下截图显示了 PC 检测到智能手机，这意味着正在使用的电缆是数据电缆：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/8efa878f-b5f0-4b6d-bad2-c8e09ce4bc1a.png)

如果您的 USB 电缆被检测到但经常断开连接，我建议您购买一根新的 USB 电缆。有时，由于磨损，旧的 USB 电缆可能无法正常工作。

# 使用 PuTTY 将树莓派 Zero W 连接到 Wi-Fi 网络

要将树莓派 Zero W 连接到 Wi-Fi 网络，请参阅*使用 PuTTY 将树莓派 3B+连接到 Wi-Fi 网络*部分。连接树莓派 Zero W 到 Wi-Fi 网络的步骤完全相同。

# 为树莓派 Zero W 启用 VNC Viewer

要为树莓派 Zero W 启用 VNC Viewer，请参阅*启用 VNC 服务器*部分。

# 在 VNC Viewer 上查看树莓派 Zero W 的输出

要在 VNC Viewer 中查看树莓派 Zero W 的输出，请参阅*在 VNC Viewer 上查看树莓派输出*部分*。*

# 总结

在本章中，我们已经学习了如何将树莓派 3B+和树莓派 Zero W 设置为普通的台式电脑。我们还学会了如何通过 Wi-Fi 网络将树莓派连接到笔记本电脑。现在，您可以在不需要连接键盘、鼠标和显示器的情况下，通过笔记本电脑远程控制树莓派。

在下一章中，我们将首先了解一些在树莓派 OS 中操作的基本命令。我们将在树莓派上安装一个名为 Wiring Pi 的 C++库，并了解该库的引脚配置。最后，我们将编写我们的第一个 C++程序，并将其无线上传到我们的树莓派。

# 问题

1.  树莓派 3B+上有哪种处理器？

1.  树莓派 3B+上有多少个 GPIO 引脚？

1.  我们用于在笔记本电脑上查看树莓派显示输出的软件是什么？

1.  树莓派的默认用户名和密码是什么？

1.  用于访问树莓派内部配置的命令是什么？


# 第二章：使用 wiringPi 实现 Blink

设置树莓派后，现在是时候连接不同的电子元件并使用 C++编程语言对其进行编程了。要使用 C++，我们首先需要下载并安装一个名为**wiringPi**的库。

在本章中，我们将涵盖以下主题：

+   在树莓派内安装`wiringPi`库

+   让 LED 闪烁

+   智能灯—使用数字传感器

+   使用 softPwm 进行脉宽调制

# 技术要求

本章的硬件要求如下：

+   1 个 LED（任何颜色）

+   1 **LDR**（**光敏电阻**）传感器模块

+   树莓派 3B+

+   5-6 个母对母连接线

本章的代码文件可以从以下网址下载：[`github.com/PacktPublishing/Hands-On-Robotics-Programming-with-Cpp/tree/master/Chapter02`](https://github.com/PacktPublishing/Hands-On-Robotics-Programming-with-Cpp/tree/master/Chapter02)。

# 在树莓派中安装 wiringPi 库

wiringPi 是一个基于引脚的 GPIO 访问库，用 C 语言编写。使用这个库，你可以用 C/C++编程控制树莓派。`wiringPi`库很容易设置。一旦安装，树莓派 GPIO 引脚将具有 wiringPi 引脚编号。让我们看看如何下载和安装 wiringPi：

1.  首先，点击任务栏上的图标打开终端窗口：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/ccf56d38-8928-47cc-be0c-ead4119c57fb.png)

1.  在安装`wiringPi`库之前，我们首先需要验证我们的树莓派是否有更新。如果你的树莓派没有更新，安装`wiringPi`库时可能会出现错误。要更新你的树莓派，输入以下命令：

```cpp
$ sudo apt-get update 
```

上述命令的输出如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/177fcaa3-a9d0-4bda-8218-6d0564a55064.png)

根据你的互联网速度，更新下载和安装需要大约 10-15 分钟。确保你将树莓派放在 Wi-Fi 路由器附近。

1.  更新后，输入以下命令升级树莓派：

```cpp
$ sudo apt-get upgrade
```

在升级过程中，你可能会收到一个要求下载特定组件的消息。输入`Y`然后按*Enter*。升级需要大约 30-40 分钟。升级完成后，你会看到以下消息：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/e293e669-4a8c-47e0-bccf-b65446f782d9.png)

1.  更新树莓派后，你需要在树莓派内下载和安装`git-core`。要安装 Git，输入以下命令：

```cpp
$ sudo apt-get install git-core
```

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/e96c7786-8561-4382-aaf7-8739fa6bf47b.png)

1.  之后，要从`git`下载`wiringPi`库，输入以下命令：

```cpp
git clone git://git.drogon.net/wiringPi
```

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/e10ba477-59d4-4a5b-9a9f-d2e4dca0d243.png)

1.  现在，如果你点击文件管理器选项并点击`pi`文件夹，你应该会看到`wiringPi`文件夹：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/fc5142f9-d5d1-49dd-b68e-420c27a6db79.png)

1.  接下来，更改目录到`wiringPi`，以便 wiringPi 文件被下载并安装到这个特定文件夹内。更改目录的命令是`cd`：

```cpp
$ cd ~/wiringPi (The ~ symbol is above the Tab key and it points to pi directory)
```

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/9df6e314-f099-4b15-86f9-98a351c609a6.png)

现在你应该看到指向`wiringPi`文件夹的目录。

1.  接下来，为了从`origin`目录获取 Git 文件，输入以下命令：

```cpp
$ git pull origin
```

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/fc06f480-b074-47f2-9e8b-d2a95b47d84d.png)

1.  最后，为了构建文件，输入以下命令：

```cpp
$ ./build 
```

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/e722c4f6-128b-43e4-868e-cf22a2718159.png)

一切都完成后，你会看到一个`All done`消息：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/2c66fbdf-02e9-4d2f-87bb-8c148679e580.png)

现在我们已经安装了 wiringPi 库，我们可以继续了解 RPi 上的 wiringPi 引脚配置。

# 通过 wiringPi 访问树莓派 GPIO 引脚

由于我们已经安装了 wiringPi，现在我们可以看一下 wiringPi 引脚编号，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/8cf066e9-8e3b-4f0d-ab08-90c43e25de71.png)

`物理`列代表树莓派编号从`1-40`。在`物理`列的两侧，您将看到 wiringPi（`wPi`）列。从`物理`列指向`wPi`的箭头代表树莓派的特定物理引脚的 wiringPi 引脚编号。

看一下以下示例：

+   物理引脚号 3 的 wiringPi 引脚号为 8

+   物理引脚号 5 的 wiringPi 引脚号为 9

+   物理引脚号 8 的 wiringPi 引脚号为 15

+   物理引脚号 11 的 wiringPi 引脚号为 0

+   物理引脚号 40 的 wiringPi 引脚号为 29

通过查阅这个表，您可以找出剩下的物理引脚对应的 wiringPi 引脚。

wiringPi 引脚号从 17 到 20 不存在。在 wPi 引脚 16 之后，我们直接跳到 wPi 引脚 21。

为了更好地理解 wiringPi 引脚和物理引脚之间的关系，您可以参考以下图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/97c2efb3-a563-478b-9e1c-441935552691.png)

wiringPi 引脚编号是编程时需要记住的。我们可以使用总共 28 个 wiringPi 引脚进行编程。除此之外，我们还有以下引脚，可以用于提供电源并可用作接地引脚：

+   物理引脚号 6、9、14、20、25、30、34 和 39 是接地引脚

+   物理引脚号 2 和 4 提供+5V 电源

+   物理引脚号 1 和 17 提供+3.3V 电源

让我们继续编写我们的第一个树莓派 C++程序。

# 让 LED 闪烁

我们要创建的第一个项目是让 LED 闪烁。对于这个项目，我们需要以下硬件组件：

+   树莓派

+   1 个 LED

+   两根母对母导线

# 接线连接

将 LED 连接到树莓派非常简单。不过，在这之前，让我们仔细看一下 LED 的引脚：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/a8e06d09-ca03-4a3b-812f-6d932b5ef25a.png)

LED 包含一个正极引脚和一个负极引脚。长引脚是正极引脚，可以连接到树莓派的任何数据引脚上。短引脚是负极引脚，可以连接到树莓派的接地引脚上。

让我们连接它。首先，将 LED 的负极引脚连接到树莓派的接地引脚（物理引脚号 6）。接下来，将 LED 的正极引脚连接到 wiringPi 引脚号 15：

**![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/0f6a2e67-aebb-4272-8974-1d153da87637.png) **

现在我们已经将 LED 连接到树莓派，让我们编写一个程序让 LED 闪烁。

# 闪烁程序

要编写我们的第一个 C++程序，我们将使用 Geany 程序编辑器。要打开 Geany，点击**树莓**图标，转到**编程**，然后选择**Geany 程序编辑器**：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/a90522b4-7b0a-4787-864c-b73596641d0a.png)

打开 Geany 后，您会看到一个名为`Untitled`的未保存文件。我们需要做的第一件事是保存文件。点击文件|另存为，并将此文件命名为`Blink.cpp`。

在这个文件中，写入以下代码使 LED 闪烁。您可以从 GitHub 存储库的`Chapter02`文件夹中下载`Blink.cpp`程序：

```cpp
#include <iostream>
#include <wiringPi.h>

int main(void)
{
wiringPiSetup();
pinMode(15,OUTPUT);

 for(;;)
 {
digitalWrite(15,HIGH);
delay(1000);
digitalWrite(15,LOW);
delay(1000);
 }
return 0;
 }
```

如果您以前做过 Arduino 编程，您可能已经理解了这段代码的大约 90%。这是因为 wiringPi 允许我们以 Arduino 格式编写 C++程序：

1.  在上面的代码中，我们首先导入了`iostream`和`wiringPi`库。

1.  接下来，我们有主函数，称为`int main`。由于这个函数没有任何参数，我们在圆括号内写入`void`语句。

1.  之后，`wiringPisetup()`函数初始化了`wiringPi`。它假定这个程序将使用 wiringPi 编号方案。

1.  接下来，使用`pinMode(15, OUTPUT)`命令，我们将 wiringPi 引脚号 15 设置为`OUTPUT`引脚。这是我们连接到 LED 正极引脚的引脚。

1.  之后，我们有一个无限的`for`循环。其中写入的代码将无限运行，除非我们从编码编辑器手动停止它。

1.  通过`digitalWrite(15,HIGH)`命令，我们在 LED 上写入`HIGH`信号，这意味着 LED 将打开。我们也可以使用数字`1`代替`HIGH`。

1.  接下来，通过`delay(1000)`命令，我们确保 LED 只亮**一秒**。

1.  接下来，通过`digitalWrite(15,LOW)`命令，在 LED 上写入`LOW`信号。这意味着 LED 将**关闭**一秒钟。

1.  由于此代码位于 for 循环中，LED 将保持**开**和**关**，直到我们另行指示为止。

# 将代码上传到树莓派

由于我们使用的是 wiringPi 编号约定，我们将在 Build 命令中添加`-lwiringPi`命令，以便我们的 C++程序能够成功编译和构建`wiringPi`库。要打开 Build 命令，点击 Build | Set Build Commands。在 Compile 和 Build 按钮旁的命令框中，添加`-lwiringPi`，然后点击 OK：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/e30cbd86-64fc-45f5-b473-f0a539dea459.png)

接下来，要编译代码，请点击**编译按钮**（棕色图标）。最后，要将代码上传到树莓派，请按**构建按钮**（飞机图标）：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/95a1fd04-a578-4b78-933d-6ad76438007c.png)

编译图标将检查代码中的错误。如果没有错误，点击构建图标以测试闪烁输出。构建代码后，构建图标将变成红色圆圈。点击红色圆圈停止程序。

# 智能灯 - 与数字传感器一起工作

在为树莓派编写我们的第一个 C/C++程序之后，我们现在可以编写一个程序，该程序将从 LDR 传感器接收输入并控制 LED 的开关。对于这个项目，您将需要以下硬件组件：

+   1 个 LDR 传感器模块

+   1 个 LED

+   树莓派

+   5 根母对母连接线

首先，让我们探讨一下 LDR 传感器的工作原理。

# LDR 传感器及其工作原理

LDR 传感器是一种模拟输入传感器，由可变电阻器组成，其电阻取决于其表面上落下的光线数量。当房间里没有光时，LDR 传感器的电阻很高（高达 1 兆欧姆），而在有光的情况下，LDR 传感器的电阻很低。LDR 传感器由两个引脚组成。这些引脚没有正负极性。我们可以使用任何引脚作为数据或地引脚，因此 LDR 传感器有时被称为特殊类型的电阻器。LDR 传感器的图像如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/64d208de-ef4f-4fef-8c6f-952cfc431afe.png)

由于 LDR 是模拟传感器，我们不能直接将其连接到 RPi，因为 RPi 不包含**模拟到数字转换器**（**ADC**）电路。因此，RPi 无法读取来自 LDR 传感器的模拟数据。因此，我们将使用 LDR 数字传感器模块，而不是 LDR 传感器，该模块将向 RPi 提供数字数据：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/a9d1de05-fc00-46b5-a57d-f16da16039a9.png)

LDR 传感器模块将读取来自 LDR 传感器的模拟数据，并以高电平或低电平的形式提供数字数据作为输出。LDR 传感器模块由 3 个引脚组成：**D0**（**数据输出**）、地和 Vcc。D0 将提供数字数据作为输出，然后作为输入提供给 RPi 引脚。在光线较暗时，D0 引脚将为高电平，在有光时，D0 引脚将为低电平。传感器模块还包括一个电位器传感器，可用于改变 LDR 传感器的电阻。

LDR 传感器模块的实际用途可见于街灯，它们在白天自动关闭，在夜晚自动打开。我们将要编写的智能灯程序与此应用有些类似，但我们将使用 LED 来简化事情，而不是街灯。

现在我们已经了解了 LDR 传感器的基本工作原理，接下来让我们将 LDR 传感器模块连接到树莓派。

# 接线连接

通过接线连接，我们可以将 LDR 传感器模块和 LED 连接到 RPi：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/72d9bc67-5467-4d05-a5a0-af7d7bc7fbff.png)

接线连接如下：

+   RPi 的 wiringPi 引脚 8 连接到 LDR 传感器模块的 D0 引脚

+   RPi 的物理引脚 2 连接到 LDR 传感器模块的 Vcc 引脚

+   RPi 的物理引脚 6 连接到 LDR 传感器模块的 Gnd 引脚

+   wiringPi 引脚 0 连接到 LED 的正极

+   物理引脚 14 连接到 LED 的负极

现在我们已经连接了 LDR 传感器模块和 LED 到 RPi，让我们编写程序，通过从 LDR 传感器获取输入来控制 LED 的开关。

# 智能灯程序

在这个智能灯程序中，我们将首先从 LDR 传感器读取输入，并根据输入值来控制 LED 的开关。智能灯的程序描述如下。您可以从本书的 GitHub 存储库的`Chapter02`文件夹中下载`SmartLight.cpp`程序：

```cpp
#include <iostream>
#include <wiringPi.h>

int main(void)
{

wiringPiSetup();

pinMode(0,OUTPUT); 
pinMode(8,INPUT); 

for(;;)
{
int ldrstate = digitalRead(8); 
if(ldrstate == HIGH) 
{
digitalWrite(0,HIGH); 
}
else
{
digitalWrite(0,LOW); 
}
 }
return 0;
 }
```

上述程序的解释如下：

+   在`main`函数中，我们将 wiringPi 引脚 8 设置为输入引脚，将 wiringPi 引脚 0 设置为输出引脚。

+   接下来，在`for`循环中，使用`digitalRead(8)`函数，我们从 LDR 传感器的数字引脚(D0)读取传入的数字数据，并将其存储在`ldrstate`变量中。从 LDR 传感器，我们将接收 HIGH(1)数据或 LOW(0)数据。当没有光时，`ldrstate`变量将为 HIGH，当有光时，`ldrstate`变量将为 LOW。

+   接下来，我们将检查`ldrstate`变量内的数据是 HIGH 还是 LOW，使用`if...else`条件。

+   使用`if(ldrstate == HIGH)`，我们比较`ldrstate`变量内的数据是否为 HIGH。如果是 HIGH，我们使用`digitalWrite(0,HIGH)`来打开 LED。

+   如果`ldrstate`为 LOW，则`else`条件将执行，并且通过使用`digitalWrite(0,LOW)`，我们将关闭 LED。接下来，您可以单击“编译”按钮来编译代码，然后单击“构建”按钮来测试代码。

现在我们了解了 SmartLight 程序，我们将探讨**脉宽调制**（**PWM**）的概念，并使用一个名为 softPWM 的库来改变 LED 的亮度。

# 使用 softPWM 的脉宽调制

PWM 是一种强大的技术，可以用来控制传递给 LED 和电机等电子元件的电源。使用 PWM，我们可以执行控制 LED 亮度或减速电机速度等操作。在本节中，我们将首先了解 PWM 的工作原理，然后逐步编写一个简单的 PWM 程序来增加 LED 的亮度。

# PWM 的工作原理

在之前的`Blink.cpp`程序中，我们将数字信号从 RPi 应用到 LED。数字信号可以处于 HIGH 状态或 LOW 状态。在 HIGH 状态下，树莓派引脚产生 3.3V 的电压，在 LOW 状态下，引脚产生 0V 的电压。因此，在 3.3V 时，LED 以全亮度开启，在 0V 时，LED 关闭：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/6afde46d-da33-4d13-9f5b-5bb3dfaa1799.png)

为了降低 LED 的亮度，我们需要降低电压。为了降低电压，我们使用 PWM。在 PWM 中，一个完整的重复波形称为一个周期，完成一个周期所需的时间称为周期。在下图中，红线代表一个完整的周期。完成该周期所需的时间称为周期：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/ab19827a-aa9f-4400-afc5-4c4ae26df015.png)

信号保持高电平的时间称为占空比，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/abbf8698-365d-473e-9aff-ac95c0e6e752.png)

占空比以百分比格式表示，计算占空比的公式如下：

*占空比 =（高信号的时间持续时间/总时间）X 100*

在上图中，信号保持高电平 7 毫秒，单个周期的总时间为 10 毫秒：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/7584af2b-571e-46c8-9570-c94b1466b4d4.png)

占空比 = 70% 或 0.7

因此，占空比为 0.7 或 70%。接下来，为了找到新的电压值，我们需要将占空比乘以最大电压值 3.3V：

*Vout = 占空比 X Vmax*

*Vout = 0.7 X 3.3*

*Vout = 2.31V*

在 70%的占空比下，提供给 LED 的电压将为 2.31V，LED 的亮度将略有降低。

现在，如果我们将占空比降低到 40%，那么提供给 LED 的电压将为 1.32V，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/6c676d13-34c8-465f-8948-eba0df3491dc.png)

现在我们已经了解了 PWM 如何用于降低 RPi 数据引脚的电压，让我们来看看 softPWM 库，使用该库可以将数据引脚用作 PWM 引脚。

# softPWM 库

wiringPi 包含一个 softPWM 库，使用该库可以从 RPi 的任何数据引脚获得 PWM 信号输出。softPWM 库包含两个主要函数：`softPwmCreate`和`softPwmWrite`。这两个函数的工作原理如下：

```cpp
softPwmCreate(pin number, initial duty cycle value, max duty cycle value);
```

`softPwmCreate`函数用于创建 PWM 引脚。它包括三个主要参数：

+   `引脚编号`：引脚编号表示我们要设置为 PWM 引脚的 wiringPi 引脚。

+   `初始占空比值`：在初始占空比值中，我们必须提供作为占空比最小值的值。初始占空比值理想情况下设置为`0`。

+   `最大占空比值`：在最大占空比值中，我们必须提供占空比的最大值。此值必须设置为`100`：

```cpp
softPwmWrite(pin number, duty cycle value);
```

`softPwmWrite`函数用于在输出设备（例如 LED）上写入 PWM 数据。它包括两个参数：

+   `引脚编号`：引脚编号表示我们必须在其上写入 PWM 数据的 wiringPi 引脚。

+   `占空比值`：在此参数中，我们必须提供占空比值。占空比值必须在初始占空比值和最大占空比值之间，即在 0 到 100 的范围内。

现在我们了解了 softPWM 库中的两个函数，我们将编写一个简单的 C++程序，以使 LED 以不同的强度闪烁。

# 使用 softPWM 库使 LED 闪烁

对于使用 softPWM 的 LED 闪烁程序，您将需要一个 LED。在我的情况下，我已将 LED 的负极连接到 RPi 的物理引脚 6（地引脚），LED 的正极连接到 wiringPi 引脚 15。连接方式如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/6c4edb3d-6fda-4910-8058-9b013f70b0fd.png)

将 LED 连接到 RPi 后，是时候编写程序了。使用 softPWM 库闪烁 LED 的程序如下。此程序称为`Soft_PWM_Blink.cpp`，您可以从本书的 GitHub 存储库的`Chapter02`文件夹中下载此程序：

```cpp
#include <iostream>
#include <wiringPi.h>
#include <softPwm.h>
int main(void)
{
 wiringPiSetup();
 softPwmCreate (15, 0, 100) ;
 for(;;)
 {
 softPwmWrite (15, 25);
 delay(1000);
 softPwmWrite (15, 0);
 delay(1000);
 softPwmWrite (15, 50);
 delay(1000);
 softPwmWrite (15, 0);
 delay(1000);
 softPwmWrite (15, 100);
 delay(1000);
 softPwmWrite (15, 0);
 delay(1000);
 }
return 0;
 }
```

前面程序的解释如下：

+   在此程序中，我们首先导入了`wiringPi`和`iostream`库，以及`softPwm`库。

+   接下来，在`main`函数中，使用`softPwmCreate`函数，我们将 wiringPi 引脚 15 设置为 PWM 引脚。初始占空比值设置为`0`，最大占空比值设置为`100`。

+   之后，在`for`循环内，我们有六个`softPwmWrite`函数，通过使用这些函数，我们以不同的亮度级别打开 LED。

+   使用`softPwmWrite(15,25)`函数代码，LED 将以 25%的亮度保持高电平。由于延迟设置为 1,000，LED 将保持高电平 1 秒。

+   之后，由于占空比值设置为`0`，LED 将在`softPwmWrite(15 , 0)`函数代码中保持低电平 1 秒。

+   接下来，使用`softPwmWrite(15,50)`命令，LED 将以 50%的亮度保持高电平 1 秒。之后，我们再次将 LED 设置为低电平 1 秒。

+   最后，使用`softPwmWrite(15 , 100)`函数代码，LED 将以 100%的亮度保持高电平 1 秒。接下来，我们再次将 LED 关闭 1 秒。

+   编写代码后，您可以单击编译按钮来编译代码，然后点击构建按钮来测试代码。

这就是我们如何使用 softPWM 库来控制 LED 亮度的方法。

# 摘要

恭喜您成功地编写了您的第一个 C++程序并在树莓派上运行！在本章中，我们首先安装了`wiringPi`库，并了解了树莓派的 wiringPi 引脚连接。接下来，我们编写了一个简单的 C++程序来让 LED 闪烁。之后，我们了解了 LDR 传感器模块的工作原理，并根据 LDR 传感器模块的输入打开/关闭 LED。之后，我们了解了 PWM，并使用 softPWM 库编写了一个程序来改变 LED 的亮度。

在下一章中，我们将看看创建汽车机器人所需的不同部件。接下来，我们将了解直流电机和电机驱动器的工作原理，并学习如何创建汽车机器人。之后，我们将编写一个 C++程序来控制机器人朝不同方向移动。

# 问题

1.  树莓派上有多少个接地针脚？

1.  在黑暗环境中，LDR 传感器的电阻是高还是低？

1.  用于从传感器读取值的命令是什么？

1.  使 LED 闪烁六次的 for 循环命令是什么？

1.  假设最大电压为 5V，占空比为 20%时的输出电压是多少？


# 第二部分：树莓派机器人技术

在这一部分，你将首先开发一个小车机器人。之后，你将了解 L298N 电机驱动器的工作原理，以及如何使机器人朝不同方向移动。你还将连接超声波传感器和 LCD 模块到机器人，并最终创建一个避障机器人。

这一部分包括以下章节：

+   第三章，*编程机器人*

+   第四章，*构建避障机器人*

+   第五章，*使用笔记本电脑控制机器人*


# 第三章：编程机器人

在树莓派上编写了几个 C++程序并测试了它们的输出后，现在是时候创建我们自己的小车机器人，并使其向前、向后、向左和向右移动了。

在本章中，我们将涵盖以下主题：

+   选择一个好的机器人底盘

+   构建和连接机器人

+   使用 H 桥

+   移动机器人

# 技术要求

本章的主要硬件要求如下：

+   机器人底盘（机器人底盘中包含的零件在“构建和连接机器人”部分中有解释）

+   两个直流电机

+   L298N 电机驱动器

+   母对母连接线

本章的代码文件可以从[`github.com/PacktPublishing/Hands-On-Robotics-Programming-with-Cpp/tree/master/Chapter03`](https://github.com/PacktPublishing/Hands-On-Robotics-Programming-with-Cpp/tree/master/Chapter03)下载。

# 选择机器人底盘

在开始制作机器人之前，选择一个好的机器人底盘是最重要的活动之一。机器人的底盘就像人的骨架。我们的骨架由提供适当支撑我们器官的骨骼组成。同样，一个好的底盘将为电子元件提供适当的支撑并将它们固定在一起。

您可以从亚马逊和 eBay 等电子商务网站购买机器人底盘，也可以直接从处理机器人设备的供应商那里购买。在亚马逊上快速搜索“机器人底盘”将为您提供不同变体的机器人底盘列表。如果您以前没有制作过机器人，从所有这些选项中进行选择可能是一项艰巨的任务。在选择机器人底盘时，请记住以下要点：

+   确保机器人底盘包括两块板（一个**上板**和一个**下板**），这样您可以将电子元件放在两块板之间以及在**上板**上，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/cfe89fce-0ff6-4d8b-b737-49c80bfd99da.png)

+   选择一个仅支持两个直流电机的机器人底盘，就像前面的照片中所示的那样。也有支持四个直流电机的机器人底盘，但您需要额外的电机驱动器来驱动四轮机器人。

+   最后，选择一个具有直流电机（两个单位）、车轮（两个单位）和一个脚轮的机器人底盘作为完整套件的一部分，这样您就不必单独购买这些组件。

在前面的照片中显示的机器人底盘是我将用于创建我的小车机器人的底盘，因为它由两块板组成，并包括必要的组件（直流电机、车轮、脚轮、螺丝和间隔柱）作为完整套件的一部分。

# 构建和连接机器人

正确构建机器人是最重要的步骤之一。一个正确构建的机器人将能够平稳移动而不会受到任何阻碍。在构建机器人之前，让我们看一下您将需要的所有组件的完整清单。

构建机器人所需的零件包括以下内容：

+   机器人底盘，必须包括以下组件：

+   一个上板和一个下板

+   两个 BO 直流电机（BO 是一种通常为黄色的直流电机）

+   **两个**车轮

+   **一个**脚轮

+   间隔柱

+   连接不同部件的螺丝

+   **一个**螺丝刀

+   **一个**L298N 电机驱动器

+   **七到八**根连接线

+   **一个**电池夹

+   **一个**9V 电池

由于这些机器人底盘是由小规模公司制造的，并且没有国际上可用的标准机器人底盘，我用于此项目的机器人底盘将与您国家可用的机器人底盘不同。

在网上购买机器人底盘时，请检查产品的用户评论。

# 制作机器人

当包括上下板、直流电机、车轮、万向轮和间隔器在内的组件都包含在一个单一的机器人底盘套件中时，构建机器人变得更加容易。如果您单独购买这些组件，有可能某些组件不会合适，这会使整个机器人的组装变得不稳定。虽然我使用的底盘可能与您使用的不同，但大多数双轮机器人的构造都是相似的。

您可以在 GitHub 存储库的`Chapter03`文件夹中查看机器人的构建。

# 将电机驱动器连接到树莓派

构建完机器人后，是时候将树莓派连接到电机驱动器，这样我们就可以对机器人进行编程并使其朝不同方向移动。然而，在这之前，让我们先了解一下电机驱动器是什么。

# 什么是电机驱动器？

电机驱动器是一个包含电机驱动**集成电路**（**IC**）的分立板。电机驱动器基本上与电流放大器相同，其主要目的是接收低电流信号并转换为高电流信号以驱动电机。下图显示了 L298N 电机驱动器：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/f97d6a6a-f6b5-4eeb-ac6b-5b952d1d6d1f.png)

我们需要电机驱动器的主要原因是，诸如电机之类的组件不能直接连接到树莓派，因为它们无法从树莓派获得足够的电流，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/0dab7eee-2480-4551-af27-bb0485e58102.png)

这就是为什么我们首先将电机连接到电机驱动器并使用电池为电机供电的原因，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/b57fbee5-e0aa-4e20-8f39-8ef886a4f088.png)

# 接线连接

L298N 电机驱动器由**四个**输入引脚，**四个**输出插座（每个电机两个插座），以及**两个**电源插座组成。树莓派引脚连接到电机驱动器的输入引脚。直流电机线连接到电机驱动器的输出插座，电池夹连接到电源插座。L298N 电机驱动器的四个输入引脚标有**IN1**，**IN2**，**IN3**和**IN4**。输出插座标有**OUT1**，**OUT2**，**OUT3**和**OUT4**。下图显示了树莓派、电机驱动器和电机的接线连接：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/b6b850a0-b20f-4033-8f12-d600d374ddcb.png)

如前图所示，wiringPi 引脚编号**0**，**2**，**3**和**4**连接到电机驱动器的输入插座，如下所示：

+   wiringPi no **0**连接到**IN1**

+   wiringPi no **2**连接到**IN2**

+   wiringPi no **3**连接到**IN3**

+   wiringPi no **4**连接到**IN4**

+   左电机线连接到**OUT1**和**OUT2**插座

+   右电机线连接到**OUT3**和**OUT4**插座

+   电池夹的红线连接到电机驱动器的**VCC**插座，黑线连接到地面插座

+   树莓派的地针连接到地面插座

# 使用 H 桥

L298N 电机驱动 IC 可以同时控制两个电机。它由双 H 桥电路组成。这意味着它由两个电路组成，每个电路看起来像下图所示的电路，每个电机一个：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/253d6933-65c5-49e3-9370-24d2332850e3.png)

H 桥电路由四个开关**S1**，**S2**，![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/99b1cc6f-a64c-456d-9452-6789523e1500.png)和![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/9ba29df2-f0df-47a9-a012-29d0d2994cf4.png)组成。这些开关将根据我们提供给 L298N IC 的输入而打开和关闭。

现在，由于我们有两个电机，我们可以向 L298N IC 提供四种可能的输入组合，如下所示：

+   高 高（1, 1）

+   高 低（1, 0）

+   低 高（0, 1）

+   低 低（0, 0）

我们将向**S1**和**S2**开关提供高（1）和低（0）信号，如下所示：

1.  首先，当*S1 = 1*和*S2 =0*时，**S1**开关将关闭，**S2**开关将保持打开。![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/aaf36f47-248a-426f-98f0-57f389c218f8.png)，或![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/aa91d868-9da9-453b-bf33-8608d361d9d8.png)，将为 0，因此![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/0a247425-ed8b-4718-ad43-8de9b59c7ede.png)开关将打开。![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/4fd8f439-1baf-47f2-af3d-6da756d2f6a6.png)，或![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/20ad82af-0c82-4284-b06a-8881aff42648.png)，将为 1，因此![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/293035e2-e863-41f9-ba7d-7b1236aeced3.png)开关将关闭。现在，由于**S1**和![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/2ef338bc-c25f-454d-bff3-f52500f29f0d.png)开关都关闭，电流将从**Vcc**流向**S1**，然后流向电机，然后流向![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/4b1ac1d1-8a3c-4a87-baa4-1597a8b623df.png)，最后到达 GND。电机将以顺时针方向旋转，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/b9aa4e50-1048-49be-b7e7-d6d7c454e8dc.png)

1.  当*S1 = 0*和*S2 = 1*时，**S1**开关将打开，**S2**开关将关闭，![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/819ca277-57f6-4e56-8859-4663691b668f.png)将关闭，![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/143742d9-a94a-4702-ab83-19828e9f9dfa.png)将打开。现在，由于**S2**和![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/2c222bb1-19a6-4fd0-90aa-797b95905efc.png)开关关闭，电流将从**Vcc**流向**S2**，然后流向电机，然后流向![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/be4f60d6-19a9-45ff-a19c-b7fb5a1e10b8.png)，最后到达**GND**。电机将以逆时针方向旋转，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/9597e40e-f0ce-41c1-90ba-6b18ab7cb7fc.png)

1.  当*S1 = 0*和*S2 = 0*时，**S1**开关将打开，**S2**开关将打开，![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/c6711146-011a-41e7-9a51-e6e690ce74bb.png)开关将关闭，![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/c53bf9a1-e1bb-4e79-8307-9939e761c813.png)开关将关闭。现在，由于**S1**和**S2**开关都打开，电流无法流向电机。在这种情况下，电机将停止，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/0aeecc23-606e-4f6d-964a-e920e8ce8f3b.png)

1.  当*S1 = 1*和*S2 = 1*时，**S1**和**S2**开关将关闭，而![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/217b56eb-475a-4c2c-a8fd-f0e3a0a818bc.png)和![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/6db4eae3-7d64-4686-b7e0-dafd78eb640d.png)开关将打开。由于**S1**和**S2**开关都关闭，这将产生短路条件，电流将无法通过电机。在这种情况下，电机将停止，与之前的情况一样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/c6797ffb-ed39-4b81-b4f1-5b98de6c968f.png)

如前所述，由于 L298N IC 由两个 H 桥组成，当我们提供高低信号时，另一个 H 桥将发生相同的过程。第二个 H 桥将控制另一个电机。

# 移动机器人

现在我们已经了解了 H 桥电路，我们将编写一个名为`Forward.cpp`的程序来使我们的机器人向前移动。之后，我们将编写一个程序来使机器人向后、向左、向右移动，然后停止。您可以从 GitHub 存储库的`Chapter03`下载`Forward.cpp`程序。

移动机器人向前的程序如下：

```cpp
#include <stdio.h>
#include <wiringPi.h>

int main(void)
{
wiringPiSetup();
pinMode(0,OUTPUT); 
pinMode(2,OUTPUT); 
pinMode(3,OUTPUT);
pinMode(4,OUTPUT); 

 for(int i=0; i<1;i++)
 {
digitalWrite(0,HIGH); //PIN O & 2 will move the Left Motor
digitalWrite(2,LOW);
digitalWrite(3,HIGH); //PIN 3 & 4 will move the Right Motor
digitalWrite(4,LOW);
delay(3000);
 }
return 0;
 }
```

让我们看看这个程序是如何工作的：

1.  首先，我们将 wiringPi 引脚（编号 0、1、2 和 3）设置为输出引脚。

1.  接下来，使用以下两行，左电机向前移动：

```cpp
digitalWrite(0,HIGH);
digitalWrite(2,LOW);
```

1.  然后，接下来的两行使右电机向前移动：

```cpp
digitalWrite(3,HIGH);
digitalWrite(4,LOW);
```

1.  之后，`delay`命令意味着电机将向前移动三秒。由于我们目前在一个`for`循环中，电机将持续旋转。

1.  编译程序以检查是否有任何错误。

1.  接下来，将 9V 电池连接到电池夹子并上传程序。但在这之前，请确保将机器人的轮子抬起。这是因为当机器人开始移动时，您可能会得到以下三种输出中的一种：

+   两个电机都向前移动。如果您得到这个输出，这意味着您的机器人将在放在地面上后向前移动。

+   一个电机向前移动，另一个电机向后移动。如果您得到这种输出，请交换在电机驱动器上向后移动的电机的电线。例如，如果右电机向后移动，请将**M3-OUT**线插入**M4-OUT**插座，将**M4-OUT**线插入**M3-OUT**插座，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/8c8acc83-f31c-4b68-9b0c-fa414b0c2bfb.png)

+   +   两个电机都向后移动。在这种情况下，您的机器人将向后移动。如果您得到这种输出，请交换电机驱动器上左右两个电机的电线。要为左电机执行此操作，请将**M1-OUT**插座线连接到**M2-OUT**插座，将**M2-OUT**插座线连接到**M1-OUT**插座。对于右电机，将**M3-OUT**插座线连接到**M4-OUT**插座，将**M4-OUT**插座线连接到**M3-OUT**插座，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/10b7768c-4245-4205-8ff5-1934ac6113d4.png)

或者，您也可以交换 RPi 上的引脚以使机器人向前移动；将引脚 0 连接到左电机的引脚 2 的位置，将引脚 2 连接到引脚 0 的位置。同样，将引脚 3 连接到右电机的引脚 4 的位置，将引脚 4 连接到引脚 3 的位置。

1.  点击上传按钮并检查最终输出。由于这个程序在一个`for`循环中，电机将持续运转。在测试输出后，断开电池与电池夹的连接，以便通过电机驱动器关闭电机的电源，停止电机运动。

# 使机器人向后移动

要使机器人向后移动，我们只需要交换`HIGH`信号和`LOW`信号。以这种方式移动机器人的完整程序编写在`RobotMovement.cpp`文件中，可以从 GitHub 存储库的`Chapter03`中下载：

```cpp
digitalWrite(0,LOW);           //PIN O & 2 will move the Left Motor
digitalWrite(2,HIGH);
digitalWrite(3,LOW);          //PIN 3 & 4 will move the Right Motor
digitalWrite(4,HIGH);
delay(3000);
```

前两行将使左电机向后移动，而接下来的两行将使右电机向后移动。最后一行表示机器人将移动三秒钟。

# 停止机器人

要停止机器人移动，可以向引脚提供`HIGH`信号或`LOW`信号。在使机器人向后移动的代码中，添加以下命令以停止电机三秒钟：

```cpp
digitalWrite(0,HIGH);           //PIN O & 2 will STOP the Left Motor
digitalWrite(2,HIGH);
digitalWrite(3,HIGH);          //PIN 3 & 4 will STOP the Right Motor
digitalWrite(4,HIGH);
delay(3000);
```

# 不同类型的转弯

机器人可以进行两种类型的转弯：

+   轴向转动

+   径向转动

轴向和径向转弯的代码已添加到`RobotMovement.cpp`程序中。

# 轴向转动

在轴向转动中，机器人的一个车轮向后移动，另一个车轮向前移动。机器人可以在原地转弯而不移动。如果机器人在转弯时有空间限制，例如在迷宫中移动，通常会进行轴向转弯。机器人可以进行轴向左转或轴向右转。

# 轴向左转

在轴向左转中，机器人的左电机向后移动，右电机向前移动，因此机器人向左转，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/381f38c3-0558-46e5-b096-df159f458fe0.png)

如果您已经了解了 H 桥的工作原理，您可能能够猜出进行轴向转弯的代码。如果不是，代码如下：

```cpp
digitalWrite(0,LOW);
digitalWrite(2,HIGH);
digitalWrite(3,HIGH);
digitalWrite(4,LOW);
delay(500);
```

您需要稍微调整延迟值，以确保机器人向左正确转向。如果延迟值较高，机器人将转过 90°以上，而如果延迟值较低，机器人将转过 90°以下。

# 轴向右转

在轴向左转中，机器人的左电机向前移动，右电机向后移动，从而向右转，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/31e89ebe-ca7e-441b-8a4d-9589d7d49a64.png)

轴向右转的代码如下：

```cpp
digitalWrite(0,HIGH);
digitalWrite(2,LOW);
digitalWrite(3,LOW);
digitalWrite(4,HIGH);
delay(500);
```

# 径向转动

在径向转弯中，机器人的一个电机停止，另一个电机向前移动。停止的轮子作为圆的中心，移动的轮子作为圆周。电机之间的距离代表半径，这就是为什么这种转弯被称为径向转弯。机器人可以进行径向左转或径向右转。

# 径向左转

在径向左转中，左侧电机停止，右侧电机向前移动，因此机器人向左转，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/ae9e5b3a-dd2f-4095-9167-cf7ab80f28a8.png)

进行径向左转的代码如下：

```cpp
digitalWrite(0,HIGH);
digitalWrite(2,HIGH);
digitalWrite(3,HIGH);
digitalWrite(4,LOW);
delay(1000);
```

# 径向右转

在径向右转中，左侧电机向前移动，右侧电机停止，因此机器人向右转，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/8510530d-bf08-42af-89b8-8aa87e847364.png)

进行径向右转的代码如下：

```cpp
digitalWrite(0,HIGH);
digitalWrite(2,LOW);
digitalWrite(3,HIGH);
digitalWrite(4,HIGH);
delay(1000);
```

# 总结

在本章中，我们已经查看了选择机器人底盘的某些标准。之后，我们构建了我们的小车，将电机驱动器连接到树莓派，并了解了 H 桥电路的工作原理。最后，我们编写程序使机器人向前、向后、向左和向右移动。

在下一章中，在了解了本章中移动机器人的基本原理之后，我们将首先编写一个程序来使用超声波传感器测量距离。接下来，我们将使用这些距离值来避开障碍物，也就是说，如果机器人靠近墙壁，超声波传感器将感应到并命令机器人转弯，从而避开障碍物。

# 问题

1.  我们使用哪种电机驱动器来控制机器人？

1.  L298N 电机驱动 IC 包括哪个桥？

1.  将机器人向前移动的 C 程序是什么？

1.  *S1 = 0*（低）和*S2 = 1*（高），将使机器人向哪个方向移动？

1.  进行径向左转的代码是什么？

1.  轴向右转的代码是什么？


# 第四章：构建避障机器人

现在我们可以让机器人以多个方向移动指定的时间，让我们考虑如何从超声波传感器中读取数值，以创建一个可以避开障碍物的机器人。我们还将使用 LCD 显示器，并用它来打印距离数值。

在本章中，我们将涵盖以下主题：

+   使用超声波传感器

+   使用 LCD

+   创建一个避障机器人

# 技术要求

本章的主要硬件要求如下：

+   一个 HC-SR04 超声波传感器

+   一个 16x2 LCD 或带有 I2C LCD 模块的 16x2 LCD

+   一个面包板

+   一个 1KΩ的电阻

+   一个 2KΩ的电阻

+   12-13 根连接线

本章的代码文件可以从[`github.com/PacktPublishing/Hands-On-Robotics-Programming-with-Cpp/tree/master/Chapter04`](https://github.com/PacktPublishing/Hands-On-Robotics-Programming-with-Cpp/tree/master/Chapter04)下载。

# 使用超声波传感器

超声波传感器用于测量障碍物或物体之间的距离。超声波传感器由发射换能器和接收换能器组成。发射换能器（触发）发出**超声脉冲**（也称为**超声波**），与附近的障碍物碰撞并被接收换能器（回波）接收。传感器通过测量超声波发送和接收之间的时间差来确定目标之间的距离。下图说明了这个过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/8f46574f-956b-4437-8c0e-980e47cc5d17.png)

我们将用于此项目的超声波传感器称为**HC-SR04 超声波传感器**，这是最广泛使用的超声波传感器之一。它可以测量 0-180 厘米范围内的距离，分辨率约为 0.3 厘米。它的频率约为 40 千赫。HC-SR04 传感器由以下四个引脚组成：

+   VCC 引脚

+   一个地线引脚

+   一个触发引脚

+   一个回波引脚

触发引脚连接到发射换能器，发射脉冲，回波引脚连接到接收换能器，接收脉冲，如 HC-SR04 超声波传感器的照片所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/73133637-f38b-49e7-879f-c72f0e9be28f.png)

# 超声波传感器如何测量距离

现在我们已经了解了超声波传感器的基本工作原理，让我们思考一下超声波传感器如何测量距离：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/609372a0-6067-4556-84bd-da0cd9761349.png)

为了测量距离，超声波传感器会产生超声脉冲。为了产生这个超声脉冲，触发引脚被设置为**高**状态，持续**10 微秒**。这产生了一个以*声速*传播的*八周期声波*，在与物体碰撞后被回波引脚接收。当接收到这个*八周期声波*时，回波将变高，并且会保持高电平一段时间，这段时间与超声脉冲到达回波引脚的时间成比例。如果超声脉冲到达回波引脚花费了 20 微秒，回波引脚将保持高电平 20 微秒。

# 确定所花时间的算术方程

让我们首先看一下计算距离的算术方程，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/ed84f223-6087-425e-8553-a3016e6073f4.png)

如前图所示，假设传感器和物体之间的距离为 30 厘米。超声波传感器的传播速度为 340 米/秒，或 0.034 厘米/微秒。

为了计算时间，我们将使用以下方程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/bc7241ea-190d-418e-b0a0-cf8d89d70a93.png)

如果我们将时间移到左边，速度移到右边，我们得到以下方程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/1ddea5b8-fca7-44ee-937c-afe3c1aea1c7.png)

如果我们输入前面的数字，我们得到以下结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/5f5d9451-5fda-467f-8e7e-b60216141bd1.png)

这个方程的结果是所花时间为 882.35 微秒。

尽管时间值为 882.35μs，但回波引脚保持高电平的时间持续值实际上将是 882.35μs 的两倍，即 1764.70μs。这是因为超声波首先朝着物体传播，然后从物体反射回来后被回波接收。它传播的距离是相同的：首先从传感器到物体，然后从物体到传感器。如果时间值加倍，距离值也将加倍。我们可以修改上述方程来找到距离，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/9724eb93-b665-47db-8dd0-3e94527ccd68.png)![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/c226d115-3dd0-4781-8a83-ba2a81032fd6.png)![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/69e3b3b7-117e-46e2-a910-00d48243a1b2.png)

请记下这个方程，因为我们稍后将使用它来找到距离，一旦我们得到时间持续值。

# 将超声波传感器连接到树莓派

HC-SRO4 传感器由四个引脚组成：**VCC**、**GND**、**trigger**（**Trig**）和**echo**，因此 RPi 和超声波传感器的接线连接应如下所示：

+   将传感器的**VCC**引脚连接到引脚编号 4。

+   将传感器的**GND**引脚连接到引脚编号 9。

+   将传感器的**Trig**引脚连接到 wiringPi 引脚编号 12。

+   传感器的**echo**引脚通过电压分压器连接到 wiringPi 引脚编号 13。电压分压器电路中使用的两个电阻的电阻值分别为 1KΩ（**R1**）和 2KΩ（**R2**）。电压分压器电路用于将来自回波引脚（到 RPi）的输入 5V 信号降低到 3.3V。RPi 和 HC-SR04 的接线连接如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/4ac40083-049a-41fd-9ec6-39e8fa313c5f.png)

将传入电压转换为 3.3V 的公式如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/00e0025c-7d65-4bcc-90d3-77a0bbbe6d7b.png)

**Vin**是来自回波引脚的输入电压，**R1**是第一个电阻，**R2**是第二个电阻。**Vin**为 5V，**R1**为 1KΩ，**R2**为 2KΩ：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/357686da-8029-432c-8e80-b638b0fc8561.png)![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/8c54b198-1b8e-47e7-be56-a0fdbe0eba7b.png)

# HC-SR04 传感器程序

将 HC-SR04 传感器连接到树莓派后，让我们编写一个程序来测量超声波传感器到物体之间的距离。距离测量程序名为`DistanceMeasurement.cpp`，您可以从 GitHub 存储库的`Chapter04`文件夹中下载。

测量距离的代码如下：

```cpp
#include <stdio.h>
#include <iostream>
#include <wiringPi.h>

using namespace std;

#define trigger 12
#define echo 13

long startTime;
long stopTime;

int main()
{

 wiringPiSetup();

 pinMode(trigger,OUTPUT);
 pinMode(echo, INPUT); 

for(;;){
 digitalWrite(trigger,LOW);
 delay(500);

 digitalWrite(trigger,HIGH);
 delayMicroseconds(10);

 digitalWrite(trigger,LOW); 

 while(digitalRead(echo) == LOW);
 startTime = micros();

 while(digitalRead(echo) == HIGH);
 stopTime = micros(); 

long totalTime= stopTime - startTime; 
 float distance = (totalTime * 0.034)/2;

 cout << "Distance is: " << distance << " cm"<<endl;
 delay(2000);
}
return 0;
}
```

在上述代码中，我们声明了`wiringPi`、`stdio`和`iostream`库。之后，我们声明了`std`命名空间：

1.  之后，使用`#define trigger 12`和`#define echo 13`这两行，我们将 wiringPi 引脚编号 12 声明为触发引脚，将 wiringPi 引脚编号 13 声明为回波引脚。

1.  然后，我们声明了两个名为`startTime`和`stopTime`的变量，它们的数据类型为`Long`。`startTime`变量将记录触发引脚发送超声波脉冲的时间，`stopTime`变量将记录回波引脚接收超声波脉冲的时间。

1.  在主函数内，将触发引脚设置为`OUTPUT`，因为它将产生超声波脉冲。将回波引脚设置为`INPUT`，因为它将接收超声波脉冲。

1.  在一个`for`循环内，将触发引脚设置为 500 毫秒或 0.5 秒的`LOW`。

1.  为了产生超声波脉冲，将触发引脚设置为`HIGH`（`digitalWrite(trigger,HIGH)`）持续 10 微秒（`delayMicroseconds(10)`）。产生了 10 微秒的脉冲后，我们再次将触发引脚设置为`LOW`。

1.  接下来，我们有两个`while`循环，在这两个循环内，有两个`micros()`函数。`micros()`将以毫秒为单位返回当前时间值。第一个`while`循环（`digitalRead(echo) == LOW`）将记录脉冲开始时的时间，并将回波引脚为`LOW`的时间持续值存储在`startTime`变量中。

1.  当回波引脚接收到脉冲时，第二个`while`循环(`digitalRead(echo) == HIGH`*)*将执行。此`while`循环中的`micros()`函数将返回超声脉冲到达回波引脚所花费的时间值。这个时间值将被存储在`stopTime`变量中。

1.  接下来，为了找到总时间，我们将从`stopTime`中减去`startTime`，并将这个时间值存储在`totalTime`变量中。

1.  找到`totalTime`后，我们使用以下公式来计算距离：

*float distance = (totalTime x 0.034)/2*

1.  为了显示距离值，我们将使用`cout`语句。调用`delay(2000);`命令，以便每两秒打印一次距离值。

完成代码后，您可以编译和构建它以检查最终输出。您可以将一个物体放在传感器前面，物体距离传感器的距离将显示在控制台内。

在我的机器人底盘上，有一个额外的部件，我已经固定了超声波传感器。

# 使用 LCD

**液晶显示器**（LCD）是一种电子显示单元，通常用于计算机、电视、智能手机和相机。16x2 LCD 是一个基本的 LCD 模块，通常用于电子或 DIY 项目。顾名思义，16x2 LCD 由 16 列和 2 行组成。这意味着它有两行，每行最多可以显示 16 个字符。16x2 LCD 由从**VSS**到**K**标记的 16 个引脚组成，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/2131f109-6a0f-44de-85f9-b39236de6b2f.png)

LCD 上的每个引脚可以描述如下：

| **引脚号** | **名称** | **工作原理** |
| --- | --- | --- |
| 1  | VSS (GND) | 地线引脚。 |
| 2 | VCC | VCC 引脚需要 5V 电源才能打开 LCD 模块。 |
| 3 | Vo | 使用此引脚，我们可以调整 LCD 的对比度。我们可以将它连接到 GND 以获得最大对比度。如果您想要改变对比度，将其连接到电位器的数据引脚。 |
| 4 | RS (RegisterSelect) | LCD 由两个寄存器组成：命令寄存器和数据寄存器。RS 引脚用于在命令寄存器和数据寄存器之间切换。它被设置为高电平（1）以用于命令寄存器，低电平（0）用于数据寄存器。 |
| 5 | R/W (Read Write) | 将此引脚设置为低电平以写入寄存器，或将其设置为高电平以从寄存器中读取。 |
| 6 | E (Enable) | 此引脚使 LCD 的时钟启用，以便 LCD 可以执行指令。 |
| 7 | D0 | 尽管 LCD 有八个数据引脚，我们可以将其用于八位模式或四位模式。在八位模式中，所有八个数据引脚（D0-D7）都连接到 RPi 引脚。在四位模式中，只有四个引脚（D4-D7）连接到 RPi。在这种情况下，我们将使用四位模式的 LCD，以便占用更少的 wiringPi 引脚。 |
| 8 | D1 |
| 9 | D2 |
| 10 | D3 |
| 11 | D4 |
| 12 | D5 |
| 13 | D6 |
| 14 | D7 |
| 15 | A (Anode) | LCD 背光的+5V 引脚。 |
| 16 | K (Cathode) | LCD 背光的 GND 引脚。 |

由于 16x2 LCD 有 16 个引脚，正确连接所有引脚到树莓派有时可能会有问题。如果您犯了一个错误，例如将需要连接到 D0 的引脚连接到 D1，您可能会得到不正确的输出。

为了避免这种潜在的混淆，您可以选择购买一个 16x2 LCD 的**I2C LCD 适配器模块**。该模块将 LCD 的 16 个引脚作为输入，并提供 4 个引脚作为输出（VCC、GND、SDA、SCL）。这意味着您只需要连接 4 个引脚到树莓派，而不是 16 个引脚。

还有带有 I2C LCD 适配器焊接的 16x2 LCD，这可以节省一些时间。我用于这个项目的 16x2 LCD 已经焊接了 I2C LCD 适配器，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/d8ddc43e-28b8-4c72-983d-55bc3a128e5e.png)

在接下来的章节中，我们将了解接线连接以及如何编程普通 LCD 和带有 I2C LCD 适配器的 LCD。

我将**16x2 LCD 与 I2C LCD 适配器**称为**I2C LCD**，以避免复杂化。

# 将 16x2 LCD 连接到 Raspberry Pi

要将 16x2 LCD 连接到 Raspberry Pi，您将需要一个迷你面包板，因为有几个引脚需要连接到 VCC 和 GND。 RPi 和 16x2 LCD 的接线连接如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/bc131ce7-56ca-450b-8f64-8a9b22acb8cb.png)

首先，将 Raspberry Pi 的引脚号 2 或引脚号 4 连接到面包板的一个水平引脚，以便我们可以将该行用作 VCC 行。同样，将 Raspberry Pi 的一个地引脚连接到面包板的一个水平引脚，以便我们可以将该行用作地行。接下来，按照以下说明进行操作：

1.  将 VSS（GND）引脚连接到面包板的地行

1.  将 VCC 引脚连接到面包板的 VCC 行

1.  将 V0 引脚连接到面包板的地行

1.  将**寄存器选择**（RS）引脚连接到 RPi 的 wiringPi 引脚号 22

1.  将 R/W 引脚连接到面包板的地行，因为我们将关闭 LCD 的寄存器

1.  将使能引脚连接到 RPi 的 wiringPi 引脚号 26

1.  我们将使用四位模式的 LCD，因此 D0 到 D3 引脚将保持未连接状态

1.  引脚 D4 应连接到 RPi 的 wiringPi 引脚号 24

1.  引脚 D5 应连接到 RPi 的 wiringPi 引脚号 25

1.  引脚 D6 应连接到 RPi 的 wiringPi 引脚号 27

1.  引脚 D7 应连接到 RPi 的 wiringPi 引脚号 28

1.  将阳极引脚连接到面包板的 VCC 行

1.  将阴极引脚连接到面包板的地行

为了测试 LCD 程序，在“Build | Set Build Commands”中打开 Build 选项，并在 Compile and Build 选项中添加`-lwiringPiDev`命令，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/b116e0b7-8c82-44f2-9b5e-e8c153012deb.png)

将 16X2 LCD 连接到 RPi 后，让我们编程 LCD。

# 编程 LCD

我们将使用普通的 16x2 LCD 编写两个程序。在第一个程序中，我们将在 16x2 LCD 上打印一个值。在第二个程序中，我们将在 LCD 屏幕上打印超声波传感器值。第一个程序称为`LCDdisplay.cpp`，您可以从`Chapter04`的 GitHub 存储库中下载。

# LCD 程序

将 LCD 连接到 Raspberry Pi 后，让我们检查在 LCD 上打印值的程序，如下所示：

```cpp
#include <wiringPi.h> 
#include <lcd.h> 

#define RS 22 //Register Select
#define E 26 //Enable

#define D4 24 //Data pin 4
#define D5 25 //Data pin 5
#define D6 27 //Data pin 6
#define D7 28 //Data pin 7

int main()
{

int fd; 
wiringPiSetup(); 
fd= lcdInit (2, 16, 4, RS, E, D4, D5, D6, D7, 0, 0, 0, 0); 
lcdPuts(fd, "LCD OUTPUT"); 

}
```

以下是前面程序的详细信息：

1.  首先，我们调用`LCD.h`库。`LCD.h`库包含了我们可以用来打印、定位和移动文本以及清除 LCD 屏幕的所有重要函数。

1.  接下来，我们定义引脚号 RS、E、D4、D5、D6 和 D7。

1.  在`lcdInit`函数内部，第一个数字`2`代表 LCD 中的行数，而数字`16`代表列数。数字`4`表示我们正在使用四位模式的 LCD。接下来是 RS 和 E 引脚，最后是四个数据引脚。由于我们没有将 D0、D1、D2 和 D3 数据引脚连接到 RPi，因此在末尾有四个零。

1.  `lcdPuts`用于在 LCD 上打印数据。它有两个输入参数：`fd`变量和需要显示的文本值。

1.  完成此代码后，您可以编译和构建代码以测试最终输出。

1.  在输出中，您会注意到文本输出将从第一列开始，而不是从第零列开始。

1.  为了将文本定位在极左侧，或列`0`，行`0`，我们需要使用`lcdPosition()`函数。`lcdPosition(fd,列位置,行位置)`函数由三个参数组成，并且应该在`lcdPuts`函数之前写入，如下所示：

```cpp
fd= lcdInit (2, 16, 4, RS, E, D4, D5, D6, D7, 0, 0, 0, 0);
lcdPosition(fd, 0, 0); 
lcdPuts(fd, "LCD OUTPUT");
```

如果文本未定位在列 0 和行 0，请重新启动 RPi 并再次测试代码。

# LCD 和超声波传感器程序

在 LCD 上打印简单的文本值后，让我们看看如何在 LCD 屏幕上查看超声波距离值。HC-SR04 超声波传感器、16x2 LCD 和 RPi 的接线连接如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/50d44944-2bea-4121-b45f-bb6aeec24483.png)

LCD 连接到 RPi 保持不变。超声波触发引脚连接到 wiringPi 引脚 12 号，回波引脚连接到 wiringPi 引脚 13 号。现在让我们看看程序。该程序称为`LCDdm.cpp`（**dm**代表**距离测量**），您可以从`Chapter04`的 GitHub 存储库中下载。`LCDdm.cpp`程序是`LCDdisplay.cpp`和`DistanceMeasurement.cpp`程序的组合：

```cpp
int main()
{
...
for(;;)
{
...
cout << "Distance is: " << distance << " cm"<<endl;
lcdPosition(fd, 0, 0);           //position the cursor on column 0, row 0
lcdPuts(fd, "Distance: ");      //this code will print Distance text
lcdPosition(fd, 0, 1);          //position the cursor on column 0, row 1
lcdPrintf(fd, distance);        // print the distance value
lcdPuts(fd, " cm");
delay(2000);
clear();                     
}
return 0
}
```

在上述代码中，找到距离值后，我们使用`lcdPosition(fd, 0, 0);`命令将光标定位在第零行，第零列。接下来，使用`lcdPuts(fd, "Distance: ")`代码，我们显示距离文本。然后，我们将光标定位在第一行的第零列。最后，使用`lcdPrintf(fd, distance);`命令打印距离值。由于我们将延迟设置为两秒，因此每两秒将打印一次距离值。然后它将被清除（`clear()`）并替换为新值。

# I2C 协议是什么？

I2C 协议用于许多电子设备。我们用它来连接一个主设备到多个从设备，或者多个主设备到多个从设备。I2C 协议的主要优势在于主设备只需要两个引脚与多个从设备通信。

在 I2C 总线中，所有设备都并行连接到相同的双线总线。我们可以使用 7 位寻址连接总共 128 个设备，使用 10 位寻址连接总共 1,024 个设备，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/cb12dc27-aadc-4936-a5a2-5e1816b59d8f.png)

使用 I2C 协议连接的每个设备都有一个唯一的 ID，这使得可以与多个设备通信。I2C 协议中的两个主要引脚是**串行数据**（SDA）引脚和**串行时钟**（SCA）引脚：

+   **SDA**：SDA 线用于传输数据。

+   **SCL**：SCL 由主设备生成。它是一个时钟信号，用于同步连接在 I2C 中的设备之间的数据传输。

现在我们已经了解了 I2C 协议的基础知识，让我们看看如何连接 I2C LCD 和树莓派。

# 连接 I2C LCD 和树莓派

在树莓派上，物理引脚 3 是 SDA 引脚，而物理引脚 5 是 SCA 引脚，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/1a26ae87-880f-47ed-bd0d-4202a77002d3.png)

以下是连接 LCD 与 RPi 的详细信息：

1.  将树莓派的 3 号引脚连接到 LCD 的 SDA 引脚

1.  将树莓派的 5 号引脚连接到 LCD 的 SCA 引脚

1.  将 LCD 的 GND 引脚连接到 RPi 的 GND 引脚

1.  将 LCD 的 VCC 引脚连接到树莓派的 2 号引脚或 4 号引脚

# 使用 I2C LCD 模块编程 LCD

在编写程序之前，我们首先需要从树莓派配置中启用 I2C 协议。为此，请打开命令窗口并输入以下命令：

```cpp
sudo raspi-config
```

在配置中，打开接口选项，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/3f02ab85-9905-400a-a784-589eb3e4ec2c.png)

接下来，打开 I2C 选项，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/2d20a283-291f-4fef-b936-bedda3ee1613.png)

选择“是”选项并按*Enter*键启用 I2C，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/b31f95ca-9171-4eae-9d40-2e3cfca6d1a7.png)

启用 I2C 后，选择“确定”选项并退出配置，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/9d1c032c-dd09-46ef-b8b1-3299651b5b8c.png)

在树莓派内部启用 I2C 协议后，让我们编写程序将值打印到 LCD 上。该程序称为`I2CLCD.cpp`，您可以从`Chapter04`的 GitHub 存储库中下载。

由于这个 LCD 连接了一个 I2C 模块，我们之前用过的`LCD.h`库在这个程序中将无法使用。相反，我创建了五个主要函数，用于初始化 LCD，打印消息和清除 LCD 屏幕，如下所示：

+   `init_lcd()`: 该函数将初始化（设置）LCD

+   `printmessage()`: 该函数用于在 LCD 上打印字符串

+   `printInt()`: 该函数用于显示整数值

+   `printfloat()`: 该函数用于显示浮点值

+   `clear()`: 该函数将清除 LCD 屏幕

```cpp
#include <wiringPiI2C.h>
#include <wiringPi.h>
#include <stdlib.h>
#include <stdio.h>

#define I2C_DEVICE_ADDRESS 0x27 
#define firstrow 0x80 // 1st line
#define secondrow 0xC0 // 2nd line
int lcdaddr;
```

1.  我们通过声明`wiringPiI2C.h`库来启动程序。接下来，我们有`wiringPi`库和另外两个标准 C 库。

1.  然后，使用`#define I2C_DEVICE_ADDRESS 0x27`命令，我们定义了 I2C 设备地址，即`0x27`。

1.  `0x80`命令代表第一行：第零行，第零列。使用`#define firstrow 0x80`命令，我们初始化 LCD 的第一行。

1.  同样，`0xC0`代表 LCD 的第二行：第一行，第零列。使用`#define secondrow 0xC0`命令，我们初始化 LCD 的第二行。

1.  接下来，在`lcdaddr`变量内，我们将存储 I2C LCD 的地址，如下所示：

```cpp
int main() {

 wiringPiSetup();

 lcdaddr = wiringPiI2CSetup(I2C_DEVICE_ADDRESS);

 init_lcd(); // initializing OR setting up the LCD 
 for(;;) {

 moveCursor(firstrow);
 printmessage("LCD OUTPUT");
 moveCursor(secondrow);
 printmessage("USING I2C");
 delay(2000);
 clear();

 moveCursor(firstrow);
 printmessage("Integer: ");
 int iNumber = 314;
 printInt(iNumber);

 moveCursor(secondrow);
 printmessage("Float: ");
 float fNumber= 3.14;
 printFloat(fNumber);
 delay(2000);
 clear();
 }
 return 0;
}
```

1.  在`main()`函数内，我们将设备地址存储在`lcdaddr`变量中。

1.  然后，我们使用`init_lcd();`命令初始化 LCD。

1.  接下来，在`for`循环中，我们使用`moveCursor(firstrow);`命令将光标移动到第一行。

1.  现在，由于光标在第一行，所以在`printmessage("LCD OUTPUT"`代码中的`LCD OUTPUT`文本将被打印在第一行。

1.  然后，使用`moveCursor(secondrow)`命令将光标移动到第二行。在该行上打印`USING I2C`文本。

1.  第一行和第二行的文本将在两秒内可见，之后 LCD 屏幕将被`clear()`命令清除。

1.  之后，使用接下来的四行，在第一行上打印一个整数`314`。`printInt(iNumber)`函数用于显示整数值。

1.  同样，`printFloat(iFloat)`函数用于显示浮点值。在接下来的四行中，将在第二行上打印`float 3.14`。

1.  之后，我们再次清除 LCD。

这就是我们如何在 I2C LCD 内显示字符串，数字和浮点值。

# I2C LCD 和超声波传感器程序

要在 I2C LCD 内读取超声波传感器值，请将超声波传感器和 I2C LCD 连接到 RPi。您可以从`Chapter04`的 GitHub 存储库中下载名为`I2CLCDdm.cpp`的完整程序。I2C LCD，超声波传感器和 RPi 的接线连接如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/870f16ba-4b07-4833-824d-4930cd0e0704.png)

这个`I2CLCDdm.cpp`程序基本上是`DistanceMeasurement.cpp`和`I2CLCD.cpp`程序的组合。在这个程序中，在`cout << "Distance: "<<distance << "cm" << endl`行下面声明了与超声波传感器和 I2C LCD 相关的所有必要库和变量，我们需要添加以下代码：

```cpp
 moveCursor(firstrow);
 printmessage("DISTANCE");
 moveCursor(secondrow);
 printFloat(distance);
 printmessage(" cm");
 delay(2000);
 clear();
```

使用`printmessage("DISTANCE")`命令将在第一行上打印文本`DISTANCE`。之后，在第二行上，使用`printFloat(distance)`命令将打印距离值，因为代码仍在第二行上。使用`printmessage(" cm")`命令，`cm`文本将在距离值旁边打印出来。

控制台内的距离值和 I2C LCD 将在两秒内可见。接下来，使用`clear()`函数，旧的距离值将被清除并替换为新值。然而，在控制台中，新值将显示在下一行。

# 构建避障机器人

在这种情况下，我们的机器人将在给定空间内自由移动，但一旦靠近物体或障碍物，它将转向或向后移动，从而避开障碍物。在这种项目中，我们通常使用超声波传感器。当机器人移动时，超声波传感器不断测量它与物体的距离。当传感器检测到距离值非常低，并且机器人可能与附近物体碰撞时，它将命令机器人改变方向，从而避开障碍物。

要创建一个避障机器人，您首先需要将超声波传感器安装在机器人上。在我的机器人套件中，已经有一个附件可以让我将超声波传感器安装在机器人上。这个附件如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/eb5a56d9-8248-406f-b183-c67105b56321.png)

在机器人上安装超声波传感器后，最终装配如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/hsn-rbt-prog-cpp/img/3314bcae-f4eb-4046-b225-99fc138a42a4.png)

# 接线连接

超声波传感器的触发引脚连接到 wiringPi 引脚号 12，而回波引脚通过电压分压电路连接到 wiringPi 引脚号 13。超声波传感器的 VCC 引脚连接到 RPi 的物理引脚 2（5V），超声波传感器的地线引脚连接到 RPi 的物理引脚 6。其余连接如下：

+   **WiringPi 引脚 0**连接到 L298N 电机驱动器的**IN1 引脚**。

+   **WiringPi 引脚 2**连接到 L298N 电机驱动器的**IN2 引脚**。

+   **WiringPi 引脚 3**连接到 L298N 电机驱动器的**IN3 引脚**。

+   **WiringPi 引脚 4**连接到 L298N 电机驱动器的**IN4 引脚**。

+   **电机驱动器的地线引脚**连接到 RPi 的**物理引脚 3**。

+   我正在使用 I2C LCD，因此 I2C LCD 的**SDA 引脚**连接到**RPi 的物理引脚 3**，**SCL 引脚**连接到**物理引脚 5**。**I2C LCD 的地线引脚**连接到**物理引脚 9**，**I2C LCD 的 VCC 引脚**连接到 RPi 的**物理引脚 4**。

将 LCD 显示器连接到机器人完全取决于您。如果机器人上有足够的空间可以放置 LCD，那就加上去。如果没有，这不是必需的。

# 编程避障机器人

在这个程序中，我们将首先使用超声波传感器找出附近物体的距离。接下来，我们将创建一个`if`条件来监测距离数值。如果距离低于某个数值，我们将命令机器人转向。否则，机器人将继续向前移动。您可以从 GitHub 存储库的`Chapter04`中下载名为`ObstacleAvoiderRobot.cpp`的完整代码：

```cpp
int main()
{
...
for(;;)
{
...
if(distance < 7)
{
digitalWrite(0,LOW);
digitalWrite(2,HIGH);
digitalWrite(3,HIGH);
digitalWrite(4,LOW);
delay(500);
moveCursor(firstrow);
printmessage("Obstacle Status");
moveCursor(secondrow);
printmessage("Obstacle detected");
clear();
}
else
{
digitalWrite(0,HIGH);
digitalWrite(2,LOW);
digitalWrite(3,HIGH);
digitalWrite(4,LOW);
moveCursor(firstrow);
printmessage("Obstacle Status");
moveCursor(secondrow);
printmessage("No Obstacle");
clear();
}
}
return 0;
}
```

在这段代码中，如果**距离**大于**7 厘米**，机器人将继续向前移动。只要障碍物不存在，LCD 将在第二行显示`No Obstacle`的消息。如果检测到障碍物，机器人将首先进行 0.5 秒的径向左转，I2C LCD 将在第二行显示`Obstacle detected`的文本。您可以根据电机速度增加或减少延迟值。

# 总结

在本章中，我们看了超声波传感器的工作原理，并编写了一个程序来测量距离值。接下来，我们编程 16x2 LCD，并使用它读取超声波距离值。我们还研究了 I2C LCD，它将 16 个 LCD 引脚作为输入，并提供四个引脚作为输出，从而简化了接线连接。最后，我们将超声波传感器安装在我们的机器人上，创建了我们的避障机器人。这个机器人在附近没有障碍物时自由移动，如果靠近障碍物，它将通过转向来避开。

在下一章中，我们将创建两种不同类型的 PC 控制机器人。在第一个 PC 控制机器人中，我们将使用一个叫做**ncurses**的库，并使用键盘作为输入。在第二个 PC 控制机器人中，我们将使用 QT 创建 UI 按钮，然后使用它们来移动机器人。

# 问题

1.  超声波传感器发送什么类型的脉冲？

1.  LCD 代表什么？

1.  HC-SR04 超声波传感器可以测量到多远的距离？

1.  `lcdPosition(fd, 4,1)`命令会从哪一行和哪一列开始打印文本？

1.  LCD 的阳极引脚（引脚 15）和阴极引脚（引脚 16）在 LCD 上有什么功能？
