# UDOO 入门手册（一）

> 原文：[`zh.annas-archive.org/md5/4AF381CD21F1B858B50BF52774AC99BB`](https://zh.annas-archive.org/md5/4AF381CD21F1B858B50BF52774AC99BB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

自 2000 年代初以来，由于工程和微电子方面的许多进步，全球对硬件制造的重新兴趣被点燃，这促进了新型低成本制造工具的激增。各年龄段的人们，甚至儿童，开始将他们的坏设备、旧玩具和所有未使用的硬件零件转变为令人惊叹的新物体。这种非传统的设计和创造新事物的做法，以表达创造力的新方式为特征，这是形成创客文化的关键因素。

这就是创客革命，一个彻底改变了我们世界的运动。开源项目提供了所有必要的工具，释放了创造力，让我们能够构建事物，无需深厚的编程和工程知识，也无需一套昂贵的组件。事实上，创客革命取得的最重要成就之一，就是将原型制造从大小工厂转移到我们的家中。

2012 年 2 月，另一个名为 UDOO 的开源项目启动了一个集成了 Linux 和 Android 操作系统的原型开发板，目标是结合 Arduino 和 Raspberry Pi 的优势于一块单板。在项目工作一年后的 2013 年 4 月，UDOO 开发板加入了 Kickstarter 众筹平台，创客社区的反馈非常积极——项目在短短 2 天内就完成了资金筹集。

全世界的创客们都如此喜欢这个项目，以至于他们决定贡献自己的力量，不仅通过 Kickstarter 的承诺支持，还在电路设计阶段提供了有用的想法和建议。创客社区提供的帮助促成了一个强大的原型开发板，让我们能够构建一直想要的互动和创意项目。

本书将教你如何使用 UDOO 开发板作为快速原型工具，来构建你的第一个硬件项目。从涉及基础电子元件的简单应用开始，你将通过不同的项目学习构建电子电路，这些项目提供了由 Android 操作系统支持的增强互动。

# 本书内容涵盖

第一章 *启动引擎* 将引导你完成 UDOO 平台的设置和所需开发环境的配置。首先介绍开发板，展示其独特性和与其他板不同的功能；然后指导你安装 Android 操作系统。最后一部分，解释如何为 Arduino 和 Android 配置开发环境，以启动第一个 Hello World Android 应用程序。

第二章，*了解你的工具*，讲述了 Android 应用如何控制连接的设备。首先介绍一些 Arduino 板载特性，然后解释如何创建第一个能够与集成 Arduino 设备通信的 Android 应用。接着展示如何使用面包板创建一个功能完整的电路，以便快速原型制作。

第三章，*测试你的物理应用*，解释了物理应用测试背后的主要概念。第一部分展示了如何构建一个可以从软件应用中测试的电路。然后展示了如何实现一个诊断模式，以测试连接的电路是否正常工作。

第四章，*使用传感器监听环境*，首先解释了传感器的工作原理以及如何使用它们使原型具有上下文感知能力。然后展示了如何构建一个心跳监测器，编写 Arduino 草图读取传感器数据，以及一个 Android 应用来可视化计算结果。

第五章，*管理物理组件的交互*，讲述了如何管理用户交互。首先解释了一些可以用来让外部世界与系统交互的组件。然后展示了如何构建一个带有物理控制器的网络收音机，以管理原型音量和更改当前电台。在最后一部分，使用 Android API 播放网络广播流。

第六章，*为家庭自动化构建 Chronotherm*，解释了如何使用 UDOOUDOO 的一些功能进行家庭自动化。展示了使用检测环境温度的电路创建 Chronotherm，以及一个 Android 用户界面来可视化传感器数据，并改变每个时间间隔所需的温度。

第七章，*使用 Android API 进行人机交互*，为前一章的应用增加了更多功能，扩展了设置管理，使用语音识别和语音合成存储不同的预设，以管理用户的交互。

第八章，*添加网络功能*，再次扩展了 Chronotherm 应用，具备通过 RESTful 网络服务收集天气预报数据的能力。在最后一部分，展示了如何使用收集到的数据为 Chronotherm 提供更多功能。

*第九章*，*使用 MQTT 监控您的设备*，介绍了物联网的主要概念和 MQTT 协议，用于物理设备之间的数据交换。然后展示了如何设置一个基于云的 MQTT 代理，能够接收和分发 Chronotherm 温度更新。最后一部分展示了如何编写一个独立的 Android 应用程序，以接收来自 Chronotherm 发送的数据。

这是一个附录章节，可以从以下链接下载：[`www.packtpub.com/sites/default/files/downloads/1942OS_Chapter_9.pdf`](https://www.packtpub.com/sites/default/files/downloads/1942OS_Chapter_9.pdf)

# 阅读本书所需的条件

为了运行本书中演示的代码，您需要配置开发环境，包括 Android 和 Arduino 的环境，以及安装了 Android 操作系统的双核或四核 UDOO 板，具体配置请参考第一章，*启动引擎*中的*下载和安装 Android*和*设置开发环境*部分。

# 本书适合的读者

本书适合想要将技能应用于构建真实环境中能与 Android 应用交互的设备的 Android 开发者。开始构建基于 Android 的真实设备需要具备基本的 Android 编程知识。不需要预先了解原型平台或电路构建知识。

本书将教您通过一些在原型构建期间经常使用的电子组件来构建真实世界设备的基础知识，以及如何将它们与 Android 用户界面集成。

# 约定

在本书中，您会发现多种文本样式，用于区分不同类型的信息。以下是一些样式示例及其含义的解释。

文本中的代码字如下显示："The `play()` 方法设置当前活动电台的流媒体 URL 并开始异步准备。"

代码块如下设置：

```kt
public class HelloWorld extends Activity {
  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_hello_world);
  }
}
```

当我们希望您注意代码块中的特定部分时，相关的行或项目会以粗体显示：

```kt
public class HelloWorld extends Activity {
  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_hello_world);
  }
}
```

**新术语**和**重要词汇**以粗体显示。您在屏幕上看到的词，例如菜单或对话框中的，会在文本中这样显示："为了这个 HelloWorld 应用程序的目的，选择一个**空白活动**并点击**下一步**。"

### 注意

警告或重要注意事项会以这样的方框显示。

### 提示

技巧和诀窍会这样显示。

# 读者反馈

我们始终欢迎读者的反馈。请告诉我们您对这本书的看法——您喜欢或可能不喜欢的内容。读者的反馈对我们开发能让您获得最大收益的标题非常重要。

要向我们发送一般反馈，只需发送电子邮件至`<feedback@packtpub.com>`，并在邮件的主题中提及书名。

如果您在某个主题上有专业知识，并且有兴趣撰写或参与书籍编写，请查看我们在[www.packtpub.com/authors](http://www.packtpub.com/authors)上的作者指南。

# 客户支持

既然您已经自豪地拥有了一本 Packt 图书，我们有一系列的事情可以帮助您充分利用您的购买。

## 下载示例代码

您可以从您的账户中下载您已购买的 Packt 图书的示例代码文件，访问地址为[`www.packtpub.com`](http://www.packtpub.com)。如果您在别处购买了这本书，可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)进行注册，我们会将文件直接通过电子邮件发送给您。

## 勘误

尽管我们已经尽力确保内容的准确性，但错误仍然会发生。如果您在我们的书中发现错误——可能是文本或代码中的错误——我们非常感激您能向我们报告。这样做，您可以避免其他读者感到沮丧，并帮助我们改进本书的后续版本。如果您发现任何勘误，请通过访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书籍，点击**勘误提交表单**链接，并输入您的勘误详情。一旦您的勘误被验证，您的提交将被接受，勘误将在我们网站的相应位置上传，或添加到现有勘误列表中。任何现有的勘误可以通过从[`www.packtpub.com/support`](http://www.packtpub.com/support)选择您的标题来查看。

## 盗版

互联网上版权资料的盗版是所有媒体面临的持续问题。在 Packt，我们非常重视保护我们的版权和许可。如果您在互联网上以任何形式遇到我们作品非法副本，请立即提供位置地址或网站名称，以便我们可以寻求补救措施。

如果您发现疑似盗版材料，请通过`<copyright@packtpub.com>`与我们联系，并提供链接。

我们感谢您在保护我们作者权益方面所提供的帮助，以及我们能够向您提供有价值内容的能力。

## 问题

如果您在书的任何方面遇到问题，可以联系`<questions@packtpub.com>`，我们会尽力解决。


# 第一章：启动引擎

任何想法都应该从原型开始。不管是游戏、网络或移动应用程序，还是一般的软件组件，都无关紧要。每次我们想要向最终用户交付某些东西时，首先必须创建一个原型。这是最重要的一步，因为这时我们开始面临最初的困难，并且可能会改变我们项目的某些重要方面。

如果我们正在编写一个软件组件，第一个原型并不会太昂贵，因为我们需要的只是时间和热情。然而，当项目包含一些硬件部分时，这可能不适用，因为购买所有必需的组件可能过于昂贵。这一说法直到程序员、工程师和开源爱好者开始发布如**Arduino**之类的项目时才不再正确。

快速原型开发板使人们能够使用便宜或回收的旧组件来实现项目，再加上**自己动手**（**DIY**）的理念，使得一个遍布全球的巨大社区得以创建。这正是 UDOO 主板在创客社区中发挥重要作用的地方：硬件原型生态系统与传统编写软件应用程序的方式相结合，为交互式项目的创建提供了强大的组合。

在本章中，我们将更详细地探讨 UDOO 主板，重点关注开始时需要了解的重要元素。特别是，我们将涵盖以下内容：

+   探索 UDOO 平台及其主要特性

+   使用 Android 操作系统设置主板

+   为 Arduino 和 Android 配置开发环境

+   引导一个简单的 Android 应用程序

+   部署一个 Android 应用程序

# 介绍 UDOO 平台

UDOO 主板旨在为我们提供极大的灵活性，包括工具、编程语言以及构建第一个原型的环境。该主板的主要目标是参与物联网时代，这就是为什么内置 Atmel SAM3X8E ARM Cortex-M3 处理器成为其第一个构建块的原因。

这个处理器与 Arduino Due 主板所使用的相同，并且完全符合 Arduino 引脚布局。这一特性的结果是，该主板兼容所有 Arduino Due 屏蔽板以及大多数 Arduino Uno 屏蔽板，因此开发者可以转换和重用他们的旧程序和电路。

### 注意

UDOO 的 I/O 引脚是 3.3V 兼容的。例如，如果你使用的是一个 5V 供电的传感器，但其信号输出到 UDOO 引脚时为 3.3V，那么是可以的。另一方面，如果传感器以 5V 的信号输出到 UDOO，则会损坏你的主板。每次使用屏蔽或传感器时，请注意提供给 UDOO 引脚的输出电压。这一预防措施对于传统的 Arduino Due 主板同样适用。

第二个核心组件是强大的 Freescale i.MX 6 ARM Cortex-A9 处理器，有双核和四核版本。官方支持的操作系统是*UDOObuntu*，这是一个基于*Lubuntu 12.04 LTS armHF*的操作系统，出厂时预装了许多工具，可以快速上手。实际上，在第一次启动后，您就可以使用完全配置好的开发环境，直接在开发板上对板载 Arduino 进行编程。

尽管如此，使 UDOO 与其他开发板真正不同的是**对 Android 的支持**。凭借流畅的运行能力，这个操作系统对于新手或经验丰富的 Android 开发人员来说是一个巨大的机会，因为他们可以创建一种由 Android 用户界面、其强大的设计模式，甚至其他开发者的应用程序提供支持的新型真实世界应用程序。

### 注意

开发人员可以选择使用 Linux 操作系统编写他们的真实应用程序。在这种情况下，他们可以使用许多知名的编程语言编写 Web 服务或桌面应用程序，如 Python、Javascript（Node.js）、Php 和 Java。然而，我们将重点放在 Android 下的应用程序开发上。

最后一个核心组件与所有 I/O 组件相关。UDOO 可以配备内部 Wi-Fi 和千兆以太网，它们都可以被 Linux 和 Android 识别。它还提供**HDMI**（**高清晰度多媒体接口**）输出连接，并配有集成的**晶体管-晶体管逻辑**（**TTL**）到**低电压差分信号**（**LVDS**）扩展槽，以便开发人员可以连接外部 LVDS 触摸屏。

### 注意

在本书的学习过程中，我们假设您将通过 HDMI 线将 UDOO 连接到外部显示器。然而，如果您拥有一个外部 LVDS 面板，可以在本章的*我们的第一次运行*部分之前进行连接。为了让 Android 使用外部面板，您应该按照官方网站上的步骤进行操作，具体步骤可以在[`www.udoo.org/faq-items/how-do-i-set-up-my-lvds/`](http://www.udoo.org/faq-items/how-do-i-set-up-my-lvds/)找到。

另一个官方支持的重要组件是摄像头模块，它易于插入开发板，并可用于需要计算机视觉或图像分析的项目。最后一个集成组件是音频卡，通过外部麦克风可以实现完全功能的音频播放和录制。

这些组件的结合，加上互联网接入和许多 Android API，使我们有机会构建真实世界的应用程序，这些程序能够监听环境并与设备进行交互，一块可以参与*物联网*的板子。

# 下载和安装 Android

我们已经了解了一些可能用于开始构建惊人项目的 UDOO 组件列表。但是，在我们继续之前，我们需要配置我们的开发板以运行 Android 操作系统，还需要配置我们的开发环境，这样我们就可以开始编写并部署我们的第一个应用程序。

### 注意

在本书中构建的所有原型都是基于 Android KitKat 4.4.2，这是本书编写时支持的最新版本。在本书的学习过程中，你将构建许多项目，这些项目使用了**Android 支持库**以确保与 UDOO 开发板将支持的较新 Android 版本兼容。

UDOO 开发板没有内置存储或内置启动程序，因为它依赖于外部存储，即 microSD 卡，你可以在其中安装引导加载程序和兼容的操作系统。创建可启动 microSD 卡的最简单方法是下载并复制预编译的镜像，尽管也可以使用发布的二进制文件和内核源代码创建干净的操作系统。

[`www.udoo.org/downloads/`](http://www.udoo.org/downloads/)指向 UDOO 官方网站的下载页面，其中包含所有可用的预编译镜像的链接。

在 Linux 镜像中，我们可以找到并下载最新支持的 Android KitKat 4.4.2 版本。正如之前所述，UDOO 有两个不同版本，分别配备双核和四核处理器，因此我们必须根据所拥有的平台下载正确的版本。

## 从 Windows 安装

要从 Windows 安装 Android 镜像，你需要一些额外的工具来解压并将镜像复制到 microSD 卡中。下载的`.zip`文件是 7-Zip 压缩格式，因此你需要安装一个第三方解压缩程序，如 7-Zip。解压过程完成后，我们得到了一个未压缩的`.img`文件，可以将其复制到空卡上。

要将未压缩的镜像写入我们的 microSD 卡，请执行以下步骤：

1.  将你的 microSD 卡插入内置的插槽读取器或外部读卡器。

1.  使用`FAT32`文件系统格式化卡片。

1.  要将镜像写入 microSD 卡，我们需要使用 Win32DiskImager 工具。从以下链接下载：[`sourceforge.net/projects/win32diskimager/`](http://sourceforge.net/projects/win32diskimager/)。

1.  运行应用程序，但请记住，如果我们使用的是 Windows 7 或 Windows 8.x，我们必须右键点击`Win32DiskImager.exe`可执行文件，并确保从上下文菜单中选择**以管理员身份运行**的选项。

1.  Win32DiskImager 是一个使用低级别指令写入原始磁盘镜像的工具。这意味着你需要严格按照以下步骤操作，并确保你正确选择了输出设备。如果这个选项错了，你可能会丢失来自不想要存储内存的所有数据。

1.  应用程序启动后，你可以看到如下截图所示的主窗口：![从 Windows 安装](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_01_01.jpg)

1.  在应用程序的主窗口中，在**镜像文件**框内，选择之前解压的`.img`文件。

1.  准确地在**设备**下拉菜单中选择 microSD 驱动器，并记住如果我们选择了错误的驱动器，可能会破坏计算机硬盘上的所有数据。

1.  点击**写入**按钮，等待进程完成，以便在 microSD 卡中拥有可启动的 Android 操作系统。

## 从 Mac OS X 安装

要从 Mac OS X 安装 Android 镜像，我们需要一个第三方工具来解压下载的`.zip`文件，因为它采用 7-Zip 压缩格式，我们不能使用内置的解压缩软件。我们必须下载像 Keka 这样的软件，它可以在[`www.kekaosx.com/`](http://www.kekaosx.com/)免费获得。

如果我们喜欢 Mac OS X 终端，可以使用 Homebrew 包管理器，它可以在[`brew.sh/`](http://brew.sh/)找到。

在此情况下，从命令行，我们可以简单地安装`p7zip`包并使用`7za`工具按以下方式解压文件：

```kt
brew install p7zip
7za x [path_to_zip_file]

```

为了将未压缩的镜像写入我们的 microSD 卡，执行以下步骤：

1.  启动**终端**应用程序，进入我们下载并解压 Android 镜像文件的文件夹。假设该文件夹名为`Downloads`，我们可以输入以下命令：

    ```kt
    cd Downloads

    ```

1.  使用以下命令获取所有已挂载设备的列表：

    ```kt
    df -h

    ```

1.  所有系统和内部硬盘分区的列表将与以下截图类似：![从 Mac OS X 安装](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_01_02.jpg)

1.  使用内置或外置读卡器连接 microSD 卡。

1.  通过系统已提供的磁盘工具应用程序格式化 microSD 卡。启动它，并从左侧列表中选择正确的磁盘。

1.  在窗口的主面板上，从顶部菜单选择**擦除**标签页，并在**格式**下拉菜单中选择**MS-DOS (FAT)**文件系统。准备好后，点击**擦除**按钮。

1.  从终端应用程序中，再次启动之前的命令：

    ```kt
    df –h

    ```

1.  挂载分区的列表已经改变，如下面的截图所示：![从 Mac OS X 安装](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_01_03.jpg)

1.  我们可以假设在首次运行时缺少的设备是我们的 microSD 卡，因此我们必须记住**文件系统**列下的新值。如果你查看之前的截图，我们的分区名为`/dev/disk1s1`而不是`/dev/disk0s2`，因为那是我们的硬盘。

1.  找到正确的分区后，我们必须使用以下命令卸载它：

    ```kt
    sudo diskutil unmount /dev/[partition_name]

    ```

1.  为了将镜像写入 microSD 卡，我们必须找到原始磁盘设备，这样我们就可以擦除并将 Android 镜像写入卡中。假设之前找到的分区名为`/dev/disk1s1`，相关的原始磁盘将是`/dev/rdisk1`。

    ### 注意

    我们将要使用 `dd` 工具。这个命令使用低级指令写入原始磁盘镜像。这意味着你需要严格遵循以下步骤，并确保你选择了正确的磁盘设备，因为如果选择错误，你可能会因为不想要的存储而丢失所有数据。

1.  使用 `dd` 将之前解压的镜像写入 microSD 卡，命令如下：

    ```kt
    sudo dd bs=1m if=[udoo_image_name].img of=/dev/[raw_disk_name]

    ```

    之前命令的完整示例如下：

    ```kt
    sudo dd bs=1m if=[udoo_image_name].img of=/dev/rdisk1

    ```

1.  当我们执行命令时，看似没有任何反应，但实际上，`dd` 在后台写入 Android 镜像。一旦进程完成，它会输出传输字节的报告，如下例所示：

    ```kt
    6771+1 records in
    6771+1 records out
    7100656640 bytes transferred in 1395.441422 secs (5088466 bytes/sec)

    ```

1.  现在我们有了可启动的 Android 操作系统，我们可以使用以下命令弹出 microSD 卡：

    ```kt
    sudo diskutil eject /dev/[raw_disk_name]

    ```

## 从 Linux 安装

要从 Linux 安装 Android 镜像，我们需要一个第三方工具来解压下载的 `.zip` 文件。因为文件是使用 7-Zip 压缩格式，我们需要通过命令行使用发行版的包管理器安装 `p7zip` 包。然后我们可以使用 `7za` 工具解压文件，或者使用任何让你感到舒适的图形化解压缩工具。

我们可以通过以下步骤将未压缩的镜像写入我们的 microSD 卡：

1.  打开 Linux 终端，进入我们下载并解压 Android 镜像的文件夹。假设文件在我们的 `Downloads` 文件夹中，我们可以输入以下命令：

    ```kt
    cd Downloads

    ```

1.  使用内置或外置读卡器连接 microSD 卡。

1.  通过以下命令找到正确的设备名称：

    ```kt
    sudo fdisk -l | grep Disk

    ```

1.  输出是找到的所有设备的筛选列表，其中包含，例如：

    ```kt
    Disk /dev/sda: 160.0 GB, 160041885696 bytes
    Disk /dev/mapper/ubuntu--vg-root: 157.5 GB, 157454172160 bytes
    Disk /dev/sdb: 7948 MB, 7948206080 bytes

    ```

    在此例中，`/dev/sda` 是我们的硬盘，而 `/dev/sdb` 是我们的 microSD 卡。如果情况并非如此，且你使用的是内置读卡器，那么设备名称可能是 `/dev/mmcblk0`。

    找到正确的设备名称后，请记住，我们稍后会使用它。

1.  通过以下命令查找上述设备的所有已挂载分区：

    ```kt
    mount | grep [device_name]

    ```

1.  如果之前的命令产生了输出，找到输出中第一列可用的分区名称，并通过以下命令卸载列出的任何分区：

    ```kt
    sudo umount /dev/[partition_name]

    ```

    ### 注意

    `dd` 是一个使用低级指令写入原始磁盘镜像的工具。这意味着你需要严格遵循以下步骤，并确保你选择了正确的磁盘设备，因为如果选择错误，你可能会因为不想要的存储设备而丢失所有数据。

1.  使用 `dd` 命令将之前解压的镜像写入上述设备名称：

    ```kt
    sudo dd bs=1M if=[udoo_image_name].img of=/dev/[device_name]

    ```

    假设 `/dev/sdb` 是我们的 microSD 卡，以下是一个完整示例：

    ```kt
    sudo dd bs=1M if=[udoo_image_name].img of=/dev/sdb

    ```

1.  当我们执行命令时，看似没有任何反应，但实际上，`dd` 在后台写入镜像。进程完成后，它会输出传输字节的报告，如下所示：

    ```kt
    6771+1 records in
    6771+1 records out
    7100656640 bytes transferred in 1395.441422 secs (5088466 bytes/sec)

    ```

1.  现在我们有了可启动的 Android 操作系统，可以使用以下命令弹出 microSD 卡：

    ```kt
    sudo eject /dev/[device_name]

    ```

## 我们的首个运行

一旦我们有了可启动的 microSD 卡，我们可以将其插入 UDOO 主板，使用外部显示器或 LVDS 面板，并连接鼠标和键盘。打开电源后，会出现 Android 标志，当加载过程完成后，我们最终可以看到 Android 主界面。

# 设置开发环境

现在 UDOO 主板上的 Android 系统已经完全功能正常，是时候配置开发环境了。我们将要构建的每个项目都由两个不同的运行应用程序组成：第一个是物理应用程序，由一个能够通过 UDOO I/O 引脚控制外部电路的 Arduino 程序组成；第二个是在板上运行并处理用户界面的 Android 应用程序。

因为我们需要编写两个相互交互的不同应用程序，所以我们需要用两个不同的 IDE 配置开发环境。

## 安装和使用 Arduino IDE

在我们开始上传程序之前，需要安装 *microUSB 串行端口驱动程序*，以便我们可以正确与主板上的 Arduino 进行通信。与 **通用异步收发传输器** (**UART**) 相兼容的 USB 驱动程序，适用于板上的 CP210x 转换器，可以从以下链接下载

[`www.silabs.com/products/mcu/pages/usbtouartbridgevcpdrivers.aspx`](http://www.silabs.com/products/mcu/pages/usbtouartbridgevcpdrivers.aspx).

在这里，我们需要根据操作系统选择正确的版本。下载完成后，我们可以解压存档，并双击可执行文件进行安装。安装过程完成后，我们可能需要重启系统。

现在 microUSB 桥接驱动程序已经可以工作，从 Arduino 网站，我们需要下载 IDE 1.5x 测试版，因为目前，测试版是唯一支持 Arduino Due 主板的版本。链接 [`arduino.cc/en/Main/Software#toc3`](http://arduino.cc/en/Main/Software#toc3) 直接指向最新版本。

### 注意事项

为了上传新程序，UDOO 需要在上传前后分别从串行端口接收 ERASE 和 RESET 信号。在官方的 Arduino Due 主板上，这个操作是由集成的 ATmega16U2 微控制器执行的，而 UDOO 主板上缺少这个微控制器。Arduino IDE 将会处理这个过程，但如果你将来想使用另一个 IDE，你就需要自己处理。

### 在 Windows 中的安装

在 Windows 上安装时，我们有两种不同的选择：使用提供的安装程序或使用归档文件进行非管理员安装。如果我们选择使用安装程序，可以双击可执行文件。当安装程序询问我们想要安装哪些组件时，请确保选中所有的复选框。如果我们选择使用归档文件而不是安装程序，提取文件并将结果目录放入你的用户文件夹中。

### 在 Mac OS X 上安装

在 Mac OS X 上安装时，我们需要下载归档版本。如果我们运行的是大于 10.7 的 OS X 版本，可以下载 Java 7 版本。在其他情况下，或者如果你不确定，请下载 Java 6 版本。

下载完成后，我们需要双击归档文件以进行解压，然后将 Arduino 应用程序图标拖放到我们的 `Applications` 文件夹中。

### 在 Linux 上安装

在 Linux 上安装时，我们需要下载与我们 32 位或 64 位架构支持的归档版本。下载完成后，我们可以解压 IDE 并将其放入我们的 `home` 文件夹或其他你选择的文件夹中。

### 首次启动

既然我们已经完成了通信驱动和 IDE 的配置，并打上了正确的补丁，我们可以启动并查看如下截图所示的 Arduino IDE：

![首次启动](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_01_04.jpg)

## 安装和使用 Android Studio

搭载 Android 操作系统的 UDOO 与其他传统 Android 设备类似。这意味着我们可以使用标准的工具链、构建系统和用于开发智能手机或平板应用程序的 IDE。目前，可用的工具链与两个主要的 IDE 相关：Eclipse 和 Android Studio。

Eclipse 是一个开源 IDE，拥有一个高级插件系统，可以轻松扩展其许多核心功能。这使得 Google 开发了**Android Development Tool**（**ADT**）插件，以创建一个集成开发环境，让开发者可以编写、调试和打包他们的 Android 应用程序。

Android Studio 是一个较新项目，2013 年 5 月发布了第一个测试版，而第一个稳定版本是在 2014 年 12 月发布的。基于知名的 Java IDE IntelliJ IDEA，它由 **Gradle** 构建系统提供支持，该系统结合了 **Ant** 的灵活性以及 **Maven** 的依赖管理。所有这些特点，加上越来越多的插件、最佳实践、**Google Cloud Platform**集成和第三方服务如 **Travis CI** 的集成，使得 Android Studio 成为未来项目开发的一个绝佳选择。

本书涵盖的所有 Android 项目都是使用 Android Studio 构建的，如果你是一个新手或经验丰富的 Android 开发者，且习惯使用 Eclipse，这可能是一个尝试新 Android Studio 的好机会。

首先需要从[`developer.android.com/sdk/`](https://developer.android.com/sdk/)下载适用于您操作系统的最新版 Android Studio。

当开始下载时，我们会重定向到与我们的操作系统相关的安装说明，当我们完成安装后，可以启动 IDE。在首次运行时，IDE 将进行所有必要的检查以获取并安装最新的可用 SDK、虚拟设备和构建系统，让您开始开发第一个应用程序。在**设置向导 - SDK 设置**页面，确保选择**Android SDK**和**Android Virtual Device**组件，然后点击**下一步**。在下一页中，您应该接受所有 Android 许可，然后点击**完成**。

安装完 IDE 后，我们可以启动 Android Studio。以下截图显示了未打开项目时的主窗口：

![安装和使用 Android Studio](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_01_05.jpg)

# 运行您的第一个 Android 应用程序

现在 Android 已经安装在我们的 UDOO 板上，所有开发环境都已配置，我们可以开始编写并部署我们的第一个 Android 应用程序。以下是其他开发者在开始深入研究新技术时的默认模式。我们将编写并部署一个简单的 Android 应用程序，该程序打印出 Hello World!。

为了启动我们的第一个项目，请执行以下步骤：

1.  在 Android Studio 的主窗口中，点击**开始一个新的 Android Studio 项目**。

1.  在**应用程序名称**字段中，输入`HelloWorld`；在**公司域名**中，写入您的域名或如果您目前没有的话，可以写`example.com`。然后点击**下一步**。

1.  在形态因素选择窗口中，选择**手机和平板**，并在**最低 SDK**中选择**API 19: Android 4.4 (KitKat)**。然后点击**下一步**。

1.  在添加活动页面，为了这个 hello world 应用程序的目的，选择**空白活动**选项并点击**下一步**。

1.  在**活动选项**页面，在**活动名称**中写入*HelloWorld*并点击**完成**。

    ### 提示

    在接下来的章节中，我们将从头开始创建应用程序，因此我们必须记住前面的步骤，因为在这本书中我们将多次重复这个过程。

现在 Android Studio 将开始下载所有 Gradle 需求，以准备我们的构建系统。当这个过程完成后，我们得到了第一个 HelloWorld 应用程序。

在不编写任何代码的情况下，我们已经创建了一个可部署的应用程序。现在，我们需要使用 microUSB 到 USB 电缆连接我们的 UDOO 板。如果我们查看一下主板，我们会看到两个不同的 microUSB 端口。左边的第一个端口，我们将在下一章中使用它，将我们的计算机连接到两个处理器的串行端口，因此我们可以使用它将 Arduino 程序上传到 UDOO 微控制器，或者我们可以使用它访问 Android 系统 shell。串行端口的激活通信取决于 J18 跳线的状态，是插入还是未插入。而右边的 microUSB 端口则将我们的计算机连接到运行 Android 的 i.MX 6 处理器，我们将使用它来上传我们的 Android 应用程序。你可以在 UDOO 官方网站上找到更多关于处理器通信的信息[`www.udoo.org/features/processors-communication/`](http://www.udoo.org/features/processors-communication/)。

为了将我们的计算机连接到 Android 操作系统以进行应用程序上传过程，我们需要使用下面截图中标有黑色的右侧 microUSB 端口：

![运行你的第一个 Android 应用程序](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_01_06.jpg)

就像在传统的 Android 应用程序中所做的那样，我们可以从顶部菜单点击**Run**（运行），然后点击**Run app**（运行应用）。此时，我们需要选择一个运行设备，但不幸的是，我们可用的设备列表是空的。这个问题是由于处理器间内部通信的方式导致的。

启动时间之后，两个处理器之间的连接已启用，插入 microUSB 电缆将不会产生任何效果。这是因为 Android 在与 Arduino 通信时并不使用内部 UART 串行端口。它使用的是**USB On-The-Go**（**OTG**）总线，允许设备充当主机，并让其他组件（如闪存驱动器、鼠标、键盘或 Arduino）通过它连接。

i.MX 6 处理器物理连接到 OTG 总线，而总线的另一端同时连接到 Arduino 和外部 microUSB 连接器。当前活动的连接可以通过软件控制的开关进行更改。当外部 OTG 端口启用时，Android 可以通过 microUSB 端口与外部计算机通信，但不能将任何数据发送回板载 Arduino。相反，当外部 OTG 端口禁用时，Android 可以与 Arduino 通信，但与计算机的连接会中断。

后者是我们的实际配置，我们需要切换 OTG 端口以启用与计算机的外部通信，完成应用程序部署。在 Android 系统中，我们必须进入**设置菜单**，选择**开发者选项**。在那里，我们需要勾选**启用外部 OTG 端口**的复选框。如果连接了 USB 线，会出现一个弹窗要求我们允许 USB 调试。如果是我们的主计算机，我们可能想要选择**始终允许此计算机**，然后点击**确定**。如果没有勾选这个选项，每次我们连接 UDOO 到计算机时都会显示弹窗。

### 注意事项

请记住，每次我们需要部署 Android 应用程序时，都需要启用外部 OTG 端口。相反，当我们的应用程序部署好，需要 Android 与 Arduino 通信时，我们需要禁用外部 OTG 端口。

现在，我们的计算机可以将 UDOO 板视为传统的 Android 设备，我们可以尝试再次部署我们的应用程序。这次，在**选择设备**对话框中，我们可以找到一个 Freescale UDOO Android 设备。选择它并点击**确定**。我们的首次部署完成，现在我们可以在连接的监视器上看到 HelloWorld 应用程序。

# 总结

在本章中，我们了解了一些 UDOO 的特性，这些特性使这块开发板与其他开发板区分开来。最大的区别之一是与 Android 平台的全面支持，这让我们能够在板上安装和配置最新支持的版本。

我们探索了开始开发实际应用所需的工具，并配置了我们的开发环境以编写 Android 应用程序和 Arduino 程序。

我们简要介绍了两个处理器之间如何通信以及如何切换 OTG 端口以启用外部访问，完成首次部署。在下一章中，我们将从零开始创建一个新的 Android 应用程序，能够使用并控制通过一套原型工具构建的物理设备。


# 第二章：了解你的工具

如上一章所述，现实世界应用不仅仅是软件。它们由在物理世界中执行动作的简单或复杂电路组成。在我们开始构建第一个交互式项目之前，我们需要了解这些物理组件是如何工作的，这样我们才知道工具箱里有什么。

在本章中，我们将涵盖以下主题：

+   上传第一个 Arduino 程序

+   与 Arduino 建立连接

+   编写一个能作为控制器作用的 Android 应用

+   构建一个由 Android 控制的简单电路

# 介绍 Arduino Due 的功能

物理世界由我们以光、热、声音或运动形式感知的多种能量形式组成。当我们在驾车时，靠近交通灯，看到前方红灯亮起，我们会开始减速并停车。我们只是感知了一种光能形式，这使我们改变了活动，因为有人教过我们每个交通灯阶段的意义。

这种自然行为正是我们希望带到我们的交互式物理应用中的。我们使用的硬件设备叫做**传感器**，它们监听环境，并与其他硬件组件，即**执行器**协同工作，执行现实世界中的动作。然而，我们需要一个叫做**微控制器**的第三种元素，它使用连接的传感器和执行器来感知并改变周围环境，根据上传的程序进行操作。

板载的 Arduino Due 采用了最新的部件，并提供了一种连接外部电子组件的通用方式。它有 54 个数字 I/O 引脚，我们可以使用它们发送或接收数字信号。当我们想要从外部设备（如开关或按钮）收集输入时，这特别有用，同时我们可以发送数字信号以打开或关闭简单的组件。在下面的图表中，你可以看到所有的数字引脚都是黑色的：

![介绍 Arduino Due 的功能](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_02_01.jpg)

我们可以使用 12 个模拟输入，其 12 位分辨率可以读取 4096 个不同的值。当需要从传感器收集数据，并使用返回值作为程序改变物理设备行为的条件时，它们非常有用。读取值的良好例子与温度、光线或接近传感器相关。板子还提供了 2 个**数字至模拟转换器**（**DAC**），具有 12 位分辨率，当需要使用数字信号驱动模拟设备时，可以作为模拟输出使用。当你需要用你的设备创建音频输出时，使用 DAC I/O 引脚的一个好例子。在下面的图表中，你将找到所有模拟引脚都是黑色的，而 2 个 DAC 引脚是灰色的：

![介绍 Arduino Due 的功能](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_02_12.jpg)

有了这些功能，我们就有了一切必要的工具来从我们的 Android 应用程序中控制小型设备。另一方面，我们也可以反过来利用，让连接的设备改变我们 Android 界面的行为。

然而，当 UDO 用于控制复杂的电路并且可能需要一个硬件驱动程序与它交互时，UDO 才能真正显示出其强大的功能。当我们打算回收我们已拥有的设备，如旧玩具，或者购买新设备如小型电动机器人或漫游车时，这可能会成为一种常见的方法。

构建硬件驱动程序是一项昂贵的任务，需要软件和电子方面的丰富经验。UDO 通过板载 Arduino 使这项任务变得简单，因为它重用了制造商社区构建的所有组件。我们可以通过将 UDO 与一个*盾板*结合来添加其他功能，这是一个可插拔的板，它实现了一个复杂的电路，包含了所有必需的硬件逻辑。好的例子包括兼容 Arduino 的 LCD 屏幕、蓝牙控制器以及控制连接电机的电机盾板，只需几行代码，无需构建外部电路。

## 上传第一个程序

既然我们已经了解了 UDO 板的主要组件和能力，我们可以开始编写并上传我们的第一个程序。我们必须牢记，尽管 SAM3X 是一个独立的处理器，但我们仍需要一个带有有效 UDO 镜像的工作 microSD 卡，否则 Arduino 编程器将无法工作。

就像之前为 Android 所做的那样，我们将编写一个简单的应用程序，在屏幕上打印“Hello World!”，此时不需要任何 Android 交互。在打开 Arduino IDE 之前，我们需要通过左侧的 microUSB 端口将板连接到我们的计算机，如下图所示：

![上传第一个程序](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_02_03.jpg)

然而，这种连接不足以让 Arduino SAM3X 和我们的计算机之间进行正确的通信，因为这两个处理器都使用这个 microUSB 端口通过串行端口与连接的设备进行通信。一个内部物理开关在运行 Android 的 i.MX6 和 Arduino SAM3X 之间选择连接的处理器。

### 注意

这是一个不同的连接，不是前一章中使用的那个。它指的是串行端口，不应与用于部署 Android 应用程序的 OTG microUSB 端口混淆。

为了使我们的计算机和 SAM3X 之间能够连接，我们必须拔掉下图所示的物理**跳线 J18**：

![上传第一个程序](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_02_04.jpg)

现在我们准备启动 Arduino IDE 并继续编写和上传我们的第一个程序。当 IDE 出现时，它将打开一个空程序。为 Arduino 编写的每个程序和代码都称为**草图**。Arduino 草图使用一组简化的 C/C++编写，如果您感兴趣，可以在[`arduino.cc/en/Reference/HomePage`](http://arduino.cc/en/Reference/HomePage)找到完整的参考资料。

初始草图包含以下两个函数：

+   `setup()`: 这在初始执行时被调用一次，我们在其中放置所有初始配置。

+   `loop()`: 这会在设备关闭之前不断被调用，它代表了我们草图的内核。

我们所有的草图都必须包含这两个函数，否则程序将无法工作。我们可以添加自己的函数以使代码更具可读性和可重用性，这样我们就可以遵循编程原则**不要重复自己**（**DRY**）。

### 注意

我们必须记住，我们是为一个最多有 512 KB 可用内存来存储代码的微控制器编写软件。此外，草图在运行时创建和操作变量的 96 KB SRAM 限制。对于复杂项目，我们应该始终优化代码以减少使用的内存，但为了本书的目的，我们编写代码使其更具可读性和易于实现。

要在屏幕上打印出“Hello World!”，我们需要编写一个向内置串行端口写入字符串的草图。这个草图可以通过以下简单步骤实现：

1.  在`setup()`函数中，以指定的每秒**比特数**（**波特**）初始化串行端口，如下所示：

    ```kt
    void setup() {
     Serial.begin(115200);
    }
    ```

    我们选择每秒`115200`波特率，因为板载的 Arduino Due 支持这个数据率。

    ### 提示

    **下载示例代码**

    您可以从您的账户下载您购买的所有 Packt 图书的示例代码文件，网址是[`www.packtpub.com`](http://www.packtpub.com)。如果您在别处购买了这本书，可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)注册，我们会将文件直接通过电子邮件发送给您。

1.  在主`loop()`函数中使用`println()`函数向串行端口写入：

    ```kt
    void loop() {
     Serial.println("Hello World!");
    }
    ```

    即使我们有上传我们项目的冲动，我们也必须记住`loop()`函数会不断被调用，这意味着我们可能会收到太多的“Hello World!”实例。一个好方法是添加一个`delay()`函数，这样 Arduino 在再次开始`loop()`函数之前会等待给定毫秒数。

1.  要每秒打印一句话，请添加以下突出显示的代码：

    ```kt
    void loop() {
     Serial.println("Hello World!");
     delay(1000);
    }
    ```

现在我们准备开始上传过程。这个过程包括两个阶段，首先编译我们的代码，然后上传到 SAM3X 处理器。如果我们上传两个不同的草图，最新的会覆盖第一个，因为我们一次只能加载和执行一个草图。

在这种情况下，我们需要配置 IDE，使其能够为连接到正确串行端口的正确电路板编程。点击**工具**，悬停在**电路板**上并选择**Arduino Due (编程端口)**。现在点击**工具**，悬停在**端口**上，并选择你配置的端口。正确的端口取决于你的操作系统，它们通常具有以下值：

+   在 Windows 中：编号最高的`COM`端口

+   在 Mac OS X 中：`/dev/tty.SLAB_USBtoUART`

+   在 Linux 中：`/dev/ttyUSB0`

要上传程序，请点击**文件**，然后点击**上传**，或者使用工具栏中可用的快捷方式。如果上传过程顺利，你将在窗口底部看到以下输出的记录器：

![上传第一个程序](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_02_05.jpg)

为了确保我们的第一个草图按预期工作，我们需要使用串行端口阅读器，而 Arduino IDE 提供了一个内置的串行监视器。点击**工具**，然后点击**串行监视器**，或者使用工具栏中可用的快捷方式。我们可能会看到一些奇怪的字符，这是因为串行监视器默认配置为以 9600 波特读取串行。在右下角的下拉菜单中，选择**115200 波特**以查看以下输出：

![上传第一个程序](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_02_06.jpg)

### 注意

使用`Serial.println()`函数可以通过串行端口发送数据。这并不是用来与 i.MX6 处理器通信的，但这是从电脑调试变量或草图流程的好方法。

当我们完成草图上传后，我们可以插入**J18 跳线**。现在我们知道如何部署 Android 应用程序和 Arduino 草图了，是时候从头开始构建我们的第一个项目了。

# 与现实世界的互动

我们第一个现实世界的原型应该是一个可以用来控制简单电子元件的 Android 应用程序。我们必须选择一个不太简单的东西，以便我们可以对其进行实验，同时也不要太复杂，以便我们可以深入了解所有主要概念，而不需要太多实现细节。一个好的起点是创建一个控制器，我们可以使用它来打开和关闭实际的**发光二极管**（**LED**）组件。

然而，在我们继续之前，我们必须了解如何创建 Android 应用程序和草图之间的通信。在部署过程中，我们通常会启用外部 OTG 端口，以便从电脑与 i.MX6 处理器通信。如果我们禁用这个选项，内部的开关会激活 i.MX6 和 SAM3X 处理器之间的双向通信。这是可能的，因为 Arduino Due 完全支持 USB OTG 连接，我们使用这个连接让 Android 和 Arduino 相互通信。

不幸的是，如果我们没有一个通信协议，上述软件开关并不十分有用。这就是**Accessory Development Kit**（**ADK**）发挥重要作用的地方。它是谷歌开发的参考实现，用于构建 Android 配件，并提供了一套软件库。UDOOboard 完全支持 ADK。通过将内部 Android API 与外部 Arduino 库相结合，我们可以轻松地使用这些功能发送命令和接收数据。这样，我们的 Android 将把我们的 Arduino 设备视为一个*Android 配件*，从而在应用程序和整个系统中支持这种连接。我们可以在[`developer.android.com/tools/adk/index.html`](http://developer.android.com/tools/adk/index.html)找到关于 ADK 的更多详细信息。

## 与 Arduino 通信

这个原型的第一步是开始一个新的草图，并从 Arduino 端设置初始连接。在我们空白的草图顶部，我们应该添加以下代码：

```kt
#include <adk.h>
#define BUFFSIZE 128
#define LED 2
```

`adk.h`头文件包含了所有我们需要的声明，用于许多实用工具和函数，例如初始化 ADK 连接，向 Android 发送硬件信息，以及两个处理器之间缓冲数据的读写。在上述代码中，我们还定义了两个*宏对象*，分别提供了读写缓冲区的最大尺寸以及用于打开和关闭 LED 的引脚。我们需要记住这个数字，因为稍后当我们连接第一个电子元件时会重新使用到它。

通过 ADK 使用的协议，Android 将 Arduino 识别为外部配件。为了将我们的配件与其他配件区分开来，Android 需要一个**配件描述符**，我们可以使用以下代码提供：

```kt
char accessoryName[] = "LED lamp";
char manufacturer[] = "Example, Inc.";
char model[] = "LedLamp";
char versionNumber[] = "0.1.0";
char serialNumber[] = "1";
char url[] = "http://www.example.com";
```

在这里，我们提供了关于配件名称、硬件制造商名称和模型唯一标识符的信息。除了这些原型描述符之外，我们还必须定义硬件版本和序列号，因为当我们将设备连接到 Android 应用程序时，这些信息是强烈需要的。实际上，`versionNumber`、`model`和`manufacturer`参数将与稍后我们提供给 Android 应用程序的值进行匹配，如果有不匹配的情况，我们的草图将不会被 Android 应用程序识别。通过这种方式，我们还可以在应用程序版本和硬件版本之间保持强绑定，以避免旧的 Android 应用程序错误地控制新的硬件发布。

### 注意

前面的描述符是 Android 应用程序识别草图和硬件所必需的。但是，请记住，这是良好*编程礼仪*的一部分，对于每个应用程序和原型，你都应该提供版本编号以及变更日志。在本书中，我们将使用**语义版本控制**，你可以访问[`semver.org`](http://semver.org)了解更多信息。

最后一个参数是`url`，Android 使用它将用户重定向到一个网站，在那里他们可以找到关于已连接配件的更多信息。每当 Android 找不到能够管理 Arduino 配件交互的已安装应用程序时，它都会显示该消息。

### 提示

在大多数情况下，将`url`参数设置为可以下载并安装打包的 Android 应用程序的链接是一个好主意。这样，如果缺少 Android 应用程序，我们就提供了一种快速获取和安装的方法，这对于将我们原型的原理图和草图分发给其他开发者尤其有用。你可以访问[`developer.android.com/tools/building/building-studio.html`](https://developer.android.com/tools/building/building-studio.html)了解更多关于如何使用 Android Studio 创建打包应用程序的信息。

为了完成 ADK 配置，我们必须在之前的声明下方添加以下代码：

```kt
uint8_t buffer[BUFFSIZE];
uint32_t bytesRead = 0;
USBHost Usb;
ADK adk(&Usb, manufacturer, model, accessoryName, versionNumber, url, serialNumber);
```

我们在读写操作期间声明了使用的`buffer`参数和一个`USBHost`对象。我们在主`loop()`函数中使用它来初始化连接，以便在发现过程中 Android 接收所有必要的信息。在最后一行，我们使用定义的值初始化 ADK 配件描述符。

要开始连接，我们需要将以下代码放入`loop()`函数中：

```kt
void loop(){
 Usb.Task();
 if (adk.isReady()) {
 // Do something
 }
}
```

`Usb.Task()`函数调用轮询连接的 USB 设备以获取它们状态更新，并等待 5 秒钟以查看是否有任何设备响应更新请求。当 Android 响应轮询时，我们使用条件语句评估`adk.isReady()`函数调用。当设备连接并准备好与 Android 通信时，它返回`True`，这样我们就能确切知道 Android 系统何时读取原型描述符以及何时通知已安装的应用程序连接了新的配件。

我们的初始配置已完成，现在可以将草图上传到电路板中。当草图上传完毕，我们禁用 OTG 外部端口时，Android 将发现正在运行的配件，然后显示一条消息，通知用户没有可用的应用程序可以与连接的 USB 配件一起工作。它还给了用户跟随所选 URL 的机会，如下面的屏幕截图所示：

![与 Arduino 通信](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_02_07.jpg)

## 编写 Android 应用程序控制器

我们的第一块构建模块已经准备好了，但目前它还没有任何我们可以使用的物理执行器，也没有用户界面进行控制。因此，下一步是通过 Android Studio 创建我们的第二个 Android 项目，名为 **LEDLamp**。就像在第一个应用程序中所做的那样，记得选择 **API 级别 19** 和一个**空白活动**，我们可以将其称为 **LightSwitch**。

当活动编辑器出现时，最好更改用户界面的可视化预览，因为我们将使用监视器视图而不是普通的智能手机视图。我们可以通过应用程序屏幕右侧的**预览**标签页进行更改，并在上下文菜单中选择 **Android TV (720p)**。

因为我们需要一个非常简单的活动，所以我们需要使用以下步骤更改默认布局：

1.  在 `res/layout/activity_light_switch.xml` 文件中，将 `RelativeLayout` 参数更改为垂直的 `LinearLayout` 参数，如下所示的高亮代码：

    ```kt
    <LinearLayout

     android:orientation="vertical"
     android:layout_width="match_parent"
     android:layout_height="match_parent"
     android:paddingLeft="@dimen/activity_horizontal_margin"
     android:paddingRight="@dimen/activity_horizontal_margin"
     android:paddingTop="@dimen/activity_vertical_margin"
     android:paddingBottom="@dimen/activity_vertical_margin"
     tools:context=".LightSwitch">
    </LinearLayout>

    ```

1.  在前面的 `LinearLayout` 中，使用以下代码更改默认的 `TextView` 参数：

    ```kt
    <TextView
     android:layout_width="wrap_content"
     android:layout_height="wrap_content"
     android:textAppearance="@android:style/TextAppearance.Large"
     android:text="Available controlled devices"/>
    ```

    我们创建一个标题，并将其放置在布局顶部。在此视图下方，我们将放置所有可控制的设备，比如我们的第一个 LED。

1.  在前面的 `TextView` 下面添加以下 `Switch` 视图：

    ```kt
    <Switch
     android:layout_width="wrap_content"
     android:layout_height="wrap_content"
     android:text="LED 2"
     android:id="@+id/firstLed"/>
    ```

    为了保持用户界面简洁，我们需要一个按钮来控制 LED 的开关。为此，我们将使用一个开关按钮，这样我们就可以将动作发送到微控制器，同时提供 LED 实际状态的视觉反馈。

    ### 提示

    在我们的 Android 应用程序中，了解微控制器正在做什么的视觉反馈总是好的。这样，我们可以轻松知道草图的状态，这有助于我们查找异常。这特别是在实际设备没有给用户任何即时反馈时尤为重要。

没有进一步的自定义，以下是预期的用户界面截图：

![编写 Android 应用控制器](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_02_08.jpg)

为了在电路板上尝试，我们可以像在前一章中那样进行应用程序部署，然后继续编写 ADK 通信逻辑。

## Android 配件开发套件

为了在我们的应用程序中启用 Android ADK，我们需要向 `AndroidManifest.xml` 文件添加一些配置。因为我们使用了 Android 系统的*特殊功能*，这依赖于可用的硬件，所以我们需要在 `manifest` 文件顶部添加以下声明：

```kt
<manifest

  package="me.palazzetti.ledlamp">

<uses-feature
android:name="android.hardware.usb.accessory"
android:required="true"/>

<!-- other declarations -->
</manifest>
```

当应用程序在系统中注册时，它应该声明能够响应在连接 USB 配件时引发的事件。为了实现这一点，我们需要向我们的 `LightSwitch` 活动声明中添加一个*意图过滤器*，如下所示的高亮代码：

```kt
<activity
 android:name=".LightSwitch"
 android:label="@string/app_name">
 <!-- other declarations -->

 <intent-filter>
 <action android:name=
 "android.hardware.usb.action.USB_ACCESSORY_ATTACHED"/>
 </intent-filter>
</activity>
```

Android 系统要求我们填写与之前在 Arduino 草图中的配件信息相同的配件信息。实际上，我们必须提供我们配件的制造商、型号和版本，为了保持组织性，我们可以创建`res/xml/`文件夹并在其中放入一个名为`usb_accessory_filter.xml`的 XML 文件。在这个文件中，我们可以添加以下代码：

```kt
<resources>
   <usb-accessory
    version="0.1.0"
    model="LampLed"
    manufacturer="Example, Inc."/>
</resources>
```

要将上述文件包含在 Android 清单中，只需在 USB 意图过滤器下方添加以下代码：

```kt
<activity
 android:name=".LightSwitch"
 android:label="@string/app_name">
 <!-- other declarations -->

 <meta-data
 android:name=
 "android.hardware.usb.action.USB_ACCESSORY_ATTACHED"
 android:resource="@xml/usb_accessory_filter"/>
 </activity>
```

既然我们的应用程序已经准备好进行发现过程，我们需要包含一些逻辑来建立连接并开始通过 ADK 发送数据。

### 注意

在这个原型中，我们将通过 Android 内部 API 使用 ADK。从第四章，*使用传感器聆听环境*开始，我们将通过一个外部库使用高级抽象，这将帮助我们更容易地实现项目，并且不需要任何样板代码。

下一步是将 ADK 的一些功能隔离在一个新的 Java 包中，以便更好地组织我们的工作。我们需要创建一个名为`adk`的新包，并在其中添加一个名为`Manager`的新类。在这个类中，我们需要使用从 Android `Context`参数中获取的`UsbManager`类、一个文件描述符和用于在 OTG 端口中写入数据的输出流。在`Manager`类中添加以下代码：

```kt
public class Manager {
 private UsbManagermUsbManager;
  private ParcelFileDescriptormParcelFileDescriptor;
  private FileOutputStreammFileOutputStream;

  public Manager(UsbManagerusbManager) {
  this.mUsbManager = usbManager;
  }
}
```

### 提示

Java 代码段需要在文件的顶部导入许多内容，为了更好的代码可读性，这些导入被故意省略了。然而，为了让一切按预期工作，我们需要编写它们并使用 Android Studio 中提供的自动补全功能。当你发现缺失导入时，只需将光标放在红色标记的语句上方，并按*Ctrl*+*Space*键。我们现在可以从建议框中选择正确的导入。

我们期望将`UsbManager`方法作为参数，因为我们无法访问 Android `Context`，我们稍后将从主活动中获取它。为了在 ADK 通信期间简化我们的工作，以下助手应该包含在我们的包装器中：

+   `openAccessory()`: 当找到设备时，它应该与设备建立连接

+   `closeAccessory()`: 如果有任何设备连接，它应该关闭并释放任何已使用的资源

+   `writeSerial()`: 当设备连接时，它应该通过已打开的流发送数据

第一个助手与配件建立连接并初始化相关输出流可以通过以下方法实现，我们应该将其添加到`Manager`类的底部：

```kt
public void openAccessory() {
 UsbAccessory[] accessoryList = mUsbManager.getAccessoryList();
  if (accessoryList != null &&accessoryList.length> 0) {
    try {
     mDescriptor = mUsbManager.openAccessory(accessoryList[0]);
     FileDescriptor file = mDescriptor.getFileDescriptor();
     mOutput = new FileOutputStream(file);
    }
   catch (Exception e) {
      // noop
    }
  }
}
```

我们使用存储的`UsbManager`对象来获取所有可用的配件。如果我们至少有一个配件，我们会打开它以初始化一个描述符和一个输出流，我们稍后将会使用它们向配件发送数据。为了关闭上述连接，我们可以按如下方式添加第二个助手：

```kt
public void closeAccessory() {
  if (mDescriptor != null) {
    try {
     mDescriptor.close();
    }
   catch (IOException e) {
      // noop
    }
  }
 mDescriptor = null;
}
```

如果我们已经打开了一个配件，我们使用创建的描述符来关闭激活的流，并从实例变量中释放引用。现在我们可以添加最新的写入助手，其中包括以下代码：

```kt
public void writeSerial(int value) {
  try {
   mOutput.write(value);
  }
 catch (IOException e) {
    // noop
  }
}
```

前面的方法将给定的`value`写入启用的输出流中。这样，如果连接了一个配件，我们使用输出流引用来写入 OTG 端口。

最后，我们需要在活动中创建一个`Manager`类的实例，这样我们就可以使用它来与 Arduino 打开通信。在`LightSwitch`活动的`onCreate`方法中，添加以下高亮代码：

```kt
public class LightSwitch extends ActionBarActivity{
 private Manager mManager;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
   super.onCreate(savedInstanceState);
   setContentView(R.layout.activity_light_switch);
 mManager = new Manager(
 (UsbManager) getSystemService(Context.USB_SERVICE));
  }
}
```

我们正在查询系统中的 USB 服务，以便我们可以在`Manager`类中使用它来访问 USB 配件的状态和功能。我们将`Manager`类的引用存储在类内部，以便我们将来可以访问我们的助手函数。

一旦`Manager`类初始化完成，我们应该根据活动的开启和关闭来上下文地打开和关闭我们的配件。实际上，通常在活动的`onResume()`和`onPause()`回调中调用`openAccessory()`和`closeAccessory()`函数是个好主意。这样，我们可以确保在活动方法中使用 ADK 通信时，它已经被初始化。为了实现这个实现 ADK 通信的最后一块拼图，请在`onCreate()`成员函数下面添加以下方法：

```kt
@Override
protected void onResume() {
 super.onResume();
 mManager.openAccessory();
}

@Override
protected void onPause() {
 super.onPause();
 mManager.closeAccessory();
}
```

既然 Android 应用程序已经准备好了，我们可以继续部署，当我们禁用外部 OTG 端口时，会出现以下消息：

![Android 配件开发套件](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_02_09.jpg)

安卓系统已经发现了物理配件，并请求使用 LED Lamp 应用程序与之工作的权限。如果我们点击**确定**，应用程序将被打开。我们甚至可以将我们的应用程序设置为*默认*；这样，每当配件开始与 Android 系统通信时，我们的应用程序将立即启动。

# 快速原型设计电路

我们已经实现了 Android 和 Arduino 之间完全功能的通信，现在是时候构建一个真正的电路了。我们的目标是使用 Android 系统来开关一个 LED，这个问题既小又独立。然而，一开始，我们可以更有野心一些，不是打开一个 LED，而是可能想打开卧室的灯泡。那么，当我们能做得更有趣时，为什么要创建这样一个简单的项目呢？因为我们对项目进行**快速原型设计**。

快速原型制作是一组我们可以使用的技巧，以便尽快创建我们的工作项目。这非常有帮助，因为我们可以移除许多实现细节，比如产品设计，只专注于我们项目的核心。在我们的案例中，我们移除了所有与点亮灯泡相关的难题，比如使用晶体管、继电器和外部电池，我们专注于创建一个由 Android 系统供电的灯开关。当第一个原型开始工作时，我们可以逐步增加要求，直到实现最终项目。

## 使用面包板

为了继续我们的项目，我们应该创建一个电路原型。我们可以使用许多工具来实现这一目标，但在一开始，最重要的工具之一就是**面包板**。它可用于连接我们的电路板和其他电子组件，无需焊接。这允许我们在设计电路时进行实验，同时还可以将面包板用于其他项目。

下面是一个典型的面包板：

![使用面包板](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_02_10.jpg)

面包板由两个相同的部分组成，中间有一条水平行将两部分隔开，以断开两侧之间的任何连接。每一侧都包含一红一蓝两行，位于侧面的顶部或底部，它们代表*电源总线*。它们在整条水平线上是连接的，我们将使用它来连接 UDOOboard 的电源和地线。颜色通常用红色表示电源，蓝色表示地线，但请记住，这只是一种约定，你的面包板颜色可能会有所不同。

剩下的五条水平线是*原型区域*，这是我们连接设备的地方。与电源总线不同，这些线在垂直方向上是连接的，而水平线之间没有连接。例如，如果我们把一根**跳线**插入 A1 孔，金属条就会与从 B1 到 E1 的孔形成电气连接。另一方面，A2-E2 和 F1-J1 范围内的孔与我们的 A1-E1 列没有连接。

作为我们的第一个原型，我们打算使用面包板连接将 LED 连接到我们的 UDOOboard 上。然而，我们需要另一个叫做*电阻器*的电子组件。它通过电线对电流的通过产生阻力，这是必要的；否则，过多的电流可能会损坏组件。另一方面，如果我们提供过多的电阻，那么通过组件的电流将不足以使其工作。该组件的电阻以*欧姆*为单位测量，在我们的案例中，我们需要一个*220 欧姆*的电阻来正确地给 LED 供电。

现在我们需要将我们的组件连接到面包板上，正如我们在下面的电路中所看到的那样：

![使用面包板](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_02_11.jpg)

我们需要将引脚 2 连接到电源总线的正线，而地线则应连接到负线。然后我们将 LED 连接到原型区域，并在其*正极*前放置电阻。我们可以通过观察 LED 的*腿长*来区分其**极性**：较长的腿是正极，较短的腿是负极。记住这一点，我们可以将长腿连接到电阻上。为了闭合电路，我们只需将电阻连接到电源总线的正线，并将 LED 的负极连接到地线。这样我们就制作了我们的第一个电路。

### 注意

LED 应该关闭，但可能仍有一小部分电流流经它。这可能是由于我们的 Arduino 草图默认没有禁用引脚造成的。这种行为是安全的，我们将在下一节中处理这个问题。

## 与外部电路的交互

在这一点上，我们已经有了工作的通信和原型电路。我们应该实现的最后一步是从 Android 应用程序发送打开和关闭的信号，并在草图中解析并执行此命令。我们可以从我们的草图中开始，在其中我们需要配置引脚以作为输出引脚工作。这类配置是在`setup()`函数中完成的；在其中，我们应该添加以下代码：

```kt
void setup(){
 pinMode(LED, OUTPUT);
 digitalWrite(LED, LOW);
}
```

使用`pinMode()`函数，我们声明所选择的引脚将作为`OUTPUT`工作，这样我们就可以控制通过它的电流流动。因为我们之前定义了`LED`宏对象，它指的是引脚 2。`digitalWrite()`函数是 Arduino 语言的另一个抽象，我们使用它来允许或阻止电流流经所选择的引脚。在这种情况下，我们表示不应该有电流通过该引脚，因为在初始化步骤中，我们希望 LED 处于关闭状态。

因为 Android 应用程序将向我们发送一个只能具有`0`和`1`值的命令，我们需要一个函数来解析此命令，以便 Arduino 知道相关的动作是什么。为了实现这一点，我们可以在草图的底部简单地添加一个`executor()`函数，如下所示：

```kt
void executor(uint8_t command){
  switch(command) {
    case 0:
   digitalWrite(LED, LOW);
      break;
    case 1:
   digitalWrite(LED, HIGH);
      break;

    default:
      // noop
      break;
  }
}
```

我们正在创建一个解析`command`参数的开关。如果该值为`0`，Arduino 使用`digitalWrite()`函数关闭 LED；然而，如果值为`1`，它使用相同的函数打开 LED。在其它任何情况下，我们只需丢弃接收到的命令。

在这一点上，我们需要在`adk.isReady`条件下的主`loop()`函数中将事物组合在一起，如下所示：

```kt
if (adk.isReady()) {
 adk.read(&bytesRead, BUFFSIZE, buffer);
 if (bytesRead> 0){
 executor(buffer[0]);
 }
}
```

在主`loop()`函数期间，如果我们发现 ADK 连接，我们从通信通道读取任何消息，并通过`adk.read()`函数调用将结果写入我们的`buffer`变量。如果我们至少读取了 1 个字节，我们将字节数组的第一个值传递给`executor()`函数。完成此步骤后，我们可以将草图上传到 UDOOboard。

## 从 Android 发送命令

既然 UDOOS 已经准备好进行物理操作，我们就需要完成 Android 应用程序，并在`LightSwitch`类中实现命令发送。作为第一步，我们需要向我们的活动添加一个变量来存储 LED 的状态。在我们的类顶部，添加`mSwitchLed`声明：

```kt
private Manager mManager;
private booleanmSwitchLed = false;

```

需要做的最后一件事情是创建一个使用 ADK 写入包装器向 Arduino 发送命令的方法。在`onCreate()`方法下面，添加以下代码：

```kt
public void switchLight(View v) {
 mSwitchLed = !mSwitchLed;
 int command = mSwitchLed ? 1 : 0;
 mManager.writeSerial(command);
}
```

我们改变 LED 的状态，并从中创建`command`参数，该参数可能是`0`或`1`的值。然后我们使用`mManager`将命令写入 OTG 端口。为了完成应用程序，我们只需要将`switchLight`方法绑定到我们的视图上。在`activity_light_switch.xml`文件中，像下面这样为我们的开关按钮添加`onClick()`属性：

```kt
<Switch
 android:layout_width="wrap_content"
 android:layout_height="wrap_content"
 android:text="LED 2"
 android:id="@+id/firstLed"
 android:onClick="switchLight"/>

```

这是我们的最后一步，现在我们有了第一个真实世界的原型。现在我们可以将 Android 应用程序上传到 UDOOboard，并使用它来开关 LED。

# 概述

在本章中，你已经了解到了 UDOOS 一些与可用输入输出引脚相关的特性，以及两个处理器是如何通过内部串行总线连接在一起的。此外，在第一部分，我们编写并将我们的第一个草图部署到电路板上。

然后，我们深入探讨了通过 ADK 实现的通信机制，并编写了一个新的 Arduino 草图，能够通过内部 OTG 端口与 Android 建立通信。为 Android 做同样的事情，我们创建了一个简单的用户界面，在设备使用期间提供视觉反馈。我们还编写了 Android 应用程序中的包装器，以便轻松地公开常用的 ADK 方法来打开和关闭连接，以及写入通信通道。

在本章的最后，你学习了如何使用面包板快速原型电路，并构建了你的第一个使用 LED 和电阻的电路。然后，我们添加了所有必要的代码，从我们的 Android 应用程序发送开关信号，并从草图中接收并执行此命令。这是一个更复杂的 Hello World 应用程序，它确实有助于构建我们的第一个真实世界设备。

在下一章中，我们将扩展上述电路的调试功能，以便测试我们的硬件，看看设备是否有任何损坏的电子组件。


# 第三章：测试您的物理应用程序

软件开发过程中最重要的步骤之一是**测试**。当我们测试软件组件时，我们使用测试框架编写单元测试，也许还有集成测试，这有助于复现错误并检查我们应用程序的预期行为。在物理应用中，这一过程并不容易，因为我们需要测试我们的草图与硬件电路的交互情况。

我们将为 LedLamp 应用程序添加所有必要的功能，以实现一种简单的方法来查找电路中的异常，这样我们可以避免复杂的调试过程。

在本章中，我们将讨论以下主题：

+   关于电子元件和电路的更多细节

+   向电路添加组件，以便它们可以被草图测试

+   编写第一个用于电路调试的测试

+   从您的原型运行电路测试

# 构建可测试的电路

在编写安卓应用程序时，我们可能会使用内部测试框架编写仪器测试。通过它们，我们可以检查应用程序在安卓堆栈所有层面的行为，包括用户界面压力测试。然而，在我们的 UDOO 项目中，我们利用安卓与板载微控制器交互，以控制和收集物理设备的数据。当我们的安卓应用程序通过测试覆盖了良好特性，并且符合我们所有要求时，我们首先遇到的问题很可能与硬件故障和异常有关。

### 注意事项

在本书中，我们将不介绍安卓单元测试框架，因为它不是在硬件原型制作初期所必需的。但是，请记住，您应该学习如何编写安卓测试，因为要提高软件质量，这是必须的。您可以在官方文档中找到更多信息，地址是[`developer.android.com/training/activity-testing/index.html`](http://developer.android.com/training/activity-testing/index.html)。

在上一章中，我们使用了许多电子元件，比如 LED 和电阻，构建了我们的第一个原型，并编写了一个安卓应用程序作为设备控制器。这是一个很好的起点，因为我们已经拥有了一个可以添加其他功能的正常工作的设备。为了使电路简单，我们将从第一个 LED 独立添加另一个 LED，使我们的设备能够控制两个不同设备的开关。我们需要对 LedLamp 电路进行一些更改，以便将第二个 LED 连接到 UDOO 板上。请查看以下电路图：

![构建可测试的电路](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_03_01.jpg)

要实现上述电路图，请采取以下步骤：

1.  从电源总线的正线断开连接，因为我们需要从不同的引脚控制不同的组件。

1.  保持地线连接到电源总线的负线，因为我们将所有的地线都连接在一起。

1.  使用两个*220 欧姆电阻器*将负极腿连接到负电源总线。

1.  将正极腿连接到 UDOOb 引脚 2 和 3。

在上一章中，我们将电阻器连接到正极腿，而现在我们连接负极腿。这两种配置都是正确的，因为当 LED 和电阻器串联连接时，电流将以相同的强度流过它们。我们可以发现，电路类似于高速公路，而汽车就像电荷。如果汽车遇到一个或多个路障，它们将从高速公路的每个点开始减速，而且不管它们距离路障是远是近。因此，即使电阻器位于电路末端，正确数量的电流仍会流过 LED。

既然电路包括了一个新的 LED，我们必须按照以下步骤更改我们的草图，使其符合我们的需求：

1.  在草图的顶部添加以下类似对象的宏：

    ```kt
    #define LED 2
    #define LED_TWO3

    ```

1.  在`setup()`函数中初始化新的 LED，如高亮代码所示：

    ```kt
    void setup(){
     pinMode(LED, OUTPUT);
     pinMode(LED_TWO, OUTPUT);
     digitalWrite(LED, LOW);
     digitalWrite(LED_TWO, LOW);
    }
    ```

1.  在`executor()`函数中添加以下代码，使新的 LED 模仿我们已经编程的第一个 LED 的行为：

    ```kt
    switch(command) {
     case 0:
       digitalWrite(LED, LOW);
       break;
     case 1:
       digitalWrite(LED, HIGH);
       break;
     case 2:
     digitalWrite(LED_TWO, LOW);
     break;
     case 3:
     digitalWrite(LED_TWO, HIGH);
     break;
     default:
      // noop
       break;
    }
    ```

1.  更改文件顶部的配件描述符，以更新草图版本：

    ```kt
    char versionNumber[] = "0.2.0";
    ```

更改版本号总是一个你应该注意的好习惯。在我们的案例中，这也是一个要求，因为我们必须通知 Android 硬件行为已经改变。正如你在第二章，*了解你的工具*中看到的，当 Android 和 Arduino 中定义的版本不匹配时，Android 应用程序将不会与微控制器通信，这防止了意外的行为，特别是在硬件更改时。实际上，如果我们再次部署新的草图，可以看到 Android 将找不到任何可用的应用程序来管理配件。

最后一步，让原型再次工作，是更新 Android 应用程序，从其用户界面和逻辑开始，使其能够管理新设备。为了实现这个目标，我们应该采取以下步骤：

1.  在`res/layout/activity_light_switch.xml`文件中，在`firstLed`声明下方添加一个新的开关按钮：

    ```kt
    <Switch
     android:layout_width="wrap_content"
     android:layout_height="wrap_content"
     android:text="LED 3"
     android:id="@+id/secondLed"
     android:onClick="switchLightTwo"/>
    ```

1.  在类的顶部`LightSwitch`活动中添加以下声明，以存储第二个 LED 的状态：

    ```kt
    private boolean mSwitchLed = false;
    private boolean mSwitchLedTwo = false;

    ```

1.  在`switchLight()`方法下方添加以下代码，根据草图开关案例控制第二个 LED：

    ```kt
    public void switchLightTwo(View v) {
     mSwitchLedTwo = !mSwitchLedTwo;
     int command = mSwitchLedTwo ? 3 : 2;
     mManager.writeSerial(command);
    }
    ```

1.  在`res/xml/`下的`usb_accessory_filter.xml`描述符文件中更新新的硬件版本：

    ```kt
    <resources>
     <usb-accessory
     version="0.2.0"
     model="LedLamp"
     manufacturer="Example, Inc."/>
    </resources>
    ```

我们正在匹配草图的版本，以便 Android 知道这个应用程序可以再次管理连接的配件。部署新应用程序后，我们可以使用原型来打开和关闭两个连接的 LED。

# 开发一个诊断模式。

拥有一个可工作的原型后，是时候添加一个功能来测试我们的电路了。即使我们很想动手写代码，但首先需要模拟一个物理损坏，这个损坏会在原型中引起故障。因为不想真正损坏我们的 LED 灯，我们可以更改电路元件来复现异常。

实际上，我们可以模拟连接到引脚 3 的电阻器一条腿断裂的情况。如果发生这种情况，电路会被切断，这会阻止电流流过 LED 灯。为了在面包板上复现这个问题，我们可以简单地移除第一个电阻器，如下一个图表中所示：

![开发诊断模式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_03_02.jpg)

现在我们已经模拟了第一个硬件故障。如果我们打开 Android 应用程序并使用开关，可以看到第二个 LED 灯按预期工作，而第一个停止工作。然而，由于软件组件对内部发生的情况一无所知，所以它们没有注意到任何问题。如果出现这样的问题，我们会感到迷茫，因为我们在不知道应该将注意力集中在哪个部分来查找故障的情况下，开始进行软件和硬件调试。

当软件出现问题时，我们通常会使用调试器。不幸的是，当处理电路问题时，我们没有太多的工具，可能需要自己实现一些功能。一个好的起点是给原型添加一个功能，使其能够通过**诊断**模式自我调试。这个模式应该*模拟并模仿我们电路的真实行为*，但要以受控的方式进行。诊断模式对于识别原型中与软件错误无关的异常原因非常有帮助。

### 提示

诊断模式是我们寻找异常应该遵循的第一步。然而，当我们发现硬件故障时，应该开始使用其他工具，比如一个能够测量电压、电流和电阻的*万用表*。

在我们开始在草图上实现这个模式之前，需要连接一个*按钮*，我们将用它来启用诊断模式。我们需要将这个组件添加到我们的面包板上，如下一个图表的左侧部分所示：

![开发诊断模式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_03_03.jpg)

按照图表所示，将组件添加到面包板的步骤如下：

1.  将按钮添加到面包板的中间，使得同一垂直线上的腿不要连接。

1.  将按钮的左腿连接到+5V 引脚。

1.  将按钮的右腿连接到引脚 4。

1.  将一个*10 KOhm*电阻的一侧连接到按钮的右腿，另一侧连接到电源总线的负线。

通过这些连接，当我们按下按钮时，我们从引脚 4 读取数字信号，因为*电流会选择电阻较小的路径*，就像水一样。在我们的案例中，机械开关将在+5V 和 4 引脚之间建立连接，并且由于这条路径的电阻远小于地线中的*10 KOhm*，UDOOb 将读取这个电压差并将其转换为数字信号。当开关打开时，唯一的路径是引脚 4 和地线，因此 UDOOb 不会读取到电压差。这使我们能够知道开关是否被按下。

## 编写第一个测试

既然我们已经有了一个物理硬件开关，我们需要在用户按下按钮时激活诊断模式。为了检测按钮按下，我们应该按照以下步骤更改草图：

1.  在 ADK 初始化之后，添加突出显示的声明：

    ```kt
    ADKadk(&Usb, manufacturer, model, accessoryName, versionNumber, url, serialNumber);
    int reading = LOW;
    int previous = LOW;
    long lastPress = 0;

    ```

    我们需要每次读取阶段的按钮状态，这样我们就可以在当前和之前的读取期间保存状态。`lastPress`变量将包含上次按下按钮的时间戳。我们将按钮状态设置为`LOW`，因为我们认为没有电流流过按钮，这意味着它没有被按下。

1.  在草图的顶部，定义以下类似对象的宏：

    ```kt
    #define LED_TWO3
    #define BUTTON 4
    #define DEBOUNCE 200

    ```

    我们设置按钮引脚 4 和 DEBOUNCE 值，该值表示在代码开始再次评估按钮按下之前应经过的毫秒数。使用这个阈值是必要的，因为它防止读取到错误的阳性结果。如果我们省略这部分，当按钮被按下时，草图将检测到数千次读数，因为 UDOOb 的读取阶段比我们松开按钮的反应要快。这个值称为**消抖阈值**。

1.  在`setup()`函数中按如下配置按钮引脚模式：

    ```kt
    pinMode(LED_TWO, OUTPUT);
    pinMode(BUTTON, INPUT);

    ```

1.  将`loop()`函数的内容移动到一个名为`readCommand()`的新函数中，使其与以下内容相匹配：

    ```kt
    void readCommand() {
     Usb.Task();
     if (adk.isReady()) {
       adk.read(&bytesRead, BUFFSIZE, buffer);
       if (bytesRead> 0) {
         executor(buffer[0]);
      }
     }
    }
    ```

1.  在空的`loop()`函数中，我们应该添加以下代码进行读取阶段：

    ```kt
    void loop(){
      // Reads the digital signal from the circuit
     reading = digitalRead(BUTTON);
      // Checks the button press if it's outside a
      // debounce threshold
     if (reading == HIGH && previous == LOW &&millis() - lastPress>DEBOUNCE) {
       lastPress = millis();
        // Visual effect prior to diagnostic activation
       digitalWrite(LED, HIGH);
       digitalWrite(LED_TWO, HIGH);
       delay(500);
       digitalWrite(LED, LOW);
       digitalWrite(LED_TWO, LOW);
       delay(500);
       startDiagnostic();
     }
     previous = reading;
     readCommand();
    }
    ```

    我们使用内置的`digitalRead()`函数存储按钮的值，该函数抽象了从所选引脚读取电压差的复杂性。然后，我们检查当前状态是否与之前不同，这样我们就能确定按钮正是在这一刻被按下。

    然而，我们还需要检查自按下按钮以来是否超过了消抖阈值。我们使用内置的`millis()`函数，它返回自 UDOOb 板开始当前程序以来的毫秒数。

    如果捕捉到按下按钮的事件，我们设置`lastPress`值，并提供视觉反馈以通知用户诊断模式即将启动。无论如何，我们都会保存先前的按钮状态，并继续执行标准操作。

    ### 提示

    有时诊断模式需要激活和停用阶段。在我们的案例中，我们简化了流程，使得诊断模式仅在按下按钮后运行一次。在其他项目中，我们可能需要一个更复杂的激活机制，可以将其隔离在独立函数中。

1.  作为最后一步，按照以下方式实现`startDiagnostic()`函数：

    ```kt
    void startDiagnostic() {
     // Turn on the first LED
     executor(1);
     delay(1000);
     executor(0);
     // Turn on the second LED
     executor(3);
     delay(1000);
     executor(2);
     // Turn on both
     executor(1);
     executor(3);
     delay(1000);
     executor(0);
     executor(2);
    }
    ```

    诊断功能应该模仿我们电路的所有或几乎所有可能的行为。在本例中，我们打开和关闭第一个和第二个 LED，作为最后的测试，我们同时为它们供电。在诊断模式下，使用内部函数来复现电路动作非常重要。这有助于我们测试`executor()`函数的输入，确保我们已经映射了 Android 应用程序发送的所有预期输入。

既然我们已经有了诊断功能，我们必须再次部署 LedLamp 草图，并按下按钮开始诊断。如预期的那样，由于虚拟损坏的电阻器，只有一个 LED 会亮起。现在我们可以重新连接电阻器，并启动诊断模式，以测试 LED 连接是否已修复。

# 总结

在本章中，我们深入探讨了硬件测试，以提高我们项目的质量。我们发现这个过程非常有价值，因为通过这种方法，我们可以将硬件故障与软件错误区分开来。

我们在之前的原型中添加了另一个 LED，以便我们可以从 Android 应用程序控制多个设备。然后，我们在其中一个电子组件中模拟了一个硬件故障，从电路中移除一个电阻器以产生一个受控的异常。这促使我们编写了自己的诊断模式，以便快速找到这类故障。

第一步是为我们的原型添加一个按钮，我们可以使用它来启动诊断模式，然后我们利用这个功能模拟所有可能的电路行为，以便轻松找到损坏的电阻器。

在下一章中，我们将从零开始构建一个新原型，它能够通过一组新的电子组件从环境中收集数据。我们还将编写一个 Android 应用程序，能够读取草图发送的这些值，并可视化处理后的数据。


# 第四章：使用传感器倾听环境

当我们构建原型时，希望为最终用户提供最佳的交互体验。有时，我们构建的实际应用没有任何人为交互，但它们只是监听环境以收集数据并决定要做什么。无论我们的原型是什么，如果我们想要读取和理解人类行为或环境变化，我们需要使用一组新的电子组件：**传感器**。

每次我们构建物理应用时，都必须牢记，我们的项目越复杂，就越有可能需要添加传感器来实现所需的交互。

在本章中，我们将从零开始构建一个能够感知我们的心跳并将结果发布到我们的安卓应用程序中的真实应用。

在本章中，我们将涵盖以下主题：

+   使用环境传感器进行工作

+   构建心跳监测器

+   从传感器收集数据

+   从安卓应用程序展示收集的数据

# 使用环境传感器进行工作

在电子学中，传感器是构建来检测特定物质或粒子属性*任何变化*的组件。当发生任何变化时，传感器提供一个电压变化，可以改变其他电子组件的电流流动和行为。如果微控制器连接到传感器，它可以根据运行程序决定采取不同的行动。

传感器可以检测许多*属性*的变化，如热辐射、湿度、光线、无线电、声波等。当我们在项目中使用传感器时，必须选择一个特定的属性进行监听，然后需要读取并管理电压的变化。有时，为了执行检查，我们需要将这些电学变化转换为其他测量单位，如米或温度度数。在其他时候，我们可能会使用更复杂的传感器，这些传感器已经为我们完成了全部或部分的转换。例如，如果我们正在构建一个机器人探测器，可能需要使用传感器来检测与物体的距离，以避开任何房间障碍。在这种情况下，我们将使用基于雷达或声纳原理相似的*超声波传感器*。它发射高频声波并评估接收到的回声。通过分析发送和接收信号回声之间的时间间隔，我们可以确定与物体的距离。

实际上，在一个通用的草图中，我们读取的是从传感器收到信号回声之前经过的微秒数。为了使这些值更有用并找到正确的距离，我们可能需要在草图内部编写一个微秒到厘米或英寸的转换器。

然而，只有在我们了解传感器的工作原理以及信号每微秒传播了多少厘米或英寸的情况下，这才可能实现。幸运的是，我们可以从组件制造商发布的文档中找到这些信息，这个文档被称为**数据手册**。有了这些知识，我们可以轻松地将所有探测到的值转换为我们要寻找的内容。当我们完成本章的原型后，可以查看 URL [`arduino.cc/en/tutorial/ping`](http://arduino.cc/en/tutorial/ping)，其中包含了一个关于如何使用超声波传感器以及如何轻松地将检测到的信号转换为不同测量单位的示例。

# 构建心跳监测器

在前面的章节中，我们构建了第一个配备 LED 执行器的原型，用以改变周围环境，并通过内部 ADK 通信使 Android 应用程序控制 LED 的行为。我们已经看到传感器对于提高我们原型的交互性非常有帮助，我们可能想要将这项新功能添加到之前的项目中。实际上，由于我们使用的是一个能够发光的组件，我们可能会考虑添加一个外部光传感器，以便微控制器可以根据环境光线来开关 LED。

这只是一个关于如何使用光传感器的示例。实际上，我们必须牢记每个传感器都可以以不同的方式使用，我们的任务是要找到检测值与物理应用目标之间的相关性。我们绝不应该仅限于使用传感器的主要用途，正如我们将在心跳监测器中看到的那样。

## 创建带有光传感器的电路

与之前的原型类似，心跳监测器由两部分组成。第一部分是电路和草图，应该从光传感器收集数据并将其转换为代表**每分钟节拍数**（**bpm**）的值。第二部分是 Android 应用程序，它会在屏幕上显示我们心率计算出的值。

### 注意

即使这个原型可能取得不错的效果，但用自制的原型用于医疗原因是不可取的。光敏电阻仅用于演示，*不应*用于任何医疗目的。

对于这个物理应用，我们将使用**光敏电阻**作为光传感器的一部分。光敏电阻，也称为**光依赖电阻器**（**LDR**），其工作原理与之前原型中使用的传统电阻类似，但在提供的电阻方面略有不同。实际上，它的电阻根据测量的光照强度而变化，如果我们监测这个值，可以轻松计算出环境强度是在增加还是减少。我们还使用了一个*鲜红色*的 LED，它不同于之前使用的 LED，因为其亮度足以让光线透过我们的皮肤。

我们的目标是创建一个电路，我们可以将食指的一侧放在光敏电阻的顶部，另一侧是明亮的 LED。这样，一部分光线会穿过我们的手指，并被光敏电阻检测到。在每次心跳时，沿着动脉的血压力波会向外移动，增加我们的血量。当光线穿过我们的组织时，这种血量变化会改变落在传感器上的光线量。因此，当我们看到探测值中出现中等到高度变化时，这很可能是我们的心跳。

为了开始构建我们的原型，我们需要将光敏电阻放入面包板中，以便我们可以实现以下电路图：

![使用光传感器创建电路](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_04_01.jpg)

按照以下步骤操作，以实现前面的电路图：

1.  光敏电阻的腿可能太长。使用电子元件剪钳将腿剪短，最多 1.5cm。这不是必须的，但可能会简化原型的使用。

1.  将 UDOO 的+3.3V 引脚连接到面包板的第一行。确保不要连接+5V 电源引脚，因为在连接过程中可能会损坏电路板。

1.  在电路板上放置一个*10 KOhm*电阻，并将其连接到+3.3V 引脚；我们还需要将另一端连接到模拟输入 A0 引脚。

1.  将光敏电阻连接到电阻和 A0 引脚的同一列；第二个引脚应连接到电源总线的负线。

    ### 提示

    光敏电阻的作用与其他电阻一样，所以在这一步我们连接哪一端并不重要，因为*它们没有极性*。

1.  将 UDOO 的地线连接到电源总线的负线。

通过这些步骤，我们构建了一个由两个电阻组成的**电压分压器**电路。这类电路根据电阻值产生一个输入电压的分数作为输出电压。这意味着，由于电阻值会随光照强度变化而变化，电压分压器输出的电压也会随光照变化。这样，电路板可以检测到这些变化，并将其转换为一个 0 到 1023 之间的数值。换句话说，当光敏电阻处于阴影中时，我们读取到一个高值；而当它处于光照中时，我们读取到一个低值。由于我们将*10 KOhm*电阻连接到+3.3V 引脚，我们可以认为这个电压分压器是使用了一个**上拉**电阻构建的。

### 提示

电压分压器在许多电子电路中经常使用。你可以在[`learn.sparkfun.com/tutorials/voltage-dividers`](https://learn.sparkfun.com/tutorials/voltage-dividers)找到关于这类电路其他应用的信息。

为了完成我们的原型，我们不得不将高亮 LED 添加到电路中。然而，因为我们需要将 LED 放在手指的另一侧，我们不能直接将组件连接到我们的面包板上，但我们需要使用一对*鳄鱼夹*。作为第一步，我们需要按照以下电路图扩展电路：

![使用光传感器创建电路](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_04_02.jpg)

按照以下步骤实现前面的电路图：

1.  将 UDOOU +5V 电源引脚连接到电源总线的正线上。

1.  在面包板上添加一个*220 欧姆*电阻，并将一个引脚连接到电源总线的负线上。

1.  将电线连接器的一边接到*220 欧姆*电阻的另一引脚上。

1.  将电线连接器的一边接到电源总线的正线上。

1.  将第一个鳄鱼夹的一边连接到连接到电源总线正线的导线上。

1.  将第二个鳄鱼夹的一边连接到电阻器的导线上。

1.  将延长+5V 引脚的鳄鱼夹连接到 LED 的长腿上。

    ### 注意

    在进行下一步之前，请记住你正在使用一个非常亮的 LED。你应该避免将其直接对准你的眼睛。

1.  将延长电阻和接地连接的鳄鱼夹连接到 LED 的短腿上。

如果所有连接都设置好了，LED 应该会亮起，我们可以将其作为原型的一个活动部分。需要记住的一件事是，鳄鱼夹的金属端头*绝对不能相互接触*，否则电路将停止工作，一些组件可能因为*短路*而损坏。

# 从草图中收集数据

既然我们已经有一个工作的电路，我们应该开始编写草图以从光传感器收集数据。然后我们应该分析这些结果，考虑一个将读数转换为心跳计数的算法。我们应该开始一个新的草图，并添加以下步骤：

1.  在草图顶部添加以下声明：

    ```kt
    #define SENSOR A0
    #define HEARTBEAT_POLL_PERIOD50
    #define SECONDS 10
    constint TIMESLOTS = SECONDS * 1000 / HEARTBEAT_POLL_PERIOD;
    int sensorReading = 0;
    ```

    我们定义了一个类似对象的宏`SENSOR`，值为`A0`，这是我们将用于模拟读数的引脚。我们设置`HEARTBEAT_POLL_PERIOD`以指定微控制器在连续传感器读数之间应该等待多少毫秒。使用`SECONDS`参数，我们定义了在处理和估计心率之前应该过去多少秒。实际上，我们将`SECONDS`乘以`1000`将这个值转换为毫秒，然后除以`HEARTBEAT_POLL_PERIOD`参数来定义`TIMESLOTS`常数。这个变量定义了我们应该循环读取阶段多少次以收集估计心率所需正确数量的读数。这样，我们在每个`TIMESLOTS`周期进行一次读取，当周期结束时，我们计算心率。最后一个变量`sensorReading`用于在每次循环迭代中存储传感器读数。

1.  在`setup()`函数中，添加串行端口的初始化，以便我们可以在 UDOOboard 和计算机之间打开通信：

    ```kt
    void setup() {
     Serial.begin(115200);
    }
    ```

1.  在草图的底部添加以下函数，通过串行端口打印读取的值：

    ```kt
    void printRawData() {
     sensorReading = analogRead(SENSOR);
     Serial.println(sensorReading);
    }
    ```

    我们使用内置的`analogRead`函数从模拟输入引脚读取传入数据。因为这些引脚是只读的，我们不需要在`setup()`函数中进行进一步配置或更改输入分辨率。

    ### 提示

    有时我们可能需要更好的模拟读取分辨率，范围在 0 到 4095 之间，而不是 0 到 1023。在这种情况下，我们应该使用`analogReadResolution`参数来改变分辨率。我们可以在官方文档中找到更多关于模拟输入分辨率的信息，地址是[`arduino.cc/en/Reference/AnalogReadResolution`](http://arduino.cc/en/Reference/AnalogReadResolution)。

    当读取完成时，我们在串行端口打印结果，这样我们就可以通过 Arduino IDE 串行监视器读取这些值。

1.  在主`loop()`函数中，为每个读取时隙添加`printRawData()`函数调用：

    ```kt
    void loop() {
     for (int j = 0; j < TIMESLOTS; j++) {
     printRawData();
     delay(HEARTBEAT_POLL_PERIOD);
     }
     Serial.println("Done!");
     delay(1000);
    }
    ```

    我们进行`TIMESLOTS`迭代是为了在 10 秒内获取读数，如之前定义的。所有读数完成后，我们在串行端口打印一条消息，并在重新开始读取前等待一秒。

    ### 提示

    一秒的延迟和**完成！**的消息仅证明读取周期正在正确工作。我们稍后会移除它们。

配置完毕后，我们可以上传草图并继续我们的第一次实验。将食指的底部放在光电阻上，同时将 LED 放在另一侧。

### 提示

为了获得更精细的读数，如果光电阻和 LED 的接触部分是指关节和指甲之间的部分会更好。

开始实验时，点击**串行监视器**按钮，当草图打印出**完成！**的消息时，我们将看到如下截图所示的一些数值：

![从草图收集数据](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_04_03.jpg)

这些是我们心跳期间光传感器捕捉到的绝对值。如果我们把一个完整的 10 秒迭代复制粘贴到 Microsoft Excel、Libre Office Calc 或 Numbers 表格中，我们可以绘制一个折线图，以更易于理解的形式查看给定结果：

![从草图收集数据](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_04_04.jpg)

我们可以看到，数值随时间变化，当发生心跳时，光传感器检测到光强的变化，这一事件导致图表中产生一个峰值。换句话说，我们可以假设每个峰值都对应一次心跳。下一步是改进我们的草图，以近似和转换这些数值，因为我们应该尝试去除读数错误和假阳性。主要思想是在每次迭代后收集固定数量的样本，以存储这次读数和上一次读数之间的差值。如果我们随着时间的推移存储所有差值，我们可以轻松找到读数趋势，并识别出我们读取峰值的时候。为了改进我们的算法，我们需要执行以下步骤：

1.  在草图的顶部添加以下变量：

    ```kt
    #define SECONDS 10
    #define SAMPLES 10

    constint TIMESLOTS = SECONDS * 1000 / HEARTBEAT_POLL_PERIOD;

    int sensorReading = 0;
    int lastReading = 0;
    int readings[SAMPLES];
    int i = 0;
    int delta = 0;
    int totalReading = 0;

    ```

    我们设置用于计算增量差值的`SAMPLES`数量。然后使用`lastReading`、`i`和`delta`变量分别存储上一次读数、用于迭代`readings`数组的当前索引，以及与上一次读数的当前差值。然后我们定义一个累加器来存储当前的读数总和。

1.  在`setup`函数中初始化`readings`数组：

    ```kt
    void setup() {
     Serial.begin(115200);

     for (int j = 0; j < SAMPLES; j++) {
     readings[j] = 0;
     }
    }
    ```

1.  在草图的底部添加`collectReads()`函数：

    ```kt
    void collectReads() {
     sensorReading = analogRead(SENSOR);
      delta = sensorReading - lastReading;
     lastReading = sensorReading;
     totalReading = totalReading - readings[i] + delta;
      readings[i] = delta;
     i = (i + 1) % SAMPLES;
    }
    ```

    在第一部分，我们将读取当前值并计算与上一次读数的差值。然后我们使用当前的`totalReading`和`readings`数组中存储的上一个差值来累加这个差值。现在我们可以用新的`delta`对象更新当前索引的`readings`数组，该索引在最后一行递增，并通过*模运算符*保持在界限内。

1.  在主`loop()`函数中，用新的`collectReads()`函数替换`printRawData()`函数调用，然后打印累积的值：

    ```kt
    for (int j = 0; j < TIMESLOTS; j++) {
     collectReads();
     Serial.println(totalReading);
      delay(HEARTBEAT_POLL_PERIOD);
    }
    ```

进行这些增强后，我们可以上传新的草图，并像之前一样重复进行实验：

1.  将你的食指放在光电阻和 LED 之间。

1.  在 Arduino IDE 上点击**串行监视器**。

1.  完成一个完整的 10 秒迭代。

1.  将这些值复制并粘贴到之前的电子表格中，并绘制条形图。我们应该避免包含前八个读数，因为它们与第一次迭代有关，而此时`readings`数组尚未初始化。

收集到的值产生了如下图表：

![从草图中收集数据](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_04_05.jpg)

在这些处理过的读数中，正负值之间会有波动，这种情况出现在我们攀登或下降之前看到的峰值时。有了这些知识，我们可以稍微改进一下算法，以便追踪攀登或下降阶段，并选择是丢弃读数还是将其计为一次心跳。要完成这部分，我们需要按照以下步骤添加以下代码：

1.  在草图的顶部添加这些声明：

    ```kt
    #define SECONDS 10
    #define POS_THRESHOLD 3
    #define NEG_THRESHOLD -3

    const int TIMESLOTS = SECONDS * 1000 / HEARTBEAT_POLL_PERIOD;
    const int PERMINUTE = 60 / SECONDS;
    int beats = 0;
    boolean hillClimb = false;

    ```

    我们定义了`POS_THRESHOLD`和`NEG_THRESHOLD`参数来设置我们丢弃值的区间边界，以避免误报。同时，我们还定义了一个`PERMINUTE`常数，以得知获取每分钟心跳数的乘数以及`beats`累加器。最后，我们设置了一个`hillClimb`变量，用来存储下一次读数是在上升阶段还是下降阶段。例如，`True`值意味着我们处于上升阶段。

1.  在草图的底部添加`findBeat()`函数：

    ```kt
    void findBeat() {
      if (totalReading<NEG_THRESHOLD) {
       hillClimb = true;
      }
      if ((totalReading>POS_THRESHOLD)&&hillClimb) {
       hillClimb = false;
        beats += 1;
      }
    }
    ```

    我们检查`totalReading`参数是否低于`NEG_THRESHOLD`参数，以确定我们是否处于峰值下降阶段。在这种情况下，我们将`hillClimb`变量设置为`True`。在最后的代码块中，我们检查是否超过了`POS_THRESHOLD`并且处于上升阶段。如果是这样，我们将`hillClimb`设置为`False`，并将此阶段变化计为一次心跳。如果我们查看之前的图表，通过前面的代码，我们可以轻松确定每次读数时我们处于哪个阶段，并且利用这些信息尽可能多地排除错误和误报。

1.  在草图的底部添加实用函数`calcHeartRate()`：

    ```kt
    int calcHeartRate() {
      return beats * PERMINUTE;
    }
    ```

1.  在主`loop()`函数中，添加以下代码以使用前面的函数，并在串行端口中打印心率及心跳数：

    ```kt
    for (int j = 0; j < TIMESLOTS; j++) {
     collectReads();
     findBeat();
      delay(HEARTBEAT_POLL_PERIOD);
    }
    Serial.print(calcHeartRate());
    Serial.print(" with: ");
    Serial.println(beats);
    beats = 0;
    delay(1000);
    ```

1.  再次上传草图并开始计算心跳。在串行监视器中，我们会注意到以下值：

    ```kt
    72 with: 12
    84 with: 14
    66 with: 11
    78 with: 13
    90 with: 15
    84 with: 14
    ```

对我们草图的最后改进是添加 ADK 功能，将计算出的心跳发送到我们的 Android 应用程序。在草图的顶部，添加以下*accessory descriptor*，它与我们之前原型中使用的基本相同：

```kt
#include <adk.h>
#define BUFFSIZE 128
char accessoryName[] = "Heartbeat monitor";
char manufacturer[] = "Example, Inc.";
char model[] = "HeartBeat";
char versionNumber[] = "0.1.0";
char serialNumber[] = "1";
char url[] = "http://www.example.com";
uint8_t buffer[BUFFSIZE];
uint32_tbytesRead = 0;
USBHostUsb;
ADKadk(&Usb, manufacturer, model, accessoryName, versionNumber, url, serialNumber);
```

作为最后一步，在主`loop()`函数中，将草图执行包裹在 ADK 通信中，并移除所有的串行打印以及最后的 1 秒延迟：

```kt
void loop() {
Usb.Task();
  if (adk.isReady()) {
    // Collect data
    for (int j = 0; j < TIMESLOTS; j++) {
      collectReads();
      findBeat();
      delay(HEARTBEAT_POLL_PERIOD);
    }
  buffer[0] = calcHeartRate();
 adk.write(1, buffer);
  beats = 0;
 }
}
```

这样，心率监测器将在 ADK 通信启动并运行时开始工作，我们将使用`adk.write()`函数将计算出的心率发送回 Android 应用程序。

# Android 用于数据可视化

既然我们的物理应用程序已经有了一个完全工作的电路，可以通过对光传感器的非常规使用来读取心率，我们应该用 Android 应用程序来完成原型设计。从 Android Studio 开始，启动一个名为*HeartMonitor*的新 Android 项目，使用**Android API 19**。在引导过程中，选择一个名为*Monitor*的**空白活动**。

我们从用户界面开始编写应用程序，并且需要思考和设计活动布局。为了这个应用程序的目的，我们编写了一个简单的布局，包含一个标题和一个文本组件，每次 Android 从草图中接收到心跳估算时，我们都会更新这个组件。这个布局可以通过以下步骤实现：

1.  在`res/values/`下的`styles.xml`文件中，添加这些颜色声明并替换标准主题：

    ```kt
    <color name="sulu">#CBE86B</color>
    <color name="bright_red">#A30006</color>

    <style name="AppTheme" parent="Theme.AppCompat">
    <!-- Customize your theme here. -->
    </style>
    ```

    `AppTheme`参数继承了`Theme.AppCompat`参数，它指的是 Android 支持库中可用的*Holo Dark*主题。我们还创建了绿色和红色，稍后将在我们的应用程序中使用。

1.  在`res/layout/`下的`activity_monitor.xml`文件中，用高亮显示的更改替换根布局：

    ```kt
    <LinearLayout

     android:orientation="vertical"
     android:layout_width="match_parent"
     android:layout_height="match_parent"
     android:paddingLeft="@dimen/activity_horizontal_margin"
     android:paddingRight="@dimen/activity_horizontal_margin"
     android:paddingTop="@dimen/activity_vertical_margin"
     android:paddingBottom="@dimen/activity_vertical_margin"
     tools:context=".Monitor">
    </LinearLayout>

    ```

1.  使用以下代码更改前一个布局中包含的`TextView`参数，以拥有一个更大的绿色标题，显示应用程序名称：

    ```kt
    <TextView
     android:text="Android heart rate monitor"
     android:gravity="center"
     android:textColor="@color/sulu"
     android:textSize="30sp"
     android:layout_width="match_parent"
     android:layout_height="wrap_content" />
    ```

1.  在根布局中嵌套一个新的`LinearLayout`：

    ```kt
    <LinearLayout
     android:layout_width="match_parent"
     android:layout_height="wrap_content"
     android:layout_marginTop="30sp"
     android:gravity="center">
    </LinearLayout>
    ```

    我们从上一个元素设置一个边距，使用所有可用空间将内部组件放置在居中位置。

1.  添加以下 TextView 以显示标签和占位符，占位符将包含计算出的每分钟节拍数：

    ```kt
    <TextView
     android:text="Current heartbeat: "
     android:textColor="@color/sulu"
     android:textSize="20sp"
     android:layout_width="wrap_content"
     android:layout_height="wrap_content"/>

    <TextView
     android:id="@+id/bpm"
     android:text="0 bpm"
     android:textColor="@color/bright_red"
     android:textSize="20sp"
     android:layout_width="wrap_content"
     android:layout_height="wrap_content"/>
    ```

1.  在活动类中获取小部件，以便在每次读取后更改它。在`Monitor`类的顶部添加以下声明：

    ```kt
    private TextViewmBpm;
    ```

1.  在`onCreate()`回调中通过高亮代码找到由`bpm`标识符标识的视图：

    ```kt
    @Override
    protected void onCreate(Bundle savedInstanceState) {
     super.onCreate(savedInstanceState);
     setContentView(R.layout.activity_monitor);
     mBpm = (TextView) findViewById(R.id.bpm);
    }
    ```

在没有进一步配置的情况下，以下是获得的布局：

![用于数据可视化的 Android](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_04_06.jpg)

现在应用程序布局已完成，我们可以继续设置 ADK 通信。

## 设置 ADKToolkit

就像我们对第一个原型所做的那样，我们需要重新编写所有的 ADK 类和方法以发送和接收数据。然而，由于软件开发的良好原则是“不要重复自己”（DRY），我们将使用一个外部库，它为所有需要的功能提供了高抽象。这个库被称为**ADKToolkit**，它是原生 ADK API 的封装，可以防止我们在每次开始新项目时重复代码。我们可以在[`docs.adktoolkit.org`](http://docs.adktoolkit.org)找到更多关于该库的信息和示例。

首先需要做的是将 ADKToolkit 库添加到应用程序依赖项中。在用 Android Studio 构建的项目中，有两个名为`build.gradle`的不同文件。这些文件包含了与 Gradle 构建系统相关的所有配置，其中一个与全局项目相关，另一个与我们正在构建的应用程序模块相关。尽管这两个文件都包含依赖项列表，但我们应该将库添加到位于`app`文件夹中的与应用程序模块相关的`build.gradle`文件中。如果我们使用 Android Studio 界面左侧可用的**Project**面板，必须双击**build.gradle (Module: app)**脚本。在这个文件中，我们需要在`dependencies`块中添加高亮显示的代码：

```kt
dependencies {
  compile fileTree(dir: 'libs', include: ['*.jar'])
 compile 'com.android.support:appcompat-v7:21.0.3'
 compile 'me.palazzetti:adktoolkit:0.3.0'
}
```

现在我们可以点击闪存消息中可用的**Sync Now**按钮，并等待 Gradle 完成同步过程，这个过程会自动下载 ADKToolkit 库。

正如在第二章，*了解你的工具*中所做的那样，我们应该更新 Android 清单文件，以注册具有正确意图过滤器和配件描述符的应用程序。要继续进行 ADK 配置，请遵循以下提醒：

1.  在`res/xml/`目录下创建配件过滤器文件`usb_accessory_filter.xml`，并使用以下代码：

    ```kt
    <resources>
     <usb-accessory
        version="0.1.0"
        model="HeartBeat"
        manufacturer="Example, Inc."/>
    </resources>
    ```

1.  在`AndroidManifest.xml`文件中添加 USB `<uses-feature>`标签。

1.  在`AndroidManifest.xml`文件的 Activity 块中，添加 ADK `<intent-filter>`和`<meta-data>`标签，以设置 USB 配件过滤器。

现在我们必须初始化 ADKToolkit 库以启用通信并开始读取处理后的数据。在`Monitor`类中，添加以下代码片段：

1.  在类的顶部声明`AdkManager`对象：

    ```kt
    private TextViewmBpm;
    private AdkManagermAdkManager;

    ```

1.  在`onCreate()`方法中添加`AdkManager`的初始化：

    ```kt
    mBpm = (TextView) findViewById(R.id.bpm);
    mAdkManager = new AdkManager(this);

    ```

    `AdkManager`是 ADKToolkit 库的主要类。为了初始化管理器实例，我们应该将当前上下文传递给它的构造函数，由于活动类从`Context`类继承，我们可以简单地使用`this`关键字传递实例。所有与 ADK 通信相关的功能都将通过`mAdkManager`实例来使用。

1.  重写`onResume()`和`onPause()`回调，以便在`Monitor`活动打开或关闭时开始和停止 ADK 连接：

    ```kt
    @Override
    protected void onResume() {
     super.onResume();
     mAdkManager.open();
    }

    @Override
     protected void onPause() {
     super.onPause();
     mAdkManager.close();
    }
    ```

    `mAdkManager`实例暴露了`close()`和`open()`方法，以便轻松控制配件连接。我们必须记住，在`onResume()`方法中打开 ADK 通信是一个要求，因为`AdkManager`的初始化不足以启用 Android 和 Arduino 之间的通道。

通过以上步骤，我们已经完成了 ADK 配置，现在可以开始编写接收草图数据的逻辑。

## 从 Android 进行连续数据读取

我们 Android 应用程序的主要概念是使用 ADKToolkit 对 UDOOboard 收集的数据进行连续读取。每次估算通过 OTG 串行端口写入时，我们需要读取这些值并更新 Android 用户界面，但在我们继续之前，我们需要对 Android 线程系统进行一些考虑。

当 Android 应用程序启动时，该应用程序的所有组件都在同一个进程和线程中运行。这称为**主线程**，它托管诸如当前前台`Activity`实例等其他组件。每当我们需要更新当前活动的任何视图时，我们应该在主线程中运行更新代码，否则应用程序将会崩溃。另一方面，我们必须记住，主线程中完成的任何操作都应该立即完成。如果我们的代码运行缓慢或执行阻塞操作（如 I/O），系统将会弹出**应用程序无响应**（**ANR**）对话框，因为主线程无法处理用户输入事件。

如果我们在主线程中运行连续读取，这种错误肯定会发生，因为我们应该在一个循环中查询光线传感器，这会导致每 10 秒发生阻塞 I/O 操作。因此，我们可以使用`ExecutorService`类来运行周期性的计划线程。在我们的案例中，我们将定义一个生命周期较短的线程，该线程将每隔 10 秒从上述调度程序中创建。

当计划线程从 OTG 串行端口读取数据完成后，它应该通过`Handler`类将接收到的消息传递给主线程。我们可以在官方 Android 文档中找到更多关于如何与主线程通信的信息和示例：

[在主线程中通信](https://developer.android.com/training/multiple-threads/communicate-ui.html)。

首先，我们应该通过以下步骤公开所有需要更新 Android 用户界面的方法：

1.  创建一个名为`OnDataChanges`的新 Java 接口，并添加以下方法：

    ```kt
    public interface OnDataChanges {
      void updateBpm(byte heartRate);
    }
    ```

    通过这段代码，我们定义了将在我们的`Handler`中使用的接口，以给定`heartRate`参数更新用户界面。

1.  在`Monitor`类中通过高亮代码实现接口：

    ```kt
    public class Monitor extends ActionBarActivity implements OnDataChanges {
      private TextViewmBpm;
      // ...
    ```

1.  在类的末尾编写以下代码，通过`updateBpm`方法更新 Android 用户界面：

    ```kt
    @Override
    public void updateBpm(byte heartRate) {
     mBpm.setText(String.format("%d bpm", heartRate));
    }
    ```

最后一个必需的步骤是实现我们的计划线程，从 Arduino 读取处理后的数据，并在用户界面中写入这些值。要完成这个最后的构建块，请执行以下步骤：

1.  在你的命名空间中创建一个名为`adk`的新包。

1.  在`adk`包中，添加一个名为`DataReader`的新类。

1.  在类的顶部，添加以下声明：

    ```kt
    private final static int HEARTBEAT_POLLING = 10000;
    private final static int HEARTBEAT_READ = 0;
    private AdkManager mAdkManager;
    private OnDataChanges mCaller;
    private ScheduledExecutorService mScheduler;
    private Handler mMainLoop;
    ```

    我们定义了心跳轮询时间和一个后面要使用的`int`变量，用于在我们的处理程序中识别发布的信息。我们还存储了`AdkManager`参数和`caller`活动的引用，分别用于 ADK 的`read`方法和`updateBpm`回调。然后我们定义了`ExecutorService`实现以及一个要附加到主线程的`Handler`。

1.  实现构造函数`DataReader`，以定义当主线程从后台线程接收到新消息时的处理消息代码。

    ```kt
    public DataReader(AdkManageradkManager, OnDataChangescaller) {
     this.mAdkManager = adkManager;
     this.mCaller = caller;
     mMainLoop = new Handler(Looper.getMainLooper()) {
        @Override
        public void handleMessage(Message message) {
          switch (message.what) {
            case HEARTBEAT_READ:
         mCaller.updateBpm((byte) message.obj);
              break;
          }
        }
      };
    }
    ```

    存储了`AdkManager`实例和`caller`活动引用之后，我们向应用程序的主 looper 附加一个新的`Handler`，该 looper 位于主线程中。我们应该重写`handleMessage`回调，以便检查用户定义的消息代码，以识别`HEARTBEAT_READ`消息。在这种情况下，我们使用接收到的`message`参数中附加的对象来调用`updateBpm`回调。

    ### 提示

    每个`Handler`都有自己消息代码的命名空间，因此你不需要担心你的`message.what`属性的可能值与其他处理程序发生冲突。

1.  在`DataReader`类的底部，添加以下实现了`Runnable`接口的私有类，以读取和发布传感器数据：

    ```kt
    private class SensorThread implements Runnable {
      @Override
      public void run() {
        // Read from ADK
       AdkMessage response = mAdkManager.read();
        // ADK response back to UI thread for update
        Message message = mMainLoop.obtainMessage(HEARTBEAT_READ, response.getByte());
       message.sendToTarget();
      }
    }
    ```

    当线程启动时，我们使用`AdkManager read`方法读取可用的数据。这个方法返回一个包含原始接收字节和一些用于解析响应的工具的`AdkMessage`实例；在我们的案例中，我们使用`getByte`方法获取第一个接收的字节。作为最后一步，我们应该通过主线程处理器发布收集到的值。然后我们使用`obtainMessage`方法创建一个`Message`实例，该方法将从处理器消息池中获取一条新消息。现在我们可以使用`sendToTarget`方法将消息派发给主线程。

1.  添加`DataReader start()`方法以启动定期生成线程的调度程序：

    ```kt
    public void start() {
      // Initialize threads
     SensorThread thread = new SensorThread();
      // Should start over and over publishing results

     Executors.newSingleThreadScheduledExecutor();
     mScheduler.scheduleAtFixedRate(thread, 0, HEARTBEAT_POLLING, TimeUnit.MILLISECONDS);
    }
    ```

    当我们从`Monitor`活动中调用这个方法时，`ExecutorService`参数将使用`newSingleThreadScheduledExecutor()`函数进行初始化。这将创建一个单线程的执行器，保证在任何给定时间执行的任务不会超过一个，尽管有轮询周期。作为最后一步，我们使用周期性调度程序每`HEARTBEAT_POLLING`毫秒运行一次我们的`SensorThread`。

1.  在`DataReader`类中添加`stop()`方法，以停止调度程序生成新线程。在我们的案例中，我们只需使用执行器的`shutdown()`方法：

    ```kt
    public void stop() {
      // Should stop the calling function
    mScheduler.shutdown();
    }
    ```

1.  现在我们应该回到`Monitor`类，在活动生命周期内启动和停止我们的线程调度程序。在`Monitor`类的顶部添加`DataReader`声明：

    ```kt
    private AdkManager mAdkManager;
    private DataReader mReader;

    ```

1.  在`onResume()`和`onPause()`活动的回调中启动和停止读取调度程序，正如以下高亮代码所示：

    ```kt
    @Override
    protected void onResume() {
     super.onResume();
     mAdkManager.open();
     mReader = new DataReader(mAdkManager, this);
     mReader.start();
    }
    @Override
    protected void onPause() {
     super.onPause();
     mReader.stop();
     mAdkManager.close();
    }
    ```

没有其他事情可做，我们的原型已经准备好部署。现在我们可以将食指放在光敏电阻和 LED 之间，同时查看 Android 应用程序，结果每 10 秒更新一次。

# 改进原型

即使原型获得了良好的结果，我们可能希望获得更准确的读数。为物理应用获得更好改进的一个方法是，为光敏电阻和明亮的 LED 提供一个更好的外壳。实际上，如果我们能够移除环境光线，并在读取时使这两个组件更加稳定，我们就能获得很大的改进。

实现此目标的一个好方法是使用一个容易获得的组件：*一个木制销钉*。我们可以一次性钻好销钉，使孔对齐。这样，我们可以将光敏电阻放在一个孔中，而 LED 在另一个孔中。其余的组件和面包板本身保持不变。以下插图显示了一个木制销钉，用于容纳这两个组件：

![改进原型](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/gtst-udoo/img/1942OS_04_07.jpg)

另一个改进是改变和调整草图中可用的算法参数。改变间隔和样本数量可能会获得更好的结果；然而，我们必须记住，这些更改也可能导致读数变得更糟。以下是我们可以更改的一些算法参数的集合：

```kt
#define SAMPLES 10
#define POS_THRESHOLD 3
#define NEG_THRESHOLD -3
#define HEARTBEAT_POLL_PERIOD 50
#define SECONDS 10
```

例如，如果我们发现光敏电阻在 50 毫秒的`HEARTBEAT_POLL_PERIOD`对象宏下工作效果不佳，我们可能会尝试使用更常见的时序，如 100 毫秒或 200 毫秒。

# 总结

在本章中，我们探讨了使用外部传感器来增强我们的物理应用功能。我们了解了传感器的工作原理，并查看了一个检测距离和物体接近程度的示例。

作为第一步，我们获取了一些关于心跳生物过程的信息，并发现了一个光敏电阻与一个明亮的 LED 如何帮助我们检测心率。我们使用第一个心率监测原型进行了一些初步实验，并收集了各种绝对值，我们后来将这些值绘制成图表。在初次分析后，我们发现每个峰值可能是一次心跳，这促使我们通过一个能够在选定间隔内计算读数差值的算法来增强读取阶段。

利用之前的数值，我们绘制了一张新图表，并发现我们应该检查相位变化以找到可能的心跳。实际上，我们最后的工作是添加一个功能，用于计算心率，并通过 ADK 通信协议将其发送回 Android 应用。

为了展示之前的结果，我们为 Android 应用创建了一个布局。我们配置并使用了 ADKToolkit 库以简化通信过程。通过一个`ScheduledExecutorService`实例，该实例启动短生命周期的线程进行数据采集，我们在自定义用户界面中设置了处理后的心率。在本章末尾，我们探讨了在进入下一章之前，如何通过一些建议来改进我们的工作原型。

在下一章中，我们将构建另一个物理应用，它将使用外部组件来控制 Android 应用。它将利用一些 Android 原生 API，以简单的方式实现一些没有复杂硬件和草图就无法完成的功能。
