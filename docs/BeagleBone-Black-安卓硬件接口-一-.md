# BeagleBone Black 安卓硬件接口（一）

> 原文：[`zh.annas-archive.org/md5/8608566C49BFB6DF1A157117C5F5286A`](https://zh.annas-archive.org/md5/8608566C49BFB6DF1A157117C5F5286A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

基于 Android 的设备的广泛普及引发了开发针对 Android 的软件应用（或应用）的极大兴趣。幸运的是，一个功能强大且成本低的硬件平台——BeagleBone Black，可以让你快速轻松地在真实硬件上测试你的应用。BeagleBone Black 专注于小型化以及广泛的扩展和接口机会，以非常低的价格提供了大量的处理能力。它还为应用开发者提供了曾经只有硬件黑客专家或昂贵的硬件开发套件拥有者才有的机会：编写能够与自定义硬件电路交互的 Android 应用。

无论你是硬件接口的新手还是经验丰富的专家，*针对 BeagleBone Black 的 Android*为你提供了开始创建与自定义硬件直接通信的 Android 应用所需的工具。从一开始，这本书将帮助你理解 Android 独特的硬件接口方法。你将安装和定制 Android，构建与你的 BeagleBone Black 平台接口的电路，并构建使用该硬件与外部世界通信的本地代码和 Android 应用。通过逐章顺序地工作示例，你将学会如何创建能够同时与多个硬件组件接口的多线程应用。

一旦你探索了本书中的各种示例电路和应用，你将走在成为 Android 硬件接口专家的道路上！

# 本书涵盖的内容

第一章，*Android 和 BeagleBone Black 的介绍*，将指导你完成将 Android 操作系统安装到你的 BeagleBone Black 开发板上的过程。同时，还提供了你在这本书中进行活动时需要用到的一系列硬件组件清单。

第二章，*与 Android 接口*，向你介绍了 BeagleBone Black 的硬件和 Android 硬件抽象层的多个方面。它描述了如何对你的开发环境和安装在 BeagleBone Black 上的 Android 进行一些修改，以便 Android 应用能够访问 BeagleBone Black 的各种硬件功能。

第三章，*使用 GPIO 处理输入和输出*，指导你构建你的第一个硬件接口电路，并解释了一个基本的 Android 应用与它通信的细节。这是你向构建更复杂交互的与 BeagleBone Black 外部世界交互的应用迈出的第一步。

第四章，*使用 I2C 存储和检索数据*，扩展了第三章，*使用 GPIO 处理输入和输出*的基础知识，并解释了应用程序内部如何使用异步后台线程与硬件通信。它指导你构建一个与非易失性存储芯片接口的电路，以及与该芯片交互的应用程序的实现细节。

第五章，*使用 SPI 与高速传感器接口*，探讨了如何创建执行高速接口的应用程序，使用温度和压力传感器与 BeagleBone Black 进行接口。

第六章，*创建一个完整的接口解决方案*，将之前章节关于 GPIO，I2C 和 SPI 接口的知识结合起来，创建一个单一的复杂硬件和软件解决方案，该方案使用这三种接口来响应来自外部世界的硬件事件。

第七章，*未来的方向*，描述了 BeagleBone Black 上更多可用的硬件接口，解释如何创建更永久的 Android 硬件/软件解决方案，并为你提供一些未来探索的项目想法。

# 你需要为这本书准备什么

我们在这本书中提供了假设你使用的是基于 Windows 或 Linux 的计算机的指导。如果你已经是 Android 应用开发者，你可能已经安装了所需的所有软件应用。我们期望你已经安装了 Eclipse ADT 和 Android NDK，尽管我们在第二章，*与 Android 接口*的开始部分提供了这些工具的下载链接，以防你还没有安装。 第一章，*Android 和 BeagleBone Black 介绍*，提供了实现书中使用的示例接口电路所需的各种硬件组件和设备列表。

# 本书的目标读者

如果你是一名想要开始实验 BeagleBone Black 平台硬件功能的 Android 应用开发者，那么这本书非常适合你。具备基本的电子原理知识会有所帮助，我们期望读者具备使用 Eclipse ADT 和 Android SDK 开发 Android 应用的基本知识，但不需要有先前的硬件经验。

# 编写约定

在这本书中，你会发现多种文本样式，用于区分不同类型的信息。以下是一些样式示例及其含义的解释。

文本中的代码字、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 处理程序会如下所示："这样可以避免在`init.{ro.hardware}.rc`文件中包含一个特殊的模块和一个加载命令的覆盖层。"

代码块设置如下：

```java
extern int openFRAM(const unsigned int bus, const unsigned int address);
extern int readFRAM(const unsigned int offset, const unsigned int 
    bufferSize, const char *buffer);
extern int writeFRAM(const unsigned int offset, const unsigned int 
    const char *buffer);
extern void closeFRAM(void);
```

当我们希望引起你对代码块中某个特定部分的注意时，相关的行或项目会以粗体显示：

```java
public void onClickSaveButton(View view) {
   hwTask = new HardwareTask();
 hwTask.saveToFRAM(this); 
}

public void onClickLoadButton(View view) {
   hwTask = new HardwareTask();
 hwTask.loadFromFRAM(this);
}
```

命令行输入或输出内容如下所示：

```java
root@beagleboneblack:/ # i2cdetect -y -r 2

```

**新术语**和**重要词汇**以粗体显示。你在屏幕上看到的词，例如菜单或对话框中的，会在文本中以这种形式出现："如果用户再次点击**Sample**按钮，将实例化另一个`HardwareTask`实例。"

### 注意

警告或重要提示会以如下框中的形式出现。

### 提示

提示和技巧会以这种形式出现。

# 读者反馈

我们始终欢迎读者的反馈。告诉我们你对这本书的看法——你喜欢或不喜欢什么。读者的反馈对我们很重要，因为它帮助我们开发出你真正能从中获得最大收益的标题。

要向我们发送一般反馈，只需通过电子邮件`<feedback@packtpub.com>`，并在邮件的主题中提及书籍的标题。

如果你有一个有经验的主题，并且你对于写作或为书籍做贡献感兴趣，请查看我们在[www.packtpub.com/authors](http://www.packtpub.com/authors)的作者指南。

# 客户支持

既然你现在拥有了 Packt 的一本书，我们有一些事情可以帮助你最大限度地利用你的购买。

## 下载示例代码

你可以从你在[`www.packtpub.com`](http://www.packtpub.com)的账户下载你所购买的所有 Packt Publishing 图书的示例代码。如果你在其他地方购买了这本书，可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)注册，我们会将文件通过电子邮件直接发送给你。

## 勘误

尽管我们已经尽力确保内容的准确性，但错误仍然可能发生。如果你在我们的书中发现了一个错误——可能是文本或代码中的错误——如果你能向我们报告，我们将不胜感激。这样做，你可以避免其他读者感到沮丧，并帮助我们在后续版本中改进这本书。如果你发现任何勘误信息，请通过访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择你的书籍，点击**Errata Submission Form**链接，并输入你的勘误详情来报告。一旦你的勘误信息被验证，你的提交将被接受，并且勘误信息将被上传到我们的网站或添加到该标题下的现有勘误列表中。

要查看先前提交的勘误信息，请访问[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)，并在搜索字段中输入书名。所需信息将显示在**勘误**部分下。

## 盗版

在互联网上，盗版受版权保护的材料是所有媒体都面临的持续问题。在 Packt，我们非常重视保护我们的版权和许可。如果您在互联网上以任何形式遇到我们作品的非法副本，请立即提供位置地址或网站名称，以便我们可以寻求补救措施。

如果您发现疑似盗版材料，请通过`<copyright@packtpub.com>`联系我们，并提供该材料的链接。

我们感谢您帮助保护我们的作者以及我们为您提供有价值内容的能力。

## 问题

如果您对这本书的任何方面有问题，可以通过`<questions@packtpub.com>`联系我们，我们将尽力解决问题。


# 第一章：Android 和 BeagleBone Black 介绍

在这本书中，你将学习如何将 Android 安装到 microSD 卡上，以便与 BeagleBone Black 配合使用，并创建与连接到 BeagleBone Black 的外部硬件接口的 Android 应用。你将开发软件，通过按钮和传感器从外部世界接收输入，从外部存储芯片存储和检索数据，以及点亮外部 LED。更棒的是，你将学会以灵活的方式进行这些操作，可以轻松集成到你的应用中。

当你探索将硬件与 Android 接口的世界时，你会发现它涵盖了许多不同的专业知识领域。理解电子电路，以及如何将它们与 BeagleBone Black 接口，理解 Linux 内核，以及开发 Android 应用只是其中的几个领域。幸运的是，你不需要在这些领域成为专家就能学习到将硬件与 Android 接口的基础知识。我们已尽最大努力指导你通过本书中的例子，而无需深入了解 Linux 内核或电子理论。

在本章中，我们将介绍以下主题：

+   回顾 Android 和 BeagleBone Black 的开发

+   购买必要的硬件设备

+   了解你将要接口的硬件

+   在 BeagleBone Black 上安装 Android

# 回顾 Android 和 BeagleBone Black 的开发

Android 操作系统已经风靡全球。自从 2007 年以测试版的形式向世界介绍以来，它已经发展成为占主导地位的移动电话操作系统。除了手机，它还被用于平板电脑（如 Barnes & Noble Nook 电子阅读器和 Tesco Hudl 平板电脑）和各种其他嵌入式多媒体设备。该操作系统在多年的发展中增加了新功能，但仍然具有最初构想时的相同的主要设计原则。它提供了一个轻量级的操作系统，具有触摸屏界面，可以快速轻松地访问多媒体应用程序，同时使用最少的资源。

除了其普遍的受欢迎程度外，Android 还有许多优势，使其成为你项目的优秀操作系统。Android 的源代码是开源的，可以从[`source.android.com`](http://source.android.com)免费获取。你可以免费在任何你创造的产品中使用它。Android 使用了流行的 Linux 内核，因此你在 Linux 方面的任何专业知识都将帮助你进行 Android 开发。有一个文档齐全的接口 API，使得为 Android 开发变得简单直接。

基于 Android 的设备的广泛普及激发了对开发针对 Android 的软件应用程序（或应用）的极大兴趣。开发 Android 应用变得更容易了。Eclipse **Android Development Tools (ADT)** 允许应用开发者在模拟的 Android 设备环境中原型化软件，然后执行该软件。然而，模拟设备在速度和外观上与真实硬件存在细微（有时是显著）的差异。幸运的是，有一个功能强大且成本低的硬件平台可以让你快速轻松地在真实硬件上测试你的应用：那就是 BeagleBone Black。

由**CircuitCo**为 BeagleBoard.org 非盈利组织生产的**BeagleBone Black (BBB)** 硬件平台是开源硬件领域的新成员。自 2013 年首次生产以来，这款基于 ARM 的低成本单板计算机是对原有 BeagleBone 平台的改进。BBB 在原版 BeagleBone 板的基础上进行了改进，提供了增强的处理能力、内置 HDMI 视频以及 2 或 4 GB（取决于 BBB 的版本）的板载 eMMC 内存。BBB 专注于小型化以及广泛的扩展和接口机会，以非常低的价格提供了大量的处理能力。以下图片展示了一个典型的 BBB：

![回顾 Android 和 BeagleBone Black 开发](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00002.jpeg)

BeagleBone Black（来源：[www.beagleboard.org](http://www.beagleboard.org)）

Android 运行在廉价的 BBB 上，这使得它成为一个优秀的硬件平台，用于探索 Android 并开发你自己的定制 Android 项目，例如，如果你有一个 Android 自助服务终端设备、手持游戏机或其他多媒体设备的主意。Android 和 BBB 的结合将使你能够快速且低成本地原型这些设备。

既然我们已经快速地了解了 BBB 和 Android，让我们看看你需要哪些硬件才能充分利用它们。

# 购买硬件必需品

当你购买 BBB 时，你将只会收到主板和一根 USB 线，用于供电和与它通信。在开始使用 BBB 进行任何严肃的硬件接口项目软件开发之前，你还需要一些额外的硬件设备。在我们看来，购买这些物品的最佳地点是**AdaFruit**（[www.adafruit.com](http://www.adafruit.com)）。几乎这里的一切都可以从这个单一来源获得，而且他们的客户服务非常好。实际上，这里列出的许多物品都可以从 AdaFruit 购买到 BeagleBone Black 入门套件（产品 ID 703）。入门套件不含 3.3 V **Future Technology Devices International (FTDI)** 电缆，但它确实包含了 BeagleBone Black 本身。

![购买硬件必需品](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00003.jpeg)

来自 AdaFruit 的 BeagleBone Black 入门套件内容（来源：[www.adafruit.com](http://www.adafruit.com)）

## FTDI 电缆

一个 3.3 伏的 FTDI 电缆（产品编号 70）可以让你查看 BBB 的所有串行调试输出。如果你进行任何认真的开发，你必须拥有这样一条电缆。如果你想观察 BBB 的启动过程（包括引导加载程序和内核输出，系统初始化时），这条电缆是必不可少的，它还提供了一个到 Linux 和 Android 的命令行外壳。这个外壳可以帮助你排除启动问题，因为当网络连接不可用，或者没有通信服务运行时，你总有一种与系统交互的方法。

## 电源供应

尽管 BBB 可以通过 USB 电缆供电，但这种方法提供的电力仅够运行 BBB。如果你使用外部扩展板，或者连接从 BBB 的 5 伏引脚获取电源的外部电路，你必须使用外部电源。BeagleBoard.org 规定，电源必须是一个 2 安培、5 伏直流电源，带有 2.1 毫米的圆筒形连接器，中心为正极。AdaFruit 出售符合 BBB 要求的电源（产品编号 276）。

## 面包板和安装板

如果你能够轻松快速地构建电路，而不必担心焊接，那么电子实验会变得简单得多。因此，我们建议你投资一个面包板和一些面包板跳线（产品编号 153）。你的面包板不必很大或花哨，但你应该至少使用一个标准半尺寸的面包板（产品编号 64）来进行本书中给出的项目。

AdaFruit 原型板（产品编号 702）是我们建议你额外购买的物品。原型板是一个塑料板，可以将 BBB 和半个尺寸的面包板固定在上面。这有助于你避免意外拉伸或断开连接电子电路到 BBB 的电线。使用原型板可以使你简单无痛地重新定位 BBB 和面包板。

## MicroSD 卡

如果你经常使用 BBB，你总会想要身边有几张额外的 microSD 卡！Android 可以安装在一个 8GB 的 microSD 卡上，并且还有足够的空间来存放你自己的应用程序。你可以将一个 Android 镜像写入更大的 microSD 卡，但大多数预先制作的 Android 系统镜像只会占用卡上最初 4-8GB 的空间。由于大多数笔记本电脑和台式机不直接接受 microSD 卡，你应该至少拥有一张 microSD 到 SD 卡的适配器。幸运的是，这些适配器通常与你购买的每张 microSD 卡一起包装。

# 了解你将要接口的硬件

学习 Android 软件与硬件接口的最佳方式是在连接实际硬件组件到 BBB 的同时进行学习。这样，你的软件将实际与硬件对话，你可以直接观察到你的应用程序如何响应与系统的物理交互。我们选择了一系列电子组件，这些组件将在本书中用于展示硬件接口的各个方面。你可以根据自己的兴趣和预算选择使用这些组件。一次购买所有这些组件可能会很昂贵，但如果你对实现该章节的示例感兴趣，请确保购买每个章节所需的全部组件。

## 通用组件

在第三章，*使用 GPIO 处理输入和输出*，以及第六章，*创建一个完整的接口解决方案*中，你将使用各种电子组件，如按钮、LED 和电阻，与 BBB 进行接口。这些项目可以从任何电子供应商处购买，例如**DigiKey** ([www.digikey.com](http://www.digikey.com))、**Mouser Electronics** ([www.mouser.com](http://www.mouser.com)) 和 **SparkFun** ([www.sparkfun.com](http://www.sparkfun.com))。Digikey 和 Mouser 提供了每个可用组件的众多变体，以至于经验不足的硬件黑客可能难以挑选出正确的组件进行购买。因此，我们将推荐 SparkFun 的几款产品，为你提供完成本书练习所需的合适组件。如果你觉得使用其他供应商更方便，欢迎你从其他供应商处选择组件。

我们的示例只需要三个组件：一个电阻、一个按钮开关和一个 LED。我们建议购买 1K 欧姆、1/6（或 1/4）瓦的电阻（部件编号 COM-08980）、12 毫米的按钮开关（部件编号 COM-09190）以及任何小型 LED（3-10 毫米大小），该 LED 可以被大约 3 伏或更低的电压触发（部件编号 COM-12903 是一组不错的 5 毫米 LED）。

## AdaFruit 内存 Breakout Board

在第四章，*使用 I2C 存储和检索数据*，以及第六章，*创建一个完整的接口解决方案*中，你将使用一个 32 KB 的**铁电随机存取存储器**（**FRAM**）进行接口，这是一种非易失性存储器 IC，用于存储和检索数据。我们选择了包含此 IC 的 AdaFruit Breakout Board（产品编号 1895）。这个 Breakout Board 已经包含了将 IC 与 BBB 接口所需的所有必要组件，因此你无需担心创建每个 IC 与 BBB 之间干净、无噪声连接所涉及的许多底层细节。

![AdaFruit 内存突破板](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00004.jpeg)

带有头部的 FRAM 突破板（来源：[www.adafruit.com](http://www.adafruit.com)）

## AdaFruit 传感器突破板

在第五章，*使用 SPI 与高速传感器接口*，和第六章，*创建一个完整的接口解决方案*中，你将接口一个传感器 IC 以接收环境数据。我们选择了一个 AdaFruit 突破板（产品 ID 1900），其中包含这些 IC。这些突破板已经包含了将 IC 接口到 BBB 所需的所有必要组件，因此你不必担心在创建每个 IC 与 BBB 之间的干净、无噪声连接过程中涉及到的许多底层细节。

## 准备突破板

每个突破板都配有一条头部条。必须将这条头部条焊接到每个突破板上，这样它们就可以轻松连接到面包板。这是完成本书练习所需的唯一焊接工作。如果你不熟悉焊接，网上有许多教程解释有效的焊接技术。如果你觉得焊接头部条不舒服，可以请朋友、导师或同事帮助你完成这个过程。

### 注意

我们建议你查看一些在线焊接教程：

+   [`www.youtube.com/watch?v=BLfXXRfRIzY`](https://www.youtube.com/watch?v=BLfXXRfRIzY)

+   [如何焊接——通孔焊接教程](https://learn.sparkfun.com/tutorials/how-to-solder---through-hole-soldering)

# 在 BeagleBone Black 上安装 Android

安卓操作系统是一个由许多组件构建的复杂软件，这些组件来自一个非常大的代码库。从源代码构建 Android 可能是一项困难和耗时的任务，因此你将使用本书中的预制的 Android 镜像，来自**BBBAndroid**项目 ([www.bbbandroid.org](http://www.bbbandroid.org))。

BBBAndroid 是将**Android 开源项目**（**AOSP**）KitKat Android 移植到 BBB 的项目。BBB 上有几种不同的 Android 发行版可供选择，但我们选择了 BBBAndroid，因为它使用了 3.8 Linux 内核。这个内核包含了**Cape 管理器**（**capemgr**）功能以及其他一些工具，这些工具可以帮助你将硬件接口到 Android 应用。BBB 上其他版本的 Android 使用的是 3.2 Linux 内核，这个内核较老，并且不支持 capemgr。第二章，*与 Android 接口*，详细讨论了 capemgr 功能。3.8 内核在为 BBB 启用新功能的同时，避免了可能不稳定、过于前沿的特性，是一个很好的平衡。

BBB 可以通过几种不同的方式启动其操作系统：

+   **板载 eMMC**：操作系统位于板载 eMMC 存储中。你的 BBB 出厂时预安装的 Angstrom 或 Debian 操作系统是从 eMMC 启动的。

+   **MicroSD 卡**：操作系统位于插入 BBB 的 microSD 卡上。如果 microSD 卡上安装了引导加载程序，板载 eMMC 上安装的引导加载程序会注意到 microSD 的存在，并从那里启动。此外，当在 BBB 开机时按住**用户启动**按钮时，将强制从 microSD 卡启动。

+   **通过网络**：引导加载程序能够通过 TFTP 从网络下载内核。实际上，操作系统可以在启动时下载，但这通常只在商业产品开发期间完成。这是一个高级功能，超出了本书的范围。

BBBAndroid 镜像被设计为写入并从 microSD 卡启动。由于镜像在 microSD 卡上创建了一个完全可启动的系统，因此你无需在 BBB 开机时按**用户启动**按钮即可启动 Android。只需将 microSD 卡插入 BBB，即可自动引导进入 Android。

使用基于 microSD 卡的操作系统对我们来说是有利的，因为你可以轻松地在 Linux PC 上挂载该卡，根据需要修改 Android 文件系统。如果操作系统安装在 eMMC 中，可能很难访问操作系统以更改文件系统中的任意文件。系统必须运行才能访问 eMMC 的内容，因此在系统损坏或无法启动时，访问 eMMC 以解决问题会比较困难。

## 下载预制的 Android 镜像。

BBBAndroid 网站的主页提供了最新预制镜像的下载链接。与任何开源项目一样，随着时间的推移，可能会发现错误并进行更改，因此每个镜像的版本号和大小可能会发生变化。但是，最新的镜像将通过网站提供。

BBBAndroid 的镜像使用 xz 压缩工具进行压缩，以节省下载时间，因此必须在将其写入 microSD 卡之前解压镜像。解压和写入镜像的工具将根据你所使用的操作系统而有所不同。虽然压缩的镜像可能只有几百 MB 大小，但解压后的镜像将是 8 GB。

### 注意

在开始解压镜像之前，请确保你有足够的硬盘空间来存放解压后的镜像。

## 在 Windows 上创建你的 Android microSD 卡

在基于 Windows 的操作系统下，可以使用如 7-Zip 或 WinRAR 的工具解压压缩的镜像，然后使用 Win32 Disk Imager 工具将其写入 microSD 卡。所有这些工具都可以免费下载。要准备一个 Android microSD 卡，请按照以下步骤操作：

1.  在这个例子中，你将使用 WinRAR 应用程序。从[www.rarlab.com](http://www.rarlab.com)下载 WinRAR 并安装它。WinRAR 将与 Windows 桌面的 Windows 资源管理器集成。

1.  下载并安装 Win32 Disk Imager 应用程序。该程序可在项目的 SourceForge 页面中找到，地址为[`sourceforge.net/projects/win32diskimager`](http://sourceforge.net/projects/win32diskimager)。

1.  右键点击你下载的 BBBAndroid 镜像，并在资源管理器外壳上下文菜单中选择**在此处解压**选项。未压缩的镜像版本（8 GB 大小）将被写入与压缩镜像相同的路径。解压过程可能需要几分钟时间。![使用 Windows 创建你的 Android microSD 卡](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00005.jpeg)

    使用 WinRAR 解压 xz 压缩的镜像

1.  向系统中插入一个 8+ GB 的 microSD 卡。如果卡是预格式化的（大多数卡为了方便用户都是预格式化的），Windows 会将其识别为具有有效文件系统。无论卡是否已格式化，Windows 都会为其分配一个驱动器字母。

1.  浏览到**此电脑**并检查**设备和驱动器**下显示的设备。卡应该会被显示出来。记下分配给卡的驱动器字母。![使用 Windows 创建你的 Android microSD 卡](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00006.jpeg)

    在 Windows 下，microSD 卡将显示一个驱动器字母（图像中的驱动器 E）

1.  启动 Win32 Disk Imager。在文本字段中输入未压缩镜像的文件名和路径，或点击文件夹图标导航到文件位置。将**设备**下拉框更改为你在步骤 4 中识别的 microSD 卡的驱动器字母。![使用 Windows 创建你的 Android microSD 卡](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00007.jpeg)

    使用指定的镜像文件启动 Win32 Disk Imager（注意驱动器字母与 microSD 卡相匹配）

1.  写入镜像将需要几分钟时间。写入完成后，从电脑中取出 microSD 卡，并将其插入 BBB 中。

1.  打开 BBB 并启动 Android，首次启动时，需要几分钟时间才能出现顶级 UI 屏幕。在后续启动中，只需 30 到 60 秒即可到达顶级 UI 屏幕。

恭喜！你的 BBB 现在正在运行 Android 操作系统。

## 使用 Linux 创建你的 Android microSD 卡

在 Linux 系统下，可以使用`xz`命令解压压缩的 Android 镜像，并使用`dd`命令将其写入 microSD 卡。要准备一个 Android microSD 卡，请按照以下步骤操作：

1.  确保你已安装了`xz`。对于使用`apt-get`的系统，尝试安装 xz-utils 包：

    ```java
    $ sudo apt-get install xz-utils

    ```

1.  使用`xz`解压镜像文件。将以下命令中的镜像文件名（带有`.xz`文件扩展名）替换为你自己的文件名：

    ```java
    $ xz --decompress [IMAGE FILENAME]

    ```

1.  解压后，镜像将失去其`.xz`文件扩展名，大小为 8 GB。将你的 microSD 卡插入电脑。在`/dev`目录中会分配一个设备给你的卡。要确定是哪个设备，请使用`fdisk`：

    ```java
    $ sudo fdisk –l

    ```

1.  `fdisk`实用程序将显示当前连接到你的电脑的所有存储设备。其中一台设备的报告大小将与 microSD 卡相同。例如，如果你插入了一张 8 GB 的 microSD 卡，你会看到与此类似的内容：

    ```java
    Disk /dev/sdb: 8018 MB, 8018460672 bytes

    ```

    不同制造商的存储卡实际存储容量略有差异，但大小约为 8 GB。分配给这张卡的设备是`/dev/sdb`。`fdisk`列出的其他设备将是次要存储设备（比如你的硬盘）。在继续之前，请确保你已经识别出属于你的 microSD 卡的适当设备文件。如果你选择了错误的设备，你将破坏该设备上的文件系统！

1.  使用`dd`将镜像写入 microSD 卡。假设你在第 5 步中识别的设备是`/dev/sdb`，使用以下命令进行写入操作：

    ```java
    $ sudo dd if=[NAME OF IMAGE] of=/dev/sdb bs=4M

    ```

1.  写入镜像需要几分钟的时间。写入完成后，从电脑中取出 microSD 卡，并将其插入到你的 BBB 中。

打开 BBB 的电源，Android 将开始启动。在首次启动时，需要几分钟时间才能出现顶级 UI 界面。在后续启动时，只需 30 到 60 秒就能到达顶级 UI 界面。

恭喜你！你的 BBB 现在正在运行 Android 操作系统。

# 总结

在本章中，你了解了为 BeagleBone Black 开发软件所需的硬件，进行本书练习所需的电子元件和设备，以及如何将 Android 发行版安装到 microSD 卡上以在 BBB 上使用。在下一章中，你将学习 Android 在软件层面上如何与硬件交互，以及如何配置 BBB 以与你在本书中将使用的硬件组件接口。


# 第二章：与 Android 交互

在上一章中，你在 BBB 上安装了 Android 系统，并收集了所有需要的硬件和组件，以便尝试本书中的练习。现在你有了可用的 Android 系统和探索它所需的硬件，是时候深入了解 Android，并找出如何为其准备与自定义硬件的接口了。

大多数人可能不会认为 Android 和 Linux 非常相似，但两者之间的共同点比你想象的要多。在精美的用户界面和各种应用之下，Android 实际上是 Linux 系统。Android 的文件系统布局和服务与典型的 Linux 系统大不相同，因此在用户空间（应用和其他进程执行的地方）肯定存在许多差异。在内核空间（设备驱动程序执行的地方，并为每个运行中的进程分配资源），它们在功能上几乎完全相同。理解 BBB 如何与 Linux 内核驱动程序交互是创建能够执行相同操作的 Android 应用程序的关键。

在本章中，我们将向您介绍 Android 的硬件抽象层（HAL）。我们还将向您介绍 PacktHAL，这是一个特殊的库，您可以在应用中包含它，以便与 BBB 上的硬件进行接口交互。我们假设您已经在系统上安装并运行了 Eclipse **Android 开发工具**（**ADT**）、Android **原生开发工具包**（**NDK**）和 **Android 调试桥**（**ADB**）工具。

在本章中，我们将涵盖以下主题：

+   了解 Android HAL

+   安装 PacktHAL

+   为 PacktHAL 设置 Android NDK

+   多路复用 BBB 引脚

### 提示

**您是否缺少一些工具？**

如果您还没有在系统上安装 Eclipse ADT 或 Android NDK 工具，您可以在以下位置找到安装说明和下载链接：

+   **Eclipse ADT**：[`developer.android.com/sdk`](http://developer.android.com/sdk)

+   **Android NDK**：[`developer.android.com/tools/sdk/ndk`](http://developer.android.com/tools/sdk/ndk)

如何安装 ADB 在本章后面会讨论。本章假设您已经将 Eclipse ADT 安装到 `c:\adt-bundle` 目录（如果您使用的是 Windows 系统，我们不假设 Linux 的情况），并且您已经将 Android NDK 安装到 `c:\android-ndk` 目录（Windows）或主目录下的 `android-ndk`（Linux）。如果您将这些工具安装到了其他位置，那么您需要对本章后面的一些指令进行一些简单的调整。

# 了解 Android HAL

安卓内核包含一些在典型 Linux 内核中找不到的额外功能，如**Binder IPC**和低内存杀手，但除此之外，它仍然是 Linux。这为您在与安卓硬件接口时提供了一个很大的优势，即如果安卓系统使用的内核中已经存在 Linux 驱动，那么您已经拥有该设备的安卓驱动。

安卓应用必须通过生成视频和音频数据、接收按钮和触摸屏输入事件以及从摄像头、加速度计等收集外部世界信息的设备接收传感器事件，与安卓设备的硬件进行交互。利用这些设备的现有 Linux 驱动，使得安卓支持变得更加容易。与传统的 Linux 发行版不同，后者允许应用程序直接访问许多不同的设备文件（直接在`/dev`文件系统中打开文件），安卓极大地限制了进程直接访问硬件的能力。

考虑到有多少不同的安卓应用使用设备的音频功能来播放声音或录制音频数据。在安卓之下，Linux 内核通过**高级 Linux 声音架构**（**ALSA**）音频驱动提供这种音频功能。在大多数情况下，一次只能有一个进程打开和控制 ALSA 驱动资源。如果各个应用负责获取、使用和释放 ALSA 驱动，那么在所有各种应用之间协调音频资源的使用将变得非常混乱。一个行为不当的应用很容易控制音频资源，并阻止所有其他应用使用它们！但是，这些资源的分配和控制如何处理呢？为了解决这个问题，安卓使用了*管理者*。

## 安卓管理者

管理者是系统中的组件，代表所有应用控制硬件设备。每个应用都需要一组资源（如音频、GPS 和网络访问）来完成其工作。管理者负责分配和接口每个资源，并确定应用是否有权限使用该资源。

让管理者处理这些低级细节可以使生活变得轻松许多。安卓可以安装在各种硬件平台上，这些平台在物理尺寸和输入/输出能力上有很大差异，不能期望应用开发者对其应用可能安装的每个平台都有深入了解。

要使用资源，应用必须通过`android.content.Context`类的`getSystemService()`方法创建对适当管理者的引用：

```java
// Create a reference to the system "location" manager
LocationManager locationManager = (LocationManager)
  mContext.getSystemService(LOCATION_SERVICE);
```

然后，通过这个管理者引用来发起信息和控制请求：

```java
// Query the location manager to determine if GPS is enabled
isGPSEnabled = locationManager.
isProviderEnabled(LocationManager.GPS_PROVIDER);
```

应用通过 Java Android API 与管理者交互。虽然管理者响应这些 Java 方法，但它们最终必须使用**Java 本地接口**（**JNI**）调用直接与硬件交互的本机代码。这才是真正控制硬件的地方。Android API 与控制硬件的本机代码调用之间的桥梁被称为**硬件抽象层**（**HAL**）。

HAL 的各个部分通常用 C/C++编写，每个设备的供应商负责实现它们。如果 HAL 的某些部分缺失，服务和应用将无法充分利用硬件平台的所有方面。各种 Android 服务使用 HAL 与硬件通信，应用通过 IPC 与这些服务通信，从而访问硬件。服务代表应用与硬件交互（假设应用具有访问该特定硬件资源的适当 Android 权限）。

## HAL 开发工作流程

通常，创建一个完整的 HAL 需要遵循以下步骤：

1.  识别或开发一个 Linux 内核设备驱动程序以控制硬件。

1.  创建一个内核设备树覆盖层，以实例化和配置驱动程序。

1.  开发一个用户空间库以与内核设备驱动程序接口。

1.  为用户空间库开发 JNI 绑定。

1.  使用 JNI 绑定开发一个 Android 管理者以与硬件接口。

有时，很难决定特定的自定义硬件应该正确地集成到 HAL 的哪个位置，以及哪个管理者应该负责访问硬件。Android 的哪些权限控制对硬件的访问？API 是否需要扩展以提供新型权限？是否需要创建自定义服务？

对于爱好者、学生和其他对硬件接口简单实验感兴趣的开发商来说，为一块自定义硬件实现一个适当 HAL 的每个方面都有点过于复杂。虽然商业 Android 系统必须完成所有这些步骤以开发适当的 HAL，但本书采取了一种更为直接的硬件访问方法。

由于我们的重点是展示如何将 Android 应用与硬件接口，我们通过提供**PacktHAL**这一本地库来跳过步骤 1 至 4。PacktHAL 是一个实现了非常简单的 HAL 的本地库，它将帮助你轻松地开始 BBB 上与硬件接口的艰巨任务，并提供了一组能够与本书示例中使用的硬件接口的函数。严格来说，你的应用将作为每个硬件资源的管理者。

## 使用 PacktHAL 工作

应用程序通过 JNI 与 PacktHAL 的本地调用进行通信。PacktHAL 展示了如何通过三种不同的接口方法：`GPIO`、`SPI` 和 `I2C`，与硬件进行用户空间交互。使用 PacktHAL，你可以直接访问硬件设备。第三章至第六章提供了这种接口如何工作以及如何在你的 Android 应用代码中使用它的示例。每一章将检查该章节应用示例中使用的 PacktHAL 的各个部分。

### 提示

**PacktHAL 实际上是如何与硬件通信的？**

通常，任何允许你在 Linux 下与硬件接口的方法也可以被 HAL 用于接口。读取、写入以及对 `/dev` 文件系统中的文件进行 `ioctl()` 调用是有效的，使用 `mmap()` 提供对内存映射控制寄存器的访问也同样有效。PacktHAL 使用这些技术与你连接到 BBB 的硬件进行接口。

使用 PacktHAL 远没有正确的 HAL 实现安全，因为我们必须改变硬件用户空间接口的权限，使得*任何*应用都能直接访问硬件。这可能会使你的系统容易受到恶意应用的攻击，因此这种做法绝不能在生产设备中使用。用户通常会对商业 Android 手机和平板进行 root（获取超级用户权限），以减少这些设备默认的严格权限。这使得他们可以安装和启用自定义功能，并为他们的设备提供更多的灵活性和定制。

由于你将 BBB 作为 Android 原型设备使用，这种做法是你与硬件交互的最简单方式。这是朝着开发自己的自定义管理器和服务迈出的一步，这些管理器和服务代表应用与你的硬件通信。理想情况下，在商业设备上，只有 Android 管理器才有必要的权限直接与硬件接口。

### 提示

一旦你习惯在应用中使用 PacktHAL，你可以检查 PacktHAL 的源代码，以更好地理解本地代码如何与 Linux 内核接口。最终，你可能会发现自己将 PacktHAL 集成到自己的自定义管理器中。你甚至可能会发现自己为实际的内核开发自定义代码！

# 安装 PacktHAL

PacktHAL 的所有组成部分都位于 `PacktHAL.tgz` 文件中，该文件可在 Packt 的网站([`www.packtpub.com/support`](http://www.packtpub.com/support))下载。这是一个压缩的 tar 文件，包含了修改 BBBAndroid 以使用 PacktHAL 并在应用中包含 PacktHAL 支持所需的所有源代码和配置文件。

## 在 Linux 下准备 PacktHAL

下载`PacktHAL.tgz`文件后，你必须解压并展开它。我们将假设你在下载后已将`PacktHAL.tgz`复制到你的主目录并从那里解压。我们将你的主目录称为`$HOME`。

使用 Linux 的`tar`命令来解压并展开文件：

```java
$ cd $HOME
$ tar –xvf PacktHAL.tgz

```

在你的`$HOME`目录中现在存在一个名为`PacktHAL`的目录。所有 PacktHAL 文件都位于此目录中。

## 在 Windows 下准备 PacktHAL

下载`PacktHAL.tgz`文件后，解压并展开它。我们将假设你在下载后已将`PacktHAL.tgz`复制到`C:`驱动器的根目录，并使用 WinRAR 从那里解压。

### 提示

**我应该在哪里解压 PacktHAL.tgz？**

你可以在桌面或其他任何地方解压和展开`PacktHAL.tgz`文件，但稍后你将需要执行一些命令行命令来复制文件。如果`PacktHAL.tgz`在`C:`驱动器的根目录下解压和展开，这些操作会简单得多，因此我们将假设你从那里执行这些操作。

执行以下步骤以提取`PacktHAL.tgz`文件：

1.  打开文件资源管理器窗口，导航至`C:`驱动器的根目录。

1.  在文件资源管理器中右键点击`PacktHAL.tgz`文件并选择**在此处解压**。

现在存在一个名为`C:\PacktHAL`的目录。所有 PacktHAL 文件都位于此目录中。

## PacktHAL 目录结构

`PacktHAL`目录具有以下结构：

```java
PacktHAL/
  |
  +----cape/
  |      |
  |      +----BB-PACKTPUB-00A0.dts
  |      +----build_cape.sh
  |
  +----jni/
  |      |
  |      +----(Various .c and .h files)
  |      +----(Various .mk files)
  |
  +----prebuilt/
  |      |
  |      +----BB-PACTPUB-00A0.dtbo
  |      +----init.genericam33xx(flatteneddevicetr.rc
  |      +----spi
  |             |
  |             +----spidev.h
  |
  +----README.txt
```

`cape`子目录包含了构建 Device Tree 覆盖所需源代码和构建脚本，以启用 PacktHAL 所需的所有硬件功能。你将在本章后面了解更多关于 Device Tree 覆盖的内容。`jni`子目录包含了实现 PacktHAL 的源代码文件。这些源文件将在后面的章节中添加到你的项目中，以便在应用中构建对 PacktHAL 的支持。`prebuilt`目录包含一些预制的文件，这些文件必须添加到你的 BBBAndroid 映像和 Android NDK 中，以构建和使用 PacktHAL。你将在接下来的几节中将`prebuilt`目录中的文件安装到它们所需的位置。

## 为 PacktHAL 准备 Android

在任何应用中使用 PacktHAL 之前，你必须准备你的 BBBAndroid 安装环境。默认情况下，Android 对硬件设备的权限分配非常严格。要使用 PacktHAL，你必须减少权限限制并为将要接口的硬件配置 Android。这些操作需要将一些预构建的文件复制到你的 Android 系统中，进行一些配置更改，以放宽各种 Android 权限并正确为 PacktHAL 配置硬件。

你将使用 ADB 工具将必要的文件推送到正在运行的 BBB 系统。在推送文件之前，启动 BBB 上的 Android 并使用随 BBB 一起提供的 USB 电缆将 BBB 连接到你的电脑。一旦你达到这个阶段，继续按照说明操作。

## 在 Linux 下推送 PacktHAL 文件

以下步骤是在 Linux 下发布 PacktHAL 文件的方法：

1.  在开始之前，请确保使用 `adb devices` 命令确认 ADB 能够看到你的 BBB。BBB 将报告有一个序列号为 `BBBAndroid`。执行以下命令：

    ```java
    $ adb devices
    List of devices attached
    BBBAndroid      device

    ```

1.  如果你缺少 `adb` 命令，可以通过 `apt-get` 安装 `android-tools-adb` 包：

    ```java
    $ sudo apt-get install android-tools-adb

    ```

    ### 提示

    **为什么 Linux 找不到我的 BBB？**

    如果你的系统上安装了 `adb` 但无法看到 BBB，你可能需要向系统添加一个 `udev` 规则并进行一些额外的故障排除。如果你遇到任何困难，Google 提供了添加此规则和故障排除步骤的指导，可以在 [`developer.android.com/tools/device.html`](http://developer.android.com/tools/device.html) 找到。

    BBBAndroid 报告其 ADB 接口的 USB 设备 ID 为 `18D1:4E23`，这是 Google Nexus S 的设备 ID，所以 BBB 的 USB 供应商 ID 是 18D1（Google 设备的设备 ID）。

1.  当你确认 `adb` 能够看到 BBB 后，切换到 `PacktHAL` 目录，通过 `adb` 进入 Android 的 shell，并将只读的 `rootfs` 文件系统重新挂载为可读写：

    ```java
    $ cd $HOME/PacktHAL/prebuilt
    $ adb shell
    root@beagleboneblack:/ # mount rootfs rootfs / rw
    root@beagleboneblack:/ # exit

    ```

1.  现在，将必要的文件推送到 Android 的 `rootfs` 文件系统：

    ```java
    $ adb push BB-PACKTPUB-00A0.dtbo /system/vendor/firmware
    $ adb push init.genericam33xx\(flatteneddevicetr.rc /
    $ adb chmod 750 /init.genericam33xx\(flatteneddevicetr.rc

    ```

1.  最后，进入 Android 的 `rootfs` 文件系统以同步它，并将其重新挂载为只读：

    ```java
    $ adb shell
    root@beagleboneblack:/ # sync
    root@beagleboneblack:/ # mount rootfs rootfs / ro remount
    root@beagleboneblack:/ # exit

    ```

1.  现在，你已经在 Linux 下为 PacktHAL 准备好了 BBBAndroid 镜像。从你的 BBB 上拔掉电源线和 USB 电缆以关闭它。

1.  然后，启动 BBB 以验证你刚才所做的修改后 Android 是否能正常启动。

## 在 Windows 下推送 PacktHAL 文件

你需要找到你的 `adb.exe` 文件的位置。它是 Android SDK 中平台工具的一部分。在以下说明中，我们假设你将 Eclipse ADT 安装在 `c:\adt-bundle` 目录下，那么 `adb` 的完整路径就是 `c:\adt-bundle\sdk\platform-tools\adb.exe`。

以下步骤是在 Windows 下发布 PacktHAL 文件的方法：

1.  在开始之前，请确保使用 `adb devices` 命令确认 `adb` 能够看到你的 BBB。BBB 将报告有一个序列号为 `BBBAndroid`：

    ```java
    $ adb devices
    List of devices attached
    BBBAndroid      device

    ```

    ### 提示

    **为什么 Windows 找不到我的 BBB？**

    在 Windows 下让`adb`识别 Android 设备可能会非常困难。这是因为每个创建 Android 设备的硬件制造商都为其提供了自己的 Windows ADB 设备驱动程序，Windows 使用该驱动程序与设备通信。BBBAndroid 报告其 ADB 接口的 USB 设备 ID 为`18D1:4E23`，这是 Google Nexus S 的设备 ID。这是 Koushik Dutta 为 Windows 提供的优秀通用 ADB 驱动程序支持的众多 USB 设备之一。如果`adb`找不到您的 BBB，请安装通用 ADB 驱动程序，然后重试。您可以从[`www.koushikdutta.com/post/universal-adb-driver`](http://www.koushikdutta.com/post/universal-adb-driver)下载驱动程序。

1.  验证这一点后，`adb`可以看到 BBB，通过`adb`进入 Android 的 shell，并将只读的`rootfs`文件系统重新挂载为读写：

    ```java
    $ adb shell
    root@beagleboneblack:/ # mount rootfs rootfs / rw
    root@beagleboneblack:/ # exit

    ```

1.  现在，将必要的文件推送到 Android 的`rootfs`文件系统：

    ```java
    $ adb push c:\PacktHAL\prebuilt\BB-PACKTPUB-00A0.dtbo /system/vendor/firmware
    $ adb push c:\PacktHAL\prebuilt\init.genericam33xx(flatteneddevicetr.rc /
    $ adb chmod 750 /init.genericam33xx\flatteneddevicetr.rc

    ```

1.  最后，通过 shell 进入 Android 的`rootfs`文件系统，将其同步并重新挂载为只读：

    ```java
    $ adb shell
    root@beagleboneblack:/ # sync
    root@beagleboneblack:/ # mount rootfs rootfs / ro remount
    root@beagleboneblack:/ # exit

    ```

1.  您现在已经在 Windows 下为 PacktHAL 准备好了 BBBAndroid 映像。请将电源线和 USB 线从 BBB 上拔下以关闭它。然后，给 BBB 供电，以验证您刚才所做的修改后 Android 是否能正常启动。

    ### 提示

    **为什么 init.genericam33xx（flatteneddevicetr.rc 文件命名如此奇怪？**

    Android 设备有一组只读属性，它们向应用程序和管理器描述系统的硬件和软件。其中之一是`ro.hardware`，它描述了内核配置的硬件。Android 中的设备特定`.rc`文件具有`init.{ro.hardware}.*rc`的形式。

    在 Linux 内核源代码中，`arch/arm/mach-omap2/board-generic.c`文件使用`DT_MACHINE_START()`宏来指定 BBB 平台的名称为`Generic AM33XX (Flattened Device Tree)`。这个文本字符串被转换为小写，删除空格，并截断以生成存储在`ro.hardware`属性中的最终字符串。

# 为 PacktHAL 设置 Android NDK

不幸的是，Android 的**原生开发工具包**（**NDK**）缺少一个构建 PacktHAL 所需的内核头文件。这个缺失的头文件描述了用户空间应用程序与通用 SPI 驱动程序（`spidev`，您将在第五章，*使用 SPI 与高速传感器接口*中使用）之间的接口。这个头文件缺失并不是 NDK 的错，因为通常应用程序不需要直接访问`spidev`驱动程序。

由于您是使用应用程序直接与硬件通信，因此需要将这个缺失的头文件复制到您的 NDK 安装中。

### 提示

为了方便起见，我们在 PacktHAL 源代码压缩包中包含了这个头文件的副本。在构建 PacktHAL 之前，您只需要将文件复制到您的 NDK 安装中。

BBBAndroid 是 4.4.4 KitKat 版本，API 级别 19 是此版本支持的最高级别。你将为本书的示例构建 API 级别 19 的所有内容。每个 API 级别在 NDK 中都有不同的头文件集，因此你必须向 API 级别 19 的`include/linux`目录添加缺失的头文件。如果你决定在较低的 API 级别构建应用，可以重复以下步骤，将附加头文件添加到你想使用的任何其他 API 级别中。

## 在 Linux 下向 NDK 添加头文件

如果你打算在 Linux 下使用 Eclipse ADT 构建应用，你需要在你的 Linux 系统上安装 Android NDK。对于这些说明，我们将假设你已经将 NDK 安装到`$HOME`目录下的`android-ndk`文件夹中。由于在本章前面你已经下载、解压并解包了`PacktHAL.tgz`文件到你的`$HOME`目录，我们将假设你创建的`PacktHAL`目录还在那里：

```java
$ cd $HOME/android-ndk/platforms/android-19/arch-arm/usr/include/linux
$ cp -rf $HOME/PacktHAL/prebuilt/spi

```

这将把`spi`头文件目录的内容复制到你的 NDK 头文件中。现在你的 Linux NDK 安装中有了构建 PacktHAL 所需的额外头文件。

## 在 Windows 下向 NDK 添加头文件

如果你打算在 Windows 下使用 Eclipse ADT 构建应用，你需要在你的 Windows 系统上安装 Android NDK。对于这些说明，我们将假设你已经将 NDK 安装到`c:\android-ndk`文件夹中。由于在本章前面你已经下载、解压并解包了`PacktHAL.tgz`文件到你的`c:\`目录，我们将假设你创建的`PacktHAL`目录还在那里：

1.  打开文件资源管理器窗口，导航至`c:\android-ndk\platforms\android-19\arch-arm\usr\include\linux`路径。

1.  打开第二个文件资源管理器窗口，导航至`c:\PacktHAL\prebuilt`路径。右键点击`spi`目录，并在上下文菜单中选择**复制**。

1.  切换到 Android NDK 窗口，在窗口中的文件列表空白处右键点击，然后在上下文菜单中选择**粘贴**。

这将把`spi`头文件目录的内容复制到你的 NDK 头文件中。现在你的 Windows NDK 安装中有了构建 PacktHAL 所需的额外头文件。

# 对 BBB 引脚进行复用

由于在 Android 下访问硬件资源与在 Linux 下遵循相同的流程，因此了解 Linux 内核如何配置设备驱动程序并将它们分配给特定的硬件非常重要。也有必要了解这些内核驱动程序如何为 PacktHAL 提供可以与之交互的用户空间接口。

BBB 的 AM3359 处理器在其数百个引脚上提供了各种各样的信号。这些信号包括许多不同的、专门的接口总线和传感器输入。潜在的信号数量远远超过了可用于将这些信号输出到外界的引脚数量。为了选择哪些信号在引脚上可用，这些引脚被复用，或称为*muxed*，到特定的信号。

处理器的几个引脚被连接到 BBB 的 P8 和 P9 头的连接上。这些特定引脚的复用对 BBB 用户来说非常重要，因为复用决定了哪些处理器信号和功能可以容易被用户用于硬件接口。BBB 的两个头各有 46 个引脚，总共有 92 个引脚可供接口使用。不幸的是，默认情况下有 61 个引脚正在使用，这意味着在不禁用 BBB 的一个或多个标准功能的情况下，只有 31 个引脚可以为你项目所变动。

![BBB 引脚复用](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00008.jpeg)

BeagleBone Black 的 P8 和 P9 扩展头

头上的某些引脚是永久分配的，例如提供访问电压（1.8、3.3 和 5 VDC 可用）和地线的引脚。然而，其他引脚可以根据项目的需要进行复用。正确复用所有的 P8/P9 引脚以提供你所需要的所有资源有时可能很棘手，特别是如果你刚开始学习 BBB 的硬件接口方面。幸运的是，我们已经为你确定了一个引脚复用配置，这将提供给 PacktHAL 运行本书中所有练习所需的所有硬件资源。

![BBB 引脚复用](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00009.jpeg)

BeagleBone Black 上默认使用的引脚

## 内核 Device Tree 和 capemgr

BBB 的引脚必须以特定的方式复用以与自定义硬件通信，但实际在哪里以及如何进行呢？"答案是"内核的**Device Tree**。" Device Tree 是内核中的一个层次化数据结构，描述了存在哪些硬件，这些硬件使用了哪些资源，以及应该使用哪些内核驱动程序与每个硬件设备通信。它描述了硬件的不同方面，例如引脚复用设置、时钟速度和传递给内核设备驱动程序的参数。

如果要求用户在每次硬件更改时都安装新内核，这将是一件非常麻烦的事情。对于 BBB 这样的硬件平台，用户可以在电源周期之间更改连接到 BBB 的硬件！能够动态地更改 Device Tree 以即时添加或移除硬件将非常有用。BBB 的 Linux 3.8 内核有一个特殊的子系统，称为**cape 管理器**（**capemgr**），它允许你这样做。

capemgr 动态地添加和移除设备树的片段或*覆盖层*。它提供了三项重要的服务：

+   它识别任何连接到 BBB 的 Cape 硬件

+   它加载适当的设备树覆盖层以启用和配置每个被识别的 Cape

+   它允许从用户空间动态加载任意的设备树覆盖层，以配置任何未被自动发现的硬件。

## 定义 Cape

Cape 是任何连接到 BBB 的 P8/P9 连接器（类似于盾板连接到 Arduino）的硬件扩展，并包含一个**电可擦可编程只读存储器**（**EEPROM**）芯片，向内核的 capebus 报告 Cape 的身份。内核中的 capemgr 然后可以为该特定 Cape 动态启用适当的设备树覆盖层。这就是允许你将各种不同的商业 Cape 板连接到 BBB，并且它们全部自动工作，而无需你更改任何配置文件的原因。

对 Cape 的定义较为宽松的是指任何通过 P8/P9 连接器接口的外部电路。如果没有包含一个 EEPROM 来告诉 capemgr “我是一个名为 XYZ 的 Cape”，capemgr 便不会自动定位并加载适合该 Cape 的正确设备树覆盖层。本书中的所有示例都是这种情况。你仍然可以将连接到 BBB 的硬件视为 Android 正在接口的 Cape，但设备树覆盖层必须从用户空间手动加载。

在本章前面，你使用了 `adb` 将一个名为 `BB-PACKTPUB-00A0.dtbo` 的文件推送到你的 Android 映像中。这个文件是配置 BBB 以适应你将在本书练习中使用的硬件的设备树覆盖层。你同样推送过去的自定义 `init.genericam33xx(flatteneddevicetr.rc` 文件在 Android 启动过程中为你手动加载了这个覆盖层。

在 Linux 文件系统中，自定义覆盖层被放置在 `/lib/firmware` 目录中。但在 Android 下，`rootfs` 中没有 `/lib` 目录，因此覆盖层被放置在 `/system/vendor/firmware` 目录中。这也是在内核编译期间构建的固件（`.fw` 文件）安装的位置。在使用你未来的项目中的自定义设备树覆盖层时，请记得将它们放置到 `/system/vendor/firmware` 目录中，以便 capemgr 能够找到它们。

### 提示

**我在哪里可以了解更多关于复用 BBB 的引脚、设备树以及创建自定义覆盖层的信息？**

学习如何为自定义项目选择最佳的引脚复用（pin muxing）并创建适当的设备树覆盖层超出了本书的范围，但有许多优秀的资源可以介绍你了解这个过程。以下是我们推荐你阅读的一些学习更多知识的优秀资源：

+   BeagleBone Black 系统参考手册：[`www.adafruit.com/datasheets/BBB_SRM.pdf`](http://www.adafruit.com/datasheets/BBB_SRM.pdf)

+   Derek Molloy 的网站：[`derekmolloy.ie/category/embedded-systems/beaglebone/`](http://derekmolloy.ie/category/embedded-systems/beaglebone/)

+   AdaFruit 的 Device Tree Overlay 教程：[`learn.adafruit.com/introduction-to-the-beaglebone-black-device-tree`](https://learn.adafruit.com/introduction-to-the-beaglebone-black-device-tree)

# 总结

在本章中，我们解释了 Android 如何使用 HAL 让 Android 管理器向应用提供硬件访问权限。我们向你介绍了 PacktHAL，它可用于与本书中的所有示例进行接口交互。你配置了 BBBAndroid 镜像以使用 PacktHAL，并且修改了你的 NDK 安装，以便将 PacktHAL 构建到你的应用中。

我们还展示了 BBB 的 P8/P9 头部哪些引脚可以进行复用，Device Tree 是什么以及如何使用它来复用引脚，以及 capemgr 如何加载 Device Tree 覆盖层以动态复用 BBB 的引脚。

在下一章中，你将开始使用 PacktHAL 并构建你的第一个使用 GPIOs 的硬件接口应用。


# 第三章：使用 GPIO 处理输入和输出

在上一章节中，你已经为开发硬件接口的 Android 应用准备好了开发 PC 和 BBBAndroid 系统。现在，你的开发环境已经搭建好并准备就绪，你将开始探索你的第一个能够与连接到 BBB 的硬件直接通信的应用。

**通用输入/输出**（**GPIO**）是数字电子学中最基本的接口之一。在本章的示例中，你将使用 GPIO 接收来自外部世界的数字输入信号，并发送数字输出信号作为响应。虽然这是一个小的开始，但这是发展和理解更复杂的硬件接口应用的第一步。GPIO 可以用来实现复杂且强大的接口逻辑。我们将讨论 GPIO 接口的硬件和软件方面，并解释如何在 Android 应用中调用 Java 方法以与低级硬件接口代码交互。

本章节，我们将涵盖以下主题：

+   了解 GPIO

+   构建 GPIO 接口电路

+   在你的应用中包含 PacktHAL

+   探索 GPIO 示例应用

# 了解 GPIO

在最基本的层面上，两块硬件之间的通信需要在它们之间来回传输数据。在计算机系统中，这些数据被表现为通过连接设备的电线发送的电压级别。电压来回的模式和级别形成了一种通信协议，设备使用该协议在彼此之间传输数据。

GPIO 是微控制器和微处理器提供的最基本的接口选项。BBB 处理器的某些引脚被分配为 GPIO，可以作为*输入*（监测线上的电压以接收数据）或*输出*（在线上放置特定电压以发送数据）。BBB 有数十个可用的 GPIO 引脚，这使得 GPIO 成为 Android 应用与外部世界交互的一种灵活且简单的方式，无需复杂的设备驱动程序或额外的接口硬件。

## GPIO 的细节

数字逻辑基于这样的概念：有两个离散的电压级别，分别代表*开启/高电平*和*关闭/低电平*状态。通过在这两个状态之间切换，可以在设备之间传输二进制位数据。BBB（BeagleBone Black）使用 3.3 V 的电压代表高电平，0 V（接地）的电压代表低电平。这种电压方案称为*3.3 V 逻辑电平*，它通常用于像 BeagleBoard 和 Raspberry Pi 这样的单板计算机。许多微控制器（例如，许多 Arduino 板）则使用 5 V 逻辑电平。

### 提示

**切勿对任何 BBB 引脚施加超过 3.3 V 的电压！**

向 BBB GPIO 施加超过 3.3V 的电压可能会烧毁 BBB 的处理器，因此在设计 BBB 的 GPIO 接口电路时，请务必确保你只使用最多 3.3V 的电压。P9.3/4 引脚提供 3.3V，而 P9.5/6 引脚提供 5V。当你打算使用 3.3V 引脚时，很容易不小心将面包板线连接到提供 5V 的引脚上。为了避免这个错误，可以尝试用一块胶带覆盖 P9.5/6 引脚。

BBB 的处理器有四个 GPIO 组，每组有 32 个单独的 GPIO。在 P8/9 连接器上只有 92 个引脚可用，不可能让每个 GPIO 都对外界开放。实际上，BBB 的系统参考手册显示，即使禁用了所有其他被复用到 P8/9 的功能，同时最多也只能将大约 65 个独特的 GPIO 复用到 P8/P9。还有一些其他的 GPIO 内部用于诸如点亮和闪烁 BBB 的 LED 等任务，但你应该认为只能使用通过 P8/P9 访问且不与任何标准的 BBB 功能冲突的 GPIO。

## Android 下的 GPIO 访问方法

与 BBB 上的 GPIO 交互有两种基本方法：**文件 I/O**和**内存映射**。使用文件 I/O，你通过读取和写入文件系统中的 GPIO 文件，通过内核驱动程序传递 GPIO 请求。使用内存映射，你将 GPIO 控制电阻映射到内存中，然后读取和写入这些映射的内存位置，直接操纵控制电阻。由于这两种方法都是由 Linux 内核实现的，它们在 Android 下的工作效果和在 Linux 下一样好。

### 文件 I/O 方法的优缺点

文件 I/O 方法可以由任何拥有适当权限来读写 GPIO 设备文件的过程执行。然而，像任何文件 I/O 操作一样，这可能会相当慢。

### 内存映射方法的优缺点

内存映射方法允许你直接访问控制 GPIO 的电阻。内存映射非常快（大约是文件 I/O 的 1000 倍！），但只有具有 root 权限的进程才能使用它。

由于你的应用程序在未进行一些重要的权限更改的情况下无法以 root 权限执行，因此你将无法使用内存映射来访问 GPIO。这实际上限制了你只能在应用程序中使用文件 I/O。

### 注意

PacktHAL 为 GPIO 访问实现了内存映射和文件 I/O。如果你对这两种方法的底层细节感兴趣，请检查`PacktHAL.tgz`中的`jni/gpio.c`文件。

## 为 GPIO 使用准备 Android

在第二章《与 Android 接口》中，你使用`adb`将两个预构建的文件从 PacktHAL 推送到你的 Android 系统中。这两个文件，`BB-PACKTPUB-00A0.dtbo`和`init.{ro.hardware}.rc`，配置了你的 Android 系统以启用特定的 GPIO，并允许你的应用访问它们。

### 注意

请记住，当我们提到`init.{ro.hardware}.rc`文件时，我们指的是 Android 文件系统的根目录中的`init.genericam33xx(flatteneddevice.tr`文件。

`BB-PACKTPUB-00A0.dtbo`文件是一个设备树覆盖（Device Tree overlay），它将 BBB 复用到以支持本书中的所有示例。就 GPIO 而言，这个覆盖将 P9.11 和 P9.13 引脚复用到 GPIO。在`PacktHAL.tgz`文件中，覆盖的源代码位于`cape/BB-PACKTPUB-00A0.dts`文件中。负责复用这两个 GPIO 的代码位于`fragment@0`中的`bb_gpio_pins`节点内。

```java
/* All GPIO pins are PULLUP, MODE7 */
bb_gpio_pins: pinmux_bb_gpio_pins {
    pinctrl-single,pins = <
        0x070 0x17  /* P9.11, gpio0_30, OUTPUT */
        0x074 0x37  /* P9.13, gpio0_31, INPUT */
    >;
};
```

`bb_gpio_pins`节点中使用的十六进制值的细节超出了本书的讨论范围。然而，大致的想法是它们指定了哪个引脚是感兴趣的，应该将引脚复用到哪种模式，关于上拉/下拉电阻的一些细节，它是输入引脚还是输出引脚，以及是否应该对信号进行偏斜调整。

### 注意

关于偏斜（skew）的细节以及如何进行调整超出了本书的讨论范围。如果你想了解更多关于偏斜的信息，我们建议从维基百科的相关页面开始了解（[`en.wikipedia.org/wiki/Clock_skew`](http://en.wikipedia.org/wiki/Clock_skew)）。

在启动时，这个覆盖通过`init.{ro.hardware}.rc`文件加载。然后内核知道哪些引脚被视为 GPIO。加载覆盖后，`init.{ro.hardware}.rc`文件执行一些命令，明确地“解锁”这些 GPIO 文件，通过*导出*使应用可以使用它们。导出一个 GPIO 引脚会在`/sys`文件系统中创建一系列文件，这些文件可以被读取和写入以与该 GPIO 引脚进行交互。 

通过导出一个 GPIO 引脚，然后通过`chmod`更改`/sys`文件系统中相应文件的权限，任何进程都可以读取或写入 GPIO。这正是`init.{ro.hardware}.rc`文件中的命令所做的，允许 Android 应用与 GPIO 接口。`init.{ro.hardware}.rc`文件的以下部分执行了导出和`chmod`操作：

```java
# Export GPIOs 30 and 31 (P9.11 and P9.13)
write /sys/class/gpio/export 30
write /sys/class/gpio/export 31

# Make GPIO 30 an output
write /sys/class/gpio/gpio30/direction out
# Make GPIOs 30 and 31 writeable from the FS
chmod 777 /sys/class/gpio/gpio30/value
chmod 777 /sys/class/gpio/gpio31/value
```

每个 GPIO 都有一个特定的整型标识符，由 GPIO 所属的银行（bank）及其在该银行中的位置决定。在我们的案例中，复用到 P9.11 的 GPIO 是银行 0 中的第 30 个 GPIO，而 P9.13 是银行 0 中的第 31 个 GPIO。这使得它们的整型标识符分别是 30 和 31。

### 注意

GPIO 引脚 30 和 31 只能通过`/sys`文件系统使用，因为它们在`init.{ro.hardware}.rc`文件中通过`write`命令明确导出。除非其他 GPIO 引脚也以同样的方式明确导出，否则它们将无法通过文件系统使用。

这种允许 GPIO 访问的方式非常不安全，因为它会打开 GPIO 供我们可能不希望直接访问它们的过程使用。对于实验和原型设计，这不是问题。然而，在商业系统中你绝对不应该这样做。除非你开发了一个合适的、有特权的 Android 管理器来处理 GPIO 资源，否则你必须允许*所有*进程访问 GPIO 文件，除非你定制权限，使其只能被属于特定用户或组的 app 使用。由于每个 app 都分配有自己的用户，你需要在将 app 的`.apk`文件安装到系统上后，将 GPIO 的所有者更改为正确的用户和组。

# 构建一个 GPIO 接口电路

在开始开发使用 GPIO 通信的软件之前，你首先需要构建一个 GPIO 接口的硬件电路。对于本章，你将构建一个简单的电路，包括 1k 欧姆电阻、LED 和按钮开关。这些部件的零件编号和供应商在第一章中列出，*Android 和 BeagleBone Black 的介绍*。在开始之前，请确保你有所有适当的部件，并在连接到 BBB 的 P8/P9 连接器之前，从 BBB 上移除所有电源（拔掉电源和 USB 电缆）。

### 提示

**不要拆开你的电路！**

本章节中的 GPIO 电路是第六章中更大电路的一部分，*创建一个完整的接口解决方案*。如果你按照下面示意图中的位置（在面包板的顶部）构建电路，那么在构建本书其余电路时，你可以简单地将 GPIO 组件和电线留在原位。这样，当你到达第六章时，它就已经构建好并可以工作了。

## 构建电路

你将构建的电路与以下四个 BBB 引脚接口：

+   P9.1（接地）

+   P9.3（3.3 V）

+   P9.11（GPIO）

+   P9.13（GPIO）

P9.11 引脚被配置为输出 GPIO，它驱动 LED。P9.13 引脚被配置为输入 GPIO，它根据施加在它上面的输入电压来设置其状态。这两个 GPIO 引脚都通过`BB-PACKTPUB-00A0.dtbo`覆盖层配置为使用内部上拉电阻。如果你不熟悉上拉电阻是什么，别担心。对于这些示例来说，它仅仅意味着如果 GPIO 引脚上没有连接任何东西，GPIO 的逻辑电平不会在开和关之间“浮动”。相反，逻辑电平会被“上拉”到开启状态。

### 注意

想了解更多关于上拉电阻是什么以及它是如何工作的吗？我们建议你查看这个关于上拉和下拉电阻的在线教程，教程地址为[`www.resistorguide.com/pull-up-resistor_pull-down-resistor`](http://www.resistorguide.com/pull-up-resistor_pull-down-resistor)。

面包板通常在两侧各有一个几乎贯穿整个面包板长度的垂直总线。这些总线用于为插入面包板的任何组件提供方便的电源和地线接入。

![构建电路](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00010.jpeg)

完整的 GPIO 接口电路

现在我们可以开始构建我们的电路了：

1.  将 BBB 的地线（P9.1）和 3.3V（P9.3）信号连接到面包板上的两个垂直总线上。地线总线是靠近面包板中心的垂直总线。3.3V 总线是靠近面包板边缘的垂直总线。

1.  接下来，将 LED 的阳极（或正极引脚）连接到 P9.11。LED 具有极性，因此电流只能在一个方向上通过它们流动。电流从 LED 较长的引脚（阳极）流向较短的引脚（阴极）。

1.  如果 LED 的引脚被剪成了相同的长度，你无法分辨哪个是哪个，可以摸一下 LED 塑料外壳的边缘。外壳边缘在阴极侧是平的，在阳极侧是圆的。只要阴极连接到地线，阳极连接到 GPIO 引脚，LED 就能正常工作。

1.  你必须限制 LED 的电流，以确保不会损坏 GPIO 引脚，因此在 LED 的阴极引脚和地线之间需要放置一个 1K 欧姆的电阻。电阻没有像 LED 那样的极性，所以你将其连接到面包板的方向并不重要。

    ### 注意

    如果你希望了解更多关于使用限流电阻与 LED 配合的信息，例如选择合适的电阻进行任务，我们建议你阅读 SparkFun 的教程，教程地址为[`www.sparkfun.com/tutorials/219`](https://www.sparkfun.com/tutorials/219)。

1.  既然 LED 和电阻已经连接到 BBB，你必须连接按钮开关。不同的开关具有不同数量的引脚，但我们为你推荐的开关总共有四个引脚。这些引脚形成两对，每对两个引脚。每对中的两个引脚始终是电气连接的，但当按下按钮时，一对才会与另一对电气连接。开关的两边是平滑的，另外两边每边有两个突出的引脚。单边开关上的两个突出引脚属于不同对的引脚。选择带有两个引脚的一边开关，将一个引脚连接到 P9.13，另一个引脚连接到面包板的接地总线。

你的电路现在完成了。再次检查你的接线与完整的 GPIO 接口电路图对照，以确保一切连接正确。

## 检查你的接线

完成 GPIO 电路的接线后，你应该测试它以确保它正常工作。幸运的是，你可以通过 shell 进入 BBB 并处理导出的 GPIO 针脚文件来轻松完成这个测试。我们将假设你正在使用`adb`进入 Android 系统，但使用 FTDI 访问控制台 shell 的方法完全相同。

### 提示

**如何使用 FTDI 电缆？**

如果你从未使用过 FTDI 电缆与 BBB 通信，有一个由 BeagleBoard.org 团队维护的[www.elinux.org](http://www.elinux.org)维基页面可以帮助你开始，它是[`elinux.org/Beagleboard:Terminal_Shells`](http://elinux.org/Beagleboard:Terminal_Shells)。

在本书中，我们只会使用 USB 电缆和 ADB shell 来访问 BBB。但是，学习如何使用 FTDI 来监控和排查 BBB 问题确实非常有用。

为你的 BBB 供电，然后使用 USB 电缆将 BBB 连接到你的开发系统。在 shell 进入 BBB 后，使用以下步骤开始测试你的 GPIO 电路：

1.  切换到与 P9.11（GPIO 针脚 30）复用的 GPIO 目录：

    ```java
    root@beagleboneblack:/ # cd /sys/class/gpio/gpio30

    ```

1.  使用`echo`命令通过将此 GPIO 的状态强制为 1 来打开 LED：

    ```java
    root@beagleboneblack:/ # echo 1 > value

    ```

1.  现在 LED 将会打开。使用`echo`命令通过将此 GPIO 的状态强制为 0 来关闭 LED：

    ```java
    root@beagleboneblack:/ # echo 0 > value

    ```

1.  现在 LED 将会熄灭。切换到与 P9.13（GPIO 针脚 31）复用的 GPIO 目录：

    ```java
    root@beagleboneblack:/ # cd /sys/class/gpio/gpio31

    ```

1.  使用`cat`命令检查按钮开关的当前状态。在执行此命令时，请确保你没有按下按钮：

    ```java
    root@beagleboneBlack:/ # cat value
    1

    ```

1.  现在，在按住按钮的同时执行以下`cat`命令。你应该输入整个命令，按下按钮，然后按*Enter*键在按住按钮的同时输入命令：

    ```java
    root@beagleboneblack:/ # cat value
    0

    ```

    ### 注意

    由于电路的连线方式，按钮的值看起来是反的。当按钮未被按下时，P9.13 上的上拉电阻会将 GPIO 的值拉至`1`。当按钮被按下时，P9.13 引脚连接到地线信号，并将 GPIO 改变为`0`。

如果你看到 LED 灯在开关按下和释放时点亮和熄灭，并且返回了正确的值，说明你已经正确地连好了电路。如果 LED 灯没有点亮，请确保你没有意外地交换了 LED 的阳极和阴极引脚。如果开关总是返回 0 值，请确保你已经将开关上的正确引脚对连接到地线总线和 P9.13。

# 在你的应用中包含 PacktHAL

在使用 PacktHAL 与 GPIO 接口之前，你必须了解如何在你的应用中包含 PacktHAL 支持。我们将指导你如何将 PacktHAL 代码添加到你的应用中，并构建它。PacktHAL 将与你的应用一起打包在`.apk`文件中，作为一个共享库。该库的源代码位于应用项目目录中，但它与应用的 Java 代码分开构建。在应用可以在`.apk`文件中包含并使用它之前，你必须手动构建 PacktHAL 共享库。

### 注意

我们在随书提供的每个示例应用项目中包含了一个预构建的 PacktHAL 库，这样你就可以立即开始构建和运行示例应用，而无需担心构建 PacktHAL 的细节。一旦你开始创建自己的自定义应用并修改 PacktHAL 以适应你的硬件项目时，你将需要了解如何从源代码构建 PacktHAL。

## 理解 Java 本地接口（JNI）

安卓应用是用 Java 编写的，但 PacktHAL 中的函数是用 C 本地代码编写的。本地代码是编译成本地二进制文件（如共享库或可执行文件）的代码，然后由安卓操作系统直接执行。本地代码使用安卓 NDK 提供的编译器工具链构建。本地二进制文件不像安卓应用的“一次构建，到处运行”的字节码那样可移植，但它们可以用 Java 代码无法实现的方式进行低级接口。与在任何拥有适当虚拟机的平台上可执行的 Java 字节码不同，本地代码是为特定的硬件架构（如 ARM、x86 或 PowerPC）编译的，并且只能在该架构上执行。

在本地代码中实现的功能是通过应用的 Java 代码通过**Java 本地接口**（**JNI**）调用的。JNI 是 Java 应用程序用来与本地 C/C++代码交互的一种流行的接口机制。除了其他特性之外，JNI 用于将 Java 数据类型*转换*为 C 数据类型，反之亦然。

例如，考虑 Java `String`类型。虽然 Java 有一个`String`实现，但 C 中没有等效类型。字符串必须适当地转换为一个兼容的类型，然后才能被 C 代码使用。每个 Java 类型在 C 中都由一系列等效类型表示，如`jint`、`jstring`和`jboolean`，这些类型在 Android NDK 提供的标准`jni.h`头文件中定义。

## 创建一个使用 PacktHAL 的新应用项目

以下步骤将演示如何创建一个包含 PacktHAL 的新自定义应用：

1.  启动 Eclipse ADT，选择菜单选项**文件**，然后**新建**，接着**Android 应用项目**。

1.  在**新建 Android 应用**对话框中，将`myapp`输入到**应用名称**字段。这将自动填充**项目名称**和**应用名称**字段。将**最低要求的 SDK**、**目标 SDK**和**编译使用**字段更改为**API 19: Android 4.4**。主题字段可以保持原样，或者根据你希望应用使用的主题进行更改。完成后，点击**下一步**按钮。创建一个使用 PacktHAL 的新应用项目

    新 Android 应用界面

1.  按照后续对话框屏幕操作，保留每个屏幕的默认设置，直到在最后一个屏幕上点击**完成**按钮。

为你的新应用创建的默认活动名称为`MainActivity`。创建新项目后，新的`myapp`项目的文件夹结构将位于`myapp`（`$PROJECT`）目录中，并具有以下类似的目录结构：

```java
myapp
  |
  +----.settings/
  +----assets/
  +----bin/
  +----gen/
  +----libs/
  +----res/
  +----src/
  +----...
```

首次创建应用后，将创建几个新文件夹以保存构建过程中生成的各种中间文件。创建应用后，你必须向其中添加 PacktHAL 代码并编译它。

### 在 Windows 下构建 PacktHAL

PacktHAL 必须构建成一个库，并包含在你的应用项目代码库中，以便你的应用使用。假设你将`PacktHAL.tgz`文件解压缩并解压在`c:\`中，你可以使用以下过程将 PacktHAL 代码复制到你的应用项目目录（`$PROJECT`）中：

1.  打开一个文件资源管理器窗口，浏览到`$PROJECT`目录。

1.  打开第二个文件资源管理器窗口，浏览到`c:\PacktHAL`。

1.  在`c:\PacktHAL`目录中的`jni`目录上右键单击，然后从上下文菜单中选择**复制**。

1.  在`$PROJECT`目录窗口内的空白处右键单击，然后从上下文菜单中选择**粘贴**。

既然`jni\`目录已经存在于你的`$PROJECT`目录中，你可以使用 Android NDK 构建 PacktHAL。假设你将 Android NDK 安装在`c:\android-ndk`中，你可以使用以下过程构建 PacktHAL：

1.  启动`cmd.exe`以获取命令提示窗口。使用命令提示符，切换到`$PROJECT`目录：

    ```java
    c:\> cd $PROJECT\jni

    ```

1.  使用 Android NDK 构建 PacktHAL 库：

    ```java
    c:\$PROJECT\jni> c:\android-ndk\ndk-build
    [armeabi] Compile thumb  : packtHAL <= jni_wrapper.c
    [armeabi] Compile thumb  : packtHAL <= gpio.c
    [armeabi] Compile thumb  : packtHAL <= fram.c
    [armeabi] Compile thumb  : packtHAL <= bmp183.c
    [armeabi] SharedLibrary  : libpacktHAL.so
    [armeabi] Install        : libpacktHAL.so => libs/armeabi/libpacktHAL.so

    ```

现在，PacktHAL 库已经构建完成，并作为文件`$PROJECT\libs\armeabi\libpacktHAL.so`存在于你的项目中。

### 在 Linux 下构建 PacktHAL

要使用 PacktHAL，必须将其构建成库并包含在你的应用程序项目代码库中。假设你在`$HOME`目录下解压并解包了`PacktHAL.tgz`文件，你可以使用以下命令将 PacktHAL 代码复制到你的应用程序项目目录（`$PROJECT`）中：

```java
$ cd $PROJECT
$ cp –rf $HOME/PacktHAL/jni .

```

既然你的`$PROJECT`目录中已经存在了`jni`目录，你可以使用 Android NDK 构建 PacktHAL。假设你在`$HOME/android-ndk`中安装了 Android NDK，你可以使用以下过程构建 PacktHAL：

1.  切换到`$PROJECT/jni`目录：

    ```java
    $ cd $PROJECT/jni

    ```

1.  使用 Android NDK 构建 PacktHAL 库：

    ```java
    $ ./$HOME/android-ndk/ndk-build
    [armeabi] Compile thumb  : packtHAL <= jni_wrapper.c
    [armeabi] Compile thumb  : packtHAL <= gpio.c
    [armeabi] Compile thumb  : packtHAL <= fram.c
    [armeabi] Compile thumb  : packtHAL <= bmp183.c
    [armeabi] SharedLibrary  : libpacktHAL.so
    [armeabi] Install        : libpacktHAL.so => libs/armeabi/libpacktHAL.so

    ```

现在，PacktHAL 库已经构建完成，并作为`$PROJECT/libs/armeabi/libpacktHAL.so`文件存在于你的项目中。

# 探索 GPIO 示例应用程序

在本节中，你将研究一个在 BBB 上进行 GPIO 接口的 Android 示例应用程序。该应用程序的目的是演示如何在实际应用程序中使用 PacktHAL 执行 GPIO 读写过程。PacktHAL 提供了一系列接口函数，你可以使用这些函数在 Android 应用程序中处理 GPIO。这些函数允许你读取输入 GPIO 的值并设置输出 GPIO 的值。硬件接口的低级细节在 PacktHAL 中实现，因此你可以快速轻松地让你的应用程序与 GPIO 交互。

在深入探讨 GPIO 应用程序的代码之前，你必须将代码安装到你的开发系统中，并将应用程序安装到你的 Android 系统中。该应用程序的源代码以及预编译的`.apk`包位于`chapter3.tgz`文件中，该文件可在本书的网站下载。

## 在 Windows 下安装应用程序和源代码

下载`chapter3.tgz`文件后，你必须解压并解包它。我们将假设你在下载后将`chapter3.tgz`复制到`c:\`的根目录，并从那里开始解压。我们将你的工作空间目录称为`$WORKSPACE`。

我们将假设你的`adb.exe`二进制文件在当前路径中。如果不是，通过使用`adb.exe`二进制文件的完整路径来调用`adb`：

1.  打开一个文件浏览器窗口并导航到该目录。

1.  在文件浏览器中右键点击`chapter3.tgz`文件并选择**在此处解压**。

现在存在一个名为`c:\gpio`的目录，其中包含了 GPIO 示例应用程序的所有文件。你必须将此项目导入到你的 Eclipse ADT 工作空间中：

1.  启动 Eclipse ADT。

1.  打开**文件**菜单并选择**导入**。

1.  在**导入**对话框中，展开**Android**文件夹并突出显示**将现有 Android 代码导入工作空间**。对话框底部的**下一步**按钮将变为激活状态。点击它以继续。

1.  在**导入项目**对话框中，在**根目录**文本字段中输入`c:\gpio`。然后，点击**刷新**按钮。`gpio`项目将出现在要导入的项目列表中。

1.  点击**全选**按钮，然后勾选**将项目复制到工作空间**的复选框。

1.  点击**完成**按钮，将`gpio`应用程序项目导入你的工作空间，并将`c:\gpio`目录复制到你的`$WORKSPACE`目录中。

现在，GPIO 应用程序的所有项目文件都位于那个`gpio`目录中。在`$WORKSPACE\gpio\bin`目录中提供了一个预构建的`.apk`软件包。你可以使用`adb`直接将这个`.apk`软件包安装到你的 Android 系统中：

1.  启动`cmd.exe`以获取命令提示窗口。使用命令提示符，切换到`$WORKSPACE\gpio\bin`目录：

    ```java
    c:\> cd $WORKSPACE\gpio\bin

    ```

1.  使用`adb devices`命令验证`adb`是否可以看到你的 BBB：

    ```java
    c:\$WORKSPACE\gpio\bin> adb devices
    List of devices attached
    BBBAndroid      device

    ```

1.  通过`adb`中的`install`命令将`gpio.apk`安装到你的 Android 系统中：

    ```java
    c:\$WORKSPACE\gpio\bin> adb install -d gpio.apk

    ```

1.  如果你已经安装过一次`gpio.apk`应用程序，并且现在收到`INSTALL_FAILED_ALREADY_EXISTS`的错误信息，请使用`adb`重新安装`gpio.apk`：

    ```java
    c:\$WORKSPACE\gpio\bin> adb install -d -r gpio.apk

    ```

现在，`gpio.apk`应用程序已安装在你的 Android 系统上，并且应用程序的源代码已安装在 Eclipse ADT 工作空间中。

## 在 Linux 下安装应用程序和源代码

下载`chapter3.tgz`文件后，你必须解压缩并展开它。我们将假设你在下载后已将`chapter3.tgz`复制到你的`$HOME`目录，并从那里开始解压缩。我们将你的工作空间目录称为`$WORKSPACE`。

使用 Linux 的`tar`命令来解压缩和展开`chapter3.tgz`文件：

```java
$ cd $HOME
$ tar –xvf chapter3.tgz

```

现在，在你的`$HOME`目录中存在一个名为`gpio`的目录，其中包含了 gpio 示例应用程序的所有文件。你必须按照以下步骤将其导入到你的 Eclipse ADT 工作空间中：

1.  启动 Eclipse ADT。

1.  打开**文件**菜单，选择**导入**。

1.  在**导入**对话框中，展开`Android`文件夹并选中**将现有 Android 代码导入工作空间**。对话框底部的**下一步**按钮将变为可用。点击它以继续。

1.  在**导入项目**对话框中，在**根目录**文本字段中输入`$HOME/gpio`（将`$HOME`替换为完整路径）。然后，点击**刷新**按钮。`gpio`项目将出现在要导入的项目列表中。

1.  点击**全选**按钮，然后勾选**将项目复制到工作空间**的复选框。

1.  点击**完成**按钮，将 gpio 应用程序项目导入你的工作空间，并将`$HOME/gpio`目录复制到你的`$WORKSPACE`目录中。

现在应用程序的所有项目文件都位于`$WORKSPACE/gpio`目录中。在`gpio/bin`目录中提供了一个为 gpio 项目预构建的`.apk`软件包。你可以使用`adb`直接将这个`.apk`软件包安装到你的 Android 系统中：

1.  切换到`gpio`项目的`bin`目录：

    ```java
    $ cd $WORKSPACE/gpio/bin

    ```

1.  使用`adb devices`命令验证`adb`是否可以看到你的 BBB：

    ```java
    $ adb devices
    List of devices attached
    BBBAndroid      device

    ```

1.  通过`adb`中的`install`命令将`gpio.apk`安装到您的 Android 系统上：

    ```java
    $ adb install -d gpio.apk

    ```

1.  如果您已经安装过一次`gpio.apk`应用程序，现在收到`INSTALL_FAILED_ALREADY_EXISTS`的错误消息，请使用`adb`重新安装`gpio.apk`：

    ```java
    $ adb install -d -r gpio.apk

    ```

`gpio.apk`应用程序现在已安装在您的 Android 系统上，应用程序的源代码现在也安装在了您的 Eclipse ADT 工作空间中。

## 应用程序的用户界面

在 Android 系统上启动`gpio`应用程序以查看应用程序的用户界面(UI)。如果您使用的是触摸屏保护盖，只需在屏幕上触摸 gpio 应用图标即可启动应用程序并与其 UI 交互。如果您使用 HDMI 进行视频输出，请将 USB 鼠标连接到 BBB 的 USB 端口，并使用鼠标点击 gpio 应用图标以启动应用程序。

应用程序使用一个非常简单的 UI 与 GPIOs 交互。由于它非常简单，因此应用程序只有一个默认的`MainActivity`。UI 仅由三个按钮和文本视图组成。

![应用程序的用户界面](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00012.jpeg)

GPIO 示例应用程序屏幕

**轮询按钮状态**按钮检查按钮开关的当前状态，并更新**按钮状态**文本视图的值以报告该状态。在第一次按下**轮询按钮状态**按钮之前，开关状态将报告为**未知**。**打开灯光**按钮将在灯光未打开的情况下打开 LED，而**关闭灯光**按钮将关闭 LED。

文本视图在`res/layout/activity_main.xml`中有一个与之关联的 ID，这样应用程序就可以编程更新文本视图的值：

```java
<TextView
  …
  android:text="@string/button_state"
  android:id="@+id/button_state" />
```

三个按钮中的每一个都有一个定义的`onClick()`处理程序：

```java
<Button
  …
  android:text="@string/button_poll"
  android:onClick="onClickButtonPollStatus" />
<Button
  …
  android:text="@string/button_lighton"
  android:onClick="onClickButtonLightOn" />
<Button
  …
  android:text="@string/button_lightoff"
  android:onClick="onClickButtonLightOff" />
```

每个按钮的`onClick()`处理程序将触发 PacktHAL GPIO 函数之一，以读取 GPIO 的状态或将新状态写入 GPIO。

### 注意

如果您需要刷新关于各种 Android UI 元素的详细信息，网上有许多资源可以帮助您。我们建议您从官方 Android 开发者网站开始，网址是[`developer.android.com/guide/topics/ui/index.html`](http://developer.android.com/guide/topics/ui/index.html)。

## 调用 PacktHAL 函数

PacktHAL 中的 GPIO 接口功能是通过四个 C 函数实现的：

+   `openGPIO()`

+   `readGPIO()`

+   `writeGPIO()`

+   `closeGPIO()`

这些函数的原型位于应用程序项目中的`jni/PacktHAL.h`头文件中：

```java
extern int openGPIO(const int useMmap);
extern int readGPIO(const unsigned int header, const unsigned int pin);
extern int writeGPIO(const unsigned int header,
    const unsigned int pin, const unsigned int value);
extern void closeGPIO(void);
```

理想情况下，您应该将 PacktHAL 共享库加载到您的应用程序中，然后直接调用库函数来控制 GPIOs。示例应用程序实际上通过`System.loadLibrary()`调用来加载 PacktHAL 库，但随后事情变得不那么直接了，因为这些 C 函数不能直接调用。您必须指定 Java 方法，当调用这些方法时，实际上会调用 C 函数。

`MainActivity`类指定了四个带有`native`关键字的方法，用于在`MainActivity.java`中调用 PacktHAL C 函数：

```java
public class MainActivity extends Activity {
  private native boolean openGPIO();
private native void closeGPIO();
private native boolean readGPIO(int header, int pin);
private native void writeGPIO(int header, int pin, int val);

static {
System.loadLibrary("packtHAL");
}
  …
}
```

`MainActivity`中指定的这四个 Java 方法实际上并不是直接映射到 PacktHAL 中同名的 C 函数。注意，`MainActivity`中的 GPIO 方法是类范围内所有`private native`的。任何使用`native`关键字定义的方法在被调用时都会尝试调用一个本地的*JNI 封装函数*。然而，被调用的 JNI 封装函数的命名遵循一些非常特定的规则，这些规则代表了它 Java 端方法的范围。下图展示了这些 JNI 封装函数最终是如何调用 PacktHAL 内部的 GPIO 接口函数的：

![调用 PacktHAL 函数](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00013.jpeg)

`MainActivity`中的方法以及它们调用的 PacktHAL GPIO 接口函数

`MainActivity`类中名为`name()`的每个`native`方法将使用 JNI 来调用名为`Java_com_packt_gpio_MainActivity_name()`的 JNI 封装函数。这个封装函数的名字是通过将应用全限定名中的每个`.`替换为下划线来确定的。函数名中的`Java_`前缀告诉 Android 该函数是通过 Java 类中的方法调用的。关于 JNI 的命名约定有一些例外，但这个通用规则可以解决大多数情况。

### 提示

**我需要了解所有关于 JNI 的知识才能进行自己的 Android 接口项目吗？**

不一定。使用 JNI 可能会相当混乱，许多书籍和教程都详细描述了它。现在，不必担心关于 JNI 的一切都不了解。当你花时间在 Android 下进行硬件接口实验后，可以重新审视这个主题，了解更多关于 JNI 工作原理的细节。在本书中，我们将专注于提供足够的关于 JNI 的信息，以帮助你开始。

作为一个例子，在我们的`com.packtpub.gpio`示例应用中，`MainActivity`类里的 Java `openGPIO()`方法使用了 JNI 来调用封装的 C 函数`Java_com_packtpub_gpio_MainActivity_openGPIO()`。这可能有些令人困惑，但仍然是可以管理的。PacktHAL 在`jni/packt_native_gpio.c`文件中实现了这些 JNI 封装的 C 函数。查看这个源文件，你可以看到 PacktHAL 中的`Java_com_packtub_gpio_MainActivity_openGPIO()`函数是如何调用 PacktHAL 中的`openGPIO()` C 函数的：

```java
jboolean Java_com_packt_gpio_MainActivity_openGPIO(JNIEnv *env,
   jobject this)
{
  jboolean ret = JNI_TRUE;
  if ( openGPIO(0) == 0 ) {
    __android_log_print(ANDROID_LOG_DEBUG, PACKT_NATIVE_TAG,
          "GPIO Opened.");
  } else {
    __android_log_print(ANDROID_LOG_ERROR, PACKT_NATIVE_TAG,
          "openGPIO() failed!");
    ret = JNI_FALSE;
  }
  return ret;
}
```

为什么不干脆取消单独的 `openGPIO()` C 函数，并将所有硬件接口代码放入 `Java_com_packt_gpio_MainActivity_openGPIO()` 中呢？一旦你让它们正常工作，PacktHAL 中的函数如 `openGPIO()` 通常不会改变，而且你可以在 Linux 和 Android 下使用这些相同的函数。像 `Java_com_packt_gpio_MainActivity_openGPIO()` 这样的包装函数会根据它们如何以及从应用的 Java 代码何处被调用而改变其名称和实现细节。将不会改变的功能隔离在其自己的函数中是更好的选择。这样可以避免在自定义或重命名通过 JNI 调用的函数时意外破坏某些东西。

### 注意

请记住，你的应用中的 Java 方法（如 `MainActivity` 类中的 `openGPIO()`）会进行 JNI 调用，以调用具有长且复杂名称的 PacktHAL C 函数，如 `Java_com_packt_gpio_MainActivity_openGPIO()`。JNI 包装函数然后将调用 PacktHAL C 函数之一，例如 `openGPIO()`，实际控制硬件。从应用开发者的角度来看，一旦你弄清楚 JNI 包装函数的细节，几乎就像直接从 Java 应用代码调用控制硬件的 C 函数一样！

## 使用 PacktHAL GPIO 函数

现在你已经了解了如何从 Java 调用 PacktHAL GPIO 函数，接下来你将了解这些函数各自的作用以及如何使用它们。

`openGPIO()` 函数初始化应用对 GPIO 的访问。这个函数为你提供了两种不同的 GPIO 接口方法，你可以使用 `openGPIO()` 函数的 `useMmap` 参数选择其中一种方法。这两种方法是文件 I/O（通过将 `useMmap` 设置为 0）和内存映射（通过将 `useMmap` 设置为非零数字）。要从一种接口方法更改为另一种，你必须调用 `closeGPIO()` 来关闭 PacktHAL 的 GPIO 部分，然后再次调用 `openGPIO()`，并为 `useMmap` 提供不同的值。

进程必须以 `root` 身份运行，以使用内存映射直接访问 GPIO 控制电阻。由于应用不能以 root 身份运行，JNI 包装函数总是将 `0` 作为 `useMmap` 参数传递给 `openGPIO()`，以强制使用文件 I/O 与 GPIO 交互。由于这个原因，`MainActivity` 类中的 `openGPIO()` 方法不接受任何参数。

示例应用从 `MainActivity` 类的 `onCreate()` 方法中调用 `openGPIO()` 方法：

```java
protected void onCreate(Bundle savedInstanceState) {
  ... //Existing statements    
  TextView tv = (TextView) findViewById(R.id.button_state);
tv.setText("Button State: UNKNOWN");

   if(openGPIO() == false) {
      Log.e("com.packt", "Unable to open GPIO.");
        finish();
   }
}
```

对 `closeGPIO()` 方法的补充调用是由 `MainActivity` 类的 `onDestroy()` 方法完成的：

```java
protected void onDestroy() {
   closeGPIO();
}
```

`readGPIO()` 方法读取特定输入 GPIO 的状态。PacktHAL 的 `readGPIO()` 函数和 `MainActivity` 中的 `readGPIO()` 方法接受相同的两个参数。第一个参数是 BBB 上的连接器编号（8 或 9），第二个参数是该连接器上的引脚位置（1 到 42）。`readGPIO()` 方法在 `PollStatus` 按钮的 `onClick()` 处理程序内被调用：

```java
public void onClickPollStatus(View view) {
   String status = readGPIO(9, 13) == true ? "ON" : "OFF";
TextView tv = (TextView) findViewById(R.id.button_state);
tv.setText("Button State: " + status);
}
```

在`onClickPollStatus()`中，`readGPIO()`方法的调用是读取 GPIO 引脚 P9.13 的状态。这是你连接到按钮开关的 GPIO 引脚。如果当调用`readGPIO()`方法时开关被按下，将返回`true`。否则，返回`false`。

`writeGPIO()`方法用于设置输出 GPIO 的状态。PacktHAL 的`writeGPIO()`函数和`MainActivity`中的`writeGPIO()`方法都接受三个参数。第一个参数是 BBB 上的连接器编号（8 或 9），第二个参数是连接器上的引脚位置（1 到 42），第三个参数是要设置的值（0 或 1）。`writeGPIO()`方法在`LightOn`和`LightOff`按钮的`onClick`处理程序内部被调用：

```java
public void onClickButtonLightOn(View view) {
   writeGPIO(9, 11, 1);
}

public void onClickButtonLightOff(View view) {
   writeGPIO(9, 11, 0);
}
```

在这两个`onClick()`处理程序中，设置的 GPIO 是 P9.11。这是你连接到 LED 的 GPIO 引脚。`onClickButtonLightOn()`方法将 GPIO 设置为 1，打开 LED。同样，`onClickButtonLightOff()`方法将 GPIO 设置为 0，关闭 LED。

### 提示

**你准备好迎接挑战了吗？**

既然你已经了解了 gpio 应用的各个部分，为什么不尝试改变它以添加新功能呢？作为一个挑战，尝试将应用改为仅使用一个按钮来切换 LED 的状态。如果 LED 当前是关闭的，按下按钮将会打开它，反之亦然。我们在`chapter3_challenge.tgz`文件中提供了一个可能的实现，你可以在本书的网站上下载。

# 总结

在本章中，我们向你介绍了 GPIO 以及它们的工作原理。你构建了一个使用 GPIO 进行输入和输出的电路，并对电路进行了基本测试，以确保电路构建正确并且内核能够通过文件系统与电路交互。你还了解了 PacktHAL 的`init.{ro.hardware}.rc`文件和`BB-PACKTPUB-00A0.dtbo`设备树覆盖部分，它们负责配置 GPIO 并使它们可供你的应用使用。

我们向你展示了如何将 PacktHAL 添加到新创建的应用项目中，以及如何使用 Android NDK 构建 PacktHAL。然后，你学习了 JNI 如何通过 JNI 包装函数将 PacktHAL 集成到你的 Java 应用中，并探索了如何在应用内部调用并使用 PacktHAL 的每个 GPIO 功能。

在下一章中，你将学习如何将 I2C 总线设备集成到你的应用中，并开始与比 GPIO 的基本开关逻辑复杂得多的硬件进行交互。


# 第四章：使用 I2C 存储和检索数据

在上一章中，你使用了 GPIO 与外部世界交换简单的数字数据。但是，如何与需要复杂的位或字节序列进行通信的更高级设备进行接口呢？

目前在嵌入式系统中使用最广泛的接口总线之一是**集成电路间**串行总线（通常简称为**IIC**、**I**2**C**或**I2C**）。在本章中，你将学习如何编写一个使用 BBB 的 I2C 接口将数据存储到 FRAM 芯片并从中检索数据的程序。我们将涵盖以下主题：

+   理解 I2C

+   BBB 上的 I2C 复用

+   在 Linux 内核中表示 I2C 设备

+   构建一个 I2C 接口电路

+   探索 I2C FRAM 示例应用

# 理解 I2C

I2C 协议最初由飞利浦半导体于 1982 年开发，作为与 IC 通信的总线，现在已经成为得到广泛支持的通用总线，被众多 IC 制造商支持。I2C 是一个多主多从总线，尽管最常见的配置是一个主设备和一条总线上的一个或多个从设备。I2C 主设备通过生成时钟信号来为总线设定节奏，并启动与从设备的通信。从设备接收主设备的时钟信号并对主设备的查询做出响应。

通过 I2C 通信只需要四根线：

+   一个时钟信号（SCL）

+   一个数据信号（SDA）

+   一个正电源电压

+   一个地线

只需要两个引脚（用于 SCL 和 SDA 信号）与多个从设备通信，这使得 I2C 成为一个吸引人的接口选择。硬件接口的一个难点是有效地分配有限的处理器引脚，以便同时与大量不同的设备进行通信。通过只需要两个处理器引脚与各种设备通信，I2C 释放了可以分配给其他任务的引脚。

![理解 I2C](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00014.jpeg)

一个带有单个主设备与三个从设备的 I2C 总线示例

## 使用 I2C 的设备

由于 I2C 总线的灵活性和广泛使用，许多设备使用它进行通信。诸如 EEPROM 和 FRAM ICs 等不同类型的存储设备通常通过 I2C 接口连接。例如，BBB 扩展板上的 EEPROM 都是通过 BBB 处理器的 I2C 进行访问的。温度、压力和湿度传感器，加速度计，LCD 控制器和步进电机控制器等设备都可以通过 I2C 总线获取。

# BBB 上的 I2C 复用

BBB 的 AM335X 处理器提供了三条 I2C 总线：

+   I2C0

+   I2C1

+   I2C2

BBB 通过其 P9 接头暴露 I2C1 和 I2C2 总线，但 I2C0 总线不容易访问。目前 I2C0 提供了 BBB 处理器与内置 HDMI cape 的 HDMI 帧处理器芯片之间的通信通道，因此应考虑不适用于你使用（除非你想通过在 BBB 上焊接电线直接到痕迹和芯片引脚来废除保修）。

I2C1 总线可供你一般使用，并且通常是与 I2C 接口的*首选*总线。如果 I2C1 达到其最大容量或不可用，I2C2 总线也可供你使用。

## 通过 P9 接头连接到 I2C

默认情况下，I2C1 没有复用到任何引脚上，而 I2C2 可以通过 P9.19 和 P9.20 引脚使用。I2C2 提供了外部 cape 板上的识别 EEPROM 与内核的 capemgr 之间的 I2C 通信。你可以将 I2C2 复用到其他引脚上，甚至完全禁用它，但如果你这样做，capemgr 将无法自动检测连接到 BBB 的 cape 板。通常来说，你可能不想这样做。

下图显示了 P9 接头上的每个潜在的引脚，I2C 信号可以被复用到这些位置：

![通过 P9 接头连接到 I2C](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00015.jpeg)

在 P9 接头不同 pinmux 模式下 I2C 总线位置

## I2C 的复用

在决定如何在项目中使用 I2C 时复用你的引脚，请记住以下事项：

+   避免将任何单一的 I2C 信号复用到多个引脚上。这样做会浪费你的一个引脚，而且没有充分的理由。

+   避免将 I2C2 从其默认位置复用，因为这会阻止 capemgr 自动检测连接到 BBB 的 cape 板。

+   你可以使用默认的 I2C2 总线进行你的项目，但请注意，它的时钟为 100 KHz，地址 0x54 到 0x57 是为 cape EEPROM 保留的。

+   将 I2C1 通道复用到 P9.17 和 P9.18 会与 SPI0 通道冲突，因此如果你也希望使用 SPI，通常不希望使用这种配置。

# 在 Linux 内核中表示 I2C 设备

I2C 总线和设备在用户空间作为`/dev`文件系统中的文件暴露出来。I2C 总线作为`/dev/i2c-X`文件暴露，其中`X`是 I2C 通道的逻辑编号。虽然 I2C 总线的硬件信号清楚地编号为 0、1 和 2，但逻辑通道编号不一定与它们的硬件对应物相同。

逻辑通道编号是按照 Device Tree 中初始化 I2C 通道的顺序分配的。例如，I2C2 通道通常是由内核初始化的第二个 I2C 通道。因此，尽管它是物理 I2C 通道 2，它将是逻辑 I2C 通道 1，并作为`/dev/i2c-1`文件访问。

在 Android API 和服务层之下，Android 最终通过在`/dev`和`/sys`文件系统中打开文件，然后读取、写入或对这些文件执行`ioctl()`调用来与内核中的设备驱动交互。虽然仅使用`/dev/i2c-X`文件的`ioctl()`调用来与任何 I2C 设备交互，直接控制 I2C 总线是可能的，但这种方法很复杂，通常应避免使用。相反，你应该尝试使用一个内核驱动，该驱动在 I2C 总线上为你与设备通信。然后你可以对该内核驱动暴露的文件执行`ioctl()`调用，以轻松控制你的设备。

## 为 FRAM 使用准备 Android

在第二章《*与 Android 接口*》中，你使用`adb`将两个预构建的文件推送到你的 Android 系统中。这两个文件，`BB-PACKTPUB-00A0.dtbo`和`init.{ro.hardware}.rc`，配置你的 Android 系统以启用处理 FRAM 接口的内核设备驱动，复用引脚以启用 I2C1 总线，并允许你的应用程序访问它。

就 I2C 而言，`BB-PACKTPUB-00A0.dtbo`覆盖层将 P9.24 和 P9.26 引脚复用为 I2C SCL 和 SDA 信号。在`PacktHAL.tgz`文件中，覆盖层的源代码位于`cape/BB-PACKTPUB-00A0.dts`文件中。负责复用这两个引脚的代码位于`fragment@0`中的`bb_i2c1a1_pins`节点内：

```java
/* All I2C1 pins are SLEWCTRL_SLOW, INPUT_PULLUP, MODE3 */
bb_i2c1a1_pins: pinmux_bb_i2c1a1_pins {
    pinctrl-single,pins = <
        0x180 0x73  /* P9.26, i2c1_sda */
        0x184 0x73  /* P9.24, i2c1_scl */
    >;
};
```

虽然这设置了复用，但它并没有为这些引脚分配和配置设备驱动。`fragment@1`节点执行这个内核驱动分配：

```java
fragment@1 {
    target = <&i2c1>;
    __overlay__ {
        status = "okay";
        pinctrl-names = "default";
        pinctrl-0 = <&bb_i2c1a1_pins>;
        clock-frequency = <400000>;
        #address-cells = <1>;
        #size-cells = <0>;

        /* This is where we specify each I2C device on this bus */
        adafruit_fram: adafruit_fram0@50 {
            /* Kernel driver for this device */
            compatible = "at,24c256";
            /* I2C bus address */
            reg = <0x50>;
        };
    };
};
```

不深入过多细节，`fragment@1`中有四个设置对你来说很有兴趣：

+   第一个设置是`pinctrl-0`，它将 Device Tree 的此节点与`bb_i2c1a1_pins`节点中复用的引脚绑定

+   第二个设置是`clock-frequency`，它将 I2C 总线速度设置为 400 KHz

+   第三个设置是`compatible`，它指定了将处理我们硬件设备的特定内核驱动（对于类似 EEPROM 的设备的`24c256`驱动）

+   最后一个设置是`reg`，它指定了该设备在 I2C 总线上的地址（在我们的案例中是`0x50`）

# 构建一个 I2C 接口电路

既然你已经了解了 I2C 设备是如何连接到 BBB 的，以及 Linux 内核是如何为这些设备提供一个接口的，现在是时候将一个 I2C 设备连接到 BBB 上了。

正如我们在第一章*Android 和 BeagleBone Black 简介*中提到的，本章你将和一个 FRAM 芯片进行接口操作。具体来说，它是富士通半导体 MB85RC256V FRAM 芯片。这个 8 引脚芯片提供 32 KB 的非易失性存储。这个特定的芯片仅提供**小型外廓封装**（**SOP**），这是一种表面贴装芯片，在构建原型电路时可能难以操作。幸运的是，AdaFruit 为 FRAM 提供的开发板已经安装了该芯片，这使得原型设计变得简单轻松。

### 提示

**不要拆开你的电路！**

本章中的 FRAM 电路是第六章*创建完整的接口解决方案*中使用的更大电路的一部分。如果你按照图中的位置（面包板底部）构建电路，那么在构建本书中剩余电路时，你可以简单地将 FRAM 开发板和电线留在原位。这样，当你到达第六章时，它就已经构建好并可以工作了。

## 连接 FRAM

每个 I2C 设备必须使用一个地址来在 I2C 总线上标识自己。我们使用的 FRAM 芯片可以配置为使用 0x50 到 0x57 范围内的地址。这是 EEPROM 设备的常见地址范围。确切的地址是通过使用开发板的地址线（A0、A1、A2）来设置的。FRAM 的基准地址是 0x50。如果 A0、A1 和/或 A2 线连接到 3.3 V 信号，则分别向地址添加 0x1、0x2 和/或 0x4。对于这个接口项目，所有地址线都不连接，这导致 FRAM 在 I2C 总线上保留其基准地址 0x50。

![连接 FRAM](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00016.jpeg)

FRAM 开发板（A0、A1 和 A2 地址线位于板子的最右侧三个端子）

### 注意

许多 I2C 设备的地址可以通过将设备的地址引脚连接到地或电压信号来进行配置。这是因为 I2C 总线上可能有相同设备的多个副本。电路设计者可以通过重新连接地址引脚，为每个设备分配不同的地址，而无需购买具有不同预分配地址且互不冲突的不同部件。

下图展示了 FRAM 开发板与 BBB 之间的连接。四个主要的 I2C 总线信号（+3.3 V、地、I2C SCL/SDA）是通过 P9 连接器的引脚实现的，因此我们将面包板放在 BBB 的 P9 侧。

![连接 FRAM](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00017.jpeg)

完整的 I2C 接口电路

让我们开始吧：

1.  将 P9.1（地）连接到面包板的垂直地线，并将 P9.3（3.3 V）连接到面包板的垂直电源线。这些连接与你在第三章，*使用 GPIO 处理输入和输出*中创建的 GPIO 面包板电路所做的连接相同。

1.  I2C 信号，SCL 和 SDA 分别位于 P9.24 和 P9.26 引脚上。将 P9.24 引脚连接到面包板上标记为 SCL 的引脚，将 P9.26 引脚连接到标记为 SDA 的引脚。

1.  将地线连接到面包板的 GND 引脚，将电源线连接到 VCC 引脚。将**写保护**（**WP**）引脚和三个地址引脚（A0、A1、A2）保持未连接。

FRAM 面包板现在电连接到 BBB，可供使用。再次检查你的布线与完整的 FRAM 接口电路图对照，以确保一切连接正确。

## 使用 I2C 工具检查 FRAM 连接

I2C 工具是一组允许你探测和与 I2C 总线交互的实用程序。这些工具在采用 Linux 内核的系统上工作，并包含在 BBBAndroid 映像中。这些实用程序通过打开`/dev/i2c-X`设备文件并与它们进行`ioctl()`调用来与 I2C 总线交互。默认情况下，使用`i2c-tools`必须具有 root 访问权限，但 BBBAndroid 降低了`/dev/i2c-X`文件的权限，使得任何进程（包括`i2c-tools`）都可以读取和写入有关 I2C 总线的信息。

作为一个例子，让我们尝试使用`i2c-tools`中的`i2cdetect`实用程序。`i2cdetect`将扫描指定的 I2C 总线，并识别 I2C 设备所在的总线地址。使用 ADB shell，你将探测 i2c-2 物理总线，这也是第二个逻辑总线（`/dev/i2c-1`）：

```java
root@beagleboneblack:/ # i2cdetect -y -r 1
 0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
00:          -- -- -- -- -- -- -- -- -- -- -- -- --
10: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
20: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
30: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
40: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
50: -- -- -- -- UU UU UU UU -- -- -- -- -- -- -- --
60: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
70: -- -- -- -- -- -- -- --

```

### 注意

`i2cdetect`的输出显示了当前总线上检测到的每个设备。任何未被使用的地址都有一个`--`标识符。在设备树中为设备驱动保留的地址，但目前没有在相应地址检测到设备，会有一个`UU`标识符。如果在特定地址检测到设备，该设备的两位十六进制地址将作为标识符出现在`i2cdetect`的输出中。

`i2cdetect`命令的输出显示，设备树已经在 i2c-2 物理总线上为四个 I2C 设备分配了驱动程序。这四个设备是 capemgr 中地址为 0x54-0x57 的 EEPROM。实际上这些设备并不存在，因为没有将 cape 板连接到 BBB，所以每个地址都有一个`UU`标识符。

在 FRAM 面包板电连接到 BBB 之后，你必须确认 FRAM 在 I2C 总线上是一个可见的设备。为此，使用`i2cdetect`检查 i2c-1 物理总线（逻辑总线 2）上存在的设备：

```java
root@beagleboneblack:/ # i2cdetect -y -r 2
 0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
00:          -- -- -- -- -- -- -- -- -- -- -- -- --
10: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
20: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
30: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
40: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
50: 50 -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
60: -- -- -- -- -- -- -- -- -- -- -- -- -- -- -- --
70: -- -- -- -- -- -- -- --

```

### 提示

**再次检查你的布线**

如果`i2cdetect`输出在 0x50 地址位置显示`UU`，则你知道 I2C 总线没有识别到连接的 FRAM。确保在将 FRAM 开发板连接到 BBB 时，你没有意外交换 SCL（P9.24）和 SDA（P9.26）电线。

# 探索 I2C FRAM 示例应用程序

在本节中，我们将检查一个与 BBB 上的 I2C 接口的示例 Android 应用程序，以连接 FRAM。此应用程序的目的是演示如何使用 PacktHAL 在实际应用程序中执行 FRAM 的读写操作。PacktHAL 提供了一组接口功能，你可以使用这些功能在你的 Android 应用程序中与 FRAM 开发板进行交互。这些功能允许你从 FRAM 检索数据块并将新数据写入 FRAM 进行存储。硬件接口的低级细节在 PacktHAL 中实现，因此你可以快速轻松地让你的应用程序与 FRAM 开发板进行交互。

在深入研究 FRAM 应用程序的代码之前，你必须将代码安装到你的开发系统中，并将应用程序安装到你的 Android 系统上。该应用程序的源代码以及预编译的`.apk`包都位于`chapter4.tgz`文件中，该文件可在 Packt 网站上下载。按照与第三章中描述的相同过程下载并添加应用程序到你的 Eclipse ADT 环境，该章节是关于使用 GPIO 处理输入和输出。

## 应用程序的用户界面

在 Android 系统上启动`fram`应用程序以查看应用程序的用户界面。如果你使用的是触摸屏保护盖，只需在屏幕上触摸**fram**应用程序图标即可启动应用程序并与其用户界面互动。如果你使用 HDMI 进行视频输出，请将 USB 鼠标连接到 BBB 的 USB 端口，并使用鼠标点击**fram**应用程序图标以启动应用程序。由于此应用程序接受用户输入文本，你可能发现连接 USB 键盘到 BBB 很方便。否则，你还可以使用屏幕上的 Android 键盘输入文本。

此应用程序的用户界面比上一章中的 GPIO 应用程序复杂一些，但仍然相当简单。由于它非常简单，因此应用程序仅有的活动是默认的`MainActivity`。用户界面包括两个文本字段，两个按钮和两个文本视图。

![应用程序的用户界面](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00018.jpeg)

FRAM 示例应用程序屏幕

`activity_main.xml`文件中的顶部文本字段具有`saveEditText`标识符。`saveEditText`字段最多接受 60 个字符，这些字符将被存储到 FRAM 中。带有**保存**标签的顶部按钮具有`saveButton`标识符。此按钮有一个名为`onClickSaveButton()`的`onClick()`方法，该方法会触发与 FRAM 接口以存储`saveEditText`文本字段中的文本的过程。

底部文本字段具有 `loadEditText` 标识符。这个文本字段将显示保存在 FRAM 中的任何数据。底部带有 **Load** 标签的按钮具有 `loadButton` 标识符。这个按钮有一个 `onClick()` 方法，名为 `onClickLoadButton()`，它会触发与 FRAM 接口的过程，加载前 60 个字节的数据，然后更新 `loadEditText` 文本字段中显示的文本。

## 调用 PacktHAL FRAM 函数

PacktHAL 中的 FRAM 接口功能是通过四个 C 函数实现的：

+   `openFRAM()`

+   `readFRAM()`

+   `writeFRAM()`

+   `closeFRAM()`

这些函数的原型位于应用项目中的 `jni/PacktHAL.h` 头文件中：

```java
extern int openFRAM(const unsigned int bus, const unsigned int address);
extern int readFRAM(const unsigned int offset, const unsigned int 
    bufferSize, const char *buffer);
extern int writeFRAM(const unsigned int offset, const unsigned int 
    const char *buffer);
extern void closeFRAM(void);
```

`openFRAM()` 函数打开 `/dev` 文件系统中的文件，该文件提供了与 24c256 EEPROM 内核驱动的接口。它的对应函数是 `closeFRAM()`，一旦不再需要与 FRAM 进行硬件接口，它就会关闭这个文件。`readFRAM()` 函数从 FRAM 中读取数据缓冲区，而 `writeFRAM()` 函数将数据缓冲区写入 FRAM 以进行持久存储。这四个函数共同提供了与 FRAM 交互所需的所有必要功能。

与前一章的 `gpio` 应用一样，`fram` 应用通过 `System.loadLibrary()` 调用来加载 PacktHAL 共享库，以访问 PacktHAL FRAM 接口函数和调用它们的 JNI 包装函数。但是，与 `gpio` 应用不同，`fram` 应用的 `MainActivity` 类并没有使用 `native` 关键字指定调用 PacktHAL JNI 包装 C 函数的方法。相反，它将硬件接口留给了一个名为 `HardwareTask` 的*异步任务*类：

```java
Public class MainActivity extends Activity {

    Public static HardwareTask hwTask;

    Static {
        System.loadLibrary("packtHAL");
    }
```

## 理解 AsyncTask 类

`HardwareTask` 扩展了 `AsyncTask` 类，使用它相比于 `gpio` 应用中实现硬件接口的方式具有显著优势。`AsyncTask` 允许你执行复杂且耗时的硬件接口任务，在任务执行期间不会让应用变得无响应。`AsyncTask` 类的每个实例可以在 Android 中创建一个新的**执行线程**。这类似于其他操作系统上的多线程程序，通过创建新线程来处理文件和网络 I/O、管理 UI 和执行并行处理。

在前一章中，`gpio` 应用在其执行过程中只使用了单个线程。这个线程是所有 Android 应用中都有的主 UI 线程。UI 线程旨在尽可能快地处理 UI 事件。当你与 UI 元素交互时，UI 线程会调用该元素的处理器方法。例如，点击按钮会导致 UI 线程调用按钮的 `onClick()` 处理器。`onClick()` 处理器然后执行一段代码并返回到 UI 线程。

Android 一直在监控 UI 线程的执行。如果一个处理程序花费太长时间来完成其执行，Android 会向用户显示**应用程序无响应**（**ANR**）对话框。你*绝对*不希望出现 ANR 对话框给用户。这是你的应用在 UI 线程中的处理程序中花费太多时间而运行低效（甚至根本不运行！）的标志。

![理解 AsyncTask 类](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00019.jpeg)

Android 中的应用程序无响应对话框

上一个章节中的`gpio`应用在 UI 线程内非常快速地读取和写入 GPIO 状态，因此触发 ANR 的风险非常小。与 FRAM 的接口是一个更慢的过程。使用 BBB 的 I2C 总线以最大速度 400 KHz 运行时，使用 FRAM 读取或写入一个字节的数据大约需要 25 微秒。对于小写入来说这并不是一个主要问题，但是读取或写入整个 32,768 字节的 FRAM 可能需要接近一秒钟来执行！

多次读取和写入整个 FRAM 很容易触发 ANR 对话框，因此有必要将这些耗时的活动移出 UI 线程。通过将你的硬件接口放入它自己的`AsyncTask`类中，你可以将这些耗时的任务执行与 UI 线程的执行解耦。这防止了你的硬件接口可能触发 ANR 对话框。

## 学习`HardwareTask`类的细节

`HardwareTask`的基类`AsyncTask`提供了许多不同的方法，你可以通过参考 Android API 文档进一步探索。对于我们硬件接口工作的四个`AsyncTask`方法立即值得关注：

+   `onPreExecute()`

+   `doInBackground()`

+   `onPostExecute()`

+   `execute()`

这四个方法中，只有`doInBackground()`方法在其自己的线程中执行。其他三个方法都在 UI 线程的上下文中执行。只有 UI 线程上下文中执行的方法能够更新屏幕 UI 元素。

![学习 HardwareTask 类的细节](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00020.jpeg)

`HardwareTask`方法和 PacktHAL 函数执行的线程上下文

类似于上一个章节中`gpio`应用的`MainActivity`类，`HardwareTask`类提供了四个`native`方法，用于调用与 FRAM 硬件接口相关的 PacktHAL JNI 函数：

```java
public class HardwareTask extends AsyncTask<Void, Void, Boolean> {

  private native boolean openFRAM(int bus, int address);
  private native String readFRAM(int offset, int bufferSize);
  private native void writeFRAM(int offset, int bufferSize, 
      String buffer);
  private native boolean closeFRAM();
```

`openFRAM()`方法初始化你的应用对位于逻辑 I2C 总线（`bus`参数）上特定总线地址（`address`参数）的 FRAM 的访问。一旦通过`openFRAM()`调用初始化了对特定 FRAM 的连接，所有`readFRAM()`和`writeFRAM()`调用都将应用于该 FRAM，直到进行了`closeFRAM()`调用。

`readFRAM()`方法将从 FRAM 中检索一系列字节，并将其返回为 Java `String`。从 FRAM 开始的位置偏移`offset`字节开始，共检索`bufferSize`字节。`writeFRAM()`方法将一系列字节存储到 FRAM 中。从 Java 字符串`buffer`中取出`bufferSize`个字符，从 FRAM 开始的位置偏移`offset`字节开始存储。

在`fram`应用中，`MainActivity`类中的**Load**和**Save**按钮的`onClick()`处理程序各自实例化一个新的`HardwareTask`。在`HardwareTask`实例化之后，立即调用`loadFromFRAM()`或`saveToFRAM()`方法开始与 FRAM 交互：

```java
public void onClickSaveButton(View view) {
   hwTask = new HardwareTask();
   hwTask.saveToFRAM(this);  
}

public void onClickLoadButton(View view) {
   hwTask = new HardwareTask();
   hwTask.loadFromFRAM(this);
}
```

`HardwareTask`类中的`loadFromFRAM()`和`saveToFRAM()`方法都调用基`AsyncTask`类的`execution()`方法来开始新线程的创建过程：

```java
public void saveToFRAM(Activity act) {
   mCallerActivity = act;
   isSave = true;
   execute();
}

public void loadFromFRAM(Activity act) {
   mCallerActivity = act;
   isSave = false;
   execute();
}
```

### 注意

每个的`AsyncTask`实例只能调用一次其`execute()`方法。如果您需要再次运行`AsyncTask`，则必须实例化一个新的实例，并调用新实例的`execute()`方法。这就是为什么我们在**Load**和**Save**按钮的`onClick()`处理程序中实例化一个新的`HardwareTask`实例，而不是实例化单个`HardwareTask`实例并多次调用其`execute()`方法的原因。

`execute()`方法自动调用`HardwareTask`类的`onPreExecute()`方法。`onPreExecute()`方法执行在新线程开始之前必须发生的任何初始化。在`fram`应用中，这需要禁用各种 UI 元素并调用`openFRAM()`通过 PacktHAL 初始化与 FRAM 的连接：

```java
protected void onPreExecute() {  
   // Some setup goes here
   ...    
  if ( !openFRAM(2, 0x50) ) {
     Log.e("HardwareTask", "Error opening hardware");
     isDone = true;
  }
  // Disable the Buttons and TextFields while talking to the hardware
  saveText.setEnabled(false);
  saveButton.setEnabled(false);
  loadButton.setEnabled(false); 
}
```

### 提示

**禁用您的 UI 元素**

当您执行后台操作时，您可能希望防止用户在操作完成前提供更多输入。在 FRAM 读写期间，我们不希望用户按下任何 UI 按钮或更改`saveText`文本字段中的数据。如果您的 UI 元素始终处于启用状态，用户可能会通过反复点击 UI 按钮同时启动多个`AsyncTask`实例。为防止这种情况，请禁用需要限制用户输入的任何 UI 元素，直到需要该输入为止。

一旦`onPreExecute()`方法执行完毕，`AsyncTask`基类将启动一个新线程并在该线程中执行`doInBackground()`方法。新线程的生命周期仅限于`doInBackground()`方法的执行期间。一旦`doInBackground()`返回，新线程将终止。

由于`doInBackground()`方法中执行的所有操作都在后台线程中完成，因此它是执行任何耗时的活动的完美场所，如果这些活动从 UI 线程中执行，可能会触发 ANR 对话框。这意味着访问 I2C 总线并与 FRAM 通信的缓慢的`readFRAM()`和`writeFRAM()`调用应该从`doInBackground()`中发出：

```java
protected Boolean doInBackground(Void... params) {  
   ...
   Log.i("HardwareTask", "doInBackground: Interfacing with hardware");
   try {
      if (isSave) {
         writeFRAM(0, saveData.length(), saveData);
      } else {
        loadData = readFRAM(0, 61);
      }
   } catch (Exception e) {
      ...
```

### 注意

在`readFRAM()`和`writeFRAM()`调用中使用的`loadData`和`saveData`字符串变量，都是`HardwareTask`类的类变量。`saveData`变量通过在`HardwareTask`类的`onPreExecute()`方法中的`saveEditText.toString()`调用，填充了`saveEditText`文本字段的内容。

### 提示

**如何在 AsyncTask 线程中更新 UI？**

尽管在本次示例中`fram`应用没有使用它们，但`AsyncTask`类提供了两个特殊方法`publishProgress()`和`onPublishProgress()`，值得一提。`AsyncTask`线程使用这些方法在运行时与 UI 线程通信。`publishProgress()`方法在`AsyncTask`线程中执行，并触发 UI 线程中的`onPublishProgress()`执行。这些方法通常用于更新进度条（因此得名`publishProgress`）或其他不能直接从`AsyncTask`线程更新的 UI 元素。你将在第六章，*创建一个完整的接口解决方案*中使用`publishProgress()`和`onPublishProgress()`方法。

当`doInBackground()`完成后，`AsyncTask`线程将终止。这会触发从 UI 线程调用`doPostExecute()`。`doPostExecute()`方法用于任何后线程清理以及需要更新的 UI 元素。`fram`应用使用`closeFRAM()` PacktHAL 函数来关闭通过`openFRAM()`在`onPreExecute()`方法中打开的当前 FRAM 上下文。

```java
protected void onPostExecute(Boolean result) {
   if (!closeFRAM()) {
    Log.e("HardwareTask", "Error closing hardware");
  }
   ...
```

现在必须通知用户任务已完成。如果按下**加载**按钮，则通过`MainActivity`类的`updateLoadedData()`方法更新`loadTextField`小部件中显示的字符串。如果按下**保存**按钮，则显示一个`Toast`消息，以通知用户保存成功。

```java
Log.i("HardwareTask", "onPostExecute: Completed.");
if (isSave) {
   Toast toast = Toast.makeText(mCallerActivity.getApplicationContext(), 
      "Data stored to FRAM", Toast.LENGTH_SHORT);
   toast.show();
} else {
   ((MainActivity)mCallerActivity).updateLoadedData(loadData);
}
```

### 提示

**向用户显示 Toast 反馈**

`Toast`类是向应用用户提供快速反馈的好方法。它会弹出一个在可配置时间后消失的小消息。如果你在后台执行与硬件相关的任务，并且想要在不更改任何 UI 元素的情况下通知用户任务完成，请尝试使用`Toast`消息！`Toast`消息只能由从 UI 线程中执行的方法触发。

![了解 HardwareTask 类的细节](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00021.jpeg)

`Toast`消息的示例

最后，`onPostExecute()`方法将重新启用所有在`onPreExecute()`中被禁用的 UI 元素：

```java
saveText.setEnabled(true);
saveButton.setEnabled(true);
loadButton.setEnabled(true);
```

`onPostExecute()`方法现在已经完成了执行，应用程序正在耐心等待用户通过按下**加载**或**保存**按钮来提出下一个`fram`访问请求。

### 小贴士

**你准备好迎接挑战了吗？**

既然你已经看到了`fram`应用程序的所有部分，为何不修改它以添加新功能呢？作为一个挑战，尝试添加一个计数器，指示用户在达到 60 个字符限制之前还可以在`saveText`文本字段中输入多少个字符。我们在`chapter4_challenge.tgz`文件中提供了一个可能的实现，你可以在 Packt 的网站上下载。

# 总结

在本章中，我们向你介绍了 I2C 总线。你构建了一个电路，将 I2C FRAM 开发板连接到 BBB，然后使用`i2c-tools`中的`i2cdetect`对电路进行了一些基本测试，以确保电路构建正确且内核能够通过文件系统与电路交互。你还了解了 PacktHAL `init.{ro.hardware}.rc`文件和 Device Tree 覆盖部分，它们负责配置并使 I2C 总线和 I2C 设备驱动可供你的应用程序使用。本章中的`fram`应用程序演示了如何使用`AsyncTask`类执行耗时硬件接口任务，而不会挂起应用程序的 UI 线程并触发 ANR 对话框。

在下一章中，你将了解到高速**串行外围设备接口**（**SPI**）总线，并使用它来与环境传感器进行接口。


# 第五章：使用 SPI 与高速传感器接口

在上一章中，你使用 I2C 总线与 FRAM 设备通信，该设备需要比 GPIO 使用的简单开关数字通信更复杂的通信。I2C 非常强大且灵活，但它的速度可能会比较慢。

在本章中，你将学习如何编写一个 Android 应用程序，利用 BBB 的 SPI 功能从高速传感器获取环境数据。我们将涵盖以下主题：

+   理解 SPI

+   BBB 上的 SPI 复用

+   在 Linux 内核中表示 SPI 设备

+   构建 SPI 接口电路

+   探索 SPI 传感器示例应用程序

# 理解 SPI

**串行外围设备接口**（**SPI**）总线是一种由摩托罗拉公司最初开发的高速串行总线。其目的是促进单一主设备与一个或多个从设备之间的点对点通信。SPI 总线通常使用四个信号实现：

+   `SCLK`

+   `MOSI`

+   `MISO`

+   `SS`/`CS`

与 I2C 类似，SPI 总线上的主设备通过产生时钟信号来控制主从设备之间的通信节奏。在 SPI 中，这个时钟信号被称为**串行时钟**（`SCLK`）。与 I2C 的双向数据总线不同，SPI 为每个设备使用专用的发送和接收数据线。使用专用线使得 SPI 能够实现远高于 I2C 的通信速度。主设备通过**主出从入**（`MOSI`）信号向从设备发送数据，并通过**主入从出**（`MISO`）信号从从设备接收数据。**从设备选择**（`SS`）信号，也称为**芯片选择**（`CS`），它告诉从设备是否应该保持唤醒状态并注意`SCLK`上的任何时钟信号以及通过`MOSI`发送给它的数据。这种四线 SPI 总线方案有变体，例如省略`SS`/`CS`信号的三线方案，但 BBB 在其 SPI 总线上使用四线方案。

![理解 SPI](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00022.jpeg)

SPI 总线上的 SPI 主设备和从设备

BBB 可以作为 SPI 的主设备或从设备，因此它没有将其 SPI 的数据输入和输出信号标记为`MISO`或`MOSI`。相反，它使用`D0`和`D1`这些信号的名字。如果 BBB 在 SPI 总线上作为主设备，`D0`是`MISO`信号，`D1`是`MOSI`信号。如果 BBB 在 SPI 总线上作为从设备，这些信号是相反的（`D1`是`MISO`，`D0`是`MOSI`）。对于本书，BBB 将始终作为 SPI 主设备。

### 提示

**我该如何记住哪个是 BBB 的 SPI 输入信号，哪个是输出信号？**

当 BBB 使用信号名称 `D0` 和 `D1` 时，记住哪个信号是 `MISO` 和哪个是 `MOSI` 可能会令人困惑。记住的一个方法是，将 `D0` 中的 `0` 视为 *O*（代表从设备输出），将 `D1` 中的 `1` 视为 *I*（代表从设备输入）。如果 BBB 是 SPI 主设备（几乎总是这种情况），那么 `D1` 就是从设备输入信号（`MOSI`），而 `D0` 就是从设备输出信号（`MISO`）。

BBB 上 SPI 的最大 `SCLK` 速度为 48 MHz，但通常使用的速度范围从 1 MHz 到 16 MHz。即使在这些降低的时钟速度下，考虑到每秒可以传输的原始数据量，SPI 也远胜于 I2C 总线的 400 KHz 时钟速度。在任何时刻，I2C 总线上只能有一个设备传输数据，但在 SPI 总线上，由于每个设备都有专用的传输信号，主设备和从设备可以同时传输数据。

# BBB 上的 SPI 复用

BBB 上的 AM335X 处理器提供了两个 SPI 总线：SPI0 和 SPI1。这两条总线都可以通过 P9 头访问。默认情况下，没有将任何 SPI 总线进行复用。下图展示了 P9 头上可能的每个引脚，这些引脚可以在不同的 pinmux 模式下复用 SPI 信号：

![BBB 上的 SPI 复用](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00023.jpeg)

在不同 pinmux 模式下 P9 头上 SPI 总线的位置

在决定如何在你的项目中使用 SPI 复用引脚时，请记住以下事项：

+   如有疑问，请坚持使用复用到 P9.17、P9.18、P9.21 和 P9.22 引脚的 SPI0 总线。

+   SPI1 通道与 capemgr 使用的 I2C 总线（P9.20）和音频输出（P9.28、P9.29、P9.31）冲突。请注意，将这些引脚复用为 SPI1 可能会禁用你依赖的一些其他功能，以实现功能齐全的 Android 系统。

+   如果在你的项目中使用了其他 cape 板，请确保这些 cape 板不需要使用 SPI 总线。除非你使用 GPIO 引脚和额外的逻辑电路手动控制每个 SPI 设备的片选信号，否则每条 SPI 总线上只能存在一个设备。

# 在 Linux 内核中表示 SPI 设备

Linux 内核提供了一个名为 `spidev` 的通用 SPI 驱动程序。`spidev` 驱动程序是一个简单的接口，它抽象了 SPI 通信中涉及到的许多细节。`spidev` 驱动程序通过 `/dev` 文件系统作为 `/dev/spidevX.Y` 文件暴露出来。根据 Device Tree 中配置的 SPI 总线数量，可能存在多个版本的这些 `spidev` 文件。`spidev` 文件名中的 `X` 值指的是 SPI 控制器编号（SPI0 为 1，SPI1 为 2），而 `Y` 值指的是该控制器的 SPI 总线（第一条总线为 0，第二条总线为 1）。对于本书中的示例，你将只使用 SPI0 控制器的第一条 SPI 总线，因此 PacktHAL 将只与 `/dev/spidev1.0` 文件交互。

## 为 SPI 传感器使用准备 Android

在第二章《*与 Android 接口*》中，你使用`adb`将两个预构建的文件推送到你的 Android 系统中。这两个文件，`BB-PACKTPUB-00A0.dtbo`和`init.{ro.hardware}.rc`，配置了你的 Android 系统以启用处理 SPI 总线接口的`spidev`内核设备驱动，复用引脚以启用 SPI0 总线，并允许你的应用程序访问它们。

就 SPI 而言，`BB-PACKTPUB-00A0.dtbo`覆盖将 P9.17、P9.18、P9.21 和 P9.22 引脚复用为 SPI 的`CS0`、`D1`、`D0`和`SCLK`信号。在`PacktHAL.tgz`文件中，覆盖源代码位于`cape/BB-PACKTPUB-00A0.dts`文件中。负责复用这两个引脚的代码位于`fragment@0`中的`bb_spi0_pins`节点内。

```java
/* All SPI0 pins are PULL, MODE0 */
bb_spi0_pins: pinmux_bb_spi0_pins {
    pinctrl-single,pins = <
        0x150 0x30  /* P9.22, spi0_sclk, INPUT */
        0x154 0x30  /* P9.21, spi0_do, INPUT */
        0x158 0x10  /* P9.18, spi0_d1, OUTPUT */
        0x15c 0x10  /* P9.17, spi0_cs0, OUTPUT */
    >;
};
```

虽然这设置了复用功能，但它并没有为这些引脚分配和配置设备驱动。`fragment@2`节点执行这个内核驱动分配的任务：

```java
fragment@2 {
    target = <&spi0>;
    __overlay__ {
        #address-cells = <1>;
        #size-cells = <0>;
        status = "okay";
        pinctrl-names = "default";
        pinctrl-0 = <&bb_spi0_pins>;

        channel@0 {
            #address-cells = <1>;
            #size-cells = <0>;
            /* Kernel driver for this device */
            compatible = "spidev";

            reg = <0>;
            /* Setting the max frequency to 16MHz */
            spi-max-frequency = <16000000>;
            spi-cpha;
        };
        …
    };
};
```

不深入研究细节，`fragment@2`中有三个设置是你感兴趣的：

+   `pinctrl-0`

+   `compatible`

+   `spi-max-frequency`

第一个是`pinctrl-0`，它将 Device Tree 的这个节点与`bb_spi0_pins`节点中复用的引脚连接起来。第二个是`compatible`，它指定了将处理我们硬件设备的特定内核驱动，即`spidev`。最后是`spi-max-frequency`，它指定了此 SPI 总线的最大允许速度（16 MHz）。16 MHz 是在 BBB 的内核源提供的 Device Tree 覆盖中为`spidev`指定的最大频率。

你推送到 Android 系统的自定义`init.{ro.hardware}.rc`文件不需要为 PacktHAL 的 SPI 接口做任何特别的事情。默认情况下，BBBAndroid 使用`chmod`将`/dev/spidev*`文件的权限设置为 777（对所有人完全访问）。这并不是一个安全的做法，因为系统上的任何进程都可能打开一个`spidev`设备并开始读写硬件。然而，对于我们的目的来说，让每个进程都能访问`/dev/spidev*`文件是必要的，以允许我们的非特权示例应用程序访问 SPI 总线。

# 构建一个 SPI 接口电路

既然你已经了解了 SPI 设备是如何连接到 BBB 的，以及 Linux 内核是如何为这些设备提供接口的，现在是时候将一个 SPI 设备连接到 BBB 上了。

正如我们在第一章《*Android 与 BeagleBone Black 简介*》中提到的，本章你将和一个传感器进行接口交互。具体来说，我们将使用博世 Sensortec 的 BMP183 数字压力传感器。这个 7 针组件为用于导航、天气预报以及测量垂直高度变化等应用提供压力数据样本（16 位至 19 位分辨率）和温度数据样本（16 位分辨率）。

这个特定的芯片仅提供**LGA**（**land grid array**，地表网格阵列）封装，这种表面贴装封装在构建原型电路时可能难以操作。幸运的是，AdaFruit 为该传感器提供的开发板已经装好了芯片，这使得原型设计变得简单和容易。

![构建 SPI 接口电路](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00024.jpeg)

传感器开发板（来源：[www.adafruit.com](http://www.adafruit.com)）

开发板将`SCLK`信号标记为`SCK`，`MOSI`为`SDI`（串行数据输入），`MISO`为`SDO`（串行数据输出），以及`SS`为`CS`（芯片选择）。为了给开发板供电，将+3.3 V 信号连接到`VCC`，并将地线连接到`GND`。开发板上的`3Vo`信号提供一个+3.3 V 信号，在我们的示例中未使用。

### 提示

**不要拆开你的电路！**

本章节中的传感器电路是第六章*创建完整的接口解决方案*中使用的更大电路的一部分。如果你按照原理图中的位置（在面包板中部）搭建电路，那么在构建本书其余电路时，你可以简单地将传感器开发板和电线留在原位。这样，当你到达第六章时，它就已经构建好并可以工作了。

## 连接传感器

下图展示了传感器开发板与 BBB 之间的连接。六个主要的 SPI 总线信号（+3.3 V、地、以及 SPI `SCLK`、`MISO`、`MOSI`和`SS`）使用 P9 连接器的引脚进行连接，因此我们将面包板放在 BBB 的 P9 侧。

![连接传感器](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00025.jpeg)

完整的传感器接口电路

让我们开始吧：

1.  将 P9.1（地）连接到面包板的地线总排，将 P9.3（3.3 V）连接到面包板的电源线总排。这些连接与你在第三章*使用 GPIO 处理输入和输出*和第四章*使用 I2C 存储和检索数据*中创建的 GPIO 和 I2C 面包板电路的连接相同。

1.  四个 SPI 总线信号，`SCLK`、`MISO` (`D0`)、`MOSI` (`D1`) 和 `SS` 分别位于 P9.22、P9.21、P9.18 和 P9.17 引脚上。将 P9.22 引脚连接到开发板上标记为 SCK 的引脚，将 P9.21 引脚连接到标记为 SDO 的引脚。然后，将 P9.18 引脚连接到标记为 SDI 的引脚，并将 P9.17 引脚连接到标记为 CS 的引脚。

1.  将地线总排连接到开发板上的 GND 引脚，以及电源线总排连接到开发板上的 VCC 引脚。将开发板上的 3Vo 引脚保持未连接。

传感器开发板现在电气连接到 BBB，并准备好供您使用。请对照完整的传感器接口电路图再次检查您的布线，以确保一切连接正确。

# 探索 SPI 传感器示例应用

在本节中，您将研究一个示例 Android 应用，该应用在 BBB 上执行 SPI 总线接口。此应用程序的目的是演示如何使用 PacktHAL 在实际应用中使用一组接口函数执行 SPI 读写。这些函数允许您在 SPI 总线主设备（BBB）和 SPI 总线从设备（SPI 传感器）之间发送和接收数据。硬件接口的底层细节在 PacktHAL 中实现，因此您可以快速轻松地使您的应用与传感器交互。

在深入探讨 SPI 应用的代码之前，您必须将代码安装到您的开发系统上，并将应用安装到您的 Android 系统上。应用的源代码和预编译的 `.apk` 包位于 `chapter5.tgz` 文件中，可以从 Packt 的网站下载。按照与 第三章，*使用 GPIO 处理输入和输出* 和 *第四章，使用 I2C 存储和检索数据* 中描述的相同过程，下载并将应用添加到您的 Eclipse ADT 环境。

## 应用的用户界面

该应用使用一个非常简单的 UI 与传感器交互。由于它非常简单，因此应用默认只有一个 `MainActivity`。UI 只包含一个按钮和两个文本视图。

![应用的界面](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00026.jpeg)

在从传感器接收第一组样本之前，传感器示例应用屏幕的外观

在 `activity_main.xml` 文件中，顶部文本视图的标识符为 `temperatureTextView`，底部文本视图的标识符为 `pressureTextView`。这些文本视图将显示从传感器获取的温度和压力数据。带有**采样**标签的按钮的标识符为 `sampleButton`。此按钮有一个 `onClick()` 方法，名为 `onClickSampleButton()`，它将触发与传感器接口的过程，以采样温度和压力数据，并更新 `temperatureTextView` 和 `pressureTextView` 文本视图显示的文本。

## 调用 PacktHAL 传感器功能

PacktHAL 中的传感器接口功能在 `sensor` 应用项目中的 `jni/bmp183.c` 文件中用各种 C 函数实现。这些函数不仅与传感器接口，还执行各种转换和校准任务。

前一章节中的`fram`应用程序使用了一个特定的内核驱动程序（`24c256` EEPROM 驱动程序）与 FRAM 芯片交互，因此在 PacktHAL 中实现的用户空间接口逻辑非常简单。PacktHAL 没有使用特定的传感器内核驱动程序与传感器通信，因此它必须使用通用的`spidev`驱动程序进行通信。由 PacktHAL 负责准备、发送、接收和解释每个 SPI 消息的每个字节，这些消息将发送到传感器或从传感器接收。

尽管 PacktHAL 中有许多函数来处理这些任务，但外部代码只使用其中四个函数与传感器交互：

+   `openSensor()`

+   `getSensorTemperature()`

+   `getSensorPressure()`

+   `closeSensor()`

这些函数的原型位于`jni/PacktHAL.h`头文件中：

```java
extern int openSensor(void);
extern float getSensorTemperature(void);
extern float getSensorPressure(void);
extern int closeSensor(void);
```

`openSensor()`函数通过打开`/dev/spidev1.0`并执行几个`ioctl()`调用，来初始化对 SPI 总线的访问并配置 SPI 总线的通信参数（如`SCLK`的时钟速率）。

完成此配置后，PacktHAL 内执行的 所有 SPI 通信都将使用此总线。调用对应的`closeSensor()`函数会关闭`/dev/spidev1.0`文件，这将关闭 SPI 总线并使其可供系统上的其他进程使用。`getSensorTemperature()`和`getSensorPressure()`函数执行所有 SPI 消息的准备、SPI 通信和样本转换逻辑，以获取并转换从传感器检索的样本。

### 注意

如果你正在使用一个专门设计的内核驱动程序，用于与我们所使用的特定传感器通信，那么 PacktHAL 代码中的传感器读取逻辑将会非常简单（仅有一两个`ioctl()`调用）。将 HAL 代码逻辑放置在内核中与保持在用户空间之间总是需要平衡。你推向内核的代码越多，用户空间代码就越简单快速。然而，开发内核代码可能非常困难，因此你必须权衡什么最容易实现以及什么将为你提供硬件设计所需的性能。

`sensor`应用程序与之前章节中的应用程序有几处相似之处。类似于第四章中的`fram`应用程序，*使用 I2C 存储和检索数据*，`sensor`应用程序使用从`AsyncTask`派生出来的自己的类`HardwareTask`，通过 JNI 调用 PacktHAL 中与底层传感器接口的函数。与硬件的接口是由应用程序用户按下的按钮的`onClick()`处理器触发的，这与`gpio`和`fram`应用程序的做法类似。

就像你在第三章，*处理 GPIO 输入输出*和[第四章，使用 I2C 存储和检索数据]中使用的 PacktHAL 的 GPIO 接口函数一样，`HardwareTask`中的传感器接口方法执行得非常快。实际上，并不需要从单独的线程中执行这些方法，因为它们不太可能执行得那么久，以至于会触发 ANR 对话框。然而，SPI 可以用于各种各样的设备，可能需要较长时间来发送大量数据，所以小心为上。

### 提示

**我在硬件接口时应该在什么时候使用`AsyncTask`？**

对于这个问题，简短的回答是“一直都要”。在我们介绍 GPIOs 的第三章，*处理 GPIO 输入输出*时，没有详细讲解`AsyncTask`类的细节，以免分散你的注意力，所以`gpio`应用程序在`onClick()`按钮处理程序中调用了 PacktHAL 函数。然而，要遵循的一般规则是，任何时候执行 I/O 操作都应该使用`AsyncTask`。I/O 操作特别慢，因此任何 I/O（网络通信、访问磁盘上的文件和硬件接口）都应该在自己的线程中通过`AsyncTask`完成。

## 使用`HardwareTask`类

与`gpio`和`fram`应用程序一样，传感器应用程序中的`HardwareTask`类提供了四个本地方法，用于调用与传感器硬件接口相关的 PacktHAL JNI 函数：

```java
public class HardwareTask extends AsyncTask<Void, Void, Boolean> {

  private native boolean openSensor();
  private native float getSensorTemperature();
  private native float getSensorPressure();
  private native boolean closeSensor();
```

由于 SPI 总线设置过程的细节被封装在 PacktHAL 函数中，并且对应用程序隐藏，因此这些方法不带参数。它们只是通过 PacktHAL JNI 包装函数调用其 PacktHAL 对应方法。

![使用 HardwareTask 类](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-hw-itf-bglbn-blk/img/00027.jpeg)

`HardwareTask`方法和 PacktHAL 函数执行的线程上下文

在传感器应用程序中，`MainActivity`类中的示例按钮的`onClick()`处理程序实例化了一个新的`HardwareTask`方法。在此实例化之后，立即调用`HardwareTask`的`pollSensor()`方法，以请求传感器提供当前的温度和压力数据集：

```java
    public void onClickSampleButton(View view) {
        hwTask = new HardwareTask();
        hwTask.pollSensor(this);  
    }
```

`pollSensor()`方法通过调用基类`AsyncTask`的`execution()`方法来启动硬件接口过程，并创建一个新线程：

```java
    public void pollSensor(Activity act) {
      mCallerActivity = act;
      execute();
    }
```

`AsyncTask`的`execute()`方法调用了`HardwareTask`用来通过其`openSensor()`本地方法初始化 SPI 总线的`onPreExecute()`方法。同时，在线程执行期间禁用`sampleButton`方法，以防止可能同时有多个线程尝试使用 SPI 总线与传感器通信。

```java
   protected void onPreExecute() {  
      Log.i("HardwareTask", "onPreExecute");
      ...    
     if ( !openSensor() ) {
         Log.e("HardwareTask", "Error opening hardware");
        isDone = true;
      }
      // Disable the Button while talking to the hardware
      sampleButton.setEnabled(false);
   }
```

一旦`onPreExecute()`方法完成，`AsyncTask`基类将启动一个新线程并在该线程中执行`doInBackground()`方法。对于传感器应用，这是执行任何必要的 SPI 总线通信以从传感器获取当前温度和压力样本的正确位置。`HardwareTask`类的`getSensorTemperature()`和`getSensorPressure()`本地方法通过 PacktHAL 中的`getSensorTemperature()`和`getSensorPressure()`函数从传感器获取最新的样本。

```java
    protected Boolean doInBackground(Void... params) { ) { 

      if (isDone) { // Was the hardware never opened?
        Log.e("HardwareTask", "doInBackground: Skipping hardware interfacing");
        return true;
      }

      Log.i("HardwareTask", "doInBackground: Interfacing with hardware");
      try {
        temperature = getSensorTemperature();
        pressure = getSensorPressure();
      } catch (Exception e) {
       ...
```

当`doInBackground()`完成后，`AsyncTask`线程终止。这会从 UI 线程触发调用`doPostExecute()`。现在，应用已经完成了 SPI 通信任务，并从传感器接收到了最新的温度和压力值，是时候关闭 SPI 连接了。`doPostExecute()`方法通过`HardwareTask`类的`closeSensor()`本地方法关闭 SPI 总线。然后，`doPostExecute()`方法通过`updateSensorData()`方法通知`MainActivity`类收到的新传感器数据，并重新启用`MainActivity`的**采样**按钮：

```java
   protected void onPostExecute(Boolean result) {
      if (!closeSensor()) {
        Log.e("HardwareTask", "Error closing hardware");
     }
      ...
         Toast toast =  
            Toast.makeText(mCallerActivity.getApplicationContext(),
            "Sensor data received", Toast.LENGTH_SHORT);
         toast.show();
         ((MainActivity)mCallerActivity).updateSensorData(temperature,
            pressure);
      ...
      // Reenable the Button after talking to the hardware
      sampleButton.setEnabled(true);
```

`MainActivity`类的`updateSensorData()`方法负责更新`temperatureTextView`和`pressureTextView`文本视图中的显示值，以反映最新收到的传感器值：

```java
    public void updateSensorData(float temperature, float pressure) {
      Toast toast = Toast.makeText(getApplicationContext(), 
          "Displaying new sensor data", Toast.LENGTH_SHORT);
      TextView tv = (TextView) findViewById(R.id.temperatureTextView);    
       tv.setText("Temperature: " + temperature);

    tv = (TextView) findViewById(R.id.pressureTextView);
       tv.setText("Pressure: " + pressure);

       toast.show();
    }
```

在这一点上，`sensor`应用的执行已经返回到空闲状态。如果用户再次点击**采样**按钮，将实例化另一个`HardwareTask`实例，硬件的开-采-关交互循环将再次发生。

### 提示

**你准备好迎接挑战了吗？**

既然你已经看到了传感器应用的所有部分，为什么不对其进行修改以添加一些新功能呢？作为一个挑战，尝试添加一个计数器，显示到目前为止已经采集了多少样本以及所有样本的平均温度和压力。我们在`chapter5_challenge.tgz`文件中提供了一个可能的实现，该文件可在 Packt 的网站上下载。

# 概述

在本章中，我们向你介绍了 SPI 总线。你构建了一个电路，将 SPI 压力和温度传感器开发板连接到 BBB，并了解了 PacktHAL `init.{ro.hardware}.rc`文件设备树覆盖中负责配置 SPI 总线和`spidev`设备驱动程序并为应用提供使用的那部分内容。本章中的传感器应用演示了如何使用一组简化函数隐藏应用中的 HAL 复杂任务。这些简化的 PacktHAL 函数调用可以从`AsyncTask`派生的类中执行，以便在应用内部简单地执行更复杂的接口任务。

在下一章中，你将了解到如何将 GPIO、I2C 和 SPI 组合到一个应用中，该应用能够提供一个完整的硬件解决方案，使用一个长生命周期的硬件接口线程。
