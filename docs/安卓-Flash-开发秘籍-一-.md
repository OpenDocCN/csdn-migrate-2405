# 安卓 Flash 开发秘籍（一）

> 原文：[`zh.annas-archive.org/md5/3A6CCF6F6AAB969F5B96A3C7E7AEF15A`](https://zh.annas-archive.org/md5/3A6CCF6F6AAB969F5B96A3C7E7AEF15A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

随着移动 Android 操作系统的持续爆发式增长，以及智能手机和平板电脑市场中 Android 设备的普及，现在是使用 Flash 平台探索 Android 开发世界的最佳时机。Adobe 最近发布的数据显示，到 2011 年底，预计将有超过 2 亿部智能手机和平板电脑支持 Adobe AIR 应用程序。对于 2011 年，公司预计全球将有超过 1.32 亿台设备支持移动 Flash 播放器。本书提供了各种基本食谱，探索在使用这些 Flash 平台运行时，移动 Android 开发者的常见需求。

许多现有的 Flash 应用程序开发人员对为 Android 设备构建移动应用程序的前景感到兴奋，但不知从何入手？使用本书作为指南，扩展您进入移动应用程序开发的领域。在可能的情况下，本书中的食谱均使用纯 ActionScript 3 编写，让读者可以使用他们选择的工具完成每个示例。在某些情况下，我们展示了在处理特定布局和结构需求时，移动 Flex 框架的强大和灵活性。通过书中的分步示例，快速启动您的移动 Android 开发经验。

《Android Flash 开发手册》将通过大量专为 Android 设备应用程序开发设计的移动特定示例，展示其直接而实用的特点。书中包含开始所需的一切内容，以及在使用 Flash、Flex 和 AIR 开发移动 Android 应用程序时进一步提升经验的建议。

本书涵盖的主题包括开发环境配置、移动项目的创建与转换、触摸和手势的使用、在 3D 空间中响应对位置和设备移动的变化、图像、视频和音频的捕获、生成和操作、应用程序布局与结构、接入本地进程和硬件、文件系统的操作以及本地应用程序数据库的管理。本书还将介绍诸如 Android 特定设备权限、应用程序优化技术，以及在移动 Android 平台上可用的打包和分发选项等事项。

## 本书内容

第一章，*准备使用 Android：开发环境与项目设置*，展示了可以用于开发移动 Android 的 Flash 内容的多种开发环境和工具的配置。

第二章，*交互体验：多点触控、手势和其他输入*，向读者介绍了可以在 Flash 平台运行时中使用的一系列独特的触摸和手势交互。

第三章, *空间移动：加速计和地理定位传感器*, 使你的应用程序能够精确地定位用户的地理位置，并通过板载加速计确定设备在本地的小幅度移动和倾斜。

第四章, *视觉和音频输入：相机和麦克风接入*, 讨论了如何通过基于 Flash 的捕获方法和使用本地相机应用程序，从集成设备硬件捕获静态图像、视频和音频。

第五章, *富媒体展示：处理图像、视频和音频*, 查看了 Flash 平台上可用的各种媒体展示机制，包括渐进式和流式视频播放、使用 Pixel Bender 着色器，甚至音频生成。

第六章, *结构适应：处理设备布局和缩放*, 讨论了我们可以使用各种方法来获取有关设备显示的详细信息，并在通过移动 Flex 框架进行结构化布局时，使用这些数据来调整视觉元素的大小和位置。

第七章, *本地交互：舞台 WebView 和 URI 处理器*, 展示了利用本地应用程序（如网页浏览器、电子邮件、短信、电话和地图）作为 Flash 基础体验扩展的方法。

第八章, *丰富访问：文件系统和本地数据库*, 为读者提供了访问、打开和写入设备存储上的文件流，创建和管理本地 SQLite 数据库，以及在应用程序中断时保存应用程序状态的必要步骤。

第九章, *宣言保障：安全与 Android 权限*, 展示了各种 Android Manifest 权限，并提供了市场筛选、加密数据库支持和其他安全相关技术的示例。

第十章, *避免问题：调试和资源考虑*, 探讨了开发者可以通过利用设备 GPU、负责任地处理用户交互和内存管理技术来提高应用程序效率的方法。

第十一章，*最后考虑：应用程序编译和发布*，为读者提供了关于项目准备、代码签名、发布编译和通过全球 Android Market 进行分发的建议。

# 你需要为这本书准备的内容

要使用本书中包含的食谱，你需要访问使用 Flash Platform 开发 Android 应用程序的软件。我们推荐使用 Adobe Flash Builder 4.5、Adobe Flash Professional CS5.5 或 PowerFlasher FDT 4.2 及更高版本。这些集成开发环境之所以首选，是因为它们对移动 Android 工作流程有特定的支持，但你可以实际上使用任何你喜欢的应用程序编写代码，这些代码将被编译为 AIR for Android 并部署到移动设备上。

然而，你还需要访问以下内容（如果不是使用这些特定的 IDE）： 

+   Adobe AIR SDK—用于将你的 Flash 应用程序编译成 Android 的.APK 文件

+   Flex 4.5 SDK—如果你想利用移动 Flex 框架

Adobe AIR SDK 包含在 Flash Professional CS5.5 和 Flash Builder 4.5 中。Flex 4.5 SDK 包含在 Flash Builder 4.5 中。如果使用其他软件开发基于 Flash 的 Android 应用程序，可以从 Adobe 开源网站免费下载这些 SDK。

你还需要确保能够访问运行 Android 2.2 或更高版本的设备，并安装了 AIR for Android 2.5 或更高版本，以便演示食谱和测试你自己的应用程序。

# 本书适合的读者群体

这本书包含了各种主题的食谱，从非常简单的到更高级的。如果你是一位经验丰富的 Flash 开发者，这本书将帮助你快速了解在 Android 上可以实现的功能。对于刚接触 Flash 的新手，欢迎进入视觉丰富、快速的移动 Android 设备应用程序开发世界！如果你对 Android 上的 Flash 开发有任何兴趣，这本书会满足你的需求。

# 约定

在本书中，你会发现多种文本样式，用于区分不同类型的信息。以下是一些样式示例，以及它们含义的解释。

文中的代码字会如下所示："创建一个名为`recipe1.py`的新文件，以放置此食谱的所有代码。"

代码块如下设置：

```kt
streamClient = new Object();
streamClient.onBWDone = onTextData;
streamClient.onTextData = onTextData;
streamClient.onMetaData = onMetaData;
streamClient.onCuePoint = onCuePoint;

```

**新术语**和**重要词汇**以粗体显示。你在屏幕上看到的词，例如菜单或对话框中的，会在文本中以这样的形式出现："有许多**IDE（集成开发环境）**可供选择，用于为 Android 设备开发 Flash 平台项目"。

### 注意

警告或重要提示会以这样的方框显示。

### 小贴士

技巧和窍门会以这样的形式出现。

# 读者反馈

我们始终欢迎读者的反馈。告诉我们你对这本书的看法——你喜欢或可能不喜欢的内容。读者的反馈对我们来说很重要，帮助我们开发出你真正能够充分利用的标题。

要给我们发送一般反馈，只需发送电子邮件至`<feedback@packtpub.com>`，并在邮件的主题中提及书名。

如果有一本书是你需要的，并且希望看到我们出版，请通过[www.packtpub.com](http://www.packtpub.com)上的**建议书名**表单给我们发送信息，或者发送电子邮件至`<suggest@packtpub.com>`。

如果有一个你擅长的主题，并且你对于写作或为书籍做出贡献感兴趣，请查看我们在[www.packtpub.com/authors](http://www.packtpub.com/authors)的作者指南。

# 客户支持

既然你现在是我们 Packt 图书的骄傲拥有者，我们有许多方法可以帮助你最大限度地利用你的购买。

## 下载示例代码

你可以从你在[`www.PacktPub.com`](http://www.PacktPub.com)的账户下载你购买的所有 Packt 图书的示例代码文件。如果你在其他地方购买了这本书，可以访问[`www.PacktPub.com/support`](http://www.PacktPub.com/support)注册，我们会直接将文件通过电子邮件发送给你。

## 错误更正

尽管我们已经尽力确保内容的准确性，但错误仍然可能发生。如果你在我们的书中发现了一个错误——可能是文本或代码中的错误——如果你能向我们报告，我们将不胜感激。这样做，你可以让其他读者避免沮丧，并帮助我们改进本书的后续版本。如果你发现任何错误，请通过访问[`www.packtpub.com/support`](http://www.packtpub.com/support)，选择你的书籍，点击**错误更正提交表单**链接，并输入错误详情来报告。一旦你的错误更正得到验证，你的提交将被接受，并且错误更正将在我们网站的相应位置上传，或者添加到该标题下的现有错误更正列表中。任何现有的错误更正都可以通过在[`www.packtpub.com/support`](http://www.packtpub.com/support)选择你的标题来查看。

## 盗版

互联网上版权材料的盗版是一个跨所有媒体持续存在的问题。在 Packt，我们非常重视保护我们的版权和许可。如果你在互联网上以任何形式遇到我们作品非法副本，请立即提供位置地址或网站名称，以便我们可以寻求补救措施。

如果你发现了疑似盗版材料，请通过`<copyright@packtpub.com>`联系我们，并提供该材料的链接。

我们感谢你帮助保护我们的作者，以及我们为你提供有价值内容的能力。

## 问题咨询

如果你对书籍的任何方面有问题，可以联系`<questions@packtpub.com>`，我们将尽力解决。


# 第一章：准备使用 Android：开发环境和项目设置

本章将涵盖以下内容：

+   使用 Flash Professional CS5.5 开发 Android 应用程序

+   使用 Flash Professional CS5.5 针对 AIR for Android 进行开发

+   使用 Flash Builder 4.5 开发 Android 应用程序

+   使 Flash Builder 4 或 Flex Builder 能够访问 Flex Mobile SDK

+   使用 Flash Builder 4 及以下版本开发 Android 应用程序

+   使用 Powerflasher FDT 4.2 开发 Android 应用程序

+   使 Powerflasher FDT 4.1 能够访问 Flex Mobile SDK

+   使用 Powerflasher FDT 4.1 及以下版本开发 Android 应用程序

+   将标准 Flex 项目转换为 Flex Mobile 项目

+   在 Windows 上配置 AIR SDK 以打包 Android 应用程序

+   在 Linux 或 Mac OS 上配置 AIR SDK 以打包 Android 应用程序

# 引言

有许多**IDE（集成开发环境）**可用于为 Android 设备开发 Flash 平台项目。我们将关注一些最受欢迎的：Adobe Flash Professional、Adobe Flash Builder 和 Powerflasher FDT。本章将包括针对每个 IDE 启动新 Android 项目的食谱，以及关于工作流程和工具集的最大化利用。您将学习如何配置每个环境以开发 Android 操作系统。

Flash Builder 和 FDT 以及 Flex 框架为 Android 开发提供了最多的支持，因为有一个简化的工作流程、控件集合和容器，特别是使用 Adobe AIR for Android 作为开发平台开发移动 Android 项目时。

Flash Professional 提供了一些工作流程工具，但主要的好处在于对环境的潜在熟悉，以及生成不依赖于 Flex 框架的项目。这个 IDE 由于其开放性，常用于游戏开发。

对于纯粹主义者或替代 IDE 的用户，也可以使用免费的 AIR SDK 工具通过命令行界面生成 Android 应用程序。

# 使用 Flash Professional CS5.5 开发 Android 应用程序（注意：重复内容不翻译）

Flash Professional 是构建比基于 Flex 的应用程序更轻量级的 Android 应用程序的一个不错的选择。与包含在 Flash Builder 等 IDE 中的流程相比，Flash Professional 的流程并不那么健壮，但根据开发的应用程序，它可能是更合适的选择。

Flash Professional CS5.5 已经内置了针对 Android 开发的所有必要工具！

## 如何操作…

在 Flash Professional CS5.5 中设置一个 AIR for Android 项目非常直接：

1.  我们首先会在 Flash Professional 欢迎屏幕的**创建新项目**部分选择**AIR for Android**来创建一个新项目：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_01_01.jpg)

1.  然后，我们可以通过查看**属性**面板下的文档属性来确认我们正在针对 Android 的 AIR：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_01_02.jpg)

1.  我们还可以通过选择**AIR for Android**作为**播放器**选项，修改现有的 Flash 文档以针对 Android。

1.  现在，只需像平常一样构建你的 Flash 项目即可。Adobe 使使用 Flash Professional CS5.5 针对 Android 的过程变得非常轻松。

## 工作原理…

使用 Flash Professional CS5.5，我们拥有比以往任何时候都多的编译器选项。按照前一部分所述步骤操作，可以确保通过向发布设置中添加一些针对 Android 的特定编译器选项，使你的项目能够以桌面 Flash Player 或桌面 AIR 为目标，转而针对 Android 的 AIR。

## 还有更多…

如果针对 Android 的移动 Flash Player 开发，我们将不需要为 AIR 运行时配置任何内容。要针对 Flash Player，我们只需牢记移动 Android 设备固有的限制和差异。

# 使用 Flash Professional CS5.5 针对 Android 的 AIR

Flash Professional 是构建比基于 Flex 的对应产品更轻量级 Android 应用程序的一个不错的选择。与包含在像 Flash Builder 这样的 IDE 中的工作流程相比，Flash Professional 的情况并不那么健壮，但根据开发中的应用程序，它可能是更合适的选择。

## 如何操作…

使用 Flash Professional 针对 Android 的 AIR 有两种方法：

1.  首先，在 Flash Professional 欢迎屏幕的**从模板创建**部分选择**AIR for Android**创建一个新项目：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_01_01a.jpg)

1.  这将提供几个针对**AIR for Android**的模板供选择。为你设备选择合适的模板：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_01_04.jpg)

1.  或者，创建一个新的 ActionScript 3.0 项目，并通过转到**文件 | 发布设置**打开你的发布设置。

1.  这将打开一个对话框，允许你选择目标平台。在这种情况下，我们要选择**AIR Android**作为适当的**播放器**：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_01_05.jpg)

1.  现在，你将能够调整针对 Android 的**应用程序**和**安装程序设置**，并将项目编译成`.apk`文件。

## 工作原理…

使用 Flash Professional 的最新版本，我们拥有比以往任何时候都多的编译器选项。按照上述步骤操作，可以确保通过向发布设置中添加一些针对 Android 的特定编译器选项，使你的项目能够以桌面 Flash Player 或桌面 AIR 为目标，转而针对 Android 的 AIR。

## 还有更多…

如果针对 Android 的移动 Flash Player 开发，我们将不需要为 AIR 运行时配置任何内容。要针对 Flash Player，我们只需牢记移动 Android 设备固有的限制和差异。

## 另请参阅…

若要了解更多关于使用 Flash Professional 编译针对 Android 应用程序的 AIR 的信息，你将需要参考第十一章，*最终考虑：应用程序编译与分发*。

# 使用 Flash Builder 4.5 开发安卓应用程序

Flash Builder 4.5 已经配备了开始使用 ActionScript 或移动 Flex 框架开发移动应用程序所需的一切。对于那些不熟悉 ActionScript 和 Flex 之间区别的人来说，基本上，Flex 框架提供了一套预配置的组件、布局和数据控制，用于构建 Flash 应用程序，而单独使用 ActionScript 时，则必须从头开始编写所有内容。Flex 4.5 包括移动特性，如针对设备运行优化过的组件皮肤、新的`ViewNavigator`应用程序类型，该类型专为移动体验量身定制，并包括对移动优化组件集的触摸和手势支持。

## 如何操作…

作为正常的 ActionScript 项目或 Flex 项目，我们必须明确创建一个 ActionScript 移动项目或 Flex 移动项目：

1.  在 Flash Builder 的**包资源管理器**中，右键点击某个空白区域并选择**新建 | Flex 移动项目**或**新建 | ActionScript 移动项目**。![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_01_06.jpg)

1.  然后，我们将为移动项目命名，并选择 Flash Builder 应在本地机器上存储项目文件的位置。

1.  下一步允许我们选择目标平台，在本例中是**谷歌安卓**，并定义使用哪个应用程序模板（如果你正在使用移动 Flex 框架）。我们还可以通过**初始视图标题**输入设置默认的`View`名称。

1.  此外，我们还将选择应用程序是否根据设备倾斜来自动重新定位，通过**自动重新定位**选项。我们可以选择通过选中**全屏**复选框来以全屏显示应用程序。

1.  在此屏幕上要做的最后一个选择是，通过选择**为不同屏幕密度自动缩放应用程序**复选框并选择适当的应用程序 DPI 设置，来确定我们是否希望移动组件中使用密度感知皮肤。![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_01_07.jpg)

1.  项目设置的其他部分实际上与 Flash Builder 中的任何其他项目都一样。

## 它是如何工作的…

在 Flash Builder 中设置新项目时的选择决定了哪些库会被导入并在应用程序中使用。定义一个移动应用程序不仅会包括针对移动设备的具体组件皮肤，还会限制我们使用不适合此类用途的组件。我们还可以完全访问移动特定的应用程序结构，如移动`ViewNavigator`、`ActionBar`或`TabBar`。这些对移动 Flex 框架的补充可以大大加快有状态移动 Android 应用程序的开发，因为它们处理的是应用程序结构、导航控制和布局。

## 另请参阅…

你实际上可以使用之前版本的 Flash Builder 来编译 Android 应用程序的 AIR。查看下一个指南，*使 Flash Builder 4 或 Flex Builder 能够访问 Flex Mobile SDKs*，以获取这方面的示例。

# 使 Flash Builder 4 或 Flex Builder 能够访问 Flex Mobile SDKs

你不一定需要最新版本的 Flash Builder 来编写 Android 应用程序。本指南将展示如何将最新的 Flex SDK 集成到较旧版本的 Flash Builder（甚至是 Flex Builder）中，以利用移动框架的改进。

### 注意

尽管我们将能够使用新的组件集和为 Android 简化的结构，但许多工作流增强，如支持新的移动应用程序视图结构、优化具有触摸和手势支持的组件皮肤以及在新版 Flash Builder 中找到的其他便利功能，将无法使用，我们将不得不使用 AIR SDK 和命令行工具编译应用程序以供分发。

## 如何操作…

以下步骤用于配置旧版本的 Flash Builder 以进行 Android 开发：

1.  访问 Adobe 开源网站 [`opensource.adobe.com/`](http://opensource.adobe.com/)，找到最新的 Flex SDK 构建版本。

1.  下载最新 Adobe Flex SDK 的`ZIP`文件并将其解压到硬盘上你能够记住的位置，例如`C:\SDKs\Flex`。

1.  启动 Flash Builder，前往**窗口 | 首选项**。

1.  向下滚动至**Flash Builder**菜单项，选择**Installed Flex SDKs**。你现在将看到 Flash Builder 中当前可用的每个 SDK 列表：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_01_08.jpg)

1.  点击标记为**Add**的按钮，浏览到你最近下载的 Flex SDK 的位置。

1.  为对话框提供一个有意义的名称并点击**OK**。例如，`Flex 4.5`。如果我们想要非常具体，可以始终使用完整的构建名称，如：`Flex 4.5.0.16076`。![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_01_09.jpg)

1.  现在`Flex 4.5` SDK 可以在你的应用程序中使用。要在项目中使用它，只需在创建新项目或在现有项目中修改**Flex Compiler**属性时选择此 SDK 即可。![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_01_10.jpg)

## 工作原理…

在 Flash Builder 中使用较新的 Flex SDK 版本，使我们能够访问移动主题选项和其他特定 API，这些 API 在之前的 SDK 版本中是不可用的。这也会将移动类暴露给代码提示和其他 IDE 工作流构建。

## 还有更多内容...

如果更改项目中使用的 Flex SDK 版本，我们可能会因为框架从版本到版本之间的变化而收到许多警告或错误。只需通过项目文件，并纠正**问题**面板中出现的每个警告或错误，以解决任何问题。

如果开发针对 Android 上 Flash Player 的项目，你只需要注意设备和操作系统的限制。

## 另请参阅...

需要特别注意的是，Flash Builder 4.5 之前的版本将不包括编译项目到`.APK`（Android 应用程序文件扩展名）的能力，你需要使用免费提供的 AIR SDK 来编译你的项目。有关如何执行此操作的信息，请参见第十一章。

还值得一提，虽然你可以使用较旧的 Flash Builder 版本为 Android 开发应用程序，但你将无法获得较新版本提供的许多好处，例如代码补全。

# 使用 Flash Builder 4 及以下版本开发 Android 应用程序

在 Flash Builder 4 中开发移动 Android 应用程序，我们需要配置 Flash Builder 以访问移动 Flex SDK。如果你还没有以这种方式配置 Flash Builder 或 Flex Builder，请参阅之前的菜谱。

## 如何操作...

在 Flash Builder 4.5 之前的版本中并没有内置特定的移动工作流程或工具。通过采取以下步骤，我们可以确保项目将是移动兼容的：

1.  在 Flash Builder 中，右键点击**包资源管理器**面板并选择**新建 | Flex 项目**。或者，我们可以选择**ActionScript 项目**，但这不会包括任何移动端的好处，因为实际的 Flex SDK 组件将不会被使用。然而，值得注意的是，由于 ActionScript 项目不依赖于如此重的框架，它们通常会比 Flex 项目表现得更好。![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_01_11.jpg)

1.  将会出现**新建 Flex 项目**对话框，在对话框中你需要提供一个**项目名称**，并选择是创建面向**Web**还是**Desktop**的项目。如果这个项目将编译为 AIR for Android，我们需要确保选择**Desktop**，因为这种应用程序类型将针对 Adobe AIR 运行时。如果创建一个面向浏览器中 Flash Player 的项目，我们将选择**Web**。

1.  在选择**桌面**时，我们还需要确保为 Android 项目选择了一个移动增强版的 Flex SDK。Flex 4.5 及其以上版本包含了开发健壮 Android 应用程序所需的一切功能。![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_01_12.jpg)

1.  我们必须做的最后一件事是确保项目将使用移动版的 Flex SWCs。为了在项目的主容器中声明 `<s:ViewNavigatorApplication>` 或 `<s:TabbedViewNavigatorApplication>`，必须能够访问这些特定的 SWCs，否则 Flash Builder 会报告错误。

1.  **新建 Flex 项目**对话框的最后一部分允许我们确保包含移动 SWCs。您会注意到 `mobilecomponents.swc` 并未包含在我们的项目中。选择标签为 **库路径** 的选项卡，并点击标签为 **添加 SWC:** 的按钮。![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_01_13.jpg)

1.  当出现**添加 SWC**对话框时，浏览到所选 Flex SDK 的位置。假设我们将 SDK 解压到 `C:\SDKs\Flex4`，我们现在将浏览到 `C:\SDKs\Flex\frameworks\libs\mobile`，选择 `mobilecomponents.swc` 文件，并点击**打开**。这将向我们的应用程序添加对移动组件的支持。

1.  完成项目设置。我们现在能够使用移动特定的容器和控制组件，而不会收到 Flash Builder 的错误，但我们必须进行一些调整才能正确编译应用程序。

1.  在项目中找到 AIR 描述符文件。它通常被命名为类似 `{MyProject}-app.xml` 的名称，并位于项目根目录。打开这个文件，将 `<visible>` 属性更改为 **true**。如果该节点已被注释掉，可能需要取消注释。

1.  在**包资源管理器**中右键点击项目，并选择**属性**。

1.  选择**Flex 编译器**菜单选项，并在**附加编译参数**中添加以下内容：`theme=C:\{SDK Location}\frameworks\themes\Mobile\mobile.swc`

1.  最后，将主应用程序文件的根节点从 `<s:Application>` 切换到 `<s:ViewNavigatorApplication>`。我们现在可以使用移动 Flex 框架组件来编写和编译应用程序。

## 工作原理…

在 Flash Builder 中指定我们要创建的项目类型时，IDE 会自动提供 Flex 框架的某些部分，以便我们可以使用项目所需的所有组件。Flash Builder 4 及其早期版本没有附带任何移动版的 Flex SDK，并且不提供针对 Android 项目的流程。因此，我们必须明确告诉 Flash Builder 使用这些额外的框架组件。

前一节步骤中提到的应用程序描述符文件用于以各种方式配置 AIR 应用程序：设置初始窗口属性、Chrome 属性，甚至系统图标。

## 另请参阅…

需要注意的是，Flash Builder 4.5 之前的版本将不包括将项目编译为 .APK（Android 应用程序文件扩展名）的能力，你将需要使用免费提供的 AIR SDK 编译你的项目。有关如何执行此操作的信息，请参阅 第十一章。

值得一提的是，尽管你可以使用旧版本的 Flash Builder 开发 Android 应用程序，但你将无法获得新版本提供的大部分好处，例如代码补全功能。

# 使 Powerflasher FDT 4.1 能够访问 Flex Mobile SDK

Powerflasher FDT 是一个越来越受欢迎的 Flash 平台项目开发环境。FDT 4 配备了开始开发 ActionScript 和 Flex 应用程序所需的一切，但 FDT 4.1 及以下版本不支持任何移动工作流程，也不包含支持移动的 Flex SDK。

## 如何操作…

配置 Powerflasher FDT 4 以进行 Android 开发的步骤很少：

1.  访问 Adobe 开源网站 [`opensource.adobe.com/`](http://opensource.adobe.com/)，找到最新版本的 Flex SDK。

1.  下载最新 Adobe Flex SDK 的 `ZIP` 文件，并将其解压到硬盘上你容易记住的位置，例如 `C:\SDKs\Flex`。

1.  启动 **FDT** 并转到 **窗口 | 首选项**。

1.  滚动到 **FDT** 菜单项，选择 **已安装的 SDK**。你现在可以看到当前你复制的 FD 中可用的每个 SDK 的列表：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_01_14.jpg)

1.  点击标有 **添加** 的按钮，浏览到你最近下载的 Flex SDK 的位置。

1.  为对话框提供一个有意义的名称，然后点击 **确定**。例如，`Flex 4.5:`![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_01_15.jpg)

1.  现在，`Flex 4.5` SDK 可用于你的应用程序。要在项目中使用它，只需在创建新项目或在现有项目中修改 **Flex 编译器** 属性时选择此 SDK：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_01_16.jpg)

## 它的工作原理…

Powerflasher FDT 4 是一个基于 Eclipse 的 IDE（与 Flash Builder 类似），采用了很多相同的方法来扩展应用程序和添加 SDK 包。在 FDT 中使用较新版本的 Flex SDK 可以让我们访问移动主题选项和其他在之前 SDK 版本中不可用的特定 API。

## 另请参阅…

需要注意的是，Flash Builder 4.5 之前的版本将不包括将项目编译为 `.APK`（Android 应用程序文件扩展名）的能力，你将需要使用免费提供的 AIR SDK 编译你的项目。有关如何执行此操作的信息，请参阅 第十一章。

值得一提的是，虽然你可以使用 Flash Builder 的旧版本为 Android 开发应用程序，但你将无法获得新版本提供的一些好处，例如代码补全。

# 使用 Powerflasher FDT 4.1 及以下版本开发 Android 应用程序

要在 FDT 4.1 中开发移动 Android 应用程序，我们将需要配置 FDT 以启用对移动 Flex SDK 的访问。如果你还没有以这种方式配置 FDT，请参阅前面的菜谱。

## 如何操作…

在 FDT 4.2 之前的版本中，没有特定的移动工作流或工具。通过执行以下步骤，我们可以确保项目将具有移动兼容性：

1.  在 FDT 中，右键点击**Flash Explorer**面板，选择**新建 | 新建 Flash 项目：**![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_01_17.jpg)

1.  将会出现**新建 Flash 项目**对话框，你必须在其中提供**项目名称**，并选择是使用**ActionScript 3**还是**Flex**创建项目。我们需要确保选择**Flex 4**，因为这包括 Spark 组件，如果使用适当版本的 Flex SDK，它们可以是移动友好的。![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_01_18.jpg)

1.  下一个部分将允许我们选择一个特定的 Flex SDK 用于我们的项目。我们应该为 Android 项目选择一个增强移动版的 Flex SDK。Flex 4.5 及以上版本包括我们开始开发健壮的 Android 应用程序所需的一切。![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_01_19.jpg)

1.  我们必须做的最后一件事是确保移动版的 Flex SWC 将在我们的项目中使用。为了声明项目的主要容器为`<s:ViewNavigatorApplication>`或`<s:TabbedViewNavigatorApplication>`，这些特定的 SWC 必须是可访问的，否则 FDT 将报告错误。

1.  下一个部分允许我们确保包含移动 SWC。选择标签为**SDK Library**的选项卡，然后点击标签为**选择 SWCs**的按钮

1.  你会注意到`mobile\mobilecomponents.swc`没有包含在我们的项目中。选中此 SWC 旁边的复选框，然后按**确定**按钮继续：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_01_20.jpg)

1.  现在，我们将能够使用特定的移动容器和控制组件，而不会从 FDT 收到错误。

## 工作原理…

在 FDT 中指定我们想要创建的项目类型时，程序会自动提供 Flex 框架的某些部分，以便我们可以使用项目所需的所有组件。FDT 4.1 及更早版本不附带任何支持移动设备的 Flex SDK，也不提供 Android 项目的相关工作流。因此，我们必须明确告诉 FDT 使用以下额外的框架组件：

+   **ViewNavigatorApplication：**这包括一个`ViewNavigator`堆栈结构，我们可以将不同的视图推送到堆栈顶部，并向用户展示最顶层的视图。

+   **TabbedViewNavigatorApplication：** 这包括在应用程序内拥有多个`ViewNavigator`堆栈的能力，通过`TabBar`用户界面元素进行控制。

## 另请参阅…

需要注意的是，Flash Builder 4.5 之前的版本将无法将项目编译为`.APK`（Android 应用文件扩展名），你需要使用免费提供的 AIR SDK 来编译项目。有关如何执行此操作的信息，请参阅第十一章。

还值得一提的是，虽然你可以使用较旧版本的 Flash Builder 开发 Android 应用程序，但你将无法获得较新版本提供的大部分好处，例如代码补全功能。

# 将标准 Flex 项目转换为 Flex Mobile 项目

目前在 Flash Builder（或 FDT）中没有工作流可以将现有应用程序转换为移动 Android 应用程序。根据被转换应用程序的复杂程度和 Flex 的版本，这项转换任务可能从非常简单到异常复杂不等。在本教程中，我们将使用基本的 Flex 结构演示一个更简单的示例。

## 如何操作…

创建一个新的移动项目，并将所有必要的文件复制到其中，保留用于移动项目的代码部分，并修改任何不支持的组件。

在此示例中，我们将使用一个简单的 Flex 项目，该项目针对桌面 AIR，目前只包含一个按钮组件：

```kt
<?xml version="1.0" encoding="utf-8"?>
<s:WindowedApplication 

>
<s:Button x="10" y="10" width="300" height="200" label="Button"/>
</s:WindowedApplication>

```

要将此项目转换为新的 Flex Mobile 项目，请执行以下步骤：

1.  菜单中选择**文件 | 新建 | Flex Mobile 项目**。

1.  为项目设置对话框提供有关新移动项目的详细信息。

    ### 注意

    项目不能与环境中任何现有项目的名称相同。

1.  从原始项目中的项目文件夹中复制所有文件到这个新的移动项目中，不包括项目描述文件`({myApp }.xml)`和`Default Application`文件。

1.  现在，将旧`Default Application`文件中的所有内容复制并粘贴到与你的移动项目一起创建的`Default Application`文件中。一旦复制完成，右键点击主应用程序文件并选择**设为默认应用程序**。

1.  将所有`<s:WindowedApplication>`的实例更改为`<s:ViewNavigatorApplication>`（或者，`<s:TabbedViewNavigatorApplication>`）。

    ### 注意

    与标准的 AIR `<s:WindowedApplication>`一样，项目中只能存在一个`<s:ViewNavigatorApplication>`或`<s:TabbedViewNavigatorApplication>`实例。

1.  查看你的**问题**面板，以了解是否需要进一步修改。

1.  如果你没有使用任何旧的 Halo 组件（mx 命名空间），建议你为打开的`<s:ViewNavigatorApplication>`标签删除命名空间声明。

1.  向 `<s:ViewNavigatorApplication>` 标签添加一个 `firstView` 属性。这应该指向当你设置移动项目时自动创建的 `View`。

1.  由于可视化 UI 元素不能直接位于 `<s:ViewNavigatorApplication />` 节点内，我们必须将 `<s:Button />` 实例包裹在 `<fx:Declarations>` </fx:Declarations> 标签集中，或者将其移动到特定的 View 中。

### 提示

**下载示例代码**

你可以从你的[`www.PacktPub.com`](http://www.PacktPub.com)账户下载你所购买的所有 Packt 图书的示例代码文件。如果你在其他地方购买了这本书，可以访问[`www.PacktPub.com/support`](http://www.PacktPub.com/support)注册，我们会将文件直接通过电子邮件发送给你。

你的`Default Application`文件现在应如下所示：

```kt
<?xml version="1.0" encoding="utf-8"?>
<s:ViewNavigatorApplication 
 firstView="views.MobileFlexProjectHomeView">
<fx:Declarations>
<s:Button x="10" y="10" width="447" height="106" label="Button"/>
</fx:Declarations>
</s:ViewNavigatorApplication>

```

此外，此应用程序的视图可能如下所示：

```kt
<?xml version="1.0" encoding="utf-8"?>
<s:View 
 title="MobileFlexProjectHomeView ">
</s:View>

```

有关 Flex Mobile 项目的结构信息，请查看以下资源：[`opensource.adobe.com/wiki/display/flexsdk/Developer+Documentation`](http://opensource.adobe.com/wiki/display/flexsdk/Developer+Documentation)。

## 工作原理…

使用 Flex 时，你的应用程序的根标签在很大程度上决定了整个项目可用的 API 和结构。确保我们选择正确的根标签对于项目的目标平台和能力非常重要。对于在 Android 上的 AIR，我们将使用 `ViewNavigatorApplication` 或 `TabbedViewNavigatorApplication`。桌面应用程序将使用 Application 或 `WindowedApplication` 标签。如果你使用 Flex 构建的 Flash 内容要在浏览器中的 Flash Player 部署，无论是在移动端还是桌面端，你都会为你的项目使用一个直接的 `Application` 标签。

## 更多信息…

如果你不想处理大量转换，并且只是开始一个将同时在桌面和移动端共享相同代码库的新项目，那么你可能考虑使用 Flex Library 项目，以允许不同的项目共享相同的底层代码库。

阅读 Flex 4 库使用说明文档：[`help.adobe.com/en_US/flashbuilder/using/WS6f97d7caa66ef6eb1e63e3d11b6c4d0d21-7fe6.html`](http://help.adobe.com/en_US/flashbuilder/using/WS6f97d7caa66ef6eb1e63e3d11b6c4d0d21-7fe6.html)。

# 在 Windows 上配置 AIR SDK 以打包适用于 Android 应用的 AIR

如果我们使用开源的 AIR **SDK（软件开发工具包）**与另一个 IDE 或甚至在简单的文本编辑器中编辑我们的项目，我们仍然可以通过命令行工具编译适用于 Android 分发的应用程序。

## 如何操作…

如果您还没有 Adobe AIR SDK，您必须首先从[`www.adobe.com/products/air/sdk/`](http://www.adobe.com/products/air/sdk/)下载，并将其文件解压到硬盘上的一个目录中，例如`C:\SDKs\AIR`。您还必须在操作系统中设置一个指向 AIR SDK 下的`bin`目录的`PATH`变量。

如果您使用的是 Windows 系统，请通过以下步骤设置环境变量：

1.  打开**系统属性**对话框。有多种方式可以进入这个对话框，最直接的方法是右键点击**我的电脑**，然后选择**属性**。

1.  从左侧菜单中选择**高级系统设置**。

1.  点击此窗口底部的按钮，上面写着**环境变量**

1.  在此窗口中点击**PATH**变量，并选择**编辑：**![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_01_21.jpg)

1.  现在，只需将您的`bin`目录的位置添加到变量集合中：如果变量值列表中的最后一个条目没有以分号结束，您必须在每个新条目前添加一个。例如：`C:\SDKs\AIR\bin`。![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_01_22.jpg)

1.  这样应该就设置好了。点击几次**确定**，然后打开命令提示符以验证我们是否正确设置了。输入`adt -version`并按下**回车**。如果一切正常，ADT 会返回一个类似`adt version "2.5.0.00000"`这样的版本字符串。

## 工作原理…

在操作系统中设置一个`PATH`变量，这样我们就可以在系统的任何位置调用 AIR Android 编译器 ADT，而无需遍历文件目录并指定长路径名。

## 参见以下内容…

如果使用 Linux 或 Mac 操作系统，您也可以在终端内设置特定的环境变量。有关示例，请参阅下一食谱《在 Linux 或 Mac OS 上配置 AIR SDK 以打包 Android 应用程序的 AIR》。

# 在 Linux 或 Mac OS 上配置 AIR SDK 以打包 Android 应用程序的 AIR

如果我们使用开源的 AIR SDK 与其他 IDE 配合使用，甚至是在简单的文本编辑器中编辑我们的项目，我们仍然可以通过命令行工具编译在 Android 上分发的应用程序。

## 如何操作…

如果您还没有 Adobe AIR SDK，您必须首先从[`www.adobe.com/products/air/sdk/`](http://www.adobe.com/products/air/sdk/)下载，并将其文件解压到硬盘上的一个目录中：例如`/home/joseph/SDKs/AIR`。您还必须在操作系统的启动脚本中设置一个指向 AIR SDK 下的`bin`目录的`PATH`变量。

我们将通过以下步骤设置环境变量：

1.  打开**终端**。

1.  现在，我们必须创建 shell 配置文件。在终端窗口中输入以下内容：在 Mac 上输入`cat >> .bash_profile`，在 Ubuntu 上输入`cat >> .bashrc`（每个 Linux 发行版对于启动脚本可能有各自的命名约定）。

1.  接下来，输入 `export PATH=$PATH:/home/joseph/SDKs/AIR/bin` 来设置 `PATH` 变量，使其指向 AIR 开发工具的 bin 目录。按下 *Enter*。

1.  输入 *Ctrl+Shift+D* 以结束此进程。

1.  现在我们将检查是否所有内容都已适当地添加。在 **终端** 中输入 `cat .bashrc` 并按下 *Enter*。您应该会看到返回的 `PATH` 命令：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_01_23.jpg)

1.  您可能需要登出您的个人资料，然后再重新登录，以便系统获取新的环境变量。

1.  在重新登录您的个人资料后，再次打开 **终端**。

1.  在终端中输入 `echo $PATH` 并按下 *Enter*。这应该会显示 `PATH` 变量中包含的所有内容，包括我们的 AIR `bin` 目录的位置。

1.  这样应该就可以了。我们现在将验证是否正确设置了 AIR SDK。输入 `adt -version` 并按下 *Enter*。如果一切正常，ADT 将返回一个类似 `adt version "2.5.0.00000"` 的版本字符串！![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_01_24.jpg)

## 它是如何工作的…

在操作系统中设置 PATH 变量，使我们能够从系统的任何位置调用 AIR Android 编译器 ADT，而无需遍历文件目录并指定长路径名。

## 另请参阅…

请注意，您可能需要登出您的会话，然后再重新登录，以便新的 `PATH` 变量生效。如果使用的是 Windows 操作系统，您也可以设置特定的环境变量。有关此示例，请参阅前面的食谱，*在 Windows 上配置 AIR SDK 以打包适用于 Android 应用的 AIR*。


# 第二章：交互体验：多点触控、手势和其他输入

本章节将涵盖以下内容：

+   检测支持的设备输入类型

+   检测设备是否支持多点触控

+   验证常见交互的具体手势支持

+   使用手势放大显示对象

+   使用手势平移显示对象

+   使用手势滑动显示对象

+   使用手势旋转显示对象

+   访问原始触摸点数据

+   基于触摸点数据创建自定义手势

+   模拟安卓长按交互

+   程序化地调用虚拟键盘

+   应对安卓软键盘交互

+   应对轨迹球和 D-Pad 事件

# 引言

通过触摸和手势与设备交互的能力是移动计算突出的特点之一，Flash 平台在安卓上完全支持多点触控和手势。本章将介绍拦截和响应用户交互的不同方式，无论是通过简单的触摸点还是复杂的手势，以及更传统的物理和虚拟键盘输入。在移动安卓设备上充分利用这一点对于流畅的体验至关重要。

本章节中的所有示例均表示为纯 ActionScript 3 类，不依赖于外部库或 Flex 框架。因此，我们可以将这些示例应用到我们希望的任何 IDE 中。

# 检测支持的设备输入类型

安卓设备上有多种输入类型可供选择，根据我们正在从事的项目，可能需要验证特定设备是否支持预期的用户交互模式。幸运的是，有许多 ActionScript 类可以帮助我们发现设备在用户输入方面的功能。

## 如何操作...

我们需要使用内部类来检测是否支持多点触控：

1.  首先，将以下类导入到项目中，以便检查各种设备上的输入类型：

    ```kt
    import flash.display.Sprite;
    import flash.display.Stage;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.system.Capabilities;
    import flash.system.TouchscreenType;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.ui.Keyboard;
    import flash.ui.KeyboardType;
    import flash.ui.Mouse;

    ```

1.  声明一个 `TextField` 和 `TextFormat` 对象，以允许在设备上输出可见内容：

    ```kt
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  我们现在将设置 `TextField`，应用 `TextFormat`，并将其添加到 `DisplayList` 中。这里，我们创建一个方法来执行所有这些操作：

    ```kt
    protected function setupTextField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 32;
    traceFormat.align = "center";
    traceFormat.color = 0x333333;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  现在，我们将简单地通过检查这些类调用一系列属性返回的数据。以下示例中，我们是在以下方法中执行此操作：

    ```kt
    protected function checkInputTypes():void {
    traceField.appendText("Touch Screen Type: " + flash.system.Capabilities.touchscreenType + "\n");
    traceField.appendText("Mouse Cursor: " + flash.ui.Mouse. supportsCursor + "\n");
    traceField.appendText("Physical Keyboard Type: " + flash. ui.Keyboard.physicalKeyboardType + "\n");
    traceField.appendText("Virtual Keyboard: " + flash.ui.Keyboard. hasVirtualKeyboard + "\n");
    }

    ```

1.  结果将类似于以下内容：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_02_01.jpg)

## 工作原理...

当调用时，Flash 平台运行时能够报告某些设备功能。报告的数据将允许我们根据运行时检测到的输入类型定制用户体验。

以下是四种可以报告的输入类型的基本概述：

`flash.system.Capabilities.touchscreenType`

调用此方法将返回一个`String`常量，值为`FINGER`、`STYLUS`或`NONE`。它告诉我们设备上是否支持某种形式的直接屏幕交互，如果是，是哪种形式。在 Android 设备上，这将始终返回`FINGER`。

`flash.ui.Mouse.supportsCursor`

调用此方法将返回一个`Boolean`值，为`true`或`false`。它简单地告诉我们设备上是否有持久鼠标光标。在 Android 设备上，这很可能会始终返回`false`。

`flash.ui.Keyboard.physicalKeyboardType`

调用此方法将返回一个`String`常量，值为`ALPHANUMERIC`、`KEYPAD`或`NONE`。它告诉我们设备上是否有某种专用的物理键盘，如果有，是哪种类型。在 Android 设备上，这很可能会始终返回`NONE`，尽管某些 Android 型号确实有物理键盘。

`flash.ui.Keyboard.hasVirtualKeyboard`

调用此方法将返回一个`Boolean`值，为`true`或`false`。它简单地告诉我们设备上是否有虚拟（软件）键盘。在 Android 设备上，这很可能会始终返回`true`。

# 检测设备是否支持多点触控

在针对 Android 操作系统的项目开发中，确保设备实际上支持多点触控总是一个好主意。在 Android 手机上，这可能总是如此，但 Google TV 或 AIR for TV 设备呢？其中许多也是基于 Android 的，但大多数电视根本没有触摸控制。永远不要假设任何设备的功能。

## 如何操作...

我们需要使用内部类来检测是否支持多点触控。

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.StageScaleMode;
    import flash.display.StageAlign;
    import flash.display.Stage;
    import flash.display.Sprite;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.ui.Multitouch;

    ```

1.  声明一个`TextField`和`TextFormat`对象，以允许在设备上可见输出：

    ```kt
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  我们现在将设置我们的`TextField`，应用一个`TextFormat`，并将其添加到`DisplayList`中。这里，我们创建一个方法来执行所有这些操作：

    ```kt
    protected function setupTextField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 44;
    traceFormat.align = "center";
    traceFormat.color = 0x333333;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  然后，只需调用`Multitouch.supportsGestureEvents`和`Multitouch.supportsTouchEvents`，即可检查这些功能，如下面的方法所示：

    ```kt
    protected function checkMultitouch():void {
    traceField.appendText(String("Gestures: " + Multitouch.supportsGestureEvents) + "\n");
    traceField.appendText(String("Touch: " + Multitouch.supportsTouchEvents));
    }

    ```

1.  这些属性中的每一个都将返回一个`Boolean`值，`true`或`false`，表示设备支持，如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_02_02.jpg)

## 工作原理...

检测设备是否支持触摸或手势事件将决定作为开发者的你，在细化用户体验方面有多少自由度。如果这些项目中的任何一个返回为 false，那么就需要你（如果可能的话）提供一种替代方式让用户与应用程序交互。这通常是通过`Mouse`事件完成的：

+   **触摸事件：**如单指轻触等基本交互。

+   **手势事件：**更复杂的用户交互解释，如捏合、缩放、滑动、平移等。

## 还有更多...

需要注意的是，尽管特定设备可能支持手势事件或触摸事件，但在使用 Flash 平台工具时，我们必须将`Multitouch.inputMode`明确设置为其中之一。

# 验证常见交互中特定手势的支持

在处理 Android 设备时，触摸和手势是用户与设备交互的主要机制。如果我们想在 Flash Player 和 AIR 中使用一些预定义的手势，可以按照以下方式操作。

## 如何操作...

要发现设备支持哪些特定的手势，执行以下操作：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.StageScaleMode;
    import flash.display.StageAlign;
    import flash.display.Stage;
    import flash.display.Sprite;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;

    ```

1.  声明一个`TextField`和`TextFormat`对象，以允许在设备上输出可见内容：

    ```kt
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  我们现在将设置我们的`TextField`，应用`TextFormat`，并将其添加到`DisplayList`中。在这里，我们创建一个方法来执行所有这些操作：

    ```kt
    protected function setupTextField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 44;
    traceFormat.align = "center";
    traceFormat.color = 0x333333;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  使用以下命令为多触控 API 设置特定的输入模式以支持手势：

    ```kt
    Multitouch.inputMode = MultitouchInputMode.GESTURE;

    ```

1.  调用`Multitouch.supportedGestures`将返回一个包含设备上 Flash 支持的所有手势名称的`String`对象`Vector`：

    ```kt
    var supportedGestures:Vector.<String> = Multitouch.supportedGestures;

    ```

1.  然后，我们可以寻找特定的手势或手势集进行监听，或者在必要时退回到其他交互事件。

    ```kt
    for(var i:int=0; i < supportedGestures.length; ++i) {
    trace(supportedGestures[i]);
    }

    ```

1.  我们可以在一个方法内执行所有这些必要功能：

    ```kt
    protected function checkGestures():void {
    Multitouch.inputMode = MultitouchInputMode.GESTURE;
    if(Multitouch.supportedGestures){
    var supportedGestures:Vector.<String> = Multitouch.supportedGestures;
    for(var i:int=0; i <supportedGestures.length; ++i) {
    traceField.appendText(supportedGestures[i] + "\n");
    }
    }else{
    traceField.appendText("no gesture support!");
    }
    }

    ```

1.  结果将类似于以下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_02_03.jpg)

## 工作原理...

Flash 播放器和 AIR 在为 Android 开发者提炼信息至关键细节方面做得非常出色。了解特定设备支持哪些手势，将使我们能够为应用程序定制事件交互，并在必要时提供后备交互。

## 还有更多...

在我们的示例类中，我们还通过`Multitouch.supportedGestures`检查以确保至少支持一些手势。如果设备确实提供了手势支持，我们可能需要向用户提供警告，解释应用程序由于硬件限制可能无法达到最佳性能。

除了在`flash.events.TransformGestureEvent`包中包含的更常见的诸如缩放、滑动、旋转和平移等手势之外，还有其他较少见的手势，如双指轻触，可以在`flash.events.GestureEvent`和`flash.events.PressAndTapGestureEvent`类中找到。如果设备支持，所有这些都将由`Multitouch.supportedGestures`引用。

# 使用手势放大显示对象

捏合和拉扯是在支持多触控输入的触摸屏上经常使用的手势。将两个手指靠近会缩小对象，而将两个手指分开会使对象在设备上变大。

## 如何操作...

本示例在一个`Shape`对象内使用`Graphics` API 绘制一个正方形，将其添加到`Stage`中，然后为缩放手势事件设置监听器，以适当缩放`Shape`：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.StageScaleMode;
    import flash.display.StageAlign;
    import flash.display.Stage;
    import flash.display.Sprite;
    import flash.display.Shape;
    import flash.events.TransformGestureEvent;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;

    ```

1.  声明一个`Shape`对象，我们将在其上执行手势操作：

    ```kt
    private var box:Shape;

    ```

1.  接下来，构建一个方法来处理我们的`Sprite`的创建并将其添加到`DisplayList`中：

    ```kt
    protected function setupBox():void {
    box = new Shape();
    box.graphics.beginFill(0xFFFFFF, 1);
    box.x = stage.stageWidth/2;
    box.y = stage.stageHeight/2;
    box.graphics.drawRect(-150,-150,300,300);
    box.graphics.endFill();
    addChild(box);
    }

    ```

1.  将多触点 API 的特定输入模式设置为支持触摸输入，通过将`Multitouch.inputMode`设置为`MultitouchInputMode.TOUCH_POINT`常量，并注册`GESTURE_ZOOM`事件的事件监听器。在这种情况下，每当应用程序检测到缩放手势时，`onZoom`方法将被触发：

    ```kt
    protected function setupTouchEvents():void {
    Multitouch.inputMode = MultitouchInputMode.GESTURE;
    stage.addEventListener(TransformGestureEvent. GESTURE_ZOOM, onZoom);
    }

    ```

1.  为了使用捏合和缩放的接受行为，我们可以根据事件监听器返回的缩放因子调整舞台上对象的缩放比例。

    ```kt
    protected function onZoom(e:TransformGestureEvent):void {
    box.scaleX *= e.scaleX;
    box.scaleY *= e.scaleY;
    }

    ```

1.  结果手势将以以下方式影响我们的视觉对象：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_02_04.jpg)

### 注意

插图由 Gestureworks 提供（www.gestureworks.com）。

## 工作原理...

由于我们将`Multitouch.inputMode`设置为通过`MultitouchInputMode.GESTURE`的手势，因此我们能够监听并响应一系列预定义的手势。在这个例子中，我们监听`TransformGestureEvent.GESTURE_ZOOM`事件，以便设置我们的`Shape`对象的缩放比例。通过将当前的缩放属性与事件报告的缩放值相乘，我们可以根据这个手势调整对象的缩放比例。

## 还有更多内容...

请注意，我们绘制正方形的方式是将`Shape`的注册点位于可见`Shape`的中心。我们这样做很重要，因为`DisplayObject`将基于注册点和变换点进行放大和缩小。

在使用 Flash Professional 中的绘图工具时，请确保将你的`MovieClip`符号的注册点设置为居中，以便正确工作。

## 另请参阅...

`TransformGestureEvent.GESTURE_ZOOM`只是我们在使用 Flash Platform 运行时和 Android 设备时可以使用的四个主要变换手势之一。参考以下食谱以获取这些手势的完整概述：

+   *使用手势平移显示对象*

+   *使用手势滑动显示对象*

+   *使用手势旋转显示对象*

# 使用手势平移显示对象

平移`DisplayObject`是通过同时用两个手指触摸屏幕，然后沿着我们想要平移对象的屏幕方向移动两个手指来完成的。这通常用于占据比屏幕更大的对象，或者已经放大到只有部分在给定时间内在屏幕上可见的对象。

## 如何操作...

这个例子使用`Graphics` API 在`Shape`对象内绘制一个正方形，将其添加到`Stage`中，然后为平移手势事件设置监听器，以适当缩放`Shape`。

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.StageScaleMode;
    import flash.display.StageAlign;
    import flash.display.Stage;
    import flash.display.Sprite;
    import flash.display.Shape;
    import flash.events.TransformGestureEvent;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;

    ```

1.  声明一个`Shape`对象，我们将在这个对象上执行手势操作：

    ```kt
    private var box:Shape;

    ```

1.  接下来，构建一个方法来处理我们的`Shape`的创建并将其添加到`DisplayList`中。我们特别努力确保我们的`Shape`比屏幕大得多，以便可以有效地进行平移：

    ```kt
    protected function setupBox():void {
    box = new Shape();
    box.graphics.beginFill(0xFFFFFF, 1);
    box.x = stage.stageWidth/2;
    box.y = stage.stageHeight/2;
    box.graphics.drawRect(-150,-150,300,300);
    box.graphics.endFill();
    box.graphics.lineStyle(10, 0x440000, 1);
    box.graphics.moveTo(0, -800);
    box.graphics.lineTo(0, 800);
    box.graphics.moveTo(-800, 0);
    box.graphics.lineTo(800, 0);
    addChild(box);
    }

    ```

1.  设置特定的输入模式以支持多点触控 API 的触摸输入，通过将`Multitouch.inputMode`设置为`MultitouchInputMode.TOUCH_POINT`常量，并注册`GESTURE_PAN`事件的事件监听器。在这种情况下，每当应用程序检测到缩放手势时，`onPan`方法将被触发：

    ```kt
    protected function setupTouchEvents():void {
    Multitouch.inputMode = MultitouchInputMode.GESTURE;
    stage.addEventListener(TransformGestureEvent. GESTURE_PAN, onPan);
    }

    ```

1.  我们现在可以响应我们的平移事件返回的数据。在这个例子中，我们只是根据平移偏移数据简单地改变了`Shape`的 x 和 y 位置：

    ```kt
    protected function onPan(e:TransformGestureEvent):void {
    box.x += e.offsetX;
    box.y += e.offsetY;
    }

    ```

1.  结果手势将以以下方式影响我们的视觉对象：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_02_05.jpg)

### 注意

图形由 Gestureworks 提供（www.gestureworks.com）。

## 工作原理...

由于我们将`Multitouch.inputMode`设置为通过`MultitouchInputMode.GESTURE`的手势，因此我们能够监听并响应一系列预定义的手势。在这个例子中，我们监听`TransformGestureEvent.GESTURE_PAN`事件，以便改变我们的`Shape`对象的 x 和 y 位置。通过调整我们的`Shape`的坐标通过报告的偏移数据，我们可以按照用户期望的方式调整对象的位置。

## 还有更多...

请注意，在某些设备上执行此操作通常很困难（因为你必须同时用两个手指触摸屏幕），而其他设备可能根本不支持它。作为后备，我们总是可以使用`startDrag()`和`stopDrag()`方法来模拟平移。 

## 另请参阅...

`TransformGestureEvent.GESTURE_PAN`只是我们在使用 Flash Platform 运行时和 Android 设备时可以使用的一组四个主要转换手势之一。参考以下食谱以获取这些手势的完整概述：

+   *使用手势缩放 DisplayObject*

+   *使用手势滑动显示对象*

+   *使用手势旋转显示对象*

# 使用手势滑动显示对象

滑动是 Android 设备上最常见的动作之一，并且有充分的理由。无论是快速翻阅一系列照片，还是在应用程序的状态之间移动，滑动手势都是用户所期望的。通过简单地触摸屏幕并在相反的方向快速向上、下、左或右滑动，即可完成滑动动作。

## 如何操作...

这个例子在`Shape`对象内使用`Graphics` API 绘制一个正方形，将其添加到`Stage`中，然后设置一个监听器来监听滑动手势事件，以便根据滑动的方向将`Shape`实例移动到屏幕边缘：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.StageScaleMode;
    import flash.display.StageAlign;
    import flash.display.Stage;
    import flash.display.Sprite;
    import flash.display.Shape;
    import flash.events.TransformGestureEvent;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;

    ```

1.  声明一个`Shape`对象，我们将对其执行手势操作：

    ```kt
    private var box:Shape;

    ```

1.  接下来，构建一个方法来处理我们的`Shape`的创建并将其添加到`DisplayList`中：

    ```kt
    protected function setupBox():void {
    box = new Shape();
    box.graphics.beginFill(0xFFFFFF, 1);
    box.x = stage.stageWidth/2;
    box.y = stage.stageHeight/2;
    box.graphics.drawRect(-150,-150,300,300);
    box.graphics.endFill();
    addChild(box);
    }

    ```

1.  将多触点 API 的特定输入模式设置为支持触摸输入，通过将`Multitouch.inputMode`设置为`MultitouchInputMode.TOUCH_POINT`常量，并注册`TransformGestureEvent.GESTURE_SWIPE`事件的事件监听器：

    ```kt
    protected function setupTouchEvents():void {
    Multitouch.inputMode = MultitouchInputMode.GESTURE;
    stage.addEventListener(TransformGestureEvent. GESTURE_SWIPE, onSwipe);
    }

    ```

1.  我们现在可以响应滑动事件返回的数据。在这种情况下，我们只是根据滑动偏移数据简单地移动`Shape`的 x 和 y 位置：

    ```kt
    protected function onSwipe(e:TransformGestureEvent):void {
    switch(e.offsetX){
    case 1:{
    box.x = stage.stageWidth - (box.width/2);
    break;
    }
    case -1:{
    box.x = box.width/2;
    break;
    }
    }
    switch(e.offsetY){
    case 1:{
    box.y = stage.stageHeight - (box.height/2);
    break;
    }
    case -1:{
    box.y = box.height/2;
    break;
    }
    }
    }

    ```

1.  结果手势将以以下方式影响我们的视觉对象：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_02_06.jpg)

### 注意

提供的手势图由 Gestureworks（www.gestureworks.com）提供。

## 工作原理...

由于我们将`Multitouch.inputMode`设置为通过`MultitouchInputMode.GESTURE`的手势，因此我们能够监听并响应许多预定义的手势。在这个例子中，我们监听`TransformGestureEvent.GESTURE_SWIPE`事件，以便改变我们的`Shape`对象的 x 和 y 位置。通过调整`Shape`的坐标，通过报告的偏移数据，我们可以按照用户期望的方式调整对象的位置。

通过这个例子我们可以看到，事件监听器返回的`offsetX`和`offsetY`值将分别是 1 或-1。这使得我们很容易确定注册的手势方向：

+   **向上滑动：** offsetY = -1

+   **向下滑动：** offsetY = 1

+   **向左滑动：** offsetX = -1

+   **向右滑动：** offsetX = 1

## 还有更多内容...

在响应滑动事件时，可能需要提供一些过渡动画，使用内置的补间机制或外部补间引擎。有许多优秀的 ActionScript 补间引擎作为开源软件免费提供。这些引擎与某些手势结合使用，可以为应用程序用户提供更愉快的使用体验。

我们可以考虑在应用程序中使用以下流行的补间引擎：

**TweenLite：**[`www.greensock.com/tweenlite/`](http://www.greensock.com/tweenlite/)

**GTween：**[`www.gskinner.com/libraries/gtween/`](http://www.gskinner.com/libraries/gtween/)

## 另请参阅...

`TransformGestureEvent.GESTURE_SWIPE`只是我们在使用 Flash Platform 运行时和 Android 设备时可用的一组四个主要转换手势之一。参考以下食谱以获取这些手势的完整概述：

+   *使用手势放大显示对象*

+   *使用手势平移显示对象*

+   *使用手势旋转显示对象*

# 使用手势旋转显示对象

旋转是通过在物体的不同点按住两个手指，然后一个手指绕另一个手指顺时针或逆时针移动来完成的。这将导致屏幕上的物体旋转。旋转可以与平移和缩放手势结合使用，为用户提供对图像或其他`DisplayObject`的完全控制。

## 如何操作...

这个例子在`Shape`对象内使用`Graphics` API 绘制一个正方形，将其添加到`Stage`，然后设置一个监听器来监听`Rotate`手势事件，以便围绕其注册点适当地旋转`Shape`实例：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.StageScaleMode;
    import flash.display.StageAlign;
    import flash.display.Stage;
    import flash.display.Sprite;
    import flash.display.Shape;
    import flash.events.TransformGestureEvent;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;

    ```

1.  声明一个`Shape`对象，我们将对其执行手势操作：

    ```kt
    private var box:Shape;

    ```

1.  接下来，构建一个方法来处理我们的`Shape`的创建并将其添加到`DisplayList`中。

    ```kt
    protected function setupBox():void {
    box = new Shape();
    box.graphics.beginFill(0xFFFFFF, 1);
    box.x = stage.stageWidth/2;
    box.y = stage.stageHeight/2;
    box.graphics.drawRect(-150,-150,300,300);
    box.graphics.endFill();
    addChild(box);
    }

    ```

1.  将多触点 API 的特定输入模式设置为支持触摸输入，通过将`Multitouch.inputMode`设置为`MultitouchInputMode.TOUCH_POINT`常量，并为`GESTURE_ROTATE`事件注册一个事件监听器。在这种情况下，每当应用程序检测到旋转手势时，都会触发`onRotate`方法：

    ```kt
    protected function setupTouchEvents():void {
    Multitouch.inputMode = MultitouchInputMode.GESTURE; stage.addEventListener(TransformGestureEvent.GESTURE_ROTATE, onRotate);
    }

    ```

1.  我们现在可以响应旋转事件返回的数据。在这个例子中，我们只是将从事件监听器返回的`rotation`值简单地赋给我们的`Shape`的`rotation`参数，以执行适当的旋转：

    ```kt
    protected function onRotate(e:TransformGestureEvent):void {
    box.rotation += e.rotation;
    }

    ```

1.  结果手势将以以下方式影响我们的视觉对象：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_02_07.jpg)

### 注意

提供的手势图由 Gestureworks (www.gestureworks.com)提供。

## 工作原理...

由于我们将`Multitouch.inputMode`设置为通过`MultitouchInputMode.GESTURE`的手势，因此我们能够监听并响应一系列预定义的手势。在这个例子中，我们正在监听`TransformGestureEvent.GESTURE_ROTATE`事件，以便将返回的`rotation`值赋给我们的`Shape`对象。

在大多数情况下，实际上无需对此数据进行进一步计算，但我们可以通过允许（例如）一个`DisplayObject`的旋转影响另一个`DisplayObject`的旋转，甚至影响`Stage`上的多个`DisplayObjects`的旋转，来进行更高级的旋转交互。

## 还有更多...

请注意，我们是以这种方式绘制正方形，使得`Shape`的注册点位于可见`Shape`的中心。我们这样做很重要，因为`DisplayObject`将基于注册点和变换点进行旋转。

在使用 Flash Professional 的绘图工具时，请确保将你的`MovieClip`符号的注册点设置为居中，以便正确工作。

## 另请参阅...

`TransformGestureEvent.GESTURE_ROTATE`只是我们在使用 Flash Platform 运行时和 Android 设备时可以使用的一组四个主要变换手势之一。参考以下食谱以获取这些手势的完整概述：

+   *使用手势放大显示对象*

+   *使用手势平移显示对象*

+   *使用手势滑动显示对象*

# 访问原始触摸点数据

有时 Flash Player 和 AIR 内置的预定义手势对于某些应用程序交互来说是不够的。这个示例将演示如何通过 Flash Player 或 AIR API 访问操作系统报告的原始触摸数据。

## 如何操作...

要在项目中读取原始触摸数据，请执行以下步骤：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.StageScaleMode;
    import flash.display.StageAlign;
    import flash.display.Stage;
    import flash.display.Sprite;
    import flash.events.TouchEvent;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;

    ```

1.  声明一个`TextField`和一个`TextFormat`对象，以允许在设备上可见输出：

    ```kt
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  我们现在将设置我们的`TextField`，应用一个`TextFormat`，并将其添加到`DisplayList`中。这里，我们创建一个方法来执行所有这些操作：

    ```kt
    protected function setupTextField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 44;
    traceFormat.align = "left";
    traceFormat.color = 0x333333;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  设置多触摸 API 的特定输入模式以支持触摸输入，通过将`Multitouch.inputMode`设置为`MultitouchInputMode.TOUCH_POINT`常量。我们还在以下方法中为`TouchEvent`数据注册一组监听器：

    ```kt
    protected function setupTouchEvents():void {
    Multitouch.inputMode = MultitouchInputMode.TOUCH_POINT;
    stage.addEventListener(TouchEvent.TOUCH_MOVE, touchMove);
    stage.addEventListener(TouchEvent.TOUCH_END, touchEnd);
    }

    ```

1.  为了在每次触摸交互结束后清除我们的`TextField`，我们将构建以下函数：

    ```kt
    protected function touchEnd(e:TouchEvent):void {
    traceField.text = "";
    }

    ```

1.  然后，我们可以从触摸事件中读取各种属性以某种方式解释。可以从返回的事件对象中派生出压力、坐标、大小等事件：

    ```kt
    protected function touchMove(e:TouchEvent):void {
    traceField.text = "";
    traceField.appendText("Primary: " + e.isPrimaryTouchPoint + "\n");
    traceField.appendText("LocalX: " + e.localX + "\n");
    traceField.appendText("LocalY: " + e.localY + "\n");
    traceField.appendText("Pressure: " + e.pressure + "\n");
    traceField.appendText("SizeX: " + e.sizeX + "\n");
    traceField.appendText("SizeY: " + e.sizeY + "\n");
    traceField.appendText("StageX: " + e.stageX + "\n");
    traceField.appendText("StageY: " + e.stageY + "\n");
    traceField.appendText("TPID: " + e.touchPointID + "\n");
    }

    ```

1.  结果将类似于以下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_02_08.jpg)

## 工作原理...

设备中注册的每个触摸点都关联有一系列特定的属性。通过注册一组监听器来检测这些交互，我们可以读取这些数据，应用程序也可以做出适当的反应。在我们的示例中，我们只是通过`TextField`显示这些值，但这正是构建压力敏感的游戏机制或其他自定义手势所需的确切数据。

请注意，在一个允许多于一个触摸点的设备上，我们可以使用同一个监听器读取两个触摸点的数据。多个触摸点通过舞台上的位置和`touchPointID`来区分。在设计复杂手势时，或者当我们需要精确地跟踪每个触摸点时，我们会使用这些 ID 来区分触摸点。

## 还有更多...

需要注意的是，当`Multitouch.inputMode`设置为`MultitouchInputMode.TOUCH_POINT`时，我们将无法利用 Flash Player 和 AIR 通过简化手势 API 提供的预定义手势。将`Multitouch.inputMode`设置为`MultitouchInputMode.GESTURE`将允许我们在应用程序中使用常见的预定义手势事件。

# 基于触摸点数据创建自定义手势

使用原始触摸数据，我们可以定义自定义手势以开发应用程序中使用的独特交互。我们通过基于原始触摸事件传递的数据进行计算来实现这一点。

## 如何操作...

在此示例中，我们将创建一个对角线滑动手势，它可以返回四个独立的值，让我们知道对角线滑动的方向。

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.Shape;
    import flash.display.Sprite;
    import flash.display.Stage;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.TouchEvent;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;

    ```

1.  声明一个`TextField`和一个`TextFormat`对象，以允许在设备上可见文本输出：

    ```kt
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  我们将设置两个附加对象以帮助跟踪我们的手势，一个名为`drawArea`的`Shape`通过图形 API 绘制手势，以及`trackBeginObject`，这是一个简单的对象，我们可以使用它来保存我们的初始触摸坐标以与触摸结束时的坐标进行比较：

    ```kt
    private var drawArea:Shape;
    private var trackBeginObject:Object;

    ```

1.  现在，我们将设置我们的`TextField`，应用一个`TextFormat`，并将其添加到`DisplayList`中。这里，我们创建一个方法来执行所有这些操作：

    ```kt
    protected function setupTextField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 32;
    traceFormat.align = "center";
    traceFormat.color = 0x333333;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  接下来，我们将在其中设置我们的`Shape`，并使用`Graphics` API 绘制手势：

    ```kt
    protected function setupDrawArea():void {
    drawArea = new Shape();
    addChild(drawArea);
    }

    ```

1.  通过将`Multitouch.inputMode`设置为`MultitouchInputMode.TOUCH_POINT`常量，为多触控 API 设置特定的输入模式以支持触摸输入。在这个例子中，我们将注册一组监听器来检测`Stage`上的触摸移动。这将有助于为我们的手势跟踪提供视觉反馈，并保存我们的初始触摸坐标以与触摸结束时的坐标进行比较。

1.  我们也将通过同样的方法初始化我们的跟踪`Object`：

    ```kt
    protected function setupTouchEvents():void {
    Multitouch.inputMode = MultitouchInputMode.TOUCH_POINT;
    trackBeginObject = new Object();
    stage.addEventListener(TouchEvent.TOUCH_BEGIN, touchBegin);
    stage.addEventListener(TouchEvent.TOUCH_MOVE, touchMove);
    stage.addEventListener(TouchEvent.TOUCH_END, touchEnd);
    }

    ```

1.  构造一个名为`touchBegin`的方法，以初始化我们手势的开始并保存坐标数据以供稍后比较。我们将确保注册的触摸点是通过测试`TouchEvent.isPrimaryTouchPoint`布尔属性来确定是可能是多个触摸中的第一个触摸点。

    ```kt
    protected function touchBegin(e:TouchEvent):void {
    if(e.isPrimaryTouchPoint){
    drawArea.graphics.clear();
    drawArea.graphics.lineStyle(20, 0xFFFFFF, 0.8);
    trackBeginObject.x = e.stageX;
    trackBeginObject.y = e.stageY;
    drawArea.graphics.moveTo(e.stageX, e.stageY);
    }
    }

    ```

1.  构造另一个名为`touchMove`的方法，以接受触摸移动数据并绘制我们的视觉反馈：

    ```kt
    protected function touchMove(e:TouchEvent):void {
    if(e.isPrimaryTouchPoint){
    drawArea.graphics.lineTo(e.stageX, e.stageY);
    }
    }

    ```

1.  构造一个名为`touchEnd`的最终方法，通过我们之前保存的`trackBeginObject`将结束触摸数据坐标与开始时的坐标进行比较，然后确定它是什么样的手势。在这种情况下，我们将结果作为`String`输出到之前创建的`TextField`中：

    ```kt
    protected function touchEnd(e:TouchEvent):void {
    if(e.isPrimaryTouchPoint){
    if(e.stageX > trackBeginObject.x && e.stageY > trackBeginObject.y){
    traceField.text = "Diagonal Gesture: TL -> BR";
    }elseif(e.stageX < trackBeginObject.x && e.stageY > trackBeginObject.y){
    traceField.text = "Diagonal Gesture: TR -> BL";
    }elseif(e.stageX < trackBeginObject.x && e.stageY < trackBeginObject.y){
    traceField.text = "Diagonal Gesture: BR -> TL";
    }elseif(e.stageX > trackBeginObject.x && e.stageY < trackBeginObject.y){
    traceField.text = "Diagonal Gesture: BL -> TR";
    }
    }
    }

    ```

1.  结果将类似于以下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_02_09.jpg)

### 注意

图形由 Gestureworks 提供（www.gestureworks.com）。

## 工作原理...

由于我们可以访问所有原始触摸点数据，因此我们可以利用常规 ActionScript 元素（如`Object, Vector`或`Array`实例）从开始到结束追踪触摸交互的生命周期。根据追踪的数据，例如坐标位置，触摸压力等，我们可以进行计算并确定交互是否合格为我们想要跟踪的手势。

在我们前面的例子中，我们对合格手势的判断相当宽松。为了更加严格，我们还可以计算不同触摸点的距离，甚至追踪从触摸开始到触摸结束的时间，以确保手势正是我们要寻找的，因此是用户有意的。

## 还有更多...

实际上，有许多手势库可以作为 Flash Player 和 AIR 运行时的内置手势库的替代品。快速进行网络搜索应该可以让我们访问到这些库，其中许多是免费的开放源码软件。最受欢迎的第三方手势库是`Gesture Works`，可以从[`gestureworks.com/`](http://gestureworks.com/)下载。

# 模拟 Android 长按交互

Android 操作系统中内置的最有用的交互之一是长按。当用户轻触特定区域并持续几秒钟而不释放时，就会实现这一功能。虽然 Flash Player 和 Android 的 AIR 都没有将长按交互作为多点触控手势事件库的一部分，但通过这两个运行时模拟这一交互是相当简单的。

## 如何操作...

我们将通过使用 ActionScript `Timer`对象以及`TouchPoint`事件来模拟 Android 的长按交互。

1.  首先，将以下类导入到您的项目中：

    ```kt
    import flash.display.StageScaleMode;
    import flash.display.StageAlign;
    import flash.display.Stage;
    import flash.display.Sprite;
    import flash.events.TimerEvent;
    import flash.events.TouchEvent;
    import flash.geom.Rectangle;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;
    import flash.utils.Timer;

    ```

1.  声明一个`Sprite`对象，我们将在其上进行长按操作，以及一个`Timer`对象：

    ```kt
    private var box:Sprite;
    private var lpTimer:Timer;

    ```

1.  设置我们的`Timer`对象以测量注册长按所需的时间；在这个例子中，是 1000 毫秒。此外，我们现在注册一个监听器，以检测`Timer`周期是否完成：

    ```kt
    protected function setupTimer():void {
    lpTimer = new Timer(1000,1);
    lpTimer.addEventListener(TimerEvent.TIMER_COMPLETE, timerEnd);
    }

    ```

1.  接下来，构建一个方法来处理我们`Sprite`的创建并将其添加到`DisplayList`中：

    ```kt
    protected function setupBox():void {
    box = new Sprite();
    box.graphics.beginFill(0xFFFFFF, 1);
    box.x = stage.stageWidth/2;
    box.y = stage.stageHeight/2;
    box.graphics.drawRect(-100,-100,200,200);
    box.graphics.endFill();
    addChild(box);
    }

    ```

1.  将多点触控 APIs 的特定输入模式设置为支持触摸输入，通过将`Multitouch.inputMode`设置为`MultitouchInputMode.TOUCH_POINT`常量。为了模拟长按，我们必须在每次触摸交互的开始通过`TouchEvent.TOUCH_BEGIN`启动一个定时器。当触发`TouchEvent.TOUCH_END`或其他触摸取消事件时，将停止`Timer`，重置我们的“长按”。

    ```kt
    protected function setupTouchEvents():void {
    Multitouch.inputMode = MultitouchInputMode.TOUCH_POINT;
    box.addEventListener(TouchEvent.TOUCH_BEGIN, touchBegin);
    box.addEventListener(TouchEvent.TOUCH_END, touchEnd);
    box.addEventListener(TouchEvent.TOUCH_OUT, touchEnd);
    box.addEventListener(TouchEvent.TOUCH_ROLL_OUT, touchEnd);
    }

    ```

1.  构造一个方法，在触摸交互开始时修改我们的`Sprite`。我们将稍微放大`Sprite`并改变 alpha 属性以表示已激活某些功能。此时，我们通过`Timer`开始测量长按：

    ```kt
    protected function touchBegin(e:TouchEvent):void {
    box.scaleX += 0.1;
    box.scaleY += 0.1;
    box.alpha = 0.8;
    lpTimer.start();
    }

    ```

1.  `Timer`被设置为在 1000 毫秒后完成一次触发。在这个触发点上，我们可以在应用程序内执行必要的操作。在这个例子中，我们使我们的`Sprite`可以被拖拽：

    ```kt
    protected function timerEnd(e:TimerEvent):void {
    var dragBounds:Rectangle = new Rectangle(box.width/2, box.height/2, stage.stageWidth-box.width, stage.stageHeight-box.height);
    box.startDrag(true, dragBounds);
    }

    ```

1.  触摸结束时应该停止我们的`Timer`并取消与我们的`Sprite`发生的任何拖拽事件。在这里，我们将`Sprite`的`scale`和`alpha`恢复到静止状态：

    ```kt
    protected function touchEnd(e:TouchEvent):void {
    lpTimer.stop();
    box.stopDrag();
    box.scaleX = 1;
    box.scaleY = 1;
    box.alpha = 1;
    }

    ```

1.  结果手势将以以下方式影响我们的视觉对象：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_02_10.jpg)

### 注意

插图由 Gestureworks 提供（www.gestureworks.com）。

## 工作原理...

我们的示例需要按住一秒钟来触发函数调用，这导致一个`Shape`对象可以在`Stage`上拖动。这是通过监听`TOUCH_BEGIN`事件，然后监控`Timer`来判断这是否是有意的长按交互来实现的。如果一秒钟内没有`TOUCH_END`事件，那么我们就让`Shape`可拖动。一旦触发`Timer`，我们就修改了`Shape`的缩放和透明度，以表示它现在是一个可拖动的对象。释放`Shape`将完成这个交互。

## 还有更多...

长按功能最常见的用途是重新定位某些视觉元素，正如我们在这里所做的那样，或者唤起菜单操作，因为安卓用户非常习惯于在设备上使用这种类型的交互。

# 程序化唤起虚拟键盘

在大多数情况下，只需将焦点放在文本输入字段上就会唤起虚拟键盘。失去焦点将关闭虚拟键盘。也许我们需要应用程序在没有用户交互的情况下这样做，或者在某些应用状态进入时立即这样做以方便用户。

## 如何操作...

我们配置了一个`Shape`，通过分配给它的`Tap`触摸事件来切换安卓虚拟键盘的开启和关闭。

1.  首先，将以下类导入到您的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.Stage;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.SoftKeyboardEvent;
    import flash.events.TouchEvent;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;

    ```

1.  声明一个`Shape`以及一个`TextField`和`TextFormat`对象。这些将用于交互和视觉反馈。

    ```kt
    private var tapBox:Sprite;
    private var tapBoxField:TextField;
    private var tapBoxFormat:TextFormat;

    ```

1.  接下来，构建一个方法来处理我们`Sprite`的创建并将其添加到`DisplayList`中。点击这个`Sprite`将允许我们唤起或隐藏虚拟键盘。我们还将构建一个`TextField`和相关的`TextFormat`对象在`Sprite`内，以允许我们向用户提供有状态的消息。

    ```kt
    protected function setupBox():void {
    tapBox = new Sprite();
    tapBox.graphics.beginFill(0xFFFFFF, 1);
    tapBox.x = stage.stageWidth/2;
    tapBox.y = stage.stageHeight/2 - 200;
    tapBox.graphics.drawRect(-200,-100,400,160);
    tapBox.graphics.endFill();
    tapBoxFormat = new TextFormat();
    tapBoxFormat.bold = true;
    tapBoxFormat.font = "_sans";
    tapBoxFormat.size = 42;
    tapBoxFormat.align = "center";
    tapBoxFormat.color = 0x333333;
    tapBoxField = new TextField();
    tapBoxField.defaultTextFormat = tapBoxFormat;
    tapBoxField.selectable = false;
    tapBoxField.mouseEnabled = false;
    tapBoxField.multiline = true;
    tapBoxField.wordWrap = true;
    tapBoxField.width = tapBox.width;
    tapBoxField.height = tapBox.height;
    tapBoxField.x = -200;
    tapBoxField.y = -80;
    tapBoxField.text = "Tap to Toggle Virtual Keyboard";
    tapBox.addChild(tapBoxField);
    addChild(tapBox);
    }

    ```

1.  通过将`Multitouch.inputMode`设置为`MultitouchInputMode.TOUCH_POINT`常量，为多点触控 API 设置特定的输入模式以支持触摸输入，并在`DisplayObject`上注册一个事件监听器，这将用于触发安卓虚拟键盘的激活和停用。在这种情况下，是一个`TouchEvent.TOUCH_TAP`事件。触摸点击相当于鼠标点击事件。我们还可以为一系列虚拟键盘事件注册多个监听器。为了让`DisplayObject`能够唤起虚拟键盘，我们需要将其`needsSoftKeyboard`属性设置为`true`。在这里注册的`SoftKeyboardEvent`监听器是可选的。

    ```kt
    protected function setupTouchEvents():void {
    Multitouch.inputMode = MultitouchInputMode.TOUCH_POINT;
    tapBox.needsSoftKeyboard = true;
    tapBox.addEventListener(TouchEvent.TOUCH_TAP, touchTap);
    tapBox.addEventListener (SoftKeyboardEvent. SOFT_KEYBOARD_ACTIVATING, vkActivating);
    tapBox.addEventListener(SoftKeyboardEvent. SOFT_KEYBOARD_ACTIVATE, vkActivate);
    tapBox.addEventListener(SoftKeyboardEvent. SOFT_KEYBOARD_DEACTIVATE, vkDeactivate);
    }

    ```

1.  为了使用前面定义的`SoftKeyboardEvent`监听器，我们必须创建各种方法，在检测到每次活动时执行。这样，我们可以在激活过程中监听、与虚拟键盘交互，甚至阻止某些事件触发，或者在检测到虚拟键盘完全完成激活或停用时进行拦截。

    ```kt
    protected function vkActivating(e:SoftKeyboardEvent):void {
    trace("Virtual Keyboard ACTIVATING");
    }
    protected function vkActivate(e:SoftKeyboardEvent):void {
    trace("Virtual Keyboard ACTIVATED");
    }
    protected function vkDeactivate(e:SoftKeyboardEvent):void {
    trace("Virtual Keyboard DEACTIVATED");
    }

    ```

1.  要调用虚拟键盘，我们只需在 `DisplayObject` 上调用 `requestSoftKeyboard()`，其 `needsSoftKeyboard` 属性已设置为 `true`。在这里，我们检查 `needsSoftKeyboard` 是否设置为 true，并据此切换此属性。

    ```kt
    protected function touchTap(e:TouchEvent):void {
    if(tapBox.needsSoftKeyboard == true){
    tapBox.requestSoftKeyboard();
    tapBoxField.text = "Virtual Keyboard is Up";
    tapBox.needsSoftKeyboard = false;
    }else{
    tapBox.needsSoftKeyboard = true;
    tapBoxField.text = "Virtual Keyboard is Down";
    }
    }

    ```

1.  要关闭虚拟键盘，用户需要点击一个 `DisplayObject`，其 `needsSoftKeyboard` 属性已设置为 `false`。

1.  结果将类似于以下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_02_11.jpg)

## 它是如何工作的...

为了通过 ActionScript 调用 Android 虚拟键盘，我们必须将交互式 `DisplayObjects.needsSoftKeyboard` 属性设置为 `true`。这将允许我们注册一个轻触监听器，并在触发轻触事件时调用 `requestSoftKeyboard()`，在屏幕上显示虚拟键盘。

点击任何 `needsSoftKeyboard` 属性设置为 `false`（默认状态）的 `DisplayObject` 将关闭虚拟键盘。在我们的前一个示例中，我们将此属性从 `true` 切换到 `false`，以便 `DisplayObject` 作为切换控件。

## 还有更多...

虽然使用 `SoftKeyboardEvent` 类通过 ActionScript 激活或关闭 Android 虚拟键盘并不是必须的，但它包含在示例类中，因为它允许我们使用一组额外的监听器函数来响应这些事件。

# 响应 Android 软键交互

AIR for Android 不包括支持调用通常出现在屏幕底部的原生操作系统选项菜单。但是，有一些方法可以模拟原生行为，我们将在本节中探讨这些方法。

在 Android 上，`back` 按钮的正常行为是通过应用程序状态向后退，直到回到主界面。再次按下 `back` 按钮将退出应用程序。默认情况下，AIR for Android 应用程序也具有这种行为。如果我们想覆盖这个默认行为，我们必须设置一个机制来拦截此交互并阻止它。

## 如何操作...

我们可以通过标准的 ActionScript 事件监听器响应软键事件。

1.  首先，将以下类导入到您的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.Stage;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.KeyboardEvent;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.ui.Keyboard;

    ```

1.  声明一个 `TextField` 和 `TextFormat` 对象，以允许在设备上显示可见输出：

    ```kt
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  然后，我们将设置我们的 `TextField`，应用 `TextFormat`，并将其添加到 `DisplayList` 中。在这里，我们创建一个方法来执行所有这些操作：

    ```kt
    protected function setupTextField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 32;
    traceFormat.align = "center";
    traceFormat.color = 0x333333;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  现在，我们需要在 `Stage` 上设置一个事件监听器来响应键盘按键：

    ```kt
    protected function registerListeners():void {
    stage.addEventListener(KeyboardEvent.KEY_DOWN, keyDown);
    }

    ```

1.  然后，我们将在 `keyDown` 方法中编写一个 switch/case 语句，以对特定的软键事件执行不同的操作。在这种情况下，我们将特定菜单项的名称输出到我们的 `TextField`：

    ```kt
    protected function keyDown(e:KeyboardEvent):void {
    var key:uint = e.keyCode;
    traceField.text = key + " pressed!\n";
    switch(key){
    case Keyboard.BACK:{
    e.preventDefault();
    traceField.appendText("Keyboard.BACK");
    break;
    }
    case Keyboard.MENU:{
    traceField.appendText("Keyboard.MENU");
    break;
    }
    case Keyboard.SEARCH:{
    traceField.appendText("Keyboard.SEARCH");
    break;
    }
    }
    }

    ```

1.  结果将类似于以下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_02_12.jpg)

## 它是如何工作的...

我们像为物理或虚拟键盘注册监听器一样，为这些 Android 设备软键注册监听器。如果使用 AIR for Android 开发 Android 应用程序，我们还可以通过`Keyboard`类访问`BACK, MENU`和`SEARCH`常量。

注册键盘`keyDown`监听器，然后通过 switch/case 语句响应特定的键值，使我们能够适当地响应用户交互。例如，如果检测到`MENU`软键的交互，我们可以显示一个选项菜单。

## 还有更多...

Android 设备上还有一个`HOME`软键。这个按键无法通过 ActionScript 捕获，因为它仅用于从任何打开的应用程序返回用户到 Android 主屏幕。

### 注意

当我们想要取消`BACK`键的默认 Android 行为时，必须使用`keyDown`事件，因为`keyUp`事件将触发得太晚，根本无法捕获。

# 响应轨迹球和 D-Pad 事件

一些 Android 设备具有我们可以利用的额外物理输入。例如，摩托罗拉 Droid 有一个滑盖键盘，包括一个方向性的 D-pad，而 HTC Nexus One 有一个内置的轨迹球控制。

## 如何操作...

我们可以通过标准的 ActionScript 事件监听器响应轨迹球和 D-pad 事件。

1.  首先，将以下类导入到您的项目中：

    ```kt
    import flash.display.Shape;
    import flash.display.Sprite;
    import flash.display.Stage;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.KeyboardEvent;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.ui.Keyboard;

    ```

1.  声明一个`Shape`以及一个`TextField`和`TextFormat`对象。这些将用于交互和视觉反馈。

    ```kt
    private var traceField:TextField;
    private var traceFormat:TextFormat;
    private var box:Shape;

    ```

1.  然后，我们将设置我们的`TextField`，应用`TextFormat`，并将其添加到`DisplayList`中。在这里，我们创建一个方法来执行所有这些操作：

    ```kt
    protected function setupTextField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 32;
    traceFormat.align = "center";
    traceFormat.color = 0x333333;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  接下来，构建一个方法来处理我们的`Shape`的创建并将其添加到`DisplayList`中。

    ```kt
    protected function setupBox():void {
    box = new Shape();
    box.graphics.beginFill(0xFFFFFF, 1);
    box.x = stage.stageWidth/2;
    box.y = stage.stageHeight/2;
    box.graphics.drawRect(-100,-100,200,200);
    box.graphics.endFill();
    addChild(box);
    }

    ```

1.  在`Stage`上设置一个事件监听器，以响应键盘按键：

    ```kt
    protected function registerListeners():void {
    stage.addEventListener(KeyboardEvent.KEY_DOWN, keyDown);
    }

    ```

1.  现在，我们只需要编写一个 switch/case 语句，以响应 D-pad/轨迹球事件执行不同的动作。在这种情况下，我们改变`Shape`的位置，并将`keyCode`输出到`TextField`：

    ```kt
    protected function keyDown(e:KeyboardEvent):void {
    var key:uint = e.keyCode;
    traceField.text = key + " pressed!";
    switch(key){
    case Keyboard.UP:{
    box.y -= 20;
    break;
    }
    case Keyboard.DOWN:{
    box.y += 20;
    break;
    }
    case Keyboard.LEFT:{
    box.x -= 20;
    break;
    }
    case Keyboard.RIGHT:{
    box.x += 20;
    break;
    }
    case Keyboard.ENTER:{
    box.x = stage.stageWidth/2;
    box.y = stage.stageHeight/2;
    break;
    }
    }
    }

    ```

1.  结果将类似于以下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_02_13.jpg)

## 工作原理...

我们像注册物理键盘上的`Keyboard.UP, Keyboard.DOWN, Keyboard.LEFT, Keyboard.RIGHT`以及`Keyboard.ENTER`键一样，为这些特殊控件注册监听器。在这个例子中，我们根据 D-pad/轨迹球被按下，在每个方向上移动目标`Shape`并重置位置。我们还将`keyCode`值输出到文本字段中。

## 还有更多...

需要注意的是，大多数 Android 设备没有这种专门的输入机制。如果我们注册了映射到这些键的事件，我们应始终提供一种替代方案。


# 第三章：空间移动：加速度计和地理定位传感器

本章节将涵盖以下内容：

+   检测 Android 设备是否支持加速度计

+   检测 Android 设备在 3D 空间中的移动

+   调整加速度计传感器更新间隔

+   通过加速度计传感器更新显示对象位置

+   根据设备倾斜在竖屏和横屏之间切换

+   检测设备是否支持地理定位传感器

+   检测用户是否禁用了地理定位传感器

+   获取设备地理定位传感器数据

+   调整地理定位传感器更新间隔

+   通过地理坐标获取地图数据

# 引言

Android 设备不仅配备了触摸面板、虚拟键盘和其他输入机制，还包括用于检测 3D 空间变化的加速度计传感器，以及细粒度（卫星）和粗粒度（三角测量）的地理定位。本章将探讨如何在基于 Flash 平台的 Android 应用中有意义地利用这些传感器。

本章中的所有内容都表示为纯 ActionScript 3 类，并不依赖于外部库或 Flex 框架。因此，我们可以将这些示例用于我们希望的任何 IDE 中。

# 检测 Android 设备是否支持加速度计

在针对 Android 操作系统开发项目时，确保设备支持某些传感器（如加速度计）总是一个好主意。在 Android 手机的情况下，这可能总是如此，但我们绝不能假设任何设备的功能。

## 如何实现...

我们需要使用加速度计 API 类来检测是否支持加速度计：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.StageScaleMode;
    import flash.display.StageAlign;
    import flash.display.Stage;
    import flash.display.Sprite;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.sensors.Accelerometer;

    ```

1.  声明一个`TextField`和`TextFormat`对象对，以允许在设备上输出可见内容：

    ```kt
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  我们现在将设置我们的`TextField`，应用`TextFormat`，并将其添加到`DisplayList`中。这里，我们创建一个方法来执行所有这些操作：

    ```kt
    protected function setupTextField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 44;
    traceFormat.align = "center";
    traceFormat.color = 0x333333;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  然后，只需调用`Accelerometer.isSupported`来确认对此功能的支持：

    ```kt
    protected function checkAccelerometer():void {
    traceField.appendText("Accelerometer: " + Accelerometer.isSupported + "\n");
    }

    ```

1.  此调用将返回一个布尔值`true`或`false`，表示设备对此传感器的支持情况：![如何实现...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_03_05.jpg)

## 工作原理...

检测设备是否包含加速度计传感器将决定用户是否能有效利用依赖于此类数据的应用程序。如果我们的查询返回为 false，那么我们有责任通知用户或提供某种替代方式，以从设备收集加速度数据作为互动形式。

# 检测 Android 设备在 3D 空间中的移动

`Accelerometer`类与设备的动作传感器协同工作，在设备在 3D 空间移动时测量并报告运动和加速度坐标。为了测量这些数据并对这些测量做出反应，我们必须执行某些操作，以便在我们的应用程序中收集加速度数据。

## 如何操作...

我们需要使用某些 ActionScript 类，以便监控加速度传感器的反馈：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.Stage;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.AccelerometerEvent;
    import flash.sensors.Accelerometer;
    import flash.text.TextField;
    import flash.text.TextFormat;

    ```

1.  声明一个`TextField`和一个`TextFormat`对象对，以便在设备上输出可见内容，以及一个`Accelerometer`对象：

    ```kt
    private var traceField:TextField;
    private var traceFormat:TextFormat;
    private var accelerometer:Accelerometer;

    ```

1.  我们现在将设置我们的`TextField`，应用一个`TextFormat`，并将其添加到`DisplayList`中。在这里，我们创建一个方法来执行所有这些操作：

    ```kt
    protected function setupTextField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 44;
    traceFormat.align = "center";
    traceFormat.color = 0x333333;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  我们现在必须实例化一个`Accelerometer`对象，以便注册一个`AccelerometerEvent`监听器。在这种情况下，我们将它调用一个名为`movementDetected`的函数。我们还首先检查设备是否支持`Accelerometer API`，通过检查`Accelerometer.isSupported`属性：

    ```kt
    protected function registerListeners():void {
    if(Accelerometer.isSupported) {
    accelerometer = new Accelerometer();
    accelerometer.addEventListener(AccelerometerEvent.UPDATE, movementDetected);
    }else{
    traceField.text = "Accelerometer not supported!";
    }
    }

    ```

1.  我们现在能够通过`movementDetected`方法监控并响应设备移动：

    ```kt
    protected function movementDetected(e:AccelerometerEvent):void {
    traceField.text = "";
    traceField.appendText("Time: " + e.timestamp + "\n");
    traceField.appendText("X: " + e.accelerationX + "\n");
    traceField.appendText("Y: " + e.accelerationY + "\n");
    traceField.appendText("Z: " + e.accelerationZ + "\n");
    }

    ```

1.  输出将类似于这样：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_03_06.jpg)

## 它的工作原理...

通过注册一个事件监听器到`AccelerometerEvent.UPDATE`，我们能够检测到 Android 设备上的动作传感器报告的变化。有四个属性通过此事件报告回来：`accelerationX, accelerationY, accelerationZ`和`timestamp`。

+   `accelerationX:` 一个`Number`类型的值，它测量沿着 x 轴的加速度，当设备直立放置时，x 轴从左到右。当设备向右移动时，表示为正加速度。向左移动则表示为负数。

+   `accelerationY:` 一个`Number`类型的值，它测量沿着 y 轴的加速度，当设备直立放置时，y 轴从下到上。当设备向上移动时，表示为正加速度。向下移动则表示为负数。

+   `accelerationZ:` 一个`Number`类型的值，它测量沿着 z 轴的加速度，z 轴垂直于设备表面。当设备移动使得表面朝向天空时，表示为正加速度。将表面定位在地面上方角度时，将表示为负数。

+   `timestamp:` 一个`int`类型的值，它测量自应用程序初始化以来经过的毫秒数。这可以用来随时间跟踪更新事件。

## 还有更多...

加速度传感器在创建基于平衡的 Android 游戏时经常被使用，例如让一个球基于设备倾斜通过迷宫，但我们也可以以任何我们想要的方式来使用这些数据，以监测空间、倾斜或基于其他动作的变化。

# 调整加速度传感器更新间隔

虽然大多数应用程序可能默认的加速度计传感器更新间隔就足够了，但如果我们要针对特定目的加快或减慢这个间隔该怎么办？

## 如何操作...

我们需要使用`Accelerometer`类中包含的方法来更改加速度计传感器更新间隔：

1.  首先，将以下类导入到您的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.Stage;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.AccelerometerEvent;
    import flash.events.TouchEvent;
    import flash.sensors.Accelerometer;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;

    ```

1.  我们现在将声明一些要在示例中使用的对象。首先，一个`TextField`和一个`TextFormat`对象对，以便在设备上允许可见输出，以及一个`Accelerometer`对象。

1.  然后，我们还需要使用一个`Number`来跟踪我们的间隔量。

1.  还需要两个`Sprite`对象供用户与之交互。

    ```kt
    private var traceField:TextField;
    private var traceFormat:TextFormat;
    private var accelerometer:Accelerometer;
    private var accelerometerInterval:Number;
    private var boxUp:Sprite;
    private var boxDown:Sprite;

    ```

1.  我们现在将设置`TextField`，应用`TextFormat`，并将其添加到`DisplayList`中。这里，我们创建一个方法来执行所有这些操作：

    ```kt
    protected function setupTextField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 44;
    traceFormat.align = "center";
    traceFormat.color = 0xFFFFFF;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  为了通过触摸检测用户输入，我们将创建两个`Sprite`实例并将每个实例添加到`Stage`中。为了在我们与这些对象注册的任何事件监听器中区分`Sprite`实例，我们将为每个`Sprite`提供一个唯一的`name`属性：

    ```kt
    protected function setupBoxes():void {
    boxUp = new Sprite();
    boxUp.name = "boxUp";
    boxUp.graphics.beginFill(0xFFFFFF, 1);
    boxUp.x = 20;
    boxUp.y = stage.stageHeight/2;
    boxUp.graphics.drawRect(0,0,100,80);
    boxUp.graphics.endFill();
    addChild(boxUp);
    boxDown = new Sprite();
    boxDown.name = "boxDown";
    boxDown.graphics.beginFill(0xFFFFFF, 1);
    boxDown.x = stage.stageWidth - 120;
    boxDown.y = stage.stageHeight/2;
    boxDown.graphics.drawRect(0,0,100,80);
    boxDown.graphics.endFill();
    addChild(boxDown);
    }

    ```

1.  首先，我们还要检查设备是否实际支持加速度计 API，通过检查`Accelerometer.isSupported`属性。

1.  然后，我们需要将多点触控 API 的特定输入模式设置为通过将`Multitouch.inputMode`设置为`MultitouchInputMode.TOUCH_POINT`常量来支持触摸输入。

1.  每个 Sprite 将注册一个`TouchEvent.TOUCH_TAP`监听器，这样它就能够通过触摸轻敲来调用一个方法来改变更新间隔。

1.  现在，我们可以实例化一个`Accelerometer`对象并调用`setRequestedUpdateInterval`方法，此方法调用需要传入以毫秒为单位的间隔。

1.  我们还将注册一个事件监听器以响应任何设备移动：

    ```kt
    protected function registerListeners():void {
    if(Accelerometer.isSupported) {
    Multitouch.inputMode = MultitouchInputMode.TOUCH_POINT;
    boxUp.addEventListener(TouchEvent.TOUCH_TAP, shiftInterval);
    boxDown.addEventListener(TouchEvent.TOUCH_TAP, shiftInterval);
    accelerometer = new Accelerometer();
    accelerometerInterval = 100;
    accelerometer.setRequestedUpdateInterval (accelerometerInterval);
    accelerometer.addEventListener(AccelerometerEvent.UPDATE, movementDetected);
    }else{
    traceField.text = "Accelerometer not supported!";
    }
    }

    ```

1.  我们的`shiftInterval`方法现在将响应我们创建的两个`Sprite`框拦截的任何触摸轻敲。我们将检查每个`Sprite`被赋予的`name`属性，并相应地调整`accelerometerInterval`：

    ```kt
    protected function shiftInterval(e:TouchEvent):void {
    switch(e.target.name){
    case "boxUp":{
    accelerometerInterval += 100;
    break;
    }
    case "boxDown":{
    accelerometerInterval -= 100;
    break;
    }
    }
    if(accelerometerInterval < 0){
    accelerometerInterval = 0;
    }
    accelerometer.setRequestedUpdateInterval(accelerometerInterval);
    }

    ```

1.  加速度计传感器更新间隔现在将调用以下函数，该函数将通过我们的`TextField`输出检测到的移动和间隔数据：

    ```kt
    protected function movementDetected(e:AccelerometerEvent):void {
    traceField.text = "Interval: " + accelerometerInterval + "\n\n";
    traceField.appendText("Time: " + e.timestamp + "\n");
    traceField.appendText("X: " + e.accelerationX + "\n");
    traceField.appendText("Y: " + e.accelerationY + "\n");
    traceField.appendText("Z: " + e.accelerationZ + "\n");
    }

    ```

1.  结果将类似于以下内容：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_03_07.jpg)

## 工作原理...

通过`setRequestedUpdateInterval()`设置加速度计更新间隔，我们能够根据特定应用程序中的情况调整此间隔。在前面演示类中，我们渲染了两个作为增加和减少`TouchEvent.TOUCH_TAP`事件受体的`Sprites`。轻敲这些`DisplayObjects`将会增加或减少加速度计更新间隔，这个间隔通过屏幕上的`TextField`进行监控。

## 还有更多内容...

请注意，默认的加速度传感器更新间隔取决于运行我们应用程序的设备。这种策略也可以用来尝试平衡不同设备间的间隔。

# 通过加速度事件更新显示对象位置

创建 Android 设备上的各种游戏或应用程序时可以使用加速度传感器。这种数据更频繁的用途之一是响应加速度更新事件数据，更新 `Stage` 上 `DisplayObject` 的位置。

## 如何操作...

我们需要使用某些 ActionScript 类，以便通过 `DisplayObject` 实例监听加速度反馈。在这个例子中，我们将使用一个简单的 `Shape` 对象，根据这些数据改变其位置：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.Shape;
    import flash.display.Sprite;
    import flash.display.Stage;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.AccelerometerEvent;
    import flash.sensors.Accelerometer;
    import flash.text.TextField;
    import flash.text.TextFormat;

    ```

1.  我们现在将声明一些要在示例中使用的对象。首先，一个 `TextField` 和 `TextFormat` 对象对，以及一个 `Shape` 以便在设备上显示输出。

1.  我们还必须声明一个 `Accelerometer` 对象，以便监听和响应设备移动：

    ```kt
    private var traceField:TextField;
    private var traceFormat:TextFormat;
    private var box:Shape;
    private var accelerometer:Accelerometer;

    ```

1.  我们现在将设置 `TextField`，应用 `TextFormat`，并将其添加到 `DisplayList` 中。这里，我们创建一个方法来执行所有这些操作：

    ```kt
    protected function setupTextField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 44;
    traceFormat.align = "center";
    traceFormat.color = 0xFFFFFF;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  创建一个名为 `box` 的新 `Shape` 对象，使用 `Graphics` API 绘制一个矩形，并将其添加到 `Stage` 上：

    ```kt
    protected function setupBox():void {
    box = new Shape();
    box.graphics.beginFill(0xFFFFFF, 1);
    box.x = stage.stageWidth/2;
    box.y = stage.stageHeight/2;
    box.graphics.drawRect(-100,-100,200,200);
    box.graphics.endFill();
    addChild(box);
    }

    ```

1.  我们现在必须实例化一个 `Accelerometer` 对象，以便注册一个 `AccelerometerEvent` 监听器。在这种情况下，我们将让它调用一个名为 `movementDetected` 的函数。我们还要首先检查设备是否支持 Accelerometer API，通过检查 `Accelerometer.isSupported` 属性：

    ```kt
    protected function registerListeners():void {
    if(Accelerometer.isSupported) {
    accelerometer = new Accelerometer();
    accelerometer.addEventListener(AccelerometerEvent.UPDATE, movementDetected);
    }else{
    traceField.text = "Accelerometer not supported!";
    }
    }

    ```

1.  现在，我们可以通过调整 `Shape` 对象的 x 和 y 坐标，通过 `movementDetected` 方法监听和响应设备移动，基于 `AccelerometerEvent.UPDATE` 事件报告的 `accelerationX` 和 `accelerationY` 数据。

1.  在以下函数中，我们将执行一系列检查，以确保当设备倾斜时 `Shape` 不会移出 `Stage`。我们还将输出 `Sprite` 的 x 和 y 属性到一个 `TextField`

    ```kt
    protected function movementDetected(e:AccelerometerEvent):void {
    traceField.text = "";
    var speed:Number = 20;
    if(box.x > box.width/2){
    box.x -= Math.floor(e.accelerationX*speed);
    }else{
    box.x = box.width/2;
    }
    if(box.x < stage.stageWidth-(box.width/2)){
    box.x -= Math.floor(e.accelerationX*speed);
    }else{
    box.x = stage.stageWidth-(box.width/2);
    }
    if(box.y > box.height/2){
    box.y += Math.floor(e.accelerationY*speed);
    }else{
    box.y = box.height/2;
    }
    if(box.y < stage.stageHeight-(box.height/2)){
    box.y += Math.floor(e.accelerationY*speed);
    }else{
    box.y = stage.stageHeight-(box.height/2);
    }
    traceField.appendText("box.x: " + box.x + "\n");
    traceField.appendText("box.y: " + box.y + "\n");
    }

    ```

1.  结果输出将类似于以下内容：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_03_08.jpg)

## 工作原理...

通过注册 `AccelerometerEvent.UPDATE` 事件监听器，我们可以检测到 Android 设备上运动传感器报告的变化。使用 ActionScript，我们可以对这些运动和倾斜的变化做出响应，如代码示例所示，根据报告的传感器数据在屏幕上移动 `DisplayObject`。

在示例中，我们不仅在屏幕上移动 `Shape` 对象，同时通过多个条件语句考虑对象的宽度、高度和检测到的屏幕尺寸，确保形状不会离开屏幕。

# 根据设备倾斜切换横屏和竖屏

大多数 Android 设备允许用户以纵向和横向视图交互。当设备以 y 轴从上到下对齐时，启用纵向模式；而通过将设备持握以 y 轴从左到右测量时，启用横向模式。通过使用加速度计传感器报告的数据，我们可以知道这些移动何时发生并在我们的应用程序内响应该移动。

## 如何操作...

我们需要使用`Accelerometer` API 来检测设备旋转和倾斜：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.Stage;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.AccelerometerEvent;
    import flash.sensors.Accelerometer;
    import flash.text.TextField;
    import flash.text.TextFormat;

    ```

1.  我们现在将声明一些在示例中要使用的对象。首先，一个`TextField`和`TextFormat`对象对，以允许在设备上输出可见内容。

1.  我们还必须声明一个`Accelerometer`对象，以便监控并响应用户设备的移动：

    ```kt
    private var traceField:TextField;
    private var traceFormat:TextFormat;
    private var accelerometer:Accelerometer;

    ```

1.  现在，我们将设置我们的`TextField`，应用一个`TextFormat`，并将其添加到`DisplayList`中。这里，我们创建一个方法来执行所有这些操作：

    ```kt
    protected function setupTextField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 44;
    traceFormat.align = "center";
    traceFormat.color = 0xFFFFFF;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  然后，我们必须创建一个`Accelerometer`实例，并为其分配一个类型为`AccelerometerEvent.UPDATE`的事件监听器。每当检测到加速度计数据发生变化时，这将触发`movementDetected`方法。我们还首先检查设备是否实际支持加速度计 API，通过检查`Accelerometer.isSupported`属性：

    ```kt
    protected function registerListeners():void {
    if(Accelerometer.isSupported) {
    accelerometer = new Accelerometer();
    accelerometer.addEventListener(AccelerometerEvent.UPDATE, movementDetected);
    }else{
    traceField.text = "Accelerometer not supported!";
    }
    }

    ```

1.  在我们的`movementDetected`方法中，我们只需监控传感器报告的加速度数据，并相应地调整我们的应用程序。我们还将输出数据到我们的`TextField`以监控设备移动：

    ```kt
    protected function movementDetected(e:AccelerometerEvent):void {
    traceField.text = "";
    traceField.appendText("Time: " + e.timestamp + "\n");
    traceField.appendText("X: " + e.accelerationX + "\n");
    traceField.appendText("Y: " + e.accelerationY + "\n");
    traceField.appendText("Z: " + e.accelerationZ + "\n");
    if(e.accelerationY > 0.5){
    traceField.appendText("\n\n\nPORTRAIT");
    }else{
    traceField.appendText("\n\n\nLANDSCAPE");
    }
    }

    ```

1.  结果将类似于以下这样：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_03_09.jpg)

## 工作原理...

当我们的应用程序检测到加速度移动时，`movementDetected`方法将报告有关设备`x, y`和`z`轴的数据。如果我们监控所报告的加速度值，我们可以以考虑垂直方向的方式响应用户设备的倾斜，从而知道是否需要调整`Stage`上的元素以适应纵向或横向观看。

## 还有更多内容...

在这个示例中，我们使用纯 ActionScript 来检测加速度计传感器数据并响应该数据。在开发应用程序时使用移动 Flex 框架，通过在**Flex Mobile Project**设置中选择**Mobile Settings**对话框中的**Automatically reorient**（自动重新定向）选项，我们可以让框架处理设备方向。

![还有更多...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_03_01.jpg)

## 另请参阅...

第六章，*结构适应性：处理设备布局和缩放*，也包含有关使用其他检测方法适应设备方向变化的信息。

# 检测设备是否支持地理定位传感器

在针对 Android 操作系统开发项目时，确保某些传感器（如地理定位传感器）实际上在设备上得到支持总是一个好主意。在 Android 设备的情况下，这可能总是如此，但我们绝不应假设任何设备的功能。

## 如何操作...

我们需要使用内部类来检测地理定位 API 是否得到支持：

1.  首先，将以下类导入到您的项目中：

    ```kt
    import flash.display.StageScaleMode;
    import flash.display.StageAlign;
    import flash.display.Stage;
    import flash.display.Sprite;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.sensors.Geolocation;

    ```

1.  声明一个`TextField`和`TextFormat`对象对，以允许在设备上可见输出：

    ```kt
    private var traceField:TextField;
    private var traceFormat:TextFormat;

    ```

1.  我们现在将设置我们的`TextField`，应用一个`TextFormat`，并将`TextField`添加到`DisplayList`中。在这里，我们创建一个方法来执行所有这些操作：

    ```kt
    protected function setupTextField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 44;
    traceFormat.align = "center";
    traceFormat.color = 0x333333;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  然后，只需调用`Geolocation.isSupported`以确认对此功能的的支持：

    ```kt
    protected function checkGeolocation():void {
    traceField.appendText("Geolocation: " + Geolocation.isSupported);
    }

    ```

1.  此调用将返回一个布尔值`true`或`false`，表示设备是否支持此传感器。此结果将输出到我们创建的`TextField`中：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_03_10.jpg)

## 工作原理...

检测设备是否包含地理定位传感器将决定用户是否可以有效利用依赖于此类数据的应用程序。如果我们的查询返回为 false，那么由我们来通知用户或提供某种替代方式来收集此类数据。这通常由用户手动输入特定位置数据来处理。

## 另请参阅…

应用开发者必须通过一个 Android 清单文件请求地理定位传感器的可用性。为了让我们的应用程序使用这些传感器，必须在清单文件中声明权限。更多信息请参见第九章，*清单保证：安全与 Android 权限*。

检测用户是否已禁用地理定位传感器

有许多原因可能导致 Android 地理定位传感器在我们的应用程序中不可用。用户可能为了节省电池寿命而关闭了此传感器，或者也许是我们作为开发者没有通过 Android 清单文件提供足够的权限以允许地理定位访问。无论如何，检查并如果传感器被禁用，以友好的提示回应是一个好主意。

## 如何操作...

我们需要检查`Geolocation`类中包含的`muted`属性：

1.  首先，将以下类导入到您的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.Stage;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.StatusEvent;
    import flash.sensors.Geolocation;
    import flash.text.TextField;
    import flash.text.TextFormat;

    ```

1.  声明一个`TextField`和`TextFormat`对象对，以允许在设备上可见输出以及一个`Geolocation`对象：

    ```kt
    private var traceField:TextField;
    private var traceFormat:TextFormat;
    private var geo:Geolocation;

    ```

1.  我们现在将设置我们的`TextField`，应用一个`TextFormat`，并将`TextField`添加到`DisplayList`中。在这里，我们创建一个方法来执行所有这些操作：

    ```kt
    protected function setupTextField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 44;
    traceFormat.align = "center";
    traceFormat.color = 0x333333;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  现在，我们必须实例化一个`Geolocation`实例，并注册一个事件监听器，以确定在应用程序运行期间地理定位是否被禁用。

    ### 注意

    现在我们已经定义了一个`Geolocation`实例，我们也可以随时简单地检查`muted`属性。

    ```kt
    protected function registerListeners():void {
    geo = new Geolocation();
    geo.addEventListener(StatusEvent.STATUS, checkGeolocationMuted);
    traceField.appendText("Geolocation Disabled? \n\n" + geo.muted);
    }

    ```

1.  一旦我们调用了这个方法，检查 muted 属性。如果这返回`true`，我们可以访问设备地理位置传感器；如果返回`false`，那么我们知道传感器已被禁用：

    ```kt
    protected function checkGeolocationMuted(e:StatusEvent):void {
    traceField.appendText("Geolocation Disabled? \n\n" + geo.muted);
    }

    ```

1.  结果将显示在设备屏幕上，如下截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_03_11.jpg)

# 工作原理...

一旦我们构建了一个`Geolocation`实例，我们就可以访问该类的`muted`属性。通过检查`Geolocation`对象的`muted`属性，我们可以在应用程序中禁用地理位置功能，提示用户手动输入他们的位置，或者简单地通知用户必须启用设备上的地理位置传感器才能继续。

# 还有更多...

如我们的示例所示，`Geolocation`对象可以注册一个`status`事件，当`muted`属性发生变化时会提醒我们。我们可以使用它在应用程序运行时检测属性变化并相应地作出响应。

# 另请参阅…

应用程序开发者必须通过 Android 清单文件请求地理位置传感器的可用性。为了让我们的应用程序使用这些传感器，必须在清单文件中声明权限。更多信息请参见第九章。

# 获取设备地理位置传感器数据

`Geolocation`类可以用来揭示一组完整的属性，用于在全球范围内跟踪设备位置。这对于地图、天气、旅行和其他位置感知应用程序很有用。为了测量这些数据并对这些测量做出反应，我们必须执行某些操作。

## 如何操作...

我们需要使用某些 ActionScript 类来允许监控地理位置反馈：

1.  首先，将以下类导入到您的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.Stage;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.GeolocationEvent;
    import flash.sensors.Geolocation;
    import flash.text.TextField;
    import flash.text.TextFormat;

    ```

1.  声明一个`TextField`和`TextFormat`对象对，允许设备上可见输出，以及一个`Geolocation`对象：

    ```kt
    private var traceField:TextField;
    private var traceFormat:TextFormat;
    private var geolocation:Geolocation;

    ```

1.  我们现在将设置我们的`TextField`，应用`TextFormat`，并将`TextField`添加到`DisplayList`中。这里，我们创建一个方法来执行所有这些操作：

    ```kt
    protected function setupTextField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 44;
    traceFormat.align = "center";
    traceFormat.color = 0x333333;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  我们现在必须实例化一个`Geolocation`对象，以注册一个`GeolocationEvent`监听器。在这种情况下，我们将调用一个名为`geolocationUpdate`的函数。我们还首先检查设备上是否实际支持 Geolocation API，通过检查`Geolocation.isSupported`属性：

    ```kt
    protected function registerListeners():void {
    if(Geolocation.isSupported) {
    geolocation = new Geolocation();
    geolocation.addEventListener(GeolocationEvent.UPDATE, geolocationUpdate);
    }else{
    traceField.text = "Geolocation not supported!";
    }
    }

    ```

1.  我们现在能够通过`geolocationUpdate`方法监控并响应用户移动设备。在这种情况下，我们将收集到的数据输出到一个`TextField`：

    ```kt
    protected function geolocationUpdate(e:GeolocationEvent):void {
    traceField.text = "";
    traceField.appendText("altitude: " + e.altitude + "\n");
    traceField.appendText("heading: " + e.heading + "\n");
    traceField.appendText("horizontal accuracy: " + e.horizontalAccuracy + "\n");
    traceField.appendText("latitude: " + e.latitude + "\n");
    traceField.appendText("longitude: " + e.longitude + "\n");
    traceField.appendText("speed: " + e.speed + "\n");
    traceField.appendText("timestamp: " + e.timestamp + "\n");
    traceField.appendText("vertical accuracy: " + e.verticalAccuracy);
    }

    ```

1.  输出将如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_03_12.jpg)

## 工作原理...

通过注册一个事件监听器到`GeolocationEvent.UPDATE`，我们能够检测到 Android 设备上报的地理传感器变化。请注意，并不是每个 Android 设备都能报告所有这些属性；这将取决于所使用的设备。通过这个事件报告回的共有八个可能的属性：`altitude, heading, horizontalAccuracy, latitude, longitude, speed, timestamp`和`verticalAccuracy`。

+   `altitude:` 一个`Number`类型的值，表示当前的海拔高度，以米为单位。

+   `heading:` 一个`Number`类型的值，表示移动的方向，以度为单位。

+   `horizontalAccuracy:` 一个`Number`类型的值，表示传感器测量的水平精度，以米为单位。

+   `latitude:` 一个`Number`类型的值，表示当前设备的纬度，以度为单位。

+   `longitude:` 一个`Number`类型的值，表示当前设备的经度，以度为单位。

+   `speed:` 一个`Number`类型的值，表示每秒的速度，以米为单位。

+   `timestamp:` 一个`int`类型的值，表示自应用程序初始化以来的毫秒数。

+   `verticalAccuracy:` 一个`Number`类型的值，表示传感器测量的垂直精度，以米为单位。

# 调整地理传感器更新间隔

尽管大多数应用程序可能默认的地理传感器更新间隔就足够了，但如果我们想为特定目的加快或减慢这个间隔呢？

## 如何操作...

我们需要使用`Geolocation`类中包含的方法来更改地理传感器更新间隔：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.Stage;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.GeolocationEvent;
    import flash.events.TouchEvent;
    import flash.sensors.Geolocation;
    import flash.text.TextField;
    import flash.text.TextFormat;
    import flash.ui.Multitouch;
    import flash.ui.MultitouchInputMode;

    ```

1.  我们现在将声明一些在示例中要使用的对象。首先是一个`TextField`和一个`TextFormat`对象，以便在设备上允许可见输出，以及一个`Geolocation`对象。

1.  然后，我们还需要使用一个`Number`来跟踪我们的间隔量。还需要两个`Sprite`对象供用户交互。

    ```kt
    private var traceField:TextField;
    private var traceFormat:TextFormat;
    private var geolocation:Geolocation;
    private var geolocationInterval:Number;
    private var boxUp:Sprite;
    private var boxDown:Sprite;

    ```

1.  我们现在将设置我们的`TextField`，应用一个`TextFormat`，并将`TextField`添加到`DisplayList`中。这里，我们创建一个方法来执行所有这些操作：

    ```kt
    protected function setupTextField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 44;
    traceFormat.align = "center";
    traceFormat.color = 0x333333;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  为了检测用户的触摸输入，我们将创建两个`Sprite`实例并将它们各自添加到`Stage`中。为了在注册这些对象的事件监听器中区分`Sprite`实例，我们将为每个`Sprite`提供一个唯一的名称属性：

    ```kt
    protected function setupBoxes():void {
    boxUp = new Sprite();
    boxUp.name = "boxUp";
    boxUp.graphics.beginFill(0xFFFFFF, 0.6);
    boxUp.x = 20;
    boxUp.y = stage.stageHeight/2;
    boxUp.graphics.drawRect(0,0,100,80);
    boxUp.graphics.endFill();
    addChild(boxUp);
    boxDown = new Sprite();
    boxDown.name = "boxDown";
    boxDown.graphics.beginFill(0xFFFFFF, 0.6);
    boxDown.x = stage.stageWidth - 120;
    boxDown.y = stage.stageHeight/2;
    boxDown.graphics.drawRect(0,0,100,80);
    boxDown.graphics.endFill();
    addChild(boxDown);
    }

    ```

1.  我们首先检查设备是否实际支持 Geolocation API，通过检查`Geolocation.isSupported`属性。

1.  我们还需要将多点触控 APIs 的特定输入模式设置为支持触摸输入，通过将`Multitouch.inputMode`设置为`MultitouchInputMode.TOUCH_POINT`常量。每个`Sprite`将注册一个`TouchEvent.TOUCH_TAP`监听器，这样它就能够通过触摸点击来调用一个方法，以改变更新间隔。

1.  现在，我们还可以实例化一个`Geolocation`对象并调用`setRequestedUpdateInterval`方法，该方法需要传递一个以毫秒为单位的间隔到方法调用中。

1.  我们将注册一个事件监听器以响应任何设备移动：

    ```kt
    protected function registerListeners():void {
    if(Geolocation.isSupported) {
    Multitouch.inputMode = MultitouchInputMode.TOUCH_POINT;
    boxUp.addEventListener(TouchEvent.TOUCH_TAP, shiftInterval);
    boxDown.addEventListener(TouchEvent.TOUCH_TAP, shiftInterval);
    geolocation = new Geolocation();
    geolocationInterval = 100;
    geolocation.setRequestedUpdateInterval(geolocationInterval);
    geolocation.addEventListener(GeolocationEvent.UPDATE, geolocationUpdate);
    }else{
    traceField.text = "Geolocation not supported!";
    }
    }

    ```

1.  我们的`shiftInterval`方法现在将响应我们创建的两个`Sprite`框拦截的任何触摸点击。我们将检查每个`Sprite`被赋予了什么名称属性，并相应地调整`accelerometerInterval`：

    ```kt
    protected function shiftInterval(e:TouchEvent):void {
    switch(e.target.name){
    case "boxUp":{
    geolocationInterval += 100;
    break;
    }
    case "boxDown":{
    geolocationInterval -= 100;
    break;
    }
    }
    if(geolocationInterval < 0){
    geolocationInterval = 0;
    }
    geolocation.setRequestedUpdateInterval(geolocationInterval);
    }

    ```

1.  现在地理传感器更新间隔将会调用以下函数，该函数将通过我们的`TextField`输出检测到的移动和间隔数据：

    ```kt
    protected function geolocationUpdate(e:GeolocationEvent):void {
    traceField.text = "Interval: " + geolocationInterval + "\n\n";
    traceField.appendText("altitude: " + e.altitude + "\n");
    traceField.appendText("heading: " + e.heading + "\n");
    traceField.appendText("horizontal accuracy: " + e.horizontalAccuracy + "\n");
    traceField.appendText("latitude: " + e.latitude + "\n");
    traceField.appendText("longitude: " + e.longitude + "\n");
    traceField.appendText("speed: " + e.speed + "\n");
    traceField.appendText("timestamp: " + e.timestamp + "\n");
    traceField.appendText("vertical accuracy: " + e.verticalAccuracy);
    }

    ```

1.  结果将类似于以下截图：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_03_13.jpg)

## 工作原理...

通过`setRequestedUpdateInterval()`设置地理定位更新间隔，我们能够根据特定应用程序中的情况调整此间隔。在前一节的`demonstration`类中，我们渲染了两个作为增加和减少`TouchEvent.TOUCH_TAP`事件受体的`Sprites`。点击这些`DisplayObjects`将会增加或减少地理定位更新间隔，这通过屏幕上的`TextField`进行监控。

## 还有更多...

请注意，默认的地理定位传感器更新间隔取决于运行我们应用程序的设备。这种策略也可以用来尝试平衡不同设备之间的间隔。然而，有些事情完全在我们的控制之外。例如，如果用户深处建筑物内并且 GPS 信号差，更新间隔实际上可能超过一分钟。应考虑此类各种因素。

# 通过地理坐标获取地图数据

使用地理坐标获取地图是 ActionScript 地理定位 API 的基本用途之一。在本教程中，我们将研究如何使用 Google 地图 API for Flash 在舞台上渲染地图，并基于设备地理传感器报告的纬度和经度坐标生成标记。

## 准备中...

在开始本教程之前，我们需要采取几个步骤。这些步骤将准备我们的项目与适当的代码库，并允许我们访问 Google 地图服务：

1.  首先，我们必须从[`code.google.com/apis/maps/documentation/flash/`](http://code.google.com/apis/maps/documentation/flash/)下载 Google 地图 API for Flash。

1.  该软件包将包括两个独立的`.swc`文件。一个用于 Flex，另一个用于 ActionScript 项目。在此示例中，我们将提取纯`AS3 .swc`到本地硬盘。

1.  从同一个 URL（在第一点）点击阅读**注册 Google 地图 API 密钥**的链接以生成 API 密钥并注册一个 URL。完成此示例你需要这两样东西。![准备中...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_03_02.jpg)

1.  现在，通过在 Flash Builder 中通过**ActionScript Build Path**属性对话框添加`.swc`（你也可以直接将`.swc`拖到`libs`目录中），或者在 Flash Professional 中通过**Advanced ActionScript Properties**对话框，将 Google Maps SDK 包含到你的开发环境中：![准备就绪...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_03_03.jpg)

1.  现在我们准备进行食谱操作。

## 如何操作...

我们需要创建我们的地图`DisplayObject`，为`Geolocation` API 更新生成事件监听器，并根据我们当前的位置调整地图属性：

1.  首先，将以下类导入到你的项目中：

    ```kt
    import flash.display.Sprite;
    import flash.display.Stage;
    import flash.display.StageAlign;
    import flash.display.StageScaleMode;
    import flash.events.GeolocationEvent;
    import flash.geom.Point;
    import flash.sensors.Geolocation;
    import flash.text.TextField;
    import flash.text.TextFormat;

    ```

1.  接下来，我们希望导入 Google Maps SDK 中包含的许多类。这些类允许我们在`Stage`上渲染`Map`，监听特定于地图的事件，并在我们当前的位置渲染`Marker`：

    ```kt
    import com.google.maps.LatLng;
    import com.google.maps.Map;
    import com.google.maps.MapEvent;
    import com.google.maps.MapType;
    import com.google.maps.overlays.Marker;

    ```

1.  我们现在将创建一些在本示例中要使用的对象引用。首先，一个`TextField`和`TextFormat`对象对，以便在设备上允许可见输出，以及一个`Geolocation`对象。

1.  然后，我们还需要使用`Map`和`LatLng`对象来渲染我们位置的地图：

    ```kt
    private var traceField:TextField;
    private var traceFormat:TextFormat;
    private var geolocation:Geolocation;
    private var map:Map;
    private var coordinates:LatLng;

    ```

1.  现在我们准备通过传递我们在注册 Google 时设置好的 API 密钥和 URL 来创建我们的`Map`，并将`Map`添加到显示列表中：

    ```kt
    protected function setupMap():void {
    map = new Map();
    map.key = "{GOOGLE_MAPS_API_KEY}";
    map.url = "{APP_URL}";
    map.sensor = "true";
    map.setSize(new Point(stage.stageWidth, stage.stageHeight));
    addChild(map);
    }

    ```

1.  我们现在将设置我们的`TextField`，应用`TextFormat`，并将`TextField`添加到`DisplayList`中。在这里，我们创建一个方法来执行所有这些操作：

    ```kt
    protected function setupTextField():void {
    traceFormat = new TextFormat();
    traceFormat.bold = true;
    traceFormat.font = "_sans";
    traceFormat.size = 44;
    traceFormat.align = "center";
    traceFormat.color = 0x333333;
    traceField = new TextField();
    traceField.defaultTextFormat = traceFormat;
    traceField.selectable = false;
    traceField.mouseEnabled = false;
    traceField.width = stage.stageWidth;
    traceField.height = stage.stageHeight;
    addChild(traceField);
    }

    ```

1.  重要的是，我们需要为地理位置更新和`Map`完成事件注册监听器，这样我们才能读取坐标数据，并知道我们的`Map`何时准备好交互。我们还首先检查设备是否实际支持 Geolocation API，通过检查`Geolocation.isSupported`属性来实现：

    ```kt
    protected function registerListeners():void {
    if(Geolocation.isSupported) {
    geolocation = new Geolocation();
    geolocation.addEventListener(GeolocationEvent.UPDATE, geolocationUpdate);
    map.addEventListener(MapEvent.MAP_READY, mapReady);
    }else{
    traceField.text = "Geolocation not supported!";
    }
    }

    ```

1.  由于地理位置更新是在本地处理的，这很可能是我们的第一个事件监听器被触发。我们将通过此事件从设备地理位置传感器提供的数据中获取`longitude`（经度）和`latitude`（纬度），并由此创建一个`LatLong`对象，在初始化时将其输入到`Map`中：

    ```kt
    protected function geolocationUpdate(e:GeolocationEvent):void {
    traceField.text = "";
    traceField.appendText("latitude:\n" + e.latitude + "\n\n");
    traceField.appendText("longitude:\n" + e.longitude);
    coordinates = new LatLng(e.latitude, e.longitude);
    }

    ```

1.  一旦我们的`mapReady`监听器方法触发，我们就已经有了通过`Map`显示我们当前坐标的必要坐标信息，同时在这个精确的位置渲染一个简单的`Marker`：

    ```kt
    protected function mapReady(e:MapEvent):void {
    map.setCenter(coordinates, 16, MapType.NORMAL_MAP_TYPE);
    var marker:Marker = new Marker(map.getCenter());
    map.addOverlay(marker);
    }

    ```

1.  结果将类似于这样：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/flash-dev-andr-cb/img/1420_03_04.jpg)

## 它的工作原理...

通过接入像 Google Maps 这样的地图服务，我们可以监听本地设备地理位置更新，并将必要的数据输入到地图服务中以执行众多任务。

在这个例子中，我们只是将`Map`中心对准设备坐标，并在`Map`上放置一个`Marker`覆盖层。每次使用这类服务时，彻底阅读文档了解服务的可能性和限制总是一个好主意。

`url` 属性应设置为在线位置，其中描述了应用程序的目的和范围，根据谷歌的要求。

### 注意事项

我们将 `Map` 实例的 `sensor` 属性设置为 `true`。如果 `Map` 是基于谷歌设备地理位置传感器反应数据，这是必需的。如果我们只是允许用户输入坐标并通过这种方式调整 `Map` 的位置，我们会将 `sensor` 属性设置为 `false`。

## 还有更多...

在这个案例中，我们使用了谷歌地图 API 的 Flash 版本。它相当健壮，但您可能希望使用其他地图系统，如 Yahoo! 地图、MapQuest 或其他服务。这是没问题的，因为它们都需要类似的信息；只是具体的 API 设置会有所不同。
