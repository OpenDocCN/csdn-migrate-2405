# Corona SDK 移动游戏初学者指南（一）

> 原文：[`zh.annas-archive.org/md5/A062C0ACF1C6EB24D4DCE7039AD45F82`](https://zh.annas-archive.org/md5/A062C0ACF1C6EB24D4DCE7039AD45F82)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书旨在介绍你在 iOS 和 Android 平台使用 Corona SDK 的基本标准。通过按部就班地构建三款独特的游戏，你将增强学习体验。除了开发游戏，你还将学习社交网络集成、应用内购买，以及将应用程序发布到苹果 App Store 和/或谷歌 Play 商店。

# 本书涵盖内容

第一章，*开始使用 Corona SDK*，首先教你如何在 Mac OS X 和 Windows 操作系统上安装 Corona SDK。你将学会如何仅用两行代码创建你的第一个程序。最后，我们将介绍构建和加载应用程序到 iOS 或 Android 设备的过程。

第二章，*Lua 速成与 Corona 框架*，深入探讨用于 Corona SDK 开发的 Lua 编程语言。我们将介绍 Lua 中变量、函数和数据结构的基础知识。本章还将介绍如何在 Corona 框架内实现各种显示对象。

第三章，*制作我们的第一款游戏——打砖块*，讨论了制作你的第一款游戏，打砖块的前半部分。你将学习如何在 Corona 项目中构建游戏文件，并创建将在屏幕上显示的游戏对象。

第四章，*游戏控制*，继续讨论制作你的第一款游戏，打砖块的后半部分。我们将涵盖游戏对象移动以及场景中对象之间的碰撞检测。你还将学习如何创建一个计分系统，该系统将实现游戏的胜利和失败条件。

第五章，*让我们的游戏动起来*，解释了如何使用精灵表来动画化游戏。本章将深入探讨在创建新游戏框架时管理动作和过渡。

第六章，*播放声音和音乐*，提供了如何在应用程序中应用声音效果和音乐的信息。在增强游戏开发感官体验方面，包含某种类型的音频至关重要。你将学习如何通过加载、执行和循环技术，利用 Corona 音频系统融入音频。

第七章，*物理现象——下落物体*，涵盖了如何在 Corona SDK 中使用显示对象实现 Box2D 引擎。你将能够自定义构建物体，并处理下落物体的物理行为。在本章中，我们将应用动态/静态物体的使用，并解释碰撞后处理的目的。

第八章，*操作编排器*，讨论如何使用 Composer API 管理所有游戏场景。我们还将详细介绍菜单设计，例如创建暂停菜单和主菜单。此外，你将学习如何在游戏中保存高分。

第九章，*处理多设备和网络应用*，提供了将你的应用程序与如 Twitter 或 Facebook 等社交网络集成的信息。这将使你的应用程序能够全球范围内触及更多受众。

第十章，*优化、测试和发布你的游戏*，解释了针对 iOS 和 Android 设备的应用提交过程。本章将指导你如何为 Apple App Store 设置分发供应配置文件，并在 iTunes Connect 中管理你的应用信息。Android 开发者将学习如何为发布签署他们的应用程序，以便提交到 Google Play Store。

第十一章，*实现应用内购买*，介绍了如何通过创建可消耗、不可消耗或订阅购买来为你的游戏实现货币化。你将使用 Corona 的商店模块在 Apple App Store 申请应用内购买。我们还将查看在设备上测试购买，以检查是否使用沙盒环境应用了交易。

附录，*弹出式测验答案*，包含了本书所有弹出式测验部分的答案。

# 你需要为本书准备以下物品

在使用 Corona SDK for Mac 开发游戏之前，你需要准备以下物品：

+   如果你正在安装适用于 Mac OS X 的 Corona，请确保你的系统具备以下条件：

    +   Mac OS X 10.9 或更高版本

    +   运行 Lion、Mountain Lion、Mavericks 或 Yosemite 的基于 Intel 的系统

    +   64 位 CPU（Core 2 Duo）

    +   OpenGL 2.0 或更高版本的图形系统

+   你必须注册 Apple Developer Program

+   XCode

+   文本编辑器，如 TextWrangler、BBEdit 或 TextMate

在使用 Corona SDK for Windows 开发游戏之前，你需要准备以下物品：

+   如果你使用的是 Microsoft Windows，请确保你的系统具备以下条件：

    +   Windows 8、Windows 7、Vista 或 XP（Service Pack 2）操作系统

    +   1 GHz 处理器（推荐）

    +   80 MB 磁盘空间（最低要求）

    +   1 GB 内存（最低要求）

    +   OpenGL 2.1 或更高版本的图形系统（大多数现代 Windows 系统中可用）

    +   Java 开发工具包（JDK）的 32 位（x86）版本

    +   使用 Corona 在 Mac 或 Windows 上创建 Android 设备构建时，不需要 Android SDK

+   Java 6 SDK

+   文本编辑器，如 Notepad ++

如果你想为 Android 设备提交和发布应用，你必须注册为 Google Play Developer。

游戏教程需要使用本书提供的资源文件，也可以从 Packt Publishing 网站下载。

最后，你需要 Corona SDK 的最新稳定版本。这适用于所有订阅级别。

# 本书适合的对象

这本书适合任何想要尝试为 Android 和 iOS 创建商业上成功的游戏的人。你不需要游戏开发或编程经验。

# 部分

在这本书中，你会发现有几个经常出现的标题（动手时间、刚刚发生了什么？、小测验和动手英雄）。

为了清楚地说明如何完成一个过程或任务，我们使用以下部分：

# 动手时间——标题

1.  操作 1

1.  操作 2

1.  操作 3

指令通常需要一些额外的解释以确保其意义明确，因此它们后面会跟着这些部分：

## *刚刚发生了什么？*

本节解释了你刚刚完成的工作或指令的运作方式。

你在书中还会发现一些其他的学习辅助工具，例如：

## 小测验——标题

这些是简短的选择题，旨在帮助你测试自己的理解。

## 动手英雄——标题

这些是实践挑战，为你提供实验所学知识的想法。

# 约定

你还会发现文本中有多种样式，用于区分不同类型的信息。以下是一些样式的例子及其含义的解释。

文本中的代码字、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 处理程序如下显示："我们可以通过使用`include`指令包含其他上下文。"

代码块如下设置：

```kt
textObject = display.newText( "Hello World!", 160, 80, native.systemFont, 36 )
textObject: setFillColor ( 1, 1, 1 )
```

当我们希望引起你注意代码块中的特定部分时，相关的行或项目会以粗体设置：

```kt
    local buyLevel2 = function ( product ) 
      print ("Congrats! Purchasing " ..product)

     -- Purchase the item
      if store.canMakePurchases then 
        store.purchase( {validProducts[1]} ) 
      else
        native.showAlert("Store purchases are not available, please try again later",  { "OK" } ) – Will occur only due to phone setting/account restrictions
      end 
    end 
    -- Enter your product ID here
 -- Replace Product ID with a valid one from iTunes Connect
 buyLevel2("com.companyname.appname.NonConsumable")

```

任何命令行输入或输出都如下书写：

```kt
keytool -genkey -v -keystore my-release-key.keystore -alias aliasname -keyalg RSA -validity 999999

```

**新** **术语**和**重要** **词汇**以粗体显示。你在屏幕上看到的词，例如菜单或对话框中的，会在文本中这样出现："点击**立即注册**按钮，并按照苹果的指示完成流程。"

### 注意

警告或重要提示会以这样的框显示。

### 提示

技巧和窍门会像这样出现。

# 读者反馈

我们始终欢迎读者的反馈。告诉我们你对这本书的看法——你喜欢或不喜欢什么。读者的反馈对我们很重要，因为它帮助我们开发出你真正能从中获得最大收益的标题。

要给我们发送一般反馈，只需发送电子邮件到`<feedback@packtpub.com>`，并在邮件的主题中提及书籍的标题。

如果你有一个擅长的主题并且有兴趣撰写或参与书籍编写，请查看我们的作者指南：[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

既然你现在拥有了 Packt Publishing 的一本书，我们有许多方法帮助你最大限度地利用你的购买。

## 下载示例代码

您可以从您的账户[`www.packtpub.com`](http://www.packtpub.com)下载所有您购买过的 Packt Publishing 书籍的示例代码文件。如果您在别处购买了这本书，可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)注册，我们会直接将文件通过电子邮件发送给您。

## 下载本书的彩色图像

我们还为您提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。彩色图像将帮助您更好地理解输出的变化。您可以从[`www.packtpub.com/sites/default/files/downloads/9343OT_ColoredImages.pdf`](https://www.packtpub.com/sites/default/files/downloads/9343OT_ColoredImages.pdf)下载此文件。

## 勘误

尽管我们已经尽力确保内容的准确性，但错误仍然会发生。如果您在我们的书中发现了一个错误——可能是文本或代码中的错误——如果您能报告给我们，我们将不胜感激。这样做，您可以避免其他读者感到沮丧，并帮助我们改进本书的后续版本。如果您发现任何勘误，请通过访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书籍，点击**Errata Submission Form**链接，并输入您的勘误详情来报告。一旦您的勘误被验证，您的提交将被接受，勘误将被上传到我们的网站或添加到该标题下的现有勘误列表中。

要查看之前提交的勘误，请访问[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)，并在搜索字段中输入书名。所需信息将在**Errata**部分出现。

## 盗版

在互联网上，盗版受版权保护的材料是所有媒体都面临的持续问题。在 Packt，我们非常重视保护我们的版权和许可。如果您在互联网上以任何形式遇到我们作品的非法副本，请立即提供位置地址或网站名称，以便我们可以寻求补救措施。

请在`<copyright@packtpub.com>`联系我们，并提供疑似盗版材料的链接。

我们感谢您保护我们的作者以及我们为您带来有价值内容的能力。

## 问题

如果您对本书的任何方面有问题，可以联系我们`<questions@packtpub.com>`，我们将尽力解决问题。


# 第一章：开始使用 Corona SDK

> *在我们开始编写一些简单的游戏之前，我们需要安装并运行必要的程序，这些程序将使我们的应用程序变得生动。**Corona SDK**主要是一个 2D 开发引擎。如果你有 iOS 或 Android 开发的经验，你会发现使用 Corona 的经历令人耳目一新。它也非常易于使用。很快，你就能创建出可以在 Apple App Store 和 Google Play Store 发布的成品。*

在本章中，我们将：

+   在 Mac OS X 和 Windows 上设置 Corona SDK

+   为 Mac OS X 安装 Xcode

+   用两行代码创建一个 Hello World 程序

+   在 iOS Provisioning Portal 中添加设备

+   将应用程序加载到 iOS 设备上

+   将应用程序加载到 Android 设备上

# 下载并安装 Corona

你可以选择 Mac OS X 或 Microsoft Windows 操作系统进行开发。请记住运行此程序所需的以下系统要求。本书中最兼容的版本是 Build 2014.2511。

如果你是在 Mac OS X 上安装 Corona，请确保你的系统具备以下特性：

+   Mac OS X 10.9 或更高版本

+   运行 Lion、Mountain Lion、Mavericks 或 Yosemite 的基于 Intel 的系统

+   一个 64 位的 CPU（Core 2 Duo）

+   OpenGL 2.0 或更高版本的图形系统

如果你使用的是 Microsoft Windows，请确保你的系统具备以下特性：

+   Windows 8、Windows 7、Vista 或 XP（Service Pack 2）操作系统

+   1 GHZ 处理器（推荐）

+   80 MB 的磁盘空间（最低）

+   1 GB 的 RAM（最低）

+   需要 OpenGL 2.1 或更高版本的图形系统（大多数现代 Windows 系统都可用）

+   **Java 开发工具包**（**JDK**）的 32 位（x86）版本

+   使用 Corona 在 Mac 或 Windows 上创建 Android 设备构建时，不需要 Android SDK

# 动手操作——在 Mac OS X 上设置并激活 Corona

让我们从在桌面上设置 Corona SDK 开始：

1.  如果你还没有下载 SDK，请从[`www.coronalabs.com/downloads/coronasdk`](http://www.coronalabs.com/downloads/coronasdk)下载。在访问 SDK 之前，你需要注册成为用户。

1.  任何 Mac 程序的文件扩展名应以`.dmg`结尾；这被称为 Apple 磁盘映像。下载磁盘映像后，双击磁盘映像文件进行挂载。名称应类似于`CoronaSDK-XXXX.XXXX.dmg`。挂载后，你应该能看到如下截图所示的已挂载磁盘映像文件夹：![动手操作——在 Mac OS X 上设置并激活 Corona](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_01.jpg)

1.  接下来，将`CoronaSDK`文件夹拖到`Applications`文件夹中。这将把 Corona 文件夹的内容复制到`/Applications`。如果你不是账户的主要管理员，系统会提示你输入管理员密码。成功安装后，你可以在`/Applications`中看到`CoronaSDK`文件夹。为了方便访问文件夹内容，你可以将`CoronaSDK`文件夹拖到 Mac 桌面的 dock 上创建别名：![行动时间——在 Mac OS X 上设置和激活 Corona](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_02.jpg)

第一次使用 Corona SDK 的用户需要完成一次快速简单的一次性授权过程才能使用。你需要连接到互联网才能完成授权过程。

1.  在 SDK 文件夹中启动 Corona 模拟器。

1.  假设这是你第一次操作，系统会展示一个**最终用户许可协议**（**EULA**）。接受协议后，输入你用来注册 Corona 的电子邮件和密码以激活 SDK。否则，点击**注册**创建一个账户。

    ### 注意

    如果你以独立开发者的身份注册 Corona，那么在 iOS 和/或 Android 设备上进行开发是免费的。

    ![行动时间——在 Mac OS X 上设置和激活 Corona](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_03.jpg)

1.  登录成功后，你会看到一个确认对话框，表明 SDK 已经可以使用：![行动时间——在 Mac OS X 上设置和激活 Corona](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_04.jpg)

1.  点击**继续**按钮，你将看到欢迎来到 Corona 的屏幕：![行动时间——在 Mac OS X 上设置和激活 Corona](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_05.jpg)

## *刚才发生了什么？*

在你的 Mac 操作系统上设置 Corona SDK 就像安装其他任何专门的 Mac 程序一样简单。在你在机器上授权 SDK 并用你的电子邮件和密码登录后，它就可以使用了。从现在开始，每次你启动 Corona，它都会自动登录到你的账户。当这种情况发生时，你会注意到屏幕上会出现 Corona SDK 的欢迎界面。

# 行动时间——在 Windows 上设置和激活 Corona

让我们按照以下步骤在桌面上安装 Corona SDK：

1.  从[`www.coronalabs.com/downloads/coronasdk`](http://www.coronalabs.com/downloads/coronasdk)下载 Corona SDK。在访问 SDK 之前，你需要注册成为用户。

1.  Corona 在 Windows 版本的文件扩展名应为`.msi`，这是微软制作的 Windows 安装程序的一部分，用于安装程序。双击该文件。文件名应该类似于`CoronaSDK.msi`。

1.  按照屏幕上的指示进行安装。

1.  Corona 默认会直接安装到您的`Programs`文件夹中。在 Microsoft Windows 上，您可以从开始菜单的程序列表中选择**Corona Simulator**，或者双击桌面上的 Corona 图标。成功激活后，您应该会看到以下屏幕：![行动时间 - 在 Windows 上设置和激活 Corona](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_06.jpg)

1.  启动 Corona SDK 的激活过程应该与 Mac 上的操作相同，这是您第一次启动 Corona 时的步骤。

    ### 注意

    如果您遇到图像显示不正常的问题，请检查您是否使用的是最新的 OpenGL 图形驱动程序，至少是 2.1 版本。

    请注意，Windows 上的 Corona SDK 只能为 Android 设备构建，不能为 iOS 设备（iPhone、iPad 或 iPod Touch）构建。而 Mac 不仅可以为 iOS 构建，也可以为 Android 设备构建 Corona。

1.  要创建设备构建，您需要在 PC 上安装 Java 6 SDK。您需要访问 Oracle 网站 [`www.oracle.com/technetwork/java/javasebusiness/downloads/java-archive-downloads-javase6-419409.html`](http://www.oracle.com/technetwork/java/javasebusiness/downloads/java-archive-downloads-javase6-419409.html) 下载 JDK，并点击**Java SE Development Kit 6u45**链接。

1.  在下一页，选择**接受许可协议**的单选按钮，然后点击**Windows x86**链接下载安装程序。如果您还没有 Oracle 网站的用户账户，系统会要求您登录或创建一个。

1.  一旦下载了 JDK，请运行安装程序。安装完成后，您就可以在 PC 上为 Android 创建设备构建了。

## *刚才发生了什么？*

在 Windows 上安装 SDK 的过程与在 Mac OS X 上的设置过程不同。执行安装文件时，Windows 会自动提供一个指定的位置来安装应用程序，比如`Programs`文件夹，这样您就不必手动选择目的地。安装成功后，您会在桌面上看到 Corona SDK 的图标以便快速访问，或者在您首次访问时，它可能会在开始菜单的程序列表中突出显示。当您在计算机上授权 Corona 并使用您的登录信息登录后，它就可以使用了，并且每次启动时都会自动登录。

# 在 Mac 和 Windows 上使用模拟器

在 Mac OS X 上，可以通过选择`Applications`目录中的 Corona 终端或 Corona 模拟器来启动 Corona SDK。这两个选择都可以访问 SDK。Corona 模拟器只打开模拟器，而 Corona 终端会同时打开模拟器和终端窗口。终端有助于调试您的程序，并显示模拟器错误/警告和`print()`消息。

在 Microsoft Windows 上，选择 `Corona SDK` 文件夹，并从开始菜单中的程序列表中点击 **Corona Simulator**，或者双击桌面上的 Corona 图标。如果你使用的是 Windows，模拟器和终端将始终一起打开。

让我们回顾一下 `Corona SDK` 文件夹（在 Mac 上的 `Applications/Corona SDK`，在 Windows 上的 `Start/All Apps/Corona SDK`）中有用的内容：

+   **调试器（Mac）/Corona 调试器（Windows）**：这是一个工具，用于查找并隔离代码中的问题。

+   **Corona 模拟器**：这是用于启动你的应用程序进行测试的环境。它在你本地计算机上模拟你正在开发的移动设备。在 Windows 上，它将同时打开模拟器和终端。

+   **Corona 终端**：这会启动 Corona 模拟器并打开一个终端窗口，以显示错误/警告消息和 `print()` 语句。这对于调试代码非常有帮助，但仅在 Mac 上可用。

+   **模拟器**：这具有与 Corona 终端相同的属性，但它是从命令行调用的，并且仅在 Mac 上可用。

+   **示例代码**：这是一组示例应用程序，帮助你开始使用 Corona。它包含代码和艺术资源以供使用。

启动模拟器时，Corona SDK 窗口会自动打开。你可以在模拟器中打开 Corona 项目，创建设备构建以进行测试或分发，并查看一些示例游戏和应用，以便熟悉 SDK。

# 动手时间——在模拟器中查看示例项目

让我们在模拟器中看看 `HelloPhysics` 示例项目：

1.  点击 `Corona SDK` 文件夹中的 **Corona Simulator**。

1.  当 Corona SDK 窗口启动时，点击 **Samples** 链接。在出现的 **Open** 对话框中，导航到 `Applications/CoronaSDK/SampleCode/Physics/HelloPhysics`（Mac）或 `C:\Program Files (x86)\Corona Labs\Corona SDK\Sample Code\Physics\HelloPhysics`（Windows）。在 Mac 上，点击 **Open**，它将自动打开 `main.lua`。在 Windows 上，双击 `main.lua` 打开文件。`HelloPhysics` 应用程序将在模拟器中打开并运行。

## *刚才发生了什么？*

通过 Corona 终端或 Corona 模拟器访问 SDK 是个人偏好的问题。许多 Mac 用户更喜欢使用 Corona 终端，这样他们可以追踪输出到终端的消息。当你通过 Corona 模拟器启动 SDK 时，将显示模拟器，但不会显示终端窗口。当 Windows 用户启动 Corona 模拟器时，它将同时显示模拟器和终端窗口。当你想要尝试 Corona 提供的示例应用程序时，这种方式很方便。

`main.lua` 文件是一个特殊的文件名，它告诉 Corona 在项目文件夹中从哪里开始执行。这个文件还可以加载其他代码文件或程序资源，如声音或图形。

当你在 Corona 中启动`HelloPhysics`应用程序时，你会观察到模拟器中的盒子对象从屏幕顶部落下并与地面对象碰撞。从启动`main.lua`文件到在模拟器中查看结果的过程几乎是立即的。

## 动手试试——使用不同的设备壳。

当你开始熟悉 Corona 模拟器时，无论是在 Windows 还是 Mac OS X 中，启动应用程序时总是使用默认设备。Windows 使用 Droid 作为默认设备，而 Mac OS X 使用常规 iPhone。尝试在不同的设备壳中启动示例代码，以查看模拟器所有可用设备之间的屏幕分辨率差异。

当将构建版本移植到多个平台时，你需要考虑 iOS 和 Android 设备中各种屏幕分辨率。构建是你所有源代码的编译版本，转换成一个文件。让你的游戏构建适用于多个平台可以扩大你的应用程序受众。

# 选择文本编辑器

Corona 没有指定的程序编辑器用于编写代码，因此你需要找到一个符合你需求的编辑器。

对于 Mac OS，TextWrangler 是一个不错的选择，而且它是免费的！你可以在[`www.barebones.com/products/textwrangler/download.html`](http://www.barebones.com/products/textwrangler/download.html)下载它。其他文本编辑器如 BBEdit（[`www.barebones.com/thedeck`](http://www.barebones.com/thedeck)）和 TextMate（[`macromates.com/`](http://macromates.com/)）也非常好，但使用它们需要购买。TextMate 还兼容 Corona TextMate Bundle，可在[`www.ludicroussoftware.com/corona-textmate-bundle/index.html`](http://www.ludicroussoftware.com/corona-textmate-bundle/index.html)获取。

对于 Microsoft Windows，推荐使用 Notepad++，可以从[`notepad-plus-plus.org/`](http://notepad-plus-plus.org/)下载。

以下文本编辑器兼容 Mac OS 和 Microsoft Windows：

+   Sublime Text ([`www.sublimetext.com`](http://www.sublimetext.com))

+   Lua Glider ([`www.mydevelopersgames.com/Glider/`](http://www.mydevelopersgames.com/Glider/))

+   Outlaw ([`outlawgametools.com/outlaw-code-editor-and-project-manager/`](http://outlawgametools.com/outlaw-code-editor-and-project-manager/))

操作系统自带的任何文本编辑器，如 Mac 的 TextEdit 或 Windows 的 Notepad，都可以使用，但使用专为编程设计的编辑器会更容易。对于 Corona 来说，使用支持 Lua 语法高亮的编辑器在编码时会更加高效。语法高亮通过为关键字和标点添加格式化属性，使读者更容易区分代码与文本。

# 在设备上开发

如果你只想使用 Corona 模拟器，则无需下载 Apple 的开发工具包 Xcode 或 Android SDK。若要在 iOS 设备（iPhone、iPod Touch 和 iPad）上构建和测试你的代码，你需要注册成为 Apple 开发者并创建和下载配置文件。如果你想在 Android 上开发，除非你想使用 ADB 工具帮助安装构建版本和查看调试信息，否则不需要下载 Android SDK。

Corona SDK 入门版本允许你为 iOS 构建 Adhoc（测试版）和调试版本（Android），以便在你的设备上进行测试。Corona Pro 用户还能享受特殊功能，如访问每日构建版本、高级功能、所有插件和高级支持。

# 操作时间——下载和安装 Xcode

要开发任何 iOS 应用程序，你需要加入 Apple 开发者计划，这需要每年支付 99 美元，并在 Apple 网站 [`developer.apple.com/programs/ios/`](http://developer.apple.com/programs/ios/) 上按照以下步骤创建一个账户：

1.  点击**立即注册**按钮，并按照 Apple 的说明完成流程。在添加程序时，选择**iOS 开发者计划**。

1.  完成注册后，点击标记为**开发中心**的部分下的 iOS 链接。

1.  滚动到**下载**部分，下载当前的 Xcode，或者你也可以从 Mac App Store 下载 Xcode。

1.  完全下载 Xcode 后，从`/Applications/Xcode`目录中双击 Xcode。系统会要求你作为管理员用户进行身份验证：![操作时间——下载和安装 Xcode](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_07.jpg)

1.  输入您的凭据后，点击**确定**按钮完成安装。你将看到以下屏幕：![操作时间——下载和安装 Xcode](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_08.jpg)

1.  安装完 Xcode 开发者工具后，你可以通过启动 Xcode 并选择**帮助**菜单中的任何项目来访问文档。像 Xcode 和 Instruments 这样的开发者应用程序安装在`/Applications/Xcode`目录下。你可以将这些应用程序图标拖到你的 Dock 中以便快速访问。

## *刚才发生了什么？*

我们刚才走过了如何在 Mac OS X 上安装 Xcode 的步骤。通过加入 Apple 开发者计划，你可以在网站上访问最新的开发工具。记住，要继续作为 Apple 开发者，*你必须支付*每年 99 美元的费用以保持订阅。

Xcode 文件相当大，所以下载需要一些时间，具体取决于你的互联网连接速度。安装完成后，Xcode 就可以使用了。

# 操作时间——用两行代码创建一个 Hello World 应用程序

既然我们已经设置好了模拟器和文本编辑器，让我们开始制作我们的第一个 Corona 程序吧！我们将要制作的第一款程序叫做`Hello World`。这是一个传统程序，许多人在开始学习一门新的编程语言时都会学习它。

1.  打开你喜欢的文本编辑器，并输入以下几行：

    ```kt
    textObject = display.newText( "Hello World!", 160, 80, native.systemFont, 36 )
    textObject: setFillColor ( 1, 1, 1 )
    ```

1.  接下来，在桌面上创建一个名为`Hello World`的文件夹。将前面的文本保存为名为`main.lua`的文件，保存在你的项目文件夹位置。

1.  启动 Corona。你会看到 Corona SDK 的界面。点击**打开**，导航到你刚刚创建的`Hello World`文件夹。你应该在这个文件夹中看到你的`main.lua`文件：![动手时间——用两行代码创建一个 Hello World 应用](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_09.jpg)

1.  在 Mac 上，点击**打开**按钮。在 Windows 上，选择`main.lua`文件并点击**打开**按钮。你会在 Corona 模拟器中看到你的新程序运行：![动手时间——用两行代码创建一个 Hello World 应用](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_10.jpg)

### 提示

**下载示例代码**

你可以从你在 [`www.packtpub.com`](http://www.packtpub.com) 的账户下载你所购买的所有 Packt Publishing 图书的示例代码文件。如果你在其他地方购买了这本书，可以访问 [`www.packtpub.com/support`](http://www.packtpub.com/support) 注册，我们会直接将文件通过电子邮件发送给你。

# 动手时间——修改我们的应用程序

在我们深入更复杂的示例之前，通过执行以下步骤，让我们对程序进行一些小修改：

1.  让我们将`main.lua`的第二行更改为如下显示：

    ```kt
    textObject = display.newText( "Hello World!", 160, 80, native.systemFont, 36 )
    textObject:setFillColor( 0.9, 0.98 ,0 )
    ```

1.  保存你的文件，回到 Corona 模拟器。模拟器将检测文件中的更改并自动重新启动并应用更改。如果保存文件后模拟器没有自动重新启动，请按 *Command* + *R* (Mac) / *Ctrl* + *R* (Windows)。你将在屏幕上看到以下输出：![动手时间——修改我们的应用程序](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_11.jpg)

### 注意

当你继续学习更多 Corona 函数时，你会注意到一些文本值是可选的。在这种情况下，我们需要使用五个值。

# 动手时间——将新字体名称应用到我们的应用程序

现在，通过执行以下步骤，让我们来玩转字体名称：

1.  将第一行更改为以下代码行：

    ```kt
    textObject = display.newText( "Hello World!", 160, 80, "Times New Roman", 36 )
    ```

1.  在对`main.lua`文件进行任何修改后，请确保保存文件；然后在 Corona 中按下 *Command* + *R* (Mac) / *Ctrl* + *R* (Windows) 重新启动模拟器以查看新字体。如果你使用的是 Mac，通常在保存文件后模拟器会自动重新启动，或者它可能会询问你是否想重新启动程序。你可以在模拟器中看到新字体：![动手时间——将新字体名称应用到我们的应用程序](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_12.jpg)

## *刚才发生了什么？*

现在你已经制作了你的第一个完整的移动应用程序！更令人惊叹的是，这是一个完整的 iPhone、iPad 和 Android 应用程序。这个两行程序实际上可以安装并在你的 iOS/Android 设备上运行，如果你创建了一个构建。现在你已经了解了 Corona 中的基本工作流程。

如果你查看`main.lua`文件中的第 2 行，你会注意到`setFillColor`改变了**Hello World!**的文本颜色。

颜色由三组 RGB 数字组成，分别代表颜色中包含的红、绿、蓝的数量。它们用三个数字表示，数值范围从 0 到 1。例如，黑色为（0,0,0），蓝色为（0,0,1），白色为（0.6, 0.4, 0.8）。

继续尝试不同的颜色值，以查看不同的结果。当你保存`main.lua`文件并重新启动 Corona 时，你可以在模拟器中看到代码的更改。

当你查看`main.lua`文件的第一行时，你会注意到`newText()`是由显示对象调用的。返回的引用是`textObject`。`newText()`函数返回一个将在屏幕上表示文本的对象。`newText()`函数是显示库的一部分。

当你需要访问`newText`的显示属性时，输入`display.newText`。`Hello World!`后面的两个数字控制了文本在屏幕上的水平和垂直位置，单位为像素。接下来的项指定了字体。我们使用了`native.systemFont`这个名字，默认情况下，它指的是当前设备上的标准字体。例如，iPhone 的默认字体是 Helvetica。你可以使用任何标准字体名称，比如前面示例中使用的 Times New Roman。最后一个数字是字体大小。

## 尝试英雄——添加更多文本对象。

既然你现在开始对编程有了初步了解，请尝试在你的当前项目文件中按照以下步骤操作：

1.  创建一个新的显示对象，并使用不同的字体和文字颜色。确保它显示在`Hello World!`文字下方。同时，请确保你的新显示对象拥有一个不同的对象名称。

1.  继续改变当前显示对象`textObject`的值。更改*x*和*y*坐标、字符串文本、字体名称，甚至字体大小。

1.  虽然`object:setFillColor( r,g,b )`设置了文本的颜色，但你可以添加一个可选参数来控制文本的不透明度。尝试使用`object:setFillColor( r, g, b [, a] )`。`a`的值也在 0 到 1 之间（1 是不透明，这是默认值）。观察你的文本颜色的结果。

# 在 iOS 设备上测试我们的应用程序

如果你只想在 Android 设备上测试应用程序，可以跳过本章节的这部分内容，直接阅读*在 Android 设备上测试我们的应用程序*。在我们能够将第一个 Hello World 应用程序上传到 iOS 设备之前，我们需要登录我们的 Apple 开发者账户，这样我们才能在开发机上创建和安装签名证书。如果你还没有创建开发者账户，请访问[`developer.apple.com/programs/ios/`](http://developer.apple.com/programs/ios/)进行创建。记住，成为 Apple 开发者每年需要支付 99 美元的费用。

### 注意

Apple 开发者账户仅适用于在 Mac OS X 上开发的用户。确保你的 Xcode 版本与手机上的操作系统版本相同或更新。例如，如果你安装了 iPhone OS 版本 5.0，你将需要包含 iOS SDK 版本 5.0 或更高版本的 Xcode。

# 行动时间——获取 iOS 开发者证书

确保你已经注册了开发者计划；你将需要使用位于`/Applications/Utilities`的钥匙串访问工具，以便创建一个证书请求。在 Apple 设备上进行任何测试之前，必须使用有效的证书对所有的 iOS 应用程序进行签名。以下步骤将向你展示如何创建 iOS 开发者证书：

1.  前往**钥匙串访问** | **证书助手** | **从证书授权中心请求证书**:![行动时间——获取 iOS 开发者证书](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_13.jpg)

1.  在**用户电子邮件地址**字段中，输入你注册 iOS 开发者时使用的电子邮件地址。在**常用名称**中，输入你的名字或团队名称。确保输入的名称与注册 iOS 开发者时提交的信息相匹配。**CA 电子邮件地址**字段无需填写，你可以将其留空。我们不将证书通过电子邮件发送给**证书授权中心**（**CA**）。勾选**保存到磁盘**和**让我指定密钥对信息**。点击**继续**后，系统会要求你选择一个保存位置。将你的文件保存到一个你能轻松找到的位置，比如桌面。![行动时间——获取 iOS 开发者证书](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_14.jpg)

1.  在以下窗口中，确保已选择**2048 位**作为**密钥大小**，选择**RSA**作为**算法**，然后点击**继续**。这将生成密钥并将其保存到你指定的位置。在下一个窗口中点击**完成**。![行动时间——获取 iOS 开发者证书](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_15.jpg)

1.  接下来，访问苹果开发者网站[`developer.apple.com/`](http://developer.apple.com/)，点击**iOS 开发者中心**，并登录到你的开发者账户。在屏幕右侧选择**iOS 开发者计划**下的**证书、标识符和配置文件**，然后导航到**iOS 应用**下的**证书**。点击页面右侧的**+**图标。在**开发**下，点击**iOS 应用开发**单选按钮。点击**继续**按钮，直到你到达生成证书的屏幕：![行动时间——获取 iOS 开发者证书](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_16.jpg)

1.  点击**选择文件**按钮，找到你保存到桌面上的证书文件，然后点击**生成**按钮。

1.  点击**生成**后，你会收到来自钥匙串访问的 CA 请求表单中指定的电子邮件通知，或者你可以直接从开发者门户下载。创建证书的人将收到此电子邮件，并通过点击**批准**按钮来批准请求。![行动时间——获取 iOS 开发者证书](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_17.jpg)

1.  点击**下载**按钮，并将证书保存到一个容易找到的位置。完成此操作后，双击该文件，证书将自动添加到钥匙串访问中。![行动时间——获取 iOS 开发者证书](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_18.jpg)

## *刚才发生了什么？*

现在我们有了 iOS 设备的有效证书。iOS 开发证书仅用于开发目的，有效期为大约一年。密钥对由你的公钥和私钥组成。私钥允许 Xcode 为 iOS 应用程序签名。私钥只对密钥对创建者可用，并存储在创建者的机器的系统钥匙串中。

## 添加 iOS 设备

在 iPhone 开发者计划中，你可以分配最多 100 个设备用于开发和测试。要注册一个设备，你需要**唯一设备识别(UDID)**号码。你可以在 iTunes 和 Xcode 中找到这个信息。

### Xcode

要查找设备的 UDID，请将设备连接到 Mac 并打开 Xcode。在 Xcode 中，导航到菜单栏，选择**窗口**，然后点击**组织者**。**标识符**字段中的 40 个十六进制字符字符串就是你的设备 UDID。打开**组织者**窗口后，你应该能在左侧的**设备**列表中看到你的设备名称。点击它，并用鼠标选择标识符，复制到剪贴板。

![Xcode](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_19.jpg)

通常，当你第一次将设备连接到**组织者**时，你会收到一个按钮通知，上面写着**用于开发**。选择它，Xcode 将为你的设备在 iOS 预配门户中完成大部分预配工作。

### iTunes

在连接设备的情况下，打开 iTunes 并点击设备列表中的您的设备。选择 **摘要** 选项卡。点击 **序列号** 标签以显示 **标识符** 字段和 40 个字符的 UDID。按 *Command* + *C* 将 UDID 复制到剪贴板。

![iTunes](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_20.jpg)

# 行动时间 - 添加/注册您的 iOS 设备

要添加用于开发/测试的设备，请执行以下步骤：

1.  在开发者门户中选择 **设备** 并点击 **+** 图标以注册新设备。选择 **注册设备** 单选按钮以注册一个设备。

1.  在 **名称** 字段中为您的设备创建一个名称，并通过按 *Command* + *V* 将您保存在剪贴板上的设备 UDID 粘贴到 **UDID** 字段中。

1.  完成后点击 **继续** 并在验证设备信息后点击 **注册**。![行动时间 - 添加/注册您的 iOS 设备](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_21.jpg)

# 行动时间 - 创建一个 App ID

现在，您已经在门户中添加了一个设备，接下来需要创建一个 App ID。App ID 具有一个由 Apple 生成的唯一 10 个字符的 Apple ID 前缀和一个由配置门户中的团队管理员创建的 Apple ID 后缀。App ID 可能如下所示：`7R456G1254.com.companyname.YourApplication`。要创建新的 App ID，请使用以下步骤：

1.  在门户的 **标识符** 部分点击 **App IDs** 并选择 **+** 图标。![行动时间 - 创建一个 App ID](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_22.jpg)

1.  在 **App ID** **描述** 字段中填写您的应用程序名称。

1.  您已经分配了一个 Apple ID 前缀（也称为团队 ID）。

1.  在 **App ID 后缀** 字段中，为您的应用指定一个唯一标识符。您可以根据自己的意愿来标识应用，但建议您使用反向域名风格的字符串，即 `com.domainname.appname`。点击 **继续** 然后点击 **提交** 以创建您的 App ID。

### 注意

您可以在捆绑标识符中创建一个通配符字符，以便在共享同一钥匙串访问的一组应用程序之间共享。为此，只需创建一个带有星号 (*) 结尾的单个 App ID。您可以将此字符单独放在捆绑标识符字段中，或者作为字符串的结尾，例如，`com.domainname.*`。关于此主题的更多信息可以在 iOS 配置门户的 App IDs 部分找到，链接为[`developer.apple.com/ios/manage/bundles/howto.action`](https://developer.apple.com/ios/manage/bundles/howto.action)。

## *刚才发生了什么？*

所有设备的 UDID 都是唯一的，我们可以在 Xcode 和 iTunes 中找到它们。当我们在 iOS 配置门户中添加设备时，我们获取了由 40 个十六进制字符组成的 UDID，并确保我们创建了一个设备名称，以便我们可以识别用于开发的设备。

现在我们有了想要安装在设备上的应用程序的 App ID。App ID 是 iOS 用来允许您的应用程序连接到 Apple Push Notification 服务、在应用程序之间共享钥匙串数据以及与您希望与 iOS 应用程序配对的外部硬件配件进行通信的唯一标识符。

## 配置文件

**配置文件**是一组数字实体，它将应用程序和设备独特地绑定到一个授权的 iOS 开发团队，并使设备能够用来测试特定的应用程序。配置文件定义了应用程序、设备和开发团队之间的关系。它们需要为应用程序的开发和分发方面进行定义。

# 行动时间 - 创建配置文件

要创建配置文件，请访问开发者门户的**配置文件**部分，并点击**+**图标。执行以下步骤：

1.  在**开发**部分下选择**iOS App Development**单选按钮，然后选择**继续**。

1.  在下拉菜单中选择您为应用程序创建的**App ID**，然后点击**继续**。

1.  选择您希望包含在配置文件中的证书，然后点击**继续**。

1.  选择您希望授权此配置文件的设备，然后点击**继续**。

1.  创建一个**配置文件名称**，完成后点击**生成**按钮：![行动时间 - 创建配置文件](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_23.jpg)

1.  点击**下载**按钮。在文件下载时，如果 Xcode 尚未打开，请启动 Xcode，并在键盘上按*Shift* + *Command* + *2*打开**组织者**。

1.  在**库**下，选择**配置文件**部分。将您下载的`.mobileprovision`文件拖到**组织者**窗口中。这将自动将您的`.mobileprovision`文件复制到正确的目录中。![行动时间 - 创建配置文件](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_24.jpg)

## *刚才发生了什么？*

在配置文件中有权限的设备只要证书包含在配置文件中，就可以用于测试。一个设备可以安装多个配置文件。

## 应用程序图标

当前，我们的应用程序在设备上没有图标图像显示。默认情况下，如果应用程序没有设置图标图像，一旦构建被加载到您的设备上，您将看到一个浅灰色框以及下面的应用程序名称。因此，启动您喜欢的创意开发工具，让我们创建一个简单的图像。

标准分辨率 iPad2 或 iPad mini 的应用程序图标图像文件为 76 x 76 px PNG。图像应始终保存为`Icon.png`，并且必须位于您当前的项目文件夹中。支持视网膜显示的 iPhone/iPod touch 设备需要一个额外的 120 x 120 px 高分辨率图标，而 iPad 或 iPad mini 需要一个 152 x 152 px 的图标，命名为`Icon@2x.png`。

您当前项目文件夹的内容应如下所示：

```kt
Hello World/       name of your project folder
 Icon.png           required for iPhone/iPod/iPad
 Icon@2x.png   required for iPhone/iPod with Retina display
 main.lua

```

为了分发你的应用，App Store 需要一张 1024 x 1024 像素的应用图标。最好先以更高分辨率创建你的图标。参考*Apple iOS Human Interface Guidelines*获取最新的官方 App Store 要求，访问[`developer.apple.com/library/ios/#documentation/userexperience/conceptual/mobilehig/Introduction/Introduction.html`](http://developer.apple.com/library/ios/#documentation/userexperience/conceptual/mobilehig/Introduction/Introduction.html)。

创建应用程序图标是你应用程序名称的视觉表示。一旦你编译了构建，你将能在设备上查看该图标。该图标也是启动你应用程序的图像。

# 为 iOS 创建 Hello World 版本构建

现在我们准备为我们的设备构建 Hello World 应用程序。由于我们已经有了配置文件，从现在开始的构建过程非常简单。在创建设备版本之前，请确保你已连接到互联网。你可以为 Xcode 模拟器或设备测试你的应用。

# 动手操作时间——创建 iOS 版本

按以下步骤在 Corona SDK 中创建一个新的 iOS 版本：

1.  打开 Corona 模拟器并选择**打开**。

1.  导航至你的 Hello World 应用程序，并选择你的`main.lua`文件。

1.  当应用程序在模拟器中启动后，请导航至 Corona 模拟器的菜单栏，选择**文件** | **构建** | **iOS**，或者在你的键盘上按*Command* + *B*。以下对话框将会出现：![动手操作时间——创建 iOS 版本](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_25.jpg)

1.  在**应用名称**字段中为你的应用创建一个名称。我们可以保持名称为`Hello World`。在**版本**字段中，保持数字为`1.0`。为了在 Xcode 模拟器中测试应用，从**构建为**下拉菜单中选择**Xcode Simulator**。如果你想为设备构建，选择**Device**以构建应用包。接下来，从**支持设备**下拉菜单中选择目标设备（iPhone 或 iPad）。从**代码签名标识**下拉菜单中选择你为特定设备创建的配置文件。它与 Apple 开发者网站上 iOS Provisioning Portal 中的**Profile Name**相同。在**保存到文件夹**部分，点击**浏览**并选择你希望保存应用的位置。

    如果对话框中的所有信息都已确认，请点击**构建**按钮。

### 提示

将你的应用程序设置为保存到桌面会更加方便；这样容易找到。

## *刚才发生了什么？*

恭喜你！现在你已经创建了可以上传到设备的第一款 iOS 应用程序文件。随着你开始开发用于分发的应用程序，你将希望创建应用程序的新版本，以便跟踪每次新构建所做的更改。你的所有信息从你的供应配置文件在 iOS 供应门户中创建，并应用于构建。Corona 编译完构建后，应用程序应该位于你保存它的文件夹中。

# 行动时间 – 在你的 iOS 设备上加载应用程序

选择你创建的 Hello World 构建版本，并选择 iTunes 或 Xcode 将你的应用程序加载到 iOS 设备上。它们可以用来传输应用程序文件。

如果使用 iTunes，将你的构建版本拖到 iTunes 资料库中，然后像以下屏幕截图所示正常同步你的设备：

![行动时间 – 在你的 iOS 设备上加载应用程序](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_26.jpg)

将应用程序安装到设备上的另一种方式是使用 Xcode，因为它提供了一种方便的方法来安装 iOS 设备应用程序。执行以下步骤：

1.  连接设备后，通过菜单栏的 **窗口** | **Organizer** 打开 Xcode 的 **Organizer**，然后在左侧的 **设备** 列表中找到你的连接设备。

1.  如果建立了正确的连接，你会看到一个绿色指示灯。如果几分钟之后变成黄色，尝试关闭设备然后再打开，或者断开设备连接并重新连接。这通常可以建立正确的连接。![行动时间 – 在你的 iOS 设备上加载应用程序](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_27.jpg)

1.  只需将你的构建文件拖放到 **Organizer** 窗口的 **应用程序** 区域，它就会自动安装到你的设备上。

## *刚才发生了什么？*

我们刚刚学习了两种将应用程序构建加载到 iOS 设备上的不同方法：使用 iTunes 和使用 Xcode。

使用 iTunes 可以轻松实现拖放功能到你的资料库，并且只要设备同步，就可以传输构建的内容。

Xcode 方法可能是将构建加载到设备上最简单且最常见的方式。只要你的设备在 Organizer 中正确连接并准备好使用，你只需将构建拖放到应用程序中，它就会自动加载。

# 在 Android 设备上测试我们的应用程序

在 Android 设备上创建和测试构建版本不需要像苹果为 iOS 设备那样需要开发者账户。为 Android 构建所需的唯一工具是 PC 或 Mac、Corona SDK、安装的 JDK6 和一个 Android 设备。如果你打算将应用程序提交到 Google Play 商店，你需要注册成为 Google Play 开发者，注册地址为 [`play.google.com/apps/publish/signup/`](https://play.google.com/apps/publish/signup/)。如果你想在 Google Play 商店上发布软件，需要支付一次性的 25 美元注册费。

# 为 Android 创建 Hello World 构建版本

构建我们的 Hello World 应用程序相当简单，因为我们不需要为调试构建创建唯一的密钥库或密钥别名。当你准备将应用程序提交到 Google Play 商店时，你需要创建一个发布构建并生成自己的私钥来签名你的应用。我们将在本书的后面详细讨论发布构建和私钥。

# 动手操作——创建一个 Android 构建

按照以下步骤在 Corona SDK 中创建一个新的 Android 构建：

1.  启动 Corona 模拟器，并选择**模拟器**。

1.  导航到你的 Hello World 应用程序，并选择你的`main.lua`文件。

1.  当你的应用程序在模拟器中运行时，转到**Corona Simulator**菜单栏，然后导航至**文件** | **构建为** | **Android**（Windows）/在键盘上按*Shift* + *Command* + *B*（Mac）。以下对话框将出现：![动手操作——创建一个 Android 构建](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_31.jpg)

1.  在**应用程序名称**字段中为你的应用创建一个名称。我们可以保持相同的名称，即**Hello World**。在**版本代码**字段中，如果默认数字不是 1，则将其设置为**1**。这个特定的字段必须始终是一个整数，并且对用户不可见。在**版本名称**字段中，保持数字为**1.0**。这个属性是显示给用户的字符串。在**包**字段中，你需要指定一个使用传统 Java 方案的名称，这基本上是你的域名反转格式；例如，**com.mycompany.app.helloworld**可以作为包名称。**项目路径**显示你的项目文件夹的位置。**最低 SDK 版本**目前支持运行在 ArmV7 处理器上的 Android 2.3.3 及更新设备。在**目标应用商店**下拉菜单中，默认商店可以保持为 Google Play。在**密钥库**字段中，你将使用 Corona 提供的`Debug`密钥库来签名你的构建。在**密钥别名**字段中，如果尚未选择，请从下拉菜单中选择`androiddebugkey`。在**保存到文件夹**部分，点击**浏览**并选择你希望保存应用程序的位置。

1.  如果对话框中的所有信息都已确认，请点击**构建**按钮。

### 提示

有关 Java 包名称的更多信息，请参阅 Java 文档中关于*唯一包名称*的部分，链接为：[`java.sun.com/docs/books/jls/third_edition/html/packages.html#40169`](http://java.sun.com/docs/books/jls/third_edition/html/packages.html#40169)。

## *刚才发生了什么？*

你已经创建了你的第一个 Android 构建！看看这有多简单？由于 Corona SDK 已经在引擎中提供了`Debug`密钥库和`androiddebugkey`密钥别名，所以大部分签名工作已经为你完成。你唯一需要做的是填写应用程序的构建信息，然后点击**构建**按钮来创建一个调试构建。你的 Hello World 应用程序将保存为`.apk`文件，保存在你指定的位置。文件名将显示为`Hello World.apk`。

# 动手时间——在 Android 设备上加载应用程序

有多种方法可以将你的 Hello World 构建加载到 Android 设备上，这些方法并不需要你下载 Android SDK。以下是一些简单的方法。

一个方便的方法是通过 Dropbox。你可以在[`www.dropbox.com/`](https://www.dropbox.com/)创建一个账户。Dropbox 是一个免费服务，允许你在 PC/Mac 和移动设备上上传/下载文件。以下是通过 Dropbox 加载 Hello World 构建的步骤：

1.  下载 Dropbox 安装程序，并在你的电脑上安装它。同时，在设备上从 Google Play 商店（也是免费的）下载移动应用并安装。

1.  在你的电脑和移动设备上登录你的 Dropbox 账户。从电脑上，上传你的`Hello World.apk`文件。

1.  上传完成后，在设备上打开 Dropbox 应用，选择你的`Hello World.apk`文件。你将看到一个询问你是否要安装该应用程序的屏幕。选择**安装**按钮。假设它安装正确，另一个屏幕将出现，显示**应用程序已安装**，你可以通过按**打开**按钮来启动你的 Hello World 应用。

将`.apk`文件上传到设备上的另一种方法是，通过 USB 接口将其传输到 SD 卡。如果你的设备没有配备某种文件管理应用程序，你可以从 Google Play 商店下载一个很好的 ASTRO 文件管理器，它的下载地址是[`play.google.com/store/apps/details?id=com.metago.astro`](https://play.google.com/store/apps/details?id=com.metago.astro)。你总是可以通过设备上的 Google Play 应用正常搜索前面提到的应用程序或类似的 apk 安装器。要将`.apk`文件传输到 SD 卡，请执行以下步骤：

1.  在设备的**设置**中，选择**应用程序**，然后选择**开发**。如果 USB 调试模式未激活，请点击**USB 调试**。

1.  回到前几屏的**应用程序**部分。如果**未知来源**尚未激活，请启用它。这将允许你安装任何非市场应用程序（即调试版本）。设置完毕后，选择设备上的主页按钮。

1.  使用 USB 电缆将设备连接到电脑。你会看到一个新通知，一个新的驱动器已经连接到你的 PC 或 Mac。访问 SD 驱动器并创建一个新文件夹。给你的 Android 构建容易识别的名字。将 `Hello World.apk` 文件从桌面拖放到文件夹中。

1.  从桌面上弹出驱动器并断开设备与 USB 电缆的连接。启动 ASTRO 文件管理器或使用你在 Google Play 商店下载的任何应用。在 ASTRO 中，选择**文件管理器**，找到你添加到 SD 卡的文件夹并选择它。你会看到你的 `Hello World.apk` 文件。选择该文件，会出现一个提示询问你是否安装它。选择**安装**按钮，你应该会在设备的**应用**文件夹中看到你的 Hello World 应用程序。![行动时间——在 Android 设备上加载应用程序](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_01_32.jpg)

最简单的方法之一是通过 Gmail。如果你还没有 Gmail 账户，可以在[`mail.google.com/`](https://mail.google.com/)创建一个。按照以下步骤在 Gmail 账户上发送 `.apk` 文件：

1.  登录你的账户，撰写一封新邮件，并将你的 `Hello World.apk` 文件作为附件添加到消息中。

1.  将消息的收件人地址设为你自己的电子邮件地址并发送。

1.  在你的 Android 设备上，确保你的电子邮件账户已经关联。一收到消息，就打开邮件。你将有机会在设备上安装该应用程序。将会有一个**安装**按钮或类似的显示。

## *刚才发生了什么？*

我们刚刚学习了几种将 `.apk` 文件加载到 Android 设备上的方法。前面的方法是最简单的方式之一，可以快速加载应用程序而不会遇到任何问题。

使用文件管理器方法可以轻松访问你的 `.apk` 文件，无需任何运营商数据或 Wi-Fi 连接。使用与你的设备兼容的 USB 电缆并将其连接到电脑是一个简单的拖放过程。

一旦在电脑和移动设备上设置好，Dropbox 方法是最方便的。你需要做的就是将 `.apk` 文件拖放到你的账户文件夹中，任何安装了 Dropbox 应用程序的设备都可以立即访问。你也可以通过下载链接分享你的文件，这也是 Dropbox 提供的另一个很棒的功能。

如果你不想在设备和电脑上下载任何文件管理器或其他程序，设置一个 Gmail 账户并将你的 `.apk` 文件作为附件发送给自己很简单。唯一要记住的是，你不能在 Gmail 中发送超过 25 MB 的附件。

## 小测验——了解 Corona

Q1. 关于使用 Corona 模拟器，以下哪个是正确的？

1.  你需要一个 `main.lua` 文件来启动你的应用程序。

1.  Corona SDK 只能在 Mac OS X 上运行。

1.  Corona 终端不会启动模拟器。

1.  以上都不是。

Q2. 在 iPhone 开发者计划中，你可以使用多少个 iOS 设备进行开发？

1.  `50`。

1.  `75`。

1.  `5`。

1.  `100`。

Q3. 在 Corona SDK 中为 Android 构建时，版本代码必须是什么？

1.  一个字符串。

1.  一个整数。

1.  它必须遵循 Java 方案格式。

1.  以上都不是。

# 概要

在本章中，我们介绍了一些开始使用 Corona SDK 开发应用程序所必需的工具。无论你是在 Mac OS X 还是 Microsoft Windows 上工作，你都会注意到在两个操作系统上工作的相似性，以及运行 Corona SDK 是多么简单。

为了进一步熟悉 Corona，尝试执行以下操作：

+   花时间查看 Corona 提供的示例代码，以了解 SDK 的功能。

+   请随意修改任何示例代码，以更好地理解 Lua 编程。

+   无论你是在 iOS（如果你是注册的 Apple 开发者）还是 Android 上工作，尝试在你的设备上安装任何示例代码，看看应用程序在模拟器环境之外是如何工作的。

+   访问 Corona 实验室论坛 [`forums.coronalabs.com/`](http://forums.coronalabs.com/)，浏览一下 Corona SDK 开发者和工作人员关于 Corona 开发的最新讨论。

既然你已经了解了如何在 Corona 中显示对象的过程，我们将能够深入探讨其他有助于创建可操作的移动游戏的函数。

在下一章中，我们将进一步了解 Lua 编程语言的细节，你将学习到类似于 Corona 示例代码的简单编程技巧。你将对 Lua 语法有更深入的理解，并注意到与其他编程语言相比，它是多么快速和容易学习。那么，让我们开始吧！


# 第二章：Lua 快速入门与 Corona 框架

> *Lua 是用于在 Corona SDK 上进行开发的编程语言。到目前为止，你已经学会了如何使用主要资源来运行 SDK 和其他开发工具，在移动设备上创建应用程序。现在我们已经涉足编写几行代码让程序运行，让我们深入到基础中，这将使你更好地了解 Lua 的能力。*

在本章中，你将学习如何：

+   在脚本中应用变量

+   使用数据结构来构建表

+   使用显示对象进行操作

+   使用对象方法和参数实现函数

+   优化你的工作流程

那么让我们开始吧。

# Lua 来拯救

Lua 是游戏编程的行业标准。它类似于 JavaScript 和 Flash 的 ActionScript。任何在这些语言中做过脚本编写的人几乎可以立即过渡到 Lua。

Lua 在创建各种应用程序和游戏中都很有用。由于它易于嵌入、执行速度快和学习曲线平缓，许多游戏程序员发现 Lua 是一种方便的脚本语言。《魔兽世界》中到处都在使用它。它还被 Electronic Arts、Rovio、ngmoco 和 Tapulous 在如《愤怒的小鸟》、《敲击复仇》、《餐厅大亨》等游戏中使用。

有关 Lua 的更多信息，请参考[`www.lua.org`](http://www.lua.org)。

# 有价值的变量

与许多脚本语言一样，Lua 也有变量。你可以将变量视为存储值的东西。当你在变量中应用一个值时，你可以使用相同的变量名来引用它。

一个应用程序由注释、块、语句和变量组成。**注释**永远不会被处理，但它被包含在内是为了解释一个语句或块的目的。**块**是一组语句的集合。**语句**提供关于需要执行哪些操作和计算的指令；**变量**存储这些计算的结果。在变量中设置值称为**赋值**。

Lua 使用三种类型的变量，如下所示：

+   全局变量

+   局部变量

+   表字段（属性）

变量占用内存空间，这在各种移动设备上可能是有限的。当一个变量不再需要时，最好将其值设置为 nil，这样它可以被快速清理。

## 全局变量

全局变量可以在每个作用域中访问，并且可以从任何地方修改。术语“作用域”用于描述一组变量可访问的区域。你不需要声明全局变量。在你为其赋值时它就会被创建：

```kt
myVariable = 10
print( myVariable ) -- prints the number 10
```

## 局部变量

局部变量从局部作用域访问，通常从函数或代码块中调用。当我们创建一个块时，我们正在创建一个变量可以存在的作用域或一系列按顺序执行的语句。当引用一个变量时，Lua 必须找到该变量。局部化变量有助于加快查找过程，提高代码性能。使用 local 语句，它声明了一个局部变量：

```kt
local i = 5 -- local variable
```

下面的代码行展示了如何在块中声明一个局部变量：

```kt
x = 10    -- global 'x' variable
local i = 1

while i <= 10 do
   local x = i * 2  -- a local 'x' variable for the while block
   print( x )       -- 2, 4, 6, 8, 10 ... 20
   i = i + 1
end

print( x )  -- prints 10 from global x
```

## 表字段（属性）

表字段是通过索引唯一访问的一组变量。数组可以用数字和字符串索引，或者任何属于 Lua 的值，除了 `nil`。你使用整数或字符串索引到数组来为字段赋值。当索引是字符串时，该字段称为属性。所有属性都可以使用点操作符（`x.y`）或字符串（`x["y"]`）来索引表。结果是一样的：

```kt
x = { y="Monday" }  -- create table 
print( x.y )  -- "Monday"
z = "Tuesday"    -- assign a new value to property "Tuesday"
print( z )  -- "Tuesday"
x.z = 20  -- create a new property 
print( x.z )  -- 20
print( x["z"] )  -- 20
```

关于表的更多信息将在后面的*表*一节中讨论。

你可能已经注意到，在前面的示例代码中的某些行中有额外的文本。这些就是你所称的注释。注释以双连字符 `--` 开头，但不能放在字符串内部。它们一直持续到行尾。块注释也是可用的。注释掉一个块的一个常见技巧是用 `--[[` 和 `]]` 包围它。

下面是如何注释一行代码的示例：

```kt
a = 2
--print(a)    -- 2
```

这是一个块注释的示例：

```kt
--[[
k = 50
print(k)    -- 50
--]]
```

# 赋值约定

变量命名有规则。变量以字母或下划线开头，除了字母、下划线或数字外不能包含其他任何字符。变量名还不能是 Lua 的以下保留字：

+   `and`

+   `break`

+   `do`

+   `else`

+   `elseif`

+   `end`

+   `false`

+   `for`

+   `function`

+   `if`

+   `in`

+   `local`

+   `nil`

+   `not`

+   `or`

+   `repeat`

+   `return`

+   `then`

+   `true`

+   `until`

+   `while`

以下是有效的变量：

+   x

+   X

+   ABC

+   _abc

+   test_01

+   myGroup

以下是不合法的变量：

+   `function`

+   my-variable

+   123

### 注意

Lua 也是一个大小写敏感的语言。例如，`else` 是一个保留字，但 Else 和 ELSE 是两个不同的有效名称。

# 值的类型

Lua 是一种动态类型的语言。在 Lua 语言中没有定义变量类型。这使得每个值都可以携带自己的类型。

正如你所注意到的，值可以存储在变量中。它们可以操作以生成任何类型的值。这也允许你将参数传递给其他函数，并将它们作为结果返回。

你将处理的值的基本类型如下：

+   **Nil**：这是唯一一个值为 `nil` 的类型。任何未初始化的变量都有 `nil` 作为其值。像全局变量一样，默认是 `nil`，可以被赋值为 `nil` 以删除它。

+   **布尔值**：这种类型有两个值：`false` 和 `true`。你会注意到，条件表达式将 `false` 和 `nil` 视为假，其他任何值视为 `true`。

+   **数字**：这些代表实数（双精度浮点数）。

+   **字符串**：这是一系列字符。允许 8 位字符和嵌入的零。

+   **表**：这些是 Lua 中的数据结构。它们通过关联数组实现，这是一个不仅可以使用数字索引，还可以使用字符串或其他任何值（除了`nil`）索引的数组（关于这一点，本章后面会详细介绍）。

+   **函数**：这些被称为 Lua 中的一等值。通常，函数可以存储在变量中，作为参数传递给其他函数，并作为结果返回。

# 行动时间——使用代码块打印值

让我们试一试，看看 Lua 语言有多强大。我们开始了解变量是如何工作的，以及当你给它们赋值时会发生什么。如果你有一个带有多个值的变量会怎样？Lua 如何区分它们？我们将使用 Corona 终端，这样我们就可以在终端框中看到输出的值。在这个过程中，你还会学习到其他编程技术。我们在这项练习中也会提到代码块。Lua 中执行单元被称为**代码块**。代码块是按顺序执行的一块代码。按照以下步骤开始学习 Lua：

如果你记得，在前面的章节中，你学习了如何为 Hello World 应用程序创建自己的项目文件夹和`main.lua`文件。

1.  在你的桌面上创建一个新的项目文件夹，并将其命名为`Variables`。

1.  打开你喜欢的文本编辑器，并将其保存为`Variables`项目文件夹中的`main.lua`。

1.  创建以下变量：

    ```kt
    local x = 10 -- Local to the chunk
    local i = 1  -- Local to the chunk        
    ```

1.  在`while`循环中加入以下内容：

    ```kt
    while (i<=x) do
      local x = i  -- Local to the "do" body
      print(x)       -- Will print out numbers 1 through 10 
      i = i + 1
    end
    ```

1.  创建一个表示另一个局部体的`if`语句：

    ```kt
    if i < 20 then
      local x          -- Local to the "then" body
      x = 20
      print(x + 5)  -- 25
    else
      print(x)         -- This line will never execute since the above "then" body is already true
    end

    print(x)  -- 10
    ```

1.  保存你的脚本。

1.  启动 Corona 终端。确保你看到 Corona SDK 屏幕和终端窗口弹出。

1.  导航到`Variables`项目文件夹，并在模拟器中打开你的`main.lua`文件。你会注意到模拟器中的设备是空白的，但如果你查看终端窗口，会看到代码输出的结果，如下所示：

    ```kt
    1
    2
    3
    4
    5
    6
    7
    8
    9
    10
    25
    10

    ```

## *刚才发生了什么？*

创建的前两个变量是每个代码块外的局部变量。注意在`while`循环的开始部分，`i <= x`指的是第 1 行和第 2 行的变量。`while`循环内的`local x = i`语句只对`do`体局部有效，并不等同于`local x = 10`。`while`循环运行 10 次，每次递增一并输出值。

`if`语句会对比`i < 20`，此时`i`等于 11，并使用另一个在`then`体内的局部变量`local x`。因为语句为真，`x`等于 20 并输出`x + 5`的值，即`25`。

最后一行代码 `print(x)` 没有附加到 `while` 循环或 `if` 语句中的任何代码块。因此，它指的是 `local x = 10` 并在终端窗口输出 10 的值。这可能看起来有些混淆，但理解 Lua 中局部变量和全局变量如何工作是很重要的。

# 表达式

**表达式**是代表值的实体。它可以包括数字常量、字符串、变量名、一元和二元运算以及函数调用。

## 算术运算符

`+`、`-`、`*`、`/`、`%` 和 `^` 被称为算术运算符。

这是一个二元算术运算符的例子：

```kt
t = 2*(2-5.5)/13+26
print(t)  -- 25.461538461538
```

这是一个模运算（除法余数）运算符的例子：

```kt
m = 18%4
print(m)  -- 2
```

运算符强大之处的一个例子如下：

```kt
n = 7²
print(n)  -- 49
```

## 关系运算符

关系运算符总是返回 false 或 true，并询问是或否的问题。关系运算符有 `<`、`>`、`<=`、`>=`、`==`、`~=`。

`==` 运算符用于测试相等性，而 `~=` 运算符用于测试不等性。如果值类型不同，结果为假。否则，Lua 根据类型比较值。数字和字符串以常规方式比较。只要两个这样的值被认为是相等的，表和函数就通过引用比较，只有当它们是同一个对象时才相等。当创建新对象时，新对象与之前存在的对象是不同的。

这里有一些关系运算符的例子。它们将显示布尔结果，不能与字符串拼接：

```kt
print(0 > 1)  --false
print(4 > 2)  --true
print(1 >= 1)  --true
print(1 >= 1.5)  --false
print(0 == 0)  --true
print(3 == 2)  --false
print(2 ~= 2)  -- false
print(0 ~= 2)  -- true
```

## 逻辑运算符

Lua 中的逻辑运算符有 `and`、`or` 和 `not`。所有逻辑运算符将 `false` 和 `nil` 视为假，其他任何值视为真。

`and` 运算符如果其值为 `false` 或 `nil`，则返回第一个参数；否则，返回第二个参数。`or` 运算符如果其值不是 `nil` 和 `false`，则返回第一个参数；否则，返回第二个参数。`and` 和 `or` 都使用短路评估；这意味着只有必要时才会评估第二个操作数。以下是一些逻辑运算符的例子：

```kt
print(10 and 20)      -- 20
print(nil and 1)      -- nil
print(false and 1)    -- false
print(10 or 20)       -- 10
print(false or 1)     -- 1
```

`not` 运算符总是返回 true 或 false：

```kt
print(not nil)      -- true
print(not true)    -- false
print(not 2)        -- false
```

## 连接

Lua 中的字符串连接运算符由两个点表示，即"`..`"。它将两个值作为操作数并将它们拼接在一起。如果其操作数中的任何一个为数字，则也会被转换成字符串。以下是一些连接运算符的例子：

```kt
print("Hello " .. "World")  -- Hello World

myString = "Hello"
print(myString .. " World")   -- Hello World
```

## 长度运算符

`#` 长度运算符用于测量字符串的长度或表的大小。字符串的长度就是它包含的字符数。一个字符被认为是一个字节。以下是一些长度运算符的例子：

```kt
print(#"*") --1
print(#"\n") --1
print(#"hello") --5
myName = "Jane Doe"
print(#myName) --8
```

## 优先级

下表显示了 Lua 中的运算符优先级，从最高到最低优先级：

+   `^`

+   `not`、`#`、`-`（一元）

+   `*`、`/`

+   `+`、`-`

+   `..`

+   `<`、`>`、`<=`、`>=`、`~=`、`==`

+   `and`

+   `or`

所有的二元运算符都是左结合的，除了`^`指数和`..`连接运算符，它们是右结合的。你可以使用括号来改变表达式的优先级。

在两个相同优先级的操作数争夺操作数的情况下，操作数属于左侧的操作符：

```kt
print(5 + 4 – 2) -- This returns the number 7
```

前一个表达式显示了加法和减法运算符，它们的优先级相等。第二个元素（数字`4`）属于加法运算符，因此表达式从数学上评估如下：

```kt
print((5 + 4) – 2) -- This returns the number 7
```

让我们关注基于优先级的优先规则。以下是一个示例：

```kt
print (7 + 3 * 9) -- This returns the number 34
```

一个没有经验的程序员可能会认为，如果从前到后评估，前一个示例的值是 90。正确的值是 34，因为乘法比加法的优先级高，所以它首先执行。为同一表达式添加括号将使其更容易阅读：

```kt
print (7 + (3 * 9)) -- This returns the number 34
```

# 字符串

在本章前面，你看到了一些使用字符序列的代码示例。这些字符序列称为**字符串**。字符串可以包含任何字符，包括数值。

## 引用字符串

有三种方式来引用字符串：使用双引号、使用单引号以及使用方括号。

### 注意

在引用字符串时，请确保代码中只使用直引号，而不是弯引号；否则，它将无法编译。

双引号字符`"`标记字符串的开始和结束。以下是一个示例：

```kt
print("This is my string.")  -- This is my string.
```

你也可以使用单引号字符`'`来引用字符串。单引号与双引号的作用相同，不同之处在于单引号字符串可以包含双引号。以下是一个示例：

```kt
print('This is another string.')  -- This is another string.

print('She said, "Hello!" ')  -- She said, "Hello!"
```

最后，使用一对方括号也可以引用字符串。它们主要用于当双引号或单引号不能使用时的字符串。没有很多这样的情况，但它们可以完成任务：

```kt
print([[Is it 'this' or "that?"]]) -- Is it 'this' or "that?"
```

# 动手时间——让我们充分使用字符串

我们开始熟悉几段代码以及它们之间的相互作用。让我们看看当我们添加一些使用字符串的表达式时会发生什么，以及它们与在终端中打印的普通字符串有何不同：

1.  在你的桌面上创建一个新的项目文件夹，并将其命名为`Working With Strings`。

1.  在你的文本编辑器中创建一个新的`main.lua`文件，并将其保存到你的文件夹中。

1.  输入以下几行（代码中不要包含行号，它们仅用于行参考）：

    ```kt
    1 print("This is a string!") -- This is a string!
    2 print("15" + 1) -- Returns the value 16
    ```

1.  添加以下变量。注意它使用了相同的变量名：

    ```kt
    3 myVar = 28
    4 print(myVar)  -- Returns 28

    5 myVar = "twenty-eight"
    6 print(myVar) -- Returns twenty-eight
    ```

1.  让我们添加一些带有字符串值的变量，并使用不同的运算符进行比较：

    ```kt
    7 Name1, Phone = "John Doe", "123-456-7890"
    8 Name2 = "John Doe"

    9 print(Name1, Phone) -- John Doe  123-456-7890
    10 print(Name1 == Phone) -- false
    11 print(Name1 <= Phone) -- false
    12 print(Name1 == Name2) -- true
    ```

1.  保存你的脚本并在 Corona 中启动你的项目。在终端窗口中观察结果：

    ```kt
    This is a string!
    16
    28
    twenty-eight
    John Doe  123-456-7890
    false
    false
    true

    ```

## *刚才发生了什么？*

你可以看到第 1 行只是一个普通的字符串，字符被打印出来。在第 2 行，注意数字 `15` 在字符串中，然后与字符串外的数字 `1` 相加。Lua 在运行时提供数字和字符串之间的自动转换。对字符串应用数值运算会尝试将字符串转换为数字。

在使用变量时，你可以使用同一个变量，并让它们在不同时间包含字符串和数字，如第 3 行和第 5 行（`myVar = 28` 和 `myVar = "twenty-eight"`）。

在最后一段代码（第 7-12 行）中，我们使用关系运算符比较了不同的变量名。首先，我们打印了 `Name1` 和 `Phone` 的字符串。接下来的行比较了 `Name1`、`Name2` 和 `Phone`。当两个字符串具有完全相同的字符顺序时，它们被认为是相同的字符串并且相等。当你查看 `print(Name1 == Phone)` 和 `print(Name1 <= Phone)` 时，这些语句返回 `false`，因为它们是根据 ASCII 顺序。数字在字母之前，比较时被视为较小。在 `print(Name1 == Name2)` 中，两个变量包含相同的字符，因此它返回 `true`。

## 动手实践——进一步操作字符串

字符串很容易处理，因为它们只是字符序列。尝试根据前面的示例进行修改，创建你自己的表达式。

1.  创建一些带有数值的变量，再创建一组带有数值字符串的变量。使用关系运算符比较这些值，然后将结果打印出来。

1.  使用连接运算符，将几个字符串或数字组合在一起，并使它们均匀地分隔开。在终端窗口中打印结果。

# 表

表是 Lua 中特有的数据结构。它们可以表示数组、列表、集合、记录、图等。Lua 中的表类似于关联数组。关联数组可以使用任何类型的值进行索引，不仅仅是数字。表高效地实现所有这些结构。例如，可以通过使用整数索引表来实现数组。数组没有固定的大小，但会根据需要增长。初始化数组时，其大小是间接定义的。

这是一个如何构建表的例子：

```kt
1 a = {}    -- create a table with reference to "a"
2 b = "y"
3 a[b] = 10    -- new entry, with key="y" and value=10
4 a[20] = "Monday"  -- new entry, with key=20 and value="Monday"
5 print(a["y"])    -- 10
6 b = 20
7 print(a[b])     -- "Monday"
8 c = "hello"     -- new value assigned to "hello" property
9 print( c )    -- "hello"
```

你会注意到第 5 行中的 `a["y"]` 正在从第 3 行索引值。在第 7 行，`a[b]` 使用变量 `b` 的新值并将数值 `20` 索引到字符串 `"Monday"` 上。最后一行 `c` 与之前的变量无关，其唯一的值是字符串 `"hello"`。

## 将表作为数组传递

表的键可以是连续的整数，从 1 开始。它们可以被制作成数组（或列表）：

```kt
colors =  {
[1] = "Green", 
[2] = "Blue", 
[3] = "Yellow", 
[4] = "Orange", 
[5] = "Red"
}
print(colors[4]) -- Orange
```

下面展示了一种更快、更方便的编写表构造函数来构建数组的方法，该方法不需要写出每个整数键：

```kt
colors = {"Green", "Blue", "Yellow", "Orange", "Red"}
print(colors[4]) -- Orange
```

## 更改表中的内容

在处理表时，你可以修改或删除表中已有的值，也可以添加新值。这可以通过赋值语句完成。以下示例创建了一个包含三个人及其最喜欢的饮料类型的表。你可以进行赋值以更改一个人的饮料，向表中添加新的人员-饮料配对，以及移除现有的人员-饮料配对：

```kt
drinks = {Jim = "orange juice", Matt = "soda", Jackie = "milk"}
drinks.Jackie = "lemonade" -- A change.
drinks.Anne = "water" -- An addition.
drinks.Jim = nil -- A removal.

print(drinks.Jackie, drinks.Anne, drinks.Matt, drinks.Jim)
-- lemonade water soda nil
```

`drinks.Jackie = "lemonade"`覆盖了`drinks.Jackie = "milk"`的原始值。

`drinks.Anne = "water"`这行代码为表格添加了一个新的键值对。在这行代码之前，`drinks.Anne`的值是 nil。

由于没有对其进行修改，`drinks.Matt = "soda"`的值保持不变。

`drinks.Jim = nil`用`nil`覆盖了`drinks.Jim = "orange juice"`的原始值。它从表格中移除了`Jim`键。

## 填充表

填充表的方法是从一个空表开始，逐一添加内容。我们将使用构造函数，这些是创建和初始化表的表达式。最简单的构造函数是空构造函数，`{}`：

```kt
myNumbers = {} -- Empty table constructor

for i = 1, 5 do
  myNumbers[i] = i 
end

for i = 1, 5 do
print("This is number " .. myNumbers[i])
end
```

以下是终端的输出结果：

```kt
--This is number 1
--This is number 2
--This is number 3
--This is number 4
--This is number 5

```

前面的示例表明`myNumbers = {}`是一个空表构造器。创建了一个`for`循环，并调用`myNumbers[i]`五次，从数字 1 开始。每次调用时，它都会增加 1，然后被打印出来。

# 对象

表和函数是对象；变量实际上并不包含这些值，只包含对它们的引用。表也用于所谓的面向对象编程。可以收集变量和操作这些变量的方法到对象中。这样的值称为**对象**，其函数称为**方法**。在 Corona 中，我们将更多地关注显示对象，因为它们对游戏开发至关重要。

## 显示对象

屏幕上显示的任何内容都是由显示对象制成的。在 Corona 中，你在模拟器中看到的资源都是显示对象的实例。你可能已经看到过形状、图像和文本，这些都是显示对象的形式。当你创建这些对象时，你将能够对它们进行动画处理，将它们变成背景，使用触摸事件与它们互动，等等。

显示对象是通过调用一个称为工厂函数的函数来创建的。每种类型的显示对象都有一个特定的工厂函数。例如，`display.newCircle()`创建一个矢量对象。

显示对象的实例行为类似于 Lua 表。这使得你可以在不与系统分配的属性和方法名称发生冲突的情况下，向对象添加自己的属性。

## 显示属性

点运算符用于访问属性。显示对象共享以下属性：

+   `object.alpha`：这是对象的透明度。0 表示完全透明，1.0 表示不透明。默认值为 1.0。

+   `object.height`：这是在本地坐标系中的高度。

+   `object.isVisible`：这个属性控制对象是否在屏幕上可见。True 表示可见，false 表示不可见。默认值为 true。

+   `object.isHitTestable`：即使对象不可见，这也允许对象继续接收击中事件。如果为 true，无论可见性如何，对象都会接收击中事件；如果为 false，则只有可见对象会发送事件。默认为 false。

+   `object.parent`：这是一个只读属性，返回对象的父对象。

+   `object.rotation`：这是当前的旋转角度（以度为单位）。可以是负数或正数。默认值为 0。

+   `object.contentBounds`：这是一个表格，包含屏幕坐标中的`xMin`、`xMax`、`yMin`和`yMax`属性。它通常用于将组中的对象映射到屏幕坐标。

+   `object.contentHeight`：这是屏幕坐标中的高度。

+   `object.contentWidth`：这是屏幕坐标中的宽度。

+   `object.width`：这是局部坐标中的宽度。

+   `object.x`：这指定了对象相对于父对象的*x*位置（在局部坐标中）——确切地说是相对于父对象的原点。它提供了对象的参考点相对于父对象的*x*位置。改变这个值将会在*x*方向移动对象。

+   `object.anchorX`：这指定了对象的对齐位置相对于父对象原点的*x*位置。锚点范围从 0.0 到 1.0。默认情况下，新对象的锚点设置为 0.5。

+   `object.xScale`：获取或设置*x*缩放因子。值为 0.5 会将对象在*x*方向缩放到 50%。缩放围绕对象的参考点进行。大多数显示对象的默认参考点是中心。

+   `object.y`：这指定了对象相对于父对象的*y*位置（在局部坐标中）——确切地说是相对于父对象的原点。

+   `object.anchorY`：这指定了对象的对齐位置相对于父对象原点的*y*位置。锚点范围从 0.0 到 1.0。默认情况下，新对象的锚点设置为 0.5。

+   `object.yScale`：获取或设置*y*缩放因子。值为 0.5 会将对象在*y*方向缩放到 50%。缩放围绕对象的锚点进行。大多数显示对象的默认参考点是中心。

## 对象方法

Corona 可以创建显示对象，将对象方法作为属性存储。有两种方法可以实现：使用点操作符（"."）或使用冒号操作符（":"）。这两种方式都是创建对象方法的有效方式。

这是点操作符的一个例子：

```kt
object = display.newRect(110, 100, 50, 50)
object.setFillColor(1.0, 1.0, 1.0)
object.translate( object, 10, 10 )
```

这是冒号操作符的一个例子：

```kt
object = display.newRect(110, 100, 50, 50)
object:setFillColor(1.0, 1.0, 1.0)
object:translate( 10, 10 )
```

使用点操作符调用对象方法的第一个参数会传递给对象。冒号操作符方法只是创建函数的快捷方式，涉及到的输入更少。

显示对象共享以下方法：

+   `object:rotate(deltaAngle)`或`object.rotate(object, deltaAngle)`：这实际上将`deltaAngle`（以度为单位）添加到当前的旋转属性中。

+   `object:scale(sx, sy)` 或 `object.scale(object, sx, sy)`：这有效地使用 `sx` 和 `sy` 分别乘以 `xScale` 和 `yScale` 属性。如果当前的 `xScale` 和 `yScale` 值为 0.5，而 `sx` 和 `sy` 也是 0.5，那么结果的比例将是 `xScale` 和 `yScale` 的 0.25。这将对象从原始大小的 50%缩放到 25%。

+   `object:translate(deltaX, deltaY)` 或 `object.translate(object, deltaX, deltaY)`：这将有效地将 `deltaX` 和 `deltaY` 分别加到 `x` 和 `y` 属性上。这将把对象从当前位置移动。

+   `object:removeSelf()` 或 `object.removeSelf(object)`：这移除了显示对象并释放其内存，假设没有其他引用它。这相当于在同一个显示对象上调用 `group:remove(IndexOrChild)`，但语法更简单。`removeSelf()` 语法也支持在其他情况下使用，例如在物理中移除物理关节。

# 图像

Corona 应用程序中使用了许多艺术资源图像。你会注意到，位图图像对象是一种显示对象类型。

## 加载图像

使用 `display.newImage(filename [, baseDirectory] [, left, top])`，将返回一个图像对象。图像数据是从你为图像指定的文件名中加载的，并在 `system.ResourceDirectory` 中查找该文件。支持的图像文件类型有 `.png`（仅限 PNG-24 或更高）和 `.jpg` 文件。避免高 `.jpg` 压缩，因为它可能会在设备上加载时间更长。`.png` 文件的质量比 `.jpg` 文件好，用于显示透明图像。`.jpg` 文件不能保存透明图像。

## 图像自动缩放

`display.newImage()` 的默认行为是自动缩放大图像。这是为了节省纹理内存。然而，有时你可能不希望图像自动缩放，参数列表中有一个可选的布尔标志可以手动控制这一点。

要覆盖自动缩放并在其全分辨率下显示图像，请使用可选的 `isFullResolution` 参数。默认情况下，它是 false，但如果你指定为 true，则新图像以其全分辨率加载：

```kt
display.newImage( [parentGroup,] filename [, baseDirectory] [, x, y] [,isFullResolution] )
```

限制和已知问题如下：

+   不支持索引 PNG 图像文件。

+   当前不支持灰度图像；图像必须是 RGB 格式。

+   如果图像大于设备可能的最大纹理尺寸，图像仍将被自动缩放。这通常是 2048 x 2048 像素（iPad）对于较新、速度更快的设备来说会更大。

+   如果你多次重新加载同一图像，后续调用 `display.newImage` 会忽略 `isFullResolution` 参数，并采用第一次传递的值。换句话说，你第一次加载图像文件的方式会影响下一次加载同一文件时的自动缩放设置。这是因为 Corona 通过自动复用已经加载的纹理来节省纹理内存。因此，你可以多次使用相同的图像，而不会消耗额外的纹理内存。

有关 Corona SDK 文档的更多信息可以在 Corona 的官方网站上找到，网址为 [`coronalabs.com`](http://coronalabs.com)。

# 动手操作时间——在屏幕上放置图像

我们终于要进入本章的视觉吸引部分，开始通过图像添加显示对象。现在我们不需要参考终端窗口。因此，让我们专注于模拟器屏幕。我们将通过执行以下步骤来创建一个背景图像和一些美术资源：

1.  首先，在桌面上创建一个新的项目文件夹，并将其命名为 `Display Objects`。

1.  在 `Chapter 2 Resources` 文件夹中，将 `glassbg.png` 和 `moon.png` 图像文件以及 `config.lua` 文件复制到你的 `Display Objects` 项目文件夹中。

1.  启动你的文本编辑器，为当前项目创建一个新的 `main.lua` 文件。

1.  编写以下几行代码：

    ```kt
    local centerX = display.contentCenterX
    local centerY = display.contentCenterY

    local background = display.newImage( "glassbg.png", centerX, centerY, true)
    local image01 = display.newImage( "moon.png", 160, 80 )

    local image02 = display.newImage( "moon.png" )
    image02.x = 160; image02.y = 200

    image03 = display.newImage( "moon.png" )
    image03.x = 160; image03.y = 320
    ```

    背景显示对象应该包含项目文件夹中背景图像的文件名。例如，如果背景图像文件名为 `glassbg.png`，那么你可以像这样显示图像：

    ```kt
    local background = display.newImage( "glassbg.png", centerX, centerY, true)
    ```

    使用 `image02.x = 160; image02.y = 200` 与以下几行代码是等效的：

    ```kt
    image02.x = 160
    image02.y = 200
    ```

    分号（`;`）表示语句的结束，是可选的。它使得在单行中分隔两个或多个语句变得更加容易，也避免了在代码中添加多余的行。

1.  保存你的脚本并在模拟器中启动你的项目。

    ### 注意

    如果你是在 Mac OS X 上使用 Corona SDK，默认设备是 iPhone。如果你是在 Windows 上使用，默认设备是 Droid。

1.  你应该会看到一个背景图像和三个相同的图像显示对象，如下屏幕所示。显示结果将根据你用于模拟的设备而有所不同。![动手操作时间——在屏幕上放置图像](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_02_01.jpg)

`image01`、`image02` 和 `image03` 变量的显示对象应包含 `moon.png` 文件名。代码中的文件名区分大小写，因此请确保你按照项目文件夹中显示的格式准确书写。

## *刚才发生了什么？*

当前，`background` 使用 `contentCenterX` 和 `contentCenterY` 被缩放以适应设备屏幕的高度和宽度。由于没有应用顶部或左侧（*x* 或 *y*）坐标，图像在其本地原点居中。由于我们在显示对象中指定了 `true`，它也被设置为全分辨率。

当你在模拟器中观察`image01`、`image02`和`image03`的位置时，它们实际上是垂直对齐的，尽管`image01`与`image02`/`image03`的脚本样式编写不同。这是因为`image01`的坐标基于显示对象的（左，上）坐标。你可以选择性地指定图像的左上角位于坐标（左，上）；如果你没有提供两个坐标，图像将围绕其本地原点居中。

`image02`和`image03`的位置是从显示对象的本地原点指定的，并通过设备屏幕的*x*和*y*属性的本地值定位。本地原点位于图像的中心；参考点初始化为此点。由于我们没有为`image02`和`image03`应用（左，上）值，因此进一步访问*x*或*y*属性将参考图像的中心。

现在，你可能已经注意到 iPhone 4 的输出看起来很好，但 Droid 的输出显示背景图像以全分辨率显示，而其他对象则位于屏幕下方。我们可以看到我们指定的所有对象都在那里，但缩放比例不对。这是因为每个 iOS 和 Android 设备的屏幕分辨率都不同。iPhone 4 的屏幕分辨率为 640 x 960 像素，而 Droid 的屏幕分辨率为 480 x 854 像素。在一个类型的设备上看起来可能很好，但在另一个设备上可能不会完全相同。别担心，在接下来的几节中，我们将讨论使用一个`config.lua`文件来解决这个问题。

## 尝试英雄——调整显示对象属性

既然你知道如何将图像添加到设备屏幕，尝试测试其他显示属性。尝试以下任何一项：

+   更改`image01`、`image02`和`image03`显示对象的所有*x*和*y*坐标

+   选择任何显示对象并更改其旋转

+   更改单个显示对象的可视性

如果你不确定如何进行上述调整，请参考本章前面提到的显示属性。

# 运行时配置

所有项目文件不仅包含一个`main.lua`文件，还包含根据项目需要而定的其他`.lua`和相关资源。一些 Corona 项目使用`config.lua`文件配置，该文件编译到你的项目中，并在运行时访问。这使得你可以同时指定动态内容缩放、动态内容对齐、动态图像分辨率、帧率控制和抗锯齿，以便在每种类型的设备上显示类似的输出。

## 动态内容缩放

Corona 允许你指定你打算针对的屏幕尺寸。这是通过一个叫做`config.lua`的文件来完成的。你将能够根据设备屏幕尺寸的大小，为你的应用程序缩放资源。

应该使用以下值来缩放内容：

+   `width`（数字）：这是原始目标设备在纵向模式下的屏幕分辨率宽度

+   `height`（数字）：这是原始目标设备在纵向模式下的屏幕分辨率高度。

+   `scale`（字符串）：这是以下值的自动缩放类型：

    +   `letterbox`：这种缩放方式尽可能均匀地放大内容。

    +   `zoomEven`：这种缩放方式均匀地放大内容以填满屏幕，同时保持宽高比。

    +   `zoomStretch`：这种缩放方式非均匀地放大内容以填满屏幕，并会垂直或水平拉伸。

    ### 注意

    `zoomStretch`值在处理 Android 设备缩放时效果很好，因为它们有许多不同的屏幕分辨率。

## 动态内容对齐

默认情况下，动态缩放的内容已经居中。你可能会遇到不希望内容居中的情况。例如 iPhone 3G 和 Droid 具有完全不同的屏幕分辨率。为了使 Droid 上显示的内容与 iPhone 3G 相似，需要调整对齐方式，使内容填满整个屏幕，而不留下任何空白的黑色屏幕空间。对齐方式如下：

+   `xAlign`：这是一个指定*x*方向对齐的字符串。可以使用以下值：

    +   `left`

    +   `center`（默认）

    +   `right`

+   `yAlign`：这是一个指定*y*方向对齐的字符串。可以使用以下值：

    +   `top`

    +   `center`（默认）

    +   `bottom`

## 动态图像分辨率

Corona 允许你为更高分辨率的设备替换更高分辨率的图片版本，而无需更改布局代码。如果要在具有不同屏幕分辨率的多个设备上构建，这是一个需要考虑的情况。

你想要显示高分辨率图片的一个例子是在 iPhone 4 上，其分辨率为 640 x 960 像素。它是早期 iOS 设备（如 iPhone 3GS，分辨率为 320 x 480 像素）分辨率的的两倍。将 iPhone 3GS 的内容放大以适应 iPhone 4 屏幕是可行的，但图片不会那么清晰，在设备上看起来会有些模糊。

通过在文件名末尾（但在句号和文件扩展名之前）添加`@2x`后缀，可以为 iPhone 4 替换更高分辨率的图片。例如，如果你的图片文件名是`myImage.png`，那么更高分辨率的文件名应该是`myImage@2x.png`。

在你的`config.lua`文件中，需要添加一个名为`imageSuffix`的表格，以使图像命名约定和图像分辨率生效。`config.lua`文件位于你的项目文件夹中，该文件夹存储了所有的`.lua`文件和图像文件。请看以下示例：

```kt
application =
{
  content =
  {
    width = 320,
    height = 480,
    scale = "letterbox",

    imageSuffix =
    {
       ["@2x"] = 2,
    },
  },
}
```

当调用你的显示对象时，使用`display.newImageRect( [parentGroup,] filename [, baseDirectory] w, h)`而不是`display.newImage()`。目标高度和宽度需要设置为你的基础图像的尺寸。

## 帧率控制

默认帧率为 30 fps（每秒帧数）。Fps 指的是游戏中图像刷新的速度。30 fps 是移动游戏的标准，特别是对于较旧的设备。当你添加了 fps 键时，可以将其设置为 60 fps。使用 60 fps 会使你的应用程序运行更加流畅。在运行动画或碰撞检测时，你可以轻松地检测到动作的逼真流畅性。

# 行动时间 – 在多个设备上缩放显示对象

在我们的 `Display Objects` 项目中，我们在模拟器中留下了一个背景图像和三个类似的显示对象未显示。在不同的设备上运行项目时，坐标和分辨率大小与 iPhone 最兼容。在为 iOS 和 Android 平台上的多个设备构建应用程序时，我们可以使用编译到项目中并在运行时访问的 `config.lua` 文件进行配置。那么，让我们开始吧！

1.  在你的文本编辑器中，创建一个新文件并写下以下几行：

    ```kt
    application =
    {
      content =
      {
        width = 320,
        height = 480,
        scale = "letterbox",
        xAlign = "left",
        yAlign = "top"
      },
    }
    ```

1.  在你的 `Display Objects` 项目文件夹中将脚本保存为 `config.lua`。

1.  对于 Mac 用户，在 Corona 下以 iPhone 设备启动你的应用程序。完成此操作后，在 Corona 模拟器菜单栏下，选择 **Window** | **View As** | **iPhone 4**。你会注意到显示对象完美地适应屏幕，并且没有出现任何空黑的空白。

1.  Windows 用户，在 Corona 下以 Droid 设备启动你的应用程序。你会注意到所有内容都被适当地缩放和对齐。在 Corona 模拟器菜单栏下，选择 **Window** | **View As** | **NexusOne**。观察内容布局与 Droid 的相似之处。在以下截图中，从左到右，你可以看到 iPhone 3GS、iPhone 4、Droid 和 NexusOne：![行动时间 – 在多个设备上缩放显示对象](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_02_02.jpg)

## *刚才发生了什么？*

你现在已经学会了一种方法，可以在 iOS 和 Android 上的多种设备上轻松配置显示内容。内容缩放功能对于多屏幕开发很有用。如果你查看我们创建的 `config.lua` 文件，`width = 320` 和 `height = 480`。这是内容最初针对的分辨率大小。在本例中，它是 iPhone 3G。由于我们使用了 `scale = "letterbox"`，它使得内容尽可能均匀地放大，同时仍然在屏幕上显示全部内容。

我们还设置了 `xAlign = "left"` 和 `yAlign = "top"`。这填补了 Droid 设备上特别显示的空黑屏幕空间。默认情况下，内容缩放是在中心的，因此将内容对齐到屏幕的左上角将消除额外的屏幕空间。

# 动态分辨率图像

之前，我们提到了动态图像分辨率。iOS 设备就是这种情况的一个完美例子。Corona 能够在同一个项目文件中使用基本图像（针对 3GS 及以下设备）和双倍分辨率图像（针对拥有视网膜显示屏的 iPhone 4），你的双倍分辨率图像可以无需修改代码，直接切换到高端 iOS 设备上。这将使得你的构建能够支持旧设备，并让你处理更复杂的多屏幕部署情况。你会注意到，动态图像分辨率与动态内容缩放是协同工作的。

使用这行代码 `display.newImageRect( [parentGroup,] filename [, baseDirectory] w, h)`，可以调用你的动态分辨率图像。

在这里，`w` 指的是图像的内容*宽度*，而 `h` 指的是图像的内容*高度*。

这是一个示例：

```kt
myImage = display.newImageRect( "image.png", 128, 128 )
```

请记住，这两个值代表基本图像的大小，*不是*图像在屏幕上的位置。你必须在代码中定义基本大小，这样 Corona 才知道如何渲染更高分辨率的替代图像。你的项目文件夹内容将按如下方式设置：

```kt
My New Project/    name of your project folder
  Icon.png         required for iPhone/iPod/iPad
  Icon@2x.png      required for iPhone/iPod with Retina display
  main.lua
  config.lua
  myImage.png      Base image (Ex. Resolution 128 x 128 pixels)
  myImage@2x.png   Double resolution image (Ex. Resolution 256 x 256 pixels)
```

在创建双倍分辨率图像时，请确保它是基本图像大小的*两倍*。在创建显示资源时，最好从双倍分辨率图像开始。Corona 允许你选择自己的图像命名模式。`@2x` 是一个可以使用的约定示例，但你也可以根据个人偏好选择命名后缀。现在，我们将使用 `@2x` 后缀，因为它可以区分双分辨率引用。创建双倍分辨率图像时，请包含 `@2x` 后缀进行命名。取相同的图像，将其大小调整为原始大小的 50%，然后使用不包含 `@2x` 后缀的相同文件名。

其他命名后缀的例子可能如下所示：

+   @2

+   -2

+   -two

如本章前面所述，你需要在 `config.lua` 文件中的 `imageSuffix` 表中为你的双倍分辨率图像定义图像后缀。你设置的内容缩放比例将允许 Corona 确定当前屏幕与基本内容尺寸之间的比例。以下示例使用 `@2x` 后缀来定义双倍分辨率图像：

```kt
application =
{
  content =
  {
    width = 320,
    height = 480,
    scale = "letterbox",

    imageSuffix =
    {
      ["@2x"] = 2,
    },
  },
}
```

## 是时候来一些形状了。

创建显示对象的另一种方式是使用矢量对象。你可以使用矢量对象来创建如下形状的矩形、圆角矩形和圆形：

+   `display.newRect([parentGroup,] x, y, width, height)`: 这个函数用于创建一个由宽度和高度确定的矩形。`x` 和 `y` 值决定了矩形的中心坐标。局部原点位于矩形的中心，锚点初始化为此局部原点。

+   `display.newRoundedRect([parentGroup,] x, y, width, height, cornerRadius)`: 这将创建一个宽度和高度的圆角矩形。`x`和`y`值决定了矩形的中心坐标。局部原点位于矩形的中心，锚点初始化为此局部原点。您可以使用`cornerRadius`来圆滑角。

+   `display.newCircle([parentGroup,] xCenter, yCenter, radius)`: 这将创建一个以`xCenter`，`yCenter`为中心的半径的圆。

### 应用笔触宽度、填充颜色和笔触颜色

所有矢量对象都可以使用笔触进行勾勒。您可以使用以下方法设置笔触宽度、填充颜色和笔触颜色：

+   `object.strokeWidth`: 这创建笔触宽度，以像素为单位

+   `object:setFillColor(red, green, blue, alpha)`: 我们可以使用 0 到 1 之间的 RGB 代码。`alpha`参数是可选的，默认值为 1.0。

+   `object:setStrokeColor(red, green, blue, alpha)`: 我们可以使用 0 到 255 之间的 RGB 代码。`alpha`参数是可选的，默认值为 1.0。

下面是使用笔触显示矢量对象的示例：

```kt
local rect = display.newRect(160, 130, 150, 150)
rect:setFillColor(1.0, 1.0, 1.0) 
rect:setStrokeColor(0.1, 0.6, 0.2) 
rect.strokeWidth = 5
```

您将在模拟器上获得与以下图像相似的输出：

![应用笔触宽度、填充颜色和笔触颜色](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_02_03.jpg)

## 文本，文本，文本

在第一章，*开始使用 Corona SDK*中，我们使用文本显示对象创建了 Hello World 应用程序。让我们详细了解一下文本如何在屏幕上实现：

+   `display.newText( [parentGroup,] text, x, y, font, fontSize)`方法使用`x`和`y`值创建文本对象。默认情况下没有文本颜色。在`font`参数中，应用库中的任何字体名称。`fontSize`参数显示文本的大小。

+   如果您不想应用字体名称，可以使用以下一些默认常量：

    +   `native.systemFont`

    +   `native.systemFontBold`

### 应用颜色和字符串值

在文本显示对象中可以设置或检索大小、颜色和文本字段：

+   `object.size`: 这是文本的大小。

+   `object:setFillColor(red, green, blue, alpha)`: 我们可以使用 0 到 1 之间的 RGB 代码。`alpha`参数是可选的，默认值为 1.0。

+   `object.text`: 这包含文本对象的文本。它允许您更新测试对象的字符串值。

# 函数是什么？

函数可以执行一个过程或计算并返回值。我们可以将函数调用作为语句，也可以将其作为表达式使用。您还可以将对象方法作为函数使用。您知道函数可以是变量。表可以使用这些变量将它们作为属性存储。

函数是 Lua 中最重要的抽象手段。我们经常使用的一个函数是`print`。在以下示例中，`print`函数被告诉执行一个数据块——`"My favorite number is 8"`字符串：

```kt
print("My favorite number is 8") -- My favorite number is 8
```

另一种表述方式是，`print`函数被调用时带有一个参数。`print`函数是 Lua 语言众多内置函数中的一个，但几乎你编写的任何程序都会涉及定义自己的函数。

## 定义一个函数

当尝试定义一个函数时，你必须给它一个名字，当你想要返回一个值时可以调用这个名字。然后，你需要创建一个语句或语句块来输出值，并在完成定义后为函数应用`end`。以下是一个示例：

```kt
function myName()
  print("My name is Jane.")
end

myName()  -- My name is Jane.
```

注意，函数名为`myName`，它被用来调用`print("My name is Jane.")`函数定义中的内容。

对定义函数的一个扩展如下：

```kt
function myName(Name)
  print("My name is " .. Name .. ".")
end

myName("Jane")  -- My name is Jane.
myName("Cory")  -- My name is Cory.
myName("Diane")  -- My name is Diane.
```

新的`myName`函数有一个使用`Name`变量的参数。`"My name is "`字符串与`Name`连接，然后以句号作为打印结果。当调用函数时，我们使用了三个不同的名字作为参数，并为每一行打印了一个新的自定义名称。

## 更多显示功能

在 Corona 中，你可以改变设备上状态栏的外观。这是代码中的一行设置，一旦你启动应用程序就会生效。你可以使用`display.setStatusBar(mode)`方法来改变状态栏的外观。这将在 iOS 设备（iPad、iPhone 和 iPod Touch）和 Android 2.x 设备上隐藏或改变状态栏的外观。Android 3.x 设备不受支持。

参数模式应该是以下之一：

+   `display.HiddenStatusBar`：若要隐藏状态栏，你可以在代码开始处使用以下这行代码：

    ```kt
    display.setStatusBar(display.HiddenStatusBar)
    ```

    在以下截图中，你可以看到状态栏已被隐藏：

    ![更多显示功能](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_02_04.jpg)

+   `display.DefaultStatusBar`：若要显示默认状态栏，你可以在代码开始处使用以下这行代码：

    ```kt
    display.setStatusBar(display.DefaultStatusBar)
    ```

    代码将显示默认状态栏，如下截图所示：

    ![更多显示功能](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_02_05.jpg)

+   `display.TranslucentStatusBar`：若要显示半透明状态栏，你可以在代码开始处使用以下这行代码：

    ```kt
    display.setStatusBar(display.TranslucentStatusBar)
    ```

    半透明状态栏将如下截图所示：

    ![更多显示功能](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_02_06.jpg)

+   `display.DarkStatusBar`：若要显示深色状态栏，你可以在代码开始处使用以下这行代码：

    ```kt
    display.setStatusBar(display.DarkStatusBar)
    ```

    以下截图是深色状态栏：

    ![更多显示功能](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/corona-sdk-mobi-gm-dev-bgd-2e/img/9343OT_02_07.jpg)

### 内容大小属性

当你想要获取设备上的显示信息时，可以使用内容大小属性来返回值。这些属性如下：

+   `display.contentWidth`：这会返回内容原始宽度的像素值。默认情况下，这将是屏幕宽度。

+   `display.contentHeight`：这会返回内容原始高度的像素值。默认情况下，这将是屏幕高度。

+   `display.viewableContentWidth`：这是一个只读属性，包含视图屏幕区域的宽度（以像素为单位），在原始内容的坐标系内。访问这个属性将显示内容是如何被查看的，无论你是在纵向还是横向模式。以下是一个示例：

    ```kt
    print(display.viewableContentWidth)
    ```

+   `display.viewableContentHeight`：这是一个只读属性，包含视图屏幕区域的高度（以像素为单位），在原始内容的坐标系内。访问这个属性将显示内容是如何被查看的，无论你是在纵向还是横向模式。以下是一个示例：

    ```kt
    print(display.viewableContentHeight)
    ```

+   `display.statusBarHeight`：这是一个只读属性，表示状态栏的高度（以像素为单位，仅在 iOS 设备上有效）。以下是一个示例：

    ```kt
    print(display.statusBarHeight)
    ```

# 优化你的工作流程

到目前为止，我们已经接触了 Lua 编程中的一些基本要点以及 Corona SDK 中使用的术语。一旦你开始开发交互式应用程序，准备在 App Store 或 Android 市场上销售，你需要注意你的设计选择以及它们如何影响应用程序的性能。这意味着要考虑你的移动设备在处理应用程序时使用的内存量。以下是一些如果你刚开始接触 Corona SDK 需要注意的事项。

## 高效使用内存

在我们早期的例子中，有时在代码中使用了全局变量。像这样的情况是个例外，因为示例没有包含大量的函数、循环调用或显示对象。一旦你开始构建一个与函数调用和众多显示对象高度相关的游戏，局部变量将提高应用程序的性能，并放置在栈上，以便 Lua 可以更快地接口它们。

以下代码将导致内存泄漏：

```kt
-- myImage is a global variable
myImage = display.newImage( "image.png" )
myImage.x = 160;  myImage.y = 240

-- A touch listener to remove object
local removeBody = function( event )
  local t = event.target
  local phase = event.phase

  if "began" == phase then
    -- variable "myImage" still exists even if it's not displayed
    t:removeSelf() -- Destroy object
  end

  -- Stop further propagation of touch event
  return true
end

myImage:addEventListener( "touch", removeBody )
```

前面的代码在`myImage`被触摸后将其从显示层次结构中移除。唯一的问题是，由于`myImage`变量仍然引用它，`myImage`使用的内存会泄漏。由于`myImage`是一个全局变量，它引用的显示对象即使不在屏幕上显示也不会被释放。

与全局变量不同，局部化变量可以帮助加快显示对象的查找过程。它也只存在于定义它的代码块或片段中。在以下代码中使用局部变量将完全移除对象并释放内存：

```kt
-- myImage is a local variable
local myImage = display.newImage( "image.png" )
myImage.x = 160;  myImage.y = 240

-- A touch listener to remove object
local removeBody = function( event )
  local t = event.target
  local phase = event.phase

  if "began" == phase then
    t:removeSelf() -- Destroy object
    t = nil
  end

  -- Stop further propagation of touch event
  return true
end

myImage:addEventListener( "touch", removeBody )
```

# 优化你的显示图像

优化你的图像文件大小非常重要。使用全屏图像可能会影响应用程序的性能。它们需要更长的时间在设备上加载，并且消耗大量的纹理内存。当应用程序消耗大量内存时，在大多数情况下它会被迫退出。

iOS 设备在可用内存大小上有所不同，具体取决于以下设备中的哪一个：

+   iPhone 3GS、iPad 和拥有 256 MB RAM 的 iTouch 3G/4G

+   iPhone 4/4S、iPad 2、iPad Mini 和拥有 512 MB RAM 的 iTouch 5G

+   iPhone 5/5S/6, 6 Plus, iPad 3G, 以及 1 GB RAM 的 iPad 4G

例如，在 iPhone 3GS 上，纹理内存应保持在 25 MB 以下，以免出现性能问题，如减慢应用程序速度甚至强制退出。iPad 2 在这方面可以更宽松，因为它有更多的可用内存。

### 注意

有关为 iOS 设备应用内存警告，请参考 [`docs.coronalabs.com/api/event/memoryWarning/index.html`](http://docs.coronalabs.com/api/event/memoryWarning/index.html)。

对于 Android 设备，大约有 24 MB 的内存限制。因此，了解你的场景中有多少显示对象以及当你的应用程序不再需要它们时如何管理它们是非常重要的。

当你不再需要在屏幕上显示一个图像时，请使用以下代码：

```kt
image.parent:remove( image ) -- remove image from hierarchy
```

或者，你也可以使用以下代码行：

```kt
image:removeSelf( ) -- same as above
```

如果你想要在应用程序的生命周期内完全移除一个图像，请在你的 `image.parent:remove( image )` 或 `image:removeSelf()` 代码后包含以下行：

```kt
image = nil
```

在应用程序中保持低内存使用可以防止崩溃并提高性能。有关优化的更多信息，请访问 [`developer.coronalabs.com/content/performance-and-optimization`](http://developer.coronalabs.com/content/performance-and-optimization)。

## 快速测验 - Lua 基础

Q1. 以下哪项是值？

1.  数字

1.  nil

1.  字符串

1.  所有以上选项

Q2. 哪个关系运算符是错误的？

1.  `print(0 == 0)`

1.  `print(3 >= 2)`

1.  `print(2 ~= 2)`

1.  `print(0 ~= 2)`

Q3. 在 *x* 方向缩放对象的正确方法是什么？

1.  `object.scaleX`

1.  `object.xscale`

1.  `object.Xscale`

1.  `object.xScale`

# 总结

本章讨论了 Lua 编程的部分内容，这将为你开始创建自己的 Corona 应用程序铺平道路。随着你继续使用 Lua，你会开始更好地理解术语。最终，你会发现新的编程解决方案，这将有利于你的开发过程。

你到目前为止学到的技能包括以下内容：

+   创建变量并赋值

+   使用运算符建立表达式

+   使用 Corona 终端输出或打印结果

+   使用表来构建列表、数组、集合等

+   在模拟器中添加显示对象

+   配置你的应用程序构建以在不同的移动设备上工作

+   实现动态分辨率图像

+   创建函数以运行代码块

这一部分确实有很多内容需要消化。关于 Lua 的还有很多信息我们没有涉及到，但你已经学到了足够多的知识来开始。有关在 Lua 中编程的更多信息，你可以参考 [`www.lua.org/pil/index.html`](http://www.lua.org/pil/index.html) 或 Corona 网站上的资源部分 [`www.coronalabs.com/resources/`](http://www.coronalabs.com/resources/)。

在下一章中，我们将开始制作我们的第一个游戏——打砖块！你将亲身体验在 Corona 中创建游戏框架，并应用所有必要的资源来开发一款移动游戏。你会惊讶地发现创建一个游戏竟然如此迅速和简单。
