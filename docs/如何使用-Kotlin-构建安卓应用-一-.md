# 如何使用 Kotlin 构建安卓应用（一）

> 原文：[`zh.annas-archive.org/md5/AFA545AAAFDFD0BBAD98F56388586295`](https://zh.annas-archive.org/md5/AFA545AAAFDFD0BBAD98F56388586295)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

# 关于本书

Android 在过去十年一直统治着应用市场，开发者们越来越多地希望开始构建自己的 Android 应用程序。*使用 Kotlin 构建 Android 应用程序*从 Android 开发的基础知识开始，教你如何使用 Android Studio（Android 的集成开发环境）和 Kotlin 编程语言进行应用程序开发。然后，你将学习如何通过引导式练习创建应用程序并在虚拟设备上运行。你将学习 Android 开发的基础知识，从应用程序结构到使用 Activities 和 Fragments 构建 UI 以及各种导航模式。随着章节的进行，你将深入了解 Android 的 RecyclerView，以充分利用显示数据列表，并熟悉从 Web 服务获取数据和处理图像。然后，你将学习地图、位置服务和权限模型，然后处理通知和数据持久化。接下来，你将掌握测试，涵盖测试金字塔的全部范围。你还将学习如何使用 AAC（Android 架构组件）来清晰地构建你的代码，并探索各种架构模式和依赖注入的好处。异步编程的核心库 RxJava 和 Coroutines 也被涵盖在内。然后重点回到 UI，演示用户与应用程序交互时如何添加动作和过渡效果。最后，你将构建一个有趣的应用程序，从电影数据库中检索并显示热门电影，然后学习如何在 Google Play 上发布你的应用程序。通过本书的学习，你将具备使用 Kotlin 构建完整的 Android 应用程序所需的技能和信心。

## 关于作者

*Alex Forrester*是一名经验丰富的软件开发者，拥有超过 20 年的移动、Web 开发和内容管理系统开发经验。他在 Android 领域工作了 8 年以上，在 Sky、The Automobile Association、HSBC、The Discovery Channel 和 O2 等著名公司开发了旗舰应用。Alex 和妻女住在赫特福德郡。在不开发软件的时候，他喜欢橄榄球和在 Chiltern 山丘上跑步。

*Eran Boudjnah*是一名拥有超过 20 年开发桌面应用程序、网站、互动景点和移动应用程序经验的开发者。他在 Android 领域工作了大约 7 年，为各种客户开发应用程序并领导移动团队，从初创公司（JustEat）到大型公司（Sky）和企业集团。他热衷于桌游（拥有数百款游戏的收藏）并且有一套他非常自豪的变形金刚收藏品。Eran 和妻子 Lea 住在伦敦北部。

*Alexandru Dumbravan*于 2011 年开始从事 Android 开发，在一家数字代理公司工作。2016 年，他搬到伦敦，在金融科技领域工作。在职业生涯中，他有机会分析和集成许多不同的技术到 Android 设备上，从像 Facebook 登录这样的知名应用到像专有网络协议这样的不太知名的技术。

*Jomar Tigcal*是一名拥有超过 10 年移动和软件开发经验的 Android 开发者。他曾在小型初创公司和大型公司的应用开发的各个阶段工作过。Jomar 还曾就 Android 进行讲座和培训，并举办过相关的工作坊。在业余时间，他喜欢跑步和阅读。他和妻子 Celine 住在加拿大温哥华。

## 受众

如果你想使用 Kotlin 构建自己的 Android 应用程序，但不确定如何开始，那么这本书适合你。对 Kotlin 编程语言的基本理解将帮助你更快地掌握本书涵盖的主题。

## 关于章节

第一章，创建您的第一个应用程序，展示了如何使用 Android Studio 构建您的第一个 Android 应用程序。在这里，您将创建一个 Android Studio 项目，并了解其组成部分，并探索构建和部署应用程序到虚拟设备所需的工具。您还将了解 Android 应用程序的结构。

第二章，构建用户屏幕流程，深入探讨了 Android 生态系统和 Android 应用程序的构建模块。将介绍活动及其生命周期、意图和任务等概念，以及恢复状态和在屏幕或活动之间传递数据。

第三章，使用片段开发 UI，教您如何使用片段来构建 Android 应用程序的用户界面的基础知识。您将学习如何以多种方式使用片段来为手机和平板电脑构建应用程序布局，包括使用 Jetpack Navigation 组件。

第四章，构建应用程序导航，介绍了应用程序中不同类型的导航。您将了解具有滑动布局的导航抽屉、底部导航和选项卡导航。

第五章，Essential Libraries: Retrofit, Moshi, and Glide，为您提供了如何构建可以使用 Retrofit 库和 Moshi 库从远程数据源获取数据的应用程序的见解，并将数据转换为 Kotlin 对象。您还将了解 Glide 库，它可以将远程图像加载到您的应用程序中。

第六章，RecyclerView，介绍了使用 RecyclerView 小部件构建列表并显示列表的概念。

第七章，Android 权限和 Google 地图，介绍了权限的概念以及如何向用户请求权限，以便您的应用程序执行特定任务，并向您介绍了地图 API。

第八章，服务、WorkManager 和通知，详细介绍了 Android 应用程序中后台工作的概念，以及如何使您的应用程序以对用户不可见的方式执行某些任务，以及如何显示此工作的通知。

第九章，使用 JUnit、Mockito 和 Espresso 进行单元测试和集成测试，教您了解 Android 应用程序的不同类型的测试，每种测试所使用的框架，以及测试驱动开发的概念。

第十章，Android 架构组件，深入了解了来自 Android Jetpack 库的组件，如 LiveData 和 ViewModel，这些组件可以帮助您构建代码，以及 Room，它允许您在设备上持久保存数据到数据库中。

第十一章，数据持久化，向您展示了在设备上存储数据的各种方式，从 SharedPreferences 到文件。还将介绍存储库的概念，让您了解如何在不同层次上构建应用程序。

第十二章，使用 Dagger 和 Koin 进行依赖注入，解释了依赖注入的概念及其对应用程序的好处。介绍了 Dagger 和 Koin 等框架，以帮助您管理依赖关系。

第十三章，RxJava 和 Coroutines，向您介绍了如何使用 RxJava 和 Coroutines 进行后台操作和数据操作。您还将学习如何使用 RxJava 操作符和 LiveData 转换来操作和显示数据。

第十四章，架构模式，解释了您可以使用的架构模式，将 Android 项目结构化为具有不同功能的不同组件。这使您更容易开发、测试和维护您的代码。

第十五章，使用 CoordinatorLayout 和 MotionLayout 进行动画和过渡，讨论了如何使用 CoordinatorLayout 和 MotionLayout 增强您的应用程序的动画和过渡。

第十六章，在 Google Play 上发布您的应用程序，通过展示如何在 Google Play 上发布您的应用程序来结束本书：从准备发布到创建 Google Play 开发者帐户，最终发布您的应用程序。

## 约定

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：

“您可以在`MyApplication` | `app` | `src` | `main`主项目窗口下找到它。”

一块代码设置如下：

```kt
<resources>
    <string name="app_name">My Application</string>
</resources>
```

在某些情况下，重要的代码行会被突出显示。这些情况如下所示：

```kt
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="app_name">My Application</string>
    <string name="first_name_text">First name:</string>
    <string name="last_name_text">Last name:</string>
</resources>
```

屏幕上显示的文字，例如菜单或对话框中的文字，也会在文本中出现，如：“单击`完成`，您的虚拟设备将被创建。”

新术语和重要单词显示如下：“这是官方的**集成开发环境**（**IDE**）用于 Android 开发，构建在 JetBrains 的**IntelliJ IDEA 软件**上，并由 Google 的 Android Studio 团队开发。”

## 开始之前

每次伟大的旅程都始于一小步。在我们可以在 Android 上做出色的事情之前，我们需要准备一个高效的环境。在本节中，我们将看到如何做到这一点。

## 最低硬件要求

为了获得最佳的学习体验，我们建议以下硬件配置：

+   处理器：Intel Core i5 或同等或更高

+   内存：最低 4GB RAM；建议 8GB RAM

+   存储：4GB 可用空间

## 软件要求

您还需要预先安装以下软件：

+   操作系统：Windows 7 SP1 64 位，Windows 8.1 64 位或 Windows 10 64 位，macOS 或 Linux

+   Android Studio 4.1 或更高版本

## 安装和设置

在开始阅读本书之前，您需要安装 Android Studio 4.1（或更高版本），这是您将在整个章节中使用的主要工具。您可以从 https://developer.android.com/studio 下载 Android Studio。

在 macOS 上，启动 DMG 文件，将 Android Studio 拖放到“应用程序”文件夹中。完成后，打开 Android Studio。在 Windows 上，启动 EXE 文件。如果您使用 Linux，请将 ZIP 文件解压缩到您喜欢的位置。打开终端并导航到`android-studio/bin/`目录，执行`studio.sh`。如果看到“导入设置”对话框弹出，请选择“不导入设置”，然后单击“确定”按钮（通常在之前安装了 Android Studio 时会出现）：

![图 0.1：导入设置对话框](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_00_01.jpg)

图 0.1：导入设置对话框

接下来，将弹出“数据共享”对话框；单击“不发送”按钮以禁用向 Google 发送匿名使用数据：

![图 0.2：数据共享对话框](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_00_02.jpg)

图 0.2：数据共享对话框

在“欢迎”对话框中，单击“下一步”按钮开始设置：

![图 0.3：欢迎对话框](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_00_03.jpg)

图 0.3：欢迎对话框

在“安装类型”对话框中，选择“标准”以安装推荐的设置。然后，单击“下一步”按钮：

![图 0.4：安装类型对话框](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_00_04.jpg)

图 0.4：安装类型对话框

在“选择 UI 主题”对话框中，选择您喜欢的 IDE 主题—“浅色”或“德拉库拉”（暗色主题）—然后单击“下一步”按钮：

![图 0.5：选择 UI 主题对话框](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_00_05.jpg)

图 0.5：选择 UI 主题对话框

在“验证设置”对话框中，查看您的设置，然后单击“完成”按钮。设置向导会下载并安装其他组件，包括 Android SDK：

![图 0.6：验证设置对话框](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_00_06.jpg)

图 0.6：验证设置对话框

下载完成后，您可以单击“完成”按钮。现在，您已经准备好创建 Android 项目了。

## 安装代码包

您可以从 GitHub 上下载代码文件和活动解决方案，网址为 https://github.com/PacktPublishing/How-to-Build-Android-Apps-with-Kotlin。参考这些代码文件获取完整的代码包。

## 保持联系

我们始终欢迎读者的反馈。

`customercare@packtpub.com`。

**勘误表**：尽管我们已经尽一切努力确保内容的准确性，但错误确实会发生。如果您在本书中发现了错误，我们将不胜感激，如果您能向我们报告。请访问 www.packtpub.com/support/errata 并填写表格。

`copyright@packt.com` 并附上材料的链接。

**如果您有兴趣成为作者**：如果您在某个专题上有专业知识，并且有兴趣撰写或为一本书做出贡献，请访问 authors.packtpub.com。

## 请留下评论

通过在亚马逊上留下详细、公正的评论，让我们知道您的想法。我们感激所有的反馈 - 它帮助我们继续制作优秀的产品，并帮助有抱负的开发人员提升他们的技能。请花几分钟时间分享您的想法 - 这对我们有很大的影响。


# 第一章：创建您的第一个应用

概述

本章是 Android 的介绍，您将设置您的环境并专注于 Android 开发的基础知识。通过本章的学习，您将获得创建 Android 应用程序所需的知识，并将其安装在虚拟或物理 Android 设备上。您将能够分析和理解`AndroidManifest.xml`文件的重要性，并使用 Gradle 构建工具来配置您的应用程序，并从 Material Design 实现 UI 元素。

# 介绍

Android 是世界上使用最广泛的手机操作系统，全球市场份额超过 70%（参见[`gs.statcounter.com/os-market-share/mobile/worldwide`](https://gs.statcounter.com/os-market-share/mobile/worldwide)）。这为学习 Android 和构建具有全球影响力的应用提供了巨大的机会。对于新手 Android 开发者来说，有许多问题需要解决才能开始学习和提高生产力。本书将解决这些问题。在学习工具和开发环境之后，您将探索构建 Android 应用的基本实践。我们将涵盖开发者面临的各种现实世界开发挑战，并探索克服这些挑战的各种技术。

在本章中，您将学习如何创建一个基本的 Android 项目并为其添加功能。您将介绍 Android Studio 的全面开发环境，并了解软件的核心领域，以使您能够高效地工作。Android Studio 提供了应用程序开发的所有工具，但不提供知识。本章将指导您有效地使用软件来构建应用程序，并配置 Android 项目的最常见区域。

让我们开始创建一个 Android 项目。

# 使用 Android Studio 创建 Android 项目

要在构建 Android 应用方面提高生产力，熟练使用**Android Studio**至关重要。这是 Android 开发的官方**集成开发环境**（**IDE**），建立在 JetBrains 的**IntelliJ IDEA IDE**上，由 Google 的 Android Studio 团队开发。您将在本课程中使用它来创建应用程序，并逐步添加更多高级功能。

Android Studio 的开发遵循了 IntelliJ IDEA IDE 的发展。当然，IDE 的基本功能都存在，使您能够通过建议、快捷方式和标准重构来优化您的代码。在本课程中，您将使用 Kotlin 来创建 Android 应用程序。自 2017 年 Google I/O（Google 的年度开发者大会）以来，这一直是 Google 首选的 Android 应用程序开发语言。Android Studio 与其他 Android 开发环境的真正区别在于**Kotlin**是由 JetBrains 创建的，这是 Android Studio 构建在其上的 IntelliJ IDEA 软件的公司。因此，您可以受益于 Kotlin 的成熟和不断发展的一流支持。 

Kotlin 是为了解决 Java 的一些缺点而创建的，包括冗长、处理空类型和添加更多的函数式编程技术等问题。自 2017 年以来，Kotlin 一直是 Android 开发的首选语言，取代了 Java，您将在本书中使用它。

熟悉并熟悉 Android Studio 将使您有信心在 Android 应用上工作和构建。所以，让我们开始创建您的第一个项目。

注意

Android Studio 的安装和设置在*前言*中有介绍。请确保在继续之前已完成这些步骤。

## 练习 1.01：为您的应用创建 Android Studio 项目

这是创建应用程序结构的起点。模板驱动的方法将使您能够在短时间内创建一个基本项目，同时设置您可以用来开发应用程序的构建块。要完成此练习，请执行以下步骤：

注意

您将使用的 Android Studio 版本为*v4.1.1*（或更高）。

1.  打开 Android Studio 后，您将看到一个窗口，询问您是要创建新项目还是打开现有项目。选择`创建新项目`。

启动窗口将如下所示：

![图 1.1：Android Studio 版本 4.1.1](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_01_01.jpg)

图 1.1：Android Studio 版本 4.1.1

1.  现在，您将进入一个简单的向导驱动流程，大大简化了您的第一个 Android 项目的创建。您将看到的下一个屏幕上有大量选项，用于您希望应用程序具有的初始设置：![图 1.2：为您的应用程序启动项目模板](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_01_02.jpg)

图 1.2：为您的应用程序启动项目模板

1.  欢迎来到您对`Activity`的第一次介绍。在 Android 中，`Activity`是一个页面或屏幕。您可以从前面的屏幕上选择的选项中以不同的方式创建此初始屏幕。描述描述了应用程序的第一个屏幕将如何显示。这些是用于构建应用程序的模板。从模板中选择`空白 Activity`，然后单击下一步。

项目配置屏幕如下：

![图 1.3：项目配置](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_01_03.jpg)

图 1.3：项目配置

1.  前面的屏幕配置了您的应用程序。让我们逐个浏览所有选项：

`名称`：与您的 Android 项目名称类似，当应用程序安装在手机上并在 Google Play 上可见时，此名称将显示为应用程序的默认名称。您可以用自己的名称替换`名称`字段，或者现在设置为您将要创建的应用程序。

`包名称`：这使用标准的反向域名模式来创建名称。它将用作应用程序中源代码和资产的地址标识符。最好使此名称尽可能清晰、描述性，并与您的应用程序的目的密切相关。因此，最好更改此名称以使用一个或多个子域（例如`com.sample.shop.myshop`）。如*图 1.3*所示，将应用程序的`名称`（小写并去除空格）附加到域名后面。

`保存位置`：这是您的计算机上的本地文件夹，应用程序最初将存储在其中。将来可以更改此位置，因此您可以保留默认设置或将其编辑为其他内容（例如`Users/MyUser/android/projects`）。默认位置将根据您使用的操作系统而变化。

`语言 - Kotlin`：这是 Google 推荐的用于 Android 应用程序开发的语言。

`最低 SDK`：取决于您下载的 Android Studio 版本，其默认值可能与*图 1.3*中显示的相同，也可能不同。保持不变。大多数 Android 的新功能都是向后兼容的，因此您的应用程序将在绝大多数旧设备上运行良好。但是，如果您想要针对新设备进行开发，您应该考虑提高最低 API 级别。有一个名为`帮助我选择`的链接，指向一个对话框，解释了您可以访问的功能集，以便在不同版本的 Android 上进行开发，以及全球各地运行每个 Android 版本的设备的当前百分比。

（复选框）使用传统的 android.support 库。不要选中此复选框。您将使用 AndroidX 库，这是支持库的替代品，旨在使新版本 Android 上的功能向后兼容旧版本，但它提供的远不止于此。它还包含称为 Jetpack 的新 Android 组件，正如其名称所示，它可以“增强”您的 Android 开发，并提供一系列丰富的功能，您将希望在应用程序中使用，从而简化常见操作。

一旦您填写了所有这些细节，选择`完成`。您的项目将被构建，然后您将看到以下屏幕或类似的屏幕：您可以立即在一个选项卡中看到已创建的活动（`MainActivity`），在另一个选项卡中看到用于屏幕的布局（`activity_main.xml`）。应用程序结构文件夹在左侧面板中。

![图 1.4：Android Studio 默认项目](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_01_04.jpg)

图 1.4：Android Studio 默认项目

在这个练习中，您已经完成了使用 Android Studio 创建您的第一个 Android 应用程序的步骤。这是一个模板驱动的方法，向您展示了您需要为应用程序配置的核心选项。

在下一节中，您将设置一个虚拟设备，并首次看到您的应用程序运行。

# 设置虚拟设备并运行您的应用

作为安装 Android Studio 的一部分，您下载并安装了最新的 Android SDK 组件。其中包括一个基本的模拟器，您将配置它来创建一个虚拟设备来运行 Android 应用程序。好处是您可以在开发应用程序时在桌面上进行更改并快速查看它们。虽然虚拟设备没有真实设备的所有功能，但反馈周期通常比连接真实设备的步骤更快。

另外，虽然您应该确保您的应用在不同设备上正常运行，但如果这是项目的要求，您可以通过下载模拟器皮肤来针对特定设备进行标准化，即使您没有真实设备也可以做到这一点。

您在安装 Android Studio 时看到的屏幕（或类似的内容）如下：

![图 1.5：SDK 组件](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_01_05.jpg)

图 1.5：SDK 组件

让我们来看看已安装的 SDK 组件以及虚拟设备的作用：

+   **Android 模拟器**：这是基本模拟器，我们将配置它来创建不同 Android 品牌和型号的虚拟设备。

+   **Android SDK 构建工具**：Android Studio 使用构建工具来构建您的应用程序。这个过程涉及编译、链接和打包您的应用程序，以便为设备安装做好准备。

+   在创建项目向导中选择了`Jelly Bean`来配置项目的最低 API 级别。从 Android 10 开始，版本将不再有与版本名称不同的代码名称。（Build-Tools 和 Platform 的版本将随着新版本的发布而改变）

+   **Android SDK 平台工具**：这些工具通常是您可以从命令行中使用的工具，用于与您的应用程序进行交互和调试。

+   **Android SDK 工具**：与平台工具相比，这些工具主要是您在 Android Studio 中使用的工具，用于完成某些任务，例如运行应用程序的虚拟设备和 SDK 管理器以下载和安装 SDK 的平台和其他组件。

+   **Intel x86 模拟器加速器（HAXM 安装程序）**：如果您的操作系统提供了它，这是您的计算机硬件级别的功能，您将被提示启用，这样您的模拟器可以运行得更快。

+   **SDK 补丁应用程序 v4**：随着新版本的 Android Studio 的推出，这使得可以应用补丁来更新您正在运行的版本。

有了这些知识，让我们开始本章的下一个练习。

## 练习 1.02：设置虚拟设备并在其上运行您的应用

我们在*练习 1.01*中设置了一个 Android Studio 项目来创建我们的应用程序，现在我们将在虚拟设备上运行它。您也可以在真实设备上运行您的应用程序，但在本练习中，您将使用虚拟设备。在开发应用程序时，这个过程是一个持续的循环。一旦您实现了一个功能，您可以根据需要验证其外观和行为。在本练习中，您将创建一个虚拟设备，但您应该确保在多个设备上运行您的应用程序，以验证其外观和行为是否一致。执行以下步骤：

1.  在 Android Studio 的顶部工具栏中，您将看到两个并排的下拉框，预先选择了`app`和`无设备`：![图 1.6：Android Studio 工具栏](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_01_06.jpg)

图 1.6：Android Studio 工具栏

`app`是我们将要运行的应用程序的配置。由于我们还没有设置虚拟设备，因此显示为`无设备`。

1.  要创建虚拟设备，请点击`AVD Manager`（`工具`菜单：![图 1.7：工具菜单中的 AVD 管理器](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_01_07.jpg)

图 1.7：工具菜单中的 AVD 管理器

1.  点击按钮或工具栏选项以打开`您的虚拟设备`窗口：![图 1.8：您的虚拟设备窗口](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_01_08.jpg)

图 1.8：您的虚拟设备窗口

1.  点击`创建虚拟设备...`按钮，如*图 1.8*所示：![图 1.9：设备定义创建](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_01_09.jpg)

图 1.9：设备定义创建

1.  我们将选择`Pixel 3`设备。由 Google 开发的真实（非虚拟设备）Pixel 系列设备可以访问最新版本的 Android 平台。选择后，点击`下一步`按钮：![图 1.10：系统镜像](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_01_10.jpg)

图 1.10：系统镜像

这里显示的`R`名称是 Android 11 的初始代码/发布名称。选择最新的系统镜像。`目标`列可能还会显示名称中的`(Google Play)`或`(Google APIs)`。Google APIs 表示系统镜像预装了 Google Play 服务。这是一组丰富的 Google API 和 Google 应用程序功能，您的应用程序可以使用和交互。首次运行应用程序时，您将看到诸如地图和 Chrome 之类的应用程序，而不是普通的模拟器图像。Google Play 系统镜像意味着除了 Google API 之外，还将安装 Google Play 应用程序。

1.  您应该使用最新版本的 Android 平台开发您的应用程序，以从最新功能中受益。首次创建虚拟设备时，您将需要下载系统镜像。如果`发布名称`旁边显示`下载`链接，请点击它并等待下载完成。选择`下一步`按钮以查看您设置的虚拟设备：![图 1.11：虚拟设备配置](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_01_11.jpg)

图 1.11：虚拟设备配置

然后您将看到最终的配置屏幕。

1.  点击`完成`，您的虚拟设备将被创建。然后您将看到您的设备被突出显示：![图 1.12：虚拟设备列表](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_01_12.jpg)

图 1.12：虚拟设备列表

1.  按下`操作`列下的右箭头按钮来启动虚拟设备：![图 1.13：虚拟设备已启动](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_01_13.jpg)

图 1.13：虚拟设备已启动

现在，您已经创建了虚拟设备并且正在运行，您可以回到 Android Studio 运行您的应用程序。

1.  您设置并启动的虚拟设备将被选中。按下绿色三角形/播放按钮启动您的应用程序：

![图 1.14：应用程序启动配置](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_01_14.jpg)

图 1.14：应用程序启动配置

![图 1.15：在虚拟设备上运行的应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_01_15.jpg)

图 1.15：在虚拟设备上运行的应用程序

在这个练习中，您已经完成了创建虚拟设备并在其上运行您创建的应用程序的步骤。您用于执行此操作的 Android 虚拟设备管理器使您能够为您的应用程序定位目标设备（或设备范围）。在虚拟设备上运行您的应用程序可以快速验证新功能开发的行为方式以及它是否显示您期望的方式。

接下来，您将探索项目的`AndroidManifest.xml`文件，其中包含应用程序的信息和配置。

# Android 清单

您刚刚创建的应用程序虽然简单，但包含了您在创建的所有项目中将使用的核心构建模块。该应用程序是从`AndroidManifest.xml`文件驱动的，这是一个详细描述您的应用程序内容的清单文件。它包含了所有组件，如活动、内容提供程序、服务、接收器以及应用程序实现其功能所需的权限列表。例如，应用程序需要相机权限来在应用程序中拍摄照片。您可以在项目视图下找到它，路径为`MyApplication` | `app` | `src` | `main`。或者，如果您正在查看 Android 视图，则它位于`app` | `manifests` | `AndroidManifest.xml`：

```kt
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.myapplication">
    <!--Permissions like camera go here-->
    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/Theme.MyApplication">
        <activity android:name=".MainActivity"           android:screenOrientation="portrait">
            <intent-filter>
              <action android:name="android.intent.action.MAIN" />

             <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

一般来说，典型的清单文件是一个描述所包含的文件或其他数据以及形成组或单元的相关元数据的顶层文件。Android 清单将这个概念应用到您的 Android 应用程序中，作为一个 XML 文件。指定的应用程序的区别特征是在清单 XML 根部定义的包：

```kt
package="com.example.myapplication"
```

每个 Android 应用程序都有一个应用程序类，允许您配置应用程序。默认情况下，在 Android Studio 的 4.1.1 版本中，应用程序元素中创建了以下 XML 属性和值：

+   `android:allowBackup="true"`：这将在重新安装或切换设备时备份目标并在 Android 6.0（API 级别 23）或更高版本上运行的应用程序的用户数据。

+   `android:icon="@mipmap/ic_launcher"`：Android 使用的资源在 XML 中以`@`符号开头引用，mipmap 指的是存储启动器图标的文件夹。

+   `android:label="@string/app_name"`：这是您创建应用程序时指定的名称。它目前显示在应用程序的工具栏中，并将显示为用户设备上启动器中应用程序的名称。它由`@`符号后跟着您创建应用程序时指定的名称的字符串引用引用。

+   `android:roundIcon="@mipmap/ic_launcher_round"`：根据用户所使用的设备，启动器图标可能是方形的或圆形的。当用户的设备在启动器中显示圆形图标时，将使用`roundIcon`。

+   `android:supportsRtl="true"`：这指定了应用程序及其布局文件是否支持从右到左的语言布局。

+   `android:theme="@style/Theme.MyApplication"`：这指定了您的应用程序的主题，包括文本样式、颜色和应用程序内的其他样式。

在`<application>`元素打开后，您可以定义应用程序包含的组件。由于我们刚刚创建了我们的应用程序，它只包含以下代码中显示的第一个屏幕：

```kt
<activity android:name=".MainActivity"> 
```

接下来指定的子 XML 节点如下：

```kt
<intent-filter> 
```

Android 使用意图作为与应用程序和系统组件交互的机制。意图被发送，而意图过滤器注册了您的应用程序对这些意图做出反应的能力。`<android.intent.action.MAIN>`是您的应用程序的主要入口点，它在`.MainActivity`的封闭 XML 中出现，指定了当应用程序启动时将启动该屏幕。`android.intent.category.LAUNCHER`表示您的应用程序将出现在用户设备的启动器中。

由于您是从模板创建应用程序，它具有一个基本的清单，将通过`Activity`组件启动应用程序并在启动时显示初始屏幕。根据您想要为应用程序添加哪些其他功能，您可能需要在 Android 清单文件中添加权限。

权限分为三种不同的类别：普通、签名和危险。

+   **普通**权限包括访问网络状态、Wi-Fi、互联网和蓝牙。通常情况下，这些权限在运行时可以不经用户同意而被允许。

+   **签名**权限是由同一组应用程序共享的权限，必须使用相同的证书进行签名。这意味着这些应用程序可以自由共享数据，但其他应用程序无法访问。

+   **危险**权限围绕用户及其隐私展开，例如发送短信、访问帐户和位置，以及读写文件系统和联系人。

这些权限必须在清单中列出，并且从 Android Marshmallow API 23（Android 6 Marshmallow）开始，对于危险权限，您还必须在运行时要求用户授予权限。

在下一个练习中，我们将配置 Android 清单文件。

## 练习 1.03：配置 Android 清单互联网权限

大多数应用程序需要的关键权限是访问互联网。这不是默认添加的。在这个练习中，我们将修复这个问题，并在此过程中加载一个`WebView`，这使得应用程序可以显示网页。这种用例在 Android 应用程序开发中非常常见，因为大多数商业应用程序都会显示隐私政策、条款和条件等。由于这些文件可能对所有平台都是通用的，通常显示它们的方式是加载一个网页。执行以下步骤：

1.  像在*练习 1.01*中一样创建一个新的 Android Studio 项目，为您的应用程序创建一个 Android Studio 项目。

1.  切换到`MainActivity`类的标签。从主项目窗口，它位于`MyApplication` | `app` | `src` | `main` | `java` | `com` | `example` | `myapplication`。这遵循您创建应用程序时定义的包结构。或者，如果您正在项目窗口中查看 Android 视图，则它位于`app` | `java` | `com` | `example` | `myapplication`。

您可以通过选择`View | Tool Windows | Project`来打开`Tool`窗口，从而更改`Project`窗口显示的内容 - 这将选择`Project`视图。`Project`窗口顶部的下拉选项允许您更改查看项目的方式，最常用的显示方式是`Project`和`Android`。

![图 1.16 工具窗口下拉](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_01_16.jpg)

```kt
package com.example.myapplication
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.Activity_main)
    }
}
```

您将在本章的下一部分更详细地检查此文件的内容，但现在，您只需要知道`setContentView(R.layout.Activity_main)`语句设置了您在虚拟设备上首次运行应用程序时看到的 UI 布局。

1.  使用以下代码更改为以下内容：

```kt
package com.example.myapplication
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.webkit.WebView
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val webView = WebView(this)
        webView.settings.javaScriptEnabled = true
        setContentView(webView)
        webView.loadUrl("https://www.google.com")
    }
}
```

因此，您正在用`WebView`替换布局文件。`val`关键字是只读属性引用，一旦设置就无法更改。WebView 需要启用 JavaScript 才能执行 JavaScript。

注意

我们没有设置类型，但 Kotlin 具有类型推断，因此如果可能的话，它会推断出类型。因此，不需要使用`val webView: WebView = WebView(this)`显式指定类型。根据您过去使用的编程语言，定义参数名称和类型的顺序可能会很熟悉，也可能不会。Kotlin 遵循 Pascal 符号，即名称后跟类型。

1.  现在，运行应用程序，文本将显示如下所示的屏幕截图：![图 1.17 无互联网权限错误消息](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_01_17.jpg)

图 1.17 无互联网权限错误消息

1.  这个错误是因为在您的`AndroidManifest.xml`文件中没有添加`INTERNET`权限。 (如果您收到错误`net::ERR_CLEARTEXT_NOT_PERMITTED`，这是因为您加载到`WebView`中的 URL 不是 HTTPS，而从 API 级别 28、Android 9.0 Pie 及以上版本开始，非 HTTPS 流量被禁用。) 让我们通过向清单添加 Internet 权限来解决这个问题。打开 Android 清单，并在`<application>`标签上方添加以下内容：

```kt
<uses-permission android:name="android.permission.INTERNET" />
```

您的清单文件现在应该如下所示：

```kt
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.myapplication">
    <uses-permission android:name="android.permission.INTERNET" />
    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/AppTheme">
        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name=                  "android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

在再次运行应用程序之前，从虚拟设备中卸载应用程序。有时需要这样做，因为应用程序权限有时会被缓存。长按应用图标，选择出现的`App Info`选项，然后按下带有`Uninstall`文本的垃圾桶图标。或者，长按应用图标，然后将其拖动到屏幕右上角带有`Uninstall`文本的垃圾桶图标旁边。

1.  再次安装应用程序，看到网页出现在`WebView`中：

![图 1.18 应用程序显示 WebView](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_01_18.jpg)

图 1.18 应用程序显示 WebView

在这个例子中，您学会了如何向清单中添加权限。Android 清单可以被视为您的应用程序的目录。它列出了应用程序使用的所有组件和权限。正如您从启动器启动应用程序所看到的那样，它还提供了进入应用程序的入口点。

在下一节中，您将探索 Android 构建系统，该系统使用 Gradle 构建工具来使您的应用程序正常运行。

# 使用 Gradle 构建、配置和管理应用程序依赖项

在创建此项目的过程中，您主要使用了 Android 平台 SDK。安装 Android Studio 时，必要的 Android 库已经下载。然而，这些并不是创建您的应用程序所使用的唯一库。为了配置和构建您的 Android 项目或应用程序，使用了一个名为 Gradle 的构建工具。Gradle 是 Android Studio 用来构建您的应用程序的多用途构建工具。在 Android Studio 中，默认情况下使用 Groovy，这是一种动态类型的 JVM 语言，用于配置构建过程，并允许轻松管理依赖项，以便向项目添加库并指定版本。Android Studio 也可以配置为使用 Kotlin 来配置构建，但是由于默认语言是 Groovy，您将使用这种语言。存储此构建和配置信息的文件名为`build.gradle`。当您首次创建应用程序时，会有两个`build.gradle`文件，一个位于项目的根/顶级目录，另一个位于应用程序`module`文件夹中。

## 项目级`build.gradle`文件

现在让我们来看一下项目级`build.gradle`文件。这是您添加到所有子项目/模块的通用配置选项的地方，如下所示：

```kt
buildscript {
    ext.kotlin_version = "1.4.21"
    repositories {
        google()
        jcenter()
    }
    dependencies {
        classpath "com.android.tools.build:gradle:4.4.1"
        classpath "org.jetbrains.kotlin:kotlin-gradle-plugin:          $kotlin_version"
        // NOTE: Do not place your application dependencies here; 
        //they belong in the individual module build.gradle files
    }
}
allprojects {
    repositories {
        google()
        jcenter()
    }
}
task clean(type: Delete) {
    delete rootProject.buildDir
}
```

`buildscript`块包含了实际创建项目的构建和配置信息，而`allprojects`块指定了所有应用程序模块的配置。Groovy 工作在一个插件系统上，因此您可以编写自己的插件来执行任务或一系列任务，并将其插入到构建流水线中。这里指定的两个插件是 Android 工具插件，它连接到`gradle`构建工具包，并提供了特定于 Android 的设置和配置来构建您的 Android 应用程序，以及 Kotlin `gradle`插件，它负责在项目中编译 Kotlin 代码。依赖项本身遵循 Maven 的`groupId`、`artifactId`和`versionId`，用"`:`"冒号分隔。因此，上面的 Android 工具插件依赖项如下所示：

`'com.android.tools.build:gradle:4.4.1'`

`groupId` 是 `com.android.tools.build`，`artifactId` 是 `gradle`，`versionId` 是 `4.4.1`。这样，构建系统通过使用`repositories`块中引用的仓库来定位和下载这些依赖项。

库的具体版本可以直接指定（就像 Android `tools`插件中所做的那样）在依赖项中，或者作为变量添加。变量上的`ext.`前缀表示它是 Groovy 扩展属性，也可以在应用程序`build.gradle`文件中使用。

注意

在前面的代码部分和本章节以及其他章节的后续部分中指定的依赖版本可能会发生变化，并且随着时间的推移会进行更新，因此在创建这些项目时可能会更高。

## 应用级别的 build.gradle

`build.gradle`应用程序是特定于您的项目配置的：

```kt
plugins {
    id 'com.android.application'
    id 'kotlin-android'
}
android {
    compileSdkVersion 30
    buildToolsVersion "30.0.3"
    defaultConfig {
        applicationId "com.example.myapplication"
        minSdkVersion 16
        targetSdkVersion 30
        versionCode 1
        versionName "1.0"
        testInstrumentationRunner           "androidx.test.runner.AndroidJUnitRunner"
        buildTypes {
            release {
                minifyEnabled false
                proguardFiles getDefaultProguardFile(                  'proguard-android-optimize.txt'), 'proguard-rules.pro'
            }
        }
        compileOptions {
            sourceCompatibility JavaVersion.VERSION_1_8
            targetCompatibility JavaVersion.VERSION_1_8
        }
        kotlinOptions {
            jvmTarget = '1.8'
        }
    }
    dependencies {
        implementation "org.jetbrains.kotlin:kotlin-stdlib:          $kotlin_version"
        implementation 'androidx.core:core-ktx:1.3.2'
        implementation 'androidx.appcompat:appcompat:1.2.0'
        implementation 'com.google.android.material:material:1.2.1'
        implementation 'androidx.constraintlayout:constraintlayout:2.0.4'
        testImplementation 'junit:junit:4.+'
        androidTestImplementation 'androidx.test.ext:junit:1.1.2'
        androidTestImplementation 'androidx.test.espresso           :espresso-core:3.3.0'
    }
}
```

在前面的解释中详细介绍的 Android 和 Kotlin 插件通过`plugins`行中的 id 应用于您的项目。

`com.android.application`插件提供的`android`块是您配置 Android 特定配置设置的地方：

+   `compileSdkVersion`：用于定义应用程序已编译的 API 级别，应用程序可以使用此 API 及更低版本的功能。

+   `buildToolsVersion`：构建应用程序所需的构建工具的版本。（默认情况下，`buildToolsVersion`行将被添加到您的项目中，但是为了始终使用最新版本的构建工具，您可以将其删除）。

+   `defaultConfig`：这是您的应用程序的基本配置。

+   `applicationId`：这是设置为您的应用程序包的标识符，并且是在 Google Play 上用于唯一标识您的应用程序的应用程序标识符。如果需要，可以更改为与包名称不同。

+   `minSdkVersion`：您的应用程序支持的最低 API 级别。这将使您的应用程序在低于此级别的设备上不会在 Google Play 中显示。

+   `targetSdkVersion`：您正在针对的 API 级别。这是您构建的应用程序预期使用并已经测试的 API 级别。

+   `versionCode`：指定您的应用程序的版本代码。每次需要对应用程序进行更新时，版本代码都需要增加 1 或更多。

+   `versionName`：一个用户友好的版本名称，通常遵循 X.Y.Z 的语义版本，其中 X 是主要版本，Y 是次要版本，Z 是补丁版本，例如，1.0.3。

+   `testInstrumentationRunner`：用于 UI 测试的测试运行器。

+   `buildTypes`：在`buildTypes`下，添加了一个`release`，用于配置您的应用程序创建一个`release`构建。如果`minifyEnabled`值设置为`true`，将通过删除任何未使用的代码来缩小应用程序的大小，并对应用程序进行混淆。这个混淆步骤会将源代码引用的名称更改为诸如`a.b.c()`的值。这使得您的代码不太容易被逆向工程，并进一步减小了构建应用程序的大小。

+   `compileOptions`：java 源代码的语言级别（`sourceCompatibility`）和字节码（`targetCompatibility`）

+   `kotlinOptions`：`kotlin gradle`插件应该使用的`jvm`库

`dependencies`块指定了您的应用程序在 Android 平台 SDK 之上使用的库，如下所示：

```kt
    dependencies {
//The version of Kotlin your app is being built with
        implementation "org.jetbrains.kotlin:kotlin-stdlib-jdk7:          $kotlin_version"
//Kotlin extensions, jetpack 
//component with Android Kotlin language features
implementation 'androidx.core:core-ktx:1.3.2'
//Provides backwards compatible support libraries and jetpack components
        implementation 'androidx.appcompat:appcompat:1.2.0'
//Material design components to theme and style your app
        implementation 'com.google.android.material:material:1.2.1'
//The ConstraintLayout ViewGroup updated separately 
//from main Android sources
        implementation 'androidx.constraintlayout:constraintlayout:2.0.4'
//Standard Test library for unit tests. 
//The '+' is a gradle dynamic version which allows downloading the 
//latest version. As this can lead to unpredictable builds if changes 
//are introduced all projects will use fixed version '4.13.1'
        testImplementation 'junit:junit:4.+'
//UI Test runner
        androidTestImplementation 'androidx.test:runner:1.1.2'
//Library for creating Android UI tests
        androidTestImplementation           'androidx.test.espresso:espresso-core:3.3.0'
    }
```

使用`implementation`标记来添加这些库意味着它们的内部依赖不会暴露给您的应用程序，从而加快编译速度。

您将看到这里`androidx`组件被添加为依赖项，而不是在 Android 平台源中。这样可以使它们独立于 Android 版本进行更新。`androidx`是重新打包的支持库和 Jetpack 组件。为了添加或验证您的`gradle.properties`文件是否启用了`androidx`，您需要检查项目根目录下的`gradle.properties`文件，并查找`android.useAndroidX`和`android.enableJetifier`属性，并确保它们设置为`true`。

您现在可以打开`gradle.properties`文件，您会看到以下内容：

```kt
# Project-wide Gradle settings.
# IDE (e.g. Android Studio) users:
# Gradle settings configured through the IDE *will override*
# any settings specified in this file.
# For more details on how to configure your build environment visit
# http://www.gradle.org/docs/current/userguide/build_environment.html
# Specifies the JVM arguments used for the daemon process.
# The setting is particularly useful for tweaking memory settings.
org.gradle.jvmargs=-Xmx2048m -Dfile.encoding=UTF-8
# When configured, Gradle will run in incubating parallel mode.
# This option should only be used with decoupled projects. 
# More details, visit
# http://www.gradle.org/docs/current/userguide/multi_project_builds
# .html#sec
#:decoupled_projects
# org.gradle.parallel=true
# AndroidX package structure to make it clearer which packages are 
# bundled with #the Android operating system, and which are packaged 
# with your app's APK
# https://developer.android.com/topic/libraries/support-library/
# androidx-rn
android.useAndroidX=true
# Automatically convert third-party libraries to use AndroidX
android.enableJetifier=true
# Kotlin code style for this project: "official" or "obsolete":
kotlin.code.style=official
```

当你使用 Android Studio 模板创建项目时，它将这些标志设置为`true`，并将应用程序使用的相关`androidx`依赖项添加到应用程序的`build.gradle`文件的`dependencies`块中。除了前面的注释解释之外，`android.useAndroidX=true`标志表示项目正在使用`androidx`库，而不是旧的支持库，`android.enableJetifier=true`还将把第三方库中使用的旧版本支持库转换为 AndroidX 格式。`kotlin.code.style=official`将把代码风格设置为官方的 kotlin 风格，而不是默认的 Android Studio 风格。

要检查的最终 Gradle 文件是`settings.gradle`。这个文件显示了你的应用程序使用的模块。在使用 Android Studio 创建项目时，只会有一个模块`app`，但当你添加更多功能时，你可以添加新的模块，这些模块专门用于包含该功能的源代码，而不是将其打包到主`app`模块中。这些被称为特性模块，你可以用其他类型的模块来补充它们，比如被所有其他模块使用的共享模块，比如网络模块。`settings.gradle`文件将如下所示：

```kt
include ':app'
rootProject.name='My Application'
```

## 练习 1.04：探索如何使用 Material Design 主题应用程序

在这个练习中，你将学习关于谷歌的新设计语言**Material Design**，并使用它来加载一个**Material Design**主题的应用程序。**Material Design**是谷歌创建的一种设计语言，它增加了基于现实世界效果的丰富 UI 元素，比如光照、深度、阴影和动画。执行以下步骤：

1.  像在*练习 1.01*中一样创建一个新的 Android Studio 项目，*为你的应用程序创建一个 Android Studio 项目*。

1.  首先，查看`dependencies`块，并找到 material design 依赖

```kt
implementation 'com.google.android.material:material:1.2.1'
```

1.  接下来，打开位于`app` | `src` | `main` | `res` | `values` | `themes.xml`的`themes.xml`文件：

```kt
<resources xmlns:tools="http://schemas.android.com/tools">
    <!-- Base application theme. -->
    <style name="Theme.MyApplication"       parent="Theme.MaterialComponents.DayNight.DarkActionBar">
        <!-- Primary brand color. -->
        <item name="colorPrimary">@color/purple_500</item>
        <item name="colorPrimaryVariant">@color/purple_700</item>
        <item name="colorOnPrimary">@color/white</item>
        <!-- Secondary brand color. -->
        <item name="colorSecondary">@color/teal_200</item>
        <item name="colorSecondaryVariant">@color/teal_700</item>
        <item name="colorOnSecondary">@color/black</item>
        <!-- Status bar color. -->
        <item name="android:statusBarColor"           tools:targetApi="l">?attr/colorPrimaryVariant</item>
        <!-- Customize your theme here. -->    </style></resources>
```

注意`Theme.MyApplication`的父级是`Theme.MaterialComponents.DayNight.DarkActionBar`

在`dependencies`块中添加的 Material Design 依赖项被用于应用程序的主题。

1.  如果现在运行应用程序，你将看到默认的 Material 主题应用程序，如*图 1.15*所示。

在这个练习中，你已经学会了如何在屏幕上使用`TextView`，不清楚 material design 提供了什么好处，但当你开始更多地使用 Material UI 设计小部件时，这将会改变。现在你已经学会了项目是如何构建和配置的，在接下来的部分中，你将详细探索项目结构，了解它是如何创建的，并熟悉开发环境的核心领域。

# Android 应用程序结构

现在我们已经介绍了 Gradle 构建工具的工作原理，我们将探索项目的其余部分。最简单的方法是检查应用程序的文件夹结构。在 Android Studio 的左上角有一个名为`Project`的工具窗口，它允许你浏览应用程序的内容。默认情况下，在创建 Android 项目时，它是`打开`/`选中`的。当你选择它时，你会看到一个类似于*图 1.19*中截图的视图。（如果你在屏幕左侧看不到任何窗口栏，那么去顶部工具栏，选择`View` | Appearance | `Tool` `Window Bars`，确保它被选中）。浏览项目有许多不同的选项，但`Android`将被预先选择。这个视图将`app`文件夹结构整齐地分组在一起，让我们来看看它。

这里是这些文件的概述，更详细地介绍了最重要的文件。打开它时，你会看到它包括以下文件夹结构：

![图 1.19：应用程序中文件和文件夹结构的概述](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_01_19.jpg)

图 1.19：应用程序中文件和文件夹结构的概述

您指定为应用程序启动时运行的 Kotlin 文件（`MainActivity`）如下：

```kt
package com.example.myapplication
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
    }
}
```

`import`语句包括此活动使用的库和源。类头`class MainActivity : AppCompatActivity()`创建了一个扩展`AppCompatActivity`的类。在 Kotlin 中，`:`冒号字符用于从类派生（也称为继承）和实现接口。

`MainActivity`派生自`androidx.appcompat.app.AppCompatActivity`，这是向后兼容的活动，旨在使您的应用程序在旧设备上运行。

Android 活动具有许多回调函数，您可以在活动生命周期的不同点重写这些函数。这就是所谓的`onCreate`函数，如下所示：

```kt
override fun onCreate(savedInstanceState: Bundle?) 
```

Kotlin 中的`override`关键字指定您正在为父类中定义的函数提供特定的实现。`fun`关键字（您可能已经猜到）代表*function*。`savedInstanceState: Bundle?`参数是 Android 用于恢复先前保存状态的机制。对于这个简单的活动，您没有存储任何状态，因此这个值将是`null`。跟随类型的问号`?`声明了这种类型可以是`null`。`super.onCreate(savedInstanceState)`行调用了基类的重写方法，最后，`setContentView(R.layout.Activity_main)`加载了我们想要在活动中显示的布局；否则，它将显示为空屏幕，因为没有定义布局。

让我们看看文件夹结构中存在的一些其他文件（*图 1.19*）：

+   `ExampleInstrumentedTest`：这是一个示例 UI 测试。您可以在应用程序运行时运行 UI 测试来检查和验证应用程序的流程和结构。

+   `ExampleUnitTest`：这是一个示例单元测试。创建 Android 应用程序的一个重要部分是编写单元测试，以验证源代码是否按预期工作。

+   `ic_launcher_background.xml`/`ic_launcher_foreground.xml`：这两个文件一起以矢量格式组成应用程序的启动器图标，将由 Android API 26（Oreo）及以上版本中的启动器图标文件`ic_launcher.xml`使用。

+   `activity_main.xml`：这是 Android Studio 创建项目时创建的布局文件。它由`MainActivity`用于绘制初始屏幕内容，该内容在应用程序运行时显示：

```kt
<?xml version="1.0" encoding="utf-8"?>
<androidx.constraintlayout.widget.ConstraintLayout   xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    xmlns:tools="http://schemas.android.com/tools"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    tools:context=".MainActivity">
    <TextView
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="Hello World!"
        app:layout_constraintBottom_toBottomOf="parent"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintTop_toTopOf="parent" />
</androidx.constraintlayout.widget.ConstraintLayout>
```

为了支持应用程序的国际化和从右到左（`rtl`）布局，如果存在这些属性，您应该删除它们：

```kt
        app:layout_constraintStart_toLeftOf="parent"
        app:layout_constraintEnd_toRightOf="parent"
```

用以下内容替换它们：

```kt
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintEnd_toEndOf="parent"
```

这样，开始和结束由应用程序语言确定，而左和右只在从左到右的语言中表示开始和结束。

Android 中的大多数屏幕显示都是使用 XML 布局创建的。文档以 XML 标头开头，后跟顶级`ViewGroup`（这里是`ConstraintLayout`），然后是一个或多个嵌套的`Views`和`ViewGroups`。

`ConstraintLayout` `ViewGroup`允许在屏幕上非常精确地定位视图，通过将视图约束到父视图和兄弟视图、指南线和障碍物。

`TextView`，当前是`ConstraintLayout`的唯一子视图，通过`android:text`属性在屏幕上显示文本。将视图水平定位到父级的开始和结束来完成视图的水平定位，因为应用了两个约束，所以视图在水平方向上居中（从左到右的语言（`ltr`）中的开始和结束是左和右，但在`non ltr`语言中是从右到左）。通过将视图约束到其父级的顶部和底部，将视图垂直定位在中心。应用所有四个约束的结果是在`ConstraintLayout`中将`TextView`水平和垂直居中。

`ConstraintLayout`标签中有三个 XML 命名空间：

+   `xmlns:android`指的是 Android 特定的命名空间，用于主要 Android SDK 中的所有属性和值。

+   `xmlns:app`命名空间用于 Android SDK 中没有的任何内容。因此，在这种情况下，`ConstraintLayout`不是主要 Android SDK 的一部分，而是作为库添加的。

+   `xmnls:tools`指的是用于向 XML 添加元数据的命名空间，用于指示布局在哪里使用（`tools:context=".MainActivity"`）。

Android XML 布局文件的两个最重要的属性是`android:layout_width`和`android:layout_height`。

这些可以设置为绝对值，通常是密度无关像素（称为`dip`或`dp`），它们将像素大小缩放到不同密度设备上大致相等。然而，更常见的是，这些属性的值设置为`wrap_content`或`match_parent`。`wrap_content`将根据其内容大小调整大小。`match_parent`将根据其父级大小调整大小。

还有其他`ViewGroups`可以用来创建布局。`LinearLayout`垂直或水平布局视图，`FrameLayout`通常用于显示单个子视图，`RelativeLayout`是`ConstraintLayout`的简化版本，它布局视图相对于父视图和兄弟视图的位置。

`ic_launcher.png`文件是`.png`启动图标，为不同密度的设备提供了图标。由于我们使用的最低版本的 Android 是 API 16：Android 4.1（果冻豆），因此这些`.png`图像被包含在内，因为直到 Android API 26（奥利奥）之前，对启动器矢量格式的支持才被引入。

`ic_launcher.xml`文件使用矢量文件（`ic_launcher_background.xml`/`ic_launcher_foreground.xml`）在 Android API 26（奥利奥）及以上版本中缩放到不同密度的设备。

注意

为了在 Android 平台上针对不同密度的设备，除了每一个`ic_launcher.png`图标外，您将看到括号中标注了它所针对的密度。由于设备的像素密度差异很大，Google 创建了密度桶，以便根据设备的每英寸点数选择正确的图像来显示。

不同密度限定符及其详细信息如下：

+   `nodpi`：密度无关资源

+   `ldpi`：120 dpi 的低密度屏幕

+   `mdpi`：160 dpi 的中密度屏幕（基线）

+   `hdpi`：240 dpi 的高密度屏幕

+   `xhdpi`：320 dpi 的超高密度屏幕

+   `xxhdpi`：480 dpi 的超高密度屏幕

+   `xxxhdpi`：640 dpi 的超超高密度屏幕

+   `tvdpi`：电视资源（约 213 dpi）

基线密度桶在中密度设备上以每英寸`160`点创建，并称为每英寸`160`点/像素，最大的显示桶是`xxxhdpi`，它有每英寸`640`点。Android 根据各个设备来确定显示的适当图像。因此，Pixel 3 模拟器的密度约为`443dpi`，因此它使用来自超超高密度桶（xxhdpi）的资源，这是最接近的匹配。Android 更倾向于缩小资源以最好地匹配密度桶，因此具有`400dpi`的设备，介于`xhdpi`和`xxhdpi`桶之间，可能会显示来自`xxhdpi`桶的`480dpi`资产。

为了为不同密度创建替代位图可绘制对象，您应该遵循六种主要密度之间的`3:4:6:8:12:16`缩放比例。例如，如果您有一个用于中密度屏幕的`48x48`像素的位图可绘制对象，则所有不同大小应该是：

+   `36x36`（`0.75x`）用于低密度（`ldpi`）

+   `48x48`（`1.0x`基线）用于中密度（`mdpi`）

+   `72x72`（`1.5x`）用于高密度（`hdpi`）

+   `96x96`（`2.0x`）用于超高密度（`xhdpi`）

+   `144x144`（`3.0x`）用于超超高密度（`xxhdpi`）

+   `192x192`（`4.0x`）用于超超超高密度（`xxxhdpi`）

要比较每个密度桶中的这些物理启动器图标，请参考以下表格：

![图 1.20：主要密度桶发射器图像尺寸比较](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_01_20.jpg)

图 1.20：主要密度桶发射器图像尺寸比较

注意

启动器图标比应用程序中的普通图像略大，因为它们将被设备的启动器使用。由于一些启动器可以放大图像，这是为了确保图像没有像素化和模糊。

现在您将查看应用程序使用的一些资源。这些资源在 XML 文件中被引用，并保持应用程序的显示和格式一致。

在`colors.xml`文件中，您以十六进制格式定义了您想在应用程序中使用的颜色。

```kt
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <color name="purple_200">#FFBB86FC</color>
    <color name="purple_500">#FF6200EE</color>
    <color name="purple_700">#FF3700B3</color>
    <color name="teal_200">#FF03DAC5</color>
    <color name="teal_700">#FF018786</color>
    <color name="black">#FF000000</color>
    <color name="white">#FFFFFFFF</color>
</resources>
```

该格式基于 RGB 颜色空间，因此前两个字符是红色，接下来两个是绿色，最后两个是蓝色，其中`#00`表示没有添加任何颜色来组成复合颜色，而`#FF`表示添加了所有颜色。

如果您希望颜色具有一定的透明度，则在前面加上两个十六进制字符，从`#00`表示完全透明到`#FF`表示完全不透明。因此，要创建蓝色和 50%透明的蓝色字符，格式如下：

```kt
    <color name="colorBlue">#0000FF</color>
    <color name="colorBlue50PercentTransparent">#770000FF</color>
```

`strings.xml`文件显示应用程序中显示的所有文本：

```kt
<resources>
    <string name="app_name">My Application</string>
</resources>
```

您可以在应用程序中使用硬编码的字符串，但这会导致重复，并且意味着如果要使应用程序支持多种语言，则无法自定义文本。通过将字符串添加为资源，如果在应用程序的不同位置使用了该字符串，您还可以在一个地方更新该字符串。

您想要在整个应用程序中使用的常见样式都添加到`themes.xml`文件中。

```kt
<resources xmlns:tools="http://schemas.android.com/tools">
    <!-- Base application theme. -->
    <style name="Theme.MyApplication"       parent="Theme.MaterialComponents.DayNight.DarkActionBar">
        <!-- Primary brand color. -->
        <item name="colorPrimary">@color/purple_500</item>
        <item name="colorPrimaryVariant">@color/purple_700</item>
        <item name="colorOnPrimary">@color/white</item>
        <!-- Secondary brand color. -->
        <item name="colorSecondary">@color/teal_200</item>
        <item name="colorSecondaryVariant">@color/teal_700</item>
        <item name="colorOnSecondary">@color/black</item>
        <!-- Status bar color. -->
        <item name="android:statusBarColor"           tools:targetApi="l">?attr/colorPrimaryVariant</item>
        <!-- Customize your theme here. -->
    </style></resources>
```

可以通过在`TextView`的属性上设置`android:textStyle="bold"`来直接向视图应用样式信息。但是，如果您想要将多个`TextView`显示为粗体，您将不得不在多个地方重复这样做。当您开始向单个视图添加多个样式属性时，会出现大量重复，并且在想要对所有类似视图进行更改时可能会导致错误，并且错过更改一个视图上的样式属性。如果您定义了一个样式，您只需更改样式，它将更新所有应用了该样式的视图。在创建项目时，`AndroidManifest.xml`文件中的应用程序标签应用了顶级主题，并被称为为应用程序中包含的所有视图设置样式的主题。您在`colors.xml`文件中定义的颜色在此处使用。实际上，如果您更改了`colors.xml`文件中定义的颜色之一，它现在也会传播到应用程序的样式中。

您现在已经探索了应用程序的核心领域。您已经添加了`TextView`视图来显示标签、标题和文本块。在下一个练习中，您将介绍允许用户与您的应用程序进行交互的 UI 元素。

## 练习 1.05：向用户添加交互式 UI 元素以显示定制的问候语

本练习的目标是使用户能够添加和编辑文本，然后提交此信息以显示带有输入数据的定制问候语。您需要添加可编辑的文本视图来实现这一点。`EditText`视图通常是这样做的，可以在 XML 布局文件中添加如下：

```kt
<EditText
    android:id="@+id/full_name"
    style="@style/TextAppearance.AppCompat.Title"
    android:layout_width="wrap_content"
    android:layout_height="wrap_content"
    android:hint="@string/first_name" />
```

这使用了一个 Android 样式`TextAppearance.AppCompat.Title`来显示标题，如下所示：

![图 1.21：带提示的 EditText](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_01_21.jpg)

图 1.21：带提示的 EditText

虽然这对于启用用户添加/编辑文本是完全可以的，但是材料`TextInputEditText`及其包装视图`TextInputLayout`为`EditText`显示提供了一些修饰。让我们使用以下代码：

```kt
    <com.google.android.material.textfield.TextInputLayout
        android:id="@+id/first_name_wrapper"
        style="@style/text_input_greeting"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:hint="@string/first_name_text">
        <com.google.android.material.textfield.TextInputEditText
            android:id="@+id/first_name"
            android:layout_width="match_parent"
            android:layout_height="wrap_content" />
    </com.google.android.material.textfield.TextInputLayout>
```

输出如下：

![图 1.22：带提示的 Material TextInputLayout/TextInputEditText](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_01_22.jpg)

图 1.22：带提示的 Material TextInputLayout/TextInputEditText

`TextInputLayout`允许我们为`TextInputEditText`视图创建一个标签，并在`TextInputEditText`视图聚焦时进行漂亮的动画（移动到字段的顶部），同时仍然显示标签。标签是使用`android:hint`指定的。

您将更改应用程序中的`Hello World`文本，以便用户可以输入他们的名字和姓氏，并在按下按钮时显示问候。执行以下步骤：

1.  通过将以下条目添加到`app` | `src` | `main` | `res` | `values` | `strings.xml`中，创建您的应用程序中要使用的标签和文本：

```kt
<resources>
    <string name="app_name">My Application</string>
    <string name="first_name_text">First name:</string>
    <string name="last_name_text">Last name:</string>
    <string name="enter_button_text">Enter</string>
    <string name="welcome_to_the_app">Welcome to the app</string>
    <string name="please_enter_a_name">Please enter a full name!
    </string>
</resources>
```

1.  接下来，我们将通过在`app` | `src` | `main` | `res` | `themes.xml`中添加以下样式来更新我们要在布局中使用的样式（在基本应用程序主题之后）

```kt
<resources xmlns:tools="http://schemas.android.com/tools">
    <!-- Base application theme. -->
    <style name="Theme.MyApplication"       parent="Theme.MaterialComponents.DayNight.DarkActionBar">
        <!-- Primary brand color. -->
        <item name="colorPrimary">@color/purple_500</item>
        <item name="colorPrimaryVariant">@color/purple_700</item>
        <item name="colorOnPrimary">@color/white</item>
        <!-- Secondary brand color. -->
        <item name="colorSecondary">@color/teal_200</item>
        <item name="colorSecondaryVariant">@color/teal_700</item>
        <item name="colorOnSecondary">@color/black</item>
        <!-- Status bar color. -->
        <item name="android:statusBarColor"           tools:targetApi="l">?attr/colorPrimaryVariant</item>
        <!-- Customize your theme here. -->
    </style>
    <style name="text_input_greeting"       parent="Widget.MaterialComponents.TextInputLayout.OutlinedBox">
        <item name="android:layout_margin">8dp</item>
    </style>
    <style name="button_greeting">
        <item name="android:layout_margin">8dp</item>
        <item name="android:gravity">center</item>
    </style>
    <style name="greeting_display"         parent="@style/TextAppearance.MaterialComponents.Body1">
        <item name="android:layout_margin">8dp</item>
        <item name="android:gravity">center</item>
        <item name="android:layout_height">40dp</item>
    </style>
    <style name="screen_layout_margin">
        <item name="android:layout_margin">12dp</item>
    </style>
</resources>
```

注意

一些样式的父样式引用了材料样式，因此这些样式将直接应用于视图，以及指定的样式。

1.  现在，我们已经添加了要应用于布局和文本中的视图的样式，我们可以在`app` | `src` | `main` | `res` | `layout`文件夹中的`activity_main.xml`中更新布局。下面的代码由于空间原因而被截断，但您可以使用下面的链接查看完整的源代码。

```kt
activity_main.xml
10    <com.google.android.material.textfield.TextInputLayout
11        android:id="@+id/first_name_wrapper"
12        style="@style/text_input_greeting"
13        android:layout_width="match_parent"
14        android:layout_height="wrap_content"
15        android:hint="@string/first_name_text"
16        app:layout_constraintTop_toTopOf="parent"
17        app:layout_constraintStart_toStartOf="parent">
18
19        <com.google.android.material.textfield.TextInputEditText
20            android:id="@+id/first_name"
21            android:layout_width="match_parent"
22            android:layout_height="wrap_content" />
23
24    </com.google.android.material.textfield.TextInputLayout>
25
26    <com.google.android.material.textfield.TextInputLayout
27        android:id="@+id/last_name_wrapper"
28        style="@style/text_input_greeting"
29        android:layout_width="match_parent"
30        android:layout_height="wrap_content"
31        android:hint="@string/last_name_text"
32        app:layout_constraintTop_toBottomOf="@id/first_name_wrapper"
33        app:layout_constraintStart_toStartOf="parent">
34
35        <com.google.android.material.textfield.TextInputEditText
36            android:id="@+id/last_name"
37            android:layout_width="match_parent"
38            android:layout_height="wrap_content" />
39
40    </com.google.android.material.textfield.TextInputLayout>
41
42    <com.google.android.material.button.MaterialButton
43        android:layout_width="match_parent"
44        android:layout_height="wrap_content"
45        style="@style/button_greeting"
46        android:id="@+id/enter_button"
47        android:text="@string/enter_button_text"
48        app:layout_constraintTop_toBottomOf="@id/last_name_wrapper"
49        app:layout_constraintStart_toStartOf="parent"/>
50
51    <TextView
52        android:id="@+id/greeting_display"
53        android:layout_width="match_parent"
54        style="@style/greeting_display"
55        app:layout_constraintTop_toBottomOf="@id/enter_button"
56        app:layout_constraintStart_toStartOf="parent" />
The complete code for this step can be found at http://packt.live/35T5IMN.
```

您已为所有视图添加了 ID，以便可以将它们约束到它们的兄弟视图，并且还提供了一种在活动中获取`TextInputEditText`视图的值的方法。`style="@style.."`符号应用了`themes.xml`文件中的样式。

1.  运行应用程序并查看外观和感觉。如果您选择`TextInputEditText`视图中的一个，您将看到标签被动画化并移动到视图的顶部：![图 1.23：TextInputEditText 字段的标签状态，无焦点和有焦点](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_01_23.jpg)

图 1.23：TextInputEditText 字段的标签状态，无焦点和有焦点

1.  现在，我们必须在我们的活动中添加与视图的交互。布局本身除了允许用户在`EditText`字段中输入文本之外，不会做任何事情。在这个阶段点击按钮不会做任何事情。您将通过在按钮被按下时使用表单字段的 ID 捕获输入的文本，然后使用文本填充`TextView`消息来实现这一点。

1.  打开`MainActivity`并完成下一步，处理输入的文本并使用这些数据显示问候并处理任何表单输入错误。

1.  在`onCreate`函数中，为按钮设置一个点击监听器，这样我们就可以响应按钮点击并通过更新`MainActivity`来检索表单数据，显示如下内容：

```kt
package com.example.myapplication
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.view.Gravity
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import com.google.android.material.textfield.TextInputEditText
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        findViewById<Button>(R.id.enter_button)?.setOnClickListener {
            //Get the greeting display text
            val greetingDisplay =               findViewById<TextView>(R.id.greeting_display)
            //Get the first name TextInputEditText value
            val firstName = findViewById<TextInputEditText>              (R.id.first_name)?.text.toString().trim()
            //Get the last name TextInputEditText value
            val lastName = findViewById<TextInputEditText>              (R.id.last_name)?.text.toString().trim()
            //Check names are not empty here:
        }
    }
}
```

1.  然后，检查修剪后的名称是否为空，并使用 Kotlin 的字符串模板格式化名称：

```kt
if (firstName.isNotEmpty() && lastName.isNotEmpty()) {
    val nameToDisplay = firstName.plus(" ").plus(lastName)
    //Use Kotlin's string templates feature to display the name
    greetingDisplay?.text =
        " ${getString(R.string.welcome_to_the_app)} ${nameToDisplay}!"
}
```

1.  最后，如果表单字段没有正确填写，显示一条消息：

```kt
else {
    Toast.makeText(this, getString(R.string.please_enter_a_name),       Toast.LENGTH_LONG).
    apply{
        setGravity(Gravity.CENTER, 0, 0)
        show()
    }
}
```

指定的`Toast`是一个小型文本对话框，它在主布局上方短暂出现，以向用户显示消息，然后消失。

1.  运行应用程序并在字段中输入文本，验证当两个文本字段都填写时是否显示问候消息，并且如果两个字段都没有填写，则弹出消息显示为什么没有设置问候。您应该看到以下显示：![图 1.24：名称填写正确和错误的应用程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_01_24.jpg)

图 1.24：名称填写正确和错误的应用程序

完整的练习代码可以在这里查看：[`packt.live/39JyOzB`](http://packt.live/39JyOzB)

前面的练习介绍了如何通过`EditText`字段向应用程序添加交互性，用户可以填写这些字段，添加点击监听器以响应按钮事件并执行一些验证。

## 访问布局文件中的视图

在布局文件中访问视图的已建立的方法是使用`findViewById`和视图的 id 名称。因此，在 Activity 中的`setContentView(R.layout.activity_main)`设置布局后，可以通过语法`findViewById<Button>(R.id.enter_button)`检索`enter_button` `Button`。您将在本课程中使用这种技术。Google 还引入了 ViewBinding 来替代`findViewById`，它创建一个绑定类来访问视图，并具有空值和类型安全的优势。您可以在这里阅读有关此内容：[`developer.android.com/topic/libraries/view-binding`](https://developer.android.com/topic/libraries/view-binding)

## 进一步的输入验证

验证用户输入是处理用户数据的关键概念，当您没有在表单中输入必填字段时，您必须已经多次看到它的作用。在上一个练习中，当检查用户是否已经在名字和姓氏字段中输入值时，就是在验证用户输入。

还有其他验证选项可以直接在 XML 视图元素中使用。例如，假设您想要验证输入到字段中的 IP 地址。您知道 IP 地址可以是由句点/点分隔的四个数字，其中数字的最大长度为 3。因此，可以输入到字段中的字符的最大数量为 15，并且只能输入数字和句点。有两个 XML 属性可以帮助我们进行验证：

+   `android:digits="0123456789."`：通过列出所有允许的单个字符，限制可以输入到字段中的字符。

+   `android:maxLength="15"`：限制用户输入超过 IP 地址将包含的最大字符数。

因此，这是您可以在表单字段中显示的方式：

```kt
<com.google.android.material.textfield.TextInputLayout
    style="@style/Widget.MaterialComponents.TextInputLayout.OutlinedBox"
    android:layout_width="match_parent"
    android:layout_height="wrap_content">
    <com.google.android.material.textfield.TextInputEditText
        android:id="@+id/ip_address"
        android:digits="0123456789."
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:maxLength="15" />
</com.google.android.material.textfield.TextInputLayout>
```

此验证限制了可以输入的字符和最大长度。还需要对字符序列以及它们是否为句点/点或数字进行额外验证，如 IP 地址格式所述，但这是帮助用户输入正确字符的第一步。

在本章中获得的知识，让我们从以下活动开始。

## 活动 1.01：创建一个应用程序来生成 RGB 颜色

在这个活动中，我们将研究一个使用验证的场景。假设您被要求创建一个应用程序，显示红色、绿色和蓝色的 RGB 通道如何添加到 RGB 颜色空间中以创建颜色。每个 RGB 通道应该作为两个十六进制字符添加，其中每个字符的值可以是 0-9 或 A-F。然后将这些值组合起来，生成一个 6 个字符的十六进制字符串，该字符串将作为颜色显示在应用程序中。

这个活动的目的是生成一个具有可编辑字段的表单，用户可以为每种颜色添加两个十六进制值。填写完所有三个字段后，用户应单击一个按钮，该按钮获取三个值并将它们连接起来以创建有效的十六进制颜色字符串。然后将其转换为颜色，并显示在应用程序的 UI 中。

以下步骤将帮助您完成该活动：

1.  创建一个名为`Colors`的新项目

1.  将标题添加到布局，约束到布局的顶部。

1.  向用户添加一个简短的说明，说明如何填写表单。

1.  在“标题”下方添加三个材料`TextInputLayout`字段，包裹三个`TextInputEditText`字段。这些应该被约束，以便每个视图位于另一个视图的上方（而不是侧面）。分别将`TextInputEditText`字段命名为“红色通道”、“绿色通道”和“蓝色通道”，并对每个字段添加限制，只能输入两个字符并添加十六进制字符。

1.  添加一个按钮，该按钮获取三个颜色字段的输入。

1.  添加一个视图，用于在布局中显示生成的颜色。

1.  最后，在布局中显示由三个通道创建的 RGB 颜色。

最终输出应如下所示（颜色将根据输入而变化）：

![图 1.25：显示颜色时的输出](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_01_25.jpg)

图 1.25：显示颜色时的输出

注意

此活动的解决方案可在此处找到：[`packt.live/3sKj1cp`](http://packt.live/3sKj1cp)

本章中所有练习和活动的来源都在这里：[`packt.live/2LLY9kb`](http://packt.live/2LLY9kb)

注意

当首次将此课程的所有已完成项目从 Github 存储库加载到 Android Studio 时，*不要*使用顶部菜单中的`File` | `Open`打开项目。始终使用`File` | `New` | `Import Project`。这是为了正确构建应用程序。在初始导入后打开项目时，可以使用`File` | `Open`或`File` | `Open Recent`。

# 摘要

本章已经涵盖了很多关于 Android 开发基础的内容。您首先学习了如何使用 Android Studio 创建 Android 项目，然后在虚拟设备上创建和运行应用程序。接着，本章通过探索`AndroidManifest`文件来详细介绍了应用程序的内容和权限模型，然后介绍了 Gradle 以及添加依赖项和构建应用程序的过程。然后深入了解了 Android 应用程序的细节以及文件和文件夹结构。介绍了布局和视图，并进行了练习，以说明如何使用 Google 的 Material Design 构建用户界面。下一章将在此基础上继续学习活动生命周期、活动任务和启动模式，以及在屏幕之间持久化和共享数据，以及如何通过应用程序创建强大的用户体验。


# 第二章：构建用户屏幕流程

概述

本章涵盖了 Android 活动生命周期，并解释了 Android 系统如何与您的应用程序交互。通过本章的学习，您将学会如何在不同屏幕之间构建用户旅程。您还将能够使用活动任务和启动模式，保存和恢复活动的状态，使用日志报告您的应用程序，并在屏幕之间共享数据。

# 介绍

上一章向您介绍了 Android 开发的核心元素，从使用`AndroidManifest.xml`文件配置您的应用程序，使用简单活动和 Android 资源结构，到使用`build.gradle`构建应用程序并在虚拟设备上运行应用程序。在本章中，您将进一步学习 Android 系统如何通过 Android 生命周期与您的应用程序交互，您将被通知应用程序状态的变化，以及您如何使用 Android 生命周期来响应这些变化。然后，您将学习如何在应用程序中创建用户旅程以及如何在屏幕之间共享数据。您将介绍不同的技术来实现这些目标，以便您能够在自己的应用程序中使用它们，并在其他应用程序中看到它们被使用时能够识别出来。

# 活动生命周期

在上一章中，我们使用`onCreate(saveInstanceState: Bundle?)`方法在屏幕的 UI 中显示布局。现在，我们将更详细地探讨 Android 系统如何与您的应用程序交互以实现这一点。一旦启动 Activity，它就会经历一系列步骤，使其经过初始化并准备好显示部分显示，然后完全显示。还有一些步骤对应着您的应用程序被隐藏、后台运行，然后被销毁。这个过程被称为**Activity 生命周期**。对于这些步骤中的每一个，都有一个**回调**，您的 Activity 可以使用它来执行操作，比如在您的应用程序被放入后台时创建和更改显示，并在您的应用程序恢复到前台后恢复数据。您可以将这些回调视为系统与您的 Activity/屏幕交互的钩子。

每个 Activity 都有一个父 Activity 类，它是扩展的。这些回调是在您的 Activity 的父类上进行的，由您决定是否需要在自己的 Activity 中实现它们以执行任何相应的操作。这些回调函数中的每一个都有`override`关键字。在 Kotlin 中，`override`关键字表示这个函数要么提供接口或抽象方法的实现，要么在这里的 Activity 中，它是一个子类，它提供了将覆盖其父类的实现。

现在您已经了解了**Activity 生命周期**的一般工作原理，让我们更详细地了解您将按顺序使用的主要回调，从创建 Activity 到销毁 Activity：

+   `override fun onCreate(savedInstanceState: Bundle?)`: 这是你在绘制全屏幕大小的活动中最常用的回调。在这里，你准备好你的活动布局以便显示。在此阶段，方法完成后，尽管如果你不实现任何其他回调，它仍未显示给用户，但如果你不实现任何其他回调，它看起来是这样的。你通常通过调用`setContentView`方法`setContentView(R.layout.activity_main)`来设置活动的 UI，并进行任何必要的初始化。这个方法只会在其`savedInstanceState`参数中调用一次，`Bundle?`类型（`?`表示类型可以为 null），在其最简单的形式中是一种优化保存和恢复数据的键值对映射。如果这是应用程序启动后首次运行活动，或者活动首次创建或重新创建而没有保存任何状态，它将为 null。如果在活动重新创建之前已在`onSaveInstanceState(outState: Bundle?)`回调中保存了状态，它可能包含一个保存的状态。

+   `override fun onRestart()`: 当活动重新启动时，此方法会在`onStart()`之前立即调用。重启活动和重新创建活动之间的区别很重要。当活动通过按下主页按钮置于后台时，例如，当它再次进入前台时，将调用`onRestart()`。重新创建活动是指发生配置更改，例如设备旋转时发生的情况。活动被结束然后重新创建。

+   `override fun onStart()`: 当活动首次显示时进行的回调。此外，在通过按下返回、主页或`最近应用/概览`硬件按钮将应用置于后台后，从`最近应用/概览`菜单或启动器中再次选择应用时，也会运行此函数。这是可见生命周期方法中的第一个。

+   `override fun onRestoreInstanceState(savedInstanceState: Bundle?)`: 如果状态已经使用`onSaveInstanceState(outState: Bundle?)`保存，系统会在`onStart()`之后调用此方法，你可以在这里检索`Bundle`状态，而不是在`onCreate(savedInstanceState: Bundle?)`期间恢复状态。

+   `override fun onResume()`: 这个回调函数在首次创建活动的最后阶段运行，也在应用程序被置于后台然后再次进入前台时运行。在完成这个回调后，屏幕/活动已经准备好被使用，接收用户事件，并且响应。

+   `override fun onSaveInstanceState(outState: Bundle?)`: 如果你想保存活动的状态，这个函数可以做到。你可以使用便捷函数之一添加键值对，具体取决于数据类型。如果你的活动在`onCreate(saveInstanceState: Bundle?)`和`onRestoreInstanceState(savedInstanceState: Bundle?)`中重新创建，这些数据将可用。

+   `override fun onPause()`: 当活动开始被置于后台或另一个对话框或活动进入前台时，调用此函数。

+   `override fun onStop()`: 当活动被隐藏时调用此函数，无论是因为被置于后台还是因为另一个活动在其上启动。

+   `override fun onDestroy()`: 当系统资源不足时，显式调用`finish()`方法，或者更常见的是用户从最近应用/概览按钮关闭应用时，系统会调用此函数来销毁活动。

既然你了解了这些常见的生命周期回调函数的作用，让我们实现它们，看它们何时被调用。

## 练习 2.01：记录活动回调

让我们创建一个名为*Activity Callbacks*的应用程序，其中包含一个空活动，就像您在*第一章*中所做的那样，创建您的第一个应用程序。这个练习的目的是记录活动回调以及它们发生的顺序，以进行常见操作：

1.  应用程序创建后，`MainActivity`将如下所示：

```kt
package com.example.activitycallbacks
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
    }
}
```

为了验证回调的顺序，让我们在每个回调的末尾添加一个日志语句。为了准备活动进行日志记录，通过在`import`语句中添加`import android.util.Log`来导入 Android 日志包。然后，在类中添加一个常量来标识您的活动。Kotlin 中的常量由`const`关键字标识，并且可以在顶层（类外）或在类内的对象中声明。如果需要公共常量，通常使用顶级常量。对于私有常量，Kotlin 提供了一种方便的方法，通过声明伴生对象来向类添加静态功能。在类的底部以下添加以下内容`onCreate(savedInstanceState: Bundle?)`：

```kt
companion object {
    private const val TAG = "MainActivity"
}
```

然后在`onCreate(savedInstanceState: Bundle?)`的末尾添加一个日志语句：

```kt
Log.d(TAG, "onCreate")
```

我们的活动现在应该有以下代码：

```kt
package com.example.activitycallbacks
import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        Log.d(TAG, "onCreate")
    }
    companion object {
        private const val TAG = "MainActivity"
    }
}
```

在前面的日志语句中，`d`代表*debug*。有六种不同的日志级别可以用来输出从最不重要到最重要的消息信息 - `v`代表*verbose*，`d`代表*debug*，`i`代表*info*，`w`代表*warn*，`e`代表*error*，`wtf`代表*what a terrible failure*。（最后一个日志级别突出显示了一个不应该发生的异常。）

```kt
        Log.v(TAG, "verbose message")
        Log.d(TAG, "debug message")
        Log.i(TAG, "info message")
        Log.w(TAG, "warning message")
        Log.e(TAG, "error message")
        Log.wtf(TAG, "what a terrible failure message")
```

1.  现在，让我们看看日志在 Android Studio 中是如何显示的。打开`Logcat`窗口。可以通过单击屏幕底部的`Logcat`选项卡或者从工具栏中转到`View` | `Tool Windows` | `Logcat`来访问它。

1.  在虚拟设备上运行应用程序并检查`Logcat`窗口输出。您应该看到您添加的日志语句的格式如*图 2.1*中的以下行：![图 2.1：Logcat 中的日志输出](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_02_01.jpg)

图 2.1：Logcat 中的日志输出

1.  日志语句一开始可能很难解释，所以让我们将以下语句分解为其各个部分：

```kt
2020-03-03  20:36:12.308  21415-21415/com.example.activitycallbacks D/MainActivity: onCreate
```

让我们详细检查日志语句的元素：

![图 2.2：解释日志语句的表](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_02_02.jpg)

图 2.2：解释日志语句的表

您可以通过将日志过滤器从`Debug`更改为下拉菜单中的其他选项来检查不同日志级别的输出。如果您选择`Verbose`，正如其名称所示，您将看到大量输出。

1.  日志语句的`TAG`选项之所以好用，是因为它使您能够通过输入标签的文本来过滤在 Android Studio 的`Logcat`窗口中报告的日志语句，如*图 2.3*所示：![图 2.3：通过 TAG 名称过滤日志语句](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_02_03.jpg)

图 2.3：通过 TAG 名称过滤日志语句

因此，如果您正在调试活动中的问题，您可以输入`TAG`名称并向您的活动添加日志以查看日志语句的顺序。这就是您接下来要做的事情，通过实现主要活动回调并向每个回调添加一个日志语句来查看它们何时运行。

1.  在`onCreate(savedInstanceState: Bundle?)`函数的右括号后的新行上放置光标，然后添加`onRestart()`回调和一个日志语句。确保调用`super.onRestart()`，以便活动回调的现有功能按预期工作：

```kt
override fun onRestart() {
    super.onRestart()
    Log.d(TAG, "onRestart")
}
```

1.  一旦您开始输入函数的名称，Android Studio 的自动完成功能将建议您要重写的函数的名称选项。

```kt
onCreate(savedInstanceState: Bundle?)
onRestart()
onStart()
onRestoreInstanceState(savedInstanceState: Bundle?)
onResume()
onPause()
onStop()
onSaveInstanceStateoutState: Bundle?)
onDestroy()
```

1.  您的活动现在应该有以下代码（此处截断）。您可以在 GitHub 上查看完整的代码[`packt.live/38W7jU5`](http://packt.live/38W7jU5

）

完成的活动现在将使用您的实现覆盖回调，其中添加了一个日志消息：

```kt
package com.example.activitycallbacks
import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        Log.d(TAG, "onCreate")
    }
    override fun onRestart() {
        super.onRestart()
        Log.d(TAG, "onRestart")
    }
    //Remaining callbacks follow: see github link above
    companion object {
        private const val TAG = "MainActivity"
    }
}
```

1.  运行应用程序，一旦加载完成，就像*图 2.4*中一样，查看`Logcat`输出；您应该会看到以下日志语句（这是一个缩短版）：

```kt
D/MainActivity: onCreate
D/MainActivity: onStart
D/MainActivity: onResume
```

已创建、启动并准备好供用户进行交互的活动：

![图 2.4：应用程序加载并显示 MainActivity](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_02_04.jpg)

图 2.4：应用程序加载并显示 MainActivity

1.  按下底部导航控件中心的圆形主页按钮，将应用程序放到后台。您现在应该看到以下`Logcat`输出：

```kt
D/MainActivity: onPause
D/MainActivity: onStop
D/MainActivity: onSaveInstanceState
```

对于目标低于 Android Pie（API 28）的应用程序，`onSaveInstanceState(outState: Bundle?)`也可能在`onPause()`或`onStop()`之前被调用。

1.  现在，通过按下右侧的最近/概览按钮（通常是一个方形或三条垂直线）并选择应用程序，或者通过转到启动器并打开应用程序，将应用程序带回前台。您现在应该看到以下内容：

```kt
D/MainActivity: onRestart
D/MainActivity: onStart
D/MainActivity: onResume
```

活动已重新启动。您可能已经注意到`onRestoreInstanceState(savedInstanceState: Bundle)`函数未被调用。这是因为活动未被销毁和重建。

1.  按下底部导航控件左侧（也可能在右侧）的三角形返回按钮，您将看到活动被销毁。您还可以通过按下最近/概览按钮，然后向上滑动应用程序来终止活动。这是输出：

```kt
D/MainActivity: onPause
D/MainActivity: onStop
D/MainActivity: onDestroy
```

1.  再次启动应用程序，然后旋转手机。您可能会发现手机不会旋转，显示屏是横向的。如果发生这种情况，请在虚拟设备顶部拉下状态栏，并选择设置中从右边数第二个的自动旋转按钮。![图 2.5：快速设置栏，选中 Wi-Fi 和自动旋转按钮](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_02_05.jpg)

```kt
D/MainActivity: onCreate
D/MainActivity: onStart
D/MainActivity: onResume
D/MainActivity: onPause
D/MainActivity: onStop
D/MainActivity: onSaveInstanceState
D/MainActivity: onDestroy
D/MainActivity: onCreate
D/MainActivity: onStart
D/MainActivity: onRestoreInstanceState
D/MainActivity: onResume
```

请注意，如步骤 11 所述，`onSaveInstanceState(outState: Bundle?)`回调的顺序可能会有所不同。

1.  默认情况下，配置更改（例如旋转手机）会重新创建活动。您可以选择不在应用程序中处理某些配置更改，这样就不会重新创建活动。要对旋转进行此操作，请在`AndroidManifest.xml`文件的`MainActivity`中添加`android:configChanges="orientation|screenSize|screenLayout"`。启动应用程序，然后旋转手机，您将看到已添加到`MainActivity`的唯一回调：

```kt
D/MainActivity: onCreate
D/MainActivity: onStart
D/MainActivity: onResume
```

`orientation`和`screenSize`值对于不同的 Android API 级别具有相同的功能，用于检测屏幕方向的更改。`screenLayout`值检测可能在可折叠手机上发生的其他布局更改。这些是您可以选择自行处理的一些配置更改（另一个常见的更改是`keyboardHidden`，用于对访问键盘的更改做出反应）。应用程序仍将通过以下回调被系统通知这些更改：

```kt
override fun onConfigurationChanged(newConfig: Configuration) {
    super.onConfigurationChanged(newConfig)
    Log.d(TAG, "onConfigurationChanged")
}
```

如果您将此回调函数添加到`MainActivity`，并且在清单中为`MainActivity`添加了`android:configChanges="orientation|screenSize|screenLayout"`，您将在旋转时看到它被调用。

在这个练习中，您已经了解了主要的活动回调以及当用户通过系统与`MainActivity`进行常见操作时它们是如何运行的。在下一节中，您将学习保存状态和恢复状态，以及看到活动生命周期的更多示例。

# 保存和恢复活动状态

在本节中，你将探索你的 Activity 如何保存和恢复状态。正如你在上一节中学到的，配置更改，比如旋转手机，会导致 Activity 被重新创建。如果系统需要杀死你的应用程序以释放内存，也会发生这种情况。在这些情景中，保留 Activity 的状态然后恢复它是很重要的。在接下来的两个练习中，你将通过一个示例确保当`TextView`被创建并从用户的数据中填充表单后，用户的数据得到恢复。

## 练习 2.02：在布局中保存和恢复状态

在这个练习中，首先创建一个名为*Save and Restore*的应用程序，其中包含一个空的活动。你将创建的应用程序将有一个简单的表单，如果用户输入一些个人信息，就会提供一个用户最喜欢的餐厅的折扣码（实际上不会发送任何信息，所以你的数据是安全的）：

1.  打开`strings.xml`文件（位于`app` | `src` | `main` | `res` | `values` | `strings.xml`），并创建你的应用程序所需的以下字符串：

```kt
<resources>
    <string name="app_name">Save And Restore</string>
    <string name="header_text">Enter your name and email       for a discount code at Your Favorite Restaurant!        </string>
    <string name="first_name_label">First Name:</string>
    <string name="email_label">Email:</string>
    <string name="last_name_label">Last Name:</string>
    <string name="discount_code_button">GET DISCOUNT</string>
    <string name="discount_code_confirmation">Your       discount code is below %s. Enjoy!</string>
</resources>
```

1.  你还将直接指定一些文本大小、布局边距和填充，因此在`app` | `src` | `main` | `res` | `values`文件夹中创建`dimens.xml`文件，并添加你的应用程序所需的尺寸（你可以通过在 Android Studio 中右键单击`res` | `values`文件夹，然后选择`New` `values`来完成）：

```kt
<?xml version="1.0" encoding="utf-8"?>
<resources>
    <dimen name="grid_4">4dp</dimen>
    <dimen name="grid_8">8dp</dimen>
    <dimen name="grid_12">12dp</dimen>
    <dimen name="grid_16">16dp</dimen>
    <dimen name="grid_24">24dp</dimen>
    <dimen name="grid_32">32dp</dimen>
    <dimen name="default_text_size">20sp</dimen>
    <dimen name="discount_code_text_size">20sp</dimen>
</resources>
```

在这里，你正在指定练习中所需的所有尺寸。你将看到`default_text_size`和`discount_code_text_size`在`sp`中指定。它们代表与密度无关的像素，不仅根据你的应用程序运行的设备的密度定义尺寸测量，而且根据用户在`设置` | `显示` | `字体样式`中定义的偏好更改文本大小（这可能是`字体大小和样式`或类似的，具体取决于你使用的确切设备）。

1.  在`R.layout.activity_main`中，添加以下 XML，创建一个包含布局文件，并添加一个带有`Enter your name and email for a discount code at Your Favorite Restaurant!`文本的标题`TextView`。这是通过添加`android:text`属性和`@string/header_text`值来完成的：

```kt
<?xml version="1.0" encoding="utf-8"?>
<androidx.constraintlayout.widget.ConstraintLayout 
    xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    xmlns:tools="http://schemas.android.com/tools"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    android:padding="@dimen/grid_4"
    android:layout_marginTop="@dimen/grid_4"
    tools:context=".MainActivity">
    <TextView
        android:id="@+id/header_text"
        android:gravity="center"
        android:textSize="@dimen/default_text_size"
        android:paddingStart="@dimen/grid_8"
        android:paddingEnd="@dimen/grid_8"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="@string/header_text"
        app:layout_constraintTop_toTopOf="parent"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent"/>
</androidx.constraintlayout.widget.ConstraintLayout>
```

你正在使用`ConstraintLayout`来约束父视图和同级视图。

尽管通常应该使用样式来指定视图的显示，但你可以直接在 XML 中进行，就像这里的一些属性所做的那样。`android:textSize`属性的值是`@dimen/default_text_size`，在前面的代码块中定义，你可以使用它来避免重复，并且它使你能够在一个地方更改所有文本的大小。使用样式是设置文本大小的首选选项，因为你将获得合理的默认值，并且你可以在样式中覆盖该值，或者像你在这里做的那样，在单独的视图上覆盖该值。

其他影响定位的属性也直接在视图中指定。最常见的是填充和边距。填充应用在视图的内部，是文本和边框之间的空间。边距在视图的外部指定，是视图的外边缘之间的空间。例如，在`ConstraintLayout`中，`android:padding`设置了具有指定值的视图的填充。或者，你可以使用`android:paddingTop`、`android:paddingBottom`、`android:paddingStart`和`android:paddingEnd`来指定视图的四个边的填充。这种模式也存在于指定边距，所以`android:layout_margin`指定了视图四个边的边距值，`android:layoutMarginTop`、`android:layoutMarginBottom`、`android:layoutMarginStart`和`android:layoutMarginEnd`允许设置单独边的边距。

对于小于 17 的 API 级别（并且您的应用程序支持到 16），如果使用`android:layoutMarginStart`，则还必须添加`android:layoutMarginLeft`，如果使用`android:layoutMarginEnd`，则必须添加`android:layoutMarginRight`。为了在整个应用程序中保持一致性和统一性，您将边距和填充值定义为包含在`dimens.xml`文件中的尺寸。

要在视图中定位内容，您可以指定`android:gravity`。`center`值会在`View`内垂直和水平方向上约束内容。

1.  接下来，在`header_text`下方添加三个`EditText`视图，供用户添加他们的名字、姓氏和电子邮件：

```kt
    <EditText
        android:id="@+id/first_name"
        android:textSize="@dimen/default_text_size"
        android:layout_marginStart="@dimen/grid_24"
        android:layout_marginLeft="@dimen/grid_24"
        android:layout_marginEnd="@dimen/grid_16"
        android:layout_marginRight="@dimen/grid_16"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:hint="@string/first_name_label"
        android:inputType="text"
        app:layout_constraintTop_toBottomOf="@id/header_text"
        app:layout_constraintStart_toStartOf="parent" />
    <EditText
        android:textSize="@dimen/default_text_size"
        android:layout_marginEnd="@dimen/grid_24"
        android:layout_marginRight="@dimen/grid_24"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:hint="@string/last_name_label"
        android:inputType="text"
        app:layout_constraintTop_toBottomOf="@id/header_text"
        app:layout_constraintStart_toEndOf="@id/first_name"
        app:layout_constraintEnd_toEndOf="parent" />
    <!-- android:inputType="textEmailAddress" is not enforced, 
      but is a hint to the IME (Input Method Editor) usually a 
      keyboard to configure the display for an email - 
      typically by showing the '@' symbol -->
    <EditText
        android:id="@+id/email"
        android:textSize="@dimen/default_text_size"
        android:layout_marginStart="@dimen/grid_24"
        android:layout_marginLeft="@dimen/grid_24"
        android:layout_marginEnd="@dimen/grid_32"
        android:layout_marginRight="@dimen/grid_32"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:hint="@string/email_label"
        android:inputType="textEmailAddress"
        app:layout_constraintTop_toBottomOf="@id/first_name"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent" />
```

`EditText`字段具有`inputType`属性，用于指定可以输入到表单字段中的输入类型。一些值，例如`EditText`上的`number`，限制了可以输入到字段中的输入，并在选择字段时建议键盘的显示方式。其他值，例如`android:inputType="textEmailAddress"`，不会强制在表单字段中添加`@`符号，但会提示键盘显示它。

1.  最后，添加一个按钮，供用户按下以生成折扣代码，并显示折扣代码本身和确认消息：

```kt
    <Button
        android:id="@+id/discount_button"
        android:textSize="@dimen/default_text_size"
        android:layout_marginTop="@dimen/grid_12"
        android:gravity="center"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="@string/discount_code_button"
        app:layout_constraintTop_toBottomOf="@id/email"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent"/>
    <TextView
        android:id="@+id/discount_code_confirmation"
        android:gravity="center"
        android:textSize="@dimen/default_text_size"
        android:paddingStart="@dimen/grid_16"
        android:paddingEnd="@dimen/grid_16"
        android:layout_marginTop="@dimen/grid_8"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        app:layout_constraintTop_toBottomOf="@id/discount_button"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent"
        tools:text="Hey John Smith! Here is your discount code" />
    <TextView
        android:id="@+id/discount_code"
        android:gravity="center"
        android:textSize="@dimen/discount_code_text_size"
        android:textStyle="bold"
        android:layout_marginTop="@dimen/grid_8"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        app:layout_constraintTop_toBottomOf="@id/discount_code           _confirmation"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent"
        tools:text="XHFG6H9O" />
```

还有一些以前没有见过的属性。在 xml 布局文件顶部指定的 tools 命名空间`xmlns:tools="http://schemas.android.com/tools"`启用了在创建应用程序时可以使用的某些功能，以帮助配置和设计。这些属性在构建应用程序时会被移除，因此它们不会影响应用程序的整体大小。您正在使用`tools:text`属性来显示通常会显示在表单字段中的文本。当您从 Android Studio 中的`Code`视图切换到`Design`视图时，这有助于您看到布局在设备上的显示近似值。

1.  运行应用程序，您应该看到输出显示在*图 2.6*中：![图 2.6：首次启动时的 Activity 屏幕](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_02_06.jpg)

图 2.6：首次启动时的 Activity 屏幕

1.  在每个表单字段中输入一些文本：![图 2.7：填写的 EditText 字段](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_02_07.jpg)

图 2.7：填写的 EditText 字段

1.  现在，使用虚拟设备控件中的第二个旋转按钮（![1](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_Icon1.png)）将手机向右旋转 90 度：![图 2.8：虚拟设备转为横向方向](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_02_08.jpg)

图 2.8：虚拟设备转为横向方向

您能发现发生了什么吗？`Last Name`字段的值不再设置。它在重新创建活动的过程中丢失了。为什么呢？嗯，在`EditText`字段的情况下，如果它们有一个 ID 设置，Android 框架将保留字段的状态。

1.  回到`activity_main.xml`布局文件，并为`EditText`字段中的`Last Name`值添加一个 ID：

```kt
<EditText
    android:id="@+id/last_name"
    android:textSize="@dimen/default_text_size"
    android:layout_marginEnd="@dimen/grid_24"
    android:layout_width="wrap_content"
    android:layout_height="wrap_content"
    android:hint="@string/last_name_label"
    android:inputType="text"
    app:layout_constraintTop_toBottomOf="@id/header_text"
    app:layout_constraintStart_toEndOf="@id/first_name"
    app:layout_constraintEnd_toEndOf="parent"
    tools:text="Last Name:"/>
```

当您再次运行应用程序并旋转设备时，它将保留您输入的值。您现在已经看到，您需要在`EditText`字段上设置一个 ID 来保留状态。对于`EditText`字段，当用户输入表单中的详细信息时，保留状态是常见的，因此如果字段有一个 ID，它就是默认行为。显然，您希望在用户输入一些文本后获取`EditText`字段的详细信息，这就是为什么要设置一个 ID，但是为其他字段类型，例如`TextView`，设置 ID 不会保留状态，如果您更新它们，您需要自己保存状态。为启用滚动的视图设置 ID，例如`RecyclerView`，也很重要，因为它可以在重新创建 Activity 时保持滚动位置。

现在，您已经为屏幕定义了布局，但尚未添加任何逻辑来创建和显示折扣代码。在下一个练习中，我们将解决这个问题。

本练习中创建的布局可在[`packt.live/35RSdgz`](http://packt.live/35RSdgz)找到

）

您可以在[`packt.live/3p1AZF3`](http://packt.live/3p1AZF3)找到整个练习的代码

## 练习 2.03：使用回调保存和恢复状态

本练习的目的是将布局中的所有 UI 元素组合在一起，在用户输入数据后生成折扣码。为了做到这一点，您将不得不添加逻辑到按钮中，以检索所有`EditText`字段，然后向用户显示确认信息，并生成一个折扣码：

1.  打开`MainActivity.kt`并替换项目创建时的默认空 Activity。这里显示了代码片段，但您需要使用下面给出的链接找到需要添加的完整代码块：

```kt
MainActivity.kt
14  class MainActivity : AppCompatActivity() {
15
16    private val discountButton: Button
17        get() = findViewById(R.id.discount_button)
18
19    private val firstName: EditText
20        get() = findViewById(R.id.first_name)
21
22    private val lastName: EditText
23        get() = findViewById(R.id.last_name)
24
25    private val email: EditText
26        get() = findViewById(R.id.email)
27  
28    private val discountCodeConfirmation: TextView
29        get() = findViewById(R.id             .discount_code_confirmation)
30
31    private val discountCode: TextView
32        get() = findViewById(R.id.discount_code)    
33  
34    override fun onCreate(savedInstanceState: Bundle?) {
35        super.onCreate(savedInstanceState)
36        setContentView(R.layout.activity_main)
37        Log.d(TAG, "onCreate")
You can find the complete code here http://packt.live/38XcdQS.
```

`get() = …`是属性的自定义访问器。

单击折扣按钮后，您将从`first_name`和`last_name`字段中检索值，将它们与一个空格连接，然后使用字符串资源格式化折扣码确认文本。您在`strings.xml`文件中引用的字符串如下：

```kt
<string name="discount_code_confirmation">Hey  %s! Here is   your discount code</string>
```

`％s`值指定在检索字符串资源时要替换的字符串值。通过在获取字符串时传入全名来完成此操作：

```kt
getString(R.string.discount_code_confirmation, fullName)
```

该代码是使用`java.util`包中的 UUID（通用唯一标识符）库生成的。这将创建一个唯一的 ID，然后使用`take()` Kotlin 函数来获取前八个字符并将其设置为大写。最后，在视图中设置 discount_code，隐藏键盘，并将所有表单字段设置回初始值。

1.  运行应用程序并在名称和电子邮件字段中输入一些文本，然后单击`GET DISCOUNT`：![图 2.9：用户生成折扣码后显示的屏幕](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_02_09.jpg)

图 2.9：用户生成折扣码后显示的屏幕

应用程序表现如预期，显示确认信息。

1.  现在，旋转手机（按下虚拟设备图片右侧带箭头的第五个按钮）并观察结果：![图 2.10：折扣码不再显示在屏幕上](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_02_10.jpg)

图 2.10：折扣码不再显示在屏幕上

哦，不！折扣码不见了。`TextView`字段不保留状态，因此您必须自己保存状态。

1.  返回`MainActivity.kt`并添加以下 Activity 回调函数：

```kt
override fun onRestoreInstanceState(savedInstanceState:   Bundle) {
    super.onRestoreInstanceState(savedInstanceState)
    Log.d(TAG, "onRestoreInstanceState")
}
override fun onSaveInstanceState(outState: Bundle) {
    super.onSaveInstanceState(outState)
    Log.d(TAG, "onSaveInstanceState")
}
```

这些回调函数，正如它们的名称所声明的那样，使您能够保存和恢复实例状态。`onSaveInstanceState(outState: Bundle)`允许您在 Activity 被置于后台或销毁时添加键值对，您可以在`onCreate(savedInstanceState: Bundle?)`或`onRestoreInstanceState(savedInstanceState: Bundle)`中检索这些键值对。

所以，一旦状态被设置，您有两个回调函数来检索状态。如果您在`onCreate(savedInstanceState: Bundle)`中进行了大量初始化，最好使用`onRestoreInstanceState(savedInstanceState: Bundle)`来在 Activity 被重新创建时检索此实例状态。这样，清楚地知道正在重新创建哪个状态。但是，如果只需要进行最小的设置，您可能更喜欢使用`onCreate(savedInstanceState: Bundle)`。

无论您决定使用这两个回调函数中的哪一个，您都必须获取在`onSaveInstanceState(outState: Bundle)`调用中设置的状态。在练习的下一步中，您将使用`onRestoreInstanceState(savedInstanceState: Bundle)`。

1.  在`MainActivity`伴生对象中添加两个常量：

```kt
private const val DISCOUNT_CONFIRMATION_MESSAGE =   "DISCOUNT_CONFIRMATION_MESSAGE"
private const val DISCOUNT_CODE = "DISCOUNT_CODE"
```

1.  现在，通过向 Activity 添加以下内容，将这些常量作为键添加到要保存和检索的值中：

```kt
    override fun onRestoreInstanceState(
        savedInstanceState: Bundle) {
        super.onRestoreInstanceState(savedInstanceState)
        Log.d(TAG, "onRestoreInstanceState")
        //Get the discount code or an empty           string if it hasn't been set
        discountCode.text = savedInstanceState           .getString(DISCOUNT_CODE,"")
        //Get the discount confirmation message           or an empty string if it hasn't been set
        discountCodeConfirmation.text =          savedInstanceState.getString(            DISCOUNT_CONFIRMATION_MESSAGE,"")
    }
    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        Log.d(TAG, "onSaveInstanceState")
        outState.putString(DISCOUNT_CODE,          discountCode.text.toString())
        outState.putString(DISCOUNT_CONFIRMATION_MESSAGE,          discountCodeConfirmation.text.toString())
    }
```

1.  运行应用程序，输入值到`EditText`字段中，然后生成折扣代码。然后，旋转设备，您将看到折扣代码在*图 2.11*中得到恢复：![图 2.11：折扣代码继续显示在屏幕上](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_02_11.jpg)

图 2.11：折扣代码继续显示在屏幕上

在这个练习中，您首先看到了`EditText`字段的状态如何在配置更改时保持不变。您还使用了 Activity 生命周期`onSaveInstanceState(outState: Bundle)`和`onCreate(savedInstanceState: Bundle?)`/`onRestoreInstanceState(savedInstanceState: Bundle)`函数保存和恢复了实例状态。这些函数提供了一种保存和恢复简单数据的方法。Android 框架还提供了`ViewModel`，这是一个生命周期感知的 Android 架构组件。如何保存和恢复此状态（使用`ViewModel`）的机制由框架管理，因此您不必像在前面的示例中那样显式管理它。您将在*第十章*，*Android 架构组件*中学习如何使用此组件。

到目前为止，您已经创建了一个单屏应用程序。虽然简单的应用程序可以使用一个 Activity，但您可能希望将应用程序组织成处理不同功能的不同活动。因此，在下一节中，您将向应用程序添加另一个 Activity，并在活动之间导航。

# 与意图交互的活动

在 Android 中，意图是组件之间的通信机制。在您自己的应用程序中，很多时候，您希望在当前活动中发生某些操作时启动另一个特定的 Activity。指定将启动哪个 Activity 称为`AndroidManifest.xml`文件，并且您将看到在`<intent-filter>` XML 元素内设置了两个意图过滤器的示例：

```kt
<activity android:name=".MainActivity">
    <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.          LAUNCHER" />
    </intent-filter>
</activity>
```

使用`<action android:name="android.intent.action.MAIN" />`指定的意图表示这是应用程序的主入口点。根据设置的类别，它决定了应用程序启动时首先启动的 Activity。另一个指定的意图过滤器是`<category android:name="android.intent.category.LAUNCHER" />`，它定义了应用程序应该出现在启动器中。当结合在一起时，这两个意图过滤器定义了从启动器启动应用程序时应启动`MainActivity`。删除任何一个这些意图过滤器都会导致`"Error running 'app': Default Activity not found"`的消息。由于应用程序没有主入口点，因此无法启动，这也是当您删除`<action android:name="android.intent.action.MAIN". />`时发生的情况。如果删除`<category android:name="android.intent.category.LAUNCHER" />`并且不指定类别，则无法从任何地方启动它。

在下一个练习中，您将了解意图如何在应用程序中导航。

## 练习 2.04：意图简介

本练习的目标是创建一个简单的应用程序，使用意图根据用户的输入向用户显示文本。在 Android Studio 中创建一个新项目，并选择一个空的 Activity。设置好项目后，转到工具栏，选择`File` | `New` | `Activity` | `Empty` `Activity`。将其命名为`WelcomeActivity`，并将所有其他默认设置保留不变。它将被添加到`AndroidManifest.xml`文件中，准备使用。现在您添加了`WelcomeActivity`后的问题是如何处理它？`MainActivity`在启动应用程序时启动，但您需要一种方法来启动`WelcomeActivity`，然后，可选地，向其传递数据，这就是使用意图的时候：

1.  为了通过这个示例，将以下代码添加到`strings.xml`文件中。这些是您将在应用程序中使用的字符串：

```kt
<resources>
    <string name="app_name">Intents Introduction</string>
    <string name="header_text">Please enter your name and       then we\'ll get started!</string>
    <string name="welcome_text">Hello %s, we hope you enjoy       using the app!</string>
    <string name="full_name_label">Enter your full       name:</string>
    <string name="submit_button_text">SUBMIT</string>
</resources>
```

1.  接下来，在`themes.xml`文件中更新样式，添加标题样式。

```kt
    <style name="header" parent=      "TextAppearance.AppCompat.Title">
        <item name="android:gravity">center</item>
        <item name="android:layout_marginStart">24dp</item>
        <item name="android:layout_marginEnd">24dp</item>
        <item name="android:layout_marginLeft">24dp</item>
        <item name="android:layout_marginRight">24dp</item>
        <item name="android:textSize">20sp</item>
    </style>
    <!--  continued below -->
```

接下来，添加`fullname`，`button`和`page`样式：

```kt
    <style name="full_name" parent=      "TextAppearance.AppCompat.Body1">
        <item name="android:layout_marginTop">16dp</item>
        <item name="android:layout_gravity">center</item>
        <item name="android:textSize">20sp</item>
        <item name="android:inputType">text</item>
    </style>
    <style name="button" parent=      "TextAppearance.AppCompat.Button">
        <item name="android:layout_margin">16dp</item>
        <item name="android:gravity">center</item>
        <item name="android:textSize">20sp</item>
    </style>
    <style name="page">
        <item name="android:layout_margin">8dp</item>
        <item name="android:padding">8dp</item>
    </style>
```

通常，您不会直接在样式中指定尺寸。它们应该被引用为`dimens`值，这样它们可以在一个地方更新，更加统一，并且可以被标记为代表实际尺寸是什么。出于简单起见，这里没有这样做。

1.  接下来，在`activity_main.xml`中更改`MainActivity`布局并添加一个`TextView`标题：

```kt
<?xml version="1.0" encoding="utf-8"?>
<androidx.constraintlayout.widget.ConstraintLayout 
    xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    xmlns:tools="http://schemas.android.com/tools"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    style="@style/page"
    tools:context=".MainActivity">
    <TextView
        android:id="@+id/header_text"
        style="@style/header"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="@string/header_text"
        app:layout_constraintTop_toTopOf="parent"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent"/>
</androidx.constraintlayout.widget.ConstraintLayout>
```

这应该是显示的第一个视图，并且由于它使用`ConstraintLayout`约束到其父级的顶部，它显示在屏幕顶部。由于它还被约束到其父级的开始和结束，当您运行应用程序时，它将显示在中间，如*图 2.12*所示：

![图 2.12：在添加 TextView 标题后的初始应用显示](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_02_12.jpg)

图 2.12：在添加 TextView 标题后的初始应用显示

1.  现在，在`activity_main.xml`文件中，在`TextView`标题下方添加一个用于全名的`EditText`字段和一个用于提交按钮的`Button`字段：

```kt
    <EditText
        android:id="@+id/full_name"
        style="@style/full_name"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:hint="@string/full_name_label"
        app:layout_constraintTop_toBottomOf="@id/header_text"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintEnd_toEndOf="parent"/>
    <Button
        android:id="@+id/submit_button"
        style="@style/button"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="@string/submit_button_text"
        app:layout_constraintTop_toBottomOf="@id/full_name"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent"/>
```

运行应用程序时，显示如*图 2.13*所示：

![图 2.13：在添加 EditText 全名字段和提交按钮后的应用显示](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_02_13.jpg)

图 2.13：在添加 EditText 全名字段和提交按钮后的应用显示

现在，您需要配置按钮，以便当点击按钮时，它从`EditText`字段中检索用户的全名，然后将其发送到启动`WelcomeActivity`的意图中。

1.  更新`activity_welcome.xml`布局文件以准备进行此操作：

```kt
<?xml version="1.0" encoding="utf-8"?>
<androidx.constraintlayout.widget.ConstraintLayout 
    xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    xmlns:tools="http://schemas.android.com/tools"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    style="@style/page"
    tools:context=".WelcomeActivity">
    <TextView
        android:id="@+id/welcome_text"
        style="@style/header"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        app:layout_constraintTop_toTopOf="parent"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintBottom_toBottomOf="parent"
        tools:text="Welcome John Smith we hope you enjoy           using the app!"/>
</androidx.constraintlayout.widget.ConstraintLayout>
```

您正在添加一个`TextView`字段来显示用户的全名和欢迎消息。创建全名和欢迎消息的逻辑将在下一步中显示。

1.  现在，打开`MainActivity`并在类头部添加一个常量值，并更新导入：

```kt
package com.example.intentsintroduction
import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
const val FULL_NAME_KEY = "FULL_NAME_KEY"
class MainActivity : AppCompatActivity()… 
```

您将使用常量来设置保存用户全名的键，通过在意图中设置它。

1.  然后，在`onCreate(savedInstanceState: Bundle?)`的底部添加以下代码：

```kt
findViewById<Button>(R.id.submit_button).setOnClickListener {
    val fullName = findViewById<EditText>(R.id.full_name)      .text.toString().trim()
    if (fullName.isNotEmpty()) {
        //Set the name of the Activity to launch
        Intent(this, WelcomeActivity::class.java)          .also { welcomeIntent ->
            //Add the data
            welcomeIntent.putExtra(FULL_NAME_KEY, fullName)
            //Launch
            startActivity(welcomeIntent)
        }
    } else {
        Toast.makeText(this, getString(          R.string.full_name_label),           Toast.LENGTH_LONG).show()
    }
}
```

有逻辑来检索全名的值并验证用户是否已填写；否则，如果为空，将显示一个弹出式提示消息。然而，主要逻辑是获取`EditText`字段的`fullName`值，并创建一个显式意图来启动`WelcomeActivity`。`also`作用域函数允许您继续使用您刚刚创建的意图`Intent(this, WelcomeActivity::class.java)`，并进一步操作它，使用一个叫做`it`的东西，但为了清晰起见，我们将其称为`welcomeIntent`。然后，您可以在`welcomeIntent.putExtra(FULL_NAME_KEY, fullName)`行中使用 lambda 参数来向意图添加`fullName`字段，使用`FULL_NAME_KEY`作为键，`fullName`作为意图持有的额外值。

然后，您使用意图启动`WelcomeActivity`。

1.  现在，运行应用程序，输入您的姓名，然后按`提交`，如*图 2.14*所示：![图 2.14：当意图额外数据未被处理时显示的默认屏幕](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_02_14.jpg)

图 2.14：当意图额外数据未被处理时显示的默认屏幕

嗯，这并不是很令人印象深刻。您已经添加了发送用户姓名的逻辑，但没有显示它。

1.  要实现这一点，请打开`WelcomeActivity`并在`onCreate(savedInstanceState: Bundle?)`回调的底部添加以下内容：

```kt
//Get the intent which started this activity
intent?.let {
    //Set the welcome message
    val fullName = it.getStringExtra(FULL_NAME_KEY)
    findViewById<TextView>(R.id.welcome_text).text =
      getString(R.string.welcome_text, fullName)
}
```

我们使用`intent?.let{}`引用启动 Activity 的意图，指定如果意图不为空，则将运行`let`块，`let`是一个作用域函数，您可以在其中使用默认的 lambda 参数`it`引用上下文对象。这意味着您不必在使用之前分配变量。您使用`it`引用意图，然后通过获取`FULL_NAME_KEY`额外键从`MainActivity`意图中传递的字符串值。然后，通过从资源中获取字符串并传入从意图中检索的`fullname`值来格式化`<string name="welcome_text">Hello %s, we hope you enjoy using the app!</string>`资源字符串。最后，将其设置为`TextView`的文本。

1.  再次运行应用程序，将显示一个简单的问候语，如*图 2.15*所示：![图 2.15：显示用户欢迎消息](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_02_15.jpg)

图 2.15：显示用户欢迎消息

尽管这个练习在布局和用户交互方面非常简单，但它可以演示意图的一些核心原则。您将使用它们来添加导航，并从应用程序的一个部分创建用户流程到另一个部分。在下一节中，您将看到如何使用意图来启动一个 Activity，并从中接收结果。

## 练习 2.05：从 Activity 中检索结果

对于某些用户流程，您只会启动一个 Activity，目的是从中检索结果。这种模式通常用于请求使用特定功能的权限，弹出一个带有关于用户是否同意访问联系人、日历等的问题的对话框，然后将结果报告给调用 Activity。在这个练习中，您将要求用户选择他们喜欢的彩虹颜色，然后一旦选择了，就在调用 Activity 中显示结果：

1.  创建一个名为`Activity Results`的新项目，并将以下字符串添加到`strings.xml`文件中：

```kt
    <string name="header_text_main">Please click the button       below to choose your favorite color of the rainbow!        </string>
    <string name="header_text_picker">Rainbow Colors</string>
    <string name="footer_text_picker">Click the button       above which is your favorite color of the rainbow.        </string>
    <string name="color_chosen_message">%s is your favorite       color!</string>
    <string name="submit_button_text">CHOOSE COLOR</string>
    <string name="red">RED</string>
    <string name="orange">ORANGE</string>
    <string name="yellow">YELLOW</string>
    <string name="green">GREEN</string>
    <string name="blue">BLUE</string>
    <string name="indigo">INDIGO</string>
    <string name="violet">VIOLET</string>
    <string name="unexpected_color">Unexpected color</string>
```

1.  将以下颜色添加到 colors.xml

```kt
    <!--Colors of the Rainbow -->
    <color name="red">#FF0000</color>
    <color name="orange">#FF7F00</color>
    <color name="yellow">#FFFF00</color>
    <color name="green">#00FF00</color>
    <color name="blue">#0000FF</color>
    <color name="indigo">#4B0082</color>
    <color name="violet">#9400D3</color>
```

1.  将相关的新样式添加到`themes.xml`文件。下面显示了一个片段，但您需要按照给定的链接查看您需要添加的所有代码：

```kt
themes.xml
11    <!-- Style for page header on launch screen -->
12    <style name="header" parent=        "TextAppearance.AppCompat.Title">
13        <item name="android:gravity">center</item>
14        <item name="android:layout_marginStart">24dp</item>
15        <item name="android:layout_marginEnd">24dp</item>
16        <item name="android:layout_marginLeft">24dp</item>
17        <item name="android:layout_marginRight">24dp</item>
18        <item name="android:textSize">20sp</item>
19    </style>
20
21    <!-- Style for page header on rainbow color         selection screen -->
22    <style name="header.rainbows" parent="header">
23        <item name="android:textSize">22sp</item>
24        <item name="android:textAllCaps">true</item>
25    </style>
You can find the complete code here http://packt.live/39J0qES.
```

注意

出于简单起见，尚未将尺寸添加到`dimens.xml`中。

1.  现在，您必须设置将在`MainActivity`中接收的结果的 Activity。转到`文件` | `新建` | `Activity` | `EmptyActivity`，创建一个名为`RainbowColorPickerActivity`的 Activity。

1.  更新`activity_main.xml`布局文件以显示标题、按钮，然后是隐藏的`android:visibility="gone"`视图，当报告结果时将其设置为可见并设置为用户喜欢的彩虹颜色：

```kt
<?xml version="1.0" encoding="utf-8"?>
<androidx.constraintlayout.widget.ConstraintLayout 
    xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    xmlns:tools="http://schemas.android.com/tools"
    android:layout_width="match_parent"
    android:layout_height="match_parent"
    style="@style/page"
    tools:context=".MainActivity">
    <TextView
        android:id="@+id/header_text"
        style="@style/header"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="@string/header_text_main"
        app:layout_constraintTop_toTopOf="parent"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent"/>
    <Button
        android:id="@+id/submit_button"
        style="@style/button"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="@string/submit_button_text"
        app:layout_constraintTop_toBottomOf="@id/header_text"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent"/>
    <TextView
        android:id="@+id/rainbow_color"
        style="@style/color_block"
        android:visibility="gone"
        app:layout_constraintTop_toBottomOf="@id/          submit_button"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintEnd_toEndOf="parent"
        tools:text="This is your favorite color of the           rainbow"/>
</androidx.constraintlayout.widget.ConstraintLayout>
```

1.  您将使用`startActivityForResult(Intent intent, int requestCode)`函数从您启动的 Activity 中获取结果。为了确保您收到的结果是您期望的操作，您必须设置`requestCode`。添加此请求代码的常量，以及另外两个用于在意图中使用的值的键，以及在 MainActivity 类头部上方设置一个默认颜色，以便显示如下所示，带有包名和导入：

```kt
package com.example.activityresults
import android.content.Intent
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
const val PICK_RAINBOW_COLOR_INTENT = 1  // The request code
// Key to return rainbow color name in intent
const val RAINBOW_COLOR_NAME = "RAINBOW_COLOR_NAME" 
// Key to return rainbow color in intent
const val RAINBOW_COLOR = "RAINBOW_COLOR" 
const val DEFAULT_COLOR = "#FFFFFF" // White
class MainActivity : AppCompatActivity()…
```

1.  然后，在`MainActivity`的`onCreate(savedInstanceState: Bundle?)`底部添加以下内容：

```kt
        findViewById<Button>(R.id.submit_button).setOnClickListener {
        //Set the name of the Activity to launch passing 
        //in request code
            Intent(this, RainbowColorPickerActivity::class.java)
            .also { rainbowColorPickerIntent ->
                startActivityForResult(
                    rainbowColorPickerIntent,
                    PICK_RAINBOW_COLOR_INTENT
                )
            }
        }
```

这使用了您之前使用`also`的语法来创建一个意图，并使用具有上下文对象的命名 lambda 参数。在这种情况下，您使用`rainbowColorPickerIntent`来引用您刚刚使用`Intent(this, RainbowColorPickerActivity::class.java)`创建的意图。

关键调用是`startActivityForResult(rainbowColorPickerIntent, PICK_RAINBOW_COLOR_INTENT)`，它使用请求代码启动`RainbowColorPickerActivity`。那么我们什么时候收到这个结果呢？当它被设置时，您将通过覆盖`onActivityResult(requestCode: Int, resultCode: Int, data: Intent?)`来接收结果。

此调用指定了请求代码，您可以检查以确认它与您发送的请求代码相同。`resultCode`报告操作的状态。您可以设置自己的代码，但通常设置为`Activity.RESULT_OK`或`Activity.RESULT_CANCELED`，最后一个参数`data`是由为结果启动的活动设置的意图，RainbowColorPickerActivity。

1.  在`MainActivity`的`onActivityResult(requestCode: Int, resultCode: Int, data: Intent?)`回调中添加以下内容：

```kt
override fun onActivityResult(requestCode: Int, resultCode:   Int, data: Intent?) {
    super.onActivityResult(requestCode, resultCode, data)
    if (requestCode == PICK_RAINBOW_COLOR_INTENT &&       resultCode == Activity.RESULT_OK) {
        val backgroundColor = data?.getIntExtra(RAINBOW_COLOR,           Color.parseColor(DEFAULT_COLOR)) ?:             Color.parseColor(DEFAULT_COLOR)
        val colorName = data?.getStringExtra           (RAINBOW_COLOR_NAME) ?: ""
        val colorMessage = getString           (R.string.color_chosen_message, colorName)
        val rainbowColor = findViewById           <TextView>(R.id.rainbow_color)
rainbowColor.setBackgroundColor(ContextCompat.getColor(this,   backgroundColor))
        rainbowColor.text = colorMessage
        rainbowColor.isVisible = true
    }
}
```

1.  因此，您要检查请求代码和响应代码的值是否符合预期，然后继续查询意图数据以获取您期望的值。对于此练习，您希望获取背景颜色名称（`colorName`）和颜色的十六进制值（`backgroundColor`），以便我们可以显示它。`?`运算符检查值是否为 null（即未在意图中设置），如果是，则 Elvis 运算符（`?:`）设置默认值。颜色消息使用字符串格式设置消息，用颜色名称替换资源值中的占位符。现在您已经获得了颜色，可以使`rainbow_color` `TextView`字段可见，并将视图的背景颜色设置为`backgroundColor`，并添加显示用户最喜欢的彩虹颜色名称的文本。

1.  对于`RainbowColorPickerActivity`活动的布局，您将显示一个按钮，每个按钮都有彩虹的七种颜色的背景颜色和颜色名称：`RED`，`ORANGE`，`YELLOW`，`GREEN`，`BLUE`，`INDIGO`和`VIOLET`。这些将显示在`LinearLayout`垂直列表中。在课程中的大多数布局文件中，您将使用`ConstrainLayout`，因为它提供了对单个视图的精细定位。对于需要显示少量项目的垂直或水平列表的情况，`LinearLayout`也是一个不错的选择。如果需要显示大量项目，则`RecyclerView`是更好的选择，因为它可以缓存单行的布局并回收不再显示在屏幕上的视图。您将在*第五章*，*RecyclerView*中了解有关`RecyclerView`的信息。

1.  在`RainbowColorPickerActivity`中，您需要做的第一件事是创建布局。这将是您向用户提供选择其最喜欢的彩虹颜色的选项的地方。

1.  打开`activity_rainbow_color_picker.xml`并替换布局，插入以下内容：

```kt
<?xml version="1.0" encoding="utf-8"?>
<ScrollView 
    xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:app="http://schemas.android.com/apk/res-auto"
    xmlns:tools="http://schemas.android.com/tools"
    android:layout_width="match_parent"
    android:layout_height="wrap_content">
</ScrollView>
```

我们正在添加`ScrollView`以允许内容在屏幕高度无法显示所有项目时滚动。`ScrollView`只能接受一个子视图，即要滚动的布局。

1.  接下来，在`ScrollView`中添加`LinearLayout`以按添加顺序显示包含的视图，并添加一个标题和页脚。第一个子视图是一个带有页面标题的标题，最后添加的视图是一个带有指示用户选择其最喜欢的颜色的说明的页脚：

```kt
    <LinearLayout
        style="@style/page"
        android:layout_width="match_parent"
        android:layout_height="wrap_content"
        android:gravity="center_horizontal"
        android:orientation="vertical"
        tools:context=".RainbowColorPickerActivity">
    <TextView
        android:id="@+id/header_text"
        style="@style/header.rainbows"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="@string/header_text_picker"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintTop_toTopOf="parent"/>
    <TextView
        style="@style/body"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="@string/footer_text_picker"
        app:layout_constraintEnd_toEndOf="parent"
        app:layout_constraintStart_toStartOf="parent"
        app:layout_constraintTop_toTopOf="parent"/>
    </LinearLayout>
```

应用程序中的布局现在应如*图 2.16*所示：

![图 2.16：带有标题和页脚的彩虹颜色屏幕](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_02_16.jpg)

图 2.16：带有标题和页脚的彩虹颜色屏幕

1.  现在，最后，在标题和页脚之间添加按钮视图以选择彩虹的颜色，然后运行应用程序：

```kt
    <Button
        android:id="@+id/red_button"
        style="@style/button"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:background="@color/red"
        android:text="@string/red"/>
    <Button
        .......
        android:text="@string/orange"/>
    <Button
        .......
        android:text="@string/yellow"/>
    <Button
        .......
        android:text="@string/green"/>
    <Button
        .......
        android:text="@string/blue"/>
    <Button
        .......
        android:text="@string/indigo"/>
    <Button
        .......
        android:text="@string/violet"/>
```

前面创建的布局可在以下链接找到：[`packt.live/2M7okBX`](http://packt.live/2M7okBX)

这些视图是按照彩虹颜色的顺序显示的按钮。尽管按钮标签是颜色和背景颜色，但最重要的 XML 属性是`id`。这是您将在 Activity 中使用的内容，以准备返回给调用活动的结果。

1.  现在，打开`RainbowColorPickerActivity`并用以下内容替换内容：

```kt
package com.example.activityresults
import android.app.Activity
import android.content.Intent
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.view.View
import android.widget.Toast
class RainbowColorPickerActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_rainbow_color_picker)
    }
    private fun setRainbowColor(colorName: String, color: Int) {
        Intent().let { pickedColorIntent ->
            pickedColorIntent.putExtra(RAINBOW_COLOR_NAME,               colorName)
            pickedColorIntent.putExtra(RAINBOW_COLOR, color)
            setResult(Activity.RESULT_OK, pickedColorIntent)
            finish()
        }
    }
}
```

这是创建意图并放置相关的字符串额外信息的函数，其中包含彩虹颜色名称和彩虹颜色`hex`值。然后将结果返回给调用的 Activity，由于你不再需要这个 Activity，所以调用`finish()`以显示调用的 Activity。你通过为布局中的所有按钮添加监听器来检索用户选择的彩虹颜色。

1.  现在，在`onCreate(savedInstanceState: Bundle?)`的底部添加以下内容：

```kt
val colorPickerClickListener = View.OnClickListener { view ->
    when (view.id) {
        R.id.red_button -> setRainbowColor(          getString(R.string.red), R.color.red)
        R.id.orange_button -> setRainbowColor(          getString(R.string.orange), R.color.orange)
        R.id.yellow_button -> setRainbowColor(          getString(R.string.yellow), R.color.yellow)
        R.id.green_button -> setRainbowColor(          getString(R.string.green), R.color.green)
        R.id.blue_button -> setRainbowColor(          getString(R.string.blue), R.color.blue)
        R.id.indigo_button -> setRainbowColor(          getString(R.string.indigo), R.color.indigo)
        R.id.violet_button -> setRainbowColor(          getString(R.string.violet), R.color.violet)
        else -> {
            Toast.makeText(this, getString(              R.string.unexpected_color), Toast.LENGTH_LONG)                .show()
        }
    }
}
```

在前面的代码中添加的`colorPickerClickListener`点击监听器确定了要为`setRainbowColor(colorName: String, color: Int)`函数设置哪些颜色，它使用了`when`语句。`when`语句相当于 Java 和基于 C 的语言中的`switch`语句。它允许满足多个条件并执行一个分支，并且更加简洁。在前面的例子中，`view.id`与彩虹布局按钮的 ID 匹配，找到后执行该分支，将颜色名称和十六进制值从字符串资源传递到`setRainbowColor(colorName: String, color: Int)`中。

1.  现在，将此点击监听器添加到布局中的按钮：

```kt
findViewById<View>(R.id.red_button).setOnClickListener(  colorPickerClickListener)
findViewById<View>(R.id.orange_button).setOnClickListener(  colorPickerClickListener)
findViewById<View>(R.id.yellow_button).setOnClickListener(  colorPickerClickListener)
findViewById<View>(R.id.green_button).setOnClickListener(  colorPickerClickListener)
findViewById<View>(R.id.blue_button).setOnClickListener(  colorPickerClickListener)
findViewById<View>(R.id.indigo_button).setOnClickListener(  colorPickerClickListener)
findViewById<View>(R.id.violet_button).setOnClickListener(  colorPickerClickListener)
```

每个按钮都附加了一个`ClickListener`接口，由于操作相同，它们都附加了相同的`ClickListener`接口。然后，当按钮被按下时，它设置用户选择的颜色的结果并将其返回给调用的 Activity。

1.  现在运行应用程序并按下“选择颜色”按钮，如*图 2.17*所示：![图 2.17：彩虹颜色应用程序启动屏幕](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_02_17.jpg)

图 2.17：彩虹颜色应用程序启动屏幕

1.  现在，选择你彩虹中最喜欢的颜色：![图 2.18：彩虹颜色选择屏幕](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_02_18.jpg)

图 2.18：彩虹颜色选择屏幕

1.  一旦你选择了你最喜欢的颜色，屏幕上会显示你最喜欢的颜色，如*图 2.19*所示：![图 2.19：应用程序显示所选颜色](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_02_19.jpg)

图 2.19：应用程序显示所选颜色

如你所见，应用程序显示了你选择的最喜欢的颜色，如*图 2.19*所示。

这个练习向你介绍了使用`startActivityForResult`创建用户流程的另一种方式。这对于执行需要在继续用户在应用程序中的流程之前获得结果的专用任务非常有用。接下来，你将探索启动模式以及它们在构建应用程序时如何影响用户旅程的流程。

# 意图、任务和启动模式

到目前为止，你一直在使用创建 Activity 和从一个 Activity 到另一个 Activity 的标准行为。你一直使用的是默认的流程，在大多数情况下，这将是你选择使用的流程。当你使用默认行为从启动器打开应用程序时，它会创建自己的任务，并且你创建的每个 Activity 都会添加到后退堆栈中，因此当你连续打开三个 Activity 作为用户旅程的一部分时，按三次返回按钮将使用户返回到之前的屏幕/Activity，然后返回到设备的主屏幕，同时保持应用程序打开。

这种类型的 Activity 的启动模式称为“标准”；这是默认的，不需要在`AndroidManifest.xml`的 Activity 元素中指定。即使你连续三次启动相同的 Activity，仍然会有三个展现之前描述行为的相同 Activity 的实例。

对于一些应用程序，您可能希望更改此行为。最常用的不符合此模式的场景是当您想要重新启动活动而不创建新的单独实例时。这种情况的常见用例是当您有一个主菜单和用户可以阅读不同新闻故事的主屏幕。一旦用户浏览到单个新闻故事，然后从菜单中按下另一个新闻故事标题，当用户按下返回按钮时，他们将期望返回到主屏幕而不是以前的新闻故事。在这里可以帮助的启动模式称为`singleTop`。如果`singleTop`活动位于任务的顶部（在这种情况下，“顶部”表示最近添加的），则启动相同的`singleTop`活动时，它将使用相同的活动并运行`onNewIntent`回调，而不是创建新的活动。在上述情况中，这将使用相同的活动来显示不同的新闻故事。在此回调中，您将收到一个意图，然后可以像以前在`onCreate`中一样处理此意图。

还有两种启动模式需要注意，称为`SingleTask`和`SingleInstance`。这些不是用于一般用途，只用于特殊情况。对于这两种启动模式，应用程序中只能存在一种此类型的活动，并且它始终位于其任务的根部。如果使用此启动模式启动活动，它将创建一个新任务。如果已经存在，则将通过`onNewIntent`调用路由意图，而不会创建另一个实例。`SingleTask`和`SingleInstance`之间的唯一区别是`SingleInstance`是其任务中唯一的活动。不能将新活动启动到其任务中。相反，`SingleTask`允许其他活动启动到其任务中，但`SingleTask`活动始终位于根部。

这些启动模式可以添加到`AndroidManifest.xml`的 XML 中，也可以通过添加意图标志以编程方式创建。最常用的是以下几种：

+   `FLAG_ACTIVITY_NEW_TASK`：将活动启动到新任务中。

+   `FLAG_ACTIVITY_CLEAR_TASK`：清除当前任务，因此完成所有活动并启动当前任务的根处的活动。

+   `FLAG_ACTIVITY_SINGLE_TOP`：复制`launchMode="singleTop"` XML 的启动模式。

+   `FLAG_ACTIVITY_CLEAR_TOP`：删除所有高于同一活动的任何其他实例的活动。如果在标准启动模式活动上启动此活动，则它将清除任务，直到第一个现有实例的同一活动，并然后启动同一活动的另一个实例。这可能不是您想要的，您可以使用`FLAG_ACTIVITY_SINGLE_TOP`标志启动此标志，以清除所有活动，直到与您要启动的活动的相同实例，并且不创建新实例，而是将新意图路由到现有活动。要使用这两个`intent`标志创建活动，您需要执行以下操作：

```kt
val intent = Intent(this, MainActivity::class.java).apply {
    flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or
    Intent.FLAG_ACTIVITY_SINGLE_TOP
}
startActivity(intent)
```

如果意图启动具有前面代码块中指定的一个或多个意图标志的活动，则指定的启动模式将覆盖在`AndroidManifest.xml`文件中设置的启动模式。

意图标志可以以多种方式组合。有关更多信息，请参阅官方文档[`developer.android.com/reference/android/content/Intent`](https://developer.android.com/reference/android/content/Intent)。

您将在下一个练习中探索这两种启动模式的行为差异。

## 练习 2.06：设置活动的启动模式

这个练习有许多不同的布局文件和活动，用来说明两种最常用的启动模式。请从[`packt.live/2LFWo8t`](http://packt.live/2LFWo8t)下载代码，然后我们将在[`packt.live/2XUo3Vk`](http://packt.live/2XUo3Vk)上进行练习：

1.  打开`activity_main.xml`文件并检查它。

这说明了在使用布局文件时的一个新概念。如果您有一个布局文件，并且希望在另一个布局中包含它，您可以使用`<include>`XML 元素（查看以下布局文件片段）。

```kt
<include layout="@layout/letters"
    android:id="@+id/letters_layout"
    android:layout_width="wrap_content"
    android:layout_height="wrap_content"
    app:layout_constraintLeft_toLeftOf="parent"
    app:layout_constraintRight_toRightOf="parent"
    app:layout_constraintTop_toBottomOf="@id/      launch_mode_standard"/>
<include layout="@layout/numbers"
    android:layout_width="wrap_content"
    android:layout_height="wrap_content"
    app:layout_constraintLeft_toLeftOf="parent"
    app:layout_constraintRight_toRightOf="parent"
    app:layout_constraintTop_toBottomOf="@id/      launch_mode_single_top"/> 
```

前面的布局使用`include` XML 元素来包含两个布局文件：`letters.xml`和`numbers.xml`。

1.  打开并检查`res` | `layout`文件夹中的`letters.xml`和`numbers.xml`文件。这些文件非常相似，只是通过按钮本身的 ID 和它们显示的文本标签来区分它们包含的按钮。

1.  运行应用程序，您将看到以下屏幕：![图 2.20：应用程序显示标准和 single top 模式](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_02_20.jpg)

图 2.20：应用程序显示标准和 single top 模式

为了演示/说明`standard`和`singleTop`活动启动模式之间的区别，您必须连续启动两到三个活动。

1.  打开`MainActivity`并检查签名后的`onCreate(savedInstanceState: Bundle?)`代码块的内容：

```kt
    val buttonClickListener = View.OnClickListener { view ->
        when (view.id) {
            R.id.letterA -> startActivity(Intent(this,               ActivityA::class.java))
            //Other letters and numbers follow the same pattern/flow
            else -> {
                Toast.makeText(
                    this,
                    getString(R.string.unexpected_button_pressed),
                    Toast.LENGTH_LONG
                )
                .show()
            }
        }
    }
    findViewById<View>(R.id.letterA).setOnClickListener(buttonClickListener)
    //The buttonClickListener is set on all the number and letter views
}
```

主要活动和其他活动中包含的逻辑基本相同。它显示一个活动，并允许用户按下按钮使用与在练习 2.05 中看到的相同的逻辑来启动另一个活动。

1.  打开`AndroidManifest.xml`文件，您将看到以下内容：

```kt
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.launchmodes">
    <application
        android:allowBackup="true"
        android:icon="@mipmap/ic_launcher"
        android:label="@string/app_name"
        android:roundIcon="@mipmap/ic_launcher_round"
        android:supportsRtl="true"
        android:theme="@style/Theme.LaunchModes">
        <activity android:name=".ActivityA"           android:launchMode="standard"/>
        <activity android:name=".ActivityB"           android:launchMode="standard"/>
        <activity android:name=".ActivityC"           android:launchMode="standard"/>
        <activity android:name=".ActivityOne"           android:launchMode="singleTop"/>
        <activity android:name=".ActivityTwo"           android:launchMode="singleTop"/>
        <activity android:name=".ActivityThree"           android:launchMode="singleTop"/>
        <activity android:name=".MainActivity">
            <intent-filter>
                <action android:name=                  "android.intent.action.MAIN" />
                <category android:name=                  "android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

您可以根据主屏幕上按下的按钮启动一个活动，但字母和数字活动具有不同的启动模式，您可以在`AndroidManifest.xml`文件中看到指定的启动模式。

在此处指定了`standard`启动模式，以说明`standard`和`singleTop`之间的区别，但`standard`是默认值，如果`android:launchMode` XML 属性不存在，则会启动 Activity。

1.  按下`Standard`标题下的字母之一，您将看到以下屏幕（带有`A`或字母`C`或`B`）：![图 2.21：应用程序显示标准活动](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_02_21.jpg)

图 2.21：应用程序显示标准活动

1.  继续按下任何字母按钮，这将启动另一个活动。已添加日志以显示启动活动的顺序。以下是随机按下 10 个字母活动后的日志：

```kt
2019-10-23 20:50:51.097 15281-15281/com.example.launchmodes D/MainActivity: onCreate
2019-10-23 20:51:16.182 15281-15281/com.example.launchmodes D/Activity B: onCreate
2019-10-23 20:51:18.821 15281-15281/com.example.launchmodes D/Activity B: onCreate
2019-10-23 20:51:19.353 15281-15281/com.example.launchmodes D/Activity C: onCreate
2019-10-23 20:51:20.334 15281-15281/com.example.launchmodes D/Activity A: onCreate
2019-10-23 20:51:20.980 15281-15281/com.example.launchmodes D/Activity B: onCreate
2019-10-23 20:51:21.853 15281-15281/com.example.launchmodes D/Activity B: onCreate
2019-10-23 20:51:23.007 15281-15281/com.example.launchmodes D/Activity C: onCreate
2019-10-23 20:51:23.887 15281-15281/com.example.launchmodes D/Activity B: onCreate
2019-10-23 20:51:24.349 15281-15281/com.example.launchmodes D/Activity C: onCreate
```

如果您观察前面的日志，每次用户按下启动模式中的字符按钮时，都会启动并添加一个新的字符 Activity 到返回堆栈中。

1.  关闭应用程序，确保它不在后台（或在最近/概述菜单中），而是实际关闭，然后再次打开应用程序，并按下`Single Top`标题下的数字按钮之一：![图 2.22：应用程序显示 Single Top 活动](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_02_22.jpg)

图 2.22：应用程序显示 Single Top 活动

1.  按下数字按钮 10 次，但确保在按下另一个数字按钮之前至少连续按下相同的数字按钮两次。

您应该在`Logcat`窗口（`View` | `Tool Windows` | `Logcat`）中看到类似以下的日志：

```kt
2019-10-23 21:04:50.201 15549-15549/com.example.launchmodes D/MainActivity: onCreate
2019-10-23 21:05:04.503 15549-15549/com.example.launchmodes D/Activity 2: onCreate
2019-10-23 21:05:08.262 15549-15549/com.example.launchmodes D/Activity 3: onCreate
2019-10-23 21:05:09.133 15549-15549/com.example.launchmodes D/Activity 3: onNewIntent
2019-10-23 21:05:10.684 15549-15549/com.example.launchmodes D/Activity 1: onCreate
2019-10-23 21:05:12.069 15549-15549/com.example.launchmodes D/Activity 2: onNewIntent
2019-10-23 21:05:13.604 15549-15549/com.example.launchmodes D/Activity 3: onCreate
2019-10-23 21:05:14.671 15549-15549/com.example.launchmodes D/Activity 1: onCreate
2019-10-23 21:05:27.542 15549-15549/com.example.launchmodes D/Activity 3: onNewIntent
2019-10-23 21:05:31.593 15549-15549/com.example.launchmodes D/Activity 3: onNewIntent
2019-10-23 21:05:38.124 15549-15549/com.example.launchmodes D/Activity 1: onCreate
```

您会注意到，当您再次按下相同的按钮时，不会调用`onCreate`，而是调用`onNewIntent`。如果按下返回按钮，您会注意到返回到主屏幕只需要不到 10 次点击，反映出并未创建 10 个活动。

## 活动 2.01：创建登录表单

此活动的目的是创建一个带有用户名和密码字段的登录表单。一旦提交这些字段中的值，请检查这些输入的值与硬编码的值是否匹配，并在它们匹配时显示欢迎消息，或者在它们不匹配时显示错误消息，并将用户返回到登录表单。实现此目的所需的步骤如下：

1.  创建一个带有用户名和密码`EditText`视图和一个`LOGIN`按钮的表单。

1.  为按钮添加一个`ClickListener`接口以对按钮按下事件做出反应。

1.  验证表单字段是否已填写。

1.  检查提交的用户名和密码字段与硬编码的值是否匹配。

1.  如果成功，显示带有用户名的欢迎消息并隐藏表单。

1.  如果不成功，显示错误消息并将用户重定向回表单。

有几种可能的方法可以尝试完成这个活动。以下是您可以采用的三种方法的想法：

+   使用`singleTop` Activity 并发送意图到同一个 Activity 以验证凭据。

+   使用一个**标准**Activity 将用户名和密码传递到另一个 Activity 并验证凭据。

+   使用`startActivityForResult`在另一个 Activity 中进行验证，然后返回结果。

完成的应用程序，在首次加载时，应该如*图 2.23*所示：

![图 2.23：首次加载时的应用程序显示](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/hwt-bd-andr-app-kt/img/B15216_02_23.jpg)

图 2.23：首次加载时的应用程序显示

注意

这个活动的解决方案可以在以下网址找到：http://packt.live/3sKj1cp

本章中所有练习和活动的源代码位于[`packt.live/3o12sp4`](http://packt.live/3o12sp4)。

# 总结

在本章中，您已经涵盖了应用程序如何与 Android 框架交互的许多基础知识，从 Activity 生命周期回调到在活动中保留状态，从一个屏幕导航到另一个屏幕，以及意图和启动模式如何实现这一点。这些都是您需要了解的核心概念，以便进入更高级的主题。

在下一章中，您将介绍片段以及它们如何适应应用程序的架构，以及更多探索 Android 资源框架。
