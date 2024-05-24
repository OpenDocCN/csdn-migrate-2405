# Android Studio 应用开发（一）

> 原文：[`zh.annas-archive.org/md5/B5F07A8FF00989BA587D2F4F3EBF3E11`](https://zh.annas-archive.org/md5/B5F07A8FF00989BA587D2F4F3EBF3E11)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

在过去的几年里，移动应用程序的受欢迎程度大幅上升，用户对此的兴趣仍在增长。移动操作系统不仅适用于智能手机，也适用于平板电脑，因此这些应用程序可能的市场份额在增加。

Android 具有让开发者感到愉悦的特性，如开源和一定程度的社区驱动开发。Android 一直在各个方面与 iOS（苹果移动系统）竞争，而 XCode 使 iOS 呈现为一个更集中的开发环境。新的集成开发环境 Android Studio 最终为 Android 开发者提供了这种集中化，使这个工具成为优秀 Android 开发者不可或缺的工具。

本书关于 Android Studio，向用户展示了如何使用这个新的集成开发环境开发构建 Android 应用程序。这不仅仅是一本入门书籍，也是一本指导高级开发者更快、更高效地构建应用程序的指南。本书将从基本功能到发布构建的步骤，包括实际示例，采用教程方法进行讲解。

# 本书涵盖内容

第一章, *安装和配置 Android Studio*, 描述了 Android Studio 的安装和基本配置。

第二章, *开始一个项目*, 展示了如何创建新项目以及我们可以选择的活动类型。

第三章, *浏览项目*, 探索了在 Android Studio 中项目的基本结构。

第四章, *使用代码编辑器*, 展示了代码编辑器的基本功能，以便充分利用它。

第五章, *创建用户界面*, 着重介绍使用图形视图和基于文本视图创建用户界面。

第六章, *Google Play 服务*, 介绍了当前现有的 Google Play 服务以及如何在 Android Studio 项目中集成它们。

第七章, *工具*, 介绍了一些额外的工具，如 Android SDK 工具、Javadoc 和版本控制集成。

第八章, *调试*, 详细展示了如何在 Android Studio 中调试应用程序以及调试时提供的信息。

第九章, *准备发布*, 介绍了如何为应用程序的发布做准备。

第十章, *获取帮助*, 介绍了如何使用 Android Studio 获取帮助，并提供了一些在线站点列表，以便了解更多关于本书所涉及的话题。

# 你需要为这本书准备什么

对于这本书，您需要一台装有 Windows、Mac OS 或 Linux 系统的计算机。您还需要在您的系统中安装 Java。

# 本书适合的读者

这本书不仅是初学者的入门书籍，也是那些尚未使用 Android Studio 来构建 Android 应用的高级开发者的指南。这本书非常适合那些想要学习 Android Studio 关键特性以及想要创建第一个应用的开发者。假设您熟悉面向对象的编程范例和 Java 编程语言。同时建议您了解 Android 移动系统的主要特点。

# 约定

在这本书中，您会发现多种文本样式，用于区分不同类型的信息。以下是一些样式示例，以及它们的含义解释。

文本中的代码字如下所示："我们将浏览项目中最重要的文件夹，`build`，`gen`，`libs`，以及 `src/main` 下的文件夹。"

代码块设置如下：

```java
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);
```

当我们希望您注意代码块中的特定部分时，相关的行或项目会以粗体设置：

```java
    setContentView(R.layout.activity_main);

    if (savedInstanceState != null) {
 System.out.println("savedInstanceState = [" + savedInstanceState + "]");
 }

```

**新术语**和**重要词汇**以粗体显示。您在屏幕上看到的词，例如菜单或对话框中的，会像这样出现在文本中："在 Android Studio 欢迎屏幕上，导航至 **配置** | **项目默认值** | **项目结构**。"

### 注意

警告或重要注意事项会像这样出现在一个框中。

### 提示

提示和技巧会像这样出现。

# 读者反馈

我们始终欢迎读者的反馈。告诉我们您对这本书的看法——您喜欢或可能不喜欢的内容。读者的反馈对我们开发能让您获得最大收益的标题非常重要。

要向我们发送一般反馈，只需发送电子邮件至 `<feedback@packtpub.com>`，并在邮件的主题中提及书名。

如果您在某个主题上有专业知识，并且有兴趣撰写或参与书籍编写，请查看我们在 [www.packtpub.com/authors](http://www.packtpub.com/authors) 的作者指南。

# 客户支持

既然您是 Packt 书籍的骄傲拥有者，我们有一系列的事情可以帮助您从您的购买中获得最大收益。

## 下载示例代码

您可以从您的账户 [`www.packtpub.com`](http://www.packtpub.com) 下载您购买的所有 Packt 书籍的示例代码文件。如果您在别处购买了这本书，可以访问 [`www.packtpub.com/support`](http://www.packtpub.com/support) 注册，我们会直接将文件通过电子邮件发送给您。

## 勘误

尽管我们已经竭尽全力确保内容的准确性，但错误仍然在所难免。如果你在我们的书中发现了一个错误——可能是文本或代码中的错误——我们非常感激你能向我们报告。这样做可以避免其他读者产生困扰，并帮助我们改进本书后续版本。如果你发现了任何勘误信息，请通过访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择你的书籍，点击**勘误提交表单**链接，并输入你的勘误详情。一旦你的勘误信息被核实，你的提交将会被接受，并且勘误信息将会被上传到我们的网站，或者添加到该书标题下的现有勘误列表中。任何现有的勘误信息可以通过选择你的书名从[`www.packtpub.com/support`](http://www.packtpub.com/support)进行查看。

## 侵权行为

在互联网上，版权材料的侵权行为是所有媒体持续面临的问题。在 Packt，我们非常重视保护我们的版权和许可。如果你在任何形式的互联网上遇到我们作品的非法副本，请立即提供位置地址或网站名称，以便我们可以寻求补救措施。

如果你发现了疑似盗版材料，请通过`<copyright@packtpub.com>`联系我们，并提供相关链接。

我们感谢你帮助保护我们的作者，以及我们为你提供有价值内容的能力。

## 问题咨询

如果你对书籍的任何方面有问题，可以通过`<questions@packtpub.com>`联系我们，我们将尽力解决。


# 第一章：安装和配置 Android Studio

你希望熟悉新的官方 Google IDE Android Studio。你想知道这个环境中可用的功能。你希望制作自己的 Android 应用程序，并希望这些应用程序能够在 Google Play 商店供其他用户使用。你能轻松做到这一点吗？你如何实现这个目标？

本章将指导你如何准备新的 Android Studio 安装，以及如何在新的环境中迈出第一步。我们将从准备安装系统和下载必要的文件开始。我们将看到第一次运行 Android Studio 时出现的欢迎屏幕，并正确配置 Android **SDK**（**软件开发工具包**），以便你准备好创建你的第一个应用程序。

这是我们将在本章中讨论的主题：

+   安装 Android Studio

+   第一次运行 Android Studio 时的欢迎屏幕

+   安装 Android SDK 的配置

# 安装前的准备

开始使用 Android Studio 的一个前提条件是在你的系统中安装 Java。系统还必须能够找到 Java 的安装路径。这可以通过设置一个名为`JAVA_HOME`的环境变量来实现，该变量必须指向你系统中**JDK**（**Java 开发工具包**）的文件夹。检查这个环境变量，以避免在安装 Android Studio 时出现未来的问题。

# 下载 Android Studio

Android Studio 的安装包可以从 Android 开发工具网页下载，地址为：[`developer.android.com/sdk/installing/studio.html`](http://developer.android.com/sdk/installing/studio.html)。

这个包是 Windows 系统的 EXE 文件：

[Windows 系统的安装包下载地址](http://dl.google.com/android/studio/android-studio-bundle-130.737825-windows.exe)。

Mac OS X 系统的 DMG 文件：

[Mac OS X 系统的安装包下载地址](http://dl.google.com/android/studio/android-studio-bundle-130.737825-mac.dmg)。

Linux 系统的 TGZ 文件：

[Linux 系统的安装包下载地址](http://dl.google.com/android/studio/android-studio-bundle-130.737825-linux.tgz)。

## 安装 Android Studio

在 Windows 系统中，请运行 EXE 文件。默认安装目录为`\`Users\\<your_user_name>\Appdata\Local\Android\android-studio`。`Appdata`目录通常是隐藏的目录。

在 Mac OS X 中，打开 DMG 文件，并将 Android Studio 拖放到你的应用程序文件夹中。默认安装目录为`/Applications/Android/ Studio.app`。

在 Linux 系统中，解压 TGZ 文件，并执行位于`android-studio/bin/`目录下的`studio.sh`脚本。

如果你在安装过程或后续步骤中遇到任何问题，可以通过查看第十章，*获取帮助*，了解有关问题和已知问题的帮助。

## 首次运行 Android Studio

执行 Android Studio 并等待其完全加载（可能需要几分钟）。首次运行 Android Studio 时，会提示一个欢迎屏幕。如下截图所示，欢迎屏幕包括一个打开最近项目的部分和一个 **快速入门** 部分。我们可以创建新项目，导入项目，打开项目，甚至执行更高级的操作，例如从版本控制系统检出或打开配置选项。

![首次运行 Android Studio](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_01_01.jpg)

让我们看看 **快速入门** 部分提供的各种选项：

+   **新建项目...**：创建一个新的 Android 项目

+   **导入项目**：通过从你的系统中导入现有源代码创建一个新项目

+   **打开项目**：打开一个现有项目

+   **从版本控制检出**：通过从版本控制系统中导入现有源代码创建一个新项目

+   **配置**：打开配置菜单

    +   **设置**：打开 Android Studio 设置

    +   **插件**：打开 Android Studio 的插件管理器

    +   **导入设置**：从文件（`.jar`）导入设置

    +   **导出设置**：将设置导出到文件（`.jar`）

    +   **项目默认设置**：打开项目默认设置菜单

    +   **设置**：打开模板项目设置。这些设置也可以从 Android Studio 设置中访问（**配置** | **设置**）

    +   **项目结构**：打开项目和平台设置

    +   **运行配置**：打开运行和调试设置

+   **文档和操作指南**：打开帮助菜单

    +   **阅读帮助**：打开在线版的 Android Studio 帮助

    +   **每日小贴士**：打开一个显示每日小贴士的对话框

    +   **默认键位参考**：打开包含默认键位的在线 PDF

    +   **JetBrains TV**：打开包含视频教程的 JetBrains 网站

    +   **插件开发**：打开包含插件开发者信息的 JetBrains 网站

# 配置 Android SDK

必须正确配置的核心功能是 Android SDK。尽管 Android Studio 会自动安装最新的可用 Android SDK，因此理论上你已经拥有创建第一个应用程序所需的一切，但检查它并了解如何更改它仍然很重要。

在 Android Studio 的欢迎界面中，导航至 **配置** | **项目默认设置** | **项目结构**。在 **平台设置** 中，点击 **SDKs**。将显示已安装的 SDK 列表，你应当在列表中至少有一个 Android SDK。在 **项目设置** 中，点击 **项目** 以打开项目默认模板的一般设置。你应当已选择一个 **项目 SDK**，如下一个截图中所示。这个选定的 SDK 将默认用于我们的 Android 项目，但即便如此，我们也可以稍后针对需要特殊设置的具体项目进行更改。

![配置 Android SDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_01_02.jpg)

如果你没有在 Android Studio 中配置任何 Android SDK，那么我们需要手动添加它。

要完成这项任务，在**平台设置** | **SDKs**中，点击绿色的加号按钮来添加 Android SDK 到列表中，然后选择 SDK 的主目录。通过导航到你的 Android Studio 安装目录来检查你的系统中是否已有 SDK。你应该能找到一个名为`sdk`的文件夹，其中包含了 Android SDK 及其工具。Android Studio 的安装目录可能在隐藏文件夹中，所以请点击以下截图高亮的按钮来**显示隐藏文件和目录**：

![配置 Android SDK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_01_03.jpg)

如果你想使用不同于 Android Studio 中包含的另一个 Android SDK，请选择它。例如，如果你之前使用的是为 Eclipse 准备的**ADT**（**Android 开发工具**）插件，那么你的系统中已经安装了 Android SDK。你也可以同时添加这两个 SDK。

添加完 SDK 后，它将出现在列表中，你可以在项目设置中选择默认值。

### 提示

**下载示例代码**

你可以从你在[`www.packtpub.com`](http://www.packtpub.com)的账户下载你所购买的所有 Packt 图书的示例代码文件。如果你在别处购买了这本书，可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)注册，我们会直接将文件通过电子邮件发送给你。

# 概述

我们已经成功为 Android Studio 准备系统并安装了我们的 Android Studio 实例。我们首次运行了 Studio，现在我们知道欢迎屏幕上有哪些选项。我们还学会了如何配置我们的 Android SDK 以及如果你想使用不同版本如何手动安装。完成这些任务后，你的系统将运行并配置好 Android Studio，以便创建你的第一个项目。

在下一章中，我们将了解项目概念以及它如何包含应用程序所需的一切，从类到库。我们将创建我们的第一个项目，并讨论向导中可用的不同类型的活动。


# 第二章：开始一个项目

你刚刚安装了 Android Studio，现在想熟悉它的功能。你想要了解创建项目时必要的字段。你可能还想知道如何为你的应用程序添加图标并将其与项目关联，以及如何创建主活动以及选择哪种类型的活动。你该如何使用 Android Studio 实现这一点呢？

本章节的目标是创建一个带有基本内容的新项目。我们将使用 Android Studio 向导创建项目，并介绍项目配置字段。我们将为我们的应用程序选择一个启动图标，并介绍向导中可用的不同类型活动，以选择作为我们项目的主活动。

这些是我们将在本章中讨论的主题：

+   创建新项目

+   创建你的应用程序图标

+   选择作为主活动的主要活动类型

# 创建新项目

要创建新项目，请从欢迎屏幕点击**新建项目**选项。如果你不在欢迎屏幕，那么导航到**文件** | **新建项目**。新项目向导会打开。

向导的第一步足以创建一个项目，但如果你勾选了**创建自定义启动图标**选项，向导将增加第二步，如果你勾选了**创建活动**选项，还会增加两个额外步骤。勾选这两个选项。

![创建新项目](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_02_01.jpg)

新项目向导将显示以下字段：

+   **应用程序名称**：这是在 Google Play 上显示的名称，也是用户看到的名称。

+   **模块名称**：这是仅由 Android Studio 使用的名称。

+   **包名**：通常是应用程序的唯一标识符，形式为`com.company_name.app_name`或`reverse_company_domain.app_name`。这种形式减少了与其他应用程序名称冲突的风险。

+   **项目位置**：这是在系统中保存项目的目录。

+   **最低要求的 SDK**：这是应用程序支持的最低 SDK。使用早期 SDK 的设备将无法安装你的应用程序。尝试在支持的设备和可用功能之间找到平衡。如果你的应用程序不需要最新 SDK 中发布的具体功能，那么你可以选择一个较旧的**API**（**应用程序编程接口**）。谷歌发布的最新平台分布数据显示，95.5%的设备使用的是 Android 2.3 或更高版本。如果你选择 Android 2.2，那么这个比例会上升到 98.5%。官方 Android 仪表盘可以在[`developer.android.com/about/dashboards/index.html`](http://developer.android.com/about/dashboards/index.html)找到。

+   **目标 SDK**：这是你已经针对应用程序测试的最高 SDK。你应该将此值更新到最新版本。

+   **编译使用**: 这是用于编译你的应用程序的 SDK。这个 SDK 是你安装在 Android Studio 中并配置的 SDK 之一。

+   **主题**: 为您的应用程序选择一个默认的用户界面主题。

**将此项目标记为库**的选项用于将项目创建为库模块。库可以在其他项目中引用，以共享其功能。不要勾选这个选项。

考虑到前一个屏幕截图显示的字段。将最低 SDK 选择为 API 10，目标 SDK 选择为 API 17。在**编译使用**字段中，选择你已安装的最高 API 版本（API 17）。点击**下一步**。

# 创建自定义启动图标

这个步骤允许你创建应用程序图标，如果你在第一步中勾选了**创建自定义启动图标**选项，这一步将会显示。

安卓项目存储了多种图像分辨率，以便在应用程序执行时根据设备屏幕分辨率选择最合适的。为了确保图标在每个设备上都能正常显示，请检查`XXHDPI`图像是否没有像素化。

有三种方法可以创建你的应用程序图标，分别是使用图片、提供的剪贴画之一或文本。最常见的是使用图片。你可以选择自己的图像文件来创建图标，并调整一些参数，比如它的内边距、形状或背景颜色。选择**图像**选项，保留默认图像和选项。点击**下一步**。

![创建自定义启动图标](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_02_02.jpg)

# 选择你的活动类型

这个步骤允许你创建应用程序的主活动。如果你在第一步中勾选了**创建活动**选项，这一步将会显示。

可以选择几种类型的活动：

+   **空白活动**: 这会创建一个带有操作栏的空白活动。操作栏包括标题和选项菜单。导航类型可以是标签式用户界面（固定标签或可滚动标签）、水平滑动或下拉菜单。更多关于操作栏的信息请访问[`developer.android.com/guide/topics/ui/actionbar.html`](http://developer.android.com/guide/topics/ui/actionbar.html)。![选择你的活动类型](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_02_03.jpg)

+   **全屏活动**: 这个模板在一个全屏视图中隐藏了系统用户界面（如通知栏）。全屏模式和显示操作栏之间可以切换，当用户触摸设备屏幕时操作栏会出现。![选择你的活动类型](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_02_04.jpg)

+   **登录活动**: 这个模板创建了一个登录界面，允许用户使用电子邮件和密码登录或注册。![选择你的活动类型](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_02_05.jpg)

+   **主/详流**: 这个模板将屏幕分为两个部分：左侧菜单和右侧选中项的详情。在较小的屏幕上，只显示一个部分，但在较大的屏幕上，两部分会同时显示。![选择活动类型](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_02_06.jpg)

+   **设置活动**：这将创建一个带有设置列表的首选项活动。![选择您的活动类型](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_02_07.jpg)

选择**空白活动**并点击**下一步**。在最后一步中，我们可以给活动和其关联的布局命名。保留默认值，选择无导航类型，然后点击**完成**。

# 总结

我们使用了 Android Studio 向导来创建我们的第一个项目，并填写了配置字段。我们为应用程序选择了启动图标，并确保它能够以任何分辨率正常显示。我们了解了不同类型的活动。

在下一章中，我们将详细介绍 Android Studio 的不同结构元素。我们将了解在哪里可以创建新类，添加和访问库，以及如何配置项目。


# 第三章：项目导航

你刚刚创建了你的第一个 Android Studio 项目，现在你想了解发生了什么。你想开始编程，但在开始之前，你需要熟悉项目导航。一切是如何组织的？你可以更改项目的哪些设置？如何更改这些设置以及它们的意义是什么？

本章旨在介绍 Android Studio 中项目的结构。我们将从理解项目导航面板开始。我们将浏览项目中最重要的文件夹 `build`、`gen`、`libs` 以及 `src/main` 下的文件夹，并学习如何更改项目设置。

这些是我们将在本章中讨论的主题：

+   导航面板

+   项目结构

+   更改项目属性

# 项目导航面板

初始状态下，在 Android Studio 的主视图中，你看不到任何项目或文件，如下一个截图所示。按照 Android Studio 的提示，按下 *Alt* + *1* 打开项目视图。你也可以通过点击左侧边缘的**项目**按钮来打开。

![项目导航面板](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_03_01.jpg)

项目视图显示打开的项目列表。项目采用分层视图显示。

在项目浏览器的左上角，我们可以更改视图类型：**项目**或**包**。第一个显示项目的目录结构，而第二个只显示包结构。

在右上角有一些操作和一个下拉菜单，用于配置项目视图。以下截图突出显示了这些操作：

![项目导航面板](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_03_02.jpg)

右键点击项目名称打开上下文菜单，或者点击项目中的任何元素。从这个菜单中我们可以：

+   创建并向项目中添加新元素

+   在项目中剪切、复制、粘贴或重命名文件

+   在项目中查找元素

+   分析和重新格式化代码

+   构建项目

+   比较文件

+   在资源管理器中打开文件

# 项目结构

在项目导航窗格中，我们可以检查项目结构。在项目结构内是一个以我们应用程序名称命名的文件夹。这个文件夹包含应用程序结构和文件。应用程序结构最重要的元素是：

+   `build/`：一个文件夹，包含构建应用程序后编译的资源以及由 Android 工具生成的类，例如 `R.java` 文件，该文件包含对应用程序资源的引用。

+   `libs/`：一个包含我们代码中引用的库的文件夹。

+   `src/main/`：一个包含应用程序源代码的文件夹。你通常要处理的文件都在这个文件夹里。主文件夹按以下方式细分：

    +   `java/`：一个包含按包组织 Java 类的文件夹。我们创建的每个类都会在我们的项目包命名空间（`com.example.myapplication`）中。当我们创建第一个项目时，也创建了它的主活动，所以活动类应该在这个包中。下一张截图显示了项目结构中的这个主活动类：![项目结构](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_03_03.jpg)

    +   `res/`：一个包含项目资源的文件夹，比如指定布局和菜单的 XML 文件，或是图片文件。

    +   `drawable/`：一个包含应用程序中使用的图片的文件夹。这里有不同分辨率的 drawable 文件夹。当我们创建第一个项目时，也创建了应用程序图标，这个图标已经存在于这些文件夹中，名为`ic_launcher.png`。

    +   `layout/`：一个包含视图及其元素的 XML 定义的文件夹。

    +   `menu/`：一个包含应用程序菜单的 XML 定义的文件夹。

    +   `values/`：一个包含定义名称-值对集合的 XML 文件的文件夹。这些值可以是颜色、字符串或样式。有不同的 values 文件夹按不同的屏幕选项分类，以适应界面。例如，当应用程序在平板上运行时，可以放大组件或字体。

    +   `AndroidManifest.xml`：这个文件是 Android 项目中的核心文件，在我们创建项目时会自动生成。这个文件声明了 Android 系统运行应用程序所需的基本信息，如包名、版本、活动、权限、意图或所需的硬件。

+   `build.gradle`：这个文件是我们构建应用程序时使用的脚本。

# 项目设置

有两个包含项目设置的对话框：**文件** | **设置**菜单和**文件** | **项目结构**。这两个选项在工具栏中也可用。

![项目设置](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_03_04.jpg)

从项目视图中选择您的项目，然后导航到**文件** | **设置**菜单。在设置对话框的左侧菜单中，有一个名为**项目设置 [MyApplication]**的部分。一些重要的选项包括：

+   **代码样式**：配置默认的代码样式方案。

+   **编译器**：配置在构建应用程序时使用的 Android DX 编译器。

+   **文件编码**：更改文件的编码。默认编码是 UTF-8。

+   **Gradle**：它提供了 Gradle 的配置。Gradle 是一个类似于 Apache Ant 和 Apache Maven 的工具，基于 Groovy 来构建和管理 Java 项目。Gradle 已集成在 Android Studio 中。

+   **语言注入**：添加或移除编辑器中使用的可用语言。

+   **Maven**：它提供了 Maven 的配置信息。Maven 是一个类似于 Apache Ant 和 Gradle 的工具，基于 XML 来构建和管理 Java 项目。Maven 已集成在 Android Studio 中。

+   **版本控制**：配置版本控制选项。版本控制将在第七章，*工具*中详细解释。

除了这些设置，项目结构对话框中还有更多设置。导航到**文件** | **项目结构**菜单。**项目设置**包括：

+   **项目**：我们可以更改项目名称和项目 SDK。记得在第一章，*安装和配置 Android Studio*中，我们选择了一个默认的 SDK。在这个屏幕上，我们可以只为当前项目更改这个 SDK。

+   **模块**：此屏幕显示现有模块及其方面的列表。我们还可以删除它们或创建新的。根据 IntelliJ IDEA（[`www.jetbrains.com/idea/webhelp/module.html`](http://www.jetbrains.com/idea/webhelp/module.html)），

    > 模块是功能的一个独立单元，你可以独立编译、运行、测试和调试。

+   **库**：此屏幕显示项目导入的库列表。我们还可以删除它们或添加新的。它们将被添加到`libs/`文件夹中。

+   **方面**：此屏幕显示现有方面的列表。我们还可以删除它们或创建新的。这些方面在**模块**视图中也显示过。根据 IntelliJ IDEA（[`www.jetbrains.com/idea/webhelp/facet.html`](http://www.jetbrains.com/idea/webhelp/facet.html)），

    > 方面表示模块中使用的各种框架、技术和语言。它们让 IntelliJ IDEA 知道如何处理模块内容，从而确保与相应框架和技术的一致性。

# 概述

我们已经了解了在 Android Studio 中如何展示项目以及项目一旦创建后默认包含哪些文件夹。现在我们理解了每个文件夹的原因以及`AndroidManifest.xml`的用途。我们通过**文件** | **设置**和**文件** | **项目结构**对话框查看了项目设置。现在，你应该知道如何在 Android Studio 中操作和导航项目。

在下一章中，我们将学习如何使用文本编辑器。正确了解文本编辑器对于提高我们的编程效率非常重要。我们将学习编辑器设置以及如何自动完成代码，使用预生成的代码块，以及如何导航代码。我们还将了解一些有用的快捷键。


# 第四章：使用代码编辑器

你已经创建了你的第一个项目，并且知道如何浏览不同的文件夹、子文件夹和文件。是时候开始编程了！你有没有想过能够更高效地编程？如何加快你的开发过程？你想要学习有用的快捷键，例如一次性注释多行，查找和替换字符串，或者在方法调用中快速移动不同的参数吗？

在本章中，我们将学习如何使用代码编辑器以及如何自定义它，以便在编程时感觉更舒适。了解代码编辑器的基本特性是值得的，以提高开发人员的工作效率。我们将了解代码补全和代码生成。最后，我们将学习一些有用的快捷键和热键，以加快我们的开发过程。

这是我们将在本章中介绍的主题：

+   自定义代码编辑器

+   代码补全

+   代码生成

+   查找相关内容

+   有用的快捷键

# 编辑器设置

要打开编辑器设置，请导航至**文件** | **设置**，在**IDE 设置**部分，选择**编辑器**菜单。此屏幕显示编辑器的一般设置。我们建议检查默认未选中的两个选项：

+   **使用 Ctrl + 鼠标滚轮更改字体大小（缩放）**：此选项允许我们使用鼠标滚轮更改编辑器的字体大小，就像在其他程序（如网页浏览器）中所做的那样。

+   **鼠标移动时显示快速文档**：如果我们选中此选项，当我们将鼠标悬停在一段代码上并等待 500 毫秒，一个小对话框将显示关于该代码的快速文档。当我们再次移动鼠标时，对话框会自动消失，但如果我们将鼠标移动到对话框内，就可以详细查看文档。这非常有用，例如，阅读一个方法的功能及其参数，而无需导航到该方法处。![编辑器设置](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_04_01.jpg)

有更多设置分布在七个类别中：

+   **智能键**：配置在打字时自动执行的操作，例如添加关闭括号、引号或标签；或者在我们按下*Enter*键时缩进行。

+   **外观**：配置编辑器的外观。我们建议检查默认未选中的以下两个选项：

    +   **显示行号**：在编辑器的左侧边缘显示行号。当我们调试或检查日志时，这可能非常有用。

    +   **显示方法分隔符**：在视觉上将类中的方法分隔开。

+   **颜色与字体**：更改字体和颜色。有许多选项和元素需要配置（关键词、数字、警告、错误、注释、字符串等）。我们可以将配置保存为方案。

+   **编辑器标签**：配置编辑器标签。我们建议选择**用星号标记修改过的标签**选项，以便轻松识别已修改但未保存的文件。

+   **代码折叠**：代码折叠选项允许我们折叠或展开代码块。它非常适用于隐藏我们未编辑的代码块，简化代码视图。我们可以通过编辑器中的图标或使用**代码** | **折叠**菜单来折叠或展开这些块。![编辑器设置](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_04_02.jpg)

+   **代码补全**：配置代码补全选项。下一节将详细探讨代码补全。

+   **自动导入**：配置当我们粘贴使用当前类中没有导入的类的代码时，编辑器的表现。默认情况下，这样做时会出现一个弹出窗口以添加导入命令。如果我们勾选了**即时添加明确的导入**选项，导入命令将会自动添加，无需我们干预。![编辑器设置](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_04_03.jpg)

# 代码补全

代码补全通过建议列表和自动完成代码来帮助我们快速编写代码。

基本代码补全是我们在输入时出现的建议列表。如果未显示列表，请按*Ctrl* + 空格键打开它。

![代码补全](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_04_04.jpg)

继续输入，从列表中选择一个命令，然后按*Enter*或双击将其添加到你的代码中。

如果我们正在编写的代码是一个表达式，但我们希望以否定的形式插入表达式，那么从建议列表中选择表达式后，不要按*Enter*或双击它，而是按感叹号键（*!*）。表达式将以否定形式添加。

另一种类型的代码补全是**智能类型代码补全**。如果我们正在输入一个调用带有`String`参数的方法的命令，那么只会建议`String`对象。这种智能补全出现在赋值语句的右侧部分、方法调用的参数、返回语句或变量初始化器中。要打开智能建议列表，请按*Ctrl* + *Shift* + 空格键。

要显示这两种建议列表之间的区别，请在你的代码中创建两个不同类的对象，`String`和`int`。然后调用带有`String`参数的方法，例如`Log`类的`i`方法。在输入`String`参数时，注意下一个屏幕截图显示的基本建议列表（*Ctrl* + 空格键）和下一页显示的智能类型建议列表（*Ctrl* + *Shift* + 空格键）之间的区别。

![代码补全](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_04_05.jpg)

在前一个屏幕截图中显示的第一个列表中，尽管`int`对象与`parameter`类不匹配，但两个对象都被建议。在下面屏幕截图中显示的第二个列表中，只建议`String`对象。

![代码补全](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_04_06.jpg)

代码补全最后一个实用功能是**语句补全**。输入一个语句，按下*Ctrl* + *Shift* + *Enter*，注意结尾的标点符号是如何自动添加的。如果在输入关键字`if`后按下这些键，会添加括号和括号以完成条件语句。此快捷键也可用于完成方法声明。开始输入一个方法，并在输入左括号或输入方法参数后按下*Ctrl* + *Shift* + *Enter*。将添加右括号和括号以完成方法规范。

# 代码生成

要在类中生成代码块，导航到**代码** | **生成**或按下快捷键*Alt* + *Insert*。我们可以生成构造函数、getter 和 setter 方法、`equals`和`toString`方法、重写或委托方法。

另一种生成代码的方法是用一些语句（`if`、`if`/`else`、`while`、`for`、`try`/`catch`等）包围我们的代码。选择一行代码并导航到**代码** | **环绕以**或按下*Ctrl* + *Alt* + *T*。

第三种选项是插入代码模板。导航到**代码** | **插入实时模板**以打开可用模板的对话框。这些模板可以插入用于遍历集合、数组、列表等的代码；用于打印格式化字符串的代码、抛出异常的代码，或者添加静态和最终变量的代码。在对话框的左侧边缘，每个模板都有一个前缀，因此在编辑器中输入前缀并按下*Tab*键，代码模板会自动添加。

尝试在主活动的`onCreate`方法末尾输入`inn`并按下*Tab*。将出现一个条件块。在这个新块中，输入`soutm`并再次按下*Tab*。结果如下所示。

```java
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);

    if (savedInstanceState != null) {
 System.out.println("savedInstanceState = [" + savedInstanceState + "]");
 }
 }
```

# 导航代码

直接导航到声明或类型声明的方法是按下*Ctrl*并点击显示为链接的符号。此选项也可以从**导航** | **声明**访问。

从编辑器的左侧边缘我们可以导航到方法的层次结构。在属于方法层次结构的方法声明旁边，有一个图标表示一个方法是否正在实现接口方法、实现抽象类方法、重写超类方法，或者相反，一个方法是否被其他后代实现或重写。

点击这些图标以导航到层次结构中的方法。此选项也可以通过**导航** | **超级方法**或**导航** | **实现**访问。通过打开我们第一个项目的主活动(`MainActivity.java`)来测试它。

![导航代码](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_04_07.jpg)

与代码导航相关的另一个有用工具是自定义区域的使用。一个**自定义区域**只是你想要分组并为其命名的一段代码。例如，如果一个类有很多方法，我们可以创建一些自定义区域来分配方法。一个区域有一个名称或描述，并且可以使用代码折叠来折叠或展开。

要创建自定义区域，我们可以使用代码生成。选择代码片段，导航到**代码** | **环绕以**，并选择以下两个选项之一：

+   **<editor-fold…> 注释**

+   **region…endregion 注释**

它们都创建一个区域，但使用不同的样式。

当我们使用自定义区域时，可以通过**导航** | **自定义区域**菜单进行导航。

其他导航选项可以从**导航**菜单访问：

+   **类**/**文件**/**符号**：通过名称查找类、文件或符号。

+   **行**：通过行号转到代码行。

+   **最后编辑位置**：导航到最近的更改点。

+   **测试**：导航到当前类的测试。

+   **文件结构**：打开一个对话框，显示文件结构。打开我们主活动的文件结构，观察结构是如何呈现的，显示方法列表，指示元素类型的图标，或指示元素可见性的图标。![导航代码](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_04_08.jpg)

+   **文件路径**：打开一个对话框，显示编辑器中打开文件的完整路径。

+   **类型层次结构**：打开一个对话框，显示选定对象的类型层次结构。

+   **方法层次结构**：打开一个对话框，显示选定方法的方法层次结构。

+   **调用层次结构**：打开一个对话框，显示选定方法的调用层次结构。

+   **下一个高亮错误**：导航到下一个错误。

+   **上一个高亮错误**：导航到上一个错误。

+   **下一个方法**：导航到下一个方法。

+   **上一个方法**：导航到上一个方法。

# 有用的操作

以下是一些有用的快捷键：

+   *Ctrl* + *W*：根据语法选择表达式。多次按这些键以扩展选择。相反的命令是*Ctrl* + *Shift* + *W*。

+   *Ctrl* + */*：注释选中代码的每一行。要使用块注释，请按*Ctrl* + *Shift* + */*。

+   *Ctrl* + *Alt* + *I*：缩进选中的代码。在完成编写代码块或方法后清理代码时很有用。

+   *Ctrl* + *Alt* + *O*：优化导入，移除未使用的并重新排序其余的。

+   *Shift* + *Ctrl* + 方向键：将选中的代码移动到另一行。

+   *Alt* + 方向键：在编辑器的打开标签页之间切换。

+   *Ctrl* + *F*：在编辑器的活动标签页中查找字符串。

+   *Ctrl* + *R*：替换编辑器活动标签页中的字符串。

+   *Ctrl* + *A*：选择打开文件中的所有代码。

+   *Ctrl* + *D*：复制选中的代码并将其粘贴到代码末尾。如果没有选中任何代码，则会复制整行并在新行中粘贴。

+   *Ctrl* + *Y*：删除整行，且不留下任何空行。

+   *Ctrl* + *Shift* + *U*：切换大小写。

+   *Tab*：移动到下一个参数。

# 总结

在本章结束时，用户应该学会一些有用的技巧和操作，以便最大限度地利用代码编辑器。我们现在知道了如何使用代码补全、代码生成以及加快不同操作的一些快捷键。我们还定制了代码编辑器，现在可以开始编程了。

在下一章中，我们将开始使用布局创建我们的第一个用户界面。我们将学习如何使用图形向导创建布局以及如何通过文本视图编辑 XML 布局文件来创建布局。我们将创建第一个应用程序，一个使用文本视图组件的经典*Hello World*示例。我们还将学习如何准备我们的应用程序以适应多种屏幕尺寸，并使它们适应不同的设备方向。最后，我们将了解 UI 主题以及如何处理事件。


# 第五章：创建用户界面

现在你已经创建了你的第一个项目，并熟悉了代码编辑器及其功能，我们将通过创建用户界面开始我们的应用程序。有没有多种方法可以使用 Android Studio 创建用户界面？你如何向你的用户界面添加组件？你是否曾想过如何让你的应用程序支持不同的屏幕尺寸和分辨率？

本章重点介绍使用布局创建用户界面。布局可以通过图形视图或基于文本的视图创建。我们将学习如何使用它们来创建我们的布局。我们还将使用简单组件编写一个 *Hello World* 应用程序。我们将了解基于不同 Android 设备的碎片化问题，以及如何为这个问题准备我们的应用程序。我们将以了解如何在我们的应用程序上处理事件的基本概念结束本章。

这是我们将在本章中讨论的主题：

+   现有的布局编辑器

+   创建新布局

+   添加组件

+   支持不同的屏幕

+   更改 UI 主题

+   处理事件

# 图形编辑器

打开位于我们项目中的 `/src/main/res/layout/activity_main.xml` 的主布局。默认情况下会打开图形编辑器。最初，这个主布局只包含一个带有 **Hello world!** 消息的文本视图。要在图形和文本编辑器之间切换，请点击底部的 **Design** 和 **Text** 标签。

![图形编辑器](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_05_01.jpg)

工具栏包含一些用于更改布局样式和预览的选项。本章将解释工具栏的选项。

![图形编辑器](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_05_02.jpg)

组件树显示布局中放置的组件层次结构。属性检查器显示从布局中选择的组件的属性，并允许我们更改它们。

调色板列出了可以在布局中放置的现有**UI**（**用户界面**）组件。调色板将这些组件按不同类别组织起来。

+   **布局**：布局是一个容器对象，用于在屏幕上分布组件。用户界面的根元素是布局对象，但布局也可以包含更多布局，创建在布局中结构的组件层次。建议保持这个布局层次尽可能简单。我们的主布局有一个相对布局作为根元素。

+   **小部件**：按钮、复选框、文本视图、开关、图像视图、进度条、下拉列表或网页视图都属于这一类。它们是大多数布局中最常用的组件。

+   **文本字段**：这些是用户可以输入文本的输入框。它们之间的区别在于用户可以输入的文本类型。

+   **容器**：这些容器将共享常见行为的组件组合在一起。单选按钮组、列表视图、滚动视图或标签主机都属于这一类。

+   **日期和时间**：这些是与日期和时间相关的组件，如日历或时钟。

+   **专家**：这些组件不如小部件类别中的那些常见，但值得一看。

+   **自定义**：这些组件允许我们包含自定义组件，通常是项目中的其他布局。

# 文本编辑器

通过点击**文本**标签页，将图形编辑器更改为文本编辑器。

![文本编辑器](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_05_03.jpg)

工具栏与图形编辑器相同。预览显示布局，但无法更改，应使用设计标签页。使用组件的 XML 声明将组件添加到布局中。属性也使用 XML 声明进行配置。与图形编辑器一样，文本编辑器仅显示根布局内的文本视图元素。

# 创建新布局

创建主活动时，关联的布局也会创建。这是在创建活动时创建布局的一种方式。

如果我们想在不创建新活动的情况下添加一个独立的布局，那么请右键点击布局文件夹（`res/layout/`）并导航到**新建** | **布局资源文件**。也可以导航到菜单选项**文件** | **新建** | **布局资源文件**。输入文件名和根元素。

创建布局后，可以从编辑器将关联的活动更改为另一个。如果布局没有活动，可以从编辑器将任何现有活动与其关联。为此，在布局编辑器的工具栏中查找活动选项，点击它，然后选择**与其他活动关联**的选项。将打开一个列出项目所有活动的对话框，以便您可以选择其中之一。

# 添加组件

我们的主布局是一个相对布局，包含一个显示**Hello world!**的文本视图，但让我们添加一个新组件。最简单的方法是使用图形编辑器，因此请打开设计标签页。选择一个组件并将其拖动到布局预览中，例如，导航到**文本字段** | **Person Name**并将其放置在文本视图下方。

在组件树视图中，现在有一个新的`EditText`对象。保持文本字段的选择状态，以便在属性检查器中检查其属性。让我们更改其中一些属性，并观察布局预览和组件树中的差异。

1.  **layout:width**：其当前值为`wrap_content`。此选项将使字段的宽度适应其内容。将其更改为`match_parent`以适应父布局的宽度（根相对布局）。

1.  **hint**：将字段的提示设置为`Enter your name`。提示是在字段为空时显示的文本，指示应输入的信息。由于字段具有默认值`Name`，提示不可见。

1.  **id**：其当前 ID 是 `@+id/editText`。这个 ID 将用于代码中访问此对象，是在组件树中显示的 ID。将其更改为 `@+id/editText_name` 以便于与其他文本字段区分。检查组件树中组件 ID 是否也已更改。![添加组件](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_05_04.jpg)

1.  **text**：删除此字段的值。现在提示应该可见。

如果我们切换到文本编辑器，我们可以看到我们编辑过的文本字段的 XML 定义：

```java
<EditText
android:layout_width="match_parent"
android:layout_height="wrap_content"
android:inputType="textPersonName"
android:ems="10"
android:id="@+id/editText_name"
android:layout_below="@+id/textView_greeting"
android:layout_alignLeft="@+id/textView_greeting"
android:layout_marginTop="15dp"
android:hint="Enter your name"
/>
```

从文本编辑器中，也可以更改现有组件及其属性。将文本视图 ID（`android:id` 属性）从 `@+id/textView` 更改为 `@+id/textView_greeting`。拥有一个描述性的 ID 很重要，因为它将用于我们的代码中。描述性变量名可以使代码自我文档化。

这一次，让我们使用文本编辑器添加另一个组件。按下开放标签键并开始输入 `Button`。让建议列表出现并选择一个 `Button` 对象。在 `Button` 标签内，添加以下属性：

```java
<Button
android:id="@+id/button_accept"
android:layout_width="wrap_content"
android:layout_height="wrap_content"
android:layout_below="@+id/editText_name"
android:layout_centerHorizontal="true"
android:text="Accept"
/>
```

创建 ID 属性，值为 `@+id/button_accept`。让宽度和高度适应按钮内容（`wrap_content` 值）。使用 `android:layout_below` 属性将按钮放置在名字文本字段下方。我们通过其 ID（`@+id/editText_name`）引用名字文本字段。使用 `layout_centerHorizontal` 属性在父布局中水平居中按钮。设置按钮的文本（`Accept`）。

按钮在布局预览中显示。下一张截图显示，如果我们切换到图形编辑器，按钮也会在其中和组件树中显示：

![添加组件](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_05_05.jpg)

# 支持多屏幕

在创建 Android 应用程序时，我们必须意识到存在多种屏幕尺寸和屏幕分辨率。检查我们的布局在不同屏幕配置下的显示情况非常重要。为了实现这一点，Android Studio 提供了一个功能，可以在设计模式下更改布局预览。

我们可以在工具栏中找到这个功能，预览中使用的**设备定义**选项默认为**Nexus 4**。点击它打开可用设备定义的列表。

![支持多屏幕](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_05_06.jpg)

尝试一些设备。平板设备与 Nexus 等设备的区别非常明显。我们应该调整视图以适应应用程序支持的所有屏幕配置，以确保它们能够最佳显示。

设备定义指出了屏幕英寸、分辨率和屏幕密度。Android 将屏幕密度分为 ldpi、mdpi、hdpi、xhdpi 甚至 xxhdpi。

+   **ldpi**（**低密度每英寸点数**）：大约 120 dpi

+   **mdpi**（**中密度每英寸点数**）：大约 160 dpi

+   **hdpi**（**高密度每英寸点数**）：大约 240 dpi

+   **xhdpi**（**超高密度每英寸点数**）：大约 320 dpi

+   **xxhdpi** (**超超高密度每英寸点数**): 大约 480 dpi

谷歌最近发布的数据显示，大多数设备具有高密度屏幕（34.3%），其次是 xxhdpi（23.7%）和 mdpi（23.5%）。因此，通过测试这三种屏幕密度，我们可以覆盖 81.5% 的设备。官方的 Android 数据面板可以在 [`developer.android.com/about/dashboards`](http://developer.android.com/about/dashboards) 上找到。

另一个需要考虑的问题是**设备方向**。我们是否希望应用程序支持横屏模式？如果答案是肯定的，我们必须在横屏方向上测试我们的布局。在工具栏上，点击布局状态选项，将模式从纵向切换到横向，或从横向切换到纵向。

如果我们的应用程序支持横屏模式，且布局在此方向上显示不如预期，我们可能需要创建布局的变体。点击工具栏上的第一个图标，即配置选项，并选择 **创建横屏变体** 选项。将在编辑器中打开一个新的布局。这个布局已经在资源文件夹中创建，位于 `layout-land` 目录下，并使用与纵向布局相同的名称：`/src/main/res/layout-land/activity_main.xml`。现在我们可以完美地编辑符合横屏模式的新布局变体。

同样，我们可以为 *xlarge* 屏幕创建布局的变体。选择 **创建 layout-xlarge 变体** 选项。新的布局将在 `layout-xlarge` 文件夹中创建：`/src/main/res/layout-xlarge/activity_main.xml`。Android 将实际屏幕尺寸分为 *small*、*normal*、*large* 和 *xlarge*。

+   **small**: 归入此类别的屏幕至少为 426 dp x 320 dp

+   **normal**: 归入此类别的屏幕至少为 470 dp x 320 dp

+   **large**: 归入此类别的屏幕至少为 640 dp x 480 dp

+   **xlarge**: 归入此类别的屏幕至少为 960 dp x 720 dp

**dp** 是一个与密度无关的像素单位，相当于在 160 dpi 屏幕上的一个物理像素。

谷歌最近发布的数据显示，大多数设备具有正常屏幕尺寸（79.6%）。如果你想覆盖更多比例的设备，还可以使用小屏幕（9.5%）测试你的应用程序，这样覆盖的设备比例将达到 89.1%。

要同时显示多个设备配置，请在工具栏上点击配置选项，并选择 **预览所有屏幕尺寸** 的选项，或者点击 **预览代表性样本** 来打开最重要的屏幕尺寸。我们还可以通过右键点击样本并选择菜单中的 **删除** 选项来删除任何样本。此菜单中的另一个有用操作是 **保存截图** 选项，它允许我们截取布局预览的屏幕截图。

![支持多屏幕](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_05_07.jpg)

如果我们创建了一些布局变体，可以选择 **预览布局版本** 选项来预览所有这些变体。

# 更改 UI 主题

布局和小部件是使用我们项目的默认 UI 主题创建的。我们可以通过创建样式来改变 UI 元素的外观。样式可以分组以创建一个主题，主题可以应用于整个活动或应用程序。一些默认提供的主题，例如 Holo 风格。样式和主题是在 `/src/res/values` 文件夹下作为资源创建的。

使用图形编辑器打开主布局。我们布局所选的主题在工具栏中指示为：`AppTheme`。这个主题是为我们的项目创建的，可以在样式文件（`/src/res/values/styles.xml`）中找到。打开样式文件，注意到这个主题是另一个主题（`Theme.Light`）的扩展。

要自定义我们的主题，请编辑样式文件。例如，在 `AppTheme` 定义中添加下一行以更改窗口背景颜色：

```java
<style name="AppTheme" parent="AppBaseTheme">
<item name="android:windowBackground">#dddddd</item>
</style>
```

保存文件并切换到布局标签。现在背景是浅灰色。由于我们在主题中配置了此背景色，而不是仅在布局中，因此它将被应用到我们所有的布局中。

要完全更改布局主题，请在图形编辑器的工具栏中点击主题选项。现在打开了主题选择对话框，显示可用主题的列表。

![更改 UI 主题](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_05_08.jpg)

我们自己项目中创建的主题列在**项目主题**部分。**清单主题**部分显示了在应用程序清单文件（`/src/main/AndroidManifest.xml`）中配置的主题。**所有**部分列出了所有可用的主题。

# 处理事件

如果应用程序的其余部分不能与用户界面交互，那么用户界面将毫无用处。在用户与我们的应用程序交互时，会在 Android 中生成事件。所有 UI 小部件都是 `View` 类的子类，它们共享一些由以下监听器处理的事件：

+   `OnClickListener`：捕获用户点击视图元素时的事件

+   `OnCreateContextMenu`：捕获用户在视图元素上执行长按操作并且我们想要打开上下文菜单时的事件

+   `OnDragListener`：捕获用户拖放事件元素时的事件

+   `OnFocusChange`：捕获用户在相同视图中从一个元素导航到另一个元素时的事件

+   `OnKeyListener`：捕获用户在视图元素具有焦点时按下任意键的事件

+   `OnLongClickListener`：捕获用户触摸并按住视图元素时的事件

+   `OnTouchListener`：捕获用户触摸视图元素时的事件

除了这些事件和监听器之外，一些 UI 小部件还有一些更具体的事件。复选框可以注册一个监听器来捕获其状态变化（`OnCheckedChangeListener`），或者下拉列表可以注册一个监听器来捕获点击项目的事件（`OnItemClickListener`）。

最常见的事件是捕获用户点击视图元素的时候。对于这个事件，有一种简单的方法来处理它，即使用视图属性。在我们的布局中选择接受按钮，并查找`onClick`属性。此属性指示当用户点击按钮时将执行的方法的名称。这个方法必须在关联当前布局的活动中创建，在本例中，是在我们的主活动`MainActivity.java`中创建。将`onAcceptClick`作为此属性的值输入。

打开主活动以创建方法定义。当一个视图被点击时的事件回调方法必须是公开的，返回类型为 void，并且接收被点击的视图作为参数。每次用户点击按钮时，都会执行此方法。

```java
public void onAcceptClick(View v) {
  // Action when the button is pressed
}
```

从主活动中，我们可以与界面上的所有组件进行交互，因此当用户点击接受按钮时，我们的代码可以读取名字字段的文本，并将问候语更改为包含名字的内容。

要获取对视图对象的引用，请使用从`Activity`类继承的`findViewById`方法。此方法接收组件的 ID 并返回与该 ID 对应的`View`对象。返回的视图对象必须转换为其特定的类，以便使用其方法，例如`EditText`类的`getText`方法，以获取用户输入的名字。

```java
public void onAcceptClick(View v) {
  TextView tv_greeting =
    (TextView) findViewById(R.id.textView_greeting);
  EditText et_name = (EditText) findViewById(R.id.editText_name);

  if(et_name.getText().length() > 0) {
    tv_greeting.setText("Hello " + et_name.getText());
  }
}
```

在方法的头两行中，获取了对布局元素的引用：包含问候语的文本视图和用户可以输入名字的文本字段。通过其 ID 找到组件，这是我们在布局文件中指定元素的属性中的相同 ID。所有资源的 ID 都包含在`R`类中。`R`类是在构建阶段自动生成的，我们不得编辑它。如果此类未自动生成，则我们的资源文件中可能包含错误。

下面的行是一个条件语句，用于检查用户是否输入了名字，如果是这种情况，文本将被替换为包含该名字的新问候语。在下一章中，我们将学习如何在模拟器中执行我们的应用程序，并且我们将能够测试这段代码。

如果我们要处理的事件不是用户点击，那么我们必须在活动的`onCreate`方法中通过代码创建并添加监听器。有两种选择：

+   在活动中实现监听器接口，然后添加未实现的方法。接口需要的方法是接收事件的方法。

+   在活动文件中创建一个私有的匿名监听器实现。在这个对象中实现了接收事件的方法。

最后，需要通过设置器方法（如`setOnClickListener`、`setOnCreateContextMenu`、`setOnDragListener`、`setOnFocusChange`、`setOnKeyListener`等）将监听器实现分配给视图元素。监听器的分配通常包含在活动的`onCreate`方法中。如果监听器是由活动直接实现的，那么传递给设置器方法的参数就是它自己的活动，使用关键字`this`，如下面的代码所示：

```java
Button b_accept = (Button) findViewById(R.id.button_accept);
b_accept.setOnClickListener(this);
```

活动应该实现监听器所需的`onClick`方法和监听器接口。

```java
public class MainActivity extends Activity 
implements View.OnClickListener {
  @Override
  public void onClick(View view) {
    // Action when the button is pressed
  }
```

# 总结

到本章结束时，我们已经学会了如何使用图形编辑器和基于文本的编辑器创建和编辑用户界面布局。我们完成了第一个小应用程序，并用一些基本组件对其进行了升级。用户现在应该能够创建一个简单的布局，并通过不同的样式、屏幕尺寸和屏幕分辨率进行测试。我们还了解了可用的不同 UI 主题，最后，我们学习了关于事件以及如何使用监听器处理它们。

在下一章中，我们将学习 Google Play 可用的服务以及如何使用 Android Studio 将它们集成到我们的项目中。我们将学习如何安装和集成不同的库，这些库可使用谷歌技术，如 Google Maps、Google Plus 等。


# 第六章：谷歌播放服务

既然你已经熟悉了在布局中使用组件，那么你应该开始考虑额外的功能。谷歌播放服务提供了使用谷歌地图、谷歌+等功能来吸引用户的功能。你如何轻松将这些功能添加到你的应用程序中？有哪些功能可用？使用谷歌播放服务需要满足哪些安卓版本要求？

本章重点介绍如何使用 Android Studio 创建、集成和使用谷歌播放服务。我们将了解哪些谷歌服务可用。我们还将学习标准的授权 API，以安全地授予和接收访问谷歌播放服务的令牌。我们还将了解这些服务的限制及其使用的好处。

以下是本章将要讨论的主题：

+   现有的谷歌服务

+   从 IDE 中添加谷歌播放服务

+   在你的应用中集成谷歌播放服务

+   理解自动更新

+   在你的应用中使用谷歌服务

# 谷歌播放服务的工作原理

当谷歌在 2012 年的谷歌 I/O 大会上预览谷歌播放服务时，它表示这个平台（[`developers.google.com/events/io/2012/`](https://developers.google.com/events/io/2012/)）...

> ...由在设备上运行的服务组件和一个与你应用一起打包的轻量级客户端库组成。

这意味着谷歌播放服务之所以能够工作，得益于两个主要组件：谷歌播放服务客户端库和谷歌播放服务 APK。

+   **客户端库**：谷歌播放服务客户端库包含了你的应用所使用的每个谷歌服务的接口。当你打包应用时，会包含这个库，它允许你的用户使用他们的凭据授权应用访问这些服务。客户端库会定期由谷歌进行升级，增加新的功能和服务。你可以在应用更新时升级这个库，当然，如果你不打算使用任何新功能，这并非必须。

+   **谷歌播放服务 APK**：谷歌播放服务**安卓软件包**（**APK**）在安卓操作系统中作为后台服务运行。使用客户端库，你的应用程序可以访问这项服务，它负责在运行时执行操作。并不保证所有设备上都安装有此 APK。如果设备未预装此 APK，可以在谷歌播放商店中获取。

这样，谷歌将其服务的运行时与作为开发者的你所做的实现分离开来，因此你无需在谷歌播放服务每次升级时都更新你的应用程序。

尽管谷歌播放服务并未包含在安卓平台本身，但它们得到了大多数基于安卓的设备的支持。任何运行安卓 2.2 或更新版本的安卓设备都可以安装使用谷歌播放服务的应用程序。

# 可用的服务

Google Play 服务被认为是轻松为各种设备上的用户添加更多特性的方式，同时使用由 Google 提供支持的知名功能。使用这些服务，你可以添加新的收入来源，管理应用程序的分布，访问统计信息并了解应用程序用户的习惯，以及通过易于实现的 Google 功能（如地图或 Google 的社交网络 Google+）来改进你的应用程序。以下是对这些服务的说明：

+   **游戏**：使用 Google Play 游戏服务，你可以通过更社交的体验来改进你的游戏。

+   **位置**：整合位置 API，你可以使你的应用程序具有位置感知功能。

+   **Google 地图**：Google 地图 API 允许你在应用程序中使用 Google 提供的地图，并对其进行自定义。

+   **Google+**：通过使用 Android 的 Google+平台，你可以验证你的应用程序的用户。一旦验证成功，你还可以访问他们的公开资料和社交网络图。

+   **应用内购买**：使用 Google Play 应用内购买，你可以从你的应用程序中出售数字内容。你可以使用这项服务来销售一次性购买或对高级服务和特性的时间订阅。

+   **云消息传递**：**Google 云消息传递**（**GCM**）允许你在运行在基于 Android 的设备和你的服务器之间的应用程序中交换数据。

+   **全景图**：它使用户能够看到 360 度的全景图片。

# 向 Android Studio 添加 Google Play 服务

我们需要知道的第一件事是什么需要添加到我们的 Android Studio 中。我们刚刚了解到 APK 在 Google Play 商店中可用，它是服务的实际运行时。作为开发者的我们，在调试应用程序时只需要这个包在测试设备上可用。我们需要添加到 Android Studio 的是 Google Play 服务客户端库。

这个库通过 Android SDK 管理器（软件开发工具包管理器）进行分发，具体将在第七章《工具》中进行详细介绍。要打开它，请导航到**工具** | **Android** | **SDK 管理器**。在**Extras**文件夹下的软件包列表中我们可以找到 Google Play 服务。勾选**Google Play 服务**复选框，然后点击**安装 1 个软件包...**按钮。

![向 Android Studio 添加 Google Play 服务](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_06_01.jpg)

执行这些操作将把库项目添加到我们 SDK 安装文件夹的位置，`/sdk/extras/google/google_play_services/`。你可以在 SDK 管理器中悬停在 Google Play 服务行上，查看工具提示来检查确切的路径。

![向 Android Studio 添加 Google Play 服务](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_06_02.jpg)

导航到库文件夹以检查其内容。`samples`文件夹包含身份验证服务（`auth/`）、Google Maps v2 服务（`maps/`）、Google+服务（`plus/`）以及全景服务（`panorama/`）的示例项目。包含 Google Play Services 库项目的文件夹是`libproject/`。在这个项目文件夹中放置了`google-play-services.jar`文件，即`libproject/google-play-services_lib/libs/google-play-services.jar`。

只需将此 JAR 文件拖放到`libs/`文件夹中即可将其添加到项目中。完成此操作后，选择 JAR 文件并在其上按鼠标右键。选择**作为库添加**的选项。在**创建库**对话框中，选择项目库级别，选择您的应用程序模块，然后点击**确定**。

您现在可以在项目库的`libs/`文件夹下找到`google-play-services.jar`文件，现在您将能够从代码中引用 Google Play 服务。

最后，您需要将库添加到您的 Gradle 构建文件中。为此，只需编辑`MyApplication/build.gradle`文件，并在`dependencies`部分添加以下行：

```java
compile files('libs/google-play-services.jar')
```

# Google Maps Android API v2

Google Maps Android API 允许您的应用程序用户探索 Google 服务上可用的地图。新的地图版本 2 提供了更多功能，如 3D 地图、室内和卫星地图、基于矢量技术的有效缓存和绘制，以及地图上的动画过渡。

让我们导入示例项目以检查最重要的类。点击**文件** | **导入项目**。在你 SDK 安装文件夹中搜索示例项目，并选择项目根目录，即 `/google_play_services/samples/maps/`。在下一个对话框中，勾选**从现有源创建项目**的选项。在后续的对话框中继续点击**下一步**，最后点击**完成**按钮，在新的窗口中打开示例项目。现在我们在 Android Studio 的新窗口中加载了 Google Play Services 项目和地图示例项目。

打开`BasicMapActivity`类，查看一个使用 Google Maps 的简单示例。你可以在`src/`文件夹中的 maps 项目里找到这个活动。`com.google.android.gms.maps`包包含了 Google Maps Android API 的类。

此活动声明了一个名为`mMap`的私有`GoogleMap`对象。**GoogleMap 类**是 API 的主要类，它是与地图相关的所有方法的入口点。您可以更改地图的主题颜色和图标以匹配您应用程序的风格。您还可以通过向地图添加标记来自定义地图。要添加一个简单的标记，你可以使用`GoogleMap`类的`addMarker`方法。在`BasicMapActivity`类中检查`setUpMap`方法，查看以下代码示例：

```java
mMap.addMarker(new MarkerOptions().position(new LatLng(0, 0)).title("Marker"));
```

`addMarker`方法有一个`MarkerOptions`对象作为参数。使用`position`方法我们指定地图上标记的坐标，使用`title`方法我们可以添加一个自定义字符串在标记上显示。

要将地图添加到布局中，我们可以使用`MapView`类，它扩展了`View`类并显示了一个地图。但在应用程序中放置地图的最简单方法是使用`MapFragment`对象。片段表示可以嵌入活动中的用户界面或行为的一部分。片段是一个可重用的模块。

**MapFragment 类**包装了一个地图视图，以自动处理组件的生命周期需求。它扩展了`Fragment`类，因此可以通过添加以下 XML 代码将其实例添加到布局中：

```java
<fragment
class="com.google.android.gms.maps.MapFragment"
android:layout_width="match_parent"
android:layout_height="match_parent" />
```

要查看前面代码的示例，请打开与`BasicMapActivity`类关联的布局；这是`/res/layout/`文件夹中的`basic_demo.xml`文件。

最后，我们需要从片段中获取`GoogleMap`对象的代码。我们可以使用`findFragmentById`方法找到地图`Fragment`，然后使用`getMap`方法从`Fragment`中获取地图。

```java
mMap = ((MapFragment) getFragmentManager().findFragmentById(R.Id.map).getMap();
```

在`BasicMapActivity`类中，此代码的示例位于`setUpMapIfNeeded`方法中。

最后一个重要的类是`GoogleMapOptions`类，它定义了地图的配置。您还可以通过编辑布局 XML 代码来修改地图的初始状态。以下是一些可用的有趣选项：

+   `mapType`：指定地图的类型。其值可以是`none`、`normal`、`hybrid`、`satellite`和`terrain`。

+   `uiCompass`：定义罗盘控制是否启用或禁用。

+   `uiZoomControls`：定义缩放控制是否启用或禁用。

+   `cameraTargetLat`和`cameraTargetLong`：指定初始相机位置。

# Android 上的 Google+平台

使用 Android 上的 Google+平台可以让开发者用用户在 Google+上使用的相同凭据对用户进行身份验证。您还可以使用公开的个人资料和社会关系图来欢迎用户，显示他们的名字、照片，或者与朋友建立联系。

包`com.google.android.gms.plus`包含了 Android 上的 Google+平台类。导入 Google+示例项目以了解最重要的类。Google+示例项目可以在 Google Play Services 安装文件夹中找到，位于`/google_play_services/samples/plus/`。

+   `PlusClient`和`PlusClient.Builder`：`PlusClient`是 API 的主要类。它是 Google+集成的入口点。`PlusClient.Builder`是一个构建器，用于配置`PlusClient`对象以正确与 Google+ API 通信。

+   `PlusOneButton`：实现 Google+上的+1 按钮以推荐 URL 的类。使用以下代码将其添加到布局中：

    ```java
    <com.google.android.gms.plus.PlusOneButton
    android:layout_width="wrap_content"
    android:layout_height="wrap_content"
    plus:size="standard" />
    ```

    可用的尺寸有小型、中型、大型或标准。

    关于此功能的示例代码可以在示例项目中找到，在`src/`文件夹中的`PlusOneActivity`类及其关联的布局`res/layout/plus_one_activity.xml`中。

+   `PlusShare`：在 Google+上共享的帖子中包含资源。关于共享资源的示例代码可以在`src/`文件夹中的`ShareActivity`类及其关联的布局`res/layout/share_activity.xml`中找到。

首先，应在活动类的`onCreate`方法中实例化一个`PlusClient`对象，以调用其异步方法`connect`，这将连接客户端到 Google+服务。当应用完成使用`PlusClient`实例时，它应该调用`disconnect`方法，该方法将终止连接，并且也应该始终从活动的`onStop`方法中调用。

# Google Play 应用内购买 v3

应用内购买 v3 允许您从应用中出售虚拟内容。这种虚拟内容可以通过一次性计费支付一次，也可以通过订阅或费用进行计时特许。使用这项服务，您可以允许用户为额外功能付费并访问高级内容。

任何在 Google Play 商店发布的应用都可以实现应用内购买 API，因为它只需要与发布应用相同的账户：一个 Google Play 开发者控制台账户和一个 Google Wallet 商家账户。

使用 Google Play 开发者控制台，您可以定义您的产品，包括类型、识别代码（SKU）、价格、描述等。定义好产品后，您可以从这个应用程序访问这些内容。当用户想要购买这些内容时，以下购买流程将在您的应用内购买应用和 Google Play 应用之间发生：

1.  您的应用调用`isBillingSupported()`来检查 Google Play 是否支持您正在使用的应用内购买版本。

1.  如果支持应用内购买 API 版本，您可以使用`getPurchases()`来获取已购买物品的 SKU 列表。这个列表将返回在一个`Bundle`对象中。

1.  您可能想要通知用户可用的应用内购买选项。为此，您的应用可以发送一个`getSkuDetails()`请求，这将导致一个列表生成，其中包含产品的价格、标题、描述以及更多关于该物品的信息。

# Google 云消息传递

Android 的 GCM 允许通过使用异步消息在您的服务器和应用程序之间进行通信。您无需担心处理这种通信的低级别方面，如排队和消息构造。使用这项服务，您可以轻松地为您的应用实现一个通知系统。

使用 GCM 时，您有两个选项：

+   服务器可以通知您的应用有新的数据可供从服务器获取，然后应用程序获取这些数据。

+   服务器可以直接在消息中发送数据。消息负载可以达到 4 KB。这使得您的应用程序可以一次性访问数据并相应地采取行动。

为了发送或接收消息，您需要获取一个注册 ID。这个注册 ID 标识了设备和应用程序的组合。为了让您的应用程序使用 GCM 服务，您需要将以下行添加到项目的清单文件中：

```java
<uses-permission android:name="com.google.android.c2dm.permission.RECEIVE"/>
```

您需要使用的主要类是`GoogleCloudMessaging`。这个类在`com.google.android.gms.gcm`包中可用。

# 总结

到本章结束时，我们将了解可用的 Google Play 服务。我们学习了如何通过其客户端库和 Android 包来改善我们的应用程序。读者应该已经通过 SDK 管理器在 Android Studio 中成功安装了 Google Play 服务客户端库，并且应该能够使用库功能构建应用程序。我们还学习了一些关于 Google Maps v2、用于 Android 身份验证的 Google+平台、Google Play 应用内购买和 GCM 的技巧。

在下一章中，我们将了解 Android Studio 中提供的某些有用工具。我们将再次详细使用 SDK 管理器来安装不同的包。我们还将学习关于 AVD 管理器，以便能够拥有不同的虚拟设备来测试我们的应用程序。我们将使用 Javadoc 工具为我们的项目生成 Javadoc 文档，并且我们将了解 Android Studio 中可用的版本控制系统。


# 第七章：工具

在上一章中，我们了解了 Google 提供的实用服务，开发者可以利用这些服务来改进他们的应用程序。现在，我们将学习 Android Studio 中提供的工具，这些工具使我们的开发工作更加轻松。你是否想知道如何管理 Android 平台？你想要一个项目有清晰的文档吗？如果你作为一个开发者团队工作，并且需要与 Android Studio 集成的版本控制管理器吗？

本章展示了 Android Studio 中提供的最重要的附加工具：Android SDK 工具，Javadoc，以及版本控制集成。首先，我们将了解 Android Studio 中的软件开发工具包管理器，通过它我们可以检查、更新和安装项目所需的不同组件。接下来，我们将回顾 Android 虚拟设备管理器，我们可以在其中编辑将在其中测试我们项目的虚拟设备。我们还将学习如何使用 Javadoc 工具进行完整文档编写，以及如何使用 Android Studio 中可用的系统进行版本控制。

这是我们将在本章中讨论的主题：

+   SDK 管理器

+   AVD 管理器

+   Javadoc

+   版本控制

# 软件开发工具包管理器

**软件开发工具包（SDK）管理器**是集成在 Android Studio 中的一个 Android 工具，用于控制我们的 Android SDK 安装。通过这个工具，我们可以检查系统中安装的 Android 平台，更新它们，安装新平台，或者安装其他组件，比如 Google Play 服务或 Android 支持库。

要从 Android Studio 打开 SDK 管理器，请导航到菜单**工具** | **Android** | **SDK 管理器**。你也可以从工具栏点击快捷方式。在管理器的顶部会显示在 Android Studio 中配置的 SDK 路径。

SDK 管理器会显示可用软件包的列表，包含以下属性：

+   **名称**：软件包或聚合了一些相关软件包的容器名称。

+   **API**：软件包添加时的 API 编号。

+   **版本号**：软件包修订或版本号。

+   **状态**：关于你的系统，软件包的状态。状态可能是**未安装**，**已安装**，**有可用更新**，**不兼容**，或**已过时**。

可以通过列表下方的复选框按状态过滤软件包，并且可以通过 API 级别或它们下载到的存储库进行排序。这些选项也可以从顶部菜单**软件包**中访问。

从菜单**工具** | **管理附加站点**，我们可以查看提供附加组件和额外软件包的官方站点列表。在**用户定义站点**菜单中，我们可以添加自定义的外部站点。

在软件包名称旁边有一个复选框，用于选择我们想要安装、更新或删除的软件包。如下截图所示，默认情况下会选中已安装在我们系统中但有待更新版本的软件包。如果有尚未安装的新安卓平台版本，其软件包也会被选中。

![软件开发工具包管理器](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_07_01.jpg)

对话框底部按钮的文本中指示了待安装或更新的选定软件包总数。其下方的按钮指示了待删除的选定软件包总数。

检查需要更新的软件包，如果您还没有安装最新的安卓平台，也请检查，并检查我们应用程序支持的最小平台，安卓 2.3.3（API 10），以便能够使用这个版本在虚拟设备中测试我们的应用程序。点击**安装**按钮。

在下一个对话框中，我们需要接受软件包许可。勾选**接受许可**单选按钮，然后点击**安装**按钮。软件包的安装或更新将开始显示其进度。首先，管理器下载软件包，然后解压，最后安装。

记得时不时检查 SDK 管理器，以查看是否有更新。

# 安卓虚拟设备管理器

**安卓虚拟设备管理器**（**AVD 管理器**）是集成在 Android Studio 中的一个安卓工具，用于管理将在安卓模拟器中执行的安卓虚拟设备。

要从 Android Studio 打开 AVD 管理器，请导航至菜单**工具** | **安卓** | **AVD 管理器**。您也可以从工具栏点击快捷方式。AVD 管理器在默认标签**安卓虚拟设备**中显示现有虚拟设备的列表。由于我们还没有创建任何虚拟设备，最初列表应为空。要创建我们的第一个虚拟设备，请点击**新建**按钮以打开配置对话框：

+   **AVD 名称**：虚拟设备的名称。

+   **设备**：选择一个可用的设备配置。这些配置是我们曾在布局编辑器预览中测试过的。选择 Nexus 4 设备，以在对话框中加载其参数。

+   **目标**：选择设备的安卓平台。我们需要创建一个最小支持我们应用程序的平台虚拟设备，以及一个目标为我们应用程序平台的虚拟设备。这两个平台都是在创建项目时配置的。对于这个第一个虚拟设备，选择目标平台，安卓 4.2.2（API 17）。

+   **CPU/ABI**：选择设备架构。此字段的值在我们选择目标平台时设置。每个平台都有其对应的架构，如果我们没有安装该架构，将会显示以下信息：**此目标没有安装系统镜像**。为解决这个问题，打开 SDK 管理器，查找目标平台的其中一个架构，如 ARM EABI v7a 系统镜像或 Intel x86 Atom 系统镜像。

+   **键盘**：选择是否在模拟器中显示硬件键盘。勾选此项。

+   **皮肤**：选择是否在模拟器中显示额外的硬件控制。勾选此项。

+   **前置摄像头**：选择模拟器是否具有前置摄像头。摄像头可以模拟，也可以通过使用计算机的摄像头实现真实效果。选择**无**。

+   **后置摄像头**：选择模拟器是否具有后置摄像头。选择**无**。

+   **内存选项**：选择虚拟设备的内存参数。保持默认值，除非出现警告信息；在这种情况下，按照信息的指示操作。例如，为**RAM**内存选择 256，为**VM Heap**选择 64。

+   **内部存储**：选择虚拟设备存储的大小，例如：200 MiB。

+   **SD 卡**：选择 SD 卡的大小，或者选择一个文件作为 SD 卡。此参数是可选的。

+   **模拟选项**：**快照**选项可以保存模拟器的状态，以便下次更快地加载。勾选此项。**使用主机 GPU**选项尝试加速 GPU 硬件，使模拟器运行得更快。

给虚拟设备一个有意义的名称以便容易识别，如`AVD_nexus4_api17`。点击**确定**按钮。

新的虚拟设备现在列在 AVD 管理器中，带有绿色勾选图标，表示它是有效的。这些图标表示虚拟设备的状态：是否有效，是否加载失败，或者其状态是否可修复。图标图例在管理器窗口底部解释。选择最近创建的虚拟设备以启用剩余操作：

+   **编辑**：编辑虚拟设备配置。

+   **删除**：删除虚拟设备。

+   **修复**：如果虚拟设备加载失败但可以修复，将提供此选项。此操作将尝试修复虚拟设备的错误状态。

+   **详情**：打开一个对话框，详细显示虚拟设备特性。

+   **启动**：运行虚拟设备。

点击**启动**按钮打开启动对话框。检查与快照相关的选项，然后点击**启动**按钮。模拟器将如下截图所示打开。等待其完全加载，然后你就可以尝试了。

![Android Virtual Device Manager](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_07_02.jpg)

从 AVD 管理器中，我们还可以配置设备定义。设备定义用于布局预览，并且是虚拟设备的基础。打开**设备定义**标签页，那里列出了现有的定义。我们可以使用**新建设备**按钮创建一个新的设备定义，可以使用**克隆**按钮轻松地克隆一个现有设备来创建一个新设备，可以使用**删除**按钮删除它们，或者可以使用**创建 AVD**按钮基于设备定义创建一个虚拟设备。

点击**新建设备**按钮检查现有的配置参数。定义一个设备最重要的参数是：

+   **名称**: 设备的名称。

+   **屏幕尺寸（英寸）**: 屏幕尺寸以英寸为单位。这个值决定了设备的尺寸类别。输入一个值`4.0`，注意**尺寸**值（在右侧）是**正常**。现在输入一个值`7.0`，**尺寸**字段将其值更改为**大**。这个参数加上屏幕分辨率也决定了密度类别。

+   **分辨率（像素）**: 屏幕分辨率以像素为单位。这个值决定了设备的密度类别。在 4.0 英寸的屏幕尺寸下，输入一个值`768 x 1280`，注意密度值是**xhdpi**。将屏幕尺寸更改为`6.0`英寸，密度值更改为**hdpi**。现在将分辨率更改为`480 x 800`，密度值是**mdpi**。

+   **传感器**: 设备中可用的传感器：加速度计、GPS、陀螺仪或接近传感器。

+   **RAM**: 设备的 RAM 内存大小。

+   **按钮**: 指示设备的 home、back 或 menu 按钮是通过软件还是硬件提供。

+   **设备状态**: 检查允许的状态。

创建一个屏幕尺寸为 4.7 英寸，分辨率为 800 x 1280，RAM 值为 200 MiB，启用软件按钮，同时启用竖屏和横屏状态的新设备。将其命名为`My Device`。点击**创建设备**按钮。

AVD 管理器现在在设备列表中显示我们的设备定义。在 Android Studio 中，使用图形编辑器打开主布局，并点击设备列表。如下截图所示，我们的自定义设备定义出现，我们可以选择它来预览布局：

![Android 虚拟设备管理器](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_07_03.jpg)

# 生成 Javadoc

Javadoc 是一个以 HTML 格式文档化 Java 代码的工具。Javadoc 文档是从添加到 Java 类或方法的注释和标签生成的。注释以`/**`字符串开始，以`*/`结束。在这些注释中，可以添加一些标签，如`@param`描述方法参数，`@throws`描述方法可能抛出的异常，或`@version`指示类或方法的版本。

Android Studio 集成了 Javadoc 的使用。在输入 Javadoc 注释时，我们可以使用代码补全功能，并且文档将显示在代码元素的弹出工具提示中。

为了生成完整的 Javadoc，我们必须编写关于我们的类和方法的 Javadoc 注释。打开项目的主活动，为我们在第五章，*创建用户界面*中创建的方法 `onAcceptClick` 添加 Javadoc 注释。将光标放在方法声明前的一行，输入 `/**` 并按下 *Enter*。Javadoc 注释会自动插入，其中包含方法声明中可用的信息：参数和返回类型。在这种情况下，没有返回类型。

文档注释的第一行是方法描述。然后，解释每个参数和返回类型。现在方法应如下所示：

```java
/**
 * Method executed when the user clicks on the Accept button.
 * Change the greeting message to include the name introduced by the user in the editText box.
 *
 * @param v View the user clicked
 */
public void onAcceptClick(View v) { ... }
```

这些关于方法的信息现在将作为其文档在弹出的对话框中显示。以下屏幕截图显示了应出现在方法上方的对话框：

![生成 Javadoc](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_07_04.jpg)

要生成 Javadoc 文档，请在顶部菜单中选择 **工具** | **生成 Javadoc**。将打开一个显示 Javadoc 选项的对话框。我们可以选择范围、输出目录、包含元素的可见性，或者是否要创建层次树、导航栏和索引。

选择 **当前文件** 作为范围以仅生成我们主活动的文档。从您的系统中选择输出目录。将可见性降低到 public 并点击 **确定** 按钮。Javadoc 文档已以 HTML 格式在输出目录中创建，`index.html` 文件是起点。浏览文档以打开 `MainActivity` 类。注意，由于我们将生成的 Javadoc 的可见性降低到 public 元素，所以不显示可见性为 protected 的 `onCreate` 方法。

# 版本控制系统

Android Studio 集成了几种版本控制系统：Git、Mercurial 或 Subversion。要启用版本控制集成，请在顶部菜单中选择 **VCS** | **启用版本控制集成** 并选择系统类型。现在，**VCS** 菜单中添加了一些更多选项。

第一步是从版本控制系统中检出。导航到 **VCS** | **从版本控制检出**，点击添加图标，并输入仓库 URL：

+   要更新整个项目，请导航到 **VCS** | **更新项目**

+   要提交项目的所有更改，请导航到 **VCS** | **提交更改**

+   要清理项目，请导航到 **VCS** | **清理项目**

版本控制操作也可以应用于单个文件。使用鼠标右键点击项目中的任何文件，并选择 **Subversion** 部分。从出现的菜单中，我们可以将文件添加到仓库，添加到忽略列表，浏览更改，恢复更改或锁定它。

控制文件版本的一个更简单的方法是使用本地历史记录。在编辑器中打开主活动文件，导航到 **VCS** | **Local History** | **Show History**。文件历史记录对话框将被打开。在对话框的左侧列出了文件的可用版本。选择一个旧版本与当前文件版本进行比较。旧版本与当前版本之间的差异会被高亮显示。灰色用于表示删除的代码块，蓝色用于突出显示已更改的文本，绿色用于指示新插入的文本。从顶部图标我们可以恢复更改并配置空白显示。下一张截图显示了主活动的两个版本之间的比较。我们可以看到我们最近添加的方法，`onAcceptClick`方法，以绿色突出显示。

![版本控制系统](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_07_05.jpg)

我们还可以检查特定代码块的本地历史记录。关闭对话框，从编辑器中选择一些代码行，然后导航到 **VCS** | **Local History** | **Show History for Selection**。将打开相同的历史记录对话框，但这次它显示所选代码的版本。

# 总结

到本章结束时，我们应该具备使用 Android SDK Manager 工具安装、更新或检查项目可用平台的知识。我们应该能够创建一个新的 Android 虚拟设备，并在必要时对其进行编辑。使用 Javadoc，编写项目的完整文档不再是一个问题，我们还应该能够使用 Android Studio 中集成的版本控制系统。

在下一章中，我们将继续使用 Android Studio 的集成功能。在本章中，我们将学习项目模拟和如何进行调试。我们将了解调试器、控制台或 LogCat 工具。我们还将学习更高级的调试工具，如 Dalvik Debug Monitor Server（DDMS）。我们将深入研究这个监控服务器，了解其提供的每种工具。


# 第八章：调试

调试环境是 IDE 最重要的功能之一。使用调试工具可以轻松优化你的应用程序并提高其性能。在 Android Studio 中编程时，你想使用这些调试工具之一吗？Android Studio 包括**Dalvik Debug Monitor Server**（**DDMS**）调试工具。

在本章中，我们将从了解运行和调试选项开始，以及如何在前一章学到的 Android 虚拟设备中模拟我们的应用程序。我们将深入探讨调试器标签页、控制台标签页和 LogCat 标签页。我们还将学习如何使用调试器设置断点，以及如何运行我们的应用程序并在这些断点处停止。我们将在本章最后介绍 Android Studio DDMS 中包含的高级调试工具的每个标签页的信息。

这是我们将在本章中介绍的主题：

+   调试

+   LogCat

+   DDMS 工具

# 运行与调试

Android 应用程序可以通过 Android Studio 在真实设备上使用 USB 连接或在虚拟设备上使用模拟器运行。虚拟设备使我们能够在不同的硬件和软件配置中测试我们的应用程序。由于简单和灵活性，在本章中我们使用模拟器来运行和调试我们的应用程序。

要直接运行一个应用程序，请导航到菜单 **运行** | **运行 'MyApplication'**。你也可以从工具栏中点击播放图标按钮。要调试一个应用程序，请导航到菜单 **运行** | **调试 'MyApplication'**，或者从工具栏中点击虫子图标。

当我们选择调试选项时，会打开一个选择设备的对话框。第一个选项是选择正在运行设备；列出可用的连接设备，无论是真实的还是虚拟的。第二个选项是启动模拟器的新实例；列出可用的虚拟设备。勾选**启动模拟器**选项，并选择在第七章，*工具*中创建的虚拟设备。点击**确定**。模拟器将被启动。下次我们运行或调试应用程序时，模拟器已经在运行，因此我们将选择第一个选项（**选择一个运行中的设备**）。

![运行与调试](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_08_01.jpg)

在调试过程中，在 Android Studio 的底部有三个标签页：**调试器**，**控制台**，和**LogCat**。

**控制台**显示在启动模拟器时发生的事件。打开它以检查消息，并确认模拟器和应用程序是否正确执行。应该出现的操作有：

+   `等待设备`：启动模拟器时的起始点。

+   `上传文件`：应用程序被打包并存储在设备上。

+   `安装`：应用程序正在设备上安装。安装完成后应该会打印成功消息。

+   `启动应用程序`：应用程序开始执行。

+   `等待进程`：应用程序现在应该正在运行，调试系统尝试连接到设备中的应用程序进程。

完成以上步骤后，应用程序将在模拟器中可见。通过在文本输入中输入任何名字并点击**接受**按钮来测试它。问候语应该会改变。

**调试器**管理断点，控制代码的执行，并显示有关变量的信息。要在我们的代码中添加断点，只需点击行代码左侧边缘。行代码旁边会出现一个红点来指示断点。要删除断点，请点击它。如果使用鼠标右键点击断点，将提供更多选项。我们可以禁用它而不删除它，或者为断点设置条件。

在我们主活动的`onAcceptClick`方法的条件语句中添加一个断点，并再次调试应用程序。

![运行和调试](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_08_02.jpg)

在应用程序中输入你的名字并点击**接受**按钮。当执行到断点时，它会暂停并打开调试标签页。由于我们在条件语句中添加了断点，在分配文本之前，我们的问候语还没有改变。

从调试标签页我们可以检查方法调用层次结构和执行到该点时的变量状态。可用的变量包括方法的参数（`v`）、通过`findViewById`方法获得的`TextView`和`EditText`对象以及当前活动的引用（`this`）。展开名为`et_name`的`EditText`对象，查找`mText`属性。这个属性应该包含你之前输入的名字：

+   要在不进入方法调用的情况下执行下一行代码，请导航到**运行** | **单步跳过**或使用为此选项指定的键盘快捷键，通常是*F8*键。

+   要进入方法调用，请导航到**运行** | **单步执行**或按*F7*键。

+   要执行到下一个断点（如果有的话），请导航到**运行** | **恢复程序**或按*F9*键。

+   要停止执行，请导航到**运行** | **停止**或按*Ctrl* + *F2*键。

这些选项（以及其他选项）也可以从调试标签页作为图标快捷方式使用。

展开对象`tv_greeting`以检查其`mText`属性的值。现在单步跳过条件语句并单步跳过`setText`方法的调用。注意`mText`属性的值是如何改变的。最后，恢复执行，以便在设备屏幕上更改问候语。

# LogCat

**LogCat** 是 Android 的日志系统，它显示运行设备中由 Android 系统生成的所有日志消息。日志消息有几个重要性级别。从 LogCat 标签页我们可以根据这些级别过滤日志消息。例如，如果我们选择信息级别作为过滤器，那么来自信息、警告和错误级别的消息将被显示。

![LogCat](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_08_03.jpg)

要从我们的代码中打印日志信息，需要导入`Log`类。这个类为每个级别都有一个方法：`v`方法用于调试级别，`d`方法用于详细，`i`方法用于信息，`w`方法用于警告，`e`方法用于错误信息。这些方法接收两个字符串参数。第一个字符串参数通常标识消息的来源类，第二个字符串参数标识消息本身。为了标识来源类，我们建议使用一个常量静态字符串标签，尽管在下一个示例中我们直接使用字符串以简化代码。在我们的主活动的`onAcceptClick`方法中添加以下日志信息：

```java
if(et_name.getText().length() > 0) {
 Log.i("MainActivity", "Name read: " + et_name.getText());
tv_greeting.setText("Hello " + et_name.getText());
} 
else {
 Log.w("MainActivity", "No name typed, greeting didn't change");
}
```

我们有一条日志信息用于提示从用户输入获取的名称，以及一条如果用户未输入任何名称则打印警告的日志信息。移除之前创建的任何断点，然后调试应用程序。

LogCat 标签打印了设备生成的所有日志信息，因此阅读我们应用程序的消息可能会比较复杂。我们需要过滤这些消息。在 LogCat 标签中有一个可扩展的列表，默认选择**无过滤**选项。展开它并选择**编辑过滤器配置**选项。将打开一个创建过滤器的对话框。可以使用正则表达式通过它们的标签或内容、打印它们的软件包名称、进程 ID（PID）或它们的级别来过滤日志消息。

创建一个名为`MyApplication`的新过滤器，并使用我们应用程序的包作为值，通过**包名称**进行过滤：`com.example.myapplication`。点击**确定**。现在 LogCat 日志已经过过滤，更容易阅读我们的消息。

1.  将焦点放在模拟器窗口上，在应用程序中输入一个名字，并点击**接受**。观察我们的日志信息如何在 LogCat 视图中打印出来。

1.  在应用程序中删除你的名字并点击**接受**。这次，打印了警告信息。注意每种类型消息使用的不同颜色。

如果我们双击 LogCat 入口，可以导航到生成该日志信息的源代码行。

# DDMS

Dalvik 调试监控服务器（DDMS）是 SDK 中一个更高级的调试工具，它也已经集成到 Android Studio 中。这个工具能够监控真实设备和模拟器。

要打开 DDMS 透视图，请导航到**工具** | **Android** | **监控（包含 DDMS）**。你也可以从工具栏点击 Android 图标按钮。将打开一个新的窗口，并显示 DDMS 透视图。

窗口的左侧显示了已连接设备的列表。目前，仅列出我们的虚拟设备。在设备部分，还展示了每个设备上运行的过程列表。我们应该能够在之前启动的设备的进程中找到我们的应用程序。从设备部分的工具栏中，我们可以使用停止标志图标按钮停止一个进程。我们还可以通过点击相机图标按钮来捕获虚拟设备的屏幕截图。其他一些选项将在后面解释。

窗口的右侧提供了设备的详细信息，这些信息分为七个标签页：**线程**，**堆**，**分配跟踪器**，**网络统计**，**文件浏览器**，**模拟器控制**和**系统信息**。窗口的底部是 LogCat，它也已经被集成到了 DDMS 视角中。

## 线程

线程标签页显示属于所选进程的线程列表。从设备部分选择我们的应用程序进程，进程通过包名`com.example.myapplication`进行标识。点击设备部分工具栏中的**更新线程**图标按钮，线程将被加载到标签页的内容中。

![线程](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_08_04.jpg)

第一列是线程的 ID。**状态**列指示线程的状态，**utime**表示线程执行用户代码的总时间，**stime**表示线程执行系统代码的总时间，**名称**表示线程的名称。我们感兴趣的线程是那些花费时间执行我们用户代码的线程。

如果我们在应用程序中除了主线程之外创建线程，这个工具将非常有用。我们可以检查它们是否在应用程序的某个点上正在执行，或者它们的执行时间是否适度。

## 方法分析

方法分析是测量选定进程中方法执行性能的工具。测量的参数是调用次数和执行时花费的 CPU 时间。有两种类型的耗时，即独占时间和包含时间：

+   **独占时间**：在执行方法本身时花费的时间。

+   **包含时间**：在执行方法中花费的总时间。这个度量包括在方法内部调用的任何方法所花费的时间。这些被调用的函数被称为它的子方法。

要收集方法分析数据，请从设备部分选择我们的应用程序进程，然后点击设备部分工具栏中的**开始方法分析**图标按钮，该按钮位于**更新线程**图标按钮旁边。接着在应用程序中执行一些操作，例如，在我们的示例应用程序中，输入一个名字并点击**接受**按钮，以执行主活动的`onAcceptClick`方法。通过点击**停止方法分析**图标按钮来停止方法分析。

当方法分析停止时，DDMS 透视图会打开一个带有结果跟踪的新标签。在这个新标签的顶部，方法调用以时间图的形式表示；每一行属于一个线程。在跟踪的底部，以表格形式表示了在方法中花费时间的概要。

按方法名称排序，以搜索我们的`onAcceptClick`方法。点击它以展开有关此方法执行详细的信息。注意以下事实：

+   在`onAcceptClick`方法内部调用的子方法被列出。我们可以看到`EditText.getText`方法、`Activity.findViewById`方法或`TextView.setText`方法，实际上我们直接在下面截图中的方法内调用它们。

+   调用次数。例如，我们可以看到`Activity.findViewById`方法被调用了两次：一次是查找`TextView`对象，第二次是查找`EditText`对象。

+   独占时间列对于父方法或子方法没有值，这是由于这种测量时间类型的自身定义。

![方法分析](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_08_05.jpg)

方法分析对于检测执行时间过长的方法非常有用，以便能够优化它们。我们可以了解哪些是最昂贵的方法，以避免对它们进行不必要的调用。

## 堆

堆标签显示了选定进程的堆内存使用信息及统计。选择应用进程，并点击设备部分工具栏中的**更新堆**图标按钮以启用它。堆信息在垃圾收集器（GC）执行后显示。若要强制执行，请点击**触发 GC**按钮，或点击设备部分工具栏中的垃圾图标按钮。

第一个表格显示了堆使用的概要：总大小、已分配空间、空闲空间以及已分配对象的数量。统计表格按类型详细显示了堆中分配的对象：对象数量、这些对象的总大小、最小和最大对象的大小、中位数大小以及平均大小。选择一个类型以加载底部条形图。该图按字节大小绘制了该类型对象的数量。如果我们使用鼠标右键点击图表，可以更改其属性（标题、颜色、字体、标签等）并将其保存为 PNG 格式的图像。

![堆](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_08_06.jpg)

## 分配跟踪器

分配跟踪器标签显示了选定进程的内存分配情况。选择应用进程并点击**开始跟踪**按钮以开始跟踪内存信息。然后点击**获取分配**按钮以获取已分配对象列表。

我们可以使用标签页顶部的过滤器来筛选分配在我们自己类中的对象。在过滤器中输入我们的包名，`com.example.myapplication`。对于每个对象，表格显示其分配大小、线程、对象或类，以及分配该对象的方法。点击任何对象查看更多信息，例如，分配它的行号。最后，点击**停止追踪**按钮。

分配追踪器对于检查在应用程序中进行某些交互时分配的对象非常有用，以便改善内存消耗。

## 网络统计

网络统计标签页展示了我们的应用程序如何使用网络资源。要获取使用网络的任何应用程序的网络统计信息，请点击**开始**按钮。数据传输将开始出现在图表中。

网络统计信息有助于优化我们代码中的网络请求，并在执行过程中的某个点控制数据传输。

## 文件浏览器

此标签页暴露了设备上的整个文件系统。对于每个元素，我们可以检查其大小、日期或权限。导航到`/data/app/`以搜索我们的应用程序包文件，`com.example.myapplication.apk`。

## 模拟器控制

模拟器控制允许我们在虚拟设备中模拟一些特殊状态或活动。我们可以在不同的环境和情况下测试我们的应用程序，以确保其行为符合预期。如果我们的应用程序具有依赖于设备物理位置的功能，我们可以使用模拟位置：

+   **通话状态**：选择语音和数据状态，其速度和延迟

+   **通话操作**：模拟来电或短信

+   **位置控制**：设置设备的地理位置

## 系统信息

系统信息标签页以图表形式展示设备的帧渲染时间、总 CPU 负载和总内存使用情况。我们可以搜索我们的应用程序，并将其轻松地与设备上运行的其他进程进行比较。

我们可以更改图表的属性，如颜色、字体、标题，并将其保存为 PNG 格式的图像。要打开这些选项，请使用右键点击图表元素。

当我们的应用程序在前台运行时，打开 CPU 负载并保存图表。然后关闭应用程序，并通过点击**从设备更新**按钮更新 CPU 负载。注意两张图表之间的差异，并注意空闲百分比的升高。

![系统信息](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_08_07.jpg)

# 概述

在本章结束时，用户应该了解他们应用程序的不同启动选项以及如何使用控制台和 LogCat 进行调试。他们还应该学会如何调试应用程序，并解读 DDMS 在每个可用标签页中提供的数据。

在下一章中，我们将使用 Android Studio 为我们的应用程序发布做准备。首先，我们会了解在以发布模式构建应用程序之前需要执行的必要步骤。我们将了解应用程序是如何在 `APK` 文件中进行压缩的，以及如何生成我们自己的 `APK`。最后，我们将学习作为开发者如何获取我们的证书，以及如何生成签名的 `APK` 文件，使其准备好发布。


# 第九章：发布准备

在前面的章节中，你已经学到了足够多的知识来测试和调试你的应用程序。那么，为了发布你的应用程序，你需要做哪些准备？如何使用 Android Studio 完成这些工作？

本章介绍了使用 Android Studio 准备应用程序发布的必要步骤。首先，我们将了解应用程序包文件，这是 JAR 文件的一种变体，安卓应用程序就是通过它来打包的。然后，我们将了解在完全测试应用程序后，我们需要对其进行哪些更改。最后，我们将签署我们的应用程序 APK（**应用程序包**）文件，使其准备好上传到任何市场，如 Google Play。

这是我们将在本章中讨论的主题：

+   发布准备

+   APK 文件

+   获取证书

+   生成签名的 `APK`

# 什么是 APK 文件

安卓应用程序打包在一个带有 `.APK` 扩展名的文件中，这是 Java JAR（**Java 归档**）文件的一种变体。这些文件实际上只是压缩的 ZIP 文件，因此其内容可以轻松查看。APK 文件通常包含以下内容：

+   `assets/`：一个包含应用程序资产文件的文件夹。这是项目中已存在的 `assets` 文件夹。

+   `META-INF/`：一个包含我们证书的文件夹。

+   `lib/`：如果需要处理器，则包含编译后的代码的文件夹。

+   `res/`：一个包含应用程序资源的文件夹。

+   `AndroidManifest.xml`：应用程序的清单文件。

+   `classes.dex`：一个包含应用程序编译后代码的文件。

+   `resources.arsc`：一个包含一些预编译资源的文件。

有了 `APK` 文件，应用程序可以在 Android 操作系统上进行分发和安装。你可以根据自己的喜好分发安卓应用程序，通过 Google Play、Amazon Appstore 或 Opera Mobile Store 等应用市场；通过自己的网站；或者甚至通过电子邮件发送给你的用户。如果你选择最后两种选项中的任何一种，请记住 Android 默认会阻止来自 Google Play 之外位置的安装。你应该通知你的用户，他们需要在设备上取消此限制才能安装你的应用程序。他们需要从 Android 设备的 **设置** | **安全** 菜单中勾选 **未知来源** 选项。

应用程序在构建时必须使用私钥进行签名。如果应用程序没有签名，它就不能在设备或模拟器上安装。为了构建我们的应用程序，有两种模式：调试和发布。这两个 `APK` 版本包含相同的文件夹和编译后的文件。不同之处在于用于签名的密钥：

+   **调试**：在前面的章节中，我们运行和测试应用时处于调试模式，但我们没有密钥，也没有对应用进行签名。Android SDK 工具会自动创建一个用于签名`APK`的调试密钥、别名及其密码。当我们使用 Android Studio 运行或调试应用时，这个过程会自动发生，而我们甚至没有意识到。我们不能发布使用 SDK 工具创建的调试密钥签名的`APK`。

+   **发布**：当我们想要在其他 Android 设备上分发我们的应用时，我们必须构建一个发布版本。要求`APK`文件使用开发者保留私钥的证书进行签名。在这种情况下，我们需要自己的私钥、别名和密码，并将它们提供给构建工具。证书标识了应用的开发者，可以是自签名的证书。不需要证书颁发机构签名证书。

    ### 提示

    将带有你证书的密钥库保存在安全的地方。为了升级你的应用，你必须使用相同的密钥来上传新版本。如果你丢失了密钥库，你将无法更新你的应用。你将不得不创建一个具有不同包名的全新应用。

# 之前的步骤

在我们生成`APK`文件之前，有必要为发布模式构建我们的应用做好准备。

首先，确保你已经彻底测试了你的应用。我们建议在以下情况下测试你的应用：

+   在使用最低要求平台的设备上进行测试。

+   在使用目标平台的设备上进行测试。

+   在使用最新可用平台的设备上进行测试。

+   在真实设备上，而不仅仅是模拟器中。

+   在各种屏幕分辨率和尺寸上进行测试。

+   如果你的应用支持平板电脑，请在平板上进行测试。

+   如果你允许，切换到横屏模式，无论是在手机还是平板电脑上。

+   在不同的网络条件下，例如没有互联网连接或覆盖范围低。

+   如果你的应用使用了 GPS 或任何定位服务，请在不激活设备上的这些服务时进行测试。

+   返回按钮的行为

第二，我们必须检查从我们的应用打印出的日志消息。打印某些日志消息可能被视为安全漏洞。由 Android 系统生成的日志可以被捕获和分析，因此我们应避免显示关于应用内部工作原理的敏感信息。你还应该从应用清单文件中移除`android:debuggable`属性。你也可以将此属性设置为`false`。

第三，如果你的应用与服务器通信，请检查配置的 URL 是否是生产环境的。在调试阶段，你可能引用了一个预发布环境中的服务器 URL。

最后，从应用程序清单文件中设置`android:versionCode`和`android:versionName`属性的准确值。版本代码是一个数字（整数），表示应用程序版本。新版本应该有更高的版本代码。此代码用于确定设备中安装的应用程序是否为最新版本，或者有更新的版本。

版本名称是一个表示应用程序版本的字符串。与版本代码不同，版本名称对用户可见，并出现在应用程序的公开信息中。它只是向用户提供的版本信息，不用于任何内部目的。

为版本代码指定值 1，版本名称为 1.0。清单标签应如下所示： 

```java
<manifest 
    package="com.example.myapplication"
    android:versionCode="1"
    android:versionName="1.0" >
```

我们应用程序的新版本将为版本代码赋予值 2，版本名称可以是 1.1。

```java
<manifest 
    package="com.example.myapplication"
    android:versionCode="2"
    android:versionName="1.1" >
```

# 生成签名 APK

要生成签名的`APK`，请导航到菜单**构建** | **生成签名 APK**。在生成签名`APK`的对话框中，系统会要求我们提供证书。`APK`由该证书签名，表示它属于我们。

如果这是我们第一个应用程序，可能我们没有任何证书。点击**创建新证书**按钮以打开创建新密钥库的对话框。我们必须填写以下信息。

+   **密钥库路径**：在系统中创建密钥库的路径。密钥库是一个带有`.jks`扩展名的文件。例如，将其命名为`release_keystore.jks`。

+   **密码**：密钥库密码。你必须确认它。

+   **别名**：证书及其公私钥对的别名。例如，将其命名为`releasekey`。

+   **密码**：证书密码。你必须确认它。

+   **有效期**：证书将直到有效期结束。建议使用 25 年或更长时间的值。

+   **证书**：证书中包含的个人资料信息。输入你的名字和姓氏、组织单位、组织、城市或地区、州或省、国家代码。例如，将**组织单位**命名为`AS example`，**组织**命名为`packtpub`，以及**国家代码**命名为`ES`。

点击**确定**。现在已加载用于创建签名`APK`的对话框，其中包含密钥库数据。下次我们创建签名`APK`时，我们已经有了证书，因此我们将点击**选择现有**按钮。点击**下一步**按钮。在下一步中，选择保存`APK`文件的路径并点击**完成**。当 APK 完全生成时，我们将得到通知，如下面的截图所示：

![生成签名 APK](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_09_01.jpg)

我们应该在所选路径中创建 APK 文件。点击**在资源管理器中显示**按钮以打开包含生成包的文件夹，或点击**关闭**按钮仅关闭消息。

既然我们已经有了发布 APK 文件，建议在分发之前在设备上再次进行测试。

# 摘要

我们已经学习了如何制作一个`APK`文件以及如何修改我们的应用程序以便发布。我们还学习了如何使用我们的开发者证书为应用签名。在本章结束时，用户应该已经生成了一个准备好发布的已签名`APK`。

在下一章中，我们将学习如何使用 Android Studio 获得帮助。我们将访问 Android Studio 的在线文档，并浏览帮助主题。最后，我们还将学习如何使用内置功能保持我们的 Android Studio 实例更新。


# 第十章：获取帮助

在新的 IDE 中开发应用程序时，总会对如何执行某个操作产生疑问。成功的 IDE 通常包括帮助向导和文档，帮助用户解决不同问题。你是否在好奇如何使用 Android Studio 获取帮助？

在最后一章中，我们将学习关于 Android Studio 的文档和帮助主题。我们将了解可以在官方 Android 网站上在线访问的官方文档中的主题。最后，我们将学习如何使用更新功能来保持我们的 Android Studio 实例保持最新。

包含主题：

+   Android Studio 帮助

+   在线文档

+   Android Studio 更新

# 从 Android Studio 获取帮助

Android Studio 的文档包含在 IntelliJ IDEA 网络帮助中。可以从 Android Studio 的菜单 **帮助** | **在线文档** 访问此文档，或者访问 [`www.jetbrains.com/idea/documentation/`](http://www.jetbrains.com/idea/documentation/)。更好的选择是导航到 **帮助** | **帮助主题** 直接打开文档内容树，或者访问 [`www.jetbrains.com/idea/webhelp/intellij-idea.html`](http://www.jetbrains.com/idea/webhelp/intellij-idea.html)。还有一些在线视频教程可供使用。导航到 **帮助** | **JetBrains TV** 或打开 URL [`tv.jetbrains.net/`](http://tv.jetbrains.net/)。

为了快速找到 Android Studio 的操作，我们可以使用 **帮助** | **查找操作** 选项。输入你想要查找的操作，将会显示匹配操作列表。

最后，Android Studio 提供了每日技巧功能。每日技巧会在对话框中解释关于 Android Studio 的一个技巧。每次打开 Android Studio 时，都会显示这个对话框。我们可以使用 **上一个技巧** 和 **下一个技巧** 按钮浏览更多技巧。通过取消选择 **启动时显示技巧** 复选框，我们可以禁用此功能。通过导航到 **帮助** | **每日技巧** 可以打开技巧对话框。

# Android 在线文档

谷歌提供的官方 Android 文档可以在 [`developer.android.com/`](http://developer.android.com/) 上找到。该文档包含了不仅如何编程 Android 应用程序，还包括如何为 Android 设计以及如何分发和推广我们的应用程序的所有必要指南。由于这个网站相当广泛，这里我们列出了一些针对本书章节中展示知识有用的特定指南。

1.  第一章，*安装和配置 Android Studio*：

    +   开始使用 Android Studio，请访问 [`developer.android.com/sdk/installing/studio.html`](http://developer.android.com/sdk/installing/studio.html)

    +   故障排除，请访问[`developer.android.com/sdk/installing/studio.html#Troubleshooting`](http://developer.android.com/sdk/installing/studio.html#Troubleshooting)

    +   已知问题，请访问[`tools.android.com/knownissues`](http://tools.android.com/knownissues)

1.  第二章，*开始一个项目*：

    +   图标设计 | 启动器，请访问[`developer.android.com/design/style/iconography.html#launcher`](http://developer.android.com/design/style/iconography.html#launcher)

    +   使用代码模板，请访问[`developer.android.com/tools/projects/templates.html`](http://developer.android.com/tools/projects/templates.html)

1.  第三章，*浏览项目*：

    +   管理项目，请访问[`developer.android.com/tools/projects/`](http://developer.android.com/tools/projects/)

    +   Android Studio 技巧与窍门 | 项目结构，请访问[`developer.android.com/sdk/installing/studio-tips.html#Project`](http://developer.android.com/sdk/installing/studio-tips.html#Project)

1.  第四章，*使用代码编辑器*：

    +   Android Studio 技巧与窍门 | 键盘命令，请访问[`developer.android.com/sdk/installing/studio-tips.html#KeyCommands`](http://developer.android.com/sdk/installing/studio-tips.html#KeyCommands)

1.  第五章，*创建用户界面*：

    +   布局，请访问[`developer.android.com/guide/topics/ui/declaring-layout.html`](http://developer.android.com/guide/topics/ui/declaring-layout.html)

    +   输入控制，请访问[`developer.android.com/guide/topics/ui/controls.html`](http://developer.android.com/guide/topics/ui/controls.html)

    +   输入事件，请访问[`developer.android.com/guide/topics/ui/ui-events.html`](http://developer.android.com/guide/topics/ui/ui-events.html)

    +   支持多屏幕，请访问[`developer.android.com/guide/practices/screens_support.html`](http://developer.android.com/guide/practices/screens_support.html)

1.  第六章，*Google Play 服务*：

    +   Google Play 服务，请访问[`developer.android.com/google/play-services/`](http://developer.android.com/google/play-services/)

    +   PlusOneButton，请访问[`developer.android.com/reference/com/google/android/gms/plus/PlusOneButton.html`](https://developer.android.com/reference/com/google/android/gms/plus/PlusOneButton.html)

1.  第七章，*工具*：

    +   SDK 管理器，请访问[`developer.android.com/tools/help/sdk-manager.html`](http://developer.android.com/tools/help/sdk-manager.html)

    +   管理虚拟设备，请访问[`developer.android.com/tools/devices/`](http://developer.android.com/tools/devices/)

1.  第八章，*调试*：

    +   使用 DDMS，请访问[`developer.android.com/tools/debugging/ddms.html`](http://developer.android.com/tools/debugging/ddms.html)

    +   阅读 和 编写 日志，请访问 [`developer.android.com/tools/debugging/debugging-log.html`](http://developer.android.com/tools/debugging/debugging-log.html)

    +   使用 Traceview 和 dmtracedump 进行分析，请访问 [`developer.android.com/tools/debugging/debugging-tracing.html`](http://developer.android.com/tools/debugging/debugging-tracing.html)

1.  第九章, *准备发布*:

    +   发布概览，请访问 [`developer.android.com/tools/publishing/publishing_overview.html`](http://developer.android.com/tools/publishing/publishing_overview.html)

# 更新

从帮助菜单中我们可以检查 Android Studio 的更新。导航到 **帮助** | **检查更新**。检查完成后，如果有我们尚未安装的 Android Studio 可用更新，更新信息将在一个对话框中显示。这个对话框在下一张截图中展示。我们可以查看当前版本、新版本代码及其大小。我们可以选择是否要忽略更新、稍后更新（**稍后提醒我**按钮）、查看关于更新的在线发行说明（**发行说明**按钮），或者安装更新（**更新并重启**按钮）。点击最后一个选项来更新 Android Studio。更新首先开始下载，然后 Android Studio 将重启并安装更新。

![更新](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/as-app-dev/img/5273OS_10_01.jpg)

如果我们已经安装了最新版本的 Android Studio，将会显示以下信息：

**你已经安装了最新版本的 Android Studio (I/O 预览)。要配置自动更新设置，请参阅 IDE 设置中的更新对话框**

点击 **更新** 链接打开更新配置对话框。我们可以选择是否希望 Android Studio 自动检查更新以及检查哪种类型的更新，例如，测试版或稳定版。

我们可以通过导航到菜单 **帮助** | **Android Studio 新功能** 来检查关于最近的 Android Studio 更新的信息。这些信息可以在网上找到，地址是 [`tools.android.com/recent`](http://tools.android.com/recent)。要获取我们当前使用的 Android Studio 版本，甚至是系统中的 Java 版本，请导航到 **帮助** | **关于**。

# 概述

我们已经学会了如何使用 Android Studio 文档，以防我们需要在 IDE 中执行任何操作的帮助。我们也了解了更新功能，以始终保持安装最新版本的 Android Studio。在本章结束时，用户应该能够使用在线文档和帮助主题搜索帮助，并使用最新功能保持他们的 Android Studio 保持更新。
