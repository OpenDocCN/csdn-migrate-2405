# Robotium 安卓自动化测试（一）

> 原文：[`zh.annas-archive.org/md5/991EAEAE686DDB72AC1C069EB72558B3`](https://zh.annas-archive.org/md5/991EAEAE686DDB72AC1C069EB72558B3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

移动设备上的自动化测试已经存在了好几年，但真正得到发展是在 Robotium 框架出现之后。

在自动化测试用例的帮助下，业务组件得到了广泛的重用，有助于执行复杂的测试用例。由于 Robotium 框架添加了许多不同的关键特性，它已经成为世界上领先的 Android 测试自动化框架，大多数行业专家和专业人士都在使用这个框架来测试他们的 Android 业务应用。

将这本书推向市场的目的是为用户提供关于 Robotium 框架及其特性的详细知识。阅读之后，你应该能够开始创建自动化测试用例，并为你的 Android 项目运行它们！

欢迎来到 Android 的 Robotium 自动化测试！

# 这本书涵盖的内容

第一章，*Robotium 入门*，讨论了 Robotium 框架，并帮助我们一步步在 Windows 上安装和设置 Android 环境。

第二章，*使用 Robotium 创建测试项目*，指导你创建一个测试项目，并帮助你使用 Eclipse 运行它。

第三章，*Robotium API*，介绍 `Solo` 类以及框架中存在的 API 信息。它还将教会你关于国际化的知识。

第四章，*Robotium 中的 Web 支持*，简要介绍如何使用 Robotium 的 Web 支持在 Android 中访问网页元素。

第五章，*与其他框架的比较*，旨在基于某些参数提供 Robotium 与其他测试框架之间的比较。

第六章，*Robotium 中的远程控制*，介绍软件自动化框架支持以及 Android 中远程控制的工作原理。

第七章，*Robotium 的其他工具*，包含了 Robotium 框架中各种现成的工具。这些工具包括 `RobotiumUtils` 类、XPath 的使用、Robotium 在已安装的 Android 应用中的使用，以及在应用签名和取消签名操作期间涉及的签名过程，以执行测试。

第八章，*Maven 中的 Robotium*，简要介绍 Maven 工具，该工具帮助你将 Android 项目连接到构建过程。这一章还解释了你需要使用 Maven 配置 Robotium 的不同方法。

# 你需要为这本书准备什么

对于这本书，你需要有 Windows XP（或更新版本）、Linux 或 Mac OS X 操作系统。

你需要下载并安装 Android SDK 和 Eclipse IDE（参考第一章中的*设置 Android 环境*部分，*Robotium 入门*）。

# 本书适合的读者对象

Robotium 是针对 Android 应用程序的自动化测试用例开发者的框架。本书旨在帮助初学者熟悉 Robotium SDK。你需要对 Java 和 Android 编程有基本的了解，以及基本的命令行熟悉度。

# 约定

在这本书中，你会发现多种文本样式，用于区分不同类型的信息。以下是一些样式示例，以及它们的含义解释。

文本中的代码词汇如下所示："我们可以通过使用`include`指令包含其他上下文。"

网站参考链接如下所示：[`github.com/jayway/robotium/tree/master/robotium-solo`](https://github.com/jayway/robotium/tree/master/robotium-solo)

代码块如下设置：

```kt
Activity activity = solo.getCurrentActivity();

ImageView imageView = (ImageView) solo.getView(act.getResources().getIdentifier("appicon", "id", act.getPackageName()));
```

任何命令行输入或输出如下所示：

```kt
# adb push app.apk <path>

```

# 读者反馈

我们始终欢迎读者的反馈。告诉我们你对这本书的看法——你喜欢或可能不喜欢的内容。读者的反馈对我们开发能让你们充分利用的标题非常重要。

如果要给我们发送一般反馈，只需发送电子邮件至`<feedback@packtpub.com>`，并在邮件的主题中提及书名。

如果你对某个主题有专业知识，并且有兴趣撰写或参与书籍编写，请查看我们在[www.packtpub.com/authors](http://www.packtpub.com/authors)上的作者指南。

# 客户支持

既然你现在拥有了 Packt 的一本书，我们有一些事情可以帮助你最大限度地利用你的购买。

## 下载示例代码

你可以从你在[`www.packtpub.com`](http://www.packtpub.com)的账户下载你所购买的所有 Packt 图书的示例代码文件。如果你在其他地方购买了这本书，可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)注册，我们会直接将文件通过电子邮件发送给你。

## 勘误

尽管我们已经竭尽全力确保内容的准确性，但错误仍然会发生。如果您在我们的书中发现了一个错误——可能是文本或代码中的错误——如果您能报告给我们，我们将不胜感激。这样做，您可以避免其他读者感到沮丧，并帮助我们在后续版本中改进这本书。如果您发现了任何勘误信息，请通过访问 [`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书籍，点击 **errata** **submission** **form** 链接，并输入您的勘误详情。一旦您的勘误信息得到验证，您的提交将被接受，并且勘误信息将被上传到我们的网站，或添加到该标题勘误部分现有的勘误列表中。任何现有的勘误信息可以通过选择您的标题从 [`www.packtpub.com/support`](http://www.packtpub.com/support) 进行查看。

## 盗版

互联网上对版权材料的盗版行为是所有媒体持续面临的问题。在 Packt，我们非常重视对我们版权和许可的保护。如果您在网上以任何形式遇到我们作品的非法副本，请立即提供其位置地址或网站名称，以便我们可以寻求补救措施。

如果您发现了疑似盗版材料，请通过 `<copyright@packtpub.com>` 联系我们，并提供该材料的链接。

我们感谢您帮助保护我们的作者，以及我们为您带来有价值内容的能力。

## 问题

如果您在书的任何方面遇到问题，可以通过 `<questions@packtpub.com>` 联系我们，我们将尽力解决。


# 第一章：开始使用 Robotium

自动化测试帮助我们保持高质量的软件，并提供了一种捕获代码更改是否影响实际用例的设施。本章介绍了 Robotium 框架，它的不同特性以及在自动化测试世界中的好处。在本章结束时，我们将在 Eclipse IDE 中完成 Android 环境的完整设置，开始使用 Robotium。

# Robotium 框架

Robotium 是一个开源自动化测试框架，用于编写针对 Android 应用程序的健壮且强大的黑盒测试（主要侧重于黑盒测试用例）。它完全支持原生和混合应用程序的测试。原生应用程序在设备上是实时的，即专为特定平台设计，可以从 Google Play 商店安装；而混合应用程序部分是原生的，部分是 Web 应用。这些也可以从应用商店安装，但需要在浏览器中渲染 HTML。

Robotium 主要用于自动化 UI 测试用例，并在内部使用运行时绑定到**图形用户界面**（**GUI**）组件。

Robotium 遵循 Apache License 2.0 发布。它是免费下载的，个人和企业都可以轻松使用，并建立在 Java 和 JUnit 3 之上。更准确地说，Robotium 是 Android Test Unit Framework 的扩展，可在[`developer.android.com/tools/testing/testing_android.html`](http://developer.android.com/tools/testing/testing_android.html)找到。Robotium 也可以在没有应用程序的情况下工作，在测试源代码之下。

使用 Robotium 编写的测试用例可以在 Android 模拟器（**Android Virtual Device** (**AVD**))上执行——我们将在下一节安装过程中看到如何创建 AVD——或者在实际的 Android 设备上执行。开发者可以跨多个活动编写功能、系统和验收测试场景。

它目前是全球领先的自动化测试框架，许多开源开发者正在贡献，以在后续版本中引入更多激动人心的功能。以下屏幕截图是 Robotium 项目的 git 仓库网站：

![Robotium 框架](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_01_01.jpg)

由于 Robotium 是一个开源项目，任何人都可以为了开发目的做出贡献，帮助增强框架，加入更多功能。Robotium 的源代码在 GitHub 上维护，可以通过以下链接访问：

[`github.com/jayway/robotium`](https://github.com/jayway/robotium)

你只需克隆项目。在克隆的项目中做出所有更改，并在你的仓库上点击**Pull Request**，告诉核心团队成员哪些更改需要合并。如果你不熟悉 git 环境，可以参考以下链接的 GitHub 教程：

[`help.github.com/`](https://help.github.com/)

Robotium 类似于 Selenium，但适用于 Android。这个项目是由*Renas Reda*在 2010 年 1 月启动的。他是 Robotium 的创始人兼主要开发者。项目从 v1.0 开始，由于新需求的出现，继续推出新版本。它支持 Android 功能，如活动、Toasts、菜单、上下文菜单、Web 视图和远程控制。

![Robotium 框架](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_01_02.jpg)

让我们看看 Robotium 为 Android 测试用例开发者提供的功能和好处。

# 功能和好处

使用 Robotium 进行自动化测试具有许多功能和好处。用户、Robotium 和 Android 设备之间的三角工作流程图清楚地解释了它们之间的用例：

![功能和好处](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_01_03.jpg)

Robotium 的功能和好处如下：

+   Robotium 可以帮助我们快速编写强大的测试用例，而无需对被测应用程序有太多了解。

+   Robotium 提供 API，可以直接与 Android 应用程序内的 UI 控件交互，如 EditText、TextView 和 Button。

+   Robotium 正式支持 Android 1.6 及以上版本。

+   Robotium 不会修改 Android 平台。

+   Robotium 测试也可以使用命令提示符执行。

+   Robotium 可以平滑地与 Maven 或 Ant 集成。这有助于将 Robotium 添加到你的项目构建自动化过程中。

+   在 Robotium 中可以捕获屏幕截图（以下是一个示例截图）：![功能和好处](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_01_04.jpg)

+   测试应用程序项目和应用程序项目在同一个 JVM 上运行，即**Dalvik 虚拟机**（**DVM**）。

+   可以在没有源代码的情况下运行 Robotium。

+   Robotium 可以与其他代码覆盖率测量工具配合使用，例如 Cobertura 和 Emma。

+   Robotium 可以检测屏幕上显示的消息（Toasts）。

+   Robotium 支持 Android 的活动、菜单和上下文菜单功能。

+   Robotium 自动化测试可以快速实现。Robotium 基于 JUnit 构建，因此它继承了 JUnit 的所有功能。Robotium 框架可以自动处理 Android 应用程序中的多个活动。

+   与标准的 instrumentation 测试相比，Robotium 测试用例的可读性更强。

+   滚动活动由 Robotium 框架自动处理。

+   Robotium 的最新版本支持混合应用程序。混合应用程序使用 WebViews 以全屏显示 HTML 和 JavaScript 文件，使用本地浏览器渲染引擎。

# 设置 Android 环境

你可以在 Eclipse 中设置 Android 环境，这是使用 Robotium 创建测试项目的基本步骤，如下所示：

## 需求

在为 Robotium 设置 Android 环境之前，你需要检查以下所有必需的元素：

+   必须安装**Java 开发工具包**（**JDK**）（你可以从[`www.oracle.com/technetwork/java/javase/downloads/index.html`](http://www.oracle.com/technetwork/java/javase/downloads/index.html)安装）

+   必须安装 Eclipse IDE

    +   标准 Eclipse IDE ([`www.eclipse.org/downloads/`](http://www.eclipse.org/downloads/))

    +   内置**Android 开发工具**（**ADT**）的 Eclipse IDE ([`developer.android.com/sdk/index.html`](http://developer.android.com/sdk/index.html))

    +   对于 Robotium for Android Starter，我们将使用标准 Eclipse IDE，这是各行各业的技术爱好者和开发人员广泛使用的。内置 ADT 的 Eclipse IDE 有一个 Android 插件，无需设置 Android SDK。两种 Eclipse IDE 中只需选择一种。

    +   要使用标准 Eclipse IDE 进行 Android 开发并设置新的 SDK，你需要下载 SDK 工具并选择要安装的附加 SDK 包。在现有版本的 Eclipse IDE 中，添加 ADT 插件

## 下载 Android SDK

下载 Android SDK 最简单的方法是从[`developer.android.com/sdk/index.html`](http://developer.android.com/sdk/index.html)获取一个压缩的 ADT 包。

Android SDK 提供了库和开发工具，用于构建、测试和调试 Android 应用程序。

将其解压到系统上的安全位置。在以下步骤中我们将使用这个包。

## 安装 ADT

你可以按照列出的步骤安装 ADT：

1.  在 Eclipse IDE（Kepler 版本）中，点击**帮助**菜单，然后选择**安装新软件**选项。你会看到以下屏幕，它会根据**工作区间：**组合框中提供的网站 URL 显示可用软件。**安装新软件**向导允许你将新软件添加到你的安装中，如下截图所示：![安装 ADT](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_01_05.jpg)

1.  使用**工作区间：**组合框，你可以随时选择任何网站浏览其内容。你也可以浏览这些网站上的所有软件。当你知道软件名称但不知道实际位置时，这很有用。

1.  在**安装新软件**窗口中点击**添加**按钮，这将打开**添加仓库**窗口，如下截图所示。

1.  在此窗口中，在**名称**字段中输入名称，在**位置**字段中输入以下 URL，然后点击**确定**按钮以下载 Android ADT：![安装 ADT](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_01_06.jpg)

1.  Eclipse 现在将从这个位置搜索所有可用的工具，并将它们列出来，如下所示：![安装 ADT](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_01_07.jpg)

1.  选择所有工具并点击**下一步**。这将打开一个窗口，如下截图所示，列出所有将作为 Eclipse 插件安装的组件：![安装 ADT](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_01_08.jpg)

1.  在 **安装详情** 窗口中点击 **下一步** 按钮。在完成许可验证后，它将开始下载所有提到的工具。成功安装后，系统会提示你重启 Eclipse IDE。重启它！

## 添加 Android SDK 位置

要将 Android SDK 添加到 Eclipse，请按照列出的步骤操作：

1.  在 Eclipse 中，从 **窗口** 菜单下，点击 **首选项**（Mac OS X 用户可能在 **Eclipse** 菜单下找到 **首选项**）。检查 **Android** 选项卡（此选项卡的存在清楚地表明 Android ADT 插件已成功安装）并会出现如下截图所示的窗口。SDK 位置告诉 Eclipse Android SDK 在系统中的位置。

1.  如果 SDK 位置不存在，浏览到解压后的 `SDK` 目录并点击 **确定**。只有在提供了正确的 SDK 位置并点击了 **应用** 或 **确定** 按钮后，SDK 目标列表才会重新加载。这些目标来自 SDK 本身。

1.  如果你仍然在目标列表中没有看到任何条目，这意味着你的 Android SDK 没有正确安装。按照步骤 3 所述安装 Android SDK，并在列表中检查 SDK 目标：

![添加 Android SDK 位置](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_01_09.jpg)

## 安装最新 SDK 版本

在实际创建虚拟设备之前，你需要安装最新版本的 SDK。从 **窗口** 菜单中进入 **Android SDK 管理器**，会出现如下截图所示的窗口。选择已安装的最新 SDK 版本。你可以根据你的选择选择任何版本，并点击 **安装包…**。安装完成后，如果包安装更改没有反映出来，请重启 Eclipse：

![安装最新 SDK 版本](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_01_10.jpg)

## 设置 AVD

Android 环境的初始配置几乎完成。现在，我们只需要设置 AVD。

AVD 用于运行 Android 应用程序。建议你使用 Android 设备来运行应用程序。但在本书的范围内，我们将只使用 AVD（Android 模拟器）来运行应用。

你可以从 Eclipse 中 **窗口** 菜单下的 **AVD 管理器** 选项中创建一个新的 AVD。在 AVD 屏幕上点击 **新建**，你会看到一个如下截图所示的窗口。填写以下详细信息并点击 **确定**。

![设置 AVD](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_01_11.jpg)

创建后，它将显示在 Android SDK 和 AVD 管理器屏幕下。

要运行创建的 AVD，请右键点击项目并导航到 **运行方式** | **Android 应用程序**。将会弹出一个 **部署目标选择模式** 窗口，要求你选择一个 AVD 或连接的 Android 设备来运行你的应用程序；选择其中任何一个，应用程序就会安装在所选设备/AVD 上。以下截图是 **部署目标选择模式** 窗口：

![设置 AVD](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_01_12.jpg)

到目前为止，你应该已经拥有了一个可以工作的 Android 环境来开始使用 Robotium 编写和执行测试用例。你可以自由地探索并了解更多相关信息。

# 总结

在本章中，我们学习了 Robotium 框架以及需要执行哪些不同的步骤来让你的 Android 环境准备好使用这个框架。

在下一章中，我们将开始使用 Robotium 实现我们的第一个测试项目。如果你想要学习关于测试用例实现的内容，请继续阅读。


# 第二章：使用 Robotium 创建测试项目

本章将指导您使用 Robotium Framework 为 Android 创建第一个测试项目。首先，让我们实现一个简单的计算器 Android 应用。然后，使用这个**被测应用（AUT）**，我们将了解创建 Robotium 测试项目的过程。

# 创建 AUT

在本节中，我们将创建一个简单的计算器应用，允许输入两个数字。用户可以对这两个数字执行以下两种操作：

+   加法

+   减法

这些操作可以通过 Spinner 控件选择。Spinner 与其他编程语言（如 HTML 和 C#）中的组合框类似。底对齐的 TextView 中的**获取结果**按钮用于获取操作结果。

以下截图展示了 ZCalculator 应用：

![创建 AUT](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_02_01.jpg)

要创建 AUT，请按照列出的步骤操作：

1.  在 Eclipse IDE 中，通过导航至**文件** | **新建** | **Android 应用项目**来创建一个**Android 应用项目**。![创建 AUT](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_02_02.jpg)

1.  输入应用详情，如以下截图所示，然后点击**下一步**按钮：![创建 AUT](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_02_03.jpg)

1.  保持默认选项，如以下截图所示，然后点击**下一步**按钮：![创建 AUT](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_02_04.jpg)

1.  对于这个 Android 应用项目，我们将配置启动图标，设置默认值，如以下截图所示，然后点击**下一步**按钮：![创建 AUT](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_02_05.jpg)

1.  如果**创建活动**复选框未选中，请勾选它，并选择**空白活动**，如以下截图所示，以在项目中创建默认的空白活动类：![创建 AUT](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_02_06.jpg)

1.  在**活动名称**字段中输入`Main`，如以下截图所示，然后点击**完成**按钮以创建 Android 应用项目：![创建 AUT](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_02_07.jpg)

你的 Android 项目现在已经设置好了。你可以参考以下给出的 ZCalculator 项目代码库：

1.  在你的`Main.java`文件中使用以下代码：

    ```kt
    package com.zcalculator;

    import com.calculator.R;

    import android.app.Activity;
    import android.os.Bundle;
    import android.view.View;
    import android.widget.Button;
    import android.widget.EditText;
    import android.widget.Spinner;
    import android.widget.TextView;

    public class Main extends Activity {
      Spinner	operationSpinner;
      TextView  result;
      Button    getResult;

      private enum OperationType
      {
        Addition, Subtraction
      }

      @Override
      public void onCreate(final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        this.setContentView(R.layout.main);

        final EditText txtfirstNumber = (EditText) this.findViewById(R.id.txtFirstNumber);
        final EditText txtsecondNumber = (EditText) this.findViewById(R.id.txtSecondNumber);

        this.result = (TextView) this.findViewById(R.id.resultText);
        this.result.setText("0.00");

        this.getResult = (Button) this.findViewById(R.id.btnGetResult);

        this.operationSpinner = (Spinner) this.findViewById(R.id.operationSpinner);

        // Adding listener to get result button
        this.getResult.setOnClickListener(new View.OnClickListener() {

          public void onClick(final View v) {
            OperationType operationType = OperationType.valueOf(Main.this.operationSpinner.getSelectedItem().toString());

            final float num1 = Float.parseFloat(txtfirstNumber.getText().toString());
            final float num2 = Float.parseFloat(txtsecondNumber.getText().toString());

        // Getting first & second values and passing to show result
            Main.this.showResult(num1,num2 ,operationType);
          }
        });
      }

      // Showing operation results
      protected void showResult(final float firstNumber, final float secondNumber, final OperationType type) {

        float resultVal = 0;
        if (type.equals(OperationType.Addition)) {
          resultVal = firstNumber + secondNumber;
        } else if (type.equals(OperationType.Subtraction)) {
          resultVal = firstNumber - secondNumber;
        }

        String operationResult = String.valueOf(resultVal);
        this.result.setText(operationResult);
      }
    }
    ```

1.  在`main.xml`布局文件中使用以下代码：

    ```kt
    <?xml version="1.0" encoding="utf-8"?>
    <LinearLayout android:orientation="vertical"android:layout_width=" match_parent"android:layout_height=" match_parent">

    <TextViewandroid:layout_width=" match_parent" android:layout_height="wrap_content" android:text="@string/hello"/>

    <TextView android:layout_width="wrap_content" 
      android:layout_height="wrap_content" 
      android:text="@string/txtSpace"/>

    <TextView android:layout_width="wrap_content" 
      android:layout_height="wrap_content" 
      android:text="@string/txtFirstNumber"/>

    <EditTextandroid:inputType="numberDecimal"
      android:id="@+id/txtFirstNumber" 
      android:layout_width=" match_parent" 
      android:layout_height="wrap_content"/>

    <TextViewandroid:layout_width="wrap_content"
      android:layout_height="wrap_content" 
      android:text="@string/txtSpace"/>

    <TextViewandroid:layout_width="wrap_content" 
      android:layout_height="wrap_content" 
      android:text="@string/txtSecondNumber"/>

    <EditTextandroid:inputType="numberDecimal"
      android:id="@+id/txtSecondNumber" 
      android:layout_width=" match_parent" 
      android:layout_height="wrap_content"/>

    <Spinnerandroid:id="@+id/operationSpinner"
      android:layout_width="match_parent"
      android:layout_height="wrap_content" 
      android:entries="@array/spinnerItems"/>

    <TextViewandroid:layout_width="wrap_content" 
      android:layout_height="wrap_content" 
      android:text="@string/txtSpace"/>

    <Buttonandroid:text="@string/btnResultString"
      android:id="@+id/btnGetResult" 
      android:layout_width=" match_parent" 
      android:layout_height="wrap_content"/>

    <TextViewandroid:layout_width="wrap_content" 
      android:layout_height="wrap_content" 
      android:text="@string/txtSpace"/>

    <TextViewandroid:id="@+id/resultText" 
      android:layout_width="wrap_content" 
      android:layout_height="wrap_content"/>

    <TextViewandroid:layout_width="wrap_content"
      android:layout_height="wrap_content" 
      android:text="@string/txtSpace"/>

    </LinearLayout>
    ```

1.  使用以下条目更新`String.xml`文件：

    ```kt
    <string name="hello">Enter any two numbers and select operation and get the result</string>
    <string name="app_name">ZCalculator</string>
    <string name="txtFirstNumber">First Number</string>
    <string name="txtSecondNumber">Second Number</string>
    <string name="btnResultString">Get Result</string>
    ```

1.  使用以下条目更新`array.xml`文件：

    ```kt
      <string-array name="spinnerItems">
        <item>Addition</item>
        <item>Subtraction</item>
      </string-array>
    ```

1.  同时，使用以下活动动作和启动器条目更新`AndroidManifest.xml`文件：

    ```kt
    <uses-sdk android:minSdkVersion="8"/>

    <application android:icon="@drawable/ic_launcher" android:label="@string/app_name">
      <activity android:name="com.zcalculator.Main"android:label="@string/app_name">
        <intent-filter>
          <action android:name="android.intent.action.MAIN" />
          <category android:name="android.intent.category.LAUNCHER" />
        </intent-filter>
      </activity>
    </application>
    ```

# 创建一个测试项目

让我们继续创建一个测试项目，以测试 ZCalculator 应用。

在 Eclipse 中，转到**新建**，从**选择**向导中选择**Android 测试项目**。输入适当的项目名称，然后点击**下一步**按钮。建议测试项目名称遵循如“Test + AUT 名称”的命名约定。这就是为什么这个测试应用被命名为`TestZCalculator`，如下截图所示：

![创建测试项目](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_02_08.jpg)

然后，选择 AUT 或目标项目（在我们的例子中是 ZCalculator），如以下截图所示，然后点击**完成**按钮：

![创建测试项目](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_02_09.jpg)

选择一个构建目标，如下截图所示（要定位的 SDK），然后点击**完成**按钮：

![创建测试项目](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_02_10.jpg)

你的测试项目已成功创建。现在我们来创建一个测试用例类以测试 ZCalculator 的主类。

# 创建测试用例

要创建测试用例，请按照列出的步骤操作：

1.  要创建测试用例，请在**包资源管理器**窗口中右键点击`com.calculator.test`包，并导航到**新建** | **JUnit 测试用例**，如下截图所示。如果该包不存在，请在**src**分支下创建它：![创建测试用例](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_02_11.jpg)

1.  在**新建 JUnit 测试用例**窗口中，大多数字段已自动填充。只需将测试用例的名称指定为`MainTest`，因为我们将要测试 ZCalculator 中的`Main`类。在方法存根部分保持**setUp()**，**tearDown()**和**构造函数**选项复选框被选中，然后点击**完成**按钮。

    ### 注意

    `setUp()`和`tearDown()`方法属于`junit.framework.TestCase`类的一部分。`setUp()`方法用于初始化运行测试所需的数据并重置环境变量。`tearDown()`方法用于调用垃圾回收以强制恢复内存。它在每个`@Test`方法之后调用，如下代码所示：

    ```kt
    Call @Before setUp
    Call @Test method test1
    Call @After tearDown
    Call @Before setUp
    Call @Test method test2
    Call @After tearDown
    ```

    ![创建测试用例](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_02_12.jpg)

1.  完成后，将在`com.calculator.test`包下创建一个测试用例`MainTest.java`，如下截图所示。同时，在`MainTest`类中会自动生成三个存根方法：![创建测试用例](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_02_13.jpg)

# 添加 Robotium 库

所有版本的 Robotium JAR 文件都可以从[`code.google.com/p/robotium/downloads/list`](https://code.google.com/p/robotium/downloads/list)下载。

可以按照列出的步骤添加 Robotium 库：

1.  你需要将 Robotium JAR 作为引用库添加到测试项目中。要引用它，请右键点击你的项目，并导航到**构建路径** | **配置构建路径**，如下截图所示：![添加 Robotium 库](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_02_14.jpg)

1.  在**Java 构建路径**面板中，转到**库**标签页，并点击如下截图所示的**添加外部 JARs…**按钮。然后，提供一个正确的 Robotium 库（最好是最新版本），并将其添加到列表中。实现这一点的另一种方式是将 JAR 文件复制到测试的`lib`目录中：![添加 Robotium 库](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_02_15.jpg)

1.  通常在最新的 SDK 版本中（主要是 API 17 及以上版本）会遇到**java.lang.NoClassDefFoundError: com.jayway.android.robotium.solo.Solo**错误，这是因为没有导出 Robotium JAR 文件。因此，要导出它，请转到**Java 构建路径**部分的**顺序和导出**标签，并在列表中选中 Robotium JAR 文件，如下截图所示，然后点击**确定**按钮：

    ### 注意

    确保已选中 Android 私有库，否则测试将无法启动。

    ![添加 Robotium 库](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_02_16.jpg)

# 在 AndroidManifest.xml 中添加包名

一旦为测试项目提供了 Robotium 库的引用，打开`AndroidManifest.xml`文件，并更改目标包名，如下所示：

```kt
<instrumentation android:targetPackage="com.calculator" android:name="android.test.InstrumentationTestRunner" />
```

下面的截图显示了`AndroidManifest.xml`文件中的上述更改：

![在 AndroidManifest.xml 中添加包名](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_02_17.jpg)

# Robotium 的测试用例代码

在深入实际代码之前，你应该熟悉 Robotium 框架的一些类和方法。

`Solo`是 Robotium 用于测试的类。它使用测试用例的 instrumentation 和第一个要测试的活动进行初始化。这将在`setUp()`方法中执行。`Solo`类提供了易于调用 Android 用户界面组件的 API，例如，`enterText()` API 将文本放入 EditText 视图中。我们将在以下部分看到大多数这些 API。

JUnit 中的测试用例方法名称应以单词"test"开头。由于 Robotium 基于 JUnit 构建，我们为测试用例提供了`testZCalculatorBlackBox()`方法。你可以在一个测试用例类中添加任意数量的测试用例方法。

在以下测试用例中，我们将访问 ZCalculator 的用户界面组件，并按顺序执行以下操作：

1.  访问用于输入（第一个和第二个数字）的**编辑文本**字段。

1.  输入任意值。

1.  访问并点击**Spinner**以选择操作。

1.  访问并点击**获取结果**按钮。

将以下代码放入`MainTest.java`文件并保存：

```kt
package com.zcalculator.test;

import android.test.ActivityInstrumentationTestCase2;
import com.jayway.android.robotium.solo.Solo;
import com.zcalculator.Main;

public class MainTest extends ActivityInstrumentationTestCase2<Main> {
  private Solo	solo;

  public MainTest() {
    super(Main.class);
  }

  @Override
  protected void setUp() throws Exception {
    super.setUp();
    this.solo = new Solo(this.getInstrumentation(), this.getActivity());
  }

  public void testZCalculatorBlackBox() {

    // Enter 5 in first number field
    this.solo.enterText(0, "5");

    // Enter 4 in second number field
    this.solo.enterText(1, "4");

    // Press Addition Spinner Item
    this.solo.pressSpinnerItem(0, 0);

    // Click on get result button
    this.solo.clickOnButton(0);

    // Verify that resultant of 5 + 4
    assertTrue(this.solo.searchText("9"));

    // Press Subtraction Spinner Item
    this.solo.pressSpinnerItem(0, 1);

    // Click on get result button
    this.solo.clickOnButton(0);

    // Verify that resultant of 5 - 4
    assertTrue(this.solo.searchText("1"));
  }
  @Override
  protected void tearDown() throws Exception {
    this.solo.finishOpenedActivities();
  }
}
```

# 运行测试用例

我们现在已经完成了为 ZCalculator 创建带有有效测试用例的测试项目。是时候运行我们的测试用例了。

在测试项目或测试用例文件`MainTest.java`上右键点击，选择**作为 Android JUnit 测试运行**。在选择设备屏幕上选择**Android 模拟器**。

### 注意

如果你想要运行特定的测试用例，请右键点击文件，然后选择**作为 Android JUnit 测试运行**。要运行测试项目中可用的所有测试用例，请右键点击项目本身，然后选择**作为 Android JUnit 测试运行**，它将运行所有测试用例。

Robotium 针对 ZCalculator 的测试用例将按以下方式工作：

1.  ZCalculator 应用程序将被加载。

1.  第一个和第二个数字将自动输入到第一个和第二个**编辑文本**字段中，然后点击下拉菜单选择操作（首先选择加法）。

1.  将点击**获取结果**按钮，并在结果文本视图中显示结果。

1.  断言语句将检查有效的操作结果。这个过程将继续针对减法进行，如果每个断言都为真，则测试用例通过，在 JUnit 标签中用绿色条表示，如下面的屏幕截图所示：![运行测试用例](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_02_18.jpg)

如果你想通过命令行运行测试项目，必须先安装应用程序和仪器。如果它们已经安装好了，那么使用以下命令：

```kt
adb shell am instrument-w com.calculator.test/android.test.InstrumentationTestRunner

```

在运行上述命令之前，请注意，你应该在包含`adb.exe`的目录下运行它，或者将`adb.exe`的路径添加到环境路径变量列表中，以便在系统的任何位置访问它。

你可以在 Android SDK 中的`platform-tools`文件夹里找到`adb`。

# 总结

在本章中，我们学习了如何使用 Robotium 框架创建测试项目。到目前为止，你已经了解了使用 Robotium 创建简单测试应用程序所需的基本流程。现在是深入框架，了解不同的 Robotium API 调用及其使用方法的时候了。在下一章中，你将了解到`Solo`类及其内部 API 的相关信息。


# 第三章：Robotium APIs

本章将向你介绍`Solo`类以及框架中存在的 API 信息。完成这部分后，我们将考虑资源 ID 测试用例，它简要介绍了如何使用 Robotium 实现国际化。

在本章结束时，你将了解到框架中和测试用例评估的大部分 API。

# Solo

`Solo`类是 Robotium 框架提供的一个主要类，它包含了编写项目测试用例的 API。Robotium 可以与 Android 测试类结合使用，例如`ActivityInstrumentationTestCase2`和`SingleLaunchActivityTestCase`。

`Solo`类有两个构造函数：

+   `Solo (android.app.Instrumentation instrumentation)`: 这个构造函数接收 instrumentation 作为参数

+   `Solo(android.app.Instrumentation instrumentation, android.app.Activity activity)`: 这个构造函数接收 instrumentation 和 activity 作为参数

# API 调用

Robotium 框架内部有许多 API，它们涵盖了 Android 中大部分可用的功能。随着用户反馈和建议的增加，方法数量也在增加。如果任何在测试项目中工作的 Robotium 测试用例开发者发现，有些方法（指的是某个特别有用的功能）可以作为 Robotium 框架的一部分添加，那么这将有助于他们在各自的项目中。

![API 调用](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_03_01.jpg)

Robotium 开发团队会根据优先级分析这些新需求。其中一些会被实施，并作为下一个版本的一部分添加/删除。如果下一个版本中停止支持任何 API，更新你的测试项目 Robotium 库可能会遇到麻烦。

所有这些方法都可以在以下链接中找到：

[`robotium.googlecode.com/svn/doc/com/jayway/android/robotium/solo/Solo.html`](http://robotium.googlecode.com/svn/doc/com/jayway/android/robotium/solo/Solo.html)

[`robotium.googlecode.com/svn/doc/com/jayway/android/robotium/solo/Solo.html`](http://robotium.googlecode.com/svn/doc/com/jayway/android/robotium/solo/Solo.html)

你可以研究 API 集的 Javadoc，也可以浏览在以下链接中可用的源代码

[`github.com/jayway/robotium/tree/master/robotium-solo`](https://github.com/jayway/robotium/tree/master/robotium-solo)

下图展示了 Robotium 的简要信息，包括总的提交数、代码行数、项目模型和技术栈：

![API 调用](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_03_02.jpg)

来自 ohloh.net 的快照

# Robotium 中的资源 ID

在 Robotium 中，你无需将**被测应用**（**AUT**）的资源导入到测试项目中，就可以使用资源 ID。

![Robotium 中的资源 ID](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_03_03.jpg)

你可以不导入资源文件夹就做到这一点。你需要做的是通过向`getIdentifier()`方法传递视图的名称和类型来获取资源 ID，然后将获得的 ID 传递给`getView()`方法以获取相应的视图对象。

```kt
Activity activity = solo.getCurrentActivity();

ImageView imageView = (ImageView) solo.getView(act.getResources().getIdentifier("appicon", "id", act.getPackageName()));
```

它同样适用于字符串参数；例如：

```kt
Solo.getView("com.robotium.R.id.icon");
```

# 理解国际化

![理解国际化](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_03_04.jpg)

你可能想知道国际化是什么。其实，它是将应用程序适应到各种语言或地区的方法。这可能会与本地化的概念混淆，但这两个概念略有不同。本地化意味着将应用程序适应到任何地区或语言，因此使用地区组件并翻译文本。

考虑一个可能有多语言支持的应用程序。如果你想测试这个应用程序，你不能将任何语言的文本硬编码为测试用例的一部分。为了概括这一点，建议你应在`res/values/strings.xml`文件中添加字符串。

让我们通过以下简单示例来看看如何实现国际化测试用例。

应用程序包含一个**Connect**切换按钮，点击后会切换到**Disconnect**按钮。它下面是一个 TextView，显示应用程序生成的所有连接日志。UI 看起来如下截图所示：

![理解国际化](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_03_05.jpg)

一旦点击了连接按钮，**Successful**就会显示在它下方的 TextView 中。

我们可以使用`res/values/string.xml`文件中指定的值来国际化切换按钮中的文本，而不是为切换按钮中的文本添加任何硬编码值，如下所示：

```kt
<ToggleButton
  android:id="@+id/toggleConnection"android:layout_width="fill_parent"android:layout_height="wrap_content"android:layout_marginTop="50dp"android:textOn="@string/on"android:checked="true"android:textOff="@string/off"/>

<TextView
  android:id="@+id/tvConnectionLogs"android:layout_width="fill_parent"android:layout_height="wrap_content"android:maxLines="5"android:test="@string/connection_logs"android:layout_marginTop="120dip"/>
```

`string.xml`文件中指定的值如下：

```kt
  <string name="on">Connect</string>
  <string name="off">Disconnect</string>
  <string name="connection_logs">Successful</string>
```

以下是测试项目`TestInterApp`的代码，该项目有一个名为`testInterAppBlackBox`的测试用例，点击**Connect**按钮并将其切换到**Disconnect**按钮。然后它在切换按钮下方的连接日志 TextView 中搜索**Successful**文本。

```kt
package com.android.testinterapp;

import android.app.Activity;
import android.test.ActivityInstrumentationTestCase2;

import com.android.interapp.MainActivity;
import com.jayway.android.robotium.solo.Solo;

public class TestInterApp extends ActivityInstrumentationTestCase2<MainActivity> {
  private Solo  solo;

  public TestInterApp() {
    super(MainActivity.class);
  }

  @Override
  protected void setUp() throws Exception {
    super.setUp();
    this.solo = new Solo(this.getInstrumentation(), this.getActivity());
  }

  public void testInterAppBlackBox() {

    // Gets the activity object from solo class using
    // method getCurrentActivity()
    Activity activity = solo.getCurrentActivity();

    // Gets the resource ID using the resource name and type passed
    // in the getIdentifier method
    int connectOnId = activity.getResources().getIdentifier("on", "string", activity.getPackageName());

    // Gets the string by using the resource id in the earlier step
    String connect = activity.getResources().getString(connectOnId);

    this.solo.clickOnToggleButton(connect);

    // Similarly for the text view field, get the resource ID using the resource name and type passed in the getIdentifier method
    int connectionLogId = activity.getResources().getIdentifier("connection_logs", "string", activity.getPackageName());

    // Gets the string by using the resource id in the earlier step
    String connectionLogText = activity.getResources().getString(connectionLogId);

    assertTrue(this.solo.searchText(connectionLogText));

  }

  @Override
  protected void tearDown() throws Exception {
    this.solo.finishOpenedActivities();
  }
}
```

以下截图显示了在 Junit 控制台中测试用例的结果：

![理解国际化](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_03_06.jpg)

测试用例及结果

由于国际化的影响，如果任何用户希望按地区更改语言，则无需修改 Robotium 测试用例。只需在`string.xml`文件中的地区语言内部更改变量值，测试用例将为所有地区和语言工作。

# 总结

在本章中，我们已经看到了大多数 Robotium API 调用及其描述，以及如何在 Robotium 中使用国际化。在下一章中，你将学习如何使用 Robotium 访问 Android 应用程序中 web 视图的不同 web 元素。


# 第四章：Robotium 中的 Web 支持

本章将简要介绍如何使用 Robotium 的 Web 支持在 Android 中访问 WebElements。我们将在本章的前部分看到这些方法，并继续一个简单的测试混合应用程序的示例。

# API 集

自 Robotium 4.0 发布以来，Robotium 框架已添加 Web 支持。Robotium 完全支持混合应用程序。本地应用程序和混合应用程序之间存在一些关键差异。让我们逐一了解它们：

| 本地应用程序 | 混合应用程序 |
| --- | --- |
| 平台相关 | 跨平台 |
| 在设备的内部软件和硬件上运行 | 使用 HTML5 和 JavaScript 构建，并封装在一个薄本地容器中，提供对本地平台功能的访问 |
| 需要更多开发人员在不同的平台上构建应用程序，学习时间更长 | 节省开发成本和时间 |
| 优秀的性能 | 较低的性能 |

本地和混合应用程序如下所示：

![API 集](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_04_01.jpg)

让我们看看 Robotium 中一些支持访问 Web 内容的方法。它们如下：

+   `searchText (String text)`

+   `scrollUp/Down()`

+   `clickOnText (String text)`

+   `takeScreenshot()`

+   `waitForText (String text)`

在专门为 Web 支持添加的方法中，`By`类被用作参数。它是一个抽象类，与 Web 方法结合使用。这些方法用于根据属性（如 ID 和名称）选择不同的 WebElements。

在 web 视图中使用的元素称为 WebElement。它与 Selenium 中实现的 WebDriver 相似。以下表格列出了`By`类中的所有方法：

| 方法 | 描述 |
| --- | --- |
| `className (String className)` | 通过其类名选择 WebElement |
| `cssSelector (String selectors)` | 通过其 CSS 选择器选择 WebElement |
| `getValue()` | 返回值 |
| `id (String id)` | 通过其 id 选择 WebElement |
| `name (String name)` | 通过其名称选择 WebElement |
| `tagName (String tagName)` | 通过其标签名选择 WebElement |
| `textContent (String textContent)` | 通过其文本内容选择 WebElement |
| `xpath (String xpath)` | 通过其 xpath 选择 WebElement |

Robotium 框架中一些重要的方法，旨在与 Android 应用程序中的 Web 内容直接通信，如下所示：

+   `clickOnWebElement(By by)`: 点击匹配指定`By`类对象的 WebElement。

+   `waitForWebElement(By by)`: 等待匹配指定`By`类对象的 WebElement。

+   `getWebElement(By by, int index)`: 返回匹配指定`By`类对象和索引的 WebElement。

+   `enterTextInWebElement(By by, String text)`: 该方法用于在匹配指定`By`类对象的 WebElement 中输入文本。

+   `typeTextInWebElement(By by)`: 它在匹配指定 `By` 类对象的 WebElement 中输入文本。在此方法中，程序实际上通过键盘逐个字母输入文本，而 `enterTextInWebElement` 直接在特定位置输入文本。

+   `clearTextInWebElement(By by)`: 它清除与指定 `By` 类对象匹配的 WebElement 中的文本。

+   `getCurrentWebElements(By by)`: 它返回与指定的 `By` 类对象匹配的、在活动 web 视图中显示的 WebElements 的 `ArrayList`。

在实际查看混合测试示例之前，让我们获取更多关于 `WebViews` 的信息。

您可以使用以下方式通过 `Solo` 类获取 `WebView` 的实例：

```kt
WebView wb = solo.getCurrentViews(WebView.class).get(0);
```

现在您控制了 `WebView`，可以如下注入您的 JavaScript 代码：

```kt
Wb.loadUrl("<JavaScript>");
```

这非常强大，因为我们可以调用当前页面上的每个函数；因此，它有助于自动化。

# 混合测试示例

让我们看看一个混合应用程序，即被测应用程序，并创建一个简单的测试项目来测试这个应用程序。

该应用程序在其布局中提供了一个 `WebView` 控件，并在其中加载了谷歌主页（如下面的截图所示）。在编写测试用例之前，您可以查看应用程序的源代码：

![混合测试示例](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_04_02.jpg)

`WebViewActivity.java` 文件的源代码如下：

```kt
public class WebViewActivity extends Activity {

  @Override
  public void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.web_main);

    WebView webView = (WebView) findViewById(R.id.mainWebView);

    WebSettings webSettings = webView.getSettings();
    webSettings.setJavaScriptEnabled(true);

    webView.setWebViewClient(new CustomWebViewClient());
    webView.setScrollBarStyle(View.SCROLLBARS_INSIDE_OVERLAY);

    webView.loadUrl("http://www.google.co.in");
  }

  private class CustomWebViewClient extends WebViewClient {
    @Override
    public boolean shouldOverrideUrlLoading(WebView view, String url)     {
      view.loadUrl(url);
      return true;
    }
  }
}
```

在您的 `web_main.xml` 布局文件中添加以下代码：

```kt
<WebView android:layout_width="match_parent" android:layout_height="match_parent" android:id="@+id/mainWebView">
</WebView>
```

如果您在 `AndroidManifest.xml` 中没有指定任何权限，请提供以下权限：

```kt
<uses-permission android:name="android.permission.INTERNET" />
```

这将使用 `WebView` 设置您的应用程序。现在，让我们编写一个测试用例，访问谷歌主页的一些 WebElements ，`WebView`，并提供结果。

在您的混合测试项目中使用以下代码作为谷歌搜索测试用例：

```kt
  // A test that searches for Robotium and asserts 
  // that Robotium is found.

public void testSearchRobotium()
{

  // Since Google's search form input box statement utilizes
  // a "q" in the name="q" parameter
  final By inputSearch = By.name("q");

  // Google search button utilizes "tsbb" in 
  // the id="tsbb" parameter
  final By buttonSearch = By.id("tsbb");

  // Wait for a WebElement without scrolling.
  this.solo.waitForWebElement(inputSearch);

  // Types Robotium in the search input field.
  this.solo.typeTextInWebElement(inputSearch, "Robotium");

  //Assert that Robotium is entered in the input field.
  assertTrue("Robotium has not been typed", solo.getWebElement(inputSearch, 0).getText().contains("Robotium"));

  // Clicks on the search button 
  this.solo.clickOnWebElement(buttonSearch);

  // Waits for the results page for Robotium
  solo.waitForText("Results");

  // Takes the screenshot of the current active screen
  solo.takeScreenshot();

}
```

上述代码在谷歌搜索框中输入文本 `Robotium` 并点击搜索按钮。它断言输入搜索栏中是否找不到单词 `Robotium`。如果存在，程序将点击搜索按钮并显示结果页面。

然后它等待测试结果，并如下截图：

![混合测试示例](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_04_03.jpg)

该截图通过 API 保存在 `/sdcard/Robotium-Screenshots/` 目录中。它需要被测应用程序的 `AndroidManifest.xml` 文件中的写入权限 (`android.permission.WRITE_EXTERNAL_STORAGE`)。

这个结果可以在 JUnit 视图中查看。当测试项目作为 Android JUnit 测试执行时，会自动启动此视图。您可以查看以下截图以了解运行测试项目的流程。

右键点击测试项目，选择 **运行方式** 然后点击 **2 Android JUnit 测试**：

![混合测试示例](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_04_04.jpg)

`testSearchRobotium` 测试用例已通过，如下面的截图所示，由绿色条指示。完成测试大约需要 66.1062 秒：

![混合测试示例](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_04_05.jpg)

# 概括

在本章中，我们学习了如何测试混合应用程序以及访问 WebElement 的不同 API。借助 Robotium 对 web 视图的支持，我们基本上可以测试移动网页。这种方式，我们模拟了使用原生浏览器打开移动网页的相同条件，因为原生浏览器中的标签包含 WebView。

在下一章中，我们将比较 Robotium 框架与其他测试框架，并了解一些有趣的事实。


# 第五章：与其他框架的比较

本章节将根据某些参数对 Robotium 与其他测试框架进行比较。这将为你提供一个根据项目需求选择合适框架的方法。在本章中，我们将比较 Robotium 与 MonkeyRunner、Robolectric、UI Automator 和 Calabash 框架。

# MonkeyRunner

**MonkeyRunner** 是一个用于编写可以从 Android 代码外部访问 Android 模拟器/设备的程序的工具。编写 Python 程序来安装 Android 测试应用并向应用发送按键。该程序获取 Android UI 的截图并将其发送到工作站以存储。

MonkeyRunner 是一个 API，不是一个程序。它使用 **Jython**（Python 的一种实现）, 该实现使用 Java 编程语言。

由于 MonkeyRunner 是 Python 的一个模块，你可以执行任何 Python 支持的操作。你需要做的就是创建一个 Python 程序，加入 MonkeyRunner，就完成了！

让我们看看下表中 Robotium 与 MonkeyRunner 的区别：

| 功能 | Robotium | MonkeyRunner |
| --- | --- | --- |
| 对象选择 | 对象选择基于诸如索引、文本/名称、图像和 ID 等属性。 | 对象选择基于其位置（x, y 坐标），当应用程序发展时可能会改变。很可能无法使用触摸事件，因为未提供确切位置。 |
| 动作 | 它只能在测试应用上执行动作。 | 它可以在整个设备上点击，即所有应用都可以。 |
| 断言 | 基于 JUnit。断言（验证）时会显示红/绿条。 | 基于截图的验证。 |
| 语言 | Java。 | Python 脚本。 |
| 安装 | Robotium JAR 可以导入 Eclipse 插件内，并将测试用例作为`.apk`文件执行。 | 要使用 MonkeyRunner，请运行 `<android sdk>/tools/` 中的 `monkeyrunner` 工具，并将要作为测试用例使用的文件名传递。它不会在模拟器/设备内安装任何程序。 |

这两个框架有一些共同点。它们可以在模拟器/设备上运行，并通过从工作站发送特定命令和事件来控制设备/模拟器。

在 Android 测试领域，针对不同的需求有各种不同的框架。由于 Robotium 主要用于 UI 测试，因此它不支持 MonkeyRunner 以下的一些功能：

+   可扩展自动化

+   多应用和设备控制

# Robolectric

**Robolectric** 是一个测试框架，它模拟了 Android 框架的一部分，并允许在 JUnit 4 框架的帮助下直接在**Java 虚拟机**（**JVM**）上运行测试用例。关于 Robolectric 最重要的是，它不需要模拟器/设备。

![Robolectric](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_05_01.jpg)

Robolectric 包含浅层的 Android 对象，这些对象的行为类似于 Android SDK 中存在的对象。

让我们通过下表了解 Robotium 和 Robolectric 之间的区别：

| 功能 | Robotium | Robolectric |
| --- | --- | --- |
| 模拟器/设备 | Robotium 需要模拟器或设备来执行测试。 | Robolectric 不需要任何模拟器/设备来执行测试。这就是它比 Robotium 快得多的原因。 |
| 构建服务器 | 它需要在构建服务器上有一个模拟器或设备来运行测试用例；否则，测试项目无法添加到构建过程中。 | 它可以轻松地在构建服务器上配置。 |
| 测试驱动开发 | 它用于在实际的 Android 设备上测试，以及测试 Robolectric 无法模拟的 API 边缘情况。 | 它比 Robotium 更能加快测试驱动开发周期的速度。 |
| 测试工具 | 它使用 JUnit 3 的仪器化测试。 | 它使用 JUnit 4 的非仪器化测试。 |

# UI Automator

UI Automator 是一个 Java 库，用于创建针对 Android 应用程序的自定义 UI 测试用例，并提供一个执行引擎来自动化和运行测试用例。

让我们通过下表了解 Robotium 和 UI Automator 之间的区别：

| 功能 | Robotium | UI Automator |
| --- | --- | --- |
| 跨应用包 | Robotium 无法跨越应用包边界。 | UI Automator 可以跨越应用包边界。例如，如果你的应用打开图库并点击任何相册，这可以通过使用 UI Automator 实现。图库是另一个应用包，而在图库内部点击相册是跨应用的操作。 |
| API 集合 | Robotium 拥有庞大的 API 集合，包含点击视图、获取视图等方法。因此，Robotium 比 UI Automator 提供了更多的测试控制。 | UI Automator 包含点击和获取视图的方法，但对这些视图的访问实现不同。 |
| API 级别支持 | Robotium 支持 API 级别 4 及以上。 | UI Automator 仅支持 API 级别 16（或更高）的设备，并且不支持更旧的 API 级别，因此不具备向后兼容性。 |
| 集成开发环境 | Robotium 与 Eclipse IDE 平滑集成。 | UI Automator 与 IDE 的集成比较繁琐，因为你需要手动添加 JUnit 库与`Android.jar`和`uiautomator.jar`，并使用 Ant 构建。 |
| 网页支持 | Robotium 完全支持应用程序中的 Web 元素。 | UI Automator 缺少这一功能。 |

# Calabash

Calabash 是一个跨平台工具，可让你为移动应用程序编写自动化功能验收测试，支持 Android 和 iOS 原生应用。

让我们通过下表了解 Robotium 和 Calabash 之间的区别：

| 功能 | Robotium | Calabash |
| --- | --- | --- |
| 编程语言 | Robotium 的测试用例用 Java 编写 | 你不需要用 Java 编写测试，可以使用更灵活的**Ruby**语言，这更适合 |
| 控制方式 | Robotium 测试需要从设备上进行控制 | Calabash 测试可以从计算机而非设备上进行控制 |
| 旋转功能 | Robotium 可以将设备方向设置为横屏或竖屏 | Calabash-Android 不能模拟手机旋转到横屏或竖屏 |

那么，哪个更好？Robotium 还是 Calabash？我认为两者都不错。它们仍在不断改进，并且会有更多版本发布。

当以上两种方法都无法满足你的需求时，你总是可以使用`android.test.ActivityInstrumentationTestCase2`类。

如我们所讨论的，每个框架都有其优缺点，并适用于自动化测试人员的不同需求。从前面的比较中我们可以看出，Robotium 和 Calabash 相当受欢迎，并且在自动化 UI 测试中一路领先。

# 总结

在本章中，我们根据不同的因素将 Robotium 与不同的测试框架进行了比较，并得出结论：所有框架都是根据不同的需求来使用的。没有完美的框架，总会有一些优缺点与之相关联。

在下一章中，我们将探讨 Robotium 中的远程控制功能及其使用方法。


# 第六章：Robotium 中的远程控制

本章将向您介绍软件自动化框架支持以及 Android 中远程控制的工作原理。它有助于测试 Android 设备与远程客户端通过 TCP 信使服务的连接。在本章结束时，您将了解远程控制与没有互联网权限的测试 APK 结合使用的内部机制，以及它如何通过 Android 套接字服务连接到远程客户端。

# 软件自动化框架支持

**软件自动化框架支持（SAFS）**的主要功能是，将 Robotium 完全集成到 Android 测试中，并与大量使用不同技术的用户一起使用 SAFS。

在 Android 中，不支持套接字、UDP 和 RMI。因此，如果 AUT 没有以下权限，测试应用程序不应具有访问 TCP 套接字的权限：

```kt
<uses-permission android:name="android.permission.INTERNET"/>
```

引入远程控制的原因是，在 Android 中有一个使用套接字服务的通用方法，这种方法完全独立于测试应用程序和 AUT。

让我们看看使用 SAFS 的远程控制是如何工作的。

# Android 远程控制的工作原理

![Android 远程控制的工作原理](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_06_01.jpg)

Android 远程控制的工作原理可以通过以下步骤来定义：

1.  用户在设备/模拟器上安装套接字服务。这个套接字服务拥有完全的互联网权限。远程进程使用 TCP 消息交换协议发送/接收命令，并与已安装的套接字服务共享结果。

1.  为 AUT 编写的测试应用程序包含用于绑定到此套接字服务的代码。这个测试应用程序不需要任何互联网权限，可以依赖套接字服务提供数据结果。![Android 远程控制的工作原理](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_06_02.jpg)

    TCP 信使服务（套接字服务）充当远程测试控制器（Windows、Linux、Mac 等）与通过 TCP 套接字通信的 Android 测试包之间的中介。它期望进行双向通信，以接收命令和返回测试数据/结果。由于这项服务，没有互联网权限的测试包可以通过 TCP 套接字进行控制。

1.  测试应用程序从套接字服务接收命令，执行测试，并返回测试控制器所需的数据和状态。

被测试的应用不应当在测试应用中硬编码。通过更新 `AndroidManifest.xml` 文件中的 `android:targetPackage` 属性，可以轻松地实现自动化，而无需开发者/测试者的代码。因此，在预测试运行时，可以提取目标 APK 的信息，并使用更新后的 `AndroidManifest.xml` 文件为目标包重新打包其他未修改的测试应用 APK。在运行时，测试 APK 可以通过 `PackageManager`、`PackageInfo` 和 `ApplicationInfo` 调用来识别目标包和要启动的初始活动。

Robotium 远程控制帮助测试用例从 JVM 执行，这使得 Robotium 能够与 JUnit 4 等 JVM 框架一起工作。对于远程控制，另一个 `Solo` 类位于 `com.jayway.android.robotium.remotecontrol.solo`。它为嵌入的传统 Robotium `Solo` 类提供远程控制 API。

由于远程控制 `Solo` 类在设备/模拟器外部运行，即在 JUnit 测试的上下文中，它无法访问 **被测应用**（**AUT**）的对象。它在测试失败时不会中止或停止。你可以通过以下来源查看为其提供的方法和信息：

[`safsdev.sourceforge.net/doc/com/jayway/android/robotium/remotecontrol/solo/Solo.html`](http://safsdev.sourceforge.net/doc/com/jayway/android/robotium/remotecontrol/solo/Solo.html)

它使用 Android 的 TCP Messenger 服务。你可以从以下 URL 下载用于 Robotium 安卓测试的 Robotium 远程控制版本：

[`sourceforge.net/projects/safsdev/files/RobotiumRemoteControl/`](http://sourceforge.net/projects/safsdev/files/RobotiumRemoteControl/)

你可以从以下 URL 获取最新的 SAFS 下载：

[`sourceforge.net/projects/safsdev/files/latest/download`](http://sourceforge.net/projects/safsdev/files/latest/download)

下载 Robotium 远程控制后，你会发现已经安装了 `SoloRemoteControl` 项目。它应该作为你自己的 Java 开发项目的参考。`SoloRemoteControl` 项目中的 `src` 文件夹包含了 `robotium-remotecontrol.jar` 文件中的所有源代码。

# 使用 SAFS 的 Robotium 远程控制

SAFS 测试没有作为 JUnit 测试进行封装，Robotium 的 SAFS 远程控制使用了一种非基于 JUnit 的实现。此外，在远程控制测试端没有技术要求使用 JUnit。

可以使用 SDK 工具实现目标应用的自动化测试设置和部署。这些工具作为测试运行时的一部分，例如 adb 和 aapt。现有的打包工具可以用来使用替代的 `AndroidManifest.xml` 文件重新打包编译后的 Robotium 测试，从而在运行时更改目标应用。

SAFS 是一个通用、数据驱动的框架。用户唯一需要提供的是目标包名称或 APK 路径参数。测试将自动提取和重新部署修改后的包，然后启动实际的测试。

传统的 JUnit/Robotium 用户可能没有，或认为不需要这种通用性质，但这很可能是由于之前的 Android 测试必须是 JUnit 测试。测试需要针对一个特定的应用。远程控制应用是特定于应用程序的。这就是为什么在设备中安装了远程控制的测试应用不再需要是一个应用。

Robotium 中的远程控制意味着对于任何给定的测试，都需要构建两个测试应用。它们如下：

+   传统设备上的 Robotium/JUnit 测试应用

+   远程控制应用

这两个构建项目具有完全不同的依赖项和构建脚本。

设备上的测试应用具有传统的 Robotium/Android/JUnit 依赖项和构建脚本，而远程控制应用只依赖于 TCP 套接字进行通信和 Robotium 远程控制 API。

远程控制的 Robotium 实现可以在以下两个部分完成：

+   **在设备上**：当 Robotium 的`Solo`类对象要用于**RobotiumTestRunner**（**RTR**）时，`ActivityInstrumentationTestCase2.setup()`会被初始化。RTR 有一个远程控制监听器，并将远程控制调用和数据路由到适当的`Solo`类方法，并根据需要将任何结果返回给远程控制器。在设备上的实现如果需要，可以利用测试结果断言。

+   **远程控制器**：`RemoteSolo` API 复制了传统的`Solo` API，但它的实现主要是通过远程控制将数据推送到 RTR，然后从远程控制器接收结果。远程控制的实现可以利用多种选项来断言、处理或以其他方式报告或跟踪每次调用的测试结果。

    如你所见，远程控制端只要求有一个`RemoteSolo` API，不需要任何特定的 JUnit 上下文。如果测试人员希望这样做，它可以被包装在 JUnit 上下文中，但并不需要在 JUnit 上下文中。

以下是 Robotium 远程控制的示例代码和安装方法链接：

[`code.google.com/p/robotium/wiki/RemoteControl`](http://code.google.com/p/robotium/wiki/RemoteControl)

# 概述

在本章中，你了解了 SAFS 框架及其在 Robotium 中的使用，以实现 Robotium 远程控制。在下一章中，你将了解到 Robotium 实用工具。


# 第七章：其他 Robotium 实用工具

本章包括 Robotium 框架中的各种实用工具。这些实用工具包括 `RobotiumUtils` 类、XPath 的使用、Robotium 对已安装的 Android 应用程序的用途，以及在应用程序签名和解签名操作期间涉及的签名过程，以执行测试。让我们逐一了解本章中的这些实用工具。

# `RobotiumUtils` 类

`RobotiumUtils` 类在 Robotium v4.2 中引入。它包含实用方法。让我们看看 `RobotiumUtils` 类的 API 集合。

![`RobotiumUtils` 类](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_07_01.jpg)

## API 集合

`RobotiumUtils` 类提供了用于排序、订购、过滤视图等方法。提供这些功能的不同方法如下：

+   下面的方法基于作为参数传递的类过滤视图：

    ```kt
    RobotiumUtils.filterViews(Class classToFilterBy, Iterable viewList)
    ```

+   下面的方法过滤掉所有不在 `classSet` 参数中的视图：

    ```kt
    RobotiumUtils.filterViewsToSet(Class<android.view.View>[] classSet, Iterable<android.view.View> viewList)
    ```

+   下面的方法检查视图是否与 `stringToMatch` 变量匹配，并返回找到的匹配数量：

    ```kt
    RobotiumUtils.getNumberOfMatches(String stringToMatch, TextView targetTextView, Set<TextView> textviewList)
    ```

+   下面的方法移除了所有可见性为不可见的视图：

    ```kt
    RobotiumUtils.removeInvisibleViews(Iterable viewList)
    ```

+   下面的方法根据屏幕上的位置对所有视图进行排序：

    ```kt
    RobotiumUtils.sortViewsByLocationOnScreen(List viewList)
    ```

+   下面的方法过滤视图集合，并返回与指定正则表达式匹配的视图。

    ```kt
    RobotiumUtils.filterViewsByText(Iterable viewList, string regex)
    ```

### 注意

你可以通过以下链接获取这些方法的更多信息：

[`robotium.googlecode.com/svn/doc/com/jayway/android/robotium/solo/RobotiumUtils.html`](http://robotium.googlecode.com/svn/doc/com/jayway/android/robotium/solo/RobotiumUtils.html)

# XPath API 及语法

可以使用类似 XPath 的表达式定位网页元素。这帮助测试人员在保持测试对应用程序 UI 的抵抗力的同时找到 DOM 的元素。请注意，这仅适用于 WebView 应用程序内的网页元素。

![XPath API 及语法](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_07_02.jpg)

XPath 主要用于在 XML 文档中导航属性和元素。可以使用简单的路径表达式通过 XPath 导航 XML 文档。

让我们通过一个简单的例子来了解如何使用 XPath：

以下是我们必须使用 XPath 解析的 XML 文件：

```kt
<?xml version="1.0"?>
<catalog>
  <book id="z24">
  <author>Hrushikesh</author>
  <title>Robotium Automated Testing For Android</title>
  <genre>Computer</genre>	
  <description>Efficiently automate test cases for Android applications using Robotium </description>
  </book>

  <book id="az24">
  <author>Bharati</author>
  <title>Mathematics MHTCET</title>
  <genre>Objective</genre>
  <description>A comprehensive guide to Mathematics for MHTCET</description>
  </book>
</catalog>
```

假设你想从上一个 XML 文件中提取作者的名字。使用 XPath 完成此操作的功能如下：

```kt
private void parseDataUsingXPath() {
  // create an InputSource object from /res/xml
  InputSource inputSrc = new InputSource(getResources().openRawResource(R.xml.data));

  // Instantiate the XPath Parser instance
  XPath xPath = XPathFactory.newInstance().newXPath();

  // Create the xpath expression
  String xPathExpression = "//author";

  // list of nodes queried
  NodeList nodes = (NodeList)xpath.evaluate(expression, inputSrc, XPathConstants.NODESET);

  // if author node found, then add to authorList i.e. the list of authors instantiated in the activity where this function is used
  if(nodes != null && nodes.getLength() > 0) {
    int len = nodes.getLength();
    for(int i = 0; i < len; ++i) {
      Node node = nodes.item(i);
      authorList.add(node.getTextContent());
    }
  }
}
```

你可以使用以下 XPath 表达式示例查找网页元素：

```kt
solo.getWebElement(By.xpath("//*[@id='nameOfelementID']/tbody/tr[11]/td[2]/input[1]"), 0);
where By.xpath(<path expression>, index);
```

# Robotium 用于预装应用程序

Robotium 允许编写和运行针对 Android 上预装应用程序的测试用例。为此，你需要使用测试项目的调试密钥对目标应用程序执行重新签名操作。这需要访问设备上的 `/system/app` 文件夹。要访问此文件夹，你必须有一个已获得根权限的设备。

![Robotium 用于预装应用程序](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_07_03.jpg)

### 注意

请注意，一些经过重新签名操作预装的应用程序可能无法正常工作。这些应用在用新的调试密钥重新签名后甚至不会显示。

要重新签名 APK 文件，请按照以下步骤操作：

1.  以 root 用户登录：`adb root`。

1.  使用以下代码重新挂载：

    ```kt
    adb remount
    adb pull /system/app/ApplicationName.apk 
    ```

1.  重新签名 `ApplicationName.apk` 文件，使其具有与 `adb pull /data/system/packages.xml` 测试项目相同的证书调试密钥签名。

1.  打开 `packages.xml` 并删除以下代码：

    ```kt
    <package name="com.ApplicationName">
    .....
    </package>
    ```

1.  将 `packages.xml` 推回设备 `adb push packages.xml /data/system`。

1.  重启你的设备。

1.  将重新签名的 `ApplicationName.apk` 文件推回设备 `adb push ApplicationName.apk /system/app`。

## 仅测试 APK

要测试的 APK 文件应具有与测试项目相同的证书签名。如果签名不同，将会发生不匹配。

![仅测试 APK](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_07_04.jpg)

+   如果你知道 APK 证书签名，请使用相同的签名对测试项目进行签名。

+   如果 APK 尚未签名，请使用 Android 调试密钥签名 APK。

+   如果你不知道 APK 证书签名，删除其证书签名，并为 APK 和你的测试项目提供调试密钥签名。

## 签名过程

在 Android 操作系统中，所有应用程序都使用持有私钥的证书进行签名，该私钥由应用程序开发者持有。

有两种构建模式可以构建你的 Android 应用程序。它们如下：

+   调试模式

+   发布模式

Android 构建过程会根据构建模式类型对应用程序进行签名。在开发测试应用程序时通常使用调试模式，而发布模式则用于将发布版本的应用程序分发给用户，或者在如 **Google Play Store** 的市场中发布应用程序。

![签名过程](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_07_05.jpg)

当你使用构建模式时，`Keytool` 实用工具用于创建调试密钥。调试密钥的别名和密码为 SDK 构建工具所知。这就是为什么工具在每次编译程序时不会提示你输入调试密钥的别名和密码。

当你在发布模式下构建应用程序时，会使用私钥。如果你没有私钥，`Keytool` 实用工具会为你创建一个。当你的应用程序在发布模式下编译时，构建工具会使用你的私钥以及 `jarsigner` 实用工具来签名应用程序 APK 文件。

当你使用安装了 ADT 插件的 Eclipse 调试或运行应用程序时，调试密钥签名过程会在后台自动进行。使用启用了调试选项的 Ant 脚本构建应用程序时，也会遵循相同的签名过程。《Eclipse 导出向导》可以帮助自动化发布签名过程或修改 Ant 构建脚本，以及使用发布选项构建应用程序。

要取消已签名的 APK 的签名，然后使用调试密钥重新签名，请执行以下步骤：

1.  使用任何 ZIP 解压工具解压 APK 文件。

1.  删除`Meta-INF`文件夹。

1.  将提取的文件重新压缩成 APK 文件，并将扩展名从`appname.apk.zip`改为`appname.apk`。这样，你就可以取消已签名的 APK 的签名！

1.  要使用 Android 调试签名密钥为这个 APK 签名，请在命令提示符中运行以下命令：

    ```kt
    > jarsigner -keystore ~/.android/debug.keystore -storepass android -keypass android appname.apk androiddebugkey	

    > zipalign 4 appname.apk tempappname.apk
    ```

`jarsigner`工具可以在 JDK 二进制文件中找到，而*zipalign*是 Android SDK 的一部分。

*zipalign*工具用于优化 Android APK 文件。其基本目的是使未压缩的数据与文件的开始位置相对齐。

借助 Eclipse，你也可以为你的 Android 应用签名并导出。执行以下步骤：

1.  在 Android 项目上右键点击，导航到**Android Tools** | **导出已签名的应用程序包**。

1.  在**导出**Android 应用程序向导中，选择你想要导出的项目，然后点击**下一步**。

1.  将会出现**密钥库选择**屏幕。

1.  如果你没有现有的密钥库，请创建一个新的密钥库。你应该可以通过输入位置和密码来创建一个密钥库。

1.  在导航到你想使用的文件夹后，在文件浏览窗口中的**文件名：**字段里输入一个名字，例如，`hrushikesh.keystore`。然后，你应该可以继续进行密钥的创建。

有关 APK 签名的更多信息，请参考以下链接：

[APK 签名指南](http://developer.android.com/tools/publishing/app-signing.html)

# 概述

在本章中，你了解到了 Robotium Framework 中不同的工具及其使用方法。在下一章中，我们将看到 Robotium 与 Maven 的集成机制，以及一些示例。


# 第八章：使用 Maven 的 Robotium

本章节介绍如何使用 Maven 工具将 Android 项目加入到构建过程中。同时，本章也解释了使用 Maven 配合 Robotium 所需的不同配置和安装步骤。

# 使用 Maven 自动化构建的 Android 应用

![使用 Maven 自动化构建的 Android 应用](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_08_01.jpg)

Maven 本质上是一个基于**项目对象模型**（**POM**）概念的项目管理工具，它需要在项目根目录中，并帮助构建项目。

它可以从一个中心信息管理项目的构建、报告和文档。

## Maven 特性

Maven 的主要目标是让开发者能够在最短时间内理解开发工作的完整状态。为了达到这个目标，Maven 尝试处理以下几个关注领域：

| 特性 | 描述 |
| --- | --- |
| 可重复构建 | 你可以在构建服务器上反复构建项目 |
| 关注自动化 | Maven 让你形成在软件开发中自动化流程的正确心态 |
| 依赖管理 | Maven 将解决并管理你的依赖关系 |
| 标准化 | 理解 Maven 的新开发者将立即知道如何构建、发布、测试，从而减少很多学习负担 |
| 插件 | 有很多插件可用于执行不同的任务。这些通过在 `pom.xml` 文件中添加引用来进行配置 |
| 测试 | 这使你能够将运行测试和集成测试作为项目生命周期的一部分 |

为了在 Android 上使用 Maven，你必须为现有的 Eclipse 项目使用**Android Maven 插件**。你可以从前面提到的图中链接下载 Maven。

Android Maven 插件的首页位于以下网站：

[`code.google.com/p/maven-android-plugin/`](https://code.google.com/p/maven-android-plugin/)

## 设置 Android SDK 和 ADT

你可以使用 Android SDK 工具提供的命令行工具来创建/构建一个 Android 项目。ADT 为 Eclipse 提供相同的功能。你也可以通过 Eclipse 导出向导手动导出 Android 应用程序。目前，Apache Ant 主要被 Android SDK 提供的工具用来构建和部署应用程序。

![设置 Android SDK 和 ADT](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/rbt-auto-test-andr/img/8010OS_08_02.jpg)

新的基于 Gradle 的 Android 应用构建系统比旧的基于 Eclipse、Ant 和 Maven 的应用程序有了巨大的改进。它有一个简单的声明式语法，使得构建应用的不同版本（例如，测试版与生产版）变得非常简单。Gradle 也是新的 Android Studio IDE 的默认构建系统，因此有很多理由将你的应用迁移到 Gradle。

Android Studio 将基于 Gradle。在 Android Studio 中，将不再有 ADT，因为它将内置 Android 实用工具。Gradle 在内部使用 Maven 仓库来管理依赖关系，这最终使得支持 Maven 变得相当容易。

## 为 Android Tools 设置环境 PATH。

当您想在 Eclipse 外部构建 Android 项目时，大多数情况下需要使用命令行或 shell。为了实现这一点，您需要确保 Android SDK 的`tools`和`platform-tools`文件夹是 PATH 环境变量的一部分。为此，请按照以下步骤操作：

1.  将环境变量`ANDROID_HOME`设置为您的 Android SDK 的路径。

    Windows 用户：

    +   从桌面右键点击**我的电脑**，然后点击**属性**。

    +   点击左侧列中的**高级系统设置**链接。

    +   在**系统属性**窗口中，点击**环境变量**按钮，并添加名为`ANDROID_HOME`的新变量。

    Unix 系统用户：

    +   导出 `ANDROID_HOME=/path/to/android/sdk`

1.  同时，将`$ANDROID_HOME/tools`和`$ANDROID_HOME/platform-tools`添加到`$PATH`中（对于 Windows，将`%ANDROID_HOME%\tools`和`%ANDROID_HOME%\platform-tools`添加到`%PATH%`）。

1.  所有 MacOS 用户请注意，为了使路径在命令行和由`launchd`启动的 IDE 中生效，您需要在`/etc/launchd.conf`中设置它。

# 使用 Maven 构建 Android 测试。

创建一个名为`com.android.build.maven`的 Android 项目。在本节中，让我们集中精力使用 Maven 为您的 Android 测试应用程序创建一个构建。添加正确的`pom.xml`文件，如下所示的项目目录，并提供命令给 Maven 来构建、安装和运行您的应用程序。

以下是`pom.xml`文件的代码：

```kt
<?xml version="1.0" encoding="UTF-8"?>
<project  
xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/maven-v4_0_0.xsd">
…
…
…
</project>
```

您可以参考`pom.xml`文件在`chapter8_code1`中的完整源代码。

前面的`pom.xml`文件与主项目中的`pom.xml`文件非常相似，但它有几个依赖项。

对于`apk`的依赖是为了让 Android Maven 插件能够找到它将在设备/模拟器上运行的测试的`apk`。对 JAR 文件的依赖是为了让编译器能够从主项目中找到您的 Java 类。为此，您使用了提供的范围，这样类实际上不会包含在您的测试项目中。

在`pom.xml`的构建部分提供的 Android Maven 插件现在将在`mvn install`时使用仪器自动运行测试，就像 Eclipse 一样。它使用了相同的底层工具。

当您只连接了一个模拟器/设备时，自动执行将起作用。如果您有多个设备/模拟器在运行，您需要使用以下命令行选项之一来指定要使用的设备：

+   `-Dandroid.device=usb`

+   `-Dandroid.device=emulator`

+   `-Dandroid.device=specificdeviceid`

您还可以使用此命令行选项禁用仪器测试：

+   `-Dandroid.enableIntegrationTest=false`

可以在`pom.xml`中设置默认属性，如下所示：

```kt
<project>
  …
  <properties>
    <android.device>emulator</android.device>
  </properties>
  …
</project>
```

使用 Maven 构建你的应用程序，并通过以下命令将其部署到设备/模拟器：

```kt
mvn install android:deploy

```

使用 Maven，你还可以自动启动和停止 Android 虚拟设备。应用程序可以通过以下 Maven 命令启动：

```kt
mvn3 android:run

```

### 注意

我们需要处于项目目录中，该目录包含`pom.xml`文件。

# 总结

在本章中，你学习了如何将 Maven 与 Android 和 Robotium 测试结合使用，以及不同的 Maven 命令与 Android 应用程序交互，也就是测试应用程序。

你觉得怎么样？准备好为你的 Android 项目创建和自动化测试用例了吗？我敢打赌你已经准备好了！开始吧，享受使用 Robotium 进行 Android 的自动化测试，并且别忘了和社区分享你的经验！

加入[`groups.google.com/forum/#!forum/robotium-developers`](https://groups.google.com/forum/#!forum/robotium-developers)的论坛，成为令人惊叹的 Robotium 开发者社区的一部分。我们在这里等你！

感谢阅读本书并支持开源技术。期待不久的将来再次见到你！
