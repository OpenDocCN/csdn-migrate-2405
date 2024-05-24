# 安卓 UI 开发（一）

> 原文：[`zh.annas-archive.org/md5/0C4D876AAF9D190F8124849256569042`](https://zh.annas-archive.org/md5/0C4D876AAF9D190F8124849256569042)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

2007 年 1 月 9 日，苹果公司正式发布了 iPhone，用户界面设计的世界发生了转变。尽管平板电脑已经存在了一段时间，但 iPhone 是第一个为如此多人提供便携式触摸屏的设备，人们喜爱它。仅仅过了一年多，谷歌和开放手持设备联盟宣布推出 Android，它在许多方面是 iPhone 的直接竞争对手。

我们为什么喜欢触摸屏手机？答案很简单——反馈。触摸屏提供了一种直接操作屏幕对象的方式，而过去这必须通过键盘、鼠标、操纵杆或其他输入设备来驱动。这种直接操作的触摸屏模式对我们作为开发人员思考用户界面的方式产生了重大影响，也改变了用户对应用程序的期望。触摸屏设备要求我们停止以表单为中心的思考方式，开始考虑面向对象的用户界面。

Android 被广泛用作快速扩展的消费电子产品的主要操作系统，包括：

+   智能手机

+   准系统

+   平板电脑

+   一些桌面系统

尽管这些设备有不同的目的和规格，但它们都运行 Android 系统。这与许多其他操作环境不同，后者几乎总是有特定的用途。它们向开发者提供的服务和 API 通常反映了它们的目标硬件。而另一方面，Android 假设一个应用程序可能需要在许多不同类型的设备上运行，这些设备的硬件能力和规格可能大不相同，并尽可能简单优雅地让开发者处理这些设备之间的差异。

# 新的挑战

随着 Android 及其所支持的触摸屏设备变得越来越普及，它们将为用户界面设计和开发带来一系列新的挑战：

+   您通常没有鼠标

+   您可能有多个指点设备

+   您通常没有键盘

+   任何存在的键盘可能是软件键盘

+   软件键盘可能会占用应用程序的部分屏幕空间

软件键盘减少了应用程序可用的屏幕空间，同样地，如果存在硬件键盘，它可能不会始终暴露给用户。因此，不同的 Android 设备不仅各不相同，而且它们在应用程序运行时可能会看似改变功能。

## 指尖法则

大多数 Android 设备都有触摸屏（尽管这不是必需的）。对任何触摸屏用户界面施加的第一个限制是人类食指的大小，这当然会因人而异。如果屏幕上的小部件太小，用户试图触摸的内容将不清楚。你会注意到，大多数 Android 小部件占用了大量的空间，并且周围有比正常更多的填充。在触摸屏设备上，你不能依赖像素级的精确。你需要确保当用户触摸一个小部件时，他们能接触到，并且不会意外地触摸到另一个小部件。

## 神奇的触摸

触摸屏对用户界面设计的另一个影响是，应用程序及其使用的所有小部件必须完全易于理解（甚至比通常更多）。我们经常用鼠标悬停或工具提示来替代良好的用户界面规划和设计，以指示小部件的功能。在触摸屏设备上，没有鼠标或指针设备。它与用户的第一次交互是当用户触摸它时，他们会期待发生一些事情。

### 提示

**一个敏感的话题**

大多数 Android 设备都有触摸屏，但这并非必需。不同设备间触摸屏的质量也大相径庭。触摸屏的种类及其功能也会因设备而异，这取决于设备的预期用途，以及常常是它的目标市场细分。

## 对世界的较小看法

大多数 Android 设备体积小巧，因此屏幕较小，通常像素比普通 PC 或笔记本电脑要少。这种尺寸的限制限制了小部件的大小。小部件必须足够大，以便安全触摸，但我们也需要在屏幕上尽可能多地展示信息。所以，不要给你的用户他们不需要的信息，同时避免索要你不需要的信息。

# 经典的用户界面原则

这里有一些每个用户界面都应该遵循的核心准则。这些准则将使你的用户感到满意，并确保你的应用程序成功。在本书的其余部分，我们将通过实际例子来讲解这些准则，展示用户界面可以做出的改进。

## 一致性

这是良好用户界面设计的基石。按钮应该看起来像按钮。确保每个屏幕的布局与应用程序中的每个其他屏幕都有关系。人们常将这一原则误认为是“遵循平台的外观和感觉”。外观和感觉很重要，但一致性主要适用于应用程序的布局和整体体验，而不是配色方案。

### 重用你的界面

维持一致用户界面的最简单方法，是尽可能多地复用界面元素。乍一看，这些建议看起来仅仅像是“好的面向对象”实践。然而，仔细观察将揭示出你未曾想到的复用图形小部件的方式。通过改变各种小部件的可见性，或者你可以复用编辑屏幕以查看预期类型的列表项。

## 简洁

这对于基于电话的应用程序尤为重要。通常，当用户遇到一个新应用程序时，是因为他们在寻找某样东西。他们可能没有时间（或者更经常是没有耐心）去学习一个新的用户界面。请确保你的应用程序尽可能少地请求信息，并以尽可能少的步骤引导用户获取他们想要的确切信息。

### 禅宗方法

通常，在使用移动设备时，你的时间有限。你也可能是在不太理想的环境中使用应用程序（比如，在火车上）。用户需要提供给应用程序的信息越少，需要从应用程序中吸收的信息越少，越好。剥离选项和信息也可以使学习曲线变短。

### 安卓的隐藏菜单

安卓一个非常实用的功能是隐藏的菜单结构。菜单仅在用户按下“菜单”按钮时可见，这通常意味着他们在寻找当前屏幕上没有的东西。通常，用户不应该需要打开菜单。然而，隐藏高级功能直到需要时，这是一种很好的方式。

## 反馈

反馈是触摸屏设备令人兴奋的原因。当你拖动一个对象时，它会跟随你的手指在屏幕上移动，直到你松开它。当用户将手指放在你的应用程序上时，他们期待某种反应。然而，你不希望挡他们的路——当他们的手指触摸一个按钮时，不要显示错误消息，而是禁用该按钮直到可以使用，或者根本不显示它。

### 位置与导航

当你来到一个以前从未去过的地方，很容易迷失方向或迷路。软件也是一样。仅仅因为应用程序对你这个开发者来说有意义，并不意味着对你的用户来说逻辑上说得通。添加过渡动画、面包屑和进度条可以帮助用户识别他们在应用程序中的位置以及正在发生的事情。

### 恢复之路

在桌面应用程序或网络上告诉用户出现问题的常见方式是打开错误对话框。在移动设备上，人们希望应用程序的使用更加流畅。在普通应用程序中，你可能会通知用户他们选择了一个无效选项，但在移动应用程序中，你通常希望确保他们根本无法选择该选项。同时，不要让他们浏览大量选项列表。相反，允许他们使用自动完成功能或类似方式过滤列表。

当出现问题时，要友好且有帮助——不要告诉用户，“我找不到任何符合你搜索的航班”。而应该告诉他们，“对于你的搜索，没有可用的航班，但如果你准备提前一天出发，以下是一份可用的航班列表”。一定要确保你的用户可以向前迈出一步，而不必返回（尽管返回的选项应该始终存在）。

# 安卓的方式

安卓平台在很多方面与为网页开发应用程序相似。有许多设备，由许多制造商制造，具有不同的能力和规格。然而，作为开发者，你将希望你的用户拥有尽可能一致的体验。与网页浏览器不同，Android 内置了应对这些差异的机制，甚至可以利用它们。

我们将从用户的角度来看待 Android，而不是纯粹以开发为中心的方法。我们将涵盖如下主题：

+   Android 提供了哪些用户界面元素

+   安卓应用程序是如何组装的

+   安卓的不同布局类型

+   向用户展示各种类型的数据

+   对现有安卓小部件进行定制

+   保持用户界面美观的技巧和工具

+   应用程序之间的集成

我们即将深入探索为安卓设备构建用户界面——所有安卓设备，从最高速的 CPU 到最小的屏幕。

# 这本书涵盖的内容

第一章，*开发一个简单的活动*介绍了构建 Android 应用程序的基础知识，从简单的用户界面开始。它还涵盖了在将你的设计实现为代码时，你可以使用的各种选项。

第二章，*带适配器的视图*展示了如何利用基于适配器的控件，这是 Android 对模型-视图-控制器（MVC）结构的回应。了解这些控件，以及它们最能为你服务的场景。

第三章，*专门的安卓视图*仔细查看了一些 Android 平台提供的更专业的控件，以及它们与普通控件的关系。这一章涵盖了诸如画廊和评分栏之类的控件，以及它们是如何被使用和定制的。

第四章，*活动和意图*更多地讨论了 Android 是如何运行你的应用程序的，以及从这个角度出发，如何最好地编写它的用户界面。这一章讲述了如何确保你的应用程序能够以用户期望的方式运行，而你所需付出的努力最小。

第五章，*非线性布局*探讨了 Android 提供的一些高级布局技术。它讲述了在考虑 Android 设备屏幕差异的同时，向用户呈现不同屏幕的最佳方式。

第六章，*输入与验证*提供了关于从用户那里接收输入的技巧，以及如何尽可能让这个过程轻松。本章探讨了 Android 提供的不同输入小部件，以及如何根据情况最佳地配置它们。同时，当其他方法都失败时，本章还讨论了如何最好地告知用户他们的操作是错误的。

第七章，*动画化小部件和布局*将告诉读者在哪里、何时、为何以及如何为你的 Android 用户界面添加动画。它还揭示了 Android 默认提供哪些类型的动画，如何将它们组合在一起，以及如何构建自己的动画。本章探讨了移动用户界面中动画的重要性，并展示了 Android 如何简化复杂动画的制作。

第八章，*以内容为中心的设计*详细介绍了如何设计屏幕布局，以便在屏幕上向用户展示信息。本章探讨了 Android 提供的一些不同显示技术的优缺点。

第九章，*样式设计 Android 应用程序*告诉我们如何保持整个应用程序的外观一致性，以使我们的应用程序更容易使用。

第十章，*构建应用程序主题*查看了设计过程，以及如何应用全局主题来使你的应用程序脱颖而出。

# 你需要为这本书准备什么

请查看 Android 开发者网站上提到的“系统要求”，链接为：[`developer.android.com/sdk/requirements.html`](http://developer.android.com/sdk/requirements.html)。

本书的代码在 Ubuntu Linux 10.04 和 Mac OS X 上进行了测试。

# 本书的目标读者

本书面向至少有一定 Java 经验，想要在 Android 平台上构建应用程序的开发者。对于那些已经在 Android 平台上开发应用程序，并希望获得关于用户界面设计额外知识的人来说，这本书也将非常有用。它还是 Android 平台提供的众多小部件和资源结构的宝贵参考资料。

这本书还对这些读者有帮助：

+   学习 Android 开发的 Java 开发者

+   想要拓宽技能范围的 MIDP 开发者

+   想要将应用程序移植到 iPhone 的开发者

+   想要拓宽用户基础的创业型 Android 开发者

# 约定

在这本书中，你会发现有几个标题经常出现。

为了清楚地说明如何完成一个过程或任务，我们使用：

# 行动时间——标题

1.  在编辑器或 IDE 中打开`res/layout/main.xml`布局资源。

1.  移除`LinearLayout`元素中的默认内容。

指令通常需要一些额外的解释，以便它们有意义，因此我们会接着提供：

## *刚才发生了什么？*

这个标题解释了你刚刚完成的任务或指令的工作原理。

你还会在书中发现一些其他的学习辅助工具，包括：

## 小测验——标题

这些是简短的选择题，旨在帮助你测试自己的理解。

## 尝试英雄——标题

这些设置实际挑战，并为你提供实验所学内容的想法。

你还会发现一些区分不同类型信息的文本样式。以下是一些这些样式的例子，以及它们的含义解释。

文本中的代码字会如下所示："我们将从创建一个选择器`Activity`和一个简单的`NewsFeedActivity`开始"。

一段代码会以下面的形式设置：

```kt
<activity
    android:name=".AskQuestionActivity"
    android:label="Ask Question">

    <intent-filter>
        <action android:name="questions.askQuestion"/>
        <category android:name="android.intent.category.DEFAULT"/>
    </intent-filter>
</activity>
```

当我们希望引起你对代码块中某个特定部分的注意时，相关的行或项目会以粗体设置：

```kt
<?xml version="1.0" encoding="UTF-8"?>
<FrameLayout
         android:layout_width="fill_parent"
         android:layout_height="fill_parent">

 <ViewStub android:id="@+id/review"
 android:inflatedId="@+id/inflated_review"
 android:layout="@layout/review"/>

 <ViewStub android:id="@+id/photos"
 android:inflatedId="@+id/inflated_photos"
 android:layout="@layout/photos"/>

 <ViewStub android:id="@+id/reservations"
 android:inflatedId="@+id/inflated_reservations"
 android:layout="@layout/reservations"/>
</FrameLayout>
```

任何命令行输入或输出都会以下面的形式编写：

```kt
android create project -n AnimationExamples -p Anima
tionExamples -k com.packtpub.animations -a AnimationSelector -t 3

```

**新术语**和**重要词汇**会以粗体显示。你在屏幕上看到的词，比如菜单或对话框中的，会在文本中以这样的形式出现："通常，如果用户选择**购买音乐**按钮而没有突然被带到网页浏览器，他们会更有信任感"。

### 注意

警告或重要注意事项会以这样的框出现。

### 提示

提示和技巧会以这样的形式出现。

# 读者反馈

我们始终欢迎读者的反馈。告诉我们你对这本书的看法——你喜欢或可能不喜欢的地方。读者的反馈对我们开发能让你们充分利用的标题非常重要。

要向我们发送一般反馈，只需发送电子邮件至`<feedback@packtpub.com>`，并在邮件的主题中提及书名。

如果有一本书你需要的，并且希望看到我们出版，请通过[www.packtpub.com](http://www.packtpub.com)上的**建议一个标题**表格给我们发送信息，或者发送电子邮件至`<suggest@packtpub.com>`。

如果你在一个主题上有专业知识，并且有兴趣撰写或为书籍做贡献，请查看我们在[www.packtpub.com/authors](http://www.packtpub.com/authors)的作者指南。

# 客户支持

既然你现在拥有了 Packt 的一本书，我们有一些事情可以帮助你最大限度地利用你的购买。

### 提示

**下载本书的示例代码**

你可以从你在[`www.PacktPub.com`](http://www.PacktPub.com)的账户下载你所购买的所有 Packt 图书的示例代码文件。如果你在其他地方购买了这本书，可以访问[`www.PacktPub.com/support`](http://www.PacktPub.com/support)注册，我们会直接将文件通过电子邮件发送给你。

## 勘误

尽管我们已经竭尽全力确保内容的准确性，但错误仍然会发生。如果你在我们的书中发现错误——可能是文本或代码中的错误——我们非常感激你能向我们报告。这样做，你可以让其他读者免受挫折，并帮助我们在后续版本中改进这本书。如果你发现任何勘误，请通过访问[`www.packtpub.com/support`](http://www.packtpub.com/support)报告，选择你的书，点击**勘误提交表单**链接，并输入你的勘误详情。一旦你的勘误被验证，你的提交将被接受，勘误将在我们网站的相应标题下的勘误部分上传或添加到现有的勘误列表中。任何现有的勘误都可以通过在[`www.packtpub.com/support`](http://www.packtpub.com/support)选择你的标题来查看。

## 盗版

网络上对版权材料的盗版行为是所有媒体持续面临的问题。在 Packt，我们非常重视对我们版权和许可的保护。如果你在互联网上以任何形式遇到我们作品的非法副本，请立即提供其位置地址或网站名称，以便我们可以寻求补救措施。

如果你怀疑有盗版材料，请通过`<copyright@packtpub.com>`联系我们，并提供相关链接。

我们感谢你帮助保护我们的作者，以及我们为你提供有价值内容的能力。

## 问题

如果你在这本书的任何方面遇到问题，可以通过`<questions@packtpub.com>`联系我们，我们将尽力解决。


# 第一章：开发一个简单的 Activity

*在 Android 的世界里，`Activity`是您与用户接触的点。这是一个您向用户捕捉和展示信息的屏幕。您可以通过使用以下方式构建您的`Activity`屏幕：XML 布局文件或硬编码的 Java。*

为了开始我们的 Android 用户界面之旅，我们需要一个用户界面作为起点。在本章中，我们将从一个简单的`Activity`开始。我们将：

+   创建一个新的 Android 项目

+   在应用程序资源文件中构建`Activity`布局

+   将资源文件与`Activity`类关联

+   动态填充`Activity`一系列的多项选择题

# 开发我们的第一个示例

对于我们的第一个示例，我们将编写一个多项选择题和答案`Activity`。我们可以将其用于诸如“谁想成为百万富翁？”或“你是什么类型的猴子？”等应用程序。这个示例将通过提问来回答一个非常关键的问题：“我应该吃什么？”当用户回答问题时，这个应用程序将筛选出食物想法的数据库。用户可以在任何时候退出流程以查看建议的餐点列表，或者等到应用程序没有问题可问为止。

由于这是一个用户界面示例，我们将跳过构建筛选器和食谱数据库。我们只向用户询问与食物偏好相关的问题。对于每个问题，我们有一系列预设答案供用户选择（即多项选择题）。他们给出的每个答案都会让我们缩小合适的食谱列表。

# 创建项目结构

在我们开始编写代码之前，我们需要一个项目结构。一个 Android 项目远不止其 Java 代码——还有清单文件、资源、图标等等。为了简化事情，我们使用默认的 Android 工具集和项目结构。

您可以从[`developer.android.com`](http://developer.android.com)为您的常用操作系统下载最新版本的 Android SDK。一个单一的 Android SDK 可以用来开发针对任何数量的目标 Android 版本。您需要遵循网站上的安装说明，在[`developer.android.com/sdk/installing.html`](http://developer.android.com/sdk/installing.html)安装最新的 SDK“入门包”和一个或多个平台目标。本书中的大多数示例将在 Android 1.5 及更高版本上运行。Android 网站还维护了一个非常有用的图表，您可以在上面看到最受欢迎的 Android 版本。

# 动手操作——设置 Android SDK

在为您的操作系统下载了 Android SDK 归档文件之后，您需要安装它，然后至少下载一个 Android 平台包。打开命令行或控制台，完成以下步骤：

1.  解压 Android SDK 归档文件。

1.  更改目录到未打包的 Android SDK 的根目录。

1.  更改目录到 Android SDK 的 `tools` 目录。

1.  通过运行以下命令更新 SDK：

    ```kt
    android update sdk
    ```

1.  通过进入**虚拟设备**屏幕并点击**新建**按钮来创建一个新的虚拟设备。将新的虚拟设备命名为**default**。

1.  将其目标指定为 SDK 下载的最新版本的 Android。将 SD 卡的大小设置为**4096 MiB**。点击**创建 AVD**按钮。

## *刚才发生了什么？*

上述命令告诉新的 Android SDK 安装程序查找可用的软件包并安装它们。这包括安装一个平台软件包。你安装的每个平台软件包都可以用来创建一个**Android 虚拟设备**（**AVD**）。你创建的每个 AVD 都像购买了一个新的设备，可以在其上进行测试，每个设备都有自己的配置和数据。这些是虚拟机，当你要测试时，Android 模拟器将在上面运行你的软件。

# 开始一个新项目的行动时间——

Android SDK 提供了一个便捷的命令行工具，名为 `android`，可用于生成新项目的基本框架。你可以在你的 Android SDK 的 `tools` 目录下找到它。它能够创建基本的目录结构和一个 `build.xml` 文件（用于 Apache Ant），帮助你开始 Android 应用程序开发。你需要确保 `tools` 目录在你的可执行路径中，以便这个工具能够正常工作。打开命令行或控制台。

1.  在你的主目录或桌面上创建一个名为 `AndroidUIExamples` 的新目录。你应该使用这个目录来存储本书中的每个示例。

1.  更改目录到新的 `AndroidUIExamples`。

1.  运行以下命令：

    ```kt
    android create project -n KitchenDroid -p KitchenDroid -k com.packtpub.kitchendroid -a QuestionActivity -t 3
    ```

## *刚才发生了什么*

我们刚刚创建了一个框架项目。在前面的命令行中，我们使用了以下选项来指定新项目的结构：

| 选项 | 描述 |
| --- | --- |
| `-n` | 给项目一个名字，在我们的例子中是 `KitchenDroid`。这实际上只是项目的内部标识符。 |
| `-p` | 指定项目的基目录。在这种情况下，使用与项目相同的名称。`android`工具将为你创建这个目录。 |
| `-k` | 指定应用程序的根 Java 包。这是一个相当重要的概念，因为它定义了我们在 Android 客户端设备上的唯一命名空间。 |
| `-a` | 为工具提供一个“主” `Activity` 类的名称。这个类将被填充一个基本的布局 XML，并作为构建你的应用程序的基础点。框架项目将预先配置为在启动时加载这个 `Activity`。 |

如果你运行命令 `android list targets`，并且它提供了一个可能的空目标列表，那么你没有下载任何 Android 平台软件包。你通常可以单独运行 android 工具，并使用其图形界面下载和安装 Android 平台软件包。前面的示例使用 API 级别 3，对应于 Android 平台版本 1.5。

## 检查 Android 项目布局

一个典型的 Android 项目几乎拥有与企业级 Java 项目一样多的目录和文件。Android 既是一个框架，也是一个操作系统环境。在某种程度上，你可以将 Android 视为为在手机和其他有限设备上运行而设计的应用容器。

作为新项目结构的一部分，你将拥有以下重要文件和目录：

| 文件夹名称 | 描述 |
| --- | --- |
| `bin` | 编译器将把你的二进制文件放在这个目录中。 |
| `gen` | 由各种 Android 工具生成的源代码。 |
| `res` | 应用资源放在这里，将与你的应用一起编译和打包。 |
| `src` | 默认的 Java 源代码目录，`build`脚本将在这里查找要编译的源代码。 |
| `AndroidManifest.xml` | 你的应用描述符，类似于`web.xml`文件。 |

### 提示

**资源类型和文件**

大多数应用资源类型（位于`res`目录中）会受到 Android 应用打包器的特殊处理。这意味着这些文件占用的空间比它们通常情况下要少（因为 XML 会被编译成二进制格式，而不是保持纯文本形式）。你可以通过各种方式访问资源，但始终要通过 Android API（它会为你将这些资源解码成它们的原始形式）。

`res`的每个子目录表示不同的文件格式。因此，你不能直接将文件放入根`res`目录中，因为打包工具不知道如何处理它（你将得到一个编译错误）。如果你需要以原始状态访问一个文件，请将其放在`res/raw`目录中。`raw`目录中的文件会以字节为单位复制到你的应用程序包中。

# 动手操作时间——运行示例项目

android 工具为我们提供了一个最小的 Android 项目示例，基本上是一个“Hello World”应用。

1.  在你的控制台或命令行中，切换到`KitchenDroid`目录。

1.  要构建并签名项目，请运行：

    ```kt
    ant debug
    ```

1.  你需要启动之前创建的`default` AVD：

    ```kt
    emulator -avd default
    ```

1.  现在在模拟器中安装你的应用：

    ```kt
    ant install
    ```

1.  在模拟器中，打开**Android**菜单，你应在菜单中看到一个名为**QuestionActivity**的图标。点击这个图标。![动手操作时间——运行示例项目](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_01_01.jpg)

## *刚才发生了什么？*

Android 模拟器是一个完整的硬件模拟器，包括 ARM CPU，承载整个 Android 操作系统栈。这意味着在模拟器下运行软件将完全和在裸机硬件上运行一样（尽管速度可能会有所不同）。

当你使用 Ant 部署你的 Android 应用时，需要使用`install` Ant 目标。`install` Ant 目标会寻找正在运行的模拟器，然后将应用归档文件安装到它的虚拟内存中。需要注意的是，Ant 不会为你启动模拟器。相反，它会发出错误，并且构建会失败。

### 提示

**应用签名**

每个 Android 应用程序包都是数字签名的。签名用于将你标识为应用程序的开发者，并建立应用程序的权限。它还用于建立应用程序之间的权限。

通常你会使用自签名证书，因为 Android 并不要求你使用证书授权机构。然而，所有应用程序必须进行签名，以便它们能够被 Android 系统运行。

# 屏幕布局

虽然 Android 允许你通过 Java 代码或通过在 XML 文件中声明布局来创建屏幕布局，但我们将在 XML 文件中声明屏幕布局。这是一个重要的决定，原因有几个。首先，使用 Java 代码中的 Android 小部件需要为每个小部件编写多行代码（声明/构造行，调用 setter 的几行，最后将小部件添加到其父级），而在 XML 中声明的小部件只占用一个 XML 标签。

将布局保持为 XML 的第二个原因是，当它存储在 APK 文件中时，会被压缩成特殊的 Android XML 格式。因此，你的应用程序在设备上占用的空间更少，下载时间更短，由于需要加载的字节码更少，其内存大小也更小。XML 在编译期间还会由 Android 资源打包工具进行验证，因此具有与 Java 代码相同类型的安全性。

将布局保持为 XML 的第三个原因是，它们需要经过与其他所有外部资源相同的选择过程。这意味着布局可以根据任何定义的属性进行变化，例如语言、屏幕方向和大小，甚至是一天中的时间。这意味着你可以在未来简单通过添加新的 XML 文件，来添加对同一布局的新变体，而无需更改任何 Java 代码。

## 布局 XML 文件

为了让 Android 打包工具能够找到它们，所有的 XML 布局文件必须放在你的 Android 项目的`/res/layout`目录下。每个 XML 文件将生成一个同名的资源变量。例如，如果我们将文件命名为`/res/layout/main.xml`，那么我们可以在 Java 中通过`R.layout.main`访问它。

由于我们将屏幕布局构建为一个资源文件，它将由应用程序资源加载器加载（在资源编译器编译后）。资源需要经过选择过程，因此尽管应用程序只加载一个资源，但在应用程序包中可能有多个相同资源的可用版本。这个选择过程也是 Android 国际化的基础。

如果我们想为几种不同类型的触摸屏构建用户界面布局的不同版本，Android 为我们定义了三种不同的触摸屏属性：`notouch`、`stylus`和`finger`。这大致相当于：没有触摸屏、电阻式触摸屏和电容式触摸屏。如果我们想为没有触摸屏的设备定义一个更依赖键盘的用户界面（`notouch`），我们可以编写一个新的布局 XML 文件，命名为`/res/layout-notouch/main.xml`。当我们在`Activity`代码中加载资源时，资源选择器会在我们运行的设备没有触摸屏时选择`notouch`版本的屏幕。

### 资源选择限定符

这里是一组常用的限定符（属性名），当 Android 选择要加载的资源文件时会考虑这些限定符。这个表格是按优先级排序的，最重要的属性在顶部。

| 名称 | 描述 | 示例 | API 级别 |
| --- | --- | --- | --- |
| MCC 和 MNC | 移动国家代码（MCC）和移动网络代码（MNC）。这些可以用来确定设备中的 SIM 卡绑定的是哪个移动运营商和国家。移动网络代码可选地跟随移动国家代码，但单独使用是不被允许的（你必须首先指定国家代码）。 | `mcc505``mcc505-mnc03``mcc238``mcc238-mnc02``mcc238-mnc20` | 1 |
| 语言和地区代码 | 语言和地区代码可能是最常使用的资源属性。通常，这是你根据用户语言偏好本地化应用程序的方式。这些值是标准的 ISO 语言和地区代码，并且不区分大小写。你不能没有国家代码指定一个地区（类似于`java.util.Locale`）。 | `en``en-rUS``es``es-rCL``es-rMX` | 1 |

| 屏幕尺寸 | 这个属性只有三种变化：小、中、大。这个值基于可使用的屏幕空间量：

+   小型：QVGA（320×240 像素）低密度类型的屏幕；

+   中型：WQVGA 低密度，HVGA（480x360 像素）中密度，以及 WVGA 高密度类型的屏幕；

+   大型：VGA（640x480 像素）或 WVGA 中密度类型的屏幕

| `small``medium``large` | 4 |
| --- | --- |
| 屏幕宽高比 | 这是基于设备“正常”使用方式的屏幕宽高比类型。这个值不会因为设备的方向改变而改变。 | `long``notlong` | 4 |
| 屏幕方向 | 用于确定设备当前是处于竖屏（`port`）还是横屏（`land`）模式。这只有在能检测到方向的设备上可用。 | `land``port` | 1 |
| 夜间模式 | 这个值简单地根据一天中的时间改变。 | `night``notnight` | 8 |

| 屏幕密度（DPI） | 设备屏幕的 DPI。这个属性有四个可能的值：

+   `ldpi`：低密度，大约 120dpi；

+   `mdpi`：中密度，大约 160dpi；

+   `hdpi`：高密度，大约 240dpi；

+   `nodpi`: 可用于不应该根据屏幕密度进行缩放的`bitmap`资源。

| `ldpi``mdpi``hdpi``nodpi` | 4 |
| --- | --- |
| 键盘状态 | 设备上可用的键盘类型是什么？这个属性不应该用来确定设备是否有硬件键盘，而应该用来确定键盘（或软件键盘）当前是否对用户可见。 | `keysexposed``keyshidden``keyssoft` | 1 |

# 动手操作时间——设置问题活动

为了开始，我们将使用 Android 最简单的布局，称为：`LinearLayout`。与 Java AWT 或 Swing 不同，Android 布局管理器被定义为特定的容器类型。因此，`LinearLayout`就像一个带有内置`LayoutManager`的`Panel`。如果您使用过 GWT，您会对这个概念非常熟悉。我们将以简单的从上到下结构（`LinearLayout`非常适合）来布局屏幕。

1.  在您喜欢的 IDE 或文本编辑器中打开项目`/res/layout`目录下名为`main.xml`的文件。

1.  删除任何模板 XML 代码。

1.  将以下 XML 代码复制到文件中：

    ```kt
    <?xml version="1.0" encoding="UTF-8"?>

    <LinearLayout

        android:orientation="vertical"
        android:layout_width="fill_parent"
        android:layout_height="wrap_content">

    </LinearLayout>
    ```

## *刚才发生了什么？*

我们刚刚移除了“Hello World”示例，并放入了一个完全空的布局结构，这将成为我们构建剩余用户界面的平台。如您所见，Android 为其资源有一个特殊的 XML 命名空间。

### 注意

Android 中的所有资源类型都使用相同的 XML 命名空间。

我们将根元素声明为`LinearLayout`。这个元素直接对应于类`android.widget.LinearLayout`。每个带有 Android 命名空间前缀的元素或属性都对应于由 Android 资源编译器解释的属性。

AAPT（Android 资源打包工具）将生成一个`R.java`文件到您的根（或主要）包中。这个文件包含了用于引用各种应用资源的 Java 变量。在我们的例子中，我们有`/res/layout`目录中的`main.xml`包。这个文件变成了一个`R.layout.main`变量，并分配一个常数作为其标识。

# 填充`View`和`ViewGroup`。

在 Android 中，一个控件被称为`View`，而一个容器（如`LinearLayout`）是`ViewGroup`。现在我们有一个空的`ViewGroup`，但我们需要开始填充它以构建我们的用户界面。虽然可以将`ViewGroup`嵌套在另一个`ViewGroup`对象中，但`Activity`只有一个根`View`——因此布局 XML 文件只能有一个根`View`。

# 动手操作时间——提出问题

为了向用户提问，你需要将`TextView`添加到布局的顶部。`TextView`有点像`Label`或`JLabel`。它也是许多其他显示文本的 Android `View`小部件的基础类。我们希望它占用所有可用的水平空间，但只需足够的垂直空间让我们的问题适应。我们用**请稍等...**作为其默认文本填充`TextView`。稍后，我们将用动态选择的问题替换它。

1.  回到你的`main.xml`文件。

1.  在`<LinearLayout...>`和`</LinearLayout>`之间创建一个`<TextView />`元素，使用空元素`/>`语法结束，因为代表`View`对象的元素不允许有子元素。

1.  为`TextView`元素设置一个 ID 属性：

    ```kt
    android:id="@+id/question"
    ```

1.  将布局的宽度和高度属性分别更改为`fill_parent`和`wrap_content`（与`LinearLayout`元素相同）：

    ```kt
    android:layout_width="fill_parent"
    android:layout_height="wrap_content"
    ```

1.  为`TextView`设置一些占位文本，以便我们可以在屏幕上看到它：

    ```kt
    android:text="Please wait..."
    ```

1.  从项目根目录使用 Apache Ant 重新安装应用程序：

    ```kt
    ant install
    ```

1.  再次在模拟器中运行应用程序，它应该看起来像以下截图：

![动手时间——提出问题](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_01_02.jpg)

`TextView`的代码最终看起来应该像这样：

```kt
<TextView android:id="@+id/question"
          android:text="Please wait..."
          android:layout_width="fill_parent"
          android:layout_height="wrap_content"/>
```

## *刚才发生了什么*

在前面的示例中，我们将`fill_parent`和`wrap_content`用作布局宽度和高度属性的值。`fill_parent`的值是一个特殊值，始终等于父视图的大小。如果它用作`android:layout_width`属性的值（如我们的示例所示），那么它就是父视图的宽度。如果它在`android:layout_height`属性中使用，那么它将等于父视图的高度。

`wrap_content`的值在 Java AWT 或 Swing 中类似于首选大小。它告诉`View`对象，“占用你所需要的空间，但不要更多”。这些特殊属性值唯一有效的使用地方是`android:layout_width`和`android:layout_height`属性中。其他任何地方使用都会导致编译错误。

我们稍后需要在 Java 代码中访问这个`TextView`，以便调用其`setText`方法（该方法直接对应于我们用于占位文本的`android:text`属性）。通过为资源分配 ID，创建了对资源变量的 Java 引用。在这个例子中，ID 在这里声明为`@+id/question`。AAPT 将为`id`类型的每个资源生成一个`int`值作为标识符，作为你的`R`类的一部分。ID 属性还用于从另一个资源文件访问资源。

# 动手时间——添加答案的空间

向用户提问当然很好，但我们还需要给他们提供回答问题的方法。我们有几种选择：可以使用带有`RadioButton`的`RadioGroup`来表示每个可能的答案，或者使用带有每个答案项的`ListView`。然而，为了最小化所需的交互，并尽可能清晰，我们为每个可能的答案使用一个`Button`。但这稍微有些复杂，因为你在布局 XML 文件中不能声明可变数量的`Button`对象。相反，我们将声明一个新的`LinearLayout`，并在 Java 代码中使用`Button`对象填充它。

1.  在我们提出问题的`TextView`下方，你需要添加一个`<LinearLayout />`元素。虽然这个元素通常会有子元素，但在我们的案例中，可能答案的数量是变化的，所以我们将其留为一个空元素。

1.  默认情况下，`LinearLayout`会将它的子`View`对象水平排列。然而，我们希望每个子`View`垂直排列，因此你需要设置`LinearLayout`的`orientation`属性：

    ```kt
    android:orientation="vertical"
    ```

1.  我们稍后需要在 Java 代码中填充新的`ViewGroup`（`LinearLayout`），所以给它一个 ID：`answers`：

    ```kt
    android:id="@+id/answers"
    ```

1.  与我们的`TextView`和根`LinearLayout`一样，将宽度设置为`fill_parent`：

    ```kt
    android:layout_width="fill_parent"
    ```

1.  将高度设置为`wrap_content`，使其不会占用比所有按钮更多的空间：

    ```kt
    android:layout_height="wrap_content"
    ```

最终代码应如下所示：

```kt
<LinearLayout android:id="@+id/answers"
              android:orientation="vertical"
              android:layout_width="fill_parent"
              android:layout_height="wrap_content"/>
```

## *刚才发生了什么？*

你可能已经注意到，对于这个例子，我们新的`LinearLayout`中没有内容。这可能看起来有些不寻常，但在这个案例中，我们希望用可变数量的按钮填充它——针对多项选择题的每个可能答案一个。然而，对于示例的下一部分，我们需要在这个`LinearLayout`中添加一些简单的内容`Button`小部件，以便我们可以看到整个屏幕布局的效果。在你的布局资源文件中使用以下代码，向`LinearLayout`添加**Yes!**，**No!**和**Maybe?** `Button`小部件：

```kt
<LinearLayout android:id="@+id/answers"
            android:orientation="vertical"
            android:layout_width="fill_parent"
            android:layout_height="wrap_content">

    <Button android:id="@+id/yes"
            android:text="Yes!"
            android:layout_width="fill_parent"
            android:layout_height="wrap_content" />

    <Button android:id="@+id/no"
            android:text="No!"
            android:layout_width="fill_parent"
            android:layout_height="wrap_content" />

    <Button android:id="@+id/maybe"
            android:text="Maybe?"
            android:layout_width="fill_parent"
            android:layout_height="wrap_content" />
</LinearLayout>
```

在 Android XML 布局资源中，任何从`ViewGroup`类扩展的`View`类都被视为容器。向它们添加小部件就像将那些`View`元素嵌套在`ViewGroup`的元素内（而不是用没有子 XML 元素的闭合它）一样简单。

以下是前述**Yes!**，**No!**，**Maybe?**选项的屏幕截图：

![发生了什么？](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_01_03.jpg)

# 动手时间——添加更多按钮

我们还需要向屏幕布局添加两个额外的按钮。一个将允许用户跳过当前问题；另一个将允许他们查看到目前为止我们已过滤的简短餐单列表（基于他们已经回答的问题）。

1.  首先，在我们答案`ViewGroup <LinearLayout />`下方（但仍在根`LinearLayout`元素内）创建一个空的`<Button />`元素。给它分配 ID `skip`，这样我们就可以在 Java 中引用它：

    ```kt
    android:id="@+id/skip"
    ```

1.  使用边距为答案和新按钮之间创建一些填充：

    ```kt
    android:layout_marginTop="12sp"
    ```

1.  给它显示标签 **跳过问题**：

    ```kt
    android:text="Skip Question"
    ```

1.  与所有之前的控件一样，宽度应为`fill_parent`，高度应为`wrap_content`：

    ```kt
    android:layout_width="fill_parent"
    android:layout_height="wrap_content"
    ```

1.  现在，在**跳过问题**按钮下方创建另一个空的 `<Button />` 元素。

1.  新按钮的 ID 应为 `view`：

    ```kt
    android:id="@+id/view"
    ```

1.  我们希望这个按钮显示文本：**Feed Me!**：

    ```kt
    android:text="Feed Me!"
    ```

1.  再次，在**跳过问题**按钮和新**Feed Me!**按钮之间放置一点空间：

    ```kt
    android:layout_marginTop="12sp"
    ```

1.  最后，将**Feed Me!**按钮的宽度和高度设置为与我们迄今为止创建的其他元素一样：

    ```kt
    android:layout_width="fill_parent"
    android:layout_height="wrap_content"

    ```

完成这两个按钮后，你的布局 XML 文件现在应该以以下内容结束：

```kt
    <Button android:id="@+id/skip"
            android:text="Skip Question"
            android:layout_marginTop="12sp"
            android:layout_width="fill_parent"
            android:layout_height="wrap_content"/>

    <Button android:id="@+id/view"
            android:text="Feed Me!"
            android:layout_marginTop="12sp"
            android:layout_width="fill_parent"
            android:layout_height="wrap_content"/>
</LinearLayout>
```

## *刚才发生了什么*

将不相关的用户界面对象分开是用户界面设计的一个非常重要的部分。可以通过空白、边框或盒子将项目组分开。在我们的案例中，我们选择使用空白，因为空间也有助于让用户界面感觉更清洁。

我们通过在每个按钮上方使用边距来创建空白空间。边距和填充的工作方式与 CSS 中的（应该）完全一样。边距是控件外的空间，而填充是控件内的空间。在 Android 中，边距是`ViewGroup`的关注点，因此其属性名称以`layout_`为前缀。由于填充是`View`对象的责任，因此填充属性没有这样的前缀：

```kt
<Button android:id="@+id/view"
        android:text="Feed Me!"
        android:padding="25sp"
        android:layout_marginTop="12sp"
        android:layout_width="fill_parent"
        android:layout_height="wrap_content"/>
```

之前的代码会在`Button`的边缘和中间文本之间创建额外的空间，同时保留按钮上方的边距。

前一个示例中的所有测量单位均为`sp`，它是“与比例无关的像素”的缩写。与 CSS 类似，你可以在你指定的尺寸单位后缀上测量数字。Android 识别以下测量单位：

| 单位后缀 | 全名 | 描述和用途 |
| --- | --- | --- |
| `px` | 像素 | 设备屏幕上的一个精确像素。这个单位在编写桌面应用程序时最常见，但随着手机屏幕尺寸的多样化，它变得较难使用。 |
| `in` | 英寸 | 一英寸（或最接近的近似值）。这是基于屏幕的物理尺寸。如果你需要与实际世界尺寸一起工作，这很棒，但由于设备屏幕尺寸的变异，它并不总是非常有用。 |
| `mm` | 毫米 | 另一个实际尺寸的测量，尽可能近似。这仅是英寸的公制版本：1 英寸等于 25.4 毫米。 |
| `pt` | 点 | 点的大小为 1/72 英寸。与毫米和英寸类似，它们对于与实际尺寸相对的大小调整非常有用。它们也常用于调整字体大小，因此相对于字体大小来说非常好用。 |
| `dp` 或 `dip` | 密度独立像素 | 单个 DP 在 160 dpi 的屏幕上与单个像素大小相同。这个大小并不总是成比例的，也不总是精确的，但它是当前屏幕的最佳近似值。 |
| `sp` | 比例独立像素 | 与`dp`单位类似，它是根据用户选择的字体大小缩放的像素。这可能是最佳的单位，因为它是基于用户选择的参数。用户可能因为觉得屏幕难以阅读而增加了字体大小。使用`sp`单位可以确保你的用户界面随之缩放。 |

## 定义通用尺寸

安卓还允许你定义自己的尺寸值作为资源常量（注意：是尺寸，不是测量）。当你想要多个`view`组件大小相同，或者定义一个通用的字体大小时，这会很有用。包含尺寸声明的文件放在项目的`/res/values`目录中。实际的文件名并不重要，常见的名称是`dimens.xml`。从技术上讲，尺寸可以与其他值类型（即字符串）一起包含，但这并不推荐，因为它使得在运行时追踪应用的尺寸变得更加困难。

将尺寸放在它们自己的文件中，而不是内联声明的一个优点是，你可以根据屏幕大小对它们进行本地化。这使得与屏幕分辨率相关的刻度（如像素）更加有用。例如，你可以将一个`dimens.xml`文件放入`/res/values-320x240`目录中，并带有不同的值，再将同一尺寸的另一个版本放入`/res/values-640x480`目录中。

尺寸资源文件是一个简单的值文件（类似于`strings.xml`），但是尺寸是通过`<dimen>`标签定义的：

```kt
<resources>
    <dimen name="half_width">160px</dimen>
</resources>
```

要在布局 XML 文件中作为大小访问，你可以使用资源引用（这与访问资源字符串的方式类似）：

```kt
<TextView layout_width="@dimen/half_width" />
```

构建一个通用尺寸列表在构建复杂布局时会很有帮助，这些布局将在许多不同的屏幕上看起来都很好，因为它避免了需要构建几个不同的布局 XML 文件。

## 尝试改进样式的大侠——提升样式

现在我们有了这个用户界面最基本的结构，但它看起来并不太好看。除了答案按钮之间的边距，以及**跳过问题**和**给我提示！**按钮之外，你几乎无法区分它们。我们需要让用户知道这些按钮各司其职。同时，我们也需要让问题更加突出，尤其是如果他们没有太多时间在屏幕上眯着眼看的时候。你可能需要安卓的文档，可以在网上找到，地址是[`developer.android.com/reference/`](http://developer.android.com/reference/)。

我们在屏幕顶部有一个问题，但正如你在之前的屏幕截图中看到的，它并不突出。因此，对于用户来说，他们需要做什么并不是非常清晰（尤其是第一次使用该应用程序时）。

尝试对屏幕顶部的题目`TextView`进行以下样式更改。这只需要你为其 XML 元素添加一些属性：

1.  文本居中。

1.  使文本加粗。

1.  将文本大小改为`24sp`。

1.  在问题和答案按钮之间添加`12sp`的间距

**喂我！**按钮也非常重要。这是让用户访问应用程序根据他们的答案过滤出的建议食谱列表的按钮，所以它应该看起来不错。

以下样式应该有助于**喂我！**按钮很好地突出（提示：`Button`继承自`TextView`）：

1.  将文本大小设置为`18sp`。

1.  将文本颜色改为好看的红色`#9d1111`。

1.  将文本样式设置为加粗。

1.  添加文本阴影：`x=0`，`y=-3`，`radius=1.5`，`color=white`（"`#fff`"）。

当你完成屏幕样式的调整后，它应该看起来像以下截图：

![尝试改进样式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_01_04.jpg)

# 布局 XML 格式的限制

布局 XML 格式最明显的限制之一是，你不能基于外部变量动态填充`Activity`的一部分——XML 文件中没有循环或方法。

在我们的示例中，这种限制以空`LinearLayout`的形式出现。因为每个问题都有任意数量的可能答案，我们需要在组内变动数量的按钮。对于我们的目的，我们将在 Java 代码中创建`Button`对象并将它们放入`LinearLayout`。

XML 布局格式另一个失败的地方是动态引用外部资源。这可以在我们的示例中看到，我们在`TextView`元素上放置了占位符文本——`question`的`android:text`属性。我们可以使用以下语法引用外部字符串：

```kt
<TextView android:id="@+id/question"
          android:text="@string/question"
          android:gravity="center"
          android:textStyle="bold"
          android:layout_width="fill_parent"
          android:layout_height="wrap_content"/>
```

这将有效地引用`strings.xml`文件中的静态变量。它不适合动态选择的问题，每次初始化`Activity`时都会改变。

## 突击测验

1.  你有什么理由用 XML 而不是纯 Java 代码来编写你的布局？

    1.  安卓可以从外部读取布局文件以进行优化。

    1.  布局成为资源选择过程的一部分。

    1.  你的用户可以从 App Store 下载新的布局。

    1.  布局可以应用自定义主题。

1.  我们如何使**下一题**按钮的文本加粗？

    1.  使用`android:typeface`属性。

    1.  创建一个自定义的`Button`实现。

    1.  添加一个 CSS 属性：`style="font-weight: bold"`。

    1.  使用`android:textStyle`属性。

1.  如果我们将`LinearLayout`从`vertical`方向改为`horizontal`方向，会发生什么？

    1.  布局会侧翻。

    1.  所有小部件在屏幕上会被挤压在一起。

    1.  只有问题的`TextView`会显示在屏幕上。

    1.  根据可用的像素数量，问题以及可能的其他`View`对象可能会显示在屏幕上。

    1.  布局将溢出，导致小部件紧挨着出现在多行上。

# 填充 QuestionActivity

我们有一个基本用户界面，但现在它是静态的。我们可能想要向用户提出许多不同的问题，每个问题都有不同的答案。我们还可能以某种方式改变我们提出的问题。简而言之，我们需要一些 Java 代码来填充布局，加入一个问题及一些可能的答案。我们的问题由两部分组成：

+   问题

+   可能答案的列表

在此示例中，我们将利用字符串数组资源来存储所有问题和答案数据。我们将使用一个字符串数组来列出问题标识符，然后为每个问题及其答案使用一个字符串数组。这种方法的优势与使用布局 XML 文件而不是硬编码的优势非常相似。你的项目的`res/values`目录中将有一个自动生成的`strings.xml`文件。这个文件包含了你希望应用程序使用的字符串和字符串数组资源。以下是我们`strings.xml`文件的开始部分，其中包含两个要问用户的问题：

```kt
<?xml version="1.0" encoding="UTF-8"?>

<resources>
    <string name="app_name">Kitchen Droid</string>

    <string-array name="questions">
        <item>vegetarian</item>
        <item>size</item>
    </string-array>

    <string-array name="vegetarian">
        <item>Are you a Vegetarian?</item>
        <item>Yes</item>
        <item>No</item>
        <item>I\'m a vegan</item>
    </string-array>

    <string-array name="size">
        <item>How much do you feel like eating?</item>
        <item>A large meal</item>
        <item>Just a nice single serving of food</item>
        <item>Some finger foods</item>
        <item>Just a snack</item>
    </string-array>
</resources>
```

每个问题数组(`vegetarian`和`size`)的第一个条目是问题本身，而随后的每个条目都是一个答案。

# 行动时间——编写更多的 Java 代码

1.  打开编辑器或 IDE 中的`QuestionActivity.java`文件。

1.  在包声明下方导入 Android 的`Resources`类：

    ```kt
    import android.content.res.Resources;
    ```

1.  为了从你的`strings.xml`文件开始提问，你需要一个方法来查找`questions <string-array>`并找到包含当前问题的数组名称。这通常不是你在应用程序资源中需要做的事情——它们的标识符通常通过`R`类为你所知。但在此情况下，我们想要按照`questions <string-array>`中定义的顺序进行操作，这使得事情变得有些复杂：

    ```kt
    private int getQuestionID(Resources res, int index) {
    ```

1.  现在我们可以查看`questions`字符串数组，它包含了每个问题的标识名称（我们的索引字符串数组）：

    ```kt
    String[] questions = res.getStringArray(R.array.questions);
    ```

1.  我们有一个问题数组，需要找到标识符值。这类似于对`vegetarian`问题使用`R.array.vegetarian`，只不过这是一个动态查找，因此比正常情况要慢得多。通常情况下，以下这行代码是不推荐的，但对我们来说非常有用：

    ```kt
    return res.getIdentifier(
            questions[index],
            "array",
            "com.packtpub.kitchendroid");
    ```

1.  `QuestionActivity`类将向用户展示几个问题。我们希望应用程序能够与手机及其环境"友好相处"。因此，每个问题都将在`QuestionActivity`的新实例中提出（允许设备控制我们`Activity`的显示）。然而，这种方法引发了一个重要问题：我们如何知道要向用户提出的问题的索引？答案是：我们的`Intent`。`Activity`是通过一个`Intent`对象启动的，每个`Intent`对象可能携带任何数量的"额外"信息（类似于`HttpServletRequest`接口中的请求属性），供`Activity`使用，有点像`main`方法的参数。所以，`Intent`也像一个`HashMap`，包含供`Activity`使用的特殊数据。在我们的例子中，我们使用了一个名为`KitchenDroid.Question`的整型属性：

    ```kt
    private int getQuestionIndex() {
        return getIntent().getIntExtra("KitchenDroid.Question", 0);
    }
    ```

这两种方法构成了我们填充问题屏幕和按定义好的问题列表进行导航的基础。完成时，它们应该看起来像这样：

```kt
private static int getQuestionID(
        final Resources res,
        final int index) {

    final String[] questions = res.getStringArray(R.array.questions);

    return res.getIdentifier(
            questions[index],
            "array",
            "com.packtpub.kitchendroid");
}

private int getQuestionIndex() {
    return getIntent().getIntExtra("KitchenDroid.Question", 0);
}
```

## *刚才发生了什么*

`getQuestionID`方法非常直接。在我们的代码中，我们使用`R.array.questions`来访问`<string-array>`，它标识了我们将要向用户提出的所有问题。每个问题都有一个`String`形式的名称，以及一个`int`形式的对应资源识别号。

在`getQuestionID`方法中，我们使用了`Resources.getIdentifier`方法，该方法用于查找给定资源名称的资源标识符（整数值）。该方法的第二个参数是要查找的资源类型。这个参数通常是生成的`R`类的内部类。最后，我们传递了资源所在的基包。除了这三个参数，你也可以通过完整的资源名称来查找资源：

```kt
return res.getIdentifier(
        "com.packtpub.kitchendroid:array/" + questions[index],
        null,
        null);
```

`getQuestionIndex`方法告诉我们当前在`questions <string-array>`中的位置，从而确定要向用户提出哪个问题。这是基于触发`Activity`的`Intent`中的"额外"信息。`getIntent()`方法为你提供了访问触发你`Activity`的`Intent`的途径。每个`Intent`可以有任何数量的"额外"数据，这些数据可以是任何"原始"或"可序列化"的类型。这里我们从`Intent`中获取了`KitchenDroid.Question`额外的整数值，如果没有设置则替换为 0（即默认值）。如果用户点击菜单中的图标，Android 没有指定该值，那么我们从第一个问题开始。

# 动态创建小部件

到目前为止，我们只使用了布局 XML 文件来填充我们的屏幕。在某些情况下，这还不够。在这个简单的例子中，我们希望用户有一个按钮列表，他们可以点击来回答提出的问题。我们可以预先创建一些按钮并将它们命名为`button1`、`button2`等，但这意味着限制了可能的答案数量。

为了从我们的 `<string-array>` 资源中创建按钮，我们需要在 Java 中进行操作。我们之前创建了一个 `ViewGroup`（以我们命名为 `answers` 的 `LinearLayout` 的形式）。这就是我们将添加动态创建的按钮的地方。

# 是时候采取行动了——将问题显示在屏幕上。

你的应用程序现在知道去哪里找问题来询问，也知道应该询问哪个问题。现在它需要将问题显示在屏幕上，并允许用户选择答案。

1.  在编辑器或 IDE 中打开 `main.xml` 文件。

1.  从布局资源中移除 **Yes!**、**No!** 和 **Maybe?** `Button` 元素。

1.  在编辑器或 IDE 中打开 `QuestionActivity.java` 文件。

1.  我们需要一个新的类字段来保存动态创建的 `Button` 对象（作为引用）：

    ```kt
    private Button[] buttons;
    ```

1.  为了保持整洁，创建一个新的 `private` 方法来将问题显示在屏幕上：`initQuestionScreen`：

    ```kt
    private void initQuestionScreen() {
    ```

1.  在这个方法中，我们假设布局 XML 文件已经加载到 `Activity` 屏幕中（即，在 `onCreate` 中 `setContentView` 之后将被调用）。这意味着我们可以将布局的部分作为 Java 对象来查找。我们需要 `TextView` 名为 `question` 和 `LinearLayout` 名为 `answers` 的这两个对象：

    ```kt
    TextView question = (TextView)findViewById(R.id.question);
    ViewGroup answers = (ViewGroup)findViewById(R.id.answers);
    ```

1.  这两个变量需要用问题和其可能的答案来填充。为此，我们需要 `<string-array>`（来自我们的 `strings.xml` 文件），其中包含这些数据，因此我们需要知道当前问题的资源标识符。然后我们可以获取实际的数据数组：

    ```kt
    int questionID = getQuestionID(resources, getQuestionIndex());
    String[] quesionData = resources.getStringArray(questionID);
    ```

1.  `question` 字符串数组的第一个元素是向用户提出的问题。接下来的 `setText` 调用与在布局 XML 文件中指定 `android:text` 属性完全相同：

    ```kt
    question.setText(quesionData[0]);
    ```

1.  然后我们需要创建一个空数组来保存对我们 `Button` 对象的引用：

    ```kt
    int answerCount = quesionData.length – 1;
    buttons = new Button[answerCount];
    ```

1.  现在我们准备填充屏幕了。根据我们的数组，对每个答案值进行 `for` 循环：

    ```kt
    for(int i = 0; i < answerCount; i++) {
    ```

1.  从数组中获取每个答案，跳过索引为零的问题字符串：

    ```kt
    String answer = quesionData[i + 1];
    ```

1.  为答案创建一个 `Button` 对象并设置其标签：

    ```kt
    Button button = new Button(this);
    button.setText(answer);
    ```

1.  最后，我们将新的 `Button` 添加到我们的 answers 对象（`ViewGroup`）中，并在我们的 `buttons` 数组中引用它（我们稍后会需要它）：

    ```kt
    answers.addView(button);
    buttons[i] = button;
    ```

1.  做完这些之后，在 `onCreate` 中的 `setContentView` 调用之后，我们需要调用我们新的 `initQuestionScreen` 方法。

## *刚才发生了什么？*

`findViewById` 方法遍历 `View` 对象的树，寻找特定的标识整数值。默认情况下，任何在资源文件中使用 `android:id` 属性声明的资源都将有一个关联的 ID。你也可以通过使用 `View.setId` 方法手动分配一个 ID。

与许多其他用户界面 API 不同，Android 用户界面 API 更倾向于 XML 开发而非纯 Java 开发。这一点的完美例证是`View`子类有三个不同的构造函数，其中两个是为与 XML 解析 API 配合使用而设计的。我们无法在构造函数中填充`Button`标签（像大多数其他 UI API 那样），而是被迫先构造对象，然后使用`setText`来定义其标签。

你传给每个`View`对象构造函数的是`Context`对象。在前面示例中，你将`Activity`对象作为`this`传递给答案`Button`对象的构造函数中。`Activity`类从`Context`类继承。`Context`对象被`View`和`ViewGroup`对象用来加载它们为了正确运行所需的应用程序资源和服务。

现在你可以尝试运行应用程序，在这种情况下，你会看到以下屏幕。你可能已经注意到这个截图中还有额外的样式。如果你没有这个，你可能需要回溯到之前的*尝试一下英雄*部分。

![刚才发生了什么？](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_01_05.jpg)

# 在 Android 中处理事件

Android 用户界面事件的工作方式与 Swing 事件监听器或 GWT 事件处理程序非常相似。根据你想接收的事件类型，实现一个接口并将一个实例传递给你希望从中接收事件的小部件。在我们的例子中，我们有`Button`小部件，当用户触摸时会触发点击事件。

事件监听接口在许多 Android 类中声明，因此没有一个单独的地方可以查找它们。而且，与大多数事件监听系统不同，许多小部件可能只有一个给定类型的事件监听器。你可以通过类名前缀为`On`来识别事件监听接口（类似于 HTML 事件属性）。为了监听小部件上的点击事件，你会使用`View.setOnClickListener`方法来设置其`OnClickListener`。

下面的代码片段展示了如何向`Button`对象添加一个点击监听器来显示一个`Toast`。`Toast`是一个小型的弹出框，会短暂显示以向用户提供一些信息：

```kt
button.setOnClickListener(new View.OnClickListener() {
    public void onClick(View clicked) {
        Toast.makeText(this, "Button Clicked!", Toast.LENGTH_SHORT).
             show();
    }
});
```

前面的事件监听器被声明为一个匿名内部类，当你需要将类似的事件监听器传递给许多不同的组件时，这样做是可以的。然而，大多数情况下，你会在 XML 布局资源中声明的组件上监听事件。在这些情况下，最好让你的`Activity`类实现所需的接口，或者为不同的事件驱动操作创建专门的类。尽管 Android 设备非常强大，但与台式电脑或笔记本电脑相比，它们仍然有限制。因此，你应该避免创建不必要的对象，以节省内存。通过将尽可能多的事件监听器方法放在已经创建的对象中，你可以降低所需的资源开销。

## 小测验

1.  当你在布局 XML 文件中声明一个对象时，你如何获取其 Java 对象？

    1.  对象将在`R`类中声明。

    1.  使用`Activity.findViewById`方法。

    1.  使用`Resources.getLayout`方法。

    1.  对象将被注入到`Activity`类中的一个字段中。

1.  在 Android 应用程序中监听事件的“最佳”方式是什么？

    1.  将监听器声明为匿名内部类。

    1.  为每个`Activity`创建一个单独的事件监听器类。

    1.  在`Activity`类中实现事件监听接口。

1.  为什么你要将`this Activity`传递给`View`对象（例如`new Button(this)`）的构造函数中？

    1.  它定义了`Activity`屏幕，它们将在上面显示。

    1.  这是事件消息将被发送到的位置。

    1.  这是`View`将引用其操作环境的方式。

# 总结

Android 提供了一些出色的工具来创建和测试应用程序，即使你没有 Android 设备在身边。话虽如此，实际触摸你的应用程序是无法替代的。这是 Android 平台如此吸引人的部分原因，它的感觉和响应方式（而模拟器并不能传达这一点）。

Android 开发者工具库中最重要工具之一是资源选择系统。通过它，你可以构建高度动态的应用程序，这些程序能够响应设备的变化，从而响应用户环境的变化。根据设备的方向改变屏幕布局，或者当用户滑出手机的 QWERTY 键盘时，让他们知道你在构建应用程序时考虑了他们的偏好。

在 Android 中构建用户界面时，强烈建议至少在 XML 文件中构建布局结构。XML 布局文件不仅被视为应用程序资源，而且 Android 也强烈倾向于通过编写 XML 用户界面而不是 Java 代码来构建。然而，有时布局 XML 文件是不够的，你需要用 Java 构建用户界面的一部分。在这种情况下，最好至少定义一个 XML 的布局框架（如果可能的话），然后使用标记 ID 和容器将动态创建的`View`对象放入布局中（类似于在 JavaScript 中动态添加到 HTML 文档）。

在构建用户界面时，要仔细考虑最终的外观和感觉。在我们的示例中，我们使用`Button`对象作为问题的答案。我们本可以使用`RadioButton`对象，但那样用户就需要选择一个选项，然后触摸**下一题**按钮，需要两次触摸。我们也本可以使用`List`（它与需要动态填充的事实很好地交互），然而，`List`并不像`Button`那样向用户清楚地表示一个“动作”。

在编写布局代码时，要小心使用测量单位。强烈建议在大多数情况下使用`sp`——除非你可以使用特殊的`fill_parent`或`wrap_content`值。其他值很大程度上取决于屏幕大小，并且不会响应用户偏好。你可以利用资源选择过程为小、中、大屏幕构建不同的屏幕设计。你也可以定义自己的测量单位，并基于屏幕大小进行设置。

时刻考虑你的用户将如何与应用程序互动，以及他们可能会花费多少时间（或很少的时间）在其中。保持每个屏幕简洁且响应迅速可以使你的用户感到满意。

既然我们已经学会了如何创建一个基本的 Android 项目和一个简单的`Activiy`，我们可以专注于 Android 用户界面设计的更微妙的问题和解决方案。在下一章中，我们将重点关注数据驱动小部件的工作。Android 有几个专门设计用于显示和选择更复杂数据结构的小部件。这些小部件构成了数据驱动应用程序（如地址簿或日历应用程序）的基础。


# 第二章：视图的数据展示

*在第一章中，我们介绍了如何创建一个项目，以及如何构建一个简单的用户界面。我们为第一个`Activity`编写了足够的代码，以动态生成用户可以用来回答我们的多项选择题的按钮。*

*现在我们已经可以捕获一些数据了，但如何显示数据呢？软件的一大优势是它能快速并以易于阅读的格式呈现和筛选大量数据。在本章中，我们将介绍一系列专门用于展示数据的安卓控件。*

大多数以数据为中心的安卓类都是建立在`Adapter`对象之上的，因此扩展了`AdapterView`。可以将`Adapter`视为 Swing Model 类和渲染器（或呈现器）之间的交叉。`Adapter`对象用于为软件需要向用户显示的数据对象创建`View`对象。这种模式允许软件维护并处理数据模型，并且只在需要时为每个数据对象创建图形`View`。这不仅有助于节省内存，而且从开发角度来看也更合逻辑。作为开发者，您处理自己的数据对象，而不是试图将数据保存在图形小部件中（这些小部件通常不是最健壮的结构）。

您最常遇到的`AdapterView`类有：`ListView`，`Spinner`和`GridView`。在本章中，我们将介绍`ListView`类和`GridView`，并探讨它们的各种使用方式和样式设置。

# 列表和选择数据

`ListView`类可能是显示数据列表的最常见方式。它由`ListAdapter`对象支持，后者负责保存数据并渲染数据对象在`View`中的显示。`ListView`内置了滚动功能，因此无需将其包裹在`ScrollView`中。

## ListView 选择模式

`ListView`类支持三种基本的项选择模式，由其常量定义：`CHOICE_MODE_NONE`，`CHOICE_MODE_SINGLE`和`CHOICE_MODE_MULTIPLE`。可以通过在布局 XML 文件中使用`android:choiceMode`属性，或者在 Java 中使用`ListView.setChoiceMode`方法来设置`ListView`的选择模式。

### 注意

**选择模式和项目**

`ListView`的选择模式改变了`ListView`结构的行为方式，但不会改变其外观。`ListView`的外观主要由`ListAdapter`定义，后者为应该出现在`ListView`中的每个项目提供`View`对象。

### 无选择模式 - CHOICE_MODE_NONE

在桌面系统中，这种情况没有意义——一个不允许用户选择任何内容的列表？然而，这是 Android `ListView` 的默认模式。原因是当用户通过触摸导航时，这很有意义。`ListView` 的默认模式允许用户点击其中一个元素，并触发一个动作。这种行为的结果是，无需“下一步”按钮或类似的东西。因此，`ListView` 的默认模式是表现为一个菜单。以下截图显示了一个默认的 `ListView` 对象，它从一个默认的 `ApiDemos` 示例中的 `String` 数组 Java 对象中展示不同的字符串列表。

![无选择模式 —— CHOICE_MODE_NONE](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_02_01.jpg)

### 单选模式 —— CHOICE_MODE_SINGLE

在此模式下，`ListView` 更像是一个桌面 `List` 小部件。它有当前选择的概念，点击列表项仅仅会选中它，不会再有其他动作。这种行为对于配置或设置等操作很合适，用户希望应用程序记住他们当前的选择。单选列表在屏幕上有其他交互式小部件时也很有用。但是，要注意不要在单个 `Activity` 中放置太多信息。`ListView` 占据几乎整个屏幕是很常见的。

### 注意

单选模式：它不会直接改变你的列表项的外观。你的列表项的外观完全由 `ListAdapter` 对象定义。

然而，Android 确实在系统资源中提供了一系列合理的默认值。在 `android` 包中，你会发现一个 `R` 类。这是访问系统默认资源的编程方式。如果你想创建一个带有 `<string-array>` 颜色列表的单选 `ListView`，你可以使用以下代码：

```kt
list.setAdapter(new ArrayAdapter(
        this,
        android.R.layout.simple_list_item_single_choice,
        getResources().getStringArray(R.array.colors)));
```

在此情况下，我们使用了 `android.widget` 包中提供的 `ArrayAdapter` 类。在第二个参数中，我们引用了名为 `simple_list_item_single_choice` 的 Android 布局资源。这个资源被 Android 系统定义为在 `CHOICE_MODE_SINGLE` 模式下显示 `ListView` 项的默认方式。通常这是一个带有 `RadioButton` 的标签，对应 `ListAdapter` 中的每个对象。

![单选模式 —— CHOICE_MODE_SINGLE](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_02_02.jpg)

### 多选模式 —— CHOICE_MODE_MULTIPLE

在多选模式下，`ListView` 用普通的复选框替换单选模式中的单选按钮。这种设计结构在桌面和基于 Web 的系统中也经常使用。复选框容易被用户识别，也便于返回并关闭选项。如果你希望使用标准的 `ListAdapter`，Android 为你提供了 `android.R.layout.simple_list_item_multiple_choice` 资源作为有用的默认选项：每个 `ListAdapter` 中的对象都有一个带有 `CheckBox` 的标签。

![多选模式 —— CHOICE_MODE_MULTIPLE](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_02_03.jpg)

## 添加头部和底部控件

`ListView`中的头部和底部允许你在列表的顶部和底部放置额外的控件。默认情况下，头部和底部控件被视为列表中的项（就像它们来自你的`ListAdapter`一样）。这意味着你可以像选择`List`结构中的数据元素一样选择它们。一个简单的头部项示例可能是：

```kt
TextView header = new TextView(this);
header.setText("Header View");
list.addHeaderView(header);
```

通常你不想让`ListView`中的头部和底部成为列表项，而是一个标签或一组标签，标识`ListView`的各个部分，或提供其他信息。在这种情况下，你需要告诉`ListView`，你的头部或底部视图不是可选的列表项。这可以通过使用`addHeaderView`或`addFooterView`的扩展实现来完成：

```kt
TextView footer = new TextView(this);
footer.setText("Footer View");
list.addFooterView(footer, null, false);
```

`ListView`类将头部和底部与列表结构紧密集成，因此你也可以提供一个`Object`，它将通过`AdapterView.getItemAtPosition(index)`方法返回。在我们之前的示例中，我们提供了`null`。每个头部项都会将后续视图的索引偏移一个（就像你向`ListView`添加新项一样）。第三个参数告诉`ListView`是否应将头部或底部视为可选择的列表项（在我们之前的示例中不应该）。

如果你习惯了桌面控件，那么 Android `ListView`上的头部和底部控件可能会让你有点惊讶。它们会随着列表中的其他项一起滚动，而不会固定在`ListView`对象的顶部和底部。

## 创建一个简单的 ListView

为了介绍`ListView`类，我们将开始一个新示例，该示例将通过本章的后续各个部分进行增强。我们将创建的第一个`Activity`将使用从`<string-array>`资源填充的简单`ListView`。

# 动手操作——创建快餐菜单

为了继续我们的食物与饮食主题，让我们构建一个简单的应用程序，允许我们订购各种类型的快餐，并送到家！用户首先会选择他们想订购的餐厅，然后选择他们想吃的各种食物。

1.  使用 Android 命令行工具创建一个新的`android`项目：

    ```kt
    android create project -n DeliveryDroid -p DeliveryDroid -k com.packtpub.deliverydroid -a SelectRestaurantActivity -t 3
    ```

1.  使用你喜欢的编辑器或 IDE 打开`/res/values/strings.xml`文件。

1.  创建一个字符串数组结构，列出用户可以订购的各种快餐餐厅：

    ```kt
    <string-array name="restaurants">
        <item>The Burger Place</item>
        <item>Mick's Pizza</item>
        <item>Four Buckets \'o Fruit</item>
        <item>Sam\'s Sushi</item>
    </string-array>
    ```

1.  使用你喜欢的编辑器或 IDE 打开`/res/layout/main.xml`文件。

1.  移除默认`LinearLayout`中的任何控件。

1.  添加一个新的`<ListView>`元素。

1.  将`<ListView>`元素的 ID 设置为`restaurant`：

    ```kt
    <ListView android:id="@+id/restaurant"/>
    ```

1.  将`ListView`的宽度和高度设置为`fill_parent`：

    ```kt
    android:layout_width="fill_parent"
    android:layout_height="fill_parent"
    ```

1.  由于我们有一个包含我们想要填充`ListView`内容的字符串数组资源，我们可以在布局 XML 文件中直接引用它：

    ```kt
    android:entries="@array/restaurants"
    ```

1.  完成指定步骤后，你应该会得到一个看起来像下面的`main.xml`布局文件：

    ```kt
    <?xml version="1.0" encoding="UTF-8"?>
    <LinearLayout

        android:orientation="vertical"
        android:layout_width="fill_parent"
        android:layout_height="fill_parent">

     <ListView android:id="@+id/restaurant"
     android:layout_width="fill_parent"
     android:layout_height="fill_parent"
     android:entries="@array/restaurants"/>
    </LinearLayout>
    ```

## *刚才发生了什么*

如果你将应用程序安装到模拟器中并运行它，你将看到一个屏幕，你可以从中选择在你字符串数组资源中指定的餐厅列表。请注意，`ListView`上的`choiceMode`设置为`CHOICE_MODE_NONE`，这使得它更像是一个直接菜单，用户选择餐厅后，可以立即跳转到该餐厅的菜单。

![刚才发生了什么](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_02_04.jpg)

在这个例子中，我们在布局 XML 文件中使用了`android:entries`属性，指定了一个引用字符串数组资源的引用，其中包含我们想要的列表项。通常，使用`AdapterView`需要你创建一个`Adapter`对象，为每个数据对象创建`View`对象。

使用`android:entries`属性允许你从布局资源中指定`ListView`的数据内容，而不是要求你编写与`AdapterView`相关的正常 Java 代码。然而，它有两个需要注意的缺点：

+   由生成的`ListAdapter`创建的`View`对象将始终是系统指定的默认值，因此不容易进行主题设置。

+   你不能定义将在`ListView`中表示的数据对象。由于字符串数组容易本地化，你的应用程序将依赖于项目索引位置来确定它们表示的内容。

你可能已经注意到截图顶部，标签`Where should we order from?`不是应用程序的默认设置。`Activity`的标签在`AndroidManifest.xml`文件中定义如下：

```kt
<activity
    android:name=".SelectRestaurantActivity"
    android:label="Where should we order from?">
```

## 设置标准 ListAdapter 的样式

标准的`ListAdapter`实现要求每个项目在`TextView`项中表示。默认的单选和多选项目是使用`CheckedTextView`构建的，尽管 Android 中有许多其他的`TextView`实现，但它确实限制了一些我们的选择。然而，标准的`ListAdapter`实现非常方便，并为最常见的列表需求提供了可靠的实现。

由于带有`CHOICE_MODE_NONE`的`ListView`与菜单非常相似，如果将项目改为`Button`对象而不是普通的`TextView`项，岂不是很好吗？从技术上讲，`ListView`可以包含任何扩展`TextView`的小部件。然而，有些实现比其他的更适合（例如，`ToggleButtonView`在用户触摸它时不会保持指定的文本值）。

### 定义标准尺寸

在这个例子中，我们将为应用程序创建各种菜单。为了保持一致的外观和感觉，我们应该定义一组标准尺寸，这些尺寸将用于我们的每个布局文件中。这样我们可以为不同类型的屏幕重新定义尺寸。对于用户来说，没有比只能看到部分项目更沮丧的了，因为它的尺寸比他们的屏幕还要大。

创建一个新的资源文件来包含尺寸。该文件应命名为`res/values/dimens.xml`。将以下代码复制到新的 XML 文件中：

```kt
<?xml version="1.0" encoding="UTF-8"?>

<resources>
    <dimen name="item_outer_height">48sp</dimen>
    <dimen name="menu_item_height">52sp</dimen>
    <dimen name="item_inner_height">45sp</dimen>
    <dimen name="item_text_size">24sp</dimen>
    <dimen name="padding">15dp</dimen>
</resources>
```

我们为列表项声明了两个高度尺寸：`item_outer_height`和`item_inner_height`。`item_outer_height`将是列表项的高度，而`item_inner_height`是列表项中包含的任何`View`对象的高度。

文件末尾的`padding`尺寸用于定义两个视觉元素之间的标准空白量。这被定义为`dp`，因此它会根据屏幕的 DPI 保持不变（而不是根据用户的字体大小偏好进行缩放）。

### 提示

**交互项目的大小调整**

在这个样式设置中，你会注意到`item_outer_height`和`menu_item_height`是`48sp`和`52sp`，这使得`ListView`中的项目相当大。Android 中列表视图项的标准大小是`48sp`。列表项的高度至关重要。如果你的用户手指较大，而你把项目设置得太小，他们将很难点击目标列表项。

这是一般针对安卓用户界面设计的“良好实践”。如果用户需要触摸操作，那么请把它设计得大一些。

# 行动时间——改善餐厅列表

我们之前整理的餐厅列表很棒，但它是一个菜单。为了进一步强调菜单，文本应该更加突出。为了使用标准`ListAdapter`实现来设置`ListView`的样式，你需要在你的 Java 代码中指定`ListAdapter`对象。

1.  在`res/layout`目录中创建一个名为`menu_item.xml`的新文件。

1.  将根 XML 元素创建为`TextView`：

    ```kt
    <?xml version="1.0" encoding="UTF-8"?>
    <TextView />
    ```

1.  导入 Android 资源 XML 命名空间：

1.  通过设置`TextView`小部件的 gravity 属性来使文本居中：

    ```kt
    android:gravity="center|center_vertical"
    ```

1.  我们将`TextView`的`textSize`赋值为我们的标准`item_text_size`：

    ```kt
    android:textSize="@dimen/item_text_size"
    ```

1.  `TextView`文本的默认颜色有点灰，我们希望它是白色：

    ```kt
    android:textColor="#ffffff"
    ```

1.  我们希望`TextView`的宽度与包含它的`ListView`相同。因为这是我们的主菜单，所以它的高度是`menu_item_height`：

    ```kt
    android:layout_width="fill_parent"
    android:layout_height="@dimen/menu_item_height"
    ```

1.  现在我们有一个样式化的`TextView`资源，我们可以将它整合到我们的菜单中。打开`SelectRestaurantActivity.java`文件。

1.  在`onCreate`方法中，使用`setContentView`之后，我们需要获取之前在`main.xml`中创建的`ListView`的引用：

    ```kt
    ListView restaurants = (ListView)findViewById(R.id.restaurant);
    ```

1.  将餐厅的`ListAdapter`设置为一个包含我们在`values.xml`文件中创建的字符串数组的新`ArrayAdapter`：

    ```kt
    restaurants.setAdapter(new ArrayAdapter<String>(
        this,
        R.layout.menu_item,
        getResources().getStringArray(R.array.restaurants)));
    ```

## *刚才发生了什么*

我们首先创建了一个新的布局 XML 资源，其中包含我们想要用于餐厅`ListView`中每个列表项的样式化`TextView`。你编写的`menu_item.xml`文件应该包含以下代码：

```kt
<?xml version="1.0" encoding="UTF-8"?>

<TextView 
              android:gravity="center|center_vertical"
              android:textSize="@dimen/item_text_size"
              android:textColor="#ffffff"
              android:layout_width="fill_parent"
              android:layout_height="@dimen/menu_item_height" />
```

与我们之前的布局资源不同，`menu_item.xml`不包含任何`ViewGroup`（如`LinearLayout`）。这是因为`ArrayAdapter`将尝试将`menu_item.xml`文件的根`View`转换为`TextView`。因此，如果我们以某种方式将`TextView`嵌套在`ViewGroup`中，我们将得到一个`ClassCastException`。

我们还创建了一个`ArrayAdapter`实例，以引用我们之前创建的`menu_item` XML 资源以及餐厅字符串数组。这个操作消除了在`main.xml`布局 XML 资源中的`ListView`上使用`android:entries`属性。如果你愿意，可以删除该属性。现在，你在`SelectRestaurantActivity`中的`onCreate`方法应如下所示：

```kt
public void onCreate(final Bundle icicle) {
        super.onCreate(icicle);
        setContentView(R.layout.main);

        final ListView restaurants = (ListView)
                findViewById(R.id.restaurant);

 restaurants.setAdapter(new ArrayAdapter<String>(
 this,
 R.layout.menu_item,
 getResources().getStringArray(R.array.restaurants)));
    }
```

尝试使用 Apache Ant 将应用程序重新安装到模拟器中，现在你将看到一个看起来更像菜单的屏幕：

![刚才发生了什么](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_02_05.jpg)

## 尝试英雄——开发一个多选题应用程序。

尝试回到我们在第一章中编写的多选题应用程序，*Developing a Simple Activity*。它使用`LinearLayout`和`Button`对象来显示问题的可能答案，但它也使用字符串数组作为答案。尝试修改应用程序以：

+   使用`ListView`代替`LinearLayout`。

+   使用`Button`对象为`ListView`设置样式，就像我们使用`TextView`对象为餐厅菜单设置样式一样。

+   确保在`Button`列表项之间有一定的间距，使它们不会过于紧密。

## 创建自定义适配器。

当我们想要点餐时，我们通常想要订购一个项目的多个数量。`ListView`的实现以及标准的`ListAdapter`实现允许我们选择一个**Cheese Burger**项目，但并不允许我们请求**3 Cheese Burgers**。为了显示用户可以以多个数量订购的不同食品的菜单，我们需要一个自定义的`ListAdapter`实现。

### 为“The Burger Place”创建菜单。

对于主菜单中的每家餐厅，我们将构建一个单独的`Activity`类。实际上，这不是一个好主意，但它允许我们研究组织和展示菜单数据的不同方式。我们的第一站是**The Burger Place**，我们向用户展示一个汉堡列表，让他们在屏幕上点击他们想要的汉堡。每次点击列表项时，他们都会再点一个汉堡。我们将在汉堡名称左侧以粗体显示他们正在订购的汉堡数量。对于他们没有订购的汉堡旁边，则不显示数字（这使得用户可以快速查看他们正在订购的内容）。

#### 汉堡类。

为了显示菜单，我们需要一个简单的`Burger`数据对象。`Burger`类将保存要在菜单中显示的名称，以及用户正在订购的`Burger`数量。在项目的根包中创建一个`Burger.java`文件，并使用以下代码：

```kt
class Burger {
    final String name;
    int count = 0;

    public Burger(String name) {
        this.name = name;
    }
}
```

你会注意到，在前面的代码中没有 getter 和 setter 方法，而且`name`和`count`字段都声明为包保护的。在 Android 2.2 之前的版本中，与直接字段查找相比，方法会产生较大的开销。由于这个类将只是渲染过程的一小部分（我们将从中提取数据以显示），我们应该确保开销尽可能小。

# 动手时间——创建汉堡项布局

为了为**汉堡店**设计一个好看的菜单，首先要做的是设计菜单项。这与使用布局 XML 资源的餐厅列表样式设计非常相似。然而，由于这次我们将自己构建`ListAdapter`，因此不必使用单个`TextView`，而是可以构建更复杂的布局。

1.  在`res/layout`目录中创建一个名为`burger_item.xml`的新 XML 文件。这个文件将用于`ListView`中的每个汉堡项。

1.  将布局的根声明为`horizontal LinearLayout`（注意高度，这将是`ListView`中每个项目的高度）：

    ```kt
    <LinearLayout 

        android:orientation="horizontal"
        android:layout_width="fill_parent"
        android:layout_height="@dimen/item_outer_height">
    ```

1.  接下来，声明一个`TextView`，我们将用它作为订购汉堡数量的`counter`。我们稍后可以通过其 ID 访问这个`TextView`：

    ```kt
    <TextView android:id="@+id/counter" />
    ```

1.  `counter`的文本大小与应用程序中所有其他列表项完全相同。然而，它应该是加粗的，这样就可以轻松识别和阅读：

    ```kt
    android:textSize="@dimen/item_text_size"
    android:textStyle="bold"

    ```

1.  我们还希望`counter`是正方形的，因此将宽度和高度设置得完全相同：

    ```kt
    android:layout_width="@dimen/item_inner_height"
    android:layout_height="@dimen/item_inner_height"
    ```

1.  我们还希望文本在`counter`内居中：

    ```kt
    android:gravity="center|center_vertical"
    ```

1.  我们还需要一个文本空间来显示汉堡的名字：

    ```kt
    <TextView android:id="@+id/text" />
    ```

1.  文本大小是标准的：

    ```kt
    android:textSize="@dimen/item_text_size"
    ```

1.  我们希望`counter`和`text`标签之间有一点空间：

    ```kt
    android:layout_marginLeft="@dimen/padding"
    ```

1.  标签的宽度应填满`ListView`，但我们希望两个`TextView`对象的大小相同：

    ```kt
    android:layout_width="fill_parent"
    android:layout_height="@dimen/item_inner_height"
    ```

1.  标签文本应垂直居中，以匹配`counter`的位置。然而，标签应该是左对齐的：

    ```kt
    android:gravity="left|center_vertical"
    ```

## *刚才发生了什么？*

你刚刚构建了一个非常不错的`LinearLayout ViewGroup`，这将为我们从**汉堡店**销售的每个汉堡渲染。由于`counter TextView`与标签是分开的对象，因此可以独立地进行样式设计和管理。如果我们想独立地为它们应用额外的样式，这将使事情变得更加灵活。现在你的`burger_item.xml`文件应该如下所示：

```kt
<?xml version="1.0" encoding="UTF-8"?>

<LinearLayout

    android:orientation="horizontal"
    android:layout_width="fill_parent"
    android:layout_height="@dimen/item_outer_height">

 <TextView android:id="@+id/counter"
 android:textSize="@dimen/item_text_size"
 android:textStyle="bold"
 android:layout_width="@dimen/item_inner_height"
 android:layout_height="@dimen/item_inner_height"
 android:gravity="center|center_vertical" />

 <TextView android:id="@+id/text"
 android:textSize="@dimen/item_text_size"
 android:layout_marginLeft="@dimen/padding"
 android:layout_width="fill_parent"
 android:layout_height="@dimen/item_inner_height"
 android:gravity="left|center_vertical" />
</LinearLayout>
```

# 动手时间——展示汉堡对象

如果你的数据对象是字符串或者很容易表示为字符串，标准的`ListAdapter`类工作得很好。为了在屏幕上美观地显示我们的`Burger`对象，我们需要编写一个自定义的`ListAdapter`类。幸运的是，Android 为我们提供了一个名为`BaseAdapter`的很好的`ListAdapter`实现框架类。

1.  创建一个名为`BurgerAdapter`的新类，并让它继承自`android.widget.BaseAdapter`类：

    ```kt
    class BurgerAdapter extends BaseAdapter {
    ```

1.  `Adapter`是表示层的一部分，但也是`ListView`的底层模型。在`BurgerAdapter`中，我们存储了一个`Burger`对象的数组，我们在构造函数中分配它：

    ```kt
    private final Burger[] burgers;
    BurgerAdapter(Burger... burgers) {
        this.burgers = burders;
    }
    ```

1.  直接在`Burger`对象数组上实现`Adapter.getCount()`和`Adapter.getItem(int)`方法：

    ```kt
    public int getCount() {
        return burgers.length;
    }

    public Object getItem(int index) {
        return burgers[index];
    }
    ```

1.  还期望`Adapter`为各个项目提供标识符，我们将仅返回它们的索引：

    ```kt
    public long getItemId(int index) {
        return index;
    }
    ```

1.  当`Adapter`被请求提供一个列表项的`View`时，它可能会接收到一个可复用的现有`View`对象。我们将实现一个简单的方法来处理这种情况，如果需要，将使用`android.view`包中的`LayoutInflator`类来填充我们之前编写的`burger_item.xml`文件：

    ```kt
    private ViewGroup getViewGroup(View reuse, ViewGroup parent) {
        if(reuse instanceof ViewGroup) {
            return (ViewGroup)reuse;
        }
        Context context = parent.getContext();
        LayoutInflater inflater = LayoutInflater.from(context);
        ViewGroup item = (ViewGroup)inflater.inflate(
                R.layout.burger_item, null);
    return item;
    }
    ```

1.  在`BurgerAdapter`中，对我们来说最重要的方法是`getView`方法。这是`ListView`请求我们提供一个`View`对象的地点，以表示它需要显示的每个列表项：

    ```kt
    public View getView(int index, View reuse, ViewGroup parent) {
    ```

1.  为了获取给定项目的正确`View`，你首先需要使用`getViewGroup`方法以确保你有`burger_item.xml ViewGroup`来显示`Burger`项：

    ```kt
    ViewGroup item = getViewGroup(reuse, parent);
    TextView counter = (TextView)item.findViewById(R.id.counter);
    TextView label = (TextView)item.findViewById(R.id.text);
    ```

1.  我们将使用请求的`index`位置上的`Burger`对象的数据来填充这两个`TextView`对象。如果当前的`count`为零，则需要从用户界面隐藏`counter`小部件：

    ```kt
    Burger burger = burgers[index];
    counter.setVisibility(
            burger.count == 0
            ? View.INVISIBLE
            : View.VISIBLE);
    counter.setText(Integer.toString(burger.count));
    label.setText(burger.name);
    return item;
    ```

## *刚才发生了什么？*

我们刚刚编写了一个自定义的`Adapter`类，用于在`ListView`中向用户展示一系列`Burger`对象。当`ListView`调用`Adapter.getView`方法时，它会尝试传入之前调用`Adapter.getView`返回的`View`对象。将为`ListView`中的每个项目创建一个`View`对象。然而，当`ListView`显示的数据发生变化时，`ListView`将要求`ListAdapter`重用第一次生成的每个`View`对象。尽量遵循这一行为非常重要，因为它直接影响到应用程序的响应性。在我们之前的示例中，我们实现了`getViewGroup`方法，以便考虑到这一要求。

`getViewGroup`方法也用于加载我们编写的`burger_item.xml`文件。我们使用`LayoutInflator`对象来完成此操作，这正是`Activity.setContentView(int)`方法加载 XML 布局资源的方式。我们从`parent ViewGroup`获取的`Context`对象（通常是`ListView`）定义了我们将从哪里加载布局资源。如果用户没有选择“汉堡”，我们使用`View.setVisibility`方法隐藏计数器`TextView`。在 AWT 和 Swing 中，`setVisible`方法接受一个`Boolean`参数，而在 Android 中，`setVisibility`接受一个`int`值。这样做的原因是 Android 将可见性视为布局过程的一部分。在我们的例子中，我们希望`counter`消失，但仍然在布局中占据其空间，这将使`text`标签保持左对齐。如果我们希望计数器消失且不占用空间，我们可以使用：

```kt
counter.setVisibility(burger.count == 0
        ? View.GONE
        : View.VISIBLE);
```

`ListView`对象将自动处理选中项目的突出显示。这包括用户在项目上按住手指，以及他们使用轨迹板或方向键导航`ListView`时。当一个项目被突出显示时，其背景通常会根据标准的 UI 约定改变颜色。

然而，在`ListView`中使用某些直接捕获用户输入的小部件（例如，`Button`或`EditText`）会导致`ListView`不再为该小部件显示选中高亮。实际上，这将阻止`ListView`完全注册`OnItemClick`事件。

### 提示

**在 ListView 中自定义分隔符**

如果重写`ListAdapter`的`isEnabled(int index)`方法，你就可以策略性地禁用`ListView`中的指定项目。这种做法的一个常见用途是将某些项目设置为逻辑分隔符。例如，在按字母排序的列表中的部分分隔符，包含下一“部分”所有项目首字母。

## 创建 TheBurgerPlaceActivity 类

为了在屏幕上显示“汉堡”菜单，并允许用户订购项目，我们需要一个新的`Activity`类。我们需要知道用户何时触摸列表中的项目，为此我们将需要实现`OnItemClickListener`接口。当发生特定事件时（在本例中是用户在`ListView`中触摸特定项目），作为监听器注册的对象将调用与发生的事件相关的相应方法。Android 提供了一个简单的`ListActivity`类，为这种情况提供一些默认布局和实用方法。

# 动手实践——实现 TheBurgerPlaceActivity

为了使用 `BurgerAdapter` 类展示 `Burger` 对象的 `ListView`，我们将需要创建一个 **The Burger Place** 的 `Activity` 实现。新的 `Activity` 还将负责监听 `ListView` 中项目的“触摸”或“点击”事件。当用户触摸其中一个项目时，我们需要更新模型和 `ListView`，以反映用户又订购了一个 `Burger`。

1.  在项目的根包中创建一个名为 `TheBurgerPlaceActivity` 的新类，并确保它继承自 `ListActivity`：

    ```kt
    public class TheBurgerPlaceActivity extends ListActivity {
    ```

1.  重写 `Activity.onCreate` 方法。

1.  调用 `super.onCreate` 以允许正常的 Android 启动过程。

1.  使用一些 `Burger` 对象创建 `BurgerAdapter` 的实例，并将其设置为 `ListActivity` 代码要使用的 `ListAdapter`：

    ```kt
    setListAdapter(new BurgerAdapter(
            new Burger("Plain old Burger"),
            new Burger("Cheese Burger"),
            new Burger("Chicken Burger"),
            new Burger("Breakfast Burger"),
            new Burger("Hawaiian Burger"),
            new Burger("Fish Burger"),
            new Burger("Vegatarian Burger"),
            new Burger("Lamb Burger"),
            new Burger("Rare Tuna Steak Burger")));
    ```

1.  最后，使用以下代码实现 `onListItemClicked` 方法：

    ```kt
    protected void onListItemClick(
            ListView parent,
            View item,
            int index,
            long id) {
    BurgerAdapter burgers = (BurgerAdapter)
                parent.getAdapter();
    Burger burger = (Burger)burgers.getItem(index);
        burger.count++;
        burgers.notifyDataSetInvalidated();
    }
    ```

## *刚才发生了什么？*

这个 `TheBurgerPlaceActivity` 的实现有一个简单的硬编码 `Burger` 对象列表供用户显示，并创建了一个 `BurgerAdapter` 来将这些对象转换为之前创建的 `burger_item View` 对象。

当用户点击列表项时，我们在 `onItemClick` 方法中增加相关 `Burger` 对象的 `count`。然后我们调用 `BurgerAdapter` 上的 `notifyDataSetInvalidated()`。此方法将通知 `ListView` 底层数据已更改。当数据更改时，`ListView` 将重新调用 `Adapter.getView` 方法，针对 `ListView` 中的每个项目。

`ListView` 中的项目由实际上是静态的 `View` 对象表示。这意味着当数据模型更新时，适配器必须允许更新或重新创建该 `View`。一种常见的替代方法是获取表示你更新数据的 `View`，并直接更新它。

## 注册并启动 TheBurgerPlaceActivity

为了从我们的餐厅菜单启动新的 `Activity` 类，你需要在 `AndroidManifest.xml` 文件中注册它。首先，在编辑器或 IDE 中打开 `AndroidManifest.xml` 文件，并将以下 `<activity>` 代码复制到 `<application>...</application>` 块中：

```kt
<activity android:name=".TheBurgerPlaceActivity"
          android:label="The Burger Place\'s Menu">

    <intent-filter>
        <action android:name=
                "com.packtpub.deliverydroid.TheBurgerPlaceActivity"/>
    </intent-filter>
</activity>
```

为了启动 `Activity`，你将需要回到 `SelectRestaurantActivity` 并实现 `OnItemClickListener` 接口。在 `restaurants ListView` 上设置 `Adapter` 之后，将 `SelectRestaurantActivity` 设置为 `restaurants ListView` 的 `OnItemClickListener`。你可以在 `onItemClick` 方法中使用 `Intent` 对象启动 `TheBurgerPlaceActivity`。现在你的 `SelectRestaurantActivity` 类应该看起来像以下代码片段：

```kt
public class SelectRestaurantActivity extends Activity
 implements OnItemClickListener {

    @Override
    public void onCreate(Bundle icicle) {
        super.onCreate(icicle);
        setContentView(R.layout.main);

        ListView restaurants = (ListView)
                findViewById(R.id.restaurant);

        restaurants.setAdapter(new ArrayAdapter<String>(
                this,
                R.layout.menu_item,
                getResources().getStringArray(R.array.restaurants)));

 restaurants.setOnItemClickListener(this);
    }

 public void onItemClick(
 AdapterView<?> parent,
 View item,
 int index,
 long id) {

 switch(index) {
 case 0:
 startActivity(new Intent(
 this,
 TheBurgerPlaceActivity.class));
 break;
 }
 }
}
```

当你重新安装应用程序并在模拟器中启动它时，你将能够导航到 **The Burger Place** 并为汉堡包下订单。在 **The Burger Place** 菜单中按下硬件“返回”按钮将带你回到餐厅菜单。

![注册并启动 TheBurgerPlaceActivity](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_02_06.jpg)

## 小测验

1.  将 `ListView` 对象的选择模式设置为 `CHOICE_MODE_SINGLE` 将：

    1.  向每个项目添加一个`RadioButton`。

    1.  不执行任何操作（这是默认行为）。

    1.  使`ListView`跟踪一个“选中”的项目。

1.  `ListAdapter`定义了`ListView`如何显示其项目。它将在何时被要求重用一个`View`来显示一个项目对象？

    1.  当数据模型无效或更改时。

    1.  在每个项目上，用于橡皮图章。

    1.  当`ListView`重新绘制自身时。

1.  当`ListView`可以滚动时，头部和底部对象将被定位：

    1.  在滚动项目之上和之下。

    1.  水平并排显示，在滚动项目之上和之下。

    1.  与其他项目一起滚动。

# 使用`ExpandableListView`类

`ListView`类非常适合显示中小量的数据，但有时它会向用户展示过多的信息。考虑一个电子邮件应用程序。如果你的用户是重度电子邮件用户，或者订阅了几个邮件列表，他们可能会在文件夹中有数百封电子邮件。即使他们可能不需要滚动超过前几封，看到滚动条缩小到只有几像素大小，对用户的心理影响并不好。

在桌面邮件客户端中，你经常会按时间将邮件列表分组：今天、昨天、本周、本月以及更早（或类似）。Android 提供了`ExpandableListView`以实现这种类型的分组。每个项目嵌套在一个组内，用户可以显示或隐藏组。这有点像树形视图，但始终只嵌套一个层级（你不能将项目显示在组外）。

### 提示

**大量的`ExpandableListView`组**

有时即使是`ExpandableListView`也可能不足以将数据量保持在合理长度。在这些情况下，考虑为用户提供组中的前几个项目，并在最后添加一个特殊的**查看更多**项目。或者，对组使用`ListView`，对嵌套项目使用单独的`Activity`。

## 创建`ExpandableListAdapter`实现

由于`ExpandableList`类包含两个详细级别，它不能与只处理单一级别的普通`ListAdapter`一起工作。相反，它包含了`ExpandableListAdapter`，后者使用两组方法：一组用于组级别，另一组用于项目级别。在实现自定义`ExpandableListAdapter`时，通常最简单的方法是让你的实现继承自`BaseExpandableListAdapter`，因为它提供了事件注册和触发的实现。

`ExpandableListAdapter` 会在每个组项的左侧放置一个箭头指针，以指示组是打开还是关闭（类似于下拉/组合框）。箭头是在由 `ExpandableListAdapter` 返回的组 `View` 对象上方渲染的。为了防止你的组标签被这个箭头部分遮挡，你需要为列表项 `View` 结构添加填充。列表项的默认填充可以通过主题参数 `expandableListPreferredItemPaddingLeft` 获取，你可以使用它：

```kt
android:paddingLeft=
    "?android:attr/expandableListPreferredItemPaddingLeft"
```

为了保持 `ExpandableListView` 的外观一致性，建议你为 `ExpandableListView` 的普通（子）项目添加相同数量的填充（以保持它们的文本与父组对齐），除非你在左侧放置一个项目，如图标或复选框。

## 尝试英雄 - 订购定制比萨

在 `Mick's Pizza` 示例中，我们将创建一个分类的比萨配料菜单。每个配料包括一个名称，以及它是否在比萨上（'on' 或 'off'），或者需要'extra'（例如，额外芝士）。每个项目使用两个水平排列的 `TextView` 对象。右侧的 `TextView` 可以显示配料名称。当不包含配料时，左侧的 `TextView` 为空，包含配料时为 `On`，用户想要比通常更多配料时为 `Extra`。

创建一个对象模型，包含 `ToppingCatagory` 对象，其中包含一个名称和 `PizzaTopping` 对象数组。你需要记录每个配料是否被点单以及数量。

你还需要实现一个 `PizzaToppingAdapter` 类，扩展 `BaseExpandableListAdapter` 类。为组标签使用默认的 Android `simple_expandable_list_item_1` 布局资源，为项目标签使用一个新的定制布局资源。

当用户点击一个比萨配料时，它的状态会在三个值之间变化：**Off**，**On**，和 **Extra**。

### 注意

使用 `ListView.getAdapter()` 方法不会返回你的 `ExpandableListAdapter` 实现，而是一个包装器。要获取原始的 `ExpandableListAdapter`，你需要使用 `getExpandableListAdapter()` 方法。你还需要使用 `ExpandableListView.OnChildClickListener` 接口来接收点击事件。

当你的新 `Activity` 完成时，你应该有一个看起来像以下的屏幕：

![尝试英雄 - 订购定制比萨](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_02_07.jpg)

# 使用 GridView 类

`GridView` 是一个具有固定列数的 `ListView`，从左到右，从上到下排列。标准的（未定主题的）Android 应用程序菜单像 `GridView` 一样排列。`GridView` 类使用与 `ListView` 完全相同的 `ListAdapter` 格式。然而，由于其固定的列数，`GridView` 非常适合图标列表。

### 提示

**有效使用 GridViews**

与`ListView`相比，`GridView`可以在单个屏幕上显示更多的信息，但代价是显示的文本信息较少。从可用性的角度来看，图标通常比文本更容易操作。由于它们的颜色，图标可以比文本更快地被识别。当您有可以使用图标表示的信息时，以这种方式显示它是一个好主意。但是，请记住，图标需要在单个屏幕内保持唯一性，最好是在整个应用程序内。

在下一个示例中，我们将使用`GridView`构建**四桶水果**菜单。`GridView`将为菜单上的每个项目提供一个图标，以及图标下方的项目名称。因此，完成后，它看起来将非常像标准的 Android 应用程序菜单。下一个示例将重点介绍`ListAdapter`的实现，因为它与我们为**汉堡店**构建的`ListAdapter`大致相同。

### 提示

**触摸屏设备上的图标**

在触摸屏设备上考虑图标非常重要。它们需要比平时更具自解释性，或者需要伴随一些文本。使用触摸屏很难提供像工具提示这样的上下文帮助。如果用户正在触摸对象，它通常会被他们的手指和/或手遮住，使得图标和工具提示不可见。

# 动手操作——创建水果图标的时间到了。

为了将各种类型的水果显示为图标，我们将需要创建一个布局 XML 文件。`GridView`中的每个图标都将作为此布局的一个实例表示，与`ListView`中表示列表项目的方式完全相同。我们为图标创建每个项目作为`ImageView`，并在其下方为标签创建一个`TextView`。

1.  在`res/layout`目录中创建一个名为`fruit_item.xml`的文件。

1.  将图标的根元素声明为垂直的`LinearLayout`：

    ```kt
    <LinearLayout

        android:orientation="vertical"
        android:layout_width="fill_parent"
        android:layout_height="fill_parent">
    ```

1.  创建将作为我们图标的`ImageView`元素：

    ```kt
    <ImageView android:id="@+id/icon"
        android:layout_width="fill_parent"
        android:layout_height="wrap_content"/>
    ```

1.  接下来，创建将作为标签的`TextView`元素：

    ```kt
    <TextView android:id="@+id/text"
        android:textSize="@dimen/item_description_size"
        android:layout_width="fill_parent"
        android:layout_height="wrap_content"
        android:gravity="center|center_vertical" />
    ```

## *刚才发生了什么？*

`fruit_item.xml`文件是我们菜单图标的非常简单的布局，也可以用于许多其他类型的图标，表现为网格形式。`ImageView`对象默认会尝试将其内容缩放到其尺寸。在我们之前的示例中，根`LinearLayout`的宽度和高度定义为`fill_parent`。当在`GridView`中作为单个项目放置时，使用`fill_parent`作为大小将导致`LinearLayout`填充为该网格项目提供的空间（不是整个`GridView`）。

## 在`GridView`中显示图标

我们需要一个对象模型和`ListAdapter`，以便在`GridView`中将水果显示给用户。此时，适配器相当直接。它是在一个项目类和为图标定义的布局 XML 之上构建的正常`ListAdapter`实现。

对于每种水果，我们需要一个同时保存水果名称和图标的对象。在根包中创建一个 `FruitItem` 类，并使用以下代码：

```kt
class FruitItem {
    final String name;
    final int image;

    FruitItem(String name, int image) {
        this.name = name;
        this.image = image;
    }
}
```

在前面的代码中，我们将水果的图标图像作为一个整数引用。在 Android 中引用应用程序资源和 ID 时，总是使用整数。在这个例子中，我们假设所有不同类型的水果都有一个作为应用程序资源的图标。另一个选项是每个 `FruitItem` 持有一个对 `Bitmap` 对象的引用。然而，这意味着当 `FruitItem` 可能不在屏幕上时，需要将完整的图像保存在内存中。

为了让 Android Asset Packaging Tool 识别并存储图标，你需要将它们放在 `res/drawable` 目录中。

### 提示

**安卓图像资源**

通常，在 Android 中，将位图图像存储为 PNG 文件被认为是一个好习惯。由于你将要从代码中访问这些文件，请确保它们具有 Java 友好的文件名。PNG 格式（与 JPG 不同）是无损的，可以具有不同的颜色深度，并且正确处理透明度。这使得它整体上成为一个很棒的图像格式。

# 是时候行动了——构建水果菜单

对于 **四个水果桶菜单**，我们需要一个 `ListAdapter` 实现，以将 `FruitItem` 对象渲染到 `fruit_item.xml` 布局资源中。我们还需要一个 `GridView` 的布局资源，我们将在新的 `Activity` 类中加载它。

1.  在项目的根包中创建一个名为 `FruitAdapter` 的类，继承自 `BaseAdapter`。

1.  `FruitAdapter` 需要保存并代表一个 `FruitItem` 对象数组。使用与 `BurgerAdapter` 相同的结构实现该类。

1.  在 `ListAdapter.getView` 方法中，按照 `fruit_item.xml` 布局资源中定义的标签和图标进行设置：

    ```kt
    FruitItem item = items[index];
    TextView text = ((TextView)view.findViewById(R.id.text));
    ImageView image = ((ImageView)view.findViewById(R.id.icon));
    text.setText(item.name);
    image.setImageResource(item.image);
    ```

1.  创建一个新的布局资源，用于保存我们将用于 **四个水果桶菜单** 的 `GridView`，并将其命名为 `res/layout/four_buckets.xml`。

1.  使用三列 `GridView` 填充新的布局资源：

    ```kt
    <GridView 

        android:numColumns="3"
        android:horizontalSpacing="5dip"
        android:verticalSpacing="5dip"
        android:layout_width="fill_parent"
        android:layout_height="fill_parent"/>
    ```

## *刚才发生了什么？*

新的 `four_buckets.xml` 布局资源中只有一个 `GridView`。这与我们迄今为止编写的其他布局资源不同，尤其是 `GridView` 没有 ID。对于这个例子，水果菜单 `Activity` 将只包含 `GridView`，因此无需 ID 引用或布局结构。我们还指定了水平和垂直间距为 `5dip`。`GridView` 对象的默认设置是在其单元格之间没有间距，这使得内容相当紧凑。为了使内容之间稍微有些间隔，我们要求在各个单元格之间有一些空白。

# 是时候行动了——创建 FourBucketsActivity

由于我们使用的是只有一个`GridView`的布局资源，并且没有 ID 引用，我们将逐步创建`Activity`。与之前的`Activity`实现不同，我们需要直接引用在`four_buckets.xml`中定义的`GridView`，这意味着需要手动加载它。

1.  从在你的项目的根包中创建一个新类开始：

    ```kt
    public class FourBucketsActivity extends Activity {
    ```

1.  重写`onCreate`方法，并调用父类实现：

    ```kt
    protected void onCreate(final Bundle istate) {
        super.onCreate(istate);
    ```

1.  为你的`Activity`对象获取`LayoutInflator`实例：

    ```kt
    LayoutInflater inflater = getLayoutInflater();
    ```

1.  充气`four_buckets.xml`资源，并将其内容直接转换为`GridView`对象：

    ```kt
    GridView view = (GridView)inflater.inflate(
            R.layout.four_buckets,
            null);
    ```

1.  将`view`对象的`ListAdapter`设置为新`FruitAdapter`类的实例，并用一些`FruitItem`对象填充新的`FruitAdapter`：

    ```kt
    view.setAdapter(new FruitAdapter(
            new FruitItem("Apple", R.drawable.apple),
            new FruitItem("Banana", R.drawable.banana),
            new FruitItem("Black Berries", R.drawable.blackberry),
            // and so on
    ```

1.  使用`setContentView`使`GridView`成为你的根`View`对象：

    ```kt
    setContentView(view);
    ```

1.  在你的`AndroidManifest.xml`中注册你的`FourBucketsActivity`类。

1.  向`SelectRestaurantActivity`添加一个案例，当用户选择时启动新的`FourBucketsActivity`。

## *刚才发生了什么？*

你刚刚完成了**四桶水果**菜单。如果你将应用程序重新安装到你的模拟器中，你现在将能够去订购水果（只需小心准备好 16 吨的重量，以防送货员攻击你）。

如果你查看`Activity`文档，你会注意到虽然有一个`setContentView`方法，但没有相应的`getContentView`方法。仔细查看，你会注意到`addContentView`方法。`Activity`对象可以有任意数量的“内容”`View`对象附加到它上面。这使得任何有用的`getContentView`方法的实现变得不可能。

为了克服这个限制，我们自己充气了布局。使用的`getLayoutInflator()`方法只是`LayoutInflator.from(this)`的简写。我们没有使用 ID 和`findViewById`，而是直接将返回的`View`转换为`GridView`，因为我们的`four_buckets.xml`文件只包含这个（与`ArrayAdapter`类处理`TextView`对象的方式类似）。如果我们想要更抽象一点，我们可以将其转换为`AdapterView<ListAdapter>`，在这种情况下，我们可以将文件中的实现替换为`ListView`。然而，这对于这个例子来说并没有太大帮助。

如果你现在重新安装并运行应用程序，你的新`FourBucketsActivity`将展示一个类似以下的屏幕：

![刚才发生了什么？](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ui-dev/img/4484_02_08.jpg)

## 尝试英雄——山姆寿司

菜单上的最后一家餐厅是`Sam's Sushi`。尝试使用`Spinner`类和`GridView`创建一个复合寿司菜单。将下拉菜单放在屏幕顶部，提供不同类型寿司的选项：

+   刺身

+   麻辣卷

+   寿司

+   押寿司

+   加州卷

+   时尚三明治

+   手卷

在`Spinner`下方，使用`GridView`显示用户可以订购的每种不同类型鱼的图标。以下是一些建议：

+   金枪鱼

+   黄尾鱼

+   鲷鱼

+   鲑鱼

+   鳗鱼

+   海胆

+   鱿鱼

+   虾

`Spinner` 类使用了 `SpinnerAdapter` 而不是 `ListAdapter`。`SpinnerAdapter` 包含了一个额外的 `View` 对象，它表示下拉菜单。这通常是指向 `android.R.layout.simple_dropdown_item_1line` 资源的引用。然而，对于这个例子，你或许可以使用 `Spinner` XML 元素上的 `android:entries` 属性。

# 概述

数据展示是移动应用程序最常见的要求之一，Android 有许多不同的选项可用。`ListView` 可能是标准 Android 套件中最常用的控件之一，对其样式进行设置可以使其用来显示不同数量的数据，从单行菜单项到多行的待办事项笔记。

`GridView` 实际上是 `ListView` 的表格版本，非常适合向用户展示图标视图。图标比文本有巨大的优势，因为用户可以更快地识别它们。图标还可以占用更少的空间，在 `GridView` 中，你可以在竖屏屏幕上轻松地放置四到六个图标，而不会让用户界面显得杂乱或难以操作。这也为其他项目显示释放了宝贵的屏幕空间。

构建自定义 `Adapter` 类不仅允许你完全控制 `ListView` 的样式，还可以决定数据来源以及如何加载数据。例如，你可以通过使用在 Web 服务响应实际数据之前生成虚拟 `View` 对象的 `Adapter` 直接从 Web 服务加载数据。仔细查看默认的 `Adapter` 实现，它们通常可以满足你的需求，尤其是与自定义布局资源结合使用时。

在下一章中，我们将看看 Android 提供的一些不那么通用、更加专业的 `View` 类。与 Android 中的几乎所有事物一样，默认值可能很具体，但它们可以通过多种方式定制，以适应一些非常特殊的需求。
