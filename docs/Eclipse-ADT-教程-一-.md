# Eclipse ADT 教程（一）

> 原文：[`zh.annas-archive.org/md5/D0CC09ADB24DCE3B2F724DF3004C1363`](https://zh.annas-archive.org/md5/D0CC09ADB24DCE3B2F724DF3004C1363)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

欢迎阅读《*Android 设计模式与最佳实践*》，这是一本全面介绍如何利用经过验证的编程哲学、设计模式使你的应用程序发挥最大价值的指南。这些模式为解决开发者面临的许多开发问题提供了逻辑清晰且优雅的方法。这些模式作为指南，为从问题到解决方案的清晰路径提供了指导，尽管应用设计模式本身并不能保证最佳实践，但它将极大地促进这个过程，并使发现设计缺陷变得更加容易。设计模式可以在许多平台上实施，并使用多种编程语言编写。一些代码库甚至将模式作为其内部机制的一部分，许多读者可能已经熟悉 Java 的 Observer 和 Observable 类。我们将要探讨的 Android SDK 大量使用了多种模式，如工厂、生成器和监听器（实际上只是观察者模式）。尽管我们会涵盖这些内置的设计模式，但本书主要探讨我们如何构建自己的、定制的模式，并将它们应用于 Android 开发中。本书不是依次介绍每个设计模式，而是从开发者的视角出发，通过应用程序开发的各个方面探索在构建 Android 应用程序过程中可能出现的个别设计模式。为了明确这一旅程，我们将专注于一个单一的虚构应用程序，旨在支持小企业。这将带领我们从应用程序的构思到发布，在此过程中涵盖 UI 设计、内部逻辑和用户交互等主题。在每一个步骤中，我们都会探索与该过程相关的设计模式，首先探索模式的抽象形式，然后将其应用于特定情况。通过本书的学习，你将了解如何将设计模式应用于 Android 开发的各个方面，以及使用它们如何有助于最佳实践。设计模式的概念比任何特定的模式本身都更为重要。模式可以也应该根据我们的具体目的进行调整，通过这种方式学习应用程序开发，我们甚至可以继续创建完全原创的模式。

# 本书涵盖的内容

第一章，*设计模式*，介绍了开发环境，以及两种常见的设计模式：工厂模式和抽象工厂模式。

第二章，*创建型模式*，涵盖了材料与界面设计，探索了设计支持库和生成器设计模式。

第三章，*材料设计模式*，介绍了 Android 用户界面以及一些最重要的材料设计组件，如应用栏和滑动导航抽屉。这将介绍菜单和操作图标以及如何实现它们，以及如何使用抽屉监听器来检测用户活动。

第四章，*布局模式*，从前一章开始，进一步深入探讨 Android 布局设计模式以及如何使用重力和权重来创建在各种设备上工作的布局。这将引导我们了解 Android 如何处理设备方向、屏幕大小和形状差异。介绍了策略模式并进行了演示。

第五章，*结构型模式*，深入探讨了设计库，并创建了一个由协调布局管理的布局，其中包含一个回收视图。这需要探索适配器设计模式，首先内部版本，然后我们自己构建一个，以及桥梁模式、外观模式和过滤模式。

第六章，*激活型模式*，展示了如何将模式直接应用于我们的应用。我们涵盖了更多设计库功能，如可折叠工具栏、滚动和分隔线。我们创建了一个自定义对话框，由用户活动触发。我们重新审视了工厂模式，并展示如何使用构建器模式来填充 UI。

第七章，*组合模式*，介绍并演示了两种新的结构型模式：原型和装饰器，涵盖它们的灵活性。然后我们将其付诸实践，使用这些模式控制由不同的复合按钮（如开关和单选按钮组）组成的 UI。

第八章，*组合型模式*，专注于组合模式以及它可以在许多情况下如何使用和如何选择正确的情况。然后我们继续在实践演示中使用它来填充嵌套的 UI。这导致了持久数据的存储和检索，使用内部存储、应用文件，最终以共享偏好设置的形式存储用户设置。

第九章，*观察型模式*，探讨了从一个活动过渡到另一个活动时涉及的视觉过程，以及这如何能远超出简单的装饰。读者将学习如何应用过渡和共享元素，以有效地使用移动设备的有限屏幕空间，并简化应用程序的使用和操作。

第十章，*行为型模式*，专注于主要的行为模式，如模板、策略、访问者和状态。它为每个模式提供了工作演示，并介绍了它们的灵活性和使用方法。

第十一章，*可穿戴模式*，展示了 Android Wear、TV 和 Auto 的工作原理，演示如何逐个设置和配置。我们检查这些与标准手持应用之间的区别。

第十二章，*社交模式*，展示了如何添加网络功能和社交媒体。首先探索 WebView 以及如何用它创建内部网页应用。接下来，探讨如何将我们的应用连接到 Facebook，展示这是如何完成的以及我们可以用它做什么。章节最后检查其他社交平台，如 Twitter。

第十三章，*发布模式*，涵盖了安卓应用的部署、发布和盈利。引导读者完成注册和发布过程，我们查看广告选项以及哪些最适合哪种用途。最后，我们通过一些部署的技巧和诀窍来探讨如何最大化潜在用户。

# 阅读本书所需的材料

Android Studio 和 SDK 都是开源的，可以从一个单独的包中安装。除了一处小例外，这在相关章节中有详细说明，这是本书所需的全部软件。

# 本书的目标读者

本书面向具有一定基础安卓开发经验的安卓开发者。要充分理解本书内容，必须具备基本的 Java 编程知识。

# 约定

在本书中，你会发现多种文本样式，用于区分不同类型的信息。以下是一些样式示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 处理方式将如下显示："向你的布局中添加三个 TextView，然后在 MainActivity 的`onCreate()`方法中添加代码。"

代码块设置如下：

```kt
Sequence prime = (Sequence) SequenceCache.getSequence("1");
primeText.setText(new StringBuilder()
        .append(getString(R.string.prime_text))
        .append(prime.getResult())
        .toString());
```

当我们希望引起你注意代码块中的特定部分时，相关的行或项目会以粗体显示：

```kt
    @Override
    public String getDescription() {
        return filling.getDescription() + " Double portion";
    }
```

任何命令行输入或输出都会如下编写：

```kt
/gradlew clean:

```

**新术语**和**重要词汇**会以粗体显示。你在屏幕上看到的词，例如菜单或对话框中的，会像这样出现在文本中："在你的手机上启用开发者选项。在某些型号上，这可能需要导航至**设置** | **关于手机**"

### 注意事项

警告或重要提示会以这样的框显示。

### 提示

技巧和诀窍会像这样显示。

# 读者反馈

我们欢迎读者的反馈。告诉我们您对这本书的看法——您喜欢或不喜欢什么。读者的反馈对我们很重要，因为它帮助我们开发出您真正能从中获得最大收益的标题。要给我们发送一般反馈，只需发送电子邮件到 feedback@packtpub.com，并在邮件的主题中提及书名。如果您在某个主题上有专业知识，并且有兴趣撰写或为书籍做出贡献，请查看我们的作者指南[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

既然您已经拥有了 Packt 的一本书，我们有一些事情可以帮助您充分利用您的购买。

## 下载示例代码

您可以从[`www.packtpub.com`](http://www.packtpub.com)的账户下载本书的示例代码文件。如果您在别处购买了这本书，可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)注册，我们会直接将文件通过电子邮件发送给您。

您可以通过以下步骤下载代码文件：

1.  使用您的电子邮件地址和密码登录或注册我们的网站。

1.  将鼠标指针悬停在顶部的**支持**标签上。

1.  点击**代码下载和勘误**。

1.  在**搜索**框中输入书名。

1.  选择您要下载代码文件的书。

1.  从下拉菜单中选择您购买本书的地方。

1.  点击**代码下载**。

下载文件后，请确保您使用最新版本的以下软件解压或提取文件夹：

+   WinRAR / 7-Zip 用于 Windows

+   Zipeg / iZip / UnRarX 用于 Mac

+   7-Zip / PeaZip 用于 Linux

本书的代码包也托管在 GitHub 上，地址为[`github.com/PacktPublishing/Android-Design-Patterns-and-Best-Practice`](https://github.com/PacktPublishing/Android-Design-Patterns-and-Best-Practice)。我们还有其他丰富的书籍和视频代码包，可以在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)查看。请查看！

## 下载本书的彩色图片

我们还为您提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。彩色图片将帮助您更好地理解输出的变化。您可以从[`www.packtpub.com/sites/default/files/downloads/AndroidDesignPatternsandBestPractice.pdf`](https://www.packtpub.com/sites/default/files/downloads/AndroidDesignPatternsandBestPractice.pdf)下载此文件。

## 勘误

尽管我们已经竭尽全力确保内容的准确性，但错误仍然会发生。如果您在我们的书中发现了一个错误——可能是文本或代码中的错误——如果您能向我们报告，我们将不胜感激。这样做，您可以避免其他读者感到沮丧，并帮助我们改进该书的后续版本。如果您发现任何勘误信息，请通过访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书籍，点击**勘误提交表单**链接，并输入您的勘误详情来进行报告。一旦您的勘误信息得到验证，您的提交将被接受，勘误信息将被上传到我们的网站或添加到该标题勘误部分下现有的勘误列表中。

要查看之前提交的勘误信息，请前往[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)，并在搜索字段中输入书籍名称。所需信息将显示在**勘误**部分下。

## 盗版

网络上对版权材料的盗版行为是所有媒体持续面临的问题。在 Packt，我们非常重视对我们版权和许可的保护。如果您在互联网上以任何形式遇到我们作品的非法副本，请立即提供其位置地址或网站名称，以便我们可以寻求补救措施。

如果您发现疑似盗版材料，请通过 copyright@packtpub.com 联系我们，并提供链接。

我们感谢您帮助保护我们的作者和我们提供有价值内容的能力。

## 问题

如果您对这本书的任何方面有问题，可以通过 questions@packtpub.com 联系我们，我们将尽力解决问题。


# 第一章：设计模式

设计模式长期以来被认为是解决常见软件设计问题最可靠和最有用的方法之一。模式为经常出现的发展问题提供了一般性和可重用的解决方案，例如如何在不对对象结构进行修改的情况下添加功能，或者如何最佳地构建复杂对象。

应用模式有几个优点，不仅仅是这种方法帮助开发者遵循最佳实践，以及它如何简化大型项目的管理。这些好处是通过提供可以重复使用的整体软件结构（模式）来实现的，以解决类似问题。这并不意味着代码可以从一个项目简单地剪切和粘贴到另一个项目，而是这些概念本身可以在许多不同情况下反复使用。

应用编程模式有许多其他好处，本书的某个部分将会涵盖这些内容，但以下一两个好处是现在值得一提的：

+   模式为团队工作的开发者之间提供了一种高效的通用语言。当一个开发者将一个结构描述为例如**适配器**或**外观**时，其他开发者能够理解其含义，并会立即识别代码的结构和目的。

+   模式提供的额外抽象层使得对已经处于开发阶段的代码进行修改和调整变得更加容易。甚至还有专门为这些情况设计的模式。

+   模式可以在许多尺度上应用，从项目的整体架构结构到最基本对象的制造。

+   应用模式可以大大减少所需的内联注释和一般文档的数量，因为模式本身也充当了自身的描述。仅类的名称或接口就能解释其目的和在模式中的位置。

安卓开发平台非常适合采用模式，因为不仅应用程序主要是用 Java 创建的，而且 SDK 包含许多自身使用模式的 API，例如用于创建对象的**工厂**接口和用于构建对象的**建造者**。像**单例**这样的简单模式甚至可以作为模板类类型使用。在本书中，我们不仅将看到如何构建自己的大型模式，还将了解如何利用这些内置结构来促进最佳实践并简化编码。

在本章中，我们首先简要概述整本书的布局、我们将使用的模式、我们接近它们的顺序，以及我们将构建的演示应用，看看如何在现实世界中应用模式。接下来，我们将快速检查 SDK 以及哪些组件将最好地协助我们的旅程，尤其是**支持库**所扮演的角色，使我们能够同时为多个平台版本开发。没有比实际经验更好的学习方式，因此本章的剩余部分将用于开发一个非常简单的演示应用，并使用我们的第一个模式——**工厂模式**及其相关的**抽象工厂**模式。

在本章中，你将学习以下内容：

+   模式如何分类以及本书涵盖哪些模式

+   本书演示应用的目的

+   如何定位平台版本

+   支持库的作用是什么

+   工厂模式是什么以及如何构建一个工厂模式

+   如何遵循 UML 类图

+   如何在实机和虚拟设备上测试应用

+   如何在运行时监控应用

+   如何使用简单的调试工具来测试代码

+   抽象工厂模式是什么以及如何使用它

# 本书如何运作

本书的目的是展示设计模式的运用如何直接协助开发 Android 应用。在本书的进程中，我们将专注于开发一个完整的客户端移动应用，特别关注在 Android 开发过程中何时、为何以及如何使用这些模式。

历史上，对于什么构成模式存在一定争议。然而，在 Erich Gamma、Richard Helm、Ralph Johnson 和 John Vlissides 于 1994 年出版的《设计模式》一书中提出的 23 种模式，被称为四人帮的模式，被广泛认为是权威集合，并为我们在软件工程中可能遇到的几乎所有问题提供解决方案，因此这些模式将成为本书的核心。这些模式可以分为三类：

+   **创建型** - 用于创建对象

+   **结构型** - 用于组织对象群组

+   **行为型** - 用于对象之间的通信

本书的实践性质意味着我们不会按照这里出现的顺序来处理这些类别；相反，我们将在开发应用时自然地探索各个模式，这通常意味着首先创建一个结构。

将所有设计模式集成到一个应用程序中是困难、笨拙且不现实的，因此我们将尝试应用尽可能多的看起来现实的模式。对于那些我们决定不直接使用的模式，我们至少会探讨我们可能如何使用它们，并且在每种情况下至少提供一个实际的使用示例。

模式并非刻在石头上，也不能解决所有可能的问题。在本书的末尾，我们将探讨一旦掌握了这个主题，我们如何可以创建自己的模式或调整现有的模式以适应那些既定模式不适用的情况。

简而言之，模式并非一套规则，而是一系列从已知问题通往经过验证的解决方案的熟悉路径。如果你在路上发现了一条捷径，那么尽可以采用它。如果你坚持这样做，那么你就创造了自己的一种模式，这种模式与我们在这里将要介绍的传统模式一样有效。

书的前几章主要关注 UI 设计，并介绍了一些基本的设计模式及其概念上的工作原理。从大约第六章《激活模式》开始，我们将开始将这些和其他模式应用于现实世界的例子，特别是针对一个应用程序。最后几章集中在开发的最后阶段，例如，调整应用程序以适应不同的设备，这项任务几乎是专为设计模式而设的，旨在达到最广泛的市场，以及如何使我们的应用程序盈利。

### 注意事项

如果你刚接触 Android 开发，前两三章中的说明会讲解得非常详细。如果你已经熟悉 Android 开发，你将能够跳过这些部分，专注于模式本身。

在深入我们第一个模式之前，仔细看看在本书过程中将要构建的应用程序，以及它所带来的挑战和机遇是有意义的。

# 我们将要构建的内容

如前所述，在本书的过程中，我们将构建一个虽小但完整的 Android 应用程序。现在了解一下我们将要构建的内容及其原因会是一个好主意。

我们将设身处地地考虑一个独立 Android 开发者的角色，这位开发者被一个潜在客户接近，这个客户经营着一家小企业，制作并配送新鲜三明治到当地的几栋办公楼。我们的客户面临几个问题，他们认为可以通过一个移动应用程序来解决。为了了解应用程序可能提供的解决方案，我们将把情况分为三个部分：场景、问题和解决方案。

## 场景概述

客户运营着一家小而成功的业务，为附近的上班族制作并送递新鲜的三明治，让他们可以在办公桌上购买并食用。三明治非常美味，由于口碑宣传，越来越受欢迎。业务有很大的扩展机会，但商业模式中存在一些明显的低效问题，客户认为可以通过使用移动应用程序来解决。

## 问题所在

客户几乎无法预测需求。很多时候某种三明治做多了，导致浪费。同样，也有准备三明治品种不足的时候，导致销售额的损失。不仅如此，顾客提供的口碑宣传也限制了业务扩展到较小的地理区域。客户没有可靠的方法来判断是否值得投资更多员工、摩托车以扩大送餐范围，甚至是否在其他镇区开设新的厨房。

## 解决方案

一款面向所有客户免费的移动应用程序不仅解决了这些问题，还提供了一系列全新的机会。不仅仅是应用程序能够解决无法预料的需求问题；我们现在有机会将这个业务提升到一个全新的层次。为何只向顾客提供固定菜单呢？我们可以提供让他们从一系列食材中构建自己的个性化三明治的机会。也许他们喜欢我们客户已经制作好的芝士和腌菜三明治，但想要加一两片苹果，或者更喜欢芒果酱而不是腌菜。也许他们是素食主义者，更喜欢从选择中过滤掉肉类产品。也许他们有过敏症。所有这些需求都可以通过一个设计良好的移动应用程序来满足。

此外，口碑宣传的地理限制，甚至当地广告如广告牌或当地报纸上的通知，都无法指示业务在更大舞台上的可能成功程度。而另一方面，社交媒体的使用不仅可以让我们客户清晰地了解当前趋势，还能将信息传播给尽可能广泛的受众。

我们的客户现在不仅能够准确判断他们业务的范围，还能添加完全新的、与现代数字生活特性相关的功能，比如应用程序的游戏化。竞赛、谜题和挑战可以为吸引顾客提供全新的维度，并呈现一种强大的增加收入和市场影响力的技术手段。

面前的任务现在更加清晰，我们现在可以开始编码了。我们将从工厂模式的简单演示开始，一路上看一些在开发过程中会用到的一些 SDK 功能。

# 定位平台版本

为了跟上最新技术，Android 平台的新版本会频繁发布。作为开发者，这意味着我们可以将最新的功能和发展融入到我们的应用程序中。显然，这样做的缺点是只有最新的设备才能运行这个平台，而这些设备在整个市场上只占很小的一部分。来看看开发者仪表板上的这张图表：

![目标平台版本](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/B05685_01_01.jpg)

仪表板可以在[developer.android.com/about/dashboards/index.html](http://developer.android.com/about/dashboards/index.html)找到，其中包含了这个以及其他最新的信息，这些信息在项目初步规划时非常有用。

如你所见，绝大多数的 Android 设备仍然运行在较旧的平台上。幸运的是，Android 允许我们针对这些旧设备进行开发，同时还能融入最新平台版本的功能。这主要是通过使用**支持库**和设置最低 SDK 级别来实现的。

决定要针对哪些平台进行开发是我们需要做出的第一个决定之一，尽管我们可以在以后的日期更改这一点，但尽早决定要融入哪些功能以及了解这些功能在旧设备上的表现，可以大大简化整个任务。

要了解如何做到这一点，请启动一个新的 Android Studio 项目，随意为其命名，选择**手机和平板电脑**作为形态因素，并选择**API 16**作为**最低 SDK**。

在模板列表中，选择**空活动**，其他保持默认设置。

![目标平台版本](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/B05685_01_02.jpg)

Android Studio 会自动选择可用的最高 SDK 版本作为目标级别。要查看如何应用，请从项目面板中打开`build.gradle (Module: app)`文件，并注意`defaultConfig`部分，它将类似于以下代码：

```kt
defaultConfig { 
    applicationId "com.example.kyle.factoryexample" 
    minSdkVersion 16 
    targetSdkVersion 25 
    versionCode 1 
    versionName "1.0" 
} 

```

这确保了我们的项目将针对这个 API 级别范围正确编译，但如果我们正在构建一个打算发布的 app，那么我们需要告诉 Google Play 商店哪些设备上可以提供我们的 app。这可以通过`build.gradle`模块文件来完成，如下所示：

```kt
minSdkVersion 21 
targetSdkVersion 24 

```

我们还需要编辑`AndroidManifest.xml`文件。对于这个例子，我们将在`manifest`节点中添加以下`uses-sdk`元素：

```kt
<uses-sdk 
    android:minSdkVersion="16" 
    android:targetSdkVersion="25" /> 

```

一旦我们确定了我们希望针对的平台范围，我们就可以继续了解支持库如何让我们在许多最旧的设备上融入许多最新的功能。

# 支持库

在构建向后兼容的应用程序方面，支持库无疑是我们的最强大工具。实际上，它是一系列单独的代码库，通过提供标准 API 中找到的类和接口的替代品来工作。

大约有 12 个单独的库，它们不仅提供兼容性；它们还包括常见的 UI 组件，如滑动抽屉和浮动操作按钮，否则这些组件必须从头开始构建。它们还可以简化针对不同屏幕大小和形状的开发过程，以及添加一个或两个杂项功能。

### 注意

由于我们是在 Android Studio 中进行开发，因此应该下载**支持仓库**而不是支持库，因为该仓库是专门为 Studio 设计的，提供的功能完全相同，而且效率更高。

在本章中我们正在工作的示例中，将不使用任何支持库。项目包含的唯一支持库是`v7 appcompat library`，它在我们开始项目时自动添加。在书中，我们将经常回到支持库，所以现在，我们可以集中精力应用我们的第一个模式。

# 工厂模式

工厂模式是最常用的创建型模式之一。顾名思义，它制造东西，或者更准确地说，它创建对象。它的有用之处在于它使用一个通用接口将逻辑与使用分离。了解这一机制的最佳方式就是现在就构建一个。打开我们在前一页或两页之前开始的项目，或者开始一个新项目。对于这个练习来说，最低和目标 SDK 级别并不重要。

### 提示

选择 API 级别为 21 或更高，允许 Android Studio 使用一种称为热交换的技术。这避免了每次运行项目时都完全重新构建项目，极大地加快了应用测试的速度。即使你打算最终针对一个更低的平台，热交换节省的时间也使得在应用开发得差不多时降低这个目标是非常值得的。

我们将要构建一个非常简单的示例应用，该应用生成对象来表示我们三明治制作应用可能提供的不同类型的面包。为了强调这个模式，我们会保持简单，让我们的对象返回的仅是一个字符串：

1.  在项目视图中找到`MainActivity.java`文件。

1.  右键点击它，并创建一个名为`Bread`的**接口**类型的`New | Java Class`：![The factory pattern](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/B05685_01_03.jpg)

1.  完成接口如下：

    ```kt
        public interface Bread { 

            String name(); 
            String calories(); 
        } 

    ```

1.  创建`Bread`的具体类，如下所示：

    ```kt
        public class Baguette implements Bread { 

            @Override 
            public String name() { 
                return "Baguette"; 
            } 

            @Override 
            public String calories() { 
                return " : 65 kcal"; 
            } 
          } 

          public class Roll implements Bread { 

            @Override 
            public String name() { 
                return "Roll"; 
            } 

            @Override 
            public String calories() { 
                return " : 75 kcal"; 
            } 
          } 

          public class Brioche implements Bread { 

            @Override 
            public String name() { 
                return "Brioche"; 
            } 

            @Override 
            public String calories() { 
                return " : 85 kcal"; 
            } 
        } 

    ```

1.  接下来，创建一个名为`BreadFactory`的新类，如下所示：

    ```kt
    public class BreadFactory { 

        public Bread getBread(String breadType) { 

            if (breadType == "BRI") { 
                return new Brioche(); 

            } else if (breadType == "BAG") { 
                return new Baguette(); 

            } else if (breadType == "ROL") { 
                return new Roll(); 
            } 

            return null; 
        } 
    } 

    ```

## UML 图表

理解设计模式的关键在于理解它们的结构以及各组成部分之间的相互关系。查看模式的一个最佳方式是图形化，统一建模语言（UML）类图是完成这一任务的好方法。

考虑一下我们刚才创建的模式以图表的形式表达，如下所示：

![UML diagrams](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/B05685_01_08.jpg)

拥有了我们的模式，需要做的就是看到它的实际效果。在这个演示中，我们将使用模板为我们生成的布局中的 **TextView** 和每次主活动启动时都会调用的 `onCreate()` 方法：

1.  以 **文本** 模式打开 `activity_main.xml` 文件。

1.  为文本视图添加一个 `id`，如下所示：

    ```kt
    <TextView 
        android:id="@+id/text_view" 
        android:layout_width="match_parent" 
        android:layout_height="wrap_content" /> 

    ```

1.  打开 `MainActivity.java` 文件，并编辑 `onCreate()` 方法以匹配以下代码：

    ```kt
    @Override 
    protected void onCreate(Bundle savedInstanceState) { 
        super.onCreate(savedInstanceState); 
        setContentView(R.layout.activity_main); 

        TextView textView = (TextView) findViewById(R.id.text_view); 

        BreadFactory breadFactory = new BreadFactory(); 
        Bread bread = breadFactory.getBread("BAG"); 

        textView.setText(new StringBuilder() 
                .append(bread.name()) 
                .toString()); 
    } 

    ```

    ### 提示

    根据您设置 Android Studio 的方式，您可能需要导入 TextView 控件：`import android.widget.TextView;`。通常，编辑器会提示您，只需按 **Alt + Enter** 就可以导入控件。

您现在可以在模拟器或真实设备上测试这个模式：

![UML 图](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/B05685_01_07.jpg)

初看之下，这或许会让人觉得是实现一个简单目标的一种极其冗长的方式，但模式的魅力正在于此。增加的抽象层使我们能够修改类，而无需编辑我们的活动，反之亦然。随着我们开发更复杂的对象，遇到需要不仅仅一个工厂的情况时，这种实用性会更加明显。

我们在这里创建的例子过于简单，实际上并不需要测试，但现在是一个探索如何在真实和虚拟设备上测试 Android 应用，以及如何监控性能和使用调试工具测试输出而不必添加不必要的屏幕组件的好时机。

# 运行和测试应用

现在市面上有大量的 Android 设备，它们有着各种各样的形状和大小。作为开发者，我们希望我们的应用程序能在尽可能多的设备和形态因素上运行，并且我们希望用最少的编码就能实现这一点。幸运的是，Android 平台非常适合应对这一挑战，它让我们可以轻松调整布局，构建虚拟设备以匹配我们所能想象到的任何形态因素。

### 提示

Google 在 firebase.google.com/docs/test-lab/ 提供了一个非常便捷的基于云的应用测试工具。

显然，虚拟设备是任何测试环境的重要组成部分，但这并不是说直接插入我们自己的设备并在此上进行应用测试就不方便。这不仅比任何模拟器都快，而且正如我们现在将要看到的，设置起来非常简单。

## 连接到真实设备

实际设备不仅比虚拟设备快，还允许我们在真实世界的情况中测试我们的应用。

将真实设备连接到我们的开发环境需要两个步骤：

1.  在您的手机上启用开发者选项。在某些型号上，这可能涉及到导航到 `设置 | 关于手机` 并点击 `Build number` 七次，之后会在设置中添加 `开发者选项`。使用它来启用 **USB 调试** 并选择 **允许模拟位置**。

1.  你现在很可能能够通过 USB 或 WiFi 插件电缆将你的设备连接到工作站，并在打开 Android Studio 时显示出来。如果不是这样，你可能需要打开 SDK 管理器，并从“工具”选项卡安装**Google USB 驱动程序**。在某些罕见的情况下，你可能需要从设备制造商处下载 USB 驱动程序。

实际设备对于快速测试应用程序功能更改非常有用，但要开发应用程序在各种屏幕形状和尺寸上的外观和行为，意味着我们将创建一些虚拟设备。

## 连接到虚拟设备

Android 虚拟设备（AVD）允许开发者自由地实验各种硬件配置的模拟，但它们速度慢，可能会耗尽许多计算机系统的资源，并且缺少实际设备中的许多功能。尽管有这些缺点，虚拟设备仍然是 Android 开发者工具箱中不可或缺的一部分，通过考虑一些事项，可以最小化许多这些障碍：

+   将你的虚拟设备精简到只包含你的应用程序所需的功能。例如，如果你的应用不需要拍照，就从模拟器中移除摄像头功能；以后可以根据需要添加。

+   将 AVD 的内存和存储需求降到最低。当应用程序需要时，可以轻松创建另一个设备。

+   只有在需要测试特定新功能时，才创建具有非常新的 API 级别的 AVD。

+   从测试低屏幕分辨率和密度的虚拟设备开始。这些设备运行速度更快，并且仍然允许你测试不同的屏幕尺寸和宽高比。

+   尝试将资源需求非常大的功能分离出来，单独测试。例如，如果你的应用使用了大量高清晰度的图片集，你可以通过单独测试这个功能来节省时间。

通常构建针对特定目的的虚拟设备比构建一个全能型的设备来测试我们所有的应用程序要快，而且现在有越来越多的第三方 Android 模拟器可用，如*Android-x86*和*Genymotion*，它们通常速度更快且拥有更多开发功能。

值得注意的是，当仅测试布局时，Android Studio 提供了一些强大的预览选项，允许我们在众多形态、SDK 级别和主题上查看我们潜在的用户界面，如下一个图像所示：

![连接到虚拟设备](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/B05685_01_04.jpg)

现在，创建一个基本的 AVD 来运行并测试当前项目。实际上并没有什么需要测试的，但我们将了解如何监控应用程序在运行时的行为，以及如何使用调试监控服务来测试输出，而无需使用设备屏幕，这不是一个吸引人的调试项目的方式。

## 监控设备

下面的演示在模拟设备或真实设备上同样有效，所以选择对你来说最简单的一个。如果你在创建 AVD，那么它不需要大屏幕或高密度屏幕，也不需要大量内存：

1.  打开我们刚才工作的项目。

1.  从`工具 | 安卓`菜单中，启用**ADB 集成**。![监控设备](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/B05685_01_05.jpg)

1.  从同一菜单中，选择**Android 设备监控器**，尽管它可能已经在运行。

1.  现在，在连接的设备上使用 Android Monitor 运行应用程序。

设备监控器在多种方式上非常有用：

+   **监控器**标签可以在运行时使用，以查看实时的系统信息，例如我们的应用使用了多少内存或 CPU 时间。当我们想要查看应用不在前台运行时使用了哪些资源时，这尤其有帮助。

+   监控器可以设置为收集各种数据，如方法跟踪和资源使用，并将这些数据存储为文件，可以在**捕获**窗格中查看（通常可以从左侧边栏打开）。

+   捕获应用运行时的屏幕截图和视频非常简单。

+   **LogCat**是一个特别有用的工具，它不仅可以实时报告应用的行为，而且如我们接下来将看到的，还可以生成用户定义的输出。

使用文本视图测试我们的工厂模式是一种方便但笨拙的方法，但一旦我们开始开发复杂的布局，它很快就会变得非常不方便。一种更优雅的解决方案是使用可以在不影响我们 UI 的情况下查看的调试工具。本练习的其余部分将演示如何做到这一点：

1.  打开`MainActivity.java`文件。

1.  声明以下常量：

    ```kt
    private static final String DEBUG_TAG = "tag"; 

    ```

1.  再次，你可能需要确认导入`android.util.Log;`。

1.  替换`onCreate()`方法中设置文本视图文本的行，使用以下行：

    ```kt
    Log.d(DEBUG_TAG, bread); 

    ```

1.  再次打开设备监控器。这可以通过按**Alt + 6**来完成。

1.  在监控器右上角的下拉菜单中，选择**编辑过滤器配置**。

1.  完成如图所示的对话框：![监控设备](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/B05685_01_06.jpg)

运行应用并测试我们的工厂演示应该在 logcat 监控器中产生类似于这里的输出：

```kt
05-24 13:25:52.484 17896-17896/? D/tag: Brioche
05-24 13:36:31.214 17896-17896/? D/tag: Baguette
05-24 13:42:45.180 17896-17896/? D/tag: Roll

```

### 提示

当然，如果你愿意，你仍然可以使用`System.out.println()`，它将在 ADB 监控器中打印出来，但你将不得不在其他输出中搜索它。

我们已经了解了如何在真实和虚拟设备上测试应用，以及如何使用调试和监控工具在运行时对应用进行询问。现在，我们可以进入一个更真实的情况，涉及不止一个工厂，输出的结果也远比一个双词字符串复杂。

# 抽象工厂模式

制作三明治时，面包只是我们第一个也是最基础的原料；显然，我们需要某种填充物。在编程术语中，这可能意味着像`Bread`一样简单地构建另一个接口，但将其称为`Filling`，并为它提供自己的关联工厂。同样，我们可以创建一个名为`Ingredient`的全局接口，并将`Bread`和`Filling`作为它的示例。无论哪种方式，我们都需要在其他地方进行大量的重新编码。

设计模式范式提供了**抽象工厂模式**，这可能是解决这一困境最灵活的解决方案。抽象工厂仅仅就是**创建其他工厂的工厂**。这种所需的额外抽象层次，在我们考虑到主活动中的顶层控制代码几乎不需要修改（如果有的话）时得到了充分的回报。能够修改低级结构而不影响之前的结构，正是应用设计模式的主要原因之一，当应用于复杂架构时，这种灵活性可以节省许多开发时间，并比其他方法提供更多的实验空间。

## 使用一个以上的工厂工作

下一个项目与上一个项目之间的相似性非常明显，应该是这样；模式最好的事情之一是我们可以重用结构。你可以编辑之前的示例或从头开始。在这里，我们将开始一个新项目；希望这将有助于使模式本身更加清晰。

**抽象工厂**的工作方式与我们的上一个示例略有不同。在这里，我们的活动使用了一个工厂生成器，该生成器进而使用一个抽象工厂类来处理决定调用哪个实际工厂的任务，从而创建哪个具体类。

与之前一样，我们不关心输入和输出的实际机制，而是专注于模式的结构。在继续之前，启动一个新的 Android Studio 项目。可以随意命名，将最低 API 级别设为你喜欢的低水平，并使用空白活动模板：

1.  我们开始，就像之前一样，创建接口；但这次，我们需要两个：一个用于面包，一个用于填充物。它们应该如下所示：

    ```kt
    public interface Bread { 

        String name(); 
        String calories(); 
    } 

    public interface Filling { 

        String name(); 
        String calories(); 
    } 

    ```

1.  与之前一样，创建这些接口的具体示例。为了节省空间，这里我们只创建每种两个。它们几乎都是相同的，所以这里只有一个：

    ```kt
    public class Baguette implements Bread { 

        @Override 
        public String name() { 
            return "Baguette"; 
        } 

        @Override 
        public String calories() { 
            return " : 65 kcal"; 
        } 
    } 

    ```

1.  创建另一个名为`Brioche`的`Bread`类和两种填充物，分别叫做`Cheese`和`Tomato`。

1.  接下来，创建一个可以调用每种类型工厂的类：

    ```kt
    public abstract class AbstractFactory { 

        abstract Bread getBread(String bread); 
        abstract Filling getFilling(String filling); 
    } 

    ```

1.  现在，创建工厂本身。首先，`BreadFactory`：

    ```kt
    public class BreadFactory extends AbstractFactory { 

        @Override 
        Bread getBread(String bread) { 

            if (bread == null) { 
                return null; 
            } 

            if (bread == "BAG") { 
                return new Baguette(); 
            } else if (bread == "BRI") { 
                return new Brioche(); 
            } 

            return null; 
        } 

        @Override 
        Filling getFilling(String filling) { 
            return null; 
        } 
    } 

    ```

1.  然后，`FillingFactory`：

    ```kt
    public class FillingFactory extends AbstractFactory { 

        @Override 
        Filling getFilling(String filling) { 

            if (filling == null) { 
                return null; 
            } 

            if (filling == "CHE") { 
                return new Cheese(); 
            } else if (filling == "TOM") { 
                return new Tomato(); 
            } 

            return null; 
        } 

        @Override 
        Bread getBread(String bread) { 
            return null; 
        } 
    } 

    ```

1.  最后，添加工厂生成器类本身：

    ```kt
    public class FactoryGenerator { 

        public static AbstractFactory getFactory(String factory) { 

            if (factory == null) { 
                return null; 
            } 

            if (factory == "BRE") { 
                return new BreadFactory(); 
            } else if (factory == "FIL") { 
                return new FillingFactory(); 
            } 

            return null; 
        } 
    } 

    ```

1.  我们可以像之前一样测试我们的代码，使用一个调试标签，如下所示：

    ```kt
    AbstractFactory fillingFactory = FactoryGenerator.getFactory("FIL"); 
    Filling filling = fillingFactory.getFilling("CHE"); 
    Log.d(DEBUG_TAG, filling.name()+" : "+filling.calories()); 

    AbstractFactory breadFactory = FactoryGenerator.getFactory("BRE"); 
    Bread bread = breadFactory.getBread("BRI"); 
    Log.d(DEBUG_TAG, bread.name()+" : "+bread.calories()); 

    ```

测试时，这应该在 Android 监视器中产生以下输出：

```kt
com.example.kyle.abstractfactory D/tag: Cheese :  : 155 kcal
com.example.kyle.abstractfactory D/tag: Brioche :  : 85 kcal

```

到本书结束时，每个成分都将是一个复杂的对象，拥有相关的图像和描述性文本、价格、卡路里价值等等。这时遵循模式将真正带来好处，但像这里一个非常简单的例子就能很好地展示出如何使用抽象工厂这样的创建型模式，让我们在不影响客户端代码或部署的情况下对产品进行修改。

与之前一样，通过视觉表示可以增强我们对模式的了解：

![同时使用多个工厂](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/B05685_01_09.jpg)

假设我们想在菜单中包含软饮料。这些既不是面包也不是填充物，我们需要引入一种全新的对象类型。添加这种模式的方案已经制定好了。我们需要一个新的接口，它与其他接口相同，只是叫做`Drink`；它将使用相同的`name()和 calories()`方法，具体的类如`IcedTea`可以按照上面的完全相同的线路实现，例如：

```kt
public class IcedTeaimplements Drink { 

    @Override 
    public String name() { 
        return "Iced tea"; 
    } 

    @Override 
    public String calories() { 
        return " : 110 kcal"; 
    } 
} 

```

我们需要扩展我们的抽象工厂，如下所示：

```kt
abstract Drink getDrink(String drinkType); 

```

当然，我们还需要实现一个`DrinkFactory`类，但这个类的结构与其他工厂相同。

换句话说，我们可以添加、删除、更改，以及随意摆弄项目的细节，而无需真正关心这些更改是如何被我们软件的高级逻辑所感知的。

工厂模式是所有模式中使用最频繁的模式之一。它可以在许多情况下使用，也应该被使用。然而，像所有模式一样，如果不仔细考虑，它可能会被过度使用或使用不足。当我们考虑项目的整体架构时，正如我们将会看到的，还有许多其他模式可供我们使用。

# 总结

考虑到这是一个介绍性的章节，我们已经涵盖了很多内容。我们已经构建了两种最著名和最有用的设计模式的示例，并希望了解它们为什么对我们有用。

我们首先探讨了模式是什么，以及为什么在 Android 环境中可能会使用它们。这得益于我们查看了一下可用的开发工具，以及我们如何以及为什么应该针对特定的平台版本和形态因素进行定位。

然后，我们将这一知识应用于创建两个非常简单的应用程序，这些程序使用了基本的工厂模式，并看到了如何测试并从运行在任何设备上的应用程序中检索数据，无论是真实的还是虚拟的。

这让我们有机会看看其他模式，并考虑在构建一个完全工作的应用程序时使用哪些模式。我们将在下一章更详细地介绍这一点，其中将介绍构建器模式以及如何生成 Android 布局。


# 第二章：创建型模式

在上一章中，我们了解了**工厂模式**及其相关的**抽象工厂模式**。然而，我们以相当普遍的方式查看了这些模式，并没有查看一旦创建后，这些对象如何在 Android 设备上被表示和操作。换句话说，我们构建的模式可以应用于许多其他软件环境，为了使它们更具 Android 特色，我们需要查看 Android UI 及其组成方式。

在本章中，我们将集中讨论如何将我们的产品表现为 Android UI 组件。我们将使用**卡片视图**来展示这些内容，每个卡片将包含一个标题、一幅图像、一些描述性文本以及成分的热量值，如下面的截图所示：

![创建型模式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_02_001.jpg)

这将引导我们初步了解**材料设计**，这是一种强大的、越来越受欢迎的**视觉设计语言**，用于创建清晰直观的 UI。最初为移动设备的小屏幕而设计，材料设计现在被认为是一个非常有价值的 UI 范例，其应用已经从 Android 设备扩展到网站，甚至其他移动平台。

**材料设计**不仅仅是一种时尚，它提供了一系列遵循最佳 UI 构建实践的非常有效的指南。材料设计提供了与我们已经讨论过的编程模式相似的视觉模式。这些模式提供了清晰、简单的操作结构。材料设计涵盖了比例、缩放、排版和间距等概念，所有这些都可以在 IDE 中轻松管理，并由材料设计指南整齐地规定。

当我们了解了如何将我们的成分表现为可操作的 UI 组件后，我们将查看另一种常用的创建型模式，即**构建器模式**。这将展示一种允许我们从单个*配料*对象构建一个*三明治*对象的模式。

在本章中，你将学习如何进行以下操作：

+   编辑材料样式和主题

+   应用调色板

+   自定义文本设置

+   管理屏幕密度

+   包含卡片视图支持库

+   理解 Z 轴深度和阴影

+   将材料设计应用于卡片视图

+   创建构建器模式

尽管可以在任何时候进行更改，但在构建 Android 应用时，我们首先应该考虑的就是配色方案。这是框架允许我们自定义许多熟悉屏幕组件的颜色和外观的方式，例如标题和状态栏背景颜色以及文本和突出显示的阴影。

# 应用主题

作为开发者，我们希望我们的应用程序能够从众多应用中脱颖而出，但同时我们也希望融入 Android 用户熟悉的全部功能。实现这一点的方法之一是在整个应用程序中应用特定的颜色方案。这最简单的方法是定制或创建 Android 主题。

自从 API 级别 21（Android 5.0）起，**材质主题**已成为 Android 设备的默认主题。然而，它不仅仅是一个新的外观。材质主题还默认提供了我们与材质设计相关的触摸反馈和过渡动画。与所有 Android 主题一样，材质主题也是基于 Android 样式的。

**Android 样式**是一组定义特定屏幕组件外观的图形属性。样式允许我们从字体大小、背景颜色、内边距和高度等方面进行定义，还有更多。Android 主题实际上就是应用于整个活动或应用程序的样式。样式被定义为 XML 文件，并存储在 Android Studio 项目的资源（`res`）目录中。

幸运的是，Android Studio 带有一个图形化的**主题编辑器**，它为我们生成 XML。不过，了解幕后发生的情况总是好的，这最好通过打开上一章的抽象工厂项目或开始一个新项目来查看。从项目浏览器中，打开`res/values/styles.xml`文件。它将包含以下样式定义：

```kt
<style name="AppTheme" parent="Theme.AppCompat.Light.DarkActionBar"> 

    <item name="colorPrimary">@color/colorPrimary</item> 
    <item name="colorPrimaryDark">@color/colorPrimaryDark</item> 
    <item name="colorAccent">@color/colorAccent</item> 

</style> 

```

在这里，虽然只定义了三种颜色，但我们也可以定义更多，例如主要和次要文本颜色、窗口背景颜色等。颜色本身在`colors.xml`文件中定义，该文件也位于`values`目录中，并将包含以下定义：

```kt
<color name="colorPrimary">#3F51B5</color> 
<color name="colorPrimaryDark">#303F9F</color> 
<color name="colorAccent">#FF4081</color> 

```

完全可以应用多个主题，并融入我们喜欢的多种样式，但通常来说，在整个应用程序中应用单一主题，并定制其中一个默认的材质主题是最简单、最整洁的方法。

定制默认主题的最简单方式是使用主题编辑器，可以从`工具 | Android`菜单中打开。编辑器提供了一个强大的所见即所得预览窗格，使我们能够在我们进行更改时即时查看任何更改，如下所示：

![应用主题](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_02_002.jpg)

尽管我们可以为我们的主题自由选择任何喜欢的颜色，但材质设计指南对于如何一起使用颜色非常明确。这最好通过查看**材质调色板**来解释。

# 定制颜色和文本

应用主题时我们首先需要考虑的是颜色和文本。材质设计指南建议从预定义的一系列调色板中选择这些颜色。

## 使用调色板

在材料主题中，我们可以编辑的最重要的两种颜色是主色。它们直接应用于状态栏和应用程序栏，使应用具有独特的观感，而不会影响整个平台的统一感。这两种颜色都应该从同一个色板中选择。有许多这样的色板可供选择，整个系列可以在 www.google.com/design/spec/style/color.html#color-color-palette 找到。

无论你决定使用哪个色板作为你的主色，谷歌建议你使用值为**500**和**700**的阴影。

![使用色板](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_02_003.jpg)

这不需要严格执行，但通常最好遵循这些值，并且总是选择同一颜色的两种阴影。

### 提示

在这里，主题编辑器会非常有帮助；它的实色块不仅提供了提示工具，告诉我们阴影值，而且一旦我们选定了主色，它还会推荐一个合适的深色版本。

选择强调色时，需要考虑我们选择的主要色调。这将应用于开关和高亮显示，并且需要与主色形成良好对比。除了选择看起来不错且具有浅色值**100**的颜色之外，没有简单的规则来决定哪些颜色之间形成对比。

### 提示

可以使用`navigationBarColor`改变屏幕底部的导航栏颜色，但不建议这样做，因为导航栏不应被视为应用的一部分。

对于大多数目的，其他主题设置可以保持原样。但是，如果你希望更改文本颜色，有一两件事需要注意。

## 自定义文本

材料文本不是通过使用更浅的色调来生成浅色阴影，而是通过使用 alpha 通道来创建不同级别的**透明度**。这样做的原因是，当它被用在不同的背景色或图像上时，看起来更加悦目。文本透明度的规则如下：

![自定义文本](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_02_004.jpg)

关于样式和主题，我们可以做很多事情，但现在只需创建一个简单的配色方案，并知道它将在整个应用程序中一致应用就足够了。我们下一个任务将是探讨如何将我们之前考虑的“三明治成分”对象扩展成一个用户友好的界面。毫无疑问，吸引用户的一个最佳方式就是使用诱人的照片。

# 添加图像资源

安卓提供的最具挑战性的问题之一是我们要适应的众多屏幕密度和尺寸。在显示位图图像时，这一点尤为正确，这里有两个需要解决的竞争性问题：

+   低分辨率图像在拉伸以适应大屏幕或高分辨率屏幕时显示效果非常差。

+   高质量图像在较小、低密度的屏幕上显示时，所使用的内存远大于所需。

屏幕尺寸先放一边，通过使用**密度独立像素**（**dp**）基本上解决了不同屏幕密度的问题。

## 管理屏幕密度

dp 是一个基于 160 dpi 屏幕显示的抽象测量单位。这意味着无论屏幕密度如何，宽度为 320 dp 的组件始终为 2 英寸宽。当涉及到屏幕的实际物理尺寸时，这可以通过各种布局类型、库和属性（如权重和重力）来管理，但现在我们将了解如何提供适合尽可能广泛的屏幕密度的图像。

安卓系统用以下限定符划分屏幕密度：

+   低密度（`ldpi`）- **120 dpi**

+   中等密度（`mdpi`）- **160 dpi**

+   高密度（`hdpi`）- **240 dpi**

+   超高密度（`xhdpi`）- **320 dpi**

+   超超超高密度（`xxhdpi`）- **480 dpi**

+   超超超高密度（`xxxhdpi`）- **640 dpi**

### 注意事项

在应用安装期间，每个设备只会下载与其规格相匹配的图像。这节省了旧设备的内存，同时为有能力的设备提供了尽可能丰富的视觉体验。

从开发者的角度来看，我们可能需要为每个项目生成六种不同版本的图像。幸运的是，通常情况下并非如此。在大多数手持设备上，640 dpi 图像与 320 dpi 图像之间的差别几乎无法察觉。考虑到我们三明治制作应用的大多数用户只想浏览食材菜单，而不是仔细检查图像质量，我们可以只安全地提供中等、高和超高密度设备的图像。

### 提示

在考虑高端设备图像质量时，一个很好的经验法则是将我们的图像尺寸与设备原生相机产生的尺寸进行比较。提供更大的图像不太可能足以改善用户体验，从而证明需要额外的内存是合理的。

在本例中，我们希望提供适合卡片视图的图像，该视图在纵向模式下将占据屏幕宽度的绝大部分。现在，找一个大约 2,000 像素宽的图像。在下面的例子中，它被称为`sandwich.png`，尺寸为 1,920×1,080 像素。你的图像不必与这些尺寸匹配，但稍后我们会看到，选择合适的图像比例是良好 UI 实践的重要组成部分。

在超高密度设备上显示 320 dpi 时，宽度为 1,920 像素的图像将显示为六英寸宽。现在至少假设我们的应用将来自移动设备，而不是计算机或电视，所以在高密度 10 英寸的平板电脑上，六英寸对我们来说已经足够了。接下来，我们还将了解如何为其他屏幕密度做准备。

## 使用指定资源

通过分配特定资源目录来满足不同屏幕密度的需求是很容易实现的。在 Android Studio 中，我们可以通过以下步骤从项目资源管理器中创建这些目录：

1.  ![使用指定资源](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_02_006.jpg)

1.  接下来，创建两个同级的目录，分别命名为`drawable-hdpi`和`drawable-xhdpi`。

1.  通过从项目资源管理器中选择`drawable`上下文菜单中的**在资源管理器中显示**直接打开这些新文件夹。

1.  将`sandwich.png`图片添加到`drawable-xhdpi`文件夹中。

1.  制作这张图片的两个副本，并按 3:4 和 1:2 的比例缩放它们。

1.  将这些副本分别放置在`drawable-hdpi`和`drawable-mdpi`目录中。

这些变化现在可以在项目资源管理器中看到，如下所示：

![使用指定资源](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_02_005.jpg)

这样一来，我们可以确保只有最适合设备原生屏幕密度的图像资源会被下载。

```kt
<ImageView 
    android:layout_width="wrap_content" 
    android:layout_height="wrap_content" 
    android:src="img/sandwich" /> 

```

首先，从`res`文件夹中创建一个`新 | 目录`，并将其命名为`drawable-mdpi`。

要查看效果，请在项目的`activity_main.xml`文件中添加以下图像视图：

这种方法的优点是，一旦我们正确指定了图片资源，就可以简单地通过引用`@drawable/sandwich`来忽略它实际存储的目录。

卡片视图是 Material Design 中最容易识别的组件之一，它设计用来以统一的方式展示多个相关的片段内容。这种内容通常包括图形、文本、操作按钮和图标等。卡片是展示像三明治配料和相关价格或热量信息这类选择的好方法。

# 创建一个卡片视图（**CardView**）。

输出可以在任何模拟器或真实设备上的预览屏幕上查看：

## 了解卡片视图属性。

如果您的最低目标 SDK 是 21 或更高，那么卡片视图小部件将作为标准包含。否则，您需要包含卡片视图支持库。这可以在`build.gradle`文件中通过添加以下高亮行轻松完成：

```kt
dependencies { 
    compile fileTree(dir: 'libs', include: ['*.jar']) 
    testCompile 'junit:junit:4.12' 
    compile 'com.android.support:appcompat-v7:23.4.0' 
    compile 'com.android.support:cardview-v7:23.4.0' 
} 

```

正如支持库的名字所暗示，我们只能支持回溯到 API 级别 7 的卡片视图。

不必手动编辑`build.gradle`文件，尽管了解如何操作是有用的，可以通过`文件 | 项目结构...`菜单选择以下所示的项目来完成：

![理解卡片视图属性](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_02_007.jpg)

### 提示

一些开发者使用`+`符号来版本化他们的支持库，如：`com.android.support:cardview-v7:23.+`。这是为了预测未来的库。这通常运作得很好，但这并不能保证这些应用在未来不会崩溃。在开发过程中使用编译的 SDK 版本，然后在应用发布后定期更新，虽然更耗时，但更明智。

在我们能够将卡片视图添加到我们的布局之前，你需要重新构建项目。首先，我们需要设置一些卡片的属性。打开`res/values/dimens.xml`文件，并添加以下三个新的尺寸资源：

```kt
<dimen name="card_height">200dp</dimen> 
<dimen name="card_corner_radius">4dp</dimen> 
<dimen name="card_elevation">2dp</dimen> 

```

现在，我们可以在主 XML 活动文件中将卡片作为小部件添加，如下所示：

```kt
<android.support.v7.widget.CardView  
    android:layout_width="match_parent" 
    android:layout_height="@dimen/card_height" 
    android:layout_gravity="center" 
    card_view:cardCornerRadius="@dimen/card_corner_radius" 
    card_view:cardElevation="@dimen/card_elevation"> 
</android.support.v7.widget.CardView> 

```

阴影的使用不仅仅是为了给界面提供三维外观；它还通过图形化地展示布局层次结构，让用户清楚地知道哪些功能可用。

### 提示

如果你花时间检查过卡片视图属性，你会注意到`translationZ`属性。这看起来与`elevation`有相同的效果。然而，`elevation`将设置卡片的绝对高度，而`translationZ`是一个相对设置，它的值将会加到或从当前高度中减去。

现在我们已经设置好了卡片视图，可以根据材料设计指南填充它，以表示我们的三明治成分。

## 应用 CardView 的度量标准

设计指南对字体、内边距和缩放等问题非常明确。一旦我们开始使用 CoordinatorLayout，这些设置中的许多将会自动设置，但现在，了解这些度量标准是如何应用的还是一个好主意。

关于卡片有许多不同的模式，它们的完整描述可以在这里找到：

[卡片设计规范](http://www.google.com/design/spec/components/cards.html)

我们将在这里创建的卡片将包含一个图片、三个文本项和一个动作按钮。卡片可以被看作是容器对象，通常它们包含自己的根布局。这可以直接放置在卡片视图内，但如果我们把卡片内容作为独立的 XML 布局创建，代码将更具可读性和灵活性。

下一个练习中，我们将至少需要一张图片。根据材料设计，照片应该是清晰、明亮、简单，并呈现单一、明确的主题。例如，如果我们想将咖啡添加到菜单中，左边的图片将是最合适的：

![应用 CardView 的度量标准](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_02_008.jpg)

卡片图片的宽高比应为 16:9 或 1:1。这里，我们将使用 16:9，理想情况下我们应该生成缩放版本以适应各种屏幕密度，但既然这只是一个演示，我们可以偷懒直接将原始图片放入`drawable`文件夹。这种方法远非最佳实践，但对于初步测试是没问题的。

在找到并保存你的图片后，下一步是创建一个卡片的布局：

1.  从项目浏览器中，导航到`新建 | XML | 布局 XML 文件`，并将其命名为`card_content.xml`。它的根视图组应该是一个垂直方向的线性布局，应该看起来像这样：

    ```kt
    <LinearLayout  
        android:id="@+id/card_content" 
        android:layout_width="match_parent" 
        android:layout_height="match_parent" 
        android:orientation="vertical"> 
    </LinearLayout> 

    ```

1.  使用图形或文本编辑器，创建一个与这里看到的**组件树**相匹配的布局结构：![应用 CardView 度量](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_02_009.jpg)

1.  现在，将此布局包含在主活动布局文件中的卡片视图中，如下所示：

    ```kt
    <android.support.v7.widget.CardView 
        android:id="@+id/card_view" 
        android:layout_width="match_parent" 
        android:layout_height="wrap_content"> 

        <include 
            android:id="@+id/card_content" 
            layout="@layout/card_content" /> 

    </android.support.v7.widget.CardView> 

    ```

    ### 提示

    尽管可以编辑，但建议卡片视图的默认高度为 2 dp，除非它已被选中和/或正在移动，在这种情况下，它的高度为 8 dp。

你无疑知道，在 XML 资源中硬编码字符串的使用是强烈不推荐的。至少，这使得将我们的应用程序翻译成其他语言的过程几乎不可能。然而，在布局设计的早期阶段，提供一些占位符值以了解布局可能的外观是有帮助的。稍后，我们将使用 Java 控制卡片内容，并根据用户输入选择此内容；但现在，我们将选择一些典型值，以便我们可以轻松快速地看到我们的设置产生的影响。为了了解这是如何有用的，请在`values`目录下的`strings.xml`文件中添加以下属性或等价物：

```kt
<string name="filling">Cheddar Cheese</string> 
<string name="filling_description">A ripe and creamy cheddar from the south west</string> 
<string name="calories">237 kcal per slice</string> 
<string name="action">ADD</string> 
<string name="alternative_text">A picture of some cheddar cheese</string> 

```

现在，我们将使用这些占位符来评估我们进行的任何更改。我们刚刚创建的布局，在预览中查看时，应该看起来像这样：

![应用 CardView 度量](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_02_010.jpg)

将其转化为材质设计组件只需要进行一些格式化处理，并了解一些材质设计指南的知识。

此布局的度量如下：

+   图片的长宽比必须是 16:9。

+   标题文本应为 24 sp。

+   描述性文本为 16 sp。

+   文本底部右侧和左侧的边距为 16 dp。

+   标题文本上方的边距为 24 dp。

+   动作文本的大小为 24 sp，并从强调色中获取其颜色。

这些属性可以通过属性面板或直接编辑 XML 非常容易地设置。这里有一两件事情没有提到，所以值得单独查看每个元素。

首先，必须指出的是，这些值绝不应像以下代码段中那样直接在代码中描述；例如，`android:paddingStart="24dp"` 应该像这样编码 `android:paddingStart="@dimen/text_paddingStart"`，其中 `text_paddingStart` 在 `dimens.xml` 文件中定义。这里，值是硬编码的，只是为了简化解释。

顶部图像视图的代码应该如下所示：

```kt
<ImageView 
       android:id="@+id/image_view" 
       android:layout_width="match_parent" 
       android:layout_height="wrap_content" 
       android:contentDescription="@string/alternative_text" 
       android:src="img/cheddar" /> 

```

这非常简单，但请注意 `contentDescription` 的使用；当视力受损的用户设置了辅助功能选项时，这会被用来让设备通过语音合成器朗读图像的描述，以便用户欣赏。

下面是以下三个文本视图。

```kt
<TextView 
    android:id="@+id/text_title" 
    android:layout_width="wrap_content" 
    android:layout_height="wrap_content" 
    android:paddingEnd="24dp" 
    android:paddingStart="24dp" 
    android:paddingTop="24dp" 
    android:text="@string/filling" 
    android:textAppearance="?android:attr/textAppearanceLarge" 
    android:textSize="24sp" /> 

<TextView 
    android:id="@+id/text_description" 
    android:layout_width="wrap_content" 
    android:layout_height="wrap_content" 
    android:paddingEnd="24dp" 
    android:paddingStart="24dp" 
    android:text="@string/filling_description" 
    android:textAppearance="?android:attr/textAppearanceMedium" 
    android:textSize="14sp" /> 

<TextView 
    android:id="@+id/text_calories" 
    android:layout_width="wrap_content" 
    android:layout_height="wrap_content" 
    android:layout_gravity="end" 
    android:paddingBottom="8dp" 
    android:paddingStart="16dp" 
    android:paddingEnd="16dp" 
    android:paddingTop="16dp" 
    android:text="@string/calories" 
    android:textAppearance="?android:attr/textAppearanceMedium" 
    android:textSize="14sp" /> 

```

这些也非常容易理解。真正需要指出的是，我们使用 `Start` 和 `End` 而不是 `Left` 和 `Right` 来定义内边距和重力，这有助于在将布局翻译成从右到左运行文本的语言时，让布局自我纠正。我们还包含了 `textAppearance` 属性，尽管我们直接设置了文本大小，这看起来可能有些多余。像 `textAppearanceMedium` 这样的属性很有用，因为它们不仅可以根据我们自定义的主题自动应用文本颜色，还可以根据个别用户的全局文本大小设置调整其大小。

这只剩下底部的动作按钮，由于这里使用的是文本视图而不是按钮，这可能需要一些解释。XML 看起来像这样：

```kt
<TextView 
    android:id="@+id/text_add" 
    android:layout_width="wrap_content" 
    android:layout_height="wrap_content" 
    android:layout_gravity="end" 
    android:clickable="true" 
    android:paddingBottom="16dp" 
    android:paddingEnd="40dp" 
    android:paddingLeft="16dp" 
    android:paddingRight="40dp" 
    android:paddingStart="16dp" 
    android:paddingTop="16dp" 
    android:text="@string/action" 
    android:textAppearance="?android:attr/textAppearanceLarge" 
    android:textColor="@color/colorAccent" 
    android:textSize="24sp" /> 

```

我们在这里选择文本视图而不是按钮控件有两个原因。首先，Android 推荐在卡片视图中使用只有文本可见的**扁平按钮**；其次，触发动作的可触摸区域需要比文本本身大。这可以通过设置内边距属性轻松实现，正如我们之前所做的那样。要让文本视图像按钮一样工作，我们只需添加一行 `android:clickable="true"`。

我们完成的卡片现在应该看起来像这样：

![应用 CardView 度量](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_02_011.jpg)

关于卡片视图的设计还有很多内容，但这应该足以作为我们需要遵循的一些原则的介绍，现在我们可以看到这些呈现对象的新方式如何反映在我们的工厂模式代码上。

## 更新工厂模式

设计模式的美之一在于它们可以轻松地适应我们希望做出的任何变化。如果我们选择，可以保留工厂代码不变，并使用单一字符串输出将客户端代码指向适当的数据集。然而，根据模式的本质，我们应该将它们适应到与我们稍微复杂的成分对象相匹配。

我们上一章代码结构中的思考现在得到了回报，因为尽管我们需要编辑我们的接口和具体示例，但我们可以将工厂类本身保持原样，这很好地展示了模式的一个优点。

使用我们构建卡片时使用的四个标准，我们更新后的接口可能看起来像这样：

```kt
public interface Bread { 

    String image(); 
    String name(); 
    String description(); 
    int calories(); 
} 

```

单个对象可能看起来像这样：

```kt
public class Baguette implements Bread { 

    @Override 
    public String image() { 
        return "R.drawable.baguette"; 
    } 

    @Override 
    public String name() { 
        return "Baguette"; 
    } 

    @Override 
    public String description() { 
        return "Fresh and crunchy"; 
    } 

    @Override 
    public int calories() { 
        return 150; 
    } 
} 

```

随着我们向前发展，我们的对象将需要更多的属性，比如价格以及它们是否是素食或含有坚果等。随着对象的变得更加复杂，我们将不得不应用更复杂的方式来管理我们的数据，但原则上这里使用的方法并没有错。它可能有些笨重，但肯定易于阅读和维护。工厂模式显然非常有用，但它们只创建单一对象。为了更真实地模拟三明治，我们需要能够将*配料*对象组合在一起，并将整个集合视为一个单独的*三明治*对象。这正是构建模式发挥作用的地方。

# 应用构建模式

构建器设计模式是最有用的创建模式之一，因为它从更小的对象构建更大的对象。这正是我们想要从配料列表构造三明治对象所做的。构建器模式的另一个优点是，可选特性稍后很容易加入。像之前一样，我们将从创建一个接口开始；我们将它称为`Ingredient`，用它来表示`面包`和`填充物`。这次，我们需要用整数来表示卡路里，因为我们需要计算成品三明治中的总含量。

打开一个 Android Studio 项目，或者开始一个新项目，并按照以下步骤创建一个基本的三明治构建模式：

1.  创建一个名为`Ingredient.java`的新接口，并完成如下：

    ```kt
    public interface Ingredient { 

        String name(); 
        int calories(); 
    } 

    ```

1.  现在像这样为`Bread`创建一个抽象类：

    ```kt
    public abstract class Bread implements Ingredient { 

        @Override 
        public abstract String name(); 

        @Override 
        public abstract int calories(); 
    } 

    ```

1.  并创建一个名为`Filling`的相同接口。

1.  接下来，像这样创建`Bread`的具体类：

    ```kt
    public class Bagel extends Bread { 

        @Override 
        public String name() { 
            return "Bagel"; 
        } 

        @Override 
        public int calories() { 
            return 250; 
        } 
    } 

    ```

1.  对`Filling`也做同样的处理。为了演示目的，每种类型两个类应该就足够了：

    ```kt
    public class SmokedSalmon extends Filling { 

        @Override 
        public String name() { 
            return "Smoked salmon"; 
        } 

        @Override 
        public int calories() { 
            return 400; 
        } 
    } 

    ```

1.  现在我们可以创建我们的`Sandwich`类：

    ```kt
    public class Sandwich { 
        private static final String DEBUG_TAG = "tag"; 

        // Create list to hold ingredients 
        private List<Ingredient> ingredients = new ArrayList<Ingredient>(); 

        // Calculate total calories 
        public void getCalories() { 
            int c = 0; 

            for (Ingredient i : ingredients) { 
                c += i.calories(); 
            } 

            Log.d(DEBUG_TAG, "Total calories : " + c + " kcal"); 
        } 

        // Add ingredient 
        public void addIngredient(Ingredient ingredient) { 
            ingredients.add(ingredient); 
        } 

        // Output ingredients 
        public void getSandwich() { 

            for (Ingredient i : ingredients) { 
                Log.d(DEBUG_TAG, i.name() + " : " + i.calories() + " kcal"); 
            } 
        } 

    } 

    ```

1.  最后，像这样创建`SandwichBuilder`类：

    ```kt
    public class SandwichBuilder { 

        // Off the shelf sandwich 
        public static Sandwich readyMade() { 
            Sandwich sandwich = new Sandwich(); 

            sandwich.addIngredient(new Bagel()); 
            sandwich.addIngredient(new SmokedSalmon()); 
            sandwich.addIngredient(new CreamCheese()); 

            return sandwich; 
        } 

        // Customized sandwich 
        public static Sandwich build(Sandwich s, Ingredient i) { 

            s.addIngredient(i); 
            return s; 
        } 
    } 

    ```

    这完成了我们的构建器设计模式，至少目前是这样。当它作为一个图表被查看时，看起来像这样：

    ![应用构建模式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_02_012.jpg)

在这里，我们为构建器提供了两个功能：返回一个现成的三明治和一个用户定制的三明治。我们目前还没有可用的接口，但我们可以通过客户端代码模拟用户选择。

我们还将输出职责委托给了`Sandwich`类本身，这样做通常是个好主意，因为它有助于保持客户端代码的清晰和明显，正如您在这里看到的：

```kt
        // Build a customized sandwich 
        SandwichBuilder builder = new SandwichBuilder(); 
        Sandwich custom = new Sandwich(); 

        // Simulate user selections 
        custom = builder.build(custom, new Bun()); 
        custom = builder.build(custom, new CreamCheese()); 

        Log.d(DEBUG_TAG, "CUSTOMIZED"); 
        custom.getSandwich(); 
        custom.getCalories(); 

        // Build a ready made sandwich 
        Sandwich offTheShelf = SandwichBuilder.readyMade(); 

        Log.d(DEBUG_TAG, "READY MADE"); 
        offTheShelf.getSandwich(); 
        offTheShelf.getCalories(); 

```

这应该会产生类似这样的输出：

```kt
D/tag: CUSTOMIZED
D/tag: Bun : 150 kcal
D/tag: Cream cheese : 350 kcal
D/tag: Total calories : 500 kcal
D/tag: READY MADE
D/tag: Bagel : 250 kcal
D/tag: Smoked salmon : 400 kcal
D/tag: Cream cheese : 350 kcal
D/tag: Total calories : 1000 kcal

```

构造者最大的优势之一是添加、删除和修改具体类非常容易，甚至接口或抽象的变更也无需修改客户端源代码。这使得构造者模式成为最强大的模式之一，并且可以应用于众多场景。但这并不是说构造者模式总是比工厂模式更优。对于简单对象，工厂通常是最佳选择。当然，模式存在于不同规模上，构造者中嵌套工厂或者工厂中嵌套构造者都是常见的情况。

# 概述

在本章中，我们介绍了大量关于如何展示产品的内容，这是任何成功应用的关键要素。我们学习了如何管理颜色和文本方案，并进一步探讨了更严肃的问题：如何管理应用可能运行在各种屏幕密度上的情况。

接下来，我们介绍了材料设计中使用最频繁的组件之一：卡片视图，并强调了支持库的重要性，尤其是设计库。我们需要进一步了解这个库，因为它对于创建我们应用所需的布局和交互至关重要。下一章将专注于更多这些视觉元素，聚焦于更常见的材料组件，如应用栏和滑动抽屉。


# 第三章：材料模式

在本书的这部分，我们探讨了如何通过使用设计模式来创建对象和对象集合，以及如何使用卡片视图来展示它们。在我们开始构建一个可工作的应用程序之前，我们需要考虑用户将如何输入他们的选择。在移动设备上有许多方式可以从用户那里收集信息，比如菜单、按钮、图标和对话框。安卓布局通常有一个应用栏（以前称为操作栏），它通常位于屏幕顶部，紧挨着状态栏，而实现材料设计的布局，通常会采用滑动导航抽屉来提供对应用顶级功能的访问。

通常情况下，使用支持库，尤其是**设计库**，可以非常容易地实现如导航栏这样的材质模式，材料设计本身包含了一些视觉模式，有助于促进最佳的 UI 实践。在本章中，我们将学习如何实现**应用栏**、**导航视图**，并探索材料设计提供的一些视觉模式。最后，我们还将快速了解一下**单例模式**。

在本章中，你将学习如何进行以下操作：

+   用应用栏替换操作栏

+   使用资产工作室添加操作图标

+   应用应用栏操作

+   在运行时控制应用栏

+   使用抽屉布局

+   添加菜单和子菜单

+   应用比例关键线

+   包含一个抽屉监听器

+   向应用中添加片段

+   管理片段回退栈

# 应用栏

安卓应用一直以来都在屏幕顶部包含一个工具栏。传统上，这被用来提供一个标题以及访问顶级菜单，被称为操作栏。自从安卓 5（API 级别 21）和材料设计的出现，这就可以用更灵活的应用栏来替代。应用栏允许我们设置其颜色，将其放置在屏幕的任何位置，并包含比其前身更广泛的内容。

大多数 Android Studio 模板使用的主题默认包含旧的操作栏，我们首先需要做的就是移除旧版本。要了解如何移除旧的操作栏并用定制的应用栏替换它，请按照以下步骤操作：

1.  使用空活动模板启动一个新的安卓项目，并通过主题编辑器设置你的材料主题。

1.  打开`styles.xml`文件，并编辑`style`定义以匹配这里的定义：

    ```kt
    <style name="AppTheme" parent="Theme.AppCompat.Light.NoActionBar"> 

    ```

1.  在`activity_main.xml`旁边创建一个新的 XML 文件，并将其命名为`toolbar.xml`。

1.  完成如下操作：

    ```kt
    <android.support.v7.widget.Toolbar  

        android:id="@+id/toolbar" 
        android:layout_width="match_parent" 
        android:layout_height="?attr/actionBarSize" 
        android:background="?attr/colorPrimary" 
        android:theme="@android:style/Theme.Material" 
        android:translationZ="4dp" /> 

    ```

1.  接下来，向`activity_main.xml`文件中添加以下元素：

    ```kt
    <include 
        android:id="@+id/toolbar" 
        layout="@layout/toolbar" /> 

    ```

    ```kt
    <android.support.v7.widget.Toolbar  

        android:id="@+id/toolbar" 
        android:layout_width="match_parent" 
        android:layout_height="?attr/actionBarSize" 
        android:background="?attr/colorPrimary" 
        android:theme="@android:style/Theme.Material" 
        android:translationZ="4dp" /> 

    ```

1.  最后，像这样编辑`dimens.xml`文件中的边距值：

    ```kt
    <resources> 
        <dimen name="activity_horizontal_margin">0dp</dimen> 
        <dimen name="activity_vertical_margin">0dp</dimen> 
    </resources> 

    ```

这个工具栏与其他任何 ViewGroup 一样，位于根布局内，因此与原始操作栏不同，它并不紧贴屏幕边缘。这就是为什么我们需要调整布局边距的原因。稍后，我们将使用 CoordinatorLayout，它会自动完成其中许多工作，但现在了解其工作原理是有用的。

工具栏现在虽然位置和阴影与原始工具栏类似，但并没有内容和功能。这可以在活动的 Java 元素中通过编辑`onCreate()`方法来实现：

```kt
@Override 
protected void onCreate(Bundle savedInstanceState) { 
    super.onCreate(savedInstanceState); 
    setContentView(R.layout.activity_main); 

    Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar); 
    if (toolbar != null) { 
        setSupportActionBar(toolbar); 
    } 
} 

```

这将产生一个错误。这是因为这里可能导入两个库。按下**Alt + Enter**并选择如下所示的支持版本的 Toolbar：

![应用栏](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_03_001.jpg)

### 提示

为了在处理 Java 时节省时间，更改设置以便在代码中包含 Java 库时自动导入。这可以通过**文件** | **设置**菜单中的**编辑器** | **常规** | **自动导入**来完成。

在运行 API 20 或更低版本的模拟器上测试项目，会立即展示 AppCompat 主题的一个缺点；尽管我们为状态栏`with colorPrimaryDark`声明了一个颜色，这在 API 21 及更高版本上完美运行，但在这里它仍然是黑色：

![应用栏](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_03_002.jpg)

然而，考虑到我们现在能够触及的受众数量，这种做法以及缺少自然阴影的代价是微不足道的。

既然我们已经用工具栏替换了过时的操作栏，并将其设置为应用栏（有时称为主工具栏），我们可以更仔细地了解其工作原理以及如何使用 Asset Studio 应用符合材质设计规范的行动图标。

## 图像资源

在应用栏中包含文本菜单是可能的，但由于空间有限，通常使用图标更为常见。Android Studio 通过其 Asset Studio 提供了一组材质图标的访问。以下步骤将展示如何操作：

1.  在项目资源管理器中，从 drawable 文件夹的菜单选择**新建 | 图像资源**。

1.  然后选择**操作栏和标签图标**作为**资源类型**，接着点击**剪贴画**图标，从剪贴画集中选择一个图标：![图像资源](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_03_003.jpg)

1.  这张图片需要修剪，且填充为 0%。

1.  根据工具栏背景颜色是浅色还是深色选择一个主题。

1.  提供一个合适的名称并点击**下一步**：![图像资源](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_03_004.jpg)

    ### 提示

    可以从以下 URL 下载更多材质图标集合：[`design.google.com/icons`](https://design.google.com/icons)

资产工作室自动为我们跨四种屏幕密度创建图标，并将它们放置在正确的文件夹中，以便它们能够部署在适当的设备上。它甚至应用了材料设计用于图标所需的**54%不透明黑色**。要在我们的应用栏中包含这些，只需在适当的菜单项中添加一个图标属性。稍后，我们将使用导航抽屉提供顶级访问，但要了解如何使用应用栏，我们将添加一个搜索功能。我们为此选择的图标叫做 `ic_action_search`。

## 应用操作

操作图标保存在可绘制文件夹中，并且可以通过在菜单 XML 文件中包含 `items` 来包含在我们的操作栏中。根据您最初创建项目时使用的模板，您可能需要添加一个新目录 `res/menu` 和一个名为 `main.xml` 或 `menu_main.xml` 的文件，或者您选择作为 **新建 | 菜单资源文件** 的其他名称。可以像这样添加操作：

```kt
<menu  

    tools:context="com.example.kyle.appbar.MainActivity"> 

    <item 
        android:id="@+id/action_settings" 
        android:orderInCategory="100" 
        android: 
        app:showAsAction="collapseActionView" /> 

    <item 
        android:id="@+id/action_search" 
        android:icon="@drawable/ic_action" 
        android:orderInCategory="100" 
        android: 
        app:showAsAction="ifRoom" /> 
</menu> 

```

请注意，前面的示例使用了对字符串资源的引用，因此必须在 `strings.xml` 文件中伴有如下定义：

```kt
<string name="menu_search">Search</string> 

```

菜单项会自动包含在应用栏中，其标题取自字符串文件中的 `string name="app_name"` 定义。以这种方式构建时，这些组件会根据材料设计指南进行定位。

要查看实际效果，请按照以下步骤操作：

1.  打开主 Java 活动并添加这个字段：

    ```kt
    private Toolbar toolbar; 

    ```

1.  然后将这些行添加到 `onCreate()` 方法中：

    ```kt
    Toolbar toolbar = (Toolbar) findViewById(R.id.toolbar); 
        if (toolbar != null) { 
            setSupportActionBar(toolbar); 
        } 

    toolbar = (Toolbar) findViewById(R.id.toolbar); 
    toolbar.setTitle("A toolbar"); 
    toolbar.setSubtitle("with a subtitle"); 

    ```

1.  最后，在活动中添加以下方法：

    ```kt
    @Override 
    public boolean onCreateOptionsMenu(Menu menu) { 
        MenuInflater inflater = getMenuInflater(); 
        inflater.inflate(R.menu.menu_main, menu); 
        return true; 
    } 

    ```

现在我们应该能够在设备或模拟器上看到我们的新工具栏：

![应用操作](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_03_005.jpg)

能够将我们喜欢的任何视图添加到工具栏，这使得它比旧的操作栏更有效。我们可以同时拥有多个，并且通过应用布局重力属性，它们甚至可以被放置在其他地方。正如之前所见，工具栏还带有自己的方法，可以通过这些方法添加图标和标志，但在这样做之前，根据材料设计指南探索应用栏的最佳实践会是一个好主意。

## 应用栏结构

尽管我们在这里应用的技术符合材料设计指南，我们除了确保其高度外不需要做很多工作，但在用自定义工具栏布局替换操作栏时，我们仍需要知道如何间隔和定位组件。这些在平板电脑和桌面上略有不同。

### 手机

在应用栏方面，只需记住一些简单的结构规则。这些规则涵盖了边距、填充、宽度、高度和定位，并且在不同平台和屏幕方向上有所不同。

+   应用栏在纵向模式下的 `layout_height` 为 `56 dp`，在横向模式下为 `48 dp`。

+   应用栏填充屏幕宽度或其包含列的宽度。它们不能被分成两个部分。它们的 `layout_width` 为 `match_parent`。

+   应用栏的 `elevation` 比它控制的材质纸张高 `2 dp`。

+   前一条规则的例外情况是，如果卡片或对话框有自己的工具栏，那么两者可以共享相同的阴影高度。

+   应用栏的填充恰好为 `16 dp`。这意味着包含的图标不能有自己的填充或边距，因此与这个边距共享边缘：![手机](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_03_006.jpg)

+   标题文本的颜色取自您主题的主文本颜色，图标则取自辅助文本颜色。

+   标题应位于工具栏左侧 `72 dp` 和底部 `20 dp` 的位置。即使工具栏展开时也适用此规则：![手机](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_03_007.jpg)

+   标题文本大小通过 `android:textAppearance="?android:attr/textAppearanceLarge"` 进行设置。

### 平板电脑

在为平板电脑和桌面构建应用栏时，规则相同，以下是一些例外：

+   工具栏的高度始终为 `64 dp`。

+   标题向内缩进 `80 dp`，并且在工具栏展开时不会向下移动。

+   应用栏的填充为 `24 dp`，顶部除外，那里是 `20 dp`。

我们已经按照材质设计指南构建了一个应用栏，但如果没有执行操作，操作图标是没有用的。本质上，当应用栏承担操作栏功能时，它实际上只是一个菜单的访问点。我们稍后会回到菜单和对话框，但现在我们将快速了解一下如何使用 Java 代码在运行时操作工具栏。

对旧操作栏所做的更改使其成为一个放置全局操作的简单直观视图。然而，空间有限，对于更复杂和图形化的导航组件，我们可以转向滑动抽屉。

# 导航抽屉

尽管可以让抽屉从屏幕的任一侧滑出，但导航抽屉应始终位于左侧，并且其阴影高度应高于除状态栏和导航栏之外的所有其他视图。将导航抽屉视为一个大部分时间隐藏在屏幕边缘之外的固定装置：

![导航抽屉](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_03_008.jpg)

在设计库之前，必须使用其他视图构建如导航视图之类的组件，尽管库极大地简化了这一过程，并使我们不必手动实现许多材质原则，但仍有一些指南需要我们注意。了解这些的最佳方式是从头开始构建一个导航滑动抽屉。这将涉及创建布局，应用关于组件比例的材质设计指南，并通过代码将所有这些连接起来。

## 抽屉构建

你在设置项目时无疑已经注意到，Android Studio 提供了一个 **Navigation Drawer Activity** 模板。这为我们创建了很多可能需要的内容，并节省了大量工作。一旦我们决定了我们的三明治制作应用将具有哪些功能，我们将使用这个模板。然而，从头开始构建一个更有教育意义，可以看到它是如何工作的，基于这个想法，我们将创建一个需要通过 Asset Studio 轻松找到图标的抽屉布局：

1.  打开一个最低 SDK 级别为 21 或更高的 Android Studio 项目，并提供你自己的自定义颜色和主题。

1.  在你的 `styles.xml` 文件中添加以下行：

    ```kt
    <item name="android:statusBarColor"> 
    @android:color/transparent 
    </item> 

    ```

1.  确保你已经编译了以下依赖项：

    ```kt
    compile 'com.android.support:design:23.4.0' 

    ```

1.  如果你没有使用前一部分中的同一个项目，请设置一个名为 `toolbar.xml` 的 app-bar 布局。

1.  打开 `activity_main` 并用以下代码替换：

    ```kt
    <android.support.v4.widget.DrawerLayout  

        android:id="@+id/drawer" 
        android:layout_width="match_parent" 
        android:layout_height="match_parent" 
        android:fitsSystemWindows="true" 
        tools:context=".MainActivity"> 

        <LinearLayout 
            android:layout_width="match_parent" 
            android:layout_height="match_parent" 
            android:orientation="vertical"> 

            <include 
                android:id="@+id/toolbar" 
                layout="@layout/toolbar" /> 

            <FrameLayout 
                android:id="@+id/fragment" 
                android:layout_width="match_parent" 
                android:layout_height="match_parent"> 
            </FrameLayout> 

        </LinearLayout> 

        <android.support.design.widget.NavigationView 
            android:id="@+id/navigation_view" 
            android:layout_width="wrap_content" 
            android:layout_height="match_parent" 
            android:layout_gravity="start" 
            app:headerLayout="@layout/header" 
            app:menu="@menu/menu_drawer" /> 

    </android.support.v4.widget.DrawerLayout> 

    ```

如你所见，这里的根布局是由支持库提供的 **DrawerLayout**。注意 `fitsSystemWindows` 属性；这就是使得抽屉延伸到状态栏下方的屏幕顶部的原因。在样式中将 `statusBarColor` 设置为 `android:color/transparent`，抽屉现在可以通过状态栏看到。

即使使用 AppCompat，这个效果在运行 Android 5.0（API 21）以下版本的设备上也是不可用的，这将改变标题的显示宽高比并裁剪任何图片。为了解决这个问题，创建一个不设置 `fitsSystemWindows` 属性的替代 `styles.xml` 资源。

布局的其余部分包括一个 LinearLayout 和 **NavigationView** 本身。这个线性布局包含我们的应用栏和一个空的 **FrameLayout**。FrameLayout 是最简单的布局，只包含单个条目，通常用作占位符，在这种情况下，它将根据用户从导航菜单中的选择来包含内容。

从前面的代码可以看出，我们需要一个用于标题的布局文件和一个用于抽屉本身的菜单文件。`header.xml` 文件应该在 `layout` 目录中创建，并如下所示：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<RelativeLayout  
    android:layout_width="match_parent" 
    android:layout_height="header_height" 
    android:background="@drawable/header_background" 
    android:orientation="vertical"> 

    <TextView 
        android:id="@+id/feature" 
        android:layout_width="wrap_content" 
        android:layout_height="wrap_content" 
        android:layout_above="@+id/details" 
        android:gravity="left" 
        android:paddingBottom="8dp" 
        android:paddingLeft="16dp" 
        android:text="@string/feature" 
        android:textColor="#FFFFFF" 
        android:textSize="14sp" 
        android:textStyle="bold" /> 

    <TextView 
        android:id="@+id/details" 
        android:layout_width="wrap_content" 
        android:layout_height="wrap_content" 
        android:layout_alignStart="@+id/feature" 
        android:layout_alignParentBottom="true" 
        android:layout_marginBottom="16dp" 
        android:gravity="left" 
        android:paddingLeft="16dp" 
        android:text="@string/details" 
        android:textColor="#FFFFFF" 
        android:textSize="14sp" /> 

</RelativeLayout> 

```

你需要向 `dimens.xml` 文件中添加以下值：

```kt
<dimen name="header_height">192dp</dimen> 

```

如你所见，我们需要一张用作标题的图片。这里称它为 `header_background`，它的宽高比应该是 4:3。

如果你在这个布局在不同的屏幕密度设备上进行测试，你很快就会发现这个宽高比没有得到保持。我们可以通过类似管理图像资源的方式，使用配置限定符来轻松解决这个问题。为此，请按照这里概述的简单步骤操作：

1.  为每个密度范围创建新的目录，其名称如 `values-ldpi`、`values-mdpi` 等，直至 `values-xxxhdpi`。

1.  在每个文件夹中复制一份 `dimens.xml` 文件。

1.  在每个文件中设置 `header_height` 的值，以匹配该屏幕密度。

菜单文件名为`menu_drawer.xml`，应放置在`menu`目录中，你可能需要创建这个目录。每个项目都有一个关联的图标，这些都可以在资源工作室中找到。代码本身应与以下内容相匹配：

```kt
<?xml version="1.0" encoding="utf-8"?> 
<menu > 

    <item 
        android:id="@+id/drama" 
        android:icon="@drawable/drama" 
        android: /> 

    <item 
        android:id="@+id/film" 
        android:icon="@drawable/film" 
        android: /> 

    <item 
        android:id="@+id/sport" 
        android:icon="@drawable/sport" 
        android: /> 

    <item 
        android:id="@+id/news" 
        android:> 
        <menu> 
            <item 
                android:id="@+id/national" 
                android:icon="@drawable/news" 
                android: /> 

            <item 
                android:id="@+id/international" 
                android:icon="@drawable/international" 
                android: /> 

        </menu> 
    </item> 
</menu> 

```

由于设计库，滑动抽屉和导航视图的大部分度量标准（如边距和文本大小）都为我们处理好了。然而，抽屉标题上的文本大小、位置和颜色并没有。尽管共享背景，但文本应该被认为是一个本身高度为 56-dp 的组件。它应该有 16-dp 的内部填充和 8-dp 的行间距。这，加上正确的文本颜色、大小和权重可以从前面的代码中得出。

## 比例关键线

当一个元素（如滑动抽屉）填满整个屏幕的高度，并被分为垂直段时，如我们的抽屉在标题和内容之间，那么这些分段只能在某些点发生，这些点称为比例关键线。这些点由元素的宽度和距离顶部发生分割的比例决定。在材料布局中有六种这样的比例，它们定义为宽高比（`width:height`），如下所示：

+   16:9

+   3:2

+   4:3

+   1:1

+   3:4

+   2:3![比例关键线](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_03_009.jpg)

在此示例中，选择了 4:3 的比例，抽屉的宽度为 256 dp。我们还可以制作一个具有 16:9 比例的标题，并将`layout_height`设置为 144 dp。

比例关键线仅与包含元素的顶部距离有关；你不能在一个 16:9 视图下方再放置另一个。但是，如果另一个视图从顶部视图的底部延伸到另一条比例关键线，你可以在其下方放置另一个视图：

![比例关键线](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_03_010.jpg)

## 激活抽屉

现在剩下的就是用 Java 实现一些代码，让布局工作。这是通过监听回调方法实现的，当用户与抽屉交互时调用。以下步骤演示了如何实现这一点：

1.  打开 MainActivity 文件，并在`onCreate()`方法中添加以下行，用我们的工具栏替换动作栏：

    ```kt
    toolbar = (Toolbar) findViewById(R.id.toolbar); 
    setSupportActionBar(toolbar); 

    ```

1.  在此之下，添加以下行来配置抽屉：

    ```kt
    drawerLayout = (DrawerLayout) findViewById(R.id.drawer); 
    ActionBarDrawerToggle toggle = new ActionBarDrawerToggle(this, drawerLayout, toolbar, R.string.openDrawer, R.string.closeDrawer) { 

    public void onDrawerOpened(View v) { 
        super.onDrawerOpened(v); 
    } 

    public void onDrawerClosed(View v) { 
         super.onDrawerClosed(v); 
    } 

    }; 

    drawerLayout.setDrawerListener(toggle); 
    toggle.syncState(); 

    ```

1.  最后，添加此代码来设置导航视图：

    ```kt
    navigationView = (NavigationView) findViewById(R.id.navigation_view); 

    navigationView.setNavigationItemSelectedListener(new NavigationView.OnNavigationItemSelectedListener() { 

        @Override 
        public boolean onNavigationItemSelected(MenuItem item) { 

            drawerLayout.closeDrawers(); 

            switch (item.getItemId()) { 
                case R.id.drama: 
                    Log.d(DEBUG_TAG, "drama"); 
                    return true; 
                case R.id.film: 
                    Log.d(DEBUG_TAG, "film"); 
                    return true; 
                case R.id.news: 
                    Log.d(DEBUG_TAG, "news"); 
                    return true; 
                case R.id.sport: 
                    Log.d(DEBUG_TAG, "sport"); 
                    return true; 
                default: 
                    return true; 
                    } 
                } 
            }); 

    ```

    ![激活抽屉](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_03_011.jpg)

上述 Java 代码允许我们在设备或模拟器上查看抽屉，但在选择导航项时几乎不起作用。我们真正需要做的是实际上跳转到应用程序的另一部分。这很容易实现，我们稍后会介绍。首先，在前面代码中有一两点需要提一下。

以 `ActionBarDrawerToggle` 开头的这行代码是导致应用栏上出现打开抽屉的汉堡包图标的代码，当然，你也可以从屏幕左侧向内滑动来打开它。两个字符串参数 `openDrawer` 和 `closeDrawer` 是出于可访问性考虑的，它们会被读给那些看不清屏幕的用户听，应该表述为类似“导航抽屉打开”和“导航抽屉关闭”。两个回调方法 `onDrawerOpened()` 和 `onDrawerClosed()` 在这里留空了，但它们展示了可以拦截这些事件的位置。

调用 `drawerLayout.closeDrawers()` 是必不可少的，因为否则抽屉将保持打开状态。在这里，我们使用了调试器来测试输出，但理想情况下我们希望菜单能引导我们到应用的其他部分。这并不是一个困难的任务，同时也提供了一个很好的机会来介绍 SDK 中最有用和多功能的类之一，即**碎片**。

## 添加碎片

根据我们目前所学到的知识，可以想象为具有多个功能的 apps 会使用单独的活动，尽管这通常是情况，但它们可能会成为资源的昂贵消耗，并且活动总是占据整个屏幕。碎片就像迷你活动，它们既有 Java 也有 XML 定义，并且具有与活动相同的许多回调和功能。与活动不同，碎片不是顶级组件，必须驻留在宿主活动中。这种做法的优点是我们可以拥有一个屏幕上的多个碎片。

要了解如何做到这一点，请创建一个新的 Java 类，比如叫 `ContentFragment`，然后按照以下步骤完成它，确保导入的是 `android.support.v4.app.Fragment` 而不是标准版本：

```kt
public class ContentFragment extends Fragment { 

    @Override 
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) { 
        View v = inflater.inflate(R.layout.content,container,false); 
        return v; 
    } 
} 

```

至于 XML 元素，创建一个名为 `content.xml` 的布局文件，并在其中放置你选择的任意视图和小部件。现在需要的只是当选择导航项时调用它的 Java 代码。

打开 `MainActivity.Java` 文件，并在 `switch` 语句中用以下内容替换一个 Debug 调用：

```kt
ContentFragment fragment = new ContentFragment(); 
android.support.v4.app.FragmentTransaction transaction = getSupportFragmentManager().beginTransaction(); 
transaction.replace(R.id.fragment, fragment); 
transaction.addToBackStack(null); 
transaction.commit(); 

```

我们在这里构建的示例只是为了演示抽屉布局和导航视图的基本结构。显然，要添加任何实际的功能，我们需要为菜单中的每个项都准备一个碎片，除非这样做，否则 `transaction.addToBackStack(null);` 这行代码实际上是多余的。它的功能是确保系统以记录使用哪个活动的方式记录用户访问每个碎片的顺序，这样当用户按下返回键时，他们将返回到上一个碎片。如果没有它，他们将被返回到上一个应用，而容器活动将被销毁。

## 右手抽屉

作为顶级导航组件，滑动抽屉应该只从左侧滑入，并遵循之前概述的度量标准。然而，要实现从右侧滑入的抽屉非常容易，对于许多次要功能来说，这可能是有吸引力的：

![右手侧抽屉](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_03_012.jpg)

让滑动抽屉从右侧出现仅是设置布局重力的问题，例如：

```kt
android:layout_gravity="end" 

```

与传统的导航视图不同，它不应比屏幕宽度减去主应用栏的高度更宽，而右手侧抽屉可以延伸到整个屏幕。

本章的内容一直关于 UI 设计，我们还没有遇到过任何设计模式。我们本可以在这里使用设计模式，但选择专注于 Android UI 的机制。我们将在本书的后面看到，门面模式对于简化复杂菜单或布局的编码非常有用。

几乎可以在任何地方引入的一个设计模式是单例模式。这是因为它几乎可以在任何地方使用，其目的是提供一个对象的全球实例。

# 单例模式。

单例模式无疑是所有模式中最简单的一个，但同时也是最具争议的一个。许多开发者认为它完全没必要，认为将一个类声明为静态可以达到相同的功能，而且更为简单。尽管单例模式确实在许多本可以使用静态类的情况下被过度使用，但确实存在一些场合，单例模式比静态类更为合适：

+   当你想要对一个传递给它的变量执行函数时，使用静态类，例如，计算价格变量的折扣值。

+   当你想要一个完整的对象，但只有一个，并且希望这个对象可以被程序的任何部分访问时，使用单例模式，例如，代表当前登录应用的个人用户的对象。

单例模式的类图，正如你所想象的，非常简单，正如你在这里看到的：

![单例模式](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-dsn-ptn-best-prac/img/image_03_013.jpg)

如前面的图表所示，以下示例假设我们一次只登录一个用户到我们的应用，并且我们将创建一个可以从代码任何部分访问的单例对象。

Android Studio 在项目资源管理器的**新建**菜单下提供了单例创建功能，因此我们可以从这里开始。这个演示只有两个步骤，如下所示。

1.  将这个类添加到你的项目中：

    ```kt
    public class CurrentUser { 
        private static final String DEBUG_TAG = "tag"; 
        private String name; 

        // Create instance 
        private static CurrentUser user = new CurrentUser(); 

        // Protect class from being instantiated 
        private CurrentUser() { 
        } 

        // Return only instance of user 
        public static CurrentUser getUser() { 
            return user; 
        } 

        // Set name 
        protected void setName(String n) { 
            name = n; 
        } 

        // Output user name 
        protected void outputName() { 
            Log.d(DEBUG_TAG, name); 
        } 
    } 

    ```

1.  通过向活动中添加如下代码来测试这个模式：

    ```kt
    CurrentUser user = CurrentUser.getUser(); 
    user.setName("Singleton Pattern"); 
    user.outputName(); 

    ```

单例模式可能非常有用，但很容易不必要地使用它。在异步任务时非常有用，如文件系统，并且当我们希望从代码的任何地方访问其内容时，比如前面示例中的用户名。

# 总结

无论应用的目的如何，用户需要一种熟悉的方式来访问它的功能。应用栏和导航抽屉不仅容易被用户理解，而且提供了极大的灵活性。

在本章中，我们了解了如何在安卓设备上应用两种最重要的输入机制以及控制它们外观的材料设计模式。"SDK，尤其是设计库，使得编写这些结构既简单又直观。尽管与迄今为止我们遇到的设计模式不同，但材料设计模式发挥着类似的功能，并指导我们走向更好的实践。

下一个章节将继续探讨布局设计，并研究在组合整个布局时我们可以使用的工具，以及我们如何设法开发适应各种屏幕形状和大小的应用。
