# JavaFX 基础知识（一）

> 原文：[`zh.annas-archive.org/md5/E51DD19915A0979B8B23880AAD773381`](https://zh.annas-archive.org/md5/E51DD19915A0979B8B23880AAD773381)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

正如其标题（JavaFX 8 Essentials）所暗示的，本书是一本实用的书，为您提供了一套强大的基本技能，将指导您自信地快速构建高性能的 JavaFX 8 客户端应用程序。这些应用程序利用现代 GPU 通过硬件加速图形，同时为您的客户提供引人注目、复杂和花哨的富客户端 GUI，这将给他们留下深刻的印象。

学习 JavaFX 8 基础知识是跳入创建应用程序的第一步，最重要的是它可以在任何平台上运行，从桌面、Web、移动设备、平板电脑到 Arduino、Raspberry Pi 和多核开发等嵌入式设备。遵循 Java 的“一次编写，到处运行”的范例，JavaFX 也保持了相同的特性。因为 JavaFX 8 完全是用 Java 语言从头开始编写的，所以您会感到非常熟悉。

大多数章节都是一个快节奏的指南，将帮助您快速入门 Java GUI 编程，利用 JavaFX 8 并在任何平台上部署和运行。

在阅读本书示例时，您会发现代码是使用 Java 8 上的 JavaFX 8 编写的（是的，Java SE 8），因此新的 API 和语言增强将帮助您成为更有生产力的开发人员。话虽如此，探索所有新的 Java 8 功能将非常方便（我鼓励您这样做）。

最后但同样重要的是，您将能够使用 JavaFX 开发令人惊叹的无触摸交互式运动应用程序，这些应用程序与 Leap 运动设备进行交互。

# 本书涵盖的内容

第一章，“使用 JavaFX 8 入门”，是对 JavaFX 8 的介绍。它讨论了 JavaFX 8 作为一种技术，为什么您应该关注它，它的历史，核心特性以及它可以使用的地方。

因此，现在是时候准备好正确的工具，并通过必要的步骤安装 JavaFX 8 及其支持的开发工具。在本章中了解将增加读者生产力的其他工具。作为我们正在正确的轨道上的最终验证，我们将以一个简单的 Hello JavaFX 应用程序结束本章。

第二章，“JavaFX 8 基础知识和创建自定义 UI”，讨论了没有比接收复杂的建议更令人沮丧的事情了。因此，我一直把重点放在基本要点上。为了在 JavaFX 场景上呈现图形，您将需要一个基本应用程序、场景、画布、形状、文本、控件和颜色。

此外，您将了解 JavaFX 8 基本应用程序结构，这些结构是未来任何应用程序的支柱。最后，我们还将探讨一些 Java SE 8 功能（如 Lambda、Streams、JavaFX 属性等），以帮助提高代码的可读性、质量和生产力。

在获得创建结构化 JavaFX 8 应用程序的实际经验后，如果您可以在不改变其功能的情况下更改应用程序的 UI，那将是件好事吗？在本章中，您将学习主题化以及如何通过应用各种主题（外观和感觉）和 JavaFX CSS 样式的基础知识来自定义应用程序。

您将使用 Scene Builder 以图形方式创建和定义 UI 屏幕，并将它们保存为 JavaFX FXML 格式的文件。最后，您将学习如何创建自定义控件。

第三章，“开发 JavaFX 桌面和 Web 应用程序”，涵盖了如何开发引人注目的桌面和 Web 应用程序，利用多核硬件加速的 GPU，提供高性能的基于 UI 的应用程序，并具有令人惊叹的外观。

由于 JavaFX 完全是用 Java 从头开始编写的，一些 Java SE 8 内置核心库将用于支持我们的应用程序。此外，您将学习如何将应用程序打包为独立应用程序以进行启动和分发。

此外，我们还将介绍任何 Web 应用程序中的基本核心 Web API，这些 API 由 JavaFX 8 支持，如`javafx.scene.web.WebEngine`和`javafx.scene.web.WebView`。

我们还将讨论 JavaFX 与 HTML5 之间的关系，这很重要，因为它们互补。JavaFX 的丰富客户端 API，加上 HTML5 的丰富 Web 内容，创建了一种类似 RIA Web 应用程序的用户体验，具有本机桌面软件的特征。

第四章，“为 Android 开发 JavaFX 应用程序”，随着非 PC 客户端的增加，移动电话和平板电脑正在获得市场份额。JavaFX 8 可以为 Web 和桌面提供丰富的客户端应用程序。如果您编写 JavaFX 应用程序，请确保您希望它在尽可能多的设备上运行。本章将为您提供关于允许用户为 Android 手机创建本机应用程序的 SDK 的基本实践经验和知识。

第五章，“为 iOS 开发 JavaFX 应用程序”，是对上一章的延伸。如果您为 Android 编写 JavaFX 应用程序，请确保您希望它在尽可能多的 iOS 设备上运行。本章将为您提供关于允许用户为 Apple iOS 创建本机应用程序的 SDK 的基本实践经验和知识。

第六章，“在树莓派上运行 JavaFX 应用程序”，将为您提供开发在信用卡大小的计算机——树莓派板上运行的 JavaFX 8 应用程序所需的所有必要技能和知识。随着物联网（IoT）最近成为热门话题。Java 实际上是为物联网而生的。

第七章，“使用 JavaFX 监控和控制 Arduino”，涵盖了另一种物联网（IoT）。Arduino 是一个开源的电子原型平台，提供低成本的原型平台，支持自助概念和创客运动。

本章将为您提供所有必要的技能和知识，以快速使用 JavaFX 与 Arduino 板开发用于监控来自现实世界的数据或控制真实设备的桌面应用程序。

第八章，“使用 JavaFX 交互式 Leap Motion 应用程序”，将使您了解手势识别。您将发现一个令人惊叹的小工具——Leap Motion 设备，它将允许一种无触摸的方法来开发增强的 JavaFX 应用程序。

机器用户输入界面越来越不再以鼠标为中心，而是更倾向于多点触摸甚至无触摸输入。手势是人类如今可以自然地与机器交流的一种方式。

附录 A，“成为 JavaFX 大师”，将帮助您找到许多有用的链接和参考资料，帮助您进一步了解所有关于 JavaFX 的事情。

在本章结束时，请务必查看今天在生产中使用 JavaFX 的许多框架、库和项目。

# 本书所需内容

本书中给出的示例利用了写作时的最新 Java SE 8 版本，即 Java SE 8 更新 45 JDK 版本。从 Java SE 8 开始，它预先捆绑了我们在整本书中使用的 JavaFX 8。此外，NetBeans IDE 8.0.2 用作集成开发环境，以及 JavaFX 设计工具 Gluon Scene Builder 版本 8，作为一般软件和工具。

由于每个章节在其性质上都是独特的，并且需要特定的软件和硬件才能正常运行 JavaFX 8 示例，因此本书提供了所有必需的软件、工具和硬件，并详细解释了如何安装和配置它们，以便顺利运行 JavaFX 8 示例。

# 这本书适合谁

如果您是 Java 开发人员，有经验的 Java Swing、Flash/Flex、SWT 或 Web 开发人员，希望将客户端应用程序提升到更高水平，那么这本书适合您。这本书将帮助您开始创建一个时尚、可定制和引人入胜的用户界面。

此外，您还将学习如何快速创建高性能的富客户端应用程序，这些应用程序可以在任何平台上运行，无论是桌面、网络、移动还是嵌入式系统，比如树莓派、Arduino 以及基于无触控 Leap Motion 的应用程序。

这本书是一本快节奏的指南，将帮助您快速入门 Java GUI 编程，利用 JavaFX 8，在任何平台上部署和运行。

# 约定

在本书中，您会发现一些区分不同信息类型的文本样式。以下是一些这些样式的例子，以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“我们可以通过使用`include`指令包含其他上下文。”

代码块设置如下：

```java
btn.setOnAction(new EventHandler<ActionEvent>() {
  @Override
  public void handle(ActionEvent event) {
    message.setText("Hello World! JavaFX style :)");
  }
});
```

任何命令行输入或输出都以以下形式书写：

```java
$ gradle build

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，比如菜单或对话框中的单词，会以这样的形式出现在文本中：“点击**安装**开始安装”。

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会出现在这样。

# 读者反馈

我们始终欢迎读者的反馈。请告诉我们您对这本书的看法——您喜欢或不喜欢的地方。读者的反馈对我们开发能让您真正受益的标题至关重要。

要向我们发送一般反馈，只需发送电子邮件至`<feedback@packtpub.com>`，并在您的消息主题中提及书名。

如果您在某个专题上有专业知识，并且有兴趣撰写或为一本书做出贡献，请参阅我们的作者指南，网址为[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

现在您是 Packt 图书的自豪所有者，我们有一些事情可以帮助您充分利用您的购买。

## 下载示例代码

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接将文件发送到您的电子邮件。

## 下载本书的彩色图片

我们还为您提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图片。彩色图片将帮助您更好地理解输出的变化。您可以从[`www.packtpub.com/sites/default/files/downloads/8026OS_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/8026OS_ColorImages.pdf)下载此文件。

## 勘误

尽管我们已经尽最大努力确保内容的准确性，但错误是难免的。如果您在我们的书籍中发现错误，无论是文字还是代码方面的错误，我们将不胜感激地接受您的报告。通过这样做，您可以帮助其他读者避免挫折，并帮助我们改进后续版本的书籍。如果您发现任何勘误，请访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)进行报告，选择您的书籍，点击**勘误提交表格**链接，并输入您的勘误详情。一旦您的勘误经过验证，您的提交将被接受，并且勘误将被上传到我们的网站上，或者添加到该书籍的勘误列表中的 Errata 部分。您可以通过访问[`www.packtpub.com/support`](http://www.packtpub.com/support)来查看任何现有的勘误。

## 盗版

互联网上侵犯版权的行为是跨媒体持续存在的问题。在 Packt，我们非常重视版权和许可的保护。如果您在互联网上发现我们作品的任何非法副本，请立即向我们提供地址或网站名称，以便我们采取补救措施。

如果您发现涉嫌盗版的材料，请通过`<copyright@packtpub.com>`与我们联系。

我们感谢您在保护我们的作者和我们为您提供有价值的内容的能力方面的帮助。

## 问题

如果您在阅读本书的过程中遇到任何问题，请通过`<questions@packtpub.com>`与我们联系，我们将尽力解决。


# 第一章：使用 JavaFX 8 入门

JavaFX 是 Java 的下一代图形用户界面（GUI）工具包。它是一个平台，可以轻松快速地构建高性能的 Java 客户端应用程序。

JavaFX 的底层引擎利用现代 GPU 通过硬件加速图形，同时提供设计良好的编程接口，从而使开发人员能够结合图形、动画和 UI 控件。

这些功能使您能够为客户提供引人入胜、复杂且完全可定制的客户端 GUI，这将让他们非常印象深刻。

虽然 Java 最初的目标是嵌入式和客户端世界，但自 2006 年以来，许多原因推动 Java 语言成为企业世界的顶级开发平台。

但最近，随着 JavaFX 平台作为标准客户端 GUI 的进入，这些最初的目标又开始重新流行起来。

尽管 JavaFX 不仅仅是一个 GUI 工具包，但它允许 Java 开发人员创建具有引人入胜的用户界面并轻松连接到后端系统的客户端应用程序。

此外，JavaFX 灵活的 FXML 支持使您能够轻松构建 MVC（模型-视图-控制器）架构模式应用，并使用 Scene Builder 工具采用所见即所得的方法。

JavaFX 的绑定功能简化了实体之间的通信，并进一步支持 MVC。除此之外，JavaFX 还提供了使用 CSS 快速、可定制的 UI 建模。

通过添加一个完整的`WebView`组件和文档模型，将其映射到 Java 代码变得容易，并为 3D 和媒体功能提供了很好的支持。

在本章中，我们将涵盖以下主题：

+   什么是 JavaFX 以及它的目标平台？

+   JavaFX 历史概览

+   JavaFX 的目标、特性以及 JavaFX 8 的新功能

+   如何安装 Java SE 8、JavaFX 8、NetBeans，并配置环境变量

+   开发一个“Hello World”JavaFX 8 应用程序，并了解 JavaFX 8 的基本应用程序架构和构建模块

# JavaFX 的目标

JavaFX 诞生的初衷是被用于许多类型的设备，如嵌入式设备、智能手机、电视、平板电脑和台式电脑。JavaFX 也遵循 Java 的“一次编写，到处运行”的范式。

JavaFX 8 完全使用 Java 语言编写，让您感到宾至如归。因此，使用 JavaFX 编写的应用程序可以部署在台式机、笔记本电脑、Web、嵌入式系统、移动设备和平板电脑上。

嵌入式系统不再得到 Oracle 的支持；它留给了像 ARM 等公司来支持。从 JavaFX 2.x 到 8.x，移动设备从未得到支持；现在的支持仅存在于 OpenJFX。社区受益于开源将 JavaFX 带入移动环境。

有关 OpenJFX 的更多信息，请访问[`wiki.openjdk.java.net/display/OpenJFX/Main`](https://wiki.openjdk.java.net/display/OpenJFX/Main)。

JavaFX 是一套图形和媒体包，使开发人员能够设计、创建、测试、调试和部署在各种平台上一致运行的丰富客户端应用程序，而无需使用许多单独的库、框架和 API 来实现相同的目标。这些单独的库包括媒体、UI 控件、`WebView`、3D 和 2D API。

因此，如果您是一名 Java 前端开发人员，一名有经验的 Java Swing、Flash/Flex、SWT 或 Web 开发人员，希望将您的客户端应用程序提升到一个新水平，并且想要为您的客户开发一个引人注目且复杂的用户界面，那么学习 JavaFX 技能是正确的选择——这本书适合您。

# 入门

本章是对 JavaFX 8 的介绍；我们已经谈到了 JavaFX 8 作为一种技术以及为什么你应该关心它。

接下来，我们将浏览其历史，探索其核心特性以及它可以使用的地方。

在开始使用本书学习 JavaFX 8 之前，我们将通过安装各种所需的软件捆绑包来准备您的开发环境，以便能够编译和运行其中的许多示例。

在本章中，您将学习如何安装所需的软件，如**Java 开发工具包 JDK**和 NetBeans **集成开发环境**（**IDE**）。

安装所需的软件后，您将首先创建一个传统的*Hello JavaFX 8*示例。一旦您对开发环境感到满意，作为我们正在正确的轨道上的最终验证，我们将浏览 Hello JavaFX 8 源代码，以了解基本的 JavaFX 8 应用程序架构。

### 注

如果您已经熟悉了 JDK 和 NetBeans IDE 的安装，您可以跳转到第二章，*JavaFX 8 基础知识和创建自定义 UI*，其中涵盖了 JavaFX 8 的基础知识以及如何创建自定义 UI 组件。

那么你还在等什么？让我们开始吧！

# JavaFX 历史

你可能认为 JavaFX 是一种相当新的技术，但实际上并不是。JavaFX 已经存在很长时间了；自 2005 年以来就一直存在。自从 Sun Microsystems 收购了*SeeBeyond*公司以来，就有了一个名为**F3**（**F**orm **F**ollows **F**unction）的图形丰富的脚本语言，由工程师 Chris Oliver 创建。

在 2007 年的 JavaOne 大会上，Sun Microsystems 正式将 JavaFX 作为语言的名称公布，而不是 F3。在 2007 年至 2010 年期间，甲骨文收购了许多大公司，如 BEA Systems、JD Edwards、Siebel Systems 等。当时我正在甲骨文工作，负责将不同的客户支持渠道整合到甲骨文支持网站*MetaLink*中。

2009 年 4 月 20 日，甲骨文公司宣布收购 Sun Microsystems，使甲骨文成为 JavaFX 的新管理者。

在 2010 年的 JavaOne 大会上，甲骨文宣布了 JavaFX 路线图，其中包括计划淘汰 JavaFX 1.3 脚本语言并为基于 Java 的 API 重新创建 JavaFX 平台。如承诺的那样，JavaFX 2.0 SDK 于 2011 年 10 月的 JavaOne 上发布。

除了发布 JavaFX 2.0 之外，Oracle 还通过宣布致力于采取措施使 JavaFX 开源，从而允许 Java 多才多艺和强大的社区帮助推动平台发展。JavaFX 开源增加了其采用率，使得错误修复的周转时间更快，并产生了新的增强功能。

在 JavaFX 2.1 和 2.2 之间，新功能的数量迅速增长。JavaFX 2.1 是 Java SDK 在 Mac OS 上的官方发布。JavaFX 2.2 是 Java SDK 在 Linux 操作系统上的官方发布。

没有 JavaFX 3.x 这样的东西，但是在 2014 年 3 月 18 日宣布的 Java SE 8 发布中，Java 开发世界发生了重大变化。Java SE 8 具有许多新的 API 和语言增强功能，包括**Lambda**、Stream API、Nashorn JavaScript 引擎和*JavaFX API*，这些都被纳入标准 JDK 捆绑包中，JavaFX 版本成为直接继承 JavaFX 2.0 的 8。

要查看 Java SE 8 中的所有新功能，请访问[`www.oracle.com/technetwork/java/javase/8-whats-new-2157071.html`](http://www.oracle.com/technetwork/java/javase/8-whats-new-2157071.html)。

## JavaFX 8 何时可用？

答案是*现在*。如前所述，Java SE 8 于 2014 年 3 月 18 日发布。对于使用 Java 构建客户端应用程序的开发人员，JavaFX 丰富的互联网应用程序框架现在支持 Java 8。

大多数 Java 企业版供应商也支持 Java 8。是否立即转移到 Java SE 8 取决于您正在处理的项目类型。

### 注

事实上，根据 Oracle JDK 支持路线图，在 2015 年 4 月之后，Oracle 将不会在其公共下载站点上发布 Java SE 7 的进一步更新。

JavaFX API 作为**Java SE Runtime Environment**（**JRE**）和 JDK 的完全集成功能可用。JDK 适用于所有主要桌面平台（*Windows*、*Mac OS X*、*Solaris*和*Linux*），因此 JavaFX 也将在所有主要桌面平台上运行。

关于 JavaFX 8，它支持以下 API：

+   3D 图形

+   富文本支持

+   打印 API。

# JavaFX 功能

根据 JavaFX 的官方文档，以下功能包括在 JavaFX 8 及以后的版本中：

+   **Java API**：JavaFX 是一个由 Java 代码编写的类和接口的 Java 库。

+   **FXML 和 Scene Builder**：这是一种基于 XML 的声明性标记语言，用于构建 JavaFX 应用程序用户界面。您可以在 FXML 中编码，也可以使用 JavaFX Scene Builder 交互式设计 GUI。Scene Builder 生成可以移植到像 NetBeans 这样的 IDE 中的 FXML 标记，您可以在其中添加业务逻辑。此外，生成的 FXML 文件可以直接在 JavaFX 应用程序中使用。

+   **WebView**：这是一个 Web 组件，使用`WebKit`，一种 HTML 渲染引擎技术，可以在 JavaFX 应用程序中嵌入网页。在`WebView`中运行的 JavaScript 可以调用 Java API，反之亦然。

+   **Swing/SWT 互操作性**：现有的 Swing 和 SWT 应用程序可以从 JavaFX 功能中受益，如丰富的图形、媒体播放和嵌入式网页内容。

+   **内置 UI 控件和 CSS**：JavaFX 提供了所有主要的 UI 控件，以及一些额外的不常见的控件，如图表、分页和手风琴，这些控件是开发完整功能的应用程序所需的。组件可以使用标准的 Web 技术（如 CSS）进行皮肤化。

+   **3D 图形功能**：包括对 3D 图形库的支持。

+   **Canvas API**：您可以使用 Canvas API 直接在 JavaFX 场景区域内绘制，它由一个图形元素（节点）组成。

+   **多点触控支持**：基于底层平台的能力支持多点触控操作。

+   **硬件加速图形管道**：JavaFX 图形基于图形渲染管道*Prism*。当与支持的图形卡或**图形处理单元**（**GPU**）一起使用时，Prism 引擎可以平滑快速地渲染 JavaFX 图形。如果系统不具备其中之一，则 Prism 将默认为软件渲染堆栈。

+   **高性能媒体引擎**：该引擎提供了一个稳定的、低延迟的基于`GStreamer`多媒体框架的媒体框架。支持 Web 多媒体内容的播放。

+   **自包含部署模型**：自包含应用程序包含所有应用程序资源和 Java 和 JavaFX 运行时的私有副本。它们被分发为本机可安装的软件包，并为该操作系统提供与本机应用程序相同的安装和启动体验。

## JavaFX 8 的新功能

以下是 Java SE 8 版本的 JavaFX 组件中新增功能和重大产品变更的简要总结：

+   新的*Modena 主题*现在是 JavaFX 应用程序的默认主题。

+   增加了对其他 HTML5 功能的支持，包括 Web Sockets、Web Workers、Web Fonts 和打印功能。

+   该 API 使您能够使用新的`SwingNode`类将**Swing**内容嵌入到 JavaFX 应用程序中，从而改进了 Swing 互操作性功能。

+   现在提供了内置的 UI 控件`DatePicker`、`Spinner`和`TableView`。

+   它通过`javafx.print`包提供了公共 JavaFX 打印 API。

+   支持高 DPI 显示。

+   CSS 可样式化类成为公共 API。

+   引入了一个计划服务类。

+   3D 图形库已经增强了几个新的 API 类。

+   在此版本中，*Camera API*类进行了重大更新。

+   现在 JavaFX 8 支持丰富的文本功能。这些包括在 UI 控件中支持泰语和印地语等双向和复杂文本脚本，以及文本节点中的多行、多样式文本。

+   对话框和辅助功能 API 得到支持。

在附录中，*成为 JavaFX 专家*，我提供了您成为 JavaFX 专家所需的所有参考资料（链接、书籍、杂志、文章、博客和工具）和真实的 JavaFX 8 生产应用程序的清单。

下图显示了使用 JavaFX 8 构建的`Ensemble8.jar`应用程序，展示了处理各种 JavaFX 8 组件、主题和概念的示例。更有趣的是，源代码可供学习和修改-请参阅最后一章以了解如何安装此应用程序。

![JavaFX 8 的新功能](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_01_01.jpg)

JavaFX 8 应用程序

应用程序涵盖了许多主题，特别是新的 JavaFX 8 3D API，可以在下图中的 3D 图形部分找到：

![JavaFX 8 的新功能](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_01_02.jpg)

JavaFX 8 3D 应用程序

# 安装所需的软件

到目前为止，我们已经对 JavaFX 有了一个很好的介绍，我和你一样急于开始创建和启动我们的第一个`"Hello JavaFX 8"`应用程序。但是，如果没有下载和安装允许我们创建和编译本书大部分代码的正确工具，这是不可能的。

您需要下载并安装*Java 8 Java 开发工具包*（JDK）或更高版本。而不是运行时版本（JRE）。

从以下位置下载最新的 Java SE 8u45 JDK 或更高版本：

[`www.oracle.com/technetwork/java/javase/downloads/index.html`](http://www.oracle.com/technetwork/java/javase/downloads/index.html)

从以下链接下载并安装 NetBeans 8.0.2 或更高版本[`netbeans.org/downloads`](https://netbeans.org/downloads)，尽管推荐使用 NetBeans IDE **All** Bundle，*您也可以使用 Java EE 捆绑包*，如图所示：

![安装所需的软件](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_01_03.jpg)

NetBeans 捆绑包下载。

目前，JavaFX 8 可以在以下操作系统上运行：

+   Windows 操作系统（XP、Vista、7、8）32 位和 64 位

+   Mac OS X（64 位）

+   Linux（32 位和 64 位），Linux ARMv6/7 VFP，HardFP ABI（32 位）

+   Solaris（32 位和 64 位）

## 安装 Java SE 8 JDK

本节概述的步骤将指导您成功下载和安装 Java SE 8。从以下位置下载 Java SE 8 JDK：

[`www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html`](http://www.oracle.com/technetwork/java/javase/downloads/jdk8-downloads-2133151.html)

在以下步骤中，将以 Mac OS X Yosemite（10.10.3）操作系统上的 Java SE 8u45 JDK 64 位版本（写作时）为例。

其他操作系统和 JDK 版本的步骤类似。但是，如果您的环境不同，请参考以下链接获取更多详细信息：

[`docs.oracle.com/javase/8/docs/technotes/guides/install/toc.html`](http://docs.oracle.com/javase/8/docs/technotes/guides/install/toc.html)

以下是安装 Java SE 8 JDK 的步骤：

1.  通过启动图像文件`jdk-8u45-macosx-x64.dmg`来安装 Java 8 JDK。一旦启动了 JDK 8 设置图像文件，屏幕将出现如下截图。这是软件包设置文件。双击它，安装程序将启动：![安装 Java SE 8 JDK](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_01_04.jpg)

JDK 8 设置图像文件

### 提示

通常，您需要在计算机上拥有管理员权限才能安装软件。

1.  开始设置 Java 8 JDK。在安装过程开始时，将出现以下屏幕截图中的屏幕。单击**继续**按钮，然后在**安装**类型屏幕向导上，单击**安装**开始安装。![安装 Java SE 8 JDK](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_01_05.jpg)

Java SE 开发工具包 8 设置

1.  一旦点击**安装**，您可能会被要求输入密码。输入密码，单击**确定**，安装将继续进行，显示一个进度条，如下图所示：![安装 Java SE 8 JDK](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_01_06.jpg)

Java SE 开发工具包 8 安装进行中

1.  设置将完成 Java 8 SE 开发工具包的安装。单击**关闭**按钮退出。

### 设置环境变量

现在您需要设置一些关键的环境变量。如何设置它们以及它们应该设置的值取决于您的操作系统。需要设置的两个变量是：

+   **JAVA_HOME**：这告诉您的操作系统 Java 安装目录在哪里。

+   **PATH**：这指定了 Java 可执行目录的位置。这个环境变量让系统搜索包含可执行文件的路径或目录。Java 可执行文件位于`JAVA_HOME`主目录下的 bin 目录中。

为了使`JAVA_HOME`和`PATH`更加永久，您将希望以这样的方式将它们添加到系统中，以便在每次启动或登录时都可以使用。根据您的操作系统，您需要能够编辑环境变量名称和值。

在*Windows 环境*中，您可以使用键盘快捷键*Windows 徽标键+暂停/中断键*，然后单击**高级系统设置**以显示**系统属性**对话框。

接下来，单击**环境变量**。这是您可以添加、编辑和删除环境变量的地方。您将使用已安装的主目录作为值来添加或编辑`JAVA_HOME`环境变量。在 Windows 操作系统的环境变量对话框中显示的是这个屏幕截图：

![设置环境变量](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_01_07.jpg)

Windows 环境变量

让我们设置环境变量：

+   要为**Mac OS X**平台设置`JAVA_HOME`环境变量，您需要启动终端窗口，编辑您的主目录的`.bash_profile`文件，添加以下导出命令：

```java
export JAVA_HOME=$(/usr/libexec/java_home -v 1.8)

```

+   在使用 Bash shell 环境的**Linux**和其他**Unix**操作系统上，启动终端窗口并编辑`~/.bashrc`或`~/.profile`文件，包含导出命令：

```java
export JAVA_HOME=/usr/java/jdk1.8.0
export PATH=$PATH:$JAVA_HOME/bin

```

+   在使用`C` shell（csh）环境的 Linux 和其他 Unix 操作系统上，启动终端窗口并编辑`~/.cshrc`或`~/.login`文件，包含`setenv`命令：

```java
setenv JAVA_HOME /usr/java/jdk1.8.0_45
setenv PATH ${JAVA_HOME}/bin:${PATH}

```

设置好路径和`JAVA_HOME`环境变量后，您将希望通过启动终端窗口并从命令提示符执行以下两个命令来验证您的设置：

```java
java -version
javac –version

```

### 注意

每种情况下的输出都应该显示一个消息，指示语言和运行时的 Java SE 8 版本。

## 安装 NetBeans IDE

在开发 JavaFX 应用程序时，您将使用 NetBeans IDE（或您喜欢的任何其他 IDE）。请确保下载包含 JavaFX 的正确 NetBeans 版本。要安装 NetBeans IDE，请按照以下步骤进行：

1.  从以下位置下载 NetBeans IDE 8.0.2 或更高版本：

[`netbeans.org/downloads/index.html`](https://netbeans.org/downloads/index.html)

1.  启动`.dmg`镜像文件`netbeans-8.0.2-macosx.dmg`。镜像将被验证，打开一个包含安装程序包存档`netbeans-8.0.2.pkg`的文件夹；双击它以启动安装程序。将出现一个带有消息的对话框：*此软件包将运行一个程序来确定是否可以安装软件。*单击**继续**按钮。

1.  一旦启动了 NetBeans 安装对话框，再次点击**继续**。接下来，接受许可证并点击**继续**，然后点击**同意**。

1.  点击**安装**按钮继续。下面的屏幕截图显示了一个**Mac**安全警告提示；输入密码并点击**安装软件**。![安装 NetBeans IDE](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_01_08.jpg)

Mac 安全警告对话框

1.  NetBeans IDE 安装过程将开始。下面的屏幕截图显示了安装进度条：![安装 NetBeans IDE](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_01_09.jpg)

安装进度

1.  点击**关闭**按钮完成安装，如下所示：![安装 NetBeans IDE](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_01_10.jpg)

设置完成

现在，您已经准备好继续创建 JavaFX 应用程序了。

# 创建“Hello World” JavaFX 风格的应用程序

展示创建和构建 JavaFX 应用程序的最佳方式是使用`Hello World`应用程序。

在本节中，您将使用刚刚安装的 NetBeans IDE 来开发、编译和运行基于 JavaFX 的`Hello World`应用程序。

## 使用 Netbeans IDE

要快速开始创建、编码、编译和运行一个简单的 JavaFX 风格的`Hello World`应用程序，使用 NetBeans IDE，按照本节中概述的步骤进行操作：

1.  从**文件**菜单中选择**新建项目**。

1.  从**JavaFX 应用程序类别**中选择**JavaFX 应用程序**。点击**下一步**。

1.  将项目命名为`HelloJavaFX`。可选地，您可以为应用程序类定义包结构。然后点击**完成**，如下所示：![使用 Netbeans IDE](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_01_11.jpg)

新的 JavaFX 应用程序向导

NetBeans 打开`HelloJavaFX.java`文件，并用基本的“Hello World”应用程序的代码填充它。

### 注意

您会发现，这个版本的代码与 NetBeans 实际创建的代码有些不同，您可以进行比较以找出差异，但它们具有相同的结构。我这样做是为了在单击**Say 'Hello World'**按钮时，将结果显示在`Scene`上的文本节点上，而不是控制台上。为此，还使用了`VBox`容器。

1.  右键单击项目，然后从菜单中点击**运行**，如下所示：![使用 Netbeans IDE](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_01_12.jpg)

运行应用程序

1.  NetBeans 将编译和运行该应用程序。输出应该如下所示的屏幕截图：![使用 Netbeans IDE](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_01_13.jpg)

从 NetBeans IDE 启动的 JavaFX Hello World

1.  点击按钮，您应该看到以下结果：![使用 Netbeans IDE](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_01_14.jpg)

JavaFX Hello World 结果

这是基本的 Hello world 应用程序（`HelloJavaFX.java`）的修改后的代码：

```java
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.text.Text;
import javafx.stage.Stage;
import static javafx.geometry.Pos.CENTER;
import javafx.scene.layout.VBox;

/**
  * @author mohamed_taman
 */
public class HelloJavaFX extends Application {

  @Override
  public void start(Stage primaryStage) {

    Button btn = new Button();
    Text message = new Text();

    btn.setText("Say 'Hello World'");

    btn.setOnAction(event -> {
      message.setText("Hello World! JavaFX style :)");
    });

    VBox root = new VBox(10,btn,message);
    root.setAlignment(CENTER);

    Scene scene = new Scene(root, 300, 250);

    primaryStage.setTitle("Hello JavaFX 8 World!");
    primaryStage.setScene(scene);
    primaryStage.show();
  }
  public static void main(String[] args) {
    launch(args);
  }
}
```

## 工作原理

以下是关于 JavaFX 应用程序基本结构的重要信息：

+   JavaFX 应用程序的主类应该扩展`javafx.application.Application`类。`start()`方法是所有 JavaFX 应用程序的*主入口点*。

+   JavaFX 应用程序通过*舞台*和*场景*定义用户界面容器。JavaFX `Stage`类是顶级 JavaFX 容器。JavaFX `Scene`类是所有内容的容器。以下代码片段创建了一个舞台和场景，并使场景在给定的像素大小下可见 - `new Scene(root, 300, 250)`。

+   在 JavaFX 中，场景的内容表示为节点的分层场景图。在本例中，根节点是一个`VBox`布局对象，它是一个可调整大小的布局节点。这意味着根节点的大小跟踪场景的大小，并且在用户调整舞台大小时发生变化。

+   在这里，`VBox`被用作容器，以单列多行的形式垂直排列其内容节点。我们将按钮**btn**控件添加到列中的第一行，然后将文本**message**控件添加到同一列的第二行，垂直间距为 10 像素，如下面的代码片段所示：

```java
VBox root = new VBox(10,btn,message);
root.setAlignment(CENTER);
```

+   我们设置了带有文本的按钮控件，以及一个事件处理程序，当单击按钮时，将消息文本控件设置为**Hello World! JavaFX style :)**。

+   您可能会注意到在 Java 中有一种奇怪的代码语法，没有编译器错误。这是一个**Lambda**表达式，它已经添加到了 Java SE 8 中，我们将在第二章 *JavaFX 8 Essentials and Creating a custom UI*中简要讨论它。与旧的匿名内部类风格相比，现在使用 Lambda 表达式更清晰、更简洁。看一下这段代码的比较：

老派：

```java
btn.setOnAction(new EventHandler<ActionEvent>() {
  @Override
  public void handle(ActionEvent event) {
    message.setText("Hello World! JavaFX style :)");
  }
});
```

新时代：

```java
btn.setOnAction(event -> {
    message.setText("Hello World! JavaFX style :)");
});
```

+   当使用 JavaFX Packager 工具创建应用程序的**JAR**文件时，不需要`main()`方法，该工具会将 JavaFX Launcher 嵌入 JAR 文件中。

+   然而，包括`main()`方法是有用的，这样您就可以运行没有 JavaFX Launcher 创建的 JAR 文件，比如在使用 JavaFX 工具没有完全集成的 IDE 中。此外，嵌入 JavaFX 代码的**Swing**应用程序需要`main()`方法。

+   在我们的`main()`方法的入口点，我们通过简单地将命令行参数传递给`Application.launch()`方法来启动 JavaFX 应用程序。

+   在`Application.launch()`方法执行后，应用程序将进入就绪状态，框架内部将调用`start()`方法开始执行。

+   此时，程序执行发生在*JavaFX 应用程序线程*上，而不是在**主线程**上。当调用`start()`方法时，一个 JavaFX `javafx.stage.Stage`对象可供您使用和操作。

### 注意

高级主题将在接下来的章节中进行详细讨论。更重要的是，我们将在接下来的章节中深入讨论 JavaFX 应用程序线程。在最后三章中，我们将看到如何将其他线程的结果带入 JavaFX 应用程序线程，以便在场景中正确呈现它。

# 总结

到目前为止，您已经了解了 JavaFX 是什么，并见识了它的强大。您已经成功下载并安装了 Java 8 JDK 和 NetBeans IDE。在成功安装了先决条件软件之后，您通过 NetBeans IDE 创建了一个 JavaFX Hello World GUI 应用程序。在学习了如何编译和运行 JavaFX 应用程序之后，您快速浏览了源文件`HelloJavaFX.java`的代码。

接下来，在第二章 *JavaFX 8 Essentials and Creating a custom*中，您将了解 JavaFX 8 架构组件和引擎，这些组件和引擎使 JavaFX 应用程序在底层高效平稳地运行。您还将了解最常见的布局 UI 组件，并了解如何为整个应用程序或单个场景节点设置主题。

我们还将介绍 Java SE 8 最重要的特性，Lambda 表达式，以及它的工作原理。然后我们将深入了解**Scene Builder**作为一种声明式 UI 和高效工具，然后学习生成的基于 FXML 的标记文档以及如何将其导入到 NetBeans IDE 中，以继续将应用程序逻辑实现与已声明的 UI 控件关联起来。

最后，您将能够创建一个自定义的 UI 组件，该组件不与默认的 JavaFX 8 UI 控件捆绑在一起。


# 第二章：JavaFX 8 基础知识和创建自定义 UI

了解 JavaFX 的基本知识肯定会帮助您轻松构建复杂的 UI 解决方案。

在本章中，您将简要介绍 JavaFX 8 架构，以便了解 JavaFX 架构组件和引擎如何有效地相互连接，并使其图形平滑地渲染。

您将学习如何在 JavaFX 场景上呈现图形，并为此创建一个使用场景、一些控件和样式的基本应用程序。

我们将涉及 Java SE 8 功能的基础知识（如**Lambda**和**函数接口**），以帮助提高代码的可读性、质量和生产力。

一旦我们有了第一个结构良好的 JavaFX 8 应用程序，如果您可以在不改变其功能的情况下更改应用程序的 UI，那不是很好吗？您将通过查看 JavaFX CSS 样式的基础知识来了解主题。

最后，您将了解如何使用 Scene Builder 以图形方式创建和定义 UI 屏幕，并将其保存为 JavaFX FXML 格式的文件。您还将亲身体验创建*自定义控件*。

在本章中，我们将涵盖以下主题：

+   了解 JavaFX 架构组件

+   使用 JavaFX 组件设置 UI

+   使用 Java SE 8，Lambda 表达式和其他功能

+   为不同平台定制应用程序的主题

+   使用 CSS 自定义应用程序 UI

+   使用 Scene Builder 工具以可视化方式创建 UI

+   使用 FXML 构建自定义 UI

# JavaFX 8 架构的快速回顾

为了更好地理解框架的组件和引擎如何相互交互以运行您的 JavaFX 应用程序，本节对 JavaFX 架构和生态系统进行了高层次描述。

以下图示了 JavaFX 平台的架构组件。它显示了每个组件以及它们如何相互连接。

负责运行 JavaFX 应用程序代码的引擎位于 JavaFX 公共 API 的下方。

此引擎由子组件组成。这些包括**Prism**，一个 JavaFX 高性能图形引擎；Glass 工具包，一个小巧高效的窗口系统；媒体引擎；和 Web 引擎。

### 注意

虽然这些组件没有通过公共 API 公开，但我们将对它们进行描述，以便您更好地了解是什么使 JavaFX 应用以高效的方式成功运行。

![JavaFX 8 架构的快速回顾](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_02_01.jpg)

JavaFX 架构图

有关 JavaFX 架构和生态系统的更多信息，请访问[`docs.oracle.com/javase/8/javafx/get-started-tutorial/jfx-architecture.htm`](http://docs.oracle.com/javase/8/javafx/get-started-tutorial/jfx-architecture.htm)。

## 场景图

每个应用程序都有一个起始根点来构建 UI 层次结构，而 JavaFX 应用程序的起始点是*场景图*。在前面的屏幕截图中，它显示为蓝色的顶层的一部分。它是表示应用程序用户界面的所有视觉元素的根节点树。它还跟踪和处理任何用户输入，并且可以被渲染，因为它本身是一个 UI 节点。

*Node*是场景图树中的任何单个元素。每个节点默认具有这些属性 - 用于标识的 ID，用于更改其视觉属性的样式类列表，以及用于正确适应场景并放置在其父布局容器节点内的边界体积，除了场景图的根节点。

场景图树中的每个节点都有一个父节点，但可以有零个或多个子节点；但是，场景根节点没有父节点（为空）。此外，JavaFX 具有一种机制，以确保节点只能有一个父节点；它还可以具有以下内容：

+   视觉效果，如模糊和阴影

+   通过不透明度控制组件的透明度

+   CPU 加速的 2D 变换、过渡和旋转

+   3D 变换，如过渡、缩放和旋转

+   事件处理程序（如鼠标事件、键盘事件或其他输入方法，如触摸事件）

+   应用程序特定状态

下图显示了舞台、场景、UI 节点和图形树之间的关系：

![场景图](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_02_02.jpg)

JavaFX UI 树层次关系

图形原语也是 JavaFX 场景图的一个组成部分，如线条、矩形和文本，以及图像、媒体、UI 控件和布局容器。

当涉及为客户提供复杂和丰富的 UI 时，场景图简化了这项任务。此外，您可以使用`javafx.animation` API 快速轻松地为场景图中的各种图形添加动画。

除了这些功能外，`javafx.scene` API 还允许创建和指定几种内容类型，如下所示：

+   **节点**：表示为 UI 控件、图表、组、容器、嵌入式 Web 浏览器、形状（2D 和 3D）、图像、媒体和文本的任何节点元素

+   **效果**：这些是简单的对象，当应用于 UI 节点时，会改变其在场景图节点上的外观，如模糊、阴影和颜色调整

+   **状态**：任何特定于应用程序的状态，如变换（节点的位置和方向）和视觉效果

## JavaFX 功能的 Java 公共 API

这是作为一套完整的 Java 公共 API 的瑞士军刀工具包，支持丰富的客户端应用程序开发。

这些 API 为您提供了前所未有的灵活性，通过将 Java SE 平台的最佳功能与全面的沉浸式媒体功能相结合，构建直观而全面的一站式开发环境，用于构建丰富的客户端 UI 应用程序。

这些 JavaFX 的 Java API 允许您执行以下操作：

+   利用 Java SE 的强大功能，从泛型、注解和多线程到新的 Lambda 表达式（Java SE 8 中引入）。

+   为 Web 开发人员提供了一种更简单的方式，可以从其他基于 JVM 的动态语言（如*JavaScript*）中使用 JavaFX。

+   通过集成其他系统语言（如*Groovy*）编写大型复杂的 JavaFX 应用程序。

+   将 UI 控件绑定到控制器属性，以便从模型到绑定的 UI 节点自动通知和更新。绑定包括对高性能延迟绑定、绑定表达式、绑定序列表达式和部分绑定重新评估的支持。我们将在第三章中看到这一点以及更多内容，*开发 JavaFX 桌面和 Web 应用程序*。

+   引入可观察列表和映射，允许应用程序将 UI 连接到数据模型，观察这些数据模型的变化，并相应地更新相应的 UI 控件，通过扩展 Java 集合库。

## 图形系统

JavaFX 图形系统，如前图中的紫色所示，支持在 JavaFX 场景图层上平稳运行的 2D 和 3D 场景图。作为该层下面的实现细节，它在运行在没有足够图形硬件支持硬件加速渲染的系统时，提供了渲染软件堆栈。

JavaFX 平台有两个实现图形加速管道：

+   **Prism**：这是处理所有渲染作业的引擎。它可以在硬件和软件渲染器上运行，包括 3D。JavaFX 场景的光栅化和渲染由此引擎处理。根据使用的设备，可能存在以下多个渲染路径：

+   DirectX 9 在 Windows XP 和 Vista 上，DirectX 11 在 Windows 7 上

+   OpenGL 在 Linux、Mac 和嵌入式系统上

+   当无法进行硬件加速时进行软件渲染。

+   **Quantum Toolkit**：这负责将 Prism 引擎和玻璃窗口工具包连接起来，使它们在堆栈中的 JavaFX 层中可用。这是除了管理与渲染与事件处理相关的任何线程规则。

## 玻璃窗口工具包

如上图中间部分所示，玻璃窗口工具包作为连接 JavaFX 平台与本机操作系统的平台相关层。

由于其主要责任是提供本机操作服务，例如管理定时器、窗口和表面，因此它在渲染堆栈中的位置最低。

## JavaFX 线程

通常，系统在任何给定时间运行两个或更多以下线程：

+   **JavaFX 应用程序线程**：这是 JavaFX 应用程序使用的主要线程。

+   **Prism 渲染线程**：这将渲染与事件分发器分开处理。它在准备处理下一个 N + 1 帧时渲染 N 帧。它的最大优势是能够执行并发处理，特别是在具有多个处理器的现代系统上。

+   **媒体线程**：这在后台运行，并通过 JavaFX 应用程序线程通过场景图同步最新帧。

+   **Pulse**：这使您能够以异步方式处理事件。它帮助您管理 JavaFX 场景图元素状态与 Prism 引擎场景图元素事件之间的同步。当它被触发时，场景图上元素的状态将与渲染层同步。

### 注意

任何布局节点和 CSS 也与脉冲事件相关联。

玻璃窗口工具包使用高分辨率本机定时器执行所有脉冲事件。

## 媒体和图像

JavaFX `javafx.scene.media` API 提供媒体功能。JavaFX 支持视觉和音频媒体。对于音频文件，它支持`MP3`、`AIFF`和`WAV`文件以及`FLV`视频文件。

您可以通过 JavaFX 媒体提供的三个主要独立组件访问媒体功能-`Media`对象表示媒体文件，`MediaPlayer`播放媒体文件，`MediaView`是一个将媒体显示到您的场景图中的节点。

### 注意

媒体引擎组件，如上图中橙色所示，经过精心设计，以稳定性和性能为考量，以在所有支持的平台上提供一致的行为。

## Web 组件

如上图中绿色所示，Web 引擎组件是最重要的 JavaFX UI 控件之一，它基于 WebKit 引擎构建，这是一个支持 HTML5、JavaScript、CSS、DOM 渲染和 SVG 图形的开源 Web 浏览器引擎。它通过其 API 提供 Web 查看器和完整的浏览功能。在第三章中，*开发 JavaFX 桌面和 Web 应用程序*，我们将深入研究这一点，当开发 Web 应用程序时。

它允许您在 Java 应用程序中添加和实现以下功能：

+   从本地或远程 URL 渲染任何 HTML 内容

+   提供后退和前进导航，并支持历史

+   重新加载任何更新的内容

+   对 Web 组件进行动画处理和应用 CSS 效果

+   为 HTML 内容提供丰富的编辑控件

+   可以执行 JavaScript 命令并处理 Web 控件事件

## 布局组件

在构建丰富和复杂的 UI 时，我们需要一种方式来允许在 JavaFX 应用程序中的 UI 控件内进行灵活和动态的排列。这是使用布局容器或窗格的最佳位置。

布局 API 包括以下容器类，它们自动化常见的布局 UI 模式：

+   **BorderPane**：这将其内容节点布局在顶部、底部、右侧、左侧或中心区域

+   **HBox**：这将其内容节点水平排列在一行中

+   **VBox**：这将其内容节点垂直排列在单列中

+   **StackPane**：这将其内容节点放置在面板中心的前后单一堆栈中

+   **GridPane**：这使得可以创建一个灵活的行和列网格，用于布置内容节点

+   FlowPane：这将其内容节点以水平或垂直流的方式排列，在指定的宽度（水平）或高度（垂直）边界处换行

+   **TilePane**：这将其内容节点放置在统一大小的布局单元或瓷砖中

+   **AnchorPane**：这使得可以将锚节点创建到布局的顶部、底部、左侧或中心，并且可以自由定位其子节点

### 提示

在 JavaFX 应用程序中可以嵌套不同的容器；为了实现所需的布局结构，我们将在下一步中看到这一点，当开发我们的自定义 UI 时。

## JavaFX 控件

JavaFX 控件是 UI 布局的构建块，它们位于`javafx.scene.control`包中作为一组 JavaFX API。它们是通过场景图中的节点构建的。它们可以通过 JavaFX CSS 进行主题和皮肤设置。它们可以在*不同平台*上进行移植。它们充分利用了 JavaFX 平台丰富的视觉特性。

这个图显示了目前支持的一些 UI 控件，还有更多未显示的：

![JavaFX 控件](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_02_03.jpg)

JavaFX UI 控件示例

### 注意

有关所有可用的 JavaFX UI 控件的更详细信息，请参阅[`docs.oracle.com/javase/8/javafx/user-interface-tutorial/ui_controls.htm#JFXUI336`](http://docs.oracle.com/javase/8/javafx/user-interface-tutorial/ui_controls.htm#JFXUI336)的官方教程和`javafx.scene.control`包的 API 文档。

# Java SE 8 特性

我们将深入了解 Java SE 8 的两个最重要的特性 - lambda 或 lambda 表达式和功能接口，这使得 lambda 可用于我们，以帮助编写更好、更简洁、更低样板的 JavaFX 8 代码。但是，请记住，本书不会涉及每一个 lambda 细节，因为这不是一本 Java SE 8 的书。

### 注意

要更好地了解 Java 的 lambda 路线图，请访问以下官方教程：[`docs.oracle.com/javase/tutorial/java/javaOO/lambdaexpressions.html`](http://docs.oracle.com/javase/tutorial/java/javaOO/lambdaexpressions.html)。

## Lambda 表达式

Java 语言项目**lambda**的主要目标是解决函数式编程的缺乏，并通过以类似于在 Java 中创建匿名对象而不是方法的方式轻松创建匿名（无名称）函数来提供一种轻松进行函数式编程的方法。

正如您在第一章的示例中所看到的，*开始使用 JavaFX 8*，我们讨论了在 JavaFX 按钮的按下事件上定义处理程序的常规方法，使用匿名内部类：

```java
btn.setOnAction(new EventHandler<ActionEvent>() {
   @Override
   public void handle(ActionEvent event) {
     message.setText("Hello World! JavaFX style :)");
   }
});
```

与在按钮动作中设置消息文本字段的`text`属性的单行代码相比，这段代码非常冗长。能否重写这个包含逻辑的代码块而不需要那么多样板代码？

Java SE 8 通过 Lambda 表达式解决了这个问题：

```java
btn.setOnAction(event -> {
    message.setText("Hello World! JavaFX style :)");
});
```

除了使您的代码更简洁和易于阅读外，Lambda 表达式还使您的代码执行性能更好。

### 语法

有两种编写 Lambda 表达式的方式，一般形式如下图所示：

![语法](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_02_04.jpg)

Lambda 表达式的一般形式 - 以创建新线程为例

这两种方式如下：

+   `(param1, param2, ...) -> expression;`

+   `(param1, param2, ...) -> { /* code statements */ };`

第一种形式，表达式形式，用于当我们只分配一行代码或只是一个简单表达式时。而第二种形式，块形式，是单行或多行代码的主体，带有返回语句，因此我们需要用大括号包裹它们。

以下三个语句是等价的：

+   `btn.setOnAction((ActionEvent event) -> {message.setText("Hello World!");});`

+   `btn.setOnAction( (event) -> message.setText("Hello World!"));`

+   `btn.setOnAction(event -> message.setText("Hello World!"));`

### 提示

要深入了解新的 lambda 表达式及其相关特性以及 Java SE 8 特性，我鼓励您尝试这个系列文章 - Java SE 8 新特性之旅：[`tamanmohamed.blogspot.com/2014/06/java-se-8-new-features-tour-big-change.html`](http://tamanmohamed.blogspot.com/2014/06/java-se-8-new-features-tour-big-change.html)

## 函数接口

lambda 表达式很棒，不是吗？但是您可能想知道它的确切类型，以便将其分配给变量并传递给方法。

答案在于函数接口的强大。如何？函数接口是由 Java 语言设计师/架构师巧妙地创建为闭包，使用**单一抽象方法**（**SAM**）的概念，提供了一个只有一个抽象方法的接口，并使用`@FunctionalInterface`注解。单一抽象方法模式是 Java SE 8 的 lambda 表达式的一个重要部分。

让我们通过一个示例来澄清函数接口和 lambda 表达式的概念。我创建了一个名为`Calculator.java`的函数接口，其中包含一个抽象方法`calculate()`。创建后，您可以声明并为 lambda 表达式分配变量。以下是函数接口：

```java
@FunctionalInterface
public interface Calculator {
    double calculate(double width, double height);
}
```

现在我们准备创建变量并为它们分配 lambda 表达式。以下代码创建并为我们的函数接口变量分配 lambda 表达式：

```java
Calculator area = (width, height) -> width * height; //Area = w × h
//Perimeter = 2(w+h)
Calculator perimeter = (width, height) -> 2 * (height + width);
out.println("Rectangle area: "+ area.calculate(4, 5)+" cm.");
out.println("Rectangle perimeter: "+ perimeter.calculate(4, 5)+" cm.");
```

代码的输出应该如下所示：

```java
Rectangle area: 20.0 cm.
Rectangle perimeter: 18.0 cm.
```

# 主题

与设计师和 UX/UI 专家合作时，您会听到关于为应用程序设置皮肤或更改其外观的说法。这两个术语通常可以互换使用，它们都反映了*主题*的基本概念。

主题的理念是通过改变控件的外观而不改变其基本功能来改变整个应用程序的样式。

在 JavaFX 中，您可以创建、修改或使用现有的主题来为应用程序、场景甚至只是 UI 控件设置皮肤。

## CSS

JavaFX **级联样式表**（**CSS**）可以应用于 JavaFX 场景图中的任何节点；它们是异步应用于节点的。样式也可以在运行时轻松地分配给场景，从而允许应用程序的外观动态变化。

它基于 W3C CSS 版本 2.1 规范，并且目前与版本 3 的当前工作中的一些附加功能兼容。JavaFX CSS 支持和扩展已经被设计为允许任何兼容的 CSS 解析器干净地解析 JavaFX CSS 样式表。这使得可以将 JavaFX 和其他目的（如 HTML 页面）的 CSS 样式混合到单个样式表中。

所有 JavaFX 属性名称都以`-fx-`为前缀，包括那些可能看起来与标准 HTML CSS 兼容的属性，因为一些 JavaFX 值与标准值的语义略有不同。

### 注意

有关 JavaFX CSS 的更多信息，请参阅使用 CSS 文档对 JavaFX 应用程序进行皮肤设置和[`docs.oracle.com/javase/8/javafx/api/javafx/scene/doc-files/cssref.html`](http://docs.oracle.com/javase/8/javafx/api/javafx/scene/doc-files/cssref.html)的参考指南。

### 应用 CSS 主题

这是一个自定义的简单 JavaFX CSS 规则，`ButtonStyle.css`，它将用于我们的主题过程来为按钮设置主题：

```java
/* ButtonStyle.css */
.button {
-fx-text-fill: SKYBLUE;
-fx-border-color: rgba(255, 255, 255, .80);
-fx-border-radius: 8;
-fx-padding: 6 6 6 6;
-fx-font: bold italic 20pt "Arial";
}
```

我们有两种方法可以应用 CSS 样式表来改变我们的 JavaFX 应用程序的外观和主题：

1.  使用 JavaFX 应用程序（`javafx.application.Application`）类的静态方法`setUserAgentStylesheet(String URL)`方法，可以为 JavaFX 应用程序中的所有场景和所有子节点设置样式。使用方法如下：

```java
Application.setUserAgentStylesheet(getClass().getResource("ButtonStyle.css").toExternalForm());
```

现在您可以使用 JavaFX 8 当前预装的两个样式表，Caspian 和 Modena，我们可以使用与此处相同的方法在它们之间切换：

```java
// Switch to JavaFX 2.x's CASPIAN Look and Feel.
Application.setUserAgentStylesheet(STYLESHEET_CASPIAN);

// Switch to JavaFX 8's Modena Look and Feel.
Application.setUserAgentStylesheet(STYLESHEET_MODENA);
```

### 提示

如果您通过传递空值来调用`setUserAgentStylesheet(null)`，则将加载默认的外观和感觉（在这种情况下为 Modena），而如果您使用 JavaFX 2.x Caspian，则将加载默认的外观和感觉。

1.  使用场景的`getStylesheets().add(String URL)`方法将自动为个别场景及其子节点设置样式，如下所示：

```java
Application.setUserAgentStylesheet(null); // defaults to Modena
// apply custom look and feel to the scene.
scene.getStylesheets()
.add(getClass().getResource("ButtonStyle.css")
.toExternalForm());
```

基本上，将加载默认主题（Modena），因为调用了`Application.setUserAgentStylesheet(null)`。然后通过调用`getStylesheets().add()`方法设置场景的额外样式。

首先应用样式到父级，然后应用到其子级。节点在添加到场景图后进行样式设置，无论它是否显示。

JavaFX CSS 实现应用以下优先顺序 - 用户代理样式表的样式优先级低于从代码设置的值，后者优先级低于场景或父级样式表。

内联样式具有最高优先级。来自父级实例的样式表被认为比场景样式表的样式更具体。

# Scene Builder

对于大多数复杂和复杂的 UI 需求，设计师使用工具在 WYSIWYG 界面中设计他们的 UI，而无需编写任何代码，然后将结果（`FXML`文件）加载到他们的 JavaFX 应用程序逻辑中会更容易吗？

因此，您需要 JavaFX Scene Builder；它是一个可视化布局工具，可以让您轻松地布置 UI 控件，以便您可以快速地使用效果和动画原型化您的应用程序。Scene Builder（2.0 及以上版本）是 JavaFX 8 的兼容版本。

在项目创建过程中的任何时候，您都可以预览您的工作，以检查其真实外观，然后再部署它。

它是开源的，因此与大多数 IDE 集成，但与 NetBeans IDE 更紧密。它还是一个跨平台的、独立的应用程序，可以在大多数平台上运行。

除了支持 CSS，它还允许您轻松地将自定义主题应用于您的原型。

## 下载和启动

2015 年初，Oracle 发布了 JavaFX Scene Builder 工具 2.0 版本，并宣布将不再提供 JavaFX Scene Builder 工具的构建（已编译形式）。

一家名为**Gluon**（[`gluonhq.com`](http://gluonhq.com)）的公司意识到工具可以改善或破坏编码体验。因此，他们决定开始提供基于他们将在公开可访问的存储库中维护的分支的构建。

Gluon 提供 IDE 插件，以及基于 OpenJFX 最新源代码的 JavaFX Scene Builder 工具的改进版本，还有基于社区参与和更好地支持第三方项目（如**ControlsFX** ([`www.controlsfx.org/`](http://www.controlsfx.org/))、**FXyz** ([`github.com/FXyz/FXyz`](https://github.com/FXyz/FXyz))和**DataFX** ([`www.datafx.io/`](http://www.datafx.io/))）的额外改进。

让我们从以下 URL 下载工具开始[`gluonhq.com/products/downloads/`](http://gluonhq.com/products/downloads/)。

下载版本 8.0 并安装后，启动它，Scene Builder 工具应该如下截图所示打开：

![下载和启动](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_02_05.jpg)

JavaFX 8 Scene Builder 工具。

## FXML

在添加组件和构建美丽的 UI 布局时，Scene Builder 在幕后自动生成一个 FXML - 基于 XML 的标记文件，以便稍后将其绑定到 Java 应用程序逻辑的 UI。

FXML 提供的主要优势之一是关注点的分离，因为它将 UI 层（*视图*）与逻辑（*控制器*）解耦；这意味着您可以随时更改 UI 而不更改底层逻辑。由于 FXML 文件未经编译，因此可以在运行时动态加载，无需任何编译。这意味着它可以帮助您进行快速原型设计。

### 将 FXML 加载到 JavaFX 应用程序中

从 Scene Builder 工具中导出结果后，很容易将 UI 设计添加到其中。这里展示了在`start()`方法中加载 FXML 文件的代码：

```java
BorderPane root = new BorderPane();
Parent content = FXMLLoader.load(getClass().getResource("filename.fxml"));
root.setCenter(content);
```

如您所见，我在`javafx.fxml.FXMLLoaderclass`上使用了`load()`静态方法，`load()`方法将加载（反序列化）由 Scene Builder 工具创建的 FXML 文件。

# 开发自定义 UI

在本章的最后部分，我们将基于 JavaFX 8 内置控件开发自定义 UI 组件。

我们将使用之前讨论过的基于 FXML 的概念来开发这个自定义 UI；其主要优势是关注点的分离，以便稍后定制组件而不改变其功能和与其绑定的任何其他逻辑。

## 登录对话框自定义 UI

我们将使用大部分之前介绍的工具和技术来开发我们的自定义 UI：登录对话框，这是每个企业应用程序中必不可少的组件。我们的 UI 组件将如下图所示：

![登录对话框自定义 UI](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_02_06.jpg)

登录自定义 UI 组件

### 登录对话框自定义 UI 的结构

基于 FXML 标记的自定义组件开发中最常见的结构和阶段如下：

+   在 Scene Builder 工具中开发 UI；然后将结果导出为基于 FXML 的文件

+   从 Scene Builder 中提取控制器骨架

+   创建一个将 UI（视图）绑定到其逻辑并扩展控件或布局的控制器

+   在 Controller 构造函数中加载 FXML 文件

+   创建一个初始化方法，确保所有 FXML 控件都被成功初始化和加载

+   公开公共属性以获取和设置控件数据和需要我们实现逻辑的动作方法

+   开发一个单独的 CSS 文件

+   在您的应用程序中使用自定义组件

### 编写登录对话框自定义 UI

让我们编写和开发我们的自定义 UI，登录对话框：

1.  打开 Scene Builder 工具并创建 UI。其属性如下图所示：![编写登录对话框自定义 UI](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_02_07.jpg)

1.  登录对话框布局层次结构如下所示：![编写登录对话框自定义 UI](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_02_08.jpg)

它由一个 Pane 布局作为顶部和根布局节点组成。然后，使用`GridPane(1,4)`来以一列和四行的网格布局放置控件，包括：

+   **第一**行包含`HBox`布局控件，位置为(`0,0`)，用于水平放置控件。它包括用于显示标志的`ImageView`控件和用于标题的 Label。

+   **第二**行放置了用于用户名属性的`TextField`，位置为(`0,1`)。

+   **第三**行放置了用于密码属性的`PasswordField`，位置为(`0,2`)。

+   **最后**一行，位置为(`0,3`)，有一个根布局控件`HBox`，它放置了另一个`HBox`，其中包含居中左对齐的`CheckBox`和`Label`（用于显示错误和其他消息）。然后有两个按钮控件，**重置**和**登录**，它们位于中心右侧。

+   在代码选项卡中，为对话框中的所有控件添加适当的**fx:id**名称，并为按钮和复选框事件添加`onAction`名称，如下图所示：

![编写登录对话框自定义 UI](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_02_09.jpg)

登录按钮属性

1.  从 Scene Builder 的**预览**菜单中，选择**在窗口中显示预览**。您的布局将弹出。如果一切正常，并且您对结果设计满意，从菜单栏中单击**文件**，然后单击**保存**，并输入文件名为`LoginUI.fxml`。恭喜！您已经创建了您的第一个 JavaFX UI 布局。

1.  现在我们将打开 NetBeans 来设置一个 JavaFX FXML 项目，因此启动 NetBeans，并从**文件**菜单中选择**新建项目**。

1.  在**JavaFX**类别中，选择**JavaFX FXML 应用程序**。单击**下一步**。然后将项目命名为**LoginControl**，将**FXML 名称**更改为`LoginUI`，然后单击**完成**。

### 提示

确保 JavaFX 平台是 Java SE 8。

1.  NetBeans 将创建如下的项目结构：![编码登录对话框自定义 UI](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_02_10.jpg)

登录控制 NetBeans 项目结构。

### 注意

在运行项目之前，请确保*清理和构建*您的项目，以避免可能出现的任何问题，特别是在运行应用程序和可能在运行时加载`*.fxml`文件时可能返回`null`。

1.  转到 Scene Builder 工具，并从**视图**中选择**显示示例控制器骨架**。将打开如下截图所示的窗口，我们将复制以替换`LoginUIController.java`（这将扩展`Pane`类内容代码与 NetBeans 中复制的内容）然后修复缺少的导入。

1.  用 NetBeans 已经创建的一个替换之前生成并保存的`LoginUI.fxml`文件。

1.  右键单击`LoginController.java`文件，选择**重构**，然后选择**重命名**，将其重命名为`Main.java`。

1.  最后，在`Main.java 类`的`start(Stage stage)`方法中添加以下代码，如下所示。我们正在创建登录组件的新实例作为我们场景的根节点，并将其添加到舞台上：

```java
LoginUIController loginPane = new LoginUIController();

stage.setScene(new Scene(loginPane));
stage.setTitle("Login Dialog Control");
stage.setWidth(500);
stage.setHeight(220);
stage.show();
```

![编码登录对话框自定义 UI](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_02_11.jpg)

1.  在`LoginUIController.java`类中，在类名下右键单击选择**插入代码**；然后选择**构造函数**，最后在构造函数中添加以下代码：

```java
public LoginUIController() throws IOException {
  FXMLLoader fxmlLoader = new FXMLLoader(getClass().getResource("LoginUI.fxml"));
  fxmlLoader.setRoot(this);
  fxmlLoader.setController(this);
  fxmlLoader.load();
}
```

此代码加载我们的`LoginUI.fxml`文档，并将其作为 Pane 布局与其层次结构返回。然后将其绑定到当前控制器实例作为控制器和根节点。请注意，控制器扩展了 Pane 作为`LoginUI.fxml`中根元素定义。

1.  从 NetBeans 中选择**清理和构建**，然后右键单击项目选择**运行**。应该出现与之前看到的相同的屏幕。

1.  在程序运行时，输入任何凭据并单击**登录**按钮；如下截图所示，将出现红色的错误消息：![编码登录对话框自定义 UI](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_02_12.jpg)

登录控制无效登录。

1.  如果输入正确的凭据（用户：*tamanm*，密码：*Tamanm*），则将显示绿色消息“*有效凭据*”，如下图所示。

1.  如果单击**重置**按钮，则所有控件都将返回默认值。

恭喜！您已成功创建并实现了一个 UI 自定义控件。

![编码登录对话框自定义 UI](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_02_13.jpg)

# 摘要

在本章中，我们涵盖了很多内容-简要介绍了 JavaFX 8 架构组件，这些组件作为基础层来顺利高效地运行 JavaFX 应用程序。然后我们探讨了如何在场景上呈现图形，并简要解释了最常见的布局和 UI 控件。

您已经了解了 Java SE 8 中的新功能，例如 lambda 表达式和函数接口，这些功能得到了示例的支持，展示了每个功能的强大之处。

您学会了如何使用`setUserAgentStylesheet(String URL)`和`getStylesheets().add(String URL)`方法来使用自定义 CSS 文件样式化您的应用程序。接下来，您简要了解了 Scene Builder 以及如何将 FXML 加载到场景中。最后，您学习了 JavaFX 中的自定义 UI 组件以及如何创建它们。

在下一章中，您将学习如何创建由多个场景组成的桌面应用程序，然后如何打包它。此外，我们还将学习如何与 Web 进行交互，并使用 JavaFX 8 开发 Web 应用程序。


# 第三章：开发 JavaFX 桌面和 Web 应用程序

本章将介绍如何开发引人注目的桌面和 Web 应用程序，利用多核、硬件加速的 GPU 来提供高性能的基于 UI 的应用程序，具有惊人的外观和感觉。

由于 JavaFX 完全是用 Java 从头开始编写的，一些 Java SE 8 内置的核心库将被用于支持我们的应用程序。此外，我们将学习如何将我们的应用程序打包为一个独立的应用程序进行启动和分发。

此外，我们还将涵盖 JavaFX 8 中任何 Web 应用程序中的基本核心 Web API，如`javafx.scene.web.WebEngine`、`java.net.HttpURLConnection`和`javafx.scene.web.WebView`。

我们将讨论 JavaFX 和 HTML5 之间的关系，这很重要，因为 JavaFX 的 API 和 HTML5 的特性互补。HTML5 是一个用于创建类似于本机桌面软件特性的用户体验的丰富 Web 内容平台。

更重要的是，我们将通过开发*笔记应用程序*的桌面版本，然后在 Web 上运行。

此外，我们将涵盖部署*笔记作为 Web 应用程序*所需的所有知识和技能，包括桌面和 Web。

在本章中将学到以下技能：

+   开发和运行桌面和 Web 应用程序

+   控制应用程序 UI

+   如何打包 JavaFX 8 桌面应用程序

+   在 JavaFX 应用程序中加载 HTML5 内容

+   从 JavaFX 发送数据到 JavaScript，反之亦然

+   部署 JavaFX Web 应用程序

# 开发一个笔记应用程序

仅为一个平台构建应用程序已经不够了。桌面、Web、移动和嵌入式支持对于成功的产品都是必需的，但学习不同的环境是困难的。这就是 JavaFX 的力量发挥作用的地方，它可以编写一个可以在不同平台上运行的应用程序，只需简单的调整，我们将在本章中看到。

在这里，我们将为桌面和 Web 构建一个*笔记*应用程序。在这个项目中，我将向您展示如何使用先前安装的开发工具（参见第一章，*开始使用 JavaFX 8*）从头开始使用 JavaFX 8 SDK 和 Java 编程语言创建完整的 JavaFX 应用程序。

然后我将向您展示如何创建应用程序的两个屏幕布局并创建控制它们的 Java 类。我将创建控制不同场景之间导航、保存数据的按钮，并使用属性绑定的功能动态更新您的 UI 控件。

最终项目将看起来像以下屏幕截图：

![开发一个笔记应用程序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_03_01.jpg)

P'Note-Taking 应用程序

这张图显示了从主屏幕新建笔记按钮打开的添加和编辑屏幕，以添加新笔记或编辑列表中的一个笔记如下：

![开发一个笔记应用程序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_03_02.jpg)

那么，您还在等什么呢？让我们开始吧！

## 构建 UI 原型

构建任何成功的应用程序的第一步（甚至是简单的应用程序）是原型化您的布局、屏幕关系、它们的状态和导航。在一张纸上草绘，然后从您的团队和经理那里获得反馈。重新修改，一旦获得批准，开始为您的客户构建一个真正的交互式原型，以便获得他们的反馈，以进行最终生产。

这就是我们现在要做的事情，我们的应用程序已经在易于使用的 UI 草图工具上布置在一张纸上，如下图所示。然后，我们将使用 Scene Builder 工具开发它作为一个完整的原型。

此外，我们将看到 NetBeans 和 Scene Builder 工具之间的互操作性。

### 注意

请注意，最好先在纸上画出布局草图，这是在与工具交互之前编辑、增强和找出最终应用程序布局的一种非常快速的方法。

现在，我们已经绘制了我们的应用程序，准备构建应用程序的真正原型。

最大限度地利用工具的最佳方法是在 NetBeans IDE 中创建应用程序骨架（*控制器类和 FXML 基本页面定义*），然后在 Scene Builder 工具中创建和开发 FXML 页面。这就是两个工具之间强大的互操作性。

![构建 UI 原型](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_03_03.jpg)

以下是开始使用 JavaFX FXML 应用程序的步骤：

1.  打开 NetBeans IDE，从主菜单中选择**文件**，然后选择**新建项目**，将打开一个**新项目**对话框。从**类别**中选择**JavaFX**，然后在**项目**下选择 JavaFX FXML 应用程序。然后，点击**下一步**按钮：![构建 UI 原型](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_03_04.jpg)

一个新的 JavaFX FXML 应用程序

1.  在**JavaFX FXML 应用程序**对话框中，添加相关信息。从**项目名称**中，添加位置和**FXML 名称**（在我的案例中为`ListNotesUI`）。在**创建应用程序类**中，我已添加`packt.taman.jfx8.ch3.NoteTakingApp`，如下图所示。点击**完成**。![构建 UI 原型](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_03_05.jpg)

1.  现在我们有了一个带有第一个 FXML UI 文档（`ListNotesUI.fxml`）的项目，我们需要添加第二个 FXML UI 文档（`AddEditUI.fxml`）以及其控制器。

1.  要做到这一点，从文件中选择**新建文件**；然后，在**类别**列表下，选择**JavaFX**，从**文件类型**列表中选择空的 FXML，最后，点击**下一步**，如下图所示。

1.  在**新建空的 FXML 和位置**对话框中，将**FXML 名称**字段编辑为`AddEditUI`，然后点击**下一步**。![构建 UI 原型](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_03_06.jpg)

添加一个新的空的 FXML 文档

1.  在控制器类对话框中，勾选**使用 Java 控制器**复选框。确保已选择**创建新控制器**，并将**控制器名称**设置为`AddEditUIController`。然后，点击**下一步**，跳过**级联样式表**对话框，最后，点击**完成**：![构建 UI 原型](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_03_07.jpg)

向 FXML 文档添加新控制器

当我们构建了项目结构后，就可以使用 Scene Builder 将控件添加到页面 UI 中，就像我们在纸上画的那样。这样做很容易：

1.  从 NetBeans 中，右键单击`ListNotesUI.fxml`并选择打开，或者直接双击它。**Scene Builder**将以设计模式打开您的 FXML 文档。

### 注意

注意：仅当 Scene Builder 安装在您的计算机上时才有效。

1.  根据以下截图设计页面。最重要的是，在返回 NetBeans 或关闭**Scene Builder**进行逻辑实现之前，不要忘记保存您的更改。![构建 UI 原型](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_03_08.jpg)

完成 ListNotesUI.fxml 文档设计

1.  对`AddEditUI.fxml`执行相同的步骤，您的设计应该最终如下所示：![构建 UI 原型](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_03_09.jpg)

完成 AddEditUI.fxml 文档设计

您需要检查 FXML 文档，看看我们如何嵌套许多容器和 UI 控件，以实现我们之前在纸上草图中所期望的 UI，另外还要使用它们的属性来控制间距、对齐、字体和颜色。

恭喜！您已经将草图布局转换为可以呈现给团队领导和经理的项目，以获得有关颜色、主题和最终布局的反馈，而不需要逻辑。此外，一旦获得批准，您可以继续进行最终客户反馈，然后再深入业务逻辑。

## 让您的应用程序生动起来-添加交互

设计应用程序后，您需要通过使其更具交互性和响应性来使其更具生命力，以执行和响应客户提出的功能要求。

我总是首先在每个 FXML 文档控制器中添加页面导航处理程序，我已经在每个 FXML 文档控制器类中完成了这一点。

为了消除冗余并实现模块化，我在`BaseController.java`类中创建了一个基本导航方法，该方法将被系统中的所有控制器扩展。这个类将用于添加任何常见功能和共享属性。

以下方法`navigate(Event event, URL fxmlDocName)`是我们系统中所有导航中最重要的代码之一（注释说明了工作机制）：

```java
protected void navigate(Event event, URL fxmlDocName) throws IOException {
  //Loading new fxml UI document
  Parent pageParent = FXMLLoader.load(fxmlDocName);
  //Creating new scene
  Scene scene = new Scene(pageParent);
  //get current stage
  Stage appStage = (Stage)((Node) event.getSource()).getScene().getWindow();
  //Hide old stage
  appStage.hide(); // Optional
  //Set stage with new Scene
  appStage.setScene(scene);
  //Show up the stage
  appStage.show();
}
```

该方法将分别从`ListNotesUI.fxml`页面的**New Note**和编辑按钮的操作处理程序中调用`ListNotesUIController.java`，以及从`AddEditUI.fxml`页面的**List Notes**、保存和**Cancel**按钮的操作处理程序中调用`AddEditUIController.java`。

注意 FXML 文档中定义的按钮与控制器之间的关系。`@FXML`注解在这里起作用，将 FXML 属性（*使用#*）与控制器中定义的操作绑定起来：

`ListNotesUI.fxml`文件中的**New Note**按钮定义如下：

```java
<Button alignment="TOP_CENTER"
        contentDisplay="TEXT_ONLY"
        mnemonicParsing="false"
        onAction="#newNote" 
        text="New Note" 
        textAlignment="CENTER" 
        wrapText="true" 
/>
```

**New Note**操作在`ListNotesUIController.java`中定义，使用`onAction="#newNote"`绑定到前面的按钮：

```java
@FXML
 private void newNote(ActionEvent event) throws IOException {
        editNote = null;
        navigate(event, ADD.getPage());
 }
```

`AddEditUI.fxml`文件中的**Back**按钮定义如下：

```java
<Button alignment="TOP_CENTER"    
        contentDisplay="TEXT_ONLY"
        mnemonicParsing="false"
        onAction="#back" 
        text="Notes List" 
        textAlignment="CENTER"
        wrapText="true"
/>
```

**Back**操作在`AddEditUIController.java`中定义，使用`onAction="#back"`绑定到前面的按钮：

```java
@FXML
private void back(ActionEvent event) throws IOException {
        navigate(event, FXMLPage.LIST.getPage());
}
```

您可能想知道`FXMLPage.java`类做什么。它是一个枚举（有关枚举的更多信息，请访问[`docs.oracle.com/javase/tutorial/java/javaOO/enum.html`](https://docs.oracle.com/javase/tutorial/java/javaOO/enum.html)）。我已经创建了枚举来定义所有我们的 FXML 文档名称及其位置，以及与这些 FXML 文档相关的任何实用方法，以帮助简化我们系统中的编码。

### 提示

这种可维护性的概念有助于在大型系统中保持常量属性和功能在一个地方进行未来的重构，使我们能够在一个地方更改名称，而不是在整个系统中漫游以更改一个名称。

如果您检查系统控制器，您会发现处理其他按钮操作的所有逻辑 - 删除、编辑、清除和保存笔记。

### 使用属性实现应用程序更改同步

属性是 JavaFX 基于对象属性的包装对象，例如 String 或 Integer。属性允许您添加监听器代码，以在对象的包装值发生更改或被标记为无效时做出响应。此外，属性对象可以相互绑定。

绑定行为允许属性根据另一个属性的更改值更新或同步它们的值。

属性是包装对象，具有使值可读/可写或只读的能力。

简而言之，JavaFX 的属性是包装对象，保存实际值的同时提供更改支持、无效支持和绑定功能。我将在以后讨论绑定，但现在让我们来看看常用的属性类。

所有包装属性类都位于`javafx.beans.property.* package`命名空间中。以下是常用的属性类。要查看所有属性类，请参考 Javadoc 中的文档（[`docs.oracle.com/javase/8/javafx/api/index.html?javafx/beans/property.html`](https://docs.oracle.com/javase/8/javafx/api/index.html?javafx/beans/property.html)）。

+   `javafx.beans.property.SimpleBooleanProperty`

+   `javafx.beans.property.ReadOnlyBooleanWrapper`

+   `javafx.beans.property.SimpleIntegerProperty`

+   `javafx.beans.property.ReadOnlyIntegerWrapper`

+   `javafx.beans.property.SimpleDoubleProperty`

+   `javafx.beans.property.ReadOnlyDoubleWrapper`

+   `javafx.beans.property.SimpleStringProperty`

+   `javafx.beans.property.ReadOnlyStringWrapper`

具有`Simple`前缀和`Property`后缀的属性是*可读/可写属性*类，而具有`ReadOnly`前缀和`Wrapper`后缀的类是只读属性。稍后，您将看到如何使用这些常用属性创建 JavaFX bean。

让我们快进到 JavaFX 的 Properties API，看看它如何处理常见问题。您可能会注意到`TableView`控件已经添加到主页面，列出了当前加载的笔记和任何新添加的笔记。

为了正确地填充`TableView`的数据，我们应该有一个数据模型来表示笔记数据，这是我在 JavaFX 的 JavaBean 风格的 Note 类中首次使用 Properties API 的地方，它定义如下：

```java
public class Note {
    private final SimpleStringProperty title;
    private final SimpleStringProperty description;
    public Note(String title, String description) {
        this.title = new SimpleStringProperty(title);
        this.description = new SimpleStringProperty(description);
    }
    public String getTitle() {
        return title.get();
    }
    public void setTitle(String title) {
        this.title.set(title);
    }
    public String getDescription() {
        return description.get();
    }
    public void setDescription(String description) {
        this.description.set(description);
    }
}
```

为了使用应用程序数据库中已存储的数据填充`TableView`类，例如（我们这里的数据库是使用`ObservableList<Note>`来存储笔记对象的临时数据库），我们必须传递这些数据的集合。

我们需要摆脱手动更新 UI 控件（在我们的情况下是`TableView`控件）的负担，每当笔记数据集合被更新时。因此，我们需要一个解决方案来自动同步表格视图和笔记数据集合模型之间的更改，例如添加、更新或删除数据，而不需要从代码中对 UI 控件进行任何进一步的修改。只有数据模型集合被更新 - UI 应该自动同步。

这个特性已经是 JavaFX 集合的一个组成部分。我们将使用 JavaFX 的`ObservableList`类。`ObservableList`类是一个集合，能够在对象被添加、更新或移除时通知 UI 控件。

JavaFX 的`ObservableList`类通常用于列表 UI 控件，比如`ListView`和`TableView`。让我们看看我们将如何使用`ObservableList`集合类。

在`BaseController`中，我已经创建了静态数据作为`ObservableList<Note>`，以便在所有控制器之间共享，以便能够向其中添加、更新和删除笔记。同时，它初始化了一些数据，如下所示：

```java
protected static ObservableList<Note> data = FXCollections.<Note>observableArrayList(
  new Note("Note 1", "Description of note 41"),
    new Note("Note 2", "Description of note 32"),
    new Note("Note 3", "Description of note 23"),
    new Note("Note 4", "Description of note 14"));
```

在`ListNotesUIController.java`类的`initialize()`方法中，我创建了一个`javafx.collections.transformation.FilteredList`类的实例，当我们在表格内容中搜索时，它将被用作过滤类。它将`ObservableList<Note>`类型的`data`对象作为源数据传递：

```java
FilteredList<Note> filteredData = new FilteredList<>(data, n -> true);
```

`FilteredList`的第二个参数是用于过滤数据的谓词；在这里，它返回`true`，表示没有过滤，我们将在以后添加过滤谓词。

创建的`ObservableList<Note>`类型的数据列表应该传递给我们的`TableView`数据，以便表格视图监视当前数据集合的操作，比如添加、删除、编辑和过滤，就像在`ListNotesUIController.java`类的`initialize()`方法中所示的那样，但是我们传递了`filteredData`包装实例：

```java
notesListTable.setItems(filteredData);
```

最后一步是确认我们的`notesListTable`列，类型为`TableColumn`，以及要呈现和处理 Note 类的哪个属性。我们使用`setCellValueFactory()`方法来完成，如下所示：

```java
titleTc.setCellValueFactory(new PropertyValueFactory<>("title"));
descriptionTc.setCellValueFactory(new PropertyValueFactory<>("description"));
```

请注意，`title`和`description`是`Note`类的实例变量名称。

检查最终项目代码以获取完整的实现。然后，从 NetBeans 主菜单中运行应用程序，选择运行，然后点击**运行主项目**。

尝试添加一个新的笔记，观察表格视图中您新添加的笔记。尝试选择和删除笔记或更新现有的笔记。您会立即注意到变化。

通过检查应用程序代码，您会发现我们所做的一切都是操纵数据列表，所有其他的同步工作都是通过`ObservableList`类来完成的。

#### 过滤 TableView 数据列表

我们将在这里接触到两个最强大的 Java SE 8 和 JavaFX 8 功能`Predicate`和`FilteredList`。让我们阐明我们手头的问题以及我们将如何使用`stream`功能来解决它。

在我们的`ListNotesUI.fxml`页面中，您可能会注意到位于笔记表格上方的文本字段；它在这里的目的是过滤当前表格数据，以缩小结果以获取特定的笔记。此外，我们需要维护当前的列表，小心不要从中删除任何数据或为每个搜索命中查询数据库。

我们已经有了笔记数据列表，我们将使用文本字段来过滤此列表中包含此字符或字符组合的任何笔记标题或描述，如下所示：

![过滤 TableView 数据列表](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_03_10.jpg)

填充了数据的表格

现在，在输入`d`、`de`、`dev`或`developing`、`JavaFX`之后，表格将被过滤，如下截图所示。另外，尝试删除所有文本；您会发现数据会再次出现。接下来，我们将发现我们是如何做到的。

![过滤 TableView 数据列表](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_03_11.jpg)

使用搜索字段中的文本过滤表格数据

以下是完成此操作的神奇代码：

```java
searchNotes.setOnKeyReleased(e ->
{
  filteredData.setPredicate(n ->
  {              
if (searchNotes.getText() == null || searchNotes.getText().isEmpty())
return true;

return n.getTitle().contains(searchNotes.getText())
|| n.getDescription().contains(searchNotes.getText());
  });
});
```

`searchNotes`是我们用来过滤笔记数据的文本字段的引用。我们已经使用`setOnKeyReleased(EventHandler<? super KeyEvent> value)`方法注册了它，一旦输入任何字符，就会获取我们的文本进行过滤。另外，请注意我们在这里使用了 Lambda 表达式，使代码更加简洁和清晰。

在动作方法的定义内部，`filteredData`是一个`FilteredList<Note>`类，我们已经传递了一个`test()`方法实现给`setPredicate(Predicate<? super E> predicate)`，只过滤与`searchNotes`文本输入匹配的笔记标题或描述。

过滤后的数据会自动更新到表格 UI 中。

有关 Predicate API 的更多信息，请访问[`docs.oracle.com/javase/8/docs/api/java/util/function/Predicate.html`](http://docs.oracle.com/javase/8/docs/api/java/util/function/Predicate.html)。

## 作为桌面应用程序的笔记

一旦您完成了应用程序，最好不要分发最终的 jar 文件，而是要求用户安装 JRE 环境以便能够运行您的应用程序，特别是如果您的目标是大众。

准备您的本机安装程序包作为`.exe`、`.msi`、`.dmg`或`.img`更加专业。

每个安装程序都会管理应用程序的要求，从所需的资产和运行时环境。这确保了您的应用程序也可以在多个平台上运行。

### 为桌面分发部署应用程序

NetBeans 的一个高级功能是通过其部署处理程序为不同的平台打包您的应用程序，它提供以下主要功能：

+   通过本机安装程序部署您的应用程序

+   管理应用程序资产，如应用程序图标、启动画面和本机安装程序图标

+   在准备最终包时，接受应用程序的最终签名证书

+   管理所需的 JavaFX 运行时版本

+   在 Windows 上使用开始菜单添加桌面快捷方式

+   处理 Java Web Start 技术的要求和自定义

让我们看看 NetBeans 部署的配置：

![为桌面分发部署应用程序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_03_12.jpg)

NetBeans 部署配置

要了解如何将您的应用程序打包成针对每个目标平台的本机安装程序，请访问以下网址，该网址提供了完成任务所需的所有步骤和软件：

[`netbeans.org/kb/docs/java/native_pkg.html`](https://netbeans.org/kb/docs/java/native_pkg.html)

# JavaFX 在 Web 上

在本节中，我们将学习有关 JavaFX 在 Web 上的知识，以及如何在那里部署我们的笔记应用程序。

## WebEngine

JavaFX 提供了一个能够加载 HTML5 内容的非 GUI 组件，称为**WebEngine** API (`javafx.scene.web.WebEngine`)。这个 API 基本上是`WebEngine`类的对象实例，用于加载包含 HTML5 内容的文件。HTML5 文件可以从本地文件系统、Web 服务器或 JAR 文件中加载。

使用 Web 引擎对象加载文件时，会使用后台线程加载文件内容，以免阻塞*JavaFX 应用程序线程*。

以下是两个用于加载 HTML5 内容的`WebEngine`方法：

+   load(String URL)

+   loadContent(String HTML)

## WebView

JavaFX 提供了一个 GUI `WebView` (`javafx.scene.web.WebView`)节点，可以将 HTML5 内容呈现到场景图上。`WebView`节点基本上是一个迷你浏览器，能够响应 Web 事件，并允许开发人员与 HTML5 内容进行交互。

由于加载 Web 内容和显示 Web 内容的能力之间的密切关系，`WebView`节点对象还包含一个`WebEngine`实例。

JavaFX 8 的`WebView`类实现支持以下 HTML5 功能：

+   Canvas 和 SVG

+   媒体播放

+   表单控件

+   历史维护

+   交互元素标签

+   DOM

+   Web workers

+   Web sockets

+   Web 字体

### WebView 和引擎的操作

我们将演示一个简单的示例，演示如何使用`WebView`将包含 Google 地图的 HTML5 网页文档集成到 JavaFX 中作为场景控件。然后，我们使用`WebEngine`从 JavaFX `TextField`控件中获取经度和纬度，执行一个 JavaScript 方法，将这些参数传递给地图，使地图居中显示在新传递的位置，并显示标记，如下图所示：

![WebView and engine in action](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_03_13.jpg)

JavaFX 8 应用程序中的 Google 地图查看器

为了清晰起见，我将只展示和解释代码中的重要部分，这演示了前面段落中提到的概念。有关本章中的完整代码，请查看`web`包代码`GoogleMapViewerFX.java`类和`map.html`文件。

要在 JavaFX 应用程序中查看 Google 地图，我们需要首先创建一个 HTML 文件，加载并集成 Maps API，这在`map.html`文件中定义。如前面的图片所示，位置居中于埃及开罗，我的城市，这是在创建地图时传递给地图的经度和纬度值，如下面的代码片段所示：

```java
var latlng = new google.maps.LatLng(30.0594885, 31.2584644);
var Options = {
    zoom: 13,
    center: latlng,
    mapTypeId: google.maps.MapTypeId.ROADMAP
};
var map = new google.maps.Map(document.getElementById("canvas"), Options);
```

接下来，我们要注意 JavaScript `goToLocation(lng, lat)`方法；这将从 JavaFX 应用程序中使用`webEngine`实例调用，根据从 JavaFX 控件中传递的经度和纬度来定位地图。

在`GoogleMapViewerFX.java`中，我们创建了四个控件来组成我们的 UI - 两个用于经度和纬度的`TextField`类，一个更新按钮，以及一个用于查看`map.html`文档的`WebView`对象：

```java
WebView webView = new WebView();
WebEngine webEngine = webView.getEngine();
final TextField latitude = new TextField("" + 29.8770037);
final TextField longitude = new TextField("" + 31.3154412);
Button update = new Button("Update");
```

请注意，我已经创建了带有初始经度和纬度的文本控件，这与原始地图位置不同。这个位置是我的家庭位置，你可以将它改为你的位置，然后点击更新以查看新位置。

要加载`map.html`文件，我们必须将其传递给我们已经创建的`WebView`类中创建的`WebEngine`类，如前面的代码片段所示。

实现按钮的`onAction()`方法，允许 JavaFX 控件和 JavaScript 之间的集成，使用`webEngine`的`executeScript()`方法，如下面的代码所示：

```java
update.setOnAction(evt -> {
   double lat = Double.parseDouble(latitude.getText());
   double lon = Double.parseDouble(longitude.getText());

   webEngine.executeScript("" +
             "window.lat = " + lat + ";" +
             "window.lon = " + lon + ";" +
             "document.goToLocation(window.lat, window.lon);");
});
```

运行应用程序，你应该看到前面的图像定位在开罗城！点击更新，你应该到达我的家，如下图所示。

尝试获取您的位置经度和纬度；然后也回到您的家！

很强大，不是吗？很容易集成 HTML5 内容，并与已经开发的 Web 应用程序进行交互，以在现有的 JavaFX 应用程序中添加更丰富的 Web 内容。

![WebView 和 engine 在操作中](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_03_14.jpg)

在 JavaFX 8 应用程序中更改 Google 地图位置

## 作为 Web 应用程序的笔记

一旦您的应用程序经过测试，就像我们之前讨论的那样，您可以将您的应用程序分发到多个平台和环境。我们已经在本章中使用分发的方式为桌面应用程序做了这样的操作，使用项目的`dist`文件夹下的`.jar`文件。

相同的`.jar`文件将用于 Web 部署，并且应用程序可以以多种方式部署为 Web 应用程序，我们将在接下来看到。

### 为 Web 运行应用程序

有三种方式可以在 Web 上运行您的 JavaFX 应用程序：

1.  使用**Java Web Start**下载和启动应用程序一次；然后，您可以在离线状态下从您的计算机上使用它

1.  将您的 JAR 嵌入到 HTML 文件中，以便在企业环境中运行

1.  从`WebEngine`类加载 HTML 内容，并从`WebView`类中查看它，如前所述

#### Java Web Start

Java Web Start 软件提供了通过单击启动功能齐全的应用程序的能力。用户可以下载和启动应用程序，例如完整的电子表格程序或互联网聊天客户端，而无需经过冗长的安装过程。

使用 Java Web Start，用户可以通过单击 Web 页面上的链接来启动 Java 应用程序。该链接指向一个**JNLP**（Java 网络启动协议）文件，该文件指示 Java Web Start 下载、缓存和运行应用程序。

Java Web Start 为 Java 开发人员和用户提供了许多部署优势：

+   使用 Java Web Start，您可以将单个 Java 应用程序放在 Web 服务器上，以便部署到包括 Windows、Linux 和 Solaris 在内的各种平台上。

+   它支持 Java 平台的多个同时版本。应用程序可以请求特定版本的 Java Runtime Environment（JRE）软件，而不会与其他应用程序的需求发生冲突。

+   用户可以创建一个桌面快捷方式来启动 Java Web Start 应用程序，而不需要浏览器。

+   Java Web Start 利用了 Java 平台固有的安全性。默认情况下，应用程序对本地磁盘和网络资源的访问受到限制。

+   使用 Java Web Start 启动的应用程序会在本地缓存，以提高性能。

+   对 Java Web Start 应用程序的更新在应用程序从用户的桌面独立运行时会自动下载。

Java Web Start 作为 JRE 软件的一部分安装。用户不需要单独安装 Java Web Start 或执行其他任务来使用 Java Web Start 应用程序。

有关**Java Web Start**的更多信息，请参阅以下链接：

+   Java Web Start 指南（[`docs.oracle.com/javase/8/docs/technotes/guides/javaws/developersguide/contents.html`](http://docs.oracle.com/javase/8/docs/technotes/guides/javaws/developersguide/contents.html)）

+   `javax.jnlp` API 文档（[`docs.oracle.com/javase/8/docs/jre/api/javaws/jnlp/index.html`](http://docs.oracle.com/javase/8/docs/jre/api/javaws/jnlp/index.html)）

+   Java Web Start 开发者网站（[`www.oracle.com/technetwork/java/javase/javawebstart/index.html`](http://www.oracle.com/technetwork/java/javase/javawebstart/index.html)）

### 为 Web 分发应用程序

要将您的 JavaFX 应用程序部署到 Web 上，可以使用 NetBeans 的一种非常简单的方法。

NetBeans 已经为您的 JavaFX 应用程序提供了三种部署类型 - 桌面、Java Web Start 和 Web，如下图所示：

![为 Web 分发应用程序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_03_15.jpg)

# 总结

到目前为止，我们一直在学习如何为桌面和 Web 开发 JavaFX 企业应用程序。

在本章中，我们掌握了开发任何应用程序的技能，从在纸上草绘布局开始；接下来，我们将其转化为实际的交互式、丰富多彩的 UI 原型。我们看到了如何嵌套容器和控件以实现所需的布局。一旦我们获得了最终开发的批准，我们通过使其响应客户操作并提供功能要求，使应用程序栩栩如生。

我们利用 Java SE 8 功能和 JavaFX 绑定使我们的代码更加强大、干净和简洁。最后，我们学会了如何将我们的应用程序部署到目标桌面客户端或 Web 用户，以适应不同的平台和环境。

在下一章中，我们将学习如何为基于 Android 的智能手机开发 JavaFX 应用程序。此外，我们还将学习下载和安装 Android SDK 工具以及与记录器、模拟器和其他工具进行交互的必要技能，这些工具将帮助您进行任何与 JavaFX 无关的未来移动开发。


# 第四章：为 Android 开发 JavaFX 应用程序

毫无疑问，我们每天都在看到非 PC 客户端的增长。几乎每个人都至少有一部手机或平板电脑，可能来自不同的供应商，但肯定是带有 Android 或 iOS 的，因为它们在 2014 年占据了 96%的智能手机操作系统销售份额。

智能手机和平板电脑现在非常流行，这些数字每年都在增加。这就是为什么开发人员应该考虑获得开发这样一个巨大市场的应用程序所需的技能。

JavaFX 8 已经为 Web 和桌面提供了丰富的客户端应用程序，正如我们在第三章中所看到的，*开发 JavaFX 桌面和 Web 应用程序*。但是，如果像我一样，您已经编写了一个 JavaFX 应用程序，您肯定希望它能在尽可能多的设备上运行，以遵循*Write Once, Run Anywhere*的真正精神。我想借此机会告诉您，是的，我们可以在移动设备上运行 JavaFX。

基于 Oracle Corporation 对 JavaFX 的官方支持，JavaFX 社区内的许多人正在努力将 JavaFX 移植到尽可能多的设备和平台（桌面、移动和嵌入式）以及不同的操作系统上，使用相同的代码库。

他们已经成功地创建了 SDK，使我们能够开发 JavaFX 应用程序作为本机应用程序在 Android 或基于 iOS 的设备上运行在一个捆绑包中（*JVM 加应用程序*），而无需像在桌面或 Web 上运行它们一样需要任何额外的软件。

本章将为您提供关于 SDK 的基本实践知识，这将使您能够为 Android 创建、打包和部署本机应用程序。

在本章中将获得以下一些技能：

+   安装和配置 Android 环境工具和软件

+   准备和创建 JavaFX 8 移动项目结构

+   创建一个 Android JavaFX 8 应用程序

+   JavaFX 8 与 Android 低级 API 之间的互操作性

+   在移动设备上打包和部署应用程序

+   为最终的 Google Play 商店提交应用程序进行签名

# 为什么要将 JavaFX 移植到移动环境？

为什么要将 JavaFX 移植到移动环境？这不是**Write Once Run Anywhere**（**WORA**）吗？这是一个非常好的问题。任何 Java 应用程序都遵循 WORA 范例，但是有一个非常关键的抽象软件，它依赖于运行，被称为**Java Virtual Machine**（**JVM**）。

JVM 是负责将编译的字节码（*.class 文件*）翻译为特定机器并提供平台指令以便它能理解和运行的软件，因此您可以运行您的应用程序。因此，您会发现为每种硬件（Intel、AMD、SPARC 或 ARM）和平台（Windows、Mac、Linux 或 Solaris）都有不同版本的 JRE 或**JDK**。

在桌面、Web 或嵌入式设备上，您必须首先安装**Java Runtime Environment**（**JRE**）才能运行您的 Java 应用程序。但是，对于移动设备，您会注意到您只需从商店下载您的应用程序，安装它，最后运行它，而无需任何额外的软件。此外，一些封闭平台不允许安装 JVM。

为了更好的最终用户体验，运行 JavaFX 应用程序和运行其他针对 Android 或 iOS 的应用程序之间不应该有任何区别。

因此，我们应该有一个自包含的（应用程序加上 JVM）JavaFX 应用程序，可以在移动设备上运行。除了能够与 Android 低级 API 交互以控制设备功能外，它将被视为 Google Play 商店中的其他应用程序。

我们应该感谢社区提出这样的移植 SDK，并填补这一空白，使我们能够使用 RoboVM（[`www.robovm.org/`](http://www.robovm.org/)）上的移植和使用 JavaFXPorts（[`javafxports.org/`](http://javafxports.org/)）上的移植在 iOS 上创建和运行我们的 JavaFX 应用程序，并在 Android 上创建和运行我们的 JavaFX 应用程序。

自 2015 年 2 月以来，这些项目背后的公司之间达成了协议，现在一个名为`jfxmobile-plugin`的单一插件允许我们从相同的代码库构建三个平台的应用程序：桌面、Android 和 iOS。

此外，一家名为**Gluon**的新公司提供了一个免费插件（[`gluonhq.com/products/tools/ide-plugins/`](http://gluonhq.com/products/tools/ide-plugins/)），用于**NetBeans**，它创建了一个项目，其中包含构建基于`jfxmobile-plugin`的应用程序所需的一切。

### 注意

但请记住，所有这些都在不断发展，事情可能会有所变化。

## 它是如何工作的

RoboVM 用于 iOS 移植和 JavaFXPorts 用于 Android 移植都包含了所有必需的库，以便轻松打包您的 JavaFX 8 应用程序和所需的运行时环境。

使用 RoboVM 将 JavaFX 应用程序打包到 iOS（到`.ipa`包文件）时，所有 JavaFX 应用程序都会转换为**Objective-C**（目前是**Swift**）应用程序。

当使用 JavaFXPorts 将 JavaFX 应用程序打包到 Android（到`.apk`包文件）时，这些应用程序将被转换为在**Dalvik** VM 上运行的 Android 包。

这些 SDK 包含了大量的本地代码，将在将它们注入到您的 JavaFX 应用程序中后，被移植到 iOS 和 Android，以提高应用程序的性能。

使用这些 SDK，我们可以将我们的应用程序打包成适合提交到商店的格式（`.ipa`用于 iOS 和`.apk`用于 Android）。

## 谁在维护它？

不用担心 - 有大规模的免费支持，用于将 JavaFX 移植到 Android 和 iOS，以及商业支持。

### 注意

对于免费和商业支持，RoboVM 和 JavaFXPorts 社区都使用这个 Google 小组：

[`groups.google.com/forum/#!forum/javafxports`](https://groups.google.com/forum/#!forum/javafxports)

免费和商业支持主要来自社区中积极参与这两个项目的人，他们鼓励更多的第三方参与。

对于 iOS，RoboVM 为开发者提供了不同的计划；您可以在[`robovm.com/pricing/`](http://robovm.com/pricing/)上查看。

而对于 Android，公司**LodgON**提供对 JavaFX-Android 集成的支持，作为他们对 JavaFX 移植的支持的一部分（[`www.lodgon.com/dali/page/JavaFX_Consulting`](http://www.lodgon.com/dali/page/JavaFX_Consulting)）。

# 入门

我们现在已经有足够的信息，了解之前讨论的工具和 SDK 将如何让我们开始开发 JavaFX 应用程序，并将它们移植到 Android 移动设备上。

但在进入开发阶段之前，我们应该正确安装和配置工具和软件，以便根据提供的 SDK 完成开发过程，以便拥有最终的`.apk`包。

我们将在真实设备上部署这个`.apk`包，并最终对其进行签名，以便提交到 Google Play 商店。

因此，让我们开始安装先决工具和软件，以便开始开发我们的应用程序。

## 准备和安装先决软件

我们需要安装以下工具和软件列表，以便在没有任何问题的情况下完成我们的构建过程。

### Java SE 8 JDK8 u45

我们以前已经做过这个了；参考第一章中的*安装 Java SE 8 JDK*部分，*开始使用 JavaFX 8*。

### 注意

Java SE 8 更新 40 是为了开发 Android 的 JavaFX 应用程序所需的最低版本。

### Gradle

从他们的网站上，这是 Gradle 的定义：

> *Gradle 是一个开源的构建自动化系统。Gradle 可以自动化构建、测试、发布、部署等软件包或其他类型的项目，比如生成的静态网站、生成的文档，或者其他任何东西。*

最近，Android 开发工具将他们的构建系统更改为 Gradle。RoboVM 和 JavaFXPorts 移植项目模仿了相同的工具。

安装 Gradle 是一个非常简单的任务：

1.  转到[`gradle.org`](https://gradle.org)。

1.  从右侧，在**GET GRADLE!**部分，点击**Downloads 2.4**（截至目前为止），下载过程将开始下载`gradle-2.4-all.zip`文件。

1.  将下载的`.zip`文件复制到您选择的方便位置并解压缩它。

1.  最后一步是将环境变量设置到您的系统中，如下所示：

+   在 Windows 上 - 假设 Gradle 安装在`c:\tools\gradle_2.4`：

```java
set GRADLE_HOME=c:\tools\gradle_2.4
set PATH=%PATH%;%GRADLE_HOME%\bin

```

+   在 Mac 上 - 假设 Gradle 安装在`/usr/local/tools/gradle_2.4`：

```java
export GRADLE_HOME=/usr/local/tools/gradle_2.4
export PATH=${PATH}:${GRADLE_HOME}/bin

```

### Android SDK

Android SDK 包括 Android 平台的完整开发和调试工具集。

安装 Android SDK 是一个非常简单的任务：

1.  转到[`developer.android.com/sdk/index.html#Other`](http://developer.android.com/sdk/index.html#Other)。

1.  在 SDK Tools Only 下，点击`android-sdk_r24.2-{platform}`.`{exe|zip|tgz}`（截至目前为止），针对您喜欢的平台的名称：![Android SDK](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_04_01.jpg)

1.  将打开一个`Download`页面；接受条款，点击`Download android-sdk_r24.2-{platform}`.`{exe|zip|tgz}`按钮，下载过程将开始。

1.  将下载的`.zip`文件复制到一个方便的位置并解压缩它，或者在 Windows 上双击`.exe`来开始安装。

1.  从命令行运行以下命令：

```java
$ android

```

Android SDK Manager 将打开；点击`Build-tools version 21.1.2`或更高版本以及 API 21 或更高版本的 SDK 平台。

点击**Install x packages**，接受许可证，然后点击**Install**。完成。

Android SDK Manager 的一个很好的参考资料在[`developer.android.com/sdk/installing/adding-packages.html`](http://developer.android.com/sdk/installing/adding-packages.html)。

1.  最后一步是在您的系统中设置环境变量，如下所示：

+   在 Windows 上 - 假设 Android SDK 安装在`c:\tools\android_ADT`：

```java
set ANDROID_HOME=c:\tools\android_ADT\sdk
set PATH=%PATH%;%ANDROID_HOME%\platform-tools;%ANDROID_HOME%\tools

```

+   在 Mac 上 - 假设 Android SDK 安装在`/usr/local/tools/android_ADT`：

```java
export ANDROID_HOME=/usr/local/tools/android_adt/sdk
export PATH=${PATH}:${ANDROID_HOME}/tools:${ANDROID_HOME}/platform-tools

```

+   这样做的最佳方法是在`C:\Users\<user>\.gradle\gradle.properties`下创建一个名为 ANDROID_HOME 的 Gradle 属性。

## 为 Android 准备项目

我们已经成功安装了先决条件软件和工具，并配置了环境变量，所以我们准备开始开发将被移植到 Android 设备的应用程序。

但在这之前，我们需要准备好我们的项目结构和构建文件，以便准备好使用 JavaFXPorts 库构建和打包我们的应用程序。

使用三种不同平台设置一个复杂的项目曾经是一项艰巨的任务，但最近 Gluon（http://gluonhq.com/）发布了一个 NetBeans 插件（[`gluonhq.com/gluon-plugin-for-netbeans/`](http://gluonhq.com/gluon-plugin-for-netbeans/)），大大简化了这项任务。

### 项目结构

最简单的方法是使用 NetBeans 的 Gluon 插件。这将为您创建一个 Java 项目，您只需要添加 JavaFX 源代码和一个带有所有任务准备的`build.gradle`文件。

安装了插件后，执行以下任务：

1.  只需创建一个新的 JavaFX 项目，并选择**Basic Gluon Application**，如下所示：![Project structure](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_04_02.jpg)

1.  为项目（`DialPad2`）、包（`packt.taman.jfx8.ch4`）和主类（`DialPad2`）选择有效的名称，您将在新项目中找到一堆文件夹。

1.  遵循 Gluon 插件的顶部项目结构将带来更复杂的结构，并且应该如下截图所示：![项目结构](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_04_04.jpg)

Gluon 插件项目结构

接下来，我们将添加我们的构建脚本文件以完成我们的任务。

#### 使用 Gradle

要构建一个 Gradle 项目，我们需要`build.gradle`脚本文件。Gluon 插件已经默认为您添加了此文件，包括所有属性，以允许我们的应用程序成功运行和编译。

默认的 Gradle 构建文件创建`build.gradle`文件应该如下所示：

```java
buildscript {
    repositories {
        jcenter()
    }
    dependencies {
        classpath 'org.javafxports:jfxmobile-plugin:1.0.0-b8'
    }
}

apply plugin: 'org.javafxports.jfxmobile'

repositories {
    jcenter()
}

mainClassName = 'packt.taman.jfx8.ch4.DialPad2'

jfxmobile {

    android {
        manifest = 'lib/android/AndroidManifest.xml'
    }
}
```

唯一需要更改的重要事项是将`jfxmobile-plugin`版本更改为 1.0.0-b8（或最新版本；请经常查看[`bitbucket.org/javafxports/javafxmobile-plugin/overview`](https://bitbucket.org/javafxports/javafxmobile-plugin/overview)以保持更新）。

## 该应用程序

您已经到达这一部分意味着我们已经正确设置了应用程序项目结构，并且现在已经准备好进行移动设备开发。

我们的应用程序将是一个新的智能手机拨号界面，用于在我们的设备上执行呼叫操作。它将使用 CSS 进行自定义以控制其外观样式，可以根据需要修改以获得不同平台的本机外观和感觉。

该应用程序的主要目的是提供一个新的 UI 概念（使用 CSS 自定义应用程序），您将学习如何使用 CSS id 和 class 选择器以及从代码内部设置它们以应用于不同的控件。

以下截图显示了应用程序在应用 CSS 文件之前和之后的样子：

![应用程序](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_04_03.jpg)

### 使用 CSS 开发和样式化应用程序 UI

正如我们之前学到的，我将开始原型设计我们的应用程序；在原型设计之后，我们应该有之前看到的应用程序 UI。

该应用程序 UI 直接写在`DialPad2.java`类的`start(Stage)`函数内，作为一种开发 UI 的替代方式，而不是使用静态的 FXML 设计。

在这里，我们从代码内部嵌套控件，以防需要动态生成 UI 控件并为它们分配不同的设置、CSS 类、id 选择器和监听器。

以下代码片段显示了我们如何生成前面的应用程序 UI：

```java
BorderPane root = new BorderPane();
Rectangle2D bounds = Screen.getPrimary().getVisualBounds();
Scene scene = new Scene(root, bounds.getWidth(), bounds.getHeight());
scene.getStylesheets().add(getClass().getResource("ui/Mobile_UI."+PlatformFactory.getName()+".css").toExternalForm());
TextField output = new TextField("");
output.setDisable(true);

root.setTop(output);
String[] keys = {"1", "2", "3",
                 "4", "5", "6",
                 "7", "8", "9",
                 "*", "0", "#"};

GridPane numPad = new GridPane();
numPad.setAlignment(Pos.CENTER);
numPad.getStyleClass().add("num-pad");
for (int i = 0; i < keys.length; i++) {
       Button button = new Button(keys[i]);
       button.getStyleClass().add("dial-num-btn");
       button.setOnAction(e -> output.setText(output.getText().concat(Button.class.
      cast(e.getSource()).getText())));
      numPad.add(button, i % 3, (int) Math.ceil(i / 3));
}
// Call button
Button call = new Button("Call");
call.setOnAction(e->PlatformFactory.getPlatform().callNumber(output.getText()));
call.setId("call-btn");
call.setMaxSize(Double.MAX_VALUE, Double.MAX_VALUE);
numPad.add(call, 0, 4);
GridPane.setColumnSpan(call, 3);
GridPane.setHgrow(call, Priority.ALWAYS);
root.setCenter(numPad);

//Stage setup
stage.setScene(scene);
stage.setTitle("Phone Dial v2.0");
stage.show();
```

代码首先创建一个以`BorderPane`为根节点的场景。创建场景后，代码加载 CSS 样式表文件`Mobile_UI.<platform>.css`，通过`getStylesheets().add()`方法来为当前场景的节点设置样式，如下所示：

```java
scene.getStylesheets().add(getClass().getResource("ui/Mobile_UI."+PlatformFactory.getName()+".css").toExternalForm());
```

在我们创建了一个`TextField`输出来显示拨号结果并将其设置为禁用，以便我们无法编辑它之后，只需点击按钮即可添加和显示数字。

接下来，代码简单地使用`GridPane`类创建一个网格，并生成 12 个按钮放置在每个单元格中。请注意，在 for 循环中，每个按钮都通过`getStyleClass().add()`方法设置为名为`dial-num-btn`的样式类。

### 注意

在这里，我们使用了一个传统的`for`循环来添加按钮，而不是一个花哨的 Java 8 流。请注意，`Dalvik VM`仅在 Java 7 上运行，并且只能使用 lambda（因为在内部，JavaFXPorts 使用 Retrolambda 项目）。

最后，深蓝色的**Call**按钮将添加到网格窗格的最后一行。因为**Call**按钮是唯一的，它的 id 选择器设置为`#call-btn`，并且将使用 id 选择器进行样式设置，这意味着 CSS 文件中的选择器将以`#`符号为前缀。

以下是用于样式化应用程序的 CSS 文件：

```java
.root {
    -fx-background-color: white;
    -fx-font-size: 20px;
    bright-green: rgb(59,223, 86);
    bluish-gray: rgb(189,218,230);
}
.num-pad {
    -fx-padding: 15px, 15px, 15px, 15px;
    -fx-hgap: 10px;
    -fx-vgap: 8px;
}

#call-btn {
    -fx-background-color: 
        #090a0c,
        linear-gradient(#38424b 0%, #1f2429 20%, #191d22 100%),
        linear-gradient(#20262b, #191d22),
        radial-gradient(center 50% 0%, radius 100%, rgba(114,131,148,0.9), rgba(255,255,255,0));
    -fx-background-radius: 5,4,3,5;
    -fx-background-insets: 0,1,2,0;
    -fx-text-fill: white;
    -fx-effect: dropshadow( three-pass-box , rgba(0,0,0,0.6) , 5, 0.0 , 0 , 1 );
    -fx-font-family: "Arial";
    -fx-text-fill: linear-gradient(white, #d0d0d0);
    -fx-font-size: 16px;
    -fx-padding: 10 20 10 20;
}
#call-btn .text {
    -fx-effect: dropshadow( one-pass-box , rgba(0,0,0,0.9) , 1, 0.0 , 0 , 1 );
}

.dial-num-btn {
    -fx-background-color:
        linear-gradient(#f0ff35, #a9ff00),
        radial-gradient(center 50% -40%, radius 200%, #b8ee36 45%, #80c800 50%);
    -fx-background-radius: 30;
    -fx-background-insets: 0,1,1;
    -fx-effect: dropshadow( three-pass-box , rgba(0,0,0,0.4) , 5, 0.0 , 0 , 1 );
    -fx-text-fill: #395306;
}

.dial-num-btn:hover {
    -fx-background-color: 
        #c3c4c4,
        linear-gradient(#d6d6d6 50%, white 100%),
        radial-gradient(center 50% -40%, radius 200%, #e6e6e6 45%, rgba(230,230,230,0) 50%);
    -fx-background-radius: 30;
    -fx-background-insets: 0,1,1;
    -fx-text-fill: black;
    -fx-effect: dropshadow( three-pass-box , rgba(0,0,0,0.6) , 3, 0.0 , 0 , 1 );
}

.dial-num-btn:pressed {
    -fx-background-color: linear-gradient(#ff5400, #be1d00);
    -fx-background-radius: 30;
    -fx-background-insets: 0,1,1;
    -fx-text-fill: white;
}
```

有关 JavaFX 8 CSS 属性的更多信息，请访问以下 JavaFX 8 CSS 参考：

[`docs.oracle.com/javase/8/javafx/api/javafx/scene/doc-files/cssref.html`](http://docs.oracle.com/javase/8/javafx/api/javafx/scene/doc-files/cssref.html)

### 添加一些逻辑

正如您在代码片段中所看到的，每个 12 个按钮都有一个分配的操作，使用 lambda 表达式动态创建如下：

```java
button.setOnAction(e -> output.setText(output.getText().concat(Button.class.cast(e.getSource()).getText())));
```

我们得到输出`TextField`并通过获取事件`e`的源来连接下一个数字、星号或井号，而在我们的情况下，这是点击的按钮，然后它的文本值，包含要拨打的号码。

### 使您的项目适用于移动设备

基本上，这个新项目是使用 Gluon 插件生成的（`build.gradle`更新到**b8**）。

为了使应用程序适用于移动设备，我们需要调整其高度和宽度以适应目标设备屏幕，并使 UI 树相应地做出响应。

这是一个非常简单但非常重要的步骤，我们可以通过将场景高度和宽度设置为目标设备屏幕尺寸来调整以下代码行。看一下以下行：

```java
Scene scene = new Scene(root, 175, 300);
```

将此更改为以下代码行：

```java
Rectangle2D bounds = Screen.getPrimary().getVisualBounds();
Scene scene = new Scene(root, bounds.getWidth(), bounds.getHeight());
```

第一行获取设备屏幕`bounds`。然后我们从这个边界变量设置场景高度和宽度。

第二行将您的源添加到源包[Java]和资源[Main]。然后添加一个`PlatformFactory`类，负责查找项目正在运行的平台。看一下具有方法签名的`Platform`接口：

```java
public interface Platform {   
    void callNumber(String number);
}
```

这允许您在源上调用以下方法：

```java
Button call = new Button("Call");
call.setOnAction(e-> PlatformFactory.getPlatform().callNumber(output.getText()));
```

最后，您为每个平台提供本机解决方案。例如，对于 Android：

```java
public class AndroidPlatform implements Platform {

    @Override
    public void callNumber(String number) {
        if (!number.equals("")) {
            Uri uriNumber = Uri.parse("tel:" + number);
            Intent dial = new Intent(Intent.ACTION_CALL, uriNumber);
            FXActivity.getInstance().startActivity(dial);
         }
    }
}
```

为了使其在 Android 上工作，我们只需要修改`AndroidManifest.xml`，添加所需的权限和活动意图。这个自定义清单必须在`build.gradle`文件中引用，如下所示：

```java
android {
    manifest = 'lib/android/AndroidManifest.xml'
  }
```

#### 与低级 Android API 的互操作性

您需要`android.jar`来使用 Android API，并且您需要`jfxdvk.jar`来访问`FXActivity`类，它是`JavaFX`和`Dalvik`运行时之间的桥梁。我们在`FXActivity`上使用一个静态方法来检索`FXActivity`，它扩展了 Android`Context`。这个`Context`可以用来查找 Android 服务。

## 构建应用程序

为了为我们的应用程序创建 Android.apk 包文件，我们首先需要构建我们的应用程序；这是一个非常简单的任务。使用命令行（或从 NetBeans，右键单击**项目**选项卡，然后选择`Tasks/task`）指向当前项目文件夹，运行以下命令：

```java
$ gradle build

```

Gradle 将下载所有所需的库并开始构建我们的应用程序。完成后，您应该看到成功的输出如下：

```java
$ gradle build
Download https://jcenter.bintray.com/org/robovm/robovm-rt/1.0.0-beta-04/robovm-rt-1.0.0-beta-08.pom
:compileJava
:compileRetrolambdaMain
Download https://jcenter.bintray.com/net/orfjackal/retrolambda/retrolambda/1.8.0/retrolambda-1.8.0.pom
:processResources UP-TO-DATE
:classes
:compileDesktopJava UP-TO-DATE
:compileRetrolambdaDesktop SKIPPED
……...…
:check UP-TO-DATE
:build

BUILD SUCCESSFUL
Total time: 44.74 secs
```

到目前为止，我们已经成功构建了我们的应用程序。接下来，我们需要生成.apk 并将其部署到许多来源。

### 构建最终的.apk Android 包

在构建我们的.apk 文件时，有两个选项。第一个是通过运行以下命令：

```java
gradle android 

```

这将在目录`build/javafxports/android`中生成.apk 文件。

第二个是通过运行此命令：

```java
androidInstall 

```

这将在连接到您的台式机或笔记本设备的设备上部署生成的.apk 包。

我们将使用第一个选项（`gradle android`）来确保我们能够成功生成.apk 文件。成功完成后，您应该在先前提到的路径下有一个名为`DialPad2.apk`的文件。

## 部署应用程序

为了能够使用`gradle androidInstall`命令在连接的移动设备上部署我们的应用程序，您必须在设备上启用**开发者选项**并在其中启用一些其他设置，如下所示：

1.  从您的设备上，点击**设置**打开设置菜单。

1.  从顶部菜单中选择**更多**。选项取决于您的设备。

1.  在**更多选项**菜单列表的末尾，您应该看到**开发者选项**。

1.  点击**开发者选项**菜单。

1.  通过在右上角打开滑块来启用**开发者选项**。

1.  测试提示

1.  您必须在 Google Play 开发者中注册自己([`play.google.com/apps/publish/`](https://play.google.com/apps/publish/))，填写一个带有描述和几张截图的表格，最后提交 DialPad2 apk。

### 如果某些功能不如预期那样工作，请转到命令行并输入：

在交付应用程序之前最重要的一点是对其进行测试，特别是在不同的基于 Android 的移动设备上。

### 恭喜！您已完成——让我们去安装我们的应用程序。

发出此命令后，它将开始构建和打包 JavaFX 8 应用程序。插件将连接到您连接的设备并将应用程序安装到其中。这是您应该得到的结果：

```java
$ gradle androidinstall

```

`apk`必须签名才能发布。**签名**意味着您需要一个私钥；为此，我们可以使用 keytool ([`developer.android.com/tools/publishing/app-signing.html#signing-manually`](http://developer.android.com/tools/publishing/app-signing.html#signing-manually))。

```java
:compileJava
:compileRetrolambdaMain
………...…
:processAndroidResources UP-TO-DATE
:apk
:zipalign
:androidInstall
Installed on device.

BUILD SUCCESSFUL
Total time: 47.537 secs
```

在基于 Android 的设备上部署

在基于 Android 的设备上部署

为了在 Google Play 商店上部署您的应用程序，您必须执行以下操作：

点击**DialPad2**应用程序，您应该看到您的应用程序在设备上运行并完全按预期功能正常运行：

在 Google Play 商店上部署

根据我的经验，在移动测试领域中的四个黄金规则是：

JavaFX 8 应用程序拨打号码

而**发布**意味着我们需要将签名配置添加到`build.gradle`中，如下所示：

**可选**：如果您看不到**开发者选项**，不要担心。它是存在的，但是隐藏的。这里是魔法——点击**关于设备**，找到**构建号**，然后点击 5 次（Lollipop 上点击 7 次）。您将看到一个数字倒计时，最后**开发者选项**将被启用。

尽可能在尽可能多的真实设备和 Android 平台上进行测试，以覆盖应用程序将在其中运行的所有情况，并了解其在生产中的行为。

```java
$ adb logcat 

```

![在基于 Android 的设备上部署](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_04_05.jpg)

### ![在基于 Android 的设备上部署](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_04_07.jpg)

现在，我们准备运行以下命令：

1.  ![在基于 Android 的设备上部署](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/javafx-ess/img/B03998_04_06.jpg)

1.  右键单击**DialPad2**项目，从**任务**中选择**apk**，然后选择**apkRelease**。

1.  签署 APK

#### 仅使用模拟器进行*GUI 测试和功能*，而不是进行*性能测试*。所有模拟器都依赖于您的底层 PC/笔记本硬件和内存，而在移动硬件上将会有很大的不同，要达到相同的性能将是非常具有挑战性的。

然后，您将获得设备上所有应用程序的输出。

在**调试**下，启用**USB 调试**，点击**允许 USB 调试**警报窗口中的**确定**按钮，并启用**未知来源**。

```java
jfxmobile {
    android {
        signingConfig {
            storeFile file("path/to/my-release-key.keystore")
            storePassword 'STORE_PASSWORD'
            keyAlias 'KEY_ALIAS'
            keyPassword 'KEY_PASSWORD'
        }
        manifest = 'lib/android/AndroidManifest.xml'
        resDirectory = 'src/android/resources'
    }
}
```

现在打开您的设备，并从主屏幕上找到您的应用程序图标；在右下角，您应该看到您的`DialPad2` JavaFX 应用程序已安装，如下截图所示，带有默认的 Android 图标：

点击**呼叫**按钮，将启动 Android 默认的拨号器，拨打您输入的号码，如下所示：

## 恭喜！生成的`DialPad2.`apk 已准备好提交到 Google Play 商店。

注意

在我与移动行业的经验中，我发现有数十家供应商的测试手机和平板电脑运行 Android 平台，它们每个都定制了每个设备的 UI 层，具有不同的功能和性能。

您还可以在`application`标签下添加您应用程序的图标（`android:icon="@icons/ic_launcher`）。这里，`icons-*`是带有几种分辨率的图像文件夹。

1.  在 Android 设备上安装的 JavaFX 8 应用程序

1.  在`AndroidManifest.xml`中，您必须通过在`application`标签上添加`android:debuggable="false"`来禁用调试选项。

1.  Chrome 有一个名为 ARC Welder 的新模拟器。请访问[`developer.chrome.com/apps/getstarted_arc`](https://developer.chrome.com/apps/getstarted_arc)查看。

1.  最终生产和性能测试在真实设备上进行测试。这样您就可以确保您的应用程序在目标市场设备上能够正常运行。

# 总结

本章使您对移动行业有了很好的了解，以及如何使用不同的项目（如**RoboVM**用于**iOS**和**JavaFXPorts**用于**Android**）开发和定制基于 JavaFX 的应用程序，从而使您的应用程序能够在两个平台上运行。

然后，我们学习了如何安装所需的软件和工具进行 Android 开发，并启用 Android SDK 以及*JavaFXPorts*库来打包和安装我们的拨号器基于 JavaFX 的应用程序到真实的 Android 设备，并将其提交到 Google Play 商店。

我们看到如何使用 CSS 自定义我们的应用程序，使同一应用程序具有不同的外观和感觉，以确保您为 Android 版本提供了不同的 CSS。

接下来，我们学习了如何将我们的设备调试模式启用，以便通过命令行成功安装来自`jfxmobile-plugin`的应用程序。最后，我们介绍了测试的四个黄金规则。

下一章与本章不会有太大的不同，但会很好地介绍和了解如何将您的 JavaFX 8 应用程序定位到运行在基于 iOS 的设备上。您还将学习如何使用其开发工具。
